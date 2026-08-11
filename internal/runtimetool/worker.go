// Package runtimetool owns capability-bound external tool execution.
package runtimetool

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

const maximumRetainedToolOutputBytes = 8 << 20

var sensitiveToolOutput = regexp.MustCompile(`(?i)(authorization|token|secret|password)(\s*[=:]\s*)([^\s,;"}]+)`)

type Request struct {
	Tenant      runtimecontent.TenantID
	SessionID   agentruntime.SessionID
	TurnID      agentruntime.TurnID
	ToolCallID  string
	OperationID runtimestate.OperationID
	// Descriptor is the exact verified immutable sandbox-control action. It is
	// supplied only after the worker's state authorization succeeds.
	Descriptor []byte
}
type Response struct {
	Output    []byte
	MediaType string
	Failure   *agentruntime.Failure
	Uncertain bool
}
type Adapter interface {
	Execute(context.Context, Request) (Response, error)
	Reconcile(context.Context, Request) (Response, error)
}

// ExternalEffectContract declares the two runtime guarantees every concrete
// tool adapter must preserve. The adapter uses OperationID as its application
// idempotency key and Reconcile observes that exact key without resubmission.
type ExternalEffectContract struct {
	IdempotencyKey string
	Reconciles     bool
}

// ContractAdapter is the sealed construction boundary for adapters that can
// cause an external effect.
type ContractAdapter interface {
	Adapter
	ExternalEffectContract() ExternalEffectContract
}
type Config struct {
	Store    runtimestate.RuntimeStateStore
	Tenants  runtimestate.OutboxTenantSource
	Compiler *runtimestate.Compiler
	Planner  *runtimestate.RuntimeStatePlanner
	Clock    clock.Clock
	Content  *runtimecontent.Store
	Adapter  Adapter
	Claimer  string
}
type Worker struct {
	store            runtimestate.RuntimeStateStore
	tenants          runtimestate.OutboxTenantSource
	compiler         *runtimestate.Compiler
	planner          *runtimestate.RuntimeStatePlanner
	clock            clock.Clock
	content          *runtimecontent.Store
	descriptorReader *runtimecontent.ToolActionDescriptorReader
	adapter          Adapter
	claimer          string
}

func NewWorker(c Config) (*Worker, error) {
	if c.Store == nil || c.Tenants == nil || c.Compiler == nil || c.Planner == nil || c.Clock == nil || c.Content == nil || c.Adapter == nil || c.Claimer == "" {
		return nil, errors.New("create runtime tool worker: complete authority is required")
	}
	contract, ok := c.Adapter.(ContractAdapter)
	if !ok || contract.ExternalEffectContract() != (ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}) {
		return nil, errors.New("create runtime tool worker: adapter must reconcile the runtime operation idempotency key")
	}
	reader, err := runtimecontent.NewToolActionDescriptorReader(c.Content, descriptorRepository{store: c.Store, compiler: c.Compiler})
	if err != nil {
		return nil, err
	}
	return &Worker{store: c.Store, tenants: c.Tenants, compiler: c.Compiler, planner: c.Planner, clock: c.Clock, content: c.Content, descriptorReader: reader, adapter: c.Adapter, claimer: c.Claimer}, nil
}

// descriptorRepository is the only bridge from content reads to the sealed
// state compiler capability. It deliberately does not expose a content
// reference or object-store key to the tool adapter.
type descriptorRepository struct {
	store    runtimestate.RuntimeStateStore
	compiler *runtimestate.Compiler
}

func (repository descriptorRepository) AuthorizeToolActionDescriptorRead(ctx context.Context, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID, sessionID agentruntime.SessionID, turnID agentruntime.TurnID, toolCallID string) (runtimecontent.ToolActionDescriptorCommitment, error) {
	authorization, err := repository.compiler.CompileAuthorizeToolActionDescriptorRead(runtimestate.ToolActionDescriptorReadCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, SessionID: sessionID, TurnID: turnID, ToolCallID: toolCallID})
	if err != nil {
		return runtimecontent.ToolActionDescriptorCommitment{}, err
	}
	return repository.store.AuthorizeToolActionDescriptorRead(ctx, authorization)
}
func (w *Worker) ScanOnce(ctx context.Context) error {
	ts, e := w.tenants.ListOutboxTenants(ctx)
	if e != nil {
		return e
	}
	for _, t := range ts {
		if e := w.retireExpiredGrants(ctx, t); e != nil {
			return e
		}
		// Approval only makes a bounded grant available. The worker owns the
		// separate consume-then-intent transition, so a public decision can never
		// dispatch an adapter directly or race a revoked/expired grant.
		if e := w.admitApprovedGrants(ctx, t); e != nil {
			return e
		}
		p, e := w.store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: t, Authority: runtimestate.AuthorityOutboxPublisher}, Limit: 128})
		if e != nil {
			return e
		}
		for _, r := range p.Records {
			if r.ToolCallID == "" || r.EventKind != "" || r.State == runtimestate.OutboxPublished || r.State == runtimestate.OutboxReconcile || (r.State == runtimestate.OutboxClaimed && r.ClaimUntil != nil && r.ClaimUntil.After(w.clock.Now())) {
				continue
			}
			recovering := r.State == runtimestate.OutboxClaimed
			claimed, e := w.claim(ctx, r)
			if e != nil {
				return e
			}
			if e = w.process(ctx, claimed, recovering); e != nil {
				return e
			}
			if e = w.ack(ctx, claimed); e != nil {
				return e
			}
		}
	}
	return nil
}

func (w *Worker) retireExpiredGrants(ctx context.Context, tenant runtimecontent.TenantID) error {
	state, err := w.store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil {
		return err
	}
	for _, grant := range state.Grants {
		if grant.RevokedAt != nil || w.clock.Now().Before(grant.ExpiresAt) {
			continue
		}
		expire, compileErr := w.compiler.CompileExpireCapabilityGrant(runtimestate.ExpireCapabilityGrantCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: grant.Principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "tool-expire-" + grant.GrantID, GrantID: grant.GrantID, ToolCallID: grant.ToolCallID, SessionID: grant.SessionID, TurnID: grant.TurnID})
		if compileErr != nil {
			return compileErr
		}
		return w.persist(ctx, expire)
	}
	return nil
}

func (w *Worker) admitApprovedGrants(ctx context.Context, tenant runtimecontent.TenantID) error {
	state, err := w.store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil {
		return err
	}
	for _, grant := range state.Grants {
		if grant.RevokedAt != nil || !w.clock.Now().Before(grant.ExpiresAt) {
			continue
		}
		operationID := runtimestate.OperationID("op-tool-" + grant.GrantID)
		existing := false
		for _, execution := range state.ToolExecutions {
			if execution.GrantID == grant.GrantID {
				existing = true
				break
			}
		}
		if existing {
			continue
		}
		var approval runtimestate.ApprovalRecord
		for _, candidate := range state.Approvals {
			if candidate.ToolCallID == grant.ToolCallID && candidate.SessionID == grant.SessionID && candidate.TurnID == grant.TurnID && candidate.State == "approved" && candidate.Principal == grant.Principal {
				approval = candidate
				break
			}
		}
		if approval.ApprovalID == "" {
			continue
		}
		turnRunning := false
		for _, turn := range state.Turns {
			if turn.SessionID == approval.SessionID && turn.TurnID == approval.TurnID && turn.Principal == grant.Principal && turn.State == agentruntime.TurnRunning {
				turnRunning = true
				break
			}
		}
		if !turnRunning {
			// Cancellation and terminal settlement are authoritative. Do not turn a
			// stale approved grant into a worker error or a late external effect.
			continue
		}
		if grant.Uses == 0 {
			consume, err := w.compiler.CompileConsumeCapabilityGrant(runtimestate.ConsumeCapabilityGrantCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: grant.Principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "tool-consume-" + grant.GrantID, GrantID: grant.GrantID, ToolCallID: grant.ToolCallID, PolicyRevisionDigest: grant.PolicyRevisionDigest, SessionID: grant.SessionID, TurnID: grant.TurnID})
			if err != nil {
				return err
			}
			if err = w.persist(ctx, consume); err != nil {
				return err
			}
		}
		begin, err := w.compiler.CompileBeginToolExecution(runtimestate.BeginToolExecutionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: grant.Principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "tool-begin-" + grant.GrantID, GrantID: grant.GrantID, ToolCallID: grant.ToolCallID, SessionID: grant.SessionID, TurnID: grant.TurnID, OperationID: operationID})
		if err != nil {
			return err
		}
		if err = w.persist(ctx, begin); err != nil {
			return err
		}
		return nil
	}
	return nil
}
func (w *Worker) process(ctx context.Context, r runtimestate.OutboxRecord, recover bool) error {
	s, e := w.store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: r.Tenant, Authority: runtimestate.AuthorityRuntimeWorker})
	if e != nil {
		return e
	}
	var x runtimestate.ToolExecutionRecord
	for _, v := range s.ToolExecutions {
		if v.OperationID == r.OperationID && v.ToolCallID == r.ToolCallID {
			x = v
			break
		}
	}
	if x.OperationID == "" {
		return runtimestate.ErrNotFoundOrDenied
	}
	if x.State != runtimestate.ToolExecutionIntent {
		return nil
	}
	if !w.executionDispatchAllowed(s, x) {
		return w.recordDispatchRefusal(ctx, r)
	}
	descriptor, err := w.descriptorReader.ReadToolActionDescriptor(ctx, r.Tenant, r.Principal, r.SessionID, r.TurnID, r.ToolCallID)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, runtimecontent.ErrUnavailable) {
			return err
		}
		return w.recordDescriptorFailure(ctx, r)
	}
	q := Request{Tenant: r.Tenant, SessionID: r.SessionID, TurnID: r.TurnID, ToolCallID: r.ToolCallID, OperationID: r.OperationID, Descriptor: descriptor}
	var out Response
	if recover {
		out, e = w.adapter.Reconcile(ctx, q)
	} else {
		out, e = w.adapter.Execute(ctx, q)
	}
	if e != nil {
		out = Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "tool operation outcome is uncertain"}, Uncertain: true}
	}
	state := runtimestate.ToolExecutionFailed
	failure := out.Failure.Clone()
	var result *runtimecontent.Reference
	if out.Uncertain {
		state = runtimestate.ToolExecutionUncertain
	}
	if len(out.Output) > maximumRetainedToolOutputBytes && failure == nil && !out.Uncertain {
		// The adapter is permitted to observe an external response, but no
		// unbounded result may enter durable state or a public event projection.
		failure = &agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: "tool output exceeds the safe retention limit"}
		state = runtimestate.ToolExecutionFailed
	}
	if len(out.Output) > 0 && failure == nil && !out.Uncertain {
		out.Output = redactToolOutput(out.Output)
		mediaType := out.MediaType
		if mediaType == "" {
			mediaType = "text/plain"
		}
		h, err := w.content.StageArtifact(ctx, r.Tenant, mediaType, out.Output)
		if err == nil {
			artifact, compileErr := w.compiler.CompileRegisterArtifact(runtimestate.RegisterArtifactCommand{Scope: runtimestate.MutationScope{Tenant: r.Tenant, Principal: r.Principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "tool-output-" + string(r.OperationID), SessionID: r.SessionID, TurnID: r.TurnID, Artifact: h})
			if compileErr == nil {
				plan, persistErr := w.persistPlan(ctx, artifact)
				if persistErr == nil {
					v := plan.Result().Artifact.Reference
					result = &v
					state = runtimestate.ToolExecutionSucceeded
				} else {
					err = persistErr
				}
			} else {
				err = compileErr
			}
			if err == nil {
			} else {
				failure = &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "tool output could not be durably finalized"}
				state = runtimestate.ToolExecutionUncertain
			}
		} else {
			failure = &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "tool output could not be durably finalized"}
			state = runtimestate.ToolExecutionUncertain
		}
	}
	if failure == nil && state != runtimestate.ToolExecutionSucceeded {
		failure = &agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "tool operation returned no terminal outcome"}
		state = runtimestate.ToolExecutionUncertain
	}
	m, e := w.compiler.CompileRecordToolExecutionOutcome(runtimestate.RecordToolExecutionOutcomeCommand{Scope: runtimestate.MutationScope{Tenant: r.Tenant, Principal: r.Principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "tool-outcome-" + string(r.OperationID), SessionID: r.SessionID, TurnID: r.TurnID, ToolCallID: r.ToolCallID, OperationID: r.OperationID, Outcome: state, Result: result, Failure: failure})
	if e != nil {
		return e
	}
	return w.persist(ctx, m)
}

func redactToolOutput(value []byte) []byte {
	// Adapter output is treated as untrusted diagnostic data. Preserve bounded
	// useful text while replacing common credential assignments before content
	// storage, events, or any owner-readable Artifact registration.
	return sensitiveToolOutput.ReplaceAll(value, []byte("$1$2[REDACTED]"))
}

func (w *Worker) executionDispatchAllowed(state runtimestate.RuntimeState, execution runtimestate.ToolExecutionRecord) bool {
	turnRunning := false
	for _, turn := range state.Turns {
		if turn.SessionID == execution.SessionID && turn.TurnID == execution.TurnID && turn.Principal == execution.Principal && turn.State == agentruntime.TurnRunning {
			turnRunning = true
			break
		}
	}
	if !turnRunning {
		return false
	}
	for _, grant := range state.Grants {
		if grant.GrantID == execution.GrantID && grant.Principal == execution.Principal && grant.SessionID == execution.SessionID && grant.TurnID == execution.TurnID {
			return grant.RevokedAt == nil && w.clock.Now().Before(grant.ExpiresAt)
		}
	}
	return false
}

func (w *Worker) recordDispatchRefusal(ctx context.Context, r runtimestate.OutboxRecord) error {
	m, err := w.compiler.CompileRecordToolExecutionOutcome(runtimestate.RecordToolExecutionOutcomeCommand{Scope: runtimestate.MutationScope{Tenant: r.Tenant, Principal: r.Principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "tool-outcome-" + string(r.OperationID), SessionID: r.SessionID, TurnID: r.TurnID, ToolCallID: r.ToolCallID, OperationID: r.OperationID, Outcome: runtimestate.ToolExecutionFailed, Failure: &agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: "tool execution is no longer authorized"}})
	if err != nil {
		return err
	}
	return w.persist(ctx, m)
}

func (w *Worker) recordDescriptorFailure(ctx context.Context, r runtimestate.OutboxRecord) error {
	m, err := w.compiler.CompileRecordToolExecutionOutcome(runtimestate.RecordToolExecutionOutcomeCommand{Scope: runtimestate.MutationScope{Tenant: r.Tenant, Principal: r.Principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "tool-outcome-" + string(r.OperationID), SessionID: r.SessionID, TurnID: r.TurnID, ToolCallID: r.ToolCallID, OperationID: r.OperationID, Outcome: runtimestate.ToolExecutionFailed, Failure: &agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: "verified tool action descriptor is invalid"}})
	if err != nil {
		return err
	}
	return w.persist(ctx, m)
}
func (w *Worker) claim(ctx context.Context, r runtimestate.OutboxRecord) (runtimestate.OutboxRecord, error) {
	return w.transition(ctx, r, func(x runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error) {
		return w.compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: r.Tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: fmt.Sprintf("tool-claim-%s-%d", r.OutboxID, x.Version), OutboxID: r.OutboxID, ExpectedVersion: x.Version, Claimer: w.claimer, ClaimUntil: w.clock.Now().Add(2 * time.Minute)})
	})
}
func (w *Worker) ack(ctx context.Context, r runtimestate.OutboxRecord) error {
	_, e := w.transition(ctx, r, func(x runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error) {
		return w.compiler.CompileAcknowledgeOutbox(runtimestate.AcknowledgeOutboxCommand{Scope: runtimestate.MutationScope{Tenant: r.Tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: fmt.Sprintf("tool-ack-%s-%d", r.OutboxID, x.Version), OutboxID: r.OutboxID, ExpectedVersion: x.Version, Claimer: w.claimer, PublishedAt: w.clock.Now()})
	})
	return e
}
func (w *Worker) persist(ctx context.Context, m runtimestate.CompiledMutation) error {
	_, err := w.persistPlan(ctx, m)
	return err
}

func (w *Worker) persistPlan(ctx context.Context, m runtimestate.CompiledMutation) (runtimestate.TransitionPlan, error) {
	s, e := w.store.LoadRuntimeState(ctx, m.ReceiptBinding().Scope)
	if e != nil {
		return runtimestate.TransitionPlan{}, e
	}
	p, e := w.planner.Plan(ctx, s, m)
	if e != nil {
		return runtimestate.TransitionPlan{}, e
	}
	if e = w.store.PersistTransitionPlan(ctx, p); e != nil {
		return runtimestate.TransitionPlan{}, e
	}
	return p, nil
}
func (w *Worker) transition(ctx context.Context, r runtimestate.OutboxRecord, f func(runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error)) (runtimestate.OutboxRecord, error) {
	s, e := w.store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: r.Tenant, Authority: runtimestate.AuthorityOutboxPublisher})
	if e != nil {
		return runtimestate.OutboxRecord{}, e
	}
	for _, x := range s.Outbox {
		if x.OutboxID == r.OutboxID {
			m, e := f(x)
			if e != nil {
				return runtimestate.OutboxRecord{}, e
			}
			p, e := w.planner.Plan(ctx, s, m)
			if e != nil {
				return runtimestate.OutboxRecord{}, e
			}
			if e = w.store.PersistTransitionPlan(ctx, p); e != nil {
				return runtimestate.OutboxRecord{}, e
			}
			return p.Result().Outbox, nil
		}
	}
	return runtimestate.OutboxRecord{}, runtimestate.ErrNotFoundOrDenied
}
