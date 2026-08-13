// Package runtimetool owns capability-bound external tool execution.
package runtimetool

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	facebookclock "github.com/facebookgo/clock"
)

const maximumRetainedToolOutputBytes = 8 << 20

// toolOutboxLease bounds restart recovery after the worker has recorded an
// external-effect intent. A new claimer must reconcile the same OperationID,
// never resubmit it, once this short lease expires.
const toolOutboxLease = 10 * time.Second

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
	// Arguments are the exact canonical model input sealed with Descriptor at
	// admission. They are private to the authorized adapter dispatch path.
	Arguments []byte
	dispatch  *dispatchCapability
}

// dispatchCapability is created only by Worker after it has loaded the
// durable execution intent and read the descriptor through the state-owned
// authorization path. Keeping it private prevents a direct adapter caller
// from turning a model descriptor into an external effect.
type dispatchCapability struct{}

func dispatchAuthorized(request Request) bool { return request.dispatch != nil }

func refusedDirectDispatch() Response {
	return Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: "tool adapter execution requires broker dispatch"}}
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
	// LeaseRenewalInterval bounds how long a healthy worker may wait before
	// extending its exact outbox claim. Zero uses half the fixed recovery lease.
	LeaseRenewalInterval time.Duration
	// LeaseScheduler drives claim-renewal checks and is required at the
	// composition root; deterministic tests can inject explicit ticks.
	LeaseScheduler LeaseScheduler
}

// LeaseTicker delivers recurring renewal opportunities for one owned claim.
type LeaseTicker interface {
	// C returns the renewal channel.
	C() <-chan time.Time
	// Stop releases the ticker after the claim is terminal or lost.
	Stop()
	// Handled records that the owning worker consumed a tick.
	Handled()
}

// LeaseScheduler constructs managed renewal tickers for active claims.
type LeaseScheduler interface {
	// NewLeaseTicker returns one ticker for the supplied positive interval.
	NewLeaseTicker(time.Duration) LeaseTicker
}

type realtimeLeaseScheduler struct{ clock facebookclock.Clock }
type realtimeLeaseTicker struct{ ticker *facebookclock.Ticker }

// NewRealtimeLeaseScheduler returns the production scheduler for injection at
// an application composition root.
func NewRealtimeLeaseScheduler() LeaseScheduler {
	return realtimeLeaseScheduler{clock: facebookclock.New()}
}

func (scheduler realtimeLeaseScheduler) NewLeaseTicker(interval time.Duration) LeaseTicker {
	return realtimeLeaseTicker{ticker: scheduler.clock.Ticker(interval)}
}
func (ticker realtimeLeaseTicker) C() <-chan time.Time { return ticker.ticker.C }
func (ticker realtimeLeaseTicker) Stop()               { ticker.ticker.Stop() }
func (realtimeLeaseTicker) Handled()                   {}

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
	dispatch         *dispatchCapability
	renewalInterval  time.Duration
	scheduler        LeaseScheduler
}

func NewWorker(c Config) (*Worker, error) {
	if c.Store == nil || c.Tenants == nil || c.Compiler == nil || c.Planner == nil || c.Clock == nil || c.Content == nil || c.Adapter == nil || c.Claimer == "" || c.LeaseScheduler == nil || c.LeaseRenewalInterval < 0 || c.LeaseRenewalInterval >= toolOutboxLease {
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
	interval := c.LeaseRenewalInterval
	if interval == 0 {
		interval = toolOutboxLease / 2
	}
	return &Worker{store: c.Store, tenants: c.Tenants, compiler: c.Compiler, planner: c.Planner, clock: c.Clock, content: c.Content, descriptorReader: reader, adapter: c.Adapter, claimer: c.Claimer, dispatch: &dispatchCapability{}, renewalInterval: interval, scheduler: c.LeaseScheduler}, nil
}

// toolClaimLease owns the exact durable claim from acquisition through
// descriptor read, external execution, finalization, and acknowledgement.
// Renewal continues during finalization; every renewal and acknowledgement
// binds the originally held durable version and claimer before it can mutate
// state. A lost fence cancels a cooperative adapter and prevents this worker
// from recording a terminal outcome.
type toolClaimLease struct {
	worker *Worker
	ctx    context.Context
	cancel context.CancelFunc
	stop   chan struct{}
	done   chan struct{}

	mu     sync.RWMutex
	record runtimestate.OutboxRecord
	err    error
	once   sync.Once
}

func (w *Worker) startClaimLease(ctx context.Context, record runtimestate.OutboxRecord) *toolClaimLease {
	executionContext, cancel := context.WithCancel(ctx)
	lease := &toolClaimLease{worker: w, ctx: executionContext, cancel: cancel, stop: make(chan struct{}), done: make(chan struct{}), record: record.Clone()}
	go lease.renewLoop(ctx)
	return lease
}

func (lease *toolClaimLease) renewLoop(parent context.Context) {
	ticker := lease.worker.scheduler.NewLeaseTicker(lease.worker.renewalInterval)
	defer ticker.Stop()
	defer close(lease.done)
	for {
		select {
		case <-parent.Done():
			lease.setError(parent.Err())
			return
		case <-lease.stop:
			return
		case <-ticker.C():
			err := lease.renew(parent)
			ticker.Handled()
			if err != nil {
				lease.setError(fmt.Errorf("renew tool outbox lease %s: %w", lease.outboxID(), err))
				return
			}
		}
	}
}

func (lease *toolClaimLease) renew(ctx context.Context) error {
	lease.mu.RLock()
	record := lease.record.Clone()
	lease.mu.RUnlock()
	if record.ClaimUntil == nil || !lease.worker.clock.Now().Add(toolOutboxLease).After(*record.ClaimUntil) {
		return nil
	}
	renewed, err := lease.worker.renew(ctx, record)
	if err != nil {
		return err
	}
	lease.mu.Lock()
	lease.record = renewed
	lease.mu.Unlock()
	return nil
}

func (lease *toolClaimLease) setError(err error) {
	lease.mu.Lock()
	if lease.err == nil {
		lease.err = err
		lease.cancel()
	}
	lease.mu.Unlock()
}

func (lease *toolClaimLease) error() error {
	lease.mu.RLock()
	defer lease.mu.RUnlock()
	return lease.err
}

func (lease *toolClaimLease) outboxID() runtimestate.OutboxID {
	lease.mu.RLock()
	defer lease.mu.RUnlock()
	return lease.record.OutboxID
}

func (lease *toolClaimLease) leaseFence() *runtimestate.OutboxLeaseFence {
	lease.mu.RLock()
	defer lease.mu.RUnlock()
	return &runtimestate.OutboxLeaseFence{OutboxID: lease.record.OutboxID, ExpectedVersion: lease.record.Version, Claimer: lease.record.ClaimedBy}
}

func (lease *toolClaimLease) recordTenant() runtimecontent.TenantID {
	lease.mu.RLock()
	defer lease.mu.RUnlock()
	return lease.record.Tenant
}

// persistFenced retries only benign whole-state snapshot conflicts. Each retry
// reloads the current held lease and lets the planner atomically reject expiry,
// replacement, or a competing claimant before committing a terminal effect.
func (lease *toolClaimLease) persistFenced(ctx context.Context, compile func(*runtimestate.OutboxLeaseFence) (runtimestate.CompiledMutation, error)) (runtimestate.TransitionPlan, error) {
	for attempt := 0; attempt < 8; attempt++ {
		if err := lease.error(); err != nil {
			return runtimestate.TransitionPlan{}, err
		}
		mutation, err := compile(lease.leaseFence())
		if err != nil {
			return runtimestate.TransitionPlan{}, err
		}
		plan, err := lease.worker.persistPlan(ctx, mutation)
		if err == nil {
			return plan, nil
		}
		if !errors.Is(err, runtimestate.ErrConflict) {
			return runtimestate.TransitionPlan{}, err
		}
		// A successful renewal publishes its durable transition before it can
		// publish the newer in-memory record. Retry once through that small
		// handoff instead of mistaking our own newer exact claim for a loss.
		if !lease.worker.heldClaimCurrent(ctx, lease.recordTenant(), lease.leaseFence()) {
			if err := lease.error(); err != nil {
				return runtimestate.TransitionPlan{}, err
			}
			continue
		}
	}
	return runtimestate.TransitionPlan{}, fmt.Errorf("persist fenced tool outbox %s: %w", lease.outboxID(), runtimestate.ErrConflict)
}

func (lease *toolClaimLease) finish() error {
	lease.once.Do(func() {
		close(lease.stop)
		<-lease.done
		lease.cancel()
	})
	return lease.error()
}

func (lease *toolClaimLease) acknowledge(ctx context.Context) error {
	if err := lease.finish(); err != nil {
		return err
	}
	lease.mu.RLock()
	record := lease.record.Clone()
	lease.mu.RUnlock()
	if record.ClaimUntil == nil || !record.ClaimUntil.After(lease.worker.clock.Now()) {
		return runtimestate.ErrConflict
	}
	return lease.worker.ack(ctx, record)
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
		// A busy durable tenant can retain far more than one page of already
		// published state transitions.  Continue from the stable outbox cursor so
		// a later pending tool operation cannot be starved behind those records.
		for after := runtimestate.OutboxID(""); ; {
			p, e := w.store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: t, Authority: runtimestate.AuthorityOutboxPublisher}, After: after, Limit: 128})
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
				lease := w.startClaimLease(ctx, claimed)
				if e = w.process(lease.ctx, claimed, recovering, lease); e != nil {
					_ = lease.finish()
					return e
				}
				if e = lease.acknowledge(ctx); e != nil {
					return e
				}
			}
			if len(p.Records) < 128 || p.Next == "" {
				break
			}
			after = p.Next
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
func (w *Worker) process(ctx context.Context, r runtimestate.OutboxRecord, recover bool, lease *toolClaimLease) error {
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
		return w.recordDispatchRefusal(ctx, r, lease)
	}
	boundDescriptor, err := w.descriptorReader.ReadToolActionDescriptor(ctx, r.Tenant, r.Principal, r.SessionID, r.TurnID, r.ToolCallID)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, runtimecontent.ErrUnavailable) {
			return err
		}
		return w.recordDescriptorFailure(ctx, r, lease)
	}
	descriptor, arguments, err := runtimecontent.UnbindToolActionDescriptor(boundDescriptor)
	if err != nil {
		return w.recordDescriptorFailure(ctx, r, lease)
	}
	q := Request{Tenant: r.Tenant, SessionID: r.SessionID, TurnID: r.TurnID, ToolCallID: r.ToolCallID, OperationID: r.OperationID, Descriptor: descriptor, Arguments: arguments, dispatch: w.dispatch}
	var out Response
	if recover {
		out, e = w.adapter.Reconcile(ctx, q)
	} else {
		out, e = w.adapter.Execute(ctx, q)
	}
	if e != nil {
		out = Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "tool operation outcome is uncertain"}, Uncertain: true}
	}
	if err := lease.error(); err != nil {
		return err
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
			plan, persistErr := lease.persistFenced(ctx, func(fence *runtimestate.OutboxLeaseFence) (runtimestate.CompiledMutation, error) {
				return w.compiler.CompileRegisterArtifact(runtimestate.RegisterArtifactCommand{Scope: runtimestate.MutationScope{Tenant: r.Tenant, Principal: r.Principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "tool-output-" + string(r.OperationID), SessionID: r.SessionID, TurnID: r.TurnID, Artifact: h, LeaseFence: fence})
			})
			if persistErr == nil {
				v := plan.Result().Artifact.Reference
				result = &v
				state = runtimestate.ToolExecutionSucceeded
			} else {
				err = persistErr
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
	return w.recordToolOutcomeAndSettle(ctx, r, lease, state, result, failure)
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

func (w *Worker) recordDispatchRefusal(ctx context.Context, r runtimestate.OutboxRecord, lease *toolClaimLease) error {
	failure := &agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: "tool execution is no longer authorized"}
	return w.recordToolOutcomeAndSettle(ctx, r, lease, runtimestate.ToolExecutionFailed, nil, failure)
}

func (w *Worker) recordDescriptorFailure(ctx context.Context, r runtimestate.OutboxRecord, lease *toolClaimLease) error {
	failure := &agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: "verified tool action descriptor is invalid"}
	return w.recordToolOutcomeAndSettle(ctx, r, lease, runtimestate.ToolExecutionFailed, nil, failure)
}

// recordToolOutcomeAndSettle advances the same durable Turn after the
// capability-bound Tool has reached a terminal outcome. Without this second
// runtime-owned transition, a completed Tool would leave ordered public Input
// stuck behind a running Turn forever.
func (w *Worker) recordToolOutcomeAndSettle(ctx context.Context, record runtimestate.OutboxRecord, lease *toolClaimLease, executionState runtimestate.ToolExecutionState, result *runtimecontent.Reference, failure *agentruntime.Failure) error {
	plan, err := lease.persistFenced(ctx, func(fence *runtimestate.OutboxLeaseFence) (runtimestate.CompiledMutation, error) {
		return w.compiler.CompileRecordToolExecutionOutcome(runtimestate.RecordToolExecutionOutcomeCommand{Scope: runtimestate.MutationScope{Tenant: record.Tenant, Principal: record.Principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "tool-outcome-" + string(record.OperationID), SessionID: record.SessionID, TurnID: record.TurnID, ToolCallID: record.ToolCallID, OperationID: record.OperationID, Outcome: executionState, Result: result, Failure: failure, LeaseFence: fence})
	})
	if err != nil {
		return err
	}
	var session runtimestate.SessionRecord
	var turn runtimestate.TurnRecord
	for _, candidate := range plan.State().Sessions {
		if candidate.Tenant == record.Tenant && candidate.Principal == record.Principal && candidate.SessionID == record.SessionID {
			session = candidate
			break
		}
	}
	for _, candidate := range plan.State().Turns {
		if candidate.Tenant == record.Tenant && candidate.Principal == record.Principal && candidate.SessionID == record.SessionID && candidate.TurnID == record.TurnID {
			turn = candidate
			break
		}
	}
	if session.SessionID == "" || turn.TurnID == "" {
		return runtimestate.ErrIntegrity
	}
	if turn.State != agentruntime.TurnRunning {
		// A concurrent owner cancellation is already terminal and authoritative.
		// The Tool outcome remains auditable, but must not overwrite it.
		return nil
	}
	state := agentruntime.TurnFailed
	if executionState == runtimestate.ToolExecutionSucceeded {
		state = agentruntime.TurnSucceeded
		failure = nil
	}
	_, err = lease.persistFenced(ctx, func(fence *runtimestate.OutboxLeaseFence) (runtimestate.CompiledMutation, error) {
		return w.compiler.CompileSettleTurn(runtimestate.SettleTurnCommand{Scope: runtimestate.MutationScope{Tenant: record.Tenant, Principal: record.Principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "tool-settle-" + string(record.OperationID), SessionID: record.SessionID, TurnID: record.TurnID, ExpectedSessionVersion: session.Version, ExpectedTurnVersion: turn.Version, Outcome: runtimestate.TerminalOutcome{State: state, Failure: failure}, LeaseFence: fence})
	})
	return err
}
func (w *Worker) claim(ctx context.Context, r runtimestate.OutboxRecord) (runtimestate.OutboxRecord, error) {
	return w.transition(ctx, r, func(x runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error) {
		return w.compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: r.Tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: fmt.Sprintf("tool-claim-%s-%d", r.OutboxID, x.Version), OutboxID: r.OutboxID, ExpectedVersion: x.Version, Claimer: w.claimer, ClaimUntil: w.clock.Now().Add(toolOutboxLease)})
	})
}
func (w *Worker) renew(ctx context.Context, r runtimestate.OutboxRecord) (runtimestate.OutboxRecord, error) {
	return w.transitionExact(ctx, r, func(runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error) {
		return w.compiler.CompileRenewOutbox(runtimestate.RenewOutboxCommand{Scope: runtimestate.MutationScope{Tenant: r.Tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: fmt.Sprintf("tool-renew-%s-%d", r.OutboxID, r.Version), OutboxID: r.OutboxID, ExpectedVersion: r.Version, Claimer: w.claimer, ClaimUntil: w.clock.Now().Add(toolOutboxLease)})
	})
}
func (w *Worker) ack(ctx context.Context, r runtimestate.OutboxRecord) error {
	_, e := w.transitionExact(ctx, r, func(runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error) {
		return w.compiler.CompileAcknowledgeOutbox(runtimestate.AcknowledgeOutboxCommand{Scope: runtimestate.MutationScope{Tenant: r.Tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: fmt.Sprintf("tool-ack-%s-%d", r.OutboxID, r.Version), OutboxID: r.OutboxID, ExpectedVersion: r.Version, Claimer: w.claimer, PublishedAt: w.clock.Now()})
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

// transitionExact applies an owned-lease transition only when the currently
// loaded durable record is still the exact version and owner held by this
// worker. It deliberately never substitutes a newer reclaimed record.
func (w *Worker) transitionExact(ctx context.Context, held runtimestate.OutboxRecord, f func(runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error)) (runtimestate.OutboxRecord, error) {
	for attempt := 0; attempt < 8; attempt++ {
		s, err := w.store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: held.Tenant, Authority: runtimestate.AuthorityOutboxPublisher})
		if err != nil {
			return runtimestate.OutboxRecord{}, err
		}
		found := false
		for _, current := range s.Outbox {
			if current.OutboxID != held.OutboxID {
				continue
			}
			found = true
			if current.Version != held.Version || current.State != runtimestate.OutboxClaimed || current.ClaimedBy != held.ClaimedBy || current.ClaimedBy != w.claimer {
				return runtimestate.OutboxRecord{}, runtimestate.ErrConflict
			}
			mutation, err := f(held)
			if err != nil {
				return runtimestate.OutboxRecord{}, err
			}
			plan, err := w.planner.Plan(ctx, s, mutation)
			if err != nil {
				return runtimestate.OutboxRecord{}, err
			}
			if err := w.store.PersistTransitionPlan(ctx, plan); err != nil {
				if errors.Is(err, runtimestate.ErrConflict) {
					break
				}
				return runtimestate.OutboxRecord{}, err
			}
			return plan.Result().Outbox, nil
		}
		if !found {
			return runtimestate.OutboxRecord{}, runtimestate.ErrNotFoundOrDenied
		}
	}
	return runtimestate.OutboxRecord{}, fmt.Errorf("persist exact tool outbox %s: %w", held.OutboxID, runtimestate.ErrConflict)
}

func (w *Worker) heldClaimCurrent(ctx context.Context, tenant runtimecontent.TenantID, fence *runtimestate.OutboxLeaseFence) bool {
	state, err := w.store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher})
	if err != nil {
		return false
	}
	for _, record := range state.Outbox {
		if record.OutboxID == fence.OutboxID {
			return record.Version == fence.ExpectedVersion && record.State == runtimestate.OutboxClaimed && record.ClaimedBy == fence.Claimer && record.ClaimUntil != nil && record.ClaimUntil.After(w.clock.Now())
		}
	}
	return false
}
