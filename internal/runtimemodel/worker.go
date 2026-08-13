// Package runtimemodel owns the narrow model-effect worker seam.
package runtimemodel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	"github.com/0x63616c/agent-runtime/internal/toolschema"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

const (
	claimDuration = 2 * time.Minute
	maxAttempts   = 4
)

// Request is the normalized, provider-neutral invocation identity supplied to
// a model adapter. It deliberately contains no provider configuration,
// credential, raw Input, or private database handle.
type Request struct {
	Tenant      runtimecontent.TenantID
	SessionID   agentruntime.SessionID
	TurnID      agentruntime.TurnID
	OperationID runtimestate.OperationID
	// ModelProfile is the immutable Agent-revision selection key. It is a
	// declarative profile name, not a provider model identifier, endpoint, or
	// credential. The model worker resolves it locally through its reviewed
	// profile adapter before it contacts any provider.
	ModelProfile string
	// CreatedAt is the durable invocation creation time. Adapters use it only
	// for deterministic response values that must remain identical during
	// recovery; it is not the current wall clock.
	CreatedAt time.Time
	// Tools is the immutable Agent-revision catalog exposed to the provider for
	// Tool-call construction. It grants no execution authority; the worker
	// validates the provider's canonical Tool request against this catalog before
	// it can reach Broker.
	Tools []agentruntime.ToolDefinition
}

// Response is one normalized model outcome. A successful response is stored
// as immutable runtime content before its state outcome is committed. Failed
// and uncertain responses must contain a caller-safe runtime Failure.
type Response struct {
	Output []byte
	// Tool is one normalized model request awaiting the private broker. It has
	// no grant or sandbox client; the worker stages its descriptor then hands
	// only the sealed reference to Broker.
	Tool      *ToolRequest
	Failure   *agentruntime.Failure
	Uncertain bool
	Usage     *runtimestate.ModelUsage
}

// ToolRequest is the bounded normalized model-to-tool handoff. The provider
// adapter cannot use it to execute an action.
type ToolRequest struct {
	ToolCallID, ApprovalID, PolicyName string
	PolicyRevision                     uint64
	ToolName                           string
	ActionDigest, CapabilityDigest     string
	Action                             agentruntime.ApprovalAction
	MaximumUses                        uint32
	ExpiresAt                          time.Time
	Descriptor                         []byte
	// Arguments are the canonical model-supplied input validated against the
	// immutable Agent tool catalog before Broker admission.
	Arguments []byte
}

// Adapter is the model-provider seam. Invoke is allowed exactly once for a
// newly claimed durable intent. Reconcile receives the same runtime-owned
// operation ID after producer loss and must not execute a second effect.
type Adapter interface {
	Invoke(context.Context, Request) (Response, error)
	Reconcile(context.Context, Request) (Response, error)
}

// WorkerConfig supplies the model worker's narrow authorities. The worker
// owns no Temporal client, public API credential, or tool/sandbox capability.
type WorkerConfig struct {
	Store    runtimestate.RuntimeStateStore
	Tenants  runtimestate.OutboxTenantSource
	Compiler *runtimestate.Compiler
	Planner  *runtimestate.RuntimeStatePlanner
	Clock    clock.Clock
	Content  *runtimecontent.Store
	Adapter  Adapter
	Broker   *runtimetool.Broker
	Claimer  string
}

// Worker processes only durable invocation-intent outbox records.
type Worker struct {
	store    runtimestate.RuntimeStateStore
	tenants  runtimestate.OutboxTenantSource
	compiler *runtimestate.Compiler
	planner  *runtimestate.RuntimeStatePlanner
	clock    clock.Clock
	content  *runtimecontent.Store
	adapter  Adapter
	broker   *runtimetool.Broker
	claimer  string
}

// NewWorker constructs the provider-neutral model worker.
func NewWorker(config WorkerConfig) (*Worker, error) {
	if config.Store == nil || config.Tenants == nil || config.Compiler == nil || config.Planner == nil || config.Clock == nil || config.Content == nil || config.Adapter == nil || config.Claimer == "" {
		return nil, errors.New("create runtime model worker: complete state, content, and adapter authority is required")
	}
	return &Worker{store: config.Store, tenants: config.Tenants, compiler: config.Compiler, planner: config.Planner, clock: config.Clock, content: config.Content, adapter: config.Adapter, broker: config.Broker, claimer: config.Claimer}, nil
}

// ScanOnce processes visible invocation intents. A recovered claimed record is
// reconciled rather than invoked, so process loss cannot cause a blind second
// external model effect.
func (worker *Worker) ScanOnce(ctx context.Context) error {
	if worker == nil {
		return errors.New("scan model invocation outbox: worker is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tenants, err := worker.tenants.ListOutboxTenants(ctx)
	if err != nil {
		return err
	}
	for _, tenant := range tenants {
		if err := worker.scanTenant(ctx, tenant); err != nil {
			return err
		}
	}
	return nil
}

func (worker *Worker) scanTenant(ctx context.Context, tenant runtimecontent.TenantID) error {
	after := runtimestate.OutboxID("")
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := worker.store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, After: after, Limit: 128})
		if err != nil {
			return err
		}
		for _, record := range page.Records {
			if err := ctx.Err(); err != nil {
				return err
			}
			if record.InvocationID == "" || record.EventKind != "" || record.State == runtimestate.OutboxPublished || record.State == runtimestate.OutboxReconcile {
				continue
			}
			if record.State == runtimestate.OutboxClaimed && (record.ClaimUntil == nil || record.ClaimUntil.After(worker.clock.Now())) {
				continue
			}
			recovering := record.State == runtimestate.OutboxClaimed
			claimed, err := worker.claim(ctx, record)
			if err != nil {
				if errors.Is(err, runtimestate.ErrConflict) {
					continue
				}
				return err
			}
			if err := worker.process(ctx, claimed, recovering); err != nil {
				return err
			}
			if err := worker.acknowledge(ctx, claimed); err != nil {
				return err
			}
		}
		if page.Next == "" || page.Next == after {
			return nil
		}
		after = page.Next
	}
}

func (worker *Worker) process(ctx context.Context, record runtimestate.OutboxRecord, recovering bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	state, err := worker.store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: record.Tenant, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil {
		return err
	}
	invocation, session, turn, found := invocationRoute(state, record)
	if !found {
		return runtimestate.ErrNotFoundOrDenied
	}
	if invocation.State != runtimestate.InvocationIntent {
		return nil
	}
	// Read the revision-owned specification before calling the provider. This
	// both makes model selection revision-pinned and prevents an adapter from
	// inferring a profile from prompt content or a mutable public request.
	specification, err := worker.agentSpecification(ctx, record.Tenant, session)
	if err != nil {
		return err
	}
	request := Request{Tenant: record.Tenant, SessionID: record.SessionID, TurnID: record.TurnID, OperationID: record.OperationID, ModelProfile: specification.ModelProfile, CreatedAt: invocation.CreatedAt, Tools: modelToolCatalog(specification.Tools)}
	var response Response
	if recovering {
		response, err = worker.adapter.Reconcile(ctx, request)
	} else {
		response, err = worker.adapter.Invoke(ctx, request)
	}
	if err != nil {
		// A caller-owned cancellation is not provider ambiguity. Leave the
		// claimed record unacknowledged so a later worker reconciles its exact
		// operation ID; do not manufacture a terminal result while shutdown is
		// in progress.
		if cause := ctx.Err(); cause != nil {
			return cause
		}
		response = Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "model invocation outcome is uncertain"}, Uncertain: true}
	}
	if response.Tool != nil {
		if worker.broker == nil {
			return errors.New("admit model tool request: broker is unavailable")
		}
		definition, found := declaredTool(specification.Tools, response.Tool.ToolName)
		if !found {
			return errors.New("admit model tool request: tool is not declared by the Agent revision")
		}
		arguments, validateErr := toolschema.CanonicalArguments(definition.InputSchemaVersion, definition.InputSchema, response.Tool.Arguments)
		if validateErr != nil {
			return fmt.Errorf("admit model tool request: arguments do not match declared input schema: %w", validateErr)
		}
		// The model's canonical arguments must survive approval and recovery with
		// the exact private action they were validated for. Bind them before
		// staging, rather than treating schema validation as a throw-away check.
		boundDescriptor, bindErr := runtimecontent.BindToolActionDescriptor(response.Tool.Descriptor, arguments)
		if bindErr != nil {
			return fmt.Errorf("admit model tool request: bind validated arguments: %w", bindErr)
		}
		handoff, stageErr := worker.content.StageToolActionDescriptor(ctx, record.Tenant, boundDescriptor)
		if stageErr != nil {
			return stageErr
		}
		actionDigest := boundToolDigest(boundDescriptor)
		capabilityDigest := boundCapabilityDigest(response.Tool.CapabilityDigest, actionDigest)
		_, admitErr := worker.broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: record.Tenant, Principal: record.Principal, SessionID: record.SessionID, TurnID: record.TurnID, ToolCallID: response.Tool.ToolCallID, ApprovalID: agentruntime.ApprovalID(response.Tool.ApprovalID), PolicyName: response.Tool.PolicyName, PolicyRevision: response.Tool.PolicyRevision, ToolName: response.Tool.ToolName, ActionDigest: actionDigest, CapabilityDigest: capabilityDigest, Action: response.Tool.Action, MaximumUses: response.Tool.MaximumUses, ExpiresAt: response.Tool.ExpiresAt, Descriptor: handoff, IdempotencyKey: fmt.Sprintf("model-tool-%s-%d", record.OperationID, invocation.Fence)})
		return admitErr
	}
	return worker.finalize(ctx, record, invocation, session, turn, response)
}

func modelToolCatalog(tools []agentruntime.ToolDefinition) []agentruntime.ToolDefinition {
	clone := append([]agentruntime.ToolDefinition(nil), tools...)
	for index := range clone {
		clone[index].InputSchema = append([]byte(nil), clone[index].InputSchema...)
	}
	return clone
}

func boundToolDigest(descriptor []byte) string {
	sum := sha256.Sum256(descriptor)
	return fmt.Sprintf("sha256:%x", sum)
}

// boundCapabilityDigest prevents a grant issued for one private action and
// validated input from being reused for a different sealed descriptor.
func boundCapabilityDigest(providerDigest, actionDigest string) string {
	encoded, err := json.Marshal(struct {
		Version        string `json:"version"`
		ProviderDigest string `json:"provider_digest"`
		ActionDigest   string `json:"action_digest"`
	}{Version: "agent-runtime.tool-capability/v1", ProviderDigest: providerDigest, ActionDigest: actionDigest})
	if err != nil {
		panic("canonical bound tool capability")
	}
	return boundToolDigest(encoded)
}

func (worker *Worker) agentSpecification(ctx context.Context, tenant runtimecontent.TenantID, session runtimestate.SessionRecord) (agentruntime.AgentSpecification, error) {
	authorization, err := worker.compiler.CompileAuthorizeAgentSpecificationBodyRead(runtimestate.AgentSpecificationBodyReadCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityRuntimeWorker}, AgentID: session.AgentID, RevisionID: session.RevisionID})
	if err != nil {
		return agentruntime.AgentSpecification{}, fmt.Errorf("authorize Agent tool catalog: %w", err)
	}
	record, err := worker.store.AuthorizeAgentSpecificationBodyRead(ctx, authorization)
	if err != nil {
		return agentruntime.AgentSpecification{}, fmt.Errorf("read Agent tool catalog: %w", err)
	}
	reader, err := runtimecontent.NewAgentSpecificationBodyReader(worker.content, runtimeSpecificationRepository{record: record})
	if err != nil {
		return agentruntime.AgentSpecification{}, err
	}
	return reader.ReadAgentSpecification(ctx, tenant, session.AgentID, session.RevisionID)
}

type runtimeSpecificationRepository struct {
	record runtimecontent.AgentSpecificationBodyRecord
}

func (repository runtimeSpecificationRepository) AuthorizeAgentSpecificationBodyRead(_ context.Context, tenant runtimecontent.TenantID, agentID agentruntime.AgentID, revisionID agentruntime.AgentRevisionID) (runtimecontent.AgentSpecificationBodyRecord, error) {
	if repository.record.Tenant != tenant || repository.record.AgentID != agentID || repository.record.RevisionID != revisionID {
		return runtimecontent.AgentSpecificationBodyRecord{}, runtimecontent.ErrNotFoundOrDenied
	}
	return repository.record, nil
}

func declaredTool(tools []agentruntime.ToolDefinition, name string) (agentruntime.ToolDefinition, bool) {
	for _, tool := range tools {
		if tool.Name == name {
			return tool, true
		}
	}
	return agentruntime.ToolDefinition{}, false
}

func (worker *Worker) finalize(ctx context.Context, record runtimestate.OutboxRecord, invocation runtimestate.InvocationRecord, session runtimestate.SessionRecord, turn runtimestate.TurnRecord, response Response) error {
	state := runtimestate.InvocationFailed
	failure := response.Failure.Clone()
	var result *runtimecontent.Reference
	if response.Uncertain {
		state = runtimestate.InvocationUncertain
	}
	if len(response.Output) > 0 && failure == nil && !response.Uncertain {
		// A normalized provider stream is only public after its bounded final
		// bytes have been committed as an owner-authorized Artifact. This keeps
		// reconnecting callers on the durable StateRuntime/HTTP/SDK path rather
		// than on a live provider connection.
		handoff, err := worker.content.StageArtifact(ctx, record.Tenant, "text/plain; charset=utf-8", response.Output)
		if err == nil {
			artifact, compileErr := worker.compiler.CompileRegisterArtifact(runtimestate.RegisterArtifactCommand{
				Scope:          runtimestate.MutationScope{Tenant: record.Tenant, Principal: record.Principal, Authority: runtimestate.AuthorityRuntimeWorker},
				IdempotencyKey: fmt.Sprintf("model-output-%s-%d", record.OperationID, invocation.Fence),
				SessionID:      record.SessionID,
				TurnID:         record.TurnID,
				Artifact:       handoff,
			})
			if compileErr != nil {
				err = compileErr
			} else if artifactPlan, persistErr := worker.persist(ctx, artifact); persistErr != nil {
				err = persistErr
			} else {
				value := artifactPlan.Result().Artifact.Reference
				result, state = &value, runtimestate.InvocationSucceeded
			}
		}
		if err != nil {
			state = runtimestate.InvocationUncertain
			failure = &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "model output could not be durably finalized"}
		}
	}
	if failure == nil && state != runtimestate.InvocationSucceeded {
		state = runtimestate.InvocationUncertain
		failure = &agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "model invocation returned no terminal outcome"}
	}
	outcome, err := worker.compiler.CompileRecordInvocationOutcome(runtimestate.RecordInvocationOutcomeCommand{
		Scope:                  runtimestate.MutationScope{Tenant: record.Tenant, Principal: record.Principal, Authority: runtimestate.AuthorityRuntimeWorker},
		IdempotencyKey:         fmt.Sprintf("model-outcome-%s-%d", record.OperationID, invocation.Fence),
		SessionID:              record.SessionID,
		TurnID:                 record.TurnID,
		OperationID:            record.OperationID,
		Ordinal:                invocation.Ordinal,
		Fence:                  invocation.Fence,
		Outcome:                state,
		Result:                 result,
		Failure:                failure,
		Usage:                  response.Usage,
		ExpectedSessionVersion: session.Version,
		ExpectedTurnVersion:    turn.Version,
	})
	if err != nil {
		return err
	}
	plan, err := worker.persist(ctx, outcome)
	if err != nil {
		return err
	}
	_, settledSession, settledTurn, found := invocationRoute(plan.State(), record)
	if !found {
		return runtimestate.ErrIntegrity
	}
	terminal := agentruntime.TurnSucceeded
	if state != runtimestate.InvocationSucceeded {
		terminal = agentruntime.TurnFailed
	}
	settle, err := worker.compiler.CompileSettleTurn(runtimestate.SettleTurnCommand{
		Scope:                  runtimestate.MutationScope{Tenant: record.Tenant, Principal: record.Principal, Authority: runtimestate.AuthorityRuntimeWorker},
		IdempotencyKey:         fmt.Sprintf("model-settle-%s-%d", record.OperationID, invocation.Fence),
		SessionID:              record.SessionID,
		TurnID:                 record.TurnID,
		ExpectedSessionVersion: settledSession.Version,
		ExpectedTurnVersion:    settledTurn.Version,
		Outcome:                runtimestate.TerminalOutcome{OperationID: record.OperationID, Ordinal: invocation.Ordinal, Fence: invocation.Fence, State: terminal, Failure: failure},
	})
	if err != nil {
		return err
	}
	_, err = worker.persist(ctx, settle)
	return err
}

func (worker *Worker) persist(ctx context.Context, mutation runtimestate.CompiledMutation) (runtimestate.TransitionPlan, error) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		state, err := worker.store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
		if err != nil {
			return runtimestate.TransitionPlan{}, err
		}
		plan, err := worker.planner.Plan(ctx, state, mutation)
		if err != nil {
			return runtimestate.TransitionPlan{}, err
		}
		if err := worker.store.PersistTransitionPlan(ctx, plan); err != nil {
			if errors.Is(err, runtimestate.ErrConflict) {
				continue
			}
			return runtimestate.TransitionPlan{}, err
		}
		return plan, nil
	}
	return runtimestate.TransitionPlan{}, runtimestate.ErrConflict
}

func (worker *Worker) claim(ctx context.Context, record runtimestate.OutboxRecord) (runtimestate.OutboxRecord, error) {
	return worker.apply(ctx, record, func(current runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error) {
		return worker.compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: record.Tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: fmt.Sprintf("model-claim-%s-%d", record.OutboxID, current.Version), OutboxID: record.OutboxID, ExpectedVersion: current.Version, Claimer: worker.claimer, ClaimUntil: worker.clock.Now().Add(claimDuration)})
	})
}

func (worker *Worker) acknowledge(ctx context.Context, record runtimestate.OutboxRecord) error {
	_, err := worker.apply(ctx, record, func(current runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error) {
		return worker.compiler.CompileAcknowledgeOutbox(runtimestate.AcknowledgeOutboxCommand{Scope: runtimestate.MutationScope{Tenant: record.Tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: fmt.Sprintf("model-ack-%s-%d", record.OutboxID, current.Version), OutboxID: record.OutboxID, ExpectedVersion: current.Version, Claimer: worker.claimer, PublishedAt: worker.clock.Now()})
	})
	return err
}

func (worker *Worker) apply(ctx context.Context, target runtimestate.OutboxRecord, compile func(runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error)) (runtimestate.OutboxRecord, error) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		state, err := worker.store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: target.Tenant, Authority: runtimestate.AuthorityOutboxPublisher})
		if err != nil {
			return runtimestate.OutboxRecord{}, err
		}
		var current runtimestate.OutboxRecord
		found := false
		for _, record := range state.Outbox {
			if record.OutboxID == target.OutboxID {
				current, found = record, true
				break
			}
		}
		if !found {
			return runtimestate.OutboxRecord{}, runtimestate.ErrNotFoundOrDenied
		}
		mutation, err := compile(current)
		if err != nil {
			return runtimestate.OutboxRecord{}, err
		}
		plan, err := worker.planner.Plan(ctx, state, mutation)
		if err != nil {
			return runtimestate.OutboxRecord{}, err
		}
		if err := worker.store.PersistTransitionPlan(ctx, plan); err != nil {
			if errors.Is(err, runtimestate.ErrConflict) {
				continue
			}
			return runtimestate.OutboxRecord{}, err
		}
		return plan.Result().Outbox, nil
	}
	return runtimestate.OutboxRecord{}, runtimestate.ErrConflict
}

func invocationRoute(state runtimestate.RuntimeState, record runtimestate.OutboxRecord) (runtimestate.InvocationRecord, runtimestate.SessionRecord, runtimestate.TurnRecord, bool) {
	var invocation runtimestate.InvocationRecord
	for _, candidate := range state.Invocations {
		if candidate.InvocationID == record.InvocationID && candidate.OperationID == record.OperationID && candidate.SessionID == record.SessionID && candidate.TurnID == record.TurnID {
			invocation = candidate
			break
		}
	}
	if invocation.InvocationID == "" {
		return runtimestate.InvocationRecord{}, runtimestate.SessionRecord{}, runtimestate.TurnRecord{}, false
	}
	var session runtimestate.SessionRecord
	for _, candidate := range state.Sessions {
		if candidate.SessionID == record.SessionID {
			session = candidate
			break
		}
	}
	var turn runtimestate.TurnRecord
	for _, candidate := range state.Turns {
		if candidate.TurnID == record.TurnID {
			turn = candidate
			break
		}
	}
	return invocation, session, turn, session.SessionID != "" && turn.TurnID != ""
}
