package runtimeapi

import (
	"context"
	"sort"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

// StateRuntimeConfig supplies the complete metadata/content authority required
// by the state-backed public runtime.
type StateRuntimeConfig struct {
	Content  *runtimecontent.Store
	Compiler *runtimestate.Compiler
	Planner  *runtimestate.RuntimeStatePlanner
	Store    runtimestate.RuntimeStateStore
	// ModelProfiles is the explicit allow-list for public Agent specifications.
	ModelProfiles []string
}

// StateRuntime is the application seam that will route every public operation
// through content staging, compiler, planner, and state persistence.
type StateRuntime struct {
	content  *runtimecontent.Store
	compiler *runtimestate.Compiler
	planner  *runtimestate.RuntimeStatePlanner
	store    runtimestate.RuntimeStateStore
	profiles map[string]struct{}
}

// NewStateRuntime validates the non-fallback durable runtime composition.
func NewStateRuntime(config StateRuntimeConfig) (*StateRuntime, error) {
	if config.Content == nil || config.Compiler == nil || config.Planner == nil || config.Store == nil {
		return nil, errors.New("create state runtime: content, compiler, planner, and state store are required")
	}
	profiles := make(map[string]struct{}, len(config.ModelProfiles))
	for _, profile := range config.ModelProfiles {
		if profile == "" || len(profile) > 128 {
			return nil, errors.New("create state runtime: model profile is invalid")
		}
		profiles[profile] = struct{}{}
	}
	if len(profiles) == 0 {
		return nil, errors.New("create state runtime: at least one model profile is required")
	}
	return &StateRuntime{content: config.Content, compiler: config.Compiler, planner: config.Planner, store: config.Store, profiles: profiles}, nil
}

var _ Runtime = (*StateRuntime)(nil)

// CreateAgent stages the immutable specification body before atomically registering its metadata revision.
func (runtime *StateRuntime) CreateAgent(ctx context.Context, identity Identity, request agentruntime.CreateAgentRequest) (agentruntime.AgentSpecification, error) {
	scope, err := administratorScope(identity)
	if err != nil {
		return agentruntime.AgentSpecification{}, err
	}
	if err := runtime.validateProfile(request.ModelProfile); err != nil {
		return agentruntime.AgentSpecification{}, err
	}
	handoff, err := runtime.content.StageAgentSpecificationBody(ctx, scope.Tenant, runtimecontent.AgentSpecificationBody{Name: request.Name, ModelProfile: request.ModelProfile, Instructions: request.Instructions, Tools: append([]agentruntime.ToolDefinition(nil), request.Tools...)})
	if err != nil {
		return agentruntime.AgentSpecification{}, stageFailure(err)
	}
	plan, err := runtime.apply(ctx, scope, func() (runtimestate.CompiledMutation, error) {
		return runtime.compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: scope, IdempotencyKey: request.IdempotencyKey, Specification: handoff})
	})
	if err != nil {
		return agentruntime.AgentSpecification{}, runtimeFailure("create Agent", err)
	}
	return runtime.readAgentSpecification(ctx, scope.Tenant, plan.Result().Revision.AgentID, plan.Result().Revision.RevisionID)
}

// ReviseAgent stages a replacement immutable body and records the next revision under optimistic concurrency.
func (runtime *StateRuntime) ReviseAgent(ctx context.Context, identity Identity, request agentruntime.ReviseAgentRequest) (agentruntime.AgentSpecification, error) {
	scope, err := administratorScope(identity)
	if err != nil {
		return agentruntime.AgentSpecification{}, err
	}
	if err := runtime.validateProfile(request.ModelProfile); err != nil {
		return agentruntime.AgentSpecification{}, err
	}
	state, err := runtime.store.LoadRuntimeState(ctx, scope)
	if err != nil {
		return agentruntime.AgentSpecification{}, runtimeFailure("load Agent revision", err)
	}
	latest, found := latestRevision(state, scope.Tenant, request.AgentID)
	if !found {
		return agentruntime.AgentSpecification{}, runtimeFailure("revise Agent", runtimestate.ErrNotFoundOrDenied)
	}
	handoff, err := runtime.content.StageAgentSpecificationBody(ctx, scope.Tenant, runtimecontent.AgentSpecificationBody{Name: latest.Name, ModelProfile: request.ModelProfile, Instructions: request.Instructions, Tools: append([]agentruntime.ToolDefinition(nil), request.Tools...)})
	if err != nil {
		return agentruntime.AgentSpecification{}, stageFailure(err)
	}
	plan, err := runtime.apply(ctx, scope, func() (runtimestate.CompiledMutation, error) {
		return runtime.compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: scope, IdempotencyKey: request.IdempotencyKey, AgentID: request.AgentID, ExpectedRevision: latest.Revision, Specification: handoff})
	})
	if err != nil {
		return agentruntime.AgentSpecification{}, runtimeFailure("revise Agent", err)
	}
	result := plan.Result().Revision
	return runtime.readAgentSpecification(ctx, scope.Tenant, result.AgentID, result.RevisionID)
}

// GetAgentRevision reads one immutable Agent revision through the state-authorized content reader.
func (runtime *StateRuntime) GetAgentRevision(ctx context.Context, identity Identity, agentID agentruntime.AgentID, revisionID agentruntime.AgentRevisionID) (agentruntime.AgentSpecification, error) {
	scope, err := administratorScope(identity)
	if err != nil {
		return agentruntime.AgentSpecification{}, err
	}
	return runtime.readAgentSpecification(ctx, scope.Tenant, agentID, revisionID)
}

// CreatePolicy creates the first immutable revision of a named tenant policy.
func (runtime *StateRuntime) CreatePolicy(ctx context.Context, identity Identity, request agentruntime.CreatePolicyRequest) (agentruntime.Policy, error) {
	scope, err := administratorScope(identity)
	if err != nil {
		return agentruntime.Policy{}, err
	}
	plan, err := runtime.apply(ctx, scope, func() (runtimestate.CompiledMutation, error) {
		return runtime.compiler.CompileRegisterPolicyRevision(runtimestate.RegisterPolicyRevisionCommand{Scope: scope, IdempotencyKey: request.IdempotencyKey, Name: request.Name, Rules: request.Rules})
	})
	if err != nil {
		return agentruntime.Policy{}, runtimeFailure("create Policy", err)
	}
	return publicPolicy(plan.Result().Policy), nil
}

// RevisePolicy creates the next immutable revision of a named tenant policy.
func (runtime *StateRuntime) RevisePolicy(ctx context.Context, identity Identity, request agentruntime.RevisePolicyRequest) (agentruntime.Policy, error) {
	scope, err := administratorScope(identity)
	if err != nil {
		return agentruntime.Policy{}, err
	}
	plan, err := runtime.apply(ctx, scope, func() (runtimestate.CompiledMutation, error) {
		return runtime.compiler.CompileRegisterPolicyRevision(runtimestate.RegisterPolicyRevisionCommand{Scope: scope, IdempotencyKey: request.IdempotencyKey, Name: request.Name, ExpectedRevision: request.ExpectedRevision, Rules: request.Rules})
	})
	if err != nil {
		return agentruntime.Policy{}, runtimeFailure("revise Policy", err)
	}
	return publicPolicy(plan.Result().Policy), nil
}

// GetPolicy reads one immutable policy revision through the administrator surface.
func (runtime *StateRuntime) GetPolicy(ctx context.Context, identity Identity, name string, revision uint64) (agentruntime.Policy, error) {
	scope, err := administratorScope(identity)
	if err != nil {
		return agentruntime.Policy{}, err
	}
	record, err := runtime.store.GetPolicyRevision(ctx, runtimestate.PolicyRevisionQuery{Scope: scope, Name: name, Revision: revision})
	if err != nil {
		return agentruntime.Policy{}, runtimeFailure("read Policy", err)
	}
	return publicPolicy(record), nil
}

// ReadArtifact returns one principal-authorized immutable artifact through the
// state-authorized runtime-content reader.  Blob storage is never addressed by
// a public ID alone.
func (runtime *StateRuntime) ReadArtifact(ctx context.Context, identity Identity, artifactID agentruntime.ArtifactID) (agentruntime.ArtifactDownload, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.ArtifactDownload{}, err
	}
	record, err := runtime.store.GetArtifact(ctx, runtimestate.ArtifactQuery{Scope: scope, ArtifactID: artifactID})
	if err != nil {
		return agentruntime.ArtifactDownload{}, runtimeFailure("read Artifact", err)
	}
	reader, err := runtimecontent.NewArtifactReader(runtime.content, stateArtifactRepository{compiler: runtime.compiler, store: runtime.store})
	if err != nil {
		return agentruntime.ArtifactDownload{}, runtimeFailure("read Artifact", err)
	}
	body, err := reader.ReadArtifact(ctx, scope.Tenant, scope.Principal, artifactID)
	if err != nil {
		return agentruntime.ArtifactDownload{}, contentReadFailure("read Artifact", err)
	}
	return agentruntime.ArtifactDownload{Artifact: publicArtifact(record), Body: body}, nil
}

// OpenArtifact opens an authorized bounded Artifact transfer without exposing a
// storage locator. The existing ReadArtifact method remains for compatibility.
func (runtime *StateRuntime) OpenArtifact(ctx context.Context, identity Identity, artifactID agentruntime.ArtifactID) (runtimecontent.ArtifactStream, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return runtimecontent.ArtifactStream{}, err
	}
	reader, err := runtimecontent.NewArtifactReader(runtime.content, stateArtifactRepository{compiler: runtime.compiler, store: runtime.store})
	if err != nil {
		return runtimecontent.ArtifactStream{}, runtimeFailure("open Artifact", err)
	}
	stream, err := reader.OpenArtifact(ctx, scope.Tenant, scope.Principal, artifactID)
	if err != nil {
		return runtimecontent.ArtifactStream{}, contentReadFailure("open Artifact", err)
	}
	return stream, nil
}

// InspectApproval returns the caller-owned projection of one approval without
// exposing the tool action, policy digest, or capability metadata.
func (runtime *StateRuntime) InspectApproval(ctx context.Context, identity Identity, approvalID agentruntime.ApprovalID) (agentruntime.Approval, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.Approval{}, err
	}
	state, err := runtime.store.LoadRuntimeState(ctx, scope)
	if err != nil {
		return agentruntime.Approval{}, runtimeFailure("inspect Approval", err)
	}
	for _, record := range state.Approvals {
		if record.Tenant == scope.Tenant && record.Principal == scope.Principal && record.ApprovalID == approvalID.String() {
			return publicApproval(record), nil
		}
	}
	return agentruntime.Approval{}, runtimeFailure("inspect Approval", runtimestate.ErrNotFoundOrDenied)
}

// DecideApproval atomically records one owner decision. A successful approval
// creates an internal bounded grant; the public result never carries it.
func (runtime *StateRuntime) DecideApproval(ctx context.Context, identity Identity, request agentruntime.DecideApprovalRequest) (agentruntime.Approval, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.Approval{}, err
	}
	if request.Decision != agentruntime.ApprovalApproved && request.Decision != agentruntime.ApprovalDenied {
		return agentruntime.Approval{}, invalidFailure("approval decision is invalid")
	}
	_, err = runtime.apply(ctx, scope, func() (runtimestate.CompiledMutation, error) {
		return runtime.compiler.CompileDecideApproval(runtimestate.DecideApprovalCommand{Scope: scope, IdempotencyKey: request.IdempotencyKey, ApprovalID: request.ApprovalID.String(), Decision: string(request.Decision)})
	})
	if err != nil {
		return agentruntime.Approval{}, runtimeFailure("decide Approval", err)
	}
	approval, err := runtime.InspectApproval(ctx, identity, request.ApprovalID)
	if err != nil {
		return agentruntime.Approval{}, err
	}
	if approval.State == agentruntime.ApprovalExpired {
		return agentruntime.Approval{}, runtimeFailure("decide Approval", runtimestate.ErrConflict)
	}
	return approval, nil
}

// IdempotencyStatus safely returns a retained receipt for the caller's exact
// durable scope. It is an observation only: no command is compiled or replayed.
func (runtime *StateRuntime) IdempotencyStatus(ctx context.Context, identity Identity, key string) (agentruntime.IdempotencyStatus, error) {
	var scope runtimestate.MutationScope
	var err error
	if identity.Admin {
		scope, err = administratorScope(identity)
	} else {
		scope, err = ownerScope(identity)
	}
	if err != nil {
		return agentruntime.IdempotencyStatus{}, err
	}
	if key == "" || len(key) > agentruntime.MaxIdempotencyKeyBytes {
		return agentruntime.IdempotencyStatus{}, invalidFailure("idempotency key is invalid")
	}
	receipt, err := runtime.store.GetMutationReceipt(ctx, runtimestate.MutationReceiptQuery{Scope: scope, IdempotencyKey: key})
	if err != nil {
		return agentruntime.IdempotencyStatus{}, runtimeFailure("read idempotency status", err)
	}
	return agentruntime.IdempotencyStatus{OperationID: string(receipt.OperationID), Command: receipt.Command, SessionID: receipt.SessionID, TurnID: receipt.TurnID, ArtifactID: receipt.ArtifactID, AcceptedAt: receipt.AcceptedAt}, nil
}

// CreateSession pins a principal-owned Session to one existing immutable revision.
func (runtime *StateRuntime) CreateSession(ctx context.Context, identity Identity, request agentruntime.CreateSessionRequest) (agentruntime.Session, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.Session{}, err
	}
	plan, err := runtime.apply(ctx, scope, func() (runtimestate.CompiledMutation, error) {
		return runtime.compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: scope, IdempotencyKey: request.IdempotencyKey, RevisionID: request.AgentRevision})
	})
	if err != nil {
		return agentruntime.Session{}, runtimeFailure("create Session", err)
	}
	return publicSession(plan.Result().Session), nil
}

// SendInput stages its immutable envelope and atomically admits one Input and Turn.
func (runtime *StateRuntime) SendInput(ctx context.Context, identity Identity, request agentruntime.SendInputRequest) (agentruntime.SendInputResult, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.SendInputResult{}, err
	}
	if err := runtime.authorizeInputArtifacts(ctx, scope, request.Parts); err != nil {
		return agentruntime.SendInputResult{}, err
	}
	handoff, err := runtime.content.StageInputEnvelope(ctx, scope.Tenant, request.Parts)
	if err != nil {
		return agentruntime.SendInputResult{}, stageFailure(err)
	}
	plan, err := runtime.apply(ctx, scope, func() (runtimestate.CompiledMutation, error) {
		return runtime.compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: scope, IdempotencyKey: request.IdempotencyKey, SessionID: request.SessionID, Input: handoff})
	})
	if err != nil {
		return agentruntime.SendInputResult{}, runtimeFailure("send Input", err)
	}
	result := plan.Result()
	parts, err := runtime.readInputEnvelope(ctx, scope, result.Input.SessionID, result.Input.InputID)
	if err != nil {
		return agentruntime.SendInputResult{}, err
	}
	return agentruntime.SendInputResult{Input: agentruntime.Input{ID: result.Input.InputID, Parts: parts, AcceptedAt: result.Input.AcceptedAt}, Turn: publicTurn(result.Turn)}, nil
}

// authorizeInputArtifacts accepts an Artifact reference only when the caller
// owns the exact immutable metadata already recorded by runtime state. The
// public reference is not an authority token: a forged digest, size, media
// type, or cross-principal ID is deliberately indistinguishable from absence.
func (runtime *StateRuntime) authorizeInputArtifacts(ctx context.Context, scope runtimestate.MutationScope, parts []agentruntime.ContentPart) error {
	for _, part := range parts {
		if part.Kind != agentruntime.ContentArtifact || part.Artifact == nil {
			continue
		}
		record, err := runtime.store.GetArtifact(ctx, runtimestate.ArtifactQuery{Scope: scope, ArtifactID: part.Artifact.ID})
		if err != nil {
			return runtimeFailure("authorize Input Artifact", err)
		}
		if publicArtifact(record) != *part.Artifact {
			return runtimeFailure("authorize Input Artifact", runtimestate.ErrNotFoundOrDenied)
		}
	}
	return nil
}

// InspectSession returns the bounded principal-scoped public projection.
func (runtime *StateRuntime) InspectSession(ctx context.Context, identity Identity, sessionID agentruntime.SessionID) (agentruntime.SessionView, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.SessionView{}, err
	}
	view, err := runtime.store.GetSessionView(ctx, runtimestate.SessionViewQuery{Scope: scope, SessionID: sessionID, RecentEventLimit: 20, QueuedTurnLimit: agentruntime.MaxSessionViewQueuedTurns})
	if err != nil {
		return agentruntime.SessionView{}, runtimeFailure("inspect Session", err)
	}
	result := agentruntime.SessionView{Session: publicSession(view.Session), QueuedTurnCount: view.QueuedTurnCount, QueuedTurnsTruncated: view.QueuedTruncated, RecentEvents: publicEvents(view.RecentEvents)}
	if view.ActiveTurn != nil {
		turn := publicTurn(*view.ActiveTurn)
		result.ActiveTurn = &turn
	}
	for _, turn := range view.QueuedTurns {
		result.QueuedTurns = append(result.QueuedTurns, publicTurn(turn))
	}
	return result, nil
}

// InspectTurn returns one exact principal-owned Turn.
func (runtime *StateRuntime) InspectTurn(ctx context.Context, identity Identity, sessionID agentruntime.SessionID, turnID agentruntime.TurnID) (agentruntime.Turn, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.Turn{}, err
	}
	record, err := runtime.store.GetTurn(ctx, runtimestate.TurnQuery{Scope: scope, SessionID: sessionID, TurnID: turnID})
	if err != nil {
		return agentruntime.Turn{}, runtimeFailure("inspect Turn", err)
	}
	state, err := runtime.store.LoadRuntimeState(ctx, scope)
	if err != nil {
		return agentruntime.Turn{}, runtimeFailure("inspect Turn usage", err)
	}
	return publicTurnWithUsage(record, latestInvocationUsage(state, record)), nil
}

// InspectToolCalls returns bounded safe projections for one principal-owned Turn.
func (runtime *StateRuntime) InspectToolCalls(ctx context.Context, identity Identity, sessionID agentruntime.SessionID, turnID agentruntime.TurnID) (agentruntime.ToolCallPage, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.ToolCallPage{}, err
	}
	if _, err := runtime.store.GetTurn(ctx, runtimestate.TurnQuery{Scope: scope, SessionID: sessionID, TurnID: turnID}); err != nil {
		return agentruntime.ToolCallPage{}, runtimeFailure("inspect Tool calls", err)
	}
	state, err := runtime.store.LoadRuntimeState(ctx, scope)
	if err != nil {
		return agentruntime.ToolCallPage{}, runtimeFailure("inspect Tool calls", err)
	}
	page := agentruntime.ToolCallPage{}
	for _, intent := range state.ToolIntents {
		if intent.Tenant != scope.Tenant || intent.Principal != scope.Principal || intent.SessionID != sessionID || intent.TurnID != turnID {
			continue
		}
		if len(page.Calls) == agentruntime.MaxToolCallsPerTurn {
			page.Truncated = true
			break
		}
		call := agentruntime.ToolCall{ID: intent.ToolCallID, Name: intent.ToolName, State: agentruntime.ToolCallIntent, CreatedAt: intent.CreatedAt}
		for _, approval := range state.Approvals {
			if approval.ToolCallID == intent.ToolCallID && approval.SessionID == sessionID && approval.TurnID == turnID {
				value := publicApproval(approval)
				call.Approval = &value
				if value.State == agentruntime.ApprovalPending {
					call.State = agentruntime.ToolCallAwaitingApproval
				}
			}
		}
		for _, grant := range state.Grants {
			if grant.ToolCallID == intent.ToolCallID && grant.Tenant == scope.Tenant && grant.Principal == scope.Principal {
				call.Grant = &agentruntime.CapabilityGrant{MaximumUses: grant.MaximumUses, Uses: grant.Uses, ExpiresAt: grant.ExpiresAt}
				if call.State != agentruntime.ToolCallAwaitingApproval {
					call.State = agentruntime.ToolCallAuthorized
				}
			}
		}
		for _, execution := range state.ToolExecutions {
			if execution.ToolCallID == intent.ToolCallID && execution.SessionID == sessionID && execution.TurnID == turnID {
				value := publicToolExecution(execution)
				call.Execution = &value
				call.State = value.State
			}
		}
		page.Calls = append(page.Calls, call)
	}
	return page, nil
}

// Events reads a bounded cursor-resumable page of principal-scoped Product events.
func (runtime *StateRuntime) Events(ctx context.Context, identity Identity, sessionID agentruntime.SessionID, after agentruntime.Cursor, limit int) (agentruntime.EventPage, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.EventPage{}, err
	}
	if limit < 1 || limit > 1000 {
		return agentruntime.EventPage{}, invalidFailure("event page limit is outside the supported range")
	}
	page, err := runtime.store.ReadEvents(ctx, runtimestate.EventsQuery{Scope: scope, SessionID: sessionID, After: after, Limit: uint32(limit)})
	if err != nil {
		return agentruntime.EventPage{}, runtimeFailure("read events", err)
	}
	return agentruntime.EventPage{Events: publicEvents(page.Events), NextCursor: page.NextCursor, Gap: page.Gap}, nil
}

// CancelTurn atomically records a caller-authorized terminal cancellation.
func (runtime *StateRuntime) CancelTurn(ctx context.Context, identity Identity, request agentruntime.CancelTurnRequest) (agentruntime.Turn, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.Turn{}, err
	}
	plan, err := runtime.apply(ctx, scope, func() (runtimestate.CompiledMutation, error) {
		return runtime.compiler.CompileCancelTurn(runtimestate.CancelTurnCommand{Scope: scope, IdempotencyKey: request.IdempotencyKey, SessionID: request.SessionID, TurnID: request.TurnID})
	})
	if err != nil {
		return agentruntime.Turn{}, runtimeFailure("cancel Turn", err)
	}
	return publicTurn(plan.Result().Turn), nil
}

// CloseSession durably rejects future Input while allowing accepted work to drain.
func (runtime *StateRuntime) CloseSession(ctx context.Context, identity Identity, request agentruntime.CloseSessionRequest) (agentruntime.Session, error) {
	scope, err := ownerScope(identity)
	if err != nil {
		return agentruntime.Session{}, err
	}
	plan, err := runtime.apply(ctx, scope, func() (runtimestate.CompiledMutation, error) {
		return runtime.compiler.CompileCloseSession(runtimestate.CloseSessionCommand{Scope: scope, IdempotencyKey: request.IdempotencyKey, SessionID: request.SessionID})
	})
	if err != nil {
		return agentruntime.Session{}, runtimeFailure("close Session", err)
	}
	return publicSession(plan.Result().Session), nil
}

func (runtime *StateRuntime) apply(ctx context.Context, scope runtimestate.MutationScope, compile func() (runtimestate.CompiledMutation, error)) (runtimestate.TransitionPlan, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if err := contextError(ctx); err != nil {
			return runtimestate.TransitionPlan{}, err
		}
		mutation, err := compile()
		if err != nil {
			return runtimestate.TransitionPlan{}, err
		}
		prior, err := runtime.store.LoadRuntimeState(ctx, scope)
		if err != nil {
			return runtimestate.TransitionPlan{}, err
		}
		plan, err := runtime.planner.Plan(ctx, prior, mutation)
		if err != nil {
			return runtimestate.TransitionPlan{}, err
		}
		if err := runtime.store.PersistTransitionPlan(ctx, plan); err == nil {
			return plan, nil
		} else if !errors.Is(err, runtimestate.ErrConflict) || attempt == 2 {
			return runtimestate.TransitionPlan{}, err
		}
	}
	return runtimestate.TransitionPlan{}, runtimestate.ErrConflict
}

func (runtime *StateRuntime) readAgentSpecification(ctx context.Context, tenant runtimecontent.TenantID, agentID agentruntime.AgentID, revisionID agentruntime.AgentRevisionID) (agentruntime.AgentSpecification, error) {
	reader, err := runtimecontent.NewAgentSpecificationBodyReader(runtime.content, stateAgentBodyRepository{compiler: runtime.compiler, store: runtime.store})
	if err != nil {
		return agentruntime.AgentSpecification{}, runtimeFailure("read Agent revision", err)
	}
	result, err := reader.ReadAgentSpecification(ctx, tenant, agentID, revisionID)
	if err != nil {
		return agentruntime.AgentSpecification{}, contentReadFailure("read Agent revision", err)
	}
	return result, nil
}

func (runtime *StateRuntime) readInputEnvelope(ctx context.Context, scope runtimestate.MutationScope, sessionID agentruntime.SessionID, inputID agentruntime.InputID) ([]agentruntime.ContentPart, error) {
	reader, err := runtimecontent.NewInputEnvelopeReader(runtime.content, stateInputRepository{compiler: runtime.compiler, store: runtime.store})
	if err != nil {
		return nil, runtimeFailure("read Input", err)
	}
	parts, err := reader.ReadInputEnvelope(ctx, scope.Tenant, scope.Principal, sessionID, inputID)
	if err != nil {
		return nil, contentReadFailure("read Input", err)
	}
	return parts, nil
}

type stateAgentBodyRepository struct {
	compiler *runtimestate.Compiler
	store    runtimestate.RuntimeStateStore
}

func (repository stateAgentBodyRepository) AuthorizeAgentSpecificationBodyRead(ctx context.Context, tenant runtimecontent.TenantID, agentID agentruntime.AgentID, revisionID agentruntime.AgentRevisionID) (runtimecontent.AgentSpecificationBodyRecord, error) {
	authorization, err := repository.compiler.CompileAuthorizeAgentSpecificationBodyRead(runtimestate.AgentSpecificationBodyReadCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, AgentID: agentID, RevisionID: revisionID})
	if err != nil {
		return runtimecontent.AgentSpecificationBodyRecord{}, err
	}
	return repository.store.AuthorizeAgentSpecificationBodyRead(ctx, authorization)
}

type stateInputRepository struct {
	compiler *runtimestate.Compiler
	store    runtimestate.RuntimeStateStore
}

type stateArtifactRepository struct {
	compiler *runtimestate.Compiler
	store    runtimestate.RuntimeStateStore
}

func (repository stateArtifactRepository) AuthorizeArtifactRead(ctx context.Context, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID, artifactID agentruntime.ArtifactID) (runtimecontent.ArtifactRecord, error) {
	authorization, err := repository.compiler.CompileAuthorizeArtifactRead(runtimestate.ArtifactReadCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, ArtifactID: artifactID})
	if err != nil {
		return runtimecontent.ArtifactRecord{}, err
	}
	return repository.store.AuthorizeArtifactRead(ctx, authorization)
}

func (repository stateInputRepository) AuthorizeInputEnvelopeRead(ctx context.Context, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID, sessionID agentruntime.SessionID, inputID agentruntime.InputID) (runtimecontent.InputEnvelopeRecord, error) {
	authorization, err := repository.compiler.CompileAuthorizeInputEnvelopeRead(runtimestate.InputEnvelopeReadCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, SessionID: sessionID, InputID: inputID})
	if err != nil {
		return runtimecontent.InputEnvelopeRecord{}, err
	}
	return repository.store.AuthorizeInputEnvelopeRead(ctx, authorization)
}

func administratorScope(identity Identity) (runtimestate.MutationScope, error) {
	if !identity.Admin {
		return runtimestate.MutationScope{}, invalidFailure("administrator authority is required")
	}
	tenant, err := runtimecontent.ParseTenantID(identity.Tenant)
	if err != nil {
		return runtimestate.MutationScope{}, invalidFailure("invalid authenticated identity")
	}
	return runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, nil
}

func ownerScope(identity Identity) (runtimestate.MutationScope, error) {
	tenant, err := runtimecontent.ParseTenantID(identity.Tenant)
	if err != nil {
		return runtimestate.MutationScope{}, invalidFailure("invalid authenticated identity")
	}
	principal, err := runtimecontent.ParsePrincipalID(identity.Principal)
	if err != nil {
		return runtimestate.MutationScope{}, invalidFailure("invalid authenticated identity")
	}
	return runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, nil
}

func (runtime *StateRuntime) validateProfile(profile string) error {
	if _, exists := runtime.profiles[profile]; !exists {
		return invalidFailure("model profile is not configured")
	}
	return nil
}

func latestRevision(state runtimestate.RuntimeState, tenant runtimecontent.TenantID, agentID agentruntime.AgentID) (runtimestate.AgentRevisionRecord, bool) {
	revisions := append([]runtimestate.AgentRevisionRecord(nil), state.Revisions...)
	sort.Slice(revisions, func(left, right int) bool { return revisions[left].Revision > revisions[right].Revision })
	for _, revision := range revisions {
		if revision.Tenant == tenant && revision.AgentID == agentID {
			return revision, true
		}
	}
	return runtimestate.AgentRevisionRecord{}, false
}

func publicSession(record runtimestate.SessionRecord) agentruntime.Session {
	return agentruntime.Session{ID: record.SessionID, AgentID: record.AgentID, AgentRevision: record.RevisionID, State: record.State, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt}
}

func publicPolicy(record runtimestate.PolicyRevisionRecord) agentruntime.Policy {
	return agentruntime.Policy{Name: record.Name, Revision: record.Revision, Digest: record.Digest, Rules: append([]agentruntime.PolicyRule(nil), record.Rules...), CreatedAt: record.CreatedAt}
}

func publicTurn(record runtimestate.TurnRecord) agentruntime.Turn {
	return publicTurnWithUsage(record, nil)
}

func publicTurnWithUsage(record runtimestate.TurnRecord, usage *runtimestate.ModelUsage) agentruntime.Turn {
	return agentruntime.Turn{ID: record.TurnID, InputID: record.InputID, Position: record.Position, State: record.State, StartedAt: record.StartedAt, CompletedAt: record.CompletedAt, Failure: record.Failure.Clone(), Usage: publicModelUsage(usage)}
}

func latestInvocationUsage(state runtimestate.RuntimeState, turn runtimestate.TurnRecord) *runtimestate.ModelUsage {
	var latest *runtimestate.InvocationRecord
	for index := range state.Invocations {
		invocation := &state.Invocations[index]
		if invocation.Tenant != turn.Tenant || invocation.Principal != turn.Principal || invocation.SessionID != turn.SessionID || invocation.TurnID != turn.TurnID || invocation.State == runtimestate.InvocationIntent {
			continue
		}
		if latest == nil || invocation.Ordinal > latest.Ordinal || invocation.Ordinal == latest.Ordinal && invocation.Fence > latest.Fence {
			latest = invocation
		}
	}
	if latest == nil {
		return nil
	}
	return latest.Usage.Clone()
}

func publicModelUsage(usage *runtimestate.ModelUsage) *agentruntime.ModelUsage {
	if usage == nil {
		return nil
	}
	result := agentruntime.ModelUsage{}
	if usage.InputTokens != nil {
		value := *usage.InputTokens
		result.InputTokens = &value
	}
	if usage.OutputTokens != nil {
		value := *usage.OutputTokens
		result.OutputTokens = &value
	}
	return &result
}

func publicToolExecution(record runtimestate.ToolExecutionRecord) agentruntime.ToolExecution {
	state := agentruntime.ToolCallExecuting
	switch record.State {
	case runtimestate.ToolExecutionSucceeded:
		state = agentruntime.ToolCallSucceeded
	case runtimestate.ToolExecutionFailed:
		state = agentruntime.ToolCallFailed
	case runtimestate.ToolExecutionUncertain:
		state = agentruntime.ToolCallUncertain
	}
	result := agentruntime.ToolExecution{State: state, Failure: record.Failure.Clone(), CreatedAt: record.CreatedAt}
	if record.State != runtimestate.ToolExecutionIntent {
		value := record.UpdatedAt
		result.CompletedAt = &value
	}
	return result
}

func publicArtifact(record runtimestate.ArtifactRecord) agentruntime.ArtifactReference {
	return agentruntime.ArtifactReference{ID: record.ArtifactID, MediaType: record.Reference.MediaType, SizeBytes: record.Reference.SizeBytes, SHA256: strings.TrimPrefix(record.Reference.Digest, "sha256:")}
}

func publicApproval(record runtimestate.ApprovalRecord) agentruntime.Approval {
	id, _ := agentruntime.ParseApprovalID(record.ApprovalID)
	state := agentruntime.ApprovalState(record.State)
	return agentruntime.Approval{ID: id, SessionID: record.SessionID, TurnID: record.TurnID, State: state, ExpiresAt: record.ExpiresAt, DecidedAt: record.DecidedAt}
}

func publicEvents(records []runtimestate.ProductEventRecord) []agentruntime.Event {
	events := make([]agentruntime.Event, len(records))
	for index, record := range records {
		events[index] = agentruntime.Event{ID: record.EventID, Cursor: record.Cursor, Sequence: record.Sequence, Kind: record.Kind, SessionID: record.SessionID, InputID: record.InputID, TurnID: record.TurnID, OccurredAt: record.OccurredAt}
	}
	return events
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("runtime context is required")
	}
	return ctx.Err()
}

func invalidFailure(message string) error {
	return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: message}}
}

func stageFailure(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, runtimecontent.ErrUnavailable) {
		return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "runtime content is unavailable", Retryable: true}}
	}
	if errors.Is(err, runtimecontent.ErrIntegrity) {
		return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "runtime content integrity check failed"}}
	}
	return invalidFailure("request content is invalid")
}

func contentReadFailure(action string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"}}
	}
	if errors.Is(err, runtimecontent.ErrUnavailable) {
		return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "runtime content is unavailable", Retryable: true}}
	}
	_ = action
	return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "request failed"}}
}

func runtimeFailure(action string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, runtimestate.ErrConflict), errors.Is(err, runtimestate.ErrReceiptExpired):
		return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureConflict, Message: action + " conflicts with current state"}}
	case errors.Is(err, runtimestate.ErrNotFoundOrDenied):
		return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"}}
	case errors.Is(err, runtimestate.ErrUnavailable):
		return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "durable runtime is unavailable", Retryable: true}}
	case errors.Is(err, runtimestate.ErrIntegrity):
		return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "request failed"}}
	default:
		return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: action + " request is invalid"}}
	}
}
