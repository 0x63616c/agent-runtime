package runtimetool

import (
	"context"
	"errors"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// ErrDenied reports a policy refusal without disclosing whether the policy,
// tool name, or revision was absent. The broker does not construct a Tool
// intent, Approval, grant, or execution when it returns this error.
var ErrDenied = errors.New("tool admission denied")

// AdmissionRequest is a model-worker-only normalized Tool request. The model
// adapter supplies opaque, preallocated correlations; it does not receive a
// capability grant or sandbox client.
type AdmissionRequest struct {
	Tenant                         runtimecontent.TenantID
	Principal                      runtimecontent.PrincipalID
	SessionID                      agentruntime.SessionID
	TurnID                         agentruntime.TurnID
	ToolCallID                     string
	ApprovalID                     agentruntime.ApprovalID
	PolicyName                     string
	PolicyRevision                 uint64
	ToolName                       string
	ActionDigest, CapabilityDigest string
	Action                         agentruntime.ApprovalAction
	MaximumUses                    uint32
	ExpiresAt                      time.Time
	Descriptor                     runtimecontent.ContentHandoff
	IdempotencyKey                 string
}

// Admission is the sealed durable correlation returned only to the private
// model worker. The public API exposes the resulting Approval by its own
// authorization rules.
type Admission struct {
	ToolCallID string
	ApprovalID agentruntime.ApprovalID
}

// Broker owns the only supported transition from normalized model Tool intent
// to durable authorization state. It has no adapter: execution remains owned
// by Worker after an owner has approved and a grant has been consumed.
type Broker struct {
	store    runtimestate.RuntimeStateStore
	compiler *runtimestate.Compiler
	planner  *runtimestate.RuntimeStatePlanner
	clock    clock.Clock
}

// BrokerConfig supplies the state authorities required to seal an admission.
type BrokerConfig struct {
	Store    runtimestate.RuntimeStateStore
	Compiler *runtimestate.Compiler
	Planner  *runtimestate.RuntimeStatePlanner
	Clock    clock.Clock
}

// NewBroker constructs the private model-to-tool authority boundary.
func NewBroker(config BrokerConfig) (*Broker, error) {
	if config.Store == nil || config.Compiler == nil || config.Planner == nil || config.Clock == nil {
		return nil, errors.New("create runtime tool broker: complete state authority is required")
	}
	return &Broker{store: config.Store, compiler: config.Compiler, planner: config.Planner, clock: config.Clock}, nil
}

// Admit evaluates one immutable policy revision and, only when that revision
// requires approval, atomically persists the Tool intent and pending Approval.
// A replay with the same idempotency key returns the same atomic state plan.
func (broker *Broker) Admit(ctx context.Context, request AdmissionRequest) (Admission, error) {
	if broker == nil || ctx == nil {
		return Admission{}, errors.New("admit tool request: broker and context are required")
	}
	scope := runtimestate.MutationScope{Tenant: request.Tenant, Principal: request.Principal, Authority: runtimestate.AuthorityRuntimeWorker}
	if request.Tenant == "" || request.Principal == "" || request.PolicyName == "" || request.PolicyRevision == 0 || request.ToolCallID == "" || request.IdempotencyKey == "" || request.ExpiresAt.IsZero() {
		return Admission{}, ErrDenied
	}
	state, err := broker.store.LoadRuntimeState(ctx, scope)
	if err != nil {
		return Admission{}, err
	}
	policy, found := policyRevision(state, request.PolicyName, request.PolicyRevision)
	if !found || !requiresApproval(policy, request.ToolName) || !request.ExpiresAt.After(broker.clock.Now()) {
		if err := broker.recordDenial(ctx, state, scope, request, "denied"); err != nil {
			return Admission{}, err
		}
		return Admission{}, ErrDenied
	}
	mutation, err := broker.compiler.CompileAdmitToolApproval(runtimestate.AdmitToolApprovalCommand{
		Scope: scope, IdempotencyKey: request.IdempotencyKey, SessionID: request.SessionID, TurnID: request.TurnID,
		ToolCallID: request.ToolCallID, ToolName: request.ToolName, ApprovalID: request.ApprovalID.String(),
		ActionDigest: request.ActionDigest, PolicyRevisionDigest: policy.Digest, CapabilityDigest: request.CapabilityDigest,
		ActionVerb: request.Action.Verb, ActionTarget: request.Action.Target, Descriptor: request.Descriptor,
		MaximumUses: request.MaximumUses, ExpiresAt: request.ExpiresAt,
	})
	if err != nil {
		return Admission{}, ErrDenied
	}
	plan, err := broker.planner.Plan(ctx, state, mutation)
	if err != nil {
		return Admission{}, err
	}
	if err := broker.store.PersistTransitionPlan(ctx, plan); err != nil {
		return Admission{}, err
	}
	return Admission{ToolCallID: request.ToolCallID, ApprovalID: request.ApprovalID}, nil
}

func (broker *Broker) recordDenial(ctx context.Context, state runtimestate.RuntimeState, scope runtimestate.MutationScope, request AdmissionRequest, decision string) error {
	mutation, err := broker.compiler.CompileDenyToolAdmission(runtimestate.DenyToolAdmissionCommand{Scope: scope, IdempotencyKey: "tool-" + decision + "-" + request.IdempotencyKey, SessionID: request.SessionID, TurnID: request.TurnID, ToolCallID: request.ToolCallID, Decision: decision})
	if err != nil {
		return err
	}
	plan, err := broker.planner.Plan(ctx, state, mutation)
	if err != nil {
		return err
	}
	return broker.store.PersistTransitionPlan(ctx, plan)
}

func policyRevision(state runtimestate.RuntimeState, name string, revision uint64) (runtimestate.PolicyRevisionRecord, bool) {
	for _, policy := range state.Policies {
		if policy.Name == name && policy.Revision == revision {
			return policy, true
		}
	}
	return runtimestate.PolicyRevisionRecord{}, false
}

func requiresApproval(policy runtimestate.PolicyRevisionRecord, tool string) bool {
	for _, rule := range policy.Rules {
		if rule.ToolName == tool {
			return rule.Decision == agentruntime.PolicyRequiresApproval
		}
	}
	return false
}
