package runtimeorchestration

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

const (
	defaultOutboxPageSize = 128
	defaultClaimDuration  = 2 * time.Minute
	maxTransitionAttempts = 4
)

// SessionWorkflowPublisher is the private Temporal publication port. It
// receives only metadata from the outbox scheduler, never public credentials
// or runtime-content handles.
type SessionWorkflowPublisher interface {
	StartSession(context.Context, SessionStart) error
	SignalSession(context.Context, SessionStart, Command) error
}

// SessionStart is the deterministic private workflow identity for one durable
// Session partition.
type SessionStart struct {
	Tenant    string
	SessionID string
}

// PublisherConfig confines an outbox scheduler to finite state work and one
// task queue publisher identity.
type PublisherConfig struct {
	Store     runtimestate.RuntimeStateStore
	Tenants   runtimestate.OutboxTenantSource
	Compiler  *runtimestate.Compiler
	Planner   *runtimestate.RuntimeStatePlanner
	Clock     clock.Clock
	Publisher SessionWorkflowPublisher
	// AuditExporter is optional because the base runtime does not claim a
	// mandatory external audit sink. When configured, its delivery is fenced by
	// the exact committed audit fact and the same outbox lease as the route.
	AuditExporter AuditExporter
	Claimer       string
}

// Publisher claims durable outbox records, performs the private Temporal
// operation, and records an acknowledgement only after that operation returns.
// A lease can be reclaimed after expiry, making the boundary at-least-once.
type Publisher struct {
	store     runtimestate.RuntimeStateStore
	tenants   runtimestate.OutboxTenantSource
	compiler  *runtimestate.Compiler
	planner   *runtimestate.RuntimeStatePlanner
	clock     clock.Clock
	publisher SessionWorkflowPublisher
	audit     AuditExporter
	claimer   string
}

// NewPublisher constructs the only state/outbox-to-Temporal scheduler seam.
func NewPublisher(config PublisherConfig) (*Publisher, error) {
	if config.Store == nil || config.Tenants == nil || config.Compiler == nil || config.Planner == nil || config.Clock == nil || config.Publisher == nil || config.Claimer == "" {
		return nil, errors.New("create runtime outbox publisher: complete state and Temporal authority is required")
	}
	return &Publisher{store: config.Store, tenants: config.Tenants, compiler: config.Compiler, planner: config.Planner, clock: config.Clock, publisher: config.Publisher, audit: config.AuditExporter, claimer: config.Claimer}, nil
}

// ScanOnce drains currently visible durable work. It intentionally has no
// callback for arbitrary requests: every operation originates in a committed
// outbox record and is claimed through compiler/planner/CAS first.
func (publisher *Publisher) ScanOnce(ctx context.Context) error {
	if publisher == nil {
		return errors.New("publish runtime outbox: publisher is required")
	}
	tenants, err := publisher.tenants.ListOutboxTenants(ctx)
	if err != nil {
		return err
	}
	for _, tenant := range tenants {
		if err := publisher.publishTenant(ctx, tenant); err != nil {
			return err
		}
	}
	return nil
}

func (publisher *Publisher) publishTenant(ctx context.Context, tenant runtimecontent.TenantID) error {
	after := runtimestate.OutboxID("")
	for {
		page, err := publisher.store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, After: after, Limit: defaultOutboxPageSize})
		if err != nil {
			return err
		}
		for _, record := range page.Records {
			// Invocation intents are owned by the model worker. They retain a
			// blank public event kind deliberately: Temporal must not consume or
			// acknowledge an effect before that worker records its outcome.
			if (record.InvocationID != "" || record.ToolCallID != "") && record.EventKind == "" {
				continue
			}
			if record.State == runtimestate.OutboxPublished || record.State == runtimestate.OutboxReconcile {
				continue
			}
			if record.State == runtimestate.OutboxClaimed && (record.ClaimUntil == nil || record.ClaimUntil.After(publisher.clock.Now())) {
				continue
			}
			claimed, err := publisher.claim(ctx, record)
			if err != nil {
				if errors.Is(err, runtimestate.ErrConflict) {
					continue
				}
				return err
			}
			if err := publisher.route(ctx, claimed); err != nil {
				return err
			}
			if err := publisher.acknowledge(ctx, claimed); err != nil {
				return err
			}
		}
		if page.Next == "" || page.Next == after {
			return nil
		}
		after = page.Next
	}
}

func (publisher *Publisher) claim(ctx context.Context, record runtimestate.OutboxRecord) (runtimestate.OutboxRecord, error) {
	return publisher.apply(ctx, record, func(current runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error) {
		return publisher.compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{
			Scope:           runtimestate.MutationScope{Tenant: record.Tenant, Authority: runtimestate.AuthorityOutboxPublisher},
			IdempotencyKey:  fmt.Sprintf("temporal-claim-%s-%d", record.OutboxID, current.Version),
			OutboxID:        record.OutboxID,
			ExpectedVersion: current.Version,
			Claimer:         publisher.claimer,
			ClaimUntil:      publisher.clock.Now().Add(defaultClaimDuration),
		})
	})
}

func (publisher *Publisher) acknowledge(ctx context.Context, record runtimestate.OutboxRecord) error {
	_, err := publisher.apply(ctx, record, func(current runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error) {
		return publisher.compiler.CompileAcknowledgeOutbox(runtimestate.AcknowledgeOutboxCommand{
			Scope:           runtimestate.MutationScope{Tenant: record.Tenant, Authority: runtimestate.AuthorityOutboxPublisher},
			IdempotencyKey:  fmt.Sprintf("temporal-ack-%s-%d", record.OutboxID, current.Version),
			OutboxID:        record.OutboxID,
			ExpectedVersion: current.Version,
			Claimer:         publisher.claimer,
			PublishedAt:     publisher.clock.Now(),
		})
	})
	return err
}

func (publisher *Publisher) apply(ctx context.Context, target runtimestate.OutboxRecord, compile func(runtimestate.OutboxRecord) (runtimestate.CompiledMutation, error)) (runtimestate.OutboxRecord, error) {
	for attempt := 0; attempt < maxTransitionAttempts; attempt++ {
		scope := runtimestate.MutationScope{Tenant: target.Tenant, Authority: runtimestate.AuthorityOutboxPublisher}
		state, err := publisher.store.LoadRuntimeState(ctx, scope)
		if err != nil {
			return runtimestate.OutboxRecord{}, err
		}
		// The target ID is stable, while its version is read from the latest
		// durable state before each compiler/planner/CAS attempt.
		current, found := findOutbox(state, target.OutboxID)
		if !found {
			return runtimestate.OutboxRecord{}, runtimestate.ErrNotFoundOrDenied
		}
		mutation, err := compile(current)
		if err != nil {
			return runtimestate.OutboxRecord{}, err
		}
		plan, err := publisher.planner.Plan(ctx, state, mutation)
		if err != nil {
			return runtimestate.OutboxRecord{}, err
		}
		if err := publisher.store.PersistTransitionPlan(ctx, plan); err != nil {
			if errors.Is(err, runtimestate.ErrConflict) {
				continue
			}
			return runtimestate.OutboxRecord{}, err
		}
		return plan.Result().Outbox, nil
	}
	return runtimestate.OutboxRecord{}, runtimestate.ErrConflict
}

func (publisher *Publisher) route(ctx context.Context, record runtimestate.OutboxRecord) error {
	if record.AuditFactID != "" && publisher.audit != nil {
		fact, err := publisher.auditFact(ctx, record)
		if err != nil {
			return err
		}
		if err := publisher.audit.Export(ctx, fact); err != nil {
			return err
		}
	}
	start := SessionStart{Tenant: string(record.Tenant), SessionID: string(record.SessionID)}
	switch record.EventKind {
	case agentruntime.EventSessionCreated:
		return publisher.publisher.StartSession(ctx, start)
	case agentruntime.EventInputAccepted, agentruntime.EventTurnCancelled, agentruntime.EventTurnSucceeded, agentruntime.EventTurnFailed, agentruntime.EventApprovalResolved, agentruntime.EventApprovalExpired, agentruntime.EventApprovalCancelled, agentruntime.EventSandboxOperationFinalized, agentruntime.EventSessionClosing, agentruntime.EventSessionCompleted, agentruntime.EventSessionCancelled, agentruntime.EventSessionFailed:
		return publisher.publisher.SignalSession(ctx, start, Command{Tenant: string(record.Tenant), OutboxID: string(record.OutboxID), SessionID: string(record.SessionID), Kind: commandKind(record.EventKind), Sequence: record.EventSequence})
	default:
		return nil
	}
}

func (publisher *Publisher) auditFact(ctx context.Context, record runtimestate.OutboxRecord) (runtimestate.AuditFactRecord, error) {
	state, err := publisher.store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: record.Tenant, Authority: runtimestate.AuthorityOutboxPublisher})
	if err != nil {
		return runtimestate.AuditFactRecord{}, err
	}
	for _, fact := range state.Audit {
		if fact.AuditFactID == record.AuditFactID && fact.Tenant == record.Tenant {
			return fact.Clone(), nil
		}
	}
	return runtimestate.AuditFactRecord{}, runtimestate.ErrIntegrity
}

func commandKind(event agentruntime.EventKind) CommandKind {
	switch event {
	case agentruntime.EventTurnCancelled:
		return CommandTurnCancelled
	case agentruntime.EventTurnSucceeded:
		return CommandTurnSucceeded
	case agentruntime.EventTurnFailed:
		return CommandTurnFailed
	case agentruntime.EventApprovalResolved:
		return CommandApprovalResolved
	case agentruntime.EventApprovalExpired:
		return CommandApprovalExpired
	case agentruntime.EventApprovalCancelled:
		return CommandApprovalCancelled
	case agentruntime.EventSandboxOperationFinalized:
		return CommandSandboxOperationFinalized
	case agentruntime.EventSessionClosing:
		return CommandSessionClosing
	case agentruntime.EventSessionCompleted:
		return CommandSessionCompleted
	case agentruntime.EventSessionCancelled:
		return CommandSessionCancelled
	case agentruntime.EventSessionFailed:
		return CommandSessionFailed
	default:
		return CommandInputAccepted
	}
}

func findOutbox(state runtimestate.RuntimeState, id runtimestate.OutboxID) (runtimestate.OutboxRecord, bool) {
	for _, record := range state.Outbox {
		if record.OutboxID == id {
			return record, true
		}
	}
	return runtimestate.OutboxRecord{}, false
}
