// Package runtimetool owns capability-bound external tool execution.
package runtimetool

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

type Request struct {
	Tenant      runtimecontent.TenantID
	SessionID   agentruntime.SessionID
	TurnID      agentruntime.TurnID
	ToolCallID  string
	OperationID runtimestate.OperationID
}
type Response struct {
	Output    []byte
	Failure   *agentruntime.Failure
	Uncertain bool
}
type Adapter interface {
	Execute(context.Context, Request) (Response, error)
	Reconcile(context.Context, Request) (Response, error)
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
	store    runtimestate.RuntimeStateStore
	tenants  runtimestate.OutboxTenantSource
	compiler *runtimestate.Compiler
	planner  *runtimestate.RuntimeStatePlanner
	clock    clock.Clock
	content  *runtimecontent.Store
	adapter  Adapter
	claimer  string
}

func NewWorker(c Config) (*Worker, error) {
	if c.Store == nil || c.Tenants == nil || c.Compiler == nil || c.Planner == nil || c.Clock == nil || c.Content == nil || c.Adapter == nil || c.Claimer == "" {
		return nil, errors.New("create runtime tool worker: complete authority is required")
	}
	return &Worker{c.Store, c.Tenants, c.Compiler, c.Planner, c.Clock, c.Content, c.Adapter, c.Claimer}, nil
}
func (w *Worker) ScanOnce(ctx context.Context) error {
	ts, e := w.tenants.ListOutboxTenants(ctx)
	if e != nil {
		return e
	}
	for _, t := range ts {
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
	q := Request{r.Tenant, r.SessionID, r.TurnID, r.ToolCallID, r.OperationID}
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
	if len(out.Output) > 0 && failure == nil && !out.Uncertain {
		h, err := w.content.StageArtifact(ctx, r.Tenant, "text/plain", out.Output)
		if err == nil {
			c, err := w.content.ValidateArtifactHandoff(h)
			if err == nil {
				v := c.Reference
				result = &v
				state = runtimestate.ToolExecutionSucceeded
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
	s, e := w.store.LoadRuntimeState(ctx, m.ReceiptBinding().Scope)
	if e != nil {
		return e
	}
	p, e := w.planner.Plan(ctx, s, m)
	if e != nil {
		return e
	}
	return w.store.PersistTransitionPlan(ctx, p)
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
