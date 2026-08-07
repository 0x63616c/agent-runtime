package kernel_test

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtime/kernel"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestKernel(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Agent Kernel Suite")
}

type sequenceSource struct {
	mu   sync.Mutex
	next uint64
}

type cancellingSource struct {
	sequenceSource
	cancel context.CancelFunc
	once   sync.Once
}

func (source *cancellingSource) Next() (string, error) {
	payload, err := source.sequenceSource.Next()
	source.once.Do(source.cancel)
	return payload, err
}

func (source *sequenceSource) Next() (string, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	return fmt.Sprintf("%016d", source.next), nil
}

var _ = Describe("durable Agent kernel", func() {
	var (
		ctx       context.Context
		now       time.Time
		fakeClock *clock.Fake
		service   *kernel.Kernel
		scope     kernel.Scope
	)

	BeforeEach(func() {
		ctx = context.Background()
		now = time.Date(2026, 8, 7, 15, 0, 0, 0, time.UTC)
		var err error
		fakeClock, err = clock.NewFake(now)
		Expect(err).NotTo(HaveOccurred())
		scope, err = kernel.ParseScope("tenant-a")
		Expect(err).NotTo(HaveOccurred())
		service, err = kernel.New(fakeClock, &sequenceSource{}, kernel.NewMemoryRepository(), []string{"balanced", "fast"})
		Expect(err).NotTo(HaveOccurred())
	})

	It("creates immutable revisions and pins Sessions to the selected revision", func() {
		first, err := service.CreateAgent(ctx, scope, agentruntime.CreateAgentRequest{
			IdempotencyKey: "create-researcher",
			Name:           "researcher",
			ModelProfile:   "balanced",
			Instructions:   "Use cited sources.",
			Tools:          []agentruntime.ToolDefinition{{Name: "search", Description: "Search approved sources."}},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Revision).To(Equal(uint64(1)))

		session, err := service.CreateSession(ctx, scope, agentruntime.CreateSessionRequest{
			IdempotencyKey: "session-one",
			AgentRevision:  first.RevisionID,
		})
		Expect(err).NotTo(HaveOccurred())

		second, err := service.ReviseAgent(ctx, scope, agentruntime.ReviseAgentRequest{
			AgentID:        first.ID,
			IdempotencyKey: "revise-researcher",
			ModelProfile:   "fast",
			Instructions:   "Use cited primary sources.",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(second.Revision).To(Equal(uint64(2)))
		Expect(second.RevisionID).NotTo(Equal(first.RevisionID))

		view, err := service.InspectSession(ctx, scope, session.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(view.Session.AgentRevision).To(Equal(first.RevisionID))
		view.Session.AgentRevision = second.RevisionID
		again, err := service.InspectSession(ctx, scope, session.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(again.Session.AgentRevision).To(Equal(first.RevisionID))
	})

	It("admits equal Input once and rejects conflicting reuse of its idempotency key", func() {
		session := createSession(service, ctx, scope)
		request := agentruntime.SendInputRequest{
			SessionID:      session.ID,
			IdempotencyKey: "input-one",
			Parts:          []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}},
		}
		first, err := service.SendInput(ctx, scope, request)
		Expect(err).NotTo(HaveOccurred())
		second, err := service.SendInput(ctx, scope, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(second).To(Equal(first))

		request.Parts[0].Text = "different"
		_, err = service.SendInput(ctx, scope, request)
		Expect(err).To(MatchError(ContainSubstring("idempotency key conflicts")))
		var runtimeError *agentruntime.Error
		Expect(stderrors.As(err, &runtimeError)).To(BeTrue())
		Expect(runtimeError.Failure.Code).To(Equal(agentruntime.FailureConflict))
	})

	It("copies admitted content and rejects unbounded or structurally invalid parts", func() {
		session := createSession(service, ctx, scope)
		request := agentruntime.SendInputRequest{
			SessionID:      session.ID,
			IdempotencyKey: "immutable-input",
			Parts:          []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "original"}},
		}
		first, err := service.SendInput(ctx, scope, request)
		Expect(err).NotTo(HaveOccurred())
		first.Input.Parts[0].Text = "caller mutation"
		request.Parts[0].Text = "caller mutation"

		request.Parts[0].Text = "original"
		again, err := service.SendInput(ctx, scope, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(again.Input.Parts[0].Text).To(Equal("original"))

		_, err = service.SendInput(ctx, scope, agentruntime.SendInputRequest{
			SessionID: session.ID, IdempotencyKey: "too-large",
			Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: string(make([]byte, agentruntime.MaxTextPartBytes+1))}},
		})
		Expect(err).To(MatchError(ContainSubstring("invalid or unbounded")))
	})

	It("serializes concurrent Input into one active Turn and a complete ordered queue", func() {
		session := createSession(service, ctx, scope)
		const count = 24
		results := make(chan agentruntime.SendInputResult, count)
		errors := make(chan error, count)
		var wait sync.WaitGroup
		for index := range count {
			wait.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wait.Done()
				result, err := service.SendInput(ctx, scope, agentruntime.SendInputRequest{
					SessionID:      session.ID,
					IdempotencyKey: fmt.Sprintf("input-%02d", index),
					Parts:          []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: fmt.Sprintf("value-%02d", index)}},
				})
				if err != nil {
					errors <- err
					return
				}
				results <- result
			}()
		}
		wait.Wait()
		close(errors)
		close(results)
		Expect(errors).To(BeEmpty())

		positions := make(map[uint64]struct{}, count)
		active := 0
		for result := range results {
			positions[result.Turn.Position] = struct{}{}
			if result.Turn.State == agentruntime.TurnRunning {
				active++
			}
		}
		Expect(positions).To(HaveLen(count))
		for position := uint64(1); position <= count; position++ {
			Expect(positions).To(HaveKey(position))
		}
		Expect(active).To(Equal(1))

		view, err := service.InspectSession(ctx, scope, session.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(view.ActiveTurn).NotTo(BeNil())
		Expect(view.QueuedTurns).To(HaveLen(count - 1))
		for index, queued := range view.QueuedTurns {
			Expect(queued.Position).To(Equal(uint64(index + 2)))
			Expect(queued.State).To(Equal(agentruntime.TurnQueued))
		}
	})

	It("settles each Turn once and advances the next queued Turn", func() {
		session := createSession(service, ctx, scope)
		first := sendText(service, ctx, scope, session.ID, "first", "one")
		second := sendText(service, ctx, scope, session.ID, "second", "two")

		completed, err := service.CompleteTurn(ctx, scope, session.ID, first.Turn.ID, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(completed.State).To(Equal(agentruntime.TurnSucceeded))
		again, err := service.CompleteTurn(ctx, scope, session.ID, first.Turn.ID, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(again).To(Equal(completed))

		view, err := service.InspectSession(ctx, scope, session.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(view.ActiveTurn.ID).To(Equal(second.Turn.ID))
		Expect(view.ActiveTurn.State).To(Equal(agentruntime.TurnRunning))
	})

	It("cancels explicitly, promotes queued work, and makes duplicate cancellation idempotent", func() {
		session := createSession(service, ctx, scope)
		first := sendText(service, ctx, scope, session.ID, "first", "one")
		second := sendText(service, ctx, scope, session.ID, "second", "two")
		request := agentruntime.CancelTurnRequest{TurnID: first.Turn.ID, IdempotencyKey: "cancel-first"}

		cancelled, err := service.CancelTurn(ctx, scope, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(cancelled.State).To(Equal(agentruntime.TurnCancelled))
		again, err := service.CancelTurn(ctx, scope, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(again).To(Equal(cancelled))

		view, err := service.InspectSession(ctx, scope, session.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(view.ActiveTurn.ID).To(Equal(second.Turn.ID))
	})

	It("cancels a queued Turn without starting another Turn beside active work", func() {
		session := createSession(service, ctx, scope)
		first := sendText(service, ctx, scope, session.ID, "first", "one")
		second := sendText(service, ctx, scope, session.ID, "second", "two")
		third := sendText(service, ctx, scope, session.ID, "third", "three")

		cancelled, err := service.CancelTurn(ctx, scope, agentruntime.CancelTurnRequest{TurnID: second.Turn.ID, IdempotencyKey: "cancel-second"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cancelled.State).To(Equal(agentruntime.TurnCancelled))

		view, err := service.InspectSession(ctx, scope, session.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(view.ActiveTurn.ID).To(Equal(first.Turn.ID))
		Expect(view.QueuedTurns).To(ConsistOf(WithTransform(func(turn agentruntime.Turn) agentruntime.TurnID { return turn.ID }, Equal(third.Turn.ID))))
	})

	It("closes admission, drains accepted Turns, and completes exactly once", func() {
		session := createSession(service, ctx, scope)
		turn := sendText(service, ctx, scope, session.ID, "first", "one")
		closing, err := service.CloseSession(ctx, scope, agentruntime.CloseSessionRequest{SessionID: session.ID, IdempotencyKey: "close"})
		Expect(err).NotTo(HaveOccurred())
		Expect(closing.State).To(Equal(agentruntime.SessionClosing))

		_, err = service.SendInput(ctx, scope, agentruntime.SendInputRequest{
			SessionID: session.ID, IdempotencyKey: "after-close",
			Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "rejected"}},
		})
		Expect(err).To(MatchError(ContainSubstring("does not accept new Input")))

		_, err = service.CompleteTurn(ctx, scope, session.ID, turn.Turn.ID, nil)
		Expect(err).NotTo(HaveOccurred())
		view, err := service.InspectSession(ctx, scope, session.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(view.Session.State).To(Equal(agentruntime.SessionCompleted))
		Expect(view.ActiveTurn).To(BeNil())

		again, err := service.CloseSession(ctx, scope, agentruntime.CloseSessionRequest{SessionID: session.ID, IdempotencyKey: "close"})
		Expect(err).NotTo(HaveOccurred())
		Expect(again.State).To(Equal(agentruntime.SessionCompleted))
	})

	It("preserves one safe failed outcome without exposing its mutable details", func() {
		session := createSession(service, ctx, scope)
		turn := sendText(service, ctx, scope, session.ID, "first", "one")
		failure := &agentruntime.Failure{
			Code: agentruntime.FailureUnavailable, Message: "model temporarily unavailable", Retryable: true,
			Details: map[string]string{"phase": "invoke"},
		}
		failed, err := service.CompleteTurn(ctx, scope, session.ID, turn.Turn.ID, failure)
		Expect(err).NotTo(HaveOccurred())
		Expect(failed.State).To(Equal(agentruntime.TurnFailed))
		failure.Details["phase"] = "caller mutation"
		failed.Failure.Details["phase"] = "result mutation"

		again, err := service.CompleteTurn(ctx, scope, session.ID, turn.Turn.ID, &agentruntime.Failure{
			Code: agentruntime.FailureUnavailable, Message: "model temporarily unavailable", Retryable: true,
			Details: map[string]string{"phase": "invoke"},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(again.Failure.Details["phase"]).To(Equal("invoke"))
	})

	It("commits exactly one terminal outcome when completion races cancellation", func() {
		session := createSession(service, ctx, scope)
		turn := sendText(service, ctx, scope, session.ID, "first", "one")
		results := make(chan agentruntime.Turn, 2)
		errors := make(chan error, 2)
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer GinkgoRecover()
			defer wait.Done()
			result, err := service.CompleteTurn(ctx, scope, session.ID, turn.Turn.ID, nil)
			results <- result
			errors <- err
		}()
		go func() {
			defer GinkgoRecover()
			defer wait.Done()
			result, err := service.CancelTurn(ctx, scope, agentruntime.CancelTurnRequest{TurnID: turn.Turn.ID, IdempotencyKey: "racing-cancel"})
			results <- result
			errors <- err
		}()
		wait.Wait()
		close(results)
		close(errors)

		succeeded := 0
		for err := range errors {
			if err == nil {
				succeeded++
				continue
			}
			Expect(err).To(MatchError(ContainSubstring("terminal outcome")))
		}
		Expect(succeeded).To(Equal(1))
		page, err := service.Events(ctx, scope, session.ID, "", 100)
		Expect(err).NotTo(HaveOccurred())
		terminalEvents := 0
		for _, event := range page.Events {
			if event.Kind == agentruntime.EventTurnSucceeded || event.Kind == agentruntime.EventTurnCancelled {
				terminalEvents++
			}
		}
		Expect(terminalEvents).To(Equal(1))
	})

	It("replays ordered events and signals an explicit gap for a compacted Cursor", func() {
		session := createSession(service, ctx, scope)
		sendText(service, ctx, scope, session.ID, "first", "one")
		page, err := service.Events(ctx, scope, session.ID, "", 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(page.Events).To(HaveLen(3))
		Expect(page.Events[0].Kind).To(Equal(agentruntime.EventSessionCreated))
		Expect(page.Events[1].Kind).To(Equal(agentruntime.EventInputAccepted))
		Expect(page.Events[2].Kind).To(Equal(agentruntime.EventTurnStarted))
		for index, event := range page.Events {
			Expect(event.Sequence).To(Equal(uint64(index + 1)))
		}

		oldCursor := page.Events[0].Cursor
		Expect(service.CompactEvents(ctx, scope, session.ID, 2)).To(Succeed())
		page, err = service.Events(ctx, scope, session.ID, oldCursor, 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(page.Events).To(BeEmpty())
		Expect(page.Gap).NotTo(BeNil())
		Expect(page.Gap.RequestedAfter).To(Equal(oldCursor))
		Expect(page.Gap.InspectSession).To(BeTrue())
		Expect(page.Gap.Earliest).To(Equal(pageOrFail(service, ctx, scope, session.ID).Events[0].Cursor))
	})

	It("pages from the last observed opaque Cursor without replaying earlier events", func() {
		session := createSession(service, ctx, scope)
		sendText(service, ctx, scope, session.ID, "first", "one")
		first, err := service.Events(ctx, scope, session.ID, "", 2)
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Events).To(HaveLen(2))
		Expect(first.NextCursor).To(Equal(first.Events[1].Cursor))

		second, err := service.Events(ctx, scope, session.ID, first.NextCursor, 2)
		Expect(err).NotTo(HaveOccurred())
		Expect(second.Events).To(HaveLen(1))
		Expect(second.Events[0].Sequence).To(Equal(uint64(3)))
		Expect(second.Gap).To(BeNil())
	})

	It("does not commit a transition after context cancellation", func() {
		session := createSession(service, ctx, scope)
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := service.SendInput(cancelled, scope, agentruntime.SendInputRequest{
			SessionID:      session.ID,
			IdempotencyKey: "cancelled-before-admission",
			Parts:          []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "never committed"}},
		})
		Expect(err).To(MatchError(context.Canceled))

		view, err := service.InspectSession(ctx, scope, session.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(view.ActiveTurn).To(BeNil())
		Expect(view.QueuedTurns).To(BeEmpty())
	})

	It("rechecks cancellation after transition evaluation and before commit", func() {
		transitionContext, cancel := context.WithCancel(ctx)
		ids := &cancellingSource{cancel: cancel}
		cancelAware, err := kernel.New(fakeClock, ids, kernel.NewMemoryRepository(), []string{"balanced"})
		Expect(err).NotTo(HaveOccurred())
		request := agentruntime.CreateAgentRequest{
			IdempotencyKey: "cancel-during-transition", Name: "assistant",
			ModelProfile: "balanced", Instructions: "Be useful.",
		}

		_, err = cancelAware.CreateAgent(transitionContext, scope, request)
		Expect(err).To(MatchError(context.Canceled))
		created, err := cancelAware.CreateAgent(ctx, scope, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(created.ID.String()).To(Equal("agent_0000000000000003"))
		Expect(created.RevisionID.String()).To(Equal("arev_0000000000000004"))
	})

	It("hides resources owned by another tenant", func() {
		session := createSession(service, ctx, scope)
		other, err := kernel.ParseScope("tenant-b")
		Expect(err).NotTo(HaveOccurred())
		_, err = service.InspectSession(ctx, other, session.ID)
		Expect(err).To(MatchError(ContainSubstring("not found")))
	})
})

func createSession(service *kernel.Kernel, ctx context.Context, scope kernel.Scope) agentruntime.Session {
	agent, err := service.CreateAgent(ctx, scope, agentruntime.CreateAgentRequest{
		IdempotencyKey: "agent",
		Name:           "assistant",
		ModelProfile:   "balanced",
		Instructions:   "Be useful.",
	})
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	session, err := service.CreateSession(ctx, scope, agentruntime.CreateSessionRequest{IdempotencyKey: "session", AgentRevision: agent.RevisionID})
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return session
}

func sendText(service *kernel.Kernel, ctx context.Context, scope kernel.Scope, sessionID agentruntime.SessionID, key, text string) agentruntime.SendInputResult {
	result, err := service.SendInput(ctx, scope, agentruntime.SendInputRequest{
		SessionID: sessionID, IdempotencyKey: key,
		Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: text}},
	})
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return result
}

func pageOrFail(service *kernel.Kernel, ctx context.Context, scope kernel.Scope, sessionID agentruntime.SessionID) agentruntime.EventPage {
	page, err := service.Events(ctx, scope, sessionID, "", 100)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return page
}
