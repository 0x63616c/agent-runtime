package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0x63616c/agent-runtime/internal/clock"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

const (
	maxNameBytes         = 128
	maxInstructionsBytes = 256 * 1024
	maxTools             = 64
	maxEventPage         = 1000
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// IDSource supplies opaque, non-secret 16-character identifier payloads.
type IDSource interface {
	Next() (string, error)
}

// Kernel coordinates deterministic transitions through one atomic Repository port.
type Kernel struct {
	clock    clock.Clock
	ids      IDSource
	store    Repository
	profiles map[string]struct{}
}

// New constructs a valid Kernel with explicit time, entropy, state, and model-profile dependencies.
func New(source clock.Clock, ids IDSource, store Repository, profiles []string) (*Kernel, error) {
	if source == nil || ids == nil || store == nil {
		return nil, errors.New("create agent kernel: clock, ID source, and repository are required")
	}
	configured := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		if !safeName(profile) {
			return nil, errors.New("create agent kernel: invalid model profile")
		}
		configured[profile] = struct{}{}
	}
	if len(configured) == 0 {
		return nil, errors.New("create agent kernel: at least one model profile is required")
	}
	return &Kernel{clock: source, ids: ids, store: store, profiles: configured}, nil
}

// CreateAgent registers the first immutable revision of an Agent specification.
func (kernel *Kernel) CreateAgent(ctx context.Context, scope Scope, request agentruntime.CreateAgentRequest) (agentruntime.AgentSpecification, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.AgentSpecification{}, err
	}
	digest, err := canonicalDigest(struct {
		Name, ModelProfile, Instructions string
		Tools                            []agentruntime.ToolDefinition
	}{request.Name, request.ModelProfile, request.Instructions, append([]agentruntime.ToolDefinition(nil), request.Tools...)})
	if err != nil {
		return agentruntime.AgentSpecification{}, internalFailure("create agent", err)
	}
	var result agentruntime.AgentSpecification
	err = kernel.store.Transact(ctx, scope, func(state *TenantState) error {
		if record, ok := state.idempotency[request.IdempotencyKey]; ok {
			if record.command != "create_agent" || record.digest != digest {
				return conflict("idempotency key conflicts with another mutation")
			}
			result = state.revisions[record.revision].Clone()
			return nil
		}
		if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
			return err
		}
		if err := kernel.validateAgent(request.Name, request.ModelProfile, request.Instructions, request.Tools); err != nil {
			return err
		}
		agentID, err := kernel.newAgentID()
		if err != nil {
			return err
		}
		revisionID, err := kernel.newRevisionID()
		if err != nil {
			return err
		}
		result = agentruntime.AgentSpecification{
			ID: agentID, RevisionID: revisionID, Revision: 1, Name: request.Name,
			ModelProfile: request.ModelProfile, Instructions: request.Instructions,
			Tools: append([]agentruntime.ToolDefinition(nil), request.Tools...), CreatedAt: kernel.now(),
		}
		state.agents[agentID] = agentRecord{id: agentID, revisions: []agentruntime.AgentSpecification{result.Clone()}}
		state.revisions[revisionID] = result.Clone()
		state.idempotency[request.IdempotencyKey] = idempotencyRecord{command: "create_agent", digest: digest, agent: agentID, revision: revisionID}
		return nil
	})
	return result.Clone(), err
}

// ReviseAgent creates another immutable revision without changing existing Sessions.
func (kernel *Kernel) ReviseAgent(ctx context.Context, scope Scope, request agentruntime.ReviseAgentRequest) (agentruntime.AgentSpecification, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.AgentSpecification{}, err
	}
	if _, err := agentruntime.ParseAgentID(request.AgentID.String()); err != nil {
		return agentruntime.AgentSpecification{}, invalid("invalid Agent ID")
	}
	digest, err := canonicalDigest(request)
	if err != nil {
		return agentruntime.AgentSpecification{}, internalFailure("revise agent", err)
	}
	var result agentruntime.AgentSpecification
	err = kernel.store.Transact(ctx, scope, func(state *TenantState) error {
		if record, ok := state.idempotency[request.IdempotencyKey]; ok {
			if record.command != "revise_agent" || record.digest != digest {
				return conflict("idempotency key conflicts with another mutation")
			}
			result = state.revisions[record.revision].Clone()
			return nil
		}
		if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
			return err
		}
		if err := kernel.validateAgent("revision", request.ModelProfile, request.Instructions, request.Tools); err != nil {
			return err
		}
		agent, ok := state.agents[request.AgentID]
		if !ok {
			return notFound("Agent not found")
		}
		revisionID, err := kernel.newRevisionID()
		if err != nil {
			return err
		}
		result = agentruntime.AgentSpecification{
			ID: request.AgentID, RevisionID: revisionID, Revision: uint64(len(agent.revisions) + 1),
			Name: agent.revisions[0].Name, ModelProfile: request.ModelProfile,
			Instructions: request.Instructions, Tools: append([]agentruntime.ToolDefinition(nil), request.Tools...), CreatedAt: kernel.now(),
		}
		agent.revisions = append(agent.revisions, result.Clone())
		state.agents[request.AgentID] = agent
		state.revisions[revisionID] = result.Clone()
		state.idempotency[request.IdempotencyKey] = idempotencyRecord{command: "revise_agent", digest: digest, agent: request.AgentID, revision: revisionID}
		return nil
	})
	return result.Clone(), err
}

// GetAgentRevision returns one immutable revision from its owning Agent catalog.
func (kernel *Kernel) GetAgentRevision(ctx context.Context, scope Scope, agentID agentruntime.AgentID, revisionID agentruntime.AgentRevisionID) (agentruntime.AgentSpecification, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.AgentSpecification{}, err
	}
	var result agentruntime.AgentSpecification
	err := kernel.store.View(ctx, scope, func(state *TenantState) error {
		revision, ok := state.revisions[revisionID]
		if !ok || revision.ID != agentID {
			return notFound("Agent revision not found")
		}
		result = revision.Clone()
		return nil
	})
	return result.Clone(), err
}

// ResolveAgentRevision returns one immutable revision when its opaque revision ID is already authorized by the caller's catalog scope.
func (kernel *Kernel) ResolveAgentRevision(ctx context.Context, scope Scope, revisionID agentruntime.AgentRevisionID) (agentruntime.AgentSpecification, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.AgentSpecification{}, err
	}
	if _, err := agentruntime.ParseAgentRevisionID(revisionID.String()); err != nil {
		return agentruntime.AgentSpecification{}, invalid("invalid Agent revision ID")
	}
	var result agentruntime.AgentSpecification
	err := kernel.store.View(ctx, scope, func(state *TenantState) error {
		revision, ok := state.revisions[revisionID]
		if !ok {
			return notFound("Agent revision not found")
		}
		result = revision.Clone()
		return nil
	})
	return result.Clone(), err
}

// CreateSession creates a durable Session pinned to one exact Agent revision.
func (kernel *Kernel) CreateSession(ctx context.Context, scope Scope, request agentruntime.CreateSessionRequest) (agentruntime.Session, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.Session{}, err
	}
	digest, err := canonicalDigest(request)
	if err != nil {
		return agentruntime.Session{}, internalFailure("create session", err)
	}
	var result agentruntime.Session
	err = kernel.store.Transact(ctx, scope, func(state *TenantState) error {
		if record, ok := state.idempotency[request.IdempotencyKey]; ok {
			if record.command != "create_session" || record.digest != digest {
				return conflict("idempotency key conflicts with another mutation")
			}
			result = state.sessions[record.session].session
			return nil
		}
		if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
			return err
		}
		revision, ok := state.revisions[request.AgentRevision]
		if !ok {
			return notFound("Agent revision not found")
		}
		sessionID, err := kernel.newSessionID()
		if err != nil {
			return err
		}
		timestamp := kernel.now()
		result = agentruntime.Session{ID: sessionID, AgentID: revision.ID, AgentRevision: revision.RevisionID, State: agentruntime.SessionOpen, CreatedAt: timestamp, UpdatedAt: timestamp}
		record := sessionRecord{session: result, inputs: make(map[agentruntime.InputID]agentruntime.Input), trimmed: make(map[agentruntime.Cursor]struct{})}
		if err := kernel.appendEvent(&record, agentruntime.EventSessionCreated, "", ""); err != nil {
			return err
		}
		state.sessions[sessionID] = record
		state.idempotency[request.IdempotencyKey] = idempotencyRecord{command: "create_session", digest: digest, session: sessionID}
		return nil
	})
	return result, err
}

// CreateSessionFromRevision pins a principal-owned Session to a revision resolved by an authorized catalog boundary.
func (kernel *Kernel) CreateSessionFromRevision(ctx context.Context, scope Scope, request agentruntime.CreateSessionRequest, revision agentruntime.AgentSpecification) (agentruntime.Session, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.Session{}, err
	}
	if request.AgentRevision != revision.RevisionID || revision.ID == "" || revision.Revision == 0 {
		return agentruntime.Session{}, invalid("resolved Agent revision does not match the Session request")
	}
	if _, err := agentruntime.ParseAgentID(revision.ID.String()); err != nil {
		return agentruntime.Session{}, invalid("resolved Agent revision has an invalid Agent ID")
	}
	if _, err := agentruntime.ParseAgentRevisionID(revision.RevisionID.String()); err != nil {
		return agentruntime.Session{}, invalid("resolved Agent revision has an invalid revision ID")
	}
	digest, err := canonicalDigest(request)
	if err != nil {
		return agentruntime.Session{}, internalFailure("create session", err)
	}
	var result agentruntime.Session
	err = kernel.store.Transact(ctx, scope, func(state *TenantState) error {
		if record, ok := state.idempotency[request.IdempotencyKey]; ok {
			if record.command != "create_session" || record.digest != digest {
				return conflict("idempotency key conflicts with another mutation")
			}
			result = state.sessions[record.session].session
			return nil
		}
		if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
			return err
		}
		if existing, ok := state.revisions[revision.RevisionID]; ok {
			existingDigest, digestErr := canonicalDigest(existing)
			if digestErr != nil {
				return internalFailure("compare resolved Agent revision", digestErr)
			}
			revisionDigest, digestErr := canonicalDigest(revision)
			if digestErr != nil {
				return internalFailure("compare resolved Agent revision", digestErr)
			}
			if existingDigest != revisionDigest {
				return conflict("resolved Agent revision conflicts with pinned revision")
			}
		} else {
			state.revisions[revision.RevisionID] = revision.Clone()
		}
		sessionID, createErr := kernel.newSessionID()
		if createErr != nil {
			return createErr
		}
		timestamp := kernel.now()
		result = agentruntime.Session{ID: sessionID, AgentID: revision.ID, AgentRevision: revision.RevisionID, State: agentruntime.SessionOpen, CreatedAt: timestamp, UpdatedAt: timestamp}
		record := sessionRecord{session: result, inputs: make(map[agentruntime.InputID]agentruntime.Input), trimmed: make(map[agentruntime.Cursor]struct{})}
		if appendErr := kernel.appendEvent(&record, agentruntime.EventSessionCreated, "", ""); appendErr != nil {
			return appendErr
		}
		state.sessions[sessionID] = record
		state.idempotency[request.IdempotencyKey] = idempotencyRecord{command: "create_session", digest: digest, session: sessionID}
		return nil
	})
	return result, err
}

// SendInput idempotently admits bounded content and creates exactly one ordered Turn.
func (kernel *Kernel) SendInput(ctx context.Context, scope Scope, request agentruntime.SendInputRequest) (agentruntime.SendInputResult, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.SendInputResult{}, err
	}
	digest, err := canonicalDigest(struct {
		SessionID agentruntime.SessionID
		Parts     []agentruntime.ContentPart
	}{request.SessionID, cloneParts(request.Parts)})
	if err != nil {
		return agentruntime.SendInputResult{}, internalFailure("send input", err)
	}
	var result agentruntime.SendInputResult
	err = kernel.store.Transact(ctx, scope, func(state *TenantState) error {
		if record, ok := state.idempotency[request.IdempotencyKey]; ok {
			if record.command != "send_input" || record.digest != digest {
				return conflict("idempotency key conflicts with another mutation")
			}
			session := state.sessions[record.session]
			result = resultFor(session, record.input, record.turn)
			return nil
		}
		if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
			return err
		}
		if err := validateInput(request); err != nil {
			return err
		}
		session, ok := state.sessions[request.SessionID]
		if !ok {
			return notFound("Session not found")
		}
		if session.session.State != agentruntime.SessionOpen {
			return conflict("Session does not accept new Input")
		}
		inputID, err := kernel.newInputID()
		if err != nil {
			return err
		}
		turnID, err := kernel.newTurnID()
		if err != nil {
			return err
		}
		timestamp := kernel.now()
		input := agentruntime.Input{ID: inputID, Parts: cloneParts(request.Parts), AcceptedAt: timestamp}
		turn := agentruntime.Turn{ID: turnID, InputID: inputID, Position: uint64(len(session.turns) + 1), State: agentruntime.TurnQueued}
		session.inputs[inputID] = input.Clone()
		session.turns = append(session.turns, turn)
		if err := kernel.appendEvent(&session, agentruntime.EventInputAccepted, inputID, turnID); err != nil {
			return err
		}
		if activeTurnIndex(session) < 0 {
			index := len(session.turns) - 1
			session.turns[index].State = agentruntime.TurnRunning
			session.turns[index].StartedAt = timePointer(timestamp)
			if err := kernel.appendEvent(&session, agentruntime.EventTurnStarted, inputID, turnID); err != nil {
				return err
			}
		} else if err := kernel.appendEvent(&session, agentruntime.EventTurnQueued, inputID, turnID); err != nil {
			return err
		}
		session.session.UpdatedAt = timestamp
		state.sessions[request.SessionID] = session
		state.idempotency[request.IdempotencyKey] = idempotencyRecord{command: "send_input", digest: digest, session: request.SessionID, input: inputID, turn: turnID}
		result = resultFor(session, inputID, turnID)
		return nil
	})
	return cloneSendResult(result), err
}

// CompleteTurn records one terminal outcome and advances the next queued Turn.
func (kernel *Kernel) CompleteTurn(ctx context.Context, scope Scope, sessionID agentruntime.SessionID, turnID agentruntime.TurnID, failure *agentruntime.Failure) (agentruntime.Turn, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.Turn{}, err
	}
	if err := validateFailure(failure); err != nil {
		return agentruntime.Turn{}, err
	}
	var result agentruntime.Turn
	err := kernel.store.Transact(ctx, scope, func(state *TenantState) error {
		session, ok := state.sessions[sessionID]
		if !ok {
			return notFound("Session not found")
		}
		index := turnIndex(session, turnID)
		if index < 0 {
			return notFound("Turn not found")
		}
		turn := session.turns[index]
		if terminal(turn.State) {
			if equalFailure(turn.Failure, failure) && turn.State != agentruntime.TurnCancelled {
				result = turn.Clone()
				return nil
			}
			return conflict("Turn already has a terminal outcome")
		}
		if turn.State != agentruntime.TurnRunning {
			return conflict("only the active Turn can complete")
		}
		timestamp := kernel.now()
		turn.CompletedAt = timePointer(timestamp)
		turn.Failure = failure.Clone()
		kind := agentruntime.EventTurnSucceeded
		turn.State = agentruntime.TurnSucceeded
		if failure != nil {
			turn.State = agentruntime.TurnFailed
			kind = agentruntime.EventTurnFailed
		}
		session.turns[index] = turn
		if err := kernel.appendEvent(&session, kind, turn.InputID, turn.ID); err != nil {
			return err
		}
		if err := kernel.advance(&session, timestamp); err != nil {
			return err
		}
		session.session.UpdatedAt = timestamp
		state.sessions[sessionID] = session
		result = turn.Clone()
		return nil
	})
	return result.Clone(), err
}

// CancelTurn records explicit cancellation exactly once and advances remaining work.
func (kernel *Kernel) CancelTurn(ctx context.Context, scope Scope, request agentruntime.CancelTurnRequest) (agentruntime.Turn, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.Turn{}, err
	}
	if _, err := agentruntime.ParseSessionID(request.SessionID.String()); err != nil {
		return agentruntime.Turn{}, invalid("invalid Session ID")
	}
	digest, err := canonicalDigest(struct {
		SessionID agentruntime.SessionID
		TurnID    agentruntime.TurnID
	}{request.SessionID, request.TurnID})
	if err != nil {
		return agentruntime.Turn{}, internalFailure("cancel turn", err)
	}
	var result agentruntime.Turn
	err = kernel.store.Transact(ctx, scope, func(state *TenantState) error {
		if record, ok := state.idempotency[request.IdempotencyKey]; ok {
			if record.command != "cancel_turn" || record.digest != digest {
				return conflict("idempotency key conflicts with another mutation")
			}
			session := state.sessions[record.session]
			result = session.turns[turnIndex(session, record.turn)].Clone()
			return nil
		}
		if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
			return err
		}
		sessionID, session, index, ok := findTurn(state, request.TurnID)
		if !ok || sessionID != request.SessionID {
			return notFound("Turn not found")
		}
		turn := session.turns[index]
		if terminal(turn.State) {
			return conflict("Turn already has a terminal outcome")
		}
		timestamp := kernel.now()
		turn.State = agentruntime.TurnCancelled
		turn.CompletedAt = timePointer(timestamp)
		session.turns[index] = turn
		if err := kernel.appendEvent(&session, agentruntime.EventTurnCancelled, turn.InputID, turn.ID); err != nil {
			return err
		}
		if err := kernel.advance(&session, timestamp); err != nil {
			return err
		}
		session.session.UpdatedAt = timestamp
		state.sessions[sessionID] = session
		state.idempotency[request.IdempotencyKey] = idempotencyRecord{command: "cancel_turn", digest: digest, session: sessionID, turn: request.TurnID}
		result = turn.Clone()
		return nil
	})
	return result.Clone(), err
}

// CloseSession stops new Input admission and drains all previously accepted work.
func (kernel *Kernel) CloseSession(ctx context.Context, scope Scope, request agentruntime.CloseSessionRequest) (agentruntime.Session, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.Session{}, err
	}
	digest, err := canonicalDigest(request.SessionID)
	if err != nil {
		return agentruntime.Session{}, internalFailure("close session", err)
	}
	var result agentruntime.Session
	err = kernel.store.Transact(ctx, scope, func(state *TenantState) error {
		if record, ok := state.idempotency[request.IdempotencyKey]; ok {
			if record.command != "close_session" || record.digest != digest {
				return conflict("idempotency key conflicts with another mutation")
			}
			result = state.sessions[record.session].session
			return nil
		}
		if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
			return err
		}
		session, ok := state.sessions[request.SessionID]
		if !ok {
			return notFound("Session not found")
		}
		if session.session.State != agentruntime.SessionOpen {
			return conflict("Session cannot enter closing state")
		}
		timestamp := kernel.now()
		session.session.State = agentruntime.SessionClosing
		session.session.UpdatedAt = timestamp
		if err := kernel.appendEvent(&session, agentruntime.EventSessionClosing, "", ""); err != nil {
			return err
		}
		if activeTurnIndex(session) < 0 {
			session.session.State = agentruntime.SessionCompleted
			if err := kernel.appendEvent(&session, agentruntime.EventSessionCompleted, "", ""); err != nil {
				return err
			}
		}
		state.sessions[request.SessionID] = session
		state.idempotency[request.IdempotencyKey] = idempotencyRecord{command: "close_session", digest: digest, session: request.SessionID}
		result = session.session
		return nil
	})
	return result, err
}

// CancelSession terminally cancels an owner Session after accepted work drained.
func (kernel *Kernel) CancelSession(ctx context.Context, scope Scope, request agentruntime.CancelSessionRequest) (agentruntime.Session, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.Session{}, err
	}
	digest, err := canonicalDigest(request.SessionID)
	if err != nil {
		return agentruntime.Session{}, internalFailure("cancel session", err)
	}
	var result agentruntime.Session
	err = kernel.store.Transact(ctx, scope, func(state *TenantState) error {
		if record, ok := state.idempotency[request.IdempotencyKey]; ok {
			if record.command != "cancel_session" || record.digest != digest {
				return conflict("idempotency key conflicts with another mutation")
			}
			result = state.sessions[record.session].session
			return nil
		}
		if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
			return err
		}
		session, ok := state.sessions[request.SessionID]
		if !ok {
			return notFound("Session not found")
		}
		if session.session.State != agentruntime.SessionOpen && session.session.State != agentruntime.SessionClosing || activeTurnIndex(session) >= 0 || queuedTurnIndex(session) >= 0 {
			return conflict("Session cannot enter cancelled state")
		}
		timestamp := kernel.now()
		session.session.State = agentruntime.SessionCancelled
		session.session.UpdatedAt = timestamp
		if err := kernel.appendEvent(&session, agentruntime.EventSessionCancelled, "", ""); err != nil {
			return err
		}
		state.sessions[request.SessionID] = session
		state.idempotency[request.IdempotencyKey] = idempotencyRecord{command: "cancel_session", digest: digest, session: request.SessionID}
		result = session.session
		return nil
	})
	return result, err
}

// InspectSession returns an immutable runtime-owned view with no backend identifiers.
func (kernel *Kernel) InspectSession(ctx context.Context, scope Scope, sessionID agentruntime.SessionID) (agentruntime.SessionView, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.SessionView{}, err
	}
	var result agentruntime.SessionView
	err := kernel.store.View(ctx, scope, func(state *TenantState) error {
		session, ok := state.sessions[sessionID]
		if !ok {
			return notFound("Session not found")
		}
		result.Session = session.session
		for _, turn := range session.turns {
			switch turn.State {
			case agentruntime.TurnRunning:
				clone := turn.Clone()
				result.ActiveTurn = &clone
			case agentruntime.TurnQueued:
				result.QueuedTurnCount++
				if len(result.QueuedTurns) < agentruntime.MaxSessionViewQueuedTurns {
					result.QueuedTurns = append(result.QueuedTurns, turn.Clone())
				}
			}
		}
		result.QueuedTurnsTruncated = result.QueuedTurnCount > uint64(len(result.QueuedTurns))
		start := len(session.events) - 20
		if start < 0 {
			start = 0
		}
		result.RecentEvents = append([]agentruntime.Event(nil), session.events[start:]...)
		return nil
	})
	return result.Clone(), err
}

// InspectTurn returns one immutable Turn snapshot from its owning Session.
func (kernel *Kernel) InspectTurn(ctx context.Context, scope Scope, sessionID agentruntime.SessionID, turnID agentruntime.TurnID) (agentruntime.Turn, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.Turn{}, err
	}
	var result agentruntime.Turn
	err := kernel.store.View(ctx, scope, func(state *TenantState) error {
		session, ok := state.sessions[sessionID]
		if !ok {
			return notFound("Turn not found")
		}
		index := turnIndex(session, turnID)
		if index < 0 {
			return notFound("Turn not found")
		}
		result = session.turns[index].Clone()
		return nil
	})
	return result.Clone(), err
}

// Events returns a bounded ordered page after an opaque Cursor or an explicit Gap.
func (kernel *Kernel) Events(ctx context.Context, scope Scope, sessionID agentruntime.SessionID, after agentruntime.Cursor, limit int) (agentruntime.EventPage, error) {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return agentruntime.EventPage{}, err
	}
	if limit < 1 || limit > maxEventPage {
		return agentruntime.EventPage{}, invalid("event page limit is outside the supported range")
	}
	if after != "" {
		if _, err := agentruntime.ParseCursor(after.String()); err != nil {
			return agentruntime.EventPage{}, invalid("invalid event Cursor")
		}
	}
	var result agentruntime.EventPage
	err := kernel.store.View(ctx, scope, func(state *TenantState) error {
		session, ok := state.sessions[sessionID]
		if !ok {
			return notFound("Session not found")
		}
		start := 0
		if after != "" {
			start = eventAfter(session.events, after)
			if start < 0 {
				earliest := agentruntime.Cursor("")
				if len(session.events) > 0 {
					earliest = session.events[0].Cursor
				}
				result.Gap = &agentruntime.EventGap{RequestedAfter: after, Earliest: earliest, InspectSession: true}
				return nil
			}
		}
		end := start + limit
		if end > len(session.events) {
			end = len(session.events)
		}
		result.Events = append([]agentruntime.Event(nil), session.events[start:end]...)
		if len(result.Events) > 0 {
			result.NextCursor = result.Events[len(result.Events)-1].Cursor
		} else {
			result.NextCursor = after
		}
		return nil
	})
	return result, err
}

// CompactEvents applies a deterministic retention boundary for cursor-gap tests and adapters.
func (kernel *Kernel) CompactEvents(ctx context.Context, scope Scope, sessionID agentruntime.SessionID, keep int) error {
	if err := kernel.validateScopeAndContext(ctx, scope); err != nil {
		return err
	}
	if keep < 1 {
		return invalid("event retention must keep at least one event")
	}
	return kernel.store.Transact(ctx, scope, func(state *TenantState) error {
		session, ok := state.sessions[sessionID]
		if !ok {
			return notFound("Session not found")
		}
		if len(session.events) <= keep {
			return nil
		}
		cut := len(session.events) - keep
		for _, event := range session.events[:cut] {
			session.trimmed[event.Cursor] = struct{}{}
		}
		session.events = append([]agentruntime.Event(nil), session.events[cut:]...)
		state.sessions[sessionID] = session
		return nil
	})
}

func (kernel *Kernel) validateScopeAndContext(ctx context.Context, scope Scope) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if _, err := ParseScope(string(scope)); err != nil {
		return invalid("invalid ownership scope")
	}
	return nil
}

func (kernel *Kernel) validateAgent(name, profile, instructions string, tools []agentruntime.ToolDefinition) error {
	if !safeName(name) || len(instructions) == 0 || len(instructions) > maxInstructionsBytes || !utf8.ValidString(instructions) {
		return invalid("Agent specification is invalid or unbounded")
	}
	if _, ok := kernel.profiles[profile]; !ok {
		return invalid("model profile is not configured")
	}
	if len(tools) > maxTools {
		return invalid("Agent specification has too many Tools")
	}
	seen := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		if !safeName(tool.Name) || len(tool.Description) == 0 || len(tool.Description) > 4096 || !utf8.ValidString(tool.Description) {
			return invalid("Tool definition is invalid or unbounded")
		}
		if _, exists := seen[tool.Name]; exists {
			return invalid("Tool definition name is duplicated")
		}
		seen[tool.Name] = struct{}{}
	}
	return nil
}

func validateInput(request agentruntime.SendInputRequest) error {
	if _, err := agentruntime.ParseSessionID(request.SessionID.String()); err != nil {
		return invalid("invalid Session ID")
	}
	if len(request.Parts) == 0 || len(request.Parts) > agentruntime.MaxInputParts {
		return invalid("Input content part count is outside the supported range")
	}
	for _, part := range request.Parts {
		switch part.Kind {
		case agentruntime.ContentText:
			if part.Text == "" || len(part.Text) > agentruntime.MaxTextPartBytes || !utf8.ValidString(part.Text) || part.Artifact != nil {
				return invalid("text Input part is invalid or unbounded")
			}
		case agentruntime.ContentArtifact:
			if part.Text != "" || part.Artifact == nil || part.Artifact.SizeBytes < 0 || part.Artifact.MediaType == "" || len(part.Artifact.MediaType) > 255 || !sha256Pattern.MatchString(part.Artifact.SHA256) {
				return invalid("Artifact Input part is invalid or unbounded")
			}
			if _, err := agentruntime.ParseArtifactID(part.Artifact.ID.String()); err != nil {
				return invalid("Artifact Input part has an invalid ID")
			}
		default:
			return invalid("Input content part kind is unsupported")
		}
	}
	return nil
}

func validateFailure(failure *agentruntime.Failure) error {
	if failure == nil {
		return nil
	}
	if failure.Code == "" || len(failure.Message) == 0 || len(failure.Message) > 1024 || !utf8.ValidString(failure.Message) || len(failure.Details) > 16 {
		return invalid("Turn Failure is invalid or unbounded")
	}
	for key, value := range failure.Details {
		if !safeName(key) || len(value) > 1024 || !utf8.ValidString(value) {
			return invalid("Turn Failure details are invalid or unbounded")
		}
	}
	return nil
}

func validateIdempotencyKey(key string) error {
	if len(key) == 0 || len(key) > agentruntime.MaxIdempotencyKeyBytes {
		return invalid("idempotency key is invalid or unbounded")
	}
	for _, character := range key {
		if character < 0x21 || character > 0x7e {
			return invalid("idempotency key contains an unsupported character")
		}
	}
	return nil
}

func safeName(value string) bool {
	if len(value) == 0 || len(value) > maxNameBytes {
		return false
	}
	for _, character := range value {
		if !nameCharacter(character) {
			return false
		}
	}
	return true
}

func nameCharacter(character rune) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') ||
		character == '-' || character == '_' || character == '.'
}

func (kernel *Kernel) appendEvent(session *sessionRecord, kind agentruntime.EventKind, inputID agentruntime.InputID, turnID agentruntime.TurnID) error {
	eventID, err := kernel.newEventID()
	if err != nil {
		return err
	}
	cursor, err := kernel.newCursor()
	if err != nil {
		return err
	}
	session.events = append(session.events, agentruntime.Event{
		ID: eventID, Cursor: cursor, Sequence: nextEventSequence(*session), Kind: kind,
		SessionID: session.session.ID, InputID: inputID, TurnID: turnID, OccurredAt: kernel.now(),
	})
	return nil
}

func (kernel *Kernel) advance(session *sessionRecord, timestamp time.Time) error {
	if activeTurnIndex(*session) >= 0 {
		return nil
	}
	queued := -1
	for index := range session.turns {
		if session.turns[index].State == agentruntime.TurnQueued {
			queued = index
			break
		}
	}
	if queued >= 0 {
		session.turns[queued].State = agentruntime.TurnRunning
		session.turns[queued].StartedAt = timePointer(timestamp)
		return kernel.appendEvent(session, agentruntime.EventTurnStarted, session.turns[queued].InputID, session.turns[queued].ID)
	}
	if session.session.State == agentruntime.SessionClosing {
		session.session.State = agentruntime.SessionCompleted
		return kernel.appendEvent(session, agentruntime.EventSessionCompleted, "", "")
	}
	return nil
}

func nextEventSequence(session sessionRecord) uint64 {
	if len(session.events) == 0 {
		return uint64(len(session.trimmed) + 1)
	}
	return session.events[len(session.events)-1].Sequence + 1
}

func activeTurnIndex(session sessionRecord) int {
	for index := range session.turns {
		if session.turns[index].State == agentruntime.TurnRunning {
			return index
		}
	}
	return -1
}

func queuedTurnIndex(session sessionRecord) int {
	for index := range session.turns {
		if session.turns[index].State == agentruntime.TurnQueued {
			return index
		}
	}
	return -1
}

func turnIndex(session sessionRecord, id agentruntime.TurnID) int {
	for index := range session.turns {
		if session.turns[index].ID == id {
			return index
		}
	}
	return -1
}

func findTurn(state *TenantState, id agentruntime.TurnID) (agentruntime.SessionID, sessionRecord, int, bool) {
	ids := make([]string, 0, len(state.sessions))
	byString := make(map[string]agentruntime.SessionID, len(state.sessions))
	for sessionID := range state.sessions {
		ids = append(ids, sessionID.String())
		byString[sessionID.String()] = sessionID
	}
	sort.Strings(ids)
	for _, value := range ids {
		sessionID := byString[value]
		session := state.sessions[sessionID]
		if index := turnIndex(session, id); index >= 0 {
			return sessionID, session, index, true
		}
	}
	return "", sessionRecord{}, -1, false
}

func terminal(state agentruntime.TurnState) bool {
	return state == agentruntime.TurnSucceeded || state == agentruntime.TurnFailed || state == agentruntime.TurnCancelled
}

func eventAfter(events []agentruntime.Event, cursor agentruntime.Cursor) int {
	for index, event := range events {
		if event.Cursor == cursor {
			return index + 1
		}
	}
	return -1
}

func resultFor(session sessionRecord, inputID agentruntime.InputID, turnID agentruntime.TurnID) agentruntime.SendInputResult {
	return agentruntime.SendInputResult{Input: session.inputs[inputID].Clone(), Turn: session.turns[turnIndex(session, turnID)].Clone()}
}

func cloneSendResult(result agentruntime.SendInputResult) agentruntime.SendInputResult {
	return agentruntime.SendInputResult{Input: result.Input.Clone(), Turn: result.Turn.Clone()}
}

func cloneParts(parts []agentruntime.ContentPart) []agentruntime.ContentPart {
	clone := make([]agentruntime.ContentPart, len(parts))
	for index := range parts {
		clone[index] = parts[index].Clone()
	}
	return clone
}

func equalFailure(left, right *agentruntime.Failure) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

func canonicalDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", errors.Wrap(err, "encode canonical mutation")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func timePointer(value time.Time) *time.Time { return &value }

func (kernel *Kernel) now() time.Time { return kernel.clock.Now().UTC() }

func (kernel *Kernel) payload(prefix string) (string, error) {
	payload, err := kernel.ids.Next()
	if err != nil {
		return "", internalFailure("allocate runtime identifier", err)
	}
	if len(payload) != 16 || strings.ContainsAny(payload, "_- ") {
		return "", internalFailure("allocate runtime identifier", errors.New("ID source returned invalid payload"))
	}
	return prefix + payload, nil
}

func (kernel *Kernel) newAgentID() (agentruntime.AgentID, error) {
	value, err := kernel.payload("agent_")
	if err != nil {
		return "", err
	}
	return agentruntime.ParseAgentID(value)
}
func (kernel *Kernel) newRevisionID() (agentruntime.AgentRevisionID, error) {
	value, err := kernel.payload("arev_")
	if err != nil {
		return "", err
	}
	return agentruntime.ParseAgentRevisionID(value)
}
func (kernel *Kernel) newSessionID() (agentruntime.SessionID, error) {
	value, err := kernel.payload("sess_")
	if err != nil {
		return "", err
	}
	return agentruntime.ParseSessionID(value)
}
func (kernel *Kernel) newInputID() (agentruntime.InputID, error) {
	value, err := kernel.payload("inpt_")
	if err != nil {
		return "", err
	}
	return agentruntime.ParseInputID(value)
}
func (kernel *Kernel) newTurnID() (agentruntime.TurnID, error) {
	value, err := kernel.payload("turn_")
	if err != nil {
		return "", err
	}
	return agentruntime.ParseTurnID(value)
}
func (kernel *Kernel) newEventID() (agentruntime.EventID, error) {
	value, err := kernel.payload("evt_")
	if err != nil {
		return "", err
	}
	return agentruntime.ParseEventID(value)
}
func (kernel *Kernel) newCursor() (agentruntime.Cursor, error) {
	value, err := kernel.payload("cur_")
	if err != nil {
		return "", err
	}
	return agentruntime.ParseCursor(value)
}

func invalid(message string) error {
	return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: message}}
}
func conflict(message string) error {
	return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureConflict, Message: message}}
}
func notFound(message string) error {
	return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: message}}
}
func internalFailure(operation string, cause error) error {
	_ = cause
	return &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureInternal, Message: operation + " failed"}}
}
