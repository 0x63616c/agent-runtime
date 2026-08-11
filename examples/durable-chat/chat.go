// Package durablechat is the public-contract Durable Chat example.
package durablechat

import (
	"context"
	"errors"
	"fmt"
	"strings"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// SessionClient is the deliberately narrow public SDK surface Durable Chat
// needs. It keeps the example independent of runtime implementation packages.
type SessionClient interface {
	CreateSession(context.Context, agentruntime.CreateSessionRequest) (agentruntime.Session, error)
	SendInput(context.Context, agentruntime.SendInputRequest) (agentruntime.SendInputResult, error)
	InspectSession(context.Context, agentruntime.SessionID) (agentruntime.SessionView, error)
	Events(context.Context, agentruntime.SessionID, agentruntime.Cursor, int) (agentruntime.EventPage, error)
	CancelTurn(context.Context, agentruntime.CancelTurnRequest) (agentruntime.Turn, error)
}

// KeySource creates a bounded idempotency key for one user action.
type KeySource interface {
	Next(string) (string, error)
}

// App coordinates Durable Chat commands entirely through the public SDK.
type App struct {
	client SessionClient
	keys   KeySource
}

// NewApp constructs one Durable Chat application controller.
func NewApp(client SessionClient, keys KeySource) (*App, error) {
	if client == nil || keys == nil {
		return nil, errors.New("create Durable Chat app: public client and idempotency keys are required")
	}
	return &App{client: client, keys: keys}, nil
}

// NewSession creates a Session pinned to the requested public Agent revision.
func (app *App) NewSession(ctx context.Context, revision agentruntime.AgentRevisionID) (agentruntime.Session, error) {
	if _, err := agentruntime.ParseAgentRevisionID(revision.String()); err != nil {
		return agentruntime.Session{}, errors.New("create Durable Chat session: Agent revision is invalid")
	}
	key, err := app.keys.Next("session")
	if err != nil {
		return agentruntime.Session{}, fmt.Errorf("create Durable Chat session: %w", err)
	}
	return app.client.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: key, AgentRevision: revision})
}

// Send queues one bounded text Input behind any active Turn.
func (app *App) Send(ctx context.Context, sessionID agentruntime.SessionID, text string) (agentruntime.SendInputResult, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil || strings.TrimSpace(text) == "" || len(text) > agentruntime.MaxTextPartBytes {
		return agentruntime.SendInputResult{}, errors.New("send Durable Chat message: session and bounded text are required")
	}
	key, err := app.keys.Next("message")
	if err != nil {
		return agentruntime.SendInputResult{}, fmt.Errorf("send Durable Chat message: %w", err)
	}
	return app.client.SendInput(ctx, agentruntime.SendInputRequest{SessionID: sessionID, IdempotencyKey: key, Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: text}}})
}

// Resume reads the durable Session projection after a server or browser restart.
func (app *App) Resume(ctx context.Context, sessionID agentruntime.SessionID) (agentruntime.SessionView, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return agentruntime.SessionView{}, errors.New("resume Durable Chat session: session is invalid")
	}
	return app.client.InspectSession(ctx, sessionID)
}

// Reconnect resumes Product-event observation from the caller's last opaque Cursor.
func (app *App) Reconnect(ctx context.Context, sessionID agentruntime.SessionID, cursor agentruntime.Cursor) (agentruntime.EventPage, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return agentruntime.EventPage{}, errors.New("reconnect Durable Chat events: session is invalid")
	}
	return app.client.Events(ctx, sessionID, cursor, 100)
}

// Cancel records a durable cancellation request for one public Turn.
func (app *App) Cancel(ctx context.Context, sessionID agentruntime.SessionID, turnID agentruntime.TurnID) (agentruntime.Turn, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return agentruntime.Turn{}, errors.New("cancel Durable Chat turn: session is invalid")
	}
	if _, err := agentruntime.ParseTurnID(turnID.String()); err != nil {
		return agentruntime.Turn{}, errors.New("cancel Durable Chat turn: turn is invalid")
	}
	key, err := app.keys.Next("cancel")
	if err != nil {
		return agentruntime.Turn{}, fmt.Errorf("cancel Durable Chat turn: %w", err)
	}
	return app.client.CancelTurn(ctx, agentruntime.CancelTurnRequest{SessionID: sessionID, TurnID: turnID, IdempotencyKey: key})
}
