package workspaceagent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"strings"
	"unicode/utf8"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// maxProjectedOutputBytes bounds a browser or terminal rendering of a model
// result even though the SDK can safely transfer a larger retained artifact.
const maxProjectedOutputBytes int64 = 64 << 10

// SessionClient is the narrow public SDK surface Workspace Agent needs for its
// durable work view. It intentionally has no sandbox-control methods.
type SessionClient interface {
	CreateSession(context.Context, agentruntime.CreateSessionRequest) (agentruntime.Session, error)
	SendInput(context.Context, agentruntime.SendInputRequest) (agentruntime.SendInputResult, error)
	InspectSession(context.Context, agentruntime.SessionID) (agentruntime.SessionView, error)
	InspectTurn(context.Context, agentruntime.SessionID, agentruntime.TurnID) (agentruntime.Turn, error)
	Events(context.Context, agentruntime.SessionID, agentruntime.Cursor, int) (agentruntime.EventPage, error)
	CancelTurn(context.Context, agentruntime.CancelTurnRequest) (agentruntime.Turn, error)
	ReadArtifact(context.Context, agentruntime.ArtifactID) (agentruntime.ArtifactDownload, error)
}

// KeySource creates an opaque idempotency key for a user action.
type KeySource interface {
	Next(string) (string, error)
}

// RandomKeys creates opaque idempotency keys without deriving them from a
// workspace request or model output.
type RandomKeys struct{}

// Next returns one bounded opaque idempotency key.
func (RandomKeys) Next(action string) (string, error) {
	if action == "" || len(action) > 32 {
		return "", errors.New("create Workspace Agent idempotency key: action is invalid")
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", errors.New("create Workspace Agent idempotency key: entropy is unavailable")
	}
	return "workspace-agent-" + action + "-" + hex.EncodeToString(bytes[:]), nil
}

// App coordinates Workspace Agent's public Session workflow.
type App struct {
	client SessionClient
	keys   KeySource
}

// NewApp constructs a Workspace Agent controller from public-contract seams.
func NewApp(client SessionClient, keys KeySource) (*App, error) {
	if client == nil || keys == nil {
		return nil, errors.New("create Workspace Agent app: public client and idempotency keys are required")
	}
	return &App{client: client, keys: keys}, nil
}

// NewSession creates one Session pinned to the supplied public Agent revision.
func (app *App) NewSession(ctx context.Context, revision agentruntime.AgentRevisionID) (agentruntime.Session, error) {
	if _, err := agentruntime.ParseAgentRevisionID(revision.String()); err != nil {
		return agentruntime.Session{}, errors.New("create Workspace Agent session: Agent revision is invalid")
	}
	key, err := app.keys.Next("session")
	if err != nil {
		return agentruntime.Session{}, fmt.Errorf("create Workspace Agent session: %w", err)
	}
	return app.client.CreateSession(ctx, agentruntime.CreateSessionRequest{AgentRevision: revision, IdempotencyKey: key})
}

// Request appends one bounded workspace request behind preceding durable work.
func (app *App) Request(ctx context.Context, sessionID agentruntime.SessionID, text string) (agentruntime.SendInputResult, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil || strings.TrimSpace(text) == "" || len(text) > agentruntime.MaxTextPartBytes {
		return agentruntime.SendInputResult{}, errors.New("request Workspace Agent work: Session and bounded text are required")
	}
	key, err := app.keys.Next("request")
	if err != nil {
		return agentruntime.SendInputResult{}, fmt.Errorf("request Workspace Agent work: %w", err)
	}
	return app.client.SendInput(ctx, agentruntime.SendInputRequest{SessionID: sessionID, IdempotencyKey: key, Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: text}}})
}

// Resume reads current durable state after an application restart.
func (app *App) Resume(ctx context.Context, sessionID agentruntime.SessionID) (agentruntime.SessionView, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return agentruntime.SessionView{}, errors.New("resume Workspace Agent session: Session is invalid")
	}
	return app.client.InspectSession(ctx, sessionID)
}

// Reconnect resumes event observation from the caller's last opaque cursor.
func (app *App) Reconnect(ctx context.Context, sessionID agentruntime.SessionID, after agentruntime.Cursor) (agentruntime.EventPage, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return agentruntime.EventPage{}, errors.New("reconnect Workspace Agent events: Session is invalid")
	}
	return app.client.Events(ctx, sessionID, after, 100)
}

// Cancel records a durable cancellation request for one public Turn.
func (app *App) Cancel(ctx context.Context, sessionID agentruntime.SessionID, turnID agentruntime.TurnID) (agentruntime.Turn, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return agentruntime.Turn{}, errors.New("cancel Workspace Agent turn: Session is invalid")
	}
	if _, err := agentruntime.ParseTurnID(turnID.String()); err != nil {
		return agentruntime.Turn{}, errors.New("cancel Workspace Agent turn: Turn is invalid")
	}
	key, err := app.keys.Next("cancel")
	if err != nil {
		return agentruntime.Turn{}, fmt.Errorf("cancel Workspace Agent turn: %w", err)
	}
	return app.client.CancelTurn(ctx, agentruntime.CancelTurnRequest{SessionID: sessionID, TurnID: turnID, IdempotencyKey: key})
}

// Output is a bounded UTF-8 projection of one finalized owner-readable model output.
type Output struct {
	Artifact agentruntime.ArtifactReference
	Text     string
}

// ReadOutput verifies that a downloaded artifact is the exact text output
// referenced by the requested Turn before projecting it into the UI.
func (app *App) ReadOutput(ctx context.Context, sessionID agentruntime.SessionID, turnID agentruntime.TurnID) (Output, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return Output{}, errors.New("read Workspace Agent output: Session is invalid")
	}
	if _, err := agentruntime.ParseTurnID(turnID.String()); err != nil {
		return Output{}, errors.New("read Workspace Agent output: Turn is invalid")
	}
	turn, err := app.client.InspectTurn(ctx, sessionID, turnID)
	if err != nil {
		return Output{}, fmt.Errorf("read Workspace Agent output: inspect Turn: %w", err)
	}
	if turn.State != agentruntime.TurnSucceeded || turn.Output == nil || turn.Output.SizeBytes < 1 || turn.Output.SizeBytes > maxProjectedOutputBytes {
		return Output{}, errors.New("read Workspace Agent output: no bounded finalized output is available")
	}
	mediaType, _, err := mime.ParseMediaType(turn.Output.MediaType)
	if err != nil || mediaType != "text/plain" {
		return Output{}, errors.New("read Workspace Agent output: finalized output is not plain text")
	}
	download, err := app.client.ReadArtifact(ctx, turn.Output.ID)
	if err != nil {
		return Output{}, fmt.Errorf("read Workspace Agent output: download artifact: %w", err)
	}
	if download.Artifact != *turn.Output || int64(len(download.Body)) != turn.Output.SizeBytes || !utf8.Valid(download.Body) || !matchesSHA256(download.Body, turn.Output.SHA256) {
		return Output{}, errors.New("read Workspace Agent output: artifact does not match finalized text output")
	}
	return Output{Artifact: download.Artifact, Text: string(download.Body)}, nil
}

func matchesSHA256(body []byte, expected string) bool {
	declared, err := hex.DecodeString(expected)
	if err != nil || len(declared) != sha256.Size {
		return false
	}
	actual := sha256.Sum256(body)
	var different byte
	for index := range actual {
		different |= actual[index] ^ declared[index]
	}
	return different == 0
}
