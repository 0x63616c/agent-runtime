// Package researchdossier is the public-contract Research Dossier application.
package researchdossier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

var citationURL = regexp.MustCompile(`https?://[^\s)\]}>]+`)

const (
	briefPrefix    = "Research dossier brief:\n"
	researchPrefix = "Research step:\n"
)

// Client is the narrow public SDK surface used by Research Dossier. It keeps
// the application independent of private state, Temporal, blob, and tool APIs.
type Client interface {
	CreateSession(context.Context, agentruntime.CreateSessionRequest) (agentruntime.Session, error)
	SendInput(context.Context, agentruntime.SendInputRequest) (agentruntime.SendInputResult, error)
	InspectSession(context.Context, agentruntime.SessionID) (agentruntime.SessionView, error)
	Events(context.Context, agentruntime.SessionID, agentruntime.Cursor, int) (agentruntime.EventPage, error)
	ListSessionArtifacts(context.Context, agentruntime.SessionID) (agentruntime.ArtifactPage, error)
	ReadArtifact(context.Context, agentruntime.ArtifactID) (agentruntime.ArtifactDownload, error)
}

// KeySource creates one opaque idempotency key for a user-initiated command.
type KeySource interface {
	Next(string) (string, error)
}

// App coordinates durable research work through the public runtime contract.
type App struct {
	client Client
	keys   KeySource
}

// NewApp constructs a public-contract Research Dossier application controller.
func NewApp(client Client, keys KeySource) (*App, error) {
	if client == nil || keys == nil {
		return nil, errors.New("create Research Dossier app: public client and idempotency keys are required")
	}
	return &App{client: client, keys: keys}, nil
}

// Start creates one research Session and durably submits its initial brief.
func (app *App) Start(ctx context.Context, revision agentruntime.AgentRevisionID, brief string) (agentruntime.Session, agentruntime.SendInputResult, error) {
	text, textErr := prefixedText(briefPrefix, brief)
	if _, err := agentruntime.ParseAgentRevisionID(revision.String()); err != nil || textErr != nil {
		return agentruntime.Session{}, agentruntime.SendInputResult{}, errors.New("start Research Dossier: Agent revision and bounded brief are required")
	}
	createKey, err := app.keys.Next("session")
	if err != nil {
		return agentruntime.Session{}, agentruntime.SendInputResult{}, fmt.Errorf("start Research Dossier: create key: %w", err)
	}
	session, err := app.client.CreateSession(ctx, agentruntime.CreateSessionRequest{AgentRevision: revision, IdempotencyKey: createKey})
	if err != nil {
		return agentruntime.Session{}, agentruntime.SendInputResult{}, err
	}
	accepted, err := app.submit(ctx, session.ID, "brief", text)
	if err != nil {
		return agentruntime.Session{}, agentruntime.SendInputResult{}, err
	}
	return session, accepted, nil
}

// Research appends one bounded research step behind earlier durable work.
func (app *App) Research(ctx context.Context, sessionID agentruntime.SessionID, question string) (agentruntime.SendInputResult, error) {
	text, textErr := prefixedText(researchPrefix, question)
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil || textErr != nil {
		return agentruntime.SendInputResult{}, errors.New("advance Research Dossier: Session and bounded research step are required")
	}
	return app.submit(ctx, sessionID, "research", text)
}

func (app *App) submit(ctx context.Context, sessionID agentruntime.SessionID, action, text string) (agentruntime.SendInputResult, error) {
	key, err := app.keys.Next(action)
	if err != nil {
		return agentruntime.SendInputResult{}, fmt.Errorf("submit Research Dossier Input: %w", err)
	}
	return app.client.SendInput(ctx, agentruntime.SendInputRequest{SessionID: sessionID, IdempotencyKey: key, Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: text}}})
}

// Progress is a durable Session snapshot paired with a resumable event page.
type Progress struct {
	Session agentruntime.SessionView
	Events  agentruntime.EventPage
}

// Resume recovers current research state and Product events after a browser,
// terminal, or API-process interruption. A Gap remains explicit to callers.
func (app *App) Resume(ctx context.Context, sessionID agentruntime.SessionID, after agentruntime.Cursor) (Progress, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return Progress{}, errors.New("resume Research Dossier: Session is invalid")
	}
	view, err := app.client.InspectSession(ctx, sessionID)
	if err != nil {
		return Progress{}, err
	}
	events, err := app.client.Events(ctx, sessionID, after, 100)
	if err != nil {
		return Progress{}, err
	}
	return Progress{Session: view, Events: events}, nil
}

// Artifacts lists retained immutable output metadata for the exact Session.
func (app *App) Artifacts(ctx context.Context, sessionID agentruntime.SessionID) (agentruntime.ArtifactPage, error) {
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return agentruntime.ArtifactPage{}, errors.New("list Research Dossier Artifacts: Session is invalid")
	}
	return app.client.ListSessionArtifacts(ctx, sessionID)
}

// Citation is one safe web citation found in a retained dossier Artifact.
type Citation struct {
	URL string
}

// Dossier is a downloaded immutable Artifact and its safe citation index.
type Dossier struct {
	Artifact  agentruntime.ArtifactReference
	Body      []byte
	Citations []Citation
}

// Download reads one exact caller-authorized dossier Artifact and derives its
// citation index from retained bytes; it never accepts an external storage URL.
func (app *App) Download(ctx context.Context, artifactID agentruntime.ArtifactID) (Dossier, error) {
	if _, err := agentruntime.ParseArtifactID(artifactID.String()); err != nil {
		return Dossier{}, errors.New("download Research Dossier: Artifact is invalid")
	}
	if streaming, ok := app.client.(agentruntime.ArtifactStreamer); ok {
		stream, err := streaming.OpenArtifact(ctx, artifactID)
		if err != nil {
			return Dossier{}, err
		}
		body, readErr := io.ReadAll(stream.Body)
		closeErr := stream.Body.Close()
		if readErr != nil {
			return Dossier{}, fmt.Errorf("download Research Dossier: read Artifact stream: %w", readErr)
		}
		if closeErr != nil {
			return Dossier{}, fmt.Errorf("download Research Dossier: close Artifact stream: %w", closeErr)
		}
		return Dossier{Artifact: stream.Artifact, Body: append([]byte(nil), body...), Citations: ExtractCitations(body)}, nil
	}
	download, err := app.client.ReadArtifact(ctx, artifactID)
	if err != nil {
		return Dossier{}, err
	}
	return Dossier{Artifact: download.Artifact, Body: append([]byte(nil), download.Body...), Citations: ExtractCitations(download.Body)}, nil
}

// ExtractCitations returns ordered, de-duplicated absolute HTTP(S) citations.
// Non-web schemes and malformed URLs never become clickable public citations.
func ExtractCitations(body []byte) []Citation {
	seen := map[string]struct{}{}
	var citations []Citation
	for _, raw := range citationURL.FindAllString(string(body), -1) {
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil {
			continue
		}
		canonical := parsed.String()
		if _, found := seen[canonical]; found {
			continue
		}
		seen[canonical] = struct{}{}
		citations = append(citations, Citation{URL: canonical})
	}
	return citations
}

func prefixedText(prefix, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(prefix)+len(trimmed) > agentruntime.MaxTextPartBytes {
		return "", errors.New("bounded text is required")
	}
	return prefix + trimmed, nil
}
