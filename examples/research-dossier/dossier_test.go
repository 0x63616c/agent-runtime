package researchdossier

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestDossierRunsResearchAndRecoversProgressUsingOnlyPublicContract(t *testing.T) {
	client := &recordingClient{
		session:   agentruntime.Session{ID: "sess_0000000000000001", AgentRevision: "arev_0000000000000001", State: agentruntime.SessionOpen},
		artifacts: agentruntime.ArtifactPage{Artifacts: []agentruntime.ArtifactReference{{ID: "art_0000000000000001", MediaType: "text/markdown", SizeBytes: 68, SHA256: strings.Repeat("a", 64)}}},
		download:  agentruntime.ArtifactDownload{Artifact: agentruntime.ArtifactReference{ID: "art_0000000000000001", MediaType: "text/markdown", SizeBytes: 68, SHA256: strings.Repeat("a", 64)}, Body: []byte("# Research Dossier\n\nEvidence: [Primary source](https://example.com/report).")},
		events:    agentruntime.EventPage{NextCursor: "cur_0000000000000001", Events: []agentruntime.Event{{ID: "evt_0000000000000001", SessionID: "sess_0000000000000001", Kind: agentruntime.EventTurnStarted}}},
	}
	app, err := NewApp(client, fixedKeys{})
	if err != nil {
		t.Fatal(err)
	}
	session, accepted, err := app.Start(context.Background(), "arev_0000000000000001", "Compare the primary evidence")
	if err != nil || session.ID != client.session.ID || accepted.Turn.ID == "" {
		t.Fatalf("start dossier = %#v %#v %v", session, accepted, err)
	}
	if len(client.inputs) != 1 || !strings.Contains(client.inputs[0].Parts[0].Text, "Research dossier brief:") {
		t.Fatalf("initial public Input = %#v", client.inputs)
	}
	if _, err := app.Research(context.Background(), session.ID, "find corroborating sources"); err != nil {
		t.Fatal(err)
	}
	if len(client.inputs) != 2 || !strings.Contains(client.inputs[1].Parts[0].Text, "Research step:") {
		t.Fatalf("research public Input = %#v", client.inputs)
	}
	progress, err := app.Resume(context.Background(), session.ID, "")
	if err != nil || progress.Events.NextCursor != client.events.NextCursor || progress.Session.Session.ID != session.ID {
		t.Fatalf("resume dossier = %#v %v", progress, err)
	}
	artifacts, err := app.Artifacts(context.Background(), session.ID)
	if err != nil || len(artifacts.Artifacts) != 1 || artifacts.Artifacts[0] != client.artifacts.Artifacts[0] {
		t.Fatalf("list dossier artifacts = %#v %v", artifacts, err)
	}
	dossier, err := app.Download(context.Background(), client.artifacts.Artifacts[0].ID)
	if err != nil || len(dossier.Citations) != 1 || dossier.Citations[0].URL != "https://example.com/report" {
		t.Fatalf("download dossier = %#v %v", dossier, err)
	}
}

func TestDossierDownloadsStreamingPublicArtifacts(t *testing.T) {
	artifact := agentruntime.ArtifactReference{ID: "art_0000000000000001", MediaType: "text/markdown", SizeBytes: 68, SHA256: strings.Repeat("a", 64)}
	body := &recordingReadCloser{Reader: strings.NewReader("# Research Dossier\n\nEvidence: https://example.com/stream")}
	client := &streamingRecordingClient{recordingClient: recordingClient{download: agentruntime.ArtifactDownload{Artifact: artifact, Body: []byte("legacy body")}}, stream: agentruntime.ArtifactStream{Artifact: artifact, Body: body}}
	app, err := NewApp(client, fixedKeys{})
	if err != nil {
		t.Fatal(err)
	}
	dossier, err := app.Download(context.Background(), artifact.ID)
	if err != nil || !body.closed || string(dossier.Body) == "legacy body" || len(dossier.Citations) != 1 || dossier.Citations[0].URL != "https://example.com/stream" {
		t.Fatalf("stream dossier = %#v, %v", dossier, err)
	}
}

func TestDossierReportsStreamingCloseFailure(t *testing.T) {
	artifact := agentruntime.ArtifactReference{ID: "art_0000000000000001", MediaType: "text/markdown", SizeBytes: 68, SHA256: strings.Repeat("a", 64)}
	body := &recordingReadCloser{Reader: strings.NewReader("complete body"), closeErr: errors.New("close failed")}
	client := &streamingRecordingClient{stream: agentruntime.ArtifactStream{Artifact: artifact, Body: body}}
	app, err := NewApp(client, fixedKeys{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Download(context.Background(), artifact.ID); err == nil || !body.closed {
		t.Fatalf("stream close failure = %v, closed=%t", err, body.closed)
	}
}

func TestDossierRefusesInvalidPublicInputsAndUnsafeCitationURLs(t *testing.T) {
	app, err := NewApp(&recordingClient{}, fixedKeys{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.Start(context.Background(), "arev_0000000000000001", " "); err == nil {
		t.Fatal("start empty brief error = nil")
	}
	if _, err := app.Research(context.Background(), "sess_0000000000000001", " "); err == nil {
		t.Fatal("research empty step error = nil")
	}
	citations := ExtractCitations([]byte("[unsafe](javascript:alert(1)) https://example.com/ok https://example.com/ok"))
	if len(citations) != 1 || citations[0].URL != "https://example.com/ok" {
		t.Fatalf("citations = %#v", citations)
	}
}

func TestDossierBoundsTheFinalPrefixedPublicPayload(t *testing.T) {
	client := &recordingClient{session: agentruntime.Session{ID: "sess_0000000000000001", AgentRevision: "arev_0000000000000001", State: agentruntime.SessionOpen}}
	app, err := NewApp(client, fixedKeys{})
	if err != nil {
		t.Fatal(err)
	}
	accepted := strings.Repeat("x", agentruntime.MaxTextPartBytes-len(briefPrefix))
	if _, _, err := app.Start(context.Background(), "arev_0000000000000001", accepted); err != nil {
		t.Fatalf("start exact final payload bound: %v", err)
	}
	if got := len(client.inputs[0].Parts[0].Text); got != agentruntime.MaxTextPartBytes {
		t.Fatalf("final brief payload bytes = %d, want %d", got, agentruntime.MaxTextPartBytes)
	}
	if _, err := app.Research(context.Background(), client.session.ID, strings.Repeat("y", agentruntime.MaxTextPartBytes-len(researchPrefix)+1)); err == nil {
		t.Fatal("research payload above final prefixed bound error = nil")
	}
}

type recordingClient struct {
	session   agentruntime.Session
	inputs    []agentruntime.SendInputRequest
	artifacts agentruntime.ArtifactPage
	download  agentruntime.ArtifactDownload
	events    agentruntime.EventPage
}

type streamingRecordingClient struct {
	recordingClient
	stream agentruntime.ArtifactStream
}

type recordingReadCloser struct {
	io.Reader
	closeErr error
	closed   bool
}

func (reader *recordingReadCloser) Close() error {
	reader.closed = true
	return reader.closeErr
}

func (client *streamingRecordingClient) OpenArtifact(context.Context, agentruntime.ArtifactID) (agentruntime.ArtifactStream, error) {
	return client.stream, nil
}

func (client *recordingClient) CreateSession(context.Context, agentruntime.CreateSessionRequest) (agentruntime.Session, error) {
	return client.session, nil
}
func (client *recordingClient) SendInput(_ context.Context, request agentruntime.SendInputRequest) (agentruntime.SendInputResult, error) {
	client.inputs = append(client.inputs, request)
	return agentruntime.SendInputResult{Turn: agentruntime.Turn{ID: agentruntime.TurnID("turn_0000000000000001"), State: agentruntime.TurnQueued}}, nil
}
func (client *recordingClient) InspectSession(context.Context, agentruntime.SessionID) (agentruntime.SessionView, error) {
	return agentruntime.SessionView{Session: client.session}, nil
}
func (client *recordingClient) Events(context.Context, agentruntime.SessionID, agentruntime.Cursor, int) (agentruntime.EventPage, error) {
	return client.events, nil
}
func (client *recordingClient) ListSessionArtifacts(context.Context, agentruntime.SessionID) (agentruntime.ArtifactPage, error) {
	return client.artifacts, nil
}
func (client *recordingClient) ReadArtifact(context.Context, agentruntime.ArtifactID) (agentruntime.ArtifactDownload, error) {
	return client.download, nil
}

type fixedKeys struct{}

func (fixedKeys) Next(action string) (string, error) { return "research-dossier-" + action, nil }
