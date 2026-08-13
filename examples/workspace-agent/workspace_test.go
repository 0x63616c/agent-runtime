package workspaceagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestAppUsesPublicSessionLifecycleAndProjectsOnlyExactTextOutput(t *testing.T) {
	body := []byte("workspace report")
	output := agentruntime.ArtifactReference{ID: "art_1234567890ABCDEF", MediaType: "text/plain; charset=utf-8", SizeBytes: int64(len(body)), SHA256: testSHA256(body)}
	client := &sessionClient{turn: agentruntime.Turn{ID: "turn_1234567890ABCDEF", State: agentruntime.TurnSucceeded, Output: &output}, download: agentruntime.ArtifactDownload{Artifact: output, Body: body}}
	app, err := NewApp(client, &testKeys{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.NewSession(context.Background(), "arev_1234567890ABCDEF")
	if err != nil || session.ID != "sess_1234567890ABCDEF" {
		t.Fatalf("new session = %#v, %v", session, err)
	}
	accepted, err := app.Request(context.Background(), session.ID, "write a concise report")
	if err != nil || accepted.Turn.ID != "turn_1234567890ABCDEF" || client.input.IdempotencyKey != "request-2" {
		t.Fatalf("request = %#v, %v input=%#v", accepted, err, client.input)
	}
	if _, err := app.Resume(context.Background(), session.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := app.Reconnect(context.Background(), session.ID, "cur_1234567890ABCDEF"); err != nil || client.after != "cur_1234567890ABCDEF" {
		t.Fatalf("reconnect: %v after=%q", err, client.after)
	}
	projected, err := app.ReadOutput(context.Background(), session.ID, accepted.Turn.ID)
	if err != nil || projected.Text != string(body) || client.artifactID != output.ID {
		t.Fatalf("output = %#v, %v artifact=%q", projected, err, client.artifactID)
	}
}

func TestAppRejectsNonTextOrMismatchedOutput(t *testing.T) {
	body := []byte("private bytes")
	output := agentruntime.ArtifactReference{ID: "art_1234567890ABCDEF", MediaType: "application/json", SizeBytes: int64(len(body)), SHA256: testSHA256(body)}
	app, _ := NewApp(&sessionClient{turn: agentruntime.Turn{ID: "turn_1234567890ABCDEF", State: agentruntime.TurnSucceeded, Output: &output}, download: agentruntime.ArtifactDownload{Artifact: output, Body: body}}, &testKeys{})
	if _, err := app.ReadOutput(context.Background(), "sess_1234567890ABCDEF", "turn_1234567890ABCDEF"); err == nil || !strings.Contains(err.Error(), "plain text") {
		t.Fatalf("non-text output error = %v", err)
	}
	output.MediaType = "text/plain"
	app, _ = NewApp(&sessionClient{turn: agentruntime.Turn{ID: "turn_1234567890ABCDEF", State: agentruntime.TurnSucceeded, Output: &output}, download: agentruntime.ArtifactDownload{Artifact: output, Body: []byte("tampered")}}, &testKeys{})
	if _, err := app.ReadOutput(context.Background(), "sess_1234567890ABCDEF", "turn_1234567890ABCDEF"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched output error = %v", err)
	}
	output.SHA256 = testSHA256(body)
	app, _ = NewApp(&sessionClient{turn: agentruntime.Turn{ID: "turn_1234567890ABCDEF", State: agentruntime.TurnSucceeded, Output: &output}, download: agentruntime.ArtifactDownload{Artifact: output, Body: []byte(strings.Repeat("x", len(body)))}}, &testKeys{})
	if _, err := app.ReadOutput(context.Background(), "sess_1234567890ABCDEF", "turn_1234567890ABCDEF"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("same-size substituted output error = %v", err)
	}
	app, _ = NewApp(&sessionClient{turn: agentruntime.Turn{ID: "turn_1234567890ABCDEF", State: agentruntime.TurnRunning, Output: &output}, download: agentruntime.ArtifactDownload{Artifact: output, Body: body}}, &testKeys{})
	if _, err := app.ReadOutput(context.Background(), "sess_1234567890ABCDEF", "turn_1234567890ABCDEF"); err == nil || !strings.Contains(err.Error(), "no bounded finalized") {
		t.Fatalf("non-succeeded output error = %v", err)
	}
}

func TestWorkspaceTerminalRunsPublicWorkLifecycleAndPrintsBoundedOutput(t *testing.T) {
	body := []byte("finished workspace \x1b]0;not-a-title\x07 report")
	output := agentruntime.ArtifactReference{ID: "art_1234567890ABCDEF", MediaType: "text/plain", SizeBytes: int64(len(body)), SHA256: testSHA256(body)}
	app, err := NewApp(&sessionClient{turn: agentruntime.Turn{ID: "turn_1234567890ABCDEF", State: agentruntime.TurnSucceeded, Output: &output}, download: agentruntime.ArtifactDownload{Artifact: output, Body: body}}, &testKeys{})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := NewInbox(&approvalClient{})
	if err != nil {
		t.Fatal(err)
	}
	var terminal bytes.Buffer
	err = RunWorkspaceTerminal(context.Background(), app, inbox, strings.NewReader("new arev_1234567890ABCDEF\nrequest sess_1234567890ABCDEF summarize the workspace\nresume sess_1234567890ABCDEF\nevents sess_1234567890ABCDEF cur_1234567890ABCDEF\noutput sess_1234567890ABCDEF turn_1234567890ABCDEF\nquit\n"), &terminal)
	if err != nil || !strings.Contains(terminal.String(), "queued turn") || !strings.Contains(terminal.String(), `"finished workspace \x1b]0;not-a-title\a report"`) || strings.Contains(terminal.String(), "\x1b]0;") || !strings.Contains(terminal.String(), "unavailable") {
		t.Fatalf("terminal = %q, %v", terminal.String(), err)
	}
}

func TestWorkspaceWebRunsPublicWorkLifecycleAndEscapesProjectedOutput(t *testing.T) {
	body := []byte("<script>not markup</script>")
	output := agentruntime.ArtifactReference{ID: "art_1234567890ABCDEF", MediaType: "text/plain", SizeBytes: int64(len(body)), SHA256: testSHA256(body)}
	client := &sessionClient{turn: agentruntime.Turn{ID: "turn_1234567890ABCDEF", State: agentruntime.TurnSucceeded, Output: &output}, download: agentruntime.ArtifactDownload{Artifact: output, Body: body}}
	app, _ := NewApp(client, &testKeys{})
	inbox, _ := NewInbox(&approvalClient{})
	handler, err := NewWorkspaceWebHandler(app, inbox)
	if err != nil {
		t.Fatal(err)
	}
	csrf := workspaceWebCSRFToken(t, handler)
	create := httptest.NewRecorder()
	request := workspaceMutation(http.MethodPost, "/sessions", url.Values{"csrf": {csrf}, "revision": {"arev_1234567890ABCDEF"}})
	handler.ServeHTTP(create, request)
	if create.Code != http.StatusSeeOther || create.Header().Get("Location") != "/?session=sess_1234567890ABCDEF" {
		t.Fatalf("create session = status=%d location=%q", create.Code, create.Header().Get("Location"))
	}
	queue := httptest.NewRecorder()
	request = workspaceMutation(http.MethodPost, "/sessions/sess_1234567890ABCDEF/requests", url.Values{"csrf": {csrf}, "text": {"summarize workspace"}})
	handler.ServeHTTP(queue, request)
	if queue.Code != http.StatusSeeOther || client.input.Parts[0].Text != "summarize workspace" {
		t.Fatalf("queue request = status=%d input=%#v", queue.Code, client.input)
	}
	read := httptest.NewRecorder()
	handler.ServeHTTP(read, httptest.NewRequest(http.MethodGet, "/sessions/sess_1234567890ABCDEF/output?turn=turn_1234567890ABCDEF", nil))
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), "&lt;script&gt;not markup&lt;/script&gt;") || strings.Contains(read.Body.String(), "<script>not markup</script>") {
		t.Fatalf("projected output = status=%d body=%q", read.Code, read.Body.String())
	}
}

func workspaceMutation(method, path string, values url.Values) *http.Request {
	request := httptest.NewRequest(method, "http://trusted.example"+path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://trusted.example")
	return request
}

type testKeys struct{ n int }

func (keys *testKeys) Next(action string) (string, error) {
	keys.n++
	return fmt.Sprintf("%s-%d", action, keys.n), nil
}

type sessionClient struct {
	input      agentruntime.SendInputRequest
	after      agentruntime.Cursor
	turn       agentruntime.Turn
	download   agentruntime.ArtifactDownload
	artifactID agentruntime.ArtifactID
}

func (*sessionClient) CreateSession(context.Context, agentruntime.CreateSessionRequest) (agentruntime.Session, error) {
	return agentruntime.Session{ID: "sess_1234567890ABCDEF", State: agentruntime.SessionOpen}, nil
}
func (client *sessionClient) SendInput(_ context.Context, request agentruntime.SendInputRequest) (agentruntime.SendInputResult, error) {
	client.input = request
	return agentruntime.SendInputResult{Turn: client.turn}, nil
}
func (*sessionClient) InspectSession(context.Context, agentruntime.SessionID) (agentruntime.SessionView, error) {
	return agentruntime.SessionView{Session: agentruntime.Session{ID: "sess_1234567890ABCDEF", State: agentruntime.SessionOpen}}, nil
}
func (client *sessionClient) InspectTurn(context.Context, agentruntime.SessionID, agentruntime.TurnID) (agentruntime.Turn, error) {
	return client.turn, nil
}
func (client *sessionClient) Events(_ context.Context, _ agentruntime.SessionID, after agentruntime.Cursor, _ int) (agentruntime.EventPage, error) {
	client.after = after
	return agentruntime.EventPage{}, nil
}
func (*sessionClient) CancelTurn(context.Context, agentruntime.CancelTurnRequest) (agentruntime.Turn, error) {
	return agentruntime.Turn{}, nil
}
func (client *sessionClient) ReadArtifact(_ context.Context, id agentruntime.ArtifactID) (agentruntime.ArtifactDownload, error) {
	client.artifactID = id
	return client.download, nil
}

func testSHA256(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
