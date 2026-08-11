package researchdossier

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestDossierWebAndTerminalUseTheSamePublicController(t *testing.T) {
	client := &recordingClient{
		session:   agentruntime.Session{ID: "sess_0000000000000001", AgentRevision: "arev_0000000000000001", State: agentruntime.SessionOpen},
		artifacts: agentruntime.ArtifactPage{Artifacts: []agentruntime.ArtifactReference{{ID: "art_0000000000000001", MediaType: "text/markdown", SizeBytes: 20, SHA256: strings.Repeat("a", 64)}}},
		download:  agentruntime.ArtifactDownload{Artifact: agentruntime.ArtifactReference{ID: "art_0000000000000001", MediaType: "text/markdown", SizeBytes: 20, SHA256: strings.Repeat("a", 64)}, Body: []byte("https://example.com/")},
	}
	app, err := NewApp(client, fixedKeys{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewWebHandler(app)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	if response.Code != 200 || !strings.Contains(response.Body.String(), "Research Dossier") || strings.Contains(response.Body.String(), "runtime bearer") {
		t.Fatalf("web page = %d %q", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/sessions/sess_0000000000000001/artifacts", nil))
	if response.Code != 200 || !strings.Contains(response.Body.String(), "art_0000000000000001") {
		t.Fatalf("artifact page = %d %q", response.Code, response.Body.String())
	}
	var output bytes.Buffer
	if err := RunTerminal(context.Background(), app, strings.NewReader("artifacts sess_0000000000000001\ndownload art_0000000000000001\nquit\n"), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "art_0000000000000001") || !strings.Contains(output.String(), "https://example.com/") {
		t.Fatalf("terminal output = %q", output.String())
	}
}

func TestDossierWebRejectsHostileOriginEvenWithLeakedFormToken(t *testing.T) {
	client := &recordingClient{session: agentruntime.Session{ID: "sess_0000000000000001", AgentRevision: "arev_0000000000000001", State: agentruntime.SessionOpen}}
	app, err := NewApp(client, fixedKeys{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewWebHandler(app)
	if err != nil {
		t.Fatal(err)
	}
	page := httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, "http://trusted.example/", nil)
	get.Host = "trusted.example"
	handler.ServeHTTP(page, get)
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if len(match) != 2 {
		t.Fatalf("CSRF token missing from page: %q", page.Body.String())
	}
	values := url.Values{"csrf": {match[1]}, "revision": {"arev_0000000000000001"}, "brief": {"hostile cross-origin request"}}
	post := httptest.NewRequest(http.MethodPost, "http://trusted.example/sessions", strings.NewReader(values.Encode()))
	post.Host = "trusted.example"
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "http://evil.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, post)
	if response.Code != http.StatusForbidden || len(client.inputs) != 0 {
		t.Fatalf("hostile origin mutation = status=%d inputs=%#v", response.Code, client.inputs)
	}
}
