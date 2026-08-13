package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const publishedSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestRunVerifiesPublishedCanonicalRoutesAndMarker(t *testing.T) {
	root, manifest := fixtureWebsite(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent-runtime/docs/start-here" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page("Start here", serverURL(r), publishedSHA, "Public introduction.")))
	}))
	defer server.Close()
	if err := run(context.Background(), options{BaseURL: server.URL + "/agent-runtime", ExpectedSHA: publishedSHA, ManifestPath: manifest, WebsiteRoot: root, RequireSourceSHAMarker: true}, server.Client()); err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunRejectsInternalTermAndRevisionMismatch(t *testing.T) {
	root, manifest := fixtureWebsite(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page("Start here", serverURL(r), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "Public introduction.")))
	}))
	defer server.Close()
	err := run(context.Background(), options{BaseURL: server.URL + "/agent-runtime", ExpectedSHA: publishedSHA, ManifestPath: manifest, WebsiteRoot: root}, server.Client())
	if err == nil || !strings.Contains(err.Error(), "source revision") {
		t.Fatalf("run() error = %v, want revision mismatch", err)
	}
}

func TestRunRejectsInternalTerm(t *testing.T) {
	root, manifest := fixtureWebsite(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page("Start here", serverURL(r), publishedSHA, "M5 internal delivery.")))
	}))
	defer server.Close()
	err := run(context.Background(), options{BaseURL: server.URL + "/agent-runtime", ExpectedSHA: publishedSHA, ManifestPath: manifest, WebsiteRoot: root}, server.Client())
	if err == nil || !strings.Contains(err.Error(), "milestone label") {
		t.Fatalf("run() error = %v, want internal-term refusal", err)
	}
}

func TestRunRejectsDuplicateTitle(t *testing.T) {
	root, manifest := fixtureWebsite(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<link rel="canonical" href="` + serverURL(r) + `"><main><h1>Start here</h1><h1>Repeated</h1></main>`))
	}))
	defer server.Close()
	err := run(context.Background(), options{BaseURL: server.URL + "/agent-runtime", ExpectedSHA: publishedSHA, ManifestPath: manifest, WebsiteRoot: root}, server.Client())
	if err == nil || !strings.Contains(err.Error(), "exactly one H1") {
		t.Fatalf("run() error = %v, want duplicate H1 refusal", err)
	}
}

func TestRunRejectsCanonicalLinkWithoutHref(t *testing.T) {
	root, manifest := fixtureWebsite(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<link rel="canonical"><main><h1>Start here</h1></main>`))
	}))
	defer server.Close()
	err := run(context.Background(), options{BaseURL: server.URL + "/agent-runtime", ExpectedSHA: publishedSHA, ManifestPath: manifest, WebsiteRoot: root}, server.Client())
	if err == nil || !strings.Contains(err.Error(), "canonical URL") {
		t.Fatalf("run() error = %v, want missing canonical href refusal", err)
	}
}

func TestRunCanReportAbsenceOfOptionalMarker(t *testing.T) {
	root, manifest := fixtureWebsite(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page("Start here", serverURL(r), "", "Public introduction.")))
	}))
	defer server.Close()
	if err := run(context.Background(), options{BaseURL: server.URL + "/agent-runtime", ExpectedSHA: publishedSHA, ManifestPath: manifest, WebsiteRoot: root}, server.Client()); err != nil {
		t.Fatalf("run() without optional marker error = %v", err)
	}
}

func fixtureWebsite(t *testing.T) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "website")
	source := filepath.Join(root, "src/content/docs/docs/start-here")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "index.mdx"), []byte("---\ntitle: Start here\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := routeManifest{SchemaVersion: 2, BasePath: "/agent-runtime", Routes: []route{{Route: "/docs/start-here", Source: "src/content/docs/docs/start-here/index.mdx"}}}
	contents, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "route-manifest.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, path
}

func page(title, canonical, marker, content string) string {
	markerHTML := ""
	if marker != "" {
		markerHTML = `<meta name="agent-runtime-source-sha" content="` + marker + `">`
	}
	return `<link rel="canonical" href="` + canonical + `">` + markerHTML + `<main><h1>` + title + `</h1><p>` + content + `</p></main>`
}

func serverURL(r *http.Request) string { return "https://" + r.Host + r.URL.Path }
