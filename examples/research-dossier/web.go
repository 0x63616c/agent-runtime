package researchdossier

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

const (
	webOperationTimeout = 20 * time.Second
	maxWebFormBytes     = agentruntime.MaxTextPartBytes + 4096
)

type webPage struct {
	Session   string
	Notice    string
	Artifacts []agentruntime.ArtifactReference
	CSRFToken string
}

// NewWebHandler creates the loopback Research Dossier web UI. Its server owns
// the public SDK credential; the browser never receives it. Mutations require
// a per-handler CSRF token and same-origin browser request.
func NewWebHandler(app *App) (http.Handler, error) {
	if app == nil {
		return nil, fmt.Errorf("create Research Dossier web handler: app is required")
	}
	csrfToken, err := newCSRFToken()
	if err != nil {
		return nil, fmt.Errorf("create Research Dossier web CSRF token: %w", err)
	}
	page, err := template.New("dossier").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Research Dossier</title></head><body><h1>Research Dossier</h1><p>Durable research runs through Agent Runtime's public API. Progress resumes from a cursor; artifacts remain separately authorized.</p><form method="post" action="/sessions"><input type="hidden" name="csrf" value="{{.CSRFToken}}"><label>Agent revision <input name="revision" required></label><label>Research brief <textarea name="brief" required></textarea></label><button>Start research</button></form>{{if .Session}}<h2>Session {{.Session}}</h2><form method="post" action="/sessions/{{.Session}}/research"><input type="hidden" name="csrf" value="{{.CSRFToken}}"><textarea name="step" required></textarea><button>Queue research step</button></form><a href="/sessions/{{.Session}}">Resume progress</a> <a href="/sessions/{{.Session}}/artifacts">Artifacts</a>{{end}}{{if .Artifacts}}<h2>Artifacts</h2><ul>{{range .Artifacts}}<li><a href="/artifacts/{{.ID}}">{{.ID}}</a> {{.MediaType}} {{.SizeBytes}} bytes</li>{{end}}</ul>{{end}}{{if .Notice}}<pre>{{.Notice}}</pre>{{end}}</body></html>`)
	if err != nil {
		return nil, fmt.Errorf("create Research Dossier web template: %w", err)
	}
	render := func(writer http.ResponseWriter, session, notice string, artifacts []agentruntime.ArtifactReference) error {
		var body bytes.Buffer
		if err := page.Execute(&body, webPage{Session: session, Notice: notice, Artifacts: artifacts, CSRFToken: csrfToken}); err != nil {
			return fmt.Errorf("render Research Dossier web page: %w", err)
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := writer.Write(body.Bytes()); err != nil {
			return fmt.Errorf("write Research Dossier web page: %w", err)
		}
		return nil
	}
	operationContext := func(request *http.Request) (context.Context, context.CancelFunc) {
		return context.WithTimeout(request.Context(), webOperationTimeout)
	}
	renderFailure := func(writer http.ResponseWriter, session string) error {
		return render(writer, session, "request could not be completed", nil)
	}
	ensureMutation := func(writer http.ResponseWriter, request *http.Request) bool {
		request.Body = http.MaxBytesReader(writer, request.Body, maxWebFormBytes)
		if err := request.ParseForm(); err != nil || !sameOrigin(request) || request.PostForm.Get("csrf") != csrfToken {
			http.Error(writer, "forbidden", http.StatusForbidden)
			return false
		}
		return true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(writer http.ResponseWriter, request *http.Request) {
		if err := render(writer, request.URL.Query().Get("session"), "", nil); err != nil {
			return
		}
	})
	mux.HandleFunc("POST /sessions", func(writer http.ResponseWriter, request *http.Request) {
		if !ensureMutation(writer, request) {
			return
		}
		revision, parseErr := agentruntime.ParseAgentRevisionID(request.PostForm.Get("revision"))
		if parseErr == nil {
			ctx, cancel := operationContext(request)
			defer cancel()
			session, _, startErr := app.Start(ctx, revision, request.PostForm.Get("brief"))
			if startErr == nil {
				http.Redirect(writer, request, "/?session="+session.ID.String(), http.StatusSeeOther)
				return
			}
		}
		if err := renderFailure(writer, ""); err != nil {
			return
		}
	})
	mux.HandleFunc("POST /sessions/{session_id}/research", func(writer http.ResponseWriter, request *http.Request) {
		if !ensureMutation(writer, request) {
			return
		}
		sessionID, parseErr := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if parseErr == nil {
			ctx, cancel := operationContext(request)
			defer cancel()
			if _, researchErr := app.Research(ctx, sessionID, request.PostForm.Get("step")); researchErr == nil {
				http.Redirect(writer, request, "/?session="+sessionID.String(), http.StatusSeeOther)
				return
			}
		}
		if err := renderFailure(writer, request.PathValue("session_id")); err != nil {
			return
		}
	})
	mux.HandleFunc("GET /sessions/{session_id}", func(writer http.ResponseWriter, request *http.Request) {
		sessionID, parseErr := agentruntime.ParseSessionID(request.PathValue("session_id"))
		cursor := agentruntime.Cursor("")
		if raw := request.URL.Query().Get("after"); raw != "" && parseErr == nil {
			cursor, parseErr = agentruntime.ParseCursor(raw)
		}
		if parseErr == nil {
			ctx, cancel := operationContext(request)
			defer cancel()
			if progress, resumeErr := app.Resume(ctx, sessionID, cursor); resumeErr == nil {
				notice := fmt.Sprintf("state=%s events=%d next_cursor=%s", progress.Session.Session.State, len(progress.Events.Events), progress.Events.NextCursor)
				if progress.Events.Gap != nil {
					notice += " replay gap; inspect current session state"
				}
				if err := render(writer, sessionID.String(), notice, nil); err != nil {
					return
				}
				return
			}
		}
		if err := renderFailure(writer, request.PathValue("session_id")); err != nil {
			return
		}
	})
	mux.HandleFunc("GET /sessions/{session_id}/artifacts", func(writer http.ResponseWriter, request *http.Request) {
		sessionID, parseErr := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if parseErr == nil {
			ctx, cancel := operationContext(request)
			defer cancel()
			if artifacts, listErr := app.Artifacts(ctx, sessionID); listErr == nil {
				if err := render(writer, sessionID.String(), "", artifacts.Artifacts); err != nil {
					return
				}
				return
			}
		}
		if err := renderFailure(writer, request.PathValue("session_id")); err != nil {
			return
		}
	})
	mux.HandleFunc("GET /artifacts/{artifact_id}", func(writer http.ResponseWriter, request *http.Request) {
		artifactID, parseErr := agentruntime.ParseArtifactID(request.PathValue("artifact_id"))
		if parseErr == nil {
			ctx, cancel := operationContext(request)
			defer cancel()
			if dossier, downloadErr := app.Download(ctx, artifactID); downloadErr == nil {
				writer.Header().Set("Content-Type", dossier.Artifact.MediaType)
				writer.Header().Set("Content-Disposition", "attachment; filename=research-dossier-"+artifactID.String()+fileExtension(dossier.Artifact.MediaType))
				writer.Header().Set("X-Content-Type-Options", "nosniff")
				if _, err := writer.Write(dossier.Body); err != nil {
					return
				}
				return
			}
		}
		http.Error(writer, "request could not be completed", http.StatusNotFound)
	})
	return mux, nil
}

func newCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func sameOrigin(request *http.Request) bool {
	origin, err := url.Parse(request.Header.Get("Origin"))
	return err == nil && origin.Scheme == "http" && origin.Host == request.Host && origin.User == nil
}

func fileExtension(mediaType string) string {
	if strings.HasPrefix(mediaType, "text/markdown") {
		return ".md"
	}
	if strings.HasPrefix(mediaType, "text/plain") {
		return ".txt"
	}
	return ".bin"
}
