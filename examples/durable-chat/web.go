package durablechat

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

const maxWebFormBytes = agentruntime.MaxTextPartBytes + 4096

// WebConfig declares the loopback-only web example presentation.
type WebConfig struct {
	App           *App
	ProviderState string
}

// NewWebHandler creates the minimal Durable Chat web UI. The UI never receives
// the runtime bearer credential; its local server owns the public SDK client.
func NewWebHandler(config WebConfig) (http.Handler, error) {
	if config.App == nil {
		return nil, fmt.Errorf("create Durable Chat web handler: app is required")
	}
	csrfToken, err := newCSRFToken()
	if err != nil {
		return nil, fmt.Errorf("create Durable Chat web CSRF token: %w", err)
	}
	state := strings.TrimSpace(config.ProviderState)
	if state == "" {
		state = "Codex subscription support is blocked pending an official production-supported model surface; this UI is not a subscription canary."
	}
	page, err := template.New("chat").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Durable Chat</title></head><body><h1>Durable Chat</h1><p>{{.Provider}}</p><form method="post" action="/sessions"><input type="hidden" name="csrf" value="{{.CSRFToken}}"><label>Agent revision <input name="revision" required></label><button>Create session</button></form>{{if .Session}}<h2>Session {{.Session}}</h2><form method="post" action="/sessions/{{.Session}}/messages"><input type="hidden" name="csrf" value="{{.CSRFToken}}"><textarea name="text" required></textarea><button>Queue message</button></form><form method="post" action="/sessions/{{.Session}}/cancel"><input type="hidden" name="csrf" value="{{.CSRFToken}}"><label>Turn <input name="turn" required></label><button>Cancel turn</button></form><form method="get" action="/sessions/{{.Session}}"><button>Resume state</button></form><form method="get" action="/sessions/{{.Session}}/events"><label>Cursor <input name="after"></label><button>Reconnect events</button></form>{{end}}{{if .Notice}}<pre>{{.Notice}}</pre>{{end}}</body></html>`)
	if err != nil {
		return nil, fmt.Errorf("create Durable Chat web handler: %w", err)
	}
	renderPage := func(writer http.ResponseWriter, provider, session, notice string) {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(writer, struct{ Provider, Session, Notice, CSRFToken string }{provider, session, notice, csrfToken})
	}
	mux := http.NewServeMux()
	ensureMutation := func(writer http.ResponseWriter, request *http.Request) bool {
		request.Body = http.MaxBytesReader(writer, request.Body, maxWebFormBytes)
		if err := request.ParseForm(); err != nil || !sameOrigin(request) || request.PostForm.Get("csrf") != csrfToken {
			http.Error(writer, "forbidden", http.StatusForbidden)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /", func(writer http.ResponseWriter, request *http.Request) {
		renderPage(writer, state, request.URL.Query().Get("session"), "")
	})
	mux.HandleFunc("POST /sessions", func(writer http.ResponseWriter, request *http.Request) {
		if !ensureMutation(writer, request) {
			return
		}
		revision, err := agentruntime.ParseAgentRevisionID(request.FormValue("revision"))
		if err == nil {
			var session agentruntime.Session
			session, err = config.App.NewSession(request.Context(), revision)
			if err == nil {
				http.Redirect(writer, request, "/?session="+session.ID.String(), http.StatusSeeOther)
				return
			}
		}
		renderPage(writer, state, "", safeNotice(err))
	})
	mux.HandleFunc("POST /sessions/{session_id}/messages", func(writer http.ResponseWriter, request *http.Request) {
		if !ensureMutation(writer, request) {
			return
		}
		sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if err == nil {
			_, err = config.App.Send(request.Context(), sessionID, request.FormValue("text"))
		}
		if err == nil {
			http.Redirect(writer, request, "/?session="+sessionID.String(), http.StatusSeeOther)
			return
		}
		renderPage(writer, state, request.PathValue("session_id"), safeNotice(err))
	})
	mux.HandleFunc("POST /sessions/{session_id}/cancel", func(writer http.ResponseWriter, request *http.Request) {
		if !ensureMutation(writer, request) {
			return
		}
		sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if err == nil {
			turnID, turnErr := agentruntime.ParseTurnID(request.FormValue("turn"))
			if turnErr != nil {
				err = turnErr
			} else {
				_, err = config.App.Cancel(request.Context(), sessionID, turnID)
			}
		}
		if err == nil {
			http.Redirect(writer, request, "/?session="+sessionID.String(), http.StatusSeeOther)
			return
		}
		renderPage(writer, state, request.PathValue("session_id"), safeNotice(err))
	})
	mux.HandleFunc("GET /sessions/{session_id}", func(writer http.ResponseWriter, request *http.Request) {
		sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if err == nil {
			var view agentruntime.SessionView
			view, err = config.App.Resume(request.Context(), sessionID)
			if err == nil {
				renderPage(writer, state, sessionID.String(), fmt.Sprintf("state=%s queued=%d", view.Session.State, view.QueuedTurnCount))
				return
			}
		}
		renderPage(writer, state, request.PathValue("session_id"), safeNotice(err))
	})
	mux.HandleFunc("GET /sessions/{session_id}/events", func(writer http.ResponseWriter, request *http.Request) {
		sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if err == nil {
			pageResult, reconnectErr := config.App.Reconnect(request.Context(), sessionID, agentruntime.Cursor(request.URL.Query().Get("after")))
			if reconnectErr == nil {
				renderPage(writer, state, sessionID.String(), fmt.Sprintf("events=%d next_cursor=%s", len(pageResult.Events), pageResult.NextCursor))
				return
			}
			err = reconnectErr
		}
		renderPage(writer, state, request.PathValue("session_id"), safeNotice(err))
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

func safeNotice(err error) string {
	if err == nil {
		return "request could not be completed"
	}
	return "request could not be completed: " + err.Error()
}
