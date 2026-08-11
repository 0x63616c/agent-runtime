package durablechat

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

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
	state := strings.TrimSpace(config.ProviderState)
	if state == "" {
		state = "Codex subscription support is blocked pending an official production-supported model surface; this UI is not a subscription canary."
	}
	page, err := template.New("chat").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Durable Chat</title></head><body><h1>Durable Chat</h1><p>{{.Provider}}</p><form method="post" action="/sessions"><label>Agent revision <input name="revision" required></label><button>Create session</button></form>{{if .Session}}<h2>Session {{.Session}}</h2><form method="post" action="/sessions/{{.Session}}/messages"><textarea name="text" required></textarea><button>Queue message</button></form><form method="get" action="/sessions/{{.Session}}"><button>Resume state</button></form><form method="get" action="/sessions/{{.Session}}/events"><label>Cursor <input name="after"></label><button>Reconnect events</button></form>{{end}}{{if .Notice}}<pre>{{.Notice}}</pre>{{end}}</body></html>`)
	if err != nil {
		return nil, fmt.Errorf("create Durable Chat web handler: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(writer http.ResponseWriter, request *http.Request) {
		renderPage(writer, page, state, request.URL.Query().Get("session"), "")
	})
	mux.HandleFunc("POST /sessions", func(writer http.ResponseWriter, request *http.Request) {
		revision, err := agentruntime.ParseAgentRevisionID(request.FormValue("revision"))
		if err == nil {
			var session agentruntime.Session
			session, err = config.App.NewSession(request.Context(), revision)
			if err == nil {
				http.Redirect(writer, request, "/?session="+session.ID.String(), http.StatusSeeOther)
				return
			}
		}
		renderPage(writer, page, state, "", safeNotice(err))
	})
	mux.HandleFunc("POST /sessions/{session_id}/messages", func(writer http.ResponseWriter, request *http.Request) {
		sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if err == nil {
			_, err = config.App.Send(request.Context(), sessionID, request.FormValue("text"))
		}
		if err == nil {
			http.Redirect(writer, request, "/?session="+sessionID.String(), http.StatusSeeOther)
			return
		}
		renderPage(writer, page, state, request.PathValue("session_id"), safeNotice(err))
	})
	mux.HandleFunc("GET /sessions/{session_id}", func(writer http.ResponseWriter, request *http.Request) {
		sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if err == nil {
			var view agentruntime.SessionView
			view, err = config.App.Resume(request.Context(), sessionID)
			if err == nil {
				renderPage(writer, page, state, sessionID.String(), fmt.Sprintf("state=%s queued=%d", view.Session.State, view.QueuedTurnCount))
				return
			}
		}
		renderPage(writer, page, state, request.PathValue("session_id"), safeNotice(err))
	})
	mux.HandleFunc("GET /sessions/{session_id}/events", func(writer http.ResponseWriter, request *http.Request) {
		sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if err == nil {
			pageResult, reconnectErr := config.App.Reconnect(request.Context(), sessionID, agentruntime.Cursor(request.URL.Query().Get("after")))
			if reconnectErr == nil {
				renderPage(writer, page, state, sessionID.String(), fmt.Sprintf("events=%d next_cursor=%s", len(pageResult.Events), pageResult.NextCursor))
				return
			}
			err = reconnectErr
		}
		renderPage(writer, page, state, request.PathValue("session_id"), safeNotice(err))
	})
	return mux, nil
}

func renderPage(writer http.ResponseWriter, page *template.Template, provider, session, notice string) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(writer, struct{ Provider, Session, Notice string }{provider, session, notice})
}

func safeNotice(err error) string {
	if err == nil {
		return "request could not be completed"
	}
	return "request could not be completed: " + err.Error()
}
