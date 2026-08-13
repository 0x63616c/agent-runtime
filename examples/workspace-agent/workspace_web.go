package workspaceagent

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

const workspaceWebOperationTimeout = 20 * time.Second

// NewWorkspaceWebHandler creates the loopback Workspace Agent work and approval UI.
func NewWorkspaceWebHandler(app *App, inbox *Inbox) (http.Handler, error) {
	if app == nil || inbox == nil {
		return nil, fmt.Errorf("create Workspace Agent web handler: app and inbox are required")
	}
	csrfToken, err := newCSRFToken()
	if err != nil {
		return nil, fmt.Errorf("create Workspace Agent web CSRF token: %w", err)
	}
	page, err := template.New("workspace").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Workspace Agent</title></head><body><h1>Workspace Agent</h1><p>{{.Status}}</p><form method="post" action="/sessions"><input type="hidden" name="csrf" value="{{.CSRFToken}}"><label>Agent revision <input name="revision" required></label><button>Create workspace session</button></form>{{if .Session}}<h2>Session {{.Session}}</h2><form method="post" action="/sessions/{{.Session}}/requests"><input type="hidden" name="csrf" value="{{.CSRFToken}}"><label>Workspace request <textarea name="text" required></textarea></label><button>Queue request</button></form><form method="get" action="/sessions/{{.Session}}"><button>Resume state and events</button></form><form method="get" action="/sessions/{{.Session}}/output"><label>Turn <input name="turn" required></label><button>Read finalized text output</button></form>{{end}}<h2>Approval inbox</h2><ul>{{range .Approvals}}<li>{{.ID}} {{if .Action}}{{.Action.Verb}} {{.Action.Target}}{{end}} {{.State}} <form method="post" action="/approvals/{{.ID}}/approve"><input type="hidden" name="csrf" value="{{$.CSRFToken}}"><input name="key" required><button>Approve</button></form><form method="post" action="/approvals/{{.ID}}/deny"><input type="hidden" name="csrf" value="{{$.CSRFToken}}"><input name="key" required><button>Deny</button></form><form method="post" action="/approvals/{{.ID}}/cancel"><input type="hidden" name="csrf" value="{{$.CSRFToken}}"><input name="key" required><button>Cancel turn</button></form></li>{{end}}</ul>{{if .Notice}}<pre>{{.Notice}}</pre>{{end}}{{if .Output}}<h2>Finalized text output</h2><pre>{{.Output}}</pre>{{end}}</body></html>`)
	if err != nil {
		return nil, fmt.Errorf("create Workspace Agent web template: %w", err)
	}
	type pageData struct {
		Status, Session, Notice, Output, CSRFToken string
		Approvals                                  []agentruntime.Approval
	}
	render := func(writer http.ResponseWriter, request *http.Request, session, notice, output string) {
		approvals, listErr := inbox.List(request.Context())
		if listErr != nil {
			notice = "request could not be completed"
		}
		var body bytes.Buffer
		if err := page.Execute(&body, pageData{Status: SandboxStatus(), Session: session, Notice: notice, Output: output, CSRFToken: csrfToken, Approvals: approvals.Approvals}); err != nil {
			return
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = writer.Write(body.Bytes())
	}
	operationContext := func(request *http.Request) (context.Context, context.CancelFunc) {
		return context.WithTimeout(request.Context(), workspaceWebOperationTimeout)
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
		render(writer, request, request.URL.Query().Get("session"), "", "")
	})
	mux.HandleFunc("POST /sessions", func(writer http.ResponseWriter, request *http.Request) {
		if !ensureMutation(writer, request) {
			return
		}
		revision, parseErr := agentruntime.ParseAgentRevisionID(request.PostForm.Get("revision"))
		if parseErr == nil {
			ctx, cancel := operationContext(request)
			defer cancel()
			if session, createErr := app.NewSession(ctx, revision); createErr == nil {
				http.Redirect(writer, request, "/?session="+session.ID.String(), http.StatusSeeOther)
				return
			}
		}
		render(writer, request, "", "request could not be completed", "")
	})
	mux.HandleFunc("POST /sessions/{session_id}/requests", func(writer http.ResponseWriter, request *http.Request) {
		if !ensureMutation(writer, request) {
			return
		}
		sessionID, parseErr := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if parseErr == nil {
			ctx, cancel := operationContext(request)
			defer cancel()
			if _, requestErr := app.Request(ctx, sessionID, request.PostForm.Get("text")); requestErr == nil {
				http.Redirect(writer, request, "/?session="+sessionID.String(), http.StatusSeeOther)
				return
			}
		}
		render(writer, request, request.PathValue("session_id"), "request could not be completed", "")
	})
	mux.HandleFunc("GET /sessions/{session_id}", func(writer http.ResponseWriter, request *http.Request) {
		sessionID, parseErr := agentruntime.ParseSessionID(request.PathValue("session_id"))
		if parseErr == nil {
			ctx, cancel := operationContext(request)
			defer cancel()
			if view, resumeErr := app.Resume(ctx, sessionID); resumeErr == nil {
				if events, eventsErr := app.Reconnect(ctx, sessionID, agentruntime.Cursor(request.URL.Query().Get("after"))); eventsErr == nil {
					render(writer, request, sessionID.String(), fmt.Sprintf("state=%s queued=%d events=%d next_cursor=%s", view.Session.State, view.QueuedTurnCount, len(events.Events), events.NextCursor), "")
					return
				}
			}
		}
		render(writer, request, request.PathValue("session_id"), "request could not be completed", "")
	})
	mux.HandleFunc("GET /sessions/{session_id}/output", func(writer http.ResponseWriter, request *http.Request) {
		sessionID, parseErr := agentruntime.ParseSessionID(request.PathValue("session_id"))
		turnID, turnErr := agentruntime.ParseTurnID(request.URL.Query().Get("turn"))
		if parseErr == nil && turnErr == nil {
			ctx, cancel := operationContext(request)
			defer cancel()
			if output, outputErr := app.ReadOutput(ctx, sessionID, turnID); outputErr == nil {
				render(writer, request, sessionID.String(), "finalized text output", output.Text)
				return
			}
		}
		render(writer, request, request.PathValue("session_id"), "request could not be completed", "")
	})
	mux.HandleFunc("POST /approvals/{approval_id}/{decision}", func(writer http.ResponseWriter, request *http.Request) {
		if !ensureMutation(writer, request) {
			return
		}
		id, decideErr := agentruntime.ParseApprovalID(request.PathValue("approval_id"))
		decision := request.PathValue("decision")
		if decideErr == nil && (decision == "approve" || decision == "deny") {
			state := agentruntime.ApprovalApproved
			if decision == "deny" {
				state = agentruntime.ApprovalDenied
			}
			_, decideErr = inbox.Decide(request.Context(), id, state, request.PostForm.Get("key"))
		}
		if decideErr == nil {
			http.Redirect(writer, request, "/", http.StatusSeeOther)
			return
		}
		render(writer, request, "", "request could not be completed", "")
	})
	mux.HandleFunc("POST /approvals/{approval_id}/cancel", func(writer http.ResponseWriter, request *http.Request) {
		if !ensureMutation(writer, request) {
			return
		}
		id, cancelErr := agentruntime.ParseApprovalID(request.PathValue("approval_id"))
		if cancelErr == nil {
			if approval, inspectErr := inbox.client.InspectApproval(request.Context(), id); inspectErr == nil {
				_, cancelErr = inbox.Cancel(request.Context(), approval, request.PostForm.Get("key"))
			}
		}
		if cancelErr == nil {
			http.Redirect(writer, request, "/", http.StatusSeeOther)
			return
		}
		render(writer, request, "", "request could not be completed", "")
	})
	return mux, nil
}
