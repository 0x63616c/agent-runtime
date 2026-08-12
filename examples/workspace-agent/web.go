package workspaceagent

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

const maxWebFormBytes = agentruntime.MaxTextPartBytes + 4096

// NewWebHandler creates the loopback Workspace Agent approval inbox UI.
func NewWebHandler(inbox *Inbox) (http.Handler, error) {
	if inbox == nil {
		return nil, fmt.Errorf("create Workspace Agent web handler: inbox is required")
	}
	csrfToken, err := newCSRFToken()
	if err != nil {
		return nil, fmt.Errorf("create Workspace Agent web CSRF token: %w", err)
	}
	page, err := template.New("workspace").Parse(`<!doctype html><title>Workspace Agent</title><h1>Workspace Agent</h1><p>{{.Status}}</p><h2>Approval inbox</h2><ul>{{range .Approvals}}<li>{{.ID}} {{if .Action}}{{.Action.Verb}} {{.Action.Target}}{{end}} {{.State}} <form method="post" action="/approvals/{{.ID}}/approve"><input type="hidden" name="csrf" value="{{$.CSRFToken}}"><input name="key" required><button>Approve</button></form><form method="post" action="/approvals/{{.ID}}/deny"><input type="hidden" name="csrf" value="{{$.CSRFToken}}"><input name="key" required><button>Deny</button></form><form method="post" action="/approvals/{{.ID}}/cancel"><input type="hidden" name="csrf" value="{{$.CSRFToken}}"><input name="key" required><button>Cancel turn</button></form></li>{{end}}</ul>{{.Notice}}`)
	if err != nil {
		return nil, err
	}
	render := func(w http.ResponseWriter, r *http.Request, notice string) {
		pageResult, err := inbox.List(r.Context())
		if err != nil {
			notice = "request could not be completed"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, struct {
			Status, Notice, CSRFToken string
			Approvals                 []agentruntime.Approval
		}{SandboxStatus(), notice, csrfToken, pageResult.Approvals})
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
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) { render(w, r, "") })
	mux.HandleFunc("POST /approvals/{approval_id}/{decision}", func(w http.ResponseWriter, r *http.Request) {
		if !ensureMutation(w, r) {
			return
		}
		id, err := agentruntime.ParseApprovalID(r.PathValue("approval_id"))
		decision := r.PathValue("decision")
		if err == nil && (decision == "approve" || decision == "deny") {
			state := agentruntime.ApprovalApproved
			if decision == "deny" {
				state = agentruntime.ApprovalDenied
			}
			_, err = inbox.Decide(r.Context(), id, state, r.FormValue("key"))
		}
		if err == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		render(w, r, "request could not be completed")
	})
	mux.HandleFunc("POST /approvals/{approval_id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !ensureMutation(w, r) {
			return
		}
		id, err := agentruntime.ParseApprovalID(r.PathValue("approval_id"))
		if err == nil {
			var approval agentruntime.Approval
			approval, err = inbox.client.InspectApproval(r.Context(), id)
			if err == nil {
				_, err = inbox.Cancel(r.Context(), approval, r.FormValue("key"))
			}
		}
		if err == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		render(w, r, "request could not be completed")
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
