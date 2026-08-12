package workspaceagent

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

type failingTerminalWriter struct{}

func (failingTerminalWriter) Write([]byte) (int, error) {
	return 0, errors.New("terminal unavailable")
}

func TestInboxUsesOnlyOwnerScopedPublicApprovalAndTurnCommands(t *testing.T) {
	approval := agentruntime.Approval{ID: "appr_1234567890ABCDEF", SessionID: "sess_1234567890ABCDEF", TurnID: "turn_1234567890ABCDEF", ToolCallID: "tcall_1234567890ABCDEF", State: agentruntime.ApprovalPending, Action: &agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, Scope: &agentruntime.ApprovalScope{MaximumUses: 1}, ExpiresAt: time.Date(2026, 8, 11, 20, 0, 0, 0, time.UTC)}
	client := &approvalClient{approval: approval}
	inbox, err := NewInbox(client)
	if err != nil {
		t.Fatal(err)
	}
	page, err := inbox.List(context.Background())
	if err != nil || len(page.Approvals) != 1 {
		t.Fatalf("list inbox = %#v, %v", page, err)
	}
	if _, err := inbox.Decide(context.Background(), approval.ID, agentruntime.ApprovalApproved, "approve-workspace"); err != nil || client.decision.Decision != agentruntime.ApprovalApproved {
		t.Fatalf("approve inbox = %v decision=%#v", err, client.decision)
	}
	if _, err := inbox.Cancel(context.Background(), approval, "cancel-workspace"); err != nil || client.cancel.SessionID != approval.SessionID || client.cancel.TurnID != approval.TurnID {
		t.Fatalf("cancel inbox = %v request=%#v", err, client.cancel)
	}
	if row := Terminal(approval); !strings.Contains(row, "write workspace-service") || strings.Contains(row, "digest") {
		t.Fatalf("terminal row = %q", row)
	}
	if row := HTML(approval); !strings.HasPrefix(row, "<li>") || !strings.HasSuffix(row, "</li>") {
		t.Fatalf("html row = %q", row)
	}
}

func TestWorkspaceApprovalWebAndTerminalStayPublicAndBlocked(t *testing.T) {
	approval := agentruntime.Approval{ID: "appr_1234567890ABCDEF", SessionID: "sess_1234567890ABCDEF", TurnID: "turn_1234567890ABCDEF", ToolCallID: "tcall_1234567890ABCDEF", State: agentruntime.ApprovalPending, Action: &agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, ExpiresAt: time.Date(2026, 8, 11, 20, 0, 0, 0, time.UTC)}
	inbox, err := NewInbox(&approvalClient{approval: approval})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewWebHandler(inbox)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	if response.Code != 200 || !strings.Contains(response.Body.String(), "Workspace sandbox execution is unavailable") || !strings.Contains(response.Body.String(), approval.ID.String()) {
		t.Fatalf("web response = %d %q", response.Code, response.Body.String())
	}
	var output bytes.Buffer
	if err := RunTerminal(context.Background(), inbox, strings.NewReader("list\nsandbox-status\nquit\n"), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), approval.ID.String()) || !strings.Contains(output.String(), "unavailable") {
		t.Fatalf("terminal output = %q", output.String())
	}
}

func TestRunTerminalReturnsOutputFailure(t *testing.T) {
	inbox, err := NewInbox(&approvalClient{})
	if err != nil {
		t.Fatal(err)
	}
	if err := RunTerminal(context.Background(), inbox, strings.NewReader("quit\n"), failingTerminalWriter{}); err == nil || !strings.Contains(err.Error(), "terminal unavailable") {
		t.Fatalf("terminal output failure = %v", err)
	}
}

func TestWorkspaceApprovalWebRejectsHostileOriginWithoutMutating(t *testing.T) {
	approval := agentruntime.Approval{ID: "appr_1234567890ABCDEF", SessionID: "sess_1234567890ABCDEF", TurnID: "turn_1234567890ABCDEF", ToolCallID: "tcall_1234567890ABCDEF", State: agentruntime.ApprovalPending, Action: &agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, ExpiresAt: time.Date(2026, 8, 11, 20, 0, 0, 0, time.UTC)}
	client := &approvalClient{approval: approval}
	inbox, err := NewInbox(client)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewWebHandler(inbox)
	if err != nil {
		t.Fatal(err)
	}
	csrf := workspaceWebCSRFToken(t, handler)
	for _, test := range []struct {
		name string
		path string
	}{
		{name: "approve", path: "/approvals/appr_1234567890ABCDEF/approve"},
		{name: "deny", path: "/approvals/appr_1234567890ABCDEF/deny"},
		{name: "cancel", path: "/approvals/appr_1234567890ABCDEF/cancel"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "http://trusted.example"+test.path, strings.NewReader(url.Values{"csrf": {csrf}, "key": {"hostile key"}}.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", "http://evil.example")
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("hostile mutation status = %d", response.Code)
			}
			if client.decision.IdempotencyKey != "" || client.cancel.IdempotencyKey != "" {
				t.Fatalf("hostile mutation reached public client: decision=%#v cancel=%#v", client.decision, client.cancel)
			}
		})
	}
}

func TestWorkspaceApprovalWebRejectsOversizedMutationWithoutMutating(t *testing.T) {
	approval := agentruntime.Approval{ID: "appr_1234567890ABCDEF", SessionID: "sess_1234567890ABCDEF", TurnID: "turn_1234567890ABCDEF", ToolCallID: "tcall_1234567890ABCDEF", State: agentruntime.ApprovalPending, Action: &agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, ExpiresAt: time.Date(2026, 8, 11, 20, 0, 0, 0, time.UTC)}
	client := &approvalClient{approval: approval}
	inbox, err := NewInbox(client)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewWebHandler(inbox)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://trusted.example/approvals/appr_1234567890ABCDEF/approve", strings.NewReader(url.Values{
		"csrf": {workspaceWebCSRFToken(t, handler)},
		"key":  {strings.Repeat("a", maxWebFormBytes+1)},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://trusted.example")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || client.decision.IdempotencyKey != "" {
		t.Fatalf("oversized mutation = status=%d decision=%#v", response.Code, client.decision)
	}
}

func workspaceWebCSRFToken(t *testing.T, handler http.Handler) string {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://trusted.example/", nil))
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(response.Body.String())
	if len(match) != 2 {
		t.Fatalf("CSRF token missing from page: %q", response.Body.String())
	}
	return match[1]
}

type approvalClient struct {
	approval agentruntime.Approval
	decision agentruntime.DecideApprovalRequest
	cancel   agentruntime.CancelTurnRequest
}

func (client *approvalClient) ListApprovals(context.Context) (agentruntime.ApprovalPage, error) {
	return agentruntime.ApprovalPage{Approvals: []agentruntime.Approval{client.approval}}, nil
}
func (client *approvalClient) InspectApproval(context.Context, agentruntime.ApprovalID) (agentruntime.Approval, error) {
	return client.approval, nil
}
func (client *approvalClient) DecideApproval(_ context.Context, request agentruntime.DecideApprovalRequest) (agentruntime.Approval, error) {
	client.decision = request
	return client.approval, nil
}
func (client *approvalClient) CancelTurn(_ context.Context, request agentruntime.CancelTurnRequest) (agentruntime.Turn, error) {
	client.cancel = request
	return agentruntime.Turn{}, nil
}
