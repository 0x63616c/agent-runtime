package workspaceagent

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

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
