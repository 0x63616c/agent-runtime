package durablechat_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	durablechat "github.com/0x63616c/agent-runtime/examples/durable-chat"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestDurableChatQueuesReconnectsCancelsAndResumesThroughPublicClient(t *testing.T) {
	client := &fakeClient{}
	app, err := durablechat.NewApp(client, &keys{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.NewSession(context.Background(), "arev_1234567890ABCDEF")
	if err != nil || session.ID != "sess_1234567890ABCDEF" {
		t.Fatalf("new session = %#v, %v", session, err)
	}
	accepted, err := app.Send(context.Background(), session.ID, "hello after restart")
	if err != nil || accepted.Turn.ID != "turn_1234567890ABCDEF" || client.sent.IdempotencyKey != "message-2" {
		t.Fatalf("send = %#v, %v %#v", accepted, err, client.sent)
	}
	page, err := app.Reconnect(context.Background(), session.ID, "cur_1234567890ABCDEF")
	if err != nil || page.NextCursor != "cur_ABCDEF1234567890" || client.after != "cur_1234567890ABCDEF" {
		t.Fatalf("reconnect = %#v, %v after=%q", page, err, client.after)
	}
	view, err := app.Resume(context.Background(), session.ID)
	if err != nil || view.Session.ID != session.ID {
		t.Fatalf("resume = %#v, %v", view, err)
	}
	turn, err := app.Cancel(context.Background(), session.ID, accepted.Turn.ID)
	if err != nil || turn.State != agentruntime.TurnCancelled || client.cancel.IdempotencyKey != "cancel-3" {
		t.Fatalf("cancel = %#v, %v %#v", turn, err, client.cancel)
	}
}

func TestWebHandlerUsesSameDurableControllerAndLabelsSubscriptionState(t *testing.T) {
	client := &fakeClient{}
	app, _ := durablechat.NewApp(client, &keys{})
	handler, err := durablechat.NewWebHandler(durablechat.WebConfig{App: app, ProviderState: "subscription canary blocked"})
	if err != nil {
		t.Fatal(err)
	}
	create := httptest.NewRecorder()
	createRequest := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader("revision=arev_1234567890ABCDEF"))
	createRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(create, createRequest)
	if create.Code != http.StatusSeeOther || create.Header().Get("Location") != "/?session=sess_1234567890ABCDEF" {
		t.Fatalf("create response = %d %q", create.Code, create.Header().Get("Location"))
	}
	message := httptest.NewRecorder()
	messageRequest := httptest.NewRequest(http.MethodPost, "/sessions/sess_1234567890ABCDEF/messages", strings.NewReader("text=queued+web+message"))
	messageRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(message, messageRequest)
	if message.Code != http.StatusSeeOther || client.sent.Parts[0].Text != "queued web message" {
		t.Fatalf("message response = %d sent=%#v", message.Code, client.sent)
	}
	cancel := httptest.NewRecorder()
	cancelRequest := httptest.NewRequest(http.MethodPost, "/sessions/sess_1234567890ABCDEF/cancel", strings.NewReader("turn=turn_1234567890ABCDEF"))
	cancelRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(cancel, cancelRequest)
	if cancel.Code != http.StatusSeeOther || client.cancel.TurnID != "turn_1234567890ABCDEF" {
		t.Fatalf("cancel response = %d cancelled=%#v", cancel.Code, client.cancel)
	}
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/?session=sess_1234567890ABCDEF", nil))
	if !strings.Contains(page.Body.String(), "subscription canary blocked") || strings.Contains(page.Body.String(), "token") {
		t.Fatalf("page = %q", page.Body.String())
	}
}

func TestTerminalUsesPublicLifecycleCommands(t *testing.T) {
	app, _ := durablechat.NewApp(&fakeClient{}, &keys{})
	var output bytes.Buffer
	err := durablechat.RunTerminal(context.Background(), app, strings.NewReader("new arev_1234567890ABCDEF\nsend sess_1234567890ABCDEF queued text\nevents sess_1234567890ABCDEF cur_1234567890ABCDEF\ncancel sess_1234567890ABCDEF turn_1234567890ABCDEF\nquit\n"), &output)
	if err != nil || !strings.Contains(output.String(), "queued turn") || !strings.Contains(output.String(), "next_cursor") || !strings.Contains(output.String(), "subscription canary") {
		t.Fatalf("terminal = %q, %v", output.String(), err)
	}
}

type keys struct{ n int }

func (keys *keys) Next(action string) (string, error) {
	keys.n++
	return fmt.Sprintf("%s-%d", action, keys.n), nil
}

type fakeClient struct {
	sent   agentruntime.SendInputRequest
	after  agentruntime.Cursor
	cancel agentruntime.CancelTurnRequest
}

func (*fakeClient) CreateSession(context.Context, agentruntime.CreateSessionRequest) (agentruntime.Session, error) {
	return agentruntime.Session{ID: "sess_1234567890ABCDEF", State: agentruntime.SessionOpen}, nil
}
func (client *fakeClient) SendInput(_ context.Context, request agentruntime.SendInputRequest) (agentruntime.SendInputResult, error) {
	client.sent = request
	return agentruntime.SendInputResult{Turn: agentruntime.Turn{ID: "turn_1234567890ABCDEF", State: agentruntime.TurnQueued}}, nil
}
func (*fakeClient) InspectSession(context.Context, agentruntime.SessionID) (agentruntime.SessionView, error) {
	return agentruntime.SessionView{Session: agentruntime.Session{ID: "sess_1234567890ABCDEF", State: agentruntime.SessionOpen}}, nil
}
func (client *fakeClient) Events(_ context.Context, _ agentruntime.SessionID, after agentruntime.Cursor, _ int) (agentruntime.EventPage, error) {
	client.after = after
	return agentruntime.EventPage{NextCursor: "cur_ABCDEF1234567890"}, nil
}
func (client *fakeClient) CancelTurn(_ context.Context, request agentruntime.CancelTurnRequest) (agentruntime.Turn, error) {
	client.cancel = request
	return agentruntime.Turn{ID: "turn_1234567890ABCDEF", State: agentruntime.TurnCancelled}, nil
}
