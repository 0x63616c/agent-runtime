package tooldispatch_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/tooldispatch"
)

func TestDispatchTriggerAuthenticatesAnEmptyRequestWithoutExposingExecutionAuthority(t *testing.T) {
	calls := 0
	service, err := tooldispatch.NewServer("broker-token", func(context.Context) error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(service)
	defer server.Close()
	for _, test := range []struct {
		token, body    string
		audience, role string
		want           int
	}{{"", "", tooldispatch.Audience, tooldispatch.Role, http.StatusNotFound}, {"Bearer wrong", "", tooldispatch.Audience, tooldispatch.Role, http.StatusNotFound}, {"Bearer broker-token", "{}", tooldispatch.Audience, tooldispatch.Role, http.StatusNotFound}, {"Bearer broker-token", "", "wrong", tooldispatch.Role, http.StatusNotFound}, {"Bearer broker-token", "", tooldispatch.Audience, tooldispatch.Role, http.StatusOK}} {
		request, err := http.NewRequest(http.MethodPost, server.URL+"/private/v1/tool-dispatch/scan", strings.NewReader(test.body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", test.token)
		request.Header.Set("X-Tool-Dispatch-Audience", test.audience)
		request.Header.Set("X-Tool-Dispatch-Role", test.role)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if response.StatusCode != test.want {
			t.Fatalf("status = %d, want %d", response.StatusCode, test.want)
		}
	}
	if calls != 1 {
		t.Fatalf("scan calls = %d, want 1", calls)
	}
}

func TestClientSendsOnlyTheFixedTriggerIdentity(t *testing.T) {
	service, err := tooldispatch.NewServer("broker-token", func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(service)
	defer server.Close()
	client, err := tooldispatch.NewClient(server.URL, "broker-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.DispatchOnce(context.Background())
	if err != nil || !receipt.Attempted {
		t.Fatalf("DispatchOnce() = %#v, %v", receipt, err)
	}
}

func TestClientRefusesInsecureTriggerEndpoint(t *testing.T) {
	client, err := tooldispatch.NewClient("http://tool-dispatch.invalid", "broker-token", nil)
	if client != nil || err == nil {
		t.Fatalf("NewClient insecure endpoint = %#v, %v", client, err)
	}
}

func TestBrokerServerRefusesMissingWorker(t *testing.T) {
	if service, err := tooldispatch.NewBrokerServer("broker-token", nil); err == nil || service != nil {
		t.Fatalf("NewBrokerServer(nil) = %#v, %v", service, err)
	}
}

func TestDispatchTriggerRejectsChunkedPayload(t *testing.T) {
	calls := 0
	service, err := tooldispatch.NewServer("broker-token", func(context.Context) error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service)
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/private/v1/tool-dispatch/scan", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.Header.Set("Authorization", "Bearer broker-token")
	request.Header.Set("X-Tool-Dispatch-Audience", tooldispatch.Audience)
	request.Header.Set("X-Tool-Dispatch-Role", tooldispatch.Role)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNotFound || calls != 0 {
		t.Fatalf("chunked trigger = status %d calls %d, want 404 and zero calls", response.StatusCode, calls)
	}
}
