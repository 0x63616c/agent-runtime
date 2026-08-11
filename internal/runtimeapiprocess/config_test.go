package runtimeapiprocess_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimeapiprocess"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

const validConfig = `{
  "version": 1,
  "listen_address": "127.0.0.1:8088",
  "storage": {"mode":"memory-unsafe"},
  "model_profiles": ["balanced"],
  "max_request_bytes": 4194304,
  "principals": [
    {"tenant":"local","principal":"admin","admin":true,"bearer_token_environment":"ADMIN_TOKEN"},
    {"tenant":"local","principal":"user","admin":false,"bearer_token_environment":"USER_TOKEN"}
  ]
}`

func TestConfigurationIsStrictAndRequiresExplicitUnsafeMemoryStorage(t *testing.T) {
	t.Parallel()
	if _, err := runtimeapiprocess.Parse(strings.NewReader(validConfig)); err != nil {
		t.Fatalf("Parse(valid): %v", err)
	}
	invalid := strings.Replace(validConfig, `"memory-unsafe"`, `"memory"`, 1)
	if _, err := runtimeapiprocess.Parse(strings.NewReader(invalid)); err == nil {
		t.Fatal("Parse(implicit storage) error = nil")
	}
	unknown := strings.Replace(validConfig, `"version": 1`, `"version": 1, "unknown": true`, 1)
	if _, err := runtimeapiprocess.Parse(strings.NewReader(unknown)); err == nil {
		t.Fatal("Parse(unknown field) error = nil")
	}
	kubernetes := strings.Replace(validConfig, "127.0.0.1:8088", "0.0.0.0:8088", 1)
	if _, err := runtimeapiprocess.Parse(strings.NewReader(kubernetes)); err != nil {
		t.Fatalf("Parse(Kubernetes bind): %v", err)
	}
	observed := strings.Replace(validConfig, `"principals": [`, `"observability":{"identity_correlation_key_environment":"OBSERVABILITY_CORRELATION_KEY"}, "principals": [`, 1)
	if _, err := runtimeapiprocess.Parse(strings.NewReader(observed)); err != nil {
		t.Fatalf("Parse(observability): %v", err)
	}
	emptyObserved := strings.Replace(validConfig, `"principals": [`, `"observability":{}, "principals": [`, 1)
	if _, err := runtimeapiprocess.Parse(strings.NewReader(emptyObserved)); err == nil {
		t.Fatal("Parse(empty observability) error = nil")
	}
	nullObserved := strings.Replace(validConfig, `"principals": [`, `"observability":null, "principals": [`, 1)
	if _, err := runtimeapiprocess.Parse(strings.NewReader(nullObserved)); err == nil {
		t.Fatal("Parse(null observability) error = nil")
	}
}

func TestConfigurationAcceptsOnlyCompleteDurablePostgresAndMinIOStorage(t *testing.T) {
	durable := strings.Replace(validConfig, `"storage": {"mode":"memory-unsafe"}`, `"storage":{"mode":"postgres","database_dsn_environment":"STATE_DATABASE_DSN","content":{"endpoint":"minio.runtime.svc:9000","access_key_environment":"CONTENT_ACCESS_KEY","secret_key_environment":"CONTENT_SECRET_KEY","bucket":"agent-runtime-content"}}`, 1)
	if _, err := runtimeapiprocess.Parse(strings.NewReader(durable)); err != nil {
		t.Fatalf("Parse(durable): %v", err)
	}
	incomplete := strings.Replace(durable, `,"bucket":"agent-runtime-content"`, "", 1)
	if _, err := runtimeapiprocess.Parse(strings.NewReader(incomplete)); err == nil {
		t.Fatal("Parse(incomplete durable) error = nil")
	}
}

func TestRunnableRoleServesPublicSDKWithoutInternalTypes(t *testing.T) {
	config, err := runtimeapiprocess.Parse(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runtimeapiprocess.Serve(ctx, config, mapLookup(map[string]string{"ADMIN_TOKEN": "admin-token-0000", "USER_TOKEN": "user-token-00000"}), listener)
	}()
	baseURL := "http://" + listener.Addr().String()
	ids := &requestIDs{}
	admin := processClient(t, baseURL, "admin-token-0000", ids)
	user := processClient(t, baseURL, "user-token-00000", ids)
	agent, err := admin.CreateAgent(context.Background(), agentruntime.CreateAgentRequest{IdempotencyKey: "create-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "help"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	session, err := user.CreateSession(context.Background(), agentruntime.CreateSessionRequest{IdempotencyKey: "create-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := user.SendInput(context.Background(), agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "send-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}}}); err != nil {
		t.Fatalf("SendInput: %v", err)
	}
	page, err := user.Events(context.Background(), session.ID, "", 10)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(page.Events) < 3 {
		t.Fatalf("events = %d", len(page.Events))
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func mapLookup(values map[string]string) runtimeapiprocess.SecretLookup {
	return func(name string) (string, bool) { value, ok := values[name]; return value, ok }
}

type requestIDs struct {
	mu   sync.Mutex
	next uint64
}

func (source *requestIDs) NextRequestID() (agentruntime.RequestID, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	return agentruntime.ParseRequestID(fmt.Sprintf("req_%016d", source.next))
}

func processClient(t *testing.T, baseURL, token string, ids agentruntime.RequestIDSource) *agentruntime.Client {
	t.Helper()
	credential, err := agentruntime.NewStaticBearerCredential(token)
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: baseURL, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: ids})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}
