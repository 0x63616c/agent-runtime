//go:build integration

package runtimeapiprocess_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimeapiprocess"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestDurablePostgresMinIOAPIProcessSurvivesRestart(t *testing.T) {
	postgresDSN := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	accessKey := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secretKey := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	bucket := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	minioClient, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: false})
	if err != nil {
		t.Fatalf("create MinIO setup client: %v", err)
	}
	if err := minioClient.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
		t.Fatalf("create declared integration bucket: %v", err)
	}
	config, err := runtimeapiprocess.Parse(strings.NewReader(fmt.Sprintf(`{"version":1,"listen_address":"127.0.0.1:0","storage":{"mode":"postgres","database_dsn_environment":"STATE_DSN","content":{"endpoint":%q,"access_key_environment":"CONTENT_ACCESS","secret_key_environment":"CONTENT_SECRET","bucket":%q}},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"durable","principal":"admin","admin":true,"bearer_token_environment":"ADMIN_TOKEN"},{"tenant":"durable","principal":"alice","admin":false,"bearer_token_environment":"ALICE_TOKEN"}]}`, endpoint, bucket)))
	if err != nil {
		t.Fatalf("parse durable process configuration: %v", err)
	}
	secrets := map[string]string{"STATE_DSN": postgresDSN, "CONTENT_ACCESS": accessKey, "CONTENT_SECRET": secretKey, "ADMIN_TOKEN": "durable-admin-token", "ALICE_TOKEN": "durable-alice-token"}
	baseURL, stop := startDurableRuntimeProcess(t, config, secrets)
	ids := &durableRequestIDs{}
	admin := durableProcessClient(t, baseURL, secrets["ADMIN_TOKEN"], ids)
	alice := durableProcessClient(t, baseURL, secrets["ALICE_TOKEN"], ids)
	agent, err := admin.CreateAgent(context.Background(), agentruntime.CreateAgentRequest{IdempotencyKey: "durable-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "persist safely"})
	if err != nil {
		t.Fatalf("create durable Agent: %v", err)
	}
	policy, err := admin.CreatePolicy(context.Background(), agentruntime.CreatePolicyRequest{IdempotencyKey: "durable-policy", Name: "workspace-write", Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil {
		t.Fatalf("create durable Policy: %v", err)
	}
	session, err := alice.CreateSession(context.Background(), agentruntime.CreateSessionRequest{IdempotencyKey: "durable-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create durable Session: %v", err)
	}
	accepted, err := alice.SendInput(context.Background(), agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "durable-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "survive restart"}}})
	if err != nil {
		t.Fatalf("send durable Input: %v", err)
	}
	stop()

	baseURL, stop = startDurableRuntimeProcess(t, config, secrets)
	defer stop()
	admin = durableProcessClient(t, baseURL, secrets["ADMIN_TOKEN"], ids)
	alice = durableProcessClient(t, baseURL, secrets["ALICE_TOKEN"], ids)
	if restored, err := admin.GetPolicy(context.Background(), policy.Name, policy.Revision); err != nil || !reflect.DeepEqual(restored, policy) {
		t.Fatalf("read restarted Policy = %#v, %v; want %#v", restored, err, policy)
	}
	if _, err := alice.GetPolicy(context.Background(), policy.Name, policy.Revision); !isSafeDurablePolicyDenial(err) {
		t.Fatalf("non-admin restarted Policy read error = %v, want non-enumerating not-found", err)
	}
	if view, err := alice.InspectSession(context.Background(), session.ID); err != nil || view.Session.ID != session.ID || view.Session.AgentID != session.AgentID || view.Session.AgentRevision != session.AgentRevision || view.Session.State != agentruntime.SessionOpen {
		t.Fatalf("inspect restarted Session = %#v, %v; want retained open Session %#v", view.Session, err, session)
	}
	if turn, err := alice.InspectTurn(context.Background(), session.ID, accepted.Turn.ID); err != nil || turn.State != agentruntime.TurnRunning {
		t.Fatalf("inspect restarted Turn = %#v, %v", turn, err)
	}
	if page, err := alice.Events(context.Background(), session.ID, "", 20); err != nil || len(page.Events) < 3 {
		t.Fatalf("read restarted events = %#v, %v", page, err)
	}
	if turn, err := alice.CancelTurn(context.Background(), agentruntime.CancelTurnRequest{SessionID: session.ID, TurnID: accepted.Turn.ID, IdempotencyKey: "durable-cancel"}); err != nil || turn.State != agentruntime.TurnCancelled {
		t.Fatalf("cancel restarted Turn = %#v, %v", turn, err)
	}
}

func TestRuntimeProcessAnnouncesReadinessOnlyAfterHealthRouteServes(t *testing.T) {
	config, err := runtimeapiprocess.Parse(strings.NewReader(`{"version":1,"listen_address":"127.0.0.1:0","storage":{"mode":"memory-unsafe"},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"local","principal":"admin","admin":true,"bearer_token_environment":"ADMIN_TOKEN"}]}`))
	if err != nil {
		t.Fatalf("parse process configuration: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readiness := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		done <- runtimeapiprocess.Run(ctx, config, mapLookup(map[string]string{"ADMIN_TOKEN": "admin-token-0000"}), func(address string) {
			response, err := http.Get("http://" + address + "/readyz") // #nosec G107 -- address is the process-owned loopback listener.
			if err != nil {
				readiness <- err
				return
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != http.StatusOK {
				readiness <- fmt.Errorf("readiness status = %d", response.StatusCode)
				return
			}
			readiness <- nil
		})
	}()
	if err := <-readiness; err != nil {
		t.Fatalf("readiness callback observed unavailable route: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("stop runtime process: %v", err)
	}
}

func isSafeDurablePolicyDenial(err error) bool {
	var runtimeError *agentruntime.Error
	return errors.As(err, &runtimeError) && runtimeError.Failure.Code == agentruntime.FailureNotFound && !strings.Contains(err.Error(), "workspace-write") && !strings.Contains(err.Error(), "durable-alice-token")
}

func startDurableRuntimeProcess(t *testing.T, config runtimeapiprocess.Config, secrets map[string]string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen durable process: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtimeapiprocess.Serve(ctx, config, mapLookup(secrets), listener) }()
	return "http://" + listener.Addr().String(), func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("stop durable process: %v", err)
		}
	}
}

func durableProcessClient(t *testing.T, baseURL, token string, ids agentruntime.RequestIDSource) *agentruntime.Client {
	t.Helper()
	credential, err := agentruntime.NewStaticBearerCredential(token)
	if err != nil {
		t.Fatal(err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: baseURL, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type durableRequestIDs struct {
	mu   sync.Mutex
	next uint64
}

func (source *durableRequestIDs) NextRequestID() (agentruntime.RequestID, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	return agentruntime.ParseRequestID(fmt.Sprintf("req_%016d", source.next))
}

func requiredRuntimeAPIEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required for durable runtime API integration", name)
	}
	return value
}
