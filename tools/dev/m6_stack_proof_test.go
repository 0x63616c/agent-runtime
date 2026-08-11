//go:build stackproof

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestLocalDemoWorkerPublicApprovalAndArtifactLifecycle(t *testing.T) {
	endpoint := requiredStackProofEnvironment(t, "M6_STACK_API_URL")
	admin := stackProofClient(t, endpoint, requiredStackProofEnvironment(t, "M6_STACK_ADMIN_TOKEN"))
	developer := stackProofClient(t, endpoint, requiredStackProofEnvironment(t, "M6_STACK_DEVELOPER_TOKEN"))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	policy, err := admin.CreatePolicy(ctx, agentruntime.CreatePolicyRequest{IdempotencyKey: "m6-proof-policy", Name: "research-dossier-demo", Rules: []agentruntime.PolicyRule{{ToolName: "research", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil || policy.Revision != 1 {
		t.Fatalf("create public demo policy = %#v, %v", policy, err)
	}
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "m6-proof-agent", Name: "research-dossier", ModelProfile: "balanced", Instructions: "use the declared research tool", Tools: []agentruntime.ToolDefinition{{Name: "research", Description: "bounded local demonstration research"}}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := developer.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "m6-proof-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := developer.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "m6-proof-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "produce the local research dossier"}}})
	if err != nil {
		t.Fatal(err)
	}

	var pending agentruntime.ToolCall
	awaitStackProof(t, ctx, func() (bool, error) {
		calls, err := developer.InspectToolCalls(ctx, session.ID, accepted.Turn.ID)
		if err != nil || len(calls.Calls) != 1 {
			return false, err
		}
		pending = calls.Calls[0]
		return pending.State == agentruntime.ToolCallAwaitingApproval && pending.Approval != nil && pending.Approval.State == agentruntime.ApprovalPending, nil
	})
	if pending.Name != "research" || pending.Approval.Action == nil || pending.Approval.Action.Verb != "write" || pending.Approval.Action.Target != "artifact" {
		t.Fatalf("public pending tool projection = %#v", pending)
	}
	if _, err := developer.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: pending.Approval.ID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "m6-proof-approve"}); err != nil {
		t.Fatal(err)
	}

	var completed agentruntime.ToolCall
	awaitStackProof(t, ctx, func() (bool, error) {
		calls, err := developer.InspectToolCalls(ctx, session.ID, accepted.Turn.ID)
		if err != nil || len(calls.Calls) != 1 {
			return false, err
		}
		completed = calls.Calls[0]
		return completed.State == agentruntime.ToolCallSucceeded && completed.Execution != nil && completed.Execution.Result != nil, nil
	})
	artifact, err := developer.OpenArtifact(ctx, completed.Execution.Result.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(artifact.Body)
	if closeErr := artifact.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil || len(body) == 0 || artifact.Artifact != *completed.Execution.Result {
		t.Fatalf("owner-readable tool artifact = %#v bytes=%d err=%v", artifact.Artifact, len(body), err)
	}
	t.Logf("public lifecycle complete: approval=%s tool=%s artifact=%s bytes=%d", pending.Approval.ID, completed.ID, artifact.Artifact.ID, len(body))
}

func requiredStackProofEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func stackProofClient(t *testing.T, endpoint, token string) *agentruntime.Client {
	t.Helper()
	credential, err := agentruntime.NewStaticBearerCredential(token)
	if err != nil {
		t.Fatal(err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: endpoint, HTTPClient: &httpClient, Credentials: credential, RequestIDs: &stackProofIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

var httpClient = http.Client{Timeout: 5 * time.Second}

type stackProofIDs struct{ next atomic.Uint64 }

func (ids *stackProofIDs) NextRequestID() (agentruntime.RequestID, error) {
	return agentruntime.RequestID(fmt.Sprintf("req_M6proof%09d", ids.next.Add(1))), nil
}

func awaitStackProof(t *testing.T, ctx context.Context, condition func() (bool, error)) {
	t.Helper()
	for {
		ready, err := condition()
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		wait, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		<-wait.Done()
		waitErr := wait.Err()
		cancel()
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		if !errors.Is(waitErr, context.DeadlineExceeded) {
			t.Fatal(waitErr)
		}
	}
}
