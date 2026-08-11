//go:build stackproof

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	workspaceagent "github.com/0x63616c/agent-runtime/examples/workspace-agent"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// TestDeclaredLocalWorkspaceFixturePublicLifecycle exercises the complete
// declared local Stack route: orchestration publishes an invocation, the model
// fixture admits one normalized Workspace Tool request through Broker, and the
// tool role writes only an owner Artifact after the public Workspace approval
// client approves. It is not Firecracker or sandbox-execution evidence.
func TestDeclaredLocalWorkspaceFixturePublicLifecycle(t *testing.T) {
	endpoint := requiredStackProofEnvironment(t, "M6_STACK_API_URL")
	admin := stackProofClient(t, endpoint, requiredStackProofEnvironment(t, "M6_STACK_ADMIN_TOKEN"))
	developerToken := requiredStackProofEnvironment(t, "M6_STACK_DEVELOPER_TOKEN")
	developer := stackProofClient(t, endpoint, developerToken)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runKey := fmt.Sprintf("m7-workspace-%d", time.Now().UnixNano())

	policy, err := admin.CreatePolicy(ctx, agentruntime.CreatePolicyRequest{IdempotencyKey: "m7-workspace-policy", Name: "workspace-write-demo", Rules: []agentruntime.PolicyRule{{ToolName: "workspace.write", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil || policy.Revision != 1 {
		t.Fatalf("create public demo policy = %#v, %v", policy, err)
	}
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "m7-workspace-agent", Name: "workspace", ModelProfile: "balanced", Instructions: "use the declared workspace tool", Tools: []agentruntime.ToolDefinition{{Name: "workspace.write", Description: "bounded declared local Workspace fixture"}}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := developer.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: runKey + "-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := developer.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: runKey + "-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "write the declared workspace report"}}})
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
	if pending.Name != "workspace.write" || pending.Approval.Action == nil || pending.Approval.Action.Verb != "write" || pending.Approval.Action.Target != "workspace-service" {
		t.Fatalf("public pending tool projection = %#v", pending)
	}
	if _, err := admin.InspectToolCalls(ctx, session.ID, accepted.Turn.ID); !stackProofNotFound(err) {
		t.Fatalf("non-owner tool inspection = %v, want safe not-found", err)
	}
	if inbox, err := admin.ListApprovals(ctx); err != nil || len(inbox.Approvals) != 0 {
		t.Fatalf("non-owner approval inbox = %#v, %v", inbox, err)
	}
	resetStackProofAfterPending(t, ctx)
	reconnectedEndpoint := restartStackProofAPITunnel(t, ctx)
	reconnectedAdmin := stackProofClient(t, reconnectedEndpoint, requiredStackProofEnvironment(t, "M6_STACK_ADMIN_TOKEN"))
	// Recreate the public client before the owner decision. A rollout can sever
	// the in-flight HTTP connection, so retry only an unobserved transport
	// failure with the same public idempotency key. This proves the retained
	// route can be reconnected/replayed without any model re-submit or duplicate
	// approval effect.
	reconnectedDeveloper := approveAfterStackReset(t, ctx, reconnectedEndpoint, developerToken, pending.Approval.ID, runKey+"-approve")
	inbox, err := workspaceagent.NewInbox(reconnectedDeveloper)
	if err != nil {
		t.Fatal(err)
	}
	if replayed, replayErr := reconnectedDeveloper.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: pending.Approval.ID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: runKey + "-approve"}); replayErr != nil || replayed.State != agentruntime.ApprovalApproved {
		t.Fatalf("replay public approval = %#v, %v", replayed, replayErr)
	}

	var completed agentruntime.ToolCall
	defer func() {
		if t.Failed() {
			executionState := "absent"
			if completed.Execution != nil {
				executionState = string(completed.Execution.State)
			}
			approvalState := "absent"
			if completed.Approval != nil {
				approvalState = string(completed.Approval.State)
			}
			t.Logf("redacted post-reset tool diagnostic: tool_state=%s approval_state=%s execution_state=%s", completed.State, approvalState, executionState)
		}
	}()
	awaitStackProof(t, ctx, func() (bool, error) {
		calls, err := reconnectedDeveloper.InspectToolCalls(ctx, session.ID, accepted.Turn.ID)
		if err != nil || len(calls.Calls) != 1 {
			return false, err
		}
		completed = calls.Calls[0]
		return completed.State == agentruntime.ToolCallSucceeded && completed.Execution != nil && completed.Execution.Result != nil, nil
	})
	artifact, err := reconnectedDeveloper.OpenArtifact(ctx, completed.Execution.Result.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(artifact.Body)
	if closeErr := artifact.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil || len(body) == 0 || artifact.Artifact.ID != completed.Execution.Result.ID || !strings.Contains(string(body), "No workspace service or sandbox was executed") {
		t.Fatalf("owner-readable tool artifact = %#v bytes=%d err=%v", artifact.Artifact, len(body), err)
	}
	if _, err := reconnectedAdmin.OpenArtifact(ctx, completed.Execution.Result.ID); !stackProofNotFound(err) {
		t.Fatalf("non-owner Artifact read = %v, want safe not-found", err)
	}
	if _, err := reconnectedDeveloper.CloseSession(ctx, agentruntime.CloseSessionRequest{SessionID: session.ID, IdempotencyKey: runKey + "-close-session"}); err != nil {
		t.Fatalf("close completed Workspace session before cancellation scenario: %v", err)
	}
	awaitStackProof(t, ctx, func() (bool, error) {
		view, inspectErr := reconnectedDeveloper.InspectSession(ctx, session.ID)
		return inspectErr == nil && view.Session.State == agentruntime.SessionCompleted, inspectErr
	})
	cancelSession, err := reconnectedDeveloper.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: runKey + "-cancel-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	cancelledInput, err := reconnectedDeveloper.SendInput(ctx, agentruntime.SendInputRequest{SessionID: cancelSession.ID, IdempotencyKey: runKey + "-cancel-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "cancel the declared workspace report"}}})
	if err != nil {
		t.Fatal(err)
	}
	var cancelPending agentruntime.ToolCall
	awaitStackProof(t, ctx, func() (bool, error) {
		calls, waitErr := reconnectedDeveloper.InspectToolCalls(ctx, cancelSession.ID, cancelledInput.Turn.ID)
		if waitErr != nil || len(calls.Calls) != 1 {
			return false, waitErr
		}
		cancelPending = calls.Calls[0]
		return cancelPending.Approval != nil && cancelPending.Approval.State == agentruntime.ApprovalPending, nil
	})
	if turn, cancelErr := inbox.Cancel(ctx, *cancelPending.Approval, runKey+"-cancel"); cancelErr != nil || turn.State != agentruntime.TurnCancelled {
		t.Fatalf("cancel pending Workspace turn = %#v, %v", turn, cancelErr)
	}
	awaitStackProof(t, ctx, func() (bool, error) {
		calls, waitErr := reconnectedDeveloper.InspectToolCalls(ctx, cancelSession.ID, cancelledInput.Turn.ID)
		if waitErr != nil || len(calls.Calls) != 1 {
			return false, waitErr
		}
		call := calls.Calls[0]
		return call.Approval != nil && call.Approval.ID == cancelPending.Approval.ID && call.Approval.State == agentruntime.ApprovalCancelled && call.Execution == nil, nil
	})
	t.Logf("public Workspace fixture lifecycle complete: approval=%s tool=%s artifact=%s bytes=%d", pending.Approval.ID, completed.ID, artifact.Artifact.ID, len(body))
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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: endpoint, HTTPClient: &http.Client{Timeout: 5 * time.Second, Transport: transport}, Credentials: credential, RequestIDs: &stackProofIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func approveAfterStackReset(t *testing.T, ctx context.Context, endpoint, token string, approvalID agentruntime.ApprovalID, idempotencyKey string) *agentruntime.Client {
	t.Helper()
	for {
		client := stackProofClient(t, endpoint, token)
		inbox, err := workspaceagent.NewInbox(client)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = inbox.Decide(ctx, approvalID, agentruntime.ApprovalApproved, idempotencyKey); err == nil {
			return client
		} else if !stackProofTransientReconnect(err) {
			t.Fatalf("approve public Workspace pending tool after reset: %v", err)
		}
		wait, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		<-wait.Done()
		waitErr := wait.Err()
		cancel()
		if ctx.Err() != nil {
			t.Fatalf("reconnect public Workspace approval after reset: %v", ctx.Err())
		}
		if !errors.Is(waitErr, context.DeadlineExceeded) {
			t.Fatal(waitErr)
		}
	}
}

func stackProofTransientReconnect(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "eof") ||
		strings.Contains(message, "connection refused") ||
		strings.Contains(message, "connection reset") ||
		strings.Contains(message, "broken pipe")
}

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

func stackProofNotFound(err error) bool {
	var runtimeErr *agentruntime.Error
	return errors.As(err, &runtimeErr) && runtimeErr.Failure.Code == agentruntime.FailureNotFound
}

func resetStackProofAfterPending(t *testing.T, ctx context.Context) {
	t.Helper()
	if os.Getenv("M7_STACK_RESET_AFTER_PENDING") != "1" {
		return
	}
	root := requiredStackProofEnvironment(t, "M7_STACK_ROOT")
	stack := requiredStackProofEnvironment(t, "M7_STACK_NAME")
	command := exec.CommandContext(ctx, "go", "run", "./tools/dev", "reset", "--stack="+stack, "--root="+root)
	command.Dir, command.Stdout, command.Stderr = root, os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		t.Fatalf("reset declared Stack after durable pending approval: %v", err)
	}
}

func restartStackProofAPITunnel(t *testing.T, ctx context.Context) string {
	t.Helper()
	root := requiredStackProofEnvironment(t, "M7_STACK_ROOT")
	stack := requiredStackProofEnvironment(t, "M7_STACK_NAME")
	command := exec.CommandContext(ctx, "go", "run", "./tools/dev", "api", "--stack="+stack, "--root="+root)
	command.Dir, command.Stderr = root, os.Stderr
	// `go run` starts the dev command, which starts kubectl. Keep both in an
	// isolated group so test cleanup closes the inherited forward pipe too.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open verified local Stack API tunnel output: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start verified local Stack API tunnel: %v", err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		_ = command.Wait()
	})

	lines := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		reported := false
		for scanner.Scan() {
			line := scanner.Text()
			if !reported && strings.HasPrefix(line, "Forwarding from 127.0.0.1:") {
				lines <- line
				reported = true
			}
		}
		if !reported {
			close(lines)
		}
	}()
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case line, ok := <-lines:
		if !ok {
			t.Fatal("verified local Stack API tunnel exited before reporting its endpoint")
		}
		address := strings.TrimSuffix(strings.TrimPrefix(line, "Forwarding from "), " -> 8088")
		return "http://" + address
	case <-wait.Done():
		t.Fatalf("await verified local Stack API tunnel after reset: %v", wait.Err())
	}
	return ""
}

func TestStackProofForwardCleanupTerminatesProcessGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "sh", "-c", "sleep 60 & wait")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatalf("terminate forward process group: %v", err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("wait terminated forward process group: want exit error")
	}
}
