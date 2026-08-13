//go:build integration

package runtimeapiprocess_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeapiprocess"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// TestDurableWorkspaceAgentBinariesUseOnlyThePublicAPI proves the M7 client
// vertical against a restarted PostgreSQL/MinIO API role.  Pending approvals
// are seeded through the private Broker because this API role does not yet
// compose a model-to-tool producer; the web and terminal binaries themselves
// use only the public HTTP/SDK contract.  No sandbox operation is executed.
func TestDurableWorkspaceAgentBinariesUseOnlyThePublicAPI(t *testing.T) {
	ctx := context.Background()
	dsn := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	access := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secret := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	bucket := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	minioClient, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
		t.Fatal(err)
	}
	config, err := runtimeapiprocess.Parse(strings.NewReader(fmt.Sprintf(`{"version":1,"profile":"local","listen_address":"127.0.0.1:0","storage":{"mode":"postgres","database_dsn_environment":"STATE_DSN","content":{"endpoint":%q,"access_key_environment":"CONTENT_ACCESS","secret_key_environment":"CONTENT_SECRET","bucket":%q}},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"workspacee2e","principal":"admin","admin":true,"bearer_token_environment":"ADMIN_TOKEN"},{"tenant":"workspacee2e","principal":"alice","admin":false,"bearer_token_environment":"ALICE_TOKEN"},{"tenant":"workspacee2e","principal":"bob","admin":false,"bearer_token_environment":"BOB_TOKEN"}]}`, "http://"+endpoint, bucket)))
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"STATE_DSN": dsn, "CONTENT_ACCESS": access, "CONTENT_SECRET": secret, "ADMIN_TOKEN": "workspace-e2e-admin-token", "ALICE_TOKEN": "workspace-e2e-alice-token", "BOB_TOKEN": "workspace-e2e-bob-token"}
	baseURL, stop := startDurableRuntimeProcess(t, config, secrets)
	ids := &durableRequestIDs{}
	admin := durableProcessClient(t, baseURL, secrets["ADMIN_TOKEN"], ids)
	alice := durableProcessClient(t, baseURL, secrets["ALICE_TOKEN"], ids)
	bob := durableProcessClient(t, baseURL, secrets["BOB_TOKEN"], ids)
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "workspace-e2e-agent", Name: "workspace", ModelProfile: "balanced", Instructions: "request approval"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := admin.CreatePolicy(ctx, agentruntime.CreatePolicyRequest{IdempotencyKey: "workspace-e2e-policy", Name: "workspace-write", Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// The broker clock stays deliberately behind the public API process clock.
	// This lets the private producer admit an expiry that the public API can
	// deterministically observe as elapsed, without a wall-clock wait.
	source, err := clock.NewFake(time.Now().UTC().Add(-2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, source)
	if err != nil {
		t.Fatal(err)
	}
	immutable, err := runtimecontent.NewMinIOImmutableClient(minioClient)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := runtimecontent.NewS3ImmutableObjects(immutable, bucket)
	if err != nil {
		t.Fatal(err)
	}
	content, err := runtimecontent.New("workspace-e2e", objects)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(source, &workspaceE2EIDs{})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("workspacee2e")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	policyState, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil || len(policyState.Policies) != 1 {
		t.Fatalf("public Policy is not visible through the durable worker state authority: state=%#v err=%v", policyState.Policies, err)
	}
	if policyState.Policies[0].Name != policy.Name || policyState.Policies[0].Revision != policy.Revision || len(policyState.Policies[0].Rules) != 1 || policyState.Policies[0].Rules[0] != (agentruntime.PolicyRule{ToolName: "write", Decision: agentruntime.PolicyRequiresApproval}) {
		t.Fatalf("public Policy does not preserve broker admission rule: public=%#v durable=%#v", policy, policyState.Policies[0])
	}
	broker, err := runtimetool.NewBroker(runtimetool.BrokerConfig{Store: store, Compiler: compiler, Planner: planner, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	type seededApproval struct {
		approvalID agentruntime.ApprovalID
		sessionID  agentruntime.SessionID
		turnID     agentruntime.TurnID
		toolCallID string
	}
	seed := func(suffix string, expiry time.Time) seededApproval {
		session, e := alice.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "workspace-e2e-session-" + suffix, AgentRevision: agent.RevisionID})
		if e != nil {
			t.Fatal(e)
		}
		accepted, e := alice.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "workspace-e2e-input-" + suffix, Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "write " + suffix}}})
		if e != nil {
			t.Fatal(e)
		}
		descriptor, e := content.StageToolActionDescriptor(ctx, tenant, []byte("write workspace "+suffix))
		if e != nil {
			t.Fatal(e)
		}
		id, e := agentruntime.ParseApprovalID("appr_" + suffix + "00000000")
		if e != nil {
			t.Fatal(e)
		}
		_, e = broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_" + suffix + "00000000", ApprovalID: id, PolicyName: policy.Name, PolicyRevision: policy.Revision, ToolName: "write", ActionDigest: "sha256:" + strings.Repeat("a", 64), CapabilityDigest: "sha256:" + strings.Repeat("b", 64), Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: expiry, Descriptor: descriptor, IdempotencyKey: "workspace-e2e-admit-" + suffix})
		if e != nil {
			t.Fatal(e)
		}
		return seededApproval{approvalID: id, sessionID: session.ID, turnID: accepted.Turn.ID, toolCallID: "tcall_" + suffix + "00000000"}
	}
	futureExpiry := source.Now().Add(4 * time.Hour)
	approve := seed("APPROVEA", futureExpiry)
	deny := seed("DENYBBBB", futureExpiry)
	cancel := seed("CANCELCC", futureExpiry)
	pending := seed("PENDINGE", futureExpiry)

	// The owner web binary presents the public safe action summary and the
	// unavailable sandbox status, then approves one request over HTTP.
	webURL, stopWeb := startWorkspaceBinary(t, "web", baseURL, secrets["ALICE_TOKEN"])
	defer func() { stopWeb() }()
	body := getWorkspacePage(t, webURL)
	if !strings.Contains(body, "write workspace-service") || !strings.Contains(body, "Workspace sandbox execution is unavailable") {
		t.Fatalf("web workspace page omitted safe state: %q", body)
	}
	postWorkspaceForm(t, webURL+"/approvals/"+approve.approvalID.String()+"/approve", "web-approve")
	// A browser replay of the exact public idempotency key stays a successful
	// redirect and cannot create a second approval effect.
	postWorkspaceForm(t, webURL+"/approvals/"+approve.approvalID.String()+"/approve", "web-approve")
	if approval, e := alice.InspectApproval(ctx, approve.approvalID); e != nil || approval.State != agentruntime.ApprovalApproved {
		t.Fatalf("web approve = %#v, %v", approval, e)
	}

	// The actual terminal binary is a second, non-owner client: it cannot list
	// Alice's inbox. Alice's terminal then denies a separate request through the
	// same public HTTP/SDK contract.
	terminal := runWorkspaceTerminal(t, baseURL, secrets["BOB_TOKEN"], "list\nquit\n")
	if strings.Contains(terminal, approve.approvalID.String()) || !strings.Contains(terminal, "Workspace sandbox execution is unavailable") {
		t.Fatalf("cross-principal terminal leaked owner approval: %q", terminal)
	}
	terminal = runWorkspaceTerminal(t, baseURL, secrets["ALICE_TOKEN"], "deny "+deny.approvalID.String()+" terminal-deny\nquit\n")
	if !strings.Contains(terminal, string(agentruntime.ApprovalDenied)) {
		t.Fatalf("owner terminal did not render denied Approval: %q", terminal)
	}
	postWorkspaceForm(t, webURL+"/approvals/"+cancel.approvalID.String()+"/cancel", "web-cancel")
	if approval, e := alice.InspectApproval(ctx, deny.approvalID); e != nil || approval.State != agentruntime.ApprovalDenied {
		t.Fatalf("web deny = %#v, %v", approval, e)
	}
	if approval, e := alice.InspectApproval(ctx, cancel.approvalID); e != nil || approval.State != agentruntime.ApprovalCancelled {
		t.Fatalf("cancel invalidates pending approval = %#v, %v", approval, e)
	}

	// The broker sees this fixed fake-clock expiry in the future, while the
	// public API role's clock is already past it. Its public decision therefore
	// exercises durable expiry without waiting for wall time.
	expire := seed("EXPIREDD", source.Now().Add(time.Hour))
	postWorkspaceFormFailure(t, webURL+"/approvals/"+expire.approvalID.String()+"/approve", "web-expired")
	if approval, e := alice.InspectApproval(ctx, expire.approvalID); e != nil || approval.State != agentruntime.ApprovalExpired {
		t.Fatalf("web expiry = %#v, %v", approval, e)
	}
	// A still-pending request must remain visibly non-terminal through an
	// actual API process restart. The client sees only the S1 HTTP/SDK
	// projection; the private Broker was used solely to seed the producer-owned
	// input because this harness does not compose the model-to-tool producer.
	pendingBeforeRestart, err := alice.InspectApproval(ctx, pending.approvalID)
	if err != nil || pendingBeforeRestart.State != agentruntime.ApprovalPending || pendingBeforeRestart.SessionID != pending.sessionID || pendingBeforeRestart.TurnID != pending.turnID || pendingBeforeRestart.ToolCallID != pending.toolCallID || pendingBeforeRestart.Action == nil || *pendingBeforeRestart.Action != (agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}) || pendingBeforeRestart.Scope == nil || pendingBeforeRestart.Scope.MaximumUses != 1 || pendingBeforeRestart.PolicyRevision == "" || pendingBeforeRestart.Requester != "alice" || pendingBeforeRestart.DecidedAt != nil {
		t.Fatalf("public pending Approval before API restart = %#v, %v", pendingBeforeRestart, err)
	}
	if pendingTurn, e := alice.InspectTurn(ctx, pending.sessionID, pending.turnID); e != nil || pendingTurn.State != agentruntime.TurnWaitingForApproval || pendingTurn.CompletedAt != nil {
		t.Fatalf("public pending Turn before API restart = %#v, %v", pendingTurn, e)
	}
	stop()
	baseURL, stop = startDurableRuntimeProcess(t, config, secrets)
	defer stop()
	// Existing web binary reconnects to the restarted role at the same public
	// contract (the test starts a new loopback client because the role port is
	// intentionally ephemeral in the disposable harness).
	stopWeb()
	webURL, stopWeb = startWorkspaceBinary(t, "web", baseURL, secrets["ALICE_TOKEN"])
	if !strings.Contains(getWorkspacePage(t, webURL), approve.approvalID.String()) {
		t.Fatal("reconnected web binary did not read retained approval inbox")
	}
	alice = durableProcessClient(t, baseURL, secrets["ALICE_TOKEN"], ids)
	pendingAfterRestart, err := alice.InspectApproval(ctx, pending.approvalID)
	if err != nil || pendingAfterRestart.State != agentruntime.ApprovalPending || pendingAfterRestart.ID != pendingBeforeRestart.ID || pendingAfterRestart.SessionID != pendingBeforeRestart.SessionID || pendingAfterRestart.TurnID != pendingBeforeRestart.TurnID || pendingAfterRestart.ToolCallID != pendingBeforeRestart.ToolCallID || pendingAfterRestart.Action == nil || pendingBeforeRestart.Action == nil || *pendingAfterRestart.Action != *pendingBeforeRestart.Action || pendingAfterRestart.Scope == nil || pendingBeforeRestart.Scope == nil || *pendingAfterRestart.Scope != *pendingBeforeRestart.Scope || !pendingAfterRestart.ExpiresAt.Equal(pendingBeforeRestart.ExpiresAt) || pendingAfterRestart.DecidedAt != nil {
		t.Fatalf("public pending Approval after API restart = %#v, %v; want retained %#v", pendingAfterRestart, err, pendingBeforeRestart)
	}
	if pendingTurn, e := alice.InspectTurn(ctx, pending.sessionID, pending.turnID); e != nil || pendingTurn.State != agentruntime.TurnWaitingForApproval || pendingTurn.CompletedAt != nil {
		t.Fatalf("public pending Turn after API restart = %#v, %v", pendingTurn, e)
	}
	decision, err := alice.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: pending.approvalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "pending-after-restart-approve"})
	if err != nil || decision.State != agentruntime.ApprovalApproved || decision.DecidedAt == nil {
		t.Fatalf("public pending Approval decision after API restart = %#v, %v", decision, err)
	}
	if replay, e := alice.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: pending.approvalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "pending-after-restart-approve"}); e != nil || !reflect.DeepEqual(replay, decision) {
		t.Fatalf("public pending Approval replay after API restart = %#v, %v; want %#v", replay, e, decision)
	}
	bob = durableProcessClient(t, baseURL, secrets["BOB_TOKEN"], ids)
	if page, e := bob.ListApprovals(ctx); e != nil || len(page.Approvals) != 0 {
		t.Fatalf("restarted cross-principal inbox = %#v, %v", page, e)
	}
}

type workspaceE2EIDs struct{ next uint64 }

func (ids *workspaceE2EIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}

func startWorkspaceBinary(t *testing.T, mode, runtimeURL, token string) (string, func()) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "workspace-agent")
	command := exec.Command("go", "build", "-o", binary, "./examples/workspace-agent/cmd/workspace-agent")
	command.Dir = repositoryRoot(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Workspace Agent binary: %v\n%s", err, output)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	process := exec.Command(binary, "--mode="+mode, "--runtime-url="+runtimeURL, "--listen="+address, "--token-env=WORKSPACE_E2E_TOKEN")
	process.Env = append(os.Environ(), "WORKSPACE_E2E_TOKEN="+token)
	var output bytes.Buffer
	process.Stdout, process.Stderr = &output, &output
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + address
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, e := http.Get(baseURL)
		if e == nil {
			_ = response.Body.Close()
			return baseURL, func() { _ = process.Process.Kill(); _ = process.Wait() }
		}
		runtime.Gosched()
	}
	_ = process.Process.Kill()
	_ = process.Wait()
	t.Fatalf("Workspace Agent web did not start: %s", output.String())
	return "", nil
}

func runWorkspaceTerminal(t *testing.T, runtimeURL, token, input string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "workspace-agent")
	command := exec.Command("go", "build", "-o", binary, "./examples/workspace-agent/cmd/workspace-agent")
	command.Dir = repositoryRoot(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Workspace Agent binary: %v\n%s", err, output)
	}
	command = exec.Command(binary, "--mode=terminal", "--runtime-url="+runtimeURL, "--token-env=WORKSPACE_E2E_TOKEN")
	command.Env = append(os.Environ(), "WORKSPACE_E2E_TOKEN="+token)
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run Workspace Agent terminal: %v\n%s", err, output)
	}
	return string(output)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(directory, "..", ".."))
}
func getWorkspacePage(t *testing.T, endpoint string) string {
	t.Helper()
	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
func postWorkspaceForm(t *testing.T, endpoint, key string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	base := parsed.Scheme + "://" + parsed.Host
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(getWorkspacePage(t, base))
	if len(match) != 2 {
		t.Fatalf("Workspace page CSRF token missing")
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(url.Values{"csrf": {match[1]}, "key": {key}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", base)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("Workspace form status = %d", response.StatusCode)
	}
}

func postWorkspaceFormFailure(t *testing.T, endpoint, key string) {
	t.Helper()
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	base := parsed.Scheme + "://" + parsed.Host
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(getWorkspacePage(t, base))
	if len(match) != 2 {
		t.Fatalf("Workspace page CSRF token missing")
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(url.Values{"csrf": {match[1]}, "key": {key}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", base)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), "request could not be completed") {
		t.Fatalf("Workspace failed form = status %d body %q error %v", response.StatusCode, body, err)
	}
}
