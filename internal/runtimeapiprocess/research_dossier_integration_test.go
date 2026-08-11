//go:build integration

package runtimeapiprocess_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	researchdossier "github.com/0x63616c/agent-runtime/examples/research-dossier"
	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeapiprocess"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
)

// TestResearchDossierRecoversLongRunningToolResearchThroughThePublicContract
// proves M8's public application seam against real disposable PostgreSQL,
// MinIO, and Temporal services. The application itself has only SDK/HTTP
// authority; the scripted model and research adapters are private disposable
// worker seams that demonstrate brokered allowed-tool artifact production.
func TestResearchDossierRecoversLongRunningToolResearchThroughThePublicContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	access := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secret := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	bucket := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	objects, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{bucket, bucket + "-m8-temporal-payload"} {
		if err := objects.MakeBucket(ctx, name, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
			t.Fatalf("create disposable bucket %q: %v", name, err)
		}
	}
	config, err := runtimeapiprocess.Parse(strings.NewReader(fmt.Sprintf(`{"version":1,"listen_address":"127.0.0.1:0","storage":{"mode":"postgres","database_dsn_environment":"STATE_DSN","content":{"endpoint":%q,"access_key_environment":"CONTENT_ACCESS","secret_key_environment":"CONTENT_SECRET","bucket":%q}},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"research-dossier-e2e","principal":"admin","admin":true,"bearer_token_environment":"ADMIN_TOKEN"},{"tenant":"research-dossier-e2e","principal":"researcher","admin":false,"bearer_token_environment":"RESEARCHER_TOKEN"}]}`, endpoint, bucket)))
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"STATE_DSN": dsn, "CONTENT_ACCESS": access, "CONTENT_SECRET": secret, "ADMIN_TOKEN": "research-dossier-admin-token", "RESEARCHER_TOKEN": "research-dossier-researcher-token"}
	baseURL, stopAPI := startDurableRuntimeProcess(t, config, secrets)
	admin := durableProcessClient(t, baseURL, secrets["ADMIN_TOKEN"], &durableRequestIDs{})
	researcher := durableProcessClient(t, baseURL, secrets["RESEARCHER_TOKEN"], &durableRequestIDs{})
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "m8-agent", Name: "research-dossier", ModelProfile: "balanced", Instructions: "produce a cited research dossier", Tools: []agentruntime.ToolDefinition{{Name: "web_research", Description: "retrieve an approved research source"}}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := admin.CreatePolicy(ctx, agentruntime.CreatePolicyRequest{IdempotencyKey: "m8-policy", Name: "research-dossier-web", Rules: []agentruntime.PolicyRule{{ToolName: "web_research", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil {
		t.Fatal(err)
	}
	app, err := researchdossier.NewApp(researcher, researchdossier.RandomKeys{})
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := app.Start(ctx, agent.RevisionID, "Compare the primary evidence with its cited source.")
	if err != nil {
		t.Fatalf("start public dossier: %v", err)
	}

	// The private Temporal worker receives only the durable outbox. The public
	// application neither receives Temporal configuration nor imports a client.
	temporalServer, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{ClientOptions: &client.Options{Namespace: "research-dossier-e2e"}})
	if err != nil {
		t.Fatalf("start disposable Temporal: %v", err)
	}
	defer func() { _ = temporalServer.Stop() }()
	stopOrchestration := startM8Orchestration(t, ctx, runtimeorchestration.ProcessConfig{DatabaseDSN: dsn, TemporalEndpoint: temporalServer.FrontendHostPort(), TemporalToken: "m8-private-temporal-token", Namespace: "research-dossier-e2e", TaskQueue: "research-dossier-e2e", PayloadBlobEndpoint: endpoint, PayloadBlobBucket: bucket + "-m8-temporal-payload", PayloadBlobPrefix: "m8", PayloadAccessKey: access, PayloadSecretKey: secret})
	defer stopOrchestration()
	if err := assertM8TemporalSession(ctx, temporalServer.FrontendHostPort(), session.ID); err != nil {
		t.Fatalf("public dossier Session has no durable Temporal workflow: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	immutable, err := runtimecontent.NewMinIOImmutableClient(objects)
	if err != nil {
		t.Fatal(err)
	}
	contentObjects, err := runtimecontent.NewS3ImmutableObjects(immutable, bucket)
	if err != nil {
		t.Fatal(err)
	}
	// The private worker must use the same durable content namespace as the
	// HTTP runtime. It publishes an artifact; the public application reads it
	// only through the authorized artifact endpoint after the API restarts.
	content, err := runtimecontent.New("runtime-content", contentObjects)
	if err != nil {
		t.Fatal(err)
	}
	clockSource, err := clock.NewFake(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(clockSource, &m8IDs{})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := runtimetool.NewBroker(runtimetool.BrokerConfig{Store: store, Compiler: compiler, Planner: planner, Clock: clockSource})
	if err != nil {
		t.Fatal(err)
	}
	modelAdapter := newM8ModelAdapter(policy, clockSource.Now())
	model, err := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: clockSource, Content: content, Adapter: modelAdapter, Broker: broker, Claimer: "m8-model"})
	if err != nil {
		t.Fatal(err)
	}
	toolAdapter := &m8ResearchTool{}
	tool, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: clockSource, Content: content, Adapter: toolAdapter, Claimer: "m8-research-tool"})
	if err != nil {
		t.Fatal(err)
	}
	runM8ResearchStep(t, ctx, model, tool, researcher, session.ID, 1)
	artifacts, err := app.Artifacts(ctx, session.ID)
	if err != nil || len(artifacts.Artifacts) != 1 {
		t.Fatalf("first public retained Artifact index = %#v, %v", artifacts, err)
	}
	first, err := app.Download(ctx, artifacts.Artifacts[0].ID)
	if err != nil || len(first.Citations) != 1 || first.Citations[0].URL != "https://example.com/research/0000000000000001" {
		t.Fatalf("first public research result = %#v, %v", first, err)
	}
	beforeRestart, err := app.Resume(ctx, session.ID, "")
	if err != nil || beforeRestart.Events.NextCursor == "" {
		t.Fatalf("public progress before API restart = %#v, %v", beforeRestart, err)
	}
	if _, err := app.Research(ctx, session.ID, "Research the first independent corroborating source."); err != nil {
		t.Fatalf("queue second ordered public research step: %v", err)
	}
	stopAPI()
	baseURL, stopAPI = startDurableRuntimeProcess(t, config, secrets)
	defer stopAPI()
	restartedClient := durableProcessClient(t, baseURL, secrets["RESEARCHER_TOKEN"], &durableRequestIDs{})
	restartedApp, err := researchdossier.NewApp(restartedClient, researchdossier.RandomKeys{})
	if err != nil {
		t.Fatal(err)
	}
	afterRestart, err := restartedApp.Resume(ctx, session.ID, beforeRestart.Events.NextCursor)
	if err != nil || afterRestart.Events.Gap != nil || afterRestart.Session.Session.State != agentruntime.SessionOpen {
		t.Fatalf("public cursor resume after API restart = %#v, %v", afterRestart, err)
	}
	researcher = restartedClient
	runM8ResearchStep(t, ctx, model, tool, researcher, session.ID, 2)
	if _, err := restartedApp.Research(ctx, session.ID, "Research the final reconciliation source and produce the downloadable dossier."); err != nil {
		t.Fatalf("queue third ordered public research step: %v", err)
	}
	runM8ResearchStep(t, ctx, model, tool, researcher, session.ID, 3)
	restartedArtifacts, err := restartedApp.Artifacts(ctx, session.ID)
	if err != nil || len(restartedArtifacts.Artifacts) != 3 {
		t.Fatalf("public Artifact retention after sequential research = %#v, %v", restartedArtifacts, err)
	}
	for index, artifact := range restartedArtifacts.Artifacts {
		dossier, downloadErr := restartedApp.Download(ctx, artifact.ID)
		wantCitation := fmt.Sprintf("https://example.com/research/%016d", index+1)
		if downloadErr != nil || len(dossier.Citations) != 1 || dossier.Citations[0].URL != wantCitation || (index == 2 && dossier.Artifact.SizeBytes <= 512*1024) {
			t.Fatalf("ordered public research result %d = %#v, %v", index+1, dossier, downloadErr)
		}
	}
	if executions := toolAdapter.Executions(); executions != 3 || modelAdapter.Invocations() != 3 {
		t.Fatalf("distinct durable research execution counts = tool=%d model=%d, want 3/3", executions, modelAdapter.Invocations())
	}

	// Exercise the shipped terminal and loopback-web binaries after recovery.
	// Both processes are deliberately configured with only a public bearer and
	// runtime URL; they receive neither object-store nor Temporal credentials.
	terminalInput := "artifacts " + session.ID.String() + "\n"
	for _, artifact := range restartedArtifacts.Artifacts {
		terminalInput += "download " + artifact.ID.String() + "\n"
	}
	terminal := runResearchDossierTerminal(t, baseURL, secrets["RESEARCHER_TOKEN"], terminalInput+"quit\n")
	if !strings.Contains(terminal, restartedArtifacts.Artifacts[0].ID.String()) || !strings.Contains(terminal, "https://example.com/research/0000000000000001") || !strings.Contains(terminal, "https://example.com/research/0000000000000002") || !strings.Contains(terminal, "https://example.com/research/0000000000000003") {
		t.Fatalf("terminal public dossier recovery = %q", terminal)
	}
	webURL, stopWeb := startResearchDossierWeb(t, baseURL, secrets["RESEARCHER_TOKEN"])
	defer stopWeb()
	artifactID := restartedArtifacts.Artifacts[len(restartedArtifacts.Artifacts)-1].ID
	if body := getResearchDossierPage(t, webURL+"/sessions/"+session.ID.String()+"/artifacts"); !strings.Contains(body, artifactID.String()) {
		t.Fatalf("web public dossier artifact index = %q", body)
	}
	download := getResearchDossierDownload(t, webURL+"/artifacts/"+artifactID.String())
	if !strings.Contains(download, "https://example.com/primary-evidence") {
		t.Fatalf("web public dossier download = %q", download)
	}
}

type m8IDs struct{ next uint64 }

func (ids *m8IDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}

type m8ModelAdapter struct {
	policy agentruntime.Policy
	now    time.Time
	mu     sync.Mutex
	tools  map[runtimestate.OperationID]runtimemodel.ToolRequest
}

func newM8ModelAdapter(policy agentruntime.Policy, now time.Time) *m8ModelAdapter {
	return &m8ModelAdapter{policy: policy, now: now, tools: map[runtimestate.OperationID]runtimemodel.ToolRequest{}}
}

func (adapter *m8ModelAdapter) Invoke(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	tool, found := adapter.tools[request.OperationID]
	if !found {
		ordinal := len(adapter.tools) + 1
		suffix := fmt.Sprintf("%016d", ordinal)
		tool = runtimemodel.ToolRequest{ToolCallID: "tcall_research_" + suffix, ApprovalID: "appr_" + suffix, PolicyName: adapter.policy.Name, PolicyRevision: adapter.policy.Revision, ToolName: "web_research", ActionDigest: "sha256:" + strings.Repeat("a", 64), CapabilityDigest: "sha256:" + strings.Repeat("b", 64), Action: agentruntime.ApprovalAction{Verb: "execute", Target: "network-request"}, MaximumUses: 1, ExpiresAt: adapter.now.Add(time.Hour), Descriptor: []byte(`{"source":"https://example.com/research/` + suffix + `"}`)}
		adapter.tools[request.OperationID] = tool
	}
	return runtimemodel.Response{Tool: &tool}, nil
}

func (adapter *m8ModelAdapter) Reconcile(ctx context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	return adapter.Invoke(ctx, request)
}

func (adapter *m8ModelAdapter) Invocations() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return len(adapter.tools)
}

type m8ResearchTool struct {
	mu         sync.Mutex
	executions int
}

func (*m8ResearchTool) ExternalEffectContract() runtimetool.ExternalEffectContract {
	return runtimetool.ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}
}
func (adapter *m8ResearchTool) Execute(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.mu.Lock()
	adapter.executions++
	adapter.mu.Unlock()
	ordinal := strings.TrimPrefix(request.ToolCallID, "tcall_research_")
	output := "# Research Dossier\n\nResearch result " + ordinal + ".\n\n"
	if ordinal == "0000000000000003" {
		output += strings.Repeat("Retained corroborating research evidence. ", 16_384) + "\n\n"
	}
	output += "Primary evidence: [source](https://example.com/research/" + ordinal + ")\n"
	return runtimetool.Response{MediaType: "text/markdown", Output: []byte(output)}, nil
}
func (adapter *m8ResearchTool) Reconcile(ctx context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	return adapter.Execute(ctx, request)
}
func (adapter *m8ResearchTool) Executions() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.executions
}

func runM8ResearchStep(t *testing.T, ctx context.Context, model *runtimemodel.Worker, tool *runtimetool.Worker, researcher *agentruntime.Client, sessionID agentruntime.SessionID, ordinal int) {
	t.Helper()
	if err := model.ScanOnce(ctx); err != nil {
		t.Fatalf("run private model research step %d: %v", ordinal, err)
	}
	approvals, err := researcher.ListApprovals(ctx)
	if err != nil {
		t.Fatalf("list public research approvals for step %d: %v", ordinal, err)
	}
	var pending *agentruntime.Approval
	for _, approval := range approvals.Approvals {
		if approval.State == agentruntime.ApprovalPending && approval.SessionID == sessionID && approval.Action != nil && approval.Action.Target == "network-request" {
			value := approval
			pending = &value
			break
		}
	}
	if pending == nil {
		t.Fatalf("public approval for allowed research step %d = %#v", ordinal, approvals)
	}
	if _, err := researcher.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: pending.ID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: fmt.Sprintf("m8-approve-research-%d", ordinal)}); err != nil {
		t.Fatalf("approve allowed research Tool step %d publicly: %v", ordinal, err)
	}
	if err := tool.ScanOnce(ctx); err != nil {
		t.Fatalf("run private allowed research Tool step %d: %v", ordinal, err)
	}
	if err := tool.ScanOnce(ctx); err != nil {
		t.Fatalf("replay private allowed research Tool step %d: %v", ordinal, err)
	}
}

func startM8Orchestration(t *testing.T, parent context.Context, config runtimeorchestration.ProcessConfig) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	firstWait := make(chan struct{})
	var waited sync.Once
	done := make(chan error, 1)
	go func() {
		done <- runtimeorchestration.RunWithWait(ctx, config, func(waitCtx context.Context, _ time.Duration) error {
			waited.Do(func() { close(firstWait) })
			<-waitCtx.Done()
			return waitCtx.Err()
		})
	}()
	select {
	case <-firstWait:
	case err := <-done:
		t.Fatalf("start M8 Temporal orchestration: %v", err)
	case <-parent.Done():
		t.Fatalf("start M8 Temporal orchestration: %v", parent.Err())
	}
	return func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("stop M8 Temporal orchestration: %v", err)
		}
	}
}

func assertM8TemporalSession(ctx context.Context, endpoint string, sessionID agentruntime.SessionID) error {
	client, err := client.Dial(client.Options{HostPort: endpoint, Namespace: "research-dossier-e2e", ConnectionOptions: client.ConnectionOptions{TLSDisabled: true}})
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = client.DescribeWorkflowExecution(ctx, "runtime-session-research-dossier-e2e-"+sessionID.String(), "")
	return err
}

func startResearchDossierWeb(t *testing.T, runtimeURL, token string) (string, func()) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "research-dossier")
	command := exec.Command("go", "build", "-o", binary, "./examples/research-dossier/cmd/research-dossier")
	command.Dir = repositoryRoot(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Research Dossier binary: %v\n%s", err, output)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	process := exec.Command(binary, "--mode=web", "--runtime-url="+runtimeURL, "--listen="+address, "--token-env=RESEARCH_DOSSIER_E2E_TOKEN")
	process.Env = append(os.Environ(), "RESEARCH_DOSSIER_E2E_TOKEN="+token)
	var output bytes.Buffer
	process.Stdout, process.Stderr = &output, &output
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + address
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(baseURL)
		if err == nil {
			_ = response.Body.Close()
			return baseURL, func() { _ = process.Process.Kill(); _ = process.Wait() }
		}
		runtime.Gosched()
	}
	_ = process.Process.Kill()
	_ = process.Wait()
	t.Fatalf("Research Dossier web did not start: %s", output.String())
	return "", nil
}

func runResearchDossierTerminal(t *testing.T, runtimeURL, token, input string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "research-dossier")
	command := exec.Command("go", "build", "-o", binary, "./examples/research-dossier/cmd/research-dossier")
	command.Dir = repositoryRoot(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Research Dossier binary: %v\n%s", err, output)
	}
	command = exec.Command(binary, "--mode=terminal", "--runtime-url="+runtimeURL, "--token-env=RESEARCH_DOSSIER_E2E_TOKEN")
	command.Env = append(os.Environ(), "RESEARCH_DOSSIER_E2E_TOKEN="+token)
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run Research Dossier terminal: %v\n%s", err, output)
	}
	return string(output)
}

func getResearchDossierPage(t *testing.T, endpoint string) string {
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

func getResearchDossierDownload(t *testing.T, endpoint string) string {
	t.Helper()
	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Disposition"), "attachment;") {
		t.Fatalf("Research Dossier download response = status %d headers %#v", response.StatusCode, response.Header)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
