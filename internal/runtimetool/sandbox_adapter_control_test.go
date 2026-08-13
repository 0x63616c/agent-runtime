package runtimetool_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrolapi"
	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestSandboxAdapterRefusesDirectDispatchBeforeControlTransport(t *testing.T) {
	client := &sandboxClient{}
	adapter, err := runtimetool.NewSandboxAdapter(client)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := sandbox.EncodeControlOperationRequest(sandbox.OperationRequest{ID: "op_tool_000000000001", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_tool_000000000001"}})
	if err != nil {
		t.Fatal(err)
	}
	request := runtimetool.Request{OperationID: "op_tool_000000000001", Descriptor: descriptor}
	for _, invoke := range []func(context.Context, runtimetool.Request) (runtimetool.Response, error){adapter.Execute, adapter.Reconcile} {
		response, err := invoke(context.Background(), request)
		if err != nil || response.Failure == nil || client.submits != 0 || client.waits != 0 || client.gets != 0 {
			t.Fatalf("direct sandbox dispatch = %#v calls=%d/%d/%d err=%v", response, client.submits, client.waits, client.gets, err)
		}
	}
}

// This crosses the concrete authenticated TLS sandbox-control process through
// Worker, preserving the normal brokered path while direct adapter calls stay
// unable to create an external effect.
func TestSandboxAdapterExecutesThroughControlProcess(t *testing.T) {
	now := time.Now().UTC()
	source, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	ledger := sandboxcontrol.NewMemoryLedger()
	limits := sandbox.ResourceLimits{MilliCPU: 100, MemoryBytes: 1024, RootDiskBytes: 1024, TmpfsBytes: 1024, PIDs: 10, ProcessCount: 10, OpenFiles: 10, Inodes: 10, Files: 10, Lifetime: time.Hour, ProducedOutputBytes: 1024, RetainedOutputBytes: 1024, TransferBytes: 1024, NetworkConnections: 10, VolumeBytes: 1024, SnapshotBytes: 1024}
	handler, err := sandboxcontrolapi.NewHandler(sandboxcontrolapi.Config{
		Store: ledger, Authenticator: controlAuthenticator{}, AssertionKey: bytes.Repeat([]byte{0x42}, 32), Entropy: bytes.NewReader(bytes.Repeat([]byte{0x99}, 128)), Clock: source,
		BindingLifetime: time.Hour, Retention: time.Hour, WaitInterval: time.Millisecond,
		Wait: func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
		Admission: sandbox.OperationAdmissionPolicy{Defaults: limits, Maximum: limits},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	trust, err := sandbox.NewStaticTrustBundleSource(map[sandbox.TrustBundleRef]sandbox.TrustBundle{"trust/test": {Version: "test/v1", PEMRoots: roots}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := sandbox.NewClient(context.Background(), sandbox.ClientConfig{Endpoint: sandbox.Endpoint{URL: server.URL}, TLS: sandbox.TLSConfig{ServerName: server.Certificate().DNSNames[0], TrustBundleRef: "trust/test"}, Credentials: controlCredentials{}, TrustBundles: trust, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := client.Close(context.Background()); closeErr != nil {
			t.Errorf("close sandbox client: %v", closeErr)
		}
	}()
	adapter, err := runtimetool.NewSandboxAdapter(client)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	objects := &toolObjects{values: map[string][]byte{}}
	content, _ := runtimecontent.New("runtime-content", objects)
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, _ := runtimestate.NewCompiler(content)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	descriptor, err := sandbox.EncodeControlOperationRequest(sandbox.OperationRequest{ID: "op_tool_000000000001", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_tool_000000000001"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _ = createToolExecutionWithDescriptor(t, ctx, content, compiler, store, tenant, principal, now, descriptor)
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "tool-worker", LeaseScheduler: newInertLeaseScheduler()})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- worker.ScanOnce(ctx) }()
	var operation sandboxcontrol.Operation
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		operation, err = ledger.Get(ctx, "tenant-a:subject-a", "op_tool_000000000001")
		if err == nil {
			break
		}
		runtime.Gosched()
	}
	if err != nil {
		t.Fatalf("control process did not retain Worker-submitted operation: %v", err)
	}
	operation, err = ledger.Transition(ctx, operation.Principal, operation.ID, operation.Version, sandboxcontrol.StateDispatched)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ledger.Transition(ctx, operation.Principal, operation.ID, operation.Version, sandboxcontrol.StateSucceeded); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("execute through sandbox control process: %v", err)
	}
}

// TestSandboxAdapterDispatchesASealedWorkspaceActionThroughControlProcess
// exercises the brokered path for a workspace copy action. The model arguments
// are sealed with the private descriptor, then unsealed only by Worker before
// SandboxAdapter submits the descriptor to sandbox-control. The in-memory
// control ledger is intentionally only a transport seam: this does not boot a
// guest, mount a workspace, or prove Firecracker isolation.
func TestSandboxAdapterDispatchesASealedWorkspaceActionThroughControlProcess(t *testing.T) {
	now := time.Now().UTC()
	source, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	ledger := sandboxcontrol.NewMemoryLedger()
	limits := sandbox.ResourceLimits{MilliCPU: 100, MemoryBytes: 1024, RootDiskBytes: 1024, TmpfsBytes: 1024, PIDs: 10, ProcessCount: 10, OpenFiles: 10, Inodes: 10, Files: 10, Lifetime: time.Hour, ProducedOutputBytes: 1024, RetainedOutputBytes: 1024, TransferBytes: 1024, NetworkConnections: 10, VolumeBytes: 1024, SnapshotBytes: 1024}
	handler, err := sandboxcontrolapi.NewHandler(sandboxcontrolapi.Config{
		Store: ledger, Authenticator: controlAuthenticator{}, AssertionKey: bytes.Repeat([]byte{0x42}, 32), Entropy: bytes.NewReader(bytes.Repeat([]byte{0x99}, 128)), Clock: source,
		BindingLifetime: time.Hour, Retention: time.Hour, WaitInterval: time.Millisecond,
		Wait: func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
		Admission: sandbox.OperationAdmissionPolicy{Defaults: limits, Maximum: limits},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	trust, err := sandbox.NewStaticTrustBundleSource(map[sandbox.TrustBundleRef]sandbox.TrustBundle{"trust/test": {Version: "test/v1", PEMRoots: roots}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := sandbox.NewClient(context.Background(), sandbox.ClientConfig{Endpoint: sandbox.Endpoint{URL: server.URL}, TLS: sandbox.TLSConfig{ServerName: server.Certificate().DNSNames[0], TrustBundleRef: "trust/test"}, Credentials: controlCredentials{}, TrustBundles: trust, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := client.Close(context.Background()); closeErr != nil {
			t.Errorf("close sandbox client: %v", closeErr)
		}
	}()
	adapter, err := runtimetool.NewSandboxAdapter(client)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	objects := &toolObjects{values: map[string][]byte{}}
	content, _ := runtimecontent.New("runtime-content", objects)
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, _ := runtimestate.NewCompiler(content)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	controlDescriptor, err := sandbox.EncodeControlOperationRequest(sandbox.OperationRequest{
		ID:   "op_tool_000000000001",
		Kind: sandbox.OperationCopyIn,
		CopyIn: &sandbox.CopyInRequest{
			SandboxID:   "sbx_tool_000000000001",
			Source:      sandbox.ArtifactRef{ID: "art_tool_000000000001", MediaType: "text/plain", SizeBytes: 7, Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			Destination: "/workspace/reports/result.txt",
			Options:     sandbox.TransferOptions{Overwrite: sandbox.OverwriteFailIfExists},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	boundDescriptor, err := runtimecontent.BindToolActionDescriptor(controlDescriptor, []byte(`{"destination":"/workspace/reports/result.txt","model_only":"never reaches sandbox control"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _ = createToolExecutionWithDescriptor(t, ctx, content, compiler, store, tenant, principal, now, boundDescriptor)
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "tool-worker", LeaseScheduler: newInertLeaseScheduler()})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- worker.ScanOnce(ctx) }()

	var operation sandboxcontrol.Operation
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		operation, err = ledger.Get(ctx, "tenant-a:subject-a", "op_tool_000000000001")
		if err == nil {
			break
		}
		runtime.Gosched()
	}
	if err != nil {
		t.Fatalf("control process did not retain Worker-submitted workspace action: %v", err)
	}
	submitted, err := sandbox.DecodeControlOperationRequest([]byte(operation.DispatchBody))
	if err != nil || submitted.Kind != sandbox.OperationCopyIn || submitted.CopyIn == nil || submitted.CopyIn.SandboxID != "sbx_tool_000000000001" || submitted.CopyIn.Destination != "/workspace/reports/result.txt" || submitted.CopyIn.Source.ID != "art_tool_000000000001" {
		t.Fatalf("submitted workspace action = %#v, decode=%v", submitted, err)
	}
	if bytes.Contains([]byte(operation.DispatchBody), []byte("model_only")) {
		t.Fatalf("sandbox control received private model arguments: %q", operation.DispatchBody)
	}
	operation, err = ledger.Transition(ctx, operation.Principal, operation.ID, operation.Version, sandboxcontrol.StateDispatched)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ledger.Transition(ctx, operation.Principal, operation.ID, operation.Version, sandboxcontrol.StateSucceeded); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("execute sealed workspace action through sandbox control process: %v", err)
	}
}

type controlCredentials struct{}

func (controlCredentials) Apply(_ context.Context, sink sandbox.CredentialSink) error {
	return sink.SetAuthorization("Bearer", "tool-token")
}

type controlAuthenticator struct{}

func (controlAuthenticator) Authenticate(ctx context.Context, authorization string) (sandboxcontrolapi.Identity, error) {
	if err := ctx.Err(); err != nil {
		return sandboxcontrolapi.Identity{}, err
	}
	if authorization != "Bearer tool-token" {
		return sandboxcontrolapi.Identity{}, errors.New("denied")
	}
	return sandboxcontrolapi.Identity{Authority: "issuer", Tenant: "tenant-a", Subject: "subject-a", Principal: "tenant-a:subject-a"}, nil
}
