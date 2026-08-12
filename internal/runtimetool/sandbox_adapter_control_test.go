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
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrolapi"
	"github.com/0x63616c/agent-runtime/sandbox"
)

// This test crosses the concrete HTTPS sandbox control process rather than a
// Client fake. It proves the runtime adapter submits only its immutable
// descriptor, then observes the durable control operation to a terminal state.
func TestSandboxAdapterExecutesThroughControlProcess(t *testing.T) {
	now := time.Now().UTC()
	source, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	ledger := sandboxcontrol.NewMemoryLedger()
	limits := sandbox.ResourceLimits{MilliCPU: 100, MemoryBytes: 1024, RootDiskBytes: 1024, TmpfsBytes: 1024, PIDs: 10, ProcessCount: 10, OpenFiles: 10, Inodes: 10, Files: 10, Lifetime: time.Hour, ProducedOutputBytes: 1024, RetainedOutputBytes: 1024, TransferBytes: 1024, NetworkConnections: 10, VolumeBytes: 1024, SnapshotBytes: 1024}
	handler, err := sandboxcontrolapi.NewHandler(sandboxcontrolapi.Config{
		Store:         ledger,
		Authenticator: controlAuthenticator{},
		AssertionKey:  bytes.Repeat([]byte{0x42}, 32), Entropy: bytes.NewReader(bytes.Repeat([]byte{0x99}, 128)), Clock: source,
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
	descriptor, err := sandbox.EncodeControlOperationRequest(sandbox.OperationRequest{ID: "op_tool_000000000001", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_tool_000000000001"}})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := adapter.Execute(context.Background(), runtimetool.Request{OperationID: "op_tool_000000000001", Descriptor: descriptor})
		result <- err
	}()
	var operation sandboxcontrol.Operation
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		operation, err = ledger.Get(context.Background(), "tenant-a:subject-a", "op_tool_000000000001")
		if err == nil {
			break
		}
		runtime.Gosched()
	}
	if err != nil {
		t.Fatalf("control process did not retain submitted operation: %v", err)
	}
	operation, err = ledger.Transition(context.Background(), operation.Principal, operation.ID, operation.Version, sandboxcontrol.StateDispatched)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ledger.Transition(context.Background(), operation.Principal, operation.ID, operation.Version, sandboxcontrol.StateSucceeded); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("execute through sandbox control process: %v", err)
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
