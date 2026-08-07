package sandbox_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestPublicAPISurfaceCompiles(t *testing.T) {
	var _ sandbox.Client
	var _ sandbox.CredentialSource = credentialSource{}
	var _ sandbox.CredentialSink = credentialSink{}
	var _ sandbox.OperationStream
	var _ sandbox.OutputStream
	var _ error = (*sandbox.Error)(nil)

	config := sandbox.ClientConfig{
		Endpoint:       sandbox.Endpoint{URL: "https://sandbox.example.test"},
		TLS:            sandbox.TLSConfig{ServerName: "sandbox.example.test", TrustBundleRef: "trust/sandbox"},
		Credentials:    credentialSource{},
		RequestTimeout: time.Second,
	}
	_, err := sandbox.NewClient(context.Background(), config)
	failure, ok := sandbox.AsFailure(err)
	if !ok || failure.Code != sandbox.FailureUnavailable {
		t.Fatalf("NewClient() failure = %#v, %v; want unavailable until a control transport is composed", failure, err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal("NewClient() must not report an unrelated context cancellation")
	}
}

func ExampleOperationRequest() {
	request := sandbox.OperationRequest{
		ID:   "op_create_example",
		Kind: sandbox.OperationCreateSandbox,
		CreateSandbox: &sandbox.CreateSandboxRequest{Spec: sandbox.SandboxSpec{
			Image: sandbox.ImageRef{Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			Resources: sandbox.ResourceLimits{
				MilliCPU:            100,
				MemoryBytes:         128 << 20,
				RootDiskBytes:       1 << 30,
				TmpfsBytes:          64 << 20,
				PIDs:                64,
				ProcessCount:        16,
				OpenFiles:           128,
				Inodes:              1024,
				Files:               1024,
				Lifetime:            time.Minute,
				ProducedOutputBytes: 1 << 20,
				RetainedOutputBytes: 64 << 10,
				TransferBytes:       1 << 20,
				NetworkConnections:  16,
				VolumeBytes:         1 << 30,
				SnapshotBytes:       1 << 30,
			},
		}},
	}
	_ = request
	// Output:
}

func TestOperationMatrixPublicTypesCompile(t *testing.T) {
	deadline := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	requests := []sandbox.OperationRequest{
		{ID: "op_create", Kind: sandbox.OperationCreateSandbox, CreateSandbox: &sandbox.CreateSandboxRequest{Spec: sandbox.SandboxSpec{Image: sandbox.ImageRef{Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}}},
		{ID: "op_restore", Kind: sandbox.OperationRestoreSandbox, RestoreSandbox: &sandbox.RestoreSandboxRequest{SnapshotID: "snap_01"}},
		{ID: "op_exec", Kind: sandbox.OperationExecProcess, ExecProcess: &sandbox.ExecProcessRequest{SandboxID: "sbx_01", Command: sandbox.Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}},
		{ID: "op_signal", Kind: sandbox.OperationSignalProcess, SignalProcess: &sandbox.SignalProcessRequest{ProcessID: "prc_01", Signal: sandbox.SignalInterrupt}},
		{ID: "op_kill", Kind: sandbox.OperationKillProcess, KillProcess: &sandbox.KillProcessRequest{ProcessID: "prc_01"}},
		{ID: "op_copy_in", Kind: sandbox.OperationCopyIn, CopyIn: &sandbox.CopyInRequest{SandboxID: "sbx_01", Source: sandbox.ArtifactRef{ID: "art_01", SizeBytes: 1}, Destination: "/work/in"}},
		{ID: "op_copy_out", Kind: sandbox.OperationCopyOut, CopyOut: &sandbox.CopyOutRequest{SandboxID: "sbx_01", Source: "/work/out"}},
		{ID: "op_snapshot", Kind: sandbox.OperationSnapshotSandbox, SnapshotSandbox: &sandbox.SnapshotSandboxRequest{SandboxID: "sbx_01"}},
		{ID: "op_close", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_01"}},
		{ID: "op_reconcile", Kind: sandbox.OperationReconcileSandbox, ReconcileSandbox: &sandbox.ReconcileSandboxRequest{SandboxID: "sbx_01"}},
		{ID: "op_volume_create", Kind: sandbox.OperationCreateVolume, CreateVolume: &sandbox.CreateVolumeRequest{Spec: sandbox.VolumeSpec{SizeBytes: 1, Inodes: 1}}},
		{ID: "op_attach", Kind: sandbox.OperationAttachVolume, AttachVolume: &sandbox.AttachVolumeRequest{SandboxID: "sbx_01", VolumeID: "vol_01", Target: "/work/volume"}},
		{ID: "op_detach", Kind: sandbox.OperationDetachVolume, DetachVolume: &sandbox.DetachVolumeRequest{SandboxID: "sbx_01", VolumeID: "vol_01"}},
		{ID: "op_volume_delete", Kind: sandbox.OperationDeleteVolume, DeleteVolume: &sandbox.DeleteVolumeRequest{VolumeID: "vol_01"}},
		{ID: "op_snapshot_delete", Kind: sandbox.OperationDeleteSnapshot, DeleteSnapshot: &sandbox.DeleteSnapshotRequest{SnapshotID: "snap_01"}},
		{ID: "op_approve", Kind: sandbox.OperationApproveSensitive, ApproveSensitive: &sandbox.ApproveSensitiveOperationRequest{SensitiveOperationID: "op_sensitive", Decision: sandbox.ApprovalApproved, ExpiresAt: deadline}},
	}
	if len(requests) != 16 {
		t.Fatalf("public operation matrix has %d entries, want 16", len(requests))
	}
}

type credentialSource struct{}

func (credentialSource) Apply(context.Context, sandbox.CredentialSink) error { return nil }

type credentialSink struct{}

func (credentialSink) SetAuthorization(string, string) error { return nil }
func (credentialSink) ClearAuthorization()                   {}
