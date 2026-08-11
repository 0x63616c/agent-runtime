package sandbox

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCoreDoesNotEnumeratePrincipalScopedOperations(t *testing.T) {
	ledger := newCoreLedger()
	policy := testLimitPolicy()
	first, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy, ledger)
	if err != nil {
		t.Fatalf("new first client: %v", err)
	}
	second, err := newCoreClientWithLedger("principal-b", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy, ledger)
	if err != nil {
		t.Fatalf("new second client: %v", err)
	}
	request := validCreateRequest("op_shared")
	if _, err := first.Submit(context.Background(), request); err != nil {
		t.Fatalf("first Submit(): %v", err)
	}
	_, err = second.GetOperation(context.Background(), request.ID)
	failureCode(t, err, FailureNotFoundOrDenied)
	_, err = second.WaitOperation(context.Background(), request.ID)
	failureCode(t, err, FailureNotFoundOrDenied)
	_, err = second.Submit(context.Background(), request)
	failureCode(t, err, FailureNotFoundOrDenied)
}

func TestCoreFreezesEveryTaggedMutableInput(t *testing.T) {
	policy := testLimitPolicy()
	policy.capabilities.Egress = CapabilityDescriptor{State: CapabilityEnforced}
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatalf("newCoreClientWithPolicy(): %v", err)
	}
	limits := testLimitPolicy().defaults
	request := OperationRequest{ID: "op_mutable", Kind: OperationRestoreSandbox, RestoreSandbox: &RestoreSandboxRequest{
		SnapshotID: "snap_01",
		Overrides:  SandboxOverrides{Resources: &limits, Capabilities: &CapabilityRequirements{Required: []CapabilityRequirement{{Feature: CapabilityEgress, Minimum: CapabilityEnforced}}}},
	}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit(): %v", err)
	}
	limits.MemoryBytes = 99
	request.RestoreSandbox.Overrides.Capabilities.Required[0].Minimum = CapabilityUnavailable
	stored := client.acceptedOperation(request.ID).request.RestoreSandbox
	if stored.Overrides.Resources.MemoryBytes != 1 {
		t.Fatalf("stored limits = %#v, want frozen defaults", stored.Overrides.Resources)
	}
	if stored.Overrides.Capabilities.Required[0].Minimum != CapabilityEnforced {
		t.Fatalf("stored capabilities = %#v, want frozen", stored.Overrides.Capabilities)
	}
}

func TestCanonicalRequestIncludesEveryTaggedOperationBody(t *testing.T) {
	for index, request := range operationMatrixRequests() {
		t.Run(string(request.Kind), func(t *testing.T) {
			client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
			request.ID = OperationID("op_matrix_" + string(rune('a'+index)))
			ref, err := client.Submit(context.Background(), request)
			if err != nil {
				t.Fatalf("Submit(%s): %v", request.Kind, err)
			}
			operation, err := client.GetOperation(context.Background(), ref.ID)
			if err != nil {
				t.Fatalf("GetOperation(): %v", err)
			}
			if operation.Target.Kind != expectedTarget(request.Kind) {
				t.Fatalf("target kind = %q, want %q", operation.Target.Kind, expectedTarget(request.Kind))
			}
			changed := copyRequest(request)
			changed.CreateSandbox = nil
			changed.RestoreSandbox = nil
			changed.ExecProcess = nil
			changed.SignalProcess = nil
			changed.KillProcess = nil
			changed.CopyIn = nil
			changed.CopyOut = nil
			changed.SnapshotSandbox = nil
			changed.CloseSandbox = nil
			changed.ReconcileSandbox = nil
			changed.CreateVolume = nil
			changed.AttachVolume = nil
			changed.DetachVolume = nil
			changed.DeleteVolume = nil
			changed.DeleteSnapshot = nil
			changed.ApproveSensitive = nil
			_, err = client.Submit(context.Background(), changed)
			failureCode(t, err, FailureInvalidArgument)
		})
	}
}

func TestCoreRejectsCrossTypeOpaqueIDsBeforeAcceptance(t *testing.T) {
	requests := []OperationRequest{
		{ID: "op_wrong_restore", Kind: OperationRestoreSandbox, RestoreSandbox: &RestoreSandboxRequest{SnapshotID: "sbx_01"}},
		{ID: "op_wrong_exec", Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{SandboxID: "prc_01", Command: Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}},
		{ID: "op_wrong_kill", Kind: OperationKillProcess, KillProcess: &KillProcessRequest{ProcessID: "sbx_01"}},
		{ID: "op_wrong_copy", Kind: OperationCopyIn, CopyIn: &CopyInRequest{SandboxID: "sbx_01", Source: ArtifactRef{ID: "vol_01", SizeBytes: 1}, Destination: "/work/in"}},
		{ID: "op_wrong_attach", Kind: OperationAttachVolume, AttachVolume: &AttachVolumeRequest{SandboxID: "sbx_01", VolumeID: "snap_01", Target: "/work/volume"}},
		{ID: "op_wrong_approval", Kind: OperationApproveSensitive, ApproveSensitive: &ApproveSensitiveOperationRequest{SensitiveOperationID: "sbx_01", Decision: ApprovalApproved, ExpiresAt: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)}},
	}
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	for _, request := range requests {
		t.Run(string(request.Kind), func(t *testing.T) {
			if _, err := client.Submit(context.Background(), request); err == nil {
				t.Fatalf("Submit(%#v) error = nil, want cross-type ID rejection", request)
			}
		})
	}
}

// S9 behavior matrix for SBX-027: an operation accepts one canonical guest
// path, rejects an escaping/reserved/ambiguous path before durable acceptance,
// and leaves a valid absolute non-reserved path available for the configured
// backend to resolve beneath its own permitted roots.
func TestCoreAdmitsOnlyCanonicalNonReservedGuestPaths(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	valid := OperationRequest{ID: "op_guest_path_valid", Kind: OperationCopyOut, CopyOut: &CopyOutRequest{SandboxID: "sbx_01", Source: "/workspace/output.txt", MediaType: "text/plain"}}
	if _, err := client.Submit(context.Background(), valid); err != nil {
		t.Fatalf("Submit(valid guest path): %v", err)
	}
	missingMedia := valid
	missingMedia.ID = "op_guest_path_missing_media"
	missingMedia.CopyOut = &CopyOutRequest{SandboxID: "sbx_01", Source: "/workspace/output.txt"}
	if _, err := client.Submit(context.Background(), missingMedia); err == nil {
		t.Fatal("Submit(copy-out without media type) error = nil, want refusal")
	}
	missingDigest := OperationRequest{ID: "op_guest_path_missing_digest", Kind: OperationCopyIn, CopyIn: &CopyInRequest{SandboxID: "sbx_01", Source: ArtifactRef{ID: "art_01", MediaType: "application/octet-stream", SizeBytes: 1}, Destination: "/workspace/input.txt"}}
	if _, err := client.Submit(context.Background(), missingDigest); err == nil {
		t.Fatal("Submit(copy-in without immutable digest) error = nil, want refusal")
	}
	for _, value := range []GuestPath{
		"", "workspace/output.txt", "/workspace/../etc/passwd", "/workspace//output.txt", "/proc/self/status", "/dev/null", "/workspace/na\u00efve.txt", "/workspace/line\nfeed",
	} {
		request := valid
		request.ID = OperationID("op_guest_path_" + strings.ReplaceAll(strings.ReplaceAll(string(value), "/", "_"), "\n", "_"))
		request.CopyOut = &CopyOutRequest{SandboxID: "sbx_01", Source: value, MediaType: "text/plain"}
		if _, err := client.Submit(context.Background(), request); err == nil {
			t.Fatalf("Submit(%q) error = nil, want invalid guest path refusal", value)
		}
	}
}

func TestCanonicalRequestIsStableForMapOrderAndDistinctForNilEmpty(t *testing.T) {
	first := validCreateRequest("op_canonical")
	first.CreateSandbox.Spec.Environment = map[string]string{"B": "two", "A": "one"}
	second := copyRequest(first)
	second.CreateSandbox.Spec.Environment = map[string]string{"A": "one", "B": "two"}
	if got, want := canonicalRequestDigest(first), canonicalRequestDigest(second); got != want {
		t.Fatalf("map-order digest = %q, want %q", got, want)
	}
	second.CreateSandbox.Spec.Environment = map[string]string{}
	if canonicalRequestDigest(first) == canonicalRequestDigest(second) {
		t.Fatal("nil/empty and populated maps must be distinct")
	}
	third := copyRequest(first)
	third.CreateSandbox.Spec.Environment = nil
	if canonicalRequestDigest(second) == canonicalRequestDigest(third) {
		t.Fatal("nil and empty maps must be distinct")
	}
}

func TestCanonicalRequestGoldenVector(t *testing.T) {
	request := validCreateRequest("op_golden")
	request.CreateSandbox.Spec.Environment = map[string]string{"A": "one", "B": "two"}
	if got, want := canonicalRequestDigest(request), Digest("sha256:f560011cc25f16753ab89bbfaa0a040cfd5060ce8232122dd5dd691b29bf0285"); got != want {
		t.Fatalf("canonical digest = %q, want %q", got, want)
	}
}

func TestControlV1OperationCodecRoundTripsOnlyExactCanonicalBytes(t *testing.T) {
	request := validCreateRequest("op_wire")
	request.CreateSandbox.Spec.Environment = map[string]string{"B": "two", "A": "one"}
	encoded, err := encodeOperationRequestV1(request)
	if err != nil {
		t.Fatalf("encodeOperationRequestV1(): %v", err)
	}
	decoded, err := decodeOperationRequestV1(encoded)
	if err != nil {
		t.Fatalf("decodeOperationRequestV1(): %v", err)
	}
	if got, want := canonicalRequestDigest(decoded), canonicalRequestDigest(request); got != want {
		t.Fatalf("round-trip digest = %q, want %q", got, want)
	}
	nonCanonicalMapOrder := bytes.Replace(encoded, []byte(`"A":"one","B":"two"`), []byte(`"B":"two","A":"one"`), 1)
	if bytes.Equal(nonCanonicalMapOrder, encoded) {
		t.Fatal("canonical fixture did not contain sorted environment keys")
	}
	for _, mutated := range [][]byte{
		[]byte(`{"version":"sandbox.control/v1","version":"sandbox.control/v1","kind":"operation-request","request":{}}`),
		append(append([]byte(nil), encoded...), []byte(" null")...),
		[]byte(`{"version":"sandbox.control/v1","kind":"operation-request","request":1.5}`),
		nonCanonicalMapOrder,
		[]byte(`{"version":"sandbox.control/v1","kind":"operation-request","request":{"ID":"op_wire","Kind":"create-sandbox","CreateSandbox":null,"RestoreSandbox":null,"ExecProcess":null,"SignalProcess":null,"KillProcess":null,"CopyIn":null,"CopyOut":null,"SnapshotSandbox":null,"CloseSandbox":null,"ReconcileSandbox":null,"CreateVolume":null,"AttachVolume":null,"DetachVolume":null,"DeleteVolume":null,"DeleteSnapshot":null,"ApproveSensitive":null},"extra":1}`),
	} {
		if _, err := decodeOperationRequestV1(mutated); err == nil {
			t.Fatalf("decodeOperationRequestV1(%s) error = nil, want strict rejection", mutated)
		}
	}
}

func TestControlV1CodecRejectsOversizedAndExcessivelyNestedInput(t *testing.T) {
	oversized := bytes.Repeat([]byte{' '}, maxControlV1Bytes+1)
	if _, err := decodeOperationRequestV1(oversized); err == nil {
		t.Fatal("oversized sandbox.control/v1 input was accepted")
	}
	nested := append(bytes.Repeat([]byte{'['}, maxControlV1Nesting+1), bytes.Repeat([]byte{']'}, maxControlV1Nesting+1)...)
	if err := validateStrictJSON(nested); err == nil {
		t.Fatal("excessively nested sandbox.control/v1 input was accepted")
	}
}

func TestCoreRetriesWithPersistedEffectiveSpecAndRejectsIncompatiblePolicy(t *testing.T) {
	ledger := newCoreLedger()
	initial := testLimitPolicy()
	initial.defaults.MemoryBytes = 64
	initial.maximum.MemoryBytes = 128
	client, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), initial, ledger)
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateRequest("op_retry")
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	changed := initial
	changed.defaults.MemoryBytes = 96
	retrier, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 6, 12, 1, 0, 0, time.UTC), changed, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retrier.Submit(context.Background(), request); err != nil {
		t.Fatalf("retry with changed defaults: %v", err)
	}
	if got := retrier.acceptedOperation(request.ID).effective.limits.MemoryBytes; got != 64 {
		t.Fatalf("retry effective memory = %d, want persisted 64", got)
	}
	incompatible := changed
	incompatible.defaults.MemoryBytes = 32
	incompatible.maximum.MemoryBytes = 32
	blocked, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 6, 12, 2, 0, 0, time.UTC), incompatible, ledger)
	if err != nil {
		t.Fatal(err)
	}
	_, err = blocked.Submit(context.Background(), request)
	failureCode(t, err, FailureIncompatiblePersistedPolicy)
}

func TestCoreRetryRejectsChangedImageCompatibilityForSameDigest(t *testing.T) {
	ledger := newCoreLedger()
	request := validCreateRequest("op_image_retry")
	image := request.CreateSandbox.Spec.Image.Digest
	initial := testLimitPolicy()
	initial.admittedImages = map[Digest]ImageInfo{image: {
		Digest: image, Architecture: "linux/amd64", Identity: NumericIdentity{UID: 1000, GID: 1000}, GuestProtocol: "guest/v1",
	}}
	client, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), initial, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	changed := initial
	changed.admittedImages = map[Digest]ImageInfo{image: {
		Digest: image, Architecture: "linux/amd64", Identity: NumericIdentity{UID: 1000, GID: 1000}, GuestProtocol: "guest/v2",
	}}
	retrier, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 6, 12, 1, 0, 0, time.UTC), changed, ledger)
	if err != nil {
		t.Fatal(err)
	}
	_, err = retrier.Submit(context.Background(), request)
	failureCode(t, err, FailureIncompatiblePersistedPolicy)
}

func TestCoreFreezesInjectedImageAdmissionMetadata(t *testing.T) {
	request := validCreateRequest("op_frozen_image_policy")
	image := request.CreateSandbox.Spec.Image.Digest
	policy := testLimitPolicy()
	policy.admittedImages = map[Digest]ImageInfo{image: {
		Digest: image, Architecture: "linux/amd64", Identity: NumericIdentity{UID: 1000, GID: 1000, Groups: []uint32{1000}}, GuestProtocol: "guest/v1",
	}}
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatal(err)
	}
	mutated := policy.admittedImages[image]
	mutated.GuestProtocol = "guest/attacker"
	mutated.Identity.Groups[0] = 0
	policy.admittedImages[image] = mutated
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	info, err := client.GetSandbox(context.Background(), sandboxIDFor(request.ID))
	if err != nil {
		t.Fatal(err)
	}
	if info.Image.GuestProtocol != "guest/v1" || !reflect.DeepEqual(info.Image.Identity.Groups, []uint32{1000}) {
		t.Fatalf("accepted image metadata = %#v, want constructor-frozen admission", info.Image)
	}
}

func TestProcessWaitCancellationAbandonsObservationAndFirstTerminalOutcomeWins(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	request := OperationRequest{ID: "op_wait", Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{SandboxID: "sbx_01", Command: Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.WaitOperation(ctx, request.ID)
	failureCode(t, err, FailureCancelled)
	if !errors.Is(func() error { _, err := client.WaitOperation(ctx, request.ID); return err }(), context.Canceled) {
		t.Fatal("wait cancellation must preserve context sentinel")
	}
	processID := processIDFor(request.ID)
	exit := 7
	result := ProcessResult{StartedAt: client.now, FinishedAt: client.now, ExitCode: &exit, Reason: TerminationExited, Cleanup: TreeCleanupConfirmed}
	if err := client.completeProcess(processID, result); err != nil {
		t.Fatal(err)
	}
	err = client.completeProcess(processID, ProcessResult{Reason: TerminationKilledByCaller, Cleanup: TreeCleanupConfirmed})
	failureCode(t, err, FailureAlreadyTerminal)
	operation, err := client.WaitOperation(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Result == nil || operation.Result.Process == nil || operation.Result.Process.Reason != TerminationExited || operation.Result.Process.ExitCode == nil || *operation.Result.Process.ExitCode != 7 {
		t.Fatalf("terminal operation = %#v, want original exited result", operation)
	}
}

func TestCancelledProcessStartRecordsTypedTerminalWithoutAHostProcess(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	request := OperationRequest{ID: "op_start_cancel", Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{SandboxID: "sbx_01", Command: Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := client.startProcess(ctx, processIDFor(request.ID))
	failureCode(t, err, FailureCancelled)
	info, err := client.GetProcess(context.Background(), processIDFor(request.ID))
	if err != nil {
		t.Fatal(err)
	}
	if info.State != ProcessTerminal || info.Result == nil || info.Result.Reason != TerminationCancelled {
		t.Fatalf("cancelled start = %#v, want typed terminal cancellation", info)
	}
}

func TestOutputLimitTerminatesWithoutReaderAndReplayHasFinal(t *testing.T) {
	policy := testLimitPolicy()
	policy.defaults.ProducedOutputBytes = 4
	policy.maximum.ProducedOutputBytes = 4
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatal(err)
	}
	request := OperationRequest{ID: "op_output", Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{SandboxID: "sbx_01", Command: Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := client.appendProcessOutput(processIDFor(request.ID), OutputStdout, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	err = client.appendProcessOutput(processIDFor(request.ID), OutputStdout, []byte("5"))
	failureCode(t, err, FailureResourceLimitExceeded)
	stream, err := client.ReplayOutput(context.Background(), processIDFor(request.ID), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := stream.Close(); closeErr != nil {
			t.Errorf("close output stream: %v", closeErr)
		}
	})
	seenFinal := false
	for {
		event, err := stream.Next(context.Background())
		if err != nil {
			break
		}
		if event.Kind == OutputEventFinal {
			seenFinal = true
			if event.Final.Result.Reason != TerminationOutputLimit {
				t.Fatalf("final reason = %q", event.Final.Result.Reason)
			}
		}
	}
	if !seenFinal {
		t.Fatal("replay must finish even with no reader during process output")
	}
}

func TestOutputRetentionGapDoesNotLeakCrossChunkSecretAndFinalIsUnique(t *testing.T) {
	spool, err := newProcessOutputSpool(32, 4, []string{"secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Write(OutputStdout, []byte("a sec")); err != nil {
		t.Fatal(err)
	}
	if err := spool.Write(OutputStdout, []byte("ret z")); err != nil {
		t.Fatal(err)
	}
	spool.Close(ProcessResult{Reason: TerminationCancelled, Cleanup: TreeCleanupConfirmed})
	events := spool.Events()
	gap, final := 0, 0
	for _, event := range events {
		if event.Chunk != nil && string(event.Chunk.Bytes) == "secret" {
			t.Fatal("raw secret reached retained output")
		}
		if event.Kind == OutputEventGap {
			gap++
		}
		if event.Kind == OutputEventFinal {
			final++
		}
	}
	if gap != 1 || final != 2 {
		t.Fatalf("events = %#v, want one retention gap and one final per stream", events)
	}
	if _, err := newSliceOutputStream(events, "999"); err == nil {
		t.Fatal("expired replay cursor must return an explicit output gap")
	}
}

func TestProcessOutputCursorsStayUnambiguousAcrossStreams(t *testing.T) {
	policy := testLimitPolicy()
	policy.defaults.ProducedOutputBytes, policy.defaults.RetainedOutputBytes = 64, 64
	policy.maximum.ProducedOutputBytes, policy.maximum.RetainedOutputBytes = 64, 64
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatal(err)
	}
	request := OperationRequest{ID: "op_output_cursors", Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{SandboxID: "sbx_01", Command: Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	processID := processIDFor(request.ID)
	if err := client.appendProcessOutput(processID, OutputStdout, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := client.appendProcessOutput(processID, OutputStderr, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := client.completeProcess(processID, ProcessResult{Reason: TerminationCancelled, Cleanup: TreeCleanupConfirmed}); err != nil {
		t.Fatal(err)
	}
	stream, err := client.ReplayOutput(context.Background(), processID, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := stream.Close(); closeErr != nil {
			t.Errorf("close output stream: %v", closeErr)
		}
	})
	seen := map[OutputCursor]OutputKind{}
	chunks := make([]string, 0, 2)
	stdoutFinal, stderrChunk := -1, -1
	position := 0
	for {
		event, nextErr := stream.Next(context.Background())
		if nextErr != nil {
			break
		}
		if prior, duplicate := seen[event.Cursor]; duplicate {
			t.Fatalf("output cursor %q is shared by %q and %q", event.Cursor, prior, event.Stream)
		}
		seen[event.Cursor] = event.Stream
		if event.Chunk != nil {
			chunks = append(chunks, string(event.Chunk.Bytes))
			if event.Stream == OutputStderr {
				stderrChunk = position
			}
		}
		if event.Final != nil && event.Stream == OutputStdout {
			stdoutFinal = position
		}
		position++
	}
	if got, want := strings.Join(chunks, ","), "one,two"; got != want {
		t.Fatalf("replayed chunk order = %q, want %q", got, want)
	}
	if stdoutFinal < stderrChunk {
		t.Fatalf("stdout final at %d arrived before prior stderr output at %d", stdoutFinal, stderrChunk)
	}
}

func TestInterleavedOutputRetentionKeepsBoundedTailsAndExplicitGaps(t *testing.T) {
	policy := testLimitPolicy()
	policy.defaults.ProducedOutputBytes, policy.defaults.RetainedOutputBytes = 64, 3
	policy.maximum.ProducedOutputBytes, policy.maximum.RetainedOutputBytes = 64, 3
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatal(err)
	}
	request := OperationRequest{ID: "op_output_retention", Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{SandboxID: "sbx_01", Command: Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	processID := processIDFor(request.ID)
	for _, write := range []struct {
		stream OutputKind
		bytes  string
	}{
		{OutputStdout, "old"},
		{OutputStderr, "bad"},
		{OutputStdout, "new"},
		{OutputStderr, "good"},
	} {
		if err := client.appendProcessOutput(processID, write.stream, []byte(write.bytes)); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.completeProcess(processID, ProcessResult{Reason: TerminationCancelled, Cleanup: TreeCleanupConfirmed}); err != nil {
		t.Fatal(err)
	}
	stream, err := client.ReplayOutput(context.Background(), processID, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := stream.Close(); closeErr != nil {
			t.Errorf("close output stream: %v", closeErr)
		}
	})
	var chunks []string
	gaps := 0
	for {
		event, nextErr := stream.Next(context.Background())
		if nextErr != nil {
			break
		}
		if event.Chunk != nil {
			chunks = append(chunks, string(event.Chunk.Bytes))
		}
		if event.Gap != nil {
			gaps++
		}
	}
	if got, want := strings.Join(chunks, ","), "new,ood"; got != want {
		t.Fatalf("retained replay chunks = %q, want %q", got, want)
	}
	retainedBytes := 0
	for _, chunk := range chunks {
		retainedBytes += len(chunk)
	}
	if retainedBytes > 6 {
		t.Fatalf("retained replay bytes = %d, want independent three-byte stream tails", retainedBytes)
	}
	if gaps != 2 {
		t.Fatalf("retention gaps = %d, want one per truncated stream", gaps)
	}
}

func TestProducedOutputLimitIsSharedAcrossAlternatingStreams(t *testing.T) {
	policy := testLimitPolicy()
	policy.defaults.ProducedOutputBytes, policy.defaults.RetainedOutputBytes = 5, 5
	policy.maximum.ProducedOutputBytes, policy.maximum.RetainedOutputBytes = 5, 5
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatal(err)
	}
	request := OperationRequest{ID: "op_process_output_limit", Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{SandboxID: "sbx_01", Command: Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	processID := processIDFor(request.ID)
	if err := client.appendProcessOutput(processID, OutputStdout, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	err = client.appendProcessOutput(processID, OutputStderr, []byte("def"))
	failureCode(t, err, FailureResourceLimitExceeded)
	info, err := client.GetProcess(context.Background(), processID)
	if err != nil {
		t.Fatal(err)
	}
	if info.Result == nil || info.Result.Reason != TerminationOutputLimit {
		t.Fatalf("output-limited process = %#v, want typed output limit", info)
	}
}

func TestControlAdmissionQuotaRejectsBeforeAddingAnotherOperation(t *testing.T) {
	policy := testLimitPolicy()
	policy.maximumOperations = 1
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(context.Background(), validCreateRequest("op_capacity_a")); err != nil {
		t.Fatal(err)
	}
	_, err = client.Submit(context.Background(), validCreateRequest("op_capacity_b"))
	failureCode(t, err, FailureControlQuotaExceeded)
	if got := client.operationCount(); got != 1 {
		t.Fatalf("operation count = %d, want one accepted operation", got)
	}
}

func TestProcessAdmissionQuotaRejectsBeforeOperationAcceptance(t *testing.T) {
	policy := testLimitPolicy()
	policy.maximumProcesses = 1
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatal(err)
	}
	process := func(id OperationID) OperationRequest {
		return OperationRequest{ID: id, Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{SandboxID: "sbx_01", Command: Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}}
	}
	if _, err := client.Submit(context.Background(), process("op_process_a")); err != nil {
		t.Fatal(err)
	}
	_, err = client.Submit(context.Background(), process("op_process_b"))
	failureCode(t, err, FailureControlQuotaExceeded)
	if got := client.operationCount(); got != 1 {
		t.Fatalf("operation count = %d, want one", got)
	}
}

func TestOperationWatchAdmissionIsFiniteAndReleasedOnLocalClose(t *testing.T) {
	policy := testLimitPolicy()
	policy.maximumWatches = 1
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateRequest("op_watch_capacity")
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	first, err := client.WatchOperation(context.Background(), request.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.WatchOperation(context.Background(), request.ID, "")
	failureCode(t, err, FailureControlQuotaExceeded)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := client.WatchOperation(context.Background(), request.ID, "")
	if err != nil {
		t.Fatalf("WatchOperation() after Close() error = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOperationWatchAdmissionIsPrincipalScopedAcrossClients(t *testing.T) {
	ledger := newCoreLedger()
	policy := testLimitPolicy()
	policy.maximumWatches = 1
	first, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy, ledger)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy, ledger)
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateRequest("op_shared_watch_capacity")
	if _, err := first.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	stream, err := first.WatchOperation(context.Background(), request.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := stream.Close(); closeErr != nil {
			t.Errorf("close operation stream: %v", closeErr)
		}
	})
	_, err = second.WatchOperation(context.Background(), request.ID, "")
	failureCode(t, err, FailureControlQuotaExceeded)
}

func TestClientCloseRejectsNewObservationWithoutClosingDurableOperation(t *testing.T) {
	ledger := newCoreLedger()
	policy := testLimitPolicy()
	client, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy, ledger)
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateRequest("op_closed_client")
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err = client.GetOperation(context.Background(), request.ID)
	failureCode(t, err, FailureUnavailable)
	reconnected, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconnected.GetOperation(context.Background(), request.ID); err != nil {
		t.Fatalf("operation was closed with local client: %v", err)
	}
}

func TestClientCloseClosesActiveOperationObservation(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	request := validCreateRequest("op_close_stream")
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	stream, err := client.WatchOperation(context.Background(), request.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err == nil {
		t.Fatal("Next() after Client.Close() error = nil, want local observation cancellation")
	}
}

func TestEveryTypedTerminationReasonRemainsDistinct(t *testing.T) {
	for _, reason := range []TerminationReason{
		TerminationExited, TerminationSignaled, TerminationTimedOut, TerminationOOMKilled, TerminationOutputLimit,
		TerminationCancelled, TerminationKilledByCaller, TerminationSandboxClosed, TerminationSandboxLost,
		TerminationStartupFailed, TerminationInfrastructureFailed, TerminationOutcomeUncertain,
	} {
		t.Run(string(reason), func(t *testing.T) {
			result := ProcessResult{Reason: reason, Cleanup: TreeCleanupConfirmed}
			if reason == TerminationExited {
				code := 1
				result.ExitCode = &code
			}
			if reason == TerminationSignaled {
				signal := SignalKill
				result.Signal = &signal
			}
			if err := validateProcessResult(result); err != nil {
				t.Fatalf("validateProcessResult(%q): %v", reason, err)
			}
		})
	}
	code := 137
	if err := validateProcessResult(ProcessResult{Reason: TerminationOutcomeUncertain, ExitCode: &code}); err == nil {
		t.Fatal("uncertain result must not flatten to an exit code")
	}
	for _, reason := range []TerminationReason{
		TerminationSignaled, TerminationTimedOut, TerminationOOMKilled, TerminationOutputLimit,
		TerminationCancelled, TerminationKilledByCaller, TerminationSandboxClosed, TerminationSandboxLost,
		TerminationStartupFailed, TerminationInfrastructureFailed,
	} {
		result := ProcessResult{Reason: reason, ExitCode: &code, Cleanup: TreeCleanupConfirmed}
		if reason == TerminationSignaled {
			signal := SignalKill
			result.Signal = &signal
		}
		if err := validateProcessResult(result); err == nil {
			t.Fatalf("%q result flattened to exit code 137", reason)
		}
	}
	invalidSignal := Signal("backend-signal-9")
	if err := validateProcessResult(ProcessResult{Reason: TerminationSignaled, Signal: &invalidSignal}); err == nil {
		t.Fatal("backend-specific signal escaped the portable result contract")
	}
}

func TestImageAdmissionReportsSafeMetadataAndRejectsUnadmittedContent(t *testing.T) {
	request := validCreateRequest("op_image")
	policy := testLimitPolicy()
	policy.admittedImages = map[Digest]ImageInfo{request.CreateSandbox.Spec.Image.Digest: {Digest: request.CreateSandbox.Spec.Image.Digest, Architecture: "linux/arm64", Identity: NumericIdentity{UID: 1000, GID: 1000, Groups: []uint32{1000}}, GuestProtocol: "guest/v7"}}
	policy.imageAdmissionVersion = "images/v7"
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	info, err := client.GetSandbox(context.Background(), sandboxIDFor(request.ID))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Image.Architecture+"/"+info.Image.GuestProtocol+"/"+info.Image.AdmissionPolicyVersion, "linux/arm64/guest/v7/images/v7"; got != want {
		t.Fatalf("image info = %q, want %q", got, want)
	}
	unadmitted := validCreateRequest("op_unadmitted")
	unadmitted.CreateSandbox.Spec.Image.Digest = Digest("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_, err = client.Submit(context.Background(), unadmitted)
	failureCode(t, err, FailureCapabilityUnavailable)
}

func TestConcurrentEquivalentSubmissionHasOnePrincipalLedgerEntry(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	request := validCreateRequest("op_race")
	var group sync.WaitGroup
	errors := make(chan error, 32)
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := client.Submit(context.Background(), copyRequest(request))
			errors <- err
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent Submit(): %v", err)
		}
	}
	if got := client.operationCount(); got != 1 {
		t.Fatalf("operation count = %d, want one", got)
	}
}

func TestCreateSandboxRefusesARequiredCapabilityThatTheProfileDoesNotAdvertise(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC))
	request := validCreateRequest("op_requires_transfer")
	request.CreateSandbox.Spec.Capabilities.Required = []CapabilityRequirement{{Feature: CapabilityTransfer, Minimum: CapabilityEnforced}}

	_, err := client.Submit(context.Background(), request)
	failureCode(t, err, FailureCapabilityUnavailable)
}

func TestCreateSandboxRefusesRequestedSecretMountAndVolumeProfilesThatAreUnavailable(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC))
	for name, mutate := range map[string]func(*SandboxSpec){
		"secret": func(spec *SandboxSpec) {
			spec.SecretBindings = []SecretBinding{{Name: "build-token", Purpose: "build"}}
		},
		"mount": func(spec *SandboxSpec) {
			spec.Mounts = []MountRequest{{Name: "workspace", Target: "/work", Mode: MountReadOnly, View: MountFrozen}}
		},
		"volume": func(spec *SandboxSpec) {
			spec.VolumeAttachments = []VolumeAttachment{{VolumeID: "vol_01", Target: "/work/data", Mode: AttachmentReadWrite}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := validCreateRequest(OperationID("op_unavailable_" + name))
			mutate(&request.CreateSandbox.Spec)
			_, err := client.Submit(context.Background(), request)
			failureCode(t, err, FailureCapabilityUnavailable)
		})
	}
}

func TestCreateSandboxRejectsUnsafeNestedGuestPathsBeforeCapabilityDispatch(t *testing.T) {
	policy := testLimitPolicy()
	policy.capabilities.Mounts = CapabilityDescriptor{State: CapabilityEnforced}
	policy.capabilities.Volumes = CapabilityDescriptor{State: CapabilityEnforced}
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatalf("newCoreClientWithPolicy(): %v", err)
	}
	for name, mutate := range map[string]func(*SandboxSpec){
		"mount": func(spec *SandboxSpec) {
			spec.Mounts = []MountRequest{{Name: "workspace", Target: "/proc/self", Mode: MountReadOnly, View: MountFrozen}}
		},
		"volume": func(spec *SandboxSpec) {
			spec.VolumeAttachments = []VolumeAttachment{{VolumeID: "vol_01", Target: "/workspace/../etc", Mode: AttachmentReadWrite}}
		},
		"tmpfs": func(spec *SandboxSpec) { spec.Tmpfs = []TmpfsMount{{Target: "/workspace//tmp", SizeBytes: 1}} },
	} {
		t.Run(name, func(t *testing.T) {
			request := validCreateRequest(OperationID("op_unsafe_nested_path_" + name))
			mutate(&request.CreateSandbox.Spec)
			_, err := client.Submit(context.Background(), request)
			failureCode(t, err, FailureInvalidArgument)
		})
	}
}

func TestRestoreSandboxRefusesARequiredCapabilityThatTheProfileDoesNotAdvertise(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC))
	request := OperationRequest{ID: "op_restore_requires_snapshot", Kind: OperationRestoreSandbox, RestoreSandbox: &RestoreSandboxRequest{SnapshotID: "snap_01", Overrides: SandboxOverrides{Capabilities: &CapabilityRequirements{Required: []CapabilityRequirement{{Feature: CapabilitySnapshots, Minimum: CapabilityEnforced}}}}}}

	_, err := client.Submit(context.Background(), request)
	failureCode(t, err, FailureCapabilityUnavailable)
}

func failureCode(t *testing.T, err error, want FailureCode) {
	t.Helper()
	failure, ok := AsFailure(err)
	if !ok || failure.Code != want {
		t.Fatalf("failure = %#v, error = %v; want %q", failure, err, want)
	}
}

func expectedTarget(kind OperationKind) OperationTargetKind {
	switch kind {
	case OperationCreateSandbox, OperationCreateVolume:
		return TargetNone
	case OperationRestoreSandbox, OperationDeleteSnapshot:
		return TargetSnapshot
	case OperationExecProcess, OperationCopyIn, OperationCopyOut, OperationSnapshotSandbox, OperationCloseSandbox, OperationReconcileSandbox:
		return TargetSandbox
	case OperationSignalProcess, OperationKillProcess:
		return TargetProcess
	case OperationAttachVolume, OperationDetachVolume, OperationDeleteVolume:
		return TargetVolume
	case OperationApproveSensitive:
		return TargetOperation
	default:
		panic("missing operation kind")
	}
}

func operationMatrixRequests() []OperationRequest {
	return []OperationRequest{
		validCreateRequest("op_unused"),
		{Kind: OperationRestoreSandbox, RestoreSandbox: &RestoreSandboxRequest{SnapshotID: "snap_01"}},
		{Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{SandboxID: "sbx_01", Command: Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}},
		{Kind: OperationSignalProcess, SignalProcess: &SignalProcessRequest{ProcessID: "prc_01", Signal: SignalInterrupt}},
		{Kind: OperationKillProcess, KillProcess: &KillProcessRequest{ProcessID: "prc_01"}},
		{Kind: OperationCopyIn, CopyIn: &CopyInRequest{SandboxID: "sbx_01", Source: ArtifactRef{ID: "art_01", MediaType: "application/octet-stream", SizeBytes: 1, Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, Destination: "/work/in"}},
		{Kind: OperationCopyOut, CopyOut: &CopyOutRequest{SandboxID: "sbx_01", Source: "/work/out", MediaType: "application/octet-stream"}},
		{Kind: OperationSnapshotSandbox, SnapshotSandbox: &SnapshotSandboxRequest{SandboxID: "sbx_01"}},
		{Kind: OperationCloseSandbox, CloseSandbox: &CloseSandboxRequest{SandboxID: "sbx_01"}},
		{Kind: OperationReconcileSandbox, ReconcileSandbox: &ReconcileSandboxRequest{SandboxID: "sbx_01"}},
		{Kind: OperationCreateVolume, CreateVolume: &CreateVolumeRequest{Spec: VolumeSpec{SizeBytes: 1, Inodes: 1}}},
		{Kind: OperationAttachVolume, AttachVolume: &AttachVolumeRequest{SandboxID: "sbx_01", VolumeID: "vol_01", Target: "/work/volume"}},
		{Kind: OperationDetachVolume, DetachVolume: &DetachVolumeRequest{SandboxID: "sbx_01", VolumeID: "vol_01"}},
		{Kind: OperationDeleteVolume, DeleteVolume: &DeleteVolumeRequest{VolumeID: "vol_01"}},
		{Kind: OperationDeleteSnapshot, DeleteSnapshot: &DeleteSnapshotRequest{SnapshotID: "snap_01"}},
		{Kind: OperationApproveSensitive, ApproveSensitive: &ApproveSensitiveOperationRequest{SensitiveOperationID: "op_sensitive", Decision: ApprovalApproved, ExpiresAt: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)}},
	}
}
