package sandbox

import (
	"context"
	"testing"
	"time"
)

func TestCoreAcceptsFrozenCreateOperation(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	request := validCreateRequest("op_01")

	ref, err := client.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	request.CreateSandbox.Spec.Labels["caller"] = "mutated"

	operation, err := client.GetOperation(context.Background(), ref.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if got, want := operation.State, OperationAccepted; got != want {
		t.Errorf("State = %q, want %q", got, want)
	}
	if got := operation.EffectiveSpecDigest; !validDigest(got) {
		t.Errorf("EffectiveSpecDigest = %q, want immutable sha256 digest", got)
	}
	stored := client.acceptedOperation(ref.ID)
	if got, want := stored.request.CreateSandbox.Spec.Labels["caller"], "original"; got != want {
		t.Errorf("accepted label = %q, want %q", got, want)
	}
}

func TestCoreReconnectsSameOperationIDAndRejectsChangedRequest(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	request := validCreateRequest("op_01")
	first, err := client.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("first Submit() error = %v", err)
	}
	second, err := client.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("same Submit() error = %v", err)
	}
	if second != first {
		t.Errorf("same request ref = %#v, want %#v", second, first)
	}

	changed := request
	changed.CreateSandbox = &CreateSandboxRequest{Spec: request.CreateSandbox.Spec}
	changed.CreateSandbox.Spec.Labels = map[string]string{"caller": "changed"}
	_, err = client.Submit(context.Background(), changed)
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureOperationConflict {
		t.Fatalf("changed Submit() failure = %#v, %v; want operation conflict", failure, err)
	}
}

func TestCoreRejectsInvalidOperationBeforeAcceptance(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	request := validCreateRequest("op_01")
	request.CreateSandbox = nil

	_, err := client.Submit(context.Background(), request)
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureInvalidArgument {
		t.Fatalf("Submit() failure = %#v, %v; want invalid argument", failure, err)
	}
	if client.operationCount() != 0 {
		t.Errorf("operation count = %d, want 0", client.operationCount())
	}
}

func TestNewClientRejectsInvalidConfigurationWithoutApplyingCredentials(t *testing.T) {
	source := &recordingCredentialSource{}
	_, err := NewClient(context.Background(), ClientConfig{Credentials: source})
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureInvalidArgument {
		t.Fatalf("NewClient() failure = %#v, %v; want invalid argument", failure, err)
	}
	if source.calls != 0 {
		t.Errorf("credential Apply calls = %d, want 0", source.calls)
	}
}

func TestCoreFreezesCommandArgumentsAndEnvironment(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	request := OperationRequest{
		ID:   "op_02",
		Kind: OperationExecProcess,
		ExecProcess: &ExecProcessRequest{SandboxID: "sbx_01", Command: Command{
			Executable:  "/bin/echo",
			Argv:        []string{"echo", "original"},
			WorkDir:     "/work",
			Environment: map[string]string{"MODE": "original"},
		}},
	}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	request.ExecProcess.Command.Argv[1] = "mutated"
	request.ExecProcess.Command.Environment["MODE"] = "mutated"
	stored := client.acceptedOperation("op_02").request.ExecProcess.Command
	if got, want := stored.Argv[1], "original"; got != want {
		t.Errorf("accepted argv = %q, want %q", got, want)
	}
	if got, want := stored.Environment["MODE"], "original"; got != want {
		t.Errorf("accepted environment = %q, want %q", got, want)
	}
}

func TestCoreTreatsEveryCreateAuthorityFieldAsOperationIdentity(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	request := validCreateRequest("op_03")
	request.CreateSandbox.Spec.SecretBindings = []SecretBinding{{Name: "build-token", Purpose: "build"}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatalf("first Submit() error = %v", err)
	}
	changed := request
	changed.CreateSandbox = &CreateSandboxRequest{Spec: copySpec(request.CreateSandbox.Spec)}
	changed.CreateSandbox.Spec.SecretBindings[0].Purpose = "deploy"
	_, err := client.Submit(context.Background(), changed)
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureOperationConflict {
		t.Fatalf("changed Submit() failure = %#v, %v; want operation conflict", failure, err)
	}
}

func TestCoreAcceptsValidatedCloseOperation(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	_, err := client.Submit(context.Background(), OperationRequest{
		ID:           "op_04",
		Kind:         OperationCloseSandbox,
		CloseSandbox: &CloseSandboxRequest{SandboxID: "sbx_01"},
	})
	failure, ok := AsFailure(err)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	_ = failure
	_ = ok
	if client.operationCount() != 1 {
		t.Errorf("operation count = %d, want 1", client.operationCount())
	}
}

func TestCoreRejectsLiteralIPNetworkGrantBeforeAcceptance(t *testing.T) {
	client := newCoreClient("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	request := OperationRequest{ID: "op_05", Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{
		SandboxID: "sbx_01",
		Command:   Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work", Grant: Grant{Network: NetworkGrantSelection{Mode: GrantSelect, Rules: []NetworkRule{{Protocol: NetworkTCP, Domain: "127.0.0.1", Ports: []PortRange{{First: 443, Last: 443}}}}}}},
	}}
	_, err := client.Submit(context.Background(), request)
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureNetworkGrantInvalid {
		t.Fatalf("Submit() failure = %#v, %v; want network grant invalid", failure, err)
	}
}

func TestCoreResolvesZeroResourcesFromInjectedFinitePolicy(t *testing.T) {
	policy := testLimitPolicy()
	policy.defaults.MemoryBytes = 4096
	policy.maximum.MemoryBytes = 4096
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatalf("newCoreClientWithPolicy() error = %v", err)
	}
	request := validCreateRequest("op_06")
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if got, want := client.acceptedOperation("op_06").request.CreateSandbox.Spec.Resources.MemoryBytes, uint64(4096); got != want {
		t.Errorf("effective memory = %d, want %d", got, want)
	}
}

func TestCoreRejectsMissingFiniteLimitPolicy(t *testing.T) {
	policy := testLimitPolicy()
	policy.defaults.MemoryBytes = 0
	_, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureInvalidArgument {
		t.Fatalf("newCoreClientWithPolicy() failure = %#v, %v; want invalid argument", failure, err)
	}
}

func TestCoreRejectsResourceRequestAboveInjectedPolicyMaximum(t *testing.T) {
	policy := testLimitPolicy()
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatalf("newCoreClientWithPolicy() error = %v", err)
	}
	request := validCreateRequest("op_07")
	request.CreateSandbox.Spec.Resources.MemoryBytes = policy.maximum.MemoryBytes + 1
	_, err = client.Submit(context.Background(), request)
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureResourceLimitExceeded {
		t.Fatalf("Submit() failure = %#v, %v; want resource limit exceeded", failure, err)
	}
}

type recordingCredentialSource struct{ calls int }

func (source *recordingCredentialSource) Apply(context.Context, CredentialSink) error {
	source.calls++
	return nil
}

func validCreateRequest(id OperationID) OperationRequest {
	return OperationRequest{
		ID:   id,
		Kind: OperationCreateSandbox,
		CreateSandbox: &CreateSandboxRequest{Spec: SandboxSpec{
			Image:  ImageRef{Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			Labels: map[string]string{"caller": "original"},
		}},
	}
}
