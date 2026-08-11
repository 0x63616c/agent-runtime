package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestSecretExecutionAuthorityBindsOnlyTheExactEnvelopeContextAndRedactsOutput(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	source, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	sink := &secretAuthoritySink{}
	manager, err := sandboxauthority.NewManager(secretAuthorityResolver{value: []byte("secret-value")}, sink, secretAuthorityAudit{})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewSecretExecutionAuthority(manager, source)
	if err != nil {
		t.Fatal(err)
	}
	request := sandboxauthority.SecretRequest{Principal: "principal-001", SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", Binding: "binding-001", Purpose: "command", ExpiresAt: now.Add(time.Minute)}
	payload, err := json.Marshal(GuestSecretCommand{Version: GuestSecretCommandOperationKind, Command: json.RawMessage(`{"version":"agent-runtime.guest-command/v1"}`), Secret: request})
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{Principal: request.Principal, SandboxID: request.SandboxID, ProcessID: request.ProcessID, OperationID: request.OperationID, OperationKind: GuestSecretCommandOperationKind, ExpiresAt: request.ExpiresAt, Payload: payload}
	if _, err := authority.Begin(context.Background(), envelope); err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if got := string(authority.RedactOutput(request.ProcessID, []byte("before secret-value after"))); got != "before [REDACTED] after" {
		t.Fatalf("RedactOutput() = %q", got)
	}
	if err := authority.AbortBeforeStart(context.Background(), request.ProcessID); err != nil {
		t.Fatalf("AbortBeforeStart() error = %v", err)
	}
	if string(payload) == "secret-value" {
		t.Fatal("secret value appeared in command authorization")
	}
}

func TestSecretExecutionAuthorityRefusesEnvelopeContextSubstitutionBeforeResolution(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	source, _ := clock.NewFake(now)
	resolver := &secretAuthorityCountingResolver{}
	manager, _ := sandboxauthority.NewManager(resolver, &secretAuthoritySink{}, secretAuthorityAudit{})
	authority, _ := NewSecretExecutionAuthority(manager, source)
	request := sandboxauthority.SecretRequest{Principal: "principal-001", SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", Binding: "binding-001", Purpose: "command", ExpiresAt: now.Add(time.Minute)}
	payload, _ := json.Marshal(GuestSecretCommand{Version: GuestSecretCommandOperationKind, Command: json.RawMessage(`{"version":"agent-runtime.guest-command/v1"}`), Secret: request})
	envelope := sandboxhostprotocol.Envelope{Principal: "other", SandboxID: request.SandboxID, ProcessID: request.ProcessID, OperationID: request.OperationID, OperationKind: GuestSecretCommandOperationKind, ExpiresAt: request.ExpiresAt, Payload: payload}
	if _, err := authority.Begin(context.Background(), envelope); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("Begin() error = %v, want capability unavailable", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver calls = %d, want no secret resolution", resolver.calls)
	}
}

type secretAuthorityResolver struct{ value []byte }

func (resolver secretAuthorityResolver) Resolve(_ context.Context, request sandboxauthority.SecretRequest) (sandboxauthority.SecretValue, error) {
	return sandboxauthority.SecretValue{Version: "version-001", ExpiresAt: request.ExpiresAt, Bytes: append([]byte(nil), resolver.value...)}, nil
}

type secretAuthorityCountingResolver struct{ calls int }

func (resolver *secretAuthorityCountingResolver) Resolve(context.Context, sandboxauthority.SecretRequest) (sandboxauthority.SecretValue, error) {
	resolver.calls++
	return sandboxauthority.SecretValue{}, errors.New("resolution must not run")
}

type secretAuthoritySink struct{}

func (secretAuthoritySink) Deliver(context.Context, sandboxauthority.SecretRequest, []byte) error {
	return nil
}
func (secretAuthoritySink) RevokeAfterTreeReap(context.Context, sandboxauthority.SecretRequest) error {
	return nil
}
func (secretAuthoritySink) AbortBeforeStart(context.Context, sandboxauthority.SecretRequest) error {
	return nil
}

type secretAuthorityAudit struct{}

func (secretAuthorityAudit) RecordSecretDelivery(context.Context, sandboxauthority.SecretAuditFact) error {
	return nil
}
