package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

// GuestSecretCommandOperationKind identifies the private command shape that
// can request one contextual secret. It never carries a secret value.
const GuestSecretCommandOperationKind = "agent-runtime.guest-secret-command/v1"

// GuestSecretCommand is the canonical secret-free command authorization sent
// across the private guest boundary. Command is the bounded typed command JSON
// interpreted only by the guest runner after its secret lifecycle is active.
type GuestSecretCommand struct {
	Version string                         `json:"version"`
	Command json.RawMessage                `json:"command"`
	Secret  sandboxauthority.SecretRequest `json:"secret"`
}

// DecodeGuestSecretCommand accepts only one canonical secret-free command
// authorization. Secret bytes have no representation in this payload.
func DecodeGuestSecretCommand(payload []byte) (GuestSecretCommand, error) {
	if len(payload) == 0 || len(payload) > maximumGuestDispatchBytes {
		return GuestSecretCommand{}, fmt.Errorf("decode guest secret command: %w", ErrCapabilityUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var command GuestSecretCommand
	if err := decoder.Decode(&command); err != nil {
		return GuestSecretCommand{}, fmt.Errorf("decode guest secret command: %w", ErrCapabilityUnavailable)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return GuestSecretCommand{}, fmt.Errorf("decode guest secret command: %w", ErrCapabilityUnavailable)
	}
	canonical, err := json.Marshal(command)
	if err != nil || !bytes.Equal(canonical, payload) || command.Version != GuestSecretCommandOperationKind || len(command.Command) == 0 || len(command.Command) > maximumGuestDispatchBytes || !validSecretRequestShape(command.Secret) {
		return GuestSecretCommand{}, fmt.Errorf("decode guest secret command: %w", ErrCapabilityUnavailable)
	}
	return command, nil
}

// SecretExecutionAuthority binds one Manager to host-control time. It owns no
// route or envelope verification and never stores secret bytes itself.
type SecretExecutionAuthority struct {
	manager *sandboxauthority.Manager
	clock   clock.Clock
}

// NewSecretExecutionAuthority constructs the command-scoped lifecycle only
// around an explicit resolver/sink/audit Manager and deterministic time source.
func NewSecretExecutionAuthority(manager *sandboxauthority.Manager, source clock.Clock) (*SecretExecutionAuthority, error) {
	if manager == nil || source == nil {
		return nil, fmt.Errorf("create guest secret authority: manager and clock are required")
	}
	return &SecretExecutionAuthority{manager: manager, clock: source}, nil
}

// Begin verifies that a signed host envelope authorizes exactly one contextual
// secret request, then delivers it through the Manager's ephemeral sink.
func (authority *SecretExecutionAuthority) Begin(ctx context.Context, envelope sandboxhostprotocol.Envelope) (GuestSecretCommand, error) {
	if authority == nil || ctx == nil {
		return GuestSecretCommand{}, fmt.Errorf("begin guest secret authority: %w", ErrCapabilityUnavailable)
	}
	command, err := DecodeGuestSecretCommand(envelope.Payload)
	if err != nil || envelope.OperationKind != GuestSecretCommandOperationKind || command.Secret.Principal != envelope.Principal || command.Secret.SandboxID != envelope.SandboxID || command.Secret.ProcessID != envelope.ProcessID || command.Secret.OperationID != envelope.OperationID || !command.Secret.ExpiresAt.Equal(envelope.ExpiresAt) {
		return GuestSecretCommand{}, fmt.Errorf("begin guest secret authority: %w", ErrCapabilityUnavailable)
	}
	if err := authority.manager.Deliver(ctx, command.Secret, authority.clock.Now().UTC()); err != nil {
		return GuestSecretCommand{}, err
	}
	return command, nil
}

// AbortBeforeStart closes a delivered secret only while the guest has proved
// that command launch never bound it to a recipient process.
func (authority *SecretExecutionAuthority) AbortBeforeStart(ctx context.Context, processID string) error {
	if authority == nil {
		return fmt.Errorf("abort guest secret authority: %w", ErrCapabilityUnavailable)
	}
	return authority.manager.AbortBeforeStart(ctx, processID)
}

// RevokeAfterTreeReap delegates the terminal process-tree proof to the
// ephemeral sink before Manager zeroizes the retained redaction bytes.
func (authority *SecretExecutionAuthority) RevokeAfterTreeReap(ctx context.Context, processID string) error {
	if authority == nil {
		return fmt.Errorf("revoke guest secret authority: %w", ErrCapabilityUnavailable)
	}
	return authority.manager.RevokeAfterTreeReap(ctx, processID)
}

// RedactOutput returns a copied literal-redacted chunk while the command
// lifecycle is active; it never returns the transient redaction values.
func (authority *SecretExecutionAuthority) RedactOutput(processID string, output []byte) []byte {
	redacted := append([]byte(nil), output...)
	if authority == nil {
		return redacted
	}
	for _, value := range authority.manager.RedactionValues(processID) {
		if len(value) > 0 {
			redacted = bytes.ReplaceAll(redacted, value, []byte("[REDACTED]"))
			for index := range value {
				value[index] = 0
			}
		}
	}
	return redacted
}

func validSecretRequestShape(request sandboxauthority.SecretRequest) bool {
	return request.Principal != "" && request.SandboxID != "" && request.ProcessID != "" && request.OperationID != "" && request.Binding != "" && request.Purpose != "" && !request.ExpiresAt.IsZero()
}
