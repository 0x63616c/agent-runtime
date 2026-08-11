package sandboxhostprocess

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostjournal"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

var errExecutionLeaseExpired = errors.New("sandbox host execution lease expired")

// HostExecutor is the private host-effect seam. Implementations must honor the
// supplied lease-derived context and must not select control authority.
type HostExecutor interface {
	Execute(context.Context, sandboxhostprotocol.Envelope) error
}

// AuthenticatedHostExecutor optionally receives the exact control-signed wire
// that sandboxhostprocess verified before it reached the durable effect seam.
// The ordinary HostExecutor door remains for deterministic adapters that do
// not have a guest data plane.
type AuthenticatedHostExecutor interface {
	HostExecutor
	ExecuteAuthenticated(context.Context, sandboxhostprotocol.Envelope, []byte) error
}

// ExecutionOutput is one bounded guest chunk before it is signed and durably
// acknowledged through the private host-control output owner.
type ExecutionOutput = sandboxhostprotocol.GuestOutput

// OutputEmitter stages and acknowledges one host-signed output observation.
type OutputEmitter = sandboxhostprotocol.GuestOutputEmitter

// OutputReportingHostExecutor is the optional result/output extension for a
// real guest transport. The ordinary executor seam remains safe for adapters
// without a guest data plane.
type OutputReportingHostExecutor interface {
	HostExecutor
	ExecuteWithOutput(context.Context, sandboxhostprotocol.Envelope, OutputEmitter) error
}

// AuthenticatedOutputReportingHostExecutor combines exact control-wire
// preservation with bounded guest output forwarding.
type AuthenticatedOutputReportingHostExecutor interface {
	AuthenticatedHostExecutor
	OutputReportingHostExecutor
	ExecuteAuthenticatedWithOutput(context.Context, sandboxhostprotocol.Envelope, []byte, OutputEmitter) error
}

type authenticatedEnvelopeExecutor struct {
	HostExecutor
	wire []byte
}

func (executor authenticatedEnvelopeExecutor) Execute(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	if authenticated, ok := executor.HostExecutor.(AuthenticatedHostExecutor); ok {
		return authenticated.ExecuteAuthenticated(ctx, envelope, append([]byte(nil), executor.wire...))
	}
	return executor.HostExecutor.Execute(ctx, envelope)
}

func (executor authenticatedEnvelopeExecutor) ExecuteWithOutput(ctx context.Context, envelope sandboxhostprotocol.Envelope, emit OutputEmitter) error {
	if authenticated, ok := executor.HostExecutor.(AuthenticatedOutputReportingHostExecutor); ok {
		return authenticated.ExecuteAuthenticatedWithOutput(ctx, envelope, append([]byte(nil), executor.wire...), emit)
	}
	if reporting, ok := executor.HostExecutor.(OutputReportingHostExecutor); ok {
		return reporting.ExecuteWithOutput(ctx, envelope, emit)
	}
	return executor.Execute(ctx, envelope)
}

func bindAuthenticatedEnvelope(executor HostExecutor, wire []byte) HostExecutor {
	if _, ok := executor.(AuthenticatedHostExecutor); !ok || len(wire) == 0 {
		return executor
	}
	return authenticatedEnvelopeExecutor{HostExecutor: executor, wire: append([]byte(nil), wire...)}
}

type executorFunc func(context.Context, sandboxhostprotocol.Envelope) error

func (executor executorFunc) Execute(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	return executor(ctx, envelope)
}

type resultSender func(context.Context, []byte) error
type executionDeadline func(context.Context, time.Time) (context.Context, context.CancelFunc)

// recoverIncompleteExecutions converts every durable, effect-ambiguous intent
// into a signed uncertain terminal observation. It never calls an executor.
func recoverIncompleteExecutions(ctx context.Context, now time.Time, journal *sandboxhostjournal.Journal, privateKey ed25519.PrivateKey, send resultSender) error {
	if ctx == nil || journal == nil || len(privateKey) != ed25519.PrivateKeySize || send == nil || now.IsZero() {
		return errors.New("recover sandbox host execution: explicit bounded dependencies are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, pending := range journal.PendingExecutions() {
		started, err := sandboxhostprotocol.VerifyResult(pending.Wire, now, privateKey.Public().(ed25519.PublicKey))
		if err != nil || started.State != "started" {
			return errors.New("recover sandbox host execution: durable started observation is invalid")
		}
		terminal, err := signRecoveredUncertain(started, now, privateKey)
		if err != nil {
			return err
		}
		if err := journal.StageRecoveryResult(pending.ReceiptKey, terminal); err != nil {
			return err
		}
		if err := send(ctx, terminal); err != nil {
			return err
		}
		if err := journal.AcknowledgeResult(pending.ReceiptKey, sandboxhostprotocol.Digest(terminal)); err != nil {
			return err
		}
	}
	return nil
}

// executeEnvelope makes the irreversible-effect boundary durable. An existing
// started intent is never replayed as an effect: it converges to uncertain so
// control's existing fenced cleanup/requeue path remains authoritative.
func executeEnvelope(ctx context.Context, envelope sandboxhostprotocol.Envelope, now time.Time, journal *sandboxhostjournal.Journal, privateKey ed25519.PrivateKey, executor HostExecutor, send resultSender, deadline executionDeadline) error {
	return executeEnvelopeWithOutput(ctx, envelope, now, journal, privateKey, executor, send, nil, deadline)
}

func executeEnvelopeWithOutput(ctx context.Context, envelope sandboxhostprotocol.Envelope, now time.Time, journal *sandboxhostjournal.Journal, privateKey ed25519.PrivateKey, executor HostExecutor, send resultSender, sendOutput resultSender, deadline executionDeadline) error {
	return executeEnvelopeWithOutputAfterTerminalSend(ctx, envelope, now, journal, privateKey, executor, send, sendOutput, deadline, nil)
}

// executeEnvelopeWithAfterTerminalSend retains a narrow test-only lost-ack
// seam. Production passes nil; a hook runs only after the terminal result has
// reached control and before the journal acknowledgement is fsynced.
func executeEnvelopeWithAfterTerminalSend(ctx context.Context, envelope sandboxhostprotocol.Envelope, now time.Time, journal *sandboxhostjournal.Journal, privateKey ed25519.PrivateKey, executor HostExecutor, send resultSender, deadline executionDeadline, afterTerminalSend func() error) error {
	return executeEnvelopeWithOutputAfterTerminalSend(ctx, envelope, now, journal, privateKey, executor, send, nil, deadline, afterTerminalSend)
}

func executeEnvelopeWithOutputAfterTerminalSend(ctx context.Context, envelope sandboxhostprotocol.Envelope, now time.Time, journal *sandboxhostjournal.Journal, privateKey ed25519.PrivateKey, executor HostExecutor, send resultSender, sendOutput resultSender, deadline executionDeadline, afterTerminalSend func() error) error {
	if ctx == nil || journal == nil || len(privateKey) != ed25519.PrivateKeySize || executor == nil || send == nil || deadline == nil || now.IsZero() || !now.Before(envelope.ExpiresAt) {
		return errExecutionLeaseExpired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if journal.ExecutionStarted(envelope) {
		return stageAndSendTerminal(ctx, envelope, now, journal, privateKey, "uncertain", send, afterTerminalSend)
	}
	started, err := signExecutionResult(envelope, "started", now, privateKey)
	if err != nil {
		return err
	}
	if err := journal.StageStarted(envelope, started); err != nil {
		return err
	}
	if err := send(ctx, started); err != nil {
		return err
	}
	entry, found := journal.Entry(envelope)
	if !found {
		return errors.New("acknowledge sandbox host started result: durable receipt is absent")
	}
	if err := journal.AcknowledgeStarted(entry.ReceiptKey, sandboxhostprotocol.Digest(started)); err != nil {
		return err
	}
	executionContext, cancel := deadline(ctx, envelope.ExpiresAt)
	defer cancel()
	if outputExecutor, ok := executor.(OutputReportingHostExecutor); ok && sendOutput != nil {
		err = outputExecutor.ExecuteWithOutput(executionContext, envelope, func(outputCtx context.Context, output ExecutionOutput) error {
			wire, signErr := signExecutionOutput(envelope, output, now, privateKey)
			if signErr != nil {
				return signErr
			}
			if stageErr := journal.StageOutput(envelope, wire); stageErr != nil {
				return stageErr
			}
			if sendErr := sendOutput(outputCtx, wire); sendErr != nil {
				return sendErr
			}
			entry, found := journal.Entry(envelope)
			if !found {
				return errors.New("acknowledge sandbox host output: durable receipt is absent")
			}
			return journal.AcknowledgeOutput(entry.ReceiptKey, sandboxhostprotocol.Digest(wire))
		})
	} else {
		err = executor.Execute(executionContext, envelope)
	}
	state := "succeeded"
	if err != nil || executionContext.Err() != nil || !now.Before(envelope.ExpiresAt) {
		state = "uncertain"
	}
	return stageAndSendTerminal(ctx, envelope, now, journal, privateKey, state, send, afterTerminalSend)
}

func signExecutionOutput(envelope sandboxhostprotocol.Envelope, output ExecutionOutput, observedAt time.Time, privateKey ed25519.PrivateKey) ([]byte, error) {
	if (output.Stream != "stdout" && output.Stream != "stderr") || output.Sequence == ^uint64(0) || len(output.Data) == 0 || len(output.Data) > 256<<10 {
		return nil, errors.New("sign sandbox host output: invalid bounded guest output")
	}
	sequence := output.Sequence + 1
	return sandboxhostprotocol.SignOutput(sandboxhostprotocol.Output{ProtocolVersion: sandboxhostprotocol.Version, OutputID: "output_" + sandboxhostprotocol.Digest([]byte(envelope.DeliveryID + "\x00" + output.Stream + "\x00" + string(output.Data)))[7:39], HostID: envelope.HostID, HostGeneration: envelope.HostGeneration, AssignmentID: envelope.AssignmentID, LeaseEpoch: envelope.LeaseEpoch, FencingToken: envelope.FencingToken, Principal: envelope.Principal, OperationID: envelope.OperationID, Stream: output.Stream, Sequence: sequence, ChunkDigest: sandboxhostprotocol.Digest(output.Data), SizeBytes: uint32(len(output.Data)), ObservedAt: observedAt.UTC()}, privateKey)
}

func stageAndSendTerminal(ctx context.Context, envelope sandboxhostprotocol.Envelope, now time.Time, journal *sandboxhostjournal.Journal, privateKey ed25519.PrivateKey, state string, send resultSender, afterTerminalSend func() error) error {
	terminal, err := signExecutionResult(envelope, state, now, privateKey)
	if err != nil {
		return err
	}
	if err := journal.StageResult(envelope, terminal); err != nil {
		return err
	}
	if err := send(ctx, terminal); err != nil {
		return err
	}
	if afterTerminalSend != nil {
		if err := afterTerminalSend(); err != nil {
			return err
		}
	}
	entry, found := journal.Entry(envelope)
	if !found {
		return errors.New("acknowledge sandbox host terminal result: durable receipt is absent")
	}
	return journal.AcknowledgeResult(entry.ReceiptKey, sandboxhostprotocol.Digest(terminal))
}

func signExecutionResult(envelope sandboxhostprotocol.Envelope, state string, observedAt time.Time, privateKey ed25519.PrivateKey) ([]byte, error) {
	return sandboxhostprotocol.SignResult(sandboxhostprotocol.Result{ProtocolVersion: sandboxhostprotocol.Version, ResultID: executionResultID(state, envelope.DeliveryID), HostID: envelope.HostID, HostGeneration: envelope.HostGeneration, AssignmentID: envelope.AssignmentID, LeaseEpoch: envelope.LeaseEpoch, FencingToken: envelope.FencingToken, Principal: envelope.Principal, OperationID: envelope.OperationID, EffectiveSpecDigest: envelope.EffectiveSpecDigest, CapabilityDigest: envelope.CapabilityDigest, State: state, ObservedAt: observedAt.UTC()}, privateKey)
}

func signRecoveredUncertain(started sandboxhostprotocol.Result, observedAt time.Time, privateKey ed25519.PrivateKey) ([]byte, error) {
	return sandboxhostprotocol.SignResult(sandboxhostprotocol.Result{ProtocolVersion: sandboxhostprotocol.Version, ResultID: executionResultID("uncertain", started.ResultID), HostID: started.HostID, HostGeneration: started.HostGeneration, AssignmentID: started.AssignmentID, LeaseEpoch: started.LeaseEpoch, FencingToken: started.FencingToken, Principal: started.Principal, OperationID: started.OperationID, EffectiveSpecDigest: started.EffectiveSpecDigest, CapabilityDigest: started.CapabilityDigest, State: "uncertain", ObservedAt: observedAt.UTC()}, privateKey)
}

func executionResultID(state, seed string) string {
	return state + "_" + sandboxhostprotocol.Digest([]byte(state + "\x00" + seed))[7:39]
}
