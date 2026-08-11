// Package firecrackerbootprobecomposition owns the private M4 command handoff.
package firecrackerbootprobecomposition

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobeprotocol"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
)

// Stage compiles one just-staged M4 identity and is the only component allowed
// to consume a verified command. It deliberately has no setter for an identity:
// implementations must derive it from their reviewed staged resources.
type Stage interface {
	Compile(context.Context) (firecracker.TrustedM4Identity, error)
	Consume(context.Context, firecrackerbootprobeprotocol.VerifiedCommand) error
	Cleanup(context.Context) (firecracker.CleanupProof, error)
}

// Journal durably records an exact verified command before a stage consumes it.
type Journal interface {
	Record(context.Context, firecrackerbootprobev2.Snapshot, firecrackerbootprobeprotocol.VerifiedCommand) error
}

// Submitter accepts a stage-ready request and returns only a locally verified M3 command.
type Submitter interface {
	Submit(context.Context, firecrackerbootprobev2.Snapshot, firecracker.TrustedM4Identity, string, ed25519.PrivateKey) (firecrackerbootprobeprotocol.VerifiedCommand, error)
}

// SubmitterFunc adapts a function to Submitter.
type SubmitterFunc func(context.Context, firecrackerbootprobev2.Snapshot, firecracker.TrustedM4Identity, string, ed25519.PrivateKey) (firecrackerbootprobeprotocol.VerifiedCommand, error)

// Submit calls the adapted function.
func (submit SubmitterFunc) Submit(ctx context.Context, snapshot firecrackerbootprobev2.Snapshot, identity firecracker.TrustedM4Identity, nonce string, key ed25519.PrivateKey) (firecrackerbootprobeprotocol.VerifiedCommand, error) {
	return submit(ctx, snapshot, identity, nonce, key)
}

// Config supplies the dependency-injected protected M4 handoff. It has no
// identity field: identity creation is intentionally confined to Stage.Compile.
type Config struct {
	Stage                 Stage
	Journal               Journal
	Snapshot              firecrackerbootprobev2.Snapshot
	GuestNonce            func(context.Context) (string, error)
	ObservationPrivateKey func(context.Context) (ed25519.PrivateKey, error)
	Submitter             Submitter
	RetryAttempts         uint8
}

// Result reports only the opaque verified command and proved cleanup outcome.
type Result struct {
	Command firecrackerbootprobeprotocol.VerifiedCommand
	Cleanup firecracker.CleanupProof
}

// Run stages and submits exactly one M4 identity, retries only the idempotent
// stage-ready submission, journals the returned verified command before
// consumption, and always requires cleanup proof after a staged attempt.
func Run(ctx context.Context, config Config) (result Result, err error) {
	if ctx == nil || config.Stage == nil || config.Journal == nil || config.GuestNonce == nil || config.ObservationPrivateKey == nil || config.Submitter == nil {
		return Result{}, fmt.Errorf("run M4 boot-probe composition: complete context, stage, journal, nonce, observation key, and submitter are required")
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 1
	}
	if config.Snapshot.Version == 0 || config.Snapshot.Session.Validate() != nil || config.Snapshot.Session.Lifecycle.Phase != firecrackerbootprobev2.LifecyclePrepared {
		return Result{}, fmt.Errorf("run M4 boot-probe composition: exact persisted prepared snapshot is required")
	}
	identity, err := config.Stage.Compile(ctx)
	if err != nil {
		return cleanup(config.Stage, result, fmt.Errorf("compile exact M4 stage: %w", err))
	}
	defer func() { result, err = cleanup(config.Stage, result, err) }()
	nonce, err := config.GuestNonce(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("mint bounded guest nonce: %w", err)
	}
	key, err := config.ObservationPrivateKey(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("load enrolled M4 observation key: %w", err)
	}
	for attempt := uint8(0); attempt < config.RetryAttempts; attempt++ {
		result.Command, err = config.Submitter.Submit(ctx, config.Snapshot, identity, nonce, key)
		if err == nil {
			break
		}
	}
	if err != nil {
		return Result{}, fmt.Errorf("submit exact M4 stage-ready: %w", err)
	}
	if err := config.Journal.Record(ctx, config.Snapshot, result.Command); err != nil {
		return Result{}, fmt.Errorf("journal verified M3 command before M4 consumption: %w", err)
	}
	if err := config.Stage.Consume(ctx, result.Command); err != nil {
		return Result{}, fmt.Errorf("consume verified M3 command: %w", err)
	}
	return result, nil
}

func cleanup(stage Stage, result Result, original error) (Result, error) {
	proof, cleanupErr := stage.Cleanup(context.Background())
	result.Cleanup = proof
	if cleanupErr != nil || !proof.Proved {
		return result, fmt.Errorf("%w; M4 staged cleanup is unproved: %v", original, cleanupErr)
	}
	return result, original
}
