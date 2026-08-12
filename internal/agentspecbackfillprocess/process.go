// Package agentspecbackfillprocess composes the AgentSpecBackfill controller from explicit, narrow ports.
package agentspecbackfillprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillcr"
	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/cockroachdb/errors"
)

const (
	maximumConfigBytes = 4096
	maximumWatchRetry  = time.Minute
)

// Config is the explicit, versioned declaration for one AgentSpecBackfill controller process.
type Config struct {
	ControllerImageDigest string
	WatchRetry            time.Duration
}

type configDocument struct {
	Version               int    `json:"version"`
	ControllerImageDigest string `json:"controller_image_digest"`
	WatchRetryMillis      uint32 `json:"watch_retry_millis"`
}

// ParseConfig decodes exactly one strict controller process configuration without ambient Kubernetes settings.
func ParseConfig(input io.Reader) (Config, error) {
	if input == nil {
		return Config{}, errors.New("parse agent spec backfill controller configuration: input is required")
	}
	encoded, err := io.ReadAll(io.LimitReader(input, maximumConfigBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumConfigBytes {
		return Config{}, errors.New("parse agent spec backfill controller configuration: bounded input is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var decoded configDocument
	if err := decoder.Decode(&decoded); err != nil {
		return Config{}, errors.Wrap(err, "parse agent spec backfill controller configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, errors.New("parse agent spec backfill controller configuration: exactly one document is required")
	}
	config := Config{ControllerImageDigest: decoded.ControllerImageDigest, WatchRetry: time.Duration(decoded.WatchRetryMillis) * time.Millisecond}
	if decoded.Version != 1 || config.validate() != nil {
		return Config{}, errors.New("validate agent spec backfill controller configuration: version, immutable image digest, and bounded watch retry are required")
	}
	return config, nil
}

func (config Config) validate() error {
	if !validDigest(config.ControllerImageDigest) || config.WatchRetry <= 0 || config.WatchRetry > maximumWatchRetry {
		return errors.New("agent spec backfill controller configuration is invalid")
	}
	return nil
}

// Source lists canonical immutable request wires and opens a cancellable change watch.
type Source interface {
	List(context.Context) ([][]byte, error)
	Watch(context.Context) (Watch, error)
}

// Watch reads canonical immutable request wires until it is closed or fails.
type Watch interface {
	Next(context.Context) ([]byte, error)
	Close() error
}

// StatusStore atomically reads and conditionally writes a single canonical terminal CR status.
type StatusStore interface {
	ReadTerminal(context.Context, agentspecbackfillcr.Request) (agentspecbackfillcr.Status, bool, error)
	CreateTerminal(context.Context, agentspecbackfillcr.Request, agentspecbackfillcr.Status) (stored agentspecbackfillcr.Status, created bool, err error)
}

// Wait waits for bounded watch recovery without an implicit wall-clock dependency.
type Wait func(context.Context, time.Duration) error

// Controller runs canonical AgentSpecBackfill reconciliation through injected infrastructure ports.
type Controller struct {
	config   Config
	source   Source
	statuses StatusStore
	reader   agentspecbackfill.FrozenLegacyReader
	verifier agentspecbackfill.ImmutableContentVerifier
	clock    clock.Clock
	wait     Wait
}

// New constructs a Controller from every required explicit process dependency.
func New(config Config, source Source, statuses StatusStore, reader agentspecbackfill.FrozenLegacyReader, verifier agentspecbackfill.ImmutableContentVerifier, sourceClock clock.Clock, wait Wait) (*Controller, error) {
	if err := config.validate(); err != nil || source == nil || statuses == nil || reader == nil || verifier == nil || sourceClock == nil || wait == nil {
		return nil, errors.New("create agent spec backfill controller: explicit valid configuration and ports are required")
	}
	return &Controller{config: config, source: source, statuses: statuses, reader: reader, verifier: verifier, clock: sourceClock, wait: wait}, nil
}

// Run reconciles listed requests, then recovers a cancellable watch until the caller cancels it.
func (controller *Controller) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		items, err := controller.source.List(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.Wrap(err, "list agent spec backfill requests")
		}
		if err := ctx.Err(); err != nil {
			return nil
		}
		for _, item := range items {
			if _, err := controller.ReconcileWire(ctx, item); err != nil {
				return errors.Wrap(err, "reconcile listed agent spec backfill request")
			}
		}
		watch, err := controller.source.Watch(ctx)
		if err != nil {
			if err := controller.recoverWatch(ctx); err != nil {
				return err
			}
			continue
		}
		_ = controller.consumeWatch(ctx, watch)
		_ = watch.Close()
		if ctx.Err() != nil {
			return nil
		}
		if err := controller.recoverWatch(ctx); err != nil {
			return err
		}
	}
}

func (controller *Controller) consumeWatch(ctx context.Context, watch Watch) error {
	for {
		item, err := watch.Next(ctx)
		if err != nil {
			return errors.Wrap(err, "read agent spec backfill watch")
		}
		if _, err := controller.ReconcileWire(ctx, item); err != nil {
			return errors.Wrap(err, "reconcile watched agent spec backfill request")
		}
	}
}

func (controller *Controller) recoverWatch(ctx context.Context) error {
	if err := controller.wait(ctx, controller.config.WatchRetry); err != nil && ctx.Err() == nil {
		return errors.Wrap(err, "wait to recover agent spec backfill watch")
	}
	return nil
}

// ReconcileWire parses and reconciles exactly one canonical immutable CR wire.
func (controller *Controller) ReconcileWire(ctx context.Context, wire []byte) (agentspecbackfill.Status, error) {
	request, err := agentspecbackfillcr.ParseRequest(bytes.NewReader(wire))
	if err != nil {
		return agentspecbackfill.Status{}, errors.Wrap(err, "parse immutable agent spec backfill request")
	}
	if request.Spec.ControllerImageDigest != controller.config.ControllerImageDigest {
		return agentspecbackfill.Status{}, errors.New("reconcile agent spec backfill request: controller image digest is not configured")
	}
	if request.Metadata.UID == "" || request.Metadata.Generation == 0 {
		return agentspecbackfill.Status{}, errors.New("reconcile agent spec backfill request: observed immutable metadata is required")
	}
	now := controller.clock.Now().UTC()
	statuses := crTerminalStatuses{store: controller.statuses, request: request, now: now}
	reconciler, err := agentspecbackfill.NewReconciler(&statuses)
	if err != nil {
		return agentspecbackfill.Status{}, errors.Wrap(err, "construct agent spec backfill reconciler")
	}
	status, err := reconciler.Reconcile(ctx, request.Spec, controller.reader, controller.verifier, now)
	if err != nil {
		return agentspecbackfill.Status{}, errors.Wrap(err, "reconcile immutable agent spec backfill request")
	}
	return status, nil
}

type crTerminalStatuses struct {
	store   StatusStore
	request agentspecbackfillcr.Request
	now     time.Time
}

func (statuses *crTerminalStatuses) ReadTerminal(ctx context.Context, _ agentspecbackfill.Request) (agentspecbackfill.Status, bool, error) {
	stored, found, err := statuses.store.ReadTerminal(ctx, statuses.request)
	if err != nil || !found {
		return agentspecbackfill.Status{}, found, err
	}
	if err := stored.ValidateFor(statuses.request, statuses.now); err != nil || !isTerminal(stored.Phase) {
		return agentspecbackfill.Status{}, false, errors.New("read terminal AgentSpecBackfill status: stored status is invalid")
	}
	return coreStatus(stored), true, nil
}

func (statuses *crTerminalStatuses) CreateTerminal(ctx context.Context, _ agentspecbackfill.Request, candidate agentspecbackfill.Status) (agentspecbackfill.Status, bool, error) {
	stored, created, err := statuses.store.CreateTerminal(ctx, statuses.request, crStatus(statuses.request, candidate))
	if err != nil {
		return agentspecbackfill.Status{}, false, err
	}
	if err := stored.ValidateFor(statuses.request, statuses.now); err != nil || !isTerminal(stored.Phase) {
		return agentspecbackfill.Status{}, false, errors.New("record terminal AgentSpecBackfill status: stored status is invalid")
	}
	return coreStatus(stored), created, nil
}

func crStatus(request agentspecbackfillcr.Request, status agentspecbackfill.Status) agentspecbackfillcr.Status {
	return agentspecbackfillcr.Status{Phase: status.Phase, RequestUID: request.Metadata.UID, ObservedGeneration: request.Metadata.Generation, ControllerImageDigest: request.Spec.ControllerImageDigest, RequestDigest: status.RequestDigest, SnapshotFingerprint: status.SnapshotFingerprint, SnapshotCount: status.SnapshotCount, ManifestDigest: request.Spec.ManifestDigest, StaticReadinessDigest: request.Spec.StaticReadinessDigest, VerifiedCount: verifiedCount(request, status), Reason: status.Reason, CompletedAt: status.CompletedAt}
}

func coreStatus(status agentspecbackfillcr.Status) agentspecbackfill.Status {
	return agentspecbackfill.Status{Phase: status.Phase, RequestDigest: status.RequestDigest, SnapshotFingerprint: status.SnapshotFingerprint, SnapshotCount: status.SnapshotCount, Reason: status.Reason, CompletedAt: status.CompletedAt}
}

func verifiedCount(request agentspecbackfillcr.Request, status agentspecbackfill.Status) uint64 {
	if status.Phase == agentspecbackfill.PhaseVerified {
		return request.Spec.SnapshotCount
	}
	return 0
}

func isTerminal(phase agentspecbackfill.Phase) bool {
	return phase == agentspecbackfill.PhaseVerified || phase == agentspecbackfill.PhaseRefused
}

func validDigest(digest string) bool {
	if len(digest) != len("sha256:")+64 || !bytes.HasPrefix([]byte(digest), []byte("sha256:")) {
		return false
	}
	for _, value := range digest[len("sha256:"):] {
		if value < '0' || value > '9' && value < 'a' || value > 'f' {
			return false
		}
	}
	return true
}
