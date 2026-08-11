// Package sandboxauthority implements internal command-secret and egress
// authority contracts. It does not activate any sandbox capability profile.
package sandboxauthority

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrDenied means a sensitive command authority was not admitted.
	ErrDenied = errors.New("sandbox authority denied")
	// ErrExpired means a finite command authority has expired.
	ErrExpired = errors.New("sandbox authority expired")
	// ErrLifecycle means a secret delivery could not make a safe lifecycle transition.
	ErrLifecycle = errors.New("sandbox authority lifecycle conflict")
)

// SecretRequest binds a secret lookup to one accepted command execution.
type SecretRequest struct {
	Principal   string
	SandboxID   string
	ProcessID   string
	OperationID string
	Binding     string
	Purpose     string
	ExpiresAt   time.Time
}

// SecretValue is transient resolver output. Bytes are never persisted or returned by Manager.
type SecretValue struct {
	Version   string
	ExpiresAt time.Time
	Bytes     []byte
}

// SecretResolver resolves one declared binding from an external secret authority.
type SecretResolver interface {
	Resolve(context.Context, SecretRequest) (SecretValue, error)
}

// SecretSink owns a proven ephemeral process-delivery mechanism. The caller
// must not substitute environment, argv, persistent files, or a host mount.
type SecretSink interface {
	Deliver(context.Context, SecretRequest, []byte) error
	RevokeAfterTreeReap(context.Context, SecretRequest) error
}

// SecretAudit receives safe authority facts only; values and binding names are excluded.
type SecretAudit interface {
	RecordSecretDelivery(context.Context, SecretAuditFact) error
}

// SecretAuditFact is safe durable evidence for secret delivery lifecycle.
type SecretAuditFact struct {
	Principal, SandboxID, ProcessID, OperationID string
	Version                                      string
	ExpiresAt                                    time.Time
	Event                                        string
}

// Manager serializes one command's secret lifecycle and zeroizes its retained
// redaction bytes only after a sink confirms complete process-tree reaping.
type Manager struct {
	mu       sync.Mutex
	resolver SecretResolver
	sink     SecretSink
	audit    SecretAudit
	active   map[string]activeSecret
	pending  map[string]struct{}
}

type activeSecret struct {
	request SecretRequest
	version string
	bytes   []byte
}

// NewManager constructs a lifecycle owner around explicit external boundaries.
func NewManager(resolver SecretResolver, sink SecretSink, audit SecretAudit) (*Manager, error) {
	if resolver == nil || sink == nil || audit == nil {
		return nil, fmt.Errorf("create command secret authority: resolver, sink, and audit are required")
	}
	return &Manager{resolver: resolver, sink: sink, audit: audit, active: map[string]activeSecret{}, pending: map[string]struct{}{}}, nil
}

// Deliver resolves and injects one short-lived secret just before command start.
func (manager *Manager) Deliver(ctx context.Context, request SecretRequest, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if manager == nil || !validSecretRequest(request, now) {
		return fmt.Errorf("deliver command secret: %w", ErrDenied)
	}
	manager.mu.Lock()
	if _, exists := manager.active[request.ProcessID]; exists {
		manager.mu.Unlock()
		return fmt.Errorf("deliver command secret: %w", ErrLifecycle)
	}
	if _, exists := manager.pending[request.ProcessID]; exists {
		manager.mu.Unlock()
		return fmt.Errorf("deliver command secret: %w", ErrLifecycle)
	}
	manager.pending[request.ProcessID] = struct{}{}
	manager.mu.Unlock()
	accepted := false
	defer func() {
		if accepted {
			return
		}
		manager.mu.Lock()
		delete(manager.pending, request.ProcessID)
		manager.mu.Unlock()
	}()
	value, err := manager.resolver.Resolve(ctx, request)
	if err != nil {
		return fmt.Errorf("deliver command secret: resolver unavailable")
	}
	if !validSecretValue(value, request, now) {
		zero(value.Bytes)
		return fmt.Errorf("deliver command secret: %w", ErrDenied)
	}
	bytes := append([]byte(nil), value.Bytes...)
	zero(value.Bytes)
	if err := manager.sink.Deliver(ctx, request, bytes); err != nil {
		zero(bytes)
		return fmt.Errorf("deliver command secret: ephemeral sink unavailable")
	}
	manager.mu.Lock()
	if _, exists := manager.active[request.ProcessID]; exists {
		manager.mu.Unlock()
		zero(bytes)
		return fmt.Errorf("deliver command secret: %w", ErrLifecycle)
	}
	manager.active[request.ProcessID] = activeSecret{request: request, version: value.Version, bytes: bytes}
	delete(manager.pending, request.ProcessID)
	manager.mu.Unlock()
	accepted = true
	if err := manager.audit.RecordSecretDelivery(ctx, SecretAuditFact{Principal: request.Principal, SandboxID: request.SandboxID, ProcessID: request.ProcessID, OperationID: request.OperationID, Version: value.Version, ExpiresAt: value.ExpiresAt.UTC(), Event: "delivered"}); err != nil {
		return fmt.Errorf("deliver command secret: audit unavailable")
	}
	return nil
}

// RedactionValues returns copied literal values for the command's output boundary.
func (manager *Manager) RedactionValues(processID string) [][]byte {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	active, ok := manager.active[processID]
	if !ok {
		return nil
	}
	return [][]byte{append([]byte(nil), active.bytes...)}
}

// RevokeAfterTreeReap revokes the sink first, then overwrites the only retained copy.
func (manager *Manager) RevokeAfterTreeReap(ctx context.Context, processID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if manager == nil {
		return fmt.Errorf("revoke command secret: %w", ErrLifecycle)
	}
	manager.mu.Lock()
	active, ok := manager.active[processID]
	manager.mu.Unlock()
	if !ok {
		return fmt.Errorf("revoke command secret: %w", ErrLifecycle)
	}
	if err := manager.sink.RevokeAfterTreeReap(ctx, active.request); err != nil {
		return fmt.Errorf("revoke command secret: sink has not confirmed tree reap")
	}
	manager.mu.Lock()
	current, ok := manager.active[processID]
	if !ok || current.request != active.request {
		manager.mu.Unlock()
		return fmt.Errorf("revoke command secret: %w", ErrLifecycle)
	}
	zero(current.bytes)
	delete(manager.active, processID)
	manager.mu.Unlock()
	if err := manager.audit.RecordSecretDelivery(ctx, SecretAuditFact{Principal: active.request.Principal, SandboxID: active.request.SandboxID, ProcessID: active.request.ProcessID, OperationID: active.request.OperationID, Version: active.version, ExpiresAt: active.request.ExpiresAt.UTC(), Event: "revoked-after-tree-reap"}); err != nil {
		return fmt.Errorf("revoke command secret: audit unavailable")
	}
	return nil
}

func validSecretRequest(request SecretRequest, now time.Time) bool {
	return request.Principal != "" && request.SandboxID != "" && request.ProcessID != "" && request.OperationID != "" && request.Binding != "" && request.Purpose != "" && request.ExpiresAt.After(now) && request.ExpiresAt.Sub(now) <= time.Hour
}
func validSecretValue(value SecretValue, request SecretRequest, now time.Time) bool {
	return value.Version != "" && len(value.Bytes) > 0 && len(value.Bytes) <= 64*1024 && value.ExpiresAt.After(now) && !value.ExpiresAt.After(request.ExpiresAt)
}
func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
	_ = subtle.ConstantTimeCompare(value, make([]byte, len(value)))
}
