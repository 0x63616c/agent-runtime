package sandboxcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

var (
	// ErrConflict reports a Principal-scoped Operation ID reused with different immutable input.
	ErrConflict = errors.New("sandbox control operation conflict")
	// ErrNotFoundOrDenied keeps guessed operation IDs indistinguishable from absent IDs.
	ErrNotFoundOrDenied = errors.New("sandbox control operation not found or denied")
	// ErrInvalidTransition reports a state change that cannot converge safely.
	ErrInvalidTransition = errors.New("sandbox control operation transition is invalid")
	// ErrStaleFence reports a host result from an expired or superseded assignment.
	ErrStaleFence = errors.New("sandbox control host result has a stale fence")
	// ErrOperationIDExpired reports an Operation ID retained as a tombstone.
	ErrOperationIDExpired = errors.New("sandbox control operation id is expired")
)

const (
	maxLedgerPage       = 1000
	maxPrincipalBytes   = 512
	maxOperationIDBytes = 128
	maxDigestBytes      = 128
	maxHostIDBytes      = 128
)

// State is one durable sandbox operation lifecycle state.
type State string

const (
	// StateAccepted records an immutable request before host routing.
	StateAccepted State = "accepted"
	// StateDispatched records a currently fenced host assignment.
	StateDispatched State = "dispatched"
	// StateStarted records host acknowledgement that work began.
	StateStarted State = "started"
	// StateSucceeded records a terminal successful outcome.
	StateSucceeded State = "succeeded"
	// StateFailed records a terminal failed outcome.
	StateFailed State = "failed"
	// StateCancelled records a terminal caller-authorized cancellation.
	StateCancelled State = "cancelled"
	// StateUncertain records an outcome whose external effect requires reconciliation.
	StateUncertain State = "uncertain"
	// StateCleanupPending records durable cleanup work owned by the reaper.
	StateCleanupPending State = "cleanup-pending"
	// StateCleanupConfirmed records successful cleanup before retention expiry.
	StateCleanupConfirmed State = "cleanup-confirmed"
	// StateExpired records expired retention before a tombstone is emitted.
	StateExpired State = "expired"
	// StateTombstoned records the bounded retained identity after cleanup/expiry.
	StateTombstoned State = "tombstoned"
)

// Assignment binds an operation to one host and monotonic fencing authority.
type Assignment struct {
	HostID         string
	HostGeneration uint64
	AssignmentID   string
	LeaseEpoch     uint64
	FencingToken   uint64
	LeaseExpiresAt time.Time
}

// ResourceProjectionKind is the closed set of resource snapshots that can be
// durably attached to an operation at admission. It is intentionally narrower
// than an operation target: a target identifies routing, while this binding
// authorizes one complete resource read-model snapshot.
type ResourceProjectionKind string

const (
	ResourceProjectionSandbox ResourceProjectionKind = "sandbox"
	ResourceProjectionProcess ResourceProjectionKind = "process"
	// ResourceProjectionVolume binds a named-volume lifecycle operation to the
	// complete principal-scoped volume projection admitted with it.
	ResourceProjectionVolume ResourceProjectionKind = "volume"
	// ResourceProjectionSnapshot reserves the matching typed binding for a
	// future snapshot source/result authority. It is not an execution claim.
	ResourceProjectionSnapshot ResourceProjectionKind = "snapshot"
)

// ResourceProjectionTransition declares how the admitted resource snapshot is
// maintained as its operation advances. The value is persisted with the
// immutable binding, so an adapter cannot silently change the projection model
// after acceptance.
type ResourceProjectionTransition string

const (
	// ResourceProjectionReplaceSnapshot requires each lifecycle transition to
	// atomically replace the complete current resource snapshot.
	ResourceProjectionReplaceSnapshot ResourceProjectionTransition = "replace-complete-snapshot"
)

// ResourceProjectionBinding is the immutable admission-time contract between
// an operation and a resource read-model. AdmittedSnapshotDigest identifies
// the exact initial complete snapshot; it is not recomputed from later state.
//
// This is an internal storage seam only. It does not make resource inspection
// public or infer host observations that have not been durably supplied.
type ResourceProjectionBinding struct {
	Kind                   ResourceProjectionKind
	ResourceID             string
	AdmittedSnapshotDigest string
	Transition             ResourceProjectionTransition
}

// Operation is the bounded durable operation ledger record.
// CanonicalDigest and EffectiveSpecDigest are references only: unbounded input
// and output content belongs in their dedicated stores.
type Operation struct {
	Principal           string
	Tenant              string
	ID                  string
	Kind                string
	TargetKind          string
	TargetID            string
	InputDigest         string
	CanonicalDigest     string
	EffectiveSpecDigest string
	CapabilityDigest    string
	DispatchBody        string
	State               State
	Version             uint64
	AcceptedAt          time.Time
	RetentionExpiresAt  time.Time
	CleanupRequired     bool
	RetainedOutputBytes uint64
	// ResourceProjectionBinding, when present, is immutable admission metadata
	// for a complete resource snapshot. Resource-aware stores enforce it before
	// accepting or replacing any projection.
	ResourceProjectionBinding *ResourceProjectionBinding
	Assignment                Assignment
}

// HostResult is a host acknowledgement guarded by its assigned fence.
type HostResult struct {
	HostID       string
	FencingToken uint64
	State        State
	// ObservedAt is supplied by the control plane's injected clock, never by the host.
	ObservedAt time.Time
}

// OutboxEvent is one bounded fact committed atomically with a ledger change.
type OutboxEvent string

const (
	// OutboxAccepted records durable operation acceptance before dispatch.
	OutboxAccepted OutboxEvent = "accepted"
	// OutboxDispatched records a fresh fenced host assignment.
	OutboxDispatched OutboxEvent = "dispatched"
	// OutboxStateChanged records a non-assignment lifecycle transition.
	OutboxStateChanged OutboxEvent = "state-changed"
	// OutboxLeaseExpired records fencing of an expired host assignment.
	OutboxLeaseExpired OutboxEvent = "lease-expired"
	// OutboxTombstoned records final bounded identity retention.
	OutboxTombstoned OutboxEvent = "tombstoned"
)

// OutboxRecord is an ordered, at-least-once publication input. It contains no
// request, output, secret, or backend content.
type OutboxRecord struct {
	ID               uint64
	Principal        string
	OperationID      string
	OperationVersion uint64
	Event            OutboxEvent
	State            State
}

// DurableStore is the control-plane persistence boundary used by routing,
// reconciliation and reaping. All methods require a principal-bound caller.
type DurableStore interface {
	Accept(context.Context, Operation) (Operation, bool, error)
	Get(context.Context, string, string) (Operation, error)
	Transition(context.Context, string, string, uint64, State) (Operation, error)
	Assign(context.Context, string, string, string, time.Time) (Operation, error)
	RecordHostResult(context.Context, string, string, HostResult) (Operation, error)
	RecoverExpiredAssignments(context.Context, time.Time, int) ([]Operation, error)
	ClaimExpiredCleanup(context.Context, time.Time, int) ([]Operation, error)
	Reap(context.Context, time.Time, int) ([]Operation, error)
	ReadOutbox(context.Context, uint64, int) ([]OutboxRecord, error)
	ReadOperationOutbox(context.Context, string, string, uint64, int) ([]OutboxRecord, error)
}

// ClaimExpiredCleanup fences any outstanding host and records durable cleanup
// ownership for expired resources before a reaper performs destructive work.
func (ledger *MemoryLedger) ClaimExpiredCleanup(ctx context.Context, now time.Time, limit int) ([]Operation, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "claim expired sandbox cleanup")
	}
	if err := validateLedgerPage(now, limit); err != nil {
		return nil, errors.Wrap(err, "claim expired sandbox cleanup")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	keys := sortedOperationKeys(ledger.operations)
	var claimed []Operation
	for _, key := range keys {
		if len(claimed) == limit {
			break
		}
		operation := ledger.operations[key]
		if !operation.CleanupRequired || now.UTC().Before(operation.RetentionExpiresAt) || operation.State == StateCleanupPending || operation.State == StateCleanupConfirmed || operation.State == StateTombstoned {
			continue
		}
		operation.Assignment = Assignment{FencingToken: operation.Assignment.FencingToken + 1}
		operation.State = StateCleanupPending
		operation.Version++
		ledger.operations[key] = operation
		ledger.appendOutbox(operation, OutboxStateChanged)
		claimed = append(claimed, copyOperationRecord(operation))
	}
	return claimed, nil
}

// MemoryLedger is a deterministic DurableStore used by hermetic lifecycle tests.
type MemoryLedger struct {
	mu           sync.Mutex
	operations   map[string]Operation
	outbox       []OutboxRecord
	hosts        map[string]HostEnrollment
	dispatches   map[string]hostAssignmentFields
	hostOutput   map[string]hostOutputFields
	hostReceipts map[string]hostDataPlaneReceiptFields
}

// NewMemoryLedger constructs an empty deterministic operation ledger.
func NewMemoryLedger() *MemoryLedger {
	return &MemoryLedger{operations: make(map[string]Operation), hosts: make(map[string]HostEnrollment), dispatches: make(map[string]hostAssignmentFields), hostOutput: make(map[string]hostOutputFields), hostReceipts: make(map[string]hostDataPlaneReceiptFields)}
}

// Accept records an immutable operation or returns a prior identical record.
func (ledger *MemoryLedger) Accept(ctx context.Context, operation Operation) (Operation, bool, error) {
	if err := ctx.Err(); err != nil {
		return Operation{}, false, errors.Wrap(err, "accept sandbox operation")
	}
	operation = normalizeOperationForPersistence(operation)
	if err := validateOperation(operation); err != nil {
		return Operation{}, false, err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := operationKey(operation.Principal, operation.ID)
	if prior, exists := ledger.operations[key]; exists {
		if prior.State == StateTombstoned {
			return Operation{}, false, ErrOperationIDExpired
		}
		if operationInputDigest(prior) != operationInputDigest(operation) || !sameResourceProjectionBinding(prior.ResourceProjectionBinding, operation.ResourceProjectionBinding) {
			return Operation{}, false, ErrConflict
		}
		return copyOperationRecord(prior), true, nil
	}
	for _, prior := range ledger.operations {
		if prior.ID == operation.ID {
			return Operation{}, false, ErrNotFoundOrDenied
		}
	}
	operation.State = StateAccepted
	operation.Version = 1
	operation.AcceptedAt = operation.AcceptedAt.UTC()
	operation.RetentionExpiresAt = operation.RetentionExpiresAt.UTC()
	ledger.operations[key] = copyOperationRecord(operation)
	ledger.appendOutbox(operation, OutboxAccepted)
	return copyOperationRecord(operation), false, nil
}

// Get returns one authorized durable operation without revealing another principal's record.
func (ledger *MemoryLedger) Get(ctx context.Context, principal, id string) (Operation, error) {
	if err := ctx.Err(); err != nil {
		return Operation{}, errors.Wrap(err, "get sandbox operation")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	operation, exists := ledger.operations[operationKey(principal, id)]
	if !exists {
		return Operation{}, ErrNotFoundOrDenied
	}
	return copyOperationRecord(operation), nil
}

// Transition records one optimistic-concurrency-checked lifecycle transition.
func (ledger *MemoryLedger) Transition(ctx context.Context, principal, id string, version uint64, next State) (Operation, error) {
	if err := ctx.Err(); err != nil {
		return Operation{}, errors.Wrap(err, "transition sandbox operation")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := operationKey(principal, id)
	operation, exists := ledger.operations[key]
	if !exists {
		return Operation{}, ErrNotFoundOrDenied
	}
	if operation.Version != version || !permits(operation.State, next) {
		return Operation{}, ErrInvalidTransition
	}
	operation.State = next
	operation.Version++
	ledger.operations[key] = operation
	ledger.appendOutbox(operation, OutboxStateChanged)
	return copyOperationRecord(operation), nil
}

// Assign records a fresh fenced host assignment and expires any prior lease.
func (ledger *MemoryLedger) Assign(ctx context.Context, principal, id, hostID string, leaseExpiresAt time.Time) (Operation, error) {
	if err := ctx.Err(); err != nil {
		return Operation{}, errors.Wrap(err, "assign sandbox operation")
	}
	if !validBounded(hostID, maxHostIDBytes) || leaseExpiresAt.IsZero() {
		return Operation{}, errors.New("assign sandbox operation: host and lease expiry are required")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := operationKey(principal, id)
	operation, exists := ledger.operations[key]
	if !exists {
		return Operation{}, ErrNotFoundOrDenied
	}
	if operation.State != StateAccepted && operation.State != StateDispatched && operation.State != StateStarted && operation.State != StateUncertain && operation.State != StateCleanupPending {
		return Operation{}, ErrInvalidTransition
	}
	operation.Assignment = Assignment{HostID: hostID, FencingToken: operation.Assignment.FencingToken + 1, LeaseExpiresAt: leaseExpiresAt.UTC()}
	operation.State = StateDispatched
	operation.Version++
	ledger.operations[key] = operation
	ledger.appendOutbox(operation, OutboxDispatched)
	return copyOperationRecord(operation), nil
}

// RecordHostResult accepts only the current host assignment's fenced result.
func (ledger *MemoryLedger) RecordHostResult(ctx context.Context, principal, id string, result HostResult) (Operation, error) {
	if err := ctx.Err(); err != nil {
		return Operation{}, errors.Wrap(err, "record sandbox host result")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := operationKey(principal, id)
	operation, exists := ledger.operations[key]
	if !exists {
		return Operation{}, ErrNotFoundOrDenied
	}
	if result.ObservedAt.IsZero() || !validBounded(result.HostID, maxHostIDBytes) || result.HostID != operation.Assignment.HostID || result.FencingToken != operation.Assignment.FencingToken || !result.ObservedAt.Before(operation.Assignment.LeaseExpiresAt) {
		return Operation{}, ErrStaleFence
	}
	if !permits(operation.State, result.State) {
		return Operation{}, ErrInvalidTransition
	}
	operation.State = result.State
	operation.Version++
	ledger.operations[key] = operation
	ledger.appendOutbox(operation, OutboxStateChanged)
	return copyOperationRecord(operation), nil
}

// RecoverExpiredAssignments fences expired host authority and makes its
// uncertain outcome available for reconciliation.
func (ledger *MemoryLedger) RecoverExpiredAssignments(ctx context.Context, now time.Time, limit int) ([]Operation, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "recover expired sandbox assignments")
	}
	if err := validateLedgerPage(now, limit); err != nil {
		return nil, errors.Wrap(err, "recover expired sandbox assignments")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	keys := sortedOperationKeys(ledger.operations)
	var recovered []Operation
	for _, key := range keys {
		if len(recovered) == limit {
			break
		}
		operation := ledger.operations[key]
		if operation.Assignment.HostID == "" || now.UTC().Before(operation.Assignment.LeaseExpiresAt) || (operation.State != StateDispatched && operation.State != StateStarted) {
			continue
		}
		if operation.Assignment.FencingToken == ^uint64(0) {
			return nil, errors.New("claim expired sandbox cleanup: fencing token exhausted")
		}
		operation.Assignment = Assignment{FencingToken: operation.Assignment.FencingToken + 1}
		operation.State = StateUncertain
		operation.Version++
		ledger.operations[key] = operation
		ledger.appendOutbox(operation, OutboxLeaseExpired)
		recovered = append(recovered, copyOperationRecord(operation))
	}
	return recovered, nil
}

// Reap tombstones only expired operations whose cleanup is either unnecessary
// or durably confirmed. Cleanup-pending records remain addressable.
func (ledger *MemoryLedger) Reap(ctx context.Context, now time.Time, limit int) ([]Operation, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "reap sandbox operations")
	}
	if err := validateLedgerPage(now, limit); err != nil {
		return nil, errors.Wrap(err, "reap sandbox operations")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	keys := sortedOperationKeys(ledger.operations)
	var reaped []Operation
	for _, key := range keys {
		if len(reaped) == limit {
			break
		}
		operation := ledger.operations[key]
		if operation.State == StateTombstoned || now.UTC().Before(operation.RetentionExpiresAt) || (operation.CleanupRequired && operation.State != StateCleanupConfirmed) {
			continue
		}
		if operation.State != StateSucceeded && operation.State != StateFailed && operation.State != StateCancelled && operation.State != StateUncertain && operation.State != StateCleanupConfirmed && operation.State != StateExpired {
			continue
		}
		operation.State = StateTombstoned
		operation.Assignment = Assignment{FencingToken: operation.Assignment.FencingToken}
		operation.Version++
		ledger.operations[key] = operation
		ledger.appendOutbox(operation, OutboxTombstoned)
		reaped = append(reaped, copyOperationRecord(operation))
	}
	return reaped, nil
}

// ReadOutbox returns ordered records strictly after afterID.
func (ledger *MemoryLedger) ReadOutbox(ctx context.Context, afterID uint64, limit int) ([]OutboxRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "read sandbox control outbox")
	}
	if limit <= 0 || limit > maxLedgerPage {
		return nil, errors.New("read sandbox control outbox: limit must be between 1 and 1000")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	records := make([]OutboxRecord, 0, limit)
	for _, record := range ledger.outbox {
		if record.ID <= afterID {
			continue
		}
		records = append(records, record)
		if len(records) == limit {
			break
		}
	}
	return records, nil
}

// ReadOperationOutbox returns one authorized Operation's ordered state facts
// strictly after its durable version cursor.
func (ledger *MemoryLedger) ReadOperationOutbox(ctx context.Context, principal, id string, afterVersion uint64, limit int) ([]OutboxRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "read sandbox operation outbox")
	}
	if !validBounded(principal, maxPrincipalBytes) || !validBounded(id, maxOperationIDBytes) || limit <= 0 || limit > maxLedgerPage {
		return nil, errors.New("read sandbox operation outbox: identity or limit is invalid")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if _, exists := ledger.operations[operationKey(principal, id)]; !exists {
		return nil, ErrNotFoundOrDenied
	}
	records := make([]OutboxRecord, 0, limit)
	for _, record := range ledger.outbox {
		if record.Principal != principal || record.OperationID != id || record.OperationVersion <= afterVersion {
			continue
		}
		records = append(records, record)
		if len(records) == limit {
			break
		}
	}
	return records, nil
}

func (ledger *MemoryLedger) appendOutbox(operation Operation, event OutboxEvent) {
	ledger.outbox = append(ledger.outbox, OutboxRecord{ID: uint64(len(ledger.outbox) + 1), Principal: operation.Principal, OperationID: operation.ID, OperationVersion: operation.Version, Event: event, State: operation.State})
}

func validateOperation(operation Operation) error {
	if !validBounded(operation.Principal, maxPrincipalBytes) || (operation.Tenant != "" && !validBounded(operation.Tenant, 256)) || len(operation.DispatchBody) > 1<<20 || !validBounded(operation.ID, maxOperationIDBytes) || !validBounded(operationInputDigest(operation), maxDigestBytes) || !validBounded(operation.CanonicalDigest, maxDigestBytes) || !validBounded(operation.EffectiveSpecDigest, maxDigestBytes) || operation.AcceptedAt.IsZero() || operation.RetentionExpiresAt.IsZero() || !operation.RetentionExpiresAt.After(operation.AcceptedAt) {
		return errors.New("accept sandbox operation: principal, id, digests and ordered retention are required")
	}
	if err := validateDispatchBody(operation.DispatchBody); err != nil {
		return err
	}
	if operation.ResourceProjectionBinding != nil {
		binding := *operation.ResourceProjectionBinding
		if !validResourceProjectionBinding(binding) || operation.TargetKind != string(binding.Kind) || operation.TargetID != binding.ResourceID {
			return errors.New("accept sandbox operation: resource projection binding is invalid")
		}
	}
	return nil
}

func validResourceProjectionBinding(binding ResourceProjectionBinding) bool {
	if !validBounded(binding.ResourceID, maxOperationIDBytes) || !validProjectionSnapshotDigest(binding.AdmittedSnapshotDigest) || binding.Transition != ResourceProjectionReplaceSnapshot {
		return false
	}
	switch binding.Kind {
	case ResourceProjectionSandbox, ResourceProjectionProcess, ResourceProjectionVolume, ResourceProjectionSnapshot:
		return true
	default:
		return false
	}
}

func validProjectionSnapshotDigest(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+sha256.Size*2 || !strings.HasPrefix(value, prefix) {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func projectionSnapshotDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func sameResourceProjectionBinding(left, right *ResourceProjectionBinding) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func copyOperationRecord(operation Operation) Operation {
	if operation.ResourceProjectionBinding != nil {
		binding := *operation.ResourceProjectionBinding
		operation.ResourceProjectionBinding = &binding
	}
	return operation
}

func operationInputDigest(operation Operation) string {
	if operation.InputDigest != "" {
		return operation.InputDigest
	}
	return operation.CanonicalDigest
}

func normalizeOperationForPersistence(operation Operation) Operation {
	if operation.Tenant == "" {
		operation.Tenant = strings.SplitN(operation.Principal, ":", 2)[0]
	}
	if operation.DispatchBody == "" {
		operation.DispatchBody = "{}"
	}
	return operation
}

func validBounded(value string, maxBytes int) bool {
	return value != "" && len(value) <= maxBytes && !strings.ContainsRune(value, '\x00')
}

func validateLedgerPage(now time.Time, limit int) error {
	if now.IsZero() || limit <= 0 || limit > maxLedgerPage {
		return errors.New("current time and limit between 1 and 1000 are required")
	}
	return nil
}

func sortedOperationKeys(operations map[string]Operation) []string {
	keys := make([]string, 0, len(operations))
	for key := range operations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func permits(current, next State) bool {
	switch current {
	case StateAccepted:
		return next == StateDispatched || next == StateCancelled || next == StateCleanupPending
	case StateDispatched:
		return next == StateStarted || next == StateSucceeded || next == StateFailed || next == StateCancelled || next == StateUncertain || next == StateCleanupPending
	case StateStarted:
		return next == StateSucceeded || next == StateFailed || next == StateCancelled || next == StateUncertain || next == StateCleanupPending
	case StateUncertain:
		return next == StateDispatched || next == StateSucceeded || next == StateFailed || next == StateCleanupPending
	case StateCleanupPending:
		return next == StateCleanupConfirmed || next == StateTombstoned
	case StateCleanupConfirmed, StateSucceeded, StateFailed, StateCancelled, StateExpired:
		return next == StateTombstoned
	default:
		return false
	}
}

func operationKey(principal, id string) string { return principal + "\x00" + id }
