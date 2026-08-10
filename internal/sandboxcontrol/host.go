package sandboxcontrol

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"math"
	"strconv"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

var (
	// ErrHostDenied deliberately merges absent, revoked, expired, quarantined,
	// incompatible and incorrectly authenticated hosts.
	ErrHostDenied = errors.New("sandbox host not found or denied")
	// ErrNoHostAssignment reports an authenticated host with no eligible work.
	ErrNoHostAssignment = errors.New("sandbox host has no assignment")
	// ErrHostProtocolViolation reports an authenticated but impossible message.
	ErrHostProtocolViolation = errors.New("sandbox host protocol violation")
	// ErrHostAttestationFailed reports a durably retained verifier refusal.
	ErrHostAttestationFailed = errors.New("sandbox host attestation failed")
)

// HostStatus is the durable enrollment security state.
type HostStatus string

const (
	HostActive      HostStatus = "active"
	HostRevoked     HostStatus = "revoked"
	HostQuarantined HostStatus = "quarantined"
	// HostAttestationFailed records a verifier refusal retained for operator
	// diagnosis. Failed hosts can never authenticate or receive work.
	HostAttestationFailed HostStatus = "attestation-failed"
)

// HostEnrollment is operator-owned durable host identity metadata. It contains
// public verification material only, never a certificate or private key.
type HostEnrollment struct {
	HostID              string
	Tenant              string
	Pool                string
	Generation          uint64
	ProtocolVersion     string
	CertificateDigest   string
	SigningPublicKey    ed25519.PublicKey
	CapabilityDigest    string
	AttestationDigest   string
	AttestationProfile  AttestationProfile
	AttestationState    AttestationState
	Status              HostStatus
	ExpiresAt           time.Time
	LastAuthenticatedAt time.Time
	QuarantineReason    string
}

// HostIdentity is derived from the mutually authenticated peer certificate.
type HostIdentity struct {
	HostID            string
	Generation        uint64
	CertificateDigest string
}

// DeliverySeed contains bounded unpredictable identities generated before a
// serializable claim/renew transaction. Store methods never invent identity.
type DeliverySeed struct {
	AssignmentID string
	EnvelopeID   string
	DeliveryID   string
	Nonce        string
}

// EnvelopeSigner signs one complete immutable assignment while its ledger row
// is locked. Implementations must be deterministic and perform no I/O.
type EnvelopeSigner func(sandboxhostprotocol.Envelope) ([]byte, error)

// HostDispatch is the persisted exact assignment and signed wire envelope.
type HostDispatch struct {
	Operation      Operation
	Envelope       []byte
	EnvelopeDigest string
	ReceiptDigest  string
	AcknowledgedAt time.Time
}

// HostControlStore is the private enrolled-host authority seam.
type HostControlStore interface {
	ProvisionHost(context.Context, HostEnrollment, AttestationInput, AttestationVerifier) error
	RevokeHost(context.Context, string, uint64, time.Time) error
	AuthenticateHost(context.Context, HostIdentity, time.Time) (HostEnrollment, error)
	PullHostAssignment(context.Context, HostIdentity, time.Time, time.Time, DeliverySeed, EnvelopeSigner) (HostDispatch, error)
	AcknowledgeHostAssignment(context.Context, HostIdentity, string, uint64, string, time.Time) (bool, error)
	RenewHostAssignment(context.Context, HostIdentity, string, uint64, time.Time, time.Time, DeliverySeed, EnvelopeSigner) (HostDispatch, error)
	RecordAuthenticatedHostOutput(context.Context, HostIdentity, sandboxhostprotocol.Output, time.Time) (bool, error)
	RecordAuthenticatedHostResult(context.Context, HostIdentity, sandboxhostprotocol.Result, time.Time) (Operation, error)
	QuarantineHost(context.Context, HostIdentity, string, time.Time) ([]Operation, error)
	ConfirmHostCleanupAndRequeue(context.Context, string, string, uint64, time.Time) (Operation, error)
}

// Assignment is durable host routing and monotonic lease authority.
// FencingToken never decreases or becomes reusable.
//
// AssignmentID and LeaseEpoch bind private host-control envelopes; the public
// sandbox API never exposes them.
type hostAssignmentFields struct {
	AssignmentID   string
	HostGeneration uint64
	LeaseEpoch     uint64
	EnvelopeID     string
	DeliveryID     string
	EnvelopeDigest string
	EnvelopeBody   []byte
	ReceiptDigest  string
	ResultDigest   string
	AcknowledgedAt time.Time
}

type hostOutputFields struct {
	OutputID     string
	AssignmentID string
	Stream       string
	Sequence     uint64
	ChunkDigest  string
	SizeBytes    uint32
	ObservedAt   time.Time
}

// ProvisionHost records an audited enrollment generation or idempotently
// reconnects the byte-equivalent current generation.
func (ledger *MemoryLedger) ProvisionHost(ctx context.Context, enrollment HostEnrollment, input AttestationInput, verifier AttestationVerifier) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "provision sandbox host")
	}
	var err error
	enrollment, err = evaluateHostEnrollment(ctx, enrollment, input, verifier)
	if err != nil {
		return err
	}
	if !validHostEnrollment(enrollment) {
		return errors.New("provision sandbox host: invalid bounded enrollment")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.hosts == nil {
		ledger.hosts = make(map[string]HostEnrollment)
	}
	for _, current := range ledger.hosts {
		if current.HostID == enrollment.HostID && enrollment.Generation < current.Generation {
			return ErrHostDenied
		}
	}
	key := hostEnrollmentKey(enrollment.HostID, enrollment.Generation)
	if current, exists := ledger.hosts[key]; exists {
		if !sameEnrollment(current, enrollment) {
			return ErrConflict
		}
		if enrollment.Status == HostAttestationFailed {
			return ErrHostAttestationFailed
		}
		return nil
	}
	enrollment.SigningPublicKey = append(ed25519.PublicKey(nil), enrollment.SigningPublicKey...)
	enrollment.ExpiresAt = enrollment.ExpiresAt.UTC()
	ledger.hosts[key] = enrollment
	if enrollment.Status == HostAttestationFailed {
		return ErrHostAttestationFailed
	}
	return nil
}

// RevokeHost fences one current generation before future authentication.
func (ledger *MemoryLedger) RevokeHost(ctx context.Context, hostID string, generation uint64, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "revoke sandbox host")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := hostEnrollmentKey(hostID, generation)
	host, exists := ledger.hosts[key]
	if !exists || now.IsZero() {
		return ErrHostDenied
	}
	host.Status = HostRevoked
	ledger.hosts[key] = host
	ledger.fenceHostLocked(hostID, generation, StateUncertain)
	return nil
}

// AuthenticateHost verifies the complete identity derived from mTLS.
func (ledger *MemoryLedger) AuthenticateHost(ctx context.Context, identity HostIdentity, now time.Time) (HostEnrollment, error) {
	if err := ctx.Err(); err != nil {
		return HostEnrollment{}, errors.Wrap(err, "authenticate sandbox host")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return ledger.authenticateHostLocked(identity, now)
}

// PullHostAssignment returns a current non-terminal envelope verbatim for
// lost receipt or result recovery, otherwise assigns the oldest eligible work.
func (ledger *MemoryLedger) PullHostAssignment(ctx context.Context, identity HostIdentity, now, leaseExpiresAt time.Time, seed DeliverySeed, signer EnvelopeSigner) (HostDispatch, error) {
	if err := ctx.Err(); err != nil {
		return HostDispatch{}, errors.Wrap(err, "pull sandbox host assignment")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	host, err := ledger.authenticateHostLocked(identity, now)
	if err != nil {
		return HostDispatch{}, err
	}
	if ledger.dispatches == nil {
		ledger.dispatches = make(map[string]hostAssignmentFields)
	}
	for key, operation := range ledger.operations {
		if operation.Assignment.HostID == host.HostID && operation.Assignment.HostGeneration == host.Generation {
			fields := ledger.dispatches[key]
			if (operation.State == StateDispatched || operation.State == StateStarted) && now.Before(operation.Assignment.LeaseExpiresAt) {
				return dispatchFrom(operation, fields), nil
			}
		}
	}
	if !validDeliverySeed(seed, true) || signer == nil || !leaseExpiresAt.After(now) || leaseExpiresAt.Sub(now) > time.Hour {
		return HostDispatch{}, ErrHostProtocolViolation
	}
	keys := sortedOperationKeys(ledger.operations)
	for _, key := range keys {
		operation := ledger.operations[key]
		if operation.State != StateAccepted || operation.Tenant != host.Tenant || operation.CapabilityDigest != host.CapabilityDigest {
			continue
		}
		if operation.Assignment.FencingToken == math.MaxUint64 {
			return HostDispatch{}, errors.New("pull sandbox host assignment: fence exhausted")
		}
		operation.Assignment = Assignment{HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: seed.AssignmentID, LeaseEpoch: 1, FencingToken: operation.Assignment.FencingToken + 1, LeaseExpiresAt: leaseExpiresAt.UTC()}
		envelope := envelopeFor(operation, host.SigningPublicKey, now, leaseExpiresAt, seed)
		wire, err := signer(envelope)
		if err != nil || len(wire) == 0 || len(wire) > 1<<20 {
			return HostDispatch{}, errors.New("pull sandbox host assignment: sign bounded envelope")
		}
		fields := hostAssignmentFields{AssignmentID: seed.AssignmentID, HostGeneration: host.Generation, LeaseEpoch: 1, EnvelopeID: seed.EnvelopeID, DeliveryID: seed.DeliveryID, EnvelopeDigest: sandboxhostprotocol.Digest(wire), EnvelopeBody: append([]byte(nil), wire...)}
		operation.State = StateDispatched
		operation.Version++
		ledger.operations[key] = operation
		ledger.dispatches[key] = fields
		ledger.appendOutbox(operation, OutboxDispatched)
		return dispatchFrom(operation, fields), nil
	}
	return HostDispatch{}, ErrNoHostAssignment
}

// AcknowledgeHostAssignment persists one receipt digest. An identical retry is
// a safe duplicate; a changed receipt for the same fence is a violation.
func (ledger *MemoryLedger) AcknowledgeHostAssignment(ctx context.Context, identity HostIdentity, assignmentID string, fence uint64, receiptDigest string, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, errors.Wrap(err, "acknowledge sandbox host assignment")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if _, err := ledger.authenticateHostLocked(identity, now); err != nil {
		return false, err
	}
	key, operation, fields, ok := ledger.assignmentLocked(identity, assignmentID, fence)
	if !ok || !validBounded(receiptDigest, maxDigestBytes) || !now.Before(operation.Assignment.LeaseExpiresAt) {
		return false, ErrStaleFence
	}
	if fields.ReceiptDigest != "" {
		if fields.ReceiptDigest != receiptDigest {
			return false, ErrHostProtocolViolation
		}
		return true, nil
	}
	fields.ReceiptDigest, fields.AcknowledgedAt = receiptDigest, now.UTC()
	ledger.dispatches[key] = fields
	return false, nil
}

// RenewHostAssignment advances both lease epoch and fencing token and persists
// a newly signed envelope before returning it.
func (ledger *MemoryLedger) RenewHostAssignment(ctx context.Context, identity HostIdentity, assignmentID string, fence uint64, now, leaseExpiresAt time.Time, seed DeliverySeed, signer EnvelopeSigner) (HostDispatch, error) {
	if err := ctx.Err(); err != nil {
		return HostDispatch{}, errors.Wrap(err, "renew sandbox host assignment")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	host, err := ledger.authenticateHostLocked(identity, now)
	if err != nil {
		return HostDispatch{}, err
	}
	key, operation, _, ok := ledger.assignmentLocked(identity, assignmentID, fence)
	if !ok || (operation.State != StateDispatched && operation.State != StateStarted) || !now.Before(operation.Assignment.LeaseExpiresAt) || !validDeliverySeed(seed, false) || signer == nil || !leaseExpiresAt.After(now) || leaseExpiresAt.Sub(now) > time.Hour || operation.Assignment.FencingToken == math.MaxUint64 || operation.Assignment.LeaseEpoch == math.MaxUint64 {
		return HostDispatch{}, ErrStaleFence
	}
	operation.Assignment.FencingToken++
	operation.Assignment.LeaseEpoch++
	operation.Assignment.LeaseExpiresAt = leaseExpiresAt.UTC()
	seed.AssignmentID = assignmentID
	envelope := envelopeFor(operation, host.SigningPublicKey, now, leaseExpiresAt, seed)
	wire, err := signer(envelope)
	if err != nil || len(wire) == 0 || len(wire) > 1<<20 {
		return HostDispatch{}, errors.New("renew sandbox host assignment: sign bounded envelope")
	}
	fields := hostAssignmentFields{AssignmentID: assignmentID, HostGeneration: identity.Generation, LeaseEpoch: operation.Assignment.LeaseEpoch, EnvelopeID: seed.EnvelopeID, DeliveryID: seed.DeliveryID, EnvelopeDigest: sandboxhostprotocol.Digest(wire), EnvelopeBody: append([]byte(nil), wire...)}
	operation.Version++
	ledger.operations[key] = operation
	ledger.dispatches[key] = fields
	ledger.appendOutbox(operation, OutboxDispatched)
	return dispatchFrom(operation, fields), nil
}

// RecordAuthenticatedHostOutput assigns the next sequence atomically. Exact
// retries are idempotent; altered duplicates and gaps fail closed.
func (ledger *MemoryLedger) RecordAuthenticatedHostOutput(ctx context.Context, identity HostIdentity, output sandboxhostprotocol.Output, receivedAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, errors.Wrap(err, "record authenticated sandbox host output")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if _, err := ledger.authenticateHostLocked(identity, receivedAt); err != nil {
		return false, err
	}
	_, operation, _, ok := ledger.assignmentLocked(identity, output.AssignmentID, output.FencingToken)
	if !ok || !validHostOutputImmutableBinding(identity, operation, output) {
		return false, ErrStaleFence
	}
	fields := outputFields(output)
	key := hostOutputKey(output.AssignmentID, output.Stream, output.Sequence)
	if prior, exists := ledger.hostOutput[key]; exists {
		if prior != fields {
			return false, ErrHostProtocolViolation
		}
		return true, nil
	}
	if !validHostOutputLiveBinding(operation, output, receivedAt) {
		return false, ErrStaleFence
	}
	var last uint64
	for _, prior := range ledger.hostOutput {
		if prior.AssignmentID == output.AssignmentID && prior.Stream == output.Stream && prior.Sequence > last {
			last = prior.Sequence
		}
	}
	if output.Sequence != last+1 {
		return false, ErrHostProtocolViolation
	}
	ledger.hostOutput[key] = fields
	return false, nil
}

// RecordAuthenticatedHostResult accepts only the current enrolled generation,
// assignment, lease epoch, fence, digests, scope and finite observed lease.
func (ledger *MemoryLedger) RecordAuthenticatedHostResult(ctx context.Context, identity HostIdentity, result sandboxhostprotocol.Result, receivedAt time.Time) (Operation, error) {
	if err := ctx.Err(); err != nil {
		return Operation{}, errors.Wrap(err, "record authenticated sandbox host result")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if _, err := ledger.authenticateHostLocked(identity, receivedAt); err != nil {
		return Operation{}, err
	}
	key := operationKey(result.Principal, result.OperationID)
	operation, exists := ledger.operations[key]
	if !exists || !validHostResultImmutableBinding(identity, operation, result) {
		return Operation{}, ErrStaleFence
	}
	fields := ledger.dispatches[key]
	if fields.ReceiptDigest == "" {
		return Operation{}, ErrHostProtocolViolation
	}
	next := State(result.State)
	resultDigest, err := authenticatedResultDigest(result)
	if err != nil {
		return Operation{}, ErrHostProtocolViolation
	}
	if operation.State == next {
		if fields.ResultDigest == resultDigest {
			return operation, nil
		}
		return Operation{}, ErrHostProtocolViolation
	}
	if !validHostResultLiveBinding(operation, result, receivedAt) {
		return Operation{}, ErrStaleFence
	}
	if !permits(operation.State, next) {
		return Operation{}, ErrInvalidTransition
	}
	operation.State = next
	operation.Version++
	ledger.operations[key] = operation
	fields.ResultDigest = resultDigest
	ledger.dispatches[key] = fields
	ledger.appendOutbox(operation, OutboxStateChanged)
	return operation, nil
}

// QuarantineHost atomically denies the host and fences every current operation.
func (ledger *MemoryLedger) QuarantineHost(ctx context.Context, identity HostIdentity, reason string, now time.Time) ([]Operation, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "quarantine sandbox host")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	host, err := ledger.authenticateHostLocked(identity, now)
	if err != nil || !validBounded(reason, 256) {
		return nil, ErrHostDenied
	}
	host.Status, host.QuarantineReason = HostQuarantined, reason
	ledger.hosts[hostEnrollmentKey(host.HostID, host.Generation)] = host
	return ledger.fenceHostLocked(host.HostID, host.Generation, StateUncertain), nil
}

// ConfirmHostCleanupAndRequeue is the explicit reconciliation boundary after
// a fenced host can no longer act. It never guesses cleanup from liveness.
func (ledger *MemoryLedger) ConfirmHostCleanupAndRequeue(ctx context.Context, principal, operationID string, version uint64, observedAt time.Time) (Operation, error) {
	if err := ctx.Err(); err != nil {
		return Operation{}, errors.Wrap(err, "confirm sandbox host cleanup")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := operationKey(principal, operationID)
	operation, exists := ledger.operations[key]
	if !exists {
		return Operation{}, ErrNotFoundOrDenied
	}
	if operation.State != StateUncertain || operation.Version != version || !operation.CleanupRequired || observedAt.IsZero() {
		return Operation{}, ErrInvalidTransition
	}
	if operation.Assignment.HostID != "" {
		if operation.Assignment.FencingToken == math.MaxUint64 {
			return Operation{}, ErrInvalidTransition
		}
		operation.Assignment = Assignment{FencingToken: operation.Assignment.FencingToken + 1}
	}
	operation.State = StateAccepted
	operation.Version++
	ledger.operations[key] = operation
	delete(ledger.dispatches, key)
	ledger.appendOutbox(operation, OutboxStateChanged)
	return operation, nil
}

func (ledger *MemoryLedger) authenticateHostLocked(identity HostIdentity, now time.Time) (HostEnrollment, error) {
	key := hostEnrollmentKey(identity.HostID, identity.Generation)
	host, exists := ledger.hosts[key]
	if !exists || !validHostEnrollment(host) || host.Status != HostActive || host.Generation != identity.Generation || host.CertificateDigest != identity.CertificateDigest || host.ProtocolVersion != sandboxhostprotocol.Version || now.IsZero() || !now.Before(host.ExpiresAt) {
		return HostEnrollment{}, ErrHostDenied
	}
	host.LastAuthenticatedAt = now.UTC()
	ledger.hosts[key] = host
	host.SigningPublicKey = append(ed25519.PublicKey(nil), host.SigningPublicKey...)
	return host, nil
}

func (ledger *MemoryLedger) assignmentLocked(identity HostIdentity, assignmentID string, fence uint64) (string, Operation, hostAssignmentFields, bool) {
	for key, operation := range ledger.operations {
		if operation.Assignment.HostID == identity.HostID && operation.Assignment.HostGeneration == identity.Generation && operation.Assignment.AssignmentID == assignmentID && operation.Assignment.FencingToken == fence {
			return key, operation, ledger.dispatches[key], true
		}
	}
	return "", Operation{}, hostAssignmentFields{}, false
}

func (ledger *MemoryLedger) fenceHostLocked(hostID string, generation uint64, next State) []Operation {
	keys := sortedOperationKeys(ledger.operations)
	var fenced []Operation
	for _, key := range keys {
		operation := ledger.operations[key]
		if operation.Assignment.HostID != hostID || operation.Assignment.HostGeneration != generation || isTerminalState(operation.State) {
			continue
		}
		operation.Assignment = Assignment{FencingToken: operation.Assignment.FencingToken + 1}
		operation.State = next
		operation.Version++
		ledger.operations[key] = operation
		delete(ledger.dispatches, key)
		ledger.appendOutbox(operation, OutboxStateChanged)
		fenced = append(fenced, operation)
	}
	return fenced
}

func envelopeFor(operation Operation, observationKey ed25519.PublicKey, issuedAt, expiresAt time.Time, seed DeliverySeed) sandboxhostprotocol.Envelope {
	sandboxID := ""
	if operation.TargetKind == "sandbox" {
		sandboxID = operation.TargetID
	}
	payload := []byte(operation.DispatchBody)
	return sandboxhostprotocol.Envelope{ProtocolVersion: sandboxhostprotocol.Version, EnvelopeID: seed.EnvelopeID, DeliveryID: seed.DeliveryID, Nonce: seed.Nonce, IssuedAt: issuedAt.UTC(), ExpiresAt: expiresAt.UTC(), HostID: operation.Assignment.HostID, HostGeneration: operation.Assignment.HostGeneration, HostObservationKeyDigest: sandboxhostprotocol.Digest(observationKey), AssignmentID: operation.Assignment.AssignmentID, LeaseEpoch: operation.Assignment.LeaseEpoch, FencingToken: operation.Assignment.FencingToken, Tenant: operation.Tenant, Principal: operation.Principal, SandboxID: sandboxID, OperationID: operation.ID, OperationKind: operation.Kind, EffectiveSpecDigest: operation.EffectiveSpecDigest, CapabilityDigest: operation.CapabilityDigest, CanonicalRequestDigest: operation.CanonicalDigest, SequenceContract: "host-proposed/control-owned-v1", PayloadDigest: sandboxhostprotocol.Digest(payload), Payload: payload}
}

func dispatchFrom(operation Operation, fields hostAssignmentFields) HostDispatch {
	return HostDispatch{Operation: operation, Envelope: append([]byte(nil), fields.EnvelopeBody...), EnvelopeDigest: fields.EnvelopeDigest, ReceiptDigest: fields.ReceiptDigest, AcknowledgedAt: fields.AcknowledgedAt}
}

func validHostEnrollment(host HostEnrollment) bool {
	return validBounded(host.HostID, maxHostIDBytes) && validBounded(host.Tenant, 256) && validBounded(host.Pool, 128) && host.Generation > 0 && host.ProtocolVersion == sandboxhostprotocol.Version && validBounded(host.CertificateDigest, maxDigestBytes) && len(host.SigningPublicKey) == ed25519.PublicKeySize && validBounded(host.CapabilityDigest, maxDigestBytes) && (host.AttestationDigest == "" || validBounded(host.AttestationDigest, maxDigestBytes)) && validHostAttestation(host) && !host.ExpiresAt.IsZero()
}

func sameEnrollment(left, right HostEnrollment) bool {
	return left.HostID == right.HostID && left.Tenant == right.Tenant && left.Pool == right.Pool && left.Generation == right.Generation && left.ProtocolVersion == right.ProtocolVersion && left.CertificateDigest == right.CertificateDigest && string(left.SigningPublicKey) == string(right.SigningPublicKey) && left.CapabilityDigest == right.CapabilityDigest && left.AttestationDigest == right.AttestationDigest && left.AttestationProfile == right.AttestationProfile && left.AttestationState == right.AttestationState && left.Status == right.Status && left.ExpiresAt.Equal(right.ExpiresAt)
}

func validDeliverySeed(seed DeliverySeed, requireAssignment bool) bool {
	if requireAssignment && !validBounded(seed.AssignmentID, 128) {
		return false
	}
	return validBounded(seed.EnvelopeID, 128) && validBounded(seed.DeliveryID, 128) && validBounded(seed.Nonce, 128)
}

func validHostOutputImmutableBinding(identity HostIdentity, operation Operation, output sandboxhostprotocol.Output) bool {
	return output.ProtocolVersion == sandboxhostprotocol.Version && output.HostID == identity.HostID && output.HostGeneration == identity.Generation && output.AssignmentID == operation.Assignment.AssignmentID && output.LeaseEpoch == operation.Assignment.LeaseEpoch && output.FencingToken == operation.Assignment.FencingToken && output.Principal == operation.Principal && output.OperationID == operation.ID && (output.Stream == "stdout" || output.Stream == "stderr") && output.Sequence > 0 && validBounded(output.OutputID, 128) && validBounded(output.ChunkDigest, maxDigestBytes) && output.SizeBytes > 0 && output.SizeBytes <= 256<<10 && !output.ObservedAt.IsZero()
}

func validHostOutputLiveBinding(operation Operation, output sandboxhostprotocol.Output, receivedAt time.Time) bool {
	return (operation.State == StateDispatched || operation.State == StateStarted) && receivedAt.Before(operation.Assignment.LeaseExpiresAt) && !output.ObservedAt.After(receivedAt)
}

func validHostResultImmutableBinding(identity HostIdentity, operation Operation, result sandboxhostprotocol.Result) bool {
	return result.HostID == identity.HostID && result.HostGeneration == identity.Generation && result.AssignmentID == operation.Assignment.AssignmentID && result.LeaseEpoch == operation.Assignment.LeaseEpoch && result.FencingToken == operation.Assignment.FencingToken && result.Principal == operation.Principal && result.OperationID == operation.ID && result.EffectiveSpecDigest == operation.EffectiveSpecDigest && result.CapabilityDigest == operation.CapabilityDigest && !result.ObservedAt.IsZero()
}

func validHostResultLiveBinding(operation Operation, result sandboxhostprotocol.Result, receivedAt time.Time) bool {
	return receivedAt.Before(operation.Assignment.LeaseExpiresAt) && !result.ObservedAt.After(receivedAt)
}

func outputFields(output sandboxhostprotocol.Output) hostOutputFields {
	return hostOutputFields{OutputID: output.OutputID, AssignmentID: output.AssignmentID, Stream: output.Stream, Sequence: output.Sequence, ChunkDigest: output.ChunkDigest, SizeBytes: output.SizeBytes, ObservedAt: output.ObservedAt.UTC()}
}

func authenticatedResultDigest(result sandboxhostprotocol.Result) (string, error) {
	wire, err := json.Marshal(result)
	if err != nil || len(wire) == 0 || len(wire) > 1<<20 {
		return "", errors.New("digest authenticated host result: invalid bounded result")
	}
	return sandboxhostprotocol.Digest(wire), nil
}

func hostOutputKey(assignmentID, stream string, sequence uint64) string {
	return assignmentID + "\x00" + stream + "\x00" + strconv.FormatUint(sequence, 10)
}

func isTerminalState(state State) bool {
	switch state {
	case StateSucceeded, StateFailed, StateCancelled, StateCleanupConfirmed, StateTombstoned:
		return true
	default:
		return false
	}
}

func hostEnrollmentKey(hostID string, generation uint64) string {
	return hostID + "\x00" + strconv.FormatUint(generation, 10)
}

var _ HostControlStore = (*MemoryLedger)(nil)
