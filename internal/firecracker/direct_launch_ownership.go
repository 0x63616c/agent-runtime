package firecracker

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/cockroachdb/errors"
)

// DirectLaunchOwnership is the exclusive, durable owner of one direct-KVM
// foundation plan. It records verified create authority before a future
// composition may start a Jailer; it neither starts a process nor promotes a
// capability profile.
type DirectLaunchOwnership struct {
	path       string
	lock       *os.File
	plan       Plan
	planDigest sandbox.Digest
	record     *directLaunchRecord
}

type directLaunchRecord struct {
	Version                string `json:"version"`
	SandboxID              string `json:"sandbox_id"`
	CreateOperationID      string `json:"create_operation_id"`
	HostID                 string `json:"host_id"`
	HostGeneration         uint64 `json:"host_generation"`
	Tenant                 string `json:"tenant"`
	Principal              string `json:"principal"`
	EffectiveSpecDigest    string `json:"effective_spec_digest"`
	CapabilityDigest       string `json:"capability_digest"`
	CanonicalRequestDigest string `json:"canonical_request_digest"`
	PayloadDigest          string `json:"payload_digest"`
	FoundationPlanDigest   string `json:"foundation_plan_digest"`
}

const directLaunchOwnershipVersion = "firecracker.direct-launch-ownership/v1"

// OpenDirectLaunchOwnership opens one absolute, exclusively locked direct-KVM
// ownership journal and refuses a record that is not exact for plan.
func OpenDirectLaunchOwnership(path string, plan Plan) (*DirectLaunchOwnership, error) {
	if !filepath.IsAbs(path) || !validCompiledPlan(plan) {
		return nil, errors.New("open direct Firecracker launch ownership: absolute path and compiled plan are required")
	}
	planDigest, err := trustedPlanDigest(plan)
	if err != nil {
		return nil, errors.Wrap(err, "open direct Firecracker launch ownership")
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("open direct Firecracker launch ownership: journal is already locked")
	}
	owner := &DirectLaunchOwnership{path: path, lock: lock, plan: cloneLinuxJailerPlan(plan), planDigest: planDigest}
	wire, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return owner, nil
	}
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	var record directLaunchRecord
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF || !owner.validRecord(record) {
		_ = owner.Close()
		return nil, errors.New("open direct Firecracker launch ownership: invalid canonical record")
	}
	canonical, _ := json.Marshal(record)
	if !bytes.Equal(wire, canonical) {
		_ = owner.Close()
		return nil, errors.New("open direct Firecracker launch ownership: non-canonical record")
	}
	owner.record = &record
	return owner, nil
}

// ClaimCreate durably binds the only valid create request to this exact
// foundation plan. It has no host side effect and leaves the plan unavailable.
func (owner *DirectLaunchOwnership) ClaimCreate(envelope sandboxhostprotocol.Envelope, wire []byte) error {
	if owner == nil || owner.lock == nil || sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(wire, envelope) != nil {
		return directLaunchOwnershipRefusal()
	}
	request, err := sandbox.DecodeControlOperationRequest(envelope.Payload)
	if err != nil || envelope.OperationKind != string(sandbox.OperationCreateSandbox) || request.Kind != sandbox.OperationCreateSandbox || string(request.ID) != envelope.OperationID || envelope.SandboxID != "" || envelope.ProcessID != "" {
		return directLaunchOwnershipRefusal()
	}
	record := directLaunchRecord{Version: directLaunchOwnershipVersion, SandboxID: string(sandbox.SandboxIDForCreateOperation(request.ID)), CreateOperationID: envelope.OperationID, HostID: envelope.HostID, HostGeneration: envelope.HostGeneration, Tenant: envelope.Tenant, Principal: envelope.Principal, EffectiveSpecDigest: envelope.EffectiveSpecDigest, CapabilityDigest: envelope.CapabilityDigest, CanonicalRequestDigest: envelope.CanonicalRequestDigest, PayloadDigest: envelope.PayloadDigest, FoundationPlanDigest: string(owner.planDigest)}
	if !owner.validRecord(record) {
		return directLaunchOwnershipRefusal()
	}
	if owner.record != nil {
		if *owner.record == record {
			return nil
		}
		return directLaunchOwnershipRefusal()
	}
	if err := owner.persist(record); err != nil {
		return errors.Wrap(err, "claim direct Firecracker launch ownership")
	}
	owner.record = &record
	return nil
}

// BindExec accepts an exec request only when its exact sandbox, host owner,
// principal, and immutable authority facts match the recovered create record.
func (owner *DirectLaunchOwnership) BindExec(envelope sandboxhostprotocol.Envelope, wire []byte) error {
	if owner == nil || owner.lock == nil || owner.record == nil || sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(wire, envelope) != nil {
		return directLaunchOwnershipRefusal()
	}
	request, err := sandbox.DecodeControlOperationRequest(envelope.Payload)
	if err != nil || envelope.OperationKind != string(sandbox.OperationExecProcess) || request.Kind != sandbox.OperationExecProcess || string(request.ID) != envelope.OperationID || request.ExecProcess == nil || string(request.ExecProcess.SandboxID) != envelope.SandboxID {
		return directLaunchOwnershipRefusal()
	}
	if !owner.matchesExecOwnership(envelope) {
		return directLaunchOwnershipRefusal()
	}
	return nil
}

// matchesExecOwnership is the post-authentication immutable ownership check.
// Envelope transport validation remains a separate protocol invariant; this
// comparison ensures a future authenticated transport cannot omit tenancy
// from direct-KVM launch ownership.
func (owner *DirectLaunchOwnership) matchesExecOwnership(envelope sandboxhostprotocol.Envelope) bool {
	if owner == nil || owner.record == nil {
		return false
	}
	record := owner.record
	return envelope.SandboxID == record.SandboxID && envelope.HostID == record.HostID && envelope.HostGeneration == record.HostGeneration && envelope.Tenant == record.Tenant && envelope.Principal == record.Principal && envelope.EffectiveSpecDigest == record.EffectiveSpecDigest && envelope.CapabilityDigest == record.CapabilityDigest
}

func (owner *DirectLaunchOwnership) validRecord(record directLaunchRecord) bool {
	return record.Version == directLaunchOwnershipVersion && record.SandboxID != "" && record.CreateOperationID != "" && record.HostID != "" && record.HostGeneration != 0 && record.Tenant != "" && strings.HasPrefix(record.Principal, record.Tenant+":") && record.EffectiveSpecDigest != "" && record.CapabilityDigest != "" && record.CanonicalRequestDigest != "" && record.PayloadDigest != "" && record.FoundationPlanDigest == string(owner.planDigest)
}

func (owner *DirectLaunchOwnership) persist(record directLaunchRecord) error {
	wire, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(owner.path+".tmp", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(wire); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(owner.path+".tmp", owner.path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(owner.path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	if closeErr := directory.Close(); err == nil {
		err = closeErr
	}
	return err
}

// Close releases the one host-instance journal lock without deleting intent.
func (owner *DirectLaunchOwnership) Close() error {
	if owner == nil || owner.lock == nil {
		return nil
	}
	lock := owner.lock
	owner.lock = nil
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return lock.Close()
}

func directLaunchOwnershipRefusal() error {
	return errors.Wrap(ErrCapabilityUnavailable, "direct Firecracker launch ownership refused")
}
