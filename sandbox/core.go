package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"path"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	defaultEffectiveSpecDigest Digest = "sha256:effective-defaults-v1"
	canonicalizerVersion       string = "sandbox.control/v1"
)

type coreClient struct {
	principal string
	now       time.Time
	closed    bool
	streams   map[*sliceOperationStream]struct{}
	limits    limitPolicy
	ledger    *coreLedger
}

// coreLedger is deliberately an in-memory control fixture. It proves the S9
// control semantics without claiming process, storage, or host persistence.
// A production ledger belongs behind the same control seam.
type coreLedger struct {
	mu         sync.RWMutex
	principals map[string]*principalLedger
}

type principalLedger struct {
	operations map[OperationID]*accepted
	watches    uint32
	sandboxes  map[SandboxID]SandboxInfo
	processes  map[ProcessID]*processRecord
	volumes    map[VolumeID]VolumeInfo
	snapshots  map[SnapshotID]SnapshotInfo
}

// limitPolicy is the explicitly injected finite resource authority for one core composition.
type limitPolicy struct {
	defaults              ResourceLimits
	maximum               ResourceLimits
	version               string
	canonicalizerVersion  string
	capabilityVersion     string
	imageAdmissionVersion string
	maximumOperations     uint32
	maximumProcesses      uint32
	maximumWatches        uint32
	admittedImages        map[Digest]ImageInfo
	capabilities          CapabilitySnapshot
}

type accepted struct {
	request   OperationRequest
	digest    Digest
	effective effectiveSpec
	value     Operation
	done      chan struct{}
	once      sync.Once
}

// effectiveSpec is the durable, resolved authority used by the in-memory
// fixture. Keeping the version facts together prevents a retry from quietly
// taking newly configured defaults.
type effectiveSpec struct {
	request               OperationRequest
	limits                ResourceLimits
	canonicalDigest       Digest
	digest                Digest
	policyVersion         string
	canonicalizerVersion  string
	capabilityVersion     string
	imageAdmissionVersion string
	capabilities          CapabilitySnapshot
	image                 ImageInfo
}

type processRecord struct {
	operationID OperationID
	info        ProcessInfo
	output      *processOutputSpool
}

func newCoreClient(principal string, now time.Time) *coreClient {
	client, err := newCoreClientWithPolicy(principal, now, testLimitPolicy())
	if err != nil {
		panic(err)
	}
	return client
}

func newCoreClientWithPolicy(principal string, now time.Time, limits limitPolicy) (*coreClient, error) {
	return newCoreClientWithLedger(principal, now, limits, newCoreLedger())
}

func newCoreClientWithLedger(principal string, now time.Time, limits limitPolicy, ledger *coreLedger) (*coreClient, error) {
	limits = freezeLimitPolicy(normalizedLimitPolicy(limits))
	if principal == "" || now.IsZero() || ledger == nil || !validLimitPolicy(limits) {
		return nil, newFailure(FailureInvalidArgument, "sandbox core requires finite limit policy", RetryNever)
	}
	return &coreClient{principal: principal, now: now.UTC(), limits: limits, ledger: ledger, streams: make(map[*sliceOperationStream]struct{})}, nil
}

func resolveControlOperationRequest(input []byte, acceptedAt, retentionExpiresAt time.Time, policy OperationAdmissionPolicy) (ResolvedOperation, error) {
	if acceptedAt.IsZero() || acceptedAt.Location() != time.UTC || retentionExpiresAt.IsZero() || retentionExpiresAt.Location() != time.UTC || !retentionExpiresAt.After(acceptedAt) {
		return ResolvedOperation{}, newFailure(FailureInvalidArgument, "operation acceptance and retention times must be ordered UTC values", RetryNever)
	}
	request, err := decodeOperationRequestV1(input)
	if err != nil {
		return ResolvedOperation{}, err
	}
	limits := limitPolicy{
		defaults:              policy.Defaults,
		maximum:               policy.Maximum,
		version:               policy.Version,
		canonicalizerVersion:  policy.CanonicalizerVersion,
		capabilityVersion:     policy.CapabilityVersion,
		imageAdmissionVersion: policy.ImageAdmissionVersion,
		admittedImages:        policy.AdmittedImages,
		capabilities:          policy.Capabilities,
	}
	limits = freezeLimitPolicy(normalizedLimitPolicy(limits))
	if !validLimitPolicy(limits) {
		return ResolvedOperation{}, newFailure(FailureInvalidArgument, "operation admission policy requires finite defaults and maximums", RetryNever)
	}
	frozen, digest, err := normalizeRequest(request, limits)
	if err != nil {
		return ResolvedOperation{}, err
	}
	effective, err := newEffectiveSpec(frozen, digest, limits)
	if err != nil {
		return ResolvedOperation{}, err
	}
	operation := Operation{
		Ref:                 OperationRef{ID: frozen.ID, AcceptedAt: acceptedAt},
		Kind:                frozen.Kind,
		State:               OperationAccepted,
		Target:              targetFor(frozen),
		CanonicalDigest:     digest,
		EffectiveSpecDigest: effective.digest,
		CapabilityDigest:    effective.capabilities.Digest,
		RetentionExpiresAt:  retentionExpiresAt,
		LatestCursor:        "operation:1",
	}
	return ResolvedOperation{Operation: operation, InputDigest: canonicalDigestBytes(input), CleanupRequired: frozen.Kind != OperationApproveSensitive}, nil
}

func freezeLimitPolicy(policy limitPolicy) limitPolicy {
	frozen := policy
	frozen.capabilities = copyCapabilitySnapshot(policy.capabilities)
	if policy.admittedImages != nil {
		frozen.admittedImages = make(map[Digest]ImageInfo, len(policy.admittedImages))
		for digest, image := range policy.admittedImages {
			image.Identity.Groups = append([]uint32(nil), image.Identity.Groups...)
			frozen.admittedImages[digest] = image
		}
	}
	return frozen
}

func newCoreLedger() *coreLedger {
	return &coreLedger{principals: make(map[string]*principalLedger)}
}

func normalizedLimitPolicy(limits limitPolicy) limitPolicy {
	if limits.version == "" {
		limits.version = "limits/v1"
	}
	if limits.canonicalizerVersion == "" {
		limits.canonicalizerVersion = canonicalizerVersion
	}
	if limits.capabilityVersion == "" {
		limits.capabilityVersion = "capabilities/v1"
	}
	if limits.imageAdmissionVersion == "" {
		limits.imageAdmissionVersion = "image-admission/v1"
	}
	if limits.maximumOperations == 0 {
		limits.maximumOperations = 1024
	}
	if limits.maximumProcesses == 0 {
		limits.maximumProcesses = 1024
	}
	if limits.maximumWatches == 0 {
		limits.maximumWatches = 32
	}
	limits.capabilities = normalizedCapabilitySnapshot(limits.capabilities, limits.capabilityVersion)
	// The capability digest is derived from the entire structured profile. A
	// supplied label is never authority: changing a data-plane, contract, or
	// precision fact must change the Effective Spec binding.
	limits.capabilities.Digest = canonicalCapabilitySnapshotDigest(limits.capabilities)
	return limits
}

func normalizedCapabilitySnapshot(snapshot CapabilitySnapshot, contractVersion string) CapabilitySnapshot {
	if snapshot.SchemaVersion == "" {
		snapshot.SchemaVersion = contractVersion
	}
	for _, descriptor := range []*CapabilityDescriptor{
		&snapshot.ControlProtocol,
		&snapshot.Isolation,
		&snapshot.Guest,
		&snapshot.Resources,
		&snapshot.Reconnect,
		&snapshot.ImageAdmission,
		&snapshot.Output,
		&snapshot.Transfer,
		&snapshot.Mounts,
		&snapshot.Volumes,
		&snapshot.Snapshots,
		&snapshot.Egress,
		&snapshot.Secrets,
	} {
		if descriptor.State == "" {
			descriptor.State = CapabilityUnavailable
		}
		if descriptor.ContractVersion == "" {
			descriptor.ContractVersion = contractVersion
		}
		if descriptor.ConformanceVersion == "" {
			descriptor.ConformanceVersion = "not-certified"
		}
		if descriptor.DataPlane == "" {
			descriptor.DataPlane = "none"
		}
		descriptor.LimitPrecision = append([]string(nil), descriptor.LimitPrecision...)
	}
	snapshot.Signals = append([]Signal(nil), snapshot.Signals...)
	return snapshot
}

func (client *coreClient) principalLedgerLocked() *principalLedger {
	ledger := client.ledger.principals[client.principal]
	if ledger == nil {
		ledger = &principalLedger{
			operations: make(map[OperationID]*accepted),
			sandboxes:  make(map[SandboxID]SandboxInfo),
			processes:  make(map[ProcessID]*processRecord),
			volumes:    make(map[VolumeID]VolumeInfo),
			snapshots:  make(map[SnapshotID]SnapshotInfo),
		}
		client.ledger.principals[client.principal] = ledger
	}
	return ledger
}

func (client *coreClient) otherPrincipalHasOperationLocked(id OperationID) bool {
	for principal, ledger := range client.ledger.principals {
		if principal == client.principal {
			continue
		}
		if _, exists := ledger.operations[id]; exists {
			return true
		}
	}
	return false
}

func (client *coreClient) Submit(ctx context.Context, request OperationRequest) (OperationRef, error) {
	if err := contextFailure(ctx); err != nil {
		return OperationRef{}, err
	}
	client.ledger.mu.Lock()
	defer client.ledger.mu.Unlock()
	if client.closed {
		return OperationRef{}, newFailure(FailureUnavailable, "sandbox client is closed", RetryAfterReconcile)
	}
	ledger := client.principalLedgerLocked()
	if prior := ledger.operations[request.ID]; prior != nil {
		// Retry against the persisted Effective Spec. A changed current default
		// must not turn the original zero value into an operation conflict.
		frozen, digest, err := normalizeRequest(request, limitPolicy{defaults: prior.effective.limits, maximum: prior.effective.limits})
		if err != nil {
			return OperationRef{}, err
		}
		if digest != prior.digest || !compatiblePersistedSpec(prior.effective, client.limits) {
			if digest == prior.digest {
				return OperationRef{}, newFailure(FailureIncompatiblePersistedPolicy, "persisted effective specification is incompatible with current policy", RetryNever)
			}
			return OperationRef{}, newFailure(FailureOperationConflict, "operation ID has a different request", RetryNever)
		}
		_ = frozen
		return prior.value.Ref, nil
	}
	if client.otherPrincipalHasOperationLocked(request.ID) {
		return OperationRef{}, newFailure(FailureNotFoundOrDenied, "operation was not found", RetryNever)
	}
	if uint32(len(ledger.operations)) >= client.limits.maximumOperations {
		return OperationRef{}, newFailure(FailureControlQuotaExceeded, "principal operation admission quota is exhausted", RetryCallerControlled)
	}
	if request.Kind == OperationExecProcess && uint32(len(ledger.processes)) >= client.limits.maximumProcesses {
		return OperationRef{}, newFailure(FailureControlQuotaExceeded, "principal process admission quota is exhausted", RetryCallerControlled)
	}
	frozen, digest, err := normalizeRequest(request, client.limits)
	if err != nil {
		return OperationRef{}, err
	}
	effective, err := newEffectiveSpec(frozen, digest, client.limits)
	if err != nil {
		return OperationRef{}, err
	}
	ref := OperationRef{ID: frozen.ID, AcceptedAt: client.now}
	value := Operation{Ref: ref, Kind: frozen.Kind, State: OperationAccepted, Target: targetFor(frozen), CanonicalDigest: digest, EffectiveSpecDigest: effective.digest, CapabilityDigest: effective.capabilities.Digest}
	entry := &accepted{request: frozen, digest: digest, effective: effective, value: value, done: make(chan struct{})}
	ledger.operations[frozen.ID] = entry
	client.reserveAcceptedResourcesLocked(ledger, entry)
	return ref, nil
}

// Capabilities returns the frozen, versioned profile that this control client
// will bind to newly accepted create and restore operations.
func (client *coreClient) Capabilities(ctx context.Context) (CapabilitySnapshot, error) {
	if err := contextFailure(ctx); err != nil {
		return CapabilitySnapshot{}, err
	}
	client.ledger.mu.RLock()
	defer client.ledger.mu.RUnlock()
	if client.closed {
		return CapabilitySnapshot{}, closedClientFailure()
	}
	return copyCapabilitySnapshot(client.limits.capabilities), nil
}

func compatiblePersistedSpec(spec effectiveSpec, policy limitPolicy) bool {
	if !withinLimits(spec.limits, policy.maximum) {
		return false
	}
	if spec.canonicalizerVersion != policy.canonicalizerVersion {
		return false
	}
	// A retry can only reconnect to the exact capability profile bound to its
	// Effective Spec. Accepting it under a downgraded profile would turn a
	// durable capability regression into a silent authority change.
	if spec.capabilities.Digest != policy.capabilities.Digest {
		return false
	}
	if spec.image.Digest != "" {
		current, err := admitImage(ImageRef{Digest: spec.image.Digest}, policy)
		if err != nil || !sameImageCompatibility(spec.image, current) {
			return false
		}
	}
	return true
}

func sameImageCompatibility(left, right ImageInfo) bool {
	return left.Digest == right.Digest &&
		left.Architecture == right.Architecture &&
		left.Identity.UID == right.Identity.UID &&
		left.Identity.GID == right.Identity.GID &&
		reflect.DeepEqual(left.Identity.Groups, right.Identity.Groups) &&
		left.GuestProtocol == right.GuestProtocol
}

func (client *coreClient) reserveAcceptedResourcesLocked(ledger *principalLedger, entry *accepted) {
	switch entry.request.Kind {
	case OperationCreateSandbox:
		id := sandboxIDFor(entry.value.Ref.ID)
		ledger.sandboxes[id] = SandboxInfo{ID: id, Desired: SandboxActive, Actual: SandboxPending, Image: entry.effective.image, Resources: entry.effective.limits, Capabilities: copyCapabilitySnapshot(entry.effective.capabilities)}
	case OperationExecProcess:
		id := processIDFor(entry.value.Ref.ID)
		limits := entry.effective.limits
		output, _ := newProcessOutputSpool(limits.ProducedOutputBytes, limits.RetainedOutputBytes, nil)
		ledger.processes[id] = &processRecord{operationID: entry.value.Ref.ID, info: ProcessInfo{ID: id, SandboxID: entry.request.ExecProcess.SandboxID, State: ProcessAccepted}, output: output}
	}
}

func testLimitPolicy() limitPolicy {
	finite := ResourceLimits{MilliCPU: 1, MemoryBytes: 1, RootDiskBytes: 1, TmpfsBytes: 1, PIDs: 1, ProcessCount: 1, OpenFiles: 1, Inodes: 1, Files: 1, Lifetime: time.Nanosecond, ProducedOutputBytes: 1, RetainedOutputBytes: 1, TransferBytes: 1, NetworkConnections: 1, VolumeBytes: 1, SnapshotBytes: 1}
	return limitPolicy{defaults: finite, maximum: finite}
}

func newEffectiveSpec(request OperationRequest, canonical Digest, policy limitPolicy) (effectiveSpec, error) {
	spec := effectiveSpec{
		request:               copyRequest(request),
		canonicalDigest:       canonical,
		policyVersion:         policy.version,
		canonicalizerVersion:  policy.canonicalizerVersion,
		capabilityVersion:     policy.capabilityVersion,
		imageAdmissionVersion: policy.imageAdmissionVersion,
		capabilities:          copyCapabilitySnapshot(policy.capabilities),
	}
	if request.CreateSandbox != nil {
		spec.limits = request.CreateSandbox.Spec.Resources
		image, err := admitImage(request.CreateSandbox.Spec.Image, policy)
		if err != nil {
			return effectiveSpec{}, err
		}
		if err := validateCapabilityRequirements(request.CreateSandbox.Spec.Capabilities, spec.capabilities); err != nil {
			return effectiveSpec{}, err
		}
		if err := validateRequestedProfileCapabilities(request.CreateSandbox.Spec, spec.capabilities); err != nil {
			return effectiveSpec{}, err
		}
		spec.image = image
	}
	if request.ExecProcess != nil {
		// Process requests inherit the sandbox limits at dispatch. The fixture
		// keeps a finite request boundary even before a host is composed.
		spec.limits = policy.defaults
	}
	if request.RestoreSandbox != nil && request.RestoreSandbox.Overrides.Capabilities != nil {
		if err := validateCapabilityRequirements(*request.RestoreSandbox.Overrides.Capabilities, spec.capabilities); err != nil {
			return effectiveSpec{}, err
		}
	}
	if spec.limits == (ResourceLimits{}) {
		spec.limits = policy.defaults
	}
	var builder strings.Builder
	canonicalField(&builder, canonicalizerVersion)
	canonicalField(&builder, string(spec.canonicalDigest))
	canonicalField(&builder, spec.policyVersion)
	canonicalField(&builder, spec.canonicalizerVersion)
	canonicalField(&builder, spec.capabilityVersion)
	canonicalField(&builder, spec.imageAdmissionVersion)
	canonicalField(&builder, string(spec.capabilities.Digest))
	canonicalImageInfo(&builder, spec.image)
	canonicalResources(&builder, spec.limits)
	spec.digest = digestCanonical(builder.String())
	return spec, nil
}

func validateCapabilityRequirements(requirements CapabilityRequirements, available CapabilitySnapshot) error {
	if len(requirements.Required) > 16 {
		return newFailure(FailureInvalidArgument, "sandbox capability requirements exceed the finite request limit", RetryNever)
	}
	seen := make(map[CapabilityFeature]struct{}, len(requirements.Required))
	for _, requirement := range requirements.Required {
		if requirement.Minimum != CapabilityDeclared && requirement.Minimum != CapabilityEnforced {
			return newFailure(FailureInvalidArgument, "sandbox capability requirement minimum is invalid", RetryNever)
		}
		if _, duplicate := seen[requirement.Feature]; duplicate {
			return newFailure(FailureInvalidArgument, "sandbox capability requirement is duplicated", RetryNever)
		}
		seen[requirement.Feature] = struct{}{}
		actual, known := capabilityDescriptor(available, requirement.Feature)
		if !known {
			return newFailure(FailureInvalidArgument, "sandbox capability requirement is unknown", RetryNever)
		}
		if !capabilityAtLeast(actual.State, requirement.Minimum) {
			return newFailure(FailureCapabilityUnavailable, "sandbox capability requirement is not met by the negotiated profile", RetryNever)
		}
	}
	return nil
}

func validateRequestedProfileCapabilities(spec SandboxSpec, available CapabilitySnapshot) error {
	for feature, requested := range map[CapabilityFeature]bool{
		CapabilitySecrets: len(spec.SecretBindings) != 0,
		CapabilityMounts:  len(spec.Mounts) != 0,
		CapabilityVolumes: len(spec.VolumeAttachments) != 0,
	} {
		if !requested {
			continue
		}
		descriptor, _ := capabilityDescriptor(available, feature)
		if !capabilityAtLeast(descriptor.State, CapabilityEnforced) {
			return newFailure(FailureCapabilityUnavailable, "sandbox request requires an unavailable authority profile", RetryNever)
		}
	}
	return nil
}

func capabilityDescriptor(snapshot CapabilitySnapshot, feature CapabilityFeature) (CapabilityDescriptor, bool) {
	switch feature {
	case CapabilityIsolation:
		return snapshot.Isolation, true
	case CapabilityEgress:
		return snapshot.Egress, true
	case CapabilityMounts:
		return snapshot.Mounts, true
	case CapabilityVolumes:
		return snapshot.Volumes, true
	case CapabilitySnapshots:
		return snapshot.Snapshots, true
	case CapabilitySecrets:
		return snapshot.Secrets, true
	case CapabilityTransfer:
		return snapshot.Transfer, true
	case CapabilityReconnect:
		return snapshot.Reconnect, true
	default:
		return CapabilityDescriptor{}, false
	}
}

func capabilityAtLeast(actual, required CapabilityState) bool {
	if actual == CapabilityEnforced {
		return required == CapabilityDeclared || required == CapabilityEnforced
	}
	return actual == CapabilityDeclared && required == CapabilityDeclared
}

func admitImage(image ImageRef, policy limitPolicy) (ImageInfo, error) {
	if image.Digest == "" || !validDigest(image.Digest) {
		return ImageInfo{}, newFailure(FailureInvalidArgument, "image digest must be immutable sha256 content", RetryNever)
	}
	if policy.admittedImages == nil {
		return ImageInfo{Digest: image.Digest, Architecture: "linux/amd64", Identity: NumericIdentity{UID: 1000, GID: 1000}, GuestProtocol: "sandbox.guest/v1", AdmissionPolicyVersion: policy.imageAdmissionVersion}, nil
	}
	info, found := policy.admittedImages[image.Digest]
	if !found || info.Digest != image.Digest || info.Architecture == "" || info.GuestProtocol == "" || info.Identity.UID == 0 {
		return ImageInfo{}, newFailure(FailureCapabilityUnavailable, "image is not admitted by the current policy", RetryNever)
	}
	info.Identity.Groups = append([]uint32(nil), info.Identity.Groups...)
	info.AdmissionPolicyVersion = policy.imageAdmissionVersion
	return info, nil
}

func (client *coreClient) GetOperation(ctx context.Context, id OperationID) (Operation, error) {
	if err := contextFailure(ctx); err != nil {
		return Operation{}, err
	}
	client.ledger.mu.RLock()
	defer client.ledger.mu.RUnlock()
	if client.closed {
		return Operation{}, closedClientFailure()
	}
	ledger := client.ledger.principals[client.principal]
	if ledger == nil || ledger.operations[id] == nil {
		return Operation{}, newFailure(FailureNotFoundOrDenied, "operation was not found", RetryNever)
	}
	return copyOperation(ledger.operations[id].value), nil
}

func (client *coreClient) WaitOperation(ctx context.Context, id OperationID) (Operation, error) {
	if err := contextFailure(ctx); err != nil {
		return Operation{}, err
	}
	client.ledger.mu.RLock()
	if client.closed {
		client.ledger.mu.RUnlock()
		return Operation{}, closedClientFailure()
	}
	ledger := client.ledger.principals[client.principal]
	if ledger == nil || ledger.operations[id] == nil {
		client.ledger.mu.RUnlock()
		return Operation{}, newFailure(FailureNotFoundOrDenied, "operation was not found", RetryNever)
	}
	entry := ledger.operations[id]
	if isTerminalOperation(entry.value.State) {
		value := copyOperation(entry.value)
		client.ledger.mu.RUnlock()
		return value, nil
	}
	done := entry.done
	client.ledger.mu.RUnlock()
	select {
	case <-done:
		return client.GetOperation(context.Background(), id)
	case <-ctx.Done():
		return Operation{}, contextFailure(ctx)
	}
}

func (client *coreClient) WatchOperation(ctx context.Context, id OperationID, from OperationCursor) (OperationStream, error) {
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	client.ledger.mu.Lock()
	if client.closed {
		client.ledger.mu.Unlock()
		return nil, closedClientFailure()
	}
	ledger := client.ledger.principals[client.principal]
	if ledger == nil || ledger.operations[id] == nil {
		client.ledger.mu.Unlock()
		return nil, newFailure(FailureNotFoundOrDenied, "operation was not found", RetryNever)
	}
	entry := ledger.operations[id]
	event := OperationEvent{Kind: OperationEventUpdate, Cursor: "1", Update: ptrOperation(copyOperation(entry.value))}
	if from != "" && from != "0" && from != "1" {
		client.ledger.mu.Unlock()
		return nil, newFailure(FailureCursorExpired, "operation cursor is outside retained history", RetryNever)
	}
	if ledger.watches >= client.limits.maximumWatches {
		client.ledger.mu.Unlock()
		return nil, newFailure(FailureControlQuotaExceeded, "operation watch admission quota is exhausted", RetryCallerControlled)
	}
	ledger.watches++
	stream := &sliceOperationStream{events: []OperationEvent{event}}
	stream.onClose = func() { client.releaseWatch(stream) }
	client.streams[stream] = struct{}{}
	client.ledger.mu.Unlock()
	return stream, nil
}

func (client *coreClient) releaseWatch(stream *sliceOperationStream) {
	client.ledger.mu.Lock()
	defer client.ledger.mu.Unlock()
	ledger := client.ledger.principals[client.principal]
	if ledger != nil && ledger.watches > 0 {
		ledger.watches--
	}
	delete(client.streams, stream)
}

func (client *coreClient) GetSandbox(ctx context.Context, id SandboxID) (SandboxInfo, error) {
	if err := contextFailure(ctx); err != nil {
		return SandboxInfo{}, err
	}
	client.ledger.mu.RLock()
	defer client.ledger.mu.RUnlock()
	if client.closed {
		return SandboxInfo{}, closedClientFailure()
	}
	ledger := client.ledger.principals[client.principal]
	if ledger == nil {
		return SandboxInfo{}, newFailure(FailureNotFoundOrDenied, "sandbox was not found", RetryNever)
	}
	value, found := ledger.sandboxes[id]
	if !found {
		return SandboxInfo{}, newFailure(FailureNotFoundOrDenied, "sandbox was not found", RetryNever)
	}
	return copySandboxInfo(value), nil
}

func (client *coreClient) GetProcess(ctx context.Context, id ProcessID) (ProcessInfo, error) {
	if err := contextFailure(ctx); err != nil {
		return ProcessInfo{}, err
	}
	client.ledger.mu.RLock()
	defer client.ledger.mu.RUnlock()
	if client.closed {
		return ProcessInfo{}, closedClientFailure()
	}
	ledger := client.ledger.principals[client.principal]
	if ledger == nil || ledger.processes[id] == nil {
		return ProcessInfo{}, newFailure(FailureNotFoundOrDenied, "process was not found", RetryNever)
	}
	return copyProcessInfo(ledger.processes[id].info), nil
}

func (client *coreClient) ReplayOutput(ctx context.Context, id ProcessID, from OutputCursor) (OutputStream, error) {
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	client.ledger.mu.RLock()
	if client.closed {
		client.ledger.mu.RUnlock()
		return nil, closedClientFailure()
	}
	ledger := client.ledger.principals[client.principal]
	if ledger == nil || ledger.processes[id] == nil {
		client.ledger.mu.RUnlock()
		return nil, newFailure(FailureNotFoundOrDenied, "process was not found", RetryNever)
	}
	record := ledger.processes[id]
	events := record.output.Events()
	client.ledger.mu.RUnlock()
	return newSliceOutputStream(events, from)
}

func (client *coreClient) GetVolume(ctx context.Context, id VolumeID) (VolumeInfo, error) {
	if err := contextFailure(ctx); err != nil {
		return VolumeInfo{}, err
	}
	client.ledger.mu.RLock()
	defer client.ledger.mu.RUnlock()
	if client.closed {
		return VolumeInfo{}, closedClientFailure()
	}
	ledger := client.ledger.principals[client.principal]
	if ledger == nil {
		return VolumeInfo{}, newFailure(FailureNotFoundOrDenied, "volume was not found", RetryNever)
	}
	value, found := ledger.volumes[id]
	if !found {
		return VolumeInfo{}, newFailure(FailureNotFoundOrDenied, "volume was not found", RetryNever)
	}
	return copyVolumeInfo(value), nil
}

func (client *coreClient) ListVolumes(ctx context.Context, page Page) (VolumePage, error) {
	if err := contextFailure(ctx); err != nil {
		return VolumePage{}, err
	}
	if page.Limit == 0 || page.Limit > 100 {
		return VolumePage{}, newFailure(FailureInvalidArgument, "page limit must be between one and one hundred", RetryNever)
	}
	client.ledger.mu.RLock()
	defer client.ledger.mu.RUnlock()
	if client.closed {
		return VolumePage{}, closedClientFailure()
	}
	ledger := client.ledger.principals[client.principal]
	if ledger == nil {
		return VolumePage{}, nil
	}
	return pageVolumes(ledger.volumes, page), nil
}

func (client *coreClient) GetSnapshot(ctx context.Context, id SnapshotID) (SnapshotInfo, error) {
	if err := contextFailure(ctx); err != nil {
		return SnapshotInfo{}, err
	}
	client.ledger.mu.RLock()
	defer client.ledger.mu.RUnlock()
	if client.closed {
		return SnapshotInfo{}, closedClientFailure()
	}
	ledger := client.ledger.principals[client.principal]
	if ledger == nil {
		return SnapshotInfo{}, newFailure(FailureNotFoundOrDenied, "snapshot was not found", RetryNever)
	}
	value, found := ledger.snapshots[id]
	if !found {
		return SnapshotInfo{}, newFailure(FailureNotFoundOrDenied, "snapshot was not found", RetryNever)
	}
	return copySnapshotInfo(value), nil
}

func (client *coreClient) ListSnapshots(ctx context.Context, page Page) (SnapshotPage, error) {
	if err := contextFailure(ctx); err != nil {
		return SnapshotPage{}, err
	}
	if page.Limit == 0 || page.Limit > 100 {
		return SnapshotPage{}, newFailure(FailureInvalidArgument, "page limit must be between one and one hundred", RetryNever)
	}
	client.ledger.mu.RLock()
	defer client.ledger.mu.RUnlock()
	if client.closed {
		return SnapshotPage{}, closedClientFailure()
	}
	ledger := client.ledger.principals[client.principal]
	if ledger == nil {
		return SnapshotPage{}, nil
	}
	return pageSnapshots(ledger.snapshots, page), nil
}

func (client *coreClient) Close(ctx context.Context) error {
	if err := contextFailure(ctx); err != nil {
		return err
	}
	client.ledger.mu.Lock()
	client.closed = true
	streams := make([]*sliceOperationStream, 0, len(client.streams))
	for stream := range client.streams {
		streams = append(streams, stream)
	}
	client.ledger.mu.Unlock()
	for _, stream := range streams {
		if err := stream.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (client *coreClient) completeProcess(id ProcessID, result ProcessResult) error {
	if err := validateProcessResult(result); err != nil {
		return err
	}
	client.ledger.mu.Lock()
	defer client.ledger.mu.Unlock()
	ledger := client.ledger.principals[client.principal]
	if ledger == nil || ledger.processes[id] == nil {
		return newFailure(FailureNotFoundOrDenied, "process was not found", RetryNever)
	}
	record := ledger.processes[id]
	if record.info.State == ProcessTerminal {
		return newFailure(FailureAlreadyTerminal, "process is already terminal", RetryNever)
	}
	client.completeProcessLocked(ledger, record, result)
	return nil
}

// startProcess is the deterministic control-side start observation used by the
// fake transport. It deliberately models acknowledgement only; it never starts
// an OS process. A cancelled start becomes a typed terminal record while a
// cancelled Wait remains observation-only.
func (client *coreClient) startProcess(ctx context.Context, id ProcessID) error {
	client.ledger.mu.Lock()
	defer client.ledger.mu.Unlock()
	ledger := client.ledger.principals[client.principal]
	if ledger == nil || ledger.processes[id] == nil {
		return newFailure(FailureNotFoundOrDenied, "process was not found", RetryNever)
	}
	record := ledger.processes[id]
	if record.info.State == ProcessTerminal {
		return newFailure(FailureAlreadyTerminal, "process is already terminal", RetryNever)
	}
	if err := contextFailure(ctx); err != nil {
		client.completeProcessLocked(ledger, record, ProcessResult{StartedAt: client.now, FinishedAt: client.now, Reason: TerminationCancelled, Cleanup: TreeCleanupNotRequired})
		return err
	}
	if record.info.State != ProcessAccepted && record.info.State != ProcessStarting {
		return newFailure(FailureAlreadyTerminal, "process cannot be started from its current state", RetryNever)
	}
	record.info.State = ProcessStarting
	// The fake acknowledgement is deterministic and immediate. A real adapter
	// reports this transition through the same ledger before guest execution.
	record.info.State = ProcessRunning
	return nil
}

func (client *coreClient) completeProcessLocked(ledger *principalLedger, record *processRecord, result ProcessResult) {
	record.info.State = ProcessTerminal
	record.info.Result = ptrProcessResult(copyProcessResult(result))
	record.output.Close(result)
	record.info.Stdout = record.output.Retention(OutputStdout)
	record.info.Stderr = record.output.Retention(OutputStderr)
	if entry := ledger.operations[record.operationID]; entry != nil && !isTerminalOperation(entry.value.State) {
		entry.value.State = OperationSucceeded
		entry.value.Result = &OperationResult{Kind: ResultProcess, Process: ptrProcessResult(copyProcessResult(result))}
		entry.once.Do(func() { close(entry.done) })
	}
}

func (client *coreClient) appendProcessOutput(id ProcessID, stream OutputKind, chunk []byte) error {
	client.ledger.mu.Lock()
	defer client.ledger.mu.Unlock()
	ledger := client.ledger.principals[client.principal]
	if ledger == nil || ledger.processes[id] == nil {
		return newFailure(FailureNotFoundOrDenied, "process was not found", RetryNever)
	}
	if err := ledger.processes[id].output.Write(stream, chunk); err != nil {
		failure, _ := AsFailure(err)
		if failure.Code == FailureResourceLimitExceeded && ledger.processes[id].info.State != ProcessTerminal {
			result := ProcessResult{StartedAt: client.now, FinishedAt: client.now, Reason: TerminationOutputLimit, Cleanup: TreeCleanupConfirmed}
			client.completeProcessLocked(ledger, ledger.processes[id], result)
		}
		return err
	}
	return nil
}

func (client *coreClient) acceptedOperation(id OperationID) accepted {
	client.ledger.mu.RLock()
	defer client.ledger.mu.RUnlock()
	ledger := client.ledger.principals[client.principal]
	if ledger == nil || ledger.operations[id] == nil {
		return accepted{}
	}
	entry := ledger.operations[id]
	return accepted{request: copyRequest(entry.request), digest: entry.digest, effective: copyEffectiveSpec(entry.effective), value: copyOperation(entry.value)}
}

func (client *coreClient) operationCount() int {
	client.ledger.mu.RLock()
	defer client.ledger.mu.RUnlock()
	ledger := client.ledger.principals[client.principal]
	if ledger == nil {
		return 0
	}
	return len(ledger.operations)
}

func normalizeRequest(request OperationRequest, limits limitPolicy) (OperationRequest, Digest, error) {
	if err := validateCanonicalStrings(reflect.ValueOf(request)); err != nil {
		return OperationRequest{}, "", err
	}
	if request.ID == "" {
		return OperationRequest{}, "", newFailure(FailureInvalidArgument, "operation ID is required", RetryNever)
	}
	if !validOperationID(request.ID) {
		return OperationRequest{}, "", newFailure(FailureInvalidArgument, "operation ID is invalid", RetryNever)
	}
	bodies := requestBodies(request)
	if len(bodies) != 1 || bodies[0] != request.Kind {
		return OperationRequest{}, "", newFailure(FailureInvalidArgument, "operation kind requires exactly one matching request body", RetryNever)
	}
	switch request.Kind {
	case OperationCreateSandbox:
		if request.CreateSandbox.Spec.Image.Digest == "" || !validDigest(request.CreateSandbox.Spec.Image.Digest) {
			return OperationRequest{}, "", newFailure(FailureInvalidArgument, "create sandbox requires an immutable image digest", RetryNever)
		}
		request.CreateSandbox.Spec.Resources = resolveLimits(request.CreateSandbox.Spec.Resources, limits.defaults)
		if !withinLimits(request.CreateSandbox.Spec.Resources, limits.maximum) {
			return OperationRequest{}, "", newFailure(FailureResourceLimitExceeded, "sandbox resources exceed policy maximum", RetryNever)
		}
	case OperationExecProcess:
		if request.ExecProcess.SandboxID == "" || !validSandboxID(request.ExecProcess.SandboxID) {
			return OperationRequest{}, "", newFailure(FailureInvalidArgument, "exec process requires a sandbox ID", RetryNever)
		}
		if err := validateCommand(request.ExecProcess.Command); err != nil {
			return OperationRequest{}, "", err
		}
	case OperationCopyIn:
		if request.CopyIn.Options.Overwrite == "" {
			request.CopyIn.Options.Overwrite = OverwriteFailIfExists
		}
		if !validTaggedTarget(request) || !validTransferOptions(request.CopyIn.Options) {
			return OperationRequest{}, "", newFailure(FailureInvalidArgument, "copy-in transfer options are invalid", RetryNever)
		}
	case OperationCopyOut:
		if request.CopyOut.Options.Overwrite == "" {
			request.CopyOut.Options.Overwrite = OverwriteFailIfExists
		}
		if !validTaggedTarget(request) || !validTransferOptions(request.CopyOut.Options) {
			return OperationRequest{}, "", newFailure(FailureInvalidArgument, "copy-out transfer options are invalid", RetryNever)
		}
	default:
		if !validTaggedTarget(request) {
			return OperationRequest{}, "", newFailure(FailureInvalidArgument, "operation target is required", RetryNever)
		}
	}
	frozen := copyRequest(request)
	return frozen, canonicalRequestDigest(frozen), nil
}

func validTaggedTarget(request OperationRequest) bool {
	switch request.Kind {
	case OperationRestoreSandbox:
		return validSnapshotID(request.RestoreSandbox.SnapshotID)
	case OperationSignalProcess:
		return validProcessID(request.SignalProcess.ProcessID) && portableSignal(request.SignalProcess.Signal)
	case OperationKillProcess:
		return validProcessID(request.KillProcess.ProcessID)
	case OperationCopyIn:
		return validSandboxID(request.CopyIn.SandboxID) && validArtifactRef(request.CopyIn.Source) && validGuestPath(request.CopyIn.Destination)
	case OperationCopyOut:
		return validSandboxID(request.CopyOut.SandboxID) && validGuestPath(request.CopyOut.Source) && validMediaType(request.CopyOut.MediaType)
	case OperationSnapshotSandbox:
		return validSandboxID(request.SnapshotSandbox.SandboxID)
	case OperationCloseSandbox:
		return validSandboxID(request.CloseSandbox.SandboxID)
	case OperationReconcileSandbox:
		return validSandboxID(request.ReconcileSandbox.SandboxID)
	case OperationCreateVolume:
		return request.CreateVolume.Spec.SizeBytes > 0 && request.CreateVolume.Spec.Inodes > 0
	case OperationAttachVolume:
		return validSandboxID(request.AttachVolume.SandboxID) && validVolumeID(request.AttachVolume.VolumeID) && validGuestPath(request.AttachVolume.Target)
	case OperationDetachVolume:
		return validSandboxID(request.DetachVolume.SandboxID) && validVolumeID(request.DetachVolume.VolumeID)
	case OperationDeleteVolume:
		return validVolumeID(request.DeleteVolume.VolumeID)
	case OperationDeleteSnapshot:
		return validSnapshotID(request.DeleteSnapshot.SnapshotID)
	case OperationApproveSensitive:
		return validOperationID(request.ApproveSensitive.SensitiveOperationID) && request.ApproveSensitive.Decision != "" && !request.ApproveSensitive.ExpiresAt.IsZero()
	default:
		return false
	}
}

func validLimitPolicy(policy limitPolicy) bool {
	return resourceFinite(policy.defaults) && resourceFinite(policy.maximum) && withinLimits(policy.defaults, policy.maximum) && validCapabilitySnapshot(policy.capabilities)
}

func validCapabilitySnapshot(snapshot CapabilitySnapshot) bool {
	if snapshot.SchemaVersion == "" || !validDigest(snapshot.Digest) {
		return false
	}
	for _, descriptor := range []CapabilityDescriptor{snapshot.ControlProtocol, snapshot.Isolation, snapshot.Guest, snapshot.Resources, snapshot.Reconnect, snapshot.ImageAdmission, snapshot.Output, snapshot.Transfer, snapshot.Mounts, snapshot.Volumes, snapshot.Snapshots, snapshot.Egress, snapshot.Secrets} {
		if (descriptor.State != CapabilityUnavailable && descriptor.State != CapabilityDeclared && descriptor.State != CapabilityEnforced) || descriptor.ContractVersion == "" || descriptor.ConformanceVersion == "" || descriptor.DataPlane == "" {
			return false
		}
	}
	return snapshot.Digest == canonicalCapabilitySnapshotDigest(snapshot)
}
func resourceFinite(value ResourceLimits) bool {
	return value.MilliCPU > 0 && value.MemoryBytes > 0 && value.RootDiskBytes > 0 && value.TmpfsBytes > 0 && value.PIDs > 0 && value.ProcessCount > 0 && value.OpenFiles > 0 && value.Inodes > 0 && value.Files > 0 && value.Lifetime > 0 && value.ProducedOutputBytes > 0 && value.RetainedOutputBytes > 0 && value.TransferBytes > 0 && value.NetworkConnections > 0 && value.VolumeBytes > 0 && value.SnapshotBytes > 0
}
func withinLimits(value, maximum ResourceLimits) bool {
	return value.MilliCPU <= maximum.MilliCPU && value.MemoryBytes <= maximum.MemoryBytes && value.RootDiskBytes <= maximum.RootDiskBytes && value.TmpfsBytes <= maximum.TmpfsBytes && value.PIDs <= maximum.PIDs && value.ProcessCount <= maximum.ProcessCount && value.OpenFiles <= maximum.OpenFiles && value.Inodes <= maximum.Inodes && value.Files <= maximum.Files && value.Lifetime <= maximum.Lifetime && value.ProducedOutputBytes <= maximum.ProducedOutputBytes && value.RetainedOutputBytes <= maximum.RetainedOutputBytes && value.TransferBytes <= maximum.TransferBytes && value.NetworkConnections <= maximum.NetworkConnections && value.VolumeBytes <= maximum.VolumeBytes && value.SnapshotBytes <= maximum.SnapshotBytes
}
func resolveLimits(value, defaults ResourceLimits) ResourceLimits {
	if value.MilliCPU == 0 {
		value.MilliCPU = defaults.MilliCPU
	}
	if value.MemoryBytes == 0 {
		value.MemoryBytes = defaults.MemoryBytes
	}
	if value.RootDiskBytes == 0 {
		value.RootDiskBytes = defaults.RootDiskBytes
	}
	if value.TmpfsBytes == 0 {
		value.TmpfsBytes = defaults.TmpfsBytes
	}
	if value.PIDs == 0 {
		value.PIDs = defaults.PIDs
	}
	if value.ProcessCount == 0 {
		value.ProcessCount = defaults.ProcessCount
	}
	if value.OpenFiles == 0 {
		value.OpenFiles = defaults.OpenFiles
	}
	if value.Inodes == 0 {
		value.Inodes = defaults.Inodes
	}
	if value.Files == 0 {
		value.Files = defaults.Files
	}
	if value.Lifetime == 0 {
		value.Lifetime = defaults.Lifetime
	}
	if value.ProducedOutputBytes == 0 {
		value.ProducedOutputBytes = defaults.ProducedOutputBytes
	}
	if value.RetainedOutputBytes == 0 {
		value.RetainedOutputBytes = defaults.RetainedOutputBytes
	}
	if value.TransferBytes == 0 {
		value.TransferBytes = defaults.TransferBytes
	}
	if value.NetworkConnections == 0 {
		value.NetworkConnections = defaults.NetworkConnections
	}
	if value.VolumeBytes == 0 {
		value.VolumeBytes = defaults.VolumeBytes
	}
	if value.SnapshotBytes == 0 {
		value.SnapshotBytes = defaults.SnapshotBytes
	}
	return value
}

func requestBodies(request OperationRequest) []OperationKind {
	var bodies []OperationKind
	if request.CreateSandbox != nil {
		bodies = append(bodies, OperationCreateSandbox)
	}
	if request.RestoreSandbox != nil {
		bodies = append(bodies, OperationRestoreSandbox)
	}
	if request.ExecProcess != nil {
		bodies = append(bodies, OperationExecProcess)
	}
	if request.SignalProcess != nil {
		bodies = append(bodies, OperationSignalProcess)
	}
	if request.KillProcess != nil {
		bodies = append(bodies, OperationKillProcess)
	}
	if request.CopyIn != nil {
		bodies = append(bodies, OperationCopyIn)
	}
	if request.CopyOut != nil {
		bodies = append(bodies, OperationCopyOut)
	}
	if request.SnapshotSandbox != nil {
		bodies = append(bodies, OperationSnapshotSandbox)
	}
	if request.CloseSandbox != nil {
		bodies = append(bodies, OperationCloseSandbox)
	}
	if request.ReconcileSandbox != nil {
		bodies = append(bodies, OperationReconcileSandbox)
	}
	if request.CreateVolume != nil {
		bodies = append(bodies, OperationCreateVolume)
	}
	if request.AttachVolume != nil {
		bodies = append(bodies, OperationAttachVolume)
	}
	if request.DetachVolume != nil {
		bodies = append(bodies, OperationDetachVolume)
	}
	if request.DeleteVolume != nil {
		bodies = append(bodies, OperationDeleteVolume)
	}
	if request.DeleteSnapshot != nil {
		bodies = append(bodies, OperationDeleteSnapshot)
	}
	if request.ApproveSensitive != nil {
		bodies = append(bodies, OperationApproveSensitive)
	}
	return bodies
}

func targetFor(request OperationRequest) OperationTarget {
	switch request.Kind {
	case OperationExecProcess:
		return OperationTarget{Kind: TargetSandbox, SandboxID: request.ExecProcess.SandboxID}
	case OperationCloseSandbox:
		return OperationTarget{Kind: TargetSandbox, SandboxID: request.CloseSandbox.SandboxID}
	case OperationReconcileSandbox:
		return OperationTarget{Kind: TargetSandbox, SandboxID: request.ReconcileSandbox.SandboxID}
	case OperationCopyIn:
		return OperationTarget{Kind: TargetSandbox, SandboxID: request.CopyIn.SandboxID}
	case OperationCopyOut:
		return OperationTarget{Kind: TargetSandbox, SandboxID: request.CopyOut.SandboxID}
	case OperationSnapshotSandbox:
		return OperationTarget{Kind: TargetSandbox, SandboxID: request.SnapshotSandbox.SandboxID}
	case OperationSignalProcess, OperationKillProcess:
		if request.SignalProcess != nil {
			return OperationTarget{Kind: TargetProcess, ProcessID: request.SignalProcess.ProcessID}
		}
		return OperationTarget{Kind: TargetProcess, ProcessID: request.KillProcess.ProcessID}
	case OperationCreateVolume:
		return OperationTarget{Kind: TargetNone}
	case OperationAttachVolume:
		return OperationTarget{Kind: TargetVolume, VolumeID: request.AttachVolume.VolumeID, SandboxID: request.AttachVolume.SandboxID}
	case OperationDetachVolume:
		return OperationTarget{Kind: TargetVolume, VolumeID: request.DetachVolume.VolumeID, SandboxID: request.DetachVolume.SandboxID}
	case OperationDeleteVolume:
		return OperationTarget{Kind: TargetVolume, VolumeID: request.DeleteVolume.VolumeID}
	case OperationRestoreSandbox, OperationDeleteSnapshot:
		if request.RestoreSandbox != nil {
			return OperationTarget{Kind: TargetSnapshot, SnapshotID: request.RestoreSandbox.SnapshotID}
		}
		return OperationTarget{Kind: TargetSnapshot, SnapshotID: request.DeleteSnapshot.SnapshotID}
	case OperationApproveSensitive:
		return OperationTarget{Kind: TargetOperation, OperationID: request.ApproveSensitive.SensitiveOperationID}
	default:
		return OperationTarget{Kind: TargetNone}
	}
}

func copyRequest(request OperationRequest) OperationRequest {
	frozen := request
	if request.CreateSandbox != nil {
		body := *request.CreateSandbox
		body.Spec = copySpec(body.Spec)
		frozen.CreateSandbox = &body
	}
	if request.ExecProcess != nil {
		body := *request.ExecProcess
		body.Command = copyCommand(body.Command)
		frozen.ExecProcess = &body
	}
	if request.RestoreSandbox != nil {
		body := *request.RestoreSandbox
		if body.Overrides.Resources != nil {
			limits := *body.Overrides.Resources
			body.Overrides.Resources = &limits
		}
		if body.Overrides.Capabilities != nil {
			capabilities := *body.Overrides.Capabilities
			capabilities.Required = append([]CapabilityRequirement(nil), body.Overrides.Capabilities.Required...)
			body.Overrides.Capabilities = &capabilities
		}
		frozen.RestoreSandbox = &body
	}
	if request.SignalProcess != nil {
		body := *request.SignalProcess
		frozen.SignalProcess = &body
	}
	if request.KillProcess != nil {
		body := *request.KillProcess
		frozen.KillProcess = &body
	}
	if request.CopyIn != nil {
		body := *request.CopyIn
		body.Options = copyTransferOptions(body.Options)
		frozen.CopyIn = &body
	}
	if request.CopyOut != nil {
		body := *request.CopyOut
		body.Options = copyTransferOptions(body.Options)
		frozen.CopyOut = &body
	}
	if request.SnapshotSandbox != nil {
		body := *request.SnapshotSandbox
		if body.RiskAttestation != nil {
			attestation := *body.RiskAttestation
			body.RiskAttestation = &attestation
		}
		frozen.SnapshotSandbox = &body
	}
	if request.CloseSandbox != nil {
		body := *request.CloseSandbox
		frozen.CloseSandbox = &body
	}
	if request.ReconcileSandbox != nil {
		body := *request.ReconcileSandbox
		frozen.ReconcileSandbox = &body
	}
	if request.CreateVolume != nil {
		body := *request.CreateVolume
		body.Spec.Labels = copyStringMap(body.Spec.Labels)
		frozen.CreateVolume = &body
	}
	if request.AttachVolume != nil {
		body := *request.AttachVolume
		frozen.AttachVolume = &body
	}
	if request.DetachVolume != nil {
		body := *request.DetachVolume
		frozen.DetachVolume = &body
	}
	if request.DeleteVolume != nil {
		body := *request.DeleteVolume
		frozen.DeleteVolume = &body
	}
	if request.DeleteSnapshot != nil {
		body := *request.DeleteSnapshot
		frozen.DeleteSnapshot = &body
	}
	if request.ApproveSensitive != nil {
		body := *request.ApproveSensitive
		frozen.ApproveSensitive = &body
	}
	return frozen
}

func copyTransferOptions(options TransferOptions) TransferOptions {
	copied := options
	if options.Owner != nil {
		owner := *options.Owner
		owner.Groups = append([]uint32(nil), options.Owner.Groups...)
		copied.Owner = &owner
	}
	return copied
}

func copySpec(spec SandboxSpec) SandboxSpec {
	copied := spec
	copied.Environment = copyStringMap(spec.Environment)
	copied.Labels = copyStringMap(spec.Labels)
	copied.SecretBindings = append([]SecretBinding(nil), spec.SecretBindings...)
	copied.VolumeAttachments = append([]VolumeAttachment(nil), spec.VolumeAttachments...)
	copied.Mounts = append([]MountRequest(nil), spec.Mounts...)
	copied.Tmpfs = append([]TmpfsMount(nil), spec.Tmpfs...)
	copied.Capabilities.Required = append([]CapabilityRequirement(nil), spec.Capabilities.Required...)
	return copied
}

func copyCommand(command Command) Command {
	copied := command
	copied.Argv = append([]string(nil), command.Argv...)
	copied.Environment = copyStringMap(command.Environment)
	copied.User.Groups = append([]uint32(nil), command.User.Groups...)
	copied.Grant.Secrets.Names = append([]string(nil), command.Grant.Secrets.Names...)
	copied.Grant.Mounts.Names = append([]string(nil), command.Grant.Mounts.Names...)
	copied.Grant.Network.Rules = append([]NetworkRule(nil), command.Grant.Network.Rules...)
	for index := range copied.Grant.Network.Rules {
		copied.Grant.Network.Rules[index].Ports = append([]PortRange(nil), command.Grant.Network.Rules[index].Ports...)
	}
	return copied
}

func copyStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	copied := make(map[string]string, len(input))
	for key, value := range input {
		copied[key] = value
	}
	return copied
}
func copyOperation(operation Operation) Operation {
	copied := operation
	copied.Result = copyOperationResult(operation.Result)
	copied.Failure = copyFailure(operation.Failure)
	return copied
}

func canonicalRequestDigest(request OperationRequest) Digest {
	return canonicalDigestBytes(canonicalRequestBytes(request))
}

// canonicalRequestBytes is the v1 owned representation used by the durable
// ledger. It distinguishes nil from empty, includes every tagged body, and
// sorts maps by their encoded keys. It deliberately has no Go JSON aliases or
// interface values, so later caller mutation cannot change the accepted hash.
func canonicalRequestBytes(request OperationRequest) []byte {
	encoded, err := encodeOperationRequestV1(request)
	if err != nil {
		panic("sandbox: attempted to canonicalize an invalid owned request")
	}
	return encoded
}

func canonicalDigestBytes(value []byte) Digest {
	sum := sha256.Sum256(value)
	return Digest("sha256:" + hex.EncodeToString(sum[:]))
}

func canonicalImageInfo(builder *strings.Builder, image ImageInfo) {
	canonicalField(builder, string(image.Digest))
	canonicalField(builder, image.Architecture)
	canonicalUint(builder, uint64(image.Identity.UID))
	canonicalUint(builder, uint64(image.Identity.GID))
	canonicalField(builder, strconv.Itoa(len(image.Identity.Groups)))
	for _, group := range image.Identity.Groups {
		canonicalUint(builder, uint64(group))
	}
	canonicalField(builder, image.GuestProtocol)
	canonicalField(builder, image.AdmissionPolicyVersion)
}

func canonicalResources(builder *strings.Builder, value ResourceLimits) {
	canonicalUint(builder, uint64(value.MilliCPU))
	canonicalUint(builder, value.MemoryBytes)
	canonicalUint(builder, value.RootDiskBytes)
	canonicalUint(builder, value.TmpfsBytes)
	canonicalUint(builder, uint64(value.PIDs))
	canonicalUint(builder, uint64(value.ProcessCount))
	canonicalUint(builder, uint64(value.OpenFiles))
	canonicalUint(builder, value.Inodes)
	canonicalUint(builder, value.Files)
	canonicalInt(builder, int64(value.Lifetime))
	canonicalUint(builder, value.ProducedOutputBytes)
	canonicalUint(builder, value.RetainedOutputBytes)
	canonicalUint(builder, value.TransferBytes)
	canonicalUint(builder, uint64(value.NetworkConnections))
	canonicalUint(builder, value.VolumeBytes)
	canonicalUint(builder, value.SnapshotBytes)
}

func canonicalCapabilitySnapshotDigest(snapshot CapabilitySnapshot) Digest {
	var builder strings.Builder
	canonicalField(&builder, "sandbox.capabilities/v1")
	canonicalField(&builder, snapshot.SchemaVersion)
	for _, descriptor := range []CapabilityDescriptor{
		snapshot.ControlProtocol,
		snapshot.Isolation,
		snapshot.Guest,
		snapshot.Resources,
		snapshot.Reconnect,
		snapshot.ImageAdmission,
		snapshot.Output,
		snapshot.Transfer,
		snapshot.Mounts,
		snapshot.Volumes,
		snapshot.Snapshots,
		snapshot.Egress,
		snapshot.Secrets,
	} {
		canonicalCapabilityDescriptor(&builder, descriptor)
	}
	canonicalField(&builder, strconv.Itoa(len(snapshot.Signals)))
	for _, signal := range snapshot.Signals {
		canonicalField(&builder, string(signal))
	}
	canonicalField(&builder, snapshot.Trust.TrustBundleVersion)
	canonicalField(&builder, snapshot.Trust.ControlSigningKeyID)
	canonicalField(&builder, snapshot.Trust.ControlSigningAlgorithm)
	canonicalUint(&builder, snapshot.Trust.RevocationEpoch)
	canonicalInt(&builder, snapshot.Trust.NotBefore.UnixNano())
	canonicalInt(&builder, snapshot.Trust.NotAfter.UnixNano())
	canonicalInt(&builder, int64(snapshot.Trust.RotationGrace))
	return canonicalDigestBytes([]byte(builder.String()))
}

func canonicalCapabilityDescriptor(builder *strings.Builder, descriptor CapabilityDescriptor) {
	canonicalField(builder, string(descriptor.State))
	canonicalField(builder, descriptor.ContractVersion)
	canonicalField(builder, descriptor.ConformanceVersion)
	canonicalField(builder, descriptor.DataPlane)
	canonicalField(builder, strconv.Itoa(len(descriptor.LimitPrecision)))
	for _, precision := range descriptor.LimitPrecision {
		canonicalField(builder, precision)
	}
}
func canonicalField(builder *strings.Builder, value string) {
	builder.WriteString(strconv.Itoa(len(value)))
	builder.WriteByte(':')
	builder.WriteString(value)
}
func canonicalUint(builder *strings.Builder, value uint64) {
	canonicalField(builder, strconv.FormatUint(value, 10))
}
func canonicalInt(builder *strings.Builder, value int64) {
	canonicalField(builder, strconv.FormatInt(value, 10))
}
func validOperationID(id OperationID) bool {
	return len(id) > 3 && len(id) <= 128 && strings.HasPrefix(string(id), "op_")
}
func validSandboxID(id SandboxID) bool {
	return validOpaqueID(string(id), "sbx_")
}
func validProcessID(id ProcessID) bool {
	return validOpaqueID(string(id), "prc_")
}
func validVolumeID(id VolumeID) bool {
	return validOpaqueID(string(id), "vol_")
}
func validSnapshotID(id SnapshotID) bool {
	return validOpaqueID(string(id), "snap_")
}
func validArtifactID(id ArtifactID) bool {
	return validOpaqueID(string(id), "art_")
}
func validArtifactRef(reference ArtifactRef) bool {
	return validArtifactID(reference.ID) && validMediaType(reference.MediaType) && reference.SizeBytes > 0 && validDigest(reference.Digest)
}
func validOpaqueID(id, prefix string) bool {
	return len(id) > len(prefix) && len(id) <= 128 && strings.HasPrefix(id, prefix)
}
func validDigest(digest Digest) bool {
	if len(digest) != len("sha256:")+64 || !strings.HasPrefix(string(digest), "sha256:") {
		return false
	}
	for _, character := range string(digest)[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
func validateCommand(command Command) error {
	if !validGuestPath(command.Executable) {
		return newFailure(FailureInvalidArgument, "command executable must be an absolute clean path", RetryNever)
	}
	if len(command.Argv) == 0 || command.Argv[0] == "" {
		return newFailure(FailureInvalidArgument, "command argv is required", RetryNever)
	}
	if !validGuestPath(command.WorkDir) {
		return newFailure(FailureInvalidArgument, "command work directory must be an absolute clean path", RetryNever)
	}
	if command.StartDeadline < 0 || command.RuntimeLimit < 0 {
		return newFailure(FailureInvalidArgument, "command durations cannot be negative", RetryNever)
	}
	if err := validateGrant(command.Grant); err != nil {
		return err
	}
	return nil
}

// validGuestPath accepts the portable part of a guest path at the public
// control boundary. A backend still selects its permitted root and resolves
// descriptor-relatively; this common grammar keeps ambiguous or host-like
// targets out of the durable request before that backend is involved.
func validGuestPath(value GuestPath) bool {
	raw := string(value)
	if len(raw) < 2 || len(raw) > 4096 || !path.IsAbs(raw) || path.Clean(raw) != raw || strings.ContainsRune(raw, '\\') {
		return false
	}
	for _, character := range raw {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(raw, "/"), "/")
	switch first {
	case "dev", "proc", "sys", "run":
		return false
	}
	return true
}

func validMediaType(value string) bool {
	if len(value) < 3 || len(value) > 255 || strings.Count(value, "/") != 1 || strings.ContainsAny(value, " ;\\\t\r\n") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || strings.ContainsRune("!#$&^_.+-/", character) {
			continue
		}
		return false
	}
	parts := strings.Split(value, "/")
	return parts[0] != "" && parts[1] != ""
}

func validTransferOptions(options TransferOptions) bool {
	if options.Overwrite != OverwriteFailIfExists && options.Overwrite != OverwriteAtomicReplace || uint32(options.Mode)&^uint32(0o777) != 0 {
		return false
	}
	return options.Owner == nil || (options.Owner.UID != 0 && options.Owner.GID != 0)
}

func validateGrant(grant Grant) error {
	if err := validateGrantSelection(grant.Secrets); err != nil {
		return err
	}
	if err := validateGrantSelection(grant.Mounts); err != nil {
		return err
	}
	network := grant.Network
	if network.Mode == "" || network.Mode == GrantNone {
		if len(network.Rules) != 0 {
			return newFailure(FailureNetworkGrantInvalid, "network none grant cannot contain rules", RetryNever)
		}
		return nil
	}
	if network.Mode == GrantInherit {
		if len(network.Rules) != 0 {
			return newFailure(FailureNetworkGrantInvalid, "network inherit grant cannot contain rules", RetryNever)
		}
		return nil
	}
	if network.Mode != GrantSelect || len(network.Rules) == 0 || len(network.Rules) > 64 {
		return newFailure(FailureNetworkGrantInvalid, "network select grant requires bounded rules", RetryNever)
	}
	seen := make(map[string]struct{}, len(network.Rules))
	for _, rule := range network.Rules {
		if rule.Protocol != NetworkTCP && rule.Protocol != NetworkUDP {
			return newFailure(FailureNetworkGrantInvalid, "network protocol is invalid", RetryNever)
		}
		domain := string(rule.Domain)
		if !validDomainPattern(domain) || net.ParseIP(domain) != nil {
			return newFailure(FailureNetworkGrantInvalid, "network domain cannot be a literal IP or host-port", RetryNever)
		}
		if len(rule.Ports) == 0 || len(rule.Ports) > 16 {
			return newFailure(FailureNetworkGrantInvalid, "network rule requires bounded ports", RetryNever)
		}
		last := uint16(0)
		for _, ports := range rule.Ports {
			if ports.First == 0 || ports.Last < ports.First || (last != 0 && ports.First <= last+1) {
				return newFailure(FailureNetworkGrantInvalid, "network ports are invalid", RetryNever)
			}
			last = ports.Last
		}
		key := string(rule.Protocol) + "\x00" + domain
		for _, ports := range rule.Ports {
			key += "\x00" + strconv.Itoa(int(ports.First)) + "-" + strconv.Itoa(int(ports.Last))
		}
		if _, duplicate := seen[key]; duplicate {
			return newFailure(FailureNetworkGrantInvalid, "network rule is duplicated", RetryNever)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validDomainPattern(domain string) bool {
	if domain == "" || domain != strings.ToLower(domain) || strings.HasSuffix(domain, ".") || strings.ContainsAny(domain, "/:@[]") || strings.Count(domain, ".") == 0 {
		return false
	}
	domain = strings.TrimPrefix(domain, "*.")
	if strings.Contains(domain, "*") || len(domain) > 253 {
		return false
	}
	numericOnly := true
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
			if character < '0' || character > '9' {
				numericOnly = false
			}
		}
	}
	return !numericOnly
}

func validateGrantSelection(selection GrantSelection) error {
	if selection.Mode == "" || selection.Mode == GrantNone || selection.Mode == GrantInherit {
		if len(selection.Names) != 0 {
			return newFailure(FailureGrantWideningDenied, "non-select grant cannot contain names", RetryNever)
		}
		return nil
	}
	if selection.Mode != GrantSelect || len(selection.Names) == 0 {
		return newFailure(FailureGrantWideningDenied, "select grant requires names", RetryNever)
	}
	seen := make(map[string]struct{}, len(selection.Names))
	for _, name := range selection.Names {
		if name == "" {
			return newFailure(FailureGrantWideningDenied, "grant name is empty", RetryNever)
		}
		if _, exists := seen[name]; exists {
			return newFailure(FailureGrantWideningDenied, "grant name is duplicated", RetryNever)
		}
		seen[name] = struct{}{}
	}
	return nil
}
func contextFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		if err == context.Canceled {
			return newContextFailure(FailureCancelled, "request was cancelled", err)
		}
		return newContextFailure(FailureDeadlineExceeded, "request deadline was exceeded", err)
	}
	return nil
}

func validateCanonicalStrings(value reflect.Value) error {
	if !value.IsValid() {
		return nil
	}
	if value.Type() == reflect.TypeFor[time.Time]() {
		return nil
	}
	switch value.Kind() {
	case reflect.String:
		text := value.String()
		if !utf8.ValidString(text) || strings.ContainsRune(text, 0) || !norm.NFC.IsNormalString(text) {
			return newFailure(FailureInvalidArgument, "sandbox.control/v1 strings must be NFC UTF-8 without NUL", RetryNever)
		}
	case reflect.Pointer, reflect.Interface:
		if !value.IsNil() {
			return validateCanonicalStrings(value.Elem())
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if err := validateCanonicalStrings(value.Field(index)); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := validateCanonicalStrings(value.Index(index)); err != nil {
				return err
			}
		}
	case reflect.Map:
		for _, key := range value.MapKeys() {
			if err := validateCanonicalStrings(key); err != nil {
				return err
			}
			if err := validateCanonicalStrings(value.MapIndex(key)); err != nil {
				return err
			}
		}
	}
	return nil
}
func newFailure(code FailureCode, message string, retry RetryClass) error {
	return &Error{failure: Failure{Code: code, Message: message, Retry: retry}}
}

func closedClientFailure() error {
	return newFailure(FailureUnavailable, "sandbox client is closed", RetryAfterReconcile)
}
func newContextFailure(code FailureCode, message string, cause error) error {
	return &Error{failure: Failure{Code: code, Message: message, Retry: RetryNever}, contextCause: cause}
}
