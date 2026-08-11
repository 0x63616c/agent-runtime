package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/sandbox"
)

const defaultGuestCID = 3

// JailerStartRequest is the complete immutable authority and staged-resource binding for one Jailer process.
type JailerStartRequest struct {
	Authority JailerExecutionAuthority
	Stage     JailedResourceStage
}

// JailedFixtureBinding maps one verified source identity to its path inside one Jailer chroot.
type JailedFixtureBinding struct {
	Source     PinnedArtifact
	JailedPath string
}

// JailedResourceStage records the complete, identity-bound mapping from verified sources to one Jailer chroot.
type JailedResourceStage struct {
	FixtureVersion string
	JailRoot       string
	OwnerUID       uint32
	OwnerGID       uint32
	Jailer         PinnedArtifact
	Firecracker    JailedFixtureBinding
	Kernel         JailedFixtureBinding
	RootFS         JailedFixtureBinding
	GuestAgent     PinnedArtifact
	GuestInitPath  string
	APISocketPath  string
	VSockUDSPath   string
	BindingDigest  sandbox.Digest
}

// JailerResourceStager creates one per-VM jailed resource mapping before the Jailer process starts.
type JailerResourceStager interface {
	Stage(context.Context, Plan, FixtureSet, string) (JailedResourceStage, error)
}

// JailerResourceDiscarder removes the exact fresh namespace returned by Stage when no Jailer process has taken ownership.
type JailerResourceDiscarder interface {
	Discard(context.Context, Plan, JailedResourceStage) (CleanupProof, error)
}

// JailerStarter starts the Jailer only after the host has validated every launch prerequisite.
type JailerStarter interface {
	Start(context.Context, JailerStartRequest) (JailerProcess, error)
}

// JailerProcess owns the running Jailer and its exact per-VM cleanup.
type JailerProcess interface {
	Terminate(context.Context) error
	Wait(context.Context) error
	Cleanup(context.Context) (CleanupProof, error)
}

// JailerSerialObserver observes the exact bounded serial stream owned by one started Jailer process.
type JailerSerialObserver interface {
	AwaitSerial(context.Context, string) error
}

// FirecrackerHTTPPort sends one bounded JSON request over the exact private Firecracker API socket.
type FirecrackerHTTPPort interface {
	Bind(context.Context, string) error
	Put(context.Context, string, any) error
}

// GuestControlChannel carries the private guest-control transport. Concrete
// AF_VSOCK composition remains profile-gated and unavailable until its Linux/KVM
// authority/evidence requirements are met.
type GuestControlChannel interface {
	Bind(context.Context, string) error
	Ping(context.Context, string) error
	Close(context.Context) error
}

// GuestDispatchChannel is the private guest-operation extension point. A
// production implementation may be composed only after its profile's exact
// capability has been certified; this repository currently binds no such
// implementation.
type GuestDispatchChannel interface {
	GuestControlChannel
	ExecuteDispatch(context.Context, sandboxhostprotocol.Envelope) error
}

// AuthenticatedGuestDispatchChannel carries the exact already-verified
// control-signed canonical envelope across the guest boundary.
type AuthenticatedGuestDispatchChannel interface {
	GuestDispatchChannel
	ExecuteAuthenticatedDispatch(context.Context, sandboxhostprotocol.Envelope, []byte) error
}

// AuthenticatedGuestResultChannel returns bounded authenticated guest output
// before its terminal result for a durable host-control owner.
type AuthenticatedGuestResultChannel interface {
	AuthenticatedGuestDispatchChannel
	DispatchAuthenticated(context.Context, sandboxhostprotocol.Envelope, []byte) (GuestDispatchResult, error)
}

// AuthenticatedGuestSecretChannel is the private extension that consumes a
// SecretExecutionAuthority only while an exact authenticated guest command is
// live. Implementations must not serialize Manager-held secret bytes into the
// host journal, output owner, or a new host-selected transport.
type AuthenticatedGuestSecretChannel interface {
	AuthenticatedGuestResultChannel
	DispatchAuthenticatedSecret(context.Context, sandboxhostprotocol.Envelope, []byte, *SecretExecutionAuthority, sandboxhostprotocol.GuestOutputEmitter) error
}

// AuthenticatedGuestProxyChannel is the private host-controlled egress
// extension. The host creates the exact lease session and owns DNS plus dial;
// the guest can neither substitute those dependencies nor open a tunnel.
type AuthenticatedGuestProxyChannel interface {
	AuthenticatedGuestResultChannel
	ProxyAuthenticated(context.Context, sandboxhostprotocol.Envelope, []byte, *sandboxauthority.ProxySession, time.Time, sandboxauthority.Resolver, sandboxauthority.Dialer) (GuestDispatchResult, error)
}

// LinuxJailerHost is the Linux/KVM-only SmokeHost adapter composed from real host ports.
type LinuxJailerHost struct {
	PreflightState KVMPreflight
	RootFSCopyPath string
	Resources      JailerResourceStager
	Authority      JailerExecutionAuthority
	Jailer         JailerStarter
	HTTP           FirecrackerHTTPPort
	Guest          GuestControlChannel

	mu                   sync.Mutex
	preflight            bool
	preparing            bool
	prepared             bool
	launching            bool
	launched             bool
	cleaning             bool
	cleaned              bool
	process              JailerProcess
	configured           bool
	configuredPlan       Plan
	secretContainment    SecretContainmentManifest
	hasSecretContainment bool
	noRouteProxy         NoRouteProxyTopologyManifest
	hasNoRouteProxy      bool
	plan                 Plan
	fixtures             FixtureSet
	authority            JailerExecutionAuthority
	request              LaunchRequest
	stage                JailedResourceStage
	serial               JailerSerialObserver
	launchDone           chan struct{}
	prepareDone          chan struct{}
	cleanupDone          chan struct{}
	cleanupProof         CleanupProof
	cleanupErr           error
}

// SecretContainmentManifest returns the fixed unavailable-profile launch
// configuration when the host was explicitly composed with one. It is only a
// configuration/refusal record: callers must not interpret it as proof that a
// guest mounted the area or `/proc`, created the cgroup, excluded snapshots,
// or enforced ptrace isolation.
func (host *LinuxJailerHost) SecretContainmentManifest() (SecretContainmentManifest, bool) {
	if host == nil {
		return SecretContainmentManifest{}, false
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.hasSecretContainment {
		return SecretContainmentManifest{}, false
	}
	return cloneSecretContainmentManifest(host.secretContainment), true
}

// NoRouteProxyTopologyManifest returns the fixed unavailable-profile topology
// configuration when the host was explicitly composed with one. It is not
// evidence of an applied no-NIC/no-route guest topology or permitted egress.
func (host *LinuxJailerHost) NoRouteProxyTopologyManifest() (NoRouteProxyTopologyManifest, bool) {
	if host == nil {
		return NoRouteProxyTopologyManifest{}, false
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.hasNoRouteProxy {
		return NoRouteProxyTopologyManifest{}, false
	}
	return host.noRouteProxy, true
}

// ExecuteDispatch is the only Firecracker handoff for an already authenticated
// and fenced host envelope. It fails closed while every Firecracker authority
// descriptor remains unavailable and never lets a guest select capabilities.
func (host *LinuxJailerHost) ExecuteDispatch(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if host == nil || envelope.HostID == "" || envelope.AssignmentID == "" || envelope.FencingToken == 0 || envelope.CapabilityDigest == "" {
		return fmt.Errorf("%w: authenticated fenced host envelope is required", ErrCapabilityUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, plan, guest := host.launched, host.cleaning || host.cleaned, cloneLinuxJailerPlan(host.plan), host.Guest
	host.mu.Unlock()
	if !launched || cleaning || !validCompiledPlan(plan) || envelope.SandboxID != plan.VMID() || sandbox.Digest(envelope.CapabilityDigest) != plan.Capabilities().Digest {
		return fmt.Errorf("%w: launch state and exact capability digest are required", ErrCapabilityUnavailable)
	}
	if firecrackerProfilesUnavailable(plan.Capabilities()) {
		return fmt.Errorf("%w: no certified Firecracker guest authority profile is active", ErrCapabilityUnavailable)
	}
	dispatch, ok := guest.(GuestDispatchChannel)
	if !ok {
		return fmt.Errorf("%w: certified guest dispatch channel is not composed", ErrCapabilityUnavailable)
	}
	return dispatch.ExecuteDispatch(ctx, envelope)
}

// ExecuteAuthenticatedDispatch is the host-process-only guest path. It uses
// the exact control-signed wire retained through verification so the private
// guest frame cannot be rebound to a different lease-fenced envelope.
func (host *LinuxJailerHost) ExecuteAuthenticatedDispatch(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte) error {
	_, err := host.DispatchAuthenticated(ctx, envelope, authenticatedEnvelope)
	return err
}

// DispatchAuthenticated returns only the bounded result/output exchange from
// the exact launched guest. It remains unavailable until protected profile
// evidence permits real guest execution.
func (host *LinuxJailerHost) DispatchAuthenticated(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte) (GuestDispatchResult, error) {
	if err := contextError(ctx); err != nil {
		return GuestDispatchResult{}, err
	}
	if host == nil || len(authenticatedEnvelope) == 0 || envelope.HostID == "" || envelope.AssignmentID == "" || envelope.FencingToken == 0 || envelope.CapabilityDigest == "" {
		return GuestDispatchResult{}, fmt.Errorf("%w: authenticated fenced host envelope is required", ErrCapabilityUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, plan, guest := host.launched, host.cleaning || host.cleaned, cloneLinuxJailerPlan(host.plan), host.Guest
	host.mu.Unlock()
	if !launched || cleaning || !validCompiledPlan(plan) || envelope.SandboxID != plan.VMID() || sandbox.Digest(envelope.CapabilityDigest) != plan.Capabilities().Digest || firecrackerProfilesUnavailable(plan.Capabilities()) {
		return GuestDispatchResult{}, fmt.Errorf("%w: launch state, exact capability digest, and certified guest profile are required", ErrCapabilityUnavailable)
	}
	dispatch, ok := guest.(AuthenticatedGuestResultChannel)
	if !ok {
		return GuestDispatchResult{}, fmt.Errorf("%w: authenticated guest result channel is not composed", ErrCapabilityUnavailable)
	}
	return dispatch.DispatchAuthenticated(ctx, envelope, authenticatedEnvelope)
}

// DispatchAuthenticatedSecret is the only future Firecracker secret-command
// composition door. It remains unavailable until the same protected profile
// can prove guest PID/FD/proc/ptrace/tree-reap containment.
func (host *LinuxJailerHost) DispatchAuthenticatedSecret(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, authority *SecretExecutionAuthority, emit sandboxhostprotocol.GuestOutputEmitter) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if host == nil || authority == nil || emit == nil || len(authenticatedEnvelope) == 0 || envelope.OperationKind != GuestSecretCommandOperationKind || envelope.HostID == "" || envelope.AssignmentID == "" || envelope.FencingToken == 0 || envelope.CapabilityDigest == "" {
		return fmt.Errorf("%w: authenticated fenced secret command is required", ErrCapabilityUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, plan, guest, containment, hasContainment, boundAuthority := host.launched, host.cleaning || host.cleaned, cloneLinuxJailerPlan(host.plan), host.Guest, cloneSecretContainmentManifest(host.secretContainment), host.hasSecretContainment, cloneJailerExecutionAuthority(host.authority)
	host.mu.Unlock()
	if !launched || cleaning || !validCompiledPlan(plan) || envelope.SandboxID != plan.VMID() || sandbox.Digest(envelope.CapabilityDigest) != plan.Capabilities().Digest || !hasContainment || !validSecretContainmentManifest(containment, plan, boundAuthority) || firecrackerProfilesUnavailable(plan.Capabilities()) {
		return fmt.Errorf("%w: certified secret profile is unavailable", ErrCapabilityUnavailable)
	}
	channel, ok := guest.(AuthenticatedGuestSecretChannel)
	if !ok {
		return fmt.Errorf("%w: certified secret guest channel is not composed", ErrCapabilityUnavailable)
	}
	return channel.DispatchAuthenticatedSecret(ctx, envelope, authenticatedEnvelope, authority, emit)
}

// DispatchAuthenticatedProxy is the only future egress composition door. It
// accepts a narrow host-control issuer which must bind the same no-route
// topology, plan, lease, DNS request, and fence before it can create a session.
// It remains unavailable until the no-route profile has protected evidence.
func (host *LinuxJailerHost) DispatchAuthenticatedProxy(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, issuer *ProxyAuthorityIssuer) (GuestDispatchResult, error) {
	if err := contextError(ctx); err != nil {
		return GuestDispatchResult{}, err
	}
	if host == nil || issuer == nil || len(authenticatedEnvelope) == 0 || envelope.OperationKind != GuestProxyOperationKind || envelope.HostID == "" || envelope.AssignmentID == "" || envelope.FencingToken == 0 || envelope.CapabilityDigest == "" {
		return GuestDispatchResult{}, fmt.Errorf("%w: authenticated fenced proxy command is required", ErrCapabilityUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, plan, guest, topology, hasTopology, boundAuthority := host.launched, host.cleaning || host.cleaned, cloneLinuxJailerPlan(host.plan), host.Guest, host.noRouteProxy, host.hasNoRouteProxy, cloneJailerExecutionAuthority(host.authority)
	host.mu.Unlock()
	if !launched || cleaning || !validCompiledPlan(plan) || envelope.SandboxID != plan.VMID() || sandbox.Digest(envelope.CapabilityDigest) != plan.Capabilities().Digest || !hasTopology || !validNoRouteProxyTopologyManifest(topology, plan, boundAuthority) || !issuer.BoundTo(plan, boundAuthority, topology) || firecrackerProfilesUnavailable(plan.Capabilities()) {
		return GuestDispatchResult{}, fmt.Errorf("%w: certified mandatory-proxy profile is unavailable", ErrCapabilityUnavailable)
	}
	channel, ok := guest.(AuthenticatedGuestProxyChannel)
	if !ok {
		return GuestDispatchResult{}, fmt.Errorf("%w: certified proxy guest channel is not composed", ErrCapabilityUnavailable)
	}
	authority, err := issuer.Issue(envelope, authenticatedEnvelope)
	if err != nil {
		return GuestDispatchResult{}, err
	}
	session, err := authority.Begin(envelope)
	if err != nil {
		return GuestDispatchResult{}, err
	}
	defer session.Close(context.Background())
	return channel.ProxyAuthenticated(ctx, envelope, authenticatedEnvelope, session, authority.now(), authority.resolve(), authority.dial())
}

// DispatchAuthenticatedTransfer is the future profile-gated bridge from an
// exact authenticated host envelope into a descriptor-rooted transfer
// authority. It has no host-share or raw-byte API and stays unavailable until
// a protected guest profile has the exact evidence to consume it.
func (host *LinuxJailerHost) DispatchAuthenticatedTransfer(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, authority *TransferExecutionAuthority, emit TransferReceiptEmitter) (TransferReceipt, error) {
	if err := contextError(ctx); err != nil {
		return TransferReceipt{}, err
	}
	if host == nil || authority == nil || emit == nil || len(authenticatedEnvelope) == 0 || envelope.OperationKind != GuestTransferOperationKind || envelope.HostID == "" || envelope.AssignmentID == "" || envelope.FencingToken == 0 || envelope.CapabilityDigest == "" {
		return TransferReceipt{}, fmt.Errorf("%w: authenticated fenced transfer command is required", ErrCapabilityUnavailable)
	}
	if err := sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope); err != nil {
		return TransferReceipt{}, fmt.Errorf("%w: exact authenticated transfer envelope is required", ErrCapabilityUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, plan := host.launched, host.cleaning || host.cleaned, cloneLinuxJailerPlan(host.plan)
	host.mu.Unlock()
	if !launched || cleaning || !validCompiledPlan(plan) || envelope.SandboxID != plan.VMID() || sandbox.Digest(envelope.CapabilityDigest) != plan.Capabilities().Digest || firecrackerProfilesUnavailable(plan.Capabilities()) {
		return TransferReceipt{}, fmt.Errorf("%w: certified descriptor-rooted transfer profile is unavailable", ErrCapabilityUnavailable)
	}
	return authority.Execute(ctx, envelope, emit)
}

// DispatchAuthenticatedSnapshotRestore is the profile-gated private resource
// restore bridge. It can move only a verified store reader into its fixed sink
// and returns only a durable snapshot identity receipt.
func (host *LinuxJailerHost) DispatchAuthenticatedSnapshotRestore(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, authority *SnapshotRestoreExecutionAuthority, emit TransferReceiptEmitter) (TransferReceipt, error) {
	if err := contextError(ctx); err != nil {
		return TransferReceipt{}, err
	}
	if host == nil || authority == nil || emit == nil || len(authenticatedEnvelope) == 0 || envelope.OperationKind != GuestSnapshotRestoreOperationKind || envelope.HostID == "" || envelope.AssignmentID == "" || envelope.FencingToken == 0 || envelope.CapabilityDigest == "" {
		return TransferReceipt{}, fmt.Errorf("%w: authenticated fenced snapshot restore is required", ErrCapabilityUnavailable)
	}
	if err := sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope); err != nil {
		return TransferReceipt{}, fmt.Errorf("%w: exact authenticated snapshot restore envelope is required", ErrCapabilityUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, plan := host.launched, host.cleaning || host.cleaned, cloneLinuxJailerPlan(host.plan)
	host.mu.Unlock()
	if !launched || cleaning || !validCompiledPlan(plan) || envelope.SandboxID != plan.VMID() || sandbox.Digest(envelope.CapabilityDigest) != plan.Capabilities().Digest || firecrackerProfilesUnavailable(plan.Capabilities()) {
		return TransferReceipt{}, fmt.Errorf("%w: certified snapshot restore profile is unavailable", ErrCapabilityUnavailable)
	}
	return authority.Execute(ctx, envelope, emit)
}

// DispatchAuthenticatedMount is the future profile-gated path from a verified
// host envelope to the strict sharing daemon authority. It rejects all mounts
// until the exact jailed daemon and protected no-escape proof are available.
func (host *LinuxJailerHost) DispatchAuthenticatedMount(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, authority *MountExecutionAuthority, emit MountReceiptEmitter) (MountReceipt, error) {
	if err := contextError(ctx); err != nil {
		return MountReceipt{}, err
	}
	if host == nil || authority == nil || emit == nil || len(authenticatedEnvelope) == 0 || envelope.OperationKind != GuestMountOperationKind || envelope.HostID == "" || envelope.AssignmentID == "" || envelope.FencingToken == 0 || envelope.CapabilityDigest == "" {
		return MountReceipt{}, fmt.Errorf("%w: authenticated fenced mount command is required", ErrCapabilityUnavailable)
	}
	if err := sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope); err != nil {
		return MountReceipt{}, fmt.Errorf("%w: exact authenticated mount envelope is required", ErrCapabilityUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, plan := host.launched, host.cleaning || host.cleaned, cloneLinuxJailerPlan(host.plan)
	host.mu.Unlock()
	if !launched || cleaning || !validCompiledPlan(plan) || envelope.SandboxID != plan.VMID() || sandbox.Digest(envelope.CapabilityDigest) != plan.Capabilities().Digest || firecrackerProfilesUnavailable(plan.Capabilities()) {
		return MountReceipt{}, fmt.Errorf("%w: certified jailed sharing profile is unavailable", ErrCapabilityUnavailable)
	}
	return authority.Execute(ctx, envelope, emit)
}

// CancelDispatch forwards a lease-fenced cancellation only to the exact
// running guest selected by the immutable compiled plan. It is intentionally
// unavailable until a future certified guest profile composes a cancellation
// channel; cleanup still closes the whole channel before reaping the Jailer.
func (host *LinuxJailerHost) CancelDispatch(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if host == nil || envelope.EnvelopeID == "" || envelope.FencingToken == 0 {
		return fmt.Errorf("%w: authenticated fenced guest cancellation is required", ErrCapabilityUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, plan, guest := host.launched, host.cleaning || host.cleaned, cloneLinuxJailerPlan(host.plan), host.Guest
	host.mu.Unlock()
	if !launched || cleaning || !validCompiledPlan(plan) || envelope.SandboxID != plan.VMID() || firecrackerProfilesUnavailable(plan.Capabilities()) {
		return fmt.Errorf("%w: certified Firecracker guest cancellation is unavailable", ErrCapabilityUnavailable)
	}
	canceller, ok := guest.(GuestDispatchCanceller)
	if !ok {
		return fmt.Errorf("%w: certified guest cancellation channel is not composed", ErrCapabilityUnavailable)
	}
	return canceller.CancelDispatch(ctx, envelope)
}

func firecrackerProfilesUnavailable(snapshot sandbox.CapabilitySnapshot) bool {
	for _, descriptor := range []sandbox.CapabilityDescriptor{snapshot.Isolation, snapshot.Transfer, snapshot.Mounts, snapshot.Volumes, snapshot.Snapshots, snapshot.Egress, snapshot.Secrets} {
		if descriptor.State != sandbox.CapabilityUnavailable {
			return false
		}
	}
	return true
}

type firecrackerMachineConfig struct {
	VCPUCount uint32 `json:"vcpu_count"`
	MemoryMiB uint32 `json:"mem_size_mib"`
	SMT       bool   `json:"smt"`
}

type firecrackerBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type firecrackerRootDrive struct {
	DriveID    string `json:"drive_id"`
	PathOnHost string `json:"path_on_host"`
	RootDevice bool   `json:"is_root_device"`
	ReadOnly   bool   `json:"is_read_only"`
}

type firecrackerVSock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

type firecrackerAction struct {
	ActionType string `json:"action_type"`
}

// Preflight rejects all missing Linux/KVM, fixture, plan, resource-stage, and port prerequisites before launch.
func (host *LinuxJailerHost) Preflight(ctx context.Context, plan Plan, fixtures FixtureSet) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if host == nil || host.Resources == nil || host.Jailer == nil || host.HTTP == nil || !safeAbsolutePath(host.RootFSCopyPath) || !validCompiledPlan(plan) || !validJailerExecutionAuthority(host.Authority, plan) || !fixturesMatchPlan(fixtures, plan) || (host.configured && !sameConfiguredLinuxJailerPlan(host.configuredPlan, plan)) {
		return fmt.Errorf("%w: Linux Jailer ports, resource stage, private rootfs copy, compiled plan, and verified fixtures are required", ErrSmokeUnavailable)
	}
	if err := host.PreflightState.Validate(); err != nil {
		return err
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.preflight || host.prepared || host.launching || host.launched || host.process != nil || host.cleaned {
		return fmt.Errorf("%w: Linux Jailer host is single-use", ErrSmokeUnavailable)
	}
	host.preflight = true
	host.authority = cloneJailerExecutionAuthority(host.Authority)
	host.plan = cloneLinuxJailerPlan(plan)
	host.fixtures = cloneLinuxJailerFixtureSet(fixtures)
	return nil
}

// Prepare stages one verified jailed mapping and binds the verified fixture version and VM ID into init arguments.
func (host *LinuxJailerHost) Prepare(ctx context.Context, plan Plan, fixtures FixtureSet) (LaunchRequest, error) {
	if err := contextError(ctx); err != nil {
		return LaunchRequest{}, err
	}
	if host == nil || !validCompiledPlan(plan) || !fixturesMatchPlan(fixtures, plan) {
		return LaunchRequest{}, fmt.Errorf("%w: compiled plan and verified fixtures are required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	if !host.preflight || host.preparing || host.prepared || host.launching || host.launched || host.process != nil || host.cleaned || !sameConfiguredLinuxJailerPlan(host.plan, plan) || !sameLinuxJailerFixtureSet(host.fixtures, fixtures) {
		host.mu.Unlock()
		return LaunchRequest{}, fmt.Errorf("%w: successful preflight bound to the exact compiled plan and verified fixtures is required", ErrSmokeUnavailable)
	}
	stager := host.Resources
	rootFSCopyPath := host.RootFSCopyPath
	boundPlan := cloneLinuxJailerPlan(host.plan)
	boundFixtures := cloneLinuxJailerFixtureSet(host.fixtures)
	host.preparing = true
	host.prepareDone = make(chan struct{})
	host.mu.Unlock()
	defer host.finishPrepare()
	stage, err := stager.Stage(ctx, boundPlan, boundFixtures, rootFSCopyPath)
	if err != nil {
		return LaunchRequest{}, fmt.Errorf("stage jailed resources: %w", err)
	}
	if !validJailedResourceStage(stage, boundPlan, boundFixtures, rootFSCopyPath) {
		return LaunchRequest{}, host.discardStagedResources(stager, boundPlan, stage, fmt.Errorf("%w: exact fixture-bound jailed kernel, root drive, API socket, and vsock paths are required", ErrSmokeUnavailable))
	}
	if err := contextError(ctx); err != nil {
		return LaunchRequest{}, host.discardStagedResources(stager, boundPlan, stage, err)
	}
	request, err := NewLaunchRequest(boundPlan, rootFSCopyPath, BootInput{VMID: boundPlan.VMID(), FixtureVersion: boundFixtures.FixtureVersion()})
	if err != nil {
		return LaunchRequest{}, err
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.preflight || !host.preparing || host.prepared || host.launching || host.launched || host.process != nil || host.cleaned {
		return LaunchRequest{}, fmt.Errorf("%w: Linux Jailer host changed during preparation", ErrSmokeUnavailable)
	}
	host.request = cloneLaunchRequest(request)
	host.plan = boundPlan
	host.stage = stage
	host.prepared = true
	return cloneLaunchRequest(request), nil
}

// Launch starts the Jailer and configures only the no-NIC Firecracker REST sequence.
func (host *LinuxJailerHost) Launch(ctx context.Context, request LaunchRequest) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if host == nil {
		return fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	if !host.preflight || !host.prepared || host.launching || host.launched || host.process != nil || host.cleaned || !sameLaunchRequest(request, host.request) || !validLinuxLaunchRequest(request) || request.JailerPath != host.plan.Jailer().Path || request.JailerPath != host.stage.Jailer.Path || !sameStrings(request.JailerArguments, host.plan.JailerArguments()) || jailerArgumentValue(request.JailerArguments, "--exec-file") != host.stage.Firecracker.Source.Path {
		host.mu.Unlock()
		return fmt.Errorf("%w: preflight-bound immutable launch request is required", ErrSmokeUnavailable)
	}
	host.launching = true
	host.launchDone = make(chan struct{})
	startRequest := JailerStartRequest{Authority: cloneJailerExecutionAuthority(host.authority), Stage: host.stage}
	jailer, http, guest, stage, plan, authority := host.Jailer, host.HTTP, host.Guest, host.stage, host.plan, host.authority
	host.mu.Unlock()
	if !validJailerExecutionAuthority(authority, plan) {
		return host.failLaunch(fmt.Errorf("%w: preflight-bound Jailer execution authority is required", ErrSmokeUnavailable))
	}

	if err := contextError(ctx); err != nil {
		return host.failLaunch(err)
	}
	process, startErr := jailer.Start(ctx, startRequest)
	if process != nil {
		host.mu.Lock()
		host.process = process
		host.mu.Unlock()
	}
	if err := contextError(ctx); err != nil {
		return host.failLaunch(err)
	}
	if startErr != nil || process == nil {
		return host.failLaunch(fmt.Errorf("start Jailer: %w", errors.Join(startErr, missingJailerProcess(process))))
	}
	serial, ok := process.(JailerSerialObserver)
	if !ok {
		return host.failLaunch(fmt.Errorf("%w: started Jailer serial observer is required", ErrSmokeUnavailable))
	}
	host.mu.Lock()
	host.serial = serial
	host.mu.Unlock()
	if err := callWithContextFence(ctx, "bind Firecracker API socket", func(callCtx context.Context) error {
		return http.Bind(callCtx, hostJailedPath(stage.JailRoot, stage.APISocketPath))
	}); err != nil {
		return host.failLaunch(err)
	}
	if guest != nil {
		if identity, ok := guest.(GuestIdentityBinder); ok {
			if err := callWithContextFence(ctx, "bind guest identity", func(callCtx context.Context) error {
				return identity.BindGuestIdentity(callCtx, request.Boot.VMID, stage.FixtureVersion)
			}); err != nil {
				return host.failLaunch(err)
			}
		}
		if err := callWithContextFence(ctx, "bind guest control", func(callCtx context.Context) error {
			return guest.Bind(callCtx, hostJailedPath(stage.JailRoot, stage.VSockUDSPath))
		}); err != nil {
			return host.failLaunch(err)
		}
	}
	for _, call := range []struct {
		path string
		body any
	}{
		{path: "/machine-config", body: firecrackerMachineConfig{VCPUCount: plan.Machine().VCPUCount, MemoryMiB: plan.Machine().MemoryMiB, SMT: false}},
		{path: "/boot-source", body: firecrackerBootSource{KernelImagePath: stage.Kernel.JailedPath, BootArgs: strings.Join(request.KernelArguments, " ")}},
		{path: "/drives/rootfs", body: firecrackerRootDrive{DriveID: "rootfs", PathOnHost: stage.RootFS.JailedPath, RootDevice: true, ReadOnly: false}},
		{path: "/vsock", body: firecrackerVSock{GuestCID: defaultGuestCID, UDSPath: stage.VSockUDSPath}},
		{path: "/actions", body: firecrackerAction{ActionType: "InstanceStart"}},
	} {
		if err := callWithContextFence(ctx, "configure Firecracker "+call.path, func(callCtx context.Context) error { return http.Put(callCtx, call.path, call.body) }); err != nil {
			return host.failLaunch(err)
		}
	}
	host.finishLaunch(true)
	return nil
}

// AwaitSerial observes the exact immutable guest marker through the injected guest channel.
func (host *LinuxJailerHost) AwaitSerial(ctx context.Context, marker string) error {
	if host == nil {
		return fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, cleaned, request, serial := host.launched, host.cleaning, host.cleaned, cloneLaunchRequest(host.request), host.serial
	host.mu.Unlock()
	if !launched || cleaning || cleaned || marker != request.SerialMarker {
		return fmt.Errorf("%w: launched immutable serial marker is required", ErrSmokeUnavailable)
	}
	if serial == nil {
		return host.abortAfterStart(fmt.Errorf("%w: started Jailer serial observer is required", ErrSmokeUnavailable))
	}
	if err := callWithContextFence(ctx, "await guest serial marker", func(callCtx context.Context) error { return serial.AwaitSerial(callCtx, marker) }); err != nil {
		return host.abortAfterStart(err)
	}
	return nil
}

// Control sends the guest protocol's bounded PING through the injected private vsock channel.
func (host *LinuxJailerHost) Control(ctx context.Context) error {
	if host == nil {
		return fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, cleaned, request, guest := host.launched, host.cleaning, host.cleaned, cloneLaunchRequest(host.request), host.Guest
	host.mu.Unlock()
	if !launched || cleaning || cleaned || guest == nil {
		return fmt.Errorf("%w: launched guest channel is required", ErrSmokeUnavailable)
	}
	if err := callWithContextFence(ctx, "control guest vsock", func(callCtx context.Context) error { return guest.Ping(callCtx, request.Boot.VMID) }); err != nil {
		return host.abortAfterStart(err)
	}
	return nil
}

// Cleanup closes guest control and delegates Jailer termination, wait, and exact resource proof to the process port.
func (host *LinuxJailerHost) Cleanup(ctx context.Context) (CleanupProof, error) {
	if host == nil {
		return CleanupProof{Reason: "Linux Jailer host is absent"}, fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	if err := contextError(ctx); err != nil {
		return CleanupProof{Reason: "cleanup context is cancelled"}, err
	}
	for {
		host.mu.Lock()
		if host.cleaned {
			proof, err := host.cleanupProof, host.cleanupErr
			host.mu.Unlock()
			return proof, err
		}
		if host.cleaning {
			done := host.cleanupDone
			host.mu.Unlock()
			select {
			case <-ctx.Done():
				return CleanupProof{Reason: "cleanup waited for concurrent cleanup"}, ctx.Err()
			case <-done:
				continue
			}
		}
		if host.launching {
			done := host.launchDone
			host.mu.Unlock()
			select {
			case <-ctx.Done():
				return CleanupProof{Reason: "cleanup waited for launch cancellation"}, ctx.Err()
			case <-done:
				continue
			}
		}
		if host.preparing {
			done := host.prepareDone
			host.mu.Unlock()
			select {
			case <-ctx.Done():
				return CleanupProof{Reason: "cleanup waited for preparation cancellation"}, ctx.Err()
			case <-done:
				continue
			}
		}
		process, guest := host.process, host.Guest
		host.process = nil
		host.cleaning = true
		host.cleanupDone = make(chan struct{})
		host.mu.Unlock()
		if process == nil {
			proof := CleanupProof{Proved: true}
			host.storeCleanup(proof, nil)
			return proof, nil
		}
		var cleanupErr error
		if guest != nil {
			if err := callWithContextFence(ctx, "close guest control", guest.Close); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
			}
		}
		if err := callWithContextFence(ctx, "terminate Jailer", process.Terminate); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
		if err := callWithContextFence(ctx, "wait for Jailer", process.Wait); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
		proof := CleanupProof{}
		if err := contextError(ctx); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("clean Jailer resources before I/O: %w", err))
		} else {
			var processErr error
			proof, processErr = process.Cleanup(ctx)
			cleanupErr = errors.Join(cleanupErr, processErr)
			if err := contextError(ctx); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("clean Jailer resources after I/O: %w", err))
			}
		}
		if cleanupErr != nil {
			proof.Proved = false
			if proof.Reason == "" {
				proof.Reason = "Jailer cleanup did not complete"
			}
		}
		host.storeCleanup(proof, cleanupErr)
		return proof, cleanupErr
	}
}

func (host *LinuxJailerHost) failLaunch(err error) error {
	host.finishLaunch(false)
	return host.abortAfterStart(err)
}

func (host *LinuxJailerHost) abortAfterStart(err error) error {
	cleanupContext, cancel := context.WithTimeout(context.Background(), maximumCleanupTimeout)
	defer cancel()
	_, cleanupErr := host.Cleanup(cleanupContext)
	return errors.Join(err, cleanupErr)
}

func (host *LinuxJailerHost) finishLaunch(launched bool) {
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.launching {
		return
	}
	host.launching = false
	host.launched = launched
	close(host.launchDone)
}

func (host *LinuxJailerHost) storeCleanup(proof CleanupProof, err error) {
	host.mu.Lock()
	host.cleanupProof = proof
	host.cleanupErr = err
	host.cleaning = false
	host.cleaned = true
	close(host.cleanupDone)
	host.mu.Unlock()
}

func (host *LinuxJailerHost) finishPrepare() {
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.preparing {
		return
	}
	host.preparing = false
	close(host.prepareDone)
}

func (host *LinuxJailerHost) discardStagedResources(stager JailerResourceStager, plan Plan, stage JailedResourceStage, cause error) error {
	proof := CleanupProof{Reason: "staged Jailer namespace cleanup did not complete"}
	discarder, ok := stager.(JailerResourceDiscarder)
	var cleanupErr error
	if !ok {
		cleanupErr = fmt.Errorf("%w: staged Jailer namespace has no discard authority", ErrSmokeUnavailable)
	} else {
		cleanupContext, cancel := context.WithTimeout(context.Background(), maximumCleanupTimeout)
		proof, cleanupErr = discarder.Discard(cleanupContext, plan, stage)
		cancel()
		if cleanupErr == nil && (!proof.Proved || len(proof.Removed) != 1 || proof.Removed[0] != filepath.Dir(expectedJailRoot(plan))) {
			cleanupErr = fmt.Errorf("%w: staged Jailer namespace discard did not prove the exact VM namespace", ErrSmokeUnavailable)
		}
	}
	if cleanupErr != nil {
		proof.Proved = false
		if proof.Reason == "" {
			proof.Reason = "staged Jailer namespace cleanup did not complete"
		}
	}
	host.mu.Lock()
	host.cleaning = true
	host.cleanupDone = make(chan struct{})
	host.mu.Unlock()
	host.storeCleanup(proof, cleanupErr)
	return errors.Join(cause, cleanupErr)
}

func (stage JailedResourceStage) bindingDigest() sandbox.Digest {
	identity := struct {
		FixtureVersion string
		JailRoot       string
		OwnerUID       uint32
		OwnerGID       uint32
		Jailer         PinnedArtifact
		Firecracker    JailedFixtureBinding
		Kernel         JailedFixtureBinding
		RootFS         JailedFixtureBinding
		GuestAgent     PinnedArtifact
		GuestInitPath  string
		APISocketPath  string
		VSockUDSPath   string
	}{
		FixtureVersion: stage.FixtureVersion,
		JailRoot:       stage.JailRoot,
		OwnerUID:       stage.OwnerUID,
		OwnerGID:       stage.OwnerGID,
		Jailer:         stage.Jailer,
		Firecracker:    stage.Firecracker,
		Kernel:         stage.Kernel,
		RootFS:         stage.RootFS,
		GuestAgent:     stage.GuestAgent,
		GuestInitPath:  stage.GuestInitPath,
		APISocketPath:  stage.APISocketPath,
		VSockUDSPath:   stage.VSockUDSPath,
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return ""
	}
	return digest(encoded)
}

func validJailedResourceStage(stage JailedResourceStage, plan Plan, fixtures FixtureSet, rootFSCopyPath string) bool {
	if stage.FixtureVersion != fixtures.FixtureVersion() || stage.JailRoot != expectedJailRoot(plan) || stage.OwnerUID != plan.UID() || stage.OwnerGID != plan.GID() || stage.Jailer != plan.Jailer() || stage.Firecracker.Source != plan.Firecracker() || stage.Kernel.Source != plan.Kernel() || stage.RootFS.Source != (PinnedArtifact{Path: rootFSCopyPath, Digest: plan.RootFS().Digest}) || stage.GuestAgent != plan.GuestAgent() || stage.GuestInitPath != "/sbin/init" || stage.APISocketPath != jailedAPISocketPath(plan.JailerArguments()) || stage.BindingDigest != stage.bindingDigest() {
		return false
	}
	paths := []string{stage.Firecracker.JailedPath, stage.Kernel.JailedPath, stage.RootFS.JailedPath, stage.APISocketPath, stage.VSockUDSPath}
	for left, candidate := range paths {
		if !safeAbsolutePath(candidate) || !jailDestinationContained(stage.JailRoot, candidate) {
			return false
		}
		for right := 0; right < left; right++ {
			if candidate == paths[right] {
				return false
			}
		}
	}
	return true
}

func expectedJailRoot(plan Plan) string {
	base := jailerArgumentValue(plan.JailerArguments(), "--chroot-base-dir")
	executableName := filepath.Base(plan.Firecracker().Path)
	if !safeAbsolutePath(base) || executableName == "." || executableName == string(filepath.Separator) {
		return ""
	}
	return filepath.Join(base, executableName, plan.VMID(), "root")
}

func jailDestinationContained(root, jailedPath string) bool {
	if !safeAbsolutePath(root) || !safeAbsolutePath(jailedPath) {
		return false
	}
	destination := filepath.Join(root, strings.TrimPrefix(jailedPath, "/"))
	relative, err := filepath.Rel(root, destination)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func jailedAPISocketPath(arguments []string) string {
	return jailerArgumentValue(arguments, "--api-sock")
}

func jailerArgumentValue(arguments []string, name string) string {
	for index := range arguments {
		if arguments[index] == name && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

func validLinuxLaunchRequest(request LaunchRequest) bool {
	return safeAbsolutePath(request.JailerPath) && len(request.JailerArguments) > 0 && safeAbsolutePath(request.RootFSCopyPath) && request.CgroupVersion == 2 && request.NetworkInterfaces == 0 && validBootInput(request.Boot) && request.SerialMarker == request.Boot.serialMarker() && sameStrings(request.KernelArguments, request.Boot.KernelArguments())
}

func sameLaunchRequest(left, right LaunchRequest) bool {
	return left.JailerPath == right.JailerPath && sameStrings(left.JailerArguments, right.JailerArguments) && left.RootFSCopyPath == right.RootFSCopyPath && left.CgroupVersion == right.CgroupVersion && left.NetworkInterfaces == right.NetworkInterfaces && left.SerialMarker == right.SerialMarker && left.Boot == right.Boot && sameStrings(left.KernelArguments, right.KernelArguments)
}

func cloneLaunchRequest(request LaunchRequest) LaunchRequest {
	request.JailerArguments = append([]string(nil), request.JailerArguments...)
	request.KernelArguments = append([]string(nil), request.KernelArguments...)
	return request
}

func cloneJailerExecutionAuthority(authority JailerExecutionAuthority) JailerExecutionAuthority {
	authority.arguments = append([]string(nil), authority.arguments...)
	authority.external = append([]ExternalJailerLimitOwner(nil), authority.external...)
	return authority
}

func cloneLinuxJailerPlan(plan Plan) Plan {
	plan.jailerArguments = append([]string(nil), plan.jailerArguments...)
	plan.network.Allowlist = append([]string(nil), plan.network.Allowlist...)
	plan.capabilities = plan.Capabilities()
	return plan
}

func sameConfiguredLinuxJailerPlan(left, right Plan) bool {
	return left.vmID == right.vmID && left.uid == right.uid && left.gid == right.gid && sameStrings(left.jailerArguments, right.jailerArguments) && left.machine == right.machine && left.resources == right.resources && left.network.Mode == right.network.Mode && sameStrings(left.network.Allowlist, right.network.Allowlist) && left.firecracker == right.firecracker && left.jailer == right.jailer && left.kernel == right.kernel && left.rootFS == right.rootFS && left.guestAgent == right.guestAgent && left.compiled == right.compiled
}

func cloneLinuxJailerFixtureSet(fixtures FixtureSet) FixtureSet {
	artifacts := fixtures.artifacts
	fixtures.artifacts = make(map[FixtureName]PinnedArtifact, len(fixtures.artifacts))
	for name, artifact := range artifacts {
		fixtures.artifacts[name] = artifact
	}
	return fixtures
}

func sameLinuxJailerFixtureSet(left, right FixtureSet) bool {
	if left.directory != right.directory || left.fixtureVersion != right.fixtureVersion || left.verified != right.verified || len(left.artifacts) != len(right.artifacts) {
		return false
	}
	for name, artifact := range left.artifacts {
		if rightArtifact, ok := right.artifacts[name]; !ok || rightArtifact != artifact {
			return false
		}
	}
	return true
}

func callWithContextFence(ctx context.Context, action string, call func(context.Context) error) error {
	if err := contextError(ctx); err != nil {
		return fmt.Errorf("%s before I/O: %w", action, err)
	}
	if err := call(ctx); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if err := contextError(ctx); err != nil {
		return fmt.Errorf("%s after I/O: %w", action, err)
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrSmokeUnavailable)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func missingJailerProcess(process JailerProcess) error {
	if process == nil {
		return errors.New("Jailer process is absent")
	}
	return nil
}
