// Package sandbox defines the public durable sandbox control contract.
package sandbox

import (
	"context"
	"errors"
	"io"
	"net/url"
	"time"
)

type SandboxID string
type ProcessID string
type VolumeID string
type SnapshotID string
type OperationID string
type ArtifactID string
type HostID string
type OperationCursor string
type OutputCursor string
type PageCursor string
type Digest string

type ClientConfig struct {
	Endpoint       Endpoint
	TLS            TLSConfig
	Credentials    CredentialSource
	TrustBundles   TrustBundleSource
	RequestTimeout time.Duration
}
type Endpoint struct{ URL string }
type TLSConfig struct {
	ServerName     string
	TrustBundleRef TrustBundleRef
}

// TrustBundleRef is an opaque reference to a versioned set of trusted roots.
type TrustBundleRef string

// TrustBundle is a resolved, versioned PEM root bundle.
type TrustBundle struct {
	Version  string
	PEMRoots []byte
}

// TrustBundleSource resolves trust bundle references without ambient system roots.
type TrustBundleSource interface {
	ResolveTrustBundle(context.Context, TrustBundleRef) (TrustBundle, error)
}
type CredentialSource interface {
	Apply(context.Context, CredentialSink) error
}
type CredentialSink interface {
	SetAuthorization(string, string) error
	ClearAuthorization()
}

// NewClient constructs and binds a Principal-scoped HTTPS control client.
func NewClient(ctx context.Context, config ClientConfig) (Client, error) {
	if err := validateClientConfig(config); err != nil {
		return nil, err
	}
	return newHTTPControlClient(ctx, config)
}

func validateClientConfig(config ClientConfig) error {
	endpoint, err := url.Parse(config.Endpoint.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return newFailure(FailureInvalidArgument, "sandbox endpoint must be an HTTPS origin", RetryNever)
	}
	if config.TLS.ServerName == "" || config.TLS.TrustBundleRef == "" {
		return newFailure(FailureInvalidArgument, "sandbox TLS server name and trust bundle are required", RetryNever)
	}
	if config.Credentials == nil {
		return newFailure(FailureInvalidArgument, "sandbox credential source is required", RetryNever)
	}
	if config.TrustBundles == nil {
		return newFailure(FailureInvalidArgument, "sandbox trust bundle source is required", RetryNever)
	}
	if config.RequestTimeout <= 0 || config.RequestTimeout > time.Minute {
		return newFailure(FailureInvalidArgument, "sandbox request timeout must be finite and positive", RetryNever)
	}
	return nil
}

type Client interface {
	Submit(context.Context, OperationRequest) (OperationRef, error)
	GetOperation(context.Context, OperationID) (Operation, error)
	WaitOperation(context.Context, OperationID) (Operation, error)
	WatchOperation(context.Context, OperationID, OperationCursor) (OperationStream, error)
	GetSandbox(context.Context, SandboxID) (SandboxInfo, error)
	GetProcess(context.Context, ProcessID) (ProcessInfo, error)
	ReplayOutput(context.Context, ProcessID, OutputCursor) (OutputStream, error)
	GetVolume(context.Context, VolumeID) (VolumeInfo, error)
	ListVolumes(context.Context, Page) (VolumePage, error)
	GetSnapshot(context.Context, SnapshotID) (SnapshotInfo, error)
	ListSnapshots(context.Context, Page) (SnapshotPage, error)
	Close(context.Context) error
}

type OperationKind string

const (
	OperationCreateSandbox    OperationKind = "create-sandbox"
	OperationRestoreSandbox   OperationKind = "restore-sandbox"
	OperationExecProcess      OperationKind = "exec-process"
	OperationSignalProcess    OperationKind = "signal-process"
	OperationKillProcess      OperationKind = "kill-process"
	OperationCopyIn           OperationKind = "copy-in"
	OperationCopyOut          OperationKind = "copy-out"
	OperationSnapshotSandbox  OperationKind = "snapshot-sandbox"
	OperationCloseSandbox     OperationKind = "close-sandbox"
	OperationReconcileSandbox OperationKind = "reconcile-sandbox"
	OperationCreateVolume     OperationKind = "create-volume"
	OperationAttachVolume     OperationKind = "attach-volume"
	OperationDetachVolume     OperationKind = "detach-volume"
	OperationDeleteVolume     OperationKind = "delete-volume"
	OperationDeleteSnapshot   OperationKind = "delete-snapshot"
	OperationApproveSensitive OperationKind = "approve-sensitive-operation"
)

type OperationRequest struct {
	ID               OperationID
	Kind             OperationKind
	CreateSandbox    *CreateSandboxRequest
	RestoreSandbox   *RestoreSandboxRequest
	ExecProcess      *ExecProcessRequest
	SignalProcess    *SignalProcessRequest
	KillProcess      *KillProcessRequest
	CopyIn           *CopyInRequest
	CopyOut          *CopyOutRequest
	SnapshotSandbox  *SnapshotSandboxRequest
	CloseSandbox     *CloseSandboxRequest
	ReconcileSandbox *ReconcileSandboxRequest
	CreateVolume     *CreateVolumeRequest
	AttachVolume     *AttachVolumeRequest
	DetachVolume     *DetachVolumeRequest
	DeleteVolume     *DeleteVolumeRequest
	DeleteSnapshot   *DeleteSnapshotRequest
	ApproveSensitive *ApproveSensitiveOperationRequest
}
type CreateSandboxRequest struct{ Spec SandboxSpec }
type RestoreSandboxRequest struct {
	SnapshotID SnapshotID
	Overrides  SandboxOverrides
}
type ExecProcessRequest struct {
	SandboxID SandboxID
	Command   Command
}
type SignalProcessRequest struct {
	ProcessID ProcessID
	Signal    Signal
}
type KillProcessRequest struct{ ProcessID ProcessID }
type CopyInRequest struct {
	SandboxID   SandboxID
	Source      ArtifactRef
	Destination GuestPath
	Options     TransferOptions
}
type CopyOutRequest struct {
	SandboxID SandboxID
	Source    GuestPath
	Options   TransferOptions
}
type SnapshotSandboxRequest struct {
	SandboxID       SandboxID
	RiskAttestation *SnapshotRiskAttestation
}
type CloseSandboxRequest struct{ SandboxID SandboxID }
type ReconcileSandboxRequest struct{ SandboxID SandboxID }
type CreateVolumeRequest struct{ Spec VolumeSpec }
type AttachVolumeRequest struct {
	SandboxID SandboxID
	VolumeID  VolumeID
	Target    GuestPath
	Mode      AttachmentMode
}
type DetachVolumeRequest struct {
	SandboxID SandboxID
	VolumeID  VolumeID
}
type DeleteVolumeRequest struct{ VolumeID VolumeID }
type DeleteSnapshotRequest struct{ SnapshotID SnapshotID }
type ApproveSensitiveOperationRequest struct {
	SensitiveOperationID OperationID
	Decision             ApprovalDecision
	ExpiresAt            time.Time
}

type SandboxSpec struct {
	Image             ImageRef
	Resources         ResourceLimits
	Environment       map[string]string
	SecretBindings    []SecretBinding
	VolumeAttachments []VolumeAttachment
	Mounts            []MountRequest
	Tmpfs             []TmpfsMount
	Capabilities      CapabilityRequirements
	Labels            map[string]string
}
type SandboxOverrides struct {
	Resources    *ResourceLimits
	Capabilities *CapabilityRequirements
}
type ImageRef struct{ Digest Digest }
type ResourceLimits struct {
	MilliCPU            uint32
	MemoryBytes         uint64
	RootDiskBytes       uint64
	TmpfsBytes          uint64
	PIDs                uint32
	ProcessCount        uint32
	OpenFiles           uint32
	Inodes              uint64
	Files               uint64
	Lifetime            time.Duration
	ProducedOutputBytes uint64
	RetainedOutputBytes uint64
	TransferBytes       uint64
	NetworkConnections  uint32
	VolumeBytes         uint64
	SnapshotBytes       uint64
}
type SecretBinding struct {
	Name    string
	Purpose string
}
type VolumeAttachment struct {
	VolumeID VolumeID
	Target   GuestPath
	Mode     AttachmentMode
}
type MountRequest struct {
	Name   string
	Target GuestPath
	Mode   MountMode
	View   MountView
}
type TmpfsMount struct {
	Target    GuestPath
	SizeBytes uint64
	Mode      FileMode
}
type CapabilityRequirements struct{ Required []CapabilityRequirement }
type CapabilityRequirement struct {
	Feature CapabilityFeature
	Minimum CapabilityState
}
type CapabilityFeature string

const (
	CapabilityIsolation CapabilityFeature = "isolation"
	CapabilityEgress    CapabilityFeature = "egress"
	CapabilityMounts    CapabilityFeature = "mounts"
	CapabilityVolumes   CapabilityFeature = "volumes"
	CapabilitySnapshots CapabilityFeature = "snapshots"
	CapabilitySecrets   CapabilityFeature = "command-secrets"
	CapabilityTransfer  CapabilityFeature = "transfer"
	CapabilityReconnect CapabilityFeature = "reconnect"
)

type GuestPath string
type FileMode uint32
type AttachmentMode string

const (
	AttachmentReadOnly  AttachmentMode = "read-only"
	AttachmentReadWrite AttachmentMode = "read-write"
)

type MountMode string

const (
	MountReadOnly  MountMode = "read-only"
	MountReadWrite MountMode = "read-write"
)

type MountView string

const (
	MountLive   MountView = "live"
	MountFrozen MountView = "frozen"
)

type Command struct {
	Executable              GuestPath
	Argv                    []string
	WorkDir                 GuestPath
	User                    NumericIdentity
	Umask                   FileMode
	Environment             map[string]string
	Grant                   Grant
	StartDeadline           time.Duration
	RuntimeLimit            time.Duration
	BindLifetimeToOperation bool
}
type NumericIdentity struct {
	UID    uint32
	GID    uint32
	Groups []uint32
}
type Grant struct {
	Secrets GrantSelection
	Mounts  GrantSelection
	Network NetworkGrantSelection
}
type GrantSelection struct {
	Mode  GrantMode
	Names []string
}
type NetworkGrantSelection struct {
	Mode  GrantMode
	Rules []NetworkRule
}
type NetworkRule struct {
	Protocol NetworkProtocol
	Domain   DomainPattern
	Ports    []PortRange
}
type NetworkProtocol string

const (
	NetworkTCP NetworkProtocol = "tcp"
	NetworkUDP NetworkProtocol = "udp"
)

type DomainPattern string
type PortRange struct {
	First uint16
	Last  uint16
}
type GrantMode string

const (
	GrantNone    GrantMode = "none"
	GrantSelect  GrantMode = "select"
	GrantInherit GrantMode = "inherit"
)

type Signal string

const (
	SignalInterrupt Signal = "interrupt"
	SignalTerminate Signal = "terminate"
	SignalKill      Signal = "kill"
	SignalHangup    Signal = "hangup"
)

type ArtifactRef struct {
	ID        ArtifactID
	MediaType string
	SizeBytes uint64
	Digest    Digest
}
type TransferOptions struct {
	Overwrite OverwriteMode
	Mode      FileMode
	Owner     *NumericIdentity
	Durable   bool
}
type OverwriteMode string

const (
	OverwriteFailIfExists  OverwriteMode = "fail-if-exists"
	OverwriteAtomicReplace OverwriteMode = "atomic-replace"
)

type SnapshotRiskAttestation struct {
	Risk  string
	Owner string
}
type VolumeSpec struct {
	SizeBytes uint64
	Inodes    uint64
	Labels    map[string]string
}
type ApprovalDecision string

const (
	ApprovalApproved ApprovalDecision = "approved"
	ApprovalDenied   ApprovalDecision = "denied"
)

type OperationRef struct {
	ID         OperationID
	AcceptedAt time.Time
}
type Operation struct {
	Ref                 OperationRef
	Kind                OperationKind
	State               OperationState
	Target              OperationTarget
	CanonicalDigest     Digest
	EffectiveSpecDigest Digest
	CapabilityDigest    Digest
	Result              *OperationResult
	Failure             *Failure
	RetentionExpiresAt  time.Time
	LatestCursor        OperationCursor
}
type OperationTargetKind string

const (
	TargetSandbox   OperationTargetKind = "sandbox"
	TargetProcess   OperationTargetKind = "process"
	TargetVolume    OperationTargetKind = "volume"
	TargetSnapshot  OperationTargetKind = "snapshot"
	TargetOperation OperationTargetKind = "operation"
	TargetNone      OperationTargetKind = "none"
)

type OperationTarget struct {
	Kind        OperationTargetKind
	SandboxID   SandboxID
	ProcessID   ProcessID
	VolumeID    VolumeID
	SnapshotID  SnapshotID
	OperationID OperationID
}
type OperationState string

const (
	OperationAccepted         OperationState = "accepted"
	OperationQueued           OperationState = "queued"
	OperationDispatched       OperationState = "dispatched"
	OperationStarted          OperationState = "started"
	OperationSucceeded        OperationState = "succeeded"
	OperationFailed           OperationState = "failed"
	OperationCancelled        OperationState = "cancelled"
	OperationUncertain        OperationState = "uncertain"
	OperationCleanupPending   OperationState = "cleanup-pending"
	OperationCleanupConfirmed OperationState = "cleanup-confirmed"
	OperationExpired          OperationState = "expired"
	OperationTombstoned       OperationState = "tombstoned"
)

type OperationResultKind string

const (
	ResultSandbox  OperationResultKind = "sandbox"
	ResultProcess  OperationResultKind = "process"
	ResultArtifact OperationResultKind = "artifact"
	ResultVolume   OperationResultKind = "volume"
	ResultSnapshot OperationResultKind = "snapshot"
	ResultControl  OperationResultKind = "control"
)

type OperationResult struct {
	Kind     OperationResultKind
	Sandbox  *SandboxResult
	Process  *ProcessResult
	Artifact *ArtifactResult
	Volume   *VolumeResult
	Snapshot *SnapshotResult
	Control  *ControlResult
}
type SandboxResult struct{ ID SandboxID }
type ArtifactResult struct{ Artifact ArtifactRef }
type VolumeResult struct {
	ID         VolumeID
	Attachment *VolumeAttachmentInfo
}
type SnapshotResult struct{ ID SnapshotID }
type ControlResult struct {
	Action  ControlAction
	Cleanup TreeCleanupState
}
type ControlAction string

const (
	ControlSignaled   ControlAction = "signaled"
	ControlKilled     ControlAction = "killed"
	ControlCopiedIn   ControlAction = "copied-in"
	ControlClosed     ControlAction = "closed"
	ControlReconciled ControlAction = "reconciled"
	ControlAttached   ControlAction = "attached"
	ControlDetached   ControlAction = "detached"
	ControlDeleted    ControlAction = "deleted"
	ControlApproved   ControlAction = "approved"
)

type Failure struct {
	Code    FailureCode
	Message string
	Retry   RetryClass
	Details []FailureDetail
}
type Error struct {
	failure      Failure
	contextCause error
}

func (e *Error) Error() string {
	if e == nil {
		return "sandbox: <nil>"
	}
	return "sandbox: " + string(e.failure.Code) + ": " + e.failure.Message
}
func (e *Error) Failure() Failure {
	if e == nil {
		return Failure{}
	}
	failure := e.failure
	failure.Details = append([]FailureDetail(nil), e.failure.Details...)
	return failure
}
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.contextCause
}
func AsFailure(err error) (Failure, bool) {
	var classified *Error
	if !errors.As(err, &classified) || classified == nil {
		return Failure{}, false
	}
	return classified.Failure(), true
}

type FailureDetail struct {
	Key   FailureDetailKey
	Value string
}
type FailureDetailKey string

const (
	DetailField            FailureDetailKey = "field"
	DetailLimit            FailureDetailKey = "limit"
	DetailResource         FailureDetailKey = "resource"
	DetailCapability       FailureDetailKey = "capability"
	DetailPolicyVersion    FailureDetailKey = "policy-version"
	DetailEarliestCursor   FailureDetailKey = "earliest-cursor"
	DetailOperationState   FailureDetailKey = "operation-state"
	DetailRetryAfterMillis FailureDetailKey = "retry-after-millis"
)

type FailureCode string

const (
	FailureInvalidArgument             FailureCode = "invalid-argument"
	FailureNotFoundOrDenied            FailureCode = "not-found-or-denied"
	FailureOperationConflict           FailureCode = "operation-conflict"
	FailureAlreadyTerminal             FailureCode = "already-terminal"
	FailureCursorExpired               FailureCode = "cursor-expired"
	FailureOutputGap                   FailureCode = "output-gap"
	FailureGrantWideningDenied         FailureCode = "grant-widening-denied"
	FailureNetworkGrantInvalid         FailureCode = "network-grant-invalid"
	FailureCapabilityUnavailable       FailureCode = "capability-unavailable"
	FailureCapabilityRegressed         FailureCode = "capability-regressed"
	FailureResourceLimitExceeded       FailureCode = "resource-limit-exceeded"
	FailureControlQuotaExceeded        FailureCode = "control-quota-exceeded"
	FailureIncompatiblePersistedPolicy FailureCode = "incompatible-persisted-policy"
	FailureOutcomeUncertain            FailureCode = "outcome-uncertain"
	FailureCancelled                   FailureCode = "cancelled"
	FailureDeadlineExceeded            FailureCode = "deadline-exceeded"
	FailureUnavailable                 FailureCode = "unavailable"
)

type RetryClass string

const (
	RetryNever            RetryClass = "never"
	RetryAfterReconcile   RetryClass = "after-reconcile"
	RetryCallerControlled RetryClass = "caller-controlled"
)

type OperationStream interface {
	Next(context.Context) (OperationEvent, error)
	Close() error
}
type OperationEventKind string

const (
	OperationEventUpdate OperationEventKind = "update"
	OperationEventGap    OperationEventKind = "gap"
)

type OperationEvent struct {
	Kind   OperationEventKind
	Cursor OperationCursor
	Update *Operation
	Gap    *OperationGap
}
type OperationGap struct {
	EarliestRetained OperationCursor
	Reason           string
}
type OutputStream interface {
	Next(context.Context) (OutputEvent, error)
	Close() error
}
type OutputEventKind string

const (
	OutputEventChunk OutputEventKind = "chunk"
	OutputEventGap   OutputEventKind = "gap"
	OutputEventFinal OutputEventKind = "final"
)

type OutputEvent struct {
	Kind   OutputEventKind
	Cursor OutputCursor
	Stream OutputKind
	Chunk  *OutputChunk
	Gap    *OutputGap
	Final  *OutputFinal
}
type OutputChunk struct {
	Bytes    []byte
	Redacted bool
}
type OutputFinal struct{ Result ProcessResult }
type OutputKind string

const (
	OutputStdout OutputKind = "stdout"
	OutputStderr OutputKind = "stderr"
)

type OutputGap struct {
	EarliestRetained OutputCursor
	Reason           string
}

type SandboxInfo struct {
	ID           SandboxID
	Desired      SandboxDesiredState
	Actual       SandboxActualState
	Image        ImageInfo
	Resources    ResourceLimits
	Capabilities CapabilitySnapshot
	Host         HostRoute
	Failure      *Failure
}
type SandboxDesiredState string

const (
	SandboxActive SandboxDesiredState = "active"
	SandboxClosed SandboxDesiredState = "closed"
)

type SandboxActualState string

const (
	SandboxPending      SandboxActualState = "pending"
	SandboxProvisioning SandboxActualState = "provisioning"
	SandboxReady        SandboxActualState = "ready"
	SandboxQuiescing    SandboxActualState = "quiescing"
	SandboxCleaning     SandboxActualState = "cleaning"
	SandboxFailed       SandboxActualState = "failed"
	SandboxUnreachable  SandboxActualState = "unreachable"
	SandboxLost         SandboxActualState = "lost"
	SandboxDeleted      SandboxActualState = "deleted"
)

type ImageInfo struct {
	Digest                 Digest
	Architecture           string
	Identity               NumericIdentity
	GuestProtocol          string
	AdmissionPolicyVersion string
}
type CapabilityState string

const (
	CapabilityUnavailable CapabilityState = "unavailable"
	CapabilityDeclared    CapabilityState = "declared"
	CapabilityEnforced    CapabilityState = "enforced"
)

type CapabilityDescriptor struct {
	State              CapabilityState
	ContractVersion    string
	ConformanceVersion string
	DataPlane          string
	LimitPrecision     []string
}
type CapabilitySnapshot struct {
	Digest          Digest
	SchemaVersion   string
	ControlProtocol CapabilityDescriptor
	Isolation       CapabilityDescriptor
	Guest           CapabilityDescriptor
	Resources       CapabilityDescriptor
	Reconnect       CapabilityDescriptor
	ImageAdmission  CapabilityDescriptor
	Output          CapabilityDescriptor
	Transfer        CapabilityDescriptor
	Mounts          CapabilityDescriptor
	Volumes         CapabilityDescriptor
	Snapshots       CapabilityDescriptor
	Egress          CapabilityDescriptor
	Secrets         CapabilityDescriptor
	Signals         []Signal
	Trust           KeyLifecycle
}
type KeyLifecycle struct {
	TrustBundleVersion      string
	ControlSigningKeyID     string
	ControlSigningAlgorithm string
	RevocationEpoch         uint64
	NotBefore               time.Time
	NotAfter                time.Time
	RotationGrace           time.Duration
}
type HostRoute struct {
	HostID         HostID
	Generation     uint64
	LeaseExpiresAt time.Time
}
type ProcessInfo struct {
	ID        ProcessID
	SandboxID SandboxID
	State     ProcessState
	Result    *ProcessResult
	Stdout    OutputRetention
	Stderr    OutputRetention
}
type ProcessState string

const (
	ProcessAccepted    ProcessState = "accepted"
	ProcessStarting    ProcessState = "starting"
	ProcessRunning     ProcessState = "running"
	ProcessTerminating ProcessState = "terminating"
	ProcessTerminal    ProcessState = "terminal"
)

type ProcessResult struct {
	StartedAt  time.Time
	FinishedAt time.Time
	ExitCode   *int
	Signal     *Signal
	Reason     TerminationReason
	Usage      ResourceUsage
	Cleanup    TreeCleanupState
}
type TerminationReason string

const (
	TerminationExited               TerminationReason = "exited"
	TerminationSignaled             TerminationReason = "signaled"
	TerminationTimedOut             TerminationReason = "timed-out"
	TerminationOOMKilled            TerminationReason = "oom-killed"
	TerminationOutputLimit          TerminationReason = "output-limit"
	TerminationCancelled            TerminationReason = "cancelled"
	TerminationKilledByCaller       TerminationReason = "killed-by-caller"
	TerminationSandboxClosed        TerminationReason = "sandbox-closed"
	TerminationSandboxLost          TerminationReason = "sandbox-lost"
	TerminationStartupFailed        TerminationReason = "startup-failed"
	TerminationInfrastructureFailed TerminationReason = "infrastructure-failed"
	TerminationOutcomeUncertain     TerminationReason = "outcome-uncertain"
)

type ResourceUsage struct {
	CPUTime         time.Duration
	PeakMemoryBytes uint64
	ReadBytes       uint64
	WrittenBytes    uint64
}
type TreeCleanupState string

const (
	TreeCleanupConfirmed   TreeCleanupState = "confirmed"
	TreeCleanupPending     TreeCleanupState = "pending"
	TreeCleanupNotRequired TreeCleanupState = "not-required"
	TreeCleanupUnknown     TreeCleanupState = "unknown"
)

type OutputRetention struct {
	EarliestCursor OutputCursor
	RetainedBytes  uint64
	Truncated      bool
}
type VolumeInfo struct {
	ID                 VolumeID
	SizeBytes          uint64
	Inodes             uint64
	Attachment         *VolumeAttachmentInfo
	Tainted            bool
	RetentionExpiresAt time.Time
}
type VolumeAttachmentInfo struct {
	SandboxID      SandboxID
	Generation     uint64
	LeaseExpiresAt time.Time
	Mode           AttachmentMode
}
type SnapshotInfo struct {
	ID                 SnapshotID
	SourceSandboxID    SandboxID
	Digest             Digest
	SizeBytes          uint64
	Tainted            bool
	RetentionExpiresAt time.Time
}
type Page struct {
	Cursor PageCursor
	Limit  uint32
}
type VolumePage struct {
	Items []VolumeInfo
	Next  PageCursor
}
type SnapshotPage struct {
	Items []SnapshotInfo
	Next  PageCursor
}

var _ io.Closer = (OperationStream)(nil)
var _ io.Closer = (OutputStream)(nil)
var _ error = (*Error)(nil)
