// Package firecracker owns the Linux/KVM-only, internal Firecracker host profile.
package firecracker

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/sandbox"
)

var (
	// ErrInvalidProfile means a declarative Firecracker host profile is unsafe or incomplete.
	ErrInvalidProfile = errors.New("invalid Firecracker host profile")
	// ErrArtifactIntegrity means a fixture differs from its declared immutable digest.
	ErrArtifactIntegrity = errors.New("firecracker fixture integrity check failed")
	// ErrCapabilityUnavailable means a requested profile has no certified Firecracker data plane.
	ErrCapabilityUnavailable = errors.New("firecracker capability is unavailable")
)

// NetworkMode identifies the only host-network authority represented by a profile.
type NetworkMode string

const (
	// NetworkDenyAll creates no guest NIC and authorizes no egress.
	NetworkDenyAll NetworkMode = "deny-all"
	// NetworkAllowlist is reserved for the separately certified mandatory-proxy profile.
	NetworkAllowlist NetworkMode = "allowlist"
)

// PinnedArtifact is an immutable host input identified by a SHA-256 digest.
type PinnedArtifact struct {
	Path   string
	Digest sandbox.Digest
}

// NetworkPolicy is the Firecracker host's explicit egress configuration.
type NetworkPolicy struct {
	Mode      NetworkMode
	Allowlist []string
}

// Profile is the versioned desired state for one untrusted Firecracker microVM.
// It intentionally contains no caller-provided host path, secret value, or ambient credential.
type Profile struct {
	Version           string
	VMID              string
	Firecracker       PinnedArtifact
	Jailer            PinnedArtifact
	Kernel            PinnedArtifact
	RootFS            PinnedArtifact
	KVMDevice         string
	ChrootBaseDir     string
	UID               uint32
	GID               uint32
	Resources         sandbox.ResourceLimits
	Network           NetworkPolicy
	HostMountsEnabled bool
}

// MachineConfig is the exact bounded subset sent to Firecracker's machine-config endpoint.
type MachineConfig struct {
	VCPUCount uint32
	MemoryMiB uint32
}

// ResourceEnforcement is the exact finite host configuration carried to the Jailer and host agent.
type ResourceEnforcement struct {
	CgroupVersion       uint8
	RootDiskBytes       uint64
	PIDs                uint32
	ProcessCount        uint32
	OpenFiles           uint32
	Inodes              uint64
	Files               uint64
	Lifetime            time.Duration
	ProducedOutputBytes uint64
	RetainedOutputBytes uint64
}

// Plan is a resolved, immutable launch plan. The host agent verifies fixture digests before launch.
type Plan struct {
	VMID            string
	JailerArguments []string
	Machine         MachineConfig
	Resources       ResourceEnforcement
	Network         NetworkPolicy
	Capabilities    sandbox.CapabilitySnapshot
	Firecracker     PinnedArtifact
	Jailer          PinnedArtifact
	Kernel          PinnedArtifact
	RootFS          PinnedArtifact
	compiled        bool
}

// Compile rejects profile widening and produces the deterministic foundation launch plan.
func Compile(profile Profile) (Plan, error) {
	if profile.Version != "firecracker.host/v1" || !validVMID(profile.VMID) {
		return Plan{}, fmt.Errorf("%w: version and VM ID are required", ErrInvalidProfile)
	}
	for _, artifact := range []PinnedArtifact{profile.Firecracker, profile.Jailer, profile.Kernel, profile.RootFS} {
		if !validArtifact(artifact) {
			return Plan{}, fmt.Errorf("%w: every executable and guest artifact must be absolute and SHA-256 pinned", ErrInvalidProfile)
		}
	}
	if profile.KVMDevice != "/dev/kvm" || !safeAbsolutePath(profile.ChrootBaseDir) || profile.UID == 0 || profile.GID == 0 {
		return Plan{}, fmt.Errorf("%w: KVM, chroot and unprivileged jailer identity are required", ErrInvalidProfile)
	}
	if profile.Network.Mode != NetworkDenyAll || len(profile.Network.Allowlist) != 0 {
		return Plan{}, fmt.Errorf("%w: foundation profile permits only deny-all networking", ErrCapabilityUnavailable)
	}
	if profile.HostMountsEnabled {
		return Plan{}, fmt.Errorf("%w: host mounts require the separately certified sharing-daemon profile", ErrCapabilityUnavailable)
	}
	machine, err := machineConfig(profile.Resources)
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		VMID:            profile.VMID,
		JailerArguments: []string{"--id", profile.VMID, "--exec-file", profile.Firecracker.Path, "--uid", strconv.FormatUint(uint64(profile.UID), 10), "--gid", strconv.FormatUint(uint64(profile.GID), 10), "--chroot-base-dir", profile.ChrootBaseDir, "--cgroup-version", "2", "--", "--api-sock", "/run/firecracker.socket"},
		Machine:         machine,
		Resources: ResourceEnforcement{
			CgroupVersion:       2,
			RootDiskBytes:       profile.Resources.RootDiskBytes,
			PIDs:                profile.Resources.PIDs,
			ProcessCount:        profile.Resources.ProcessCount,
			OpenFiles:           profile.Resources.OpenFiles,
			Inodes:              profile.Resources.Inodes,
			Files:               profile.Resources.Files,
			Lifetime:            profile.Resources.Lifetime,
			ProducedOutputBytes: profile.Resources.ProducedOutputBytes,
			RetainedOutputBytes: profile.Resources.RetainedOutputBytes,
		},
		Network:      NetworkPolicy{Mode: NetworkDenyAll},
		Capabilities: foundationCapabilities(),
		Firecracker:  profile.Firecracker,
		Jailer:       profile.Jailer,
		Kernel:       profile.Kernel,
		RootFS:       profile.RootFS,
		compiled:     true,
	}, nil
}

func machineConfig(limits sandbox.ResourceLimits) (MachineConfig, error) {
	const mib = uint64(1 << 20)
	if limits.MilliCPU == 0 || limits.MilliCPU%1000 != 0 || limits.MemoryBytes < 128*mib || limits.MemoryBytes%mib != 0 || limits.RootDiskBytes == 0 || limits.PIDs == 0 || limits.ProcessCount == 0 || limits.OpenFiles == 0 || limits.Inodes == 0 || limits.Files == 0 || limits.Lifetime <= 0 || limits.ProducedOutputBytes == 0 || limits.RetainedOutputBytes == 0 || limits.RetainedOutputBytes > limits.ProducedOutputBytes {
		return MachineConfig{}, fmt.Errorf("%w: Firecracker requires exact vCPU, MiB memory and finite resource limits", ErrInvalidProfile)
	}
	return MachineConfig{VCPUCount: limits.MilliCPU / 1000, MemoryMiB: uint32(limits.MemoryBytes / mib)}, nil
}

func foundationCapabilities() sandbox.CapabilitySnapshot {
	unavailable := sandbox.CapabilityDescriptor{State: sandbox.CapabilityUnavailable, ContractVersion: "firecracker.host/v1", ConformanceVersion: "not-certified", DataPlane: "none"}
	return sandbox.CapabilitySnapshot{SchemaVersion: "sandbox.capabilities/v1", ControlProtocol: unavailable, Isolation: unavailable, Guest: unavailable, Resources: unavailable, Reconnect: unavailable, ImageAdmission: unavailable, Output: unavailable, Transfer: unavailable, Mounts: unavailable, Volumes: unavailable, Snapshots: unavailable, Egress: unavailable, Secrets: unavailable}
}

func validArtifact(artifact PinnedArtifact) bool {
	return safeAbsolutePath(artifact.Path) && validSHA256(artifact.Digest)
}

func safeAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/"
}

func validVMID(value string) bool {
	if len(value) == 0 || len(value) > 63 || !vmIDAlphaNumeric(value[0]) || !vmIDAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		if value[index] != '-' && !vmIDAlphaNumeric(value[index]) {
			return false
		}
	}
	return true
}

func vmIDAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func validSHA256(value sandbox.Digest) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(string(value), "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

type artifactOpener interface {
	Open(string) (io.ReadCloser, error)
}
type artifactOpenFunc func(string) (io.ReadCloser, error)

func (f artifactOpenFunc) Open(path string) (io.ReadCloser, error) { return f(path) }

// VerifyPlanArtifacts checks all launch inputs before a Jailer or VMM process may start.
func VerifyPlanArtifacts(plan Plan, opener artifactOpener) error {
	if !validCompiledPlan(plan) {
		return fmt.Errorf("%w: a complete compiled launch plan is required", ErrArtifactIntegrity)
	}
	if opener == nil {
		return fmt.Errorf("%w: opener is required", ErrArtifactIntegrity)
	}
	for _, artifact := range []PinnedArtifact{plan.Firecracker, plan.Jailer, plan.Kernel, plan.RootFS} {
		file, err := opener.Open(artifact.Path)
		if err != nil {
			return fmt.Errorf("%w: open %s: %v", ErrArtifactIntegrity, artifact.Path, err)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != string(artifact.Digest) {
			return fmt.Errorf("%w: digest mismatch for %s", ErrArtifactIntegrity, artifact.Path)
		}
	}
	return nil
}

type environment interface {
	verify(environmentPrerequisite, Plan) error
}

type environmentFunc func(environmentPrerequisite, Plan) error

func (f environmentFunc) verify(prerequisite environmentPrerequisite, plan Plan) error {
	return f(prerequisite, plan)
}

type environmentPrerequisite string

const (
	usableKVMPrerequisite       environmentPrerequisite = "usable-kvm"
	jailerPrerequisite          environmentPrerequisite = "jailer"
	cgroupV2Prerequisite        environmentPrerequisite = "cgroup-v2"
	pinnedArtifactsPrerequisite environmentPrerequisite = "pinned-artifacts"
)

// EnvironmentCheck records whether one required protected-runner prerequisite was verified.
type EnvironmentCheck struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// EnvironmentReport is retained by the KVM lane whenever the runner is unavailable.
type EnvironmentReport struct {
	Available       bool             `json:"available"`
	Linux           EnvironmentCheck `json:"linux"`
	KVM             EnvironmentCheck `json:"kvm"`
	Jailer          EnvironmentCheck `json:"jailer"`
	CgroupV2        EnvironmentCheck `json:"cgroup_v2"`
	PinnedArtifacts EnvironmentCheck `json:"pinned_artifacts"`
	Reasons         []string         `json:"reasons"`
}

// AssessEnvironment verifies every prerequisite for one protected Firecracker runner.
// A readable /dev/kvm is not proof of usable KVM; the protected lane supplies that proof through its verifier.
func AssessEnvironment(host environment, goos string, plan Plan) EnvironmentReport {
	report := EnvironmentReport{Linux: checkLinux(goos)}
	report.KVM = checkEnvironment(host, usableKVMPrerequisite, plan)
	report.CgroupV2 = checkEnvironment(host, cgroupV2Prerequisite, plan)
	if !hasPinnedLaunchPlan(plan) {
		missingPlan := EnvironmentCheck{Reason: "a compiled plan with pinned Firecracker, Jailer, kernel and root filesystem is required"}
		report.Jailer = missingPlan
		report.PinnedArtifacts = missingPlan
	} else {
		report.Jailer = checkEnvironment(host, jailerPrerequisite, plan)
		report.PinnedArtifacts = checkEnvironment(host, pinnedArtifactsPrerequisite, plan)
	}
	report.Available = report.Linux.Available && report.KVM.Available && report.Jailer.Available && report.CgroupV2.Available && report.PinnedArtifacts.Available
	for _, check := range []struct {
		name  string
		value EnvironmentCheck
	}{
		{"linux", report.Linux},
		{"usable KVM", report.KVM},
		{"jailer", report.Jailer},
		{"cgroup v2", report.CgroupV2},
		{"pinned artifacts", report.PinnedArtifacts},
	} {
		if !check.value.Available {
			report.Reasons = append(report.Reasons, check.name+": "+check.value.Reason)
		}
	}
	return report
}

func checkLinux(goos string) EnvironmentCheck {
	if goos == "linux" {
		return EnvironmentCheck{Available: true}
	}
	return EnvironmentCheck{Reason: "host OS is " + goos + ", want linux"}
}

func checkEnvironment(host environment, prerequisite environmentPrerequisite, plan Plan) EnvironmentCheck {
	if host == nil {
		return EnvironmentCheck{Reason: "protected-runner verifier is required"}
	}
	if err := host.verify(prerequisite, plan); err != nil {
		return EnvironmentCheck{Reason: err.Error()}
	}
	return EnvironmentCheck{Available: true}
}

func hasPinnedLaunchPlan(plan Plan) bool {
	return validCompiledPlan(plan)
}

func validCompiledPlan(plan Plan) bool {
	return plan.compiled && validVMID(plan.VMID) && validArtifact(plan.Firecracker) && validArtifact(plan.Jailer) && validArtifact(plan.Kernel) && validArtifact(plan.RootFS) && len(plan.JailerArguments) > 0 && plan.Machine.VCPUCount > 0 && plan.Machine.MemoryMiB >= 128 && validResourceEnforcement(plan.Resources) && plan.Network.Mode == NetworkDenyAll && len(plan.Network.Allowlist) == 0
}

func validResourceEnforcement(resources ResourceEnforcement) bool {
	return resources.CgroupVersion == 2 && resources.RootDiskBytes > 0 && resources.PIDs > 0 && resources.ProcessCount > 0 && resources.OpenFiles > 0 && resources.Inodes > 0 && resources.Files > 0 && resources.Lifetime > 0 && resources.ProducedOutputBytes > 0 && resources.RetainedOutputBytes > 0 && resources.RetainedOutputBytes <= resources.ProducedOutputBytes
}

type localEnvironment struct{ check func(string) error }

func (host localEnvironment) verify(prerequisite environmentPrerequisite, _ Plan) error {
	if host.check == nil {
		return errors.New("local path checker is required")
	}
	switch prerequisite {
	case usableKVMPrerequisite:
		if err := host.check("/dev/kvm"); err != nil {
			return fmt.Errorf("/dev/kvm read/write access: %w", err)
		}
		return errors.New("opened, but KVM API and jailed guest execution were not verified")
	case cgroupV2Prerequisite:
		if err := host.check("/sys/fs/cgroup/cgroup.controllers"); err != nil {
			return fmt.Errorf("cgroup v2 controller file: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("local report cannot verify %s", prerequisite)
	}
}

// LocalEnvironmentReport probes the current host without starting a VMM and always fails closed without protected-runner proof.
func LocalEnvironmentReport(check func(string) error) EnvironmentReport {
	return AssessEnvironment(localEnvironment{check: check}, runtime.GOOS, Plan{})
}
