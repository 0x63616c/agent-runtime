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

	"github.com/0x63616c/agent-runtime/sandbox"
)

var (
	// ErrInvalidProfile means a declarative Firecracker host profile is unsafe or incomplete.
	ErrInvalidProfile = errors.New("invalid Firecracker host profile")
	// ErrArtifactIntegrity means a fixture differs from its declared immutable digest.
	ErrArtifactIntegrity = errors.New("Firecracker fixture integrity check failed")
	// ErrCapabilityUnavailable means a requested profile has no certified Firecracker data plane.
	ErrCapabilityUnavailable = errors.New("Firecracker capability is unavailable")
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

// Plan is a resolved, immutable launch plan. The host agent verifies fixture digests before launch.
type Plan struct {
	VMID            string
	JailerArguments []string
	Machine         MachineConfig
	Network         NetworkPolicy
	Capabilities    sandbox.CapabilitySnapshot
	Firecracker     PinnedArtifact
	Jailer          PinnedArtifact
	Kernel          PinnedArtifact
	RootFS          PinnedArtifact
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
		Network:         NetworkPolicy{Mode: NetworkDenyAll},
		Capabilities:    foundationCapabilities(),
		Firecracker:     profile.Firecracker,
		Jailer:          profile.Jailer,
		Kernel:          profile.Kernel,
		RootFS:          profile.RootFS,
	}, nil
}

func machineConfig(limits sandbox.ResourceLimits) (MachineConfig, error) {
	const mib = uint64(1 << 20)
	if limits.MilliCPU == 0 || limits.MilliCPU%1000 != 0 || limits.MemoryBytes < 128*mib || limits.MemoryBytes%mib != 0 || limits.RootDiskBytes == 0 || limits.PIDs == 0 || limits.ProcessCount == 0 || limits.OpenFiles == 0 || limits.Lifetime <= 0 || limits.ProducedOutputBytes == 0 || limits.RetainedOutputBytes == 0 || limits.RetainedOutputBytes > limits.ProducedOutputBytes {
		return MachineConfig{}, fmt.Errorf("%w: Firecracker requires exact vCPU, MiB memory and finite resource limits", ErrInvalidProfile)
	}
	return MachineConfig{VCPUCount: limits.MilliCPU / 1000, MemoryMiB: uint32(limits.MemoryBytes / mib)}, nil
}

func foundationCapabilities() sandbox.CapabilitySnapshot {
	unavailable := sandbox.CapabilityDescriptor{State: sandbox.CapabilityUnavailable, ContractVersion: "firecracker.host/v1", ConformanceVersion: "not-certified", DataPlane: "none"}
	return sandbox.CapabilitySnapshot{SchemaVersion: "sandbox.capabilities/v1", Isolation: unavailable, Guest: unavailable, Resources: unavailable, Reconnect: unavailable, ImageAdmission: unavailable, Output: unavailable, Transfer: unavailable, Mounts: unavailable, Volumes: unavailable, Snapshots: unavailable, Egress: unavailable, Secrets: unavailable}
}

func validArtifact(artifact PinnedArtifact) bool {
	return safeAbsolutePath(artifact.Path) && validSHA256(artifact.Digest)
}

func safeAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/"
}

func validVMID(value string) bool {
	return len(value) > 0 && len(value) <= 63 && !strings.ContainsAny(value, "/\\ \t\n")
}

func validSHA256(value sandbox.Digest) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(string(value), "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
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
	if opener == nil {
		return fmt.Errorf("%w: opener is required", ErrArtifactIntegrity)
	}
	for _, artifact := range []PinnedArtifact{plan.Firecracker, plan.Jailer, plan.Kernel, plan.RootFS} {
		if artifact.Path == "" && artifact.Digest == "" {
			continue
		}
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

type environment interface{ check(string) error }
type environmentFunc func(string) error

func (f environmentFunc) check(path string) error { return f(path) }

// EnvironmentReport is retained by the KVM lane whenever the runner is unavailable.
type EnvironmentReport struct {
	Available bool     `json:"available"`
	Reasons   []string `json:"reasons"`
}

// AssessEnvironment verifies only the prerequisites that make a real KVM run possible.
func AssessEnvironment(host environment, goos string) EnvironmentReport {
	report := EnvironmentReport{Available: true}
	if goos != "linux" {
		report.Available = false
		report.Reasons = append(report.Reasons, "host OS is "+goos+", want linux")
	}
	if err := host.check("/dev/kvm"); err != nil {
		report.Available = false
		report.Reasons = append(report.Reasons, "/dev/kvm: "+err.Error())
	}
	return report
}

// LocalEnvironmentReport probes the current host without starting a VMM.
func LocalEnvironmentReport(check func(string) error) EnvironmentReport {
	return AssessEnvironment(environmentFunc(check), runtime.GOOS)
}
