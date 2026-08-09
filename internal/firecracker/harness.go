package firecracker

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/sandbox"
)

var (
	// ErrFixtureLock means a fixture lock is incomplete or permits mutable provenance.
	ErrFixtureLock = errors.New("invalid Firecracker fixture lock")
	// ErrSmokeUnavailable means a protected-run host cannot prove a smoke prerequisite.
	ErrSmokeUnavailable = errors.New("Firecracker smoke harness unavailable")
)

// FixtureName identifies one non-interchangeable Firecracker fixture.
type FixtureName string

const (
	// FixtureFirecracker identifies the Firecracker VMM executable.
	FixtureFirecracker FixtureName = "firecracker"
	// FixtureJailer identifies the Firecracker Jailer executable.
	FixtureJailer FixtureName = "jailer"
	// FixtureKernel identifies the admitted guest kernel.
	FixtureKernel FixtureName = "kernel"
	// FixtureRootFS identifies the admitted guest root filesystem.
	FixtureRootFS FixtureName = "rootfs"
)

// LockedArtifact records immutable provenance required before an artifact may be used.
type LockedArtifact struct {
	Name      FixtureName    `json:"name"`
	Source    string         `json:"source"`
	Digest    sandbox.Digest `json:"sha256"`
	SizeBytes uint64         `json:"size_bytes"`
	License   string         `json:"license"`
}

// FixtureLock is a reviewed, complete fixture identity lock.
type FixtureLock struct {
	Version   string           `json:"version"`
	Artifacts []LockedArtifact `json:"artifacts"`
}

// Validate rejects partial, mutable, duplicate, or unlicensed fixture locks.
func (lock FixtureLock) Validate() error {
	if lock.Version != "firecracker.fixtures/v1" || len(lock.Artifacts) != 4 {
		return fmt.Errorf("%w: version and exactly four artifacts are required", ErrFixtureLock)
	}
	want := map[FixtureName]bool{FixtureFirecracker: false, FixtureJailer: false, FixtureKernel: false, FixtureRootFS: false}
	for _, artifact := range lock.Artifacts {
		seen, known := want[artifact.Name]
		if !known || seen || !strings.HasPrefix(artifact.Source, "https://") || !validSHA256(artifact.Digest) || artifact.SizeBytes == 0 || artifact.SizeBytes >= math.MaxInt64 || strings.TrimSpace(artifact.License) == "" {
			return fmt.Errorf("%w: every named artifact needs one HTTPS source, SHA-256, non-zero size, and license", ErrFixtureLock)
		}
		want[artifact.Name] = true
	}
	for name, seen := range want {
		if !seen {
			return fmt.Errorf("%w: missing %s", ErrFixtureLock, name)
		}
	}
	return nil
}

// FixtureResponse is a non-executable immutable fixture response. ContentLength
// is -1 when the source did not declare one.
type FixtureResponse struct {
	Body          io.ReadCloser
	ContentLength int64
}

// FixtureFetcher retrieves an immutable source without executing it.
type FixtureFetcher interface {
	Open(context.Context, string) (FixtureResponse, error)
}

type fixtureStoreFunc func(context.Context, string) (io.ReadCloser, error)

func (f fixtureStoreFunc) Open(ctx context.Context, source string) (FixtureResponse, error) {
	body, err := f(ctx, source)
	return FixtureResponse{Body: body, ContentLength: -1}, err
}

// FixtureSet contains fixtures that have been downloaded and completely verified.
type FixtureSet struct {
	directory string
	artifacts map[FixtureName]PinnedArtifact
	verified  bool
}

// Directory returns the private staging directory containing verified fixtures.
func (set FixtureSet) Directory() string { return set.directory }

// Names returns the complete fixture set in deterministic order.
func (set FixtureSet) Names() []FixtureName {
	names := make([]FixtureName, 0, len(set.artifacts))
	for name := range set.artifacts {
		names = append(names, name)
	}
	sort.Slice(names, func(left, right int) bool { return names[left] < names[right] })
	return names
}

// Artifact returns one verified fixture identity.
func (set FixtureSet) Artifact(name FixtureName) (PinnedArtifact, bool) {
	artifact, ok := set.artifacts[name]
	return artifact, ok
}

// ProvisionFixtures downloads every locked fixture to private staging and only returns after all size and digest checks pass.
func ProvisionFixtures(ctx context.Context, lock FixtureLock, fetcher FixtureFetcher, destination string) (FixtureSet, error) {
	if err := lock.Validate(); err != nil {
		return FixtureSet{}, err
	}
	if fetcher == nil || !safeAbsolutePath(destination) {
		return FixtureSet{}, fmt.Errorf("%w: fetcher and private destination are required", ErrFixtureLock)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return FixtureSet{}, fmt.Errorf("create fixture staging: %w", err)
	}
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		entries, readErr := os.ReadDir(destination)
		if readErr != nil {
			return
		}
		for _, entry := range entries {
			_ = os.RemoveAll(filepath.Join(destination, entry.Name()))
		}
	}()
	set := FixtureSet{directory: destination, artifacts: make(map[FixtureName]PinnedArtifact, len(lock.Artifacts))}
	for _, artifact := range lock.Artifacts {
		response, err := fetcher.Open(ctx, artifact.Source)
		if err != nil {
			return FixtureSet{}, fmt.Errorf("%w: download %s: %v", ErrArtifactIntegrity, artifact.Name, err)
		}
		if response.Body == nil {
			return FixtureSet{}, fmt.Errorf("%w: download %s: empty response body", ErrArtifactIntegrity, artifact.Name)
		}
		if response.ContentLength >= 0 && uint64(response.ContentLength) > artifact.SizeBytes {
			_ = response.Body.Close()
			return FixtureSet{}, fmt.Errorf("%w: download %s: declared content length exceeds fixture limit", ErrArtifactIntegrity, artifact.Name)
		}
		path := filepath.Join(destination, string(artifact.Name))
		file, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			_ = response.Body.Close()
			return FixtureSet{}, fmt.Errorf("stage %s: %w", artifact.Name, createErr)
		}
		hash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, int64(artifact.SizeBytes)+1))
		closeErr := errors.Join(file.Close(), response.Body.Close())
		if copyErr != nil || closeErr != nil || uint64(written) != artifact.SizeBytes || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != string(artifact.Digest) {
			return FixtureSet{}, fmt.Errorf("%w: verify %s", ErrArtifactIntegrity, artifact.Name)
		}
		set.artifacts[artifact.Name] = PinnedArtifact{Path: path, Digest: artifact.Digest}
	}
	set.verified = true
	cleanup = false
	return set, nil
}

// LaunchRequest is the complete no-NIC Jailer request passed to a protected host implementation.
type LaunchRequest struct {
	JailerPath        string
	JailerArguments   []string
	RootFSCopyPath    string
	CgroupVersion     uint8
	NetworkInterfaces uint8
	SerialMarker      string
}

// NewLaunchRequest freezes the exact Jailer argv and deny-all launch configuration for one verified rootfs copy.
func NewLaunchRequest(plan Plan, rootFSCopyPath, serialMarker string) (LaunchRequest, error) {
	if !validCompiledPlan(plan) || !safeAbsolutePath(rootFSCopyPath) || serialMarker == "" {
		return LaunchRequest{}, fmt.Errorf("%w: compiled plan, private rootfs copy, and serial marker are required", ErrSmokeUnavailable)
	}
	return LaunchRequest{
		JailerPath:        plan.Jailer().Path,
		JailerArguments:   plan.JailerArguments(),
		RootFSCopyPath:    rootFSCopyPath,
		CgroupVersion:     2,
		NetworkInterfaces: 0,
		SerialMarker:      serialMarker,
	}, nil
}

// CleanupProof records only non-sensitive cleanup observations.
type CleanupProof struct {
	Proved  bool     `json:"proved"`
	Removed []string `json:"removed,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

// SmokeHost is the protected-runner boundary; implementations must perform actual host operations.
type SmokeHost interface {
	Preflight(context.Context, Plan, FixtureSet) error
	Prepare(context.Context, Plan, FixtureSet) (LaunchRequest, error)
	Launch(context.Context, LaunchRequest) error
	AwaitSerial(context.Context, string) error
	Control(context.Context) error
	Cleanup(context.Context) (CleanupProof, error)
}

// EvidenceResult classifies an observed protected-run outcome.
type EvidenceResult string

const (
	// EvidencePassed means the exact Linux/KVM smoke protocol completed.
	EvidencePassed EvidenceResult = "passed"
	// EvidenceBlocked means an unavailable prerequisite prevented a run.
	EvidenceBlocked EvidenceResult = "blocked"
	// ProofLevelLinuxKVME2E identifies only a real protected KVM run.
	ProofLevelLinuxKVME2E = "linux_kvm_e2e"
)

// SmokeEvidence is a bounded, redacted record suitable for workflow retention.
type SmokeEvidence struct {
	SchemaVersion string         `json:"schema_version"`
	ProofLevel    string         `json:"proof_level"`
	Result        EvidenceResult `json:"result"`
	SerialMarker  string         `json:"serial_marker"`
	Cleanup       CleanupProof   `json:"cleanup"`
}

// SmokeHarness orders verification, launch, guest observation, control, and cleanup under one bounded timeout.
type SmokeHarness struct {
	Host    SmokeHost
	Timeout time.Duration
}

const maximumCleanupTimeout = 30 * time.Second

// KVMPreflight captures the non-secret, necessary host observations before a protected run.
type KVMPreflight struct {
	GOOS               string `json:"goos"`
	GOARCH             string `json:"goarch"`
	KVMCharacterDevice bool   `json:"kvm_character_device"`
	KVMReadWrite       bool   `json:"kvm_read_write"`
	CgroupV2           bool   `json:"cgroup_v2"`
}

// Validate rejects every environment other than an actual Linux x86_64 KVM and cgroups-v2 host.
func (preflight KVMPreflight) Validate() error {
	if preflight.GOOS != "linux" || preflight.GOARCH != "amd64" || !preflight.KVMCharacterDevice || !preflight.KVMReadWrite || !preflight.CgroupV2 {
		return fmt.Errorf("%w: require linux/amd64, read-write character /dev/kvm, and cgroups v2", ErrSmokeUnavailable)
	}
	return nil
}

// InspectLocalKVMPreflight performs only environment inspection; it does not launch a VMM.
func InspectLocalKVMPreflight() KVMPreflight {
	preflight := KVMPreflight{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	info, err := os.Stat("/dev/kvm")
	preflight.KVMCharacterDevice = err == nil && info.Mode()&os.ModeCharDevice != 0
	if preflight.KVMCharacterDevice {
		file, openErr := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
		preflight.KVMReadWrite = openErr == nil
		if file != nil {
			_ = file.Close()
		}
	}
	_, err = os.Stat("/sys/fs/cgroup/cgroup.controllers")
	preflight.CgroupV2 = err == nil
	return preflight
}

// Run executes a protected smoke run. It never invokes Launch until the compiled plan and fixture set are complete.
func (harness SmokeHarness) Run(ctx context.Context, plan Plan, fixtures FixtureSet) (evidence SmokeEvidence, err error) {
	if harness.Host == nil || harness.Timeout <= 0 || !validCompiledPlan(plan) || !fixturesMatchPlan(fixtures, plan) {
		return SmokeEvidence{}, fmt.Errorf("%w: complete host, timeout, plan, and verified fixtures are required", ErrSmokeUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, harness.Timeout)
	defer cancel()
	cleanupTimeout := harness.Timeout
	if cleanupTimeout > maximumCleanupTimeout {
		cleanupTimeout = maximumCleanupTimeout
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cleanupCancel()
		proof, cleanupErr := harness.Host.Cleanup(cleanupCtx)
		evidence.Cleanup = proof
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("cleanup protected Firecracker resources: %w", cleanupErr))
		}
		if !proof.Proved {
			if proof.Reason == "" {
				proof.Reason = "cleanup proof is absent"
				evidence.Cleanup = proof
			}
			err = errors.Join(err, fmt.Errorf("cleanup protected Firecracker resources: cleanup proof is absent"))
		}
		if err != nil {
			evidence.Result = EvidenceBlocked
		}
	}()
	if err := harness.Host.Preflight(ctx, plan, fixtures); err != nil {
		return SmokeEvidence{}, fmt.Errorf("%w: preflight: %v", ErrSmokeUnavailable, err)
	}
	request, err := harness.Host.Prepare(ctx, plan, fixtures)
	if err != nil {
		return SmokeEvidence{}, fmt.Errorf("prepare jailed rootfs: %w", err)
	}
	if !safeAbsolutePath(request.JailerPath) || len(request.JailerArguments) == 0 || request.CgroupVersion != 2 || request.NetworkInterfaces != 0 || request.RootFSCopyPath == "" || request.SerialMarker == "" {
		return SmokeEvidence{}, fmt.Errorf("%w: incomplete no-NIC jailed request", ErrSmokeUnavailable)
	}
	if err := harness.Host.Launch(ctx, request); err != nil {
		return SmokeEvidence{}, fmt.Errorf("launch jailer: %w", err)
	}
	if err := harness.Host.AwaitSerial(ctx, request.SerialMarker); err != nil {
		return SmokeEvidence{}, fmt.Errorf("await guest serial marker: %w", err)
	}
	if err := harness.Host.Control(ctx); err != nil {
		return SmokeEvidence{}, fmt.Errorf("guest control channel: %w", err)
	}
	return SmokeEvidence{SchemaVersion: "firecracker.smoke-evidence/v1", ProofLevel: ProofLevelLinuxKVME2E, Result: EvidencePassed, SerialMarker: request.SerialMarker}, nil
}

func fixturesMatchPlan(set FixtureSet, plan Plan) bool {
	for name, want := range planArtifacts(plan) {
		got, ok := set.artifacts[name]
		if !ok || !validArtifact(got) || got != want {
			return false
		}
	}
	return set.verified && len(set.artifacts) == 4 && safeAbsolutePath(set.directory)
}

func planArtifacts(plan Plan) map[FixtureName]PinnedArtifact {
	return map[FixtureName]PinnedArtifact{FixtureFirecracker: plan.Firecracker(), FixtureJailer: plan.Jailer(), FixtureKernel: plan.Kernel(), FixtureRootFS: plan.RootFS()}
}

func digest(content []byte) sandbox.Digest {
	return sandbox.Digest(fmt.Sprintf("sha256:%x", sha256.Sum256(content)))
}
