// Command firecracker-smoke runs the protected no-NIC Firecracker smoke path
// only after its exact runner, fixture, and Jailer inputs are present.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
	"github.com/0x63616c/agent-runtime/sandbox"
)

const runnerContract = "protected-linux-kvm-v1"

type report struct {
	SchemaVersion  string                     `json:"schema_version"`
	ProofLevel     string                     `json:"proof_level"`
	Result         firecracker.EvidenceResult `json:"result"`
	Preflight      firecracker.KVMPreflight   `json:"preflight"`
	FixtureVersion string                     `json:"fixture_version,omitempty"`
	FixtureDigests map[string]string          `json:"fixture_digests,omitempty"`
	SerialMarker   string                     `json:"serial_marker,omitempty"`
	Cleanup        firecracker.CleanupProof   `json:"cleanup,omitempty"`
	Reason         string                     `json:"reason,omitempty"`
}

func main() {
	reportPath := flag.String("report", "", "required path for a redacted smoke report")
	fixtureLockPath := flag.String("fixture-lock", "tools/firecracker/fixtures.lock", "reviewed firecracker.fixtures/v2 lock")
	vmID := flag.String("vm-id", "", "required unique Jailer-safe VM ID")
	uid := flag.Uint64("uid", 0, "required unprivileged Jailer UID")
	gid := flag.Uint64("gid", 0, "required unprivileged Jailer GID")
	cgroupParent := flag.String("cgroup-parent", "", "required delegated cgroup-v2 parent relative to /sys/fs/cgroup")
	stackResource := flag.String("stack-resource", "", "required declared Stack resource owning the cgroup parent")
	externalOwner := flag.String("external-owner", "", "required declared Stack resource owning non-Jailer smoke limits")
	timeout := flag.Duration("timeout", 2*time.Minute, "bounded protected smoke timeout")
	flag.Parse()
	if *reportPath == "" {
		fmt.Fprintln(os.Stderr, "firecracker-smoke: -report is required")
		os.Exit(2)
	}

	record := report{SchemaVersion: "firecracker.smoke-evidence/v2", ProofLevel: firecracker.ProofLevelLinuxKVME2E, Result: firecracker.EvidenceBlocked, Preflight: firecracker.InspectLocalKVMPreflight()}
	err := run(recordRunnerConfig{fixtureLockPath: *fixtureLockPath, vmID: *vmID, uid: *uid, gid: *gid, cgroupParent: *cgroupParent, stackResource: *stackResource, externalOwner: *externalOwner, timeout: *timeout}, &record)
	if writeErr := writeReport(*reportPath, record); writeErr != nil {
		fmt.Fprintf(os.Stderr, "firecracker-smoke: write report: %v\n", writeErr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "firecracker-smoke:", record.Reason)
		os.Exit(1)
	}
}

type recordRunnerConfig struct {
	fixtureLockPath, vmID, cgroupParent, stackResource, externalOwner string
	uid, gid                                                          uint64
	timeout                                                           time.Duration
}

func run(config recordRunnerConfig, record *report) (err error) {
	if record == nil {
		return errors.New("smoke report is required")
	}
	if os.Getenv("FIRECRACKER_RUNNER_CONTRACT") != runnerContract {
		return block(record, "protected self-hosted KVM runner contract is absent")
	}
	if err := record.Preflight.Validate(); err != nil {
		return block(record, err.Error())
	}
	if config.fixtureLockPath == "" || config.vmID == "" || config.uid == 0 || config.gid == 0 || config.uid > math.MaxUint32 || config.gid > math.MaxUint32 || config.cgroupParent == "" || config.stackResource == "" || config.externalOwner == "" || config.timeout <= 0 || config.timeout > 5*time.Minute {
		return block(record, "reviewed fixture lock, VM identity, unprivileged Jailer identity, cgroup authority, external limit owner, and bounded timeout are required")
	}
	lockFile, err := os.Open(config.fixtureLockPath)
	if err != nil {
		return block(record, "reviewed fixture lock is unavailable")
	}
	lock, parseErr := firecracker.ParseFixtureLock(lockFile)
	closeErr := lockFile.Close()
	if parseErr != nil || closeErr != nil {
		return block(record, "reviewed fixture lock is invalid")
	}
	workDirectory, err := os.MkdirTemp("", "agent-runtime-firecracker-smoke-")
	if err != nil {
		return block(record, "private fixture staging directory is unavailable")
	}
	defer func() {
		cleanupErr := os.RemoveAll(workDirectory)
		if cleanupErr == nil {
			if _, statErr := os.Lstat(workDirectory); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
				cleanupErr = errors.New("private fixture staging directory remains")
			}
		}
		if cleanupErr != nil {
			err = block(record, "private fixture staging cleanup failed")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()
	fixtures, err := firecracker.ProvisionFixtures(ctx, lock, lockedHTTPSFetcher{}, filepath.Join(workDirectory, "fixtures"))
	if err != nil {
		return block(record, "verified fixture provisioning failed")
	}
	record.FixtureVersion = fixtures.FixtureVersion()
	record.FixtureDigests = fixtureDigests(fixtures)
	plan, authority, err := firecracker.CompileProtectedSmokePlan(firecracker.ProtectedSmokeConfig{
		VMID:          config.vmID,
		UID:           uint32(config.uid),
		GID:           uint32(config.gid),
		ExternalOwner: config.externalOwner,
		Cgroup: firecracker.JailerCgroupAssignment{
			Version:       "firecracker.jailer-cgroup/v1",
			StackResource: config.stackResource,
			Parent:        config.cgroupParent,
		},
	}, fixtures)
	if err != nil {
		return block(record, "protected smoke plan or Jailer authority is invalid")
	}
	rootFS, ok := fixtures.Artifact(firecracker.FixtureRootFS)
	if !ok {
		return block(record, "verified rootfs fixture is unavailable")
	}
	privateRootFS := filepath.Join(workDirectory, "rootfs.ext4")
	if err := copyPrivateRootFS(ctx, rootFS.Path, privateRootFS, rootFS.Digest); err != nil {
		return block(record, "private rootfs copy integrity check failed")
	}
	host, err := firecracker.NewLinuxJailerHost(firecracker.LinuxJailerHostConfig{
		Plan:           plan,
		PreflightState: record.Preflight,
		RootFSCopyPath: privateRootFS,
		Authority:      authority,
		UnixDialer:     &net.Dialer{},
	})
	if err != nil {
		return block(record, "protected Linux Jailer host composition failed")
	}
	evidence, err := (firecracker.SmokeHarness{Host: host, Timeout: config.timeout}).Run(ctx, plan, fixtures)
	record.Cleanup, record.SerialMarker, record.Result = evidence.Cleanup, evidence.SerialMarker, evidence.Result
	if err != nil {
		return block(record, "protected smoke harness did not retain a complete boot/control/cleanup observation")
	}
	return nil
}

func block(record *report, reason string) error {
	record.Result = firecracker.EvidenceBlocked
	record.Reason = reason
	return errors.New(reason)
}

func writeReport(path string, record report) error {
	if !filepath.IsAbs(path) && filepath.Clean(path) != path {
		return errors.New("report path must be clean")
	}
	contents, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(contents, '\n'), 0o600)
}

func fixtureDigests(fixtures firecracker.FixtureSet) map[string]string {
	digests := make(map[string]string, len(fixtures.Names()))
	for _, name := range fixtures.Names() {
		if artifact, ok := fixtures.Artifact(name); ok {
			digests[string(name)] = string(artifact.Digest)
		}
	}
	return digests
}

func copyPrivateRootFS(ctx context.Context, source, destination string, expected sandbox.Digest) error {
	if ctx == nil || source == "" || destination == "" || filepath.Dir(destination) == "." {
		return errors.New("private rootfs source and destination are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	const maximumSmokeRootFSBytes = int64(1 << 30)
	bytesCopied, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, maximumSmokeRootFSBytes+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || bytesCopied > maximumSmokeRootFSBytes || "sha256:"+fmt.Sprintf("%x", hash.Sum(nil)) != string(expected) {
		_ = os.Remove(destination)
		return errors.New("private rootfs differs from verified fixture")
	}
	return ctx.Err()
}

// lockedHTTPSFetcher does not follow redirects or use ambient proxy settings.
// ProvisionFixtures has already validated each exact lock URL and digest.
type lockedHTTPSFetcher struct{}

func (lockedHTTPSFetcher) Open(ctx context.Context, source string) (firecracker.FixtureResponse, error) {
	if ctx == nil {
		return firecracker.FixtureResponse{}, errors.New("fixture context is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Fragment != "" {
		return firecracker.FixtureResponse{}, errors.New("locked HTTPS source is required")
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false}
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		return firecracker.FixtureResponse{}, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return firecracker.FixtureResponse{}, fmt.Errorf("fixture source returned HTTP %d", response.StatusCode)
	}
	return firecracker.FixtureResponse{Body: response.Body, ContentLength: response.ContentLength}, nil
}
