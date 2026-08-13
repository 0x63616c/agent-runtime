// Command firecracker-smoke runs the protected no-NIC Firecracker smoke path
// only after its exact runner, fixture, and Jailer inputs are present.
package main

import (
	"bytes"
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
	"strings"
	"syscall"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
	"github.com/0x63616c/agent-runtime/sandbox"
)

const runnerContract = "protected-linux-kvm-v1"

const directExecutionMode = "direct"

const directKVMConfigPath = "/var/lib/agent-runtime/firecracker-direct/kvm-config.json"
const directFixtureLockPath = "/var/lib/agent-runtime/firecracker-fixtures/home-server/fixtures.lock"
const directFixtureSourceMapPath = "/var/lib/agent-runtime/firecracker-direct/fixture-source-map.json"

type report struct {
	SchemaVersion           string                     `json:"schema_version"`
	ProofLevel              string                     `json:"proof_level"`
	Result                  firecracker.EvidenceResult `json:"result"`
	Preflight               firecracker.KVMPreflight   `json:"preflight"`
	FixtureVersion          string                     `json:"fixture_version,omitempty"`
	FixtureDigests          map[string]string          `json:"fixture_digests,omitempty"`
	SerialMarker            string                     `json:"serial_marker,omitempty"`
	Cleanup                 firecracker.CleanupProof   `json:"cleanup,omitempty"`
	Reason                  string                     `json:"reason,omitempty"`
	ExecutionMode           string                     `json:"execution_mode,omitempty"`
	directEvidenceDirectory string
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
	executionMode := flag.String("execution-mode", "protected", "protected or direct execution authority")
	directConfigPath := flag.String("direct-config", directKVMConfigPath, "root-owned direct KVM configuration")
	directFixtureSourceMap := flag.String("direct-fixture-source-map", directFixtureSourceMapPath, "root-owned direct fixture source map")
	timeout := flag.Duration("timeout", 2*time.Minute, "bounded protected smoke timeout")
	flag.Parse()
	if *reportPath == "" {
		fmt.Fprintln(os.Stderr, "firecracker-smoke: -report is required")
		os.Exit(2)
	}
	if *executionMode == directExecutionMode && !validDirectEvidenceReportPath(*reportPath) {
		fmt.Fprintln(os.Stderr, "firecracker-smoke: direct execution report must be a clean JSON path beneath /var/lib/agent-runtime/firecracker-evidence")
		os.Exit(2)
	}

	record := report{SchemaVersion: "firecracker.smoke-evidence/v2", ProofLevel: firecracker.ProofLevelLinuxKVME2E, Result: firecracker.EvidenceBlocked, Preflight: firecracker.InspectLocalKVMPreflight()}
	err := run(recordRunnerConfig{fixtureLockPath: *fixtureLockPath, reportPath: *reportPath, vmID: *vmID, uid: *uid, gid: *gid, cgroupParent: *cgroupParent, stackResource: *stackResource, externalOwner: *externalOwner, executionMode: *executionMode, directConfigPath: *directConfigPath, directFixtureSourceMapPath: *directFixtureSourceMap, timeout: *timeout}, &record)
	write := writeReport
	if *executionMode == directExecutionMode {
		write = writeDirectReport
	}
	if writeErr := write(*reportPath, record); writeErr != nil {
		fmt.Fprintf(os.Stderr, "firecracker-smoke: write report: %v\n", writeErr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "firecracker-smoke:", record.Reason)
		os.Exit(1)
	}
}

type recordRunnerConfig struct {
	fixtureLockPath, reportPath, vmID, cgroupParent, stackResource, externalOwner, executionMode, directConfigPath, directFixtureSourceMapPath string
	uid, gid                                                                                                                                   uint64
	timeout                                                                                                                                    time.Duration
}

func run(config recordRunnerConfig, record *report) (err error) {
	if record == nil {
		return errors.New("smoke report is required")
	}
	if config.executionMode == "" {
		config.executionMode = "protected"
	}
	record.ExecutionMode = config.executionMode
	if config.executionMode == "protected" && os.Getenv("FIRECRACKER_RUNNER_CONTRACT") != runnerContract {
		return block(record, "protected self-hosted KVM runner contract is absent")
	}
	var fetcher firecracker.FixtureFetcher = lockedHTTPSFetcher{}
	if config.executionMode == directExecutionMode {
		localFetcher, err := validateDirectExecutionBinding(config, record)
		if err != nil {
			return block(record, err.Error())
		}
		fetcher = localFetcher
	}
	if config.executionMode != "protected" && config.executionMode != directExecutionMode {
		return block(record, "execution mode must be protected or direct")
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
	fixtures, err := firecracker.ProvisionFixtures(ctx, lock, fetcher, filepath.Join(workDirectory, "fixtures"))
	if err != nil {
		return block(record, "verified fixture provisioning failed")
	}
	record.FixtureVersion = fixtures.FixtureVersion()
	record.FixtureDigests = fixtureDigests(fixtures)
	compileSmokePlan := firecracker.CompileProtectedSmokePlan
	if config.executionMode == directExecutionMode {
		compileSmokePlan = firecracker.CompileDirectSmokePlan
	}
	plan, authority, err := compileSmokePlan(firecracker.ProtectedSmokeConfig{
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
		return block(record, smokeObservationFailureReason(err))
	}
	return nil
}

// smokeObservationFailureReason exposes the failed proof boundary without
// retaining arbitrary process, guest, API, or environment output in an
// operator evidence record. SmokeHarness wraps each lifecycle edge with one
// of these fixed prefixes; errors below that edge can include host-specific
// details and are deliberately not copied into the redacted report.
func smokeObservationFailureReason(err error) string {
	const prefix = "protected smoke harness did not retain a complete boot/control/cleanup observation"
	if err == nil {
		return prefix
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "prepare jailed rootfs:"):
		return prefix + ": Jailer fixture staging failed"
	case strings.Contains(message, "await Firecracker API socket"):
		// The Jailer has been started, but Firecracker did not expose its
		// private API socket before the bounded launch context ended. Keep the
		// host-specific Jailer stderr out of the durable report while retaining
		// the actionable lifecycle boundary.
		return prefix + ": Firecracker API socket was not observed"
	case strings.Contains(message, "launch jailer:"):
		return prefix + ": Jailer or Firecracker launch failed"
	case strings.Contains(message, "await guest serial marker:"):
		return prefix + ": guest serial boot marker was not observed"
	case strings.Contains(message, "guest control channel:"):
		return prefix + ": private guest control handshake failed"
	case strings.Contains(message, "cleanup protected Firecracker resources:"):
		return prefix + ": Jailer cleanup proof failed"
	default:
		return prefix + ": an unclassified bounded smoke lifecycle edge failed"
	}
}

type directExecutionBinding struct {
	Version             string `json:"version"`
	ExecutionNamespace  string `json:"execution_namespace"`
	EvidenceDirectory   string `json:"evidence_directory"`
	JailerChrootBaseDir string `json:"jailer_chroot_base_dir"`
	CgroupParent        string `json:"cgroup_parent"`
	StackResource       string `json:"stack_resource"`
	ExternalOwner       string `json:"external_owner"`
	JailerUID           uint32 `json:"jailer_uid"`
	JailerGID           uint32 `json:"jailer_gid"`
}

// validateDirectExecutionBinding makes the post-preflight smoke command use
// exactly the root-owned direct authority, rather than trusting repeated shell
// arguments. The preflight has already verified ownership, directories, KVM,
// and fixture provenance before this binding is read.
func validateDirectExecutionBinding(config recordRunnerConfig, record *report) (firecracker.FixtureFetcher, error) {
	if config.directConfigPath != directKVMConfigPath {
		return nil, errors.New("direct Firecracker config path does not match the reviewed authority")
	}
	info, err := os.Stat(config.directConfigPath)
	if err != nil || validateRootOwnedDirect(info) != nil {
		return nil, errors.New("root-owned direct KVM config is unavailable after preflight")
	}
	contents, err := os.ReadFile(config.directConfigPath)
	if err != nil {
		return nil, errors.New("root-owned direct KVM config is unavailable after preflight")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var binding directExecutionBinding
	if err := decoder.Decode(&binding); err != nil {
		return nil, errors.New("root-owned direct KVM config is invalid after preflight")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("root-owned direct KVM config has trailing data after preflight")
	}
	if binding.Version != "agent-runtime.firecracker-direct-kvm/v1" || !validDirectName(binding.ExecutionNamespace) || !validDirectEvidenceDirectory(binding.EvidenceDirectory) || binding.JailerChrootBaseDir != "/var/lib/agent-runtime/firecracker-jailer" || !validDirectRelativePath(binding.CgroupParent) || !validDirectName(binding.StackResource) || !validDirectName(binding.ExternalOwner) || binding.JailerUID == 0 || binding.JailerGID == 0 || config.uid != uint64(binding.JailerUID) || config.gid != uint64(binding.JailerGID) || config.cgroupParent != binding.CgroupParent || config.stackResource != binding.StackResource || config.externalOwner != binding.ExternalOwner || !strings.HasPrefix(config.vmID, binding.ExecutionNamespace+"-") {
		return nil, errors.New("direct smoke inputs do not match the root-owned direct KVM authority")
	}
	for _, path := range []string{binding.JailerChrootBaseDir, binding.EvidenceDirectory, filepath.Join("/sys/fs/cgroup", binding.CgroupParent)} {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() || validateRootOwnedDirect(info) != nil {
			return nil, errors.New("root-owned direct KVM directories changed after preflight")
		}
	}
	if filepath.Dir(config.reportPath) != binding.EvidenceDirectory || !validDirectEvidenceReportPath(config.reportPath) {
		return nil, errors.New("direct smoke report does not use the root-owned configured evidence directory")
	}
	if config.fixtureLockPath != directFixtureLockPath {
		return nil, errors.New("direct fixture lock does not use the root-owned direct fixture authority")
	}
	localFetcher, err := loadDirectFixtureSourceMap(config.directFixtureSourceMapPath, config.fixtureLockPath)
	if err != nil {
		return nil, err
	}
	record.directEvidenceDirectory = binding.EvidenceDirectory
	return localFetcher, nil
}

func validateRootOwnedDirect(info os.FileInfo) error {
	if info == nil {
		return errors.New("missing file information")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("must be root-owned and not writable by group or others")
	}
	return nil
}

func validDirectEvidenceDirectory(value string) bool {
	const directEvidenceRoot = "/var/lib/agent-runtime/firecracker-evidence"
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != directEvidenceRoot && strings.HasPrefix(value, directEvidenceRoot+"/")
}

func validDirectRelativePath(value string) bool {
	return value != "" && filepath.Clean(value) == value && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && !strings.Contains(value, "//")
}

func validDirectName(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n/")
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

func writeDirectReport(path string, record report) error {
	if record.directEvidenceDirectory == "" || filepath.Dir(path) != record.directEvidenceDirectory || !validDirectEvidenceReportPath(path) {
		return errors.New("direct evidence destination is not bound to root-owned configuration")
	}
	contents, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create immutable direct evidence report: %w", err)
	}
	if _, writeErr := file.Write(append(contents, '\n')); writeErr != nil {
		_ = file.Close()
		return writeErr
	}
	if syncErr := file.Sync(); syncErr != nil {
		_ = file.Close()
		return syncErr
	}
	return file.Close()
}

func validDirectEvidenceReportPath(path string) bool {
	const directEvidenceRoot = "/var/lib/agent-runtime/firecracker-evidence"
	return filepath.IsAbs(path) && filepath.Clean(path) == path && strings.HasPrefix(path, directEvidenceRoot+"/") && strings.HasSuffix(path, ".json")
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
	defer func() { _ = input.Close() }()
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
