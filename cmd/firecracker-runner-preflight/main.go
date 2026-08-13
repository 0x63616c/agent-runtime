// Command firecracker-runner-preflight validates the static bootstrap contract
// required before a protected Firecracker KVM workflow can mint smoke evidence.
// It never provisions a runner, changes cgroups, downloads fixtures, or reads
// credentials.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

const runnerContract = "protected-linux-kvm-v1"

type contract struct {
	Version           int    `json:"version"`
	Purpose           string `json:"purpose"`
	GitHubEnvironment string `json:"github_environment"`
	Runner            struct {
		RequiredLabels   []string `json:"required_labels"`
		RequiredWorkflow string   `json:"required_workflow"`
		ProtectedRef     bool     `json:"protected_ref_required"`
		Platform         struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"platform"`
		KVMDevice string `json:"kvm_device"`
	} `json:"runner"`
	Bootstrap struct {
		ConfigPath                          string   `json:"config_path"`
		OwnerUID                            uint32   `json:"owner_uid"`
		ConfigMustBeRootOwned               bool     `json:"config_must_be_root_owned"`
		ConfigMustNotBeGroupOrOtherWritable bool     `json:"config_must_not_be_group_or_other_writable"`
		RequiredFields                      []string `json:"required_fields"`
		JailerChrootBaseDir                 string   `json:"jailer_chroot_base_dir"`
		CgroupRoot                          string   `json:"cgroup_root"`
	} `json:"bootstrap"`
	Fixtures struct {
		LockPath                     string   `json:"lock_path"`
		LockVersion                  string   `json:"lock_version"`
		RequiredSourceIDs            []string `json:"required_source_ids"`
		ProjectReleaseAssetsRequired []string `json:"project_release_assets_required"`
	} `json:"fixtures"`
	SecretValuesInRepository bool   `json:"secret_values_in_repository"`
	ProvisioningStatus       string `json:"provisioning_status"`
}

// bootstrap is installed by the runner operator. It has no credentials: it
// binds protected workflow variables to the root-owned jailer/cgroup boundary.
type bootstrap struct {
	Version             string `json:"version"`
	JailerChrootBaseDir string `json:"jailer_chroot_base_dir"`
	CgroupParent        string `json:"cgroup_parent"`
	StackResource       string `json:"stack_resource"`
	ExternalOwner       string `json:"external_owner"`
	JailerUID           uint32 `json:"jailer_uid"`
	JailerGID           uint32 `json:"jailer_gid"`
}

func main() {
	contractPath := flag.String("contract", "deploy/firecracker/runner-contract.json", "machine-readable protected runner contract")
	bootstrapPath := flag.String("bootstrap-config", "", "root-owned Firecracker runner bootstrap configuration")
	fixtureLockPath := flag.String("fixture-lock", "", "reviewed Firecracker fixture lock")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "firecracker-runner-preflight: arguments are not accepted")
		os.Exit(2)
	}
	if err := run(*contractPath, *bootstrapPath, *fixtureLockPath, os.Getenv, os.Stat, runtime.GOOS, runtime.GOARCH); err != nil {
		fmt.Fprintln(os.Stderr, "firecracker-runner-preflight:", err)
		os.Exit(1)
	}
	fmt.Println("protected Firecracker KVM runner preflight passed; no fixture was downloaded and no VM was started")
}

func run(contractPath, bootstrapPath, fixtureLockPath string, getenv func(string) string, stat func(string) (os.FileInfo, error), goos, goarch string) error {
	loaded, err := readContract(contractPath)
	if err != nil {
		return err
	}
	if err := validateWorkflow(loaded, getenv, goos, goarch); err != nil {
		return err
	}
	if bootstrapPath == "" {
		bootstrapPath = getenv("FIRECRACKER_RUNNER_BOOTSTRAP_CONFIG")
	}
	if bootstrapPath != loaded.Bootstrap.ConfigPath {
		return errors.New("root-owned runner bootstrap config path does not match the reviewed contract")
	}
	info, err := stat(bootstrapPath)
	if err != nil {
		return fmt.Errorf("stat root-owned runner bootstrap config: %w", err)
	}
	if err := validateRootOwned(info, loaded.Bootstrap.OwnerUID); err != nil {
		return fmt.Errorf("root-owned runner bootstrap config: %w", err)
	}
	configured, err := readBootstrap(bootstrapPath)
	if err != nil {
		return err
	}
	if err := validateBootstrap(loaded, configured, getenv, stat); err != nil {
		return err
	}
	if fixtureLockPath == "" {
		fixtureLockPath = getenv("FIRECRACKER_FIXTURE_LOCK")
	}
	if fixtureLockPath != loaded.Fixtures.LockPath {
		return errors.New("fixture lock path does not match the reviewed contract")
	}
	if err := validateFixtureLock(loaded, fixtureLockPath); err != nil {
		return err
	}
	return nil
}

func readContract(path string) (contract, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return contract{}, fmt.Errorf("read runner contract: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var loaded contract
	if err := decoder.Decode(&loaded); err != nil {
		return contract{}, fmt.Errorf("decode runner contract: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return contract{}, errors.New("runner contract has trailing data")
	}
	if loaded.Version != 1 || loaded.Purpose != "Protected Firecracker KVM runner bootstrap contract" || loaded.GitHubEnvironment != "firecracker-kvm" || !loaded.Runner.ProtectedRef || loaded.Runner.RequiredWorkflow != "firecracker-kvm" || loaded.Runner.Platform.OS != "linux" || loaded.Runner.Platform.Architecture != "amd64" || loaded.Runner.KVMDevice != "/dev/kvm" || loaded.Bootstrap.ConfigPath != "/etc/agent-runtime/firecracker-kvm-runner.json" || loaded.Bootstrap.OwnerUID != 0 || !loaded.Bootstrap.ConfigMustBeRootOwned || !loaded.Bootstrap.ConfigMustNotBeGroupOrOtherWritable || !sameStrings(loaded.Bootstrap.RequiredFields, []string{"version", "jailer_chroot_base_dir", "cgroup_parent", "stack_resource", "external_owner", "jailer_uid", "jailer_gid"}) || loaded.Bootstrap.JailerChrootBaseDir != "/srv/agent-runtime/jailer" || loaded.Bootstrap.CgroupRoot != "/sys/fs/cgroup" || loaded.Fixtures.LockPath != "tools/firecracker/fixtures.lock" || loaded.Fixtures.LockVersion != "firecracker.fixtures/v2" || loaded.SecretValuesInRepository || loaded.ProvisioningStatus != "not_provisioned" || !sameStrings(loaded.Runner.RequiredLabels, []string{"self-hosted", "linux", "x64", "kvm", "firecracker-protected"}) || !sameStrings(loaded.Fixtures.RequiredSourceIDs, []string{"firecracker-release", "kernel", "rootfs", "guest-agent"}) || !sameStrings(loaded.Fixtures.ProjectReleaseAssetsRequired, []string{"kernel", "rootfs", "guest-agent"}) {
		return contract{}, errors.New("runner contract is incomplete or changed from the protected Firecracker KVM authority")
	}
	return loaded, nil
}

func validateWorkflow(loaded contract, getenv func(string) string, goos, goarch string) error {
	if getenv("FIRECRACKER_RUNNER_CONTRACT") != runnerContract {
		return errors.New("protected Firecracker runner contract is absent")
	}
	for name, want := range map[string]string{
		"GITHUB_ACTIONS":                 "true",
		"GITHUB_REF_PROTECTED":           "true",
		"GITHUB_WORKFLOW":                loaded.Runner.RequiredWorkflow,
		"RUNNER_ENVIRONMENT":             "self-hosted",
		"RUNNER_OS":                      "Linux",
		"RUNNER_ARCH":                    "X64",
		"FIRECRACKER_GITHUB_ENVIRONMENT": loaded.GitHubEnvironment,
		"FIRECRACKER_RUNNER_LABELS":      strings.Join(loaded.Runner.RequiredLabels, ","),
	} {
		if getenv(name) != want {
			return fmt.Errorf("protected Firecracker runner %s=%q is required", name, want)
		}
	}
	if goos != loaded.Runner.Platform.OS || goarch != loaded.Runner.Platform.Architecture {
		return fmt.Errorf("protected Firecracker runner requires %s/%s", loaded.Runner.Platform.OS, loaded.Runner.Platform.Architecture)
	}
	return nil
}

func readBootstrap(path string) (bootstrap, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return bootstrap{}, fmt.Errorf("read runner bootstrap config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var configured bootstrap
	if err := decoder.Decode(&configured); err != nil {
		return bootstrap{}, fmt.Errorf("decode runner bootstrap config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return bootstrap{}, errors.New("runner bootstrap config has trailing data")
	}
	return configured, nil
}

func validateBootstrap(loaded contract, configured bootstrap, getenv func(string) string, stat func(string) (os.FileInfo, error)) error {
	if configured.Version != "agent-runtime.firecracker-kvm-runner-bootstrap/v1" || configured.JailerChrootBaseDir != loaded.Bootstrap.JailerChrootBaseDir || configured.JailerUID == 0 || configured.JailerGID == 0 || !validRelativePath(configured.CgroupParent) || !validName(configured.StackResource) || !validName(configured.ExternalOwner) {
		return errors.New("root-owned runner bootstrap config has invalid jailer or cgroup authority")
	}
	for name, want := range map[string]string{
		"FIRECRACKER_JAILER_UID":     strconv.FormatUint(uint64(configured.JailerUID), 10),
		"FIRECRACKER_JAILER_GID":     strconv.FormatUint(uint64(configured.JailerGID), 10),
		"FIRECRACKER_CGROUP_PARENT":  configured.CgroupParent,
		"FIRECRACKER_STACK_RESOURCE": configured.StackResource,
		"FIRECRACKER_EXTERNAL_OWNER": configured.ExternalOwner,
	} {
		if getenv(name) != want {
			return fmt.Errorf("protected Firecracker runner %s does not match root-owned bootstrap config", name)
		}
	}
	jailerInfo, err := stat(configured.JailerChrootBaseDir)
	if err != nil {
		return fmt.Errorf("stat root-owned jailer base directory: %w", err)
	}
	if !jailerInfo.IsDir() {
		return errors.New("root-owned jailer base directory is not a directory")
	}
	if err := validateRootOwned(jailerInfo, loaded.Bootstrap.OwnerUID); err != nil {
		return fmt.Errorf("root-owned jailer base directory: %w", err)
	}
	cgroupInfo, err := stat(filepath.Join(loaded.Bootstrap.CgroupRoot, configured.CgroupParent))
	if err != nil {
		return fmt.Errorf("stat root-owned cgroup parent: %w", err)
	}
	if !cgroupInfo.IsDir() {
		return errors.New("root-owned cgroup parent is not a directory")
	}
	if err := validateRootOwned(cgroupInfo, loaded.Bootstrap.OwnerUID); err != nil {
		return fmt.Errorf("root-owned cgroup parent: %w", err)
	}
	kvmInfo, err := stat(loaded.Runner.KVMDevice)
	if err != nil {
		return fmt.Errorf("stat %s: %w", loaded.Runner.KVMDevice, err)
	}
	if kvmInfo.Mode()&os.ModeCharDevice == 0 {
		return errors.New("/dev/kvm is not a character device")
	}
	file, err := os.OpenFile(loaded.Runner.KVMDevice, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/kvm read/write: %w", err)
	}
	return file.Close()
}

func validateFixtureLock(loaded contract, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open reviewed fixture lock: %w", err)
	}
	lock, parseErr := firecracker.ParseFixtureLock(file)
	closeErr := file.Close()
	if parseErr != nil {
		return fmt.Errorf("parse reviewed fixture lock: %w", parseErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close reviewed fixture lock: %w", closeErr)
	}
	if lock.Version != loaded.Fixtures.LockVersion {
		return errors.New("reviewed fixture lock version does not match the protected runner contract")
	}
	sources := make(map[string]firecracker.LockedSource, len(lock.Sources))
	for _, source := range lock.Sources {
		sources[source.ID] = source
	}
	for _, id := range loaded.Fixtures.RequiredSourceIDs {
		if _, ok := sources[id]; !ok {
			return fmt.Errorf("reviewed fixture lock is missing required source %q", id)
		}
	}
	for _, id := range loaded.Fixtures.ProjectReleaseAssetsRequired {
		source := sources[id]
		if source.Kind != firecracker.FixtureSourceProjectReleaseAsset || !strings.HasPrefix(source.Reference, "commit:") {
			return fmt.Errorf("reviewed fixture lock %s source must be a commit-pinned project release asset", id)
		}
	}
	return nil
}

func validateRootOwned(info os.FileInfo, owner uint32) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner {
		return errors.New("must be owned by root")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("must not be writable by group or others")
	}
	return nil
}

func validRelativePath(value string) bool {
	return value != "" && filepath.Clean(value) == value && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && !strings.Contains(value, "//")
}

func validName(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
