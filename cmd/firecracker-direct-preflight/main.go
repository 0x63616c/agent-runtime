// Command firecracker-direct-preflight validates an operator-owned Linux/KVM
// boundary before a direct Firecracker smoke run. It performs no provisioning,
// downloads no fixture, and starts no virtual machine.
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
	"strings"
	"syscall"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

const (
	directConfigVersion = "agent-runtime.firecracker-direct-kvm/v1"
	directConfigPath    = "/etc/agent-runtime/firecracker-direct-kvm.json"
	directEvidenceRoot  = "/var/lib/agent-runtime/firecracker-evidence"
	directFixtureLock   = "/var/lib/agent-runtime/firecracker-fixtures/home-server/fixtures.lock"
	fixtureLockVersion  = "firecracker.fixtures/v2"
)

// directConfig is root-owned operator configuration. It deliberately names
// the one isolated Jailer namespace and one redacted evidence directory used
// by direct runs; it contains no credentials.
type directConfig struct {
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

func main() {
	configPath := flag.String("config", directConfigPath, "root-owned direct KVM configuration")
	fixtureLockPath := flag.String("fixture-lock", directFixtureLock, "root-owned direct Firecracker fixture lock")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "firecracker-direct-preflight: arguments are not accepted")
		os.Exit(2)
	}
	if err := run(*configPath, *fixtureLockPath, os.Stat, runtime.GOOS, runtime.GOARCH); err != nil {
		fmt.Fprintln(os.Stderr, "firecracker-direct-preflight:", err)
		os.Exit(1)
	}
	fmt.Println("direct Firecracker KVM preflight passed; no fixture was downloaded and no VM was started")
}

func run(configPath, fixtureLockPath string, stat func(string) (os.FileInfo, error), goos, goarch string) error {
	if goos != "linux" || goarch != "amd64" {
		return errors.New("direct Firecracker execution requires linux/amd64")
	}
	if configPath != directConfigPath {
		return errors.New("direct Firecracker config path does not match the reviewed authority")
	}
	info, err := stat(configPath)
	if err != nil {
		return fmt.Errorf("stat root-owned direct config: %w", err)
	}
	if err := validateRootOwned(info); err != nil {
		return fmt.Errorf("root-owned direct config: %w", err)
	}
	configured, err := readConfig(configPath)
	if err != nil {
		return err
	}
	if err := validateConfig(configured, stat); err != nil {
		return err
	}
	if err := validateKVM(stat); err != nil {
		return err
	}
	return validateFixtureLock(fixtureLockPath)
}

func readConfig(path string) (directConfig, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return directConfig{}, fmt.Errorf("read root-owned direct config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var configured directConfig
	if err := decoder.Decode(&configured); err != nil {
		return directConfig{}, fmt.Errorf("decode root-owned direct config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return directConfig{}, errors.New("root-owned direct config has trailing data")
	}
	return configured, nil
}

func validateConfig(configured directConfig, stat func(string) (os.FileInfo, error)) error {
	if configured.Version != directConfigVersion || !validName(configured.ExecutionNamespace) || !validEvidenceDirectory(configured.EvidenceDirectory) || configured.JailerChrootBaseDir != "/srv/agent-runtime/jailer" || !validRelativePath(configured.CgroupParent) || !validName(configured.StackResource) || !validName(configured.ExternalOwner) || configured.JailerUID == 0 || configured.JailerGID == 0 {
		return errors.New("root-owned direct config has invalid namespace, evidence, jailer, or cgroup authority")
	}
	for description, path := range map[string]string{
		"root-owned isolated Jailer base directory": configured.JailerChrootBaseDir,
		"root-owned direct evidence directory":      configured.EvidenceDirectory,
		"root-owned delegated cgroup parent":        filepath.Join("/sys/fs/cgroup", configured.CgroupParent),
	} {
		info, err := stat(path)
		if err != nil {
			return fmt.Errorf("stat %s: %w", description, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", description)
		}
		if err := validateRootOwned(info); err != nil {
			return fmt.Errorf("%s: %w", description, err)
		}
	}
	return nil
}

func validateKVM(stat func(string) (os.FileInfo, error)) error {
	info, err := stat("/dev/kvm")
	if err != nil {
		return fmt.Errorf("stat /dev/kvm: %w", err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("/dev/kvm is not a character device")
	}
	file, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/kvm read/write: %w", err)
	}
	return file.Close()
}

func validateFixtureLock(path string) error {
	if path != directFixtureLock {
		return errors.New("fixture lock path does not match the direct evidence authority")
	}
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
	if lock.Version != fixtureLockVersion {
		return errors.New("reviewed fixture lock version does not match direct KVM authority")
	}
	required := map[string]bool{"firecracker-release": false, "kernel": false, "rootfs": false, "guest-agent": false}
	for _, source := range lock.Sources {
		if _, ok := required[source.ID]; ok {
			required[source.ID] = true
		}
	}
	for id, present := range required {
		if !present {
			return fmt.Errorf("reviewed fixture lock is missing required source %q", id)
		}
	}
	return nil
}

func validateRootOwned(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("must be owned by root")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("must not be writable by group or others")
	}
	return nil
}

func validEvidenceDirectory(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != directEvidenceRoot && strings.HasPrefix(value, directEvidenceRoot+"/")
}

func validRelativePath(value string) bool {
	return value != "" && filepath.Clean(value) == value && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && !strings.Contains(value, "//")
}

func validName(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n/")
}
