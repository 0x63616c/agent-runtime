package firecracker

import (
	"fmt"
	"path"
	"strings"
)

const linuxJailerSecretContainmentVersion = "firecracker.jailer-secret-containment/v1"

// SecretContainmentManifest is the fixed launch configuration a future
// protected guest must consume before accepting a command secret. It records
// only cgroup and guest-mount policy, never a secret value, host path, or
// capability promotion. Its presence is a prerequisite/refusal input, not
// Linux/KVM or ptrace/proc containment evidence.
type SecretContainmentManifest struct {
	Version                   string
	VMID                      string
	HostCgroupPath            string
	GuestCgroupPath           string
	SecretAreaPath            string
	SecretAreaFilesystem      string
	SecretAreaMountOptions    []string
	ProcMountPath             string
	ProcFilesystem            string
	ProcMountOptions          []string
	MountNamespaceRequired    bool
	SnapshotExclusionRequired bool
	CgroupV2LifecycleRequired bool
}

// CompileSecretContainmentManifest derives one exact protected-secret launch
// configuration from the same Plan and Jailer authority used to start the VM.
// Callers cannot choose its cgroup, secret-area, or /proc paths. The result
// remains an unavailable-profile prerequisite until a protected Linux/KVM
// fixture proves that the guest initializer applied it.
func CompileSecretContainmentManifest(plan Plan, authority JailerExecutionAuthority) (SecretContainmentManifest, error) {
	if !validCompiledPlan(plan) || !validJailerExecutionAuthority(authority, plan) {
		return SecretContainmentManifest{}, fmt.Errorf("compile Jailer secret containment manifest: %w", ErrCapabilityUnavailable)
	}
	manifest := SecretContainmentManifest{
		Version:                   linuxJailerSecretContainmentVersion,
		VMID:                      plan.VMID(),
		HostCgroupPath:            authority.CgroupPath(),
		GuestCgroupPath:           "/agent-runtime/secrets/" + plan.VMID(),
		SecretAreaPath:            "/run/agent-runtime/secrets/" + plan.VMID(),
		SecretAreaFilesystem:      "tmpfs",
		SecretAreaMountOptions:    []string{"mode=0700", "nodev", "noexec", "nosuid"},
		ProcMountPath:             "/proc",
		ProcFilesystem:            "proc",
		ProcMountOptions:          []string{"hidepid=2", "nodev", "noexec", "nosuid", "subset=pid"},
		MountNamespaceRequired:    true,
		SnapshotExclusionRequired: true,
		CgroupV2LifecycleRequired: true,
	}
	if !validSecretContainmentManifest(manifest, plan, authority) {
		return SecretContainmentManifest{}, fmt.Errorf("compile Jailer secret containment manifest: %w", ErrCapabilityUnavailable)
	}
	return cloneSecretContainmentManifest(manifest), nil
}

// SecretContainmentConfigured reports whether the manifest is still exactly
// bound to plan and authority. It says nothing about an applied guest mount,
// cgroup, ptrace/proc policy, snapshot exclusion, or protected KVM run.
func (manifest SecretContainmentManifest) SecretContainmentConfigured(plan Plan, authority JailerExecutionAuthority) bool {
	return validSecretContainmentManifest(manifest, plan, authority)
}

func validSecretContainmentManifest(manifest SecretContainmentManifest, plan Plan, authority JailerExecutionAuthority) bool {
	return manifest.Version == linuxJailerSecretContainmentVersion && validCompiledPlan(plan) && validJailerExecutionAuthority(authority, plan) && manifest.VMID == plan.VMID() && manifest.HostCgroupPath == authority.CgroupPath() && manifest.GuestCgroupPath == "/agent-runtime/secrets/"+plan.VMID() && manifest.SecretAreaPath == "/run/agent-runtime/secrets/"+plan.VMID() && manifest.SecretAreaFilesystem == "tmpfs" && sameStrings(manifest.SecretAreaMountOptions, []string{"mode=0700", "nodev", "noexec", "nosuid"}) && manifest.ProcMountPath == "/proc" && manifest.ProcFilesystem == "proc" && sameStrings(manifest.ProcMountOptions, []string{"hidepid=2", "nodev", "noexec", "nosuid", "subset=pid"}) && manifest.MountNamespaceRequired && manifest.SnapshotExclusionRequired && manifest.CgroupV2LifecycleRequired && validSecretContainmentGuestPaths(manifest)
}

func validSecretContainmentGuestPaths(manifest SecretContainmentManifest) bool {
	for _, value := range []string{manifest.GuestCgroupPath, manifest.SecretAreaPath, manifest.ProcMountPath} {
		if !strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "/" || strings.Contains(value, "//") {
			return false
		}
	}
	return true
}

func cloneSecretContainmentManifest(manifest SecretContainmentManifest) SecretContainmentManifest {
	manifest.SecretAreaMountOptions = append([]string(nil), manifest.SecretAreaMountOptions...)
	manifest.ProcMountOptions = append([]string(nil), manifest.ProcMountOptions...)
	return manifest
}
