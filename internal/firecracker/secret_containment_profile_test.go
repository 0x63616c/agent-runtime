package firecracker

import (
	"errors"
	"reflect"
	"testing"
)

func TestCompileSecretContainmentManifestBindsTheExactJailerAndGuestBoundary(t *testing.T) {
	plan := mustCompile(t, validProfile())
	authority := mustCompileJailerExecutionAuthority(t, plan)
	manifest, err := CompileSecretContainmentManifest(plan, authority)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.SecretContainmentConfigured(plan, authority) || manifest.HostCgroupPath != authority.CgroupPath() || manifest.GuestCgroupPath != "/agent-runtime/secrets/"+plan.VMID() || manifest.SecretAreaPath != "/run/agent-runtime/secrets/"+plan.VMID() || !manifest.MountNamespaceRequired || !manifest.SnapshotExclusionRequired || !manifest.CgroupV2LifecycleRequired {
		t.Fatalf("manifest = %#v, want exact unavailable secret boundary", manifest)
	}
	if got, want := manifest.SecretAreaMountOptions, []string{"mode=0700", "nodev", "noexec", "nosuid"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("secret-area mount options = %#v, want %#v", got, want)
	}
	if got, want := manifest.ProcMountOptions, []string{"hidepid=2", "nodev", "noexec", "nosuid", "subset=pid"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("proc mount options = %#v, want %#v", got, want)
	}
}

func TestSecretContainmentManifestAndHostCompositionRefuseSubstitution(t *testing.T) {
	plan := mustCompile(t, validProfile())
	authority := mustCompileJailerExecutionAuthority(t, plan)
	manifest, err := CompileSecretContainmentManifest(plan, authority)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SecretContainmentManifest){
		"different host cgroup": func(manifest *SecretContainmentManifest) { manifest.HostCgroupPath = "other/sandbox-001" },
		"shared secret area": func(manifest *SecretContainmentManifest) {
			manifest.SecretAreaPath = "/run/agent-runtime/secrets/shared"
		},
		"proc path substitution": func(manifest *SecretContainmentManifest) {
			manifest.ProcMountPath = "/proc/../other"
		},
		"snapshot guard omitted": func(manifest *SecretContainmentManifest) { manifest.SnapshotExclusionRequired = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneSecretContainmentManifest(manifest)
			mutate(&candidate)
			if candidate.SecretContainmentConfigured(plan, authority) {
				t.Fatal("SecretContainmentConfigured() accepted a substituted manifest")
			}
			if host, err := NewLinuxJailerHost(LinuxJailerHostConfig{Plan: plan, PreflightState: validKVMPreflight(), RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4", Authority: authority, SecretContainment: &candidate, UnixDialer: &recordingUnixDialer{}}); host != nil || !errors.Is(err, ErrSmokeUnavailable) {
				t.Fatalf("NewLinuxJailerHost() = (%#v, %v), want pre-I/O refusal", host, err)
			}
		})
	}

	host, err := NewLinuxJailerHost(LinuxJailerHostConfig{Plan: plan, PreflightState: validKVMPreflight(), RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4", Authority: authority, SecretContainment: &manifest, UnixDialer: &recordingUnixDialer{}})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := host.SecretContainmentManifest()
	if !ok || !got.SecretContainmentConfigured(plan, authority) {
		t.Fatalf("SecretContainmentManifest() = (%#v, %t)", got, ok)
	}
	got.SecretAreaMountOptions[0] = "mutated"
	again, ok := host.SecretContainmentManifest()
	if !ok || again.SecretAreaMountOptions[0] != "mode=0700" {
		t.Fatalf("host retained caller mutation = %#v", again)
	}
}
