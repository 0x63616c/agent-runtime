package firecracker

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestCompileCreatesJailedDenyAllFoundationPlan(t *testing.T) {
	profile := validProfile()
	plan, err := Compile(profile)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if !reflect.DeepEqual(plan.JailerArguments, []string{
		"--id", "sandbox-001", "--exec-file", "/opt/firecracker/firecracker", "--uid", "10001", "--gid", "10001", "--chroot-base-dir", "/srv/agent-runtime/jailer", "--cgroup-version", "2", "--", "--api-sock", "/run/firecracker.socket",
	}) {
		t.Errorf("JailerArguments = %#v", plan.JailerArguments)
	}
	if plan.Network.Mode != NetworkDenyAll || len(plan.Network.Allowlist) != 0 {
		t.Errorf("Network = %#v, want deny-all with no allow-list", plan.Network)
	}
	if plan.Machine.VCPUCount != 1 || plan.Machine.MemoryMiB != 256 {
		t.Errorf("Machine = %#v, want one vCPU and 256 MiB", plan.Machine)
	}
	if plan.Capabilities.Isolation.State != sandbox.CapabilityUnavailable || plan.Capabilities.Mounts.State != sandbox.CapabilityUnavailable || plan.Capabilities.Secrets.State != sandbox.CapabilityUnavailable || plan.Capabilities.Egress.State != sandbox.CapabilityUnavailable {
		t.Errorf("Capabilities = %#v, must remain unavailable before retained Linux/KVM evidence", plan.Capabilities)
	}
	if plan.Jailer != profile.Jailer || plan.Firecracker != profile.Firecracker {
		t.Errorf("Plan lost pinned executables: %#v", plan)
	}
}

func TestVerifyPlanArtifactsRejectsAChangedPinnedArtifactBeforeLaunch(t *testing.T) {
	const fixture = "fixture"
	plan := Plan{Firecracker: PinnedArtifact{Path: "/firecracker", Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}
	err := VerifyPlanArtifacts(plan, artifactOpenFunc(func(path string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBufferString(fixture)), nil
	}))
	if !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("VerifyPlanArtifacts() error = %v, want integrity refusal", err)
	}
}

func TestCompileRefusesProfilesThatWouldWidenFoundationAuthority(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Profile)
	}{
		{"allows network", func(p *Profile) { p.Network.Mode = NetworkAllowlist }},
		{"declares host mounts", func(p *Profile) { p.HostMountsEnabled = true }},
		{"rounds cpu", func(p *Profile) { p.Resources.MilliCPU = 500 }},
		{"accepts unpinned rootfs", func(p *Profile) { p.RootFS.Digest = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profile := validProfile()
			tc.mutate(&profile)
			_, err := Compile(profile)
			if !errors.Is(err, ErrInvalidProfile) && !errors.Is(err, ErrCapabilityUnavailable) {
				t.Fatalf("Compile() error = %v, want explicit refusal", err)
			}
		})
	}
}

func TestAssessEnvironmentRetainsEveryMissingPrerequisite(t *testing.T) {
	report := AssessEnvironment(environmentFunc(func(path string) error {
		if path == "/dev/kvm" {
			return errors.New("not found")
		}
		return nil
	}), "darwin")
	if report.Available || !reflect.DeepEqual(report.Reasons, []string{"host OS is darwin, want linux", "/dev/kvm: not found"}) {
		t.Errorf("AssessEnvironment() = %#v", report)
	}
}

func validProfile() Profile {
	return Profile{
		Version:       "firecracker.host/v1",
		VMID:          "sandbox-001",
		Firecracker:   PinnedArtifact{Path: "/opt/firecracker/firecracker", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Jailer:        PinnedArtifact{Path: "/opt/firecracker/jailer", Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		Kernel:        PinnedArtifact{Path: "/opt/firecracker/vmlinux", Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		RootFS:        PinnedArtifact{Path: "/opt/firecracker/rootfs.ext4", Digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		KVMDevice:     "/dev/kvm",
		ChrootBaseDir: "/srv/agent-runtime/jailer",
		UID:           10001,
		GID:           10001,
		Resources: sandbox.ResourceLimits{
			MilliCPU: 1000, MemoryBytes: 256 << 20, RootDiskBytes: 1 << 30,
			PIDs: 64, ProcessCount: 32, OpenFiles: 512, Inodes: 10_000, Files: 5_000,
			Lifetime: time.Minute, ProducedOutputBytes: 1 << 20, RetainedOutputBytes: 1 << 20,
			TransferBytes: 1 << 20, NetworkConnections: 1, VolumeBytes: 1 << 30, SnapshotBytes: 1 << 30,
		},
		Network: NetworkPolicy{Mode: NetworkDenyAll},
	}
}
