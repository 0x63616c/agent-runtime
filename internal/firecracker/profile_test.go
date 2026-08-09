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
	if !reflect.DeepEqual(plan.JailerArguments(), []string{
		"--id", "sandbox-001", "--exec-file", "/opt/firecracker/firecracker", "--uid", "10001", "--gid", "10001", "--chroot-base-dir", "/srv/agent-runtime/jailer", "--cgroup-version", "2", "--", "--api-sock", "/run/firecracker.socket",
	}) {
		t.Errorf("JailerArguments = %#v", plan.JailerArguments())
	}
	network := plan.Network()
	if network.Mode != NetworkDenyAll || len(network.Allowlist) != 0 {
		t.Errorf("Network = %#v, want deny-all with no allow-list", network)
	}
	machine := plan.Machine()
	if machine.VCPUCount != 1 || machine.MemoryMiB != 256 {
		t.Errorf("Machine = %#v, want one vCPU and 256 MiB", machine)
	}
	wantResources := ResourceEnforcement{
		CgroupVersion:       2,
		RootDiskBytes:       profile.Resources.RootDiskBytes,
		TmpfsBytes:          profile.Resources.TmpfsBytes,
		PIDs:                profile.Resources.PIDs,
		ProcessCount:        profile.Resources.ProcessCount,
		OpenFiles:           profile.Resources.OpenFiles,
		Inodes:              profile.Resources.Inodes,
		Files:               profile.Resources.Files,
		Lifetime:            profile.Resources.Lifetime,
		ProducedOutputBytes: profile.Resources.ProducedOutputBytes,
		RetainedOutputBytes: profile.Resources.RetainedOutputBytes,
	}
	if resources := plan.Resources(); resources != wantResources {
		t.Errorf("Resources = %#v, want exact enforcement %#v", resources, wantResources)
	}
	capabilities := plan.Capabilities()
	for name, capability := range map[string]sandbox.CapabilityDescriptor{
		"control protocol": capabilities.ControlProtocol,
		"isolation":        capabilities.Isolation,
		"guest":            capabilities.Guest,
		"resources":        capabilities.Resources,
		"reconnect":        capabilities.Reconnect,
		"image admission":  capabilities.ImageAdmission,
		"output":           capabilities.Output,
		"transfer":         capabilities.Transfer,
		"mounts":           capabilities.Mounts,
		"volumes":          capabilities.Volumes,
		"snapshots":        capabilities.Snapshots,
		"egress":           capabilities.Egress,
		"secrets":          capabilities.Secrets,
	} {
		if capability.State != sandbox.CapabilityUnavailable {
			t.Errorf("%s capability = %#v, must remain unavailable before retained Linux/KVM evidence", name, capability)
		}
	}
	if plan.VMID() != profile.VMID || plan.Firecracker() != profile.Firecracker || plan.Jailer() != profile.Jailer || plan.Kernel() != profile.Kernel || plan.RootFS() != profile.RootFS {
		t.Errorf("Plan lost pinned executables: %#v", plan)
	}
}

func TestPlanAccessorsDefensivelyCopyMutableState(t *testing.T) {
	profile := validProfile()
	emptyDigest := sandbox.Digest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	profile.Firecracker.Digest = emptyDigest
	profile.Jailer.Digest = emptyDigest
	profile.Kernel.Digest = emptyDigest
	profile.RootFS.Digest = emptyDigest
	plan := mustCompile(t, profile)

	arguments := plan.JailerArguments()
	arguments[0] = "--mutated"
	capabilities := plan.Capabilities()
	capabilities.Isolation.State = sandbox.CapabilityEnforced
	capabilities.Isolation.LimitPrecision = append(capabilities.Isolation.LimitPrecision, "mutated")
	capabilities.Signals = append(capabilities.Signals, sandbox.Signal("mutated"))
	network := plan.Network()
	network.Allowlist = append(network.Allowlist, "mutated.example")

	if plan.JailerArguments()[0] != "--id" {
		t.Fatalf("JailerArguments() retained caller mutation: %#v", plan.JailerArguments())
	}
	gotCapabilities := plan.Capabilities()
	if gotCapabilities.Isolation.State != sandbox.CapabilityUnavailable || len(gotCapabilities.Isolation.LimitPrecision) != 0 || len(gotCapabilities.Signals) != 0 {
		t.Fatalf("Capabilities() retained caller mutation: %#v", gotCapabilities)
	}
	if gotNetwork := plan.Network(); gotNetwork.Mode != NetworkDenyAll || len(gotNetwork.Allowlist) != 0 {
		t.Fatalf("Network() retained caller mutation: %#v", gotNetwork)
	}
	if err := VerifyPlanArtifacts(plan, artifactOpenFunc(func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(nil)), nil
	})); err != nil {
		t.Fatalf("VerifyPlanArtifacts() after accessor mutation error = %v", err)
	}
}

func TestVerifyPlanArtifactsRejectsAChangedPinnedArtifactBeforeLaunch(t *testing.T) {
	const fixture = "fixture"
	plan := mustCompile(t, validProfile())
	err := VerifyPlanArtifacts(plan, artifactOpenFunc(func(path string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBufferString(fixture)), nil
	}))
	if !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("VerifyPlanArtifacts() error = %v, want integrity refusal", err)
	}
}

func TestVerifyPlanArtifactsRejectsUncompiledOrIncompletePlanBeforeOpening(t *testing.T) {
	compiled := mustCompile(t, validProfile())
	uncompiled := compiled
	uncompiled.compiled = false
	incomplete := compiled
	incomplete.rootFS = PinnedArtifact{}
	incompleteResources := compiled
	incompleteResources.resources = ResourceEnforcement{}
	incompleteJailer := compiled
	incompleteJailer.jailerArguments = nil
	for _, test := range []struct {
		name string
		plan Plan
	}{
		{name: "zero", plan: Plan{}},
		{name: "uncompiled", plan: uncompiled},
		{name: "missing artifact", plan: incomplete},
		{name: "missing resources", plan: incompleteResources},
		{name: "missing jailer configuration", plan: incompleteJailer},
	} {
		t.Run(test.name, func(t *testing.T) {
			opens := 0
			err := VerifyPlanArtifacts(test.plan, artifactOpenFunc(func(string) (io.ReadCloser, error) {
				opens++
				return io.NopCloser(bytes.NewReader(nil)), nil
			}))
			if !errors.Is(err, ErrArtifactIntegrity) {
				t.Fatalf("VerifyPlanArtifacts() error = %v, want incomplete-plan refusal", err)
			}
			if opens != 0 {
				t.Fatalf("artifact opens = %d, want none before complete compiled-plan validation", opens)
			}
		})
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
		{"exceeds Firecracker memory field", func(p *Profile) { p.Resources.MemoryBytes = (uint64(1) << 32) << 20 }},
		{"omits root disk limit", func(p *Profile) { p.Resources.RootDiskBytes = 0 }},
		{"omits tmpfs limit", func(p *Profile) { p.Resources.TmpfsBytes = 0 }},
		{"omits PID limit", func(p *Profile) { p.Resources.PIDs = 0 }},
		{"omits process limit", func(p *Profile) { p.Resources.ProcessCount = 0 }},
		{"omits open-file limit", func(p *Profile) { p.Resources.OpenFiles = 0 }},
		{"omits inode limit", func(p *Profile) { p.Resources.Inodes = 0 }},
		{"omits file limit", func(p *Profile) { p.Resources.Files = 0 }},
		{"omits lifetime limit", func(p *Profile) { p.Resources.Lifetime = 0 }},
		{"omits produced-output limit", func(p *Profile) { p.Resources.ProducedOutputBytes = 0 }},
		{"omits retained-output limit", func(p *Profile) { p.Resources.RetainedOutputBytes = 0 }},
		{"widens retained output beyond produced output", func(p *Profile) { p.Resources.RetainedOutputBytes = p.Resources.ProducedOutputBytes + 1 }},
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

func TestCompileRejectsUnsafeVMIDGrammar(t *testing.T) {
	for _, vmID := range []string{
		".",
		"..",
		"sandbox.001",
		"../sandbox",
		"sandbox/child",
		`sandbox\child`,
		"sandbox\x00child",
		"sandbox\x1fchild",
		"sandbox\x7fchild",
		"-sandbox",
		"sandbox-",
		"Sandbox_001",
	} {
		t.Run(vmID, func(t *testing.T) {
			profile := validProfile()
			profile.VMID = vmID
			if _, err := Compile(profile); !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("Compile() error = %v, want unsafe VM ID refusal", err)
			}
		})
	}
}

func TestAssessEnvironmentRetainsEveryMissingPrerequisite(t *testing.T) {
	plan := mustCompile(t, validProfile())
	for _, prerequisite := range []environmentPrerequisite{
		usableKVMPrerequisite,
		jailerPrerequisite,
		cgroupV2Prerequisite,
		pinnedArtifactsPrerequisite,
	} {
		t.Run(string(prerequisite), func(t *testing.T) {
			report := AssessEnvironment(environmentFunc(func(got environmentPrerequisite, gotPlan Plan) error {
				if !reflect.DeepEqual(gotPlan, plan) {
					t.Errorf("verify() plan = %#v, want %#v", gotPlan, plan)
				}
				if got == prerequisite {
					return errors.New("unverified")
				}
				return nil
			}), "linux", plan)
			if report.Available {
				t.Fatalf("AssessEnvironment() = %#v, want unavailable when %s is unverified", report, prerequisite)
			}
			if got := checkFor(report, prerequisite); got.Available || got.Reason != "unverified" {
				t.Errorf("%s check = %#v, want unavailable unverified check", prerequisite, got)
			}
		})
	}
}

func TestAssessEnvironmentRequiresACompletePinnedPlan(t *testing.T) {
	report := AssessEnvironment(environmentFunc(func(_ environmentPrerequisite, _ Plan) error { return nil }), "linux", Plan{})
	if report.Available || report.Jailer.Available || report.PinnedArtifacts.Available {
		t.Fatalf("AssessEnvironment() = %#v, want incomplete plan unavailable", report)
	}
	if report.Jailer.Reason == "" || report.PinnedArtifacts.Reason == "" {
		t.Errorf("AssessEnvironment() = %#v, want explicit missing plan reasons", report)
	}
}

func TestAssessEnvironmentReportsAvailableOnlyAfterEveryProtectedCheckPasses(t *testing.T) {
	plan := mustCompile(t, validProfile())
	seen := map[environmentPrerequisite]bool{}
	report := AssessEnvironment(environmentFunc(func(prerequisite environmentPrerequisite, _ Plan) error {
		seen[prerequisite] = true
		return nil
	}), "linux", plan)
	if !report.Available {
		t.Fatalf("AssessEnvironment() = %#v, want all protected checks available", report)
	}
	for _, prerequisite := range []environmentPrerequisite{usableKVMPrerequisite, jailerPrerequisite, cgroupV2Prerequisite, pinnedArtifactsPrerequisite} {
		if !seen[prerequisite] {
			t.Errorf("AssessEnvironment() did not verify %s", prerequisite)
		}
	}
}

func TestAssessEnvironmentDoesNotTreatOpeningKVMAsUsableKVM(t *testing.T) {
	report := AssessEnvironment(localEnvironment{check: func(path string) error {
		if path != "/dev/kvm" && path != "/sys/fs/cgroup/cgroup.controllers" {
			t.Fatalf("unexpected host probe %q", path)
		}
		return nil
	}}, "linux", Plan{})
	if report.Available || report.KVM.Available || report.KVM.Reason != "opened, but KVM API and jailed guest execution were not verified" {
		t.Errorf("AssessEnvironment() = %#v, want unavailable usable-KVM check", report)
	}
	if !report.CgroupV2.Available {
		t.Errorf("AssessEnvironment() = %#v, want cgroup v2 observation retained", report)
	}
}

func mustCompile(t *testing.T, profile Profile) Plan {
	t.Helper()
	plan, err := Compile(profile)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return plan
}

func checkFor(report EnvironmentReport, prerequisite environmentPrerequisite) EnvironmentCheck {
	switch prerequisite {
	case usableKVMPrerequisite:
		return report.KVM
	case jailerPrerequisite:
		return report.Jailer
	case cgroupV2Prerequisite:
		return report.CgroupV2
	case pinnedArtifactsPrerequisite:
		return report.PinnedArtifacts
	default:
		return EnvironmentCheck{Reason: "unknown prerequisite"}
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
			MilliCPU: 1000, MemoryBytes: 256 << 20, RootDiskBytes: 1 << 30, TmpfsBytes: 64 << 20,
			PIDs: 64, ProcessCount: 32, OpenFiles: 512, Inodes: 10_000, Files: 5_000,
			Lifetime: time.Minute, ProducedOutputBytes: 2 << 20, RetainedOutputBytes: 1 << 20,
			TransferBytes: 1 << 20, NetworkConnections: 1, VolumeBytes: 1 << 30, SnapshotBytes: 1 << 30,
		},
		Network: NetworkPolicy{Mode: NetworkDenyAll},
	}
}
