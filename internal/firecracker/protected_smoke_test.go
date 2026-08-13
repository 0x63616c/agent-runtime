package firecracker

import (
	"strings"
	"testing"
)

func TestCompileProtectedSmokePlanBindsEveryVerifiedFixtureAndExternalOwner(t *testing.T) {
	fixtures := verifiedPlanFixtures(mustCompile(t, validProfile()))
	config := ProtectedSmokeConfig{
		VMID:          "smoke-001",
		UID:           1001,
		GID:           1002,
		ExternalOwner: "firecracker-kvm",
		Cgroup:        JailerCgroupAssignment{Version: "firecracker.jailer-cgroup/v1", StackResource: "firecracker-kvm", Parent: "agent-runtime"},
	}
	plan, authority, err := CompileProtectedSmokePlan(config, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if plan.VMID() != config.VMID || plan.Network().Mode != NetworkDenyAll || len(plan.Network().Allowlist) != 0 || plan.Resources() != sandboxSmokeResourceEnforcement() || !validJailerExecutionAuthority(authority, plan) || authority.CgroupPath() != "agent-runtime/smoke-001" {
		t.Fatalf("CompileProtectedSmokePlan() = (%#v, %#v), want fixed no-NIC plan and authority", plan, authority)
	}
	for _, owner := range authority.ExternalLimitOwners() {
		if owner.StackResource != config.ExternalOwner {
			t.Fatalf("external owner = %#v, want %q", owner, config.ExternalOwner)
		}
	}
}

func TestCompileDirectSmokePlanUsesTalosWritableJailerBaseWithoutChangingProtectedPlan(t *testing.T) {
	fixtures := verifiedPlanFixtures(mustCompile(t, validProfile()))
	config := ProtectedSmokeConfig{
		VMID:          "direct-smoke-001",
		UID:           1001,
		GID:           1002,
		ExternalOwner: "firecracker-direct-limits",
		Cgroup:        JailerCgroupAssignment{Version: "firecracker.jailer-cgroup/v1", StackResource: "firecracker-direct-kvm", Parent: "agent-runtime/firecracker-direct"},
	}
	directPlan, directAuthority, err := CompileDirectSmokePlan(config, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if got := jailerArgumentValue(directPlan.JailerArguments(), "--chroot-base-dir"); got != directJailerBaseDirectory {
		t.Fatalf("direct chroot base = %q, want %q", got, directJailerBaseDirectory)
	}
	if !validJailerExecutionAuthority(directAuthority, directPlan) {
		t.Fatal("direct authority must bind the fixed Talos writable base")
	}
	protectedPlan, _, err := CompileProtectedSmokePlan(config, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if got := jailerArgumentValue(protectedPlan.JailerArguments(), "--chroot-base-dir"); got != declaredJailerBaseDirectory {
		t.Fatalf("protected chroot base = %q, want unchanged %q", got, declaredJailerBaseDirectory)
	}
}

func TestCompileDirectSmokePlanRefusesAnUnreachableHostVisibleAPISocket(t *testing.T) {
	fixtures := verifiedPlanFixtures(mustCompile(t, validProfile()))
	config := ProtectedSmokeConfig{
		VMID:          "a" + strings.Repeat("b", 62),
		UID:           1001,
		GID:           1002,
		ExternalOwner: "firecracker-direct-limits",
		Cgroup:        JailerCgroupAssignment{Version: "firecracker.jailer-cgroup/v1", StackResource: "firecracker-direct-kvm", Parent: "agent-runtime/firecracker-direct"},
	}
	if _, _, err := CompileDirectSmokePlan(config, fixtures); err == nil || !strings.Contains(err.Error(), "host-visible Firecracker API socket path exceeds Linux limit") {
		t.Fatalf("CompileDirectSmokePlan() error = %v, want Unix socket path limit refusal", err)
	}
}

func TestCompileProtectedSmokePlanRefusesIncompleteInputsBeforeAnyHostOperation(t *testing.T) {
	fixtures := verifiedPlanFixtures(mustCompile(t, validProfile()))
	valid := ProtectedSmokeConfig{
		VMID:          "smoke-001",
		UID:           1001,
		GID:           1002,
		ExternalOwner: "firecracker-kvm",
		Cgroup:        JailerCgroupAssignment{Version: "firecracker.jailer-cgroup/v1", StackResource: "firecracker-kvm", Parent: "agent-runtime"},
	}
	for name, mutate := range map[string]func(*ProtectedSmokeConfig, *FixtureSet){
		"missing VM":        func(config *ProtectedSmokeConfig, _ *FixtureSet) { config.VMID = "" },
		"root identity":     func(config *ProtectedSmokeConfig, _ *FixtureSet) { config.UID = 0 },
		"missing owner":     func(config *ProtectedSmokeConfig, _ *FixtureSet) { config.ExternalOwner = "" },
		"wrong cgroup":      func(config *ProtectedSmokeConfig, _ *FixtureSet) { config.Cgroup.Parent = "../other" },
		"unverified source": func(_ *ProtectedSmokeConfig, set *FixtureSet) { set.verified = false },
		"relative source":   func(_ *ProtectedSmokeConfig, set *FixtureSet) { set.directory = "fixtures" },
	} {
		t.Run(name, func(t *testing.T) {
			config, set := valid, cloneLinuxJailerFixtureSet(fixtures)
			mutate(&config, &set)
			if _, _, err := CompileProtectedSmokePlan(config, set); err == nil {
				t.Fatal("CompileProtectedSmokePlan() error = nil, want pre-I/O refusal")
			}
		})
	}
}

func sandboxSmokeResourceEnforcement() ResourceEnforcement {
	resources := sandboxSmokeResources()
	return ResourceEnforcement{
		CgroupVersion:       2,
		RootDiskBytes:       resources.RootDiskBytes,
		TmpfsBytes:          resources.TmpfsBytes,
		PIDs:                resources.PIDs,
		ProcessCount:        resources.ProcessCount,
		OpenFiles:           resources.OpenFiles,
		Inodes:              resources.Inodes,
		Files:               resources.Files,
		Lifetime:            resources.Lifetime,
		ProducedOutputBytes: resources.ProducedOutputBytes,
		RetainedOutputBytes: resources.RetainedOutputBytes,
	}
}
