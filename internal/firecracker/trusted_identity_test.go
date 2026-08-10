package firecracker

import (
	"reflect"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestCompileTrustedM4IdentityReturnsDeterministicRedactedBindings(t *testing.T) {
	plan := mustCompile(t, validProfile())
	plan.firecracker.Path = "/private/operator-secret/firecracker"
	plan.jailer.Path = "/private/operator-secret/jailer"
	plan.kernel.Path = "/private/operator-secret/vmlinux"
	plan.rootFS.Path = "/private/operator-secret/rootfs.ext4"
	plan.guestAgent.Path = "/private/operator-secret/guest-agent"
	plan.jailerArguments = baseJailerArguments(plan.VMID(), plan.Firecracker().Path, plan.UID(), plan.GID())
	fixtures := verifiedPlanFixtures(plan)
	fixtures.directory = "/private/operator-secret/fixture-staging"
	stage := validBoundJailedResourceStage(plan, fixtures, "/private/operator-secret/rootfs-copy.ext4")
	authority := mustCompileJailerExecutionAuthority(t, plan)

	first, err := CompileTrustedM4Identity(plan, fixtures, authority, stage)
	if err != nil {
		t.Fatalf("CompileTrustedM4Identity() error = %v", err)
	}
	second, err := CompileTrustedM4Identity(plan, fixtures, authority, stage)
	if err != nil {
		t.Fatalf("CompileTrustedM4Identity() second error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("CompileTrustedM4Identity() = %#v then %#v, want deterministic identity", first, second)
	}
	if first.VMID != plan.VMID() || first.FixtureVersion != fixtures.FixtureVersion() {
		t.Fatalf("identity labels = (%q, %q), want (%q, %q)", first.VMID, first.FixtureVersion, plan.VMID(), fixtures.FixtureVersion())
	}
	for name, value := range map[string]sandbox.Digest{
		"plan": first.PlanDigest, "fixture": first.FixtureDigest, "stage": first.StageDigest, "authority": first.AuthorityDigest,
	} {
		if !validSHA256(value) {
			t.Fatalf("%s digest = %q, want canonical SHA-256", name, value)
		}
	}
	if first.PlanDigest == first.FixtureDigest || first.PlanDigest == first.StageDigest || first.PlanDigest == first.AuthorityDigest || first.FixtureDigest == first.StageDigest || first.FixtureDigest == first.AuthorityDigest || first.StageDigest == first.AuthorityDigest {
		t.Fatalf("trusted identity digests = %#v, want domain-separated values", first)
	}
	if rendered := first.String(); strings.Contains(rendered, "operator-secret") || strings.Contains(rendered, "/private/") {
		t.Fatalf("identity rendered %q, want no host path material", rendered)
	}
}

func TestCompileTrustedM4IdentityChangesWhenOneVerifiedFixtureIsSubstituted(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	authority := mustCompileJailerExecutionAuthority(t, plan)
	baseline, err := CompileTrustedM4Identity(plan, fixtures, authority, stage)
	if err != nil {
		t.Fatalf("CompileTrustedM4Identity() baseline error = %v", err)
	}

	substitutedPlan := cloneLinuxJailerPlan(plan)
	substitutedPlan.kernel.Digest = trustedIdentityTestDigest('f')
	substitutedFixtures := cloneLinuxJailerFixtureSet(fixtures)
	substitutedFixtures.artifacts[FixtureKernel] = substitutedPlan.Kernel()
	substitutedStage := validBoundJailedResourceStage(substitutedPlan, substitutedFixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	substitutedAuthority := mustCompileJailerExecutionAuthority(t, substitutedPlan)
	substituted, err := CompileTrustedM4Identity(substitutedPlan, substitutedFixtures, substitutedAuthority, substitutedStage)
	if err != nil {
		t.Fatalf("CompileTrustedM4Identity() substituted error = %v", err)
	}
	if baseline.PlanDigest == substituted.PlanDigest || baseline.FixtureDigest == substituted.FixtureDigest || baseline.StageDigest == substituted.StageDigest || baseline.AuthorityDigest == substituted.AuthorityDigest {
		t.Fatalf("substituted identity = %#v, want every exact object binding to change from %#v", substituted, baseline)
	}
}

func TestCompileTrustedM4IdentityChangesWhenCompiledPlanCapabilitiesDrift(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	authority := mustCompileJailerExecutionAuthority(t, plan)
	baseline, err := CompileTrustedM4Identity(plan, fixtures, authority, stage)
	if err != nil {
		t.Fatalf("CompileTrustedM4Identity() baseline error = %v", err)
	}

	driftedPlan := cloneLinuxJailerPlan(plan)
	driftedPlan.capabilities.Guest.DataPlane = "changed-capability-state"
	drifted, err := CompileTrustedM4Identity(driftedPlan, fixtures, authority, stage)
	if err != nil {
		t.Fatalf("CompileTrustedM4Identity() drifted error = %v", err)
	}
	if baseline.PlanDigest == drifted.PlanDigest {
		t.Fatalf("drifted plan digest = %q, want a changed exact-plan identity", drifted.PlanDigest)
	}
}

func TestCompileTrustedM4IdentityRefusesUnverifiedOrMismatchedM4Objects(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	authority := mustCompileJailerExecutionAuthority(t, plan)

	for name, mutate := range map[string]func(*Plan, *FixtureSet, *JailerExecutionAuthority, *JailedResourceStage){
		"unverified fixtures": func(_ *Plan, candidate *FixtureSet, _ *JailerExecutionAuthority, _ *JailedResourceStage) {
			candidate.verified = false
		},
		"fixture does not match plan": func(_ *Plan, candidate *FixtureSet, _ *JailerExecutionAuthority, _ *JailedResourceStage) {
			artifact := candidate.artifacts[FixtureKernel]
			artifact.Digest = trustedIdentityTestDigest('f')
			candidate.artifacts[FixtureKernel] = artifact
		},
		"authority is changed after compilation": func(_ *Plan, _ *FixtureSet, candidate *JailerExecutionAuthority, _ *JailedResourceStage) {
			candidate.arguments[13] = "other-parent"
		},
		"stage provenance digest is changed": func(_ *Plan, _ *FixtureSet, _ *JailerExecutionAuthority, candidate *JailedResourceStage) {
			candidate.BindingDigest = trustedIdentityTestDigest('f')
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidatePlan := cloneLinuxJailerPlan(plan)
			candidateFixtures := cloneLinuxJailerFixtureSet(fixtures)
			candidateAuthority := cloneJailerExecutionAuthority(authority)
			candidateStage := stage
			mutate(&candidatePlan, &candidateFixtures, &candidateAuthority, &candidateStage)

			if _, err := CompileTrustedM4Identity(candidatePlan, candidateFixtures, candidateAuthority, candidateStage); err == nil {
				t.Fatal("CompileTrustedM4Identity() error = nil, want refusal")
			}
		})
	}
}

func trustedIdentityTestDigest(character rune) sandbox.Digest {
	return sandbox.Digest("sha256:" + strings.Repeat(string(character), 64))
}
