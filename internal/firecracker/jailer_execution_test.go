package firecracker

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCompileJailerExecutionAuthorityBindsOnlyJailerOwnedLimits(t *testing.T) {
	plan := mustCompile(t, validProfile())
	authority, err := CompileJailerExecutionAuthority(plan, validJailerCgroupAssignment(), completeExternalJailerLimitOwners())
	if err != nil {
		t.Fatalf("CompileJailerExecutionAuthority() error = %v", err)
	}

	if got, want := authority.Arguments(), []string{
		"--id", "sandbox-001",
		"--exec-file", "/opt/firecracker/firecracker",
		"--uid", "10001",
		"--gid", "10001",
		"--chroot-base-dir", "/srv/agent-runtime/jailer",
		"--cgroup-version", "2",
		"--parent-cgroup", "agent-runtime/firecracker",
		"--cgroup", "cpu.max=100000 100000",
		"--cgroup", "memory.max=268435456",
		"--cgroup", "pids.max=64",
		"--resource-limit", "no-file=512",
		"--", "--api-sock", "/run/firecracker.socket",
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("Arguments() = %#v, want %#v", got, want)
	}
	if got, want := authority.CgroupPath(), "agent-runtime/firecracker/sandbox-001"; got != want {
		t.Errorf("CgroupPath() = %q, want %q", got, want)
	}
	if got, want := authority.CgroupParent(), "agent-runtime/firecracker"; got != want {
		t.Errorf("CgroupParent() = %q, want %q", got, want)
	}
	if got, want := authority.CgroupStackResource(), "firecracker-cgroup-delegation"; got != want {
		t.Errorf("CgroupStackResource() = %q, want %q", got, want)
	}
	if got, want := authority.ExternalLimitOwners(), completeExternalJailerLimitOwners(); !reflect.DeepEqual(got, want) {
		t.Errorf("ExternalLimitOwners() = %#v, want %#v", got, want)
	}
}

func TestCompileJailerExecutionAuthorityFailsClosedWithoutEveryExternalOwner(t *testing.T) {
	owners := completeExternalJailerLimitOwners()
	owners = owners[1:]

	_, err := CompileJailerExecutionAuthority(mustCompile(t, validProfile()), validJailerCgroupAssignment(), owners)
	if !errors.Is(err, ErrCapabilityUnavailable) || !strings.Contains(err.Error(), "root-disk") {
		t.Fatalf("CompileJailerExecutionAuthority() error = %v, want root-disk authority refusal", err)
	}
}

func TestCompileJailerExecutionAuthorityCanonicalizesExternalOwners(t *testing.T) {
	owners := completeExternalJailerLimitOwners()
	for left, right := 0, len(owners)-1; left < right; left, right = left+1, right-1 {
		owners[left], owners[right] = owners[right], owners[left]
	}
	authority, err := CompileJailerExecutionAuthority(mustCompile(t, validProfile()), validJailerCgroupAssignment(), owners)
	if err != nil {
		t.Fatalf("CompileJailerExecutionAuthority() error = %v", err)
	}
	if got, want := authority.ExternalLimitOwners(), completeExternalJailerLimitOwners(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ExternalLimitOwners() = %#v, want canonical %#v", got, want)
	}
}

func TestCompileJailerExecutionAuthorityRefusesPlanWithWidenedJailerArguments(t *testing.T) {
	plan := mustCompile(t, validProfile())
	plan.jailerArguments = append([]string{"--netns", "/run/other-namespace", "--cgroup", "memory.max=max"}, plan.jailerArguments...)

	if _, err := CompileJailerExecutionAuthority(plan, validJailerCgroupAssignment(), completeExternalJailerLimitOwners()); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("CompileJailerExecutionAuthority() error = %v, want widened Jailer argv refusal", err)
	}
}

func TestCompileJailerExecutionAuthorityRefusesUnsafeOrAmbiguousAuthority(t *testing.T) {
	plan := mustCompile(t, validProfile())
	for name, mutate := range map[string]func(*JailerCgroupAssignment, *[]ExternalJailerLimitOwner){
		"missing stack resource": func(assignment *JailerCgroupAssignment, _ *[]ExternalJailerLimitOwner) { assignment.StackResource = "" },
		"absolute parent": func(assignment *JailerCgroupAssignment, _ *[]ExternalJailerLimitOwner) {
			assignment.Parent = "/agent-runtime/firecracker"
		},
		"traversal parent": func(assignment *JailerCgroupAssignment, _ *[]ExternalJailerLimitOwner) {
			assignment.Parent = "agent-runtime/../other"
		},
		"duplicate external owner": func(_ *JailerCgroupAssignment, owners *[]ExternalJailerLimitOwner) {
			*owners = append(*owners, (*owners)[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			assignment := validJailerCgroupAssignment()
			owners := completeExternalJailerLimitOwners()
			mutate(&assignment, &owners)

			if _, err := CompileJailerExecutionAuthority(plan, assignment, owners); !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("CompileJailerExecutionAuthority() error = %v, want authority refusal", err)
			}
		})
	}
}

func TestJailerExecutionAuthorityAccessorsDefensivelyCopy(t *testing.T) {
	authority, err := CompileJailerExecutionAuthority(mustCompile(t, validProfile()), validJailerCgroupAssignment(), completeExternalJailerLimitOwners())
	if err != nil {
		t.Fatalf("CompileJailerExecutionAuthority() error = %v", err)
	}
	arguments := authority.Arguments()
	arguments[0] = "--changed"
	owners := authority.ExternalLimitOwners()
	owners[0].StackResource = "changed"

	if authority.Arguments()[0] != "--id" || authority.ExternalLimitOwners()[0].StackResource == "changed" {
		t.Fatalf("JailerExecutionAuthority accessors retained caller mutation: %#v", authority)
	}
}

func TestJailerExecutionAuthorityRemainsBoundToItsCompiledPlan(t *testing.T) {
	plan := mustCompile(t, validProfile())
	authority, err := CompileJailerExecutionAuthority(plan, validJailerCgroupAssignment(), completeExternalJailerLimitOwners())
	if err != nil {
		t.Fatalf("CompileJailerExecutionAuthority() error = %v", err)
	}
	if !validJailerExecutionAuthority(authority, plan) {
		t.Fatal("validJailerExecutionAuthority() = false, want compiled authority")
	}
	tamperedPlan := plan
	tamperedPlan.uid++
	if validJailerExecutionAuthority(authority, tamperedPlan) {
		t.Fatal("validJailerExecutionAuthority() accepted an authority with another Jailer UID")
	}
	tamperedAuthority := authority
	tamperedAuthority.arguments[1] = "other-vm"
	if validJailerExecutionAuthority(tamperedAuthority, plan) {
		t.Fatal("validJailerExecutionAuthority() accepted a changed Jailer argv")
	}
}

func validJailerCgroupAssignment() JailerCgroupAssignment {
	return JailerCgroupAssignment{
		Version:       "firecracker.jailer-cgroup/v1",
		StackResource: "firecracker-cgroup-delegation",
		Parent:        "agent-runtime/firecracker",
	}
}

func completeExternalJailerLimitOwners() []ExternalJailerLimitOwner {
	return []ExternalJailerLimitOwner{
		{Limit: ExternalJailerLimitRootDisk, StackResource: "firecracker-root-overlay"},
		{Limit: ExternalJailerLimitTmpfs, StackResource: "firecracker-tmpfs"},
		{Limit: ExternalJailerLimitProcessCount, StackResource: "firecracker-process-accounting"},
		{Limit: ExternalJailerLimitInodes, StackResource: "firecracker-filesystem-quota"},
		{Limit: ExternalJailerLimitFiles, StackResource: "firecracker-filesystem-quota"},
		{Limit: ExternalJailerLimitLifetime, StackResource: "firecracker-lifecycle-reaper"},
		{Limit: ExternalJailerLimitProducedOutput, StackResource: "sandbox-output-spool"},
		{Limit: ExternalJailerLimitRetainedOutput, StackResource: "sandbox-output-spool"},
	}
}
