package firecracker

import (
	"fmt"
	"time"

	"github.com/0x63616c/agent-runtime/sandbox"
)

// ProtectedSmokeConfig is the explicit operator input needed to compile one
// no-NIC Firecracker smoke launch from already verified fixtures. It does not
// provision cgroups, stage fixtures, start a Jailer, or make a capability
// available.
type ProtectedSmokeConfig struct {
	VMID, ExternalOwner string
	UID, GID            uint32
	Cgroup              JailerCgroupAssignment
}

// CompileProtectedSmokePlan derives the fixed small protected-run plan and its
// Jailer authority from one verified fixture set. Every non-Jailer resource
// limit remains explicitly assigned to ExternalOwner; the protected runner must
// prove those owners before any resulting smoke evidence is accepted.
func CompileProtectedSmokePlan(config ProtectedSmokeConfig, fixtures FixtureSet) (Plan, JailerExecutionAuthority, error) {
	return compileSmokePlan(config, fixtures, declaredJailerBaseDirectory)
}

// CompileDirectSmokePlan derives the same fixed no-NIC Firecracker smoke plan
// for the separately reviewed Talos direct-run authority. The jailer base is
// fixed here rather than taken from any command line or operator input.
func CompileDirectSmokePlan(config ProtectedSmokeConfig, fixtures FixtureSet) (Plan, JailerExecutionAuthority, error) {
	plan, authority, err := compileSmokePlan(config, fixtures, directJailerBaseDirectory)
	if err != nil {
		return Plan{}, JailerExecutionAuthority{}, err
	}
	// Linux sockaddr_un reserves one byte of its 108-byte sun_path field for
	// NUL. The Jailer receives a chroot-visible socket path, whereas the host
	// reaches the same socket through its complete Jailer root. Refuse a plan
	// that could launch a healthy VMM but leave its API unreachable.
	if len(hostJailedPath(expectedJailRoot(plan), fixedFirecrackerAPISocket)) > 107 {
		return Plan{}, JailerExecutionAuthority{}, fmt.Errorf("compile direct smoke plan: %w: host-visible Firecracker API socket path exceeds Linux limit", ErrSmokeUnavailable)
	}
	return plan, authority, nil
}

func compileSmokePlan(config ProtectedSmokeConfig, fixtures FixtureSet, jailerBaseDirectory string) (Plan, JailerExecutionAuthority, error) {
	if config.VMID == "" || config.ExternalOwner == "" || config.UID == 0 || config.GID == 0 || !approvedJailerBaseDirectory(jailerBaseDirectory) || !fixturesMatchSmokePlanInputs(fixtures) {
		return Plan{}, JailerExecutionAuthority{}, fmt.Errorf("compile protected smoke plan: %w", ErrSmokeUnavailable)
	}
	firecrackerArtifact, firecrackerOK := fixtures.Artifact(FixtureFirecracker)
	jailerArtifact, jailerOK := fixtures.Artifact(FixtureJailer)
	kernelArtifact, kernelOK := fixtures.Artifact(FixtureKernel)
	rootFSArtifact, rootFSOK := fixtures.Artifact(FixtureRootFS)
	guestAgentArtifact, guestAgentOK := fixtures.Artifact(FixtureGuestAgent)
	if !firecrackerOK || !jailerOK || !kernelOK || !rootFSOK || !guestAgentOK {
		return Plan{}, JailerExecutionAuthority{}, fmt.Errorf("compile protected smoke plan: %w", ErrSmokeUnavailable)
	}
	plan, err := Compile(Profile{
		Version:       "firecracker.host/v1",
		VMID:          config.VMID,
		Firecracker:   firecrackerArtifact,
		Jailer:        jailerArtifact,
		Kernel:        kernelArtifact,
		RootFS:        rootFSArtifact,
		GuestAgent:    guestAgentArtifact,
		KVMDevice:     "/dev/kvm",
		ChrootBaseDir: jailerBaseDirectory,
		UID:           config.UID,
		GID:           config.GID,
		Resources:     sandboxSmokeResources(),
		Network:       NetworkPolicy{Mode: NetworkDenyAll},
	})
	if err != nil {
		return Plan{}, JailerExecutionAuthority{}, fmt.Errorf("compile protected smoke plan: %w", err)
	}
	authority, err := CompileJailerExecutionAuthority(plan, config.Cgroup, protectedSmokeExternalOwners(config.ExternalOwner))
	if err != nil {
		return Plan{}, JailerExecutionAuthority{}, fmt.Errorf("compile protected smoke authority: %w", err)
	}
	return plan, authority, nil
}

func fixturesMatchSmokePlanInputs(fixtures FixtureSet) bool {
	if !fixtures.verified || !safeAbsolutePath(fixtures.directory) || fixtures.fixtureVersion == "" || len(fixtures.artifacts) != 5 {
		return false
	}
	for _, name := range []FixtureName{FixtureFirecracker, FixtureJailer, FixtureKernel, FixtureRootFS, FixtureGuestAgent} {
		artifact, ok := fixtures.Artifact(name)
		if !ok || !validArtifact(artifact) {
			return false
		}
	}
	return true
}

func sandboxSmokeResources() sandbox.ResourceLimits {
	return sandbox.ResourceLimits{
		MilliCPU:            1000,
		MemoryBytes:         256 << 20,
		RootDiskBytes:       1 << 30,
		TmpfsBytes:          64 << 20,
		PIDs:                64,
		ProcessCount:        32,
		OpenFiles:           128,
		Inodes:              1024,
		Files:               1024,
		Lifetime:            2 * time.Minute,
		ProducedOutputBytes: 1 << 20,
		RetainedOutputBytes: 1 << 20,
	}
}

func protectedSmokeExternalOwners(owner string) []ExternalJailerLimitOwner {
	owners := make([]ExternalJailerLimitOwner, 0, len(requiredExternalJailerLimits))
	for _, limit := range requiredExternalJailerLimits {
		owners = append(owners, ExternalJailerLimitOwner{Limit: limit, StackResource: owner})
	}
	return owners
}
