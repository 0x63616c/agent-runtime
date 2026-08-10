package firecracker

import (
	"encoding/json"
	"fmt"

	"github.com/0x63616c/agent-runtime/sandbox"
)

const trustedM4IdentityVersion = "agent-runtime.firecracker.trusted-m4/v1"

// TrustedM4Identity is the redacted, domain-separated identity of the exact M4 objects required by a private Firecracker boot-probe grant.
// It is an immutable value only: compiling it neither interprets a control request nor starts a Jailer, VMM, guest, or vsock connection.
type TrustedM4Identity struct {
	VMID            string
	FixtureVersion  string
	PlanDigest      sandbox.Digest
	FixtureDigest   sandbox.Digest
	StageDigest     sandbox.Digest
	AuthorityDigest sandbox.Digest
}

// String returns the safe labels and opaque digests that may cross the private M3/M4 binding seam.
func (identity TrustedM4Identity) String() string {
	return fmt.Sprintf("%s vm_id=%q fixture_version=%q plan_digest=%s fixture_digest=%s stage_digest=%s authority_digest=%s", trustedM4IdentityVersion, identity.VMID, identity.FixtureVersion, identity.PlanDigest, identity.FixtureDigest, identity.StageDigest, identity.AuthorityDigest)
}

// CompileTrustedM4Identity commits to one exact compiled plan, verified fixture set, Jailer authority, and staged namespace without exposing host paths, fixture sources, launch argv, or secrets.
func CompileTrustedM4Identity(plan Plan, fixtures FixtureSet, authority JailerExecutionAuthority, stage JailedResourceStage) (TrustedM4Identity, error) {
	if !validJailerExecutionPlan(plan) {
		return TrustedM4Identity{}, fmt.Errorf("%w: exact fixed-base compiled Jailer plan is required", ErrInvalidProfile)
	}
	if !fixturesMatchPlan(fixtures, plan) {
		return TrustedM4Identity{}, fmt.Errorf("%w: complete verified fixtures bound to the compiled plan are required", ErrArtifactIntegrity)
	}
	if !validJailerExecutionAuthority(authority, plan) {
		return TrustedM4Identity{}, fmt.Errorf("%w: exact Jailer execution authority bound to the compiled plan is required", ErrInvalidProfile)
	}
	if stage.RootFS.Source.Path == plan.RootFS().Path || !validJailedResourceStage(stage, plan, fixtures, stage.RootFS.Source.Path) || !validJailerExecutionStage(authority, stage) {
		return TrustedM4Identity{}, fmt.Errorf("%w: exact private fixture-bound Jailer resource stage is required", ErrSmokeUnavailable)
	}

	planDigest, err := trustedPlanDigest(plan)
	if err != nil {
		return TrustedM4Identity{}, err
	}
	fixtureDigest, err := trustedFixtureDigest(fixtures)
	if err != nil {
		return TrustedM4Identity{}, err
	}
	authorityDigest, err := trustedAuthorityDigest(authority, planDigest)
	if err != nil {
		return TrustedM4Identity{}, err
	}
	stageDigest, err := trustedStageDigest(stage, planDigest, fixtureDigest, authorityDigest)
	if err != nil {
		return TrustedM4Identity{}, err
	}
	return TrustedM4Identity{
		VMID:            plan.VMID(),
		FixtureVersion:  fixtures.FixtureVersion(),
		PlanDigest:      planDigest,
		FixtureDigest:   fixtureDigest,
		StageDigest:     stageDigest,
		AuthorityDigest: authorityDigest,
	}, nil
}

func trustedPlanDigest(plan Plan) (sandbox.Digest, error) {
	return trustedM4Digest("agent-runtime.firecracker.plan-identity/v1", struct {
		VMID         string                     `json:"vm_id"`
		UID          uint32                     `json:"uid"`
		GID          uint32                     `json:"gid"`
		Machine      MachineConfig              `json:"machine"`
		Resources    ResourceEnforcement        `json:"resources"`
		Network      NetworkMode                `json:"network"`
		Capabilities sandbox.CapabilitySnapshot `json:"capabilities"`
		Firecracker  sandbox.Digest             `json:"firecracker_digest"`
		Jailer       sandbox.Digest             `json:"jailer_digest"`
		Kernel       sandbox.Digest             `json:"kernel_digest"`
		RootFS       sandbox.Digest             `json:"rootfs_digest"`
		GuestAgent   sandbox.Digest             `json:"guest_agent_digest"`
	}{
		VMID:         plan.VMID(),
		UID:          plan.UID(),
		GID:          plan.GID(),
		Machine:      plan.Machine(),
		Resources:    plan.Resources(),
		Network:      plan.Network().Mode,
		Capabilities: plan.Capabilities(),
		Firecracker:  plan.Firecracker().Digest,
		Jailer:       plan.Jailer().Digest,
		Kernel:       plan.Kernel().Digest,
		RootFS:       plan.RootFS().Digest,
		GuestAgent:   plan.GuestAgent().Digest,
	})
}

func trustedFixtureDigest(fixtures FixtureSet) (sandbox.Digest, error) {
	return trustedM4Digest("agent-runtime.firecracker.fixture-set-identity/v1", struct {
		FixtureVersion string         `json:"fixture_version"`
		Firecracker    sandbox.Digest `json:"firecracker_digest"`
		Jailer         sandbox.Digest `json:"jailer_digest"`
		Kernel         sandbox.Digest `json:"kernel_digest"`
		RootFS         sandbox.Digest `json:"rootfs_digest"`
		GuestAgent     sandbox.Digest `json:"guest_agent_digest"`
	}{
		FixtureVersion: fixtures.FixtureVersion(),
		Firecracker:    fixtures.artifacts[FixtureFirecracker].Digest,
		Jailer:         fixtures.artifacts[FixtureJailer].Digest,
		Kernel:         fixtures.artifacts[FixtureKernel].Digest,
		RootFS:         fixtures.artifacts[FixtureRootFS].Digest,
		GuestAgent:     fixtures.artifacts[FixtureGuestAgent].Digest,
	})
}

func trustedAuthorityDigest(authority JailerExecutionAuthority, planDigest sandbox.Digest) (sandbox.Digest, error) {
	return trustedM4Digest("agent-runtime.firecracker.jailer-authority-identity/v1", struct {
		Version       string                     `json:"version"`
		PlanDigest    sandbox.Digest             `json:"plan_digest"`
		StackResource string                     `json:"stack_resource"`
		CgroupParent  string                     `json:"cgroup_parent"`
		CgroupPath    string                     `json:"cgroup_path"`
		External      []ExternalJailerLimitOwner `json:"external_limit_owners"`
	}{
		Version:       authority.version,
		PlanDigest:    planDigest,
		StackResource: authority.stackResource,
		CgroupParent:  authority.cgroupParent,
		CgroupPath:    authority.cgroupPath,
		External:      authority.ExternalLimitOwners(),
	})
}

func trustedStageDigest(stage JailedResourceStage, planDigest, fixtureDigest, authorityDigest sandbox.Digest) (sandbox.Digest, error) {
	return trustedM4Digest("agent-runtime.firecracker.jailed-stage-identity/v1", struct {
		PlanDigest      sandbox.Digest `json:"plan_digest"`
		FixtureDigest   sandbox.Digest `json:"fixture_digest"`
		AuthorityDigest sandbox.Digest `json:"authority_digest"`
		BindingDigest   sandbox.Digest `json:"binding_digest"`
	}{
		PlanDigest:      planDigest,
		FixtureDigest:   fixtureDigest,
		AuthorityDigest: authorityDigest,
		BindingDigest:   stage.BindingDigest,
	})
}

func trustedM4Digest(domain string, identity any) (sandbox.Digest, error) {
	encoded, err := json.Marshal(struct {
		Domain   string `json:"domain"`
		Identity any    `json:"identity"`
	}{Domain: domain, Identity: identity})
	if err != nil {
		return "", fmt.Errorf("encode trusted M4 %s: %w", domain, err)
	}
	return digest(encoded), nil
}
