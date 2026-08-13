package firecracker

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const jailerExecutionAuthorityVersion = "firecracker.jailer-execution/v1"

var stackResourceReferencePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// JailerCgroupAssignment names the Stack-owned, delegated cgroup parent that a Jailer may use.
// Compiling this value neither creates the parent nor proves the parent has enabled controllers.
type JailerCgroupAssignment struct {
	Version       string
	StackResource string
	Parent        string
}

// ExternalJailerLimit identifies a finite limit whose enforcement is outside Jailer authority.
type ExternalJailerLimit string

const (
	// ExternalJailerLimitRootDisk requires the Stack-owned root-overlay provisioner.
	ExternalJailerLimitRootDisk ExternalJailerLimit = "root-disk"
	// ExternalJailerLimitTmpfs requires the Stack-owned tmpfs provisioner.
	ExternalJailerLimitTmpfs ExternalJailerLimit = "tmpfs"
	// ExternalJailerLimitProcessCount requires a process-accounting owner because cgroup pids limits tasks, not processes.
	ExternalJailerLimitProcessCount ExternalJailerLimit = "process-count"
	// ExternalJailerLimitInodes requires the Stack-owned filesystem quota owner.
	ExternalJailerLimitInodes ExternalJailerLimit = "inodes"
	// ExternalJailerLimitFiles requires the Stack-owned filesystem quota owner.
	ExternalJailerLimitFiles ExternalJailerLimit = "files"
	// ExternalJailerLimitLifetime requires the Stack-owned lifecycle reaper.
	ExternalJailerLimitLifetime ExternalJailerLimit = "lifetime"
	// ExternalJailerLimitProducedOutput requires the core-owned output spool.
	ExternalJailerLimitProducedOutput ExternalJailerLimit = "produced-output"
	// ExternalJailerLimitRetainedOutput requires the core-owned output spool.
	ExternalJailerLimitRetainedOutput ExternalJailerLimit = "retained-output"
)

var requiredExternalJailerLimits = []ExternalJailerLimit{
	ExternalJailerLimitRootDisk,
	ExternalJailerLimitTmpfs,
	ExternalJailerLimitProcessCount,
	ExternalJailerLimitInodes,
	ExternalJailerLimitFiles,
	ExternalJailerLimitLifetime,
	ExternalJailerLimitProducedOutput,
	ExternalJailerLimitRetainedOutput,
}

// ExternalJailerLimitOwner binds one limit outside Jailer authority to a reviewed Stack resource reference.
// This declaration is a prerequisite, not a claim that the referenced resource has been provisioned or verified.
type ExternalJailerLimitOwner struct {
	Limit         ExternalJailerLimit
	StackResource string
}

// JailerExecutionAuthority is an immutable, exact Jailer invocation bound to one compiled plan.
// It carries only Jailer-enforceable controls and names every required external resource owner.
type JailerExecutionAuthority struct {
	version       string
	stackResource string
	cgroupParent  string
	cgroupPath    string
	arguments     []string
	external      []ExternalJailerLimitOwner
}

// Arguments returns a defensive copy of the complete Jailer argument vector.
func (authority JailerExecutionAuthority) Arguments() []string {
	return append([]string(nil), authority.arguments...)
}

// CgroupPath returns the exact per-VM cgroup path relative to the unified hierarchy.
func (authority JailerExecutionAuthority) CgroupPath() string { return authority.cgroupPath }

// CgroupParent returns the Stack-delegated parent cgroup relative to the unified hierarchy.
func (authority JailerExecutionAuthority) CgroupParent() string { return authority.cgroupParent }

// CgroupStackResource returns the declared Stack resource responsible for the delegated parent cgroup.
func (authority JailerExecutionAuthority) CgroupStackResource() string {
	return authority.stackResource
}

// ExternalLimitOwners returns defensive copies of the Stack dependencies that Jailer cannot enforce.
func (authority JailerExecutionAuthority) ExternalLimitOwners() []ExternalJailerLimitOwner {
	return append([]ExternalJailerLimitOwner(nil), authority.external...)
}

// CompileJailerExecutionAuthority binds a verified Plan to a Stack-delegated cgroup and exact Jailer-owned limits.
// It fails closed until each non-Jailer limit has a named external owner; it does not start Jailer or provision cgroups.
func CompileJailerExecutionAuthority(plan Plan, assignment JailerCgroupAssignment, external []ExternalJailerLimitOwner) (JailerExecutionAuthority, error) {
	if !validJailerExecutionPlan(plan) {
		return JailerExecutionAuthority{}, fmt.Errorf("%w: an exact fixed-base compiled Jailer plan is required", ErrInvalidProfile)
	}
	if !validJailerCgroupAssignmentValue(assignment) {
		return JailerExecutionAuthority{}, fmt.Errorf("%w: a versioned Stack-owned relative cgroup parent is required", ErrInvalidProfile)
	}
	external = append([]ExternalJailerLimitOwner(nil), external...)
	if missing, invalid := validateExternalJailerLimitOwners(external); missing != "" {
		return JailerExecutionAuthority{}, fmt.Errorf("%w: %s requires a named external Stack owner", ErrCapabilityUnavailable, missing)
	} else if invalid != "" {
		return JailerExecutionAuthority{}, fmt.Errorf("%w: %s", ErrInvalidProfile, invalid)
	}
	external = canonicalExternalJailerLimitOwners(external)

	arguments, err := jailerExecutionArguments(plan, assignment.Parent)
	if err != nil {
		return JailerExecutionAuthority{}, err
	}
	return JailerExecutionAuthority{
		version:       jailerExecutionAuthorityVersion,
		stackResource: assignment.StackResource,
		cgroupParent:  assignment.Parent,
		cgroupPath:    assignment.Parent + "/" + plan.VMID(),
		arguments:     arguments,
		external:      external,
	}, nil
}

func validJailerExecutionAuthority(authority JailerExecutionAuthority, plan Plan) bool {
	if !validJailerExecutionPlan(plan) || authority.version != jailerExecutionAuthorityVersion || !validStackResourceReference(authority.stackResource) || !validRelativeCgroupPath(authority.cgroupParent) || authority.cgroupPath != authority.cgroupParent+"/"+plan.VMID() || !sameStrings(authority.arguments, mustJailerExecutionArguments(plan, authority.cgroupParent)) {
		return false
	}
	missing, invalid := validateExternalJailerLimitOwners(authority.external)
	return missing == "" && invalid == "" && sameExternalJailerLimitOwners(authority.external, canonicalExternalJailerLimitOwners(authority.external))
}

func jailerExecutionArguments(plan Plan, parent string) ([]string, error) {
	if !validJailerExecutionPlan(plan) || !validRelativeCgroupPath(parent) {
		return nil, fmt.Errorf("%w: exact fixed-base compiled Jailer plan and delegated cgroup parent are required", ErrInvalidProfile)
	}
	arguments := plan.JailerArguments()
	separator := -1
	for index, argument := range arguments {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return nil, fmt.Errorf("%w: Jailer arguments must contain the Firecracker separator", ErrInvalidProfile)
	}
	const cgroupPeriodMicros = uint64(100000)
	cpuQuotaMicros := uint64(plan.Machine().VCPUCount) * cgroupPeriodMicros
	memoryBytes := uint64(plan.Machine().MemoryMiB) * (1 << 20)
	owned := []string{
		"--parent-cgroup", parent,
		"--cgroup", "cpu.max=" + strconv.FormatUint(cpuQuotaMicros, 10) + " " + strconv.FormatUint(cgroupPeriodMicros, 10),
		"--cgroup", "memory.max=" + strconv.FormatUint(memoryBytes, 10),
		"--cgroup", "pids.max=" + strconv.FormatUint(uint64(plan.Resources().PIDs), 10),
		"--resource-limit", "no-file=" + strconv.FormatUint(uint64(plan.Resources().OpenFiles), 10),
	}
	result := make([]string, 0, len(arguments)+len(owned))
	result = append(result, arguments[:separator]...)
	result = append(result, owned...)
	result = append(result, arguments[separator:]...)
	return result, nil
}

func validJailerExecutionPlan(plan Plan) bool {
	return validCompiledPlan(plan) && sameStrings(plan.jailerArguments, baseJailerArguments(plan.vmID, plan.firecracker.Path, plan.uid, plan.gid, plan.chrootBaseDir))
}

func mustJailerExecutionArguments(plan Plan, parent string) []string {
	arguments, err := jailerExecutionArguments(plan, parent)
	if err != nil {
		return nil
	}
	return arguments
}

func validJailerCgroupAssignmentValue(assignment JailerCgroupAssignment) bool {
	return assignment.Version == "firecracker.jailer-cgroup/v1" && validStackResourceReference(assignment.StackResource) && validRelativeCgroupPath(assignment.Parent)
}

func validateExternalJailerLimitOwners(owners []ExternalJailerLimitOwner) (missing, invalid string) {
	seen := make(map[ExternalJailerLimit]bool, len(owners))
	for _, owner := range owners {
		if !validExternalJailerLimit(owner.Limit) || !validStackResourceReference(owner.StackResource) {
			return "", "external Jailer limit owners must contain only known limits and Stack resource references"
		}
		if seen[owner.Limit] {
			return "", "external Jailer limit owners must not duplicate a limit"
		}
		seen[owner.Limit] = true
	}
	for _, limit := range requiredExternalJailerLimits {
		if !seen[limit] {
			return string(limit), ""
		}
	}
	return "", ""
}

func canonicalExternalJailerLimitOwners(owners []ExternalJailerLimitOwner) []ExternalJailerLimitOwner {
	byLimit := make(map[ExternalJailerLimit]ExternalJailerLimitOwner, len(owners))
	for _, owner := range owners {
		byLimit[owner.Limit] = owner
	}
	canonical := make([]ExternalJailerLimitOwner, 0, len(requiredExternalJailerLimits))
	for _, limit := range requiredExternalJailerLimits {
		canonical = append(canonical, byLimit[limit])
	}
	return canonical
}

func sameExternalJailerLimitOwners(left, right []ExternalJailerLimitOwner) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validExternalJailerLimit(limit ExternalJailerLimit) bool {
	for _, required := range requiredExternalJailerLimits {
		if limit == required {
			return true
		}
	}
	return false
}

func validStackResourceReference(value string) bool {
	return stackResourceReferencePattern.MatchString(value)
}

func validRelativeCgroupPath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if !validStackResourceReference(segment) {
			return false
		}
	}
	return true
}
