package stack

import "github.com/cockroachdb/errors"

// SandboxQuotaPolicy supplies explicit defaults and ceilings to sandbox core.
type SandboxQuotaPolicy struct {
	// Defaults resolves every omitted sandbox limit once at acceptance.
	Defaults SandboxResourceLimits `json:"defaults"`
	// Maximums is the finite profile admission ceiling for every limit.
	Maximums SandboxResourceLimits `json:"maximums"`
}

// SandboxResourceLimits mirrors every public sandbox ResourceLimits dimension with explicit units.
type SandboxResourceLimits struct {
	// MilliCPU is CPU capacity in integer millicores.
	MilliCPU uint32 `json:"milli_cpu"`
	// MemoryBytes is the memory limit in bytes.
	MemoryBytes uint64 `json:"memory_bytes"`
	// RootDiskBytes is root filesystem capacity in bytes.
	RootDiskBytes uint64 `json:"root_disk_bytes"`
	// TmpfsBytes is aggregate tmpfs capacity in bytes.
	TmpfsBytes uint64 `json:"tmpfs_bytes"`
	// PIDs is the task limit.
	PIDs uint32 `json:"pids"`
	// ProcessCount is the process limit.
	ProcessCount uint32 `json:"process_count"`
	// OpenFiles is the open-file limit.
	OpenFiles uint32 `json:"open_files"`
	// Inodes is the inode limit.
	Inodes uint64 `json:"inodes"`
	// Files is the file-count limit.
	Files uint64 `json:"files"`
	// LifetimeSeconds is finite sandbox lifetime in seconds.
	LifetimeSeconds uint64 `json:"lifetime_seconds"`
	// ProducedOutputBytes is total output production before termination.
	ProducedOutputBytes uint64 `json:"produced_output_bytes"`
	// RetainedOutputBytes is bounded retained output per policy.
	RetainedOutputBytes uint64 `json:"retained_output_bytes"`
	// TransferBytes is aggregate portable transfer capacity.
	TransferBytes uint64 `json:"transfer_bytes"`
	// NetworkConnections is the concurrent connection limit.
	NetworkConnections uint32 `json:"network_connections"`
	// VolumeBytes is aggregate named-volume capacity.
	VolumeBytes uint64 `json:"volume_bytes"`
	// SnapshotBytes is aggregate snapshot capacity.
	SnapshotBytes uint64 `json:"snapshot_bytes"`
}

func validateSandboxQuotaPolicy(policy SandboxQuotaPolicy) error {
	if !limitsNonZero(policy.Defaults) || !limitsNonZero(policy.Maximums) {
		return errors.New("sandbox quota defaults and maximums must set every limit to a non-zero finite value")
	}
	if !limitsWithin(policy.Defaults, policy.Maximums) {
		return errors.New("sandbox quota defaults must not exceed profile maximums")
	}
	return nil
}

func limitsNonZero(limits SandboxResourceLimits) bool {
	return limits.MilliCPU > 0 && limits.MemoryBytes > 0 && limits.RootDiskBytes > 0 && limits.TmpfsBytes > 0 &&
		limits.PIDs > 0 && limits.ProcessCount > 0 && limits.OpenFiles > 0 && limits.Inodes > 0 && limits.Files > 0 &&
		limits.LifetimeSeconds > 0 && limits.ProducedOutputBytes > 0 && limits.RetainedOutputBytes > 0 &&
		limits.TransferBytes > 0 && limits.NetworkConnections > 0 && limits.VolumeBytes > 0 && limits.SnapshotBytes > 0
}

func limitsWithin(value, maximum SandboxResourceLimits) bool {
	return value.MilliCPU <= maximum.MilliCPU && value.MemoryBytes <= maximum.MemoryBytes && value.RootDiskBytes <= maximum.RootDiskBytes &&
		value.TmpfsBytes <= maximum.TmpfsBytes && value.PIDs <= maximum.PIDs && value.ProcessCount <= maximum.ProcessCount &&
		value.OpenFiles <= maximum.OpenFiles && value.Inodes <= maximum.Inodes && value.Files <= maximum.Files &&
		value.LifetimeSeconds <= maximum.LifetimeSeconds && value.ProducedOutputBytes <= maximum.ProducedOutputBytes &&
		value.RetainedOutputBytes <= maximum.RetainedOutputBytes && value.TransferBytes <= maximum.TransferBytes &&
		value.NetworkConnections <= maximum.NetworkConnections && value.VolumeBytes <= maximum.VolumeBytes && value.SnapshotBytes <= maximum.SnapshotBytes
}
