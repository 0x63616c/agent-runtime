ALTER TABLE runtime.firecracker_boot_probe_sessions
    DROP COLUMN command_version,
    DROP COLUMN command_wire,
    DROP COLUMN grant_wire,
    DROP COLUMN stage_ready_digest,
    DROP COLUMN stage_ready_wire,
    DROP COLUMN boot_probe_profile;

ALTER TABLE runtime.sandbox_host_enrollments
    DROP COLUMN boot_probe_profile,
    DROP COLUMN observation_public_key;
