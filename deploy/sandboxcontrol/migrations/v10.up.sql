-- M3 persists the operator-owned M4 profile and the distinct observation key
-- before any v2 preparation. Stage-ready, grant, and command bytes are kept
-- with the exact session so a lost response can converge without minting a
-- second authorization.
ALTER TABLE runtime.sandbox_host_enrollments
    ADD COLUMN observation_public_key BYTEA CHECK (observation_public_key IS NULL OR octet_length(observation_public_key) = 32),
    ADD COLUMN boot_probe_profile BYTEA CHECK (boot_probe_profile IS NULL OR octet_length(boot_probe_profile) BETWEEN 1 AND 4096);

ALTER TABLE runtime.firecracker_boot_probe_sessions
    ADD COLUMN boot_probe_profile BYTEA CHECK (boot_probe_profile IS NULL OR octet_length(boot_probe_profile) BETWEEN 1 AND 4096),
    ADD COLUMN stage_ready_wire BYTEA CHECK (stage_ready_wire IS NULL OR octet_length(stage_ready_wire) BETWEEN 1 AND 32768),
    ADD COLUMN stage_ready_digest TEXT CHECK (stage_ready_digest IS NULL OR octet_length(stage_ready_digest) BETWEEN 1 AND 128),
    ADD COLUMN grant_wire BYTEA CHECK (grant_wire IS NULL OR octet_length(grant_wire) BETWEEN 1 AND 16384),
    ADD COLUMN command_wire BYTEA CHECK (command_wire IS NULL OR octet_length(command_wire) BETWEEN 1 AND 32768),
    ADD COLUMN command_version BIGINT CHECK (command_version IS NULL OR command_version > 0);
