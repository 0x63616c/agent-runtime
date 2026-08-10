-- The private v2 Firecracker path has an independent durable lifecycle.  It
-- deliberately has no foreign key to the generic v1 delivery journal.
CREATE TABLE runtime.firecracker_boot_probe_sessions (
    host_instance_session_id TEXT PRIMARY KEY CHECK (octet_length(host_instance_session_id) BETWEEN 1 AND 128),
    host_id TEXT NOT NULL CHECK (octet_length(host_id) BETWEEN 1 AND 128),
    host_generation BIGINT NOT NULL CHECK (host_generation > 0),
    principal TEXT NOT NULL CHECK (octet_length(principal) BETWEEN 1 AND 512),
    operation_id TEXT NOT NULL CHECK (octet_length(operation_id) BETWEEN 1 AND 128),
    assignment_id TEXT NOT NULL CHECK (octet_length(assignment_id) BETWEEN 1 AND 128),
    version BIGINT NOT NULL CHECK (version > 0),
    session_body BYTEA NOT NULL CHECK (octet_length(session_body) BETWEEN 1 AND 65536),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX firecracker_boot_probe_sessions_host_idx
    ON runtime.firecracker_boot_probe_sessions (host_id, host_generation);
