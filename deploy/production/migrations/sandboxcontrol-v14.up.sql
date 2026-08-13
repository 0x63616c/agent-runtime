-- Output retention is resolved by public admission and immutable per operation.
ALTER TABLE runtime.sandbox_operations
    ADD COLUMN retained_output_bytes BIGINT NOT NULL DEFAULT 16777216
    CHECK (retained_output_bytes > 0 AND retained_output_bytes <= 268435456);

-- Signed host output headers existed before durable replay. Keep their
-- metadata table immutable and retain the bounded redacted bytes in a child
-- table so pre-v14 receipts remain auditable without pretending replay exists.
CREATE TABLE runtime.sandbox_host_output_chunks (
    assignment_id TEXT NOT NULL CHECK (octet_length(assignment_id) BETWEEN 1 AND 128),
    stream TEXT NOT NULL CHECK (stream IN ('stdout', 'stderr')),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    chunk BYTEA NOT NULL CHECK (octet_length(chunk) BETWEEN 1 AND 262144),
    redacted BOOLEAN NOT NULL,
    PRIMARY KEY (assignment_id, stream, sequence),
    FOREIGN KEY (assignment_id, stream, sequence)
        REFERENCES runtime.sandbox_host_outputs (assignment_id, stream, sequence)
        ON DELETE CASCADE
);

CREATE INDEX sandbox_host_output_chunks_replay_idx
    ON runtime.sandbox_host_output_chunks (assignment_id, stream, sequence);
