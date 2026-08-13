-- An operation may opt into a complete resource projection only at admission.
-- The original snapshot digest and transition model remain immutable even as
-- later lifecycle transitions replace the current read-model body.
ALTER TABLE runtime.sandbox_operations
    ADD COLUMN resource_projection_kind TEXT,
    ADD COLUMN resource_projection_id TEXT,
    ADD COLUMN resource_projection_admitted_snapshot_digest TEXT,
    ADD COLUMN resource_projection_transition TEXT,
    ADD CONSTRAINT sandbox_operations_resource_projection_binding_check CHECK (
        (resource_projection_kind IS NULL
            AND resource_projection_id IS NULL
            AND resource_projection_admitted_snapshot_digest IS NULL
            AND resource_projection_transition IS NULL)
        OR
        (resource_projection_kind IN ('sandbox', 'process')
            AND octet_length(resource_projection_id) BETWEEN 1 AND 128
            AND resource_projection_admitted_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'
            AND resource_projection_transition = 'replace-complete-snapshot')
    ),
    ADD CONSTRAINT sandbox_operations_resource_projection_target_check CHECK (
        resource_projection_kind IS NULL
        OR (target_kind = resource_projection_kind AND target_id = resource_projection_id)
    );
