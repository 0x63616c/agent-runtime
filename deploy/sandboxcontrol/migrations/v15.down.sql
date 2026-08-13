ALTER TABLE runtime.sandbox_operations
    DROP CONSTRAINT sandbox_operations_resource_projection_binding_check,
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
    );

ALTER TABLE runtime.sandbox_resource_projections
    DROP CONSTRAINT sandbox_resource_projections_resource_kind_check,
    ADD CONSTRAINT sandbox_resource_projections_resource_kind_check
        CHECK (resource_kind IN ('sandbox', 'process'));
