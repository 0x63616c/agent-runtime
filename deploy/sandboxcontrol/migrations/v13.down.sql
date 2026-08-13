ALTER TABLE runtime.sandbox_operations
    DROP CONSTRAINT IF EXISTS sandbox_operations_resource_projection_target_check,
    DROP CONSTRAINT IF EXISTS sandbox_operations_resource_projection_binding_check,
    DROP COLUMN IF EXISTS resource_projection_transition,
    DROP COLUMN IF EXISTS resource_projection_admitted_snapshot_digest,
    DROP COLUMN IF EXISTS resource_projection_id,
    DROP COLUMN IF EXISTS resource_projection_kind;
