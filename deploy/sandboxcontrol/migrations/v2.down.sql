ALTER TABLE runtime.sandbox_operations
    DROP COLUMN IF EXISTS capability_digest,
    DROP COLUMN IF EXISTS target_id,
    DROP COLUMN IF EXISTS target_kind,
    DROP COLUMN IF EXISTS kind;
