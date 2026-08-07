-- Opaque Operation IDs are globally non-reassignable. A different Principal
-- colliding with a known ID receives the same non-enumerating denial as a
-- guessed object lookup.
CREATE UNIQUE INDEX sandbox_operations_global_id_idx
    ON runtime.sandbox_operations (operation_id);
