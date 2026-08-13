-- Public Operation reconstruction remains metadata-only and bounded. Host
-- dispatch inputs belong to the later authenticated envelope/spec store.
ALTER TABLE runtime.sandbox_operations
    ADD COLUMN kind TEXT NOT NULL DEFAULT '' CHECK (octet_length(kind) <= 64),
    ADD COLUMN target_kind TEXT NOT NULL DEFAULT '' CHECK (octet_length(target_kind) <= 32),
    ADD COLUMN target_id TEXT NOT NULL DEFAULT '' CHECK (octet_length(target_id) <= 128),
    ADD COLUMN capability_digest TEXT NOT NULL DEFAULT '' CHECK (octet_length(capability_digest) <= 128);
