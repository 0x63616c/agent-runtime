-- A reference-only terminal data-plane receipt must reach durable control
-- before a host reports terminal success. One exact receipt is allowed for an
-- assignment; control retains only its signed metadata digest, never content.
ALTER TABLE runtime.sandbox_host_dispatches
    ADD COLUMN data_receipt_kind TEXT CHECK (data_receipt_kind IS NULL OR data_receipt_kind IN ('transfer', 'snapshot-restore', 'mount')),
    ADD COLUMN data_receipt_digest TEXT CHECK (data_receipt_digest IS NULL OR octet_length(data_receipt_digest) BETWEEN 1 AND 128),
    ADD COLUMN data_receipt_id TEXT CHECK (data_receipt_id IS NULL OR octet_length(data_receipt_id) BETWEEN 1 AND 128),
    ADD CONSTRAINT sandbox_host_dispatches_data_receipt_shape CHECK ((data_receipt_kind IS NULL AND data_receipt_digest IS NULL AND data_receipt_id IS NULL) OR (data_receipt_kind IS NOT NULL AND data_receipt_digest IS NOT NULL AND data_receipt_id IS NOT NULL));
