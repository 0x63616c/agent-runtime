-- Preserve the exact accepted wire identity independently from effective
-- policy digests so retries survive operator-default changes safely.
ALTER TABLE runtime.sandbox_operations
    ADD COLUMN input_digest TEXT
        CHECK (octet_length(input_digest) BETWEEN 1 AND 128);

UPDATE runtime.sandbox_operations
SET input_digest = canonical_digest
WHERE input_digest IS NULL;

ALTER TABLE runtime.sandbox_operations
    ALTER COLUMN input_digest SET NOT NULL;
