-- Persist an explicit attestation assurance profile and its safe outcome.
-- The metadata-only local profile is intentionally distinct from verification.
ALTER TABLE runtime.sandbox_host_enrollments
    ADD COLUMN attestation_profile TEXT NOT NULL DEFAULT 'local-metadata-v1'
        CHECK (attestation_profile IN ('local-metadata-v1', 'verified-v1')),
    ADD COLUMN attestation_state TEXT NOT NULL DEFAULT 'metadata-only'
        CHECK (attestation_state IN ('metadata-only', 'verified', 'failed'));

ALTER TABLE runtime.sandbox_host_enrollments
    DROP CONSTRAINT sandbox_host_enrollments_status_check,
    ADD CONSTRAINT sandbox_host_enrollments_status_check
        CHECK (status IN ('active', 'revoked', 'quarantined', 'attestation-failed'));
