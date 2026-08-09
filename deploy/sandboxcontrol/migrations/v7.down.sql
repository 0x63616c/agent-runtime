ALTER TABLE runtime.sandbox_host_enrollments
    DROP CONSTRAINT sandbox_host_enrollments_status_check;

UPDATE runtime.sandbox_host_enrollments
SET status = 'revoked'
WHERE status = 'attestation-failed';

ALTER TABLE runtime.sandbox_host_enrollments
    ADD CONSTRAINT sandbox_host_enrollments_status_check
        CHECK (status IN ('active', 'revoked', 'quarantined')),
    DROP COLUMN attestation_state,
    DROP COLUMN attestation_profile;
