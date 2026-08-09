-- Keep assurance profile, predicate outcome, digest presence and admission
-- status as one coherent durable attestation tuple.
ALTER TABLE runtime.sandbox_host_enrollments
    ADD CONSTRAINT sandbox_host_enrollments_attestation_tuple_check CHECK (
        (
            attestation_profile = 'local-metadata-v1'
            AND attestation_state = 'metadata-only'
            AND attestation_digest IS NULL
            AND status IN ('active', 'revoked', 'quarantined')
        )
        OR
        (
            attestation_profile = 'verified-v1'
            AND attestation_state = 'verified'
            AND attestation_digest IS NOT NULL
            AND status IN ('active', 'revoked', 'quarantined')
        )
        OR
        (
            attestation_profile = 'verified-v1'
            AND attestation_state = 'failed'
            AND attestation_digest IS NOT NULL
            AND status = 'attestation-failed'
        )
    );
