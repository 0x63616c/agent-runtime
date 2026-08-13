-- Resource inspection is backed only by explicit metadata emitted with a
-- control-plane lifecycle transition. Operation targets are deliberately not
-- sufficient to populate these rows.
CREATE TABLE runtime.sandbox_resource_projections (
    principal TEXT NOT NULL CHECK (octet_length(principal) BETWEEN 1 AND 512),
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('sandbox', 'process')),
    resource_id TEXT NOT NULL CHECK (octet_length(resource_id) BETWEEN 1 AND 128),
    operation_id TEXT NOT NULL CHECK (octet_length(operation_id) BETWEEN 1 AND 128),
    operation_version BIGINT NOT NULL CHECK (operation_version > 0),
    body JSONB NOT NULL CHECK (octet_length(body::text) BETWEEN 2 AND 65536),
    PRIMARY KEY (principal, resource_kind, resource_id)
);

CREATE INDEX sandbox_resource_projections_operation_idx
    ON runtime.sandbox_resource_projections (principal, operation_id);
