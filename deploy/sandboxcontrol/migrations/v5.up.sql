-- Persist the authenticated tenant scope and exact bounded normalized dispatch
-- body before any host can receive an assignment.
ALTER TABLE runtime.sandbox_operations
    ADD COLUMN tenant TEXT CHECK (octet_length(tenant) BETWEEN 1 AND 256),
    ADD COLUMN dispatch_body TEXT CHECK (octet_length(dispatch_body) BETWEEN 1 AND 1048576);

UPDATE runtime.sandbox_operations
SET tenant = split_part(principal, ':', 1),
    dispatch_body = '{}'
WHERE tenant IS NULL OR dispatch_body IS NULL;

ALTER TABLE runtime.sandbox_operations
    ALTER COLUMN tenant SET NOT NULL,
    ALTER COLUMN dispatch_body SET NOT NULL;
