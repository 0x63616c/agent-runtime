-- Rollback is an explicit audited operator action. Dropping the operation
-- ledger destroys recovery authority and therefore never occurs at startup.
DROP TABLE IF EXISTS runtime.sandbox_operation_outbox;
DROP TABLE IF EXISTS runtime.sandbox_operations;
