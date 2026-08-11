-- Runtime v4 is forward-only. Restore a tested PostgreSQL backup rather than
-- deleting lifecycle receipts, invocation fences, or outbox lease evidence.
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('agent-runtime/runtime-v4', 0));
DO $$ BEGIN RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'runtime v4 migration is forward-only; restore a tested PostgreSQL backup'; END $$;
COMMIT;
