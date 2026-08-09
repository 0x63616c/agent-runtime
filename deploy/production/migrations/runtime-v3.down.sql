BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('agent-runtime/runtime-v3', 0));
DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'runtime v3 migration is forward-only; restore an operator-approved PostgreSQL backup for recovery';
END $$;
COMMIT;
