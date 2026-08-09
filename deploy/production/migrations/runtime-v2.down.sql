BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('agent-runtime/runtime-v2', 0));

DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'runtime v2 migration is forward-only; restore a tested PostgreSQL backup instead of destructive rollback';
END $$;

COMMIT;
