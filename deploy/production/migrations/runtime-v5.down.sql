-- Runtime v5 is forward-only. Restoring a tested PostgreSQL backup is the
-- only safe way to reverse physical tenant partitions or RLS policy changes.
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('agent-runtime/runtime-v5', 0));
DO $$ BEGIN RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'runtime v5 migration is forward-only; restore a tested PostgreSQL backup'; END $$;
COMMIT;
