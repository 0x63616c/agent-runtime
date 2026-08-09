-- Runtime v3 raises only the bounded immutable input-reference metadata limit.
-- It is forward-only; runtime-v2 remains an immutable historical catalog.
BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('agent-runtime/runtime-v3', 0));

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM runtime.schema_migrations WHERE migration_version = 2) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'runtime v3 requires runtime v2 authority';
    END IF;
END $$;

ALTER TABLE runtime.inputs DROP CONSTRAINT IF EXISTS inputs_content_size_bytes_check;
ALTER TABLE runtime.inputs ADD CONSTRAINT inputs_content_size_bytes_v3_bound
    CHECK (content_size_bytes BETWEEN 0 AND 2101248);

INSERT INTO runtime.schema_migrations (migration_version, schema_fingerprint, applied_at)
VALUES (3, 'md5:0d3bfa37b8e0feeb2e483206ff93fa9d', now())
ON CONFLICT (migration_version) DO NOTHING;

DO $$
DECLARE
    expected_fingerprint TEXT := 'md5:0d3bfa37b8e0feeb2e483206ff93fa9d';
    stored_fingerprint TEXT;
    actual_fingerprint TEXT;
BEGIN
    SELECT schema_fingerprint INTO stored_fingerprint
    FROM runtime.schema_migrations WHERE migration_version = 3;
    IF stored_fingerprint IS DISTINCT FROM expected_fingerprint THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'runtime v3 migration fingerprint mismatch';
    END IF;
    WITH objects AS (
        SELECT format('T|%s', relation.relname) AS line
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'runtime' AND relation.relkind = 'r' AND relation.relname = 'inputs'
        UNION ALL
        SELECT format('C|%s|%s|%s|%s|%s', relation.relname, attribute.attname,
            format_type(attribute.atttypid, attribute.atttypmod), attribute.attnotnull,
            coalesce(pg_get_expr(default_value.adbin, default_value.adrelid), ''))
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        JOIN pg_attribute attribute ON attribute.attrelid = relation.oid AND attribute.attnum > 0 AND NOT attribute.attisdropped
        LEFT JOIN pg_attrdef default_value ON default_value.adrelid = relation.oid AND default_value.adnum = attribute.attnum
        WHERE namespace.nspname = 'runtime' AND relation.relkind = 'r' AND relation.relname = 'inputs'
        UNION ALL
        SELECT format('K|%s|%s|%s|%s', relation.relname, con.conname, con.contype, pg_get_constraintdef(con.oid, true))
        FROM pg_constraint con
        JOIN pg_class relation ON relation.oid = con.conrelid
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'runtime' AND relation.relname = 'inputs'
        UNION ALL
        SELECT format('I|%s|%s|%s', tablename, indexname, indexdef)
        FROM pg_indexes WHERE schemaname = 'runtime' AND tablename = 'inputs'
    )
    SELECT 'md5:' || md5(string_agg(line, E'\n' ORDER BY line)) INTO actual_fingerprint FROM objects;
    IF actual_fingerprint IS DISTINCT FROM expected_fingerprint THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'runtime v3 migration physical catalog fingerprint mismatch';
    END IF;
END $$;

COMMIT;
