BEGIN;

DROP TABLE runtime.runtime_outbox;
DROP TABLE runtime.audit_records;
DROP TABLE runtime.session_events;
DROP TABLE runtime.turns;
DROP TABLE runtime.inputs;
DROP TABLE runtime.sessions;
DROP TABLE runtime.agent_revisions;
DROP TABLE runtime.tenants;

COMMIT;
