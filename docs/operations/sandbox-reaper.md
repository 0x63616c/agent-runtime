# Sandbox reaper

`sandbox-reaper` is an independently deployable M3 process. Its failure domain
is separate from the public API, Temporal workers, sandbox-control listeners,
and execution hosts. It requires only the sandbox PostgreSQL credential and
never opens a public listener.

The strict version-1 declaration contains:

| Field | Meaning |
| --- | --- |
| `database_dsn_environment` | Explicit injected secret name for the already-created sandbox ledger. |
| `interval_millis` | Positive reconciliation interval, no greater than one minute. |
| `page_size` | Positive bounded transaction page, no greater than 1000. |

Every pass uses one injected UTC observation and invokes, in order:

1. expired assignment recovery, which advances the fence and exposes
   unresolved work as `uncertain`;
2. cleanup claiming, which removes live host authority and records
   `cleanup-pending`; and
3. safe reaping, which tombstones only work that requires no cleanup or already
   has explicit cleanup confirmation.

Each successful pass emits one structured, content-free summary with the
observation time and counts for all three decisions. Errors retain operation
boundaries but do not include DSNs, credentials, request bodies, output, or
guest data. A failure exits the process so its declarative workload supervisor
can restart it; PostgreSQL locking and durable state make every pass retryable.

The reaper never treats lease expiry, host disconnect, process exit,
revocation, or quarantine as proof that a guest process tree, proxy, mount, or
disk is gone. M3 therefore leaves cleanup-required records pending until an
authorized cleanup confirmer supplies evidence. M4 will connect real
Linux/KVM cleanup through that existing boundary.
