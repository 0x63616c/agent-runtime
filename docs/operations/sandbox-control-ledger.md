# Sandbox-control ledger and recovery

Status: the PostgreSQL operation-ledger adapter and deterministic memory
conformance fixture are implemented. The public control service, complete host
protocol, output-store integration, and end-to-end worker/control/host failure
suite are not yet implemented. This guide does not promote SBX-002,
SBX-005–SBX-006, or SBX-013–SBX-014.

## Authority boundary

The sandbox-control role is the only runtime role that owns operation-ledger
mutation. It receives an explicit PostgreSQL pool from the composition root.
The role never creates a database, schema, table, credential, or migration.
An audited infrastructure operator applies the reviewed migration under
`deploy/sandboxcontrol/migrations/` before starting the role.

The ledger retains only bounded recovery facts: Principal scope, Operation ID,
canonical-request and Effective-Spec digests, lifecycle state/version,
acceptance and finite retention times, cleanup obligation, and current host
lease/fence. Request bodies, output, artifacts, secrets, backend handles, and
credentials belong in their dedicated stores and never enter these rows.

## Commit and reconnect rules

Acceptance and its outbox fact commit in one serializable transaction.

| Observation | Durable outcome |
| --- | --- |
| First Principal/Operation-ID/canonical digest | one accepted record at version 1 and one `accepted` outbox fact |
| Same Principal/Operation ID and immutable input | current durable record with `replay=true`; no second fact |
| Same Principal/Operation ID with changed immutable input | conflict; no dispatch or publication |
| Another Principal guesses the ID | indistinguishable not-found-or-denied result |
| Tombstoned Operation ID is submitted again | expired-ID result; the ID never becomes reusable |

Every assignment increments a finite monotonic fence before a `dispatched`
fact commits. A host result is accepted only for the current host/fence and
only when control observed it strictly before lease expiry. Expired assignments
are locked in bounded pages, fenced, cleared, changed to `uncertain`, and
published for reconciliation. This reconciles sandbox-owned state; it does not
promise exactly-once behavior for an external command effect.

## Cleanup and tombstones

The reaper owns eventual cleanup independently of a caller or Temporal
activity. At retention expiry it claims cleanup-required records in bounded,
locked pages, clears host authority, increments the fence, and records
`cleanup-pending`. Destructive cleanup happens outside the database
transaction. A separate transition records `cleanup-confirmed` only after the
execution boundary proves the process tree, proxy, shares, mounts, and disks
are gone.

`Reap` can tombstone an expired record only when cleanup was unnecessary or is
durably confirmed. Cleanup-pending records remain addressable. Tombstones keep
the Principal/Operation identity and bounded recovery facts so garbage
collection cannot make an idempotency key reusable.

## Operator integration lane

Run the explicit disposable PostgreSQL harness from the repository root:

```sh
./deploy/sandboxcontrol/postgres/run-integration.sh
```

The harness generates a per-run password, launches the digest-pinned
PostgreSQL declaration on an OS-selected loopback port, applies the reviewed
migration explicitly, runs the adapter under the race detector, and removes
its container, network, and volume. The tests prove restart reconnect,
Principal non-enumeration, concurrent immutable acceptance, conflict,
lease-expiry fencing, cleanup claim/confirmation, tombstone retention, and
ordered outbox replay through the PostgreSQL seam.

This is PostgreSQL adapter integration evidence, not a completed sandbox
control-plane E2E. The remaining #16 gate requires the real control process,
output/artifact store, host routing, restart across separate processes,
unknown-outcome recovery, and full reaper failure injection.
