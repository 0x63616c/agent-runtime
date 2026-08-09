# Sandbox-control ledger and recovery

Status: the PostgreSQL operation ledger, deterministic memory conformance
fixture, strict public operation transport, separately runnable TLS control
role, private enrolled-host protocol, and one-shot reference host are
implemented. Output/artifact content storage and Linux/KVM execution are not.
This guide does not promote a milestone ledger row without retained evidence
and independent M3 review.

## Authority boundary

The sandbox-control role is the only runtime role that owns operation-ledger
mutation. It receives an explicit PostgreSQL pool from the composition root.
The role never creates a database, schema, table, credential, or migration.
An audited infrastructure operator applies the reviewed migration under
`deploy/sandboxcontrol/migrations/` before starting the role.

The ledger retains bounded recovery facts: Principal and tenant scope,
Operation ID, the exact bounded canonical dispatch request, canonical-request,
Effective-Spec and capability digests; safe operation/target metadata;
lifecycle state/version, acceptance and finite retention times, cleanup
obligation, current host generation/assignment/lease/fence, exact signed
envelope and receipt, and output integrity sequence headers. Output content,
artifacts, secrets, backend handles, private keys, and certificate bodies
belong elsewhere and never enter these rows.

The bounded dispatch JSON may retain ordinary non-sensitive environment data,
for example `{"environment":{"MODE":"test"}}`. A secret binding is retained
only as an indirect reference such as
`{"secret_bindings":[{"name":"model","purpose":"command"}]}`; resolution and
the value itself belong to the ephemeral secret channel. Acceptance refuses
secret-shaped environment names and recognizable direct secret material such
as bearer tokens, provider key prefixes, or PEM private keys. This is a strict
boundary check, not a claim that arbitrary caller strings can be proven
secret-free.

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

`cmd/sandbox-reaper` is the independently deployable owner of these periodic
database passes. Its strict declaration names only a PostgreSQL DSN secret,
finite interval, and finite page size; see
`deploy/sandboxreaper/reaper.example.json`. It emits bounded JSON summaries of
recovered assignments, cleanup claims, and tombstones. It has no public API,
Temporal dependency, certificate authority, migration authority, or guest
backend credential. Until M4 supplies a certified cleanup adapter, it leaves
cleanup-required records visibly pending for separately authorized cleanup
evidence rather than guessing from liveness.

## Operator integration lane

Run the explicit disposable PostgreSQL harness from the repository root:

```sh
./deploy/sandboxcontrol/postgres/run-integration.sh
```

The harness generates a per-run password, launches the digest-pinned
PostgreSQL declaration on an OS-selected loopback port, applies the reviewed
migrations explicitly, builds both TLS roles under the race detector, runs
adapter tests, then starts and restarts them as separate OS processes through
the public pinned-TLS client and private mTLS host listener. It removes its
temporary binaries, container, network, and volume. The tests prove restart reconnect,
Principal non-enumeration, concurrent immutable acceptance, conflict,
lease-expiry fencing, cleanup claim/confirmation, tombstone retention, and
ordered outbox replay plus host enrollment, signed envelopes, stable receipts,
lost-result recovery, quarantine, rotation, cleanup, and reassignment through
the PostgreSQL seam.

This is durable acceptance/reconnect and reference host-protocol evidence, not
a completed sandbox execution E2E. Output/artifact content storage, real guest
execution, Linux/KVM isolation, and full production reaper failure injection
remain separately gated.
