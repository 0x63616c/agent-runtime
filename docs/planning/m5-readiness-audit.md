# M5 readiness audit

Status: implementation audit; incomplete. This is not a requirement promotion
or a substitute for the one M5 independent review.

## Ownership result

The authoritative terminal-owner map is
[work-map.md](work-map.md): issue #23 owns `DOM-001` through `DOM-013` and
`API-001` through `API-012`; issue #24 owns `DAT-001` through `DAT-013`; and
issue #25 owns `TMP-002` through `TMP-004` plus `TMP-009` and `TMP-010`.
The generated requirements catalog records every one of those rows as M5. M6
owns only `MOD-*`; M7 owns only `TOL-*`, `HITL-*`, and its examples. A later
milestone may depend on the M5 foundations, but it does not transfer their
terminal evidence ownership.

## Implemented and tested foundation

| Area | Current implementation and evidence | Remaining terminal gap |
| --- | --- | --- |
| DOM-001–011 (bounded foundation) | Immutable Agent revisions, revision-pinned Sessions, bounded Input references, serialized Turns, invocation records/fences, cancellation and settlement are implemented by `internal/runtimestate`; `compiler_planner_test.go`, `state_runtime_test.go`, and durable API integration cover the initial lifecycle. `AppendConversation` persists only immutable content references under expected-version conflict/idempotency, while `RegisterArtifact` and the state-authorized content reader provide ID/digest metadata plus principal-checked readback. A Tool intent remains non-executing; an approved Approval creates a bounded capability grant, and worker consumption enforces owner, policy revision, expiry, and maximum uses before an external effect. `internal/runtimemodel` now owns a provider-neutral invocation adapter: fresh intents invoke once, expired claims reconcile by the same operation ID, and both persist a fenced terminal result plus optional unknown-preserving token usage before acknowledgement. | Artifact input authorization is not wired through `StateRuntime`; conversation/model production-provider composition, normalized streaming, and Tool execution remain absent. |
| API-001–012 (bounded public/admin foundation) | Temporal-free SDK/OpenAPI route contract, strict HTTP handling, bounded public models, authorization, cursors, cancellation, inspection and model-profile allowlist have unit/architecture coverage. Artifact download is a state-authorized SDK/HTTP read; scoped durable receipt status is observable without replaying work. Approval inspect and idempotent approve/deny are public Go SDK and HTTP operations with an owner-scoped StateRuntime integration test and HTTP/SDK contract test. A fake-clock StateRuntime regression test proves a late decision durably transitions the Approval to `expired`, records the terminal audit fact, and returns a safe conflict instead of authorizing execution. The same real StateRuntime behind the HTTP handler and public Go SDK proves the safe conflict, durable expired projection, idempotent retry, and retained receipt for an expired Approval decision. A short-retention, real HTTP/SDK scenario proves an expired Input mutation is not replayed, status lookup returns safe conflict, and a fresh idempotency key admits a distinct Turn. Tenant administrators can now create, revise, replay, and read immutable named Policy revisions through the compiler/planner/state-store/HTTP/SDK boundary; direct StateRuntime composition also refuses catalog mutations without `Identity.Admin`. `deploy/runtimeapi/run-durable-integration.sh` additionally proves that a Policy created through the real disposable PostgreSQL/MinIO HTTP process remains readable after process restart. A checked-in v1 OpenAPI compatibility baseline preserves public routes, success statuses, schema fields, and existing enum members; `docs/reference/api-compatibility.md` gives the compatible-addition versus breaking-change migration policy. | API-012 still needs the final combined admin authorization suite; the compatibility evidence needs the final M5 release-consumer check. |
| DAT-001–003, DAT-005–007 (bounded foundation) | Conversation expected-version/idempotent planner behavior, immutable Artifact digest authorization, planner-produced ordered events/audit/outbox, CAS state persistence, cursor behavior, and lease claim/ack are tested. State records now use named independently configurable retention classes: events, audit, outbox, and idempotency receipts have horizons distinct from the Agent/Session/Input records they accompany. An operator-authorized PostgreSQL retention collector locks one tenant, deletes only expired unpinned Agent/Input/Artifact/Conversation metadata and exact no-longer-referenced content, and leaves metadata intact on content failure; the disposable PostgreSQL/MinIO test proves both denied and successful collection. The orchestration suite simulates the process-loss window after Temporal accepts a route but before durable acknowledgement: the lease reclaims the exact route, whose duplicate is workflow-safe, and only then records `published`. Its state-to-publisher route test also persists a fenced `uncertain` invocation following producer loss, terminally settles the Turn as failed, and proves that the approval and finalization outbox routes are rechecked only after publication. The provider-neutral model-worker test proves a fresh intent invokes exactly once and an expired model claim reconciles using the same operation ID without a second invocation; both paths durably finalize before their intent outbox is acknowledged. An uncertain outcome creates ordered public `producer.gap` then `turn.failed` Events, so replay observes a terminal gap rather than a silent loss. The disposable PostgreSQL integration runs migrations, rollback refusal, and state-store checks. Its operator-only backup/restore drill seeds a tenant row, takes a custom-format backup using the service-matched PostgreSQL client, deletes the source row, restores into a fresh disposable database, and verifies that exact tenant row is recovered; the Docker-backed run passed on this branch. The same integration suite proves a tenant/action-bound authorization denial leaves a staged immutable body unchanged, while an authorized composed erasure deletes only the state-referenced object and then removes that tenant's PostgreSQL metadata. | Artifact streaming/retention evidence, provider-stream replay coverage, full audit fact lifecycle/outage matrix, production retention/PITR evidence, and process-kill boundary matrix are absent. |
| TMP-002–004 (Session route) | Private Temporal-free public API boundary; owned codec factory; durable state/outbox scheduler; replay-safe Session workflow versioning, duplicate tolerance, Continue-As-New, and development-server replay evidence. | A retained historic replay fixture and the complete lifecycle coverage are still absent. |

## Missing M5 work before review

The acceptance ledger specifies the missing proof/behavior, not merely
documentation:

- DOM-008–009, DOM-012–013: Tool broker/execution integration and expiry
  acceptance evidence, plus provider-neutral usage and public failure contracts
  integrated with runtime state/API.
- API-011: retain the release-consumer compatibility check; API-012: final combined admin authorization suite.
- DAT-002, DAT-004, DAT-008–013: artifact streaming/retention authority,
  real producer-loss stream gap/replay behavior beyond the persisted uncertain
  finalization path, lifecycle/GC classification, production
  PostgreSQL retention/partition/erasure/backup-restore evidence, and
  process-kill outbox recovery.
- TMP-010: full durable-state and retained-history evidence for the approval,
  sandbox-operation, and event-finalization lifecycle. A state-to-publisher
  test now covers approval plus uncertain producer-loss finalization, and the
  Temporal test environment retains the ordered lifecycle vocabulary; the
  sandbox external-effect and retained-history completion proof remains.
  TMP-009 has a closed retry decision table and focused classification proof,
  but remains part of the final M5 evidence bundle.

The existing M5 implementation must not claim these rows or request its
independent review until this table is closed with named evidence.
