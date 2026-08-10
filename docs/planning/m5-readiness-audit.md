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
| DOM-001–007 | Immutable Agent revisions, revision-pinned Sessions, bounded Input references, serialized Turns, invocation records/fences, cancellation and settlement are implemented by `internal/runtimestate`; `compiler_planner_test.go`, `state_runtime_test.go`, and durable API integration cover the initial lifecycle. | Artifact input authorization is not wired through `StateRuntime`; model-attempt dispatch has no model adapter. |
| API-002–003, API-005–010 (initial Session surface) | Temporal-free SDK/OpenAPI route contract, strict HTTP handling, bounded public models, authorization, cursors, cancellation, inspection and model-profile allowlist have unit/architecture coverage. | API-001 is not complete: the public Artifact and Approval operations are absent. API-004 lacks the required durable idempotency-status lookup; API-011 lacks policy/tool compatibility artifacts; API-012 has no policy administration surface. |
| DAT-003, DAT-005–007 (initial event/audit/outbox) | Planner-produced ordered events/audit/outbox, CAS state persistence, cursor behavior, and lease claim/ack are tested. The disposable PostgreSQL integration runs migrations, rollback refusal, and state-store checks. | Producer-loss gap/finalization, full audit fact lifecycle/outage matrix, data-classification/GC, tenant erasure, backup/restore, and process-kill boundary matrix are absent. |
| TMP-002–004 (Session route) | Private Temporal-free public API boundary; owned codec factory; durable state/outbox scheduler; replay-safe Session workflow versioning, duplicate tolerance, Continue-As-New, and development-server replay evidence. | A retained historic replay fixture and the complete lifecycle coverage are still absent. |

## Missing M5 work before review

The acceptance ledger specifies the missing proof/behavior, not merely
documentation:

- DOM-008–013: durable Tool-intent/grant, conversation, Artifact readback,
  provider-neutral usage, and public failure contracts integrated with runtime
  state/API.
- API-001, API-004, API-011–012: Artifact/Approval HTTP+SDK operations,
  idempotency-status lookup, compatibility fixtures, and policy admin surface.
- DAT-001–002, DAT-004, DAT-008–013: conversation/artifact authority,
  producer-loss finalization, lifecycle/GC classification, production
  PostgreSQL retention/partition/erasure/backup-restore evidence, and
  process-kill outbox recovery.
- TMP-009–010: the retry decision table including uncertain external effect
  and incompatible policy, plus Temporal test-environment approval and
  sandbox-operation lifecycle scenarios.

The existing M5 implementation must not claim these rows or request its
independent review until this table is closed with named evidence.
