# M0 planning reconciliation

Status: accepted governance correction; no production capability is claimed by
this document.

This record closes the six P0 planning blockers from
[planning review](planning-review.md). Binding authority now resides in the
[master requirements](requirements/master-requirements.md),
[`CONTEXT.md`](../../CONTEXT.md), the [accepted system architecture](../architecture/system.md)
and [accepted ADRs](../adr/README.md). Proposed planning documents and the
supplied external discussion draft are useful historical input but cannot
override those sources.

## P0 corrections

| Review blocker | Binding correction | Requirements / seam / ADR | Evidence and documentation plan | Status |
| --- | --- | --- | --- | --- |
| P0-1 — declarative infrastructure | One typed Stack specification owns all desired infrastructure; startup and helpers cannot create it; rendering, ownership, lifecycle, diff and audited reconciliation are mandatory. | INF-001–005; S11; INV-INF-001–003; [ADR-0002](../adr/0002-declarative-infrastructure.md) | Renderer/policy/two-stack/migration/RBAC/NetworkPolicy suites; desired-state inventory and operator lifecycle/rollback docs. | Closed as a planning decision; implementation starts M0/M1. |
| P0-2 — data/event authority | PostgreSQL is required v1 authority for control/metadata/events/audit/outbox; Temporal orchestrates; blob storage holds immutable large content. Workflow Streams cannot own public events/cursors/retention. | DAT-009–013; S7; INV-DAT-008–010; [ADR-0003](../adr/0003-postgresql-event-outbox-authority.md) | PostgreSQL migration/conflict/outbox/backup/restore/tenant-negative evidence; product-event/cursor and data-authority docs. | Closed as a planning decision; implementation starts M0/M3/M5. |
| P0-3 — Codex subscription requirement | Subscription support is binding. Current official support/terms/protocol/credential verification and a protected live Durable Chat canary are release gates; an API-key route is never a substitute. | MOD-001–005; S4; [ADR-0004](../adr/0004-codex-subscription-support.md) | Secret-safe source/refresh/redaction/cancel fixtures; retained official verification and protected live canary. | Closed as a policy; external support/credential availability remains RSK-002. |
| P0-4 — host-agent trust protocol | Enrolled mutually authenticated hosts act only on authenticated, fenced operation envelopes; control plane owns assignment, stale-result rejection, quarantine and reconciliation. | SBX-040–044; S9–S11; INV-SBX-010–011; [ADR-0005](../adr/0005-sandbox-control-host-protocol.md) | M3 protocol/refusal/restart/quarantine suite; Linux/KVM M4 validation and operator authority matrix. | Closed as a planning decision; implementation starts M3. |
| P0-5 — disagreeing architecture sources | Master requirements, root glossary, accepted system architecture and accepted ADRs are the exclusive source. Approval is v1, active input is durably queued, PostgreSQL is required, events are runtime/PostgreSQL-authoritative, and all code is in the monorepo. | MON-006–009; DOM-006; HITL-001–006; DAT-009–013; [ADR-0001](../adr/0001-source-of-truth-and-monorepo.md), [ADR-0006](../adr/0006-go-module-and-release-topology.md) | Architecture-authority/lint checks, ADR index and clean external-consumer test; explicit external-draft supersession in system architecture. | Closed as a planning decision. |
| P0-6 — status/notification | Retain milestone evidence first, then send a redacted typed payload to `https://ntfy.sh/0x63616c-ai-agant`; delivery failure is visible and retryable. | OPS-STAT-001–002; S12; INV-OPS-001–002; [ADR-0007](../adr/0007-milestone-status-and-ntfy-reporting.md) | Fake notifier schema/redaction/failure suite, allowlisted transport fixture, retained completion evidence and status/reporting runbook. Corrected-topic test event `GCXy4IYjJp96` proves topic reachability on 2026-08-06 only. | Closed as a planning decision; implementation starts M0. |

## P1 correction map and remaining non-blocking risk

| Review finding | Binding correction | Follow-through and risk |
| --- | --- | --- |
| P1-1 — Go topology | One root module, root package imports, one release tag and external-consumer proof. | MON-003, MON-009 and ADR-0006 resolve the choice. Implementation and release automation remain planned. |
| P1-2 — Tilt command/teardown | `tilt up -- --stack=<name>` is the one planned Stack identity. A later wrapper may not introduce `instance`; teardown requires state ownership, labels and object UIDs. | DEP-009 and ADR-0002 bind the correction. The older proposed Tilt design has a divergent `instance` draft and must be aligned before M1; tracked by RSK-018. No local command is currently represented as working. |
| P1-3 — documentation publication | Publication has a locked toolchain/site root/Pages URL+permissions/versioning/search/accessibility/rollback model and a protected drift-detecting docs skill. | DOC-008 binds it; implementation remains a docs-lane M0 deliverable. RSK-018 prevents current proposed-doc wording from being treated as accepted source. |
| P1-4 — direct-main AFK safety | Direct-main commits are vertical/evidence-linked, do not rewrite history, have pre-push and main-CI gates, halt red main and retain AFK evidence. | MON-010 binds it. Root `AGENTS.md`/CI implementation remains M0 work and must not use PR-only wording. |
| P1-5 — example production boundaries | Examples use least-privilege bootstrap, isolated demo tenants, authorized downloads, redacted evidence and named UI harnesses. | EX-007 binds it before M5. |

One root-guide correction has been reported to its owner: the generic runtime
cannot state that every Sandbox is session-scoped. Only Workspace Agent requires
a session-scoped workspace Sandbox; generic Sandbox lifetime is product/policy
defined. This is not a change to the domain glossary, which already uses that
canonical language.

## Status estimate method

The required `estimated_overall_percent` is a labelled estimate, not a release
claim. Its accountable input is a weighted evidence register: every ledger
requirement has an owning milestone and a positive weight; a status calculation
is `100 × green weight / total release weight`. A requirement without retained
green evidence contributes zero, and blocked/not-applicable status remains
visible alongside the percentage. Until the register and notifier exist, any
human estimate is explicitly provisional and cannot be used as
OPS-STAT-001 completion evidence.

Every notifier payload uses exactly these fields:

```json
{
  "milestone": "M0 — Contract and foundations",
  "estimated_overall_percent": 0,
  "evidence_summary": ["bounded evidence reference"],
  "next_milestone": "M1 — Isolated developer environment",
  "commit_or_revision": "immutable revision",
  "utc_time": "RFC3339 UTC time",
  "status": "completed"
}
```

The example is a schema illustration, not an emitted notification or status
claim. It must exclude credential-bearing URLs, credentials, tokens, secrets,
raw user/model/tool content and internal backend IDs.

## Validation performed

- The master requirements and acceptance ledger each contain **183** unique
  requirement IDs, with no identifier missing from either side and no duplicate
  ledger row.
- All accepted ADR links in the ADR index resolve within this repository.
- The accepted system architecture names the supplied external draft as
  superseded and states the corrected approval, input, data/event, subscription,
  infrastructure and monorepo decisions.
- This is governance-only evidence. It neither creates infrastructure nor
  claims that any planned command, notifier, renderer, database adapter or
  sandbox backend exists.
