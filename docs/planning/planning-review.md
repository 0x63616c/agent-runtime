# Planning review — implementation release gate

**Reviewer stance:** skeptical staff architect and release engineer
**Reviewed:** binding requirements, acceptance ledger, seams/invariants, reuse and
environment plans, the supplied architecture draft/glossary, and the binding
user decisions.
**Review date:** 2026-08-06

## Verdict

**No-ship for implementation today.** The component-level requirements are
strong, but six cross-cutting contracts are missing or contradictory. Starting
feature work would make the data store, event source of truth, Codex
authentication path, host-agent protocol, infrastructure topology, and release
reporting accidental architecture.

This is an M0 correction, not a scope cut. Once every P0 amendment is made
binding in the master requirements, acceptance ledger, seams, and ADRs,
implementation may start at M0/M1.

## P0 — block implementation until resolved

### P0-1 — all owned infrastructure must be declarative and explicit

The user requires declarative, reviewable infrastructure. The Tilt plan has
good namespace guardrails, but no binding contract prevents runtime binaries,
migrations, or helper scripts from inventing namespaces, Temporal settings,
buckets, RBAC, networking, ports, or schemas. There is no desired-state model,
ownership/lifecycle policy, drift rule, or complete proof.

Add a binding `INF` requirement family:

- **INF-001:** Every owned Kubernetes object, Temporal namespace/search
  attribute/schedule declaration, blob bucket/prefix, database schema and
  migration, service-account/RBAC binding, NetworkPolicy, Secret *reference*,
  ingress/service/port, persistence policy, resource request/limit, telemetry
  resource, and stack name is versioned declarative input in this repository.
  Runtime binaries and workflows do not create, mutate, or infer them.
- **INF-002:** A typed, versioned stack specification is the only input to
  deterministic local, CI, and production renderers. Tilt may parameterize and
  apply rendered state; it cannot create a second topology. Scripts must not
  synthesize unreviewed YAML, SQL, bucket policy, or Temporal configuration.
- **INF-003:** Every resource declares owner, scope, dependencies, retention,
  backup/restore owner, safe delete/tombstone behavior, and whether an
  external controller creates it. Runtime service accounts lack infrastructure
  mutation authority outside their explicit ownership.
- **INF-004:** Rendered/effective state and migrations are checked in or
  deterministically generated. Render/check/diff and policy tests reject
  implicit namespaces, unbounded resources, mutable image tags, undeclared
  storage defaults/ports, ambient credentials, and drift. Reconciliation is an
  audited operator command, never startup side effect.
- **INF-005:** CI renders every profile and proves schema, policy, ownership,
  migration upgrade/rollback, RBAC-negative behavior, NetworkPolicy admission,
  and two-stack isolation. Operator documentation publishes the ownership and
  lifecycle matrix plus reconcile/rollback commands.

The acceptance ledger needs a new row for each requirement. Two named stacks
must be proven separate across namespace, Temporal, database/schema, blob
prefix, queues, Secret references, ports, labels, and telemetry. An allocated
loopback port for a foreground port-forward is connection state, not desired
infrastructure; it must not create an undeclared service or ingress.

### P0-2 — authoritative data, PostgreSQL, and product events are undecided

`seams-and-invariants.md` names Postgres/blob/event-log implementations and
the Tilt plan deploys PostgreSQL, but the architecture says PostgreSQL is
needed only “if the chosen design requires it.” It never chooses the
transactional system of record or defines the commit boundaries between it,
Temporal, blob storage, and audit/event publication. Likewise, the architecture
calls Workflow Streams only “one candidate,” while the requirements mandate
runtime-owned cursor, gap, finalization, retention, and audit semantics.

For v1, **PostgreSQL must be required** as the authoritative metadata/control/
event store. Temporal remains the durable orchestrator; object storage holds
immutable large content. PostgreSQL owns runtime tenancy/identity, idempotency,
Session/Turn projections, conversation/artifact indexes, public product-event
sequence/cursors, audit/outbox records, and the sandbox desired/actual
operation ledger. This does not put unbounded content in PostgreSQL.

Add an M0 ADR and requirements which specify:

1. schemas, migrations, transaction/locking model, retention/partitioning,
   backup/restore drill, tenant erasure, and operator ownership; and whether
   Temporal persistence is separately deployed with separate credentials,
   database/schema, and retention;
2. the product-event state machine: producer intent -> durable ordered runtime
   event -> delivery/replay -> terminal or gap. A public cursor is an event
   store cursor, never a Workflow Stream offset;
3. atomic versus at-least-once/outbox behavior for input, model/tool output,
   artifacts, approvals, sandbox operations, audit, and Continue-As-New; and
4. production PostgreSQL adapter tests: migration, transaction conflict/retry,
   process-kill outbox recovery, cursor expiry/gap, backup/restore, and
   cross-tenant denial.

Workflow Streams may be an internal producer/transport adapter only. They
cannot be the event source of truth, public cursor, or retention contract.
Without this decision, M3 and M5 will construct incompatible durable ledgers.

### P0-3 — Codex subscription support conflicts with the current plan

The user answered **yes, 100%** to Codex subscription support. The baseline
says “one Codex adapter” and its example configuration names
`codex-subscription`. The reuse audit, correctly, says the direct
subscription backend was unsupported at audit time, recommends an official API
credential as the default supported route, and calls subscription experimental
and feature-gated. These cannot all be the promised first release.

Before M6, write one support-policy ADR and amend `MOD-001`–`MOD-003`:

- Re-verify current official OpenAI documentation, product terms, protocol,
  and credential lifecycle. The copied Factory/CLI facts are time-sensitive.
- If a subscription path is officially supportable, make it a first-class
  operator-configured credential source: appropriate interactive local login,
  model-role-only access, a redacted reference rather than copied credentials,
  explicit refresh/lock/revocation, offline fixtures, and a protected live
  canary. Durable Chat must actually use it.
- If it is not officially supportable, mark the explicit user requirement
  blocked. An API-key adapter may advance deterministic core work, but is not a
  substitute for subscription support.
- Specify exactly how a self-hosted operator provides the credential source and
  what never enters the repository, a Kubernetes Secret, Temporal payload,
  sandbox, event, log, artifact, example, or docs fixture.

Add acceptance for source validation, redaction, cancel, expired/rejected/
ambiguous refresh, a single refresh writer, provider normalization, protected
live subscription canary, and Durable Chat E2E. No live credentialed test runs
on an untrusted PR or fork.

### P0-4 — the sandbox control-plane/host-agent trust protocol is absent

The plans rightly require durable control, recovery, reaping, immutable
effective specs, and a core-wrapped backend SPI. They stop at “per-host
execution agents.” Binding principal context at the public client is not enough
to prevent stale, compromised, or cross-tenant host agents from acting under
the wrong lease.

Before M3, add a sandbox-control ADR and requirements for:

- host enrollment/identity, mutually authenticated control transport,
  credential rotation/revocation, protocol compatibility, and explicit
  attestation limits;
- authenticated operation envelopes with tenant/principal, immutable
  Effective-Spec digest, operation ID, capability snapshot, expiry,
  lease/fencing token, and protocol version;
- durable host assignment, renewal/fencing, duplicate/stale result rejection,
  output sequence integrity, loss/quarantine, reassignment, and reconciliation;
- clear authority between control plane, core, host agent, and Jailer for
  cgroups, network, image admission, mounts, output limits, and cleanup; and
- negative tests for replay/revocation, stale lease, wrong tenant, rogue host,
  lost acknowledgment, control/host restart, and quarantine cleanup.

M3 may use fake and explicitly unsafe local adapters, but it must implement
this protocol/refusal semantics. M4 proves it against the real Linux/KVM
Firecracker foundation. A `local-unsafe` result never proves this boundary.

### P0-5 — active architecture sources disagree, including monorepo scope

The master requirements say they are binding, but the supplied architecture
draft remains active-looking and materially disagrees:

- it proposes a codec module shared between Software Factory and this
  repository, contrary to the single-mono-repo requirement and the reuse plan;
- it places approval later, while `HITL-001`–`HITL-006` require it in v1;
- it permits active-turn Input rejection or queueing, while `DOM-006`
  requires durable queueing;
- it leaves Workflow Streams as a product-event candidate; and
- it makes PostgreSQL conditional.

Create an ADR index entry that makes the master requirements plus M0 ADRs the
only implementation source of truth. Move/copy the accepted architecture into
this repository with explicit status and label the external draft superseded.
Update `CONTEXT.md`: it currently omits Sandbox, Operation, Approval, policy,
capability profile, and cursor terms required by `MON-006`.

### P0-6 — milestone completion notifications and status estimates are absent

The user requires a notification to `https://ntfy.sh/0x63616c-ai-agant` at
the completion of every milestone, containing its name, estimated overall
percent complete, evidence summary, and next milestone. Regular understandable
status estimates are also required. A live test notification has succeeded
with corrected-topic event id `GCXy4IYjJp96`.

Add **OPS-STAT-001**: milestone completion is not recorded until the notifier
posts a secret-safe JSON/text payload to that topic containing:
`milestone`, `estimated_overall_percent`, `evidence_summary`,
`next_milestone`, immutable commit/revision, UTC time, and status. The
percentage is an explicitly labeled estimate derived from weighted ledger
evidence, never an assertion that blocked requirements passed. The message
must exclude credentials, tokens, URLs with credentials, raw user/model/tool
content, secrets, and internal backend IDs.

Add **OPS-STAT-002**: regular status reports use the same evidence model,
state completed/in-progress/blocked work, uncertainty, current estimate, and
next observable checkpoint. A network failure must be retained as a visible
release-operation failure/retry record; it cannot silently claim that the
notification was sent.

The ledger must prove a fake notifier schema/redaction/failed-delivery suite,
an integration send to an allowlisted test topic or recorded transport fixture,
and the real milestone-completion message retained as release evidence. The
notifier endpoint/topic/configuration is typed operator configuration and
declaratively referenced; no runtime workflow sends user-controlled URLs.

## Milestone corrections

| Milestone | Required correction |
| --- | --- |
| M0 contract/governance | Close P0 ADRs: declarative infrastructure/ownership; PostgreSQL/event/outbox; subscription support; sandbox host protocol; Go module/release strategy. Establish Docusaurus skeleton, docs skill, docs checks, renderer/policy checks, evidence schema, notification/status mechanism. Docs build from M0, not only M10. |
| M1 Tilt + hello runtime | Apply only M0-rendered desired state. Prove two-stack isolation, including distinct runtime and Temporal database/schema, blobs, queues, Secret refs, labels, ports, and telemetry. No bootstrap binary creates missing infrastructure. |
| M2 codec/blob | Declare MinIO/S3-compatible resources and codec-UI policy. Prove local worker/UI codec parity; the remote codec service is never a runtime decode dependency. |
| M3 durable sandbox control | Use the PostgreSQL control ledger and host fencing protocol. It cannot be a process-local fake with persistence added later. |
| M4 Firecracker foundation | Validate protected KVM lane before security claims. Prove M3 protocol, Jailer/cgroup cleanup, deny-all, and capability/refusal semantics, not merely boot. |
| M5 scripted durable sessions | Deliver the minimum product-event cursor/outbox and approval state machine needed by the public SDK. M8 may extend scale/retention but cannot be the first reconnect correctness. |
| M6 Codex + Durable Chat | Meet the subscription support policy with protected canary and documented user path. A scripted demo is not proof of subscription support. |
| M7 tools/approval/workspace | Deliver portable copy-in/out and capability negotiation before file APIs. Prove approve/deny/expiry/cancel/reconnect/cleanup. Other authority profiles remain unavailable until individually green. |
| M8 Research Dossier | Use the existing event/artifact authority for large-result offload, final gaps, resumption, citation/artifact retention, and download authorization. |
| M9 operations/security | Split “hardening” into individually gated host-mount, volume, snapshot, egress, and command-secret profiles. A blocked profile blocks its own claim and the all-profiles final gate. |
| M10 public docs/release | Promote continuously-built versioned docs/Pages, final completion report, KVM evidence, SBOM/provenance, and public release artifacts. Send and retain the M10 notification. |

## P1 — resolve in M0/M1 before the affected surface

### P1-1 — Go module/release topology is not executable

The plans alternate between independent `go.work` submodules and one release
train. A workspace helps contributors but does not publish submodules; external
Go consumers need real module paths and module-specific tags. Choose one root
module with public packages, or define real multi-module tags, versions,
compatibility policy, release automation, and a clean external-consumer test.
Specify SDK import path, Go version floor, deprecation policy, generated API
ownership, and docs-version mapping.

### P1-2 — Tilt command and teardown contract is inconsistent

The master requirement advertises `tilt up -- --stack=<name>`; the detailed
design advertises `just dev` and `--instance=<id>`. Pick one public
contract. State-file locking/ownership must prevent stale or copied state from
deleting another stack; `dev-down` needs rendered-label and object-UID
checks plus refusal when ownership is not proven.

### P1-3 — docs publication needs an operational design

Docusaurus/Pages needs a reproducible Node/package-manager lock, a site root
that does not collide with `docs/planning`, base URL/domain, versioning,
search implementation and privacy/cost model, accessibility gates,
permissions, and rollback. Pages alone does not provide a search backend.
Make the docs skill's path/invocation agree between its implementation plan and
`AGENTS.md`; fixture tests must prove it detects route/config/example/reference
drift without rewriting curated security/operator content.

### P1-4 — direct-main AFK safety is only a statement, not a policy

The user declined PRs, yet the matrix says “every PR”; CI after a direct main
push observes breakage after the fact. The proposed `AGENTS.md` also omits the
direct-main policy demanded by `MON-005`. Require atomic vertical commits
that name requirements/seams/docs/evidence, no force push/history rewrite,
pre-push slice checks, main-push CI, a red-main halt/escalation rule, and a
machine-readable AFK evidence log. Replace PR-only wording with “every main
change and optional review branch.”

### P1-5 — example production boundaries remain implicit

Before M5, specify auth bootstrap, demo tenant ownership/cleanup, artifact
download authorization, evidence redaction, browser/TUI harness ownership, and
shared cursor-client behavior. An example profile must not hold broad admin
credentials merely to simplify a tutorial.

## P2 — clarity improvements

- The architecture draft's `AgentEvent` block declares `Cursor` twice; make
  the public schema compile before reference generation.
- Record local ARM64 versus Linux x86_64 KVM guest/image compatibility in the
  release matrix.
- Give `TST-010` a reviewer independence rule, retention location, and
  explicit scope-change record.
- Classify every docs security statement as local unsafe, fake, Linux/KVM
  verified, operator assertion, or planned.

## Required evidence before verdict changes

1. M0 ADRs plus requirement/ledger/seam updates close P0-1 through P0-6.
2. A dependency-ordered M0–M10 map names ledger IDs, runnable evidence, docs,
   notification/status evidence, and blocked-asset behavior per milestone.
3. `AGENTS.md`, docs skill, module map, direct-main policy, and developer
   commands agree and do not advertise nonexistent commands.
4. A planning consistency check finds no active conflict for approval, input
   admission, event/data authority, subscription support, infrastructure
   ownership, or monorepo boundary.

Then begin M0/M1. Final release remains blocked until all ledger entries, the
public docs deployment, all required milestone notifications, and Linux/KVM
proof are green.
