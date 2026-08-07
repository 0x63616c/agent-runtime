# AGENTS.md — Agent Runtime

This file governs every active directory in this public MIT-licensed monorepo.
Read it before changing code, tests, examples, generated output, deployment,
skills, documentation, or GitHub tracking. It is the always-loaded operating
contract required by MON-004 and MON-005.

## What this is

Agent Runtime is a durable platform for session-based agents. It owns Agent
revisions, Sessions, Turns, streamed Events, cancellation, human Approvals,
Artifacts, tools, provider boundaries, Temporal orchestration, and optional
Sandboxes whose lifetime is product- and policy-defined. Workspace Agent's
workspace Sandbox is session-scoped. The repository also ships the reusable size-aware
`temporalpayload`/blob codec pipeline and three public-contract applications:
Durable Chat, Workspace Agent, and Research Dossier.

This is one repository, one root Go module, and one release train. Public Go
packages have stable root-module import paths; a contributor-only `go.work`
may not define a public module or release boundary. No capability is split into
a separate repository. Examples consume only the public HTTP contract and Go
SDK; they are executable compatibility tests, not internal implementation
clients.

## Authoritative sources and planning status

M0 is complete. M1 infrastructure, M2 payload, and M3 sandbox work may proceed
along their declared dependency edges. Planning is not proof that a feature
exists; the requirements ledger and retained evidence remain authoritative.
Never document planned behavior as implemented.

| Source | Authority |
| --- | --- |
| `docs/planning/requirements/master-requirements.md` | Binding scope and permanent requirement IDs. |
| `docs/planning/requirements/acceptance-ledger.md` | Required test/evidence and documentation for each requirement. |
| `docs/planning/requirements/seams-and-invariants.md` | Approved module seams, invariants, and test-first behavior matrices. |
| `docs/planning/requirements/open-risks.md` | Active blockers and honest-claim policy. |
| `docs/planning/planning-review.md` | M0 implementation gate and unresolved cross-cutting corrections. |
| `docs/planning/environment/`, `docs/planning/docs-stack.md`, and `docs/planning/reuse/` | Proposed designs, reuse provenance, and implementation constraints. |
| `CONTEXT.md` and `docs/adr/` | Canonical ubiquitous language and hard-to-reverse decisions once created. |
| `docs/agents/*.md` | Issue-tracker, triage-label, and domain-documentation conventions. |
| `skills/refresh-agent-runtime-docs/SKILL.md` | Documentation refresh procedure once it exists. |

The master requirements and accepted ADRs win if sources conflict. Never
silently down-scope an uncompleted requirement. A missing
decision is not permission to make it accidental architecture: record or seek
an ADR before an irreversible choice. Update the binding requirement and
acceptance ledger with explicit authority first.

## Engineering provenance and priority order

These standards adapt the active `software-factory` `AGENTS.md` and
`docs/SoftwareStyle.md` (inspected at commit
`4a427d0080ba6cc73609af13242251d3f45d6c70`) to Agent Runtime. Factory-only
Ticket, GitHub-merge, Run Worker, and Kubernetes product rules do not apply.
The reuse rationale is recorded in `docs/planning/reuse/reuse-audit.md` and
`docs/planning/reuse/proposed-agents-md.md`.

Resolve trade-offs in this order:

> **Legibility > Correctness > Operability > Economy**

Testability is a floor beneath all four and is never traded. This service is
model- and network-bound; micro-performance is not an architectural priority.

- **Legibility:** Prefer deep modules with narrow doors, explicit names,
  typed invariants, manual composition, and no hidden global state.
- **Correctness:** Parse external input at its boundary into valid owned types;
  make invalid states unrepresentable; fail early and helpfully.
- **Operability:** Durable work must be observable, cancellable, resumable,
  and auditable. Record decisions and bounded references, not secrets or
  unbounded content.
- **Economy:** Spend model tokens and human time only for a demonstrated
  correctness or operability gain.

## Non-negotiable architecture boundaries

```text
public Go SDK / public HTTP contract / examples
                    │
                    ▼
              runtime application ──► deterministic kernel
                    │                         ▲
                    ▼                         │
Temporal, models, tools, sandboxes, blobs, databases ─┘
```

- The kernel owns domain transitions and imports no Temporal SDK, HTTP
  framework, provider SDK, blob implementation, sandbox backend, database
  driver, or telemetry exporter.
- Temporal is a private adapter. A Session maps to a workflow chain; input,
  model, tool, and sandbox effects are durable operations. No Temporal type,
  identifier, task queue, or storage URL crosses a public API, SDK, example, or
  test seam.
- Workflow code is replay-sensitive: use only `workflow.Context`,
  `workflow.Now`, `workflow.Sleep`, `workflow.Go`, deterministic data, and
  activities. Never use real time, I/O, environment, unmanaged goroutines,
  random values, or provider clients inside a workflow. A command-sequence
  change requires `workflow.GetVersion` at the changed branch and retained
  history replay evidence.
- Provider, sandbox, blob, database, and protocol SDK types remain inside
  narrow adapter packages. Interfaces are consumer-side and small: accept
  interfaces and return concrete types. Do not create `util`, `common`,
  `helpers`, `misc`, or `shared` packages.
- A model Tool call is intent, not authorization. The Tool broker persists and
  evaluates policy/grants, optionally awaits Approval, then records execution
  separately. Workspace Agent uses a session-scoped workspace Sandbox; the
  generic runtime does not impose a Sandbox lifetime. Credentials and
  capabilities are command-scoped and least-privilege.

## Declarative, explicit infrastructure

All infrastructure is version-controlled desired state. Every Kubernetes
object, Temporal namespace/search attribute/schedule, database migration,
blob bucket/prefix, Secret reference, RBAC binding, NetworkPolicy, service,
port, persistence policy, resource limit, telemetry resource, and stack name
must be declared, owned, scoped, and lifecycle-documented.

- A typed, versioned stack specification is the only input to deterministic
  local, CI, and production renderers. Tilt parameterizes/applies rendered
  state; it does not invent a different topology.
- Runtime binaries, workflows, and startup helpers do not create, mutate, or
  infer infrastructure. Reconciliation is an audited operator action, never a
  startup side effect.
- Rendered/effective state and migrations are checked in or deterministically
  generated. Reject ambient credentials, implicit namespaces, mutable image
  tags, undeclared ports/storage, unbounded resources, and drift.
- Every resource declares owner, dependencies, retention, backup/restore
  owner, safe deletion/tombstone behavior, and whether an external controller
  creates it. Runtime service accounts have no undeclared infrastructure
  mutation authority.
- Local macOS sandbox adapters are explicitly unsafe and never evidence of
  Firecracker or hostile-tenant isolation. Linux/KVM evidence is required for
  Firecracker claims.

## Go construction, identity, time, and errors

- Use Go, `log/slog`, `github.com/cockroachdb/errors`, Ginkgo/Gomega,
  Stripe-style opaque typed IDs, fake clocks, and the established Factory
  techniques unless an ADR documents an exception. Preserve `errors.Is` and
  `errors.As` behavior when wrapping/classifying errors.
- Required dependencies are constructor parameters. Optional configuration is
  validated once through small sealed functional options. No usable but invalid
  zero values.
- Each externally visible runtime object has one typed opaque ID service.
  Prefix, parse/validation, JSON/database representation, redaction, and
  authorization semantics have contract tests. Technical Temporal IDs and
  blob digests are not replacements for runtime IDs.
- UTC only; wire times are RFC3339 UTC. Raw numeric names carry units
  (`sizeBytes`, `limitSeconds`); `time.Duration` values do not. Wall-clock time,
  local time, entropy, and environment reads live only behind injected
  composition-root interfaces.
- `context.Context` is first, propagated, never struct-stored, and always
  honored. Activities/clients use standard context; workflows use
  `workflow.Context`. Do not use unmanaged goroutines.
- Wrap failures at meaningful boundaries with an action and safe identity;
  never return a bare error. Map retryable/non-retryable behavior to Temporal's
  taxonomy at the Temporal adapter boundary rather than inventing competing
  leaf retry policy. Invariant violations are assertion failures, not normal
  control flow.
- Process execution is argv-only, context-bounded, output/exit-capturing, and
  fakeable. Never use shell interpolation for attacker-controlled text.

## Safety, logging, and public data

- Build JSON `slog` loggers at composition roots and inject them. Log durable
  state transitions and policy decisions using safe correlation fields; bound
  metric label cardinality.
- Secrets, tokens, authorization headers, raw user prompts, model reasoning,
  internal backend IDs, and unbounded tool output never enter logs, Temporal
  history, public events, artifacts, fixtures, generated docs, or examples.
- Public streams are cursor-addressable append-only runtime records. Connection
  loss affects observation only, not durable work. Reconnect, cursor expiry,
  duplicate delivery, terminal finalization, and producer gaps are explicit
  contracts with tests.
- Public SDK and HTTP changes require a compatibility decision, OpenAPI/SDK
  reference regeneration, docs update, runnable example coverage, and release
  notes as applicable.

## Test-driven evidence

Write acceptance criteria and behavior tests before implementation. Begin each
vertical slice by naming its approved seam and a small matrix: happy path, most
dangerous negative path, retry/cancel/lifecycle path, and a literal expected
outcome where useful. Demonstrate red, implement only that slice, then refactor
without widening scope.

1. Unit tests are hermetic. No real network, subprocess, filesystem, wall
   clock, randomness, provider, sandbox, or database; inject fakes at real
   seams.
2. Workflow tests use Temporal's test environment, mocked activities, virtual
   time, and retained-history replay tests for compatibility changes.
3. Adapter contract tests run every implementation through the same black-box
   suite. Production integrations use named dependencies and fail visibly when
   unavailable; they do not silently skip as a pass.
4. E2E tests exercise the public API/SDK, event reconnection, artifacts,
   sandbox lifecycle, Approval, cancellation, and restart/recovery. Record
   machine-readable evidence and its proof level: unit, workflow, integration,
   local Tilt E2E, or Linux/KVM E2E.
5. Never sleep to make a test pass. Advance fake/virtual time and wait only on
   explicit bounded conditions. Run race detection in the complete Go gate.

Every exported package/symbol has a doc comment beginning with its name and
ending in a period. Comments explain why, not what; test names are present-tense
behavior sentences. Generated output is never hand-edited.

## Commands and documentation

`just check` is the implemented incremental repository gate; `just verify` is
the implemented milestone/release completion gate and must remain red until
every canonical ledger row has valid completed evidence. `just docs`, `just
docs-generate`, and `just docs-check` are implemented for the M0 public-docs
foundation. Do **not** claim that `tilt`, integration, E2E, or release commands
work until their implementation and tests land.

The intended command vocabulary is `just check`, `tilt up`, `just test`, `just
integration`, `just e2e`, `just verify`, `just docs`, and `just docs-check`.
Only implemented commands are instructions; the remainder are planning
vocabulary. When a
public capability, route, configuration field, example, security claim, or
operator path changes, use `skills/refresh-agent-runtime-docs/SKILL.md`; its
allow-listed runner must remain green and must not invent unimplemented
behavior.

## Direct-main AFK policy

This user-authorized build commits directly to `main`; it does not open PRs.
Direct main is not an exemption from review, tests, or evidence.

1. Work from a tracked GitHub Issue (or explicitly recorded program task) with
   requirement IDs, approved seams, acceptance evidence, and documentation
   impact. Claim the issue before the first external write.
2. Make atomic vertical commits. Each commit contains one coherent behavior
   slice plus its tests, docs/ledger impact, generated output when applicable,
   and evidence references. Do not mix unrelated cleanup or another agent's
   work.
3. Before each incremental push, run every applicable focused check plus
   `just check`, and record exact command, revision, scope, time, exit status,
   and retained redacted evidence. `just verify` is the milestone/release
   completion gate and must fail until every canonical ledger row has valid
   completed evidence.
4. Never force-push, rewrite published history, bypass hooks/checks, or erase
   evidence. Use additive corrective commits. Preserve unrelated dirty work.
5. A red `main`, failed required check, failed evidence upload, or missing
   required notification halts unrelated direct-main delivery. Diagnose and
   repair or explicitly record the blocker before continuing. Do not hide it
   with a skipped test, weakened assertion, or claimed success.
6. Completion evidence belongs with the requirement's ledger/evidence record
   and GitHub Issue. Until the machine-readable evidence log exists, include
   the immutable commit, proof level, command/result, limitations, and next
   checkpoint in the issue comment and commit body.
7. On each completed milestone, send the required redacted status notification
   to `https://ntfy.sh/0x63616c-ai-agant` only after its implementation, tests,
   documentation, and evidence gates pass. Include milestone, estimated overall
   percentage (explicitly an estimate), evidence summary, next milestone,
   immutable revision, UTC time, and delivery result. Retain failure/retry
   evidence; never claim a notification was sent without it.
8. Regular status updates use the same evidence model: completed, in-progress,
   and blocked work; estimate and uncertainty; last retained proof; and next
   observable checkpoint. They are understandable progress reports, not a
   substitute for green acceptance evidence.

## Agent skills

### Issue tracker

GitHub Issues are the tracker for implementation work and planning tasks. See
`docs/agents/issue-tracker.md`.

### Triage labels

The default AFK triage vocabulary is defined in
`docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository. Read `CONTEXT.md` and relevant ADRs when
they exist; see `docs/agents/domain.md`.
