# Agent Runtime — master requirements

Status: binding implementation baseline for the AFK build

Architecture authority: this ledger and the accepted ADRs in `docs/adr/` are
the sole implementation source of truth. The discussion draft named in
`docs/architecture/system.md` is superseded and is retained only as historical
input.

Decision date: 2026-08-06

Repository: `github.com/0x63616c/agent-runtime` (public, MIT)
Scope: one versioned public monorepo and one root Go module. Sandbox, Temporal
payload codec/blob package, runtime, public Go SDK, deployment, examples,
documentation site, and their tests ship together.

## How to use this document

This is the source of truth for the build. A requirement is complete only when
the associated evidence in [the acceptance ledger](acceptance-ledger.md) is
green, its public/operator documentation is current, and its invariants are
preserved. Requirement identifiers are permanent: a replacement requirement
must supersede the old identifier rather than reuse it.

The first sandbox draft is **not** an approved implementation contract. The
P0 review findings are incorporated below as mandatory design corrections:
durable control rather than process-local handles; operation identity for all
mutations; tenant-scoped durable ledgers; fail-closed grants; immutable
normalized inputs; a core-wrapped backend SPI; a precise mediated egress data
plane; durable output; and independently gated security profiles. The project
does not make a production security claim until those requirements are proven.

## Delivery decisions already made

- The project is a single public monorepo with one root Go module. Public
  packages have stable import paths below `github.com/0x63616c/agent-runtime`;
  a contributor-only `go.work` may exist but cannot define a public module or
  release boundary.
- The primary developer experience is an isolated local Kubernetes stack via
  Tilt. Docker Compose is not a supported primary path.
- macOS/local development uses an explicitly unsafe local sandbox adapter.
  The Firecracker production adapter is proved on a Linux host with KVM in a
  dedicated integration lane. A local adapter is never evidence of
  adversarial isolation.
- Human approval is a first-release runtime capability, not later work.
- The public documentation site uses Astro Starlight, pinned to a current
  compatible release at implementation time, and is deployed through GitHub Pages.
- Development lands as intentional commits directly on `main`; the user has
  explicitly declined PRs for this effort.

## Requirements

### Monorepo, governance, and engineering standards

- **MON-001** — Create the public MIT-licensed `0x63616c/agent-runtime`
  repository and push the complete build to `main` without opening PRs.
- **MON-002** — Keep the sandbox, reusable Temporal payload codec/blob module,
  runtime service, Go SDK, examples, deploy assets, docs site, and test suites
  in this repository and on the same release train.
- **MON-003** — Keep all public Go packages in the root
  `github.com/0x63616c/agent-runtime` module. A `go.work` is optional local
  contributor convenience only; it cannot add a second public module, change
  import paths, or be required by an external consumer.
- **MON-004** — Copy the applicable Software Factory engineering style guide
  into the root `AGENTS.md`, preserve its intent and provenance, and make it
  mandatory reading for every contributor/agent.
- **MON-005** — `AGENTS.md` shall additionally name this ledger, the glossary,
  architecture records, the documentation skill, required checks, direct-main
  policy, and the rule that uncompleted requirements may not be silently
  down-scoped.
- **MON-006** — Maintain `CONTEXT.md` as the implementation-free ubiquitous
  language for Agent specification, Session, Turn, Input, Model invocation,
  Tool call, Tool execution, Policy, Capability grant, Capability profile,
  Sandbox, Operation, Approval, Artifact, Product event, Cursor, and Audit
  record; update it when a term crystallizes.
- **MON-007** — Record hard-to-reverse, surprising trade-offs as numbered ADRs
  with alternatives and consequences, including durable sandbox control,
  payload compatibility, approval persistence, and docs deployment.
- **MON-008** — Treat this master requirement ledger, `CONTEXT.md`,
  `docs/architecture/system.md`, and accepted ADRs as the only binding
  implementation contract. Planning drafts and copied/external architecture
  documents are explicitly marked superseded; a conflict is resolved here and
  in an ADR before implementation proceeds.
- **MON-009** — Release one root Go module from this repository. The public
  SDK import path is `github.com/0x63616c/agent-runtime/sdk/go`; reusable
  public packages use root-module paths. Releases use one semver tag
  (`vX.Y.Z`), one documented Go-version floor, one compatibility/deprecation
  policy, one generated API ownership policy, and one docs-version mapping.
  A clean external-consumer test imports the released SDK and reusable payload
  package without `go.work`.
- **MON-010** — Direct-to-`main` delivery uses atomic vertical commits naming
  requirement IDs, seams, documentation and evidence; forbids force pushes and
  history rewrites; runs the applicable pre-push slice gates and main-push CI;
  halts/escalates on red main; and retains a machine-readable AFK evidence log.
  “Every PR” requirements mean every main change and any optional review
  branch.
- **ENG-001** — Use Go, standard `log/slog` structured logging, typed
  CockroachDB errors (with `errors.Is`/`errors.As` behavior), Ginkgo/Gomega,
  Stripe-style opaque IDs, and the established Software Factory patterns
  unless a documented ADR justifies an exception.
- **ENG-002** — Every runtime-owned identifier shall have a typed Stripe-style
  prefix, be globally opaque, safe to log, non-parseable by callers, and be
  scoped by authorization rather than treated as a capability.
- **ENG-003** — Inject clocks, random/ID sources where required for
  determinism, and retry/backoff policies. Production code must not use wall
  clock sleeps or unbounded polling as a synchronization mechanism.
- **ENG-004** — Provide deterministic fake clocks and controllable test
  schedulers. Tests must advance logical time rather than wait five real
  seconds for a timeout, lease, retry, approval expiry, or cleanup.
- **ENG-005** — Follow vertical-slice TDD. Before implementing a capability,
  write and agree its seam and a small behavior matrix (normally 3–5 cases),
  demonstrate the intended red behavior, then implement only that slice to
  green. Do not bulk-write horizontal speculative tests for the whole system.
- **ENG-006** — Every public type, request field, enum, and error must have
  documented zero-value, validation, serialization, concurrency, and failure
  semantics before it is considered stable.
- **ENG-007** — All configuration is typed, validated at startup, redacted in
  diagnostics, and has one owner. Environment/config values may not be read
  directly from workflows or domain code.
- **ENG-008** — Keep a small command vocabulary once implemented: `just check`,
  `tilt up`, `just test`, `just integration`, `just e2e`, `just verify`, `just
  docs`, and `just docs-check`. A command is documented as runnable only after its
  checked-in implementation and clean-checkout test exist; planning documents
  label future commands as planned rather than advertising them as working.
- **ENG-009** — Treat generated code and generated OpenAPI/reference material
  as checked, reproducible outputs. CI shall fail on regeneration drift.
- **ENG-010** — No workflow, public SDK, example, or test may depend on
  Temporal identifiers, task queues, implementation-private storage URLs, or
  internal Go packages.

### Declarative and explicit infrastructure

- **INF-001** — Every owned Kubernetes object, Temporal namespace, search
  attribute and schedule declaration, blob bucket/prefix, database schema and
  migration, service-account/RBAC binding, NetworkPolicy, Secret reference,
  ingress/service/port, persistence policy, resource request/limit, telemetry
  resource, and stack name is versioned declarative input in this repository.
  Runtime binaries, workflows and ad-hoc helper scripts do not create, mutate,
  infer, or bootstrap this infrastructure; a declared migration job applies
  only its reviewed versioned schema change.
- **INF-002** — A typed, versioned Stack specification is the sole input to
  deterministic local, CI and production renderers. Tilt may parameterize and
  apply rendered desired state but cannot create a second topology. Scripts do
  not synthesize unreviewed YAML, SQL, bucket policy or Temporal configuration.
- **INF-003** — Each owned resource declares owner, scope, dependencies,
  retention, backup/restore owner, safe delete/tombstone behavior, and whether
  an external controller creates it. Runtime service accounts have no
  infrastructure mutation authority outside their explicitly declared
  ownership.
- **INF-004** — Rendered/effective state and migrations are checked in or
  deterministically generated. Render/check/diff and policy tests reject
  implicit namespaces, unbounded resources, mutable image tags, undeclared
  storage defaults or ports, ambient credentials, and drift. Reconciliation is
  an audited operator command, never a process-startup side effect.
- **INF-005** — CI renders every profile and proves schema, policy, ownership,
  migration upgrade/rollback, RBAC-negative behavior, NetworkPolicy admission
  and two-stack isolation. Operator documentation publishes an ownership and
  lifecycle matrix plus reconcile and rollback procedures. An OS-assigned
  foreground port-forward is connection state, not desired infrastructure, and
  cannot create an undeclared service or ingress.

### Runtime domain and public application interface

- **DOM-001** — An Agent specification is immutable and versioned; changing it
  creates a new Agent revision.
- **DOM-002** — A Session is pinned to one Agent revision for its lifetime.
  Migration to another revision is not implicit and is out of scope for v1.
- **DOM-003** — A Session has explicit durable states (`open`, `closing`,
  `completed`, `cancelled`, `failed`) and state-transition legality.
- **DOM-004** — An Input has a caller idempotency key and non-text content is
  represented by bounded content parts and Artifact references, not by large
  orchestration payloads.
- **DOM-005** — A Turn is the one durable progression from accepted Input to
  exactly one terminal outcome: succeeded, failed, or cancelled.
- **DOM-006** — v1 serializes turns: at most one Turn mutates a Session at a
  time. Input admitted while a Turn is active is explicitly queued in durable
  order; it is neither rejected silently nor allowed to race.
- **DOM-007** — A Model invocation is an observable attempt inside a Turn;
  retrying a model invocation creates a new invocation attempt, never a new
  Turn or duplicate Input.
- **DOM-008** — A Tool call is model intent. A Tool execution is a separately
  recorded runtime attempt made only after authorization; the two are never
  conflated.
- **DOM-009** — A Capability grant is a bounded authorization with an owner,
  scope, expiry, maximum use count, policy revision, and audit identity. Raw
  secret bytes never occur in the domain model.
- **DOM-010** — Conversation semantic context is durable external state with
  optimistic versioning; orchestration state holds only a stable reference and
  version.
- **DOM-011** — Artifact references contain a stable ID, media type, size, and
  integrity digest—not a bucket URL—and support authorization-aware readback.
- **DOM-012** — A public Failure is a stable runtime-owned code, safe message,
  retryability indication, and bounded safe details. Backend/provider errors
  must be translated at their seams.
- **DOM-013** — Model usage is provider-neutral and preserves unknown values as
  unknown; provider-specific fields remain private diagnostics.
- **API-001** — Expose a versioned HTTP contract and a small public Go SDK for
  creating Sessions, sending Input, inspecting Session/Turn, resuming Events,
  cancelling Turns, closing Sessions, reading approved Artifacts, and
  responding to Approval requests.
- **API-002** — The public Go SDK contains public request/response models,
  authentication transport, HTTP/event clients, and runtime-owned errors only;
  it imports no Temporal, model-provider, sandbox-backend, blob, or telemetry
  implementation package.
- **API-003** — HTTP and Go SDK behavior are contract-tested against the same
  checked-in OpenAPI description; generated reference material is published.
- **API-004** — All externally supplied mutation requests use idempotency keys
  with tenant-scoped canonical request equality, conflict behavior, durable
  retention, and safe status lookup.
- **API-005** — The API authenticates callers, authorizes every tenant/session/
  turn/artifact/approval access, and returns non-enumerating not-found/denied
  behavior as appropriate.
- **API-006** — Request, response, event and error payloads have explicit
  bounded sizes, pagination/cursor behavior where applicable, and redaction
  rules.
- **API-007** — Public event cursors are runtime-owned opaque values with a
  documented retention, replay, expiry, duplicate, ordering, and gap contract.
- **API-008** — Client transport loss never cancels durable work. Cancellation
  is an explicit authenticated command and reports cleanup progress.
- **API-009** — Provide a runtime-owned Session inspection view containing the
  Session, active Turn if any, recent safe events, and public references; it
  must not expose backend execution IDs.
- **API-010** — Agent model profile selection is constrained to
  operator-configured logical profiles; public Agent specifications do not
  contain provider credential or SDK types.
- **API-011** — Agent specifications, policies, tool definitions, public event
  vocabulary, failure codes, and HTTP routes have compatibility/versioning
  rules and migration guidance.
- **API-012** — The runtime has an explicit authorization/admin surface for
  agent registration/revision management and policy management; it is separate
  from ordinary end-user session commands.

### Durable orchestration and Temporal payloads

- **TMP-001** — Temporal is an internal implementation seam for application
  callers and an explicit operator dependency with documented endpoint,
  namespace, authentication, retention, worker deployment, and capacity
  responsibilities.
- **TMP-002** — Map Session to a long-lived workflow execution chain, Input to
  a durable update/signal plus idempotency record, model/tool work to
  activities, cancellation to durable workflow control, and history rollover
  to Continue-As-New without leaking these choices to callers.
- **TMP-003** — Workflow state is deterministic, versioned, small, and contains
  only domain IDs, operation IDs, effective-policy/version references, and
  bounded state. It contains no handles, streams, interfaces, raw output,
  secrets, or backend configuration.
- **TMP-004** — Workflow changes have replay tests and documented versioning;
  history rollover preserves public session/event semantics.
- **TMP-005** — One runtime-owned Temporal client/worker factory installs the
  same DataConverter everywhere. Constructing a raw unconfigured Temporal
  client/worker in owned code is prohibited and mechanically checked.
- **TMP-006** — Startup performs an encode/decode compatibility round trip for
  the configured codec chain and fails safely before accepting work when it
  cannot decode compatible persisted payloads.
- **TMP-007** — Split runtime roles into API, orchestration worker, model
  worker, tool worker, blob service, codec service, and sandbox control/host
  agent as separately deployable processes while retaining one versioned
  `runtime serve --role=…` binary for runtime-owned roles.
- **TMP-008** — Orchestration workers hold Temporal/state access but no model
  or tool secrets; model workers hold only model/conversation access; tool
  workers hold narrow tool/sandbox access. `--role=all` does not relax these
  trust rules.
- **TMP-009** — Activity retry policy distinguishes cancellation, deterministic
  policy error, backend unavailability, uncertain external effect, and
  incompatible persisted policy. It never blindly repeats an unknown external
  side effect.
- **TMP-010** — Temporal test-environment tests prove replay-safe session,
  input, cancellation, approval, sandbox-operation, event finalization, and
  Continue-As-New orchestration.
- **PAY-001** — The reusable `temporalpayload` public package lives in this
  monorepo at a root-module import path, is independently importable by an
  external consumer without a Go workspace, and is versioned and released with
  the runtime rather than copied between products.
- **PAY-002** — The payload chain serializes normally, tries zstd compression
  only when it reduces bytes, then remote-offloads only when its compact
  reference reduces bytes; the stored offloaded payload may itself be
  compressed.
- **PAY-003** — The module owns content-addressed blob keys, `BlobStore`,
  size-aware transformation, zstd, remote offload, chain/version metadata,
  local DataConverter, remote Temporal-UI codec HTTP handler, metrics, and
  black-box conformance tests.
- **PAY-004** — The HTTP codec service is only an authorized Temporal UI
  inspection adapter; runtime workers encode/decode locally through the same
  chain and never call it on their normal path.
- **PAY-005** — The codec’s outer/inner encoding format, reference integrity,
  missing/corrupt blob errors, compatibility window, and safe garbage
  collection are specified and tested.
- **PAY-006** — Payload selection is transparent to workflow/application code;
  callers never implement payload-size branches.
- **PAY-007** — Codec encryption is not claimed or implied until a separately
  designed and proven cryptographic layer, key lifecycle, rotation, and UI
  compatibility contract exists.
- **PAY-008** — A codec conformance consumer verifies that the runtime and a
  second in-repo consumer can exchange inline, compressed, and remote payloads
  and inspect each through the codec service.

### Model, tools, capabilities, and human approval

- **MOD-001** — Codex subscription support is a binding first-release user
  requirement. Provide it behind a small internal Model seam, only after a
  current official OpenAI documentation, product-terms, protocol and credential
  lifecycle verification says the path is supportable. An API-key adapter may
  advance deterministic core work but is not a substitute for this requirement;
  if the path is not supportable, release remains visibly blocked rather than
  silently substituted.
- **MOD-002** — Model invocation streaming is normalized into stable runtime
  events and persisted/output-finalized so reconnecting callers do not depend
  on a live provider connection.
- **MOD-003** — Model credentials are loaded only by the model role through
  a redacted, operator-configured credential source, never stored in Agent
  specs, workflow state, product events, logs, artifacts, Kubernetes Secret
  values, sandboxes, or example fixtures.
- **MOD-004** — A supported subscription source defines local interactive
  login where appropriate, model-role-only access, a redacted credential
  reference rather than copied credentials, explicit refresh/lock/revocation,
  a single refresh writer, cancellation, and offline fixtures. Expired,
  rejected and ambiguous refresh outcomes have stable safe behavior.
- **MOD-005** — Durable Chat uses the supported subscription path in a
  protected live canary and E2E gate. Provider normalization, source
  validation, redaction and credential lifecycle are tested; credentialed tests
  never run on an untrusted PR or fork and retain only secret-safe evidence.
- **TOL-001** — Provide a Tool broker as the sole implementation seam between
  a model Tool call and Tool execution. It owns registration, JSON-schema
  validation, policy lookup, authorization, grant issuance, execution,
  auditing, result normalization, retries, and error translation.
- **TOL-002** — Built-in, sandbox, and MCP tools are adapters behind the Tool
  broker. An adapter cannot bypass authorization/audit or return arbitrary
  unbounded event/history data.
- **TOL-003** — Tool execution receives the least-privilege, single-operation
  capability grant derived from the approved policy and expires/revokes it on
  completion, cancellation, or timeout.
- **TOL-004** — Every authorization decision—allow, deny, pending approval,
  expired, exhausted, and execution result—has an append-only audit record
  with actor, tenant, agent/policy revisions, capability scope, and operation
  correlation but no secret value.
- **TOL-005** — Tool outputs are bounded, redacted as needed, blob-backed when
  large, and normalized to safe public result/event references.
- **TOL-006** — Tools that can have external effects require an execution
  operation ID and an application-level external idempotency strategy; the
  runtime must surface uncertain outcome rather than claim exactly once.
- **HITL-001** — A Tool policy may require human approval. The runtime shall
  durably pause the Turn in a `waiting_for_approval` execution phase without
  making it a terminal Turn state.
- **HITL-002** — An Approval request contains a stable ID, tenant/session/turn/
  tool-call linkage, safe human-readable action summary, proposed bounded
  capability scope, policy revision, requester, expiry, and decision state.
- **HITL-003** — Only an authorized approver may approve or deny. Approval is
  idempotent, durable, auditable, expires under the injected clock, and cannot
  broaden the proposed scope or survive policy/turn invalidation.
- **HITL-004** — Approval, denial, expiry, cancellation and post-approval tool
  execution publish safe ordered product events and independent audit records.
- **HITL-005** — Workflow/worker restart, client disconnect, and event replay
  preserve a pending approval exactly once; a late decision returns a stable
  conflict/expired response and never runs a tool.
- **HITL-006** — The Workspace Agent example includes a real human-approval
  interaction for an elevated action and the full E2E suite proves approve,
  deny, expiry, duplicate response, and cancellation behavior.

### Conversation, artifacts, events, audit, and observability

- **DAT-001** — Conversation appends use expected-version optimistic
  concurrency, durable idempotency, bounded entries, and immutable content
  references; conflicts are retryable only when safely re-readable.
- **DAT-002** — Artifacts use content integrity digests, access authorization,
  media/size limits, immutable metadata, storage lifecycle/retention policy,
  and safe download streaming.
- **DAT-003** — Product events are ordered per Session, stable-versioned,
  caller-safe, resumable from a cursor, at-least-once deliverable, duplicate
  tolerant, bounded, and finalizable after producer recovery.
- **DAT-004** — Runtime event publication uses a durable sequence/finalization
  protocol so tool/sandbox/model stream connection loss yields an explicit gap
  or replay, never silent loss or uncontrolled duplication.
- **DAT-005** — Event retention and cursor expiry are documented and tested;
  clients receive a recoverable cursor-expired outcome and can inspect current
  state rather than guessing.
- **DAT-006** — Security audit records are append-only, independently retained,
  tenant-scoped, deduplicated by operation identity, and distinguish attempted,
  authorized, committed, terminal, and reconciled facts.
- **DAT-007** — Any mandatory audit configuration has a defined durable outbox
  or explicitly at-least-once protocol. It shall never promise transactional
  fail-closed audit semantics it cannot enforce.
- **DAT-008** — Conversation, artifacts, product events, audit records,
  Temporal payload blobs, sandbox operation data, volume manifests, and
  snapshots have independent data classifications and retention/GC contracts.
- **DAT-009** — PostgreSQL is required for v1 as the authoritative metadata,
  control and event store. It owns runtime tenancy/identity, idempotency,
  Session/Turn projections, conversation/artifact indexes, public product-event
  sequence and cursors, audit/outbox records, and sandbox desired/actual
  operation ledgers. It does not store unbounded content. Temporal remains the
  durable orchestrator and object storage holds immutable large content.
- **DAT-010** — PostgreSQL schemas, versioned migrations, transaction and
  locking model, retention/partitioning, tenant erasure, and backup/restore
  ownership are explicit. Temporal persistence is separately deployed with its
  own declared database/schema, credentials, retention and lifecycle.
- **DAT-011** — Product events follow one durable state machine: producer
  intent, durable ordered runtime event, delivery/replay, then terminal or
  explicit gap. PostgreSQL is the event and public-cursor authority; Temporal
  Workflow Streams may be an internal producer/transport adapter only and are
  never the source of truth, a public cursor or a retention contract.
- **DAT-012** — Input, model/tool output, artifacts, approvals, sandbox
  operations, audits and Continue-As-New effects declare their transaction
  boundary and either an atomic commit or an explicit at-least-once durable
  outbox/reconciliation behavior. No effect claims stronger exactly-once
  semantics than its recorded protocol proves.
- **DAT-013** — The production PostgreSQL adapter proves migrations,
  transaction conflict/retry, process-kill outbox recovery, cursor expiry/gap,
  backup/restore, tenant erasure and cross-tenant denial against the declared
  production configuration.
- **OBS-001** — Emit OpenTelemetry-compatible traces, metrics, and `slog`
  records with runtime correlation fields: tenant, agent/revision, session,
  turn, invocation, tool call/execution, approval, sandbox, process, and
  operation IDs.
- **OBS-002** — Backend IDs may be operator-only diagnostic attributes but are
  not part of product events, public SDK models, or application control flow.
- **OBS-003** — Logs, metrics, traces, errors, labels, audit data, and event
  attributes are validated/redacted and never include raw secret bytes,
  environment maps, captured I/O, artifact content, or unsafe arbitrary argv
  by default.
- **OBS-004** — Provide dashboards and documented alerts for sessions/turns,
  model usage/retries, tool authorization/execution, approval queue/expiry,
  sandbox provisioning/reaping, event lag/gaps, blob/codec health, Temporal
  poll/schedule-to-start health, and redaction/oversize failures.
- **OBS-005** — Observability verification asserts correlation across the
  public Session, audit record, trace, runtime operator view, Temporal
  execution, and sandbox operation without exposing a private identifier to
  an application caller.

### Sandbox durable control plane and core contract

- **SBX-001** — The sandbox is a first-class in-repo subsystem with a durable
  control plane/service and per-host execution agents. It is not merely an
  in-process `Sandbox` handle inside a Temporal activity.
- **SBX-002** — The control plane owns desired/actual resource state, host
  routing, leases, durable request/operation ledger, authorization scope,
  process/output records, tombstones, reconciliation, and reaping across
  worker deploys, process crashes, and host failures.
- **SBX-003** — The public sandbox client supports authenticated, tenant-scoped
  lookup and control by Sandbox, Process, Volume, Snapshot, and Operation ID:
  inspect, attach/reconnect, wait/result retrieval, output replay, signal/kill,
  close, and reconciliation status. IDs alone are not authorization.
- **SBX-004** — Every mutating sandbox operation—create, restore, exec,
  copy/write, snapshot, close, volume create/attach/detach/delete, snapshot
  delete, and approval-sensitive operation—accepts a durable Operation ID or
  request ID with a canonical immutable request.
- **SBX-005** — The durable request ledger is tenant/principal-scoped, survives
  client/provider/host restart, records policy/schema version and fully
  resolved effective inputs, provides accepted/started/terminal/tombstone
  states and retention/expiry, detects reuse-with-different-input conflicts,
  and reconciles uncertain commit order.
- **SBX-006** — Operation result/output retention, stream offsets/gaps,
  reconnect rules, host-unreachable behavior, cancellation ownership, and
  exactly-once limits are explicit. External side effects remain
  application-idempotent even when one sandbox exec is deduplicated.
- **SBX-007** — Bind a non-forgeable principal/tenant context at client/control
  construction and authorize every object, operation, resolver call, image,
  volume, snapshot, audit record, and registry entry against it.
- **SBX-008** — Normalize, validate, deep-copy, and freeze all public Spec,
  Command, Grant, labels, maps, slices, readers and tagged-union inputs before
  acceptance; use a versioned canonical wire schema and never hash Go structs.
- **SBX-009** — Resolve defaults, image digest/admission evidence, numeric
  identity, resources, and policy-engine version into a persisted Effective
  Spec before accepting an operation. Retries use that exact effective value or
  return explicit incompatibility, never silently adopt new defaults.
- **SBX-010** — Use a core-wrapped, expert-only backend SPI. Adapters receive
  normalized internal requests and cannot bypass core lifecycle, grant,
  redaction, bounded-I/O, authorization, or error invariants. Ordinary callers
  cannot directly invoke a provider.
- **SBX-011** — The sandbox public interface uses typed opaque Stripe-style IDs,
  typed argv commands, durable operation/result references, safe errors, and
  reconnectable controls—not backend VM/KVM/jailer/vsock types.
- **SBX-012** — Publish a compileable API/semantics table for every exported
  sandbox field and method, including zero values, wire form, limits,
  concurrency, authorization, idempotency, cancellation, uncertain outcome,
  and error behavior.
- **SBX-013** — Sandbox lifecycle includes durable desired/actual state,
  operation-exclusive quiescing, process state, cleanup-pending/confirmed,
  failure retention, tombstones, lease expiry, and reaper ownership. Close is
  idempotent and converges across concurrent callers and restart.
- **SBX-014** — A production reaper independently reconciles leaked VMMs,
  agents, network rules, mounts, storage, process trees, and leases after
  activity/worker/control-plane restart; it has bounded retry/backoff and
  observable proof of cleanup.
- **SBX-015** — Process results have a typed termination model separating
  normal exit, signal, timeout, OOM, output limit, cancellation, caller kill,
  sandbox loss, unknown/uncertain, and confirmed process-tree cleanup. No
  adapter may flatten these into an exit code.
- **SBX-016** — Process start acknowledgement and process lifetime use separate
  cancellation semantics. `Wait` cancellation only abandons that wait; a
  process’s timeout/kill/close/lifetime policy is explicit and race-tested.
- **SBX-017** — A core-owned bounded per-stream spool/tee provides stdout and
  stderr replay, tails, backpressure behavior, independent truncation/gap
  markers, redaction, completion, and result retention. `Wait` progress does
  not depend on a live reader draining an unbounded pipe.
- **SBX-018** — Sandbox resource enforcement and deployment admission quotas
  are distinct and bounded: CPU/memory/root disk/tmpfs/PIDs/open files/process
  count/inodes/files/output/file transfer/network connections/control requests/
  snapshot and volume count/bytes/image admission/global tenant capacity. Each
  exceeded limit has a typed outcome.
- **SBX-019** — Zero resource values resolve to documented finite Effective
  Spec defaults; production has no implicit unlimited resource setting.
- **SBX-020** — Images are immutable content-addressed identities admitted by a
  production policy. `Info` exposes safe admitted metadata (digest,
  architecture, numeric non-root user, guest protocol, verification-policy
  version); a digest alone is not treated as provenance proof.
- **SBX-040** — Every production host agent is enrolled with a durable host
  identity and uses mutually authenticated control transport with explicit
  credential rotation, revocation, protocol compatibility and documented
  attestation limits. An unenrolled, revoked, incompatible or untrusted host
  cannot receive or complete an operation.
- **SBX-041** — Control-plane requests to a host agent use authenticated,
  versioned operation envelopes containing tenant/principal, immutable
  Effective-Spec digest, Operation ID, capability snapshot, expiry, lease or
  fencing token, host assignment and protocol version. The host refuses an
  absent, invalid, expired, replayed or incompatible envelope.
- **SBX-042** — The control plane durably assigns hosts and owns lease renewal,
  fencing, duplicate/stale-result rejection, output sequence integrity, loss
  and quarantine, reassignment and reconciliation. A host result cannot
  overwrite a newer lease or cross an assignment boundary.
- **SBX-043** — The control plane, sandbox core, host agent and Jailer have
  explicit non-overlapping authority for cgroups, network, image admission,
  mounts, output limits and cleanup. A local-unsafe adapter implements the
  same refusal protocol but never proves this trust boundary.
- **SBX-044** — Host-protocol acceptance tests cover replay/revocation, stale
  lease, wrong tenant, rogue host, lost acknowledgement, control/host restart,
  output sequencing, quarantine cleanup and reassignment. M3 uses this durable
  protocol and M4 proves it on the Linux/KVM Firecracker path.

### Sandbox authority profiles

- **SBX-021** — The production foundation profile provides hardware-isolated
  Linux/KVM Firecracker execution with a jailed unprivileged VMM, cgroups v2,
  minimal authenticated guest agent, immutable admitted image, non-root guest,
  bounded overlay/tmpfs, typed argv, deny-all network, no host mounts/secrets,
  durable control/reaping, and reconnectable operations.
- **SBX-022** — The local adapter explicitly advertises `local-unsafe`, requires
  an acknowledgement at construction, sanitizes local developer environment
  as a convenience only, and mechanically rejects real secret bindings and
  any policy it cannot enforce. It never claims filesystem/network/secret
  isolation or serves as production-security evidence.
- **SBX-023** — A deterministic fake adapter/control client supports scripted
  durable states, process results, failures, stream gaps and fake clocks for
  unit/orchestration tests without pretending to execute commands.
- **SBX-024** — All adapters expose a versioned structured capability contract
  (not a boolean bag), negotiated and bound to create/restore results. It
  covers isolation, egress form/data plane, mounts, volumes, snapshots,
  resource precision, architectures, cleanup/reconnect support, protocol and
  admission versions; capability regression fails closed.
- **SBX-025** — A shared black-box capability-driven conformance suite runs
  against every adapter. Claiming a capability enables all its semantics and
  adversarial tests; unsupported capability requests fail closed rather than
  silently degrading.
- **SBX-026** — The portable workspace profile supplies bounded, checksummed,
  authorization-aware streaming copy-in/copy-out (file and directory/archive)
  before host mounts are relied on. It specifies overwrite, symlink,
  descriptor-relative path resolution, ownership/mode, partial cleanup,
  cancellation and durability behavior.
- **SBX-027** — Filesystem paths are absolute clean POSIX guest paths, reject
  reserved/overlapping/ambiguous targets, resolve descriptor-relatively beneath
  allowed roots, resist symlink/replacement races, and never expose host
  devices/sockets/control paths by default.
- **SBX-028** — Host mounts are a separately gated capability profile. Until
  its entire conformance/security suite passes, the Firecracker adapter reports
  them unsupported. The final release implements RO/RW mounts only through
  exact-source-identity-pinned, per-sandbox jailed sharing with clear
  link/rename/execution/daemon-compromise semantics.
- **SBX-029** — Named volumes are quota-bounded, principal-owned, manifest
  backed, encryption/integrity-reported, explicitly attached through leased
  generation-numbered ownership, reconciled after crashes, and have deletion
  tombstone/race semantics. Attachment is not a Boolean.
- **SBX-030** — Snapshot capability is separately gated and provides quiesced
  disk-only snapshots with manifest/provenance/effective-policy ceiling,
  owner, taint evidence, schema/version, encryption/integrity status,
  request ID, inspect/list/lease/delete/tombstone/restore semantics, and
  corruption/concurrent-delete recovery tests.
- **SBX-031** — Snapshot guarantees state only that SDK-managed secret delivery
  tmpfs, process memory, sockets, host mount contents, and named-volume
  contents are excluded; they never claim arbitrary secret-derived bytes are
  absent.
- **SBX-032** — SDK-known secret exposure taints a sandbox. Named volumes carry
  persistent taint provenance; mounting a tainted volume taints the sandbox.
  Writable external storage and unknown secret channels require explicit
  snapshot attestation/denial according to documented policy.
- **SBX-033** — Secret resolution receives an authenticated contextual request
  (principal, sandbox/process/operation, binding/purpose), returns a bounded
  versioned expiring value through an ephemeral channel, and is audited. No
  secret value is persisted in specs, hashes, logs, errors, metrics, events,
  snapshots or provider configuration.
- **SBX-034** — Command-sensitive authority is fail closed. Omitted secret,
  mount, and network grants mean no authority; inheritance requires an
  explicit, policy-approved marker. Grant intersection can only narrow an
  admitted Effective Spec and has a documented nil/empty/duplicate/unknown
  truth table.
- **SBX-035** — Command-scoped secrets require independently proven PID/mount/
  FD/proc/ptrace/process-tree isolation. They are injected just in time into a
  non-snapshotted area, revoked only after complete tree reap, literal-redacted
  across output chunks, and serialized when concurrency cannot be proven.
- **SBX-036** — In-guest "trusted helper" path selection is not treated as a
  high-value credential boundary. Elevated credentials use an external typed
  broker or an admitted immutable trusted-exec capability with fixed
  environment, workdir/mount view, loader dependencies, and argument schema.
- **SBX-037** — The egress profile uses a documented mandatory host-controlled
  proxy data plane: the guest has no routable exit except authenticated proxy
  transport; the proxy independently resolves, validates, pins and connects to
  allowed domain+port destinations; direct IP/private/link-local/metadata/
  control-plane/bypass traffic fails closed. The guarantee is destination
  restriction, not TLS/HTTP semantic inspection or DLP.
- **SBX-038** — Egress profile semantics define IDNA/wildcards, DNS/CNAME and
  address lifecycle limits, IPv4/IPv6, proxy outage, ECH/no-SNI/shared-IP
  implications, connection reuse, DoH, redirects and SNI/Host behavior. Tests
  assert the promised proxy-destination outcome, not an impossible claim about
  encrypted application semantics.
- **SBX-039** — The final sandbox delivery includes all authority profiles
  above—portable transfer, host mounts, volumes, snapshots, egress and
  command-scoped secrets—each only after its own threat model, capability
  declaration, conformance/security suite and durable-control story pass.

### Deployment, developer experience, examples, and documentation

- **DEP-001** — `tilt up -- --stack=<name>` creates a deterministic,
  fully-isolated local Kubernetes stack: namespace, Temporal deployment/
  namespace, storage, blob prefix/volume, task-queue prefix, secrets/service
  accounts, ports, ingress names, and telemetry attributes derive from the
  validated stack name.
- **DEP-002** — The default Tilt profile uses dedicated per-stack Temporal and
  persistence resources. A later fast/shared profile may exist only with
  explicit logical isolation; isolation evidence always uses the full profile.
- **DEP-003** — Tilt builds the production runtime images, offers live rebuild,
  readiness ordering, role-grouped logs, links to API/Temporal UI/codec/docs,
  and stack-scoped safe reset/reseed actions that cannot target another
  namespace.
- **DEP-004** — Deploy manifests/Helm and configuration document self-hosted
  Temporal, blob store, codec ingress/origins/namespaces, model credentials,
  sandbox control hosts, secrets, role scaling, retention, backup, and
  observability. Third-party infrastructure is deployed alongside, never
  embedded in the runtime binary.
- **DEP-005** — Production uses separate trust-scoped processes and validates
  credential non-presence in roles that should not possess them.
- **DEP-006** — The operator deployment contract explains the difference
  between application developer configuration (agents/sessions) and operator
  configuration (Temporal, storage, roles, model profile, sandbox capacity,
  secrets, observability).
- **DEP-007** — The sandbox Firecracker integration suite runs on a documented
  Linux/KVM host lane; its image/kernel/guest-agent/Firecracker compatibility
  matrix is pinned and released. macOS Tilt does not attempt to emulate this
  evidence.
- **DEP-008** — Repository bootstrap detects missing prerequisites and gives
  direct repair instructions without mutating the user’s Kubernetes context,
  credentials or unrelated local resources.
- **DEP-009** — The planned canonical local-stack invocation is
  `tilt up -- --stack=<name>`. Any optional `just` convenience wrapper accepts
  the same validated stack identity and renders the same topology; it cannot
  introduce an `instance` identity or a second lifecycle. Neither command is
  represented as working until its checked-in implementation and clean-checkout
  proof exist. Teardown proves state-file ownership, rendered labels and object
  UIDs before deleting only the owned stack.
- **EX-001** — Deliver Durable Chat as a usable web and TUI application using
  only the public SDK/HTTP contract. It creates/resumes sessions, streams and
  reconnects from cursors, queues input, cancels, inspects state, and proves
  durable continuation across API/worker restart.
- **EX-002** — Deliver Workspace Agent as a usable application with a
  session-scoped workspace sandbox, safe file APIs, tool execution, live
  process output, artifact creation/download, local safe defaults, and a real
  human approval for an elevated action. It is not Software Factory and does
  not include ticket/PR/CI/merge lifecycle.
- **EX-003** — Deliver Research Dossier as a usable application that performs
  durable multi-step research, uses allowed tools, handles long conversations
  and large tool results, publishes progress and citations, writes artifacts,
  resumes after interruption, and produces a downloadable dossier.
- **EX-004** — Examples import only public SDK modules and use no internal
  package, direct Temporal client, blob store, sandbox control or test-only
  route. This is mechanically checked.
- **EX-005** — Each example has an isolated Tilt profile, seed/demo flow,
  screenshots or recorded terminal evidence, tutorial, E2E test, and
  troubleshooting guide. A clean user can run it with the documented commands.
- **EX-006** — End-to-end demos prove: stream then restart/reconnect; sandbox
  output/artifact/approval; large compressed/offloaded payload inspection via
  authorized Temporal UI codec; cancellation and cleanup; and no secret in a
  public event or artifact fixture.
- **EX-007** — Each example has least-privilege authentication bootstrap,
  isolated demo-tenant ownership and cleanup, authorized artifact download,
  redacted evidence, named browser/TUI harness ownership, and one shared public
  cursor-client behavior. An example never receives broad administrator
  credentials merely to simplify a tutorial.
- **DOC-001** — Publish a modern Astro Starlight documentation site through GitHub
  Pages, with versioned/searchable navigation and an accessible responsive
  design. Pin and periodically upgrade compatible Astro and Starlight releases.
- **DOC-002** — The docs site includes overview/architecture, concepts,
  quickstart, Tilt/local stack, complete SDK/API reference, OpenAPI reference,
  operator deployment/configuration, Temporal/codec/blob operation, sandbox
  security/capabilities, approvals, observability, troubleshooting, extension
  guides, ADRs, and all three complete example tutorials.
- **DOC-003** — Public HTTP/OpenAPI and Go SDK references are generated from
  source/contract and published; documentation prose explains stable semantics
  rather than duplicating unverified generated details.
- **DOC-004** — Every documented command and code sample is executable in CI
  (or explicitly marked non-executable with rationale); link checking, spell/
  format checks, generation and a full production docs build are release gates.
- **DOC-005** — Add a repository-local documentation skill that, when asked to
  “update the repository’s docs,” inventories public/config/behavior changes,
  updates conceptual/tutorial/reference material, regenerates references,
  validates samples/links/build, and reports undocumented behavior rather than
  claiming success.
- **DOC-006** — README is an opinionated landing page with the project promise,
  safety limits, architecture, five-minute local start, command reference,
  example links, docs link, status/evidence, contributing, security policy,
  license, and support boundaries.
- **DOC-007** — Docs distinguish verified local behavior, verified Linux/KVM
  security evidence, operator responsibilities, assumptions, and unverified
  deployment-specific claims. They must never represent local adapter behavior
  as Firecracker isolation.
- **DOC-008** — Documentation publication has a reproducible locked Node and
  package-manager environment; a public-site root distinct from planning docs;
  declared Pages URL/base URL, versioning, search privacy/cost model,
  accessibility gates, permissions and rollback; and a docs-skill path and
  invocation that agree with `AGENTS.md`. Fixture tests detect route,
  configuration, example and reference drift without rewriting curated
  security/operator content.

### Milestone status and completion reporting

- **OPS-STAT-001** — A milestone is not recorded complete until the configured
  notifier posts a secret-safe JSON or text payload to
  `https://ntfy.sh/0x63616c-ai-agant` containing `milestone`,
  `estimated_overall_percent`, `evidence_summary`, `next_milestone`, immutable
  `commit_or_revision`, `utc_time`, and `status`. The percentage is an
  explicitly labelled estimate derived from weighted ledger evidence, never an
  assertion that blocked requirements passed. The payload excludes credentials,
  tokens, credential-bearing URLs, raw user/model/tool content, secrets and
  internal backend IDs.
- **OPS-STAT-002** — Regular status reports use the same evidence model and
  state completed, in-progress and blocked work, uncertainty, current estimate
  and next observable checkpoint. A failed notification is retained as a
  visible release-operations failure/retry record and cannot silently claim a
  notification was sent. The notifier endpoint/topic/configuration is typed
  operator configuration declared under INF-001; no runtime workflow sends a
  user-controlled URL.

### Verification and release evidence

- **TST-001** — Unit tests cover deterministic kernel/domain transitions,
  IDs, clocks, validation, canonical wire/hash vectors, policy intersections,
  failure translation, redaction, and every declared invariant at its public
  seam.
- **TST-002** — Contract/integration tests cover public HTTP/SDK parity,
  authentication/tenant isolation, idempotency, events/cursors/gaps, stores,
  tools, approvals, codec/blob chain, and sandbox control restart/reconnect.
- **TST-003** — Sandbox conformance tests exercise every adapter only through
  the public sandbox client/control interface and conditionally activate all
  tests advertised by its structured capabilities.
- **TST-004** — Sandbox adversarial tests include input mutation races,
  cross-tenant guessed IDs, operation retry at every acknowledgement boundary,
  worker/control/host failure, reaper/lease recovery, process-tree escape,
  resource exhaustion, filesystem traversal/replacement, secret output
  redaction, taint laundering, snapshot corruption, egress bypass, and unsafe
  local-adapter refusal.
- **TST-005** — Linux/KVM Firecracker E2E tests kill/restart a worker/control
  path mid-create/mid-exec/mid-output/mid-snapshot/mid-close, route retry to a
  different worker, then prove exactly the documented reconciliation and
  cleanup outcome.
- **TST-006** — Full local Tilt E2E starts an isolated stack and runs all three
  examples through their real public paths, including restarts, reconnect,
  approval, artifacts, payload inspection, cancellation and cleanup.
- **TST-007** — Tests use fake/injected time and bounded deterministic
  synchronization. Test code may not hide correctness behind arbitrary real
  sleeps, eventual polling without a deadline, or reliance on test order.
- **TST-008** — CI runs formatting, static analysis, type checking, unit,
  race, fuzz-budget, contract, integration, docs, dependency/security,
  generated-drift, local-stack E2E where supported, and Linux/KVM security/
  E2E lanes; failures retain actionable artifacts/logs with secret-safe
  redaction.
- **TST-009** — A final `just verify` produces a machine-readable completion
  report mapped to this ledger, with every requirement marked proven, blocked,
  or not-applicable and links to evidence. “Not implemented” is never silently
  treated as passed.
- **TST-010** — At least one independent review pass checks the completed code
  against this ledger and the Software Factory style guide, then all findings
  are resolved or recorded with explicit user-approved scope change.

## Explicit non-goals for this release

The following are deliberately outside the destination and must not be
represented as complete features:

- Operating Temporal, object storage, or Kubernetes as a hosted managed
  service for third parties; this release is self-hosted/open-source.
- An embedded worker kit that asks applications to run Temporal workers.
- Multi-agent delegation/coordination, parallel turns within one session,
  cross-session shared state, autonomous schedules, long-term retrieval/memory,
  dynamic agent-revision migration, and multi-provider model support.
- Inbound sandbox networking, GPUs/devices, nested virtualization, PTYs,
  interactive terminal semantics, warm-pool reuse, fleet scheduling beyond the
  needed durable host routing, live-memory snapshots, or generic privileged/
  backend-options escape hatches.
- A promise to prevent a process from disclosing authority intentionally
  granted to that process, to provide DLP through domain allowlisting, or to
  defend against host-kernel/hypervisor compromise.
- Software Factory’s tickets, GitHub/PR, CI policy, or merge workflow.

## Completion rule

The system is complete only when every requirement above has green evidence in
the ledger, every milestone has its retained `OPS-STAT-001` completion record,
the three examples run end-to-end from a documented local Tilt stack, the
Linux/KVM lane has produced the documented Firecracker evidence, the public
docs site is deployed, and the repository’s `README.md` and `AGENTS.md`
accurately describe that state.
