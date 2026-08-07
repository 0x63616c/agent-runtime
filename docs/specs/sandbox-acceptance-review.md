# Sandbox planning acceptance review

Status: **failed — do not start sandbox implementation tickets after M0 yet.**

Reviewed: 2026-08-06. This is an independent planning acceptance review, not
implementation evidence. It compares the supplied first-pass draft and
skeptical pass-2 review with the revised sandbox specification, feature
inventory and disposition. It also treats the current master requirements,
acceptance ledger, seams/invariants, active-risk register, and accepted ADRs
as authoritative.

## Verdict

The revision substantively resolves the original pass-2 design findings for
the `SBX-001`–`SBX-039` model. It makes the correct architectural move from a
live in-process handle to a principal-scoped durable control plane, gives every
mutation an Operation ID and ledger, defines a fail-closed Grant model, and
separates capability profiles rather than silently cutting them.

It is **not an acceptable current implementation contract**. The later binding
host-control requirements `SBX-040`–`SBX-044` are absent from the specification
scope and from the 143-row inventory. This is not a documentation nicety: it
leaves the control plane unable to distinguish a legitimate assigned host from
a stale, revoked, rogue, replayed or cross-tenant agent. The declarative
infrastructure table also does not yet satisfy the project-wide explicit
infrastructure contract for the control/host trust boundary.

The only work that may start is an M0 **contract-correction** task. Do not
start durable-control, host-agent, Firecracker, or security-profile
implementation tickets until the P0 findings below are resolved and this
review is rerun. The correction is additive; it does not remove any final
release authority profile.

## Gate results

| Gate | Result | Basis |
| --- | --- | --- |
| Original pass-2 P0/P1/P2 design corrections | **Conditional pass** | The revised body gives a coherent answer for the original 30 findings, except that the promised compileable public API remains a planned artifact. |
| Temporal durable-control model | **Conditional pass** | Durable IDs, host routing, ledger, reaper, output replay and external-effect limits are specified for the original review. It fails the current host-protocol requirements below. |
| Current host-control protocol (`SBX-040`–`SBX-044`) | **Fail (P0)** | The specification explicitly scopes itself to `SBX-001`–`SBX-039`; the inventory contains no `SBX-040`–`SBX-044` rows or evidence families. |
| Public API coherent and compile-plausible | **Fail (P1)** | The `Client` method shape is coherent, but all referenced value/transport types are only names and there is no compile example or field-by-field semantics artifact yet. |
| Operation ledger, lifecycle and recovery | **Conditional pass** | Sections 4–8 provide an implementable model for the original findings, subject to the missing authenticated host protocol that makes dispatch/receipts trustworthy. |
| Declarative and explicit infrastructure | **Fail (P0)** | Section 3.3 names policy objects but omits the Stack/resource ownership, Secret-reference, mTLS enrollment, RBAC, network, port, backup/restore and delete/rollback declaration needed by `INF-001`–`INF-005`. |
| Inventory body/API/evidence traceability | **Fail (P0)** | The 143 original rows have body and ledger-family links, but the inventory is not exhaustive against binding scope: it omits `SBX-040`–`SBX-044`. |
| Final evidence status | **Expected red** | Every inventory row is unchecked; no implementation or green test evidence exists yet. Planning must not be represented as feature completion. |

## Original review finding disposition

The table below tests the substance of the original pass-2 findings, not the
revision's assertion that they are resolved.

| Original finding | Result | Independent acceptance basis |
| --- | --- | --- |
| P0-1 stable IDs/recovery | Pass | Durable `Get`/`Wait`/`Watch`/output replay and principal-scoped `SandboxID`/`ProcessID`/`OperationID` appear in sections 3.2 and 4; `INV-006`–`008`, `021`–`026`, `042` trace to the ledger. |
| P0-2 mutation retry safety | Pass | Section 6 makes every mutation an Operation, records receipt journals and exposes `uncertain`; it truthfully preserves application-level idempotency for external effects. |
| P0-3 request ledger | Pass | Sections 5–6 define principal keying, canonical digest/version, transaction/outbox, retention, tombstones and reconciliation. |
| P0-4 Grant defaults | Pass | Section 10 has an unambiguous none/select/inherit table; absent/zero/empty is no sensitive authority. |
| P0-5 mutable Go input | Pass | Section 5.1 freezes deep-copied values and consumes readers to bounded immutable artifacts before authorization. |
| P0-6 principal ownership | Pass | Section 3.4 binds a non-forgeable principal and makes every durable object/action principal-scoped. |
| P0-7 secret taint | Pass | Section 11.2 narrows the claim to SDK-known exposure, propagates volume taint and requires denial/attestation for risky snapshots. |
| P0-8 provider bypass | Pass | Sections 3.1 and 15 replace the public provider with an internal normalized SPI and require malicious-adapter tests. |
| P0-9 egress claim | Pass | Section 12 defines a mandatory authenticated proxy and explicitly limits the guarantee to proxy destination domain and port. |
| P0-10 resource gaps | Pass | Section 13 separates enforcement/admission and includes inodes, IOPS, network, storage, control and global capacity. |
| P1-11 termination model | Pass | Section 7.2 gives one typed reason plus separate cleanup state; exit code cannot flatten it. |
| P1-12 cancellation lifetime | Pass | Section 7.1 separates start acknowledgement, runtime lifetime and observational wait cancellation. |
| P1-13 streams/redaction | Pass | Section 8 specifies core spool/tee ownership, bounded retention, replay/gaps, progress without readers and deterministic chunk-safe redaction. |
| P1-14 host mounts | Pass | Section 9 makes portable transfer precede a separately-gated, descriptor-pinned mount profile and names the share agent as TCB. |
| P1-15 trusted helper | Pass | Section 11.3 requires an external broker or immutable trusted-exec proof and otherwise grants the full process tree. |
| P1-16 snapshots | Pass | Section 14.3 defines manifest, quiesce/publish, inspect/list/lease/delete/restore, retention and constrained policy ceiling. |
| P1-17 volumes | Pass | Section 14.2 uses manifest-backed generation leases and explicit attach/detach/delete reconciliation. |
| P1-18 lifecycle | Pass | Section 7 gives desired/actual/process state and races; section 6.3 gives durable reaper ownership. |
| P1-19 file APIs | Pass | Section 9.1 makes bounded checksummed copy-in/out the portable API and defines archive/path/overwrite/cancel behavior. |
| P1-20 image admission | Pass | Sections 3.3 and 14.1 distinguish immutable identity from admitted provenance metadata. |
| P1-21 resolver semantics | Pass | Section 11.1 gives authenticated context, bounds, pinned version/expiry and ephemeral audited delivery. |
| P1-22 capability negotiation | Pass | Section 15 uses structured versioned capability snapshots, persistence, recheck and fail-closed regression. |
| P1-23 audit boundary | Pass | Section 16 gives a ledger/resource/audit transactional outbox and makes sink delivery at-least-once rather than falsely atomic. |
| P1-24 local adapter | Pass | Section 15 requires an unsafe acknowledgement and rejects authority it cannot prove. |
| P2-25 canonical serialization | Pass | Sections 5.1–5.2 define strict `sandbox.control/v1`, tagged unions, normalization, bounds and golden vectors. |
| P2-26 path/user/executable | Pass | Sections 7.1, 9.1 and 14.1 require absolute argv, numeric admitted identity and descriptor-relative guest paths. |
| P2-27 safe errors | Pass | Section 16 separates non-unwrappable safe public failures from authorized diagnostic records. |
| P2-28 default evolution | Pass | Section 5.3 persists the versioned resolved Effective Spec and rejects incompatible persisted policy. |
| P2-29 performance | Pass | Section 16 requires full-path benchmark context and saturation/cleanup reporting. |
| P2-30 coherent compileable API | **Partial (P1)** | The design removes prior contradictions, but only an interface refers to undefined types. The required compile examples and complete field/method semantics table are explicitly deferred. |

The pass-2 review additionally recorded 47 unnumbered or separately numbered
findings. They are individually checked below so that “all 77 resolved” is not
accepted merely as an assertion in the disposition document.

| Finding | Result | Revised body and inventory evidence |
| --- | --- | --- |
| T-1 worker location | Pass | 3.1 makes control/host agents durable and `INV-002`–`004` records it. |
| T-2 long-lived owner | Pass | 3.1 and 6 assign ownership to control ledger/resource state, not an activity. |
| T-3 retry routing | Pass | 3.2 and `INV-006`–`008` persist host ID/generation and route reconnects. |
| T-4 durable output boundary | Pass | 4.1, 8 and `INV-058`–`064` define ordered redacted spool/replay/gap/final state. |
| T-5 external-effect policy | Pass | 6.2 and `INV-042`–`044` retain uncertain result and require application idempotency. |
| T-6 cancellation after worker loss | Pass | 6.3 and 16 make kill/close durable and cleanup reaper-owned. |
| T-7 deploy/host-failure cleanup | Pass | 3.2 and 6.3 define lease, fencing, lost state and reaper recovery. |
| T-8 heartbeat recovery | Pass | 4 and `INV-021`–`026` allow durable operation/result/output inspection. |
| T-9 workflow-history content | Pass | 16 and `INV-133` restrict Temporal state to IDs/references/cursors. |
| T-10 activity retry taxonomy | Pass | 4.1, 6.2 and 16 distinguish validation, loss, result and uncertain effect. |
| O-1 deep copy/freeze | Pass | 5.1 and `INV-028`–`030`. |
| O-2 reconnect/control by ID | Pass | 4 and `INV-021`–`026`. |
| O-3 exec/snapshot idempotency and retention | Pass | 4, 6 and 14.3 with `INV-023`, `037`–`044`, `113`–`118`. |
| O-4 namespaced canonical ledger | Pass | 5–6 and `INV-031`–`044`. |
| O-5 ownership authorization | Pass | 3.4 and `INV-017`–`020`. |
| O-6 host-affine routing | Pass | 3.2 and `INV-006`–`008`. |
| O-7 stream replay/gaps | Pass | 8 and `INV-058`–`064`. |
| O-8 durable cancellation leases | Pass | 6.3 and `INV-045`–`047`. |
| O-9 hostile resource dimensions | Pass | 13 and `INV-099`–`106`. |
| O-10 secret version/expiry and volume taint | Pass | 11 and `INV-080`–`087`. |
| O-11 volume/snapshot inspection and lifecycle | Pass | 14 and `INV-110`–`118`. |
| O-12 image admission/effective policy | Pass | 3.3, 5.3, 14.1 and `INV-012`, `035`, `107`–`109`. |
| O-13 Grant omission/inheritance | Pass | 10 and `INV-076`–`079`. |
| O-14 process termination model | Pass | 7.2 and `INV-055`–`057`. |
| O-15 strict canonical wire | Pass | 5.2 and `INV-031`–`034`. |
| O-16 Client close/reaper | Pass | 4, 6.3 and `INV-022`, `046`–`047`. |
| O-17 egress data plane | Pass | 12 and `INV-090`–`098`. |
| O-18 Temporal artifact/output durability | Pass | 8, 16 and `INV-058`–`064`, `134`. |
| U-1 resolved limits in inspection | Pass | 3.3, 5.3 and `INV-013`, `035`. |
| U-2 snapshot store/retention/encryption | Pass | 3.3, 14.3 and `INV-012`, `113`–`118`. |
| U-3 mandatory audit sink | Pass | 16 and `INV-129`–`130`. |
| U-4 logs, metrics and traces | Pass | 16 and `INV-131`–`132`. |
| U-5 versioned capability matrix | Pass | 3.3, 15 and `INV-011`, `119`–`124`. |
| U-6 timeout/OOM distinction | Pass | 7.2 and `INV-055`–`057`. |
| U-7 cleanup observations | Pass | 4.1, 6.3 and `INV-026`, `046`. |
| U-8 streaming/atomic file transfer | Pass | 9.1 and `INV-067`–`070`. |
| U-9 deterministic fake | Pass | 15 and `INV-128`. |
| U-10 mount requirement versus partial state | Pass | 1, 9.2, 15 and `INV-071`–`075`, `124`. |
| U-11 secret-free snapshot overclaim | Pass | 11.2 and `INV-084`–`087`. |
| C-1 cleanup leases were deferred | Pass | 6.3 and `INV-045`–`047` make them foundation behavior. |
| C-2 I/O/bandwidth were deferred | Pass | 13 and `INV-101`–`106` make them bounded required dimensions. |
| C-3 transfer was deferred behind mounts | Pass | 9.1 and `INV-067`–`070` put transfer first. |
| C-4 broker was deferred behind push flow | Pass | 1, 11.3, 15 and `INV-088`–`089`, `124` retain a gated final profile. |
| C-5 per-command starvation was unclear | Pass | 7, 13 and `INV-049`, `101` give process/I-O limits and typed outcomes. |
| C-6 remote host control was deferred | Pass | 3.1–3.2 and `INV-002`–`008` make it foundation. |
| C-7 snapshot encryption was optional | Pass | 14.3 and `INV-115` require production encryption/integrity. |
| C-8 recommended foundation/profile split | Pass | 1, 15, 17 and `INV-071`, `090`, `110`, `113`, `124`, `141` retain all profiles while independently gating them. |

These 47 historical corrections pass only against the historical scope. The
newer host-protocol authority added after that review is the P0 exception
described next.

## Remaining findings

### P0-1 — The binding host-control protocol is missing from the sandbox contract

The accepted host-protocol ADR and `SBX-040`–`SBX-044` require durable host
enrollment and identity, mutual authentication, credential rotation/revocation,
compatibility and attestation limits; an authenticated versioned envelope;
durable assignment/renewal/fencing/quarantine; non-overlapping control/core/
host/Jailer authority; and public-seam acceptance tests.

The revised sandbox specification instead stops at an “authenticated host-agent
control channel,” records Host ID/generation and says a dispatch envelope has
some fields. It does not specify enrollment, mutual-auth material and rotation,
revocation/quarantine behavior, attestation limits, replay detection, a
protocol version, explicit host assignment or the capability snapshot in the
envelope. Nor does it define how intentional at-least-once redelivery returns a
prior receipt while a malicious replay is refused. Its scope sentence ends at
`SBX-039`, and inventory coverage has no rows or evidence for `SBX-040` through
`SBX-044`.

Required correction: make the ADR's protocol concrete in the sandbox body,
add all five requirement IDs to its scope and inventory, and add test rows
covering every acceptance-ledger case. Define envelope signing/authentication,
encryption where required, nonce/delivery versus operation identity, receipt
replay handling, host result fencing, sequence ownership, quarantine and
reassignment. The public S9 seam, not a host internal, must prove this.

### P0-2 — The declarative sandbox infrastructure contract is not explicit enough

Section 3.3 is a useful policy-object catalogue, but it is not yet a complete
declarative resource contract. It does not state that the typed versioned Stack
is the sole local/CI/production rendering input. It also lacks declared
resources and ownership/lifecycle metadata for control/host mTLS Secret
references and rotation, host enrollment/revocation authority, Kubernetes
service accounts/RBAC, control/host/proxy NetworkPolicies and services/ports,
PostgreSQL/outbox persistence and migrations, output/artifact storage,
telemetry, backup/restore owner, safe delete/tombstone and rollback behavior.

This violates `INF-001`–`INF-005`, the project-wide declarative-infrastructure
contract and the user's explicit requirement. It is especially material because
the omitted host-trust objects are security controls, not ordinary deployment
details.

Required correction: add a sandbox resource/authority matrix tied to the
typed Stack and deterministic render/check/diff/reconcile contract. For every
owned resource/reference, declare owner, scope, dependency, finite limit,
retention, backup/restore owner, delete/tombstone behavior, external-controller
status and runtime RBAC denial. Add the renderer/policy/two-stack and
operator-reconcile evidence rows rather than relying on prose that a future
renderer will exist.

### P1-1 — The public control interface is not yet compileable or complete enough to certify

The method-level interface is directionally coherent and is a sound replacement
for the historical `Provider` pass-through. However, `OperationRequest`,
`Operation`, all `*Info` values, references, cursors, streams, pages and public
failure/result types have no definitions anywhere in the repository. The
specification delegates their zero values, wire form, bounds, authorization,
idempotency, cancellation and failure semantics to a future generated
reference.

Required correction: check in a compile-only public API package/example (or a
complete API appendix that is compiled as a fixture) before the first public
control ticket. It must expose the tagged request union and result/stream
shapes needed for `Submit`, terminal status, `WatchOperation`, output replay,
pagination and all operation kinds. Wire it to `SBX-011` and `SBX-012` evidence.

### P2-1 — Inventory evidence is traceable but needs a stronger completion hook

For `SBX-001`–`SBX-039`, every inventory row has a requirement, a sandbox-body
link and an acceptance-ledger evidence family. That is good M0 traceability,
not a green implementation test. Rows 139–140 use the free-text “Linux/KVM
release benchmark” rather than a stable ledger identifier, and the inventory
has no owner/ticket field. This is not a scope cut, but it will make automated
completion reporting weaker than it needs to be.

Required correction: give benchmark evidence a ledger ID and ensure the
planned verifier emits each inventory row's requirement, seam/profile, test or
evidence artifact, proof level and status. Add ownership/work-item linkage
when implementation tickets are created.

## Required rerun evidence

This review may change to pass only after all of the following are committed:

1. `sandbox.md` explicitly implements `SBX-040`–`SBX-044` and reconciles
   at-least-once delivery with malicious-envelope replay refusal.
2. The feature inventory gains exhaustive rows for those requirements, with
   body links and the exact acceptance-ledger evidence families.
3. The declarative Stack/resource authority matrix covers sandbox control,
   host agents and their security dependencies under `INF-001`–`INF-005`.
4. A compileable public API fixture/reference makes all types in the `Client`
   signature concrete and proves `SBX-011`/`SBX-012` semantics.
5. The acceptance review confirms all original review findings and current
   binding requirements are represented without deleting any final profile.

Until then, the pass-3 disposition's statement that all 77 historical findings
are resolved is accurate only relative to the older review scope. It is not
evidence that the current binding sandbox contract is ready for implementation.
