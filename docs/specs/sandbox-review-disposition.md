# Sandbox review disposition

Status: binding pass-3 disposition of the pass-2 sandbox review supplied to
this planning task.

Every actionable finding is resolved. None is rejected or down-scoped. When the
review recommended a smaller initial security claim, the resolution is an
independently gated profile that remains a required final-release feature; it
is not a deletion. Section pointers are to
[sandbox.md](sandbox.md) and inventory identifiers are in
[sandbox-feature-inventory.md](sandbox-feature-inventory.md).

## P0 blockers

| Finding | Disposition | Resolution pointer |
| --- | --- | --- |
| P0-1 Stable IDs could not recover/control after crash | Resolved | Durable client Get/Wait/Watch/Replay/control by ID, host routing and restart semantics: sections 3.2, 4 and 6.2; INV-006–008, INV-021–026, INV-042. |
| P0-2 Exec and other mutations lacked retry safety | Resolved | Every mutator is an Operation; receipt journal, uncertain result and external-effect limitation: sections 4, 6.1–6.2; INV-023, INV-037–044. |
| P0-3 Request ID durability/namespace/reconciliation undefined | Resolved | Principal-scoped ledger, canonical request, retention/tombstone, transaction/outbox and reconciliation: sections 3.4, 5, 6; INV-031–044. |
| P0-4 Grant omission widened authority | Resolved | Explicit none/select/inherit truth table and no-authority default: section 10; INV-076–079. |
| P0-5 Go Specs were shallow mutable | Resolved | Deep copy/freeze, bounded reader artifact and canonical acceptance pipeline: section 5.1; INV-028–030. |
| P0-6 Tenant/principal ownership absent | Resolved | Construction-time authenticated bind pins one opaque authority/tenant/subject; every credential refresh/retry/redirect/reconnect/renewal re-authenticates to that binding, identity mismatch is non-enumerating/no-effect/no-rebind, and every object is authorized against it: sections 3.7 and 4; INV-017–022, INV-160, INV-163. |
| P0-7 Secret taint did not survive persistent data | Resolved | SDK-known taint definition, volume propagation, unknown path and snapshot attestation/denial: section 11.2; INV-084–087. |
| P0-8 Public Provider bypassed core enforcement | Resolved | Public durable client plus internal normalized Backend SPI and malicious adapter test: sections 3.1, 15; INV-005, INV-125–126. |
| P0-9 Network claim lacked implementable invariant | Resolved | Mandatory authenticated proxy, no direct route and typed domain/protocol/port authority only; proxy-resolved IPv4/IPv6 answers are validated/pinned and every guest literal IP fails closed: sections 4.4 and 12; INV-076–079, INV-090–098, INV-159. |
| P0-10 Resource/availability gaps | Resolved | Finite Effective Spec, limits versus admission and full hostile-resource matrix: section 13; INV-099–106. |

## P1 major issues

| Finding | Disposition | Resolution pointer |
| --- | --- | ---|
| P1-11 Result could not express promised termination | Resolved | Typed ProcessResult and independent cleanup observation: section 7.2; INV-055–057. |
| P1-12 Exec context lifetime was ambiguous | Resolved | Separate StartDeadline, RuntimeLimit, lifetime ownership and wait cancellation: section 7.1; INV-053–054. |
| P1-13 Streaming/redaction/capture semantics conflicted | Resolved | Core spool/tee, per-stream sequence/gap, redactor algorithm and limits: section 8; INV-058–064. |
| P1-14 Host mounts were risky and not portable | Resolved without deletion | Portable transfer is prerequisite; RO/RW mount remains final gated profile with pinned source/daemon contract: section 9; INV-067–075. |
| P1-15 Helper pathname did not constrain secret recipient | Resolved | External broker or immutable admitted trusted-exec contract: section 11.3; INV-088–089. |
| P1-16 Snapshot storage API/semantics incomplete | Resolved | Manifest, quiesce/publish, inspect/list/lease/delete/restore and narrowed override: section 14.3; INV-113–118. |
| P1-17 Volume lifecycle too thin | Resolved | Manifest, generation lease, exclusive attach, reconcile/delete races and taint: section 14.2; INV-110–112. |
| P1-18 Lifecycle machine incomplete | Resolved | Desired/actual/process states and action race table; durable close/reaper: sections 6.3, 7; INV-045–050. |
| P1-19 File APIs unsafe/undefined | Resolved | Bounded artifact transfer, checksums, archive/path rules, mode/owner/atomic/cancel details: section 9.1; INV-065–070. |
| P1-20 Image admission outside contract | Resolved | Declared admission policy and safe admitted metadata/numeric identity: sections 3.3, 14.1; INV-012, INV-107–109. |
| P1-21 Resolver had no auth/version/expiry model | Resolved | Signed contextual resolver request, pinning, bounds, audit and ephemeral delivery: section 11.1; INV-080–083. |
| P1-22 Capability negotiation was boolean/incomplete | Resolved | Structured canonical capability descriptors, typed requirements, declared/enforced state, key lifecycle, negotiation and regression behavior: sections 3.3, 15; INV-011, INV-119–124, INV-162. |
| P1-23 Mandatory audit lacked transaction boundary | Resolved | Ledger/audit outbox transaction, at-least-once sink and synchronous-outage semantics: section 16; INV-129–130. |
| P1-24 Local adapter too easy to misuse | Resolved | Explicit acknowledgement, refusal of unprovable authority and synthetic resolver: section 15; INV-127–128. |

## P2 API and specification issues

| Finding | Disposition | Resolution pointer |
| --- | --- | --- |
| P2-25 Serialization was not designed | Resolved | Strict tagged-union canonical schema, duplicate/unknown handling, limits and goldens: section 5.2; INV-031–034. |
| P2-26 Paths, users and executable resolution were unclear | Resolved | Absolute argv command, numeric admitted identity and descriptor-relative paths: sections 7.1, 9.1, 14.1; INV-051–052, INV-065–066, INV-107–109. |
| P2-27 Error sanitization leaked nested causes | Resolved | Public `Error`/`AsFailure` exposes only a defensive safe Failure and standard context sentinel; backend/source causes never unwrap and authorized diagnostics remain separate: sections 4.3–4.4 and 16; INV-131–132, INV-161. |
| P2-28 Default evolution broke replay | Resolved | Versioned persisted Effective Spec and incompatible-policy result: section 5.3; INV-035–036. |
| P2-29 Performance objectives omitted mandatory paths | Resolved | Full-path benchmark declaration and saturation metrics: section 16; INV-139–140. |
| P2-30 Public API details were internally inconsistent | Resolved | Public `NewClient` construction, per-attempt credential lifecycle, single operation submission, typed target/pointer-result/event/failure unions, optional attachment, Client Close semantics and exhaustive reference table: sections 4.2–4.4, 7, 7.2, 14.2; INV-021–022, INV-027, INV-048–056, INV-110, INV-160–161. |

## Temporal consumption review

| Finding | Disposition | Resolution pointer |
| --- | --- | --- |
| T-1 Where sandbox lives relative to workers | Resolved | Durable control and host-agent ownership, never activity-local: sections 3.1–3.2; INV-002–008. |
| T-2 Who owns long-lived sandbox between activities | Resolved | Control ledger/resource desired state owns it; activity holds IDs only: sections 3.1, 6; INV-001–004, INV-037–046. |
| T-3 How retries route to owning host | Resolved | Persisted Host ID/generation and fenced router: section 3.2; INV-006–008. |
| T-4 Durable boundary for output | Resolved | Core durable redacted spool with sequence/gap/final state: sections 4.1, 8; INV-025, INV-058–064. |
| T-5 Side-effect policy | Resolved | Exec deduplication plus visible uncertain outcome and application idempotency disclaimer: section 6.2; INV-042–044. |
| T-6 Cancellation after activity worker death | Resolved | Workflow submits durable kill/close; reaper owns cleanup: sections 6.3, 16; INV-046, INV-134. |
| T-7 Cleanup after deploy/host failure | Resolved | Leases, fencing, reaper and cleanup observations: sections 3.2, 6.3; INV-008, INV-045–047. |
| T-8 Heartbeat recovery | Resolved | Operation Get/Wait/Watch/Replay by ID plus result/output state: section 4; INV-021–026. |
| T-9 Workflow-history payload rule | Resolved | IDs/effective references/cursors only; no handles/output/secrets: section 16; INV-133. |
| T-10 Retry decision policy | Resolved | Separate validation/control/policy/result/loss/unknown effect outcomes: sections 4.1, 6.2, 16; INV-043–044, INV-134. |

## Inventory audit: omissions from the original draft

| Finding | Disposition | Resolution pointer |
| --- | --- | --- |
| Deep copy/freeze mutable inputs | Resolved | Section 5.1; INV-028–030. |
| Reconnect/lookup/control by sandbox/process ID | Resolved | Section 4; INV-021–026. |
| Exec/snapshot idempotency, retention and tombstones | Resolved | Sections 4, 6 and 14.3; INV-023, INV-037–044, INV-113–118. |
| Durable namespaced ledger and canonical policy version | Resolved | Sections 5–6; INV-031–044. |
| Principal ownership and authorization | Resolved | Section 3.4; INV-017–020. |
| Host routing for host-affine sandbox | Resolved | Section 3.2; INV-006–008. |
| Output replay/gap across connection loss | Resolved | Section 8; INV-060–064. |
| Durable leases for abandoned cancellation | Resolved | Section 6.3; INV-045–047. |
| Inode/file/network/control/storage limits | Resolved | Section 13; INV-099–106. |
| Secret size/version/expiry and volume-taint propagation | Resolved | Section 11; INV-080–087. |
| Snapshot/volume inspect, attachment reconciliation and encryption | Resolved | Section 14; INV-110–118. |
| Image admission evidence/effective policy | Resolved | Sections 3.3, 5.3 and 14.1; INV-012, INV-035–036, INV-107–109. |
| Exact Grant omission/inheritance semantics | Resolved | Section 10; INV-076–079. |
| Process termination reason model | Resolved | Section 7.2; INV-055–057. |
| Canonical tagged-union schema/strict decoder | Resolved | Section 5.2; INV-031–034. |
| Client Close and reaper ownership | Resolved | Sections 4, 6.3; INV-022, INV-046–047. |
| Egress reference data plane and invariant | Resolved | Section 12; INV-090–098. |
| Temporal artifact/output durability protocol | Resolved | Sections 8, 16; INV-058–064, INV-134. |

## Inventory audit: original inventory claims unsupported by API

| Finding | Disposition | Resolution pointer |
| --- | --- | --- |
| Resolved limits visible | Resolved | Effective Spec, desired-state inspection and SandboxInfo contract: sections 3.3, 5.3; INV-013, INV-035. |
| Snapshot retention/deletion/encryption store seam | Resolved | StoragePolicy plus snapshot manifest/lifecycle: sections 3.3, 14.3; INV-012, INV-113–118. |
| Mandatory audit sink | Resolved | Transactional audit outbox and sink semantics: section 16; INV-129–130. |
| Structured logs, metrics and traces | Resolved | Sanitized correlation/DiagnosticID contract: section 16; INV-131–132. |
| Versioned capabilities/matrix | Resolved | Structured snapshot/profile contract: sections 3.3, 15; INV-011, INV-119–124. |
| Timeout/OOM distinctions | Resolved | Typed ProcessResult: section 7.2; INV-055–057. |
| Cleanup-pending/confirmed observation | Resolved | Operation/reaper contract: sections 4.1, 6.3; INV-026, INV-046. |
| Streamed/atomic WriteFile and portable transfer | Resolved | Artifact transfer contract: section 9.1; INV-067–070. |
| Deterministic fake advertised as MVP | Resolved | Required fake profile with explicit no-execution claim: section 15; INV-128. |
| Firecracker mount mandatory while partial state ambiguous | Resolved without deletion | Feature remains final-release mount profile and false until security evidence: sections 1, 9.2, 15; INV-071–075, INV-124. |
| Secret-free snapshot claim | Resolved | Stated exclusions only and taint/attestation: section 11.2; INV-084–087. |

## Inventory audit: classification conflicts and recommended cut

| Finding | Disposition | Resolution pointer |
| --- | --- | --- |
| Leases were Later but needed by cleanup | Resolved | Durable leases/reaper are foundation requirements: section 6.3; INV-045–047. |
| I/O/bandwidth were Later despite availability claim | Resolved | Required IOPS/bandwidth/admission dimensions: section 13; INV-101–106. |
| Copy transfer was Later while mounts were primary path | Resolved | Portable transfer precedes mounts: section 9.1; INV-067–070. |
| Credential brokering was Later despite push flow | Resolved | Broker/trusted-exec is final required profile: sections 1, 11.3, 15; INV-088–089, INV-124. |
| Per-command resource starvation unclear | Resolved | Process limits and typed resource outcome belong to Effective Spec: sections 7, 13; INV-049, INV-101. |
| Remote/multi-host control was Later despite Temporal | Resolved | Durable host routing is foundation: sections 3.1–3.2; INV-002–008. |
| Snapshot encryption configurable against safety claim | Resolved | Production snapshot encryption/integrity mandatory: section 14.3; INV-115. |
| Recommended foundation/profile split | Resolved without deletion | Foundation/transfer first; every egress/mount/volume/snapshot/secret profile is final release gate: sections 1, 15, 17; INV-071, INV-090, INV-110, INV-113, INV-124, INV-141. |

## Disposition totals

There are 30 numbered P0/P1/P2 findings, 10 Temporal findings, 18 original
body-omission findings, 11 unsupported-claim findings and 8 classification/
scope findings: 77 review findings total. All 77 are resolved; 0 are rejected;
3 resolutions explicitly preserve a feature through a security-profile gate
rather than deleting it.

## Current-contract gate traceability

This disposition covers the historical 77-finding pass-2 review only. The later
binding `SBX-040` through `SBX-044`, `INF-001` through `INF-005`, and
compileable-public-API corrections are tracked additively in
[sandbox-gate-repair-evidence.md](sandbox-gate-repair-evidence.md). That author
repair record is not an independent re-review and does not change an unchecked
inventory row into implementation evidence. The second author pass additionally
repairs the independent gate's P0 typed network authority and P1 public
construction/result-event-attachment-failure/capability gaps at sections
3.3, 4.3–4.4, 5.2, 10, 12 and 15 with INV-159–162. The independent gate remains
failed until a new reviewer verifies those changes; no historical disposition
or author note authorizes sandbox implementation. The third author pass removes
the intervening literal-IP grant expansion, makes Operation Result absence a
pointer/null state contract, adds synchronous `Error`/`AsFailure`
classification, and specifies the concurrent CredentialSource/request-header/
Client-Close lifecycle. Its traceability is additive in the gate-repair
evidence; it does not alter the failed independent verdict.
The fourth author pass closes only the later principal-pinning contradiction by
making CredentialSource Apply participate in a construction-time authenticated
bind and requiring exact identity continuity thereafter. INV-163 holds its
rotation-versus-switch and race vectors. This author update still does not
alter the independent gate verdict.
