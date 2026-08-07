# Sandbox specification gate-repair evidence

Status: author repair traceability; this is not an independent re-review and
does not claim implementation or green acceptance tests.

Purpose: map every exit criterion in
[sandbox-acceptance-review.md](sandbox-acceptance-review.md#required-rerun-evidence)
to the repaired binding contract, inventory rows and exact acceptance-ledger
families. All listed inventory rows remain unchecked until their implementation
evidence is real and green.

This record also maps the subsequent failed
[sandbox-gate-rereview.md](sandbox-gate-rereview.md) P0/P1 contract corrections.
It is still an author record, never a substitute for the next independent
review.

## Exit-criterion mapping

| Acceptance-review exit criterion | Repaired specification contract | Inventory rows | Required acceptance evidence |
| --- | --- | --- | --- |
| 1. Explicitly implement `SBX-040`–`SBX-044`, including safe at-least-once delivery versus malicious replay refusal. | [3.3 Host enrollment, authenticated envelopes and fencing](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing) defines durable enrollment, mTLS, rotation/revocation, attestation limits, versioned signed/encrypted envelopes, envelope/delivery identity, receipt-keyed lost-ack behavior, stale/nonce/signature refusal, signed host results, sequence ownership, quarantine and reassignment. [3.6 Authority boundary](sandbox.md#36-authority-boundary) defines enforcement ownership. | `INV-144`–`INV-151`; supporting `INV-006`–`008`, `020`, `041`–`047`, `060`–`061`. | `SBX-040`, `SBX-041`, `SBX-042`, `SBX-043`, `SBX-044`. |
| 2. Gain exhaustive host-protocol inventory rows with body links and exact ledger families. | The scope names `SBX-001`–`SBX-044`; sections [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing) and [3.6](sandbox.md#36-authority-boundary) provide the linked contract. | `INV-144`–`INV-151`, each names its exact requirement and evidence family. | `SBX-040`–`SBX-044`. |
| 3. Cover sandbox control, host agents and security dependencies in a typed declarative Stack/resource authority matrix under `INF-001`–`INF-005`. | [3.4 Declarative Stack, resource ownership and reconciliation](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation) makes `SandboxStack/v1` the sole renderer input and declares every Stack resource/reference’s owner, scope, dependency, finite lifecycle, backup/restore, deletion/tombstone, external-controller and runtime-RBAC denial. It includes control/host workloads, trust and enrollment, database/outbox/migrations, RBAC, networks/services/ports, proxy, stores, telemetry and Temporal reference. | `INV-009`–`016`, `152`–`155`. | `INF-001`, `INF-002`, `INF-003`, `INF-004`, `INF-005`; supporting `DEP-005`, `DEP-007`. |
| 4. Make every `Client` signature type concrete and prove `SBX-011`/`SBX-012` public semantics. | [4.3 Compileable public API reference](sandbox.md#43-compileable-public-api-reference) now includes `NewClient`, validated endpoint/TLS/credential-source construction, IDs/request/body/target/result/event/stream/cursor/page/info/failure types, tagged shape matrix and all operation kinds without backend leakage. [4.4 Public API field and method semantics](sandbox.md#44-public-api-field-and-method-semantics) defines zero, strict wire, bounds, authorization, idempotency, cancellation, concurrency, uncertain outcome and stable failure behavior. | `INV-021`–`027`, `051`, `131`, `156`–`157`, `159`–`163`. | `SBX-003`, `SBX-007`, `SBX-011`, `SBX-012`, `SBX-015`, `SBX-017`, `SBX-018`. The first public-control implementation ticket must compile the stated fixture; no implementation fixture is claimed in this planning repair. |
| 5. Confirm original findings and binding requirements remain represented without deleting a final profile. | [1 Binding decision and release scope](sandbox.md#1-binding-decision-and-release-scope) retains every final profile; [15 Capabilities, SPI and adapters](sandbox.md#15-capabilities-spi-and-adapters) retains independent gates. The host, Stack and API additions are additive. [sandbox-review-disposition.md](sandbox-review-disposition.md#current-contract-gate-traceability) narrows its historical claim and points here rather than asserting a new independent pass. | `INV-001`–`158`, particularly `INV-071`, `090`, `110`, `113`, `124`, `141`, `144`–`157`. | `SBX-039`, `TST-009`, `TST-010`, plus every named row’s own evidence family. |

## Review finding to repair location

| Finding | Repair location | Inventory/evidence hook |
| --- | --- | --- |
| P0-1 Host-control protocol absent | [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing), [3.6](sandbox.md#36-authority-boundary) | `INV-144`–`151`; `SBX-040`–`044`. |
| P0-2 Declarative resource contract incomplete | [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation) | `INV-009`–`016`, `152`–`155`; `INF-001`–`005`. |
| P1-1 Public API types/semantics incomplete | [4.3](sandbox.md#43-compileable-public-api-reference), [4.4](sandbox.md#44-public-api-field-and-method-semantics) | `INV-156`–`157`; `SBX-011`–`012`. |
| P2-1 Completion traceability weak | inventory [rows 139–140](sandbox-feature-inventory.md#i-verification-performance-and-release-gate) now use `TST-008`; [row 158](sandbox-feature-inventory.md#j-host-trust-boundary-stack-evidence-and-api-certification) requires stable requirement/profile/seam/work-item/proof/status emission. | `INV-139`, `INV-140`, `INV-158`; `TST-008`, `TST-009`. |

## Second author repair: independent gate P0/P1 findings

This table records the prior author pass. Its domain/IP network correction was
subsequently rejected by the second independent re-review and is superseded by
the third-author table below; it is retained only as repair history.

| Gate finding | Repaired specification contract | Inventory/evidence hook | Required independent check |
| --- | --- | --- | --- |
| P0-1 — Network authority was an ambiguous `Names []string`. | The prior pass introduced `NetworkGrantSelection` and `NetworkRule` with domain/IP targets. The typed shape fixed ambiguous names but wrongly added literal-IP authority; the current replacement is recorded below. | Historical hooks were `INV-033`–`034`, `076`–`079`, `090`–`098`, `159`; ledger families `SBX-011`, `SBX-012`, `SBX-034`, `SBX-037`, `SBX-038`. | Superseded: current independent check must prove domain-only authority and direct-IP refusal. |
| P1-1 — No public construction path. | [4](sandbox.md#4-public-durable-control-interface) and [4.3](sandbox.md#43-compileable-public-api-reference) define `NewClient(ctx, ClientConfig)` with endpoint/TLS/credential-source validation and local `Close` ownership. | `INV-021`, `022`, `160`; ledger families `SBX-003`, `SBX-011`, `SBX-012`. | Compile exact API; verify no Principal/backend/ambient credential/insecure TLS construction path exists. |
| P1-2 — Result/event/attachment/failure states ambiguous. | [4.3](sandbox.md#43-compileable-public-api-reference) declares tagged target/result/event types, pointer attachment and finite Failure code/detail types. [4.4](sandbox.md#44-public-api-field-and-method-semantics) supplies the exhaustive 16-kind result matrix and public failure mapping. | `INV-027`, `034`, `161`; ledger families `SBX-011`, `SBX-012`, `SBX-015`, `SBX-017`, `SBX-018`. | Compile exact API and inspect every impossible mixed payload, unattached volume, unknown code/detail and typed-limit case. |
| P1-3 — Capability Snapshot was a feature string bag. | [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing) defines control-signing-key lifecycle; [4.3](sandbox.md#43-compileable-public-api-reference) declares structured descriptors and `KeyLifecycle`; [15](sandbox.md#15-capabilities-spi-and-adapters) defines negotiation/recheck/fail-closed semantics. | `INV-119`–`122`, `146`–`147`, `162`; ledger families `SBX-024`, `SBX-040`, `SBX-041`. | Verify Snapshot expresses every required profile dimension, carries no secret/key material, and fails on expired/revoked/regressed lifecycle. |

## Third author repair: second re-review P0/P1 findings

| Gate finding | Repaired specification contract | Inventory/evidence hook | Required independent check |
| --- | --- | --- | --- |
| P0-1 — Literal IP grants contradicted SBX-037. | [4.3](sandbox.md#43-compileable-public-api-reference) removes `IPAddress` and makes `NetworkRule` domain/protocol/ports only. [4.4](sandbox.md#44-public-api-field-and-method-semantics), [5.2](sandbox.md#52-canonical-schema), [10](sandbox.md#10-grant-truth-table) and [12](sandbox.md#12-egress-profile-invariant) reject all literal IPv4/IPv6/CIDR/host-port inputs while retaining proxy-only resolver normalization, prohibited-range refusal and per-connection pinning. | `INV-033`–`034`, `076`–`079`, `090`–`098`, `159`; `SBX-011`, `SBX-012`, `SBX-034`, `SBX-037`, `SBX-038`. | Search/extract exact API; inspect dotted/integer/short IPv4, bracketed/unbracketed/scoped/mapped IPv6, CIDR and host-port rejection; confirm resolver IP handling grants no IP authority. |
| P1-1 — Operation Result absence was ambiguous. | [4.3](sandbox.md#43-compileable-public-api-reference) declares `Operation.Result *OperationResult`. [4.4](sandbox.md#44-public-api-field-and-method-semantics) defines nil/canonical-null and exact Result/Failure combinations for every Operation state, including retained outcome during cleanup and absent details after expiry/tombstone. | `INV-027`, `034`, `161`; `SBX-011`, `SBX-012`. | Compile API and reject empty non-nil Result, wrong Kind/payload, omitted wire fields and every invalid state/result/failure combination. |
| P1-2 — Synchronous errors lacked public Failure inspection. | [4.3](sandbox.md#43-compileable-public-api-reference) adds immutable `Error`, defensive `Failure()`, `AsFailure`, context-only `Unwrap` and cancellation/deadline codes. [4.4](sandbox.md#44-public-api-field-and-method-semantics) applies the contract to construction, RPCs, stream Next/Close and Client Close without backend/source causes. | `INV-021`, `027`, `131`, `161`; `SBX-011`, `SBX-012`, `OBS-003`. | Compile and conformance-test direct/wrapped AsFailure, defensive copies, safe formatting, context `errors.Is`, arbitrary error refusal and backend/source cause non-disclosure. |
| P1-3 — CredentialSource lifecycle was undefined. | [4](sandbox.md#4-public-durable-control-interface) defines per-outbound-attempt fresh sinks, concurrent Apply, injected-clock single-writer refresh, waiter cancellation, expired/rejected/ambiguous outcomes, exact-origin header scope/clearing and Client Close revocation/wait behavior. [4.3](sandbox.md#43-compileable-public-api-reference) makes sink set failures and clearing explicit. | `INV-022`, `160`; `SBX-003`, `SBX-011`, `SBX-012`. | Race/fake-clock tests prove one refresh writer, independent waiter cancellation, no partial/expired/rejected publish, sink revocation on every path, no redirect/request/client boundary leak and bounded idempotent Close. |

## Fourth author repair: principal-pinning P0

| Gate finding | Repaired specification contract | Inventory/evidence hook | Required independent check |
| --- | --- | --- | --- |
| P0-1 — Per-attempt credentials could authenticate as a different Principal under one Client. | [3.7](sandbox.md#37-principal-and-authorization) now requires a construction-time authenticated no-operation bind handshake and an internal opaque server-authenticated assertion pinning canonical authority/issuer, tenant and subject. [4](sandbox.md#4-public-durable-control-interface) makes the construction Apply/handshake the single binding linearization and requires every refresh, retry, same-origin redirect, reconnect and assertion renewal credential to re-authenticate as the exact same identity before lookup/ledger/policy/operation effects. Same-identity rotation is allowed; any identity change is non-enumerating `FailureNotFoundOrDenied`, safe-audited, no-effect and cannot rebind. Construction cancel/install, immediate Close and concurrent constructor/first-request behavior are exact. | Updated `INV-017`, `021`, `022`, `160`; new `INV-163`; `SBX-007`, `SBX-011`, `SBX-012`. | Deterministic race/fake-clock vectors must distinguish ordinary same-identity rotation from authority, tenant or subject switching at construction, concurrent first calls, refresh, retry, redirect, reconnect and renewal; prove no operation/idempotency lookup before match, no rebind, safe audit fields only, install-vs-cancel linearization and Close clearing. |

## Author validation performed

- Scope/search coverage confirms `SBX-040`–`SBX-044` appear in the binding
  specification and inventory and each maps to its acceptance-ledger family.
- The Stack matrix makes all required lifecycle columns explicit instead of
  relying on an implied future renderer.
- The Go API declaration block was extracted to an ephemeral module, formatted
  and compiled with `go test`; it is not claimed as a built sandbox library or
  a passing sandbox test suite.
- Markdown links and whitespace are checked in this author pass. The required
  independent re-review remains the authority for changing acceptance-review
  gate status.
- The second repair extends the compile fixture and inventory to 162 unchecked
  rows. Its final extraction/compile and link/coverage validation are retained
  below when this author pass completes; an independent reviewer must still
  decide whether the P0 gate is clear.

## Second author validation (2026-08-06)

- Extracted the exact `package sandbox` block from section 4.3 into a fresh
  temporary Go 1.26.5 module, ran `gofmt`, then `go test ./...`: exit 0. The
  constructor body remains an explicitly labelled reference stub; this proves
  declaration syntax only and is not production code.
- Checked 202 local Markdown links across the specification, inventory,
  disposition and this evidence record: 0 missing files or anchors.
- Counted 162 unique, unchecked inventory rows (`INV-001` through `INV-162`).
  Literal traceability checks found all `SBX-001` through `SBX-044` and
  `INF-001` through `INF-005` in both specification and inventory.
- Ran `git diff --check`: exit 0.

The next required action is an **independent** gate re-review. This author pass
does not change `sandbox-gate-rereview.md` from failed, does not start sandbox
implementation, and does not check any inventory row.

## Third author validation (2026-08-06)

- Extracted the exact section 4.3 `package sandbox` block into a fresh temporary
  Go 1.26.5 module. `gofmt`, `go test ./...` and `go vet ./...` each exited 0;
  the formatted declaration fixture is 801 lines. This remains declaration
  proof only, not production implementation.
- Confirmed the extracted API has no `IPAddress` type or IP field in
  `NetworkRule`, uses `Result *OperationResult`, exports `Error`/`AsFailure`,
  and gives `CredentialSink` explicit set-error and clear operations.
- Checked 219 local Markdown file/anchor links across the specification,
  inventory, disposition, author evidence and independent re-review: 0 missing.
- Counted 162 unique unchecked inventory rows, exactly `INV-001` through
  `INV-162`, and found every `SBX-001` through `SBX-044` and `INF-001` through
  `INF-005` in both specification and inventory.
- Confirmed no literal-IP grant type or authority phrase remains in the current
  specification, inventory or disposition. IPv4/IPv6 now appears only in
  fail-closed input and proxy-resolver validation contracts.
- Whitespace checks over all five gate documents exited 0, and the current M0
  `just check` gate completed successfully (requirement-manifest drift, all Go
  tests, `go vet`, and no-real-wait scan).

This is third-author evidence only. The independent re-review remains failed
until a different reviewer reruns its gate; no implementation ticket, inventory
checkmark, commit, push or Issue closure is authorized by this record.

## Fourth author validation (2026-08-06)

- Extracted the exact section 4.3 `package sandbox` block into a fresh temporary
  Go 1.26.5 module. `gofmt`, `go test ./...` and `go vet ./...` each exited 0;
  the formatted declaration fixture is 802 lines. No public Principal-binding or
  binding-assertion type is exported.
- Checked 220 local Markdown file/anchor links across the specification,
  inventory, disposition, author evidence and independent re-review: 0 missing.
- Counted 163 unique unchecked inventory rows, exactly `INV-001` through
  `INV-163`, and found every `SBX-001` through `SBX-044` and `INF-001` through
  `INF-005` in both specification and inventory.
- Confirmed there is no remaining contract saying Apply is absent from
  construction. Construction binds once before Client publication; the
  rotation-versus-identity-switch and no-rebind acceptance hook is `INV-163`.
- Whitespace checks over all five gate documents exited 0, and the current M0
  `just check` gate completed successfully (manifest drift, module integrity,
  race tests, `go vet`, no-real-wait scan and complete-catalog ledger report).

This is fourth-author evidence only. The independent re-review remains failed
until a different reviewer reruns its gate; no production implementation,
inventory checkmark, commit, push, Issue closure or acceptance claim is
authorized by this record.
