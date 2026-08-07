# Sandbox implementation-gate independent re-review

## Final independent re-review — 2026-08-06

This fourth pass independently reviewed the current
[sandbox specification](sandbox.md), 163-row
[feature inventory](sandbox-feature-inventory.md),
[review disposition](sandbox-review-disposition.md),
[author repair evidence](sandbox-gate-repair-evidence.md), Issue #6's latest
author comment, binding requirements, seams/invariants, acceptance ledger and
every accepted ADR. Author validation was treated as a claim and repeated.
Unchecked inventory rows remain implementation plans, not completed evidence.

## Gate results

| Gate | Result | Independent basis |
| --- | --- | --- |
| Original 77-finding contract corrections | Pass | Durable control, ledger/recovery, immutable inputs, grant defaults, lifecycle, security profiles and final-release scope remain represented. No requested profile was removed or weakened. |
| SBX-040–SBX-044 host-control protocol | Pass | Enrollment, TLS 1.3 mutual authentication, credential/signing-key rotation and revocation, bounded attestation, canonical signed/encrypted envelopes, receipt/replay distinction, fencing, sequencing, quarantine, reassignment and non-overlapping authority remain explicit. |
| INF-001–INF-005 Stack/ownership/lifecycle | Pass | `SandboxStack/v1` remains the sole renderer input. The ownership matrix covers resources/references, owners, scope/dependencies, finite lifecycle, restore/deletion and runtime-RBAC denial, with render/diff/reconcile/two-stack evidence. |
| Domain-only SBX-037 authority | Pass | `NetworkRule` contains only protocol, domain and ports. Every literal IPv4/IPv6, CIDR and host:port form is refused; the proxy alone resolves permitted domains, filters and pins answers, and guests have no direct route. |
| Result and failure API | Pass | `Operation.Result` is pointer-optional with an exact state/null matrix. Exported `Error`, defensive `Failure()`, `AsFailure`, complete public codes and context-only unwrap semantics classify every synchronous construction/call/stream/Close failure without backend causes. |
| Credential attempt and refresh lifecycle | Pass | Construction and every outbound retry/redirect/reconnect/renewal use fresh origin-bound sinks. Concurrent refresh has injected-clock, finite-timeout, single-writer and atomic-publication rules; cancellation, rejection and ambiguity fail safely; headers/sinks are cleared or revoked; `Close` is bounded, concurrent and idempotent. |
| Authenticated Principal binding | Pass | `NewClient` completes an authenticated no-operation bind before publishing a Client, and only the transport retains the opaque finite-lived assertion. No public type/config/request can select, read, replace or serialize its authority, tenant or subject. |
| Identity continuity | Pass | Every refresh, retry, same-origin redirect, stream reconnect and assertion renewal re-authenticates the fresh credential and compares exact canonical authority/issuer, tenant and subject before object lookup, idempotency access, policy evaluation or operation effects. Same-identity credential rotation is allowed; any identity switch is refused. |
| Mismatch effects and audit | Pass | Identity mismatch returns non-enumerating `FailureNotFoundOrDenied`, performs no sandbox/control operation, never retries under or rebinds to the new identity, and cannot replace the pin. Its bounded audit fact contains only opaque correlation, attempt class and outcome—never credentials, authorization headers, raw tenant/subject, issuer claim, token version or authentication response. |
| Bind/cancel/install/Close races | Pass | Assertion installation after authenticated validation is the sole construction linearization point. Cancel-before-install returns no Client and clears the sink; install-before-cancel returns the bound Client; concurrent constructors remain independent; first requests occur only after binding; immediate and concurrent Close use the normal bounded rules and successful Close clears the assertion. |
| Public API mechanical compileability | Pass | Extracted the exact section 4.3 Go block, source lines 480–828, into a fresh Go 1.26.5 module. `gofmt`, `go test ./...` and `go vet ./...` exited 0; the formatted declaration fixture is 802 lines and exports no Principal binding/assertion type. |
| Inventory and binding-ID coverage | Pass | Independently counted exactly 163 unique unchecked rows in the exact sequence `INV-001`–`INV-163`, with zero duplicates/checkmarks. Every INF-001–INF-005 and SBX-001–SBX-044 occurs in both specification and inventory. |
| Local documentation links | Pass | Independently resolved 220 local Markdown file/anchor links across the five gate documents; none was missing. |
| Repository verification | Pass | A fresh `just check` completed manifest drift, module integrity, race tests, vet, no-real-wait and complete-catalog/ledger structural validation. Final `just verify` is expected to fail while ledger rows remain non-green. This is supporting repository hygiene, not sandbox implementation evidence. |

## Principal-pinning security verification

The prior P0 exit criterion is satisfied by the combined contracts in
[section 3.7](sandbox.md#37-principal-and-authorization) and section 4:

1. Control authenticates the construction credential and derives canonical
   authority/issuer, tenant and subject; the caller and credential source do
   not supply the binding identity.
2. A finite-lived server-authenticated assertion is installed before Client
   publication and retained only inside the transport. The assertion alone is
   non-authorizing and always requires a currently authenticated credential.
3. Every later attempt, including refresh, retry, same-origin redirect, stream
   reconnect and renewal, applies a fresh credential and must match all pinned
   identity fields before lookup, ledger access, authorization or operation
   effects. Refresh success alone cannot establish continuity.
4. Ordinary token/certificate/signing-key rotation succeeds only for the same
   identity. Authority, tenant or subject changes use one non-enumerating
   refusal, create no operation effect, do not retry under the new identity and
   cannot replace or widen the binding. A later credential for the original
   identity remains usable only while the assertion is valid.
5. Renewal requires both the old valid assertion and a matching current
   identity. Expiry requires a new Client construction; it is not a lazy rebind.
6. INV-160 and INV-163 require deterministic race/fake-clock vectors covering
   construction, concurrent first calls, refresh, retry, redirect, reconnect,
   renewal, same-identity rotation, each identity-switch dimension, safe audit,
   no effect/no rebind, install-versus-cancel and immediate Close.

This is consistent with SBX-007's construction-bound non-forgeable
Principal/tenant requirement
([master requirements](../planning/requirements/master-requirements.md#sandbox-durable-control-plane-and-core-contract))
and with the Principal-scoped ledger, object, resolver, store, audit and host
envelope rules. No stale statement says credential application is absent from
construction, no binding value crosses the public API or canonical wire, and
no accepted ADR supplies a competing identity or authority path.

## Findings and scope

No P0 or P1 contract finding remains. No new contradiction, security escape,
API trap or scope cut was found. The new binding handshake and INV-163 are
within Issue #6's SBX-007/SBX-011/SBX-012 contract-correction scope and do not
claim a production implementation, completed inventory row, hostile-tenant
isolation proof or milestone completion.

## Implementation verdict

**PASS.** Issue #6's sandbox contract gate has passed, but Issue #6 remains open
until its native blocker Issue #2 is satisfied. Downstream sandbox implementation
may begin only after each issue's native dependency blockers are satisfied; this
contract pass does not waive Issue #2 or any other work-map edge.
Production/security/profile claims remain gated by their own unchecked
inventory rows and required implementation, integration and Linux/KVM evidence.
