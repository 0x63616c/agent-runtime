# Agent Runtime — open risks and implementation gates

Status: active AFK risk register. This document lists risks and unavailable
external assets, not undecided product intent. The user has authorized the
public monorepo, local Tilt, direct-to-main development, a real sandbox, and
the three complete examples. Do not re-ask those decisions or quietly narrow
them.

## Closed design choices (do not reopen during implementation)

| Choice | Decision | Rationale / binding requirements |
|---|---|---|
| Repository topology | One public MIT monorepo, `0x63616c/agent-runtime`, containing one root Go module and all public packages. | MON-001–003 |
| Go release topology | One root Go module, root-package import paths and one semver release train; `go.work` is contributor-only convenience. | MON-003, MON-009 |
| Architecture authority | The master requirements, root glossary, accepted architecture and accepted ADRs are binding; supplied/copy drafts are historical input only. | MON-006–008 |
| Application interface | Runtime service with HTTP/OpenAPI and a small Go SDK; no Temporal exposure. | API-001–003, TMP-001–002 |
| Data and event authority | PostgreSQL is the v1 metadata/control/event/audit/outbox authority; Temporal orchestrates; object storage retains immutable large content. | DAT-009–013 |
| Infrastructure ownership | Owned infrastructure is explicit, typed, versioned desired state; runtime startup does not create it and reconciliation is an audited operator action. | INF-001–005 |
| Sandbox ownership | Durable sandbox control plane plus host agents, not activity-local in-process handles. | SBX-001–006 |
| Developer platform | Local isolated Kubernetes stack via Tilt; local sandbox is explicitly unsafe. | DEP-001–003, SBX-022 |
| Production sandbox proof | Firecracker on Linux/KVM in a dedicated integration lane. | SBX-021, DEP-007, TST-005 |
| Authority semantics | Deny by default; omitted command grants mean no sensitive authority; capabilities ship with individual profiles. | SBX-024–039 |
| Approval | Durable human approval is first-release functionality. | HITL-001–006 |
| Codex subscription support | Subscription support is a binding user requirement with current official support verification and protected live canary; API credentials are not a substitute. | MOD-001–005 |
| Milestone reporting | Completion records notify `ntfy.sh/0x63616c-ai-agant` with redacted evidence-derived status; failed delivery remains visible. | OPS-STAT-001–002 |
| Documentation | Docusaurus public site on GitHub Pages; repo-local docs skill and executable docs checks. | DOC-001–007 |
| Examples | Durable Chat, Workspace Agent, and Research Dossier are complete public-contract applications. | EX-001–006 |

## Sandbox review blockers traceability

The following records how the critical review is being resolved. A row is not
"closed" by writing it here; it closes only with its ledger evidence.

| Review finding | Resolution requirements | Gate |
|---|---|---|
| P0-1: stable IDs lacked recovery/control | SBX-001–003, SBX-013–014 | Cross-process attach/control/reaper test after worker/host restart. |
| P0-2: retries safe only for provisioning | SBX-004–006, SBX-015–017 | Operation-ID/reconciliation test at every acknowledgement boundary. |
| P0-3: request ledger undefined | SBX-005, SBX-008–009 | Durable tenant ledger, canonical Effective Spec, tombstone/expiry tests. |
| P0-4: Grant omission broad/ambiguous | SBX-034 | Published truth table and omitted/empty/widening conformance tests. |
| P0-5: Go inputs not immutable | SBX-008 | Mutation-after-submit race/property tests under `-race`. |
| P0-6: no tenant/principal authorization | SBX-007 | Cross-tenant negative and request-ID collision tests. |
| P0-7: secret taint overstated | SBX-031–033 | Volume laundering, snapshot attestation, and honest-claim review. |
| P0-8: Provider bypassed core | SBX-010, SBX-025 | Expert-only SPI plus malicious adapter conformance test. |
| P0-9: egress claim incoherent | SBX-037–038 | Mandatory-proxy reference data plane with explicit outcome tests. |
| P0-10: resource limits incomplete | SBX-018–019 | Enforcement/admission matrix includes all named exhaustion paths. |
| P1: terminal/cancel/stream semantics incomplete | SBX-015–017 | Typed-result and spool/tee race/conformance suite. |
| P1: mounts/snapshots/volumes/files incomplete | SBX-026–032 | Each feature profile has manifest/lease/transfer and adversarial tests. |
| P1: admission/resolver/capability/audit/local gaps | SBX-020–025, SBX-033, DAT-006–007 | Admission/resolver/capability/outbox/refusal suites. |
| Temporal consumption was activity-local | TMP-009–010, SBX-001–006, TST-005 | Different-worker retry and durable event/output reconciliation E2E. |

## Active risks

| ID | Risk / unavailable dependency | Likelihood / impact | Trigger or early indicator | Mitigation and stop rule | Owner / evidence to close |
|---|---|---|---|---|---|
| RSK-001 | A Linux host with KVM usable from the CI/integration lane may not be available to this workspace. macOS cannot prove Firecracker/KVM behavior. | Medium / release-blocking for Firecracker claims | `/dev/kvm` unavailable, nested virtualization disabled, or runner cannot start jailed Firecracker. | Build/test local and fake paths normally; provision or select a documented Linux/KVM runner. Do not replace the KVM suite with local/container tests or claim the production profile. | Release owner; retained `K` lane report, version matrix, `TST-005` green. |
| RSK-002 | A usable and officially supportable Codex subscription credential/model profile may be unavailable or its refresh semantics may differ from the planned adapter. | Medium / blocks the required subscription release gate; deterministic core work may continue | Current official verification rejects/does not document the path, model-role startup cannot authenticate, or protected canary fails. | Keep the model seam scripted for deterministic core progress; re-verify the official support/terms/protocol/credential lifecycle; bind real credentials only in model role. Do not substitute an API-key adapter or claim release support until the live subscription suite passes. | Model lane; sanitized official-verification record, protected canary and `MOD-001–005` evidence. |
| RSK-003 | GitHub Pages publishing permission or Actions token scope may not be enabled on the newly created repository. | Low / blocks public docs deployment | Pages workflow cannot configure/deploy despite successful local docs build. | Implement a Pages-native workflow and local build first; surface the exact repository setting/permission needed. Do not substitute a local-only site for deployment evidence. | Docs/release lane; public Pages URL and `DOC-001` workflow. |
| RSK-004 | The prescribed sandbox scope combines hard kernel/VM, filesystems, network proxying, secrets, durable control and security verification. A broad early implementation could create unprovable security claims. | High / high | A feature is coded before its durable control model, threat model, capability contract, or adversarial tests exist. | Sequence foundation then independently gated profiles. The final release still includes every requested profile, but each remains unavailable and unclaimed until its profile gate is green. | Sandbox lane; `SBX-021–039` release matrix. |
| RSK-005 | Host mounts are a particularly large file-sharing attack surface and may be incompatible with the selected Firecracker/host implementation. | High / high | No per-sandbox jailed sharing design can preserve source identity and pass traversal/TOCTOU/special-file tests. | Make portable copy-in/out the working path first. Keep host mount capability false until all mount suite tests pass; do not weaken confinement to make examples convenient. | Sandbox filesystem lane; `SBX-026–028` K evidence. |
| RSK-006 | Command-scoped in-guest secrets cannot safely be equated with a helper path; values can be copied or execution context subverted. | High / high | Proposed design grants a secret to arbitrary guest command/loader/workdir or relies only on path selection. | Implement an external broker or formally admitted trusted-exec capability with immutable provenance and constrained schema. Preserve explicit limitation that a recipient can disclose granted secret. | Security/tool lane; `SBX-033–036`, `TOL-003–006`. |
| RSK-007 | Egress allowlisting can accidentally overclaim application-level identity/DLP or permit bypass via guest routing, proxy, DNS, shared IP or DoH. | High / high | Design relies on only DNS-to-IP firewalling, unvalidated SNI/Host, guest-visible routable interface, or unbounded proxy paths. | Use mandatory proxy reference data plane and document only destination restriction. Run bypass matrix including metadata/direct IP/CNAME/IPv6/DoH/proxy outage. | Network lane; `SBX-037–038` K evidence. |
| RSK-008 | Snapshot safety can be overstated because arbitrary code may persist a secret from a declared secret, network, host mount or volume. | High / high | Docs/code call snapshots "secret-free" without provenance/taint/attestation proof. | Track only SDK-known exposure, propagate volume taint, deny/attest risky snapshots, inspect canary artifacts, and state limits precisely. | Storage/security lane; `SBX-030–033` evidence. |
| RSK-009 | Temporal activity retries can repeat irreversible external effects even with sandbox operation deduplication. | High / high | A tool retry reissues network/git/etc. command after lost acknowledgement with no external idempotency key. | Persist operation identity before schedule, reconcile sandbox result, require tool-specific external idempotency/uncertain outcome policy. Do not advertise exactly-once external effects. | Orchestration/tool lane; `TMP-009`, `TOL-006`, `TST-005`. |
| RSK-010 | Payload codec compatibility can break existing histories or leave Temporal UI unable to inspect new/old payloads. | Medium / high | A client/worker is constructed without converter, encoding order changes, or UI handler differs from local chain. | Single factory, startup round trip, golden compatibility corpus, two-consumer conformance test and versioned codec metadata. | Payload lane; `TMP-005–006`, `PAY-001–008`. |
| RSK-011 | Local Tilt may have missing Kubernetes/Tilt/registry or port conflicts, making the advertised easy start fail. | Medium / medium | Fresh checkout cannot form two isolated named stacks; a reset changes another stack. | Bootstrap prereq checks; deterministic stack-scoped names; full profile test using two names; direct diagnostics. | Deployment lane; `DEP-001–003`, `DEP-008`. |
| RSK-012 | Documentation can drift from generated public contract, runnable commands, or security evidence faster than prose review catches it. | Medium / high | API/config/example changes land without corresponding doc diff or a snippet becomes non-runnable. | Repo docs skill, doc coverage manifest, generated references, snippet harness, link/build/deploy CI gates. | Docs lane; `DOC-002–005`, `TST-008`. |
| RSK-013 | AFK multi-agent work can lose requirement context, overlap ownership, or assert completion without cross-lane evidence. | Medium / high | A commit implements a feature without a requirement ID, ledger test, seam or docs update. | Persist this baseline in-repo; issue/task templates reference IDs/seams; `just verify` rejects unreported requirements; independent review is a release gate. | Program/review lane; `MON-005`, `TST-009–010`. |
| RSK-014 | Dependency/API drift in Temporal, Codex, Firecracker, Docusaurus, Kubernetes/Tilt or Go can invalidate an assumed interface. | Medium / medium | Pin update changes generated contracts, replay/codec behavior, KVM profile, or docs build. | Pin versions and compatibility matrix; use official docs/release notes during bootstrap; run upgrade conformance/replay/docs checks before promotion. | Each module owner; ADR/lockfile/update evidence. |
| RSK-015 | Public repository history could accidentally contain model credentials, test secrets, payloads, artifacts, or source copied without attribution/license review. | Low / critical | Secret scanner finds data; reuse audit lacks source/provenance. | Use synthetic secrets, deny secret fixtures in docs/tests, scan history/working tree, record copied Software Factory source provenance/license. Treat discovery as immediate security response, not a cleanup after release. | Security/release lane; scan report, `MON-004`, `OBS-003`. |
| RSK-016 | Declarative renderer, ownership catalog and policy gates do not yet exist, so a future bootstrap path could accidentally create infrastructure or hide defaults. | Medium / high | A binary, workflow, migration or helper mutates infrastructure; a rendered profile has an unowned resource/default; or two stacks share an authority boundary. | Build typed Stack specification, deterministic render/check/diff and audited reconciliation before M1. Do not call a manually created dependency or imperative script a valid stack. | Infrastructure lane; `INF-001–005`, `DEP-001–009` evidence. |
| RSK-017 | Ntfy delivery could be unavailable, misconfigured or leak unsafe material even though the initial operational test succeeded. | Low / medium | Schema/redaction test or configured delivery fails, or no retained retry record exists. | Use typed declarative notifier config, bounded schema/redaction, idempotency and visible retained failure/retry. The successful corrected-topic test event `GCXy4IYjJp96` is historical evidence only, not a release notification. | Release operations lane; `OPS-STAT-001–002` evidence. |
| RSK-018 | The older proposed Tilt/docs plans use competing command/field names and cannot yet prove safe teardown, publication, direct-main or example-production boundaries. | Medium / medium | A plan advertises `instance`, a nonexistent command, incorrect notification fields, a PR-only gate, broad example credentials, or mutable teardown state. | Treat the accepted ledger/ADRs as authoritative; align the implementation plans before their milestones and retain their named negative tests. Do not advertise a planned command as implemented. | M0/M1 program lane; `DEP-009`, `DOC-008`, `MON-010`, `EX-007` evidence. |

## Escalation policy

1. A risk that prevents a required evidence lane from running remains
   **blocked**, with its exact external dependency and the last safe evidence.
   It is never converted to a weaker test or an undocumented non-goal.
2. A newly discovered security issue blocks the affected capability profile.
   The foundation and other profiles may continue only when their own evidence
   remains valid; no shared `production-ready` label masks the block.
3. Scope changes need an explicit update to the master requirements and
   acceptance ledger. A code comment, skipped CI job or changed checklist is
   not an authorized scope change.
4. A decision that actually requires user authority—spend for a KVM runner,
   providing a model credential, or enabling a repository Pages setting—is
   reported with the smallest actionable request. Everything not requiring
   that authority continues.
