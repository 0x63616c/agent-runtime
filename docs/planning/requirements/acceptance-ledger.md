# Agent Runtime — acceptance ledger

Status: planned evidence map. Every identifier in
[master requirements](master-requirements.md) appears exactly once below.

`U` means deterministic unit/property test; `C` means contract/integration
test; `E` means end-to-end test; `K` means Linux/KVM security test; `M` means
manual/operator evidence retained as a release artifact; `D` means published
documentation or generated reference. The paths are intended repository paths,
not evidence claimed to exist today.

| Requirement | Acceptance evidence | Required documentation/release evidence |
|---|---|---|
| MON-001 | `tests/release/repository_test.go` verifies license, default branch and release metadata; `just verify` records pushed commit. | README, LICENSE, release record. |
| MON-002 | `tests/architecture/monorepo_test.go` verifies owned module/source layout and no external copied codec/sandbox source. | Architecture and contributing guide. |
| MON-003 | Go workspace/module resolution test from clean checkout. | Module import/install guide. |
| MON-004 | `tests/architecture/agents_guide_test.go` asserts required Software Factory guidance/provenance remains in `AGENTS.md`. | Root `AGENTS.md`. |
| MON-005 | Same guide test asserts ledger, glossary, docs skill, checks and direct-main instructions. | Root `AGENTS.md`. |
| MON-006 | Glossary-link lint ensures public concepts use canonical terms. | `CONTEXT.md`. |
| MON-007 | ADR index/link check. | `docs/adr/` index and decisions. |
| MON-008 | Architecture-authority check rejects an implementation document that conflicts with the ledger/accepted ADRs and records superseded draft provenance. | `docs/architecture/system.md`, ADR index and draft-status record. |
| MON-009 | Clean external-consumer test imports released SDK and `temporalpayload` package without `go.work`; release-tag/version-policy check passes. | Module, compatibility, deprecation and docs-version policy. |
| MON-010 | Main-change evidence parser verifies atomic requirement/seam/docs/evidence references, no history rewrite, pre-push/main-CI records and red-main halt record. | Direct-main/AFK operations policy. |
| ENG-001 | Static dependency/style check and representative Ginkgo suites compile. | Engineering/contributing guide. |
| ENG-002 | `U ids` validates prefix, parsing refusal, uniqueness and log-safe format. | ID/reference docs. |
| ENG-003 | Static forbidden-time/sleep lint outside adapters plus injected-clock tests. | Testing architecture. |
| ENG-004 | `U testclock` proves retries, expiry and lease transitions advance fake time. | Testing architecture. |
| ENG-005 | Slice plans reference agreed seams; review checks prove red/green evidence attached per slice. | `AGENTS.md` TDD workflow. |
| ENG-006 | Exported API semantics lint/checklist and compile examples. | GoDoc/API reference. |
| ENG-007 | `C config` validates startup rejection/redaction/ownership. | Configuration reference. |
| ENG-008 | Clean-checkout command smoke suite runs each documented command. | README command table. |
| ENG-009 | `just generate && git diff --exit-code` CI gate. | Generation guide. |
| ENG-010 | Import/dependency guard test for examples/workflows/SDK. | Architecture boundaries. |
| INF-001 | Render/catalog test inventories every named resource and rejects runtime/bootstrap creation paths. | Declarative desired-state inventory. |
| INF-002 | Typed Stack specification golden-render suite proves local, CI and production render the one reviewed topology. | Renderer input/schema reference. |
| INF-003 | Ownership/lifecycle matrix lint rejects missing owner, scope, dependencies, retention, backup/restore or delete/tombstone behavior; RBAC-negative test passes. | Ownership/lifecycle matrix. |
| INF-004 | Render/check/diff/policy suite rejects implicit namespaces, mutable tags, unbounded resources, undeclared ports/storage/defaults, ambient credentials and drift. | Render, diff and audited reconcile procedures. |
| INF-005 | CI profile matrix proves migration upgrade/rollback, RBAC-negative behavior, NetworkPolicy admission and two-stack isolation. | Profile evidence and operator rollback/runbook. |
| DOM-001 | `U agentspec` proves immutable revision creation and lookup. | Agent concepts. |
| DOM-002 | `U session` proves revision pinning and migration refusal. | Session concepts. |
| DOM-003 | State-machine table test for all Session transitions. | Session lifecycle diagram. |
| DOM-004 | `C input` tests text/artifact input bounds and idempotency. | Input API reference. |
| DOM-005 | State-machine/property test proves one terminal Turn outcome. | Turn lifecycle. |
| DOM-006 | `E serialized-turns` proves durable ordered queue under concurrent input. | Input admission semantics. |
| DOM-007 | `U invocation` proves retry creates attempts within one Turn. | Model invocation concepts. |
| DOM-008 | `C tool-intent` proves a Tool call alone never executes. | Tool authorization model. |
| DOM-009 | `C grants` tests expiry/max-use/policy revision/audit without secret data. | Capability grants. |
| DOM-010 | `C conversation` tests optimistic version conflict/idempotent append. | Conversation storage model. |
| DOM-011 | `C artifacts` tests digest metadata and authorization-aware read. | Artifact model. |
| DOM-012 | `U failures` tests stable translation/sanitization/retryability. | Failure code reference. |
| DOM-013 | `U usage` tests unknown provider values stay unknown. | Usage/accounting caveats. |
| API-001 | HTTP/OpenAPI and Go SDK integration suite exercises every listed command. | SDK quickstart/API reference. |
| API-002 | Import graph gate forbids implementation dependencies in SDK module. | SDK package overview. |
| API-003 | OpenAPI/SDK contract conformance and generated-drift job. | OpenAPI and Go reference. |
| API-004 | `C api-idempotency` tests same, conflict, expiry and status lookup. | Idempotency guide. |
| API-005 | `C api-authz` cross-tenant negative suite. | Authentication/authorization guide. |
| API-006 | Request/response/event limit tests and fuzzed decoding. | API limits/pagination reference. |
| API-007 | `C events-cursor` covers replay, duplicate, gap, expiry and ordering. | Event cursor contract. |
| API-008 | `E disconnect` proves dropped client does not cancel, explicit cancel does. | Cancellation guide. |
| API-009 | Public inspection contract test forbids backend IDs. | Session inspection reference. |
| API-010 | Agent validation test rejects provider credentials/types and unconfigured profiles. | Model profile configuration. |
| API-011 | Compatibility/golden schema tests and migration fixtures. | Compatibility policy. |
| API-012 | Admin authorization/agent-policy lifecycle integration suite. | Administration API reference. |
| TMP-001 | Deployment config acceptance test and operator smoke check. | Temporal operator guide. |
| TMP-002 | Workflow behavior test maps public lifecycle without leaked IDs. | Runtime architecture. |
| TMP-003 | Workflow payload-size/serialization guard and replay tests. | Workflow determinism rules. |
| TMP-004 | Historic replay fixtures plus Continue-As-New test. | Workflow versioning/runbook. |
| TMP-005 | Static constructor guard and worker/client converter integration test. | Codec integration guide. |
| TMP-006 | Startup compatibility failure/success integration test. | Upgrade troubleshooting. |
| TMP-007 | Role registration/process startup integration matrix. | Deployment roles reference. |
| TMP-008 | Credential absence/presence role test using fixture secret source. | Trust-separation diagram. |
| TMP-009 | Activity retry decision table test with uncertain-effect case. | Retry policy guide. |
| TMP-010 | Temporal test-environment suite for listed lifecycle scenarios. | Test evidence report. |
| PAY-001 | Workspace import/build and second in-repo consumer test. | Module reference/version policy. |
| PAY-002 | Golden inline/zstd/remote size-selection vectors. | Payload chain architecture. |
| PAY-003 | Module conformance suite covers store/key/layer/handler/metrics. | Codec module reference. |
| PAY-004 | Codec handler-only integration verifies workers do not invoke HTTP codec. | Temporal UI codec guide. |
| PAY-005 | Missing/corrupt/GC/compatibility integration tests. | Storage retention/recovery guide. |
| PAY-006 | Workflow/application source guard rejects caller payload-size branching. | Payload transparency notes. |
| PAY-007 | Security/ADR check ensures encryption claims/config are absent until implemented. | Encryption status statement. |
| PAY-008 | Two-consumer codec exchange and UI inspection E2E. | Codec compatibility tutorial. |
| MOD-001 | Current official support/terms/protocol/credential-lifecycle review is retained; subscription route has a deterministic seam suite and a visible blocked result when support cannot be verified. | Codex subscription support policy and release gate. |
| MOD-002 | Provider-disconnect/reconnect event finalization test. | Model events semantics. |
| MOD-003 | Secret-scanning/role credential test rejects credential values from every prohibited store and validates redacted reference diagnostics. | Model credential setup. |
| MOD-004 | Credential-source fixture suite covers local login path, source validation, redaction, cancel, expired/rejected/ambiguous refresh, single-writer refresh and revocation. | Subscription operator setup and credential-lifecycle guide. |
| MOD-005 | Protected live subscription canary plus Durable Chat E2E retain secret-safe evidence and are mechanically excluded from untrusted PR/fork execution. | Durable Chat subscription proof and safe CI policy. |
| TOL-001 | Tool broker behavior suite validates schema/policy/grant/audit/result path. | Tool broker architecture. |
| TOL-002 | Builtin/sandbox/MCP adapter contract tests prove broker cannot be bypassed. | Tool adapter guide. |
| TOL-003 | Grant expiry/revocation/max-use integration test. | Capability lifecycle. |
| TOL-004 | Audit append-only authorization decision integration test. | Audit record reference. |
| TOL-005 | Large/redacted tool-output blob/event limits test. | Tool output guide. |
| TOL-006 | Unknown-external-effect test asserts surfaced uncertainty and idempotency key. | External-effect policy. |
| HITL-001 | Workflow state test proves durable pending approval phase. | Human approval concepts. |
| HITL-002 | Approval request contract/golden schema tests. | Approval API reference. |
| HITL-003 | Authorized approve/deny/expiry/idempotency/scope-narrowing suite with fake clock. | Approver guide. |
| HITL-004 | Product event plus audit ordering integration test. | Approval event/audit reference. |
| HITL-005 | Restart/replay/late decision E2E. | Recovery/expiry troubleshooting. |
| HITL-006 | Workspace Agent browser/TUI E2E approve/deny/expiry/cancel scenario. | Workspace Agent tutorial. |
| DAT-001 | Conversation store conflict/idempotency/property suite. | Conversation consistency contract. |
| DAT-002 | Artifact integrity/auth/limit/download-stream suite. | Artifact reference. |
| DAT-003 | Event ordering/replay/duplicate tolerance contract suite. | Product events reference. |
| DAT-004 | Producer-loss stream gap/replay/finalization integration test. | Event durability architecture. |
| DAT-005 | Cursor-retention fake-clock expiry/recovery test. | Retention/cursor-expired guide. |
| DAT-006 | Audit attempted-to-reconciled append-only/dedupe test. | Audit retention model. |
| DAT-007 | Audit-outbox outage/retry contract test. | Mandatory-audit limitations. |
| DAT-008 | Data-classification/GC integration tests and lifecycle inventory lint. | Retention and data handling matrix. |
| DAT-009 | Production PostgreSQL adapter suite proves authoritative tenancy, idempotency, projections, indexes, cursor sequence, audit/outbox and sandbox-operation ledger; large-content guard rejects unbounded rows. | Data-authority architecture and storage map. |
| DAT-010 | Migration/schema/locking/retention/partitioning/tenant-erasure and separate-Temporal-persistence configuration tests pass; backup/restore drill is retained. | PostgreSQL and Temporal-persistence operator runbooks. |
| DAT-011 | Product-event state-machine contract proves PostgreSQL cursor ordering, replay, terminal/gap and rejects Workflow Stream offsets as public cursors. | Product-event/cursor contract. |
| DAT-012 | Transaction/outbox integration matrix kills producers at each acknowledgement boundary and proves only declared atomic or at-least-once/reconciled outcomes. | Effect-boundary and outbox policy. |
| DAT-013 | Production PostgreSQL integration retains migration, conflict/retry, killed-outbox recovery, cursor-expiry/gap, backup/restore, tenant-erasure and cross-tenant-denial evidence. | Production PostgreSQL evidence record. |
| OBS-001 | Trace/metric/log correlation fixture test. | Observability reference. |
| OBS-002 | Public payload/operator attribute separation test. | Operator inspection guide. |
| OBS-003 | Secret/argv/content redaction tests through slog/OTel/error encoders. | Observability security guide. |
| OBS-004 | Dashboard JSON provisioning check and synthetic alert metric tests. | Dashboards/alerts runbook. |
| OBS-005 | Full correlated-session operator inspection E2E. | Operator troubleshooting walkthrough. |
| SBX-001 | Control-plane API/process startup E2E; no activity-local ownership check. | Sandbox architecture. |
| SBX-002 | Durable state/host-routing/lease/reconciliation integration suite. | Control-plane operations guide. |
| SBX-003 | Cross-process reconnect/get/wait/kill/close/output replay contract suite. | Sandbox client reference. |
| SBX-004 | Operation-ID test matrix for every mutating endpoint. | Operation/idempotency reference. |
| SBX-005 | Durable ledger restart/conflict/tombstone/expiry/property suite. | Ledger/retention specification. |
| SBX-006 | Unknown exec/output/host/cancel recovery E2E and external-effect disclaimer test. | Side-effect recovery guide. |
| SBX-007 | Principal-scoping and guessed-ID cross-tenant negative suite. | Sandbox tenancy/security model. |
| SBX-008 | Adversarial caller mutation plus `-race` and canonical-wire golden suite. | Canonical wire schema. |
| SBX-009 | Default-change retry/restore incompatibility tests. | Effective Spec/versioning guide. |
| SBX-010 | Malicious backend SPI conformance test proves core wrapper enforcement. | Backend SPI contributor guide. |
| SBX-011 | Public API compile examples and forbidden-backend-type import test. | Sandbox Go API reference. |
| SBX-012 | Exported-field semantics table lint/compile examples. | API semantics appendix. |
| SBX-013 | Durable lifecycle/close race/state transition table tests. | Lifecycle diagram. |
| SBX-014 | Reaper recovery test after worker/control/host agent failure. | Reaper operations runbook. |
| SBX-015 | Termination-reason conformance suite forbids exit-code flattening. | Process result reference. |
| SBX-016 | Cancellation/signal/timeout/close/natural-exit race matrix with fake clock. | Process-control semantics. |
| SBX-017 | Bounded spool/tee/redaction/backpressure/replay/gap tests per stream. | Output stream contract. |
| SBX-018 | Resource/admission exhaustion suite including inodes/connections/control/storage. | Limits and quota reference. |
| SBX-019 | Effective-default finite-limit golden tests. | Default limits table. |
| SBX-020 | Image admission rejection/Info metadata/compatibility test. | Image admission policy. |
| SBX-040 | Host-enrollment/mTLS/rotation/revocation/protocol-compatibility suite rejects unenrolled, revoked and incompatible hosts and records attestation limits. | Host-agent enrollment and trust guide. |
| SBX-041 | Signed/encrypted envelope contract tests tenant/principal, Effective-Spec digest, operation, capability, expiry, lease/fencing and protocol refusal behavior. | Host-control protocol reference. |
| SBX-042 | Durable assignment/renewal/fencing/stale-result/output-sequence/loss/quarantine/reassignment integration suite. | Host routing and reconciliation runbook. |
| SBX-043 | Authority-boundary review and negative deployment tests show control/core/host/Jailer permissions cannot bypass declared cgroup/network/image/mount/output/cleanup owners. | Authority matrix. |
| SBX-044 | M3 proves replay, revocation, stale lease, wrong tenant, rogue host, lost acknowledgement, restart and quarantine cleanup in its durable protocol lane; M4 separately reproves the same bindings in Linux/KVM before any Firecracker claim. | M3/M4 host-protocol evidence. |
| SBX-021 | Linux/KVM Firecracker foundation smoke/security suite. | Firecracker security profile. |
| SBX-022 | Local adapter acknowledgement/refusal/sanitization tests. | Local adapter warning guide. |
| SBX-023 | Fake adapter scripted lifecycle/retry/clock unit suite. | Test adapter guide. |
| SBX-024 | Capability negotiation/regression/create-restore binding conformance suite. | Capability matrix. |
| SBX-025 | Shared adapter black-box conformance runner in CI. | Adapter certification guide. |
| SBX-026 | Copy-in/out checksum/symlink/cancel/partial-file/archive E2E. | Portable workspace transfer tutorial. |
| SBX-027 | Fuzz/property tests for path and mount target normalization/races. | Filesystem safety contract. |
| SBX-028 | Firecracker mount traversal/TOCTOU/special-file/daemon-boundary K tests. | Host mount threat model. |
| SBX-029 | Volume lease/generation/attach-crash/delete-race/taint tests. | Volume lifecycle reference. |
| SBX-030 | Snapshot manifest/corruption/delete-race/restore-ceiling K tests. | Snapshot lifecycle/security guide. |
| SBX-031 | Snapshot artifact canary inspection proves stated exclusions only. | Snapshot limitations. |
| SBX-032 | Volume-taint laundering and attestation/denial tests. | Taint provenance guide. |
| SBX-033 | Contextual resolver auth/version/expiry/size/audit/redaction tests. | Secret resolver contract. |
| SBX-034 | Grant truth-table tests for omitted/empty/explicit/unknown/widening. | Grant semantics table. |
| SBX-035 | Proc/FD/ptrace/daemon/chunk-redaction security suite on capable adapter. | Command-scoped secret profile. |
| SBX-036 | Broker/trusted-exec provenance and hostile-workdir/environment tests. | Elevated credential model. |
| SBX-037 | Mandatory proxy/no-direct-route/metadata-bypass K tests. | Egress data-plane architecture. |
| SBX-038 | DNS/CNAME/IDNA/IPv4/v6/ECH/DoH/reuse/proxy-outage K test matrix. | Egress semantics and limitations. |
| SBX-039 | Release profile gate requires all profile suites green; no unsupported final claim. | Security profile matrix/release evidence. |
| DEP-001 | Two-stack isolation E2E verifies independent namespace/Temporal/storage/queues/ports. | Tilt stack guide. |
| DEP-002 | Full-profile isolation regression and any fast-profile separation test. | Development profiles reference. |
| DEP-003 | Tilt manifest/link/readiness/reset target safety smoke test. | Tilt UX tutorial. |
| DEP-004 | Helm/render/config validation and self-hosted deploy smoke. | Operator deployment/configuration guides. |
| DEP-005 | Role credential-negative pod/process tests. | Trust separation diagram. |
| DEP-006 | Operator/application config boundary validation. | Ownership/responsibility matrix. |
| DEP-007 | Linux/KVM compatibility matrix assertion and artifact publishing. | KVM runner setup/evidence. |
| DEP-008 | Bootstrap prerequisite/mutation-safety integration test. | Prerequisites/troubleshooting. |
| DEP-009 | Command-contract/teardown suite proves the one `--stack` identity, rejects divergent wrapper state, and requires labels/object UIDs before containment-safe cleanup. | Local stack/teardown contract, marked planned until implemented. |
| EX-001 | Durable Chat web+TUI public-contract E2E restart/reconnect/cancel/queue suite. | Durable Chat tutorial. |
| EX-002 | Workspace Agent public-contract sandbox/artifact/approval E2E. | Workspace Agent tutorial. |
| EX-003 | Research Dossier long-run/blob/citation/resume/download E2E. | Research Dossier tutorial. |
| EX-004 | Example import/static dependency guard. | Example architecture notes. |
| EX-005 | Per-example clean Tilt seed/demo/test/docs screenshots check. | Each tutorial/troubleshooting page. |
| EX-006 | Cross-example presentation E2E covering required proof sequence. | Demo verification walkthrough. |
| EX-007 | Example auth/bootstrap/tenant-cleanup/download-authorization/redacted-evidence/browser-TUI-harness/shared-cursor integration suite. | Example production-boundary guides. |
| DOC-001 | Astro Starlight build/Pagefind search/navigation/accessibility and Pages deployment workflow check. | Public docs site. |
| DOC-002 | Documentation coverage manifest/link check for every named section. | Astro Starlight information architecture. |
| DOC-003 | Generated OpenAPI/GoDoc reference build and drift check. | Reference pages. |
| DOC-004 | Snippet harness, link checker, docs build/format/spell CI gate. | Docs contribution guide. |
| DOC-005 | Docs skill fixture test validates changed API/config behavior is detected and checked. | `skills/refresh-agent-runtime-docs/SKILL.md`. |
| DOC-006 | README command/link/quickstart smoke test. | Root README. |
| DOC-007 | Claim-classification lint/review with local-vs-KVM fixtures. | Security evidence policy. |
| DOC-008 | Locked docs-toolchain/site-root/Pages URL/version/search/accessibility/permissions/rollback and docs-skill drift/curated-content fixture suite. | Documentation publication operations guide. |
| OPS-STAT-001 | Fake-notifier schema/redaction/completion-order/retention suite; allowlisted transport fixture; retained real milestone-completion notification evidence. | Status-reporting payload and release-evidence record. |
| OPS-STAT-002 | Regular-status evidence-model and failed-delivery/retry-record integration suite; typed declarative notifier config check. | Status reporting and notification-failure runbook. |
| TST-001 | Kernel/ID/clock/canonical/policy/failure/redaction unit/property/fuzz suites. | Test architecture. |
| TST-002 | Public API/store/tool/approval/codec/control integration suites. | CI evidence index. |
| TST-003 | Adapter conformance runner and capability activation report. | Adapter certification. |
| TST-004 | Sandbox adversarial suite with retained sanitized artifacts. | Security test matrix. |
| TST-005 | Cross-worker Linux/KVM acknowledgment-boundary kill/reconcile suite. | Firecracker E2E report. |
| TST-006 | Local Tilt three-example full E2E. | Local verification runbook. |
| TST-007 | Lint rejecting real sleeps/unbounded waits plus fake-time tests. | Deterministic test rules. |
| TST-008 | CI workflow matrix shows all required lanes and secret-safe artifacts. | CI/reference runbook. |
| TST-009 | `just verify` ledger-report parser rejects missing/unknown/non-green requirements. | Completion report format. |
| TST-010 | Independent standards/spec review record and resolved-finding check. | Review report/contributing guide. |

## Release gate

`just verify` is successful only when this table’s planned tests have become
real green evidence, the generated ledger report names every requirement, the
documentation site build/deployment is green, and the Linux/KVM lane’s result
is attached. A skipped test or unavailable KVM runner is a visible blocked
requirement, never a pass.
