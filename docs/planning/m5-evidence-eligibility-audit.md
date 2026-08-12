# M5 evidence eligibility audit

Initial mapping revision: `3d1e1c4ab5483d5ca3956ef03f19bfe4724782e3`.
The `TMP-002` and `TMP-003` supplement is bound to
`6197e7ec3854aaab1b0a57b78ddbd162c5020f1f`.
The public API supplement for `API-001`, `API-002`, `API-004` through
`API-012` is bound to `77ca92ff30836d9847a0b7ee857f83d4eb2ce4bc`.
Its ledger reference `m5-public-api-77ca92f` resolves to
[`m5-public-api-contract.json`](../../evidence/m5-public-api-contract.json).
The domain-model supplement for `DOM-001`, `DOM-002`, and `DOM-004` through
`DOM-013` is bound to `3f40dab755cecfb0d8647fcf88731db2aa757f48`.
Its ledger reference `m5-domain-model-3f40dab` resolves to
[`m5-domain-model-contract.json`](../../evidence/m5-domain-model-contract.json).
The terminal-Session supplement for `DOM-003` is bound to
`2ee91a8560f0682d5a7423a0a1b3580d3a3512d3`. Its ledger reference
`m5-domain-session-states-2ee91a8` resolves to
[`m5-domain-session-states.json`](../../evidence/m5-domain-session-states.json).
The data-authority supplement for `DAT-002` through `DAT-008` and `DAT-011`
through `DAT-012` is bound to `4454bf9c5cbb1a7120508d6f84f14fd5be6d110f`.
Its ledger reference `m5-data-authority-4454bf9` resolves to
[`m5-data-authority-contract.json`](../../evidence/m5-data-authority-contract.json).
The conversation durability supplement for `DAT-001` is bound to
`1ae636bfc1b3e5f9ac9d650c7b5021b3b93aec9c`. Its ledger reference
`m5-data-conversation-1ae636b` resolves to
[`m5-data-conversation-contract.json`](../../evidence/m5-data-conversation-contract.json).

This audit maps each M5 requirement to the current implementation proof. It is
not a completion claim: a row changes to `completed` only in the atomic bundle
which retains a matching redacted command result. The first bundle promotes
the private-Temporal rows `TMP-004`, `TMP-009`, and `TMP-010`, backed by
[`m5-temporal-core-integration.json`](../../evidence/m5-temporal-core-integration.json).
The public-boundary supplement for `TMP-002` and `TMP-003` is
[`m5-temporal-public-boundary.json`](../../evidence/m5-temporal-public-boundary.json).

| Rows | Current implementation/test map | Evidence disposition |
| --- | --- | --- |
| DOM-001 | Kernel immutable Agent revision/revision-pinned Session test plus state compiler/planner revision-registration test. | Promoted with retained domain evidence. |
| DOM-002 | Kernel resolved-revision Session creation and later-revision pin-preservation test. | Promoted with retained domain evidence. |
| DOM-003 | State-planner transition tables cover `open`, `closing`, `completed`, `cancelled`, and `failed`, including pending-work and terminal refusals, exact replay, and owner/worker authority separation. The disposable PostgreSQL/MinIO harness proves public cancellation, worker failure, safe event projection, recomposition, and durable replay; private Temporal routing recognizes every terminal Session event. | Promoted with retained terminal-Session evidence; no provider, sandbox, protected-production, or PITR claim. |
| DOM-004 | Kernel bounded/idempotent Input tests plus disposable PostgreSQL admission reference-only, concurrent, replay, and Artifact-authorization tests. | Promoted with retained domain evidence. |
| DOM-005 | Kernel completion/cancellation race and planner one-winning-settlement tests. | Promoted with retained domain evidence. |
| DOM-006 | Kernel 24-concurrent Input queue test plus disposable PostgreSQL concurrent distinct-admission test, now invoked by the durable harness. | Promoted with retained domain evidence. |
| DOM-007 | State-planner retry-within-one-running-Turn test, model-worker fresh/recovery/uncertain tests, and disposable PostgreSQL/MinIO producer-loss and normalized-stream integrations. | Promoted without a live-provider claim. |
| DOM-008 | Tool-intent/approval planner test plus durable authorized-descriptor lifecycle and pre-execution corruption/missing-descriptor refusal. | Promoted as control-plane authorization evidence only. |
| DOM-009 | Grant owner/scope/expiry/max-use/policy/audit tests in planner/public StateRuntime plus durable tool lifecycle. | Promoted with no raw-secret claim. |
| DOM-010 | `TestPlannerAppendsConversationOnlyAtExpectedVersionAndReplaysIdempotently`. | Promoted with retained domain evidence. |
| DOM-011 | State/planner Artifact metadata/authorization tests plus disposable PostgreSQL/MinIO input and owner readback tests. | Promoted with retained domain evidence. |
| DOM-012 | `TestStateRuntimeHTTPAndSDKExposeProviderNeutralUsageAndSafeModelFailure` and model-worker uncertainty translation tests. | Promoted with retained domain evidence. |
| DOM-013 | Provider-neutral unknown-preserving public usage test plus durable normalized model-output integration. | Promoted without a live-provider claim. |
| API-001 | Public Go SDK/HTTP suite covers the listed Session, Input, inspection, Event, cancellation, close, Artifact, and Approval commands; standalone binary and disposable durable composition also pass. | Promoted with retained public-contract evidence. |
| API-002 | SDK package import graph and independent temporary consumer compile reject Temporal, provider, sandbox, blob, database, and telemetry implementation dependencies. | Promoted with retained contract evidence. |
| API-003 | OpenAPI compatibility and generated route tests plus generated references build locally. | Defer: no current-SHA documentation publication/HTTPS evidence is retained. |
| API-004 | Public HTTP/SDK tests cover equal replay, conflicting reuse, expired receipts, and caller-scoped status lookup. | Promoted with retained public-contract evidence. |
| API-005 | `TestStateRuntimeHTTPAndSDKAuthorizationMatrixKeepsAdminAndOwnerScopesNonEnumerating` covers authenticated same-tenant and cross-tenant denial across public routes. | Promoted with retained public-contract evidence. |
| API-006 | Strict HTTP/SDK limits, Artifact stream limits, public request/event limit test, and 500-execution malformed-decoder fuzz run pass. | Promoted with retained contract evidence. |
| API-007 | Public HTTP/SDK cursor tests cover replay, duplicate-tolerant resume, ordered pages, and explicit compacted-cursor Gap. | Promoted with retained public-contract evidence. |
| API-008 | Public dropped-observation test retains durable work; explicit cancellation/drain and durable workflow cancellation tests pass. | Promoted with retained public/durable evidence. |
| API-009 | Raw authenticated Session inspection response recursively rejects backend execution-ID field names. | Promoted with retained public-contract evidence. |
| API-010 | Public SDK rejects an unconfigured model profile and raw HTTP rejects a provider credential-shaped field without echoing it. | Promoted with retained public-contract evidence. |
| API-011 | Checked-in v1 compatibility baseline, generated route-table drift check, temporary `GOWORK=off` consumer compile, and migration policy pass. | Promoted as candidate-module compatibility evidence; no immutable release tag is claimed. |
| API-012 | Immutable Agent/Policy revision lifecycle and admin/non-admin HTTP/SDK separation pass. | Promoted with retained public-contract evidence. |
| DAT-001 | Disposable PostgreSQL `RuntimeStateStore` persists an Agent revision and Session, then appends and reloads an immutable Conversation reference; exact replay leaves durable semantic state unchanged and a stale expected-version append conflicts. | Promoted with retained conversation durability evidence. |
| DAT-002 | Artifact authorization/integrity/streaming tests and disposable PostgreSQL/MinIO input/readback path. | Promoted with retained data-authority evidence. |
| DAT-003 | ordered event/outbox planner, public cursor, producer-loss and publisher-recovery tests. | Promoted with retained data-authority evidence. |
| DAT-004 | durable producer-gap and PostgreSQL/Temporal publisher acknowledgement-loss/process-recovery integrations. | Promoted with retained data-authority evidence. |
| DAT-005 | retention-class policy plus cursor compaction/explicit Gap and current-inspection tests. | Promoted with retained data-authority evidence. |
| DAT-006 | complete audit lifecycle vocabulary plus durable PostgreSQL audit export outage/reclaim integration. | Promoted with retained data-authority evidence. |
| DAT-007 | concrete HTTP audit exporter and durable PostgreSQL lease-reclaim-after-outage integration; explicitly at-least-once. | Promoted with retained data-authority evidence. |
| DAT-008 | retention-class inventory lint, exact collector/erasure reconciliation integrations, and lifecycle documentation. | Promoted with retained data-authority evidence. |
| DAT-009 | partition/RLS and unbound/cross-tenant integration tests. | Not eligible until the protected operations report exists. |
| DAT-010 | migration, rollback refusal, locking, collection, erasure, and disposable backup/restore tests. | Not eligible until protected retention/PITR evidence exists. |
| DAT-011 | state-owned cursor/event tests, producer-gap integration, and PostgreSQL-to-Temporal route recovery. | Promoted with retained data-authority evidence. |
| DAT-012 | sealed-plan persistence plus acknowledgement-loss and child-process kill/recovery integrations. | Promoted with retained data-authority evidence. |
| DAT-013 | production-adapter disposable matrix covers migration, conflict, recovery, expiry/gap, restore, erasure, and cross-tenant denial. | Not eligible until the protected operations report exists. |
| TMP-002 | `TestPublicSDKInputStartsAndSignalsThePrivateSessionWorkflow` drives public Go SDK/HTTP admission through PostgreSQL outbox to a real private Temporal worker. | Promoted with disposable integration evidence; the typed SDK observation exposes runtime-owned Input and Turn IDs, while raw HTTP field omission is not asserted. |
| TMP-003 | `TestSessionWorkflowRejectsOversizedPrivatePayloads` rejects oversized continuation/command metadata before dispatch; durable harness replays historic workflow corpus. | Promoted with workflow bound and replay evidence. |
| TMP-004 | Continue-As-New plus checked-in v1 historic replay and versioning guide. | Promoted in this bundle. |
| TMP-009 | `TestDispatchStateCommandClassifiesRetrySafetyWithoutRepeatingUnknownEffects`, retry, and cancellation workflow tests. | Promoted in this bundle. |
| TMP-010 | terminal-effect route matrix, historic replay, acknowledgement-loss, and process-kill durable integrations. | Promoted in this bundle. |

The promoted rows prove only the private state/control-plane orchestration
boundary. They do not claim a live provider, sandbox-command execution,
Firecracker isolation, protected production operations, or a release tag.
