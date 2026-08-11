# M5 evidence eligibility audit

Initial mapping revision: `3d1e1c4ab5483d5ca3956ef03f19bfe4724782e3`.
The `TMP-002` and `TMP-003` supplement is bound to
`6197e7ec3854aaab1b0a57b78ddbd162c5020f1f`.

This audit maps each M5 requirement to the current implementation proof. It is
not a completion claim: a row changes to `completed` only in the atomic bundle
which retains a matching redacted command result. The first bundle promotes
the private-Temporal rows `TMP-004`, `TMP-009`, and `TMP-010`, backed by
[`m5-temporal-core-integration.json`](../../evidence/m5-temporal-core-integration.json).
The public-boundary supplement for `TMP-002` and `TMP-003` is
[`m5-temporal-public-boundary.json`](../../evidence/m5-temporal-public-boundary.json).

| Rows | Current implementation/test map | Evidence disposition |
| --- | --- | --- |
| DOM-001 | `TestCompilerCreatesTheOnlyReceiptBoundMutationAndPlannerCreatesRevision`; immutable Agent-revision public contract. | Defer to the domain/public bundle. |
| DOM-002 | `TestStateRuntimeServesTheCompletePublicLifecycleThroughContentAndMemoryState`; revision-pinned Session. | Defer to the domain/public bundle. |
| DOM-003 | `TestPlannerCancelsQueuedWorkClosesAfterDrainAndFencesOutboxLeases`; Session transition tests. | Defer to the domain/public bundle. |
| DOM-004 | Compiler/planner Input tests plus `TestDurableStateRuntimeAuthorizesArtifactInputReferences`. | Defer to the domain/public bundle. |
| DOM-005 | `TestPlannerPromotesQueuedTurnAfterOneWinningSettlement`. | Defer to the domain/public bundle. |
| DOM-006 | `TestPlannerPromotesQueuedTurnAfterOneWinningSettlement` and cancellation/drain matrix. | Defer to the domain/public bundle. |
| DOM-007 | Invocation fence/recovery tests in `internal/runtimemodel`, including normalized-stream durable integration. | Defer; it must be bound with its model-worker evidence. |
| DOM-008 | `TestPlannerPersistsToolIntentBeforeApprovalDecision` and durable tool lifecycle. | Defer; it must not be confused with M7 broker acceptance. |
| DOM-009 | `TestPlannerConsumesApprovedCapabilityOnlyWithinItsPolicyAndExpiry` and durable tool lifecycle. | Defer; it must be bound with its approval/grant evidence. |
| DOM-010 | `TestPlannerAppendsConversationOnlyAtExpectedVersionAndReplaysIdempotently`. | Defer to the state/data bundle. |
| DOM-011 | authorized Artifact tests in StateRuntime and durable PostgreSQL/MinIO input/readback tests. | Defer to the state/data bundle. |
| DOM-012 | `TestStateRuntimeHTTPAndSDKExposeProviderNeutralUsageAndSafeModelFailure`. | Defer to the public API bundle. |
| DOM-013 | `TestStateRuntimeHTTPAndSDKExposeProviderNeutralUsageAndSafeModelFailure`; durable normalized model output integration. | Defer; no live-provider claim is needed or made. |
| API-001 | HTTP/SDK matrix in `state_runtime_test.go` exercises Agent, Session, Input, inspection, Events, cancel, close, Artifact, and Approval routes. | Defer to a public-contract retained run. |
| API-002 | SDK contract tests and import-graph/architecture guards; `docs/reference/runtime-go-contract.md`. | Defer to the public-contract retained run. |
| API-003 | OpenAPI compatibility and generated route tests; generated HTTP and SDK reference inventory. | Defer pending a public-contract retained run and publication check. |
| API-004 | `TestStateRuntimeHTTPAndSDKRejectExpiredMutationReceiptWithoutReplayingWork`. | Defer to the public-contract retained run. |
| API-005 | `TestStateRuntimeHTTPAndSDKAuthorizationMatrixKeepsAdminAndOwnerScopesNonEnumerating`. | Defer to the public-contract retained run. |
| API-006 | strict HTTP server and SDK boundary tests, including bounded Artifact streaming. | Defer to the public-contract retained run. |
| API-007 | StateRuntime cursor/replay and explicit Gap contract tests. | Defer to the public-contract retained run. |
| API-008 | explicit cancellation and drain tests plus workflow cancellation classification. | Defer to the public-contract retained run. |
| API-009 | StateRuntime inspection matrix; backend IDs are excluded by public model tests. | Defer to the public-contract retained run. |
| API-010 | compiler validation and public model-profile tests reject credentials and unconfigured profiles. | Defer to the public-contract retained run. |
| API-011 | `internal/openapicontract` compatibility baseline and external-consumer compile test; migration guide. | Defer pending a release/publication check. |
| API-012 | `TestStateRuntimeAdministratorsManageImmutablePolicyRevisions` and admin/non-admin HTTP/SDK matrix. | Defer to the public-contract retained run. |
| DAT-001 | conversation expected-version/idempotency planner test. | Defer to the PostgreSQL state bundle. |
| DAT-002 | Artifact authorization/integrity/streaming tests and durable MinIO input path. | Defer to the PostgreSQL state bundle. |
| DAT-003 | ordered event/outbox planner and public cursor tests. | Defer to the PostgreSQL state bundle. |
| DAT-004 | durable producer-gap and publisher-recovery integrations. | Defer to the PostgreSQL state bundle. |
| DAT-005 | retention/cursor fake-clock and collector tests. | Defer to the PostgreSQL state bundle. |
| DAT-006 | `TestEveryClosedMutationVocabularyHasDurableAuditLifecyclePhases`. | Defer to the PostgreSQL state bundle. |
| DAT-007 | audit exporter outage/reclaim integration. | Defer to the PostgreSQL state bundle. |
| DAT-008 | retention-class inventory plus collector/erasure lifecycle tests. | Defer to the PostgreSQL state bundle. |
| DAT-009 | partition/RLS and unbound/cross-tenant integration tests. | Not eligible until the protected operations report exists. |
| DAT-010 | migration, rollback refusal, locking, collection, erasure, and disposable backup/restore tests. | Not eligible until protected retention/PITR evidence exists. |
| DAT-011 | state-owned cursor/event tests and PostgreSQL-to-Temporal route recovery. | Defer with the PostgreSQL state bundle. |
| DAT-012 | outbox acknowledgement-loss and child-process kill/recovery integrations. | Defer with the PostgreSQL state bundle. |
| DAT-013 | production-adapter disposable matrix covers migration, conflict, recovery, expiry/gap, restore, erasure, and cross-tenant denial. | Not eligible until the protected operations report exists. |
| TMP-002 | `TestPublicSDKInputStartsAndSignalsThePrivateSessionWorkflow` drives public Go SDK/HTTP admission through PostgreSQL outbox to a real private Temporal worker. | Promoted with disposable integration evidence; the typed SDK observation exposes runtime-owned Input and Turn IDs, while raw HTTP field omission is not asserted. |
| TMP-003 | `TestSessionWorkflowRejectsOversizedPrivatePayloads` rejects oversized continuation/command metadata before dispatch; durable harness replays historic workflow corpus. | Promoted with workflow bound and replay evidence. |
| TMP-004 | Continue-As-New plus checked-in v1 historic replay and versioning guide. | Promoted in this bundle. |
| TMP-009 | `TestDispatchStateCommandClassifiesRetrySafetyWithoutRepeatingUnknownEffects`, retry, and cancellation workflow tests. | Promoted in this bundle. |
| TMP-010 | terminal-effect route matrix, historic replay, acknowledgement-loss, and process-kill durable integrations. | Promoted in this bundle. |

The promoted rows prove only the private state/control-plane orchestration
boundary. They do not claim a live provider, sandbox-command execution,
Firecracker isolation, protected production operations, or a release tag.
