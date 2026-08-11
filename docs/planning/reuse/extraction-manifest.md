# Extraction manifest — source to Agent Runtime monorepo

This manifest is the authorization and verification checklist for source reuse. A row is not permission to blindly copy code. It is complete only when the destination owner records the source commit, destination test result, generated-diff result, dependency/license scan, and removal of every Software Factory import.

Source baseline: `github.com/0x63616c/software-factory` commit `4a427d0080ba6cc73609af13242251d3f45d6c70` (2026-08-06).
Destination baseline: this single MIT-licensed `github.com/0x63616c/agent-runtime` monorepo.
Copy authority: user explicitly authorized reuse into the public MIT repository.
Secret rule: no credential values, `.env` files, Kubernetes Secret manifests/values, auth documents, recorded HTTP authorization headers, or private deployment configuration may be copied.

## Package manifest

| ID | Source paths | Source dependencies/coupling | Proposed monorepo destination | Disposition | Required destination tests |
|---|---|---|---|---|---|
| EX-001 | `internal/clock/{clock.go,system.go,clocktest/fake.go,clock_test.go}` | Standard library only; Factory package/import path. | `platform/clock` and `platform/clock/clocktest` in root module. | Adapt directly; preserve behavior and fake API. | UTC, cancelled sleep, fake advance, fake cancellation, no real waiting outside the system-clock test. |
| EX-002 | `internal/blobs/{store.go,key.go,file.go,http.go,mem.go}` and `*_test.go` | Standard library. Bucket enum hard-codes `payloads`/`conversations`. | `packages/blobstore` Go module, joined by root `go.work`. | Adapt contract/key/file/HTTP/memory code; redesign typed namespaces and public error ownership. | Existing round trips, traversal rejection, idempotency, digest verification, HTTP status/body bound, plus S3/MinIO contract suite and cancellation/timeout tests. |
| EX-003 | `cmd/blobs/{main.go,main_test.go}`, `images/blobs/Dockerfile` | `blobs`, Factory configuration/env names, Factory image layout/logger. | `apps/blobd`; `deploy/images/blobd`. | Reimplement composition root around EX-002. Do not copy configuration names. | PUT/GET, 404, malformed key, size limit, health, safe logs, local Tilt readiness, MinIO artifact round trip. |
| EX-004 | `internal/work/paths.go`, `internal/work/paths_test.go` | Temporal `converter.SerializationContext`; Factory `work` package. | `packages/temporalpayload/internal/payloadkey` or an unexported implementation beside the codec. | Adapt algorithm and safety tests. Do not export Factory path vocabulary. | Namespace/workflow path safety, unkeyed fallback, SHA-256 determinism, stable fixture format. |
| EX-005 | `internal/payloads/{layer.go,compress.go,offload.go,chain.go,observe.go}` and five tests/golden fixture | Temporal SDK/API, `klauspost/compress`, Factory blobs/work/clock/telemetry. Fixed 30s timeout and Factory metadata key. | `packages/temporalpayload` Go module. | Refactor, not a direct copy. Own configuration, metadata, context policy, metrics hook, and protocol version. | Layer pass-through and metadata preservation, compression golden wire format, offload threshold/idempotency, full chain order, legacy decode, injected observer clock, timeout/cancellation, concurrency, codec UI handler parity. |
| EX-006 | `internal/clients/temporal/dial.go`, `dial_test.go` | Temporal client, Factory payloads/telemetry. | `internal/temporal/client` composition adapter. | Reimplement only the invariant that every dial uses the same data converter. | Dial requires blob store, cannot accept a divergent caller converter, worker/client/UI codec compatibility against real local Temporal. |
| EX-007 | `cmd/codec/{main.go,main_test.go}`, `images/codec/Dockerfile` | Factory payloads, blobs, telemetry; static `software-factory` namespace allowlist. | `apps/codec`; `deploy/images/codec`. | Reimplement around EX-005. Namespace/origin policy comes from local stack configuration. | Decode/encode, CORS allow/deny, health, request metadata only, multi-namespace local stack policy, Temporal UI manual/automated decode proof. |
| EX-008 | `internal/agent/{conversation.go,conversation_seed.go,conversation_store.go,transcript_store.go,artifact_store.go,names.go,errors.go}` and all matching tests | Factory blobs and `work` usage/accounting. Identities are Factory workflow strings. | `internal/runtime/conversations`, `internal/runtime/artifacts`, `internal/runtime/events`. | Reimplement the immutable-chain/content-reference pattern with Session/Turn/Artifact typed IDs. | Predecessor/identity integrity, chain reconstruction, digest/byte verification, tool output bounds, content never appears in durable event index, artifact download authorization. |
| EX-009 | `internal/clients/codexresponses/{doc.go,types.go,client.go,errors.go,managed_source.go}` and tests | Standard HTTP/SSE/JSON; Factory `work.Credential`; unsupported subscription endpoint; Factory `originator` header. | `internal/providers/codexsubscription` only; runtime-facing model seam lives in `internal/runtime/model`. | Experimental adapter only, after independently verifying current behavior and policy. Never public SDK API. | Request encoding, SSE finals/tool calls/errors, safe provider metadata, redaction, cancellation, idempotency, provider-canary marked external, no Factory header/path. |
| EX-010 | `internal/clients/codexauth/{authfile,deps,errors,oauth,options,refresh,source,state}.go`, `codexauthtest`, `storefake`, tests | Factory clock/telemetry/work types and Kubernetes CAS secret implementation. Provider facts came from a particular Codex CLI version. | `internal/providers/codexsubscription/auth`; generic secret interface belongs in `internal/secrets`. | Reimplement only after EX-001 and a CAS secret adapter exist. No credential files in repository or examples. | Source/secret-store contract suite, all formatting/log redaction, refresh-token stripping, HTTPS/loopback rules, redirect refusal, known rejected vs ambiguous presentation, lease/CAS recovery, fake-clock timing. |
| EX-011 | `internal/telemetry/*.go`, `cmd/worker/logging_test.go` | Prometheus, Factory work stages and metric names/prefix. | `internal/telemetry` and runtime-specific metrics. | Reuse design, not code wholesale. Start with `slog`, bounded labels, runtime session/turn/tool/sandbox metrics. | JSON log correlation/redaction, metric registration/failure, bounded labels, metric semantic tests. |
| EX-012 | `docs/SoftwareStyle.md`, `AGENTS.md`, `.golangci.yml`, `Justfile`, `scripts/bootstrap.sh`, `scripts/regenerate.sh`, `CONTRIBUTING.md` | Factory domain paths, Go 1.26.5/Bun 1.2.19/sqlc/Huma/Orval stack. | Root `AGENTS.md`, `docs/engineering/`, `.golangci.yml`, `Justfile`, CI. | Adopt standards and verification patterns; rewrite every product-specific path, command, tool/version, and generated artifact. | Linter probes for protected boundaries, toolchain bootstrap test, regeneration check, `just verify` in CI. |
| EX-013 | `dimensions/skills/refresh-dims-skill/**`, `skills/develop-with-dims/source-manifest.json`, related contract tests | dims contract ledger, Go/CAD sources, curated example paths. | `skills/refresh-agent-runtime-docs/**` and `skills/develop-with-agent-runtime/**`. | Reimplement pattern; do not copy dimensions capabilities. | Deterministic render; check mode; output containment; atomic write; dirty output refusal; curated-section preservation/proposal; docs build/link/snippet/example/API checks; exact diff presentation. |

## Explicitly excluded Factory product code

The following may inform design but must not be extracted into the runtime implementation:

| Factory areas | Why excluded |
|---|---|
| `internal/workflows/dispatcher.go`, `work_on_ticket.go`, `maintain_factory.go` and their tests | Ticket admission, planning/implementation/review stages, GitHub merge and Factory ownership state are a different product. Rebuild session/turn/approval workflows from the new domain contract. |
| `internal/activities/**` except general test patterns | Activities encode Tickets, Runs, PR/CI policy, Factory record persistence, and its agent-stage model. |
| `internal/clients/github/**`, `internal/githubpolicy/**`, `internal/webhook/**`, `cmd/relay`, `cmd/verify-github-policy` | Out of scope for a generic runtime and hazardous as accidental scope growth. |
| `internal/clients/k8s/**`, `cmd/run-worker`, `cmd/tool-worker`, `internal/runworkercapability/**`, `images/run-worker/**` | The new sandbox must have a purpose-built contract and backend lifecycle; Factory's pod model and GitHub credentials are not a substitute. |
| `internal/store/**`, `internal/database/**`, `sqlc.yaml`, migration history | Ticket/Run/Attempt schema and Factory audit model are not the runtime schema. Learn from its typed store/fake/contract approach instead. |
| `web/**`, `cmd/api`, `internal/api/**` | Factory console and Ticket API are not examples or runtime public contract. Build the new API/OpenAPI and Astro Starlight documentation from the new domain. |
| `_archived/**` | Explicitly historical and excluded by Software Factory's own active instructions. Never copy from it. |

## Adoption sequence and completion record

Copy in this order so dependencies and proof move together:

1. EX-012 standards/CI scaffolding and EX-001 clock.
2. EX-002 blobstore and EX-003 blob service, including MinIO adapter.
3. EX-004/EX-005 temporalpayload and EX-006/EX-007 worker/UI codec parity.
4. New runtime kernel/storage types, then EX-008 patterns.
5. New sandbox contract/backend and tools; these are new work, not extraction.
6. Provider-neutral model seam, then EX-009/EX-010 only if current external verification permits the experimental adapter.
7. EX-013 documentation skills, Astro Starlight integration, and generated public documentation checks.

For every extraction, append a completion row here with:

```text
EX-ID:
source commit:
source paths:
destination paths:
source imports removed: yes/no
destination-owned tests:
verification commands and result:
third-party license/SBOM result:
documentation refresh/check result:
reviewer:
```

No row may state `complete` while it still imports `github.com/0x63616c/software-factory`, lacks its destination test set, or has not passed the monorepo's generated-docs and license checks.
