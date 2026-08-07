# Reuse audit — Software Factory and dimensions

Status: planning evidence, not an extraction.
Sources inspected: `software-factory` at `4a427d0080ba6cc73609af13242251d3f45d6c70` and the dimensions documentation-skill implementation on 2026-08-06.
Destination: this single public MIT monorepo. No package is proposed as a separate repository.

## Decision

Reuse the proven *boundaries, contracts, tests, and implementation techniques* from Software Factory. Copy small, infrastructure-only packages only after their imports have been removed or consciously rehomed. Do not fork the Factory product into this repository: Tickets, GitHub policy, pull requests, Run Workers, Kubernetes pod policy, SQL schema, and its operator console have different domain ownership.

The first extraction wave is deliberately narrow:

1. `platform/clock` — direct, small adaptation.
2. `packages/blobstore` — direct adaptation plus a real object-store backend.
3. `packages/temporalpayload` — refactor from the payload pipeline, with its own compatibility suite.
4. The durable conversation/artifact approach — reimplement beneath the runtime domain types.
5. The Codex subscription provider and credential rotation logic — adopt only behind an experimental, isolated provider adapter after a current compatibility and terms review.

The design rules, TDD discipline, contract fakes, `slog`, toolchain checks, generator discipline, and Temporal replay practices are mandatory repository conventions from the first commit.

## Evidence and what it proves

| Source evidence | What is reusable | What cannot move unchanged |
|---|---|---|
| `software-factory/AGENTS.md:1-183`, `docs/SoftwareStyle.md:18-274`, `.golangci.yml:1-221` | The priority order; deterministic workflow discipline; injected external edges; single composition root; no leaky SDK types; `slog`; race testing; generator-as-contract approach. | Factory names, archived-tree rules, GitHub/Run Worker policy, specific queue names, and the instruction typo at `AGENTS.md:185`. |
| `internal/clock/clock.go:16-26`, `clocktest/fake.go`, `clock_test.go` | UTC clock interface, cancellation-aware sleep, fake-clock advancement, and no test sleeps. | The package path and Factory-only comments. The runtime must also inject the timer used by any observability wrapper. |
| `internal/blobs/{store,key,file,http,mem}.go` and four focused test files | Opaque content-addressed storage contract; safe key parsing; atomic filesystem writes; HTTP client with bounded errors; in-memory fake. | Closed buckets `payloads`/`conversations`; file service configuration; only a filesystem implementation exists — MinIO/S3 is still required. |
| `internal/payloads/{layer,compress,offload,chain,observe}.go` and five focused test files | Layered codec structure; zstd-before-offload ordering; exact metadata/wire-format golden test; codec server shares exactly the worker chain; context-derived content address. | It imports Factory `work`, `blobs`, and telemetry; uses a fixed 30-second background timeout; its observer reads the system clock; it has no public configuration/version policy. |
| `cmd/blobs`, `cmd/codec`, Dockerfiles, and their unit tests | Separate blob and Temporal codec processes, health endpoints, CORS tests, and payload-safe logging. | Namespace allowlist, image names, CORS configuration, metric prefix, all Factory deployment configuration. |
| `internal/agent/{conversation_store,transcript_store,artifact_store}.go` and tests | Immutable revision chains, SHA-256 verification, content-addressed tool/result artifacts, and keeping payload contents out of durable audit events. | Factory workflow identities, `work.Usage`, agent stage semantics, and the `conversations` bucket. |
| `internal/clients/codexresponses/*` and tests | Typed provider boundary; streamed SSE parsing; tool-call continuation; structured output; safe provider-error metadata; explicit idempotency headers; transient event sink separate from durable result. | It declares the endpoint unsupported (`doc.go:1-4`), hard-codes the Factory originator (`client.go:81-99`), and is an internal implementation rather than a runtime-neutral model API. |
| `internal/clients/codexauth/*` and its contract/fake tests | Credential redaction; refresh-token-free presentation; CAS-backed single-writer refresh lease; redirect refusal; bounded response; conservative unknown-result handling. | It imports Factory `work`, its Kubernetes secret adapter, Factory metrics, and provider facts captured from a particular Codex CLI release. It must never be surfaced in the public SDK or copied into examples. |
| `scripts/regenerate.sh`, `scripts/bootstrap.sh`, `Justfile`, `sqlc.yaml`, `.github/workflows/ci.yml` | Pinned tools; a small command vocabulary; regeneration followed by a clean-diff check; race, integration, E2E, and image gates. | SQLC, Huma/Orval, React/Bun versions, Postgres schema, and every Factory release/publish workflow. |
| `dimensions/skills/refresh-dims-skill/SKILL.md:1-21`, `references/regeneration.md:1-66`, `scripts/refresh/main.go:11-77` | A docs skill backed by deterministic generated facts, an explicit source manifest, atomic writes, dirty-output protection, check mode, full validation, and exact diff review. | dims-specific contracts, source paths, Go-only discovery, and its curated CAD/example content. |

Focused source verification passed before this audit:

```text
go test -race ./internal/payloads ./internal/blobs \
  ./internal/clients/codexresponses ./internal/clients/codexauth ./internal/clock
```

The five packages passed. This proves the source packages' current local tests, not compatibility with Agent Runtime; every adopted seam needs new destination-owned tests.

## Required architecture changes before copying

### Shared package boundaries

The Factory's imports run through `internal/`, so none of its reusable code can be imported directly by this monorepo's public API or SDK. Rehome code before changing it:

```text
agent-runtime (one public MIT monorepo)
├── packages/blobstore/        opaque byte storage; file, HTTP, S3/MinIO adapters
├── packages/temporalpayload/  codec chain and Temporal UI codec handler
├── packages/sandbox/          independent sandbox contract and implementations
├── sdk/go/                    separate Go module; HTTP/event contract only
├── apps/                      runtime API, worker, blob service, codec service, CLI
└── internal/runtime/          kernel, Temporal adapter, providers, tools, artifacts
```

`go.work` may join the root module, `sdk/go`, `packages/blobstore`, `packages/temporalpayload`, and `packages/sandbox`; that is a monorepo layout, not a set of repositories. The public Go SDK must not import a Temporal, blob-store, sandbox, provider, or telemetry implementation.

### Payload/blob pipeline

Keep the important order: serialization -> zstd compression -> remote offload on encode, and reverse it on decode. It is a durable wire contract. The destination package must add:

- explicitly versioned metadata keys owned by `temporalpayload`, never `sf-codec-v`;
- an exported, validated options type (threshold, timeout, bucket/prefix, encryption-layer position);
- injected timing/metrics hooks instead of `clock.System{}` in `observe.go`;
- a complete context strategy for Temporal's contextless codec API, with test-controlled timeout behaviour;
- golden fixtures copied only after updating their protocol ownership and retaining legacy-decode tests;
- an S3/MinIO implementation, integrity checks on all immutable artifact reads, and a retention policy before adding deletion;
- codec-server configuration derived from the local Tilt stack namespace rather than the Factory's static namespace map.

The existing `Bucket` is intentionally closed (`payloads`, `conversations`) and must be redesigned as runtime-owned typed namespaces. `artifacts`, `conversations`, `transcripts`, and codec payloads must have a policy document before names become public storage layout.

### Agent evidence and artifacts

The immutable conversation/transcript chain is a good fit, but it must be expressed as `SessionID`, `TurnID`, `ToolCallID`, `ArtifactID`, and content digest references rather than a Factory `run/stage/attempt` identity. Keep these invariants:

- every revision points to an existing predecessor of the same logical stream;
- content references contain key, byte count, and SHA-256 digest;
- structured model/tool content stays in blobs, while event/audit records remain bounded;
- a failed verification is terminal for that attempted read rather than silently recovering.

Do not use the Factory's implicit identity strings as the user-visible identity scheme. The requested Stripe-style IDs need one runtime-owned generator and parser; the Factory's current persistence relies primarily on Postgres integers and Temporal UUIDs (`internal/store/domain.go:33`, `internal/work/runworker.go:21-45`), so it is not the implementation to copy.

### Codex provider and authentication

The split between provider-neutral turn semantics and a provider-specific adapter is sound. The direct subscription-backed client is expressly an unsupported ChatGPT backend contract, so it is unsuitable as the default public path. The new runtime should:

1. Define the runtime's internal `Model`/streaming interface first.
2. Ship a documented, supported provider route using the current official API credentials.
3. Keep any Codex subscription adapter at `internal/providers/codexsubscription`, marked experimental and feature-gated, with a current canary and a manual operator setup step.
4. Replace `originator: software-factory`, Factory metrics and `work.Credential` with runtime-owned values and redacted types.
5. Reuse the refresh safety model only with an atomic CAS-capable secret store; no refresh token enters a sandbox, Temporal history, HTTP response, log, artifact, or example fixture.
6. Add tests that prove redaction, redirect refusal, rejected/ambiguous refresh handling, cancellation, and replay-safe durable results.

The Factory source contains a public OAuth client ID and endpoint, not a checked-in token, but those provider facts are time-sensitive. Re-verify them against an authoritative current source during implementation; do not treat this audit as a promise that the endpoint remains available.

## Style and test conventions to adopt unchanged in intent

- `Legibility > Correctness > Operability > Economy`; testability is a non-negotiable floor.
- Parse external input once at a boundary into typed values. No usable invalid zero values.
- Required dependencies are constructor parameters; options are small, sealed functional options.
- Consumer-side interfaces are minimal. Accept interfaces; return concrete types.
- `context.Context` is the first parameter and never lives in a struct. Temporal workflows instead use `workflow.Context`, `workflow.Now`, `workflow.Sleep`, `workflow.Go`, and explicit compatibility versions.
- Use `fmt.Errorf("action: %w", err)` at every meaningful boundary. Map durable retry/terminal behaviour onto Temporal's error taxonomy in the Temporal adapter; do not build a competing global error framework.
- Use JSON `slog` at decision points, with session/turn/workflow/correlation identifiers. Never log token-bearing values or unbounded user/model/tool payloads.
- `time.Now`, local time, sleeps, environment reads, random sources, and real clients are composition-root-only external edges. Unit tests use fakes; real integrations are labelled separately.
- Test names describe present-tense behaviour. Use `go test -race`; use Temporal's testsuite for workflow behaviour and exported-history replay tests for compatibility.
- Generated source is not hand-edited. Regenerate, run a check mode, and require a clean diff in CI.

## Documentation skill: adopt the dimensions pattern, broaden its scope

Create a repo-local `skills/refresh-agent-runtime-docs/SKILL.md`. It is not a prose reminder. It must be a tested workflow with a small generator and explicit input manifest:

```text
skills/
├── develop-with-agent-runtime/
│   ├── SKILL.md
│   ├── source-manifest.json
│   └── references/runtime-map.md          generated
└── refresh-agent-runtime-docs/
    ├── SKILL.md
    ├── references/regeneration.md
    └── scripts/refresh-docs/              deterministic runner
```

Its source of truth is current code plus passing contracts, OpenAPI generation, the SDK's public Go doc surface, Docusaurus configuration, and executable examples. Curated conceptual/security/runbook sections are marked and never silently overwritten. The runner must atomically regenerate only named outputs, refuse overwriting conflicting edits, support `--check`, then run `just docs-check` and print the exact docs/skills diff. CI runs its check mode and fails on stale generated reference, code sample, route, config key, or OpenAPI client documentation.

Unlike dimensions, it must additionally validate public API reference, every public configuration key, all three runnable examples, markdown links, Docusaurus build/search metadata, and every fenced command/snippet that claims to run. It must never advertise planned routes as implemented.

## Public MIT and provenance controls

`agent-runtime/LICENSE` is MIT, copyright Calum (2026). The inspected Factory root has no active `LICENSE`, `COPYING`, or `NOTICE` file, and the current source history reports one author, Calum. The user has expressly authorized this extraction. That is sufficient project direction, but not a substitute for preserving third-party notices.

Before each source copy:

1. Record source commit, exact paths, destination paths, and test provenance in `docs/planning/reuse/extraction-manifest.md`.
2. Check all imported dependencies are compatible with MIT distribution and generate an SBOM/license report in CI.
3. Preserve any required third-party notices. Do not copy vendored modules, generated third-party code, credentials, test recordings containing credentials, `.env` files, Kubernetes Secrets, or deployment values.
4. Give copied code destination-owned package comments, ownership names, metrics, configuration, and tests. Source imports of `github.com/0x63616c/software-factory/...` must be zero before the copied change is considered complete.

## Non-negotiable gaps still to build

This audit identifies reusable foundations; it does not claim the following exist yet:

- sandbox API, real Linux execution backend, Firecracker/KVM strategy, artifact transfer, capability enforcement, and recovery tests;
- runtime kernel, sessions/turns/events/approval domain, HTTP API/OpenAPI, Go SDK, authorization, and Temporal workflows;
- local Tilt topology, MinIO/S3, Postgres, Temporal, codec, observability, and one-command verification;
- Docusaurus site and tested documentation-refresh skill;
- all three working examples and their end-to-end tests;
- an approval workflow that persists the request, streams the pending state, accepts/rejects an idempotent response, survives restart, and is demonstrated in an example.

Those are build requirements, not areas where the Factory code may be copied as a shortcut.
