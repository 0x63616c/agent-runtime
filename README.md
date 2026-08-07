# Agent Runtime

Agent Runtime is a Go monorepo for a durable, session-based agent platform.
M0 currently provides the governed foundation only; it does not yet bootstrap
infrastructure, expose a runtime service, or claim sandbox isolation.

## Verification

The supported incremental M0 check is:

```sh
just check
```

It requires `just` 1.58.0 (pinned in `.tool-versions`) and runs module
verification, the Go race suite, vet, an AST-based real-time-wait check, and
schema/completeness validation for the generated 183-row
[catalog](evidence/requirements-catalog.json) and
[ledger](evidence/requirements-ledger.json). `check` proves the evidence
register is structurally honest; it does not turn non-green rows into passes.

`just verify` is the binding milestone/release completion gate. It reruns
`check`, emits the complete 183-row status/evidence report, and currently fails
because requirements are `in_progress` or `not_started`, with no immutable
main-CI or complete acceptance evidence. `just completion-check` is an alias.
M0 remains open and no notification is sent.

## Configuration and status evidence

Process configuration is constructed explicitly through `runtimeconfig`; domain
packages do not read environment variables. Diagnostics, JSON, formatting and
structured logs redact notifier credentials. The only accepted status topic is
`https://ntfy.sh/0x63616c-ai-agant` (spelling intentional).

The internal milestone foundation accepts a complete canonical catalog before it
builds a weighted estimate, retains evidence before notifier delivery, records
failures as retryable classified codes, and transports only the ADR-defined
structured payload. It provides a deterministic fake notifier for tests. This foundation
does not send a real milestone notification; a later completion owner may do so
only after all M0 evidence gates are green.

## Compatibility

The repository publishes one root module,
`github.com/0x63616c/agent-runtime`, and currently requires Go 1.26 or newer.
Contributor and delivery policy is in [CONTRIBUTING.md](CONTRIBUTING.md); the
[Go compatibility](docs/engineering/go-compatibility.md) and
[generated ownership](docs/engineering/generated-ownership.md) policies state
the current M0 boundaries.
All public packages share one semver release train. Compatibility, deprecation,
generated API ownership, and clean external-consumer verification remain
in-progress M0 requirements and are not yet release guarantees.
