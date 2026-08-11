# Agent Runtime

Agent Runtime is a Go monorepo for a durable, session-based agent platform.
Public documentation is available at
[0x63616c.github.io/agent-runtime](https://0x63616c.github.io/agent-runtime/).
M0 and the M2 payload milestone are complete. M1 declarative infrastructure
and M3 sandbox-control work are active. The repository now exposes a runnable
isolated Tilt infrastructure foundation and the reusable `temporalpayload`
package, but it does not yet expose the public agent runtime service, working
examples, production runtime image composition, or verified Firecracker
isolation.

The first M5 slice now publishes the Temporal-free Go contract at
`github.com/0x63616c/agent-runtime/sdk/go` plus a deterministic internal kernel
for immutable Agent revisions, revision-pinned Sessions, idempotent Input,
serialized Turns, cancellation, and cursor-addressed Product events. The
contract compiles from an independent module. It is not yet backed by the
public HTTP service, PostgreSQL, or Temporal orchestration.

The current Tilt foundation projects the reviewed typed local Stack into eight
health-only trust-scoped role images—API, orchestration, model, tool, blob,
codec, sandbox control, and sandbox host—with per-role identities and exact
credential references. It proves isolated infrastructure, image builds,
readiness, reset, and teardown; it is not yet the public Agent Runtime. See the
[local Stack guide](website/src/content/docs/docs/build-and-run/local-stack.mdx) for the exact
boundary.

## Verification

The supported incremental repository check is:

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
This is expected until the full release ledger is green; it does not reopen a
previously completed milestone.

## Configuration and status evidence

Process configuration is constructed explicitly through `runtimeconfig`; domain
packages do not read environment variables. Diagnostics, JSON, formatting and
structured logs redact notifier credentials. The only accepted status topic is
`https://ntfy.sh/0x63616c-ai-agant` (spelling intentional).

The milestone implementation accepts a complete canonical catalog before it
builds a weighted estimate, retains evidence before notifier delivery, records
failures as retryable classified codes, and transports only the ADR-defined
structured payload. It provides a deterministic fake notifier for tests and a
fixed-topic ntfy transport for completion operations. The retained M0 record
preceded successful delivery; later milestone owners use the same pipeline only
after their complete evidence gates are green.

## Compatibility

The repository publishes one root module,
`github.com/0x63616c/agent-runtime`, and currently requires Go 1.26 or newer.
Contributor and delivery policy is in [CONTRIBUTING.md](CONTRIBUTING.md); the
[Go compatibility](docs/engineering/go-compatibility.md) and
[generated ownership](docs/engineering/generated-ownership.md) policies state
the current boundaries.
All public packages share one semver release train. Compatibility, deprecation,
generated API ownership, and clean external-consumer verification remain
release requirements and are not yet release guarantees.
