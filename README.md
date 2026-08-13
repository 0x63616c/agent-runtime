# Agent Runtime

Agent Runtime is a Go platform for durable, session-based agents. It gives an
application a stable public API for versioned Agents and Policies, Sessions,
Turns, ordered Events, approvals, artifacts, and governed tools. The runtime
keeps orchestration, model access, and sandbox execution behind explicit,
reviewable boundaries.

This is self-hosted, open-source software. It is not a hosted managed service,
a generic autonomous-agent platform, or a promise that a granted process cannot
disclose the authority it was deliberately given.

## What is here

- A versioned HTTP API and [public Go SDK reference](https://0x63616c.github.io/agent-runtime/docs/reference/overview).
- Durable runtime-state and orchestration seams.
- Durable Chat, Workspace Agent, and Research Dossier examples.
- A local Kubernetes Stack with separately declared API, orchestration, model,
  tool, blob, codec, sandbox-control, and sandbox-host roles.
- Sandbox contracts that fail closed when an advertised isolation capability is
  unavailable.

Read the [public documentation](https://0x63616c.github.io/agent-runtime/),
then use the [tutorial](website/src/content/docs/docs/tutorials/durable-chat.mdx)
and [code overview](website/src/content/docs/docs/concepts/code-overview.mdx)
to orient yourself in the repository.

## Safety and evidence boundary

The supplied API configuration uses in-memory storage and loopback networking
for local exploration. It is not a production deployment configuration. The
local unsafe sandbox adapter is useful for development compatibility checks; it
is not Firecracker isolation. Firecracker claims require separate, retained
Linux/x86_64 KVM evidence.

The generated [requirements dashboard](docs/planning/requirements-dashboard.html)
and [evidence/status runbook](docs/operations/evidence-and-status.md) show the
distinction between code, local checks, hosted CI, and environment proof. Do
not treat a green local command as evidence for a deployment-specific boundary.

## Architecture

The public API and SDK own the application contract. Runtime state and
orchestration own durable session progress. Model and tool adapters pass
through policy, approval, capability-grant, audit, and bounded-output seams.
The sandbox control plane and host agent have separate authority; a sandbox
adapter may advertise capabilities only when it can enforce them.

For the accepted system view, see the [architecture guide](docs/architecture/system.md),
[runtime language](website/src/content/docs/docs/concepts/runtime-language.mdx),
and [sandbox verified boundaries](website/src/content/docs/docs/security/verified-boundaries.mdx).

## Five-minute local start

Prerequisites: Go 1.26+, and two disposable local bearer strings. This starts
only the loopback API; it intentionally does not create a production Stack or
claim sandbox isolation.

```sh
export AGENT_RUNTIME_ADMIN_TOKEN='replace-with-at-least-16-bytes'
export AGENT_RUNTIME_DEVELOPER_TOKEN='replace-with-at-least-16-bytes'
go run ./cmd/agent-runtime-api --config "$PWD/deploy/runtimeapi/api.example.json"
```

In another terminal, start the browser example. It listens only on loopback and
keeps the runtime bearer token out of the browser:

```sh
go run ./examples/durable-chat/cmd/durable-chat \
  --mode=web \
  --runtime-url=http://127.0.0.1:8088
```

Stop both processes with `Ctrl-C`. For the declarative local Stack, its
preflight and its cleanup contract, follow the [local Stack guide](website/src/content/docs/docs/build-and-run/local-stack.mdx).

## Commands

| Command | Purpose |
| --- | --- |
| `just check` | Fast repository gate: generated artifacts, race tests, vet, Linux lint, and ledger structure. |
| `just docs-check` | Regenerate/check docs, validate routes, and build the production documentation site. |
| `just generate` | Regenerate checked-in requirement and OpenAPI artifacts. |
| `just requirements-dashboard` | Refresh the local HTML requirement/evidence view. |
| `just dev-preflight` | Validate the explicitly allow-listed local Stack context before any Kubernetes writes. |
| `just dev` / `just dev-down` | Create or remove one labelled local development Stack. |
| `just verify` | Final release gate; deliberately remains red until every canonical requirement has valid completed evidence. |

Run `just` with no arguments to list the complete command surface. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the direct-main verification and
evidence workflow.

## Examples and tutorials

- [Durable Chat tutorial](website/src/content/docs/docs/tutorials/durable-chat.mdx)
- [Workspace Agent](website/src/content/docs/docs/examples/index.mdx)
- [Research Dossier](website/src/content/docs/docs/examples/research-dossier.mdx)
- [Local runtime foundation](website/src/content/docs/docs/build-and-run/local-foundation.mdx)

Examples use narrow demo identities and cleanup boundaries. They are not
templates for granting broad administrator credentials to application code.

## Documentation, support, and contributing

The public docs contain the [HTTP and SDK references](https://0x63616c.github.io/agent-runtime/docs/reference/overview),
operator material, troubleshooting, and documentation publication policy.
Questions and contributions should start with [CONTRIBUTING.md](CONTRIBUTING.md),
[AGENTS.md](AGENTS.md), and the binding
[requirements](docs/planning/requirements/master-requirements.md).

Report security-sensitive issues privately to the repository owner rather than
including secrets, raw prompts, or exploitable detail in a public issue. The
[verified-boundaries guide](website/src/content/docs/docs/security/verified-boundaries.mdx)
records what the project does and does not currently prove.

## License

Licensed under the terms in [LICENSE](LICENSE).
