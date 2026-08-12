# Agent Runtime

Agent Runtime is a Go platform for durable, session-based agents. It gives an
application a stable public API for versioned Agents and Policies, Sessions,
Turns, ordered Events, approvals, artifacts, and governed tools—while keeping
the orchestration and infrastructure boundaries explicit.

The repository includes:

- a versioned HTTP API and Go SDK;
- a deterministic runtime kernel and durable orchestration seams;
- Durable Chat, Workspace Agent, and Research Dossier examples;
- a local Kubernetes Stack with isolated API, orchestration, model, tool,
  blob, codec, sandbox-control, and sandbox-host roles;
- sandbox contracts that fail closed when an isolation capability is not
  actually available.

Read the [public documentation](https://0x63616c.github.io/agent-runtime/),
start with the [tutorial](website/src/content/docs/docs/tutorials/durable-chat.mdx),
or use the [code overview](website/src/content/docs/docs/concepts/code-overview.mdx)
to navigate the repository.

## Verify a change

```sh
just check
```

This runs module verification, the Go race suite, vet, generated-contract
checks, and architecture tests. Documentation changes should also run:

```sh
just docs-check
```

## Run the local API and example

```sh
export AGENT_RUNTIME_ADMIN_TOKEN='replace-with-at-least-16-bytes'
export AGENT_RUNTIME_DEVELOPER_TOKEN='replace-with-at-least-16-bytes'
go run ./cmd/agent-runtime-api --config "$PWD/deploy/runtimeapi/api.example.json"
```

In another terminal:

```sh
go run ./examples/durable-chat/cmd/durable-chat \
  --mode=web \
  --runtime-url=http://127.0.0.1:8088
```

The example listens only on loopback and keeps the runtime bearer token out of
the browser. The supplied API configuration uses in-memory storage for local
exploration; it is not a production deployment configuration.

## Compatibility

The root module is `github.com/0x63616c/agent-runtime` and requires Go 1.26 or
newer. Public API and generated-source ownership policies are documented in
[CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/engineering/go-compatibility.md](docs/engineering/go-compatibility.md).
