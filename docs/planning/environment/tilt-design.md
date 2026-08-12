# Tilt isolation design

## Decision

Use one public `agent-runtime` monorepo and one already-running local OrbStack
Kubernetes cluster. Each working directory runs an independent Tilt stack in its
own Kubernetes namespace with stack-specific image names and host ports.

The design is deliberately stricter than "a namespace per developer": one
developer can run several Git worktrees at once without a database, workflow,
image, or port collision.

```text
worktree A ── just dev ── Tilt ── namespace ar-calum-81f2c4a9
                                     ├─ api, worker, temporal
                                     ├─ postgres, blob store, telemetry
                                     └─ images agent-runtime-dev/calum-81f2c4a9/*

worktree B ── just dev ── Tilt ── namespace ar-calum-2b17d6e0
                                     ├─ same resource names, isolated namespace
                                     └─ images agent-runtime-dev/calum-2b17d6e0/*
```

This is a development-only topology. It neither deploys to production nor
pretends that a local container sandbox has production microVM isolation.

## Developer contract

The finished repository exposes this small command surface:

```text
just dev                         # start this worktree's isolated Tilt stack
just dev STACK=feature-x         # choose a readable, validated stack id
just dev-status                  # show the selected namespace and endpoints
just dev-down                    # delete only this stack's namespace
just dev-preflight               # verify the local, non-secret prerequisites
```

`just dev` is the friendly entrypoint. The exact controlled Tilt invocation is:

```text
tilt up \
  --context orbstack \
  --namespace ar-<stack> \
  --port <free-dashboard-port> \
  -- --stack=<stack> --profile=local
```

Tilt supports `--context`, `--namespace`, `--port`, and Tiltfile arguments
after `--`; this invocation is therefore based on documented CLI behavior.
See [Tilt `up`](https://docs.tilt.dev/cli/tilt_up.html) and
[Tiltfile configuration](https://docs.tilt.dev/api.html#config-parse).

The launcher owns the derived values in a gitignored per-worktree state file,
for example `.runtime/dev/<stack>.json`. That file contains only the
worktree path fingerprint, namespace, dashboard port, and creation timestamp;
it contains no credentials or secret values. It lets `dev-status` and `dev-down`
address the same stack after a restart.

### Stack identity

The default stack id is deterministic for a worktree, not a branch:

```text
<sanitised-local-user>-<first-8-hex-of-canonical-worktree-path>
```

The launcher derives the canonical path, converts the supplied or derived id to
lowercase DNS-label characters, and rejects anything that cannot form the
namespace `ar-<stack>` within Kubernetes' 63-character limit. `STACK` is
an optional human-friendly override. An override is still validated and is
recorded before it is used for a teardown.

This prevents two worktrees on the same branch from silently sharing a stack.
It also makes the destructive command target discoverable and reviewable.

### Context and namespace guardrails

The Tiltfile must contain both a static allow-list and a runtime assertion:

```python
allow_k8s_contexts('orbstack')

config.define_string('stack', usage='unique local stack id')
config.define_string('profile', usage='local or ci')
cfg = config.parse()
stack = cfg.get('stack')
if k8s_context() != 'orbstack':
    fail('agent-runtime local development only permits Kubernetes context orbstack')
if not stack:
    fail('use just dev or pass -- --stack=<id>')
```

`allow_k8s_contexts` is an intentional second layer, not a replacement for the
assertion: the local kubeconfig also has non-local context names. Tilt documents
the function as a guard against accidental deployment to production
clusters. [Tiltfile API](https://docs.tilt.dev/api.html#allow-k8s-contexts)

The render step must meet these rules:

- It emits one `Namespace` named `ar-<stack>` and no other Namespace.
- Namespaced objects omit `metadata.namespace`; Tilt's explicit `--namespace`
  supplies the target namespace. A manifest test rejects hard-coded `default`
  or any other namespace.
- It emits no CRD, `ClusterRole`, `ClusterRoleBinding`, `StorageClass`,
  `IngressClass`, admission webhook, or other cluster-scoped object.
- All objects carry `app.kubernetes.io/part-of: agent-runtime` and
  `agent-runtime.dev/stack: <stack>`. The cleanup command validates both
  the stored namespace and that stack label before it calls Tilt.
- `just dev-down` invokes the matching `tilt down --context orbstack
  --namespace ar-<stack> --delete-namespaces -- --stack=<stack>`.
  Tilt documents that namespaces are retained by default and are deleted only
  with `--delete-namespaces`; the explicit flag makes teardown behavior
  inspectable rather than implicit.

The CLI must never write the user's current kubeconfig namespace. Selecting
`--context` and `--namespace` per invocation is both safer and reversible.

## Image and host-port isolation

### Images

Every Tilt build reference includes the stack id:

```text
agent-runtime-dev/<stack>/api
agent-runtime-dev/<stack>/worker
agent-runtime-dev/<stack>/example-<name>
```

The same image name must appear in the rendered workload so Tilt can inject the
built image. This matters on a shared OrbStack Docker daemon: two worktrees
must not retag `agent-runtime/api` over each other. `docker_build` is the
appropriate Tilt primitive; Tilt documents that it selects a runtime-accessible
handoff strategy when it recognizes the target runtime. See
[`docker_build`](https://docs.tilt.dev/api.html#docker-build).

The local profile builds native `linux/arm64` images. It must not set
`DOCKER_DEFAULT_PLATFORM=linux/amd64` or use amd64-only base images. Multi-arch
release images are a separate release concern, verified in Linux CI.

### Ports

Fixed host ports make parallel Tilt stacks fragile, including Tilt's dashboard
port (which otherwise defaults to 10350). `just dev` allocates an available
localhost dashboard port, stores it with the stack state, and prints its
URL. It retries the launch if another program wins the short allocation race.

Application services have no fixed `k8s_resource(port_forwards=...)` mapping.
The checked-in Stack deliberately has no durable public API workload or
port-forward command while its pinned production image lacks that executable.
Tilt's documented port-forward feature remains available for explicitly
requested debugging of declared role services. See [Tilt service
endpoints](https://docs.tilt.dev/accessing_resource_endpoints.html).

## Development dependency boundary

| Boundary | Included | Excluded |
| --- | --- | --- |
| Host prerequisites | Git checkout, `just`, Tilt, Docker, an already-running OrbStack Kubernetes cluster | A host PostgreSQL, Temporal server, MinIO, broker, local daemon, cloud account, or persistent kubeconfig change |
| Per-stack namespace | API, worker, all example applications, Temporal development server, PostgreSQL, S3-compatible blob store, development telemetry collector, migrations, and generated dev-only secrets | Cluster-scoped controllers, CRDs, a shared database, shared message broker, a production certificate, a production registry credential |
| Sandbox | A contract-compatible development/test driver with an explicit `development` security mode | A claim that macOS containers are Firecracker microVMs or that they are appropriate for hostile multi-tenant code |
| Production / KVM | Linux KVM Firecracker driver, Jailer configuration, egress policy, host hardening, production secrets | Tilt and a developer's laptop |

Dependencies may reuse the same simple names (`postgres`, `temporal`, `blob`)
because the namespace is unique. They must use ephemeral development storage by
default, request/limit resources explicitly, and be disposable as a group.

Temporal's production deployment, long-lived storage, and Firecracker fleet
management are not dependencies of `just dev`. This keeps the fast path easy to
run while preserving one source repository for every deployment asset,
integration test, generated API artifact, and documentation site.

## Implementation layout

The proposed layout stays inside the monorepo:

```text
Tiltfile
justfile
tools/dev/                    # stack validation, state, preflight, forwarding
deploy/dev/                   # namespaced Helm/Kustomize inputs and dev values
deploy/production/            # separately reviewed production deployment inputs
cmd/ internal/ pkg/           # Go API, worker, SDK, and shared contracts
examples/                     # runnable examples used by docs and tests
website/                      # Astro Starlight public site and generated reference output
.github/workflows/            # ordinary CI plus the Linux-KVM proof workflow
```

`tools/dev` is a versioned part of the product contract. Its tests must include
bad context, malformed id, conflicting state, stale namespace, and cleanup
target cases; it must not become an undocumented personal shell script.

## What local Tilt proves, and does not prove

`just dev` proves that the Go services, Temporal integration, payload/blob
paths, example applications, configuration, and development sandbox interface
compose on a real Kubernetes API. `tilt ci` exits successfully only when its
resources are healthy, which makes it useful for a disposable cluster
integration gate. [Tilt CI](https://docs.tilt.dev/ci.html)

It does not prove KVM availability, Firecracker's production Jailer path,
host firewall configuration, kernel/microcode posture, or hostile-tenant
isolation. Those claims require the Linux/KVM path in the verification matrix.
