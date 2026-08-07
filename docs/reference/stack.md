# Declarative Stack reference

Status: M1 typed contract, Kubernetes manifest projection, and audited
operator boundary implemented; local Tilt application remains owned by issue
#12 and is not yet a runnable quickstart.

`internal/stack` is the sole typed desired-state contract for operator-owned
infrastructure. It is intentionally private to the repository composition and
operator boundary: runtime/product APIs do not expose Temporal, Kubernetes,
storage-provider, or backend identifiers.

## Stack identity and profiles

One schema-version `1` document declares one lowercase DNS-label-safe `name`
and the closed profile set `local`, `ci`, and `production`. The operator tool
accepts its path as `--stack-file`; the planned Tilt surface accepts that exact
validated `name` as `--stack=<name>`. There is no competing `instance` identity.
Each profile explicitly declares its namespace:

| Profile | Namespace binding |
| --- | --- |
| `local` | `ar-<stack-name>` |
| `ci` | `ar-ci-<stack-name>` |
| `production` | `<stack-name>` |

The explicit values must match those bindings. This prevents two Stack names
from silently targeting the same namespace while keeping the namespace in
reviewed desired state. Unknown fields, missing profiles, empty resource sets,
duplicate IDs, dangling dependencies, cycles, and profile topology divergence
are rejected before rendering.

## Resource contract

Every resource has a stable `id`, closed `kind`, owner, scope, complete
dependency list, retention policy, backup/restore owner, safe delete behavior,
and an explicit external-controller flag. Exactly one matching typed payload is
required.

| Kind | Typed declaration |
| --- | --- |
| `kubernetes` | Allowlisted namespaced object, immutable workload image, explicit service account/ports/storage, finite compute, bounded RBAC, or default-deny network policy. |
| `orchestration` | Namespace, finite retention, task-queue prefix, and explicit search-attribute/schedule sets. The current private Temporal adapter reconciles namespace existence and retention; it rejects non-empty search-attribute or schedule sets until those provider mappings are implemented. |
| `blob` | Bucket/prefix plus declared endpoint and credential-resource references. |
| `database` | Database/schema, credential-resource reference, and ordered immutable upgrade/rollback migration digests. Runtime persistence and Temporal primary/visibility persistence are separate explicit declarations. |
| `secret_reference` | Provider-owned reference and version only. Literal secret material is not a schema field. Local/CI generated references are ephemeral/delete; production external-provider references are retained. |
| `telemetry` | Declared collector-service reference, port name, and finite retention. Provider verification binds collector TTL to that declaration. |

The renderer emits canonical ResourceID order, canonical nested lists, an
ownership/lifecycle catalog, per-resource SHA-256 digests, Stack/profile labels,
and one whole-render digest. `RenderKubernetes` projects typed Kubernetes
resources to a Kubernetes `v1/List`: it always includes the explicitly declared
profile Namespace and adds Stack/profile/resource containment labels to every
object. Workloads become bounded one-replica controllers with immutable images,
explicit resources, ports, service account, non-secret environment, and any
declared readiness probe. Rendering reads no environment, clock, randomness,
kubeconfig, provider, or network state.

## Sandbox quota policy

Every profile declares `sandbox_quota_policy.defaults` and
`sandbox_quota_policy.maximums`. Both set every public Sandbox
`ResourceLimits` dimension to a non-zero finite value: CPU millicores, memory,
root disk, tmpfs, PIDs, process count, open files, inodes, files, lifetime,
produced and retained output, transfer bytes, network connections, volume
bytes, and snapshot bytes. Every default must be at or below its maximum.

Sandbox core consumes this typed policy through
`Spec.SandboxQuotaPolicy(profile)`. It must not hard-code production defaults
or read ambient configuration.

## Implemented operator commands

The current checked-in command is deliberately read-only:

```text
go run ./cmd/stackctl render --stack-file <document.json> --profile local
go run ./cmd/stackctl manifests --stack-file <document.json> --profile local
go run ./cmd/stackctl check --stack-file <document.json> --profile local --observed <rendered.json>
go run ./cmd/stackctl diff --stack-file <document.json> --profile local --observed <rendered.json>
go run ./cmd/stackctl preflight --stack-file <document.json> --profile local \
  --kubeconfig </absolute/path/to/kubeconfig> --context <context>
```

`render` writes canonical provider-independent desired state and `manifests`
writes its typed Kubernetes projection. `check` verifies provenance and exact
digest equality. `diff` accepts only self-consistent rendered input and reports
bounded added/modified/removed resource IDs. `preflight` requires the same
absolute kubeconfig and explicit context shape as mutating actions, proves that
the named context is selectable from that file, then performs declared
read-only executable, Kubernetes-context, architecture, and free-disk probes.
It returns direct repairs but never applies them or reads current-context.

`stackctl` also exposes separately audited `bootstrap`, `apply`, `observe`,
`diff-live`, `reconcile`, `rollback`, and `teardown` actions. `bootstrap`
atomically creates only an absent rendered Namespace, then records its
provider UID, exact containment labels, and Stack digest; it never adopts or
relabels an existing Namespace. Each audited action requires the exact
`--stack` identity, `--stack-file`, `--profile`, absolute `--kubeconfig`,
explicit `--context`, `--actor`, `--audit-file`, and absolute
`--migration-root`; rollback additionally requires `--rollback-stack-file`.
It never uses current-context, `KUBECONFIG`, or an inferred migration location.
The audit record contains only action, actor, context, Stack/profile/digest,
result, and bounded resource IDs; the bootstrap record additionally contains
the newly assigned Namespace UID and its non-secret containment labels.

For a Database declaration, each migration also names reviewed relative upgrade
and rollback artifact paths and their SHA-256 digests, plus the declared
Kubernetes workload target. Apply waits for that target's explicit readiness
probe, verifies the artifact digest, and invokes `psql` only through that
target. Rollback runs only current migration versions absent from the previous
reviewed Stack document, in descending order, before applying the previous
Kubernetes manifests.

For the implemented Temporal namespace declaration, apply first awaits the
declared Temporal Deployment readiness probe, then reads bounded structured
namespace state. It creates a missing namespace, updates drifted finite history
retention, and accepts a concurrent-create race idempotently. Transport errors
are retried a bounded number of times and are never treated as namespace
absence. Safe CLI diagnostics are bounded and credential-shaped output is
redacted. The production declaration currently has empty search-attribute and
schedule sets; a non-empty set fails visibly rather than being silently
ignored. Task-queue prefixes are consumed by the later worker composition and
are not provider namespace state.

`tilt up -- --stack=<name>` remains the planned canonical local application
command until issue #12 checks in and proves it.

## Disposable NetworkPolicy harness

`deploy/harness/run-k3s-networkpolicy-evidence.sh` creates a temporary,
exactly named Docker K3s container without a global install. Its adjacent
declaration pins the arm64 K3s OCI manifest digest, host API port, and explicit
Kubernetes context. The harness emits an append-only operator audit and refuses
to overwrite a result file; its retained result proves three consecutive
default-deny failures followed by three consecutive successes after the named
Postgres egress exception. It always deletes the exact container and temporary
kubeconfig on exit.

[`deploy/stacks/contract-example.json`](../../deploy/stacks/contract-example.json)
is a schema/command example, not a deployable Agent Runtime topology. It keeps
all three profiles and quota fields visible without inventing images,
credentials, controllers, or infrastructure that later implementation issues
have not supplied.
