# Self-hosted deployment contract

Status: the v1 declarative role-composition and configuration-validation slice,
M5 state-backed public API process, and private Session Temporal worker are
implemented. A signed, digest-pinned production role image is published to
GHCR. Model/tool/approval execution and Firecracker host-agent production
operation remain later milestones. Do not treat a rendered reference Stack or
published role image as a completed production rollout; live
Kubernetes/Temporal/blob evidence is retained separately.

The checked-in Stack's `runtime serve --role api` deployment remains the
health-only role-composition fixture. The separately runnable
`agent-runtime-api` has an explicit durable PostgreSQL/content configuration
and named disposable-dependency integration evidence, but a production API
credential/configuration rollout is operator work and is not inferred from the
health-only Stack role.

Agent Runtime is self-hosted as explicit, separately deployable processes. An
operator applies a reviewed typed Stack with `stackctl`; no runtime binary,
worker, workflow, or startup helper creates Kubernetes objects, Temporal
namespaces, buckets, database schemas, or Secrets. Third-party dependencies
run beside the runtime; the `runtime` binary never embeds Temporal, PostgreSQL,
an object-store, or a sandbox host.

## Responsibilities

| Owner | Configures and operates | Does not configure |
| --- | --- | --- |
| Application developer | Agent specifications, Agent revisions, Session inputs, and requests for documented Tools. | Database URLs, Temporal endpoint/namespace, storage credentials, worker scaling, sandbox host capacity, secret values, or telemetry retention. |
| Platform operator | Stack identity, namespaces, images, service accounts, NetworkPolicies, resource limits, role replicas, Secret references, Temporal, PostgreSQL, blob storage, backup/restore, codec ingress/CORS policy, host enrollment, and observability. | Application Session behavior or a user’s authority decision. |
| Security operator | Secret-provider bindings, rotation, model access, certificate authority, ingress origins, audit access, and sandbox host admission. | Giving a Tool call authority merely because it was requested. |

The boundary is enforced by strict role configuration. `cmd/runtime` accepts
one `--role` that exactly matches one configuration document. `--role=all` is
refused because a process containing the union of model, tool, state and host
credentials would destroy the trust boundary.

## Role and credential matrix

| Role | Visible dependencies | Credential environment references | Explicitly absent |
| --- | --- | --- | --- |
| `api` | state, telemetry | none in this early composition slice | Temporal, model, tool, blob, sandbox secrets |
| `orchestration` | state, telemetry, Temporal | `STATE_DATABASE_DSN`, `TEMPORAL_AUTH_TOKEN` | Model, tool, blob, sandbox-host secrets |
| `orchestration-codec` | state metadata, telemetry, Temporal, dedicated temporal-payload bucket/prefix and task queue; optional HTTPS audit sink | `STATE_DATABASE_DSN`, `TEMPORAL_AUTH_TOKEN`, `ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY`, `ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY` | Public/API credentials, runtime-content bucket/prefix, model, tool, sandbox-host secrets |
| `model` | conversation, egress proxy, model, telemetry | `CONVERSATION_ACCESS_TOKEN`, `MODEL_API_KEY` | Temporal, state DB, tool, storage, host secrets |
| `tool` | sandbox control, telemetry, tool broker | `SANDBOX_CONTROL_TOKEN`, `TOOL_BROKER_TOKEN` | Temporal, model, state DB, blob credentials |
| `blob` | storage, telemetry | `BLOB_STORAGE_CREDENTIAL` | Temporal, model, tool and sandbox credentials |
| `codec` | blob, telemetry | `CODEC_BLOB_CREDENTIAL` | Temporal client credentials and model/tool credentials |
| `sandbox-control` | host CA, sandbox state, telemetry | `SANDBOX_HOST_CA`, `SANDBOX_STATE_DSN` | Model, tool, Temporal and storage credentials |
| `sandbox-host` | host identity, sandbox control, telemetry | `SANDBOX_HOST_IDENTITY`, `SANDBOX_CONTROL_TOKEN` | Model, tool, Temporal, DB and blob credentials |

The M1 health-only `sandbox-control` role is explicitly plain HTTP on Service
port `8086`; the tool and sandbox-host placeholders use that exact address, and
the Kubernetes smoke proves the tool egress identity can reach `/readyz` there.
It is not the M3 private control protocol. M3 owns a separate TLS 1.3 endpoint
on port `9443`, with its own trust, enrollment, and Linux/KVM evidence.

The production Stack fixture is required to give each role its own Kubernetes
ServiceAccount, only the narrowly declared RBAC binding (or no Kubernetes API
permission), a default-deny NetworkPolicy, finite resource limits, Secret
references and Deployment. The role-composition package does not manufacture
those resources; it refuses configurations that attempt to merge authority.
Policies whose workload resolves a declared Service dependency opt into the
typed `allow_dns` capability. That capability renders only UDP and TCP port 53
to pods labelled `k8s-app=kube-dns` in the `kube-system` namespace; it does not
grant arbitrary namespace, address, or Internet egress. Workloads with no
declared service dependency keep DNS denied.
Credentials are never written in a Stack, rendered manifest, role JSON,
Temporal history, log, health response, or retained evidence. Values arrive
only through the declared external Secret provider and runtime process
environment at the composition root.

The model role has no direct provider egress. It reaches a separately deployed
`egress-proxy` Service, whose finite host-and-port allowlist is explicit
operator configuration. The proxy permits only exact DNS targets (no wildcard,
CIDR, or implicit port), strips proxy credentials before ordinary HTTP
forwarding, and sends both ordinary HTTP forwarding and CONNECT tunnels through
the same resolved dialer. Configuration deliberately has no transport override
that can select a destination after the proxy validates it. Every DNS result is
checked against the reviewed IANA
[IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
special-purpose registries before dialing; private, loopback, link-local,
carrier-grade NAT, documentation, benchmarking, transition, multicast and
reserved ranges all fail closed, including registry entries that are globally
reachable for protocol-specific purposes.
Its own Internet reachability is deliberately a separate network/host policy:
Kubernetes NetworkPolicy cannot truthfully enforce FQDN domain allowlists, so
the proxy is the application-layer enforcement point. Provider credentials and
CA material remain external Secret references; they are not proxy arguments.

## Temporal ownership

Temporal remains a private runtime implementation detail for callers. It is an
operator dependency with an explicit endpoint, namespace, authentication
reference, task-queue prefix, history retention, worker role, scaling policy,
and capacity review in the Stack. The generic orchestration and dedicated
`orchestration-codec` worker roles receive Temporal endpoint/authentication
configuration. Only `orchestration-codec` has the separate,
prefix-restricted temporal-payload blob capability required by the local
worker codec. The UI codec remains an inspection adapter: it does not become
a worker or gain Temporal client credentials.

The pinned Temporal auto-setup image is explicitly configured with
`BIND_ON_IP=0.0.0.0`; its entrypoint otherwise derives a pod address that may
be IPv6-only on dual-stack clusters while operator and readiness commands use
IPv4 loopback. The declared exec readiness probe must pass before namespace
reconciliation. The operator verifies structured namespace state and enforces
the declared 30-day history retention. Search attributes and schedules are
currently declared as complete empty sets; non-empty declarations are rejected
until their reconciliation path is implemented.

Before a production rollout, the platform operator must define and test:

- Temporal namespace history retention, archival/backup policy, frontend and
  worker capacity, namespace authentication, and task-queue isolation.
- PostgreSQL backup/restore ownership, immutable migration artifacts, migration
  Job readiness, and recovery authority. The runtime v2 base migration is
  deliberately forward-only: its declared rollback artifact refuses before any
  destructive action, so recovery requires an operator-approved PostgreSQL
  backup/PITR procedure rather than automatic schema deletion. The owned
  `deploy/runtimeapi/run-durable-integration.sh` harness proves a disposable
  PostgreSQL backup/restore drill: it backs up a tenant row, removes it from
  the source, restores into a fresh database, and verifies recovery. This is
  not a production PITR procedure; the platform operator must retain and
  authorize the production backup/PITR runbook and its evidence. A production
  drill must restore into an isolated target, select a documented recovery
  point from the platform-managed WAL archive, verify tenant isolation and the
  exact recovered durable row set, then destroy only that isolated target. The
  checked-in Stack does not declare a WAL archive, recovery target, or native
  partition maintenance job, so this remains an explicit external
  production-run evidence blocker rather than an implied capability. The upgrade uses a transaction
  advisory lock plus migration fingerprint and physical-schema checks, then
  declares normalized tenant, Agent revision, Session,
  content-reference Input, Turn, Product-event, audit, and outbox tables. It
  intentionally contains no raw prompt or event-body columns; the blob
  authority owns content bytes. The runtime v3 forward-only migration follows
  and raises only the bounded immutable Input-reference metadata size limit. A
  M5 `agent-runtime-api` accepts an explicit PostgreSQL plus immutable-content
  configuration and composes the complete public lifecycle through that state
  authority; `memory-unsafe` remains an explicitly labelled local-only mode.
  The `orchestration-codec` role publishes only durable outbox routes with
  lease recovery and no runtime-content credential. This foundation does not
  yet provide tenant RLS or least-privilege database-role enforcement.
- An optional `orchestration-codec.worker.audit_sink` may point only to an
  explicit HTTPS endpoint with a 1–60 second timeout. It exports committed,
  redacted facts through the durable outbox and never turns audit delivery into
  a transactionally fail-closed runtime mutation. No reference Stack enables
  it: a platform/security operator must provision the transport identity,
  sink retention, outage alert, access control, and a live delivery/recovery
  record before declaring an operational audit sink.
- Blob bucket/prefix lifecycle, retention, backup/restore, encryption and
  credential rotation.
- Codec ingress hosts and CORS origins. Routing hosts are Stack Ingress rules;
  CORS origins are codec process configuration and are deliberately not
  conflated with Kubernetes ingress routing.
- The egress-proxy's exact provider host/port inventory, certificate policy,
  DNS/rebinding protection and its independent perimeter/egress policy.
- Sandbox-control and sandbox-host enrollment, certificate rotation, host
  capacity/quarantine, and the separate Linux/KVM evidence lane. A macOS
  development adapter is not a production sandbox claim.
- Metrics/traces/log exporter endpoint, retention, redaction policy, alert
  ownership, and access to authorized diagnostics.

## Running the implemented composition check

Each workload's `RUNTIME_ROLE_CONFIG` value in the typed Stack is the sole role
configuration source. `stackctl role-configs` extracts those exact canonical
documents for inspection; there is no separately maintained role-config file
tree. After the declared external Secret controller injects the matching
credential environment keys, an operator can validate that exact role:

```sh
RUNTIME_ROLE_CONFIG="$(go run ./cmd/stackctl role-configs \
  --stack-file deploy/production/stack.json --profile production |
  jq -c '.orchestration')" \
go run ./cmd/runtime serve --config-env RUNTIME_ROLE_CONFIG \
  --role orchestration --check
```

The command verifies strict schema, the role allowlist, endpoint shape,
namespace, and presence of only the declared credentials. It makes no
infrastructure mutation. Without `--check`, `orchestration-codec` starts the
M5 private worker after startup codec compatibility succeeds; other roles in
this slice serve health and readiness only. Its S3 policy must be separately
restricted to the declared temporal-payload bucket/prefix and must not include
runtime-content.

`deploy/production/stack.json` is the checked-in typed reference Stack. Its
role/Secret/replica/ingress/NetworkPolicy/migration topology is parsed and
rendered by the production Stack smoke suite, and extracted role documents are
validated through the same composition seam. Runtime workloads pin the
attested GHCR image by digest; PostgreSQL, Temporal, MinIO, telemetry, and the
migration runner are separately pinned third-party workloads. The publisher
never changes the Stack, and Stack-only promotions do not rebuild an image:
the operator verifies the source revision label and GitHub provenance for an
immutable digest, then makes a reviewed Stack revision that pins it. Never
hand-convert this desired state into untracked manifests.

The committed main-CI workflow is configured to create a disposable k3d `v5.9.0` cluster with the multi-architecture
K3s image pinned as
`rancher/k3s:v1.33.9-k3s1@sha256:f17e43023cce2b9c613e198f26e73637bf734b5156d37c9f44819d97bac4d655`.
The downloaded Linux amd64 k3d binary is verified against
`06d8f25bc3a971c4eb29e0ff08429b180402db0f4dec838c9eac427e296800a0`;
the local Darwin arm64 proof uses
`fe106541d5d0a3f18debcd4d432a16f8c0ce3e6ddc06f8fbb6f696a122313e00`.
Development images pass only through a loopback k3d registry pinned as
`registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373`;
the pre-apply Tilt plan rejects Docker Hub runtime-image references and binds
the host and in-cluster registry names explicitly.
Every CI attempt deterministically derives unique k3d cluster and registry
names, plus API and registry loopback-port candidates, from its GitHub run and
attempt identifiers. It availability-checks each candidate before creation; a
TOCTOU collision when k3d later binds it fails safely rather than using an
OS-selected port or reusing a pre-existing resource. After successful registry
creation, the workflow discovers the verified `5000/tcp` host mapping and
threads the exact host and in-cluster registry addresses into the Tiltfile.
It uses a private temporary kubeconfig named for that generated cluster, and a
fixed twelve-minute startup bound. This accommodates a clean node's bounded
immutable dependency-image pulls without prewarming an unreviewed dependency
set; both Stack starts remain individually bounded inside the 45-minute CI job. It then runs live
declared-egress/default-deny connectivity probes. Before Tilt
starts either Stack, it reads K3s's `local-path-config` helper declaration and
requires `rancher/mirrored-library-busybox:1.37.0` with `IfNotPresent`. It
resolves the pinned multi-architecture index
`rancher/mirrored-library-busybox@sha256:101b4afd76732482eff9b95cae5f94bcf295e521fbec4e01b69c5421f3f3f3e5`,
allows exactly one 120-second host-index pull and one platform-manifest pull,
imports that exact node-platform image into the named k3d cluster, then has the
node CRI resolve the reviewed index digest before checking its tag and digest
reference. A mounted disposable consumer makes the `WaitForFirstConsumer`
local-path PVC bind; the namespace and volume are then removed. Its evidence is explicitly
K3s-in-container evidence and makes no KVM claim.

## M1 proof provenance and CI safety

The retained artifacts are explicit, bounded proof rather than a claim about
an arbitrary checkout. The final hosted two-Stack proof source is
`6bb0da69befd89adffbf3aefd5068194607cfca9`, retained at
`8b9d57a30800e0b9fcaf3f19631ec31e689c6ab0` and provenance-bound at
`97c2229`. Its companion hosted contract record from the same source proves
the local/CI/production profile, schema/policy/ownership, migration
upgrade/rollback, RBAC-negative, and NetworkPolicy-admission matrix; it is
retained at `7ae871a` and provenance-bound at `b2ab54e`. The self-hosted proof source is
`fa8ac05de0b347bffdf1b23c86f8f09acd6341f8`, retained at
`c27b334ebfbbb3e496b88e216c9283addc8741e8` and provenance-bound at
`6131c4f`. Each envelope records its source commit/tree, retention commit, and
SHA-256. This is provenance, not a claim that either proof ran on its
retention commit or on the current checkout.

The final hosted job is
[`31441677625`](https://github.com/0x63616c/agent-runtime/actions/runs/31441677625),
whose successful isolated job retained the two bounded records under artifact
`two-stack-isolation-6bb0da69befd89adffbf3aefd5068194607cfca9`. It proves
the reviewed rollback transition through the contract gate and then proves the
two concurrently live Stack instances through Tilt. Its top-level workflow is
not release-green: the separate docs job is blocked by the locked transitive
`image-size` audit finding with no available upstream fix, and the generic
check job is blocked by existing repository-wide Firecracker lint findings.
Neither red job is relabelled as a passing M1 proof.

The two-Stack CI lane refuses an existing generated k3d cluster or registry
name before it starts creation. It records ownership only after each exact k3d create
returns successfully, and cleanup deletes only a resource with that successful
ownership record and exact name. That record includes the immutable Docker ID
of the registry container and of the cluster's exact server container. Every
cleanup path re-reads those IDs before invoking k3d; a same-named replacement
is retained and reported rather than deleted. A failed or raced create also
retains its bounded ownership record and does not authorize deletion of a
same-named resource. This permits fully owned per-run infrastructure without
adopting or deleting user-owned k3d resources. CI retains only schema-validated diagnostic summaries
(identity, bounded readiness counts, and Tilt exit code); it never publishes
workload logs, raw Tilt snapshots, arbitrary Kubernetes object dumps, or K3s
server logs.
