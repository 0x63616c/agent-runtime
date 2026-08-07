# Issue #14 deployment-role evidence

Status: local composition, declarative-render, immutable multi-architecture
image publication, and disposable Kubernetes/Temporal/blob integration proof.
This is local operator evidence, not a claim that a production cluster was
mutated or that backup/restore and production perimeter policy are complete.

## Published image proof

On 2026-08-07, GitHub Actions run `31152555763` built and published the
Linux AMD64/ARM64 index
`ghcr.io/0x63616c/agent-runtime@sha256:7c60d4d6078da20db1f3c4e19cec03d033f9a37e4f7ec98fe5b1858f806ee1b3`
from source revision `a372977`. The publisher completed its Buildx push,
SBOM/provenance generation, GitHub signed attestation, and digest inspection
successfully. A local
`gh attestation verify` against the digest and `0x63616c/agent-runtime`
succeeded. This proves the published artifact provenance, not Kubernetes
runtime behavior.

## Disposable Kubernetes integration proof

On 2026-08-07, `deploy/production/run-kubernetes-smoke.sh` applied the
production profile through the audited operator to the explicit OrbStack
context. The retained audit digest was
`sha256:4b9e22ecb07cabff81dc72aacf6e9c08362a1fe1a228697f5ca4e783be4085ab`
and recorded `result: applied` with the complete bounded set of 50 declared
Kubernetes resource IDs. All 14 rendered Deployments reached Ready (17 pods because
`egress-proxy` has two replicas and `orchestration` has three). The operator
verified the migration digest and applied schema
version 1 through the declared Postgres workload. It awaited the declared
Temporal health probe, created the `agent-runtime` namespace, and structured
describe reported exactly `2592000s` (30 days) retention. The pinned MinIO
client then created a disposable bucket, wrote and read the exact `smoke`
content, removed the object and bucket, and the harness deleted the exact
Kubernetes namespace. A following read confirmed the namespace no longer
existed.

The same run exposed and fixed a dual-stack portability error: the pinned
Temporal entrypoint derived an IPv6 pod bind address while its probe and
operator used IPv4 loopback. All profiles now explicitly declare
`BIND_ON_IP=0.0.0.0`, and a production contract test locks the bind/probe
alignment. The namespace adapter parses structured describe output, updates
retention drift, distinguishes namespace absence from transport failure,
handles concurrent creation idempotently, and bounds/redacts diagnostics.

## Retained local proof

On 2026-08-06, the following commands exited zero from the repository root:

```text
go test -race ./internal/roles ./cmd/runtime ./cmd/egress-proxy ./internal/egressproxy
go test ./...
golangci-lint run ./internal/roles/... ./internal/egressproxy/... ./cmd/runtime/... ./cmd/egress-proxy/...
go run ./cmd/stackctl render --stack-file deploy/production/stack.json --profile production
go run ./cmd/stackctl manifests --stack-file deploy/production/stack.json --profile production
STATE_DATABASE_DSN=fixture TEMPORAL_AUTH_TOKEN=fixture go run ./cmd/runtime serve --config deploy/production/role-configs/orchestration.json --role orchestration --check
go run ./cmd/egress-proxy --listen 127.0.0.1:8088 --allowed-target model-provider.example.invalid:443 --check
docker build --file deploy/production/Dockerfile --tag agent-runtime-role-smoke:local .
deploy/production/run-container-smoke.sh
```

The migration artifacts were verified against the digests referenced by each
profile of the Stack:

```text
9e2ebf76c416f3d3da19e1601a71a3b9742ff4641b2a31999774f32e0a9aea3f  runtime-v1.up.sql
311919bbb28bc9abe61077e60e46c7040edb56e078bc52a2c0a01dd8e5f4ee6a  runtime-v1.down.sql
```

## What this proves

- All three Stack profiles parse from one typed document and production
  Kubernetes manifests render deterministically.
- Every named runtime role has a dedicated process configuration, exact
  dependency/secret entitlement validation, and a health/readiness composition
  path.
- The model role must use a finite-target egress proxy; the proxy rejects
  undeclared targets and private/loopback resolution before dialing.
- The production desired state declares Secret references rather than values,
  role replicas, service accounts, default-deny NetworkPolicies, explicit
  ingress routing, Temporal namespace retention, blob prefix, telemetry, and
  reversible migration artifacts.
- The pinned-base production Dockerfile built under the local OrbStack Docker
  engine. Its local manifest identity was
  `sha256:5351594ba7e4c8e1cb2b12a0aeab206f825db7f572d537935f4a654274fabdab`.
  The container ran as a read-only non-root process with dropped Linux
  capabilities, accepted only its declared orchestration credentials, and
  returned `{"role":"orchestration","namespace":"agent-runtime","status":"ready"}`
  from its dynamically bound `/readyz` port before containment-safe removal.
- `run-container-smoke.sh` builds the same image and starts every declared
  runtime role with only its role-specific fixture environment keys, plus the
  separate egress proxy. This prevents a permissive all-secrets container
  fixture from standing in for trust separation.

## Remaining acceptance evidence

- Backup/restore and observability-export recovery remain unproved; the live
  proof covers Kubernetes apply/readiness, migration, Temporal namespace
  retention, blob write/read/delete, audit, and containment-safe cleanup.
- The final production egress perimeter and DNS/CA policy requires a real
  operator environment; Kubernetes NetworkPolicy alone is not cited as FQDN
  enforcement.
- Documentation manifest/website integration is pending concurrent M1/M2/M3
  generated-output reconciliation.
