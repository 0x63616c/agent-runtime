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

On 2026-08-07, revision
`8d15f19abacceb38d76ee138b58cb2c70d4ceb51` ran
`deploy/production/run-kubernetes-smoke.sh` from a clean checkout against the
explicit absolute kubeconfig and `orbstack` context. It used the disposable
`local` profile, not production, because the proof must own and remove its
complete namespace. The retained render digest is
`sha256:a05ea7461ae88d2bf6ea26e6b56aae8703c683ad04d526c4f7f86a7d907c8860`.
The four-record audit proves `bootstrap -> apply -> reconcile -> teardown`;
apply and teardown each account for all 78 resources (60 Kubernetes and 18
provider resources), while zero-drift reconcile accounts for all 18 providers.

All 16 rendered Deployments reached Ready, all 19 expected pods were Running
and Ready, and the eight independently configured runtime roles were present.
The operator digest-verified and applied runtime migration version 1. Temporal
structured describe matched 30-day retention, and direct database inventory
proved separate `temporal` and `temporal_visibility` databases. All 12 generated
Secret references had exact key inventories, non-empty UIDs, containment and
controller labels, and annotations binding the bootstrap Namespace UID and
render digest. No secret value is retained in evidence.

The exact declared MinIO bucket/prefix completed a write/read/delete round
trip and retained only its provider marker before teardown. The live Jaeger
Deployment matched the declared `720h` TTL and accepted an OTLP span that was
then queried by its trace ID. Audited reconcile reported no Kubernetes drift
while re-verifying every provider. Audited teardown removed provider resources,
generated Secrets, workloads, volumes, bucket and Namespace; a cluster-wide
label query found zero residual resources.

The real runs exposed and fixed four portability/operability defects before
this retained proof: newline-bearing generated credential files, deprecated
Endpoints warnings contaminating combined JSON output, a hard-coded PostgreSQL
verification user that did not match Temporal's declared owner, and insufficient
MinIO client reconciliation capacity. Secret creation is now create-only and
newline-free, telemetry health uses EndpointSlice, database verification uses
the workload's declared `POSTGRES_USER`, and idempotent blob reconciliation has
finite capacity plus a bounded retry. The earlier dual-stack Temporal bind
correction remains locked by the production contract test.

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
  undeclared targets and the complete reviewed IANA IPv4/IPv6 special-purpose
  address inventory before dialing.
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

- Backup/restore and observability-export recovery after collector loss remain
  unproved; the live proof covers a healthy OTLP export/query round trip, not
  disaster recovery.
- The final production egress perimeter and DNS/CA policy requires a real
  operator environment; Kubernetes NetworkPolicy alone is not cited as FQDN
  enforcement.
- Documentation manifest/website integration is pending concurrent M1/M2/M3
  generated-output reconciliation.
