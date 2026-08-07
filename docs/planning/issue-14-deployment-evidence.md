# Issue #14 deployment-role evidence

Status: local composition and declarative-render evidence only. This record is
not a claim that a production cluster was mutated or that the placeholder
runtime image was deployed.

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

- A released immutable runtime image must replace the deliberate placeholder
  digest before a real cluster apply/startup smoke can run.
- The platform-owned live Kubernetes/Temporal/blob/backup/observability smoke
  must be executed through the audited operator action with explicit operator
  target and retained redacted results.
- The final production egress perimeter and DNS/CA policy requires a real
  operator environment; Kubernetes NetworkPolicy alone is not cited as FQDN
  enforcement.
- Documentation manifest/website integration is pending concurrent M1/M2/M3
  generated-output reconciliation.
