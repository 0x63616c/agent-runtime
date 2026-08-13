set shell := ["bash", "-ceu"]

# Runs the passing deterministic gate for an incremental main change. Requires just 1.58.0.
check:
    go run ./cmd/generate-requirement-manifest --check
    go run ./cmd/generate-runtime-openapi --check
    node ./scripts/generate-project-dashboard.mjs --check
    for evidence_file in evidence/afk/*.json; do go run ./cmd/afk-evidence -mode validate -file "$evidence_file"; done
    go mod verify
    go test -race ./...
    go vet ./...
    GOOS=linux GOARCH=amd64 golangci-lint run --timeout=5m
    go run ./cmd/no-real-wait --root .
    go run ./cmd/ledger-report --catalog evidence/requirements-catalog.json --ledger evidence/requirements-ledger.json

# Regenerates checked-in source artifacts from their binding authorities.
generate:
    go run ./cmd/generate-requirement-manifest
    go run ./cmd/generate-runtime-openapi

# Runs check, then requires all 183 rows to have valid completed evidence.
verify: check
    go run ./cmd/ledger-report --catalog evidence/requirements-catalog.json --ledger evidence/requirements-ledger.json --complete

# Compatibility alias for the final completion gate.
completion-check: verify

# Writes the exact immutable release hand-off for a clean main checkout. This
# command is read-only: it neither tags nor publishes a release.
release-readiness tag="" hosted_runs="":
    go run ./cmd/release-readiness -tag "{{tag}}" -hosted-runs "{{hosted_runs}}"

# Runs the Research Dossier public end-to-end proof against a freshly composed
# disposable PostgreSQL and MinIO dependency set. The test starts its own
# disposable Temporal dev server and retains no evidence artifact.
research-dossier-e2e:
    deploy/runtimeapi/run-durable-integration.sh --research-dossier-only

# Builds and starts the separately deployed durable API binary with the
# production Stack's config-env/secret naming against disposable PostgreSQL
# and MinIO. It performs no Kubernetes or home-server mutation.
runtime-api-durable-e2e:
    deploy/runtimeapi/run-durable-integration.sh --runtime-api-binary-only

# Renders and validates a separately named production-profile live lab without
# contacting Kubernetes. Applying it requires a later reviewed operator run.
live-lab-manifest name="agent-runtime-live-lab-review" context="home-server" output="/tmp/agent-runtime-live-lab-stack.json":
    deploy/production/live-lab-manifest.sh render --name "{{name}}" --context "{{context}}" --output "{{output}}"

# Offline-only direct home-server test profile. Its generated ci profile uses
# namespace-local, short-lived input files rather than cluster-wide secrets.
direct-live-lab-manifest name="agent-runtime-direct-live-lab-m1" context="home-server" output="/tmp/agent-runtime-direct-live-lab-stack.json":
    deploy/production/direct-live-lab-manifest.sh render --name "{{name}}" --context "{{context}}" --output "{{output}}"

# Requires the protected self-hosted Linux/x86_64/KVM runner contract and always
# retains a redacted blocked report rather than treating a local machine as proof.
firecracker-smoke report="evidence/firecracker-smoke.json" vm_id="" uid="0" gid="0" cgroup_parent="" stack_resource="" external_owner="" fixture_lock="tools/firecracker/fixtures.lock":
    go run ./cmd/firecracker-smoke -report "{{ report }}" -fixture-lock "{{ fixture_lock }}" -vm-id "{{ vm_id }}" -uid "{{ uid }}" -gid "{{ gid }}" -cgroup-parent "{{ cgroup_parent }}" -stack-resource "{{ stack_resource }}" -external-owner "{{ external_owner }}"

# Direct home-server preflight. Unlike the protected GitHub path, this checks
# only the operator-owned Linux/KVM boundary and never relies on runner labels,
# GitHub environments, or protected refs. It changes no host state.
firecracker-direct-preflight config="/var/lib/agent-runtime/firecracker-direct/kvm-config.json" fixture_lock="/var/lib/agent-runtime/firecracker-fixtures/home-server/fixtures.lock":
    go run ./cmd/firecracker-direct-preflight -config "{{ config }}" -fixture-lock "{{ fixture_lock }}"

# Runs the same no-NIC smoke harness directly after the operator-owned direct
# preflight. All input identities must match the root-owned direct config.
firecracker-direct-smoke report="" vm_id="" uid="0" gid="0" cgroup_parent="" stack_resource="" external_owner="" fixture_lock="/var/lib/agent-runtime/firecracker-fixtures/home-server/fixtures.lock" config="/var/lib/agent-runtime/firecracker-direct/kvm-config.json" fixture_source_map="/var/lib/agent-runtime/firecracker-direct/fixture-source-map.json":
    just firecracker-direct-preflight "{{ config }}" "{{ fixture_lock }}"
    go run ./cmd/firecracker-smoke -execution-mode direct -direct-config "{{ config }}" -direct-fixture-source-map "{{ fixture_source_map }}" -report "{{ report }}" -fixture-lock "{{ fixture_lock }}" -vm-id "{{ vm_id }}" -uid "{{ uid }}" -gid "{{ gid }}" -cgroup-parent "{{ cgroup_parent }}" -stack-resource "{{ stack_resource }}" -external-owner "{{ external_owner }}"

# Offline-only manifest for the single privileged KVM pod used by the direct
# home-server proof. Applying it is deliberately unavailable as a Just alias:
# the harness requires the explicit --execute-authorized-direct-kvm consent.
firecracker-direct-runner-manifest run_id="smoke-test" image="" output="/tmp/agent-runtime-direct-kvm.yaml":
    deploy/production/direct-kvm-runner.sh render --run-id "{{ run_id }}" --image "{{ image }}" --output "{{ output }}"

# Offline-only manifest for staging the two exact upstream bytes consumed by
# the no-network fixture builder. Applying it requires its explicit consent
# flag and deletes the disposable privileged namespace afterwards.
firecracker-direct-fixture-input-manifest run_id="fixture-input-test" revision="" rootfs_builder_manifest="" output="/tmp/agent-runtime-direct-fixture-inputs.yaml":
    deploy/production/direct-fixture-input-stager.sh render --run-id "{{ run_id }}" --revision "{{ revision }}" --rootfs-builder-manifest "{{ rootfs_builder_manifest }}" --output "{{ output }}"

# Compatibility alias for the protected boot harness. It is not the enrolled
# public runtime-command integration suite.
firecracker-integration report="evidence/firecracker-integration.json" vm_id="" uid="0" gid="0" cgroup_parent="" stack_resource="" external_owner="" fixture_lock="tools/firecracker/fixtures.lock":
    just firecracker-smoke "{{ report }}" "{{ vm_id }}" "{{ uid }}" "{{ gid }}" "{{ cgroup_parent }}" "{{ stack_resource }}" "{{ external_owner }}" "{{ fixture_lock }}"

# Runs only on an approved protected runner with live operator capabilities.
# Missing authority fails closed and does not create a report.
runtime-operations-drill report="evidence/runtime-operations-report.json":
    go run ./cmd/runtime-operations-drill -report "{{report}}"

# Exercises the same protected database/audit/PITR observations without
# creating an evidence artifact. Use it to validate the isolated lab before
# the single retained protected drill.
runtime-operations-preflight:
    go run ./cmd/runtime-operations-drill -preflight

# Validates the explicit, redacted contract for a protected subscription model
# canary. This local command never reads values beyond presence, calls a
# provider, persists an artifact, or creates evidence.
subscription-model-canary-preflight:
    go run ./cmd/subscription-model-canary -preflight

# Exercises the offline fake-provider cancellation and restart-reconciliation
# seam. It never reads real credentials, calls a provider, or creates evidence.
subscription-model-canary-semantic-e2e:
    go test ./internal/runtimemodel -run TestSubscriptionCanarySemanticE2ECancelsThenReconcilesWithoutOpaqueValues -count=1

# Starts a disposable two-PostgreSQL + TLS audit-sink composition and exercises
# the exact runner-contract preflight without creating operational evidence.
runtime-operations-rehearsal:
    ./deploy/runtimeoperations/local/run-rehearsal.sh

# Installs the locked Astro Starlight toolchain and starts the local site.
docs:
    npm --prefix website ci
    npm --prefix website run start

# Regenerates allow-listed documentation, validates it, and prints its exact diff.
docs-generate:
    go run ./skills/refresh-agent-runtime-docs/scripts/refresh-docs --root .

# Proves generated bytes, TypeScript, links, routes, and the production site build.
docs-check:
    go run ./skills/refresh-agent-runtime-docs/scripts/refresh-docs --root . --check
    npm --prefix website ci
    npm --prefix website audit --omit=dev --audit-level=high
    npm --prefix website run typecheck
    PUBLIC_AGENT_RUNTIME_SOURCE_SHA="$(git rev-parse HEAD)" npm --prefix website run build
    PUBLIC_AGENT_RUNTIME_SOURCE_SHA="$(git rev-parse HEAD)" npm --prefix website run check:build-marker
    npm --prefix website run check:routes
    npm --prefix website run check:public-claims
    npm --prefix website run check:quality

requirements-dashboard:
    node ./scripts/generate-project-dashboard.mjs

requirements-dashboard-check:
    node ./scripts/generate-project-dashboard.mjs --check

# Starts one isolated declarative OrbStack environment. STACK is optional; an
# omitted value derives a deterministic identity from this worktree.
dev stack="" kubeconfig="" actor="local-development":
    go run ./tools/dev up --stack "{{stack}}" --root . --kubeconfig "{{kubeconfig}}" --actor "{{actor}}"

dev-preflight stack="" kubeconfig="":
    go run ./tools/dev preflight --stack "{{stack}}" --root . --kubeconfig "{{kubeconfig}}"

dev-status stack="":
    go run ./tools/dev status --stack "{{stack}}" --root .

# Restarts all eight declared local runtime-role Deployments after label/UID checks.
dev-reset stack="":
    go run ./tools/dev reset --stack "{{stack}}" --root .

# Deletes only a verified labelled Stack namespace and its declared local objects.
dev-down stack="":
    go run ./tools/dev down --stack "{{stack}}" --root .

# Proves two full Stack instances coexist and teardown remains contained.
two-stack-smoke profile="local" context="orbstack" evidence="":
    AGENT_RUNTIME_DEV_PROFILE="{{profile}}" AGENT_RUNTIME_DEV_CONTEXT="{{context}}" AGENT_RUNTIME_TWO_STACK_EVIDENCE="{{evidence}}" deploy/dev/run-two-stack-smoke.sh
