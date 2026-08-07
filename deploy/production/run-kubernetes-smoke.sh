#!/usr/bin/env bash
# Runs the explicit disposable self-hosted proof through the audited Stack
# operator. It never deletes or relabels a namespace that existed before this run.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
stack_file="$root/deploy/production/stack.json"
stack_name="agent-runtime"
profile="local"
namespace="ar-agent-runtime"
kubeconfig="${AGENT_RUNTIME_SMOKE_KUBECONFIG:?set an explicit absolute kubeconfig path}"
context="${AGENT_RUNTIME_SMOKE_CONTEXT:?set an explicit Kubernetes context}"
audit_file="${AGENT_RUNTIME_SMOKE_AUDIT:?set an explicit absolute audit file path}"

if [[ "$kubeconfig" != /* || "$audit_file" != /* ]]; then
  echo "smoke kubeconfig and audit file paths must be absolute" >&2
  exit 1
fi
for executable in jq kubectl openssl; do
  command -v "$executable" >/dev/null || {
    echo "required smoke executable is unavailable: $executable" >&2
    exit 1
  }
done

secret_dir="$(mktemp -d)"
bootstrap_complete=false
apply_complete=false

operator_arguments=(
  --stack-file "$stack_file"
  --stack "$stack_name"
  --profile "$profile"
  --kubeconfig "$kubeconfig"
  --context "$context"
  --actor issue-14-smoke
  --audit-file "$audit_file"
  --migration-root "$root/deploy/production"
)

cleanup() {
  local original_status=$?
  local cleanup_status=0
  set +e
  if [[ "$apply_complete" == true ]]; then
    go run "$root/cmd/stackctl" teardown "${operator_arguments[@]}" >/dev/null
    cleanup_status=$?
    if [[ $cleanup_status -ne 0 ]]; then
      echo "audited teardown refused cleanup; retained $namespace for inspection" >&2
    fi
  elif [[ "$bootstrap_complete" == true ]]; then
    echo "full desired state was not observed; retained $namespace for inspection" >&2
  fi
  rm -rf -- "$secret_dir"
  trap - EXIT
  if [[ $original_status -ne 0 ]]; then
    exit "$original_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

# Preflight selects this exact kubeconfig/context. Bootstrap then uses create,
# not apply, so a race or any pre-existing namespace fails without takeover.
go run "$root/cmd/stackctl" preflight \
  --stack-file "$stack_file" --profile "$profile" \
  --kubeconfig "$kubeconfig" --context "$context" >/dev/null
bootstrap_result="$(go run "$root/cmd/stackctl" bootstrap "${operator_arguments[@]}")"
bootstrap_complete=true
bootstrap_uid="$(printf '%s' "$bootstrap_result" | jq -er '.uid')"
render_digest="$(printf '%s' "$bootstrap_result" | jq -er '.render_digest')"

rendered="$(go run "$root/cmd/stackctl" render --stack-file "$stack_file" --profile "$profile")"
while IFS=$'\t' read -r secret_name secret_key; do
  directory="$secret_dir/$secret_name"
  mkdir -p "$directory"
  openssl rand -hex 32 >"$directory/$secret_key"
  chmod 600 "$directory/$secret_key"
done < <(printf '%s' "$rendered" | jq -r '
  .resources[] |
  select(.kind == "secret_reference" and .secret_reference.provider == "local-generated") |
  .secret_reference.reference as $name |
  .secret_reference.keys[] |
  [$name, .] | @tsv
')

secret_reference() {
  printf '%s' "$rendered" | jq -er --arg id "$1" '.resources[] | select(.id == $id) | .secret_reference.reference'
}
state_secret="$(secret_reference state-db-secret)"
temporal_database_secret="$(secret_reference temporal-db-secret)"
sandbox_state_secret="$(secret_reference sandbox-state-secret)"
state_password="$(<"$secret_dir/$state_secret/POSTGRES_PASSWORD")"
printf 'postgres://postgres:%s@state:5432/agent_runtime?sslmode=disable' "$state_password" >"$secret_dir/$state_secret/STATE_DATABASE_DSN"
printf 'postgres://postgres:%s@state:5432/agent_runtime?sslmode=disable' "$state_password" >"$secret_dir/$sandbox_state_secret/SANDBOX_STATE_DSN"
chmod 600 "$secret_dir/$state_secret/STATE_DATABASE_DSN" "$secret_dir/$sandbox_state_secret/SANDBOX_STATE_DSN"
test -s "$secret_dir/$temporal_database_secret/POSTGRES_PASSWORD"

# This is the declared local-generated external Secret controller. Secret
# values flow through stdin from mode-0600 files; no value enters argv or logs.
for directory in "$secret_dir"/*; do
  secret_name="$(basename "$directory")"
  from_files=()
  for secret_file in "$directory"/*; do
    from_files+=("--from-file=$(basename "$secret_file")=$secret_file")
  done
  kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
    create secret generic "$secret_name" "${from_files[@]}" --dry-run=client -o json |
    jq \
      --arg uid "$bootstrap_uid" \
      --arg digest "$render_digest" \
      '.metadata.labels = {
        "app.kubernetes.io/part-of":"agent-runtime",
        "agent-runtime.dev/stack":"agent-runtime",
        "agent-runtime.dev/profile":"local",
        "agent-runtime.dev/external-controller":"local-generated"
      } | .metadata.annotations = {
        "agent-runtime.dev/bootstrap-uid":$uid,
        "agent-runtime.dev/render-digest":$digest
      }' |
    kubectl --kubeconfig "$kubeconfig" --context "$context" apply -f - >/dev/null
done

apply_result="$(go run "$root/cmd/stackctl" apply "${operator_arguments[@]}")"
expected_ids="$(printf '%s' "$rendered" | jq -c '[.resources[] | select(.kind == "kubernetes") | .id] | sort')"
observed_ids="$(printf '%s' "$apply_result" | jq -c '.ObjectIDs | sort')"
if [[ "$observed_ids" != "$expected_ids" ]]; then
  echo "observed Kubernetes resource IDs do not exactly match desired state" >&2
  exit 1
fi
apply_complete=true
echo "all declared Kubernetes and provider resource IDs were reconciled exactly"

manifests="$(go run "$root/cmd/stackctl" manifests --stack-file "$stack_file" --profile "$profile")"
deployments="$(printf '%s' "$manifests" | jq -r '.items[] | select(.kind == "Deployment") | .metadata.name')"
deployment_count="$(printf '%s' "$manifests" | jq '[.items[] | select(.kind == "Deployment")] | length')"
while IFS= read -r deployment; do
  [[ -n "$deployment" ]] || continue
  kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
    rollout status "deployment/$deployment" --timeout=120s >/dev/null
done <<<"$deployments"
echo "all $deployment_count declared Deployments are Ready"

expected_pods="$(printf '%s' "$manifests" | jq '[.items[] | select(.kind == "Deployment") | (.spec.replicas // 1)] | add')"
kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" get pods \
  -l 'app.kubernetes.io/part-of=agent-runtime,agent-runtime.dev/stack=agent-runtime,agent-runtime.dev/profile=local' -o json |
  jq -e --argjson expected "$expected_pods" '
    (.items | length) == $expected and
    all(.items[]; .status.phase == "Running" and ([.status.containerStatuses[]?.ready] | all))
  ' >/dev/null
echo "all $expected_pods expected pods are Running and Ready"

temporal_namespace="$(printf '%s' "$rendered" | jq -er '.resources[] | select(.kind == "orchestration") | .orchestration.namespace')"
retention_days="$(printf '%s' "$rendered" | jq -er '.resources[] | select(.kind == "orchestration") | .orchestration.retention_days')"
expected_retention_seconds=$((retention_days * 24 * 60 * 60))
kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" exec deploy/temporal -- \
  temporal --address 127.0.0.1:7233 --command-timeout 30s --output json \
  operator namespace describe --namespace "$temporal_namespace" |
  jq -e --arg expected "${expected_retention_seconds}s" '.config.workflowExecutionRetentionTtl == $expected' >/dev/null
echo "Temporal namespace retention matches the declared $retention_days days"

blob_bucket="$(printf '%s' "$rendered" | jq -er '.resources[] | select(.kind == "blob") | .blob.bucket')"
blob_prefix="$(printf '%s' "$rendered" | jq -er '.resources[] | select(.kind == "blob") | .blob.prefix')"
# shellcheck disable=SC2016 # Positional and credential variables expand only inside the reconciler pod.
blob_value="$(kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" exec deploy/blob-reconciler -- \
  /bin/sh -c 'set -eu; mc alias set declared "$3" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null; printf smoke | mc pipe "declared/$1/$2/proof" >/dev/null; mc cat "declared/$1/$2/proof"; mc rm "declared/$1/$2/proof" >/dev/null' \
  smoke-blob "$blob_bucket" "$blob_prefix" http://blob:9000)"
if [[ "$blob_value" != "smoke" ]]; then
  echo "declared blob round trip returned unexpected content" >&2
  exit 1
fi
echo "declared blob prefix write/read/delete round trip succeeded"
