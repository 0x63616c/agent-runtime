#!/usr/bin/env bash
# Runs the explicit disposable self-hosted proof. Fixture secrets are created
# only in the named disposable namespace and are deleted with that namespace.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
namespace="agent-runtime"
stack_file="$root/deploy/production/stack.json"
kubeconfig="${AGENT_RUNTIME_SMOKE_KUBECONFIG:?set an explicit kubeconfig path}"
context="${AGENT_RUNTIME_SMOKE_CONTEXT:-orbstack}"
audit_file="${AGENT_RUNTIME_SMOKE_AUDIT:?set an explicit audit file path}"

cleanup() {
  kubectl --kubeconfig "$kubeconfig" --context "$context" delete namespace "$namespace" --ignore-not-found --wait=true --timeout=120s
  kubectl --kubeconfig "$kubeconfig" --context "$context" wait --for=delete "namespace/$namespace" --timeout=120s 2>/dev/null || true
}
trap cleanup EXIT

cleanup

go run "$root/cmd/stackctl" manifests --stack-file "$stack_file" --profile production |
  jq '{apiVersion,kind,items:[.items[0]]}' |
  kubectl --kubeconfig "$kubeconfig" --context "$context" apply -f -

secret() {
  kubectl --kubeconfig "$kubeconfig" --context "$context" -n "$namespace" create secret generic "$1" "${@:2}" --dry-run=client -o json |
    kubectl --kubeconfig "$kubeconfig" --context "$context" apply -f -
}
secret agent-runtime-state-db-secret --from-literal=POSTGRES_PASSWORD=fixture-password --from-literal=STATE_DATABASE_DSN='postgres://postgres:fixture-password@state:5432/agent_runtime?sslmode=disable'
secret agent-runtime-temporal-auth-secret --from-literal=TEMPORAL_AUTH_TOKEN=fixture
secret agent-runtime-conversation-secret --from-literal=CONVERSATION_ACCESS_TOKEN=fixture
secret agent-runtime-model-secret --from-literal=MODEL_API_KEY=fixture
secret agent-runtime-tool-broker-secret --from-literal=TOOL_BROKER_TOKEN=fixture
secret agent-runtime-sandbox-control-secret --from-literal=SANDBOX_CONTROL_TOKEN=fixture
secret agent-runtime-blob-storage-secret --from-literal=BLOB_STORAGE_CREDENTIAL=fixture --from-literal=MINIO_ROOT_USER=minioadmin --from-literal=MINIO_ROOT_PASSWORD=minioadmin
secret agent-runtime-codec-blob-secret --from-literal=CODEC_BLOB_CREDENTIAL=fixture
secret agent-runtime-sandbox-host-ca-secret --from-literal=SANDBOX_HOST_CA=fixture
secret agent-runtime-sandbox-state-secret --from-literal=SANDBOX_STATE_DSN=fixture
secret agent-runtime-sandbox-host-identity-secret --from-literal=SANDBOX_HOST_IDENTITY=fixture

go run "$root/cmd/stackctl" apply --stack-file "$stack_file" --stack agent-runtime --profile production --kubeconfig "$kubeconfig" --context "$context" --actor issue-14-smoke --audit-file "$audit_file" --migration-root "$root/deploy/production"
kubectl --kubeconfig "$kubeconfig" --context "$context" -n "$namespace" exec deploy/temporal -- temporal operator namespace list --address 127.0.0.1:7233

kubectl --kubeconfig "$kubeconfig" --context "$context" -n "$namespace" port-forward service/blob 9000:9000 >/dev/null 2>&1 &
forward_pid=$!
trap 'kill "$forward_pid" 2>/dev/null || true; cleanup' EXIT
mc_image="minio/mc@sha256:aead63c77f9db9107f1696fb08ecb0faeda23729cde94b0f663edf4fe09728e3"
curl --fail --silent --show-error --retry 10 --retry-connrefused --max-time 30 http://127.0.0.1:9000/minio/health/live >/dev/null
docker run --rm "$mc_image" sh -c 'mc alias set local http://host.docker.internal:9000 minioadmin minioadmin >/dev/null && printf smoke | mc pipe local/issue14/proof && mc cat local/issue14/proof && mc rm local/issue14/proof'
