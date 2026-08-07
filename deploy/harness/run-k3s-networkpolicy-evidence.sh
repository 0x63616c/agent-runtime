#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
. "$script_dir/k3s-networkpolicy.env"
cd "$repo_root"

audit_path=${1:?usage: run-k3s-networkpolicy-evidence.sh <absolute-audit-path> <absolute-result-path>}
result_path=${2:?usage: run-k3s-networkpolicy-evidence.sh <absolute-audit-path> <absolute-result-path>}
case "$audit_path" in
  /*) ;;
  *) echo "audit path must be absolute" >&2; exit 2 ;;
esac
case "$result_path" in
  /*) ;;
  *) echo "result path must be absolute" >&2; exit 2 ;;
esac
if [ -e "$result_path" ]; then
  echo "refusing to overwrite retained result $result_path" >&2
  exit 2
fi

kubectl_bin=$(command -v kubectl || true)
docker_bin=$(command -v docker || true)
if [ -z "$kubectl_bin" ] || [ -z "$docker_bin" ]; then
  echo "kubectl and docker are explicit prerequisites" >&2
  exit 2
fi
if "$docker_bin" container inspect "$K3S_CONTAINER" >/dev/null 2>&1; then
  echo "refusing to reuse existing disposable container $K3S_CONTAINER" >&2
  exit 2
fi

harness_tmp=$(mktemp -d "${TMPDIR:-/tmp}/agent-runtime-issue10-k3s.XXXXXX")
cleanup() {
  "$docker_bin" rm -f "$K3S_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$harness_tmp"
}
trap cleanup EXIT INT TERM

"$docker_bin" run --detach --privileged --name "$K3S_CONTAINER" --hostname "$K3S_CONTAINER" \
  --tmpfs /var/lib/rancher/k3s:rw,exec,nosuid,size=2g \
  --publish "127.0.0.1:${K3S_HOST_PORT}:6443" \
  "$K3S_IMAGE" server --disable traefik --disable servicelb --write-kubeconfig-mode 600 >/dev/null

kubeconfig_path="$harness_tmp/kubeconfig"
for attempt in $(seq 1 90); do
  "$docker_bin" cp "$K3S_CONTAINER:/etc/rancher/k3s/k3s.yaml" "$kubeconfig_path" 2>/dev/null || true
  if [ -s "$kubeconfig_path" ]; then
    sed "s/127.0.0.1:6443/127.0.0.1:${K3S_HOST_PORT}/" "$kubeconfig_path" > "$kubeconfig_path.rewritten"
    mv "$kubeconfig_path.rewritten" "$kubeconfig_path"
    if "$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$K3S_CONTEXT" get nodes >/dev/null 2>&1; then
      break
    fi
  fi
  if [ "$attempt" = 90 ]; then
    "$docker_bin" logs "$K3S_CONTAINER" >&2 || true
    echo "k3s API did not become ready" >&2
    exit 1
  fi
  sleep 1
done

v1="$repo_root/deploy/stacks/issue10-disposable-v1.json"
v2="$repo_root/deploy/stacks/issue10-disposable-v2.json"

stackctl() {
  go run ./cmd/stackctl "$@" --kubeconfig "$kubeconfig_path" --context "$K3S_CONTEXT" --actor platform-operator --audit-file "$audit_path" --migration-root "$repo_root"
}

stackctl apply --stack-file "$v1" --stack issue10-work --profile ci
service_ip=$("$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$K3S_CONTEXT" --namespace ar-ci-issue10-work get service database-service -o jsonpath='{.spec.clusterIP}')

denied_observations=0
for attempt in $(seq 1 45); do
  if "$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$K3S_CONTEXT" --namespace ar-ci-issue10-work exec deployment/probe -- pg_isready -h "$service_ip" -p 5432 -U postgres >/dev/null 2>&1; then
    denied_observations=0
  else
    denied_observations=$((denied_observations + 1))
    if [ "$denied_observations" = 3 ]; then
      break
    fi
  fi
  if [ "$attempt" = 45 ]; then
    echo "default-deny NetworkPolicy did not block probe egress three consecutive times" >&2
    exit 1
  fi
  sleep 1
done

stackctl apply --stack-file "$v2" --stack issue10-work --profile ci
allowed_observations=0
for attempt in $(seq 1 45); do
  if "$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$K3S_CONTEXT" --namespace ar-ci-issue10-work exec deployment/probe -- pg_isready -h "$service_ip" -p 5432 -U postgres >/dev/null 2>&1; then
    allowed_observations=$((allowed_observations + 1))
    if [ "$allowed_observations" = 3 ]; then
      result_tmp=$(mktemp "${result_path}.XXXXXX")
      printf '{"k3s_image":"%s","profile":"ci","default_deny_consecutive_failures":3,"declared_egress_consecutive_successes":3,"container_cleanup":"required"}\n' "$K3S_IMAGE" > "$result_tmp"
      chmod 600 "$result_tmp"
      mv "$result_tmp" "$result_path"
      echo "NetworkPolicy deny and declared postgres egress allow proof passed"
      exit 0
    fi
  else
    allowed_observations=0
  fi
  if [ "$attempt" = 45 ]; then
    echo "declared NetworkPolicy egress exception did not restore database connection" >&2
    exit 1
  fi
  sleep 1
done
