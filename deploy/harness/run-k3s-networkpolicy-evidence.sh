#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
. "$script_dir/k3s-networkpolicy.env"
cd "$repo_root"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "sha256sum or shasum is an explicit prerequisite" >&2
    exit 2
  fi
}

if [ "${1:-}" = "--self-test" ]; then
  test "$#" = 1
  command -v jq >/dev/null 2>&1
  test "$(sha256_file "$0")" = "$(sha256_file "$repo_root/deploy/harness/run-k3s-networkpolicy-evidence.sh")"
  "$repo_root/deploy/harness/install-pinned-calico-cni.sh" --self-test
  "$repo_root/deploy/harness/install-pinned-cilium-cni.sh" --self-test
  echo "NetworkPolicy evidence harness metadata self-test passed"
  exit 0
fi

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
bootstrap_capability_file="$harness_tmp/bootstrap-capability.json"
cleanup() {
  "$docker_bin" rm -f "$K3S_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$harness_tmp"
}
trap cleanup EXIT INT TERM

"$docker_bin" run --detach --privileged --name "$K3S_CONTAINER" --hostname "$K3S_CONTAINER" \
  --tmpfs /var/lib/rancher/k3s:rw,exec,nosuid,size=2g \
  --publish "127.0.0.1:${K3S_HOST_PORT}:6443" \
  "$K3S_IMAGE" server --flannel-backend=none --disable-network-policy --disable traefik --disable servicelb --write-kubeconfig-mode 600 >/dev/null

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

# K3s' bundled flannel and policy controller are disabled above. Linux CI uses
# Cilium; the Darwin Docker/K3s harness uses Calico's iptables dataplane because
# Docker there does not expose the shared BPF mount Cilium requires.
case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    policy_engine=cilium
    cni_installer="$repo_root/deploy/harness/install-pinned-cilium-cni.sh"
    "$cni_installer" "$kubeconfig_path" "$K3S_CONTEXT"
    ;;
  Darwin:arm64)
    policy_engine=calico-iptables
    cni_installer="$repo_root/deploy/harness/install-pinned-calico-cni.sh"
    "$cni_installer" "$kubeconfig_path" "$K3S_CONTEXT"
    ;;
  *)
    echo "disposable NetworkPolicy harness supports only Linux x86_64 and Darwin arm64" >&2
    exit 2
    ;;
esac
cni_metadata=$("$cni_installer" --evidence-metadata)
jq -e '.installer | type == "string" and length > 0' >/dev/null <<EOF
$cni_metadata
EOF

v1="$repo_root/deploy/stacks/issue10-disposable-v1.json"
v2="$repo_root/deploy/stacks/issue10-disposable-v2.json"

stackctl() {
  go run ./cmd/stackctl "$@" --kubeconfig "$kubeconfig_path" --context "$K3S_CONTEXT" --actor platform-operator --audit-file "$audit_path" --migration-root "$repo_root"
}

stackctl bootstrap --stack-file "$v1" --stack issue10-work --profile ci --bootstrap-capability-file "$bootstrap_capability_file"
# This is the declared disposable-harness external Secret controller boundary.
# The reference declares no key material; the empty synthetic Secret is created
# only after namespace bootstrap and is never retained as evidence.
printf '%s\n' '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"postgres-trust"},"type":"Opaque","data":{}}' |
  "$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$K3S_CONTEXT" --namespace ar-ci-issue10-work create -f - >/dev/null
stackctl apply --stack-file "$v1" --stack issue10-work --profile ci --bootstrap-capability-file "$bootstrap_capability_file"
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

# A v2 policy is a distinct reviewed rendering. Advance the private capability
# only after re-observing the v1 Namespace UID and nonce binding; apply cannot
# silently cross a reviewed render-digest boundary.
stackctl transition --stack-file "$v2" --current-stack-file "$v1" --stack issue10-work --profile ci --bootstrap-capability-file "$bootstrap_capability_file"
stackctl apply --stack-file "$v2" --stack issue10-work --profile ci --bootstrap-capability-file "$bootstrap_capability_file"
allowed_observations=0
for attempt in $(seq 1 45); do
  if "$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$K3S_CONTEXT" --namespace ar-ci-issue10-work exec deployment/probe -- pg_isready -h "$service_ip" -p 5432 -U postgres >/dev/null 2>&1; then
    allowed_observations=$((allowed_observations + 1))
    if [ "$allowed_observations" = 3 ]; then
      implementation_revision=$(git rev-parse HEAD)
      harness_sha256=$(sha256_file "$0")
      cni_installer_sha256=$(sha256_file "$cni_installer")
      v1_render_sha256=$(sha256_file "$v1")
      v2_render_sha256=$(sha256_file "$v2")
      audit_sha256=$(sha256_file "$audit_path")
      "$docker_bin" rm -f "$K3S_CONTAINER" >/dev/null
      if "$docker_bin" container inspect "$K3S_CONTAINER" >/dev/null 2>&1; then
        echo "disposable NetworkPolicy container survived cleanup" >&2
        exit 1
      fi
      trap - EXIT INT TERM
      rm -rf "$harness_tmp"
      result_tmp=$(mktemp "${result_path}.XXXXXX")
      jq -n \
        --arg utc_time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg implementation_revision "$implementation_revision" \
        --arg harness_path "deploy/harness/run-k3s-networkpolicy-evidence.sh" \
        --arg harness_sha256 "$harness_sha256" \
        --arg k3s_image "$K3S_IMAGE" \
        --arg policy_engine "$policy_engine" \
        --arg cni_installer_sha256 "$cni_installer_sha256" \
        --arg v1_render_sha256 "$v1_render_sha256" \
        --arg v2_render_sha256 "$v2_render_sha256" \
        --arg audit_sha256 "$audit_sha256" \
        --argjson cni "$cni_metadata" \
        '{version:2,proof_level:"disposable_kubernetes_integration",implementation_revision:$implementation_revision,utc_time:$utc_time,command:{path:$harness_path,sha256:$harness_sha256,profile:"ci",result:"passed"},toolchain:{k3s_image:$k3s_image,policy_engine:$policy_engine,cni:($cni + {installer_sha256:$cni_installer_sha256})},render:{v1_sha256:$v1_render_sha256,v2_sha256:$v2_render_sha256},audit:{sha256:$audit_sha256},network_policy:{default_deny_consecutive_failures:3,declared_egress_consecutive_successes:3,service_ip_probe:true},cleanup:{container_absent:true,tempdir_absent:true}}' > "$result_tmp"
      jq -e '(.implementation_revision | test("^[0-9a-f]{40}$")) and (.utc_time | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T")) and (.command.result == "passed") and (.toolchain.cni.version | type == "string") and (.toolchain.cni.artifact_sha256 | test("^[0-9a-f]{64}$")) and (.render.v1_sha256 | test("^[0-9a-f]{64}$")) and (.render.v2_sha256 | test("^[0-9a-f]{64}$")) and (.audit.sha256 | test("^[0-9a-f]{64}$")) and (.cleanup.container_absent and .cleanup.tempdir_absent)' "$result_tmp" >/dev/null
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
