#!/bin/sh
set -eu

# Calico is used only by the Darwin Docker/K3s harness. Its iptables dataplane
# works without the shared BPF mount that Cilium requires in that environment.

usage() {
  echo "usage: install-pinned-calico-cni.sh <absolute-kubeconfig> <context>" >&2
  exit 2
}

CALICO_VERSION=v3.32.1
CALICO_MANIFEST_SHA256=a1df919d9721cf667accdc3e72848911b0cb25cfab7d2478ad0c996302c95744

if [ "${1:-}" = "--self-test" ]; then
  test "$#" = 1
  test "$CALICO_VERSION" = "v3.32.1"
  test "$CALICO_MANIFEST_SHA256" = "a1df919d9721cf667accdc3e72848911b0cb25cfab7d2478ad0c996302c95744"
  exit 0
fi

kubeconfig_path=${1:-}
context=${2:-}
case "$kubeconfig_path" in
  /*) ;;
  *) usage ;;
esac
[ -n "$context" ] || usage
[ -f "$kubeconfig_path" ] || { echo "kubeconfig does not exist: $kubeconfig_path" >&2; exit 2; }

case "$(uname -s):$(uname -m)" in
  Darwin:arm64) ;;
  *) echo "pinned Calico installer is limited to the Darwin arm64 disposable harness" >&2; exit 2 ;;
esac

kubectl_bin=$(command -v kubectl || true)
curl_bin=$(command -v curl || true)
if [ -z "$kubectl_bin" ] || [ -z "$curl_bin" ]; then
  echo "kubectl and curl are explicit prerequisites" >&2
  exit 2
fi

verify_sha256() {
  expected=$1
  file=$2
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected" "$file" | sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected" "$file" | shasum -a 256 -c -
  else
    echo "sha256sum or shasum is an explicit prerequisite" >&2
    exit 2
  fi
}

installer_tmp=$(mktemp -d "${TMPDIR:-/tmp}/agent-runtime-calico.XXXXXX")
cleanup() {
  rm -rf "$installer_tmp"
}
trap cleanup EXIT INT TERM

manifest="$installer_tmp/calico.yaml"
"$curl_bin" -fsSLo "$manifest" "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
verify_sha256 "$CALICO_MANIFEST_SHA256" "$manifest"
"$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$context" apply -f "$manifest"

# Be explicit: this local proof uses Calico's standard iptables dataplane, not
# its optional eBPF dataplane. Recent Calico manifests also include an optional
# best-effort eBPF bootstrap init container. Docker's Darwin VM cannot create
# its bidirectional /sys/fs mount even when eBPF is disabled, so remove it
# before waiting for the daemonset. This leaves the normal iptables node agent.
"$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$context" --namespace kube-system patch daemonset calico-node --type=strategic -p '{"spec":{"template":{"spec":{"initContainers":[{"name":"ebpf-bootstrap","$patch":"delete"}]}}}}'
"$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$context" --namespace kube-system set env daemonset/calico-node FELIX_BPFENABLED=false
"$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$context" --namespace kube-system rollout status daemonset/calico-node --timeout=5m
"$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$context" --namespace kube-system rollout status deployment/calico-kube-controllers --timeout=5m
observed_ebpf_bootstrap=$("$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$context" --namespace kube-system get daemonset/calico-node -o jsonpath='{.spec.template.spec.initContainers[?(@.name=="ebpf-bootstrap")].name}')
[ -z "$observed_ebpf_bootstrap" ] || { echo "Calico eBPF bootstrap init container remains enabled" >&2; exit 1; }
observed_bpf_enabled=$("$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$context" --namespace kube-system get daemonset/calico-node -o jsonpath='{range .spec.template.spec.containers[?(@.name=="calico-node")].env[?(@.name=="FELIX_BPFENABLED")]}{.value}{end}')
[ "$observed_bpf_enabled" = false ] || { echo "Calico eBPF dataplane was not disabled" >&2; exit 1; }
