#!/bin/sh
set -eu

# Install the reviewed Cilium release into a disposable K3s cluster.  The
# caller owns the cluster and passes its explicit kubeconfig/context so this
# helper cannot select or change a developer's default Kubernetes context.

usage() {
  echo "usage: install-pinned-cilium-cni.sh <absolute-kubeconfig> <context>" >&2
  exit 2
}

# Cilium CLI and its chart are independently checksum-verified. The chart
# itself uses image digests, so no mutable image tag becomes part of this lane.
CILIUM_VERSION=v1.18.11
CILIUM_CHART_SHA256=85ea267d7fb4a7f95fe0775ebad3919658905fb78627541a55e96478c33a8473
CILIUM_CLI_VERSION=v0.19.4
CILIUM_CLI_LINUX_AMD64_SHA256=98ecd554591a592b0ee32f5d73871133bcee06639619f1c032bcba339340dc26
CILIUM_CLI_DARWIN_ARM64_SHA256=9e58b4b8cb6d926946b2e59eb25fc2fb923965d3e000e00325e0227704fcd318

if [ "${1:-}" = "--evidence-metadata" ]; then
	test "$#" = 1
	printf '%s\n' '{"installer":"deploy/harness/install-pinned-cilium-cni.sh","version":"v1.18.11","artifact_sha256":"85ea267d7fb4a7f95fe0775ebad3919658905fb78627541a55e96478c33a8473","configuration":{"transport":"chart","wait_seconds":300}}'
	exit 0
fi

if [ "${1:-}" = "--self-test" ]; then
	test "$#" = 1
  test "$CILIUM_VERSION" = "v1.18.11"
  test "$CILIUM_CHART_SHA256" = "85ea267d7fb4a7f95fe0775ebad3919658905fb78627541a55e96478c33a8473"
	test "$CILIUM_CLI_LINUX_AMD64_SHA256" = "98ecd554591a592b0ee32f5d73871133bcee06639619f1c032bcba339340dc26"
	test "$CILIUM_CLI_DARWIN_ARM64_SHA256" = "9e58b4b8cb6d926946b2e59eb25fc2fb923965d3e000e00325e0227704fcd318"
	test "$("$0" --evidence-metadata)" = '{"installer":"deploy/harness/install-pinned-cilium-cni.sh","version":"v1.18.11","artifact_sha256":"85ea267d7fb4a7f95fe0775ebad3919658905fb78627541a55e96478c33a8473","configuration":{"transport":"chart","wait_seconds":300}}'
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

# shellcheck disable=SC2039 # uname output is POSIX, mappings are explicit.
case "$(uname -s):$(uname -m)" in
  Linux:x86_64) platform=linux-amd64; cli_sha256=$CILIUM_CLI_LINUX_AMD64_SHA256 ;;
  Darwin:arm64) platform=darwin-arm64; cli_sha256=$CILIUM_CLI_DARWIN_ARM64_SHA256 ;;
  *) echo "pinned Cilium installer supports only Linux x86_64 and Darwin arm64" >&2; exit 2 ;;
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

installer_tmp=$(mktemp -d "${TMPDIR:-/tmp}/agent-runtime-cilium.XXXXXX")
cleanup() {
  rm -rf "$installer_tmp"
}
trap cleanup EXIT INT TERM

cli_archive="$installer_tmp/cilium-${platform}.tar.gz"
chart_archive="$installer_tmp/cilium-${CILIUM_VERSION#v}.tgz"
cli_dir="$installer_tmp/bin"
chart_dir="$installer_tmp/chart"
mkdir -p "$cli_dir" "$chart_dir"
"$curl_bin" -fsSLo "$cli_archive" "https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-${platform}.tar.gz"
verify_sha256 "$cli_sha256" "$cli_archive"
tar -xzf "$cli_archive" -C "$cli_dir" cilium

"$curl_bin" -fsSLo "$chart_archive" "https://helm.cilium.io/cilium-${CILIUM_VERSION#v}.tgz"
verify_sha256 "$CILIUM_CHART_SHA256" "$chart_archive"
tar -xzf "$chart_archive" -C "$chart_dir"

"$cli_dir/cilium" install \
  --kubeconfig "$kubeconfig_path" \
  --context "$context" \
	--chart-directory "$chart_dir/cilium" \
  --version "$CILIUM_VERSION" \
  --wait \
  --wait-duration 5m
"$cli_dir/cilium" status \
  --kubeconfig "$kubeconfig_path" \
  --context "$context" \
  --wait \
  --wait-duration 5m
"$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$context" --namespace kube-system rollout status daemonset/cilium --timeout=5m
"$kubectl_bin" --kubeconfig "$kubeconfig_path" --context "$context" --namespace kube-system rollout status deployment/cilium-operator --timeout=5m
