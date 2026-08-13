#!/usr/bin/env bash
# Renders and validates a separately named, production-profile Stack for a
# reviewed disposable live lab. This command is deliberately offline: it does
# not read a kubeconfig, contact Kubernetes, or create a namespace.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source_stack="$root/deploy/production/stack.json"
derive_profiles="$root/deploy/production/derive-profiles.jq"

usage() {
  cat >&2 <<'EOF'
usage:
  live-lab-manifest.sh render --name NAME --context CONTEXT --output STACK.json
  live-lab-manifest.sh validate --stack-file STACK.json
  live-lab-manifest.sh --self-test

NAME must begin with agent-runtime-live-lab-. The rendered Stack has a unique
production namespace, external Secret references, immutable image digests,
bounded resource quotas, default-deny workload policies, and an explicit
operator teardown boundary. Rendering and validation never contact a cluster.
EOF
  exit 2
}

require_command() {
  command -v "$1" >/dev/null || {
    echo "required executable is unavailable: $1" >&2
    exit 1
  }
}

validate_name() {
  local name="$1"
  if [[ ! "$name" =~ ^agent-runtime-live-lab-[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
    echo "live lab name must be a DNS label beginning agent-runtime-live-lab-" >&2
    exit 1
  fi
}

render() {
  local name=""
  local output=""
  local context=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name="${2:-}"; shift 2 ;;
      --context) context="${2:-}"; shift 2 ;;
      --output) output="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$name" && -n "$context" && -n "$output" ]] || usage
  validate_name "$name"
  [[ "$context" =~ ^[A-Za-z0-9][-A-Za-z0-9_.:/]*$ ]] || {
    echo "live lab context must be an explicit non-empty Kubernetes context name" >&2
    exit 1
  }
  [[ "$output" == /* ]] || {
    echo "live lab output path must be absolute" >&2
    exit 1
  }
  mkdir -p "$(dirname "$output")"
  jq --arg name "$name" --arg context "$context" '
    .name = $name |
    .profiles.local.namespace = ("ar-" + $name) |
    .profiles.ci.namespace = ("ar-ci-" + $name) |
    .profiles.production.namespace = $name |
    .profiles.production.prerequisites = [
      {name:"kubectl",kind:"executable",expected:"present",minimum_bytes:0,repair:"install kubectl before the reviewed live-lab preflight"},
      {name:"target-context",kind:"kubernetes_context",expected:$context,minimum_bytes:0,repair:"select the dedicated reviewed live-lab context"},
      {name:"linux-amd64",kind:"architecture",expected:"amd64",minimum_bytes:0,repair:"use an amd64 Linux Kubernetes operator host"},
      {name:"workspace-disk",kind:"free_disk",expected:"",minimum_bytes:21474836480,repair:"free at least 20 GiB before the reviewed live-lab preflight"}
    ] |
    .profiles |= with_entries(
      .value.resources += [
        {id:"live-lab-quota",kind:"kubernetes",owner:"platform-operator",scope:"namespace",dependencies:[],retention:{policy:"ephemeral",days:0},backup_restore_owner:"none",delete_behavior:"delete",external_controller:false,kubernetes:{api_version:"v1",kind:"ResourceQuota",name:"live-lab-quota",compute:{request_milli_cpu:4000,limit_milli_cpu:8000,request_memory_bytes:8589934592,limit_memory_bytes:17179869184}}},
        {id:"egress-proxy-default-deny",kind:"kubernetes",owner:"security-operator",scope:"namespace",dependencies:["egress-proxy"],retention:{policy:"ephemeral",days:0},backup_restore_owner:"none",delete_behavior:"delete",external_controller:false,kubernetes:{api_version:"networking.k8s.io/v1",kind:"NetworkPolicy",name:"egress-proxy-default-deny",network:{default_deny:true,subject:"egress-proxy",allowed_egress:[]}}}
      ]
    )
  ' "$source_stack" | jq -f "$derive_profiles" >"$output"
  validate --stack-file "$output"
}

validate() {
  local stack_file=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --stack-file) stack_file="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$stack_file" && -f "$stack_file" ]] || {
    echo "live lab stack file must exist" >&2
    exit 1
  }
  local name namespace rendered manifests
  name="$(jq -er '.name' "$stack_file")"
  validate_name "$name"
  namespace="$(jq -er '.profiles.production.namespace' "$stack_file")"
  [[ "$namespace" == "$name" ]] || {
    echo "live lab production namespace must equal its separate Stack name" >&2
    exit 1
  }
  jq -e --arg name "$name" '
    .profiles.local.namespace == ("ar-" + $name) and
    .profiles.ci.namespace == ("ar-ci-" + $name) and
    .profiles.production.namespace == $name and
    (.profiles.production.prerequisites | length) > 0 and
    ([.profiles.production.resources[] | select(.kind == "secret_reference") |
      .external_controller == true and
      .secret_reference.provider == "external-secrets" and
      (.secret_reference.reference | startswith($name + "-")) and
      .retention.policy == "external" and .delete_behavior == "retain"] | all) and
    ([.profiles.production.resources[] | select(.kind == "kubernetes" and (.kubernetes.kind == "Deployment" or .kubernetes.kind == "StatefulSet" or .kubernetes.kind == "Job")) |
      (.kubernetes.image | test("@sha256:[0-9a-f]{64}$")) and
      .kubernetes.compute.request_milli_cpu > 0 and .kubernetes.compute.limit_milli_cpu > 0 and
      .kubernetes.compute.request_memory_bytes > 0 and .kubernetes.compute.limit_memory_bytes > 0] | all)
  ' "$stack_file" >/dev/null || {
    echo "live lab requires external secret references, immutable images, and bounded workloads" >&2
    exit 1
  }
  rendered="$(go run "$root/cmd/stackctl" render --stack-file "$stack_file" --profile production)"
  manifests="$(go run "$root/cmd/stackctl" manifests --stack-file "$stack_file" --profile production)"
  printf '%s' "$rendered" | jq -e --arg name "$name" '
    .stack == $name and .profile == "production" and .namespace == $name and
    ([.resources[] | select(.kind == "kubernetes" and .kubernetes.kind == "ResourceQuota")] | length) == 1 and
    ([.resources[] | select(.kind == "kubernetes" and (.kubernetes.kind == "Deployment" or .kubernetes.kind == "StatefulSet" or .kubernetes.kind == "Job")) | .id] -
      [.resources[] | select(.kind == "kubernetes" and .kubernetes.kind == "NetworkPolicy" and .kubernetes.network.default_deny == true) | .kubernetes.network.subject]) == []
  ' >/dev/null || {
    echo "live lab requires one quota and a default-deny policy for every workload" >&2
    exit 1
  }
  printf '%s' "$manifests" | jq -e --arg name "$name" '
    .kind == "List" and
    .items[0].kind == "Namespace" and .items[0].metadata.name == $name and
    .items[0].metadata.labels["agent-runtime.dev/stack"] == $name and
    .items[0].metadata.labels["agent-runtime.dev/profile"] == "production" and
    ([.items[] | select(.kind == "Ingress") | .spec.rules[]? | .host] | all(length > 0))
  ' >/dev/null || {
    echo "live lab manifest must retain exact ownership labels and explicit ingress routes" >&2
    exit 1
  }
  echo "validated offline live-lab Stack $name: external secrets, immutable images, bounded default-deny workloads, and explicit namespace-only teardown boundary"
}

self_test() {
  local temporary_stack
  temporary_stack="$(mktemp)"
  trap "rm -f '$temporary_stack' '${temporary_stack}.invalid'" EXIT
  render --name agent-runtime-live-lab-selftest --context home-server --output "$temporary_stack" >/dev/null
  jq '.profiles.production.resources[0].secret_reference.provider = "local-generated"' "$temporary_stack" >"${temporary_stack}.invalid"
  if "$0" validate --stack-file "${temporary_stack}.invalid" >/dev/null 2>&1; then
    echo "live lab validator accepted a local secret provider" >&2
    exit 1
  fi
  echo "live lab manifest validator rejects non-external secrets and accepts a separately named production profile"
}

require_command jq
require_command go
case "${1:-}" in
  render) shift; render "$@" ;;
  validate) shift; validate "$@" ;;
  --self-test) self_test ;;
  *) usage ;;
esac
