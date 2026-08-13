#!/usr/bin/env bash
# Renders the deliberately ephemeral, direct home-server lab profile.  It is
# separate from production: its credentials are namespace-local files supplied
# by the operator, never a cluster-wide ExternalSecrets controller.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source_stack="$root/deploy/production/stack.json"
derive_profiles="$root/deploy/production/derive-profiles.jq"

usage() {
  cat >&2 <<'EOF'
usage:
  direct-live-lab-manifest.sh render --name NAME --context CONTEXT --output /absolute/STACK.json
  direct-live-lab-manifest.sh validate --stack-file /absolute/STACK.json
  direct-live-lab-manifest.sh --self-test

NAME must begin with agent-runtime-direct-live-lab- and be at most 34
characters. The selected `ci`
profile is repurposed only inside the generated, throw-away Stack: it has a
unique namespace, local-generated namespace-owned Secret references, immutable
images, a quota, and default-deny policies.  The checked-in production profile
is not changed. Rendering never contacts Kubernetes.
EOF
  exit 2
}

fail() { echo "direct live-lab manifest failed: $*" >&2; exit 1; }
valid_name() { [[ "$1" =~ ^agent-runtime-direct-live-lab-[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && ${#1} -le 34 ]]; }

render() {
  local name="" context="" output=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name="${2:-}"; shift 2;; --context) context="${2:-}"; shift 2;; --output) output="${2:-}"; shift 2;; *) usage;;
    esac
  done
  valid_name "$name" || fail "name must begin with agent-runtime-direct-live-lab- and be at most 34 characters"
  [[ "$context" =~ ^[A-Za-z0-9][-A-Za-z0-9_.:/]*$ ]] || fail "context must be explicit"
  [[ "$output" == /* ]] || fail "output must be absolute"
  mkdir -p "$(dirname "$output")"
  jq --arg name "$name" --arg context "$context" '
    .name = $name |
    .profiles.local.namespace = ("ar-" + $name) |
    .profiles.ci.namespace = ("ar-ci-" + $name) |
    .profiles.production.namespace = $name |
    .profiles.ci.prerequisites = [
      {name:"kubectl",kind:"executable",expected:"present",minimum_bytes:0,repair:"install kubectl before direct live-lab preflight"},
      {name:"target-context",kind:"kubernetes_context",expected:$context,minimum_bytes:0,repair:"select the reviewed home-server context"},
      {name:"linux-amd64",kind:"architecture",expected:"amd64",minimum_bytes:0,repair:"use a Linux amd64 operator host"},
      {name:"workspace-disk",kind:"free_disk",expected:"",minimum_bytes:21474836480,repair:"free at least 20 GiB before direct live-lab preflight"}
    ] |
    .profiles.ci.resources |= map(
      if .kind == "secret_reference" then
        .secret_reference.provider = "local-generated" |
        .retention = {policy:"ephemeral",days:0} | .delete_behavior = "delete" |
        .backup_restore_owner = "none" | .external_controller = true
      else . end
    )
  ' "$source_stack" | jq -f "$derive_profiles" | jq '
    .profiles.ci.resources |= map(
      if .kind == "kubernetes" and .kubernetes.kind == "PersistentVolumeClaim" then
        .kubernetes.storage |= map(.class = "local-lvm")
      else . end
    ) |
    .profiles |= with_entries(.value.resources += [
      {id:"direct-live-lab-quota",kind:"kubernetes",owner:"platform-operator",scope:"namespace",dependencies:[],retention:{policy:"ephemeral",days:0},backup_restore_owner:"none",delete_behavior:"delete",external_controller:false,kubernetes:{api_version:"v1",kind:"ResourceQuota",name:"direct-live-lab-quota",compute:{request_milli_cpu:4000,limit_milli_cpu:8000,request_memory_bytes:8589934592,limit_memory_bytes:17179869184}}},
      {id:"direct-live-lab-egress-proxy-deny",kind:"kubernetes",owner:"security-operator",scope:"namespace",dependencies:["egress-proxy"],retention:{policy:"ephemeral",days:0},backup_restore_owner:"none",delete_behavior:"delete",external_controller:false,kubernetes:{api_version:"networking.k8s.io/v1",kind:"NetworkPolicy",name:"direct-live-lab-egress-proxy-deny",network:{default_deny:true,subject:"egress-proxy",allowed_egress:[]}}}
    ])
  ' >"$output"
  validate --stack-file "$output"
}

validate() {
  local stack_file=""
  while [[ $# -gt 0 ]]; do case "$1" in --stack-file) stack_file="${2:-}"; shift 2;; *) usage;; esac; done
  [[ "$stack_file" == /* && -f "$stack_file" ]] || fail "stack file must be an existing absolute file"
  local name namespace rendered manifests
  name="$(jq -er '.name' "$stack_file")"; namespace="$(jq -er '.profiles.ci.namespace' "$stack_file")"
  valid_name "$name" && [[ "$namespace" == "ar-ci-$name" ]] || fail "ci namespace must be uniquely bound to the direct lab name"
  jq -e --arg name "$name" '
    ([.profiles.ci.resources[] | select(.kind == "secret_reference")]) as $secrets |
    ($secrets|length)>0 and ($secrets|all(.external_controller and .secret_reference.provider == "local-generated" and (.secret_reference.reference|startswith("ar-ci-"+$name+"-")) and .retention.policy == "ephemeral" and .delete_behavior == "delete")) and
    ([.profiles.ci.resources[] | select(.kind == "kubernetes" and (.kubernetes.kind == "Deployment" or .kubernetes.kind == "StatefulSet" or .kubernetes.kind == "Job"))] | all(.kubernetes.image | test("@sha256:[0-9a-f]{64}$")))
    and ([.profiles.ci.resources[] | select(.kind == "kubernetes" and .kubernetes.kind == "PersistentVolumeClaim") | .kubernetes.storage[] | .class] | all(. == "local-lvm"))
  ' "$stack_file" >/dev/null || fail "direct lab requires namespace-local secret references and immutable images"
  rendered="$(go run "$root/cmd/stackctl" render --stack-file "$stack_file" --profile ci)"
  manifests="$(go run "$root/cmd/stackctl" manifests --stack-file "$stack_file" --profile ci)"
  printf '%s' "$rendered" | jq -e --arg name "$name" --arg namespace "$namespace" '.stack==$name and .profile=="ci" and .namespace==$namespace and ([.resources[]|select(.kind=="kubernetes" and .kubernetes.kind=="ResourceQuota")]|length)==1 and (([.resources[]|select(.kind=="kubernetes" and (.kubernetes.kind=="Deployment" or .kubernetes.kind=="StatefulSet" or .kubernetes.kind=="Job"))|.id])-([.resources[]|select(.kind=="kubernetes" and .kubernetes.kind=="NetworkPolicy" and .kubernetes.network.default_deny==true)|.kubernetes.network.subject]))==[]' >/dev/null || fail "direct lab requires quota and default-deny policy for every workload"
  printf '%s' "$manifests" | jq -e --arg namespace "$namespace" '.items[0].kind=="Namespace" and .items[0].metadata.name==$namespace and .items[0].metadata.labels["agent-runtime.dev/profile"]=="ci"' >/dev/null || fail "manifest ownership differs"
  echo "validated direct ephemeral live-lab profile: namespace-local secrets, immutable images, quota, and default-deny policies"
}

self_test() {
  local tmp="$(mktemp)"
  render --name agent-runtime-direct-live-lab-test --context home-server --output "$tmp" >/dev/null
  jq '.profiles.ci.resources[0].secret_reference.provider="external-secrets"' "$tmp" >"$tmp.bad"
  if (validate --stack-file "$tmp.bad") >/dev/null 2>&1; then fail "accepted a cluster-wide secret controller"; fi
  echo "direct live-lab manifest rejects ExternalSecrets and accepts only isolated ephemeral inputs"
}

command -v jq >/dev/null || fail "jq is required"; command -v go >/dev/null || fail "go is required"
case "${1:-}" in render) shift; render "$@";; validate) shift; validate "$@";; --self-test) self_test;; *) usage;; esac
