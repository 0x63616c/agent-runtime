#!/usr/bin/env bash
# Runs an explicitly authorised, separately named direct lab.  It deliberately
# has no production-profile or ExternalSecrets path: local input files become
# short-lived, identity-bound Secrets only after Stack bootstrap has created a
# fresh namespace.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="$root/deploy/production/direct-live-lab-manifest.sh"
inputs="$root/deploy/production/direct-live-lab-inputs.sh"

usage() {
  cat >&2 <<'EOF'
usage:
  direct-live-lab-evidence.sh prepare --stack-file /absolute/STACK.json --secrets-dir /absolute/DIR --kubeconfig /absolute/KUBECONFIG --context CONTEXT --plan-file /absolute/PLAN.json --evidence-file /absolute/EVIDENCE.json
  direct-live-lab-evidence.sh dry-run --stack-file /absolute/STACK.json --secrets-dir /absolute/DIR --kubeconfig /absolute/KUBECONFIG --context CONTEXT --plan-file /absolute/PLAN.json --evidence-file /absolute/EVIDENCE.json --actor ACTOR --output /absolute/DRY-RUN.json
  direct-live-lab-evidence.sh execute --stack-file /absolute/STACK.json --secrets-dir /absolute/DIR --kubeconfig /absolute/KUBECONFIG --context CONTEXT --plan-file /absolute/PLAN.json --evidence-file /absolute/EVIDENCE.json --actor ACTOR --execute-authorized-direct-live-lab
  direct-live-lab-evidence.sh --self-test

prepare and dry-run are offline. execute is the only mutating mode: it first
rechecks namespace absence, then bootstraps the exact ci-profile Stack, creates
only its labelled namespace-local Secrets from 0700/0600 files, applies,
observes, reconciles, and tears down. It never accepts production profile,
ExternalSecrets, an existing namespace, or a secret value on argv.
EOF
  exit 2
}

fail() { echo "direct live-lab evidence failed: $*" >&2; exit 1; }
require_file() { [[ "$1" == /* && -f "$1" ]] || fail "$2 must be an existing absolute file"; }
require_new() { [[ "$1" == /* && ! -e "$1" ]] || fail "$2 must be a new absolute path"; mkdir -p "$(dirname "$1")"; }
valid_actor() { [[ "$1" =~ ^[a-z0-9][a-z0-9@._-]{0,127}$ ]] || fail "actor must be a bounded operator identity"; }

identity() {
  local stack_file="$1" context_value="$2"
  "$manifest" validate --stack-file "$stack_file" >/dev/null
  stack_name="$(jq -er '.name' "$stack_file")"
  namespace="$(jq -er '.profiles.ci.namespace' "$stack_file")"
  expected_context="$(jq -er '.profiles.ci.prerequisites[] | select(.name == "target-context") | .expected' "$stack_file")"
  [[ "$context_value" == "$expected_context" ]] || fail "context does not equal the rendered direct lab context"
  [[ "$namespace" == "ar-ci-$stack_name" ]] || fail "direct namespace is not bound to Stack identity"
  stack_digest="sha256:$(shasum -a 256 "$stack_file" | awk '{print $1}')"
}

preflight() {
  local stack_file="$1" secrets_dir="$2" kubeconfig="$3" context_value="$4"
  require_file "$stack_file" "stack file"; require_file "$kubeconfig" "kubeconfig"
  identity "$stack_file" "$context_value"
  "$inputs" validate --stack-file "$stack_file" --secrets-dir "$secrets_dir" >/dev/null
  command -v kubectl >/dev/null || fail "kubectl is required"
  kubectl --kubeconfig "$kubeconfig" config get-contexts -o name | grep -Fx -- "$context_value" >/dev/null || fail "explicit context is unavailable"
  local present rendered manifests nodes
  present="$(kubectl --kubeconfig "$kubeconfig" --context "$context_value" get "namespace/$namespace" --ignore-not-found -o json)"
  [[ -z "${present//[[:space:]]/}" ]] || fail "namespace already exists; direct lab will not take it over"
  kubectl --kubeconfig "$kubeconfig" --context "$context_value" api-resources --api-group networking.k8s.io -o name | grep -Fx networkpolicies >/dev/null || fail "NetworkPolicy API is unavailable"
  rendered="$(go run "$root/cmd/stackctl" render --stack-file "$stack_file" --profile ci)"
  manifests="$(go run "$root/cmd/stackctl" manifests --stack-file "$stack_file" --profile ci)"
  printf '%s' "$rendered" | jq -e --arg stack "$stack_name" --arg namespace "$namespace" '
    .stack == $stack and .profile == "ci" and .namespace == $namespace and
    ([.resources[]|select(.kind == "secret_reference")]|length) > 0 and
    ([.resources[]|select(.kind == "secret_reference")]|all(.secret_reference.provider == "local-generated" and .delete_behavior == "delete")) and
    ([.resources[]|select(.kind == "kubernetes" and (.kubernetes.kind == "Deployment" or .kubernetes.kind == "StatefulSet" or .kubernetes.kind == "Job"))]|all(.kubernetes.image|test("@sha256:[0-9a-f]{64}$")))
  ' >/dev/null || fail "direct rendered resources are not immutable and locally owned"
  printf '%s' "$manifests" | jq -e --arg namespace "$namespace" '
    .items[0].kind == "Namespace" and .items[0].metadata.name == $namespace and
    ([.items[]|select(.kind == "Deployment" or .kind == "StatefulSet" or .kind == "Job")|.metadata.labels["agent-runtime.dev/resource"]] - [.items[]|select(.kind == "NetworkPolicy" and .spec.policyTypes|index("Egress"))|.spec.podSelector.matchLabels["agent-runtime.dev/resource"]]) == []
  ' >/dev/null || fail "each direct workload needs an egress policy"
  nodes="$(kubectl --kubeconfig "$kubeconfig" --context "$context_value" get nodes -o json)"
  printf '%s' "$nodes" | jq -e '[.items[]|select(.status.nodeInfo.operatingSystem == "linux" and .status.nodeInfo.architecture == "amd64" and (.spec.unschedulable // false | not) and ([.status.conditions[]?|select(.type == "Ready" and .status == "True")]|length == 1))]|length > 0' >/dev/null || fail "no Ready schedulable Linux/amd64 node"
  jq -n --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$context_value" --arg digest "$stack_digest" '{version:1,status:"ready-for-direct-authorized-execute",read_only:true,stack:$stack,namespace:$namespace,context:$context,stack_sha256:$digest,validated:{namespace_absent:true,local_generated_inputs:true,network_policy_api:true,immutable_images:true,linux_amd64_capacity:true}}'
}

prepare() {
  local stack_file="" secrets_dir="" kubeconfig="" context_value="" plan="" evidence=""
  while [[ $# -gt 0 ]]; do case "$1" in --stack-file) stack_file="$2"; shift 2;; --secrets-dir) secrets_dir="$2"; shift 2;; --kubeconfig) kubeconfig="$2"; shift 2;; --context) context_value="$2"; shift 2;; --plan-file) plan="$2"; shift 2;; --evidence-file) evidence="$2"; shift 2;; *) usage;; esac; done
  [[ -n "$stack_file" && -n "$secrets_dir" && -n "$kubeconfig" && -n "$context_value" && -n "$plan" && -n "$evidence" ]] || usage
  require_file "$stack_file" "stack file"; require_file "$kubeconfig" "kubeconfig"; require_new "$plan" "plan file"; [[ "$evidence" == /* ]] || fail "evidence file must be absolute"
  identity "$stack_file" "$context_value"; "$inputs" validate --stack-file "$stack_file" --secrets-dir "$secrets_dir" >/dev/null
  jq -n --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$context_value" --arg digest "$stack_digest" --arg evidence "$evidence" '{version:1,status:"prepared-offline",read_only:true,stack:$stack,namespace:$namespace,context:$context,stack_sha256:$digest,evidence_file:$evidence,profile:"ci",required_execute_flag:"--execute-authorized-direct-live-lab",lifecycle:["preflight","bootstrap","create-identity-bound-secrets","apply","observe","reconcile","teardown"],claims:{preparation_does_not_contact_kubernetes:true,secret_values_are_not_read_or_printed:true}}' >"$plan"
  echo "prepared offline direct live-lab plan for $namespace"
}

validate_plan() {
  local plan="$1" evidence="$2"
  require_file "$plan" "plan file"
  jq -e --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$expected_context" --arg digest "$stack_digest" --arg evidence "$evidence" '.version == 1 and .status == "prepared-offline" and .read_only == true and .profile == "ci" and .stack == $stack and .namespace == $namespace and .context == $context and .stack_sha256 == $digest and .evidence_file == $evidence and .required_execute_flag == "--execute-authorized-direct-live-lab"' "$plan" >/dev/null || fail "plan is not bound to the exact direct Stack"
}

command_json() {
  local action="$1" stack_file="$2" kubeconfig="$3" actor="$4" audit="$5" capability="$6"
  jq -cn '$ARGS.positional' --args -- go run "$root/cmd/stackctl" "$action" --stack-file "$stack_file" --stack "$stack_name" --profile ci --kubeconfig "$kubeconfig" --context "$expected_context" --actor "$actor" --audit-file "$audit" --migration-root "$root/deploy/production" --bootstrap-capability-file "$capability"
}

dry_run() {
  local stack_file="" secrets_dir="" kubeconfig="" context_value="" plan="" evidence="" actor="" output=""
  while [[ $# -gt 0 ]]; do case "$1" in --stack-file) stack_file="$2"; shift 2;; --secrets-dir) secrets_dir="$2"; shift 2;; --kubeconfig) kubeconfig="$2"; shift 2;; --context) context_value="$2"; shift 2;; --plan-file) plan="$2"; shift 2;; --evidence-file) evidence="$2"; shift 2;; --actor) actor="$2"; shift 2;; --output) output="$2"; shift 2;; *) usage;; esac; done
  [[ -n "$stack_file" && -n "$secrets_dir" && -n "$kubeconfig" && -n "$context_value" && -n "$plan" && -n "$evidence" && -n "$actor" && -n "$output" ]] || usage
  require_file "$stack_file" "stack file"; require_file "$kubeconfig" "kubeconfig"; require_new "$output" "dry-run output"; valid_actor "$actor"
  identity "$stack_file" "$context_value"; "$inputs" validate --stack-file "$stack_file" --secrets-dir "$secrets_dir" >/dev/null; validate_plan "$plan" "$evidence"
  local audit="${evidence}.operator-audit.jsonl" capability="${evidence}.bootstrap-capability.json"
  jq -n --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$expected_context" --arg evidence "$evidence" --arg audit "$audit" --arg capability "$capability" --argjson bootstrap "$(command_json bootstrap "$stack_file" "$kubeconfig" "$actor" "$audit" "$capability")" --argjson apply "$(command_json apply "$stack_file" "$kubeconfig" "$actor" "$audit" "$capability")" --argjson observe "$(command_json observe "$stack_file" "$kubeconfig" "$actor" "$audit" "$capability")" --argjson reconcile "$(command_json reconcile "$stack_file" "$kubeconfig" "$actor" "$audit" "$capability")" --argjson teardown "$(command_json teardown "$stack_file" "$kubeconfig" "$actor" "$audit" "$capability")" '{version:1,status:"validated-dry-run",read_only:true,stack:$stack,namespace:$namespace,context:$context,evidence_file:$evidence,profile:"ci",operator:{audit_file:$audit,bootstrap_capability_file:$capability,commands:{bootstrap:$bootstrap,apply:$apply,observe:$observe,reconcile:$reconcile,teardown:$teardown}},claims:{does_not_contact_kubernetes:true,does_not_read_or_print_secret_values:true}}' >"$output"
  echo "validated offline direct operator argv for $namespace"
}

create_secrets() {
  local stack_file="$1" secrets_dir="$2" kubeconfig="$3" context_value="$4" bootstrap_uid="$5" render_digest="$6" rendered directory secret_file secret_name
  rendered="$(go run "$root/cmd/stackctl" render --stack-file "$stack_file" --profile ci)"
  while IFS= read -r directory; do
    secret_name="$(basename "$directory")"; local from_files=()
    while IFS= read -r secret_file; do from_files+=("--from-file=$(basename "$secret_file")=$secret_file"); done < <(find "$directory" -maxdepth 1 -type f -print | sort)
    kubectl --kubeconfig "$kubeconfig" --context "$context_value" --namespace "$namespace" create secret generic "$secret_name" "${from_files[@]}" --dry-run=client -o json |
      jq --arg uid "$bootstrap_uid" --arg digest "$render_digest" --arg stack "$stack_name" '.metadata.labels={"app.kubernetes.io/part-of":"agent-runtime","agent-runtime.dev/stack":$stack,"agent-runtime.dev/profile":"ci","agent-runtime.dev/external-controller":"local-generated"}|.metadata.annotations={"agent-runtime.dev/bootstrap-uid":$uid,"agent-runtime.dev/render-digest":$digest}' |
      kubectl --kubeconfig "$kubeconfig" --context "$context_value" create -f - >/dev/null
  done < <(find "$secrets_dir" -mindepth 1 -maxdepth 1 -type d -print | sort)
}

execute() {
  local stack_file="" secrets_dir="" kubeconfig="" context_value="" plan="" evidence="" actor="" approved=false
  while [[ $# -gt 0 ]]; do case "$1" in --stack-file) stack_file="$2"; shift 2;; --secrets-dir) secrets_dir="$2"; shift 2;; --kubeconfig) kubeconfig="$2"; shift 2;; --context) context_value="$2"; shift 2;; --plan-file) plan="$2"; shift 2;; --evidence-file) evidence="$2"; shift 2;; --actor) actor="$2"; shift 2;; --execute-authorized-direct-live-lab) approved=true; shift;; *) usage;; esac; done
  [[ "$approved" == true && -n "$stack_file" && -n "$secrets_dir" && -n "$kubeconfig" && -n "$context_value" && -n "$plan" && -n "$evidence" && -n "$actor" ]] || usage
  require_file "$stack_file" "stack file"; require_file "$kubeconfig" "kubeconfig"; require_new "$evidence" "evidence file"; valid_actor "$actor"
  identity "$stack_file" "$context_value"; validate_plan "$plan" "$evidence"
  local current audit capability bootstrap apply_result observe_result reconcile_result teardown_result cleanup=false
  current="$(preflight "$stack_file" "$secrets_dir" "$kubeconfig" "$context_value")"
  audit="${evidence}.operator-audit.jsonl"; capability="${evidence}.bootstrap-capability.json"; [[ ! -e "$audit" && ! -e "$capability" ]] || fail "derived evidence paths already exist"
  local common=(--stack-file "$stack_file" --stack "$stack_name" --profile ci --kubeconfig "$kubeconfig" --context "$context_value" --actor "$actor" --audit-file "$audit" --migration-root "$root/deploy/production" --bootstrap-capability-file "$capability")
  trap 'if [[ "$cleanup" == true ]]; then go run "$root/cmd/stackctl" teardown "${common[@]}" >/dev/null || echo "direct live-lab cleanup failed; namespace $namespace requires manual contained teardown" >&2; fi' EXIT
  bootstrap="$(go run "$root/cmd/stackctl" bootstrap "${common[@]}")"; cleanup=true
  create_secrets "$stack_file" "$secrets_dir" "$kubeconfig" "$context_value" "$(printf '%s' "$bootstrap" | jq -er .uid)" "$(printf '%s' "$bootstrap" | jq -er .render_digest)"
  apply_result="$(go run "$root/cmd/stackctl" apply "${common[@]}")"
  observe_result="$(go run "$root/cmd/stackctl" observe "${common[@]}")"
  reconcile_result="$(go run "$root/cmd/stackctl" reconcile "${common[@]}")"
  teardown_result="$(go run "$root/cmd/stackctl" teardown "${common[@]}")"; cleanup=false
  jq -n --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$context_value" --arg actor "$actor" --arg audit "$audit" --argjson preflight "$current" --argjson bootstrap "$bootstrap" --argjson apply "$apply_result" --argjson observe "$observe_result" --argjson reconcile "$reconcile_result" --argjson teardown "$teardown_result" '{version:1,status:"direct-lab-lifecycle-complete",stack:$stack,namespace:$namespace,context:$context,actor:$actor,profile:"ci",operator_audit_file:$audit,preflight:$preflight,operator:{bootstrap:$bootstrap,apply:$apply,observe:$observe,reconcile:$reconcile,teardown:$teardown}}' >"$evidence"
  trap - EXIT
  echo "direct live-lab lifecycle completed and evidence written to $evidence"
}

self_test() {
  local tmp stack secrets kubeconfig plan evidence output name key
  tmp="$(mktemp -d)"; trap 'rm -rf -- "${tmp:-}"' EXIT
  stack="$tmp/stack.json"; secrets="$tmp/secrets"; kubeconfig="$tmp/kubeconfig"; plan="$tmp/plan.json"; evidence="$tmp/evidence.json"; output="$tmp/dry-run.json"
  printf 'apiVersion: v1\nkind: Config\n' >"$kubeconfig"
  "$manifest" render --name agent-runtime-direct-live-lab-test --context home-server --output "$stack" >/dev/null
  mkdir -m 700 "$secrets"
  while IFS=$'\t' read -r name key; do mkdir -p "$secrets/$name"; printf '\n' >"$secrets/$name/$key"; chmod 600 "$secrets/$name/$key"; done < <(go run "$root/cmd/stackctl" render --stack-file "$stack" --profile ci | jq -r '.resources[]|select(.kind == "secret_reference")|.secret_reference.reference as $n|.secret_reference.keys[]|[$n,.]|@tsv')
  "$0" prepare --stack-file "$stack" --secrets-dir "$secrets" --kubeconfig "$kubeconfig" --context home-server --plan-file "$plan" --evidence-file "$evidence" >/dev/null
  "$0" dry-run --stack-file "$stack" --secrets-dir "$secrets" --kubeconfig "$kubeconfig" --context home-server --plan-file "$plan" --evidence-file "$evidence" --actor direct-lab --output "$output" >/dev/null
  jq -e '.status == "validated-dry-run" and .read_only == true and .profile == "ci" and .claims.does_not_contact_kubernetes == true and (.operator.commands.bootstrap | index("bootstrap") != null)' "$output" >/dev/null
  if "$0" execute --stack-file "$stack" --secrets-dir "$secrets" --kubeconfig "$kubeconfig" --context home-server --plan-file "$plan" --evidence-file "$evidence" --actor direct-lab >/dev/null 2>&1; then fail "execute accepted no explicit authorization flag"; fi
  echo "direct live-lab evidence harness keeps prepare and dry-run offline and requires an explicit execute flag"
}

command -v jq >/dev/null || fail "jq is required"
command -v go >/dev/null || fail "go is required"
command -v shasum >/dev/null || fail "shasum is required"
case "${1:-}" in prepare) shift; prepare "$@";; dry-run) shift; dry_run "$@";; execute) shift; execute "$@";; --self-test) self_test;; *) usage;; esac
