#!/usr/bin/env bash
# Prepares, and only with a target-bound human approval executes, the M1 live
# lab Stack operator lifecycle. Preparation never contacts Kubernetes.  The
# explicit execute mode is intentionally separate because a passing preflight
# is readiness information, not authority to create a namespace or evidence.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest_validator="$root/deploy/production/live-lab-manifest.sh"

usage() {
  cat >&2 <<'EOF'
usage:
  live-lab-evidence.sh prepare --stack-file STACK.json --preflight-file PREFLIGHT.json --plan-file /absolute/PLAN.json --evidence-file /absolute/EVIDENCE.json
  live-lab-evidence.sh dry-run --stack-file STACK.json --preflight-file PREFLIGHT.json --plan-file /absolute/PLAN.json --evidence-file /absolute/EVIDENCE.json --kubeconfig /absolute/kubeconfig --approval-file /absolute/APPROVAL.json --actor ACTOR --output /absolute/DRY-RUN.json
  live-lab-evidence.sh execute --stack-file STACK.json --preflight-file PREFLIGHT.json --plan-file /absolute/PLAN.json --evidence-file /absolute/EVIDENCE.json --kubeconfig /absolute/kubeconfig --approval-file /absolute/APPROVAL.json --actor ACTOR --apply-reviewed-live-lab
  live-lab-evidence.sh --self-test

prepare is offline: it validates a captured read-only live-lab preflight and
creates a reviewable operator plan. It never calls kubectl or stackctl.

dry-run is also offline. It validates the target-bound approval and renders the
exact Stack operator argv for independent review; it never calls Kubernetes,
stackctl, or an operator binary.

execute re-runs the read-only preflight, then calls the audited Stack operator
only after an exact, unexpired approval document binds the Stack digest,
namespace, context, actor, and output evidence path. It creates and tears down
only the separately named namespace. An approval document is a local human
intent boundary; it is not a substitute for target-cluster RBAC or a protected
evidence store.
EOF
  exit 2
}

fail() { echo "live-lab evidence failed: $*" >&2; exit 1; }
require_absolute() { [[ "$1" == /* ]] || fail "$2 must be absolute"; }
require_new_output() { require_absolute "$1" "$2"; [[ ! -e "$1" ]] || fail "$2 already exists"; mkdir -p "$(dirname "$1")"; }
require_regular() { require_absolute "$1" "$2"; [[ -f "$1" ]] || fail "$2 must be an existing regular file"; }

read_identity() {
  local stack_file="$1"
  "$manifest_validator" validate --stack-file "$stack_file" >/dev/null
  stack_name="$(jq -er '.name' "$stack_file")"
  namespace="$(jq -er '.profiles.production.namespace' "$stack_file")"
  context="$(jq -er '.profiles.production.prerequisites[] | select(.name == "target-context") | .expected' "$stack_file")"
  stack_digest="sha256:$(shasum -a 256 "$stack_file" | awk '{print $1}')"
  [[ "$stack_name" == "$namespace" ]] || fail "live lab namespace must equal Stack name"
}

validate_preflight() {
  local file="$1"
  require_regular "$file" "preflight file"
  jq -e --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$context" '
    .status == "ready-for-reviewed-operator-apply" and .read_only == true and
    .stack == $stack and .namespace == $namespace and .context == $context and
    .validated.namespace_absent == true and
    .validated.external_secrets_api == true and
    .validated.network_policy_api == true and
    .validated.external_secret_references == true and
    .validated.immutable_images == true and
    .validated.default_deny_workload_policies == true and
    .ready_linux_amd64_capacity.nodes > 0
  ' "$file" >/dev/null || fail "preflight does not prove this Stack is ready for reviewed apply"
}

write_plan() {
  local plan_file="$1" evidence_file="$2"
  require_new_output "$plan_file" "plan file"
  require_absolute "$evidence_file" "evidence file"
  jq -n --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$context" \
    --arg stack_digest "$stack_digest" --arg evidence_file "$evidence_file" \
    '{version:1,status:"prepared-offline",read_only:true,stack:$stack,namespace:$namespace,context:$context,stack_sha256:$stack_digest,evidence_file:$evidence_file,required_approval:{action:"apply-and-collect-live-lab-evidence",binds:["stack_sha256","stack","namespace","context","actor","evidence_file","expires_at"]},operator_lifecycle:["preflight","bootstrap","apply","observe","reconcile","teardown"],claims:{preflight_is_not_apply_authority:true,evidence_requires_explicit_approval:true,namespace_must_be_absent:true}}' >"$plan_file"
}

prepare() {
  local stack_file="" preflight_file="" plan_file="" evidence_file=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --stack-file) stack_file="${2:-}"; shift 2 ;;
      --preflight-file) preflight_file="${2:-}"; shift 2 ;;
      --plan-file) plan_file="${2:-}"; shift 2 ;;
      --evidence-file) evidence_file="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$stack_file" && -n "$preflight_file" && -n "$plan_file" && -n "$evidence_file" ]] || usage
  require_regular "$stack_file" "stack file"
  read_identity "$stack_file"
  validate_preflight "$preflight_file"
  write_plan "$plan_file" "$evidence_file"
  echo "prepared offline live-lab evidence plan for $namespace; explicit target-bound approval is still required"
}

validate_plan() {
  local plan_file="$1" evidence_file="$2"
  require_regular "$plan_file" "plan file"
  jq -e --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$context" --arg digest "$stack_digest" --arg evidence "$evidence_file" '
    .version == 1 and .status == "prepared-offline" and .read_only == true and
    .stack == $stack and .namespace == $namespace and .context == $context and
    .stack_sha256 == $digest and .evidence_file == $evidence and
    .required_approval.action == "apply-and-collect-live-lab-evidence"
  ' "$plan_file" >/dev/null || fail "plan is not bound to this reviewed Stack and evidence path"
}

validate_approval() {
  local approval_file="$1" actor="$2" evidence_file="$3" mode=""
  require_regular "$approval_file" "approval file"
  mode="$(stat -f '%Lp' "$approval_file" 2>/dev/null || stat -c '%a' "$approval_file" 2>/dev/null || true)"
  [[ "$mode" == "600" ]] || fail "approval file must have mode 0600"
  jq -e --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$context" --arg digest "$stack_digest" --arg actor "$actor" --arg evidence "$evidence_file" '
    .version == 1 and .action == "apply-and-collect-live-lab-evidence" and
    .stack == $stack and .namespace == $namespace and .context == $context and
    .stack_sha256 == $digest and .actor == $actor and .evidence_file == $evidence and
    (.approved_by | type == "string" and length > 0) and
    (.expires_at | fromdateiso8601 > now)
  ' "$approval_file" >/dev/null || fail "approval is missing, expired, or not bound to this exact apply/evidence target"
}

operator_command_json() {
  local action="$1" stack_file="$2" kubeconfig="$3" actor="$4" audit_file="$5" capability_file="$6"
  jq -cn '$ARGS.positional' --args -- \
    go run "$root/cmd/stackctl" "$action" \
    --stack-file "$stack_file" --stack "$stack_name" --profile production \
    --kubeconfig "$kubeconfig" --context "$context" --actor "$actor" \
    --audit-file "$audit_file" --migration-root "$root/deploy/production" \
    --bootstrap-capability-file "$capability_file"
}

dry_run() {
  local stack_file="" preflight_file="" plan_file="" evidence_file="" kubeconfig="" approval_file="" actor="" output=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --stack-file) stack_file="${2:-}"; shift 2 ;;
      --preflight-file) preflight_file="${2:-}"; shift 2 ;;
      --plan-file) plan_file="${2:-}"; shift 2 ;;
      --evidence-file) evidence_file="${2:-}"; shift 2 ;;
      --kubeconfig) kubeconfig="${2:-}"; shift 2 ;;
      --approval-file) approval_file="${2:-}"; shift 2 ;;
      --actor) actor="${2:-}"; shift 2 ;;
      --output) output="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$stack_file" && -n "$preflight_file" && -n "$plan_file" && -n "$evidence_file" && -n "$kubeconfig" && -n "$approval_file" && -n "$actor" && -n "$output" ]] || usage
  require_regular "$stack_file" "stack file"
  require_regular "$kubeconfig" "kubeconfig"
  require_new_output "$output" "dry-run output"
  [[ "$actor" =~ ^[a-z0-9][a-z0-9@._-]{0,127}$ ]] || fail "actor must be a bounded operator identity"
  read_identity "$stack_file"
  validate_preflight "$preflight_file"
  validate_plan "$plan_file" "$evidence_file"
  validate_approval "$approval_file" "$actor" "$evidence_file"

  local audit_file capability_file bootstrap apply observe reconcile teardown
  audit_file="${evidence_file}.operator-audit.jsonl"
  capability_file="${evidence_file}.bootstrap-capability.json"
  bootstrap="$(operator_command_json bootstrap "$stack_file" "$kubeconfig" "$actor" "$audit_file" "$capability_file")"
  apply="$(operator_command_json apply "$stack_file" "$kubeconfig" "$actor" "$audit_file" "$capability_file")"
  observe="$(operator_command_json observe "$stack_file" "$kubeconfig" "$actor" "$audit_file" "$capability_file")"
  reconcile="$(operator_command_json reconcile "$stack_file" "$kubeconfig" "$actor" "$audit_file" "$capability_file")"
  teardown="$(operator_command_json teardown "$stack_file" "$kubeconfig" "$actor" "$audit_file" "$capability_file")"
  jq -n \
    --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$context" --arg digest "$stack_digest" \
    --arg actor "$actor" --arg evidence "$evidence_file" --arg audit "$audit_file" --arg capability "$capability_file" \
    --argjson bootstrap "$bootstrap" --argjson apply "$apply" --argjson observe "$observe" --argjson reconcile "$reconcile" --argjson teardown "$teardown" \
    '{version:1,status:"validated-dry-run",read_only:true,stack:$stack,namespace:$namespace,context:$context,stack_sha256:$digest,actor:$actor,evidence_file:$evidence,ownership:{namespace_only:true,stack_equals_namespace:true,profile:"production",teardown_removes_only_the_separate_namespace:true},operator:{audit_file:$audit,bootstrap_capability_file:$capability,commands:{bootstrap:$bootstrap,apply:$apply,observe:$observe,reconcile:$reconcile,teardown:$teardown}},claims:{does_not_contact_kubernetes:true,does_not_invoke_stackctl:true,approval_is_validated_not_consumed:true}}' >"$output"
  echo "validated offline live-lab operator argv for $namespace; no Kubernetes or Stack operator command was invoked"
}

execute() {
  local stack_file="" preflight_file="" plan_file="" evidence_file="" kubeconfig="" approval_file="" actor="" apply=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --stack-file) stack_file="${2:-}"; shift 2 ;;
      --preflight-file) preflight_file="${2:-}"; shift 2 ;;
      --plan-file) plan_file="${2:-}"; shift 2 ;;
      --evidence-file) evidence_file="${2:-}"; shift 2 ;;
      --kubeconfig) kubeconfig="${2:-}"; shift 2 ;;
      --approval-file) approval_file="${2:-}"; shift 2 ;;
      --actor) actor="${2:-}"; shift 2 ;;
      --apply-reviewed-live-lab) apply=true; shift ;;
      *) usage ;;
    esac
  done
  [[ "$apply" == true && -n "$stack_file" && -n "$preflight_file" && -n "$plan_file" && -n "$evidence_file" && -n "$kubeconfig" && -n "$approval_file" && -n "$actor" ]] || usage
  require_regular "$stack_file" "stack file"; require_regular "$kubeconfig" "kubeconfig"; require_new_output "$evidence_file" "evidence file"
  [[ "$actor" =~ ^[a-z0-9][a-z0-9@._-]{0,127}$ ]] || fail "actor must be a bounded operator identity"
  read_identity "$stack_file"; validate_preflight "$preflight_file"; validate_plan "$plan_file" "$evidence_file"
  # Deliberately re-run the separate read-only probe immediately before the first
  # mutation. Its JSON is retained only in the caller-supplied evidence path.
  current_preflight="$("$root/deploy/production/live-lab-preflight.sh" --stack-file "$stack_file" --kubeconfig "$kubeconfig" --context "$context")"
  printf '%s' "$current_preflight" | jq -e '.read_only == true and .validated.namespace_absent == true' >/dev/null || fail "fresh preflight is not ready"
  # The preflight can take long enough for an approval to expire. Re-read the
  # private document immediately before the first mutation; an approval is not
  # authority to bootstrap after its bound expiry.
  validate_approval "$approval_file" "$actor" "$evidence_file"
  local audit_file capability_file bootstrap apply_result observe_result reconcile_result teardown_result cleanup_needed=false
  audit_file="${evidence_file}.operator-audit.jsonl"; capability_file="${evidence_file}.bootstrap-capability.json"
  [[ ! -e "$audit_file" && ! -e "$capability_file" ]] || fail "derived audit or bootstrap capability path already exists"
  common=(--stack-file "$stack_file" --stack "$stack_name" --profile production --kubeconfig "$kubeconfig" --context "$context" --actor "$actor" --audit-file "$audit_file" --migration-root "$root/deploy/production")
  trap 'if [[ "$cleanup_needed" == true ]]; then
    cleanup_error=""
    if ! go run "$root/cmd/stackctl" teardown "${common[@]}" --bootstrap-capability-file "$capability_file" >/dev/null; then
      cleanup_error="operator teardown failed"
    fi
    # Never imply that an attempted teardown was successful. The namespace is
    # the containment boundary, so explicitly prove it is absent after any
    # recovery path and leave a clear failure for the operator if it remains.
    if kubectl --kubeconfig "$kubeconfig" --context "$context" get "namespace/$namespace" >/dev/null 2>&1; then
      cleanup_error="${cleanup_error:+$cleanup_error; }live-lab namespace remains after cleanup"
    fi
    if [[ -n "$cleanup_error" ]]; then
      echo "live-lab evidence cleanup failed: $cleanup_error; manual contained teardown is required for $namespace" >&2
    fi
  fi' EXIT
  bootstrap="$(go run "$root/cmd/stackctl" bootstrap "${common[@]}" --bootstrap-capability-file "$capability_file")"; cleanup_needed=true
  apply_result="$(go run "$root/cmd/stackctl" apply "${common[@]}" --bootstrap-capability-file "$capability_file")"
  observe_result="$(go run "$root/cmd/stackctl" observe "${common[@]}" --bootstrap-capability-file "$capability_file")"
  reconcile_result="$(go run "$root/cmd/stackctl" reconcile "${common[@]}" --bootstrap-capability-file "$capability_file")"
  teardown_result="$(go run "$root/cmd/stackctl" teardown "${common[@]}" --bootstrap-capability-file "$capability_file")"; cleanup_needed=false
  jq -n --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$context" --arg digest "$stack_digest" --arg actor "$actor" --arg audit "$audit_file" --argjson preflight "$current_preflight" --argjson bootstrap "$bootstrap" --argjson apply "$apply_result" --argjson observe "$observe_result" --argjson reconcile "$reconcile_result" --argjson teardown "$teardown_result" '{version:1,status:"operator-lifecycle-complete",stack:$stack,namespace:$namespace,context:$context,stack_sha256:$digest,actor:$actor,operator_audit_file:$audit,preflight:$preflight,operator:{bootstrap:$bootstrap,apply:$apply,observe:$observe,reconcile:$reconcile,teardown:$teardown}}' >"$evidence_file"
  trap - EXIT
  echo "live-lab operator lifecycle completed and evidence written to $evidence_file"
}

self_test() {
  local tmp stack preflight plan evidence bad approval kubeconfig dry_run_output fake_kubectl
  tmp="$(mktemp -d)"; trap 'rm -rf -- "${tmp:-}"' EXIT
  stack="$tmp/stack.json"; preflight="$tmp/preflight.json"; plan="$tmp/plan.json"; evidence="$tmp/evidence.json"; bad="$tmp/bad.json"; approval="$tmp/approval.json"; kubeconfig="$tmp/kubeconfig"; dry_run_output="$tmp/dry-run.json"; fake_kubectl="$tmp/kubectl"
  printf 'apiVersion: v1\nkind: Config\n' >"$kubeconfig"
  cat >"$fake_kubectl" <<'EOF'
#!/usr/bin/env bash
echo "dry-run unexpectedly invoked kubectl" >&2
exit 99
EOF
  chmod 700 "$fake_kubectl"
  "$manifest_validator" render --name agent-runtime-live-lab-selftest --context home-server --output "$stack" >/dev/null
  jq -n '{status:"ready-for-reviewed-operator-apply",read_only:true,stack:"agent-runtime-live-lab-selftest",namespace:"agent-runtime-live-lab-selftest",context:"home-server",validated:{namespace_absent:true,external_secrets_api:true,network_policy_api:true,external_secret_references:true,immutable_images:true,default_deny_workload_policies:true},ready_linux_amd64_capacity:{nodes:1}}' >"$preflight"
  "$0" prepare --stack-file "$stack" --preflight-file "$preflight" --plan-file "$plan" --evidence-file "$evidence" >/dev/null
  jq -e '.status == "prepared-offline" and .read_only == true and .claims.evidence_requires_explicit_approval == true' "$plan" >/dev/null
  read_identity "$stack"
  jq -n --arg digest "$stack_digest" --arg evidence "$evidence" '{version:1,action:"apply-and-collect-live-lab-evidence",stack:"agent-runtime-live-lab-selftest",namespace:"agent-runtime-live-lab-selftest",context:"home-server",stack_sha256:$digest,actor:"operator",evidence_file:$evidence,approved_by:"reviewer",expires_at:"2030-01-01T00:00:00Z"}' >"$approval"
  chmod 600 "$approval"
  validate_approval "$approval" operator "$evidence"
  PATH="$tmp:$PATH" "$0" dry-run --stack-file "$stack" --preflight-file "$preflight" --plan-file "$plan" --evidence-file "$evidence" --kubeconfig "$kubeconfig" --approval-file "$approval" --actor operator --output "$dry_run_output" >/dev/null
  jq -e --arg root "$root" --arg stack "$stack" --arg kubeconfig "$kubeconfig" --arg evidence "$evidence" '
    def expected($action): [
      "go", "run", ($root + "/cmd/stackctl"), $action,
      "--stack-file", $stack, "--stack", "agent-runtime-live-lab-selftest", "--profile", "production",
      "--kubeconfig", $kubeconfig, "--context", "home-server", "--actor", "operator",
      "--audit-file", ($evidence + ".operator-audit.jsonl"), "--migration-root", ($root + "/deploy/production"),
      "--bootstrap-capability-file", ($evidence + ".bootstrap-capability.json")
    ];
    .status == "validated-dry-run" and .read_only == true and
    .ownership.namespace_only == true and .ownership.stack_equals_namespace == true and
    .claims.does_not_contact_kubernetes == true and .claims.does_not_invoke_stackctl == true and
    .operator.commands.bootstrap == expected("bootstrap") and
    .operator.commands.apply == expected("apply") and
    .operator.commands.observe == expected("observe") and
    .operator.commands.reconcile == expected("reconcile") and
    .operator.commands.teardown == expected("teardown") and
    .operator.bootstrap_capability_file == ($evidence + ".bootstrap-capability.json")
  ' "$dry_run_output" >/dev/null
  jq '.expires_at = "1970-01-01T00:00:00Z"' "$approval" >"$bad"
  chmod 600 "$bad"
  if (validate_approval "$bad" operator "$evidence") >/dev/null 2>&1; then fail "execute accepted an expired target-bound approval"; fi
  jq '.validated.namespace_absent = false' "$preflight" >"$bad"
  if "$0" prepare --stack-file "$stack" --preflight-file "$bad" --plan-file "$tmp/bad-plan.json" --evidence-file "$tmp/bad-evidence.json" >/dev/null 2>&1; then fail "prepare accepted a preflight that could take over a namespace"; fi
  rm -rf -- "$tmp"
  trap - EXIT
  echo "live-lab evidence harness keeps preparation offline and rejects unsafe preflight input"
}

command -v jq >/dev/null || fail "jq is required"
command -v shasum >/dev/null || fail "shasum is required"
case "${1:-}" in
  prepare) shift; prepare "$@" ;;
  dry-run) shift; dry_run "$@" ;;
  execute) shift; execute "$@" ;;
  --self-test) self_test ;;
  *) usage ;;
esac
