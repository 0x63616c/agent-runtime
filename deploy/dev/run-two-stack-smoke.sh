#!/usr/bin/env bash
# Proves two local Stack instances can coexist and that tearing down one cannot
# mutate the other. It refuses to adopt either namespace if it already exists.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
context="${AGENT_RUNTIME_DEV_CONTEXT:-orbstack}"
profile="${AGENT_RUNTIME_DEV_PROFILE:-local}"
ci_context="${AGENT_RUNTIME_CI_CONTEXT:-}"
ci_registry_host="${AGENT_RUNTIME_CI_REGISTRY_HOST:-}"
ci_registry_host_from_cluster="${AGENT_RUNTIME_CI_REGISTRY_HOST_FROM_CLUSTER:-}"
stack_a="${AGENT_RUNTIME_DEV_STACK_A:-m1-isolation-a}"
stack_b="${AGENT_RUNTIME_DEV_STACK_B:-m1-isolation-b}"
evidence_file="${AGENT_RUNTIME_TWO_STACK_EVIDENCE:-}"
diagnostics_dir="${AGENT_RUNTIME_TWO_STACK_DIAGNOSTICS:-}"
diagnostic_self_test=false
if [[ "${1:-}" == "--self-test-diagnostics" ]]; then
  diagnostic_self_test=true
fi
# A clean K3s node needs to fetch immutable dependency images before either
# Stack can become Ready. Keep this bounded while allowing that cold path.
readiness_timeout=12m
cluster_runtime="${AGENT_RUNTIME_CLUSTER_RUNTIME:-not-applicable}"
cluster_image="${AGENT_RUNTIME_CLUSTER_IMAGE:-not-applicable}"
registry_image="${AGENT_RUNTIME_REGISTRY_IMAGE:-not-applicable}"
kubectl_version="${AGENT_RUNTIME_KUBECTL_VERSION:-}"
tilt_version="${AGENT_RUNTIME_TILT_VERSION:-}"
if [[ "$profile" == "local" ]]; then
  namespace_a="ar-$stack_a"
  namespace_b="ar-$stack_b"
elif [[ "$profile" == "ci" ]]; then
  namespace_a="ar-ci-$stack_a"
  namespace_b="ar-ci-$stack_b"
else
  echo "two-Stack smoke profile must be local or ci" >&2
  exit 1
fi
if [[ "$context" == "orbstack" && "$profile" != "local" ]]; then
  echo "orbstack two-Stack smoke only permits the local profile" >&2
  exit 1
fi
ci_tilt_args=()
if [[ "$profile" == "ci" ]]; then
  ci_context_prefix="k3d-ar-ci-"
  if [[ "$context" != "$ci_context" || "$ci_context" != "$ci_context_prefix"* ]]; then
    echo "CI two-Stack smoke requires its generated private k3d context" >&2
    exit 1
  fi
  ci_identity="${ci_context#"$ci_context_prefix"}"
  if [[ -z "$ci_identity" || ! "$ci_registry_host" =~ ^localhost:[1-9][0-9]{0,4}$ || "$ci_registry_host_from_cluster" != "k3d-ar-reg-${ci_identity}.localhost:5000" ]]; then
    echo "CI two-Stack smoke requires generated registry identities" >&2
    exit 1
  fi
  ci_tilt_args=(--ci-context="$ci_context" --ci-registry-host="$ci_registry_host" --ci-registry-host-from-cluster="$ci_registry_host_from_cluster")
elif [[ "$context" != "orbstack" ]]; then
  echo "two-Stack smoke context is not allowlisted" >&2
  exit 1
fi
if [[ -n "$evidence_file" && "$evidence_file" != /* ]]; then
  echo "two-Stack evidence path must be absolute" >&2
  exit 1
fi
if [[ -n "$diagnostics_dir" && "$diagnostics_dir" != /* ]]; then
  echo "two-Stack diagnostics path must be absolute" >&2
  exit 1
fi
if [[ -z "$diagnostics_dir" ]]; then
  diagnostics_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-runtime-two-stack-diagnostics.XXXXXX")"
elif [[ -e "$diagnostics_dir" ]]; then
  echo "refuse to overwrite existing two-Stack diagnostics" >&2
  exit 1
else
  mkdir -p -- "$diagnostics_dir"
fi
echo "two-Stack diagnostics will be retained at $diagnostics_dir"
created_a=false
created_b=false
runtime_role_ids='["api","orchestration","model","tool","blob-role","codec","sandbox-control","sandbox-host"]'

runtime_roles_ready() {
  jq -e --argjson roles "$runtime_role_ids" '
    [.items[] | select(.metadata.labels["agent-runtime.dev/resource"] as $id | $roles | index($id) != null)] as $runtime_roles |
    ($runtime_roles | length) == ($roles | length) and all($runtime_roles[]; .status.readyReplicas == .spec.replicas)
  ' >/dev/null
}

empty_runtime_role_status() {
  jq -nc --argjson roles "$runtime_role_ids" '
    $roles | map({id:.,replicas:0,ready_replicas:0,available_replicas:0})
  '
}

runtime_role_status() {
  jq -c --argjson roles "$runtime_role_ids" '
    [
      $roles[] as $id |
      ([.items[] | select(.metadata.labels["agent-runtime.dev/resource"] == $id)] | if length == 1 then .[0] else null end) as $deployment |
      {
        id:$id,
        replicas:($deployment.spec.replicas // 0),
        ready_replicas:($deployment.status.readyReplicas // 0),
        available_replicas:($deployment.status.availableReplicas // 0)
      }
    ]
  '
}

# Diagnostics are a deliberately small, typed status record, not a redacted
# copy of Kubernetes/Tilt output.  Workload output can contain credentials in
# arbitrary JSON, headers, or environment dumps, so retaining it is unsafe even
# when a best-effort redactor believes it has removed known keys.
write_safe_diagnostic_summary() {
  local stack="$1"
  local namespace="$2"
  local ci_status="$3"
  local probe_status="$4"
  local roles_observed="$5"
  local roles_ready="$6"
  local role_status="$7"
  local destination="$diagnostics_dir/$stack.summary.json"

  jq -n \
    --arg stack "$stack" \
    --arg namespace "$namespace" \
    --arg profile "$profile" \
    --arg probe_status "$probe_status" \
    --argjson tilt_ci_exit_code "$ci_status" \
    --argjson runtime_roles_observed "$roles_observed" \
    --argjson runtime_roles_ready "$roles_ready" \
    --argjson runtime_role_status "$role_status" \
    '{kind:"diagnostic-summary/v1",version:1,stack:$stack,namespace:$namespace,profile:$profile,tilt_ci_exit_code:$tilt_ci_exit_code,workload_probe:$probe_status,runtime_roles_observed:$runtime_roles_observed,runtime_roles_ready:$runtime_roles_ready,runtime_role_status:$runtime_role_status}' \
    >"$destination"

  jq -e '
    keys == ["kind","namespace","profile","runtime_role_status","runtime_roles_observed","runtime_roles_ready","stack","tilt_ci_exit_code","version","workload_probe"] and
    .kind == "diagnostic-summary/v1" and .version == 1 and
    (.stack | type == "string") and (.namespace | type == "string") and (.profile | type == "string") and
    (.tilt_ci_exit_code | type == "number") and (.workload_probe | type == "string") and
    (.runtime_roles_observed | type == "number") and (.runtime_roles_ready | type == "boolean") and
    (.runtime_role_status | type == "array" and length == 8 and
      ([.[].id] | unique | sort) == ["api","blob-role","codec","model","orchestration","sandbox-control","sandbox-host","tool"] and
      all(.[]; keys == ["available_replicas","id","ready_replicas","replicas"] and
        (.id | type == "string") and (.replicas | type == "number") and
        (.ready_replicas | type == "number") and (.available_replicas | type == "number")))
  ' "$destination" >/dev/null || {
    rm -f -- "$destination"
    echo "refusing to retain a diagnostic summary outside the safe schema" >&2
    return 1
  }
}

# Tiltfile evaluation happens before there is a namespace to probe. Retain the
# same bounded schema so a rejected CI render remains diagnosable without
# uploading Tilt output, which can include workload credentials.
capture_plan_failure_diagnostics() {
  local stack="$1"
  local namespace="$2"
  write_safe_diagnostic_summary "$stack" "$namespace" 1 "unavailable" 0 false "$(empty_runtime_role_status)"
}

if [[ "$diagnostic_self_test" == true ]]; then
  command -v jq >/dev/null || {
    echo "jq is required for diagnostic self-test" >&2
    exit 1
  }
  fixture_role_status="$(empty_runtime_role_status)"
  write_safe_diagnostic_summary "fixture-stack" "ar-fixture-stack" 7 "unavailable" 0 false "$fixture_role_status"
  for unsafe_value in 'Bearer adversarial-header-token' 'MODEL_API_KEY=adversarial-env-secret' '{"token":"adversarial-json-secret"}'; do
    if grep -F -- "$unsafe_value" "$diagnostics_dir/fixture-stack.summary.json" >/dev/null; then
      echo "safe diagnostic summary retained an unsafe fixture value" >&2
      exit 1
    fi
  done
  capture_plan_failure_diagnostics "preflight-stack" "ar-preflight-stack"
  jq -e '
    .stack == "preflight-stack" and .namespace == "ar-preflight-stack" and
    .tilt_ci_exit_code == 1 and .workload_probe == "unavailable" and
    .runtime_roles_observed == 0 and .runtime_roles_ready == false and
    (.runtime_role_status | length == 8 and all(.[]; .replicas == 0 and .ready_replicas == 0 and .available_replicas == 0))
  ' "$diagnostics_dir/preflight-stack.summary.json" >/dev/null || {
    echo "preflight diagnostic summary did not retain bounded failed-plan metadata" >&2
    exit 1
  }
  rm -f -- "$diagnostics_dir/fixture-stack.summary.json" "$diagnostics_dir/preflight-stack.summary.json"
  rmdir -- "$diagnostics_dir"
  echo "safe diagnostic summary rejects raw JSON, header, and environment payloads"
  exit 0
fi

if [[ "${1:-}" == "--self-test-selectors" ]]; then
  command -v jq >/dev/null || {
    echo "jq is required for selector self-test" >&2
    exit 1
  }
  selector_fixture="$(jq -n --argjson roles "$runtime_role_ids" '
    {items: (($roles | map({metadata:{labels:{"agent-runtime.dev/resource":.}},spec:{replicas:1},status:{readyReplicas:1}})) +
      [{metadata:{labels:{"agent-runtime.dev/resource":"state"}},spec:{replicas:1},status:{readyReplicas:1}}])}
  ')"
  printf '%s' "$selector_fixture" | runtime_roles_ready
  if printf '%s' "$selector_fixture" | jq '.items[0].status.readyReplicas = 0' | runtime_roles_ready; then
    echo "runtime-role selector accepted an unready role" >&2
    exit 1
  fi
  echo "runtime-role selector ignores ready dependencies and requires exactly eight ready roles"
  exit 0
fi

for executable in cmp cut go jq kubectl shasum tilt; do
  command -v "$executable" >/dev/null || {
    echo "required two-Stack smoke executable is unavailable: $executable" >&2
    exit 1
  }
done
if [[ -z "$kubectl_version" ]]; then
  kubectl_version="$(kubectl version --client -o json | jq -r '.clientVersion.gitVersion // "unknown"')"
fi
if [[ -z "$tilt_version" ]]; then
  tilt_version="$(tilt version | cut -d, -f1)"
fi
if [[ "$stack_a" == "$stack_b" ]]; then
  echo "two-Stack smoke identities must differ" >&2
  exit 1
fi

local_file() {
  local stack="$1"
  local kind="$2"
  if [[ "$kind" == "secrets" && "$profile" != "local" ]]; then
    printf '%s/.runtime/dev/%s.%s.secrets.json' "$root" "$stack" "$profile"
  else
    printf '%s/.runtime/dev/%s.%s.json' "$root" "$stack" "$kind"
  fi
}

remove_local_state() {
  local stack="$1"
  rm -f -- "$(local_file "$stack" stack)" "$(local_file "$stack" secrets)" "$(local_file "$stack" state)" \
    "$root/.runtime/dev/$stack.ci.bootstrap.json" "$root/.runtime/dev/$stack.ci.operator-audit.jsonl"
}

require_absent_local_state() {
  local stack="$1"
  local kind
  for kind in stack secrets state; do
    if [[ -e "$(local_file "$stack" "$kind")" ]]; then
      echo "refuse to adopt pre-existing local Stack state for $stack" >&2
      exit 1
    fi
  done
  if [[ -e "$root/.runtime/dev/$stack.ci.bootstrap.json" || -e "$root/.runtime/dev/$stack.ci.operator-audit.jsonl" ]]; then
    echo "refuse to adopt pre-existing CI Stack authority state for $stack" >&2
    exit 1
  fi
}

kubectl --context "$context" get --raw=/readyz >/dev/null
for namespace in "$namespace_a" "$namespace_b"; do
  if kubectl --context "$context" get "namespace/$namespace" >/dev/null 2>&1; then
    echo "refuse to adopt pre-existing namespace $namespace" >&2
    exit 1
  fi
done
require_absent_local_state "$stack_a"
require_absent_local_state "$stack_b"

verify_registry_plan() {
	local stack="$1"
	local plan
	plan="$(mktemp "${TMPDIR:-/tmp}/agent-runtime-tilt-plan.XXXXXX")"
	if ! tilt alpha tiltfile-result --context "$context" -- --stack="$stack" --profile="$profile" "${ci_tilt_args[@]}" >"$plan"; then
		rm -f -- "$plan"
		remove_local_state "$stack"
		return 1
	fi
	if ! jq -e --arg prefix "agent-runtime-dev/$stack/" --arg registry_host "$ci_registry_host" --arg registry_host_from_cluster "$ci_registry_host_from_cluster" '
		.DefaultRegistry.host == $registry_host and
		.DefaultRegistry.hostFromContainerRuntime == $registry_host_from_cluster and
		.CISettings.readinessTimeout == "12m0s" and
		([.Manifests[]?.ImageTargets[]?.selector] | length) == 9 and
		all(.Manifests[]?.ImageTargets[]?.selector; startswith($prefix)) and
		((tostring | contains("docker.io/agent-runtime-dev")) | not)
	' "$plan" >/dev/null; then
		rm -f -- "$plan"
		remove_local_state "$stack"
		return 1
	fi
	rm -f -- "$plan"
	remove_local_state "$stack"
}

if [[ "$profile" == "ci" ]]; then
	if ! verify_registry_plan "$stack_a"; then
		capture_plan_failure_diagnostics "$stack_a" "$namespace_a"
		exit 1
	fi
	if ! verify_registry_plan "$stack_b"; then
		capture_plan_failure_diagnostics "$stack_b" "$namespace_b"
		exit 1
	fi
fi

down_stack() {
  local stack="$1"
  local namespace="$2"
  local tilt_down_status=0
  tilt down --context "$context" --namespace "$namespace" --delete-namespaces -- --stack="$stack" --profile="$profile" "${ci_tilt_args[@]}" >/dev/null || tilt_down_status=$?
  if ! kubectl --context "$context" wait --for=delete "namespace/$namespace" --timeout=180s >/dev/null 2>&1; then
    echo "contained Stack namespace did not delete within the bounded teardown window" >&2
    return 1
  fi
  remove_local_state "$stack"
  if [[ "$tilt_down_status" != 0 ]] && kubectl --context "$context" get "namespace/$namespace" >/dev/null 2>&1; then
    echo "Tilt teardown failed while the contained Stack namespace remained present" >&2
    return "$tilt_down_status"
  fi
}

prepare_evidence_draft() {
  if [[ -z "$evidence_file" ]]; then
    return
  fi
  if [[ -e "$evidence_file" ]]; then
    echo "refusing to retain two-Stack evidence over an existing file" >&2
    return 1
  fi
  evidence_temporary="$(mktemp "${evidence_file}.tmp.XXXXXX")"
  jq -n \
    --arg utc_time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "$(git rev-parse HEAD)" \
    --arg context "$context" --arg profile "$profile" \
		--arg cluster_runtime "$cluster_runtime" --arg cluster_image "$cluster_image" --arg registry_image "$registry_image" \
    --arg kubectl_version "$kubectl_version" --arg tilt_version "$tilt_version" \
    --arg stack_a "$stack_a" --arg stack_b "$stack_b" \
    --arg namespace_a "$namespace_a" --arg namespace_b "$namespace_b" \
    --arg uid_a "$uid_a" --arg uid_b "$uid_b" '
    {
      version:1,
      milestone:"M1 local Stack instance isolation",
      proof_level:"isolated_kubernetes_integration",
      utc_time:$utc_time,
      implementation_revision:$revision,
      command:{path:"deploy/dev/run-two-stack-smoke.sh",kubernetes_context:$context,profile:$profile,result:"pending"},
		toolchain:{cluster_runtime:$cluster_runtime,cluster_image:$cluster_image,registry_image:$registry_image,kubectl:$kubectl_version,tilt:$tilt_version},
      stacks:[{name:$stack_a,namespace:$namespace_a,namespace_uid:$uid_a},{name:$stack_b,namespace:$namespace_b,namespace_uid:$uid_b}],
      both_stacks_concurrently_ready:true,
      distinct_namespace_and_workload_identities:true,
		distinct_private_state:true,
		network_policy:{declared_egress_consecutive_successes:3,default_deny_consecutive_failures:3,service_ip_probe:true},
      first_teardown_left_second_unchanged:true,
      cleanup:{namespaces_absent:false,local_state_absent:false},
      limitations:["does not claim Linux KVM or Firecracker isolation","does not mutate a production cluster"]
    }' >"$evidence_temporary"
  if ! jq -e '.command.result == "pending" and .cleanup.namespaces_absent == false and .cleanup.local_state_absent == false' "$evidence_temporary" >/dev/null; then
    echo "refusing destructive teardown because the owned two-Stack evidence draft is invalid" >&2
    return 1
  fi
}

finalize_evidence() {
  if [[ -z "$evidence_file" ]]; then
    return
  fi
  evidence_finalization="$(mktemp "${evidence_file}.final.XXXXXX")"
  jq '.command.result = "passed" | .cleanup.namespaces_absent = true | .cleanup.local_state_absent = true' "$evidence_temporary" >"$evidence_finalization"
  if ! jq -e '.command.result == "passed" and .cleanup.namespaces_absent == true and .cleanup.local_state_absent == true' "$evidence_finalization" >/dev/null; then
    echo "refusing to retain two-Stack evidence before contained teardown is observed" >&2
    return 1
  fi
  mv -- "$evidence_finalization" "$evidence_temporary"
  mv -- "$evidence_temporary" "$evidence_file"
  echo "retained bounded two-Stack evidence at $evidence_file"
}

cleanup() {
  local original_status=$?
  set +e
  if [[ "$created_a" == true ]]; then
    down_stack "$stack_a" "$namespace_a"
  fi
  if [[ "$created_b" == true ]]; then
    down_stack "$stack_b" "$namespace_b"
  fi
  trap - EXIT
  exit "$original_status"
}
trap cleanup EXIT

capture_stack_diagnostics() {
  local stack="$1"
  local namespace="$2"
  local ci_status="$3"
  local probe_status="unavailable"
  local roles_observed=0
  local roles_ready=false
  local role_status
  local deployment_state

  if deployment_state="$(kubectl --context "$context" --namespace "$namespace" get deployments -l "app.kubernetes.io/part-of=agent-runtime,agent-runtime.dev/profile=$profile,agent-runtime.dev/stack=$stack" -o json 2>/dev/null)"; then
    probe_status="available"
    roles_observed="$(printf '%s' "$deployment_state" | jq --argjson roles "$runtime_role_ids" '[.items[] | select(.metadata.labels["agent-runtime.dev/resource"] as $id | $roles | index($id) != null)] | length' 2>/dev/null || printf '0')"
    if printf '%s' "$deployment_state" | runtime_roles_ready; then
      roles_ready=true
    fi
    role_status="$(printf '%s' "$deployment_state" | runtime_role_status)"
  else
    role_status="$(empty_runtime_role_status)"
  fi
  write_safe_diagnostic_summary "$stack" "$namespace" "$ci_status" "$probe_status" "$roles_observed" "$roles_ready" "$role_status"
}

start_stack() {
  local stack="$1"
  local namespace="$2"
  local ci_status=0
  if [[ "$profile" == "ci" ]]; then
    # Bootstrap is deliberately outside the Tiltfile: plan rendering must be
    # side-effect free, and stackctl must create the Namespace before Tilt can
    # apply the same reviewed topology.
    deploy/dev/bootstrap-ci-stack.sh --stack="$stack" --context="$context" >/dev/null 2>&1 || ci_status=$?
  fi
  # Do not retain Tilt output: it may contain workload environment or headers.
  # The allowlisted summary below records only bounded readiness metadata.
  if [[ "$ci_status" == 0 ]]; then
    tilt ci --context "$context" --namespace "$namespace" --port 0 --timeout "$readiness_timeout" \
      -- --stack="$stack" --profile="$profile" "${ci_tilt_args[@]}" >/dev/null 2>&1 || ci_status=$?
  fi
  capture_stack_diagnostics "$stack" "$namespace" "$ci_status"
  if [[ "$ci_status" != 0 ]]; then
    return "$ci_status"
  fi
}

created_a=true
start_stack "$stack_a" "$namespace_a"
created_b=true
start_stack "$stack_b" "$namespace_b"

uid_a="$(kubectl --context "$context" get "namespace/$namespace_a" -o json | jq -er '.metadata.uid')"
uid_b="$(kubectl --context "$context" get "namespace/$namespace_b" -o json | jq -er '.metadata.uid')"
if [[ "$uid_a" == "$uid_b" ]]; then
  echo "two local Stack namespaces unexpectedly share an identity" >&2
  exit 1
fi

role_selector="app.kubernetes.io/part-of=agent-runtime,agent-runtime.dev/profile=$profile"
for pair in "$stack_a:$namespace_a" "$stack_b:$namespace_b"; do
  stack="${pair%%:*}"
  namespace="${pair#*:}"
  if ! kubectl --context "$context" --namespace "$namespace" get deployments -l "$role_selector,agent-runtime.dev/stack=$stack" -o json | runtime_roles_ready; then
    echo "$stack does not have exactly eight Ready runtime roles" >&2
    exit 1
  fi
  test -s "$(local_file "$stack" stack)"
  test -s "$(local_file "$stack" secrets)"
done
if cmp -s "$(local_file "$stack_a" secrets)" "$(local_file "$stack_b" secrets)"; then
  echo "two local Stack instances unexpectedly share private secret state" >&2
  exit 1
fi

# Prove the CNI enforces the rendered egress policy, rather than merely
# accepting NetworkPolicy objects. Both probes use the state Service IP so DNS
# is not part of the allow/deny observation.
state_service_ip="$(kubectl --context "$context" --namespace "$namespace_a" get service state -o jsonpath='{.spec.clusterIP}')"
declared_egress_consecutive_successes=0
for attempt in $(seq 1 45); do
	if kubectl --context "$context" --namespace "$namespace_a" exec deployment/migration-runner -- \
		pg_isready -h "$state_service_ip" -p 5432 -U postgres -d agent_runtime -t 1 >/dev/null 2>&1; then
		declared_egress_consecutive_successes=$((declared_egress_consecutive_successes + 1))
		if [[ "$declared_egress_consecutive_successes" == 3 ]]; then
			break
		fi
	else
		declared_egress_consecutive_successes=0
	fi
	if [[ "$attempt" == 45 ]]; then
		echo "declared state egress did not succeed three consecutive times" >&2
		exit 1
	fi
	sleep 1
done
default_deny_consecutive_failures=0
for attempt in $(seq 1 45); do
	if kubectl --context "$context" --namespace "$namespace_a" exec deployment/temporal-state -- \
		pg_isready -h "$state_service_ip" -p 5432 -U postgres -d agent_runtime -t 1 >/dev/null 2>&1; then
		default_deny_consecutive_failures=0
	else
		default_deny_consecutive_failures=$((default_deny_consecutive_failures + 1))
		if [[ "$default_deny_consecutive_failures" == 3 ]]; then
			break
		fi
	fi
	if [[ "$attempt" == 45 ]]; then
		echo "default-deny egress did not fail three consecutive times" >&2
		exit 1
	fi
	sleep 1
done

b_deployments_before="$(kubectl --context "$context" --namespace "$namespace_b" get deployments -l "$role_selector,agent-runtime.dev/stack=$stack_b" -o json | jq -c '[.items[] | [.metadata.name,.metadata.uid]] | sort')"
b_stack_hash_before="$(shasum -a 256 "$(local_file "$stack_b" stack)" | cut -d ' ' -f 1)"
b_secrets_hash_before="$(shasum -a 256 "$(local_file "$stack_b" secrets)" | cut -d ' ' -f 1)"

prepare_evidence_draft
down_stack "$stack_a" "$namespace_a"
created_a=false
if kubectl --context "$context" get "namespace/$namespace_a" >/dev/null 2>&1; then
  echo "first local Stack namespace survived its teardown" >&2
  exit 1
fi
if [[ -e "$(local_file "$stack_a" stack)" || -e "$(local_file "$stack_a" secrets)" || -e "$(local_file "$stack_a" state)" || -e "$root/.runtime/dev/$stack_a.ci.bootstrap.json" || -e "$root/.runtime/dev/$stack_a.ci.operator-audit.jsonl" ]]; then
  echo "first local Stack private state survived its teardown" >&2
  exit 1
fi

observed_uid_b="$(kubectl --context "$context" get "namespace/$namespace_b" -o json | jq -er '.metadata.uid')"
b_deployments_after="$(kubectl --context "$context" --namespace "$namespace_b" get deployments -l "$role_selector,agent-runtime.dev/stack=$stack_b" -o json | jq -c '[.items[] | [.metadata.name,.metadata.uid]] | sort')"
b_stack_hash_after="$(shasum -a 256 "$(local_file "$stack_b" stack)" | cut -d ' ' -f 1)"
b_secrets_hash_after="$(shasum -a 256 "$(local_file "$stack_b" secrets)" | cut -d ' ' -f 1)"
if [[ "$observed_uid_b" != "$uid_b" || "$b_deployments_after" != "$b_deployments_before" || "$b_stack_hash_after" != "$b_stack_hash_before" || "$b_secrets_hash_after" != "$b_secrets_hash_before" ]]; then
  echo "tearing down the first local Stack mutated the second" >&2
  exit 1
fi
if ! kubectl --context "$context" --namespace "$namespace_b" get deployments -l "$role_selector,agent-runtime.dev/stack=$stack_b" -o json |
  runtime_roles_ready; then
  echo "second local Stack runtime roles lost readiness after first-instance teardown" >&2
  exit 1
fi

down_stack "$stack_b" "$namespace_b"
created_b=false
if kubectl --context "$context" get "namespace/$namespace_b" >/dev/null 2>&1; then
  echo "second local Stack namespace survived final cleanup" >&2
  exit 1
fi
echo "two local Stack instances remained isolated across first-instance teardown"
finalize_evidence
