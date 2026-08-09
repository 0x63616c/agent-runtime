#!/usr/bin/env bash
# Proves two local Stack instances can coexist and that tearing down one cannot
# mutate the other. It refuses to adopt either namespace if it already exists.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
context="${AGENT_RUNTIME_DEV_CONTEXT:-orbstack}"
profile="${AGENT_RUNTIME_DEV_PROFILE:-local}"
stack_a="${AGENT_RUNTIME_DEV_STACK_A:-m1-isolation-a}"
stack_b="${AGENT_RUNTIME_DEV_STACK_B:-m1-isolation-b}"
evidence_file="${AGENT_RUNTIME_TWO_STACK_EVIDENCE:-}"
diagnostics_dir="${AGENT_RUNTIME_TWO_STACK_DIAGNOSTICS:-}"
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
if [[ "$context" == "k3d-agent-runtime-isolated" && "$profile" != "ci" ]]; then
	echo "isolated k3d two-Stack smoke only permits the ci profile" >&2
	exit 1
fi
if [[ "$context" != "orbstack" && "$context" != "k3d-agent-runtime-isolated" ]]; then
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
  rm -f -- "$(local_file "$stack" stack)" "$(local_file "$stack" secrets)" "$(local_file "$stack" state)"
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
	if ! tilt alpha tiltfile-result --context "$context" -- --stack="$stack" --profile="$profile" >"$plan"; then
		rm -f -- "$plan"
		remove_local_state "$stack"
		return 1
	fi
	if ! jq -e --arg prefix "agent-runtime-dev/$stack/" '
		.DefaultRegistry.host == "localhost:5111" and
		.DefaultRegistry.hostFromContainerRuntime == "k3d-agent-runtime-registry.localhost:5111" and
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

if [[ "$context" == "k3d-agent-runtime-isolated" ]]; then
	verify_registry_plan "$stack_a"
	verify_registry_plan "$stack_b"
fi

down_stack() {
  local stack="$1"
  local namespace="$2"
  tilt down --context "$context" --namespace "$namespace" --delete-namespaces -- --stack="$stack" --profile="$profile" >/dev/null
  kubectl --context "$context" wait --for=delete "namespace/$namespace" --timeout=120s >/dev/null 2>&1 || true
  remove_local_state "$stack"
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

redact_diagnostics() {
  local source="$1"
  local destination="$2"
  # The retained diagnostic set is useful only if it cannot carry a credential
  # from a workload log or a Tilt session. Keep keys but replace their values.
  sed -E \
    -e 's/((password|secret|token|credential|api[_-]?key)[[:space:]]*[:=][[:space:]]*)[^[:space:]",}]+/\1[REDACTED]/Ig' \
    -e 's/(Authorization:[[:space:]]*(Bearer|Basic)[[:space:]]+)[^[:space:]"]+/\1[REDACTED]/Ig' \
    "$source" >"$destination"
}

capture_stack_diagnostics() {
  local stack="$1"
  local namespace="$2"
  local ci_status="$3"
  local prefix="$diagnostics_dir/$stack"
  local raw_snapshot="$prefix.tilt-session.raw.json"

  printf '%s\n' "$ci_status" >"$prefix.tilt-ci.exit-code"
  if [[ -f "$raw_snapshot" ]]; then
    redact_diagnostics "$raw_snapshot" "$prefix.tilt-session.json"
    rm -f -- "$raw_snapshot"
  fi
  kubectl --context "$context" --namespace "$namespace" get pods,deployments,persistentvolumeclaims,events -o json \
    >"$prefix.resources.raw.json" 2>&1 || true
  redact_diagnostics "$prefix.resources.raw.json" "$prefix.resources.json"
  rm -f -- "$prefix.resources.raw.json"
  kubectl --context "$context" --namespace "$namespace" get events --sort-by=.lastTimestamp \
    >"$prefix.events.raw.txt" 2>&1 || true
  redact_diagnostics "$prefix.events.raw.txt" "$prefix.events.txt"
  rm -f -- "$prefix.events.raw.txt"
  kubectl --context "$context" --namespace "$namespace" describe pods \
    >"$prefix.pods.raw.txt" 2>&1 || true
  redact_diagnostics "$prefix.pods.raw.txt" "$prefix.pods.txt"
  rm -f -- "$prefix.pods.raw.txt"
  kubectl --context "$context" --namespace "$namespace" logs --all-containers --prefix --tail=200 -l "agent-runtime.dev/stack=$stack" \
    >"$prefix.workload-logs.raw.txt" 2>&1 || true
  redact_diagnostics "$prefix.workload-logs.raw.txt" "$prefix.workload-logs.txt"
  rm -f -- "$prefix.workload-logs.raw.txt"
}

start_stack() {
  local stack="$1"
  local namespace="$2"
  local prefix="$diagnostics_dir/$stack"
  local ci_status=0
  # Local-path provisioners serialize four PVC helper operations; retain a
  # bounded allowance for both volume work and dependent role startup.
  printf 'tilt ci --context %q --namespace %q --port 0 --timeout %q --output-snapshot-on-exit %q -- --stack=%q --profile=%q\n' \
    "$context" "$namespace" "$readiness_timeout" "$prefix.tilt-session.raw.json" "$stack" "$profile" >"$prefix.tilt-ci.command.txt"
  tilt ci --context "$context" --namespace "$namespace" --port 0 --timeout "$readiness_timeout" \
    --output-snapshot-on-exit "$prefix.tilt-session.raw.json" -- --stack="$stack" --profile="$profile" \
    >"$prefix.tilt-ci.raw.log" 2>&1 || ci_status=$?
  redact_diagnostics "$prefix.tilt-ci.raw.log" "$prefix.tilt-ci.log"
  rm -f -- "$prefix.tilt-ci.raw.log"
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

down_stack "$stack_a" "$namespace_a"
created_a=false
if kubectl --context "$context" get "namespace/$namespace_a" >/dev/null 2>&1; then
  echo "first local Stack namespace survived its teardown" >&2
  exit 1
fi
if [[ -e "$(local_file "$stack_a" stack)" || -e "$(local_file "$stack_a" secrets)" || -e "$(local_file "$stack_a" state)" ]]; then
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
if [[ -n "$evidence_file" ]]; then
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
      command:{path:"deploy/dev/run-two-stack-smoke.sh",kubernetes_context:$context,profile:$profile,result:"passed"},
		toolchain:{cluster_runtime:$cluster_runtime,cluster_image:$cluster_image,registry_image:$registry_image,kubectl:$kubectl_version,tilt:$tilt_version},
      stacks:[{name:$stack_a,namespace:$namespace_a,namespace_uid:$uid_a},{name:$stack_b,namespace:$namespace_b,namespace_uid:$uid_b}],
      both_stacks_concurrently_ready:true,
      distinct_namespace_and_workload_identities:true,
		distinct_private_state:true,
		network_policy:{declared_egress_consecutive_successes:3,default_deny_consecutive_failures:3,service_ip_probe:true},
      first_teardown_left_second_unchanged:true,
      cleanup:{namespaces_absent:true,local_state_absent:true},
      limitations:["does not claim Linux KVM or Firecracker isolation","does not mutate a production cluster"]
    }' >"$evidence_file"
  echo "retained bounded two-Stack evidence at $evidence_file"
fi
