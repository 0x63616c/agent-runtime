#!/usr/bin/env bash
# Proves two local Stack instances can coexist and that tearing down one cannot
# mutate the other. It refuses to adopt either namespace if it already exists.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
context="${AGENT_RUNTIME_DEV_CONTEXT:-orbstack}"
stack_a="${AGENT_RUNTIME_DEV_STACK_A:-m1-isolation-a}"
stack_b="${AGENT_RUNTIME_DEV_STACK_B:-m1-isolation-b}"
namespace_a="ar-$stack_a"
namespace_b="ar-$stack_b"
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
if [[ "$stack_a" == "$stack_b" ]]; then
  echo "two-Stack smoke identities must differ" >&2
  exit 1
fi
kubectl --context "$context" get --raw=/readyz >/dev/null
for namespace in "$namespace_a" "$namespace_b"; do
  if kubectl --context "$context" get "namespace/$namespace" >/dev/null 2>&1; then
    echo "refuse to adopt pre-existing namespace $namespace" >&2
    exit 1
  fi
done

local_file() {
  printf '%s/.runtime/dev/%s.%s.json' "$root" "$1" "$2"
}

remove_local_state() {
  local stack="$1"
  rm -f -- "$(local_file "$stack" stack)" "$(local_file "$stack" secrets)" "$(local_file "$stack" state)"
}

down_stack() {
  local stack="$1"
  local namespace="$2"
  tilt down --context "$context" --namespace "$namespace" --delete-namespaces -- --stack="$stack" >/dev/null
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

start_stack() {
  local stack="$1"
  local namespace="$2"
  # OrbStack's local-path provisioner serializes four PVC helper operations;
  # retain a bounded allowance for both volume work and dependent role startup.
  tilt ci --context "$context" --namespace "$namespace" --port 0 --timeout 10m -- --stack="$stack" >/dev/null
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

role_selector='app.kubernetes.io/part-of=agent-runtime,agent-runtime.dev/profile=local'
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
