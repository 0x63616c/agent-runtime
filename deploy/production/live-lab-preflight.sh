#!/usr/bin/env bash
# Checks whether a separately rendered live-lab Stack can be safely handed to
# the reviewed operator. This command is deliberately read-only: it never
# creates a namespace, Secrets, workloads, or evidence.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest_validator="$root/deploy/production/live-lab-manifest.sh"
kubectl_binary="kubectl"

usage() {
  cat >&2 <<'EOF'
usage:
  live-lab-preflight.sh --stack-file STACK.json --kubeconfig /absolute/kubeconfig --context CONTEXT
  live-lab-preflight.sh --self-test

The stack must be the output of live-lab-manifest.sh render. Preflight only
performs Kubernetes GET/discovery/configuration reads. It refuses an existing
namespace, a substituted context, insufficient Linux/amd64 schedulable node
capacity, unavailable ExternalSecrets/NetworkPolicy APIs, or a manifest that
lacks immutable images, external Secret references, quota, or default-deny
network policies. A passing preflight is not permission to apply the Stack.
EOF
  exit 2
}

fail() {
  echo "live-lab preflight failed: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null || fail "required executable is unavailable: $1"
}

require_absolute_regular_file() {
  local path="$1" label="$2"
  [[ "$path" == /* && -f "$path" ]] || fail "$label must be an existing absolute file"
}

preflight() {
  local stack_file="" kubeconfig="" context=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --stack-file) stack_file="${2:-}"; shift 2 ;;
      --kubeconfig) kubeconfig="${2:-}"; shift 2 ;;
      --context) context="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$stack_file" && -n "$kubeconfig" && -n "$context" ]] || usage
  require_absolute_regular_file "$stack_file" "live lab stack file"
  require_absolute_regular_file "$kubeconfig" "live lab kubeconfig"
  [[ "$context" =~ ^[A-Za-z0-9][-A-Za-z0-9_.:/]*$ ]] || fail "context must be an explicit Kubernetes context name"
  require_command jq
  require_command go
  require_command "$kubectl_binary"

  "$manifest_validator" validate --stack-file "$stack_file" >/dev/null

  local stack_name namespace expected_context rendered manifests required_cpu required_memory
  stack_name="$(jq -er '.name' "$stack_file")"
  namespace="$(jq -er '.profiles.production.namespace' "$stack_file")"
  expected_context="$(jq -er '.profiles.production.prerequisites[] | select(.name == "target-context" and .kind == "kubernetes_context") | .expected' "$stack_file")"
  [[ "$namespace" == "$stack_name" ]] || fail "production namespace must equal the separately named Stack"
  [[ "$context" == "$expected_context" ]] || fail "context $context does not equal the rendered lab context $expected_context"

  rendered="$(go run "$root/cmd/stackctl" render --stack-file "$stack_file" --profile production)"
  manifests="$(go run "$root/cmd/stackctl" manifests --stack-file "$stack_file" --profile production)"
  required_cpu="$(printf '%s' "$rendered" | jq -er '[.resources[] | select(.kind == "kubernetes" and .kubernetes.kind == "ResourceQuota") | .kubernetes.compute.request_milli_cpu] | if length == 1 then .[0] else error("exactly one quota") end')"
  required_memory="$(printf '%s' "$rendered" | jq -er '[.resources[] | select(.kind == "kubernetes" and .kubernetes.kind == "ResourceQuota") | .kubernetes.compute.request_memory_bytes] | if length == 1 then .[0] else error("exactly one quota") end')"
  printf '%s' "$rendered" | jq -e --arg namespace "$namespace" '
    .stack == $namespace and .profile == "production" and .namespace == $namespace and
    ([.resources[] | select(.kind == "secret_reference")]) as $secrets |
    ($secrets | length) > 0 and
    ($secrets | all(.external_controller == true and .secret_reference.provider == "external-secrets" and (.secret_reference.reference | startswith($namespace + "-")))) and
    ([.resources[] | select(.kind == "kubernetes" and (.kubernetes.kind == "Deployment" or .kubernetes.kind == "StatefulSet" or .kubernetes.kind == "Job"))]) as $workloads |
    ($workloads | length) > 0 and
    ($workloads | all(.kubernetes.image | test("@sha256:[0-9a-f]{64}$")))
  ' >/dev/null || fail "rendered lab must use only external Secret references and immutable workload images"
  printf '%s' "$manifests" | jq -e '
    ([.items[] | select(.kind == "Deployment" or .kind == "StatefulSet" or .kind == "Job") | .metadata.labels["agent-runtime.dev/resource"]] | unique) as $workloads |
    ([.items[] | select(.kind == "NetworkPolicy" and .spec.podSelector.matchLabels["agent-runtime.dev/resource"] != null and (.spec.policyTypes | index("Egress")) != null) | .spec.podSelector.matchLabels["agent-runtime.dev/resource"]] | unique) as $restricted |
    ($workloads - $restricted) == []
  ' >/dev/null || fail "every lab workload must have a rendered restrictive egress NetworkPolicy"

  "$kubectl_binary" --kubeconfig "$kubeconfig" config get-contexts -o name |
    grep -Fx -- "$context" >/dev/null || fail "explicit context is unavailable in the supplied kubeconfig"
  local namespace_observation
  namespace_observation="$("$kubectl_binary" --kubeconfig "$kubeconfig" --context "$context" get namespace "$namespace" --ignore-not-found -o json)"
  [[ -z "${namespace_observation//[[:space:]]/}" ]] || fail "namespace $namespace already exists; preflight will not take it over"

  "$kubectl_binary" --kubeconfig "$kubeconfig" --context "$context" api-resources --api-group external-secrets.io -o name |
    grep -Fx 'externalsecrets' >/dev/null || fail "ExternalSecrets API is unavailable"
  "$kubectl_binary" --kubeconfig "$kubeconfig" --context "$context" get crd externalsecrets.external-secrets.io -o json |
    jq -e '[.status.conditions[]? | select(.type == "Established" and .status == "True")] | length == 1' >/dev/null ||
    fail "ExternalSecrets CRD is not established"
  "$kubectl_binary" --kubeconfig "$kubeconfig" --context "$context" api-resources --api-group networking.k8s.io -o name |
    grep -Fx 'networkpolicies' >/dev/null || fail "NetworkPolicy API is unavailable"

  local nodes capacity
  nodes="$("$kubectl_binary" --kubeconfig "$kubeconfig" --context "$context" get nodes -o json)"
  capacity="$(printf '%s' "$nodes" | jq -er '
    def cpu_milli:
      if test("^[0-9]+m$") then rtrimstr("m") | tonumber
      elif test("^[0-9]+(\\.[0-9]+)?$") then tonumber * 1000
      else error("unsupported CPU quantity " + .) end;
    def memory_bytes:
      capture("^(?<amount>[0-9]+)(?<unit>Ki|Mi|Gi|Ti|K|M|G|T)?$") as $q |
      ($q.amount | tonumber) *
        (if $q.unit == null then 1 elif $q.unit == "Ki" then 1024 elif $q.unit == "Mi" then 1048576 elif $q.unit == "Gi" then 1073741824 elif $q.unit == "Ti" then 1099511627776 elif $q.unit == "K" then 1000 elif $q.unit == "M" then 1000000 elif $q.unit == "G" then 1000000000 elif $q.unit == "T" then 1000000000000 else error("unsupported memory unit") end);
    [.items[] |
      select(.status.nodeInfo.operatingSystem == "linux" and .status.nodeInfo.architecture == "amd64" and (.spec.unschedulable // false | not) and ([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length == 1))] as $ready |
    if ($ready | length) == 0 then error("no Ready schedulable Linux/amd64 node") else
      {nodes: ($ready | length), cpu_milli: ([$ready[] | .status.allocatable.cpu | cpu_milli] | add), memory_bytes: ([$ready[] | .status.allocatable.memory | memory_bytes] | add)}
    end
  ')"
  [[ "$(printf '%s' "$capacity" | jq -r '.cpu_milli >= $required' --argjson required "$required_cpu")" == true ]] || fail "ready Linux/amd64 allocatable CPU is below lab quota request"
  [[ "$(printf '%s' "$capacity" | jq -r '.memory_bytes >= $required' --argjson required "$required_memory")" == true ]] || fail "ready Linux/amd64 allocatable memory is below lab quota request"

  jq -n --arg stack "$stack_name" --arg namespace "$namespace" --arg context "$context" --argjson required_cpu "$required_cpu" --argjson required_memory "$required_memory" --argjson capacity "$capacity" '{status:"ready-for-reviewed-operator-apply",read_only:true,stack:$stack,namespace:$namespace,context:$context,required_quota:{cpu_milli:$required_cpu,memory_bytes:$required_memory},ready_linux_amd64_capacity:$capacity,validated:{namespace_absent:true,external_secrets_api:true,network_policy_api:true,external_secret_references:true,immutable_images:true,default_deny_workload_policies:true}}'
}

self_test() {
  local temporary_directory stack_file kubeconfig fake_kubectl
  temporary_directory="$(mktemp -d)"
  stack_file="$temporary_directory/live-lab.json"
  kubeconfig="$temporary_directory/kubeconfig"
  fake_kubectl="$temporary_directory/kubectl"
  trap "rm -rf -- '$temporary_directory'" EXIT
  printf 'apiVersion: v1\nkind: Config\n' >"$kubeconfig"
  "$manifest_validator" render --name agent-runtime-live-lab-selftest --context home-server --output "$stack_file" >/dev/null
  cat >"$fake_kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
arguments="$*"
case "$arguments" in
  *'config get-contexts -o name'*) printf 'home-server\n' ;;
  *'get namespace agent-runtime-live-lab-selftest --ignore-not-found -o json'*)
    if [[ -n "${FAKE_OCCUPIED_NAMESPACE_FILE:-}" ]]; then cat "$FAKE_OCCUPIED_NAMESPACE_FILE"; fi ;;
  *'api-resources --api-group external-secrets.io -o name'*) printf 'externalsecrets\n' ;;
  *'get crd externalsecrets.external-secrets.io -o json'*) printf '{"status":{"conditions":[{"type":"Established","status":"True"}]}}\n' ;;
  *'api-resources --api-group networking.k8s.io -o name'*) printf 'networkpolicies\n' ;;
  *'get nodes -o json'*) printf '%s\n' '{"items":[{"spec":{},"status":{"nodeInfo":{"operatingSystem":"linux","architecture":"amd64"},"conditions":[{"type":"Ready","status":"True"}],"allocatable":{"cpu":"8","memory":"32Gi"}}}]}' ;;
  *) printf 'unexpected kubectl invocation: %s\n' "$arguments" >&2; exit 1 ;;
esac
EOF
  chmod 700 "$fake_kubectl"
  PATH="$temporary_directory:$PATH" "$0" --stack-file "$stack_file" --kubeconfig "$kubeconfig" --context home-server |
    jq -e '.status == "ready-for-reviewed-operator-apply" and .read_only == true and .validated.namespace_absent == true and .ready_linux_amd64_capacity.nodes == 1' >/dev/null
  printf '{"items":[{"metadata":{"name":"agent-runtime-live-lab-selftest"}}]}' >"$temporary_directory/occupied-namespace.json"
  if FAKE_OCCUPIED_NAMESPACE_FILE="$temporary_directory/occupied-namespace.json" PATH="$temporary_directory:$PATH" "$0" --stack-file "$stack_file" --kubeconfig "$kubeconfig" --context home-server >/dev/null 2>&1; then
    fail "preflight accepted an existing namespace"
  fi
  echo "live lab preflight accepts only read-only ready prerequisites and rejects namespace takeover"
}

case "${1:-}" in
  --self-test) self_test ;;
  *) preflight "$@" ;;
esac
