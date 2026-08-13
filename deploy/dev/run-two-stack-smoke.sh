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
local_kubeconfig=""
trust_wiring_a=""
trust_wiring_b=""
runtime_role_ids='["api","orchestration","model","tool","blob-role","codec","sandbox-control","sandbox-host"]'
# These are Tilt resource names declared in the reviewed Tiltfile. Snapshot
# extraction rejects every other resource name, so a future Tilt extension or
# an adversarial manifest cannot turn this diagnostic into an inventory dump.
tilt_resource_ids='["api","blob","blob-role","blob-reconciler","codec","egress-proxy","migration-runner","model","orchestration","otel-collector","sandbox-control","sandbox-host","sandbox-host-bootstrap","stack-reconcile","state","telemetry","temporal","temporal-state","tool"]'

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

# Pod status is useful when Tilt has stopped before a dependent runtime role
# was even applied, but Kubernetes event messages and container logs can carry
# arbitrary process output. Retain only fixed Kubernetes state names, numeric
# restart counts, and readiness counts; no messages, environment, command, or
# image data is retained.
runtime_role_startup_status() {
  jq -c --argjson roles "$runtime_role_ids" '
    def safe_phase:
      if . == "Pending" or . == "Running" or . == "Succeeded" or . == "Failed" or . == "Unknown" then . else "unknown" end;
    def safe_reason:
      if . == "ContainerCreating" or . == "CrashLoopBackOff" or . == "CreateContainerConfigError" or
         . == "CreateContainerError" or . == "ErrImageNeverPull" or . == "ErrImagePull" or
         . == "ImagePullBackOff" or . == "InvalidImageName" or . == "OOMKilled" or
         . == "PodInitializing" or . == "RunContainerError" or . == "ContainerCannotRun" or
         . == "Error" or . == "Completed" then . else "other" end;
    [
      $roles[] as $id |
      {
        id:$id,
        pods:([
          .items[] | select(.metadata.labels["agent-runtime.dev/resource"] == $id) |
          {
            phase:(.status.phase // "unknown" | safe_phase),
            ready_containers:([.status.containerStatuses[]? | select(.ready == true)] | length),
            restart_count:([.status.containerStatuses[]?.restartCount // 0] | add // 0),
            state_reasons:([
              .status.initContainerStatuses[]?, .status.containerStatuses[]? |
              .state.waiting.reason?, .state.terminated.reason? | safe_reason
            ] | unique | sort)
          }
        ])
      }
    ]
  '
}

empty_runtime_role_startup_status() {
  jq -nc --argjson roles "$runtime_role_ids" '$roles | map({id:.,pods:[]})'
}

# A Tilt snapshot contains the complete UI log store, links, status messages,
# and resource metadata. It is an unsafe, short-lived diagnostic input. This
# extractor retains only declared resource names and three bounded state enums.
# It deliberately does not retain build errors, log spans, URLs, pod names, or
# condition messages/reasons.
tilt_snapshot_diagnostics() {
  local snapshot="$1"
  if [[ ! -s "$snapshot" ]]; then
    printf '%s' '{"snapshot_state":"unavailable","resource_status":[]}'
    return 0
  fi
  jq -c --argjson resources "$tilt_resource_ids" '
    def safe_build:
      if (.status | type) != "object" then "unknown"
      elif (.status.currentBuild? | type) == "object" then "running"
      elif (.status.buildHistory? | type) != "array" then "not_observed"
      elif (.status.buildHistory | length) == 0 then "not_observed"
      elif (.status.buildHistory[-1].error? | type) == "string" and (.status.buildHistory[-1].error | length) > 0 then "failed"
      elif (.status.buildHistory[-1].error? == null) or ((.status.buildHistory[-1].error? | type) == "string") then "succeeded"
      else "unknown" end;
    def safe_runtime:
      if (.status.runtimeStatus? | type) != "string" then "unknown"
      elif .status.runtimeStatus == "ok" then "healthy"
      elif .status.runtimeStatus == "error" then "unhealthy"
      elif .status.runtimeStatus == "pending" then "pending"
      elif .status.runtimeStatus == "not_applicable" then "not_applicable"
      else "unknown" end;
    def safe_update:
      if (.status.updateStatus? | type) != "string" then "unknown"
      elif .status.updateStatus == "ok" then "succeeded"
      elif .status.updateStatus == "error" then "failed"
      elif .status.updateStatus == "pending" then "pending"
      elif .status.updateStatus == "not_applicable" then "not_applicable"
      else "unknown" end;
    if (.view | type) != "object" or (.view.uiResources | type) != "array" then
      error("snapshot is missing its resource list")
    else
      [(.view.uiResources)[]? |
        .metadata.name? as $id |
        select(($id | type) == "string" and ($resources | index($id))) |
        {id:$id,build_state:safe_build,runtime_state:safe_runtime,update_state:safe_update}
      ] | unique_by(.id) | sort_by(.id) as $resource_status |
      {snapshot_state:"observed",resource_status:$resource_status}
    end
  ' "$snapshot" 2>/dev/null || printf '%s' '{"snapshot_state":"unavailable","resource_status":[]}'
}

# This is intentionally narrower than the existing aggregate pod state: the
# only numeric termination detail retained is the reviewed API container's
# latest exit code. Kubernetes messages are never copied into diagnostics.
api_last_termination() {
  jq -c '
    def safe_reason:
      if . == "ContainerCreating" or . == "CrashLoopBackOff" or . == "CreateContainerConfigError" or
         . == "CreateContainerError" or . == "ErrImageNeverPull" or . == "ErrImagePull" or
         . == "ImagePullBackOff" or . == "InvalidImageName" or . == "OOMKilled" or
         . == "PodInitializing" or . == "RunContainerError" or . == "ContainerCannotRun" or
         . == "Error" or . == "Completed" then . else "other" end;
    [ .items[]? |
      select(.metadata.labels["agent-runtime.dev/resource"] == "api") |
      .status.containerStatuses[]? |
      select(.name == "api" and (.lastState.terminated? | type) == "object") |
      .lastState.terminated |
      select((.exitCode? | type) == "number" and .exitCode >= 0 and .exitCode <= 255) |
      {exit_code:.exitCode,reason:(.reason? | safe_reason),finished_at:(.finishedAt? // "")}
    ] as $terminations |
    if ($terminations | length) == 0 then
      {observed:false,exit_code:0,reason:"not_observed"}
    else
      ($terminations | sort_by(.finished_at) | last) as $latest |
      {observed:true,exit_code:$latest.exit_code,reason:$latest.reason}
    end
  '
}

# Tilt output can include rendered workload configuration, so it is never
# retained. This classifier reads a private, short-lived output file and emits
# one bounded phase token only. The token separates failures before Kubernetes
# workload creation (render/image/apply) from a readiness timeout without
# copying arbitrary output into the CI artifact or log.
classify_tilt_ci_failure() {
  local output="$1"
  # A successful Tilt invocation normally prints the word "Tiltfile", so it
  # is not evidence of a render failure. Match only an error/failure adjacent
  # to a renderer operation, and prefer a terminal readiness timeout when it
  # is present alongside earlier routine Tiltfile output.
  if grep -Eiq '(^|[^[:alpha:]])(timed out waiting|resource .* failed)([^[:alpha:]]|$)' "$output"; then
    printf '%s' readiness
  elif grep -Eiq '(^|[^[:alpha:]])(imagepullbackoff|errimagepull|failed to pull image|image pull failed|registry .* (unavailable|timeout|connection))([^[:alpha:]]|$)' "$output"; then
    # A just-pushed image can briefly be unavailable through k3d's private
    # registry path. This is the sole retryable class; render, apply, build,
    # and readiness failures must remain immediately visible.
    printf '%s' registry_sync
  elif grep -Eiq '(^|[^[:alpha:]])(docker build|build failed|failed to solve|error building image)([^[:alpha:]]|$)' "$output"; then
    printf '%s' image_build
  elif grep -Eiq '(^|[^[:alpha:]])(error from server|apply failed|failed to apply|unable to recognize)([^[:alpha:]]|$)' "$output"; then
    printf '%s' kubernetes_apply
  elif grep -Eiq '(tiltfile.*(error|failed)|error.*tiltfile|go run ./tools/dev render.*(error|failed)|stackctl manifests.*(error|failed)|tools/dev secrets.*(error|failed))' "$output"; then
    printf '%s' render
  else
    printf '%s' unknown
  fi
}

run_tilt_ci_attempt() {
  local stack="$1"
  local namespace="$2"
  local output
  local snapshot
  output="$(mktemp "${TMPDIR:-/tmp}/agent-runtime-tilt-ci-output.XXXXXX")"
  snapshot="$(mktemp "${TMPDIR:-/tmp}/agent-runtime-tilt-ci-snapshot.XXXXXX")"
  chmod 600 "$output"
  chmod 600 "$snapshot"
  local exit_code=0
  if ! tilt ci --context "$context" --namespace "$namespace" --port 0 --timeout "$readiness_timeout" --output-snapshot-on-exit "$snapshot" \
    -- --stack="$stack" --profile="$profile" "${ci_tilt_args[@]}" >"$output" 2>&1; then
    exit_code=1
  fi
  local snapshot_diagnostics resource_status snapshot_state phase
  snapshot_diagnostics="$(tilt_snapshot_diagnostics "$snapshot")"
  resource_status="$(jq -ec '.resource_status' <<<"$snapshot_diagnostics")"
  snapshot_state="$(jq -er '.snapshot_state' <<<"$snapshot_diagnostics")"
  if [[ "$exit_code" != 0 ]]; then
    phase="$(classify_tilt_ci_failure "$output")"
  fi
  rm -f -- "$snapshot" "$output"
  if [[ "$exit_code" == 0 ]]; then
    jq -nc --argjson resource_status "$resource_status" --arg snapshot_state "$snapshot_state" '{phase:"none",snapshot_state:$snapshot_state,resource_status:$resource_status}'
    return 0
  fi
  jq -nc --arg phase "$phase" --arg snapshot_state "$snapshot_state" --argjson resource_status "$resource_status" '{phase:$phase,snapshot_state:$snapshot_state,resource_status:$resource_status}'
  return 1
}

# Observe only stable identity and configuration metadata from the live Stack.
# Kubernetes Secret values and workload output are intentionally never read or
# retained. The strict credential-name mapping proves each runtime role is not
# accidentally given another role's credentials.
observe_stack_trust_wiring() {
  local stack="$1"
  local namespace="$2"
  local deployments
  local service_accounts
  local orchestration_config
  local temporal_description
  local retention_days
  local temporal_endpoint
  local task_queue
  local expected_wiring

  deployments="$(kubectl --context "$context" --namespace "$namespace" get deployments -l "app.kubernetes.io/part-of=agent-runtime,agent-runtime.dev/profile=$profile,agent-runtime.dev/stack=$stack" -o json)"
  service_accounts="$(kubectl --context "$context" --namespace "$namespace" get serviceaccounts -o json)"
  # Derive expected, non-secret metadata from this Stack's own reviewed render.
  # This keeps local and CI profiles truthful without duplicating their secret
  # policy in the harness, while comparing exact Secret names and keys.
  expected_wiring="$(jq -cer --arg profile "$profile" --argjson roles "$runtime_role_ids" '
    .profiles[$profile].resources as $resources |
    (reduce $resources[] as $resource ({};
      if $resource.kind == "secret_reference" then .[$resource.id] = $resource.secret_reference.reference else . end
    )) as $secret_references |
    {
      runtime_roles: [
        $resources[] | select(.kind == "kubernetes" and .kubernetes.kind == "Deployment" and (.id as $id | $roles | index($id) != null)) |
        {
          id, service_account:.kubernetes.service_account,
          secret_environment:([.kubernetes.secret_environment[]? | {name,secret:$secret_references[.secret],key}] | sort_by(.name,.secret,.key)),
          secret_mounts:([.kubernetes.secret_mounts[]? | {secret:$secret_references[.secret],key,path}] | sort_by(.secret,.key,.path))
        }
      ] | sort_by(.id),
      supporting_workloads: [
        $resources[] | select(.kind == "kubernetes" and .kubernetes.kind == "Deployment" and (.id == "state" or .id == "blob" or .id == "telemetry")) |
        {id,service_account:.kubernetes.service_account}
      ] | sort_by(.id)
    }
  ' "$(local_file "$stack" stack)")"
  if ! jq -e --argjson roles "$runtime_role_ids" --argjson expected "$expected_wiring" '
    [.items[] | select(.metadata.labels["agent-runtime.dev/resource"] as $id | $roles | index($id) != null) |
      {
        id:.metadata.labels["agent-runtime.dev/resource"],
        service_account:(.spec.template.spec.serviceAccountName // ""),
        service_account_token:(.spec.template.spec.automountServiceAccountToken // true),
        secret_environment:([.spec.template.spec.containers[].env[]? | select(.valueFrom.secretKeyRef != null) | {name,secret:.valueFrom.secretKeyRef.name,key:.valueFrom.secretKeyRef.key}] | sort_by(.name,.secret,.key)),
        env_from:([.spec.template.spec.containers[].envFrom[]?]),
        secret_mounts:([
          .spec.template.spec.volumes[]? as $volume |
          select($volume.secret != null) |
          $volume.secret as $secret |
          $secret.items[]? | {secret:$secret.secretName,key,path}
        ] | sort_by(.secret,.key,.path)),
        init_containers:(.spec.template.spec.initContainers // [])
      }
    ] | sort_by(.id) as $observed |
    ($observed | length == ($roles | length)) and
    ([ $observed[].id ] | unique | sort) == ($roles | sort) and
    all($observed[];
      (. as $role | $expected.runtime_roles[] | select(.id == $role.id)) as $expected_role |
      .service_account == $expected_role.service_account and
      .service_account_token == false and
      .secret_environment == $expected_role.secret_environment and
      .secret_mounts == $expected_role.secret_mounts and
      (.env_from | length == 0) and (.init_containers | length == 0)
    )
  ' <<<"$deployments" >/dev/null; then
    echo "runtime role trust wiring differs from the declared CI profile" >&2
    return 1
  fi
  if ! jq -e --argjson expected "$expected_wiring" '
    [.items[] | select(.metadata.labels["agent-runtime.dev/resource"] as $id | ["state","blob","telemetry"] | index($id) != null) |
      {id:.metadata.labels["agent-runtime.dev/resource"],service_account:(.spec.template.spec.serviceAccountName // "")}]
    | sort_by(.id) == $expected.supporting_workloads
  ' <<<"$deployments" >/dev/null; then
    echo "state, blob, or telemetry workload identity differs from the declared CI profile" >&2
    return 1
  fi
  if ! jq -e --argjson expected "$expected_wiring" '
    [.items[].metadata.name] as $accounts |
    ($expected.runtime_roles + $expected.supporting_workloads | map(.service_account) | unique) |
    all(. as $account | $accounts | index($account) != null)
  ' <<<"$service_accounts" >/dev/null; then
    echo "state, blob, or telemetry ServiceAccount is absent" >&2
    return 1
  fi

  orchestration_config="$(jq -er '
    [.items[] | select(.metadata.labels["agent-runtime.dev/resource"] == "orchestration") |
      .spec.template.spec.containers[].env[]? | select(.name == "RUNTIME_ROLE_CONFIG") | .value] |
    if length == 1 then .[0] else error("expected one orchestration role configuration") end
  ' <<<"$deployments")"
  retention_days="$(jq -er '.profiles.ci.resources[] | select(.id == "temporal-namespace") | .orchestration.retention_days' "$(local_file "$stack" stack)")"
  temporal_endpoint="temporal.$namespace.svc:7233"
  task_queue="$namespace-session-v1"
  if ! jq -e --arg namespace "$namespace" --arg endpoint "$temporal_endpoint" --arg task_queue "$task_queue" '
    .namespace == $namespace and
    ([.dependencies[] | select(.name == "temporal") | .endpoint] == [$endpoint]) and
    .worker.task_queue == $task_queue
  ' <<<"$orchestration_config" >/dev/null; then
    echo "orchestration Temporal endpoint, namespace, or task queue differs from the declared Stack identity" >&2
    return 1
  fi
  temporal_description="$(kubectl --context "$context" --namespace "$namespace" exec deployment/temporal -- \
    temporal --address 127.0.0.1:7233 --command-timeout 30s --output json \
    operator namespace describe --namespace "$namespace")"
  if ! jq -e --argjson retention_days "$retention_days" '
    .config.workflowExecutionRetentionTtl == (($retention_days * 86400 | tostring) + "s")
  ' <<<"$temporal_description" >/dev/null; then
    echo "Temporal namespace does not retain the declared bounded retention" >&2
    return 1
  fi

  jq -nc \
    --arg stack "$stack" \
    --arg namespace "$namespace" \
    --arg temporal_endpoint "$temporal_endpoint" \
    --arg task_queue "$task_queue" \
    --argjson retention_days "$retention_days" \
    --argjson expected "$expected_wiring" \
    '{version:1,stack:$stack,namespace:$namespace,runtime_roles:{service_accounts:($expected.runtime_roles | map({key:.id,value:.service_account}) | from_entries),service_account_tokens_disabled:true,secret_references_scoped:true},temporal:{endpoint:$temporal_endpoint,namespace:$namespace,task_queue:$task_queue,retention_days:$retention_days},dependencies:($expected.supporting_workloads | map({key:(.id + "_service_account"),value:.service_account}) | from_entries)}'
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
  local tilt_ci_attempts="$8"
  local startup_status="$9"
  local tilt_ci_failure_phases="${10}"
  local tilt_resource_status="${11}"
  local api_termination="${12}"
  local tilt_snapshot_state="${13}"
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
    --argjson tilt_ci_attempts "$tilt_ci_attempts" \
    --argjson runtime_role_startup_status "$startup_status" \
    --argjson tilt_ci_failure_phases "$tilt_ci_failure_phases" \
    --argjson tilt_resource_status "$tilt_resource_status" \
    --argjson api_last_termination "$api_termination" \
    --arg tilt_snapshot_state "$tilt_snapshot_state" \
    '{kind:"diagnostic-summary/v4",version:4,stack:$stack,namespace:$namespace,profile:$profile,tilt_ci_exit_code:$tilt_ci_exit_code,tilt_ci_attempts:$tilt_ci_attempts,tilt_ci_failure_phases:$tilt_ci_failure_phases,tilt_snapshot_state:$tilt_snapshot_state,tilt_resource_status:$tilt_resource_status,workload_probe:$probe_status,runtime_roles_observed:$runtime_roles_observed,runtime_roles_ready:$runtime_roles_ready,runtime_role_status:$runtime_role_status,runtime_role_startup_status:$runtime_role_startup_status,api_last_termination:$api_last_termination}' \
    >"$destination"

  jq -e '
    keys == ["api_last_termination","kind","namespace","profile","runtime_role_startup_status","runtime_role_status","runtime_roles_observed","runtime_roles_ready","stack","tilt_ci_attempts","tilt_ci_exit_code","tilt_ci_failure_phases","tilt_resource_status","tilt_snapshot_state","version","workload_probe"] and
    .kind == "diagnostic-summary/v4" and .version == 4 and
    (.stack | type == "string") and (.namespace | type == "string") and (.profile | type == "string") and
    (.tilt_ci_exit_code | type == "number") and (.tilt_ci_attempts | type == "number" and . >= 0 and . <= 2) and
    (.tilt_ci_attempts as $attempts | .tilt_ci_failure_phases | type == "array" and (if $attempts == 0 then length <= 1 else length <= $attempts end) and all(.[]; . == "bootstrap" or . == "render" or . == "image_build" or . == "kubernetes_apply" or . == "readiness" or . == "registry_sync" or . == "unknown")) and
    (.tilt_snapshot_state == "observed" or .tilt_snapshot_state == "unavailable") and
    (.tilt_resource_status | type == "array" and length <= 19 and
      ([.[].id] | unique | length) == length and all(.[];
        keys == ["build_state","id","runtime_state","update_state"] and
        (.id == "api" or .id == "blob" or .id == "blob-role" or .id == "blob-reconciler" or .id == "codec" or .id == "egress-proxy" or .id == "migration-runner" or .id == "model" or .id == "orchestration" or .id == "otel-collector" or .id == "sandbox-control" or .id == "sandbox-host" or .id == "sandbox-host-bootstrap" or .id == "stack-reconcile" or .id == "state" or .id == "telemetry" or .id == "temporal" or .id == "temporal-state" or .id == "tool") and
        (.build_state == "failed" or .build_state == "not_observed" or .build_state == "running" or .build_state == "succeeded" or .build_state == "unknown") and
        (.runtime_state == "healthy" or .runtime_state == "not_applicable" or .runtime_state == "pending" or .runtime_state == "unhealthy" or .runtime_state == "unknown") and
        (.update_state == "failed" or .update_state == "not_applicable" or .update_state == "pending" or .update_state == "succeeded" or .update_state == "unknown"))) and
    (.api_last_termination | keys == ["exit_code","observed","reason"] and
      (.observed | type == "boolean") and (.exit_code | type == "number" and . >= 0 and . <= 255) and
      (.reason == "not_observed" or .reason == "ContainerCreating" or .reason == "CrashLoopBackOff" or .reason == "CreateContainerConfigError" or .reason == "CreateContainerError" or .reason == "ErrImageNeverPull" or .reason == "ErrImagePull" or .reason == "ImagePullBackOff" or .reason == "InvalidImageName" or .reason == "OOMKilled" or .reason == "PodInitializing" or .reason == "RunContainerError" or .reason == "ContainerCannotRun" or .reason == "Error" or .reason == "Completed" or .reason == "other")) and
    (.workload_probe | type == "string") and
    (.runtime_roles_observed | type == "number") and (.runtime_roles_ready | type == "boolean") and
    (.runtime_role_status | type == "array" and length == 8 and
      ([.[].id] | unique | sort) == ["api","blob-role","codec","model","orchestration","sandbox-control","sandbox-host","tool"] and
      all(.[]; keys == ["available_replicas","id","ready_replicas","replicas"] and
        (.id | type == "string") and (.replicas | type == "number") and
        (.ready_replicas | type == "number") and (.available_replicas | type == "number")))
    and
    (.runtime_role_startup_status | type == "array" and length == 8 and
      ([.[].id] | unique | sort) == ["api","blob-role","codec","model","orchestration","sandbox-control","sandbox-host","tool"] and
      all(.[]; keys == ["id","pods"] and (.id | type == "string") and
        (.pods | type == "array" and length <= 4 and all(.[];
          keys == ["phase","ready_containers","restart_count","state_reasons"] and
          (.phase == "Pending" or .phase == "Running" or .phase == "Succeeded" or .phase == "Failed" or .phase == "Unknown" or .phase == "unknown") and
          (.ready_containers | type == "number" and . >= 0) and (.restart_count | type == "number" and . >= 0) and
          (.state_reasons | type == "array" and all(.[]; . == "ContainerCreating" or . == "CrashLoopBackOff" or . == "CreateContainerConfigError" or . == "CreateContainerError" or . == "ErrImageNeverPull" or . == "ErrImagePull" or . == "ImagePullBackOff" or . == "InvalidImageName" or . == "OOMKilled" or . == "PodInitializing" or . == "RunContainerError" or . == "ContainerCannotRun" or . == "Error" or . == "Completed" or . == "other"))))
    ))
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
  write_safe_diagnostic_summary "$stack" "$namespace" 1 "unavailable" 0 false "$(empty_runtime_role_status)" 0 "$(empty_runtime_role_startup_status)" '["render"]' '[]' '{"observed":false,"exit_code":0,"reason":"not_observed"}' unavailable
}

if [[ "$diagnostic_self_test" == true ]]; then
  command -v jq >/dev/null || {
    echo "jq is required for diagnostic self-test" >&2
    exit 1
  }
  fixture_role_status="$(empty_runtime_role_status)"
  pod_status_fixture='{"items":[{"metadata":{"labels":{"agent-runtime.dev/resource":"api"}},"status":{"phase":"Pending","containerStatuses":[{"ready":false,"restartCount":1,"state":{"waiting":{"reason":"adversarial-runtime-detail"}}}]}}]}'
  fixture_startup_status="$(printf '%s' "$pod_status_fixture" | runtime_role_startup_status)"
  snapshot_fixture="$(mktemp "${TMPDIR:-/tmp}/agent-runtime-tilt-snapshot-fixture.XXXXXX")"
  cat >"$snapshot_fixture" <<'EOF'
{"view":{"log":"Bearer adversarial-header-token","uiResources":[{"metadata":{"name":"api"},"status":{"buildHistory":[{"error":"MODEL_API_KEY=adversarial-env-secret"}],"runtimeStatus":"error","updateStatus":"error","endpointLinks":[{"url":"https://token:adversarial-json-secret@example.invalid"}]}},{"metadata":{"name":"foreign-resource"},"status":{"buildHistory":[{"error":"foreign secret"}],"runtimeStatus":"error","updateStatus":"error"}}]}}
EOF
  fixture_snapshot_diagnostics="$(tilt_snapshot_diagnostics "$snapshot_fixture")"
  fixture_tilt_resource_status="$(jq -ec '.resource_status' <<<"$fixture_snapshot_diagnostics")"
  fixture_tilt_snapshot_state="$(jq -er '.snapshot_state' <<<"$fixture_snapshot_diagnostics")"
  rm -f -- "$snapshot_fixture"
  empty_snapshot_fixture="$(mktemp "${TMPDIR:-/tmp}/agent-runtime-tilt-snapshot-empty-fixture.XXXXXX")"
  printf '%s' '{"view":{"uiResources":[]}}' >"$empty_snapshot_fixture"
  if [[ "$(tilt_snapshot_diagnostics "$empty_snapshot_fixture")" != '{"snapshot_state":"observed","resource_status":[]}' ]]; then
    echo "safe diagnostic summary did not distinguish an observed empty Tilt snapshot" >&2
    exit 1
  fi
  rm -f -- "$empty_snapshot_fixture"
  malformed_snapshot_fixture="$(mktemp "${TMPDIR:-/tmp}/agent-runtime-tilt-snapshot-malformed-fixture.XXXXXX")"
  printf '%s' '{"view":' >"$malformed_snapshot_fixture"
  if [[ "$(tilt_snapshot_diagnostics "$malformed_snapshot_fixture")" != '{"snapshot_state":"unavailable","resource_status":[]}' ]]; then
    echo "safe diagnostic summary accepted a malformed Tilt snapshot" >&2
    exit 1
  fi
  rm -f -- "$malformed_snapshot_fixture"
  missing_view_snapshot_fixture="$(mktemp "${TMPDIR:-/tmp}/agent-runtime-tilt-snapshot-missing-view-fixture.XXXXXX")"
  printf '%s' '{}' >"$missing_view_snapshot_fixture"
  if [[ "$(tilt_snapshot_diagnostics "$missing_view_snapshot_fixture")" != '{"snapshot_state":"unavailable","resource_status":[]}' ]]; then
    echo "safe diagnostic summary accepted a snapshot without a view" >&2
    exit 1
  fi
  rm -f -- "$missing_view_snapshot_fixture"
  missing_resource_list_fixture="$(mktemp "${TMPDIR:-/tmp}/agent-runtime-tilt-snapshot-missing-resource-list-fixture.XXXXXX")"
  printf '%s' '{"view":{}}' >"$missing_resource_list_fixture"
  if [[ "$(tilt_snapshot_diagnostics "$missing_resource_list_fixture")" != '{"snapshot_state":"unavailable","resource_status":[]}' ]]; then
    echo "safe diagnostic summary accepted a snapshot without a resource list" >&2
    exit 1
  fi
  rm -f -- "$missing_resource_list_fixture"
  fixture_api_termination="$(printf '%s' '{"items":[{"metadata":{"labels":{"agent-runtime.dev/resource":"api"}},"status":{"containerStatuses":[{"name":"api","lastState":{"terminated":{"exitCode":137,"reason":"OOMKilled","message":"adversarial termination message"}}},{"name":"sidecar","lastState":{"terminated":{"exitCode":9,"reason":"Error"}}}]}}]}' | api_last_termination)"
  write_safe_diagnostic_summary "fixture-stack" "ar-fixture-stack" 7 "unavailable" 0 false "$fixture_role_status" 2 "$fixture_startup_status" '["image_build","unknown"]' "$fixture_tilt_resource_status" "$fixture_api_termination" "$fixture_tilt_snapshot_state"
  tilt_fixture="$(mktemp "${TMPDIR:-/tmp}/agent-runtime-tilt-classifier.XXXXXX")"
  printf '%s\n' 'Build Failed: MODEL_API_KEY=adversarial-env-secret' >"$tilt_fixture"
  if [[ "$(classify_tilt_ci_failure "$tilt_fixture")" != image_build ]]; then
    echo "Tilt failure classifier did not classify a build failure" >&2
    exit 1
  fi
  printf '%s\n' 'Loading Tiltfile at: /workspace/Tiltfile' >"$tilt_fixture"
  if [[ "$(classify_tilt_ci_failure "$tilt_fixture")" != unknown ]]; then
    echo "Tilt failure classifier treated routine Tiltfile output as a render failure" >&2
    exit 1
  fi
  printf '%s\n' 'Error: Tiltfile execution failed while rendering manifests' >"$tilt_fixture"
  if [[ "$(classify_tilt_ci_failure "$tilt_fixture")" != render ]]; then
    echo "Tilt failure classifier did not classify a render failure" >&2
    exit 1
  fi
  printf '%s\n' 'timed out waiting for resource api to become ready' >"$tilt_fixture"
  if [[ "$(classify_tilt_ci_failure "$tilt_fixture")" != readiness ]]; then
    echo "Tilt failure classifier did not classify a readiness failure" >&2
    exit 1
  fi
  printf '%s\n' 'Error: Tiltfile execution failed while reading readiness_timeout' >"$tilt_fixture"
  if [[ "$(classify_tilt_ci_failure "$tilt_fixture")" != render ]]; then
    echo "Tilt failure classifier treated a render setting as a readiness failure" >&2
    exit 1
  fi
  printf '%s\n' 'ErrImagePull: failed to pull image from the private registry' >"$tilt_fixture"
  if [[ "$(classify_tilt_ci_failure "$tilt_fixture")" != registry_sync ]]; then
    echo "Tilt failure classifier did not classify a private-registry catch-up failure" >&2
    exit 1
  fi
  printf '%s\n' 'unrecognized failure Bearer adversarial-header-token' >"$tilt_fixture"
  if [[ "$(classify_tilt_ci_failure "$tilt_fixture")" != unknown ]]; then
    echo "Tilt failure classifier did not classify an unknown failure" >&2
    exit 1
  fi
  rm -f -- "$tilt_fixture"
  for unsafe_value in 'Bearer adversarial-header-token' 'MODEL_API_KEY=adversarial-env-secret' 'adversarial-json-secret' 'adversarial termination message' 'adversarial-runtime-detail' 'foreign-resource' 'foreign secret'; do
    if grep -F -- "$unsafe_value" "$diagnostics_dir/fixture-stack.summary.json" >/dev/null; then
      echo "safe diagnostic summary retained an unsafe fixture value" >&2
      exit 1
    fi
  done
  capture_plan_failure_diagnostics "preflight-stack" "ar-preflight-stack"
  jq -e '
    .stack == "preflight-stack" and .namespace == "ar-preflight-stack" and
    .tilt_ci_exit_code == 1 and .tilt_ci_attempts == 0 and .tilt_ci_failure_phases == ["render"] and .workload_probe == "unavailable" and
    .runtime_roles_observed == 0 and .runtime_roles_ready == false and
    (.runtime_role_startup_status | length == 8 and all(.[]; (.pods | length) == 0)) and
    (.runtime_role_status | length == 8 and all(.[]; .replicas == 0 and .ready_replicas == 0 and .available_replicas == 0))
  ' "$diagnostics_dir/preflight-stack.summary.json" >/dev/null || {
    echo "preflight diagnostic summary did not retain bounded failed-plan metadata" >&2
    exit 1
  }
  trust_fixture='{"items":[{"metadata":{"labels":{"agent-runtime.dev/resource":"api"}},"spec":{"template":{"spec":{"serviceAccountName":"api-account","automountServiceAccountToken":false,"containers":[{"env":[{"name":"TOKEN","valueFrom":{"secretKeyRef":{"name":"approved","key":"TOKEN"}}}]}],"volumes":[]}}}}]}'
  expected_trust_fixture='{"runtime_roles":[{"id":"api","service_account":"api-account","secret_environment":[{"name":"TOKEN","secret":"approved","key":"TOKEN"}],"secret_mounts":[]}]}'
  jq -e --argjson expected "$expected_trust_fixture" '
    [.items[] | {id:.metadata.labels["agent-runtime.dev/resource"],service_account:.spec.template.spec.serviceAccountName,service_account_token:.spec.template.spec.automountServiceAccountToken,secret_environment:([.spec.template.spec.containers[].env[]? | select(.valueFrom.secretKeyRef != null) | {name,secret:.valueFrom.secretKeyRef.name,key:.valueFrom.secretKeyRef.key}] | sort_by(.name,.secret,.key)),env_from:([.spec.template.spec.containers[].envFrom[]?]),secret_mounts:([.spec.template.spec.volumes[]? | select(.secret != null) | .secret as $secret | $secret.items[]? | {secret:$secret.secretName,key,path}] | sort_by(.secret,.key,.path)),init_containers:(.spec.template.spec.initContainers // [])}] as $observed |
    all($observed[]; (. as $role | $expected.runtime_roles[] | select(.id == $role.id)) as $expected_role | .service_account == $expected_role.service_account and .service_account_token == false and .secret_environment == $expected_role.secret_environment and .secret_mounts == $expected_role.secret_mounts and (.env_from | length == 0) and (.init_containers | length == 0))
  ' <<<"$trust_fixture" >/dev/null || exit 1
  if jq -e --argjson expected "$expected_trust_fixture" '.items[0].spec.template.spec.containers[0].envFrom = [{secretRef:{name:"foreign"}}]' <<<"$trust_fixture" | jq -e --argjson expected "$expected_trust_fixture" '[.items[] | {id:.metadata.labels["agent-runtime.dev/resource"],env_from:([.spec.template.spec.containers[].envFrom[]?])}] | all(.[]; (.env_from | length == 0))' >/dev/null; then
    echo "trust wiring self-test accepted envFrom" >&2
    exit 1
  fi
  jq -e '.runtime_role_startup_status[] | select(.id == "api") | .pods == [{phase:"Pending",ready_containers:0,restart_count:1,state_reasons:["other"]}]' "$diagnostics_dir/fixture-stack.summary.json" >/dev/null || {
    echo "safe diagnostic summary did not replace an unapproved pod state reason" >&2
    exit 1
  }
  jq -e '.kind == "diagnostic-summary/v4" and .version == 4 and .tilt_ci_failure_phases == ["image_build","unknown"] and .tilt_snapshot_state == "observed" and .tilt_resource_status == [{id:"api",build_state:"failed",runtime_state:"unhealthy",update_state:"failed"}] and .api_last_termination == {observed:true,exit_code:137,reason:"OOMKilled"}' "$diagnostics_dir/fixture-stack.summary.json" >/dev/null || {
    echo "safe diagnostic summary did not retain typed Tilt failure phases" >&2
    exit 1
  }
  rm -f -- "$diagnostics_dir/fixture-stack.summary.json" "$diagnostics_dir/preflight-stack.summary.json"
  rmdir -- "$diagnostics_dir"
  echo "safe diagnostic summary rejects raw JSON, header, and environment payloads; trust wiring rejects envFrom"
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
    "$root/.runtime/dev/$stack.bootstrap-capability.json" "$root/.runtime/dev/$stack.operator-audit.jsonl" \
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
  if [[ -e "$root/.runtime/dev/$stack.bootstrap-capability.json" || -e "$root/.runtime/dev/$stack.operator-audit.jsonl" || -e "$root/.runtime/dev/$stack.ci.bootstrap.json" || -e "$root/.runtime/dev/$stack.ci.operator-audit.jsonl" ]]; then
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
	if ! jq -e --arg prefix "agent-runtime-dev/$stack/" --arg registry_host "$ci_registry_host" --arg registry_host_from_cluster "$ci_registry_host_from_cluster" --argjson expected_image_targets '["api","blob-role","codec","egress-proxy","model","orchestration","sandbox-control","sandbox-host","sandbox-host-bootstrap","tool"]' '
		.DefaultRegistry.host == $registry_host and
		.DefaultRegistry.hostFromContainerRuntime == $registry_host_from_cluster and
		.CISettings.readinessTimeout == "12m0s" and
		([.Manifests[]?.ImageTargets[]?.selector] | all(startswith($prefix))) and
		([.Manifests[]?.ImageTargets[]?.selector | ltrimstr($prefix)] | sort) == ($expected_image_targets | sort) and
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
    --arg uid_a "$uid_a" --arg uid_b "$uid_b" \
    --argjson trust_wiring_a "$trust_wiring_a" --argjson trust_wiring_b "$trust_wiring_b" '
    {
      version:2,
      milestone:"M1 local Stack instance isolation",
      proof_level:"isolated_kubernetes_integration",
      utc_time:$utc_time,
      implementation_revision:$revision,
      command:{path:"deploy/dev/run-two-stack-smoke.sh",kubernetes_context:$context,profile:$profile,result:"pending"},
		toolchain:{cluster_runtime:$cluster_runtime,cluster_image:$cluster_image,registry_image:$registry_image,kubectl:$kubectl_version,tilt:$tilt_version},
      stacks:[{name:$stack_a,namespace:$namespace_a,namespace_uid:$uid_a},{name:$stack_b,namespace:$namespace_b,namespace_uid:$uid_b}],
      trust_wiring:[$trust_wiring_a,$trust_wiring_b],
      both_stacks_concurrently_ready:true,
      distinct_namespace_and_workload_identities:true,
		distinct_private_state:true,
		network_policy:{declared_egress_consecutive_successes:3,default_deny_consecutive_failures:3,service_ip_probe:true},
      first_teardown_left_second_unchanged:true,
      cleanup:{namespaces_absent:false,local_state_absent:false},
      limitations:["does not claim Linux KVM or Firecracker isolation","does not mutate a production cluster"]
    }' >"$evidence_temporary"
  if ! jq -e '
    .version == 2 and
    .command.result == "pending" and
    .cleanup.namespaces_absent == false and .cleanup.local_state_absent == false and
    (.trust_wiring | length == 2 and all(.[];
      .version == 1 and
      (.runtime_roles.service_accounts | length == 8) and
      .runtime_roles.service_account_tokens_disabled == true and
      .runtime_roles.secret_environment_scoped == true and
      (.temporal.endpoint == ("temporal." + .namespace + ".svc:7233")) and
      .temporal.namespace == .namespace and
      .temporal.task_queue == (.namespace + "-session-v1") and
      (.temporal.retention_days | type == "number" and . > 0) and
      .dependencies == {state_service_account:"state-account",blob_service_account:"blob-account",telemetry_service_account:"telemetry-account"}
    ))
  ' "$evidence_temporary" >/dev/null; then
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
	if [[ -n "$local_kubeconfig" ]]; then
		rm -f -- "$local_kubeconfig"
	fi
  trap - EXIT
  exit "$original_status"
}
trap cleanup EXIT

# The local reconciler refuses ambient credentials.  Create one private,
# context-scoped kubeconfig for its short-lived state record so the same
# identity used by this smoke script is carried into stackctl.  The EXIT trap
# removes it along with both contained Stack namespaces.
if [[ "$profile" == "local" ]]; then
	local_kubeconfig="$(mktemp "${TMPDIR:-/tmp}/agent-runtime-two-stack-kubeconfig.XXXXXX")"
	chmod 600 "$local_kubeconfig"
	kubectl config view --raw -o json | jq --arg context "$context" '
		.contexts |= map(select(.name == $context)) |
		.contexts[0] as $selected |
		.clusters |= map(select(.name == $selected.context.cluster)) |
		.users |= map(select(.name == $selected.context.user)) |
		."current-context" = $context
	' >"$local_kubeconfig"
	jq -e --arg context "$context" '
		.contexts | length == 1 and .[0].name == $context
	' "$local_kubeconfig" >/dev/null || {
		echo "failed to create a context-scoped local kubeconfig" >&2
		exit 1
	}
fi

capture_stack_diagnostics() {
  local stack="$1"
  local namespace="$2"
  local ci_status="$3"
  local tilt_ci_attempts="$4"
  local tilt_ci_failure_phases="$5"
  local tilt_resource_status="$6"
  local tilt_snapshot_state="$7"
  local probe_status="unavailable"
  local roles_observed=0
  local roles_ready=false
  local role_status
  local startup_status
  local api_termination
  local deployment_state
  local pod_state

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
  if pod_state="$(kubectl --context "$context" --namespace "$namespace" get pods -l "app.kubernetes.io/part-of=agent-runtime,agent-runtime.dev/profile=$profile,agent-runtime.dev/stack=$stack" -o json 2>/dev/null)"; then
    startup_status="$(printf '%s' "$pod_state" | runtime_role_startup_status)"
    api_termination="$(printf '%s' "$pod_state" | api_last_termination)"
  else
    startup_status="$(empty_runtime_role_startup_status)"
    api_termination='{"observed":false,"exit_code":0,"reason":"not_observed"}'
  fi
  write_safe_diagnostic_summary "$stack" "$namespace" "$ci_status" "$probe_status" "$roles_observed" "$roles_ready" "$role_status" "$tilt_ci_attempts" "$startup_status" "$tilt_ci_failure_phases" "$tilt_resource_status" "$api_termination" "$tilt_snapshot_state"
}

start_stack() {
  local stack="$1"
  local namespace="$2"
  local ci_status=0
  local tilt_ci_attempts=0
  local tilt_ci_failure_phases='[]'
  local tilt_resource_status='[]'
  local tilt_snapshot_state='unavailable'
  local tilt_ci_attempt
  local tilt_ci_failure_phase
  if [[ "$profile" == "ci" ]]; then
    # Bootstrap is deliberately outside the Tiltfile: plan rendering must be
    # side-effect free, and stackctl must create the Namespace before Tilt can
    # apply the same reviewed topology.
    deploy/dev/bootstrap-ci-stack.sh --stack="$stack" --context="$context" >/dev/null 2>&1 || ci_status=$?
	else
		go run ./tools/dev prepare --stack="$stack" --root=. --kubeconfig="$local_kubeconfig" --actor=two-stack-smoke >/dev/null 2>&1 || ci_status=$?
		if [[ "$ci_status" == 0 ]]; then
			go run ./tools/dev bootstrap --stack="$stack" --root=. >/dev/null 2>&1 || ci_status=$?
		fi
  fi
  if [[ "$ci_status" != 0 ]]; then
    tilt_ci_failure_phases='["bootstrap"]'
  fi
  # Do not retain Tilt output: it may contain workload environment or headers.
  # The allowlisted summary below records only bounded readiness metadata.
  if [[ "$ci_status" == 0 ]]; then
    tilt_ci_attempts=1
    if ! tilt_ci_attempt="$(run_tilt_ci_attempt "$stack" "$namespace")"; then
      ci_status=1
      tilt_ci_failure_phase="$(jq -er '.phase' <<<"$tilt_ci_attempt")"
      tilt_resource_status="$(jq -ec '.resource_status' <<<"$tilt_ci_attempt")"
      tilt_snapshot_state="$(jq -er '.snapshot_state' <<<"$tilt_ci_attempt")"
      tilt_ci_failure_phases="$(jq -nc --arg phase "$tilt_ci_failure_phase" '[ $phase ]')"
    else
      tilt_resource_status="$(jq -ec '.resource_status' <<<"$tilt_ci_attempt")"
      tilt_snapshot_state="$(jq -er '.snapshot_state' <<<"$tilt_ci_attempt")"
    fi
    # A disposable k3d node can transiently reject a just-built image while
    # its local registry catch-up completes. Only that classified condition
    # may retry: retrying render, apply, or readiness failures could conceal a
    # broken reviewed topology. Keep the first failure token even if retry
    # succeeds so retained diagnostics show the exact execution history.
    if [[ "$ci_status" != 0 && "$profile" == "ci" && "$tilt_ci_failure_phase" == "registry_sync" ]]; then
      ci_status=0
      tilt_ci_attempts=2
      sleep 5
      if ! tilt_ci_attempt="$(run_tilt_ci_attempt "$stack" "$namespace")"; then
        ci_status=1
        tilt_ci_failure_phase="$(jq -er '.phase' <<<"$tilt_ci_attempt")"
        tilt_resource_status="$(jq -ec '.resource_status' <<<"$tilt_ci_attempt")"
        tilt_snapshot_state="$(jq -er '.snapshot_state' <<<"$tilt_ci_attempt")"
        tilt_ci_failure_phases="$(jq -c --arg phase "$tilt_ci_failure_phase" '. + [ $phase ]' <<<"$tilt_ci_failure_phases")"
      else
        tilt_resource_status="$(jq -ec '.resource_status' <<<"$tilt_ci_attempt")"
        tilt_snapshot_state="$(jq -er '.snapshot_state' <<<"$tilt_ci_attempt")"
      fi
    fi
  fi
  capture_stack_diagnostics "$stack" "$namespace" "$ci_status" "$tilt_ci_attempts" "$tilt_ci_failure_phases" "$tilt_resource_status" "$tilt_snapshot_state"
  if [[ "$ci_status" != 0 ]]; then
    return "$ci_status"
  fi
}

created_a=true
start_stack "$stack_a" "$namespace_a"
created_b=true
start_stack "$stack_b" "$namespace_b"
trust_wiring_a="$(observe_stack_trust_wiring "$stack_a" "$namespace_a")"
trust_wiring_b="$(observe_stack_trust_wiring "$stack_b" "$namespace_b")"

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
