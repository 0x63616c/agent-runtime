#!/usr/bin/env bash
# Runs the explicit disposable self-hosted proof through the audited Stack
# operator. It never deletes or relabels a namespace that existed before this run.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

role_pod_manifest() {
  local name="$1"
  local image="$2"
  local account="$3"
  local role="$4"
  local foreign="$5"
  local environment="$6"
  jq -n \
    --arg name "$name" --arg image "$image" --arg account "$account" \
    --arg role "$role" --arg foreign "$foreign" --argjson environment "$environment" \
    '{apiVersion:"v1",kind:"Pod",metadata:{name:$name},spec:{restartPolicy:"Never",serviceAccountName:$account,automountServiceAccountToken:false,containers:[{name:"runtime",image:$image,imagePullPolicy:"Never",command:["/runtime"],args:["serve","--config-env","RUNTIME_ROLE_CONFIG","--role",$role,"--check"],env:($environment + (if $foreign == "" then [] else [{name:$foreign,value:"synthetic-negative"}] end)),resources:{requests:{cpu:"100m",memory:"128Mi"},limits:{cpu:"500m",memory:"512Mi"}}}]}}'
}

self_test_role_pod_constructor() {
  fixture_environment='[{"name":"RUNTIME_ROLE_CONFIG","value":"fixture"},{"name":"MODEL_API_KEY","valueFrom":{"secretKeyRef":{"name":"fixture-model","key":"MODEL_API_KEY"}}}]'
  role_pod_manifest fixture-negative fixture.invalid/runtime fixture-account api STATE_DATABASE_DSN "$fixture_environment" |
    jq -e '
      .kind == "Pod" and .metadata.name == "fixture-negative" and
      .spec.serviceAccountName == "fixture-account" and .spec.automountServiceAccountToken == false and
      (.spec.containers | length) == 1 and
      .spec.containers[0].imagePullPolicy == "Never" and
      .spec.containers[0].args == ["serve","--config-env","RUNTIME_ROLE_CONFIG","--role","api","--check"] and
      (.spec.containers[0].env | length) == 3 and
      .spec.containers[0].env[1].valueFrom.secretKeyRef.name == "fixture-model" and
      .spec.containers[0].env[2] == {name:"STATE_DATABASE_DSN",value:"synthetic-negative"}
    ' >/dev/null
  role_pod_manifest fixture-positive fixture.invalid/runtime fixture-account model "" "$fixture_environment" |
    jq -e '.spec.containers[0].env | length == 2' >/dev/null
}

if [[ "${1:-}" == "--self-test-negative-pod-constructor" ]]; then
  command -v jq >/dev/null || {
    echo "jq is required for Pod constructor self-test" >&2
    exit 1
  }
  self_test_role_pod_constructor
  echo "role Pod constructor preserves allowed references and appends exactly one foreign key only for negative cases"
  exit 0
fi

stack_file="$root/deploy/production/stack.json"
stack_name="agent-runtime"
profile="local"
namespace="ar-agent-runtime"
kubeconfig="${AGENT_RUNTIME_SMOKE_KUBECONFIG:?set an explicit absolute kubeconfig path}"
context="${AGENT_RUNTIME_SMOKE_CONTEXT:?set an explicit Kubernetes context}"
audit_file="${AGENT_RUNTIME_SMOKE_AUDIT:?set an explicit absolute audit file path}"
evidence_file="${AGENT_RUNTIME_SMOKE_EVIDENCE:?set an explicit absolute evidence file path}"
role_smoke_image="${AGENT_RUNTIME_SMOKE_ROLE_IMAGE:-agent-runtime-role-smoke:kubernetes-local}"

if [[ "$kubeconfig" != /* || "$audit_file" != /* || "$evidence_file" != /* ]]; then
  echo "smoke kubeconfig, audit, and evidence file paths must be absolute" >&2
  exit 1
fi
for executable in docker git jq kubectl openssl shasum; do
  command -v "$executable" >/dev/null || {
    echo "required smoke executable is unavailable: $executable" >&2
    exit 1
  }
done
self_test_role_pod_constructor
implementation_revision="$(git rev-parse HEAD)"
docker build \
  --file "$root/deploy/production/Dockerfile" \
  --label "agent-runtime.dev/revision=$implementation_revision" \
  --tag "$role_smoke_image" "$root" >/dev/null
role_smoke_image_id="$(docker image inspect "$role_smoke_image" --format '{{.Id}}')"
role_smoke_revision="$(docker image inspect "$role_smoke_image" --format '{{index .Config.Labels "agent-runtime.dev/revision"}}')"
if [[ "$role_smoke_image_id" != sha256:* || "$role_smoke_revision" != "$implementation_revision" ]]; then
  echo "current-revision role smoke image identity or revision label differs" >&2
  exit 1
fi
echo "current role smoke image $role_smoke_image_id is labelled with revision $implementation_revision"

secret_dir="$(mktemp -d)"
bootstrap_capability_file="${audit_file}.bootstrap-capability.json"
bootstrap_complete=false
apply_complete=false

operator_arguments=(
  --stack-file "$stack_file"
  --stack "$stack_name"
  --profile "$profile"
  --kubeconfig "$kubeconfig"
  --context "$context"
  --actor issue-14-smoke
  --audit-file "$audit_file"
  --migration-root "$root/deploy/production"
)

cleanup() {
  local original_status=$?
  local cleanup_status=0
  set +e
  if [[ "$apply_complete" == true ]]; then
    go run "$root/cmd/stackctl" teardown "${operator_arguments[@]}" >/dev/null
    cleanup_status=$?
    if [[ $cleanup_status -ne 0 ]]; then
      echo "audited teardown refused cleanup; retained $namespace for inspection" >&2
    fi
  elif [[ "$bootstrap_complete" == true ]]; then
    echo "full desired state was not observed; retained $namespace and $bootstrap_capability_file for inspection" >&2
  fi
  rm -rf -- "$secret_dir"
  trap - EXIT
  if [[ $original_status -ne 0 ]]; then
    exit "$original_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

# Preflight selects this exact kubeconfig/context. Bootstrap then uses create,
# not apply, so a race or any pre-existing namespace fails without takeover.
go run "$root/cmd/stackctl" preflight \
  --stack-file "$stack_file" --profile "$profile" \
  --kubeconfig "$kubeconfig" --context "$context" >/dev/null
bootstrap_result="$(go run "$root/cmd/stackctl" bootstrap "${operator_arguments[@]}" --bootstrap-capability-file "$bootstrap_capability_file")"
bootstrap_complete=true
bootstrap_uid="$(printf '%s' "$bootstrap_result" | jq -er '.uid')"
render_digest="$(printf '%s' "$bootstrap_result" | jq -er '.render_digest')"
operator_arguments+=(--bootstrap-capability-file "$bootstrap_capability_file")

rendered="$(go run "$root/cmd/stackctl" render --stack-file "$stack_file" --profile "$profile")"
while IFS=$'\t' read -r secret_name secret_key; do
  directory="$secret_dir/$secret_name"
  mkdir -p "$directory"
  openssl rand -hex 32 | tr -d '\n' >"$directory/$secret_key"
  chmod 600 "$directory/$secret_key"
done < <(printf '%s' "$rendered" | jq -r '
  .resources[] |
  select(.kind == "secret_reference" and .secret_reference.provider == "local-generated") |
  .secret_reference.reference as $name |
  .secret_reference.keys[] |
  [$name, .] | @tsv
')

secret_reference() {
  printf '%s' "$rendered" | jq -er --arg id "$1" '.resources[] | select(.id == $id) | .secret_reference.reference'
}
state_secret="$(secret_reference state-db-secret)"
temporal_database_secret="$(secret_reference temporal-db-secret)"
sandbox_state_secret="$(secret_reference sandbox-state-secret)"
state_password="$(<"$secret_dir/$state_secret/POSTGRES_PASSWORD")"
printf 'postgres://postgres:%s@state:5432/agent_runtime?sslmode=disable' "$state_password" >"$secret_dir/$state_secret/STATE_DATABASE_DSN"
printf 'postgres://postgres:%s@state:5432/agent_runtime?sslmode=disable' "$state_password" >"$secret_dir/$sandbox_state_secret/SANDBOX_STATE_DSN"
chmod 600 "$secret_dir/$state_secret/STATE_DATABASE_DSN" "$secret_dir/$sandbox_state_secret/SANDBOX_STATE_DSN"
test -s "$secret_dir/$temporal_database_secret/POSTGRES_PASSWORD"

# This is the declared local-generated external Secret controller. Secret
# values flow through stdin from mode-0600 files; no value enters argv or logs.
for directory in "$secret_dir"/*; do
  secret_name="$(basename "$directory")"
  from_files=()
  for secret_file in "$directory"/*; do
    from_files+=("--from-file=$(basename "$secret_file")=$secret_file")
  done
  kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
    create secret generic "$secret_name" "${from_files[@]}" --dry-run=client -o json |
    jq \
      --arg uid "$bootstrap_uid" \
      --arg digest "$render_digest" \
      '.metadata.labels = {
        "app.kubernetes.io/part-of":"agent-runtime",
        "agent-runtime.dev/stack":"agent-runtime",
        "agent-runtime.dev/profile":"local",
        "agent-runtime.dev/external-controller":"local-generated"
      } | .metadata.annotations = {
        "agent-runtime.dev/bootstrap-uid":$uid,
        "agent-runtime.dev/render-digest":$digest
      }' |
    kubectl --kubeconfig "$kubeconfig" --context "$context" create -f - >/dev/null
done

apply_result="$(go run "$root/cmd/stackctl" apply "${operator_arguments[@]}")"
expected_ids="$(printf '%s' "$rendered" | jq -c '[.resources[] | select(.kind == "kubernetes") | .id] | sort')"
observed_ids="$(printf '%s' "$apply_result" | jq -c '.ObjectIDs | sort')"
if [[ "$observed_ids" != "$expected_ids" ]]; then
  echo "observed Kubernetes resource IDs do not exactly match desired state" >&2
  exit 1
fi
apply_complete=true
echo "all declared Kubernetes and provider resource IDs were reconciled exactly"

manifests="$(go run "$root/cmd/stackctl" manifests --stack-file "$stack_file" --profile "$profile")"
deployments="$(printf '%s' "$manifests" | jq -r '.items[] | select(.kind == "Deployment") | .metadata.name')"
deployment_count="$(printf '%s' "$manifests" | jq '[.items[] | select(.kind == "Deployment")] | length')"
while IFS= read -r deployment; do
  [[ -n "$deployment" ]] || continue
  kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
    rollout status "deployment/$deployment" --timeout=120s >/dev/null
done <<<"$deployments"
echo "all $deployment_count declared Deployments are Ready"

expected_pods="$(printf '%s' "$manifests" | jq '[.items[] | select(.kind == "Deployment") | (.spec.replicas // 1)] | add')"
kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" get pods \
  -l 'app.kubernetes.io/part-of=agent-runtime,agent-runtime.dev/stack=agent-runtime,agent-runtime.dev/profile=local' -o json |
  jq -e --argjson expected "$expected_pods" '
    (.items | length) == $expected and
    all(.items[]; .status.phase == "Running" and ([.status.containerStatuses[]?.ready] | all))
  ' >/dev/null
echo "all $expected_pods expected pods are Running and Ready"

runtime_roles='["api","orchestration","model","tool","blob-role","codec","sandbox-control","sandbox-host"]'
printf '%s' "$manifests" | jq -e --argjson roles "$runtime_roles" '
  [.items[] | select(.kind == "Deployment") | .metadata.labels["agent-runtime.dev/resource"]] as $deployments |
  all($roles[]; . as $role | $deployments | index($role) != null)
' >/dev/null
for role in api orchestration model tool blob-role codec sandbox-control sandbox-host; do
  kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
    get "deployment/$role" -o json | jq -e '.status.readyReplicas == .spec.replicas' >/dev/null
done
echo "all 8 independently configured runtime roles are Ready"

# Prove the M1 dependency address is not merely schema-consistent: a Job with
# the tool role's exact egress labels must reach the declared HTTP Service on
# 8086. The later M3 private TLS protocol remains a separate 9443 endpoint.
connectivity_image="$(printf '%s' "$manifests" | jq -cer '
  .items[] | select(.kind == "Deployment" and .metadata.name == "telemetry") |
  .spec.template.spec.containers[0].image
')"
jq -n \
  --arg image "$connectivity_image" --arg stack "$stack_name" --arg profile "$profile" \
  '{apiVersion:"batch/v1",kind:"Job",metadata:{name:"sandbox-control-connectivity"},spec:{backoffLimit:0,activeDeadlineSeconds:60,template:{metadata:{labels:{"app.kubernetes.io/part-of":"agent-runtime","agent-runtime.dev/stack":$stack,"agent-runtime.dev/profile":$profile,"agent-runtime.dev/resource":"tool"}},spec:{restartPolicy:"Never",serviceAccountName:"tool-account",automountServiceAccountToken:false,containers:[{name:"probe",image:$image,command:["/bin/sh","-c"],args:["wget -qO- http://sandbox-control:8086/readyz"],resources:{requests:{cpu:"25m",memory:"32Mi"},limits:{cpu:"100m",memory:"128Mi"}}}]}}}}' |
  kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" create -f - >/dev/null
kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
  wait --for=condition=complete job/sandbox-control-connectivity --timeout=60s >/dev/null
connectivity_output="$(kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" logs job/sandbox-control-connectivity 2>&1)"
if [[ "$connectivity_output" != *'"role":"sandbox-control"'* || "$connectivity_output" != *'"status":"ready"'* ]]; then
  echo "tool-labelled dependency probe did not reach sandbox-control over declared HTTP port 8086" >&2
  exit 1
fi
kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
  delete job/sandbox-control-connectivity --wait=true >/dev/null
echo "tool dependency reached sandbox-control over the declared M1 HTTP port 8086"

# Existing role Pods prove their declared credentials work. Compare the live
# credential-key inventory to the reviewed manifest without reading values.
# Then start one disposable negative Pod for every role/foreign-known-key pair.
# Each negative Pod retains the role's allowed credentials so only the foreign
# credential can cause the expected composition-boundary rejection.
known_credentials="$(printf '%s' "$manifests" | jq -r --argjson roles "$runtime_roles" '
  [.items[] | select(.kind == "Deployment" and (.metadata.labels["agent-runtime.dev/resource"] as $id | $roles | index($id) != null)) |
   .spec.template.spec.containers[0].env[]? |
   select(.valueFrom.secretKeyRef != null) | .name] | unique | .[]
')"
negative_count=0
positive_count=0
for role in api orchestration model tool blob-role codec sandbox-control sandbox-host; do
  expected_credentials="$(printf '%s' "$manifests" | jq -c --arg role "$role" '
    .items[] | select(.kind == "Deployment" and .metadata.name == $role) |
    [.spec.template.spec.containers[0].env[]? | select(.valueFrom.secretKeyRef != null) | .name] | sort
  ')"
  actual_credentials="$(kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
    get "deployment/$role" -o json | jq -c '
      [.spec.template.spec.containers[0].env[]? | select(.valueFrom.secretKeyRef != null) | .name] | sort
    ')"
  if [[ "$actual_credentials" != "$expected_credentials" ]]; then
    echo "live credential-key inventory differs for $role" >&2
    exit 1
  fi

  runtime_role="${role/blob-role/blob}"
  allowed_environment="$(printf '%s' "$manifests" | jq -cer --arg role "$role" '
    .items[] | select(.kind == "Deployment" and .metadata.name == $role) |
    .spec.template.spec.containers[0].env
  ')"
  service_account="$(printf '%s' "$manifests" | jq -cer --arg role "$role" '
    .items[] | select(.kind == "Deployment" and .metadata.name == $role) |
    .spec.template.spec.serviceAccountName
  ')"
  positive_pod="credential-positive-$role"
  role_pod_manifest "$positive_pod" "$role_smoke_image" "$service_account" "$runtime_role" "" "$allowed_environment" |
    kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" create -f - >/dev/null
  kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
    wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$positive_pod" --timeout=60s >/dev/null
  positive_output="$(kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" logs "pod/$positive_pod" 2>&1)"
  if [[ -n "$positive_output" ]]; then
    echo "$role emitted unexpected output while accepting its entitled credentials" >&2
    exit 1
  fi
  kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
    delete "pod/$positive_pod" --wait=true >/dev/null
  positive_count=$((positive_count + 1))
  while IFS= read -r foreign_credential; do
    [[ -n "$foreign_credential" ]] || continue
    if printf '%s' "$expected_credentials" | jq -e --arg foreign "$foreign_credential" 'index($foreign) != null' >/dev/null; then
      continue
    fi
    negative_count=$((negative_count + 1))
    negative_pod="credential-negative-$role-$negative_count"
    role_pod_manifest "$negative_pod" "$role_smoke_image" "$service_account" "$runtime_role" "$foreign_credential" "$allowed_environment" |
      kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" create -f - >/dev/null
    kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
      wait --for=jsonpath='{.status.phase}'=Failed "pod/$negative_pod" --timeout=60s >/dev/null
    negative_output="$(kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" logs "pod/$negative_pod" 2>&1)"
    expected_rejection="prepare runtime role: known credential $foreign_credential is not entitled to role $runtime_role"
    if [[ "$negative_output" != *"$expected_rejection"* ]]; then
      echo "$role rejected $foreign_credential, but not at the credential entitlement boundary" >&2
      exit 1
    fi
    if [[ "$negative_output" == *"synthetic-negative"* ]]; then
      echo "$role leaked credential material while rejecting $foreign_credential" >&2
      exit 1
    fi
    kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
      delete "pod/$negative_pod" --wait=true >/dev/null
  done <<<"$known_credentials"
done
if [[ "$negative_count" -ne 76 ]]; then
  echo "credential rejection matrix executed $negative_count Pods, want 76" >&2
  exit 1
fi
if [[ "$positive_count" -ne 8 ]]; then
  echo "credential allowed-path matrix executed $positive_count Pods, want 8" >&2
  exit 1
fi
echo "all live role credential inventories matched and all $negative_count foreign-credential Pods were rejected"

temporal_namespace="$(printf '%s' "$rendered" | jq -er '.resources[] | select(.kind == "orchestration") | .orchestration.namespace')"
retention_days="$(printf '%s' "$rendered" | jq -er '.resources[] | select(.kind == "orchestration") | .orchestration.retention_days')"
expected_retention_seconds=$((retention_days * 24 * 60 * 60))
kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" exec deploy/temporal -- \
  temporal --address 127.0.0.1:7233 --command-timeout 30s --output json \
  operator namespace describe --namespace "$temporal_namespace" |
  jq -e --arg expected "${expected_retention_seconds}s" '.config.workflowExecutionRetentionTtl == $expected' >/dev/null
echo "Temporal namespace retention matches the declared $retention_days days"

temporal_databases="$(kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
  exec deploy/temporal-state -- psql -At -U temporal -d temporal -c \
  "SELECT datname FROM pg_database WHERE datname IN ('temporal','temporal_visibility') ORDER BY datname")"
if [[ "$temporal_databases" != $'temporal\ntemporal_visibility' ]]; then
  echo "Temporal primary and visibility databases do not match desired state" >&2
  exit 1
fi
echo "Temporal primary and visibility databases are separately present"

blob_bucket="$(printf '%s' "$rendered" | jq -er '.resources[] | select(.kind == "blob") | .blob.bucket')"
blob_prefix="$(printf '%s' "$rendered" | jq -er '.resources[] | select(.kind == "blob") | .blob.prefix')"
# shellcheck disable=SC2016 # Positional and credential variables expand only inside the reconciler pod.
blob_value="$(kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" exec deploy/blob-reconciler -- \
  /bin/sh -c 'set -eu; mc alias set declared "$3" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null; printf smoke | mc pipe "declared/$1/$2/proof" >/dev/null; mc cat "declared/$1/$2/proof"; mc rm "declared/$1/$2/proof" >/dev/null' \
  smoke-blob "$blob_bucket" "$blob_prefix" http://blob:9000)"
if [[ "$blob_value" != "smoke" ]]; then
  echo "declared blob round trip returned unexpected content" >&2
  exit 1
fi
echo "declared blob prefix write/read/delete round trip succeeded"

# The provider marker must be the only retained object beneath the exact
# declared prefix after the round trip.
blob_inventory="$(kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" exec deploy/blob-reconciler -- \
  /bin/sh -c 'set -eu; mc alias set declared "$3" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null; mc find "declared/$1/$2" --name "*"' \
  smoke-blob "$blob_bucket" "$blob_prefix" http://blob:9000)"
if [[ "$blob_inventory" != *"/$blob_prefix/.agent-runtime-prefix" || "$(printf '%s\n' "$blob_inventory" | sed '/^$/d' | wc -l | tr -d ' ')" != "1" ]]; then
  echo "declared blob prefix contains an undeclared object" >&2
  exit 1
fi
echo "declared blob prefix contains only its provider marker"

secret_count=0
while IFS=$'\t' read -r resource_id secret_name expected_keys; do
  secret_count=$((secret_count + 1))
  kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" get "Secret/$secret_name" -o json |
    jq -e \
      --arg uid "$bootstrap_uid" \
      --arg digest "$render_digest" \
      --arg stack "$stack_name" \
      --arg profile "$profile" \
      --arg keys "$expected_keys" '
        (.metadata.uid | length) > 0 and
        .metadata.labels == {
          "app.kubernetes.io/part-of":"agent-runtime",
          "agent-runtime.dev/stack":$stack,
          "agent-runtime.dev/profile":$profile,
          "agent-runtime.dev/external-controller":"local-generated"
        } and
        .metadata.annotations == {
          "agent-runtime.dev/bootstrap-uid":$uid,
          "agent-runtime.dev/render-digest":$digest
        } and
        ((.data | keys | sort | join(",")) == $keys)
      ' >/dev/null || {
        echo "generated Secret identity differs for $resource_id" >&2
        exit 1
      }
done < <(printf '%s' "$rendered" | jq -r '
  .resources[] |
  select(.kind == "secret_reference" and .secret_reference.provider == "local-generated") |
  [.id, .secret_reference.reference, (.secret_reference.keys | sort | join(","))] | @tsv
')
echo "all $secret_count generated Secret references match exact identity and key inventories"

telemetry_retention_days="$(printf '%s' "$rendered" | jq -er '.resources[] | select(.kind == "telemetry") | .telemetry.retention_days')"
expected_telemetry_ttl="$((telemetry_retention_days * 24))h"
actual_telemetry_ttl="$(kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
  get deployment/telemetry -o json | jq -er '.spec.template.spec.containers[0].env[] | select(.name == "BADGER_SPAN_STORE_TTL") | .value')"
if [[ "$actual_telemetry_ttl" != "$expected_telemetry_ttl" ]]; then
  echo "live telemetry TTL differs from desired state" >&2
  exit 1
fi
trace_id="11111111111111111111111111111111"
span_id="2222222222222222"
start_time="$(( $(date +%s) * 1000000000 ))"
end_time="$((start_time + 1000000))"
otlp_payload="$(jq -cn --arg trace "$trace_id" --arg span "$span_id" --arg start "$start_time" --arg end "$end_time" '{resourceSpans:[{resource:{attributes:[{key:"service.name",value:{stringValue:"agent-runtime-m1-smoke"}}]},scopeSpans:[{scope:{name:"m1-smoke"},spans:[{traceId:$trace,spanId:$span,name:"m1-export-proof",kind:1,startTimeUnixNano:$start,endTimeUnixNano:$end,status:{code:1}}]}]}]}')"
kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" exec deploy/telemetry -- \
  wget -qO- --header='Content-Type: application/json' --post-data="$otlp_payload" http://127.0.0.1:4318/v1/traces >/dev/null
telemetry_exported=false
for _ in $(seq 1 20); do
  if kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" exec deploy/telemetry -- \
    wget -qO- "http://127.0.0.1:16686/api/traces/$trace_id" 2>/dev/null |
    jq -e --arg trace "$trace_id" '.data | any(.traceID == $trace)' >/dev/null; then
    telemetry_exported=true
    break
  fi
  sleep 1
done
if [[ "$telemetry_exported" != true ]]; then
  echo "OTLP telemetry export was not queryable from the declared collector" >&2
  exit 1
fi
echo "telemetry TTL and OTLP export/query path are live"

reconcile_result="$(go run "$root/cmd/stackctl" reconcile "${operator_arguments[@]}")"
printf '%s' "$reconcile_result" | jq -e '.Applied == false and (.Changes | length) == 0' >/dev/null
echo "audited reconcile verified all providers with zero Kubernetes drift"

go run "$root/cmd/stackctl" teardown "${operator_arguments[@]}" >/dev/null
apply_complete=false
bootstrap_complete=false
kubectl --kubeconfig "$kubeconfig" --context "$context" wait --for=delete "namespace/$namespace" --timeout=120s >/dev/null
if [[ -n "$(kubectl --kubeconfig "$kubeconfig" --context "$context" get namespace "$namespace" --ignore-not-found -o name)" ]]; then
  echo "audited teardown left the disposable Namespace present" >&2
  exit 1
fi
residual_count="$(kubectl --kubeconfig "$kubeconfig" --context "$context" get \
  deployments,statefulsets,jobs,services,ingresses,serviceaccounts,roles,rolebindings,networkpolicies,persistentvolumeclaims,configmaps,resourcequotas,secrets \
  --all-namespaces -l "app.kubernetes.io/part-of=agent-runtime,agent-runtime.dev/stack=$stack_name,agent-runtime.dev/profile=$profile" -o json |
  jq '.items | length')"
if [[ "$residual_count" != "0" ]]; then
  echo "audited teardown left labelled resources" >&2
  exit 1
fi

audit_summary="$(jq -sc '
  (map(select(.action == "bootstrap" and .result == "bootstrapped")) | length) == 1 and
  (map(select(.action == "apply" and .result == "applied")) | length) == 1 and
  (map(select(.action == "reconcile" and .result == "reconciled")) | length) == 1 and
  (map(select(.action == "teardown" and .result == "torn_down")) | length) == 1
' "$audit_file")"
if [[ "$audit_summary" != "true" ]]; then
  echo "operator audit does not contain the exact successful lifecycle" >&2
  exit 1
fi

audit_digest="sha256:$(shasum -a 256 "$audit_file" | awk '{print $1}')"
declared_provider_count="$(printf '%s' "$rendered" | jq '[.resources[] | select(.kind != "kubernetes")] | length')"
jq -n \
  --arg utc_time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg revision "$implementation_revision" \
  --arg digest "$render_digest" \
  --arg context "$context" \
  --arg audit_digest "$audit_digest" \
  --arg namespace "$namespace" \
  --arg temporal_namespace "$temporal_namespace" \
  --arg temporal_retention "${expected_retention_seconds}s" \
  --arg blob_bucket "$blob_bucket" \
  --arg blob_prefix "$blob_prefix" \
  --arg telemetry_ttl "$actual_telemetry_ttl" \
  --argjson expected_rejections 76 \
  --argjson rejected "$negative_count" \
  --argjson allowed_paths "$positive_count" \
  --argjson kubernetes_resources "$(printf '%s' "$expected_ids" | jq 'length')" \
  --argjson provider_resources "$declared_provider_count" \
  --argjson deployments "$deployment_count" \
  --argjson pods "$expected_pods" \
  --argjson secrets "$secret_count" '
  {
    version:2,
    milestone:"M1 self-hosted roles and deployment",
    proof_level:"local_disposable_kubernetes_integration",
    utc_time:$utc_time,
    implementation_revision:$revision,
    stack:{path:"deploy/production/stack.json",profile:"local",name:"agent-runtime",render_digest:$digest},
    command:{path:"deploy/production/run-kubernetes-smoke.sh",kubernetes_context:$context,result:"passed"},
    operator:{audit_sha256:$audit_digest,bootstrap:true,apply:true,reconcile_zero_kubernetes_drift:true,audited_teardown:true,declared_kubernetes_resources:$kubernetes_resources,declared_provider_resources:$provider_resources},
    runtime:{declared_deployments:$deployments,running_ready_pods:$pods,independent_roles_ready:8},
    credential_matrix:{expected_rejections:$expected_rejections,rejected:$rejected,allowed_paths:$allowed_paths,secret_values_redacted:true},
    secrets:{local_generated_references:$secrets,exact_key_inventory:true,uid_and_containment_labels:true,bootstrap_uid_and_render_digest_binding:true,values_retained:false},
    temporal:{namespace:$temporal_namespace,retention:$temporal_retention,primary_database:"temporal",visibility_database:"temporal_visibility",both_present:true},
    blob:{bucket:$blob_bucket,prefix:$blob_prefix,write_read_delete_round_trip:true,only_provider_marker_remained_before_teardown:true,bucket_removed_by_audited_teardown:true},
    telemetry:{ttl:$telemetry_ttl,otlp_export_query_round_trip:true},
    cleanup:{kubernetes_namespace:$namespace,namespace_absent_after_run:true,labelled_residual_resources:0},
    limitations:[
      "local OrbStack integration is not production-cluster mutation evidence",
      "backup and restore recovery is not proved by this artifact",
      "production egress perimeter and Linux KVM isolation remain separate evidence"
    ]
  }' >"$evidence_file"
echo "audited teardown left zero residual resources; evidence retained at $evidence_file"
