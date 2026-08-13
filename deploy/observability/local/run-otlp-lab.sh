#!/usr/bin/env bash
# Runs a disposable API -> OTLP collector -> Jaeger/Prometheus lab from the
# checked-in Stack collector configuration. It never contacts Kubernetes or a
# home server, and retains only a redacted lab result when explicitly asked.
set -euo pipefail

report=""
authorized=false
validate_probe_response=""
usage() {
  echo "usage: run-otlp-lab.sh [--report /absolute/new/report.json --execute-authorized-disposable-lab] | [--validate-redaction-probe-response /absolute/jaeger-response.json]" >&2
  exit 2
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report) report="${2:-}"; shift 2 ;;
    --execute-authorized-disposable-lab) authorized=true; shift ;;
    --validate-redaction-probe-response) validate_probe_response="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
if [[ -n "$report" ]]; then
  [[ "$authorized" == true && "$report" == /* && ! -e "$report" && -d "$(dirname "$report")" ]] || usage
elif [[ "$authorized" == true ]]; then
  usage
fi
if [[ -n "$validate_probe_response" && ( -n "$report" || "$authorized" == true || "$validate_probe_response" != /* || ! -f "$validate_probe_response" ) ]]; then
  usage
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
collector_config="$root/deploy/observability/otelcol/collector.yaml"
stack_file="$root/deploy/production/stack.json"
for program in docker jq curl; do command -v "$program" >/dev/null || { echo "OTLP lab requires $program" >&2; exit 1; }; done
[[ -f "$collector_config" && -f "$stack_file" ]] || { echo "OTLP lab inputs are missing" >&2; exit 1; }
# A retained report names this immutable source revision. Recheck before report
# creation so a concurrent checkout cannot be misrepresented as the evidence
# source.
source_revision="$(git -C "$root" rev-parse --verify HEAD)"

verify_evidence_checkout() {
  local expected_revision="$1"
  local branch main_revision current_revision status
  branch="$(git -C "$root" symbolic-ref --quiet --short HEAD)" || { echo "OTLP evidence requires a checkout attached to main" >&2; return 1; }
  [[ "$branch" == "main" ]] || { echo "OTLP evidence requires a checkout attached to main" >&2; return 1; }
  main_revision="$(git -C "$root" rev-parse --verify refs/heads/main)"
  current_revision="$(git -C "$root" rev-parse --verify HEAD)"
  [[ "$current_revision" == "$main_revision" && "$current_revision" == "$expected_revision" ]] || { echo "OTLP evidence requires HEAD to equal refs/heads/main" >&2; return 1; }
  status="$(git -C "$root" status --porcelain --untracked-files=all)"
  [[ -z "$status" ]] || { echo "OTLP evidence requires a clean checkout" >&2; return 1; }
}

if [[ -n "$report" ]]; then
  verify_evidence_checkout "$source_revision"
fi
# Every network observation has a transport deadline. The surrounding bounded
# poll controls total convergence time; an individual unavailable endpoint
# cannot make one iteration hang indefinitely.
curl_timeout=(--connect-timeout 2 --max-time 5)

# The lab asserts and dynamically probes the exact collector redaction contract.
unsafe_attribute_keys=(
  http.request.header.authorization
  http.request.body
  http.response.body
  gen_ai.prompt
  gen_ai.completion
  runtime.model.reasoning
  runtime.tool.output
  process.command_args
)
for key in "${unsafe_attribute_keys[@]}"; do
  grep -F -- "- key: $key" "$collector_config" >/dev/null || { echo "collector redaction contract lacks $key" >&2; exit 1; }
done

validate_collector_redaction_probe() {
  local response="$1"
  jq -e --arg safe "collector-redaction-probe-safe-v1" '[.data[]?.spans[]?.tags[]? | select(.key == "safe.probe" and .value == $safe)] | length > 0' <<<"$response" >/dev/null || { echo "Jaeger trace store did not retain collector redaction safe probe" >&2; return 1; }
  local tag_keys
  tag_keys="$(jq -cer '[.data[]?.spans[]?.tags[]?.key] | unique' <<<"$response")"
  local key
  for key in "${unsafe_attribute_keys[@]}"; do
    jq -e --arg key "$key" 'index($key) | not' <<<"$tag_keys" >/dev/null || { echo "collector forwarded unsafe probe attribute key" >&2; return 1; }
  done
}

if [[ -n "$validate_probe_response" ]]; then
  validate_collector_redaction_probe "$(<"$validate_probe_response")"
  echo "collector redaction probe response passed"
  exit 0
fi

tmp="$(mktemp -d)"
network="agent-runtime-otlp-lab-$RANDOM-$RANDOM"
collector="${network}-collector"
trace_store="${network}-trace-store"
api="${network}-api"
image="agent-runtime-otlp-lab:$RANDOM-$RANDOM"
# This ephemeral client has no access to the host or retained evidence. It
# sends one synthetic span solely to prove the running collector applies its
# checked-in redaction processor before forwarding a trace.
probe_client_image="curlimages/curl:8.12.1"
cleanup() {
  docker rm -f "$api" "$collector" "$trace_store" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

docker network create "$network" >/dev/null
docker run -d --name "$trace_store" --network "$network" --network-alias trace-store -p 127.0.0.1::16686 \
  jaegertracing/all-in-one:1.67.0 >/dev/null
docker run -d --name "$collector" --network "$network" --network-alias otel-collector -p 127.0.0.1::8889 \
  -v "$collector_config:/etc/otelcol-contrib/config.yaml:ro" \
  otel/opentelemetry-collector-contrib:0.121.0 --config=/etc/otelcol-contrib/config.yaml >/dev/null

docker build -f "$root/deploy/production/Dockerfile" -t "$image" "$root" >/dev/null
api_config="$(jq -cer '.profiles.local.resources[] | select(.id == "api") | .kubernetes.environment[] | select(.name == "RUNTIME_API_CONFIG") | (.value | fromjson | .listen_address = "0.0.0.0:8080" | .storage = {mode:"memory-unsafe"} | tojson)' "$stack_file")"
docker run -d --name "$api" --network "$network" -p 127.0.0.1::8080 --entrypoint /agent-runtime-api \
  -e "RUNTIME_API_CONFIG=$api_config" -e RUNTIME_API_DEVELOPER_TOKEN=direct-lab-developer-token \
  -e RUNTIME_API_ADMIN_TOKEN=direct-lab-admin-token -e OBSERVABILITY_CORRELATION_KEY=0123456789abcdef0123456789abcdef \
  "$image" --config-env RUNTIME_API_CONFIG >/dev/null

api_port="$(docker port "$api" 8080/tcp | sed 's/.*://')"
collector_port="$(docker port "$collector" 8889/tcp | sed 's/.*://')"
trace_port="$(docker port "$trace_store" 16686/tcp | sed 's/.*://')"
# The deliberately unknown public route must return its exact safe 400
# response, not a 2xx. Treating curl's --fail result as readiness made this
# lab wait for a response that its own next assertion correctly expects to be
# a 400.
for _ in $(seq 1 60); do
  response="$(curl "${curl_timeout[@]}" -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$api_port/v1/unknown" -H 'Authorization: Bearer direct-lab-developer-token' || true)"
  if [[ "$response" == 400 ]]; then
    break
  fi
  sleep 0.25
done
response="$(curl "${curl_timeout[@]}" -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$api_port/v1/unknown" -H 'Authorization: Bearer direct-lab-developer-token')"
[[ "$response" == 400 ]] || { echo "API request did not reach exact public route" >&2; exit 1; }
docker stop "$api" >/dev/null
for _ in $(seq 1 80); do curl "${curl_timeout[@]}" -fsS "http://127.0.0.1:$collector_port/metrics" | grep -F 'runtime_api_request_completed' >/dev/null && break; sleep 0.25; done
metrics="$(curl "${curl_timeout[@]}" -fsS "http://127.0.0.1:$collector_port/metrics")"
grep -F 'runtime_api_request_completed' <<<"$metrics" >/dev/null || { echo "collector Prometheus exporter did not expose API metric" >&2; exit 1; }
for _ in $(seq 1 80); do curl "${curl_timeout[@]}" -fsS "http://127.0.0.1:$trace_port/api/services" | grep -F 'unknown_service:agent-runtime-api' >/dev/null && break; sleep 0.25; done
services="$(curl "${curl_timeout[@]}" -fsS "http://127.0.0.1:$trace_port/api/services")"
grep -F 'unknown_service:agent-runtime-api' <<<"$services" >/dev/null || { echo "Jaeger trace store did not receive API trace" >&2; exit 1; }

# The API deliberately never emits request bodies or authorization values. A
# direct OTLP probe is therefore required to prove that the *running* collector
# deletes unsafe attributes, rather than merely proving the checked-in YAML
# lists a deletion rule. Both marker values are synthetic and live only in this
# disposable network/process memory; neither is written to the report.
probe_service="agent-runtime-collector-redaction-probe"
safe_probe="collector-redaction-probe-safe-v1"
unsafe_probe="collector-redaction-probe-unsafe-v1"
probe_started_at="$(( $(date +%s) * 1000000000 ))"
probe_ended_at="$(( probe_started_at + 1000000 ))"
probe_payload="$(jq -cn --arg service "$probe_service" --arg safe "$safe_probe" --arg unsafe "$unsafe_probe" --arg start "$probe_started_at" --arg end "$probe_ended_at" '{resourceSpans:[{resource:{attributes:[{key:"service.name",value:{stringValue:$service}}]},scopeSpans:[{scope:{name:"agent-runtime.direct-lab"},spans:[{traceId:"0123456789abcdef0123456789abcdef",spanId:"0123456789abcdef",name:"collector-redaction-probe",kind:1,startTimeUnixNano:$start,endTimeUnixNano:$end,attributes:([{key:"safe.probe",value:{stringValue:$safe}}] + ($ARGS.positional | map({key:.,value:{stringValue:$unsafe}})))}]}]}]}' --args "${unsafe_attribute_keys[@]}")"
docker run --rm --network "$network" "$probe_client_image" --fail --silent --show-error --connect-timeout 2 --max-time 5 \
  -H 'Content-Type: application/json' --data "$probe_payload" http://otel-collector:4318/v1/traces >/dev/null
for _ in $(seq 1 80); do
  probe_trace="$(curl "${curl_timeout[@]}" -fsS --get --data-urlencode "service=$probe_service" --data-urlencode 'limit=20' "http://127.0.0.1:$trace_port/api/traces")"
  validate_collector_redaction_probe "$probe_trace" && break
  sleep 0.25
done
validate_collector_redaction_probe "$probe_trace"

if [[ -n "$report" ]]; then
  verify_evidence_checkout "$source_revision"
  jq -n --arg revision "$source_revision" '{schema_version:"agent-runtime.direct-lab-evidence/v1",proof_level:"direct_authorized_disposable_otlp_lab",result:"passed",environment:"disposable_local_docker_lab",source_revision:$revision,coverage:{api_to_collector:true,collector_to_trace_store:true,collector_prometheus_metrics:true,collector_unsafe_attribute_contract:true,collector_unsafe_attribute_runtime_probe:true},redaction:"No bearer token, request ID, endpoint, container ID, raw trace, metric body, or collector log is retained.",limitations:["This is a disposable Docker lab, not Kubernetes or production evidence.","The collector runtime probe uses synthetic values and verifies all declared unsafe attribute keys are deleted before the trace store; it does not prove production telemetry, deployment, or recovery."]}' >"$report"
  chmod 600 "$report"
  echo "redacted disposable OTLP lab evidence written to $report"
fi
echo "disposable OTLP lab passed; API exported a request trace and metric through the checked-in collector pipeline"
