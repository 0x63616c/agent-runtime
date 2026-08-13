#!/usr/bin/env bash
# Runs a disposable API -> OTLP collector -> Jaeger/Prometheus lab from the
# checked-in Stack collector configuration. It never contacts Kubernetes or a
# home server, and retains only a redacted lab result when explicitly asked.
set -euo pipefail

report=""
authorized=false
usage() {
  echo "usage: run-otlp-lab.sh [--report /absolute/new/report.json --execute-authorized-disposable-lab]" >&2
  exit 2
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report) report="${2:-}"; shift 2 ;;
    --execute-authorized-disposable-lab) authorized=true; shift ;;
    *) usage ;;
  esac
done
if [[ -n "$report" ]]; then
  [[ "$authorized" == true && "$report" == /* && ! -e "$report" && -d "$(dirname "$report")" ]] || usage
elif [[ "$authorized" == true ]]; then
  usage
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
collector_config="$root/deploy/observability/otelcol/collector.yaml"
stack_file="$root/deploy/production/stack.json"
for program in docker jq curl; do command -v "$program" >/dev/null || { echo "OTLP lab requires $program" >&2; exit 1; }; done
[[ -f "$collector_config" && -f "$stack_file" ]] || { echo "OTLP lab inputs are missing" >&2; exit 1; }
# Every network observation has a transport deadline. The surrounding bounded
# poll controls total convergence time; an individual unavailable endpoint
# cannot make one iteration hang indefinitely.
curl_timeout=(--connect-timeout 2 --max-time 5)

# The lab asserts the exact collector redaction contract before it starts.
for key in http.request.header.authorization http.request.body http.response.body gen_ai.prompt gen_ai.completion runtime.model.reasoning runtime.tool.output process.command_args; do
  grep -F -- "- key: $key" "$collector_config" >/dev/null || { echo "collector redaction contract lacks $key" >&2; exit 1; }
done

tmp="$(mktemp -d)"
network="agent-runtime-otlp-lab-$RANDOM-$RANDOM"
collector="${network}-collector"
trace_store="${network}-trace-store"
api="${network}-api"
image="agent-runtime-otlp-lab:$RANDOM-$RANDOM"
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

if [[ -n "$report" ]]; then
  jq -n --arg revision "$(git -C "$root" rev-parse HEAD)" '{schema_version:"agent-runtime.direct-lab-evidence/v1",proof_level:"direct_authorized_disposable_otlp_lab",result:"passed",environment:"disposable_local_docker_lab",source_revision:$revision,coverage:{api_to_collector:true,collector_to_trace_store:true,collector_prometheus_metrics:true,collector_unsafe_attribute_contract:true},redaction:"No bearer token, request ID, endpoint, container ID, raw trace, metric body, or collector log is retained.",limitations:["This is a disposable Docker lab, not Kubernetes or production evidence.","Unsafe attributes are verified as checked-in collector processor contract; the API public request telemetry contains no raw authorization or request-body attribute."]}' >"$report"
  chmod 600 "$report"
  echo "redacted disposable OTLP lab evidence written to $report"
fi
echo "disposable OTLP lab passed; API exported a request trace and metric through the checked-in collector pipeline"
