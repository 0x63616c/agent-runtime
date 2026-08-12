#!/usr/bin/env bash
set -euo pipefail

# Builds the reviewed production image and proves each independently deployed
# trust role can start with only its declared fixture credentials. This is a
# container composition smoke, not a claim that Kubernetes or Temporal was
# mutated. It leaves no container behind.

smoke_image="${AGENT_RUNTIME_SMOKE_IMAGE:-agent-runtime-role-smoke:local}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
role_configs="$(go run "${repository_root}/cmd/stackctl" role-configs --stack-file "${repository_root}/deploy/production/stack.json" --profile production)"
smoke_secret="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
runtime_api_admin_secret="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
runtime_api_developer_secret="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"

export STATE_DATABASE_DSN="${smoke_secret}"
export TEMPORAL_AUTH_TOKEN="${smoke_secret}"
export CONVERSATION_ACCESS_TOKEN="${smoke_secret}"
export MODEL_API_KEY="${smoke_secret}"
export SANDBOX_CONTROL_TOKEN="${smoke_secret}"
export TOOL_BROKER_TOKEN="${smoke_secret}"
export BLOB_STORAGE_CREDENTIAL="${smoke_secret}"
export CODEC_BLOB_CREDENTIAL="${smoke_secret}"
export SANDBOX_HOST_CA="${smoke_secret}"
export SANDBOX_STATE_DSN="${smoke_secret}"
export SANDBOX_HOST_IDENTITY="${smoke_secret}"

docker build --file "${repository_root}/deploy/production/Dockerfile" --tag "${smoke_image}" "${repository_root}"

run_role() {
  local role="$1"
  local config
  config="$(printf '%s' "${role_configs}" | jq -cer --arg role "${role}" '.[$role]')"
  shift
  docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
    "$@" \
    -e RUNTIME_ROLE_CONFIG="${config}" \
    "${smoke_image}" serve --config-env RUNTIME_ROLE_CONFIG --role "${role}" --check
}

run_role api
run_role orchestration -e STATE_DATABASE_DSN -e TEMPORAL_AUTH_TOKEN
run_role model -e CONVERSATION_ACCESS_TOKEN -e MODEL_API_KEY
run_role tool -e SANDBOX_CONTROL_TOKEN -e TOOL_BROKER_TOKEN
run_role blob -e BLOB_STORAGE_CREDENTIAL
run_role codec -e CODEC_BLOB_CREDENTIAL
run_role sandbox-control -e SANDBOX_HOST_CA -e SANDBOX_STATE_DSN
run_role sandbox-host -e SANDBOX_HOST_IDENTITY -e SANDBOX_CONTROL_TOKEN

# The public HTTP server is deliberately not the generic health-only `api`
# role. Its image entrypoint, strict durable configuration, and five declared
# credentials are checked in one least-privilege container invocation.
runtime_api_config="$(jq -cer '.profiles.production.resources[] | select(.id == "runtime-api") | .kubernetes.environment[] | select(.name == "RUNTIME_API_CONFIG") | .value' "${repository_root}/deploy/production/stack.json")"
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e RUNTIME_API_CONFIG="${runtime_api_config}" \
  -e STATE_DATABASE_DSN -e AR_RUNTIME_MINIO_ACCESS_KEY="${smoke_secret}" -e AR_RUNTIME_MINIO_SECRET_KEY="${smoke_secret}" \
  -e RUNTIME_API_ADMIN_TOKEN="${runtime_api_admin_secret}" -e RUNTIME_API_DEVELOPER_TOKEN="${runtime_api_developer_secret}" \
  --entrypoint /agent-runtime-api "${smoke_image}" --config-env RUNTIME_API_CONFIG --check

negative_count=0
run_role_rejecting_foreign_credential() {
  local role="$1"
  local foreign="$2"
  local config
  local output
  local -a allowed_environment=()
  config="$(printf '%s' "${role_configs}" | jq -cer --arg role "${role}" '.[$role]')"
  while IFS= read -r credential; do
    [[ -n "$credential" ]] && allowed_environment+=("-e" "$credential")
  done < <(printf '%s' "${role_configs}" | jq -r --arg role "${role}" '.[$role].dependencies[]?.secret_environment? // empty')
  if output="$(docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
    "${allowed_environment[@]}" \
    -e RUNTIME_ROLE_CONFIG="${config}" \
    -e "${foreign}" \
    "${smoke_image}" serve --config-env RUNTIME_ROLE_CONFIG --role "${role}" --check 2>&1)"; then
    echo "role ${role} admitted foreign known credential ${foreign}" >&2
    exit 1
  fi
  expected="prepare runtime role: known credential ${foreign} is not entitled to role ${role}"
  if [[ "$output" != *"$expected"* ]]; then
    echo "role ${role} rejected ${foreign}, but not at the credential entitlement boundary" >&2
    exit 1
  fi
  if [[ "$output" == *"$smoke_secret"* ]]; then
    echo "role ${role} leaked credential material while rejecting ${foreign}" >&2
    exit 1
  fi
  negative_count=$((negative_count + 1))
}

# The positive starts above prove every entitlement works. For every role, a
# real container receives each known credential outside its entitlement, while
# retaining all allowed credentials so another missing dependency cannot cause
# a false-positive failure. Captured diagnostics are checked but never printed.
for role in api orchestration model tool blob codec sandbox-control sandbox-host; do
  while IFS= read -r foreign; do
    if ! printf '%s' "${role_configs}" | jq -e --arg role "$role" --arg foreign "$foreign" \
      'any(.[$role].dependencies[]?; .secret_environment == $foreign)' >/dev/null; then
      run_role_rejecting_foreign_credential "$role" "$foreign"
    fi
  done < <(printf '%s' "${role_configs}" | jq -r '
    [to_entries[].value.dependencies[]?.secret_environment? | select(type == "string" and length > 0)] | unique | .[]
  ')
done
if [[ "$negative_count" -ne 76 ]]; then
  echo "credential rejection matrix executed $negative_count cases, want 76" >&2
  exit 1
fi
echo "all 76 foreign known credential containers were rejected without secret leakage"

docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /egress-proxy "${smoke_image}" \
  --listen 127.0.0.1:8088 --allowed-target model-provider.example.invalid:443 --check
