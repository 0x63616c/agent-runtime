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

run_role_rejecting_foreign_credential() {
  local role="$1"
  local foreign="$2"
  local config
  config="$(printf '%s' "${role_configs}" | jq -cer --arg role "${role}" '.[$role]')"
  if docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
    -e RUNTIME_ROLE_CONFIG="${config}" \
    -e "${foreign}" \
    "${smoke_image}" serve --config-env RUNTIME_ROLE_CONFIG --role "${role}" --check >/dev/null 2>&1; then
    echo "role ${role} admitted a foreign known credential" >&2
    exit 1
  fi
}

# The positive starts above prove every entitlement works. Each real container
# below receives one other known credential and must fail before listening. The
# value is synthetic and neither it nor container diagnostics are retained.
for role in api orchestration model tool blob codec sandbox-control sandbox-host; do
  foreign=MODEL_API_KEY
  if [[ "$role" == "model" ]]; then
    foreign=STATE_DATABASE_DSN
  fi
  run_role_rejecting_foreign_credential "${role}" "$foreign"
done

docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /egress-proxy "${smoke_image}" \
  --listen 127.0.0.1:8088 --allowed-target model-provider.example.invalid:443 --check
