#!/usr/bin/env bash
set -euo pipefail

# Builds the reviewed production image and proves each independently deployed
# trust role can start with only its declared fixture credentials. This is a
# container composition smoke, not a claim that Kubernetes or Temporal was
# mutated. It leaves no container behind.

smoke_image="${AGENT_RUNTIME_SMOKE_IMAGE:-agent-runtime-role-smoke:local}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config_root="${repository_root}/deploy/production/role-configs"

docker build --file "${repository_root}/deploy/production/Dockerfile" --tag "${smoke_image}" "${repository_root}"

run_role() {
  local role="$1"
  local config="$2"
  shift 2
  docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
    "$@" \
    -v "${config_root}/${config}:/config/role.json:ro" \
    "${smoke_image}" serve --config /config/role.json --role "${role}" --check
}

run_role api api.json
run_role orchestration orchestration.json -e STATE_DATABASE_DSN=fixture -e TEMPORAL_AUTH_TOKEN=fixture
run_role model model.json -e CONVERSATION_ACCESS_TOKEN=fixture -e MODEL_API_KEY=fixture
run_role tool tool.json -e SANDBOX_CONTROL_TOKEN=fixture -e TOOL_BROKER_TOKEN=fixture
run_role blob blob.json -e BLOB_STORAGE_CREDENTIAL=fixture
run_role codec codec.json -e CODEC_BLOB_CREDENTIAL=fixture
run_role sandbox-control sandbox-control.json -e SANDBOX_HOST_CA=fixture -e SANDBOX_STATE_DSN=fixture
run_role sandbox-host sandbox-host.json -e SANDBOX_HOST_IDENTITY=fixture -e SANDBOX_CONTROL_TOKEN=fixture

docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /egress-proxy "${smoke_image}" \
  --listen 127.0.0.1:8088 --allowed-target model-provider.example.invalid:443 --check
