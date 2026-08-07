#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
compose_file="$repository_root/deploy/temporalpayload/minio/compose.yaml"
environment_file=$(mktemp)
project_name="agent-runtime-payload-$RANDOM-$RANDOM"

cleanup() {
  docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -f "$environment_file"
}
trap cleanup EXIT

umask 077
printf 'AR_MINIO_ROOT_USER=agent-runtime-integration\nAR_MINIO_ROOT_PASSWORD=%s\n' "$(openssl rand -hex 24)" > "$environment_file"
docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" up --detach --wait
port=$(docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" port minio 9000 | sed 's/.*://')
export AR_MINIO_ENDPOINT="127.0.0.1:$port"
export AR_MINIO_ACCESS_KEY=agent-runtime-integration
export AR_MINIO_SECRET_KEY
AR_MINIO_SECRET_KEY=$(awk -F= '/^AR_MINIO_ROOT_PASSWORD=/{print $2}' "$environment_file")
export AR_MINIO_BUCKET=agent-runtime-payloads
export AR_MINIO_CREATE_BUCKET=1
go test -tags=integration ./temporalpayload/s3
