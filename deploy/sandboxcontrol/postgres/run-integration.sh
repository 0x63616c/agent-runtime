#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
compose_file="$repository_root/deploy/sandboxcontrol/postgres/compose.yaml"
migration_file="$repository_root/deploy/sandboxcontrol/migrations/v1.up.sql"
environment_file=$(mktemp)
project_name="agent-runtime-sandbox-control-$RANDOM-$RANDOM"

cleanup() {
  docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -f "$environment_file"
}
trap cleanup EXIT

umask 077
printf 'AR_SANDBOXCONTROL_POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 24)" > "$environment_file"
docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" up --detach --wait
docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" exec --no-TTY postgres \
  psql -v ON_ERROR_STOP=1 -U sandbox_control -d agent_runtime < "$migration_file"
port=$(docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" port postgres 5432 | sed 's/.*://')
password=$(awk -F= '/^AR_SANDBOXCONTROL_POSTGRES_PASSWORD=/{print $2}' "$environment_file")
export AR_SANDBOXCONTROL_POSTGRES_DSN="postgres://sandbox_control:${password}@127.0.0.1:${port}/agent_runtime?sslmode=disable"
go test -race -tags=integration ./internal/sandboxcontrol
