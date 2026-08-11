#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
compose_file="$repository_root/deploy/sandboxcontrol/postgres/compose.yaml"
migration_root="$repository_root/deploy/sandboxcontrol/migrations"
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
while IFS= read -r migration_file; do
  docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" exec --no-TTY postgres \
    psql -v ON_ERROR_STOP=1 -U sandbox_control -d agent_runtime < "$migration_file"
done < <(find "$migration_root" -maxdepth 1 -type f -name 'v*.up.sql' -print | sort -V)
port=$(docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" port postgres 5432 | sed 's/.*://')
password=$(awk -F= '/^AR_SANDBOXCONTROL_POSTGRES_PASSWORD=/{print $2}' "$environment_file")
export AR_SANDBOXCONTROL_POSTGRES_DSN="postgres://sandbox_control:${password}@127.0.0.1:${port}/agent_runtime?sslmode=disable"
binary_root=$(mktemp -d)
trap 'rm -rf "$binary_root"; cleanup' EXIT
go build -race -o "$binary_root/sandbox-control" ./cmd/sandbox-control
go build -race -o "$binary_root/sandbox-host" ./cmd/sandbox-host
export AR_SANDBOXCONTROL_BINARY="$binary_root/sandbox-control"
export AR_SANDBOXHOST_BINARY="$binary_root/sandbox-host"
go test -race -tags=integration ./internal/sandboxcontrol
go test -race -tags=integration ./cmd/sandbox-control
go test -race -tags=integration ./cmd/sandbox-host
