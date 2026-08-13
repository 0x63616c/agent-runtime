#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
compose_file="$repository_root/deploy/sandboxcontrol/postgres/compose.yaml"
migration_root="$repository_root/deploy/sandboxcontrol/migrations"
environment_file=$(mktemp)
project_name="agent-runtime-sandbox-control-$RANDOM-$RANDOM"
image_tag="agent-runtime-sandbox-control-e2e:$RANDOM-$RANDOM"
image_container=""
image_root=""
binary_root=""

cleanup() {
  if [[ -n "$image_container" ]]; then
    docker rm --force "$image_container" >/dev/null 2>&1 || true
  fi
  docker image rm --force "$image_tag" >/dev/null 2>&1 || true
  if [[ -n "$image_root" ]]; then
    rm -rf "$image_root"
  fi
  if [[ -n "$binary_root" ]]; then
    rm -rf "$binary_root"
  fi
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

# Validate the sealed production image carries every daemon selected by the
# Stack. The functional process E2E below remains host-native and race-enabled:
# this runner is also used on macOS, which cannot execute the Linux image
# binaries. Do not mistake the image check for a deployed-cluster or Linux/KVM
# claim.
docker build --file "$repository_root/deploy/production/Dockerfile" --tag "$image_tag" "$repository_root"
image_container=$(docker create "$image_tag")
image_root=$(mktemp -d)
for daemon in sandbox-control sandbox-host sandbox-host-bootstrap; do
  docker cp "$image_container:/$daemon" "$image_root/$daemon"
  test -s "$image_root/$daemon" -a -x "$image_root/$daemon"
done
docker rm "$image_container" >/dev/null
image_container=""
rm -rf "$image_root"
image_root=""
binary_root=$(mktemp -d)
go build -race -o "$binary_root/sandbox-control" ./cmd/sandbox-control
go build -race -o "$binary_root/sandbox-host" ./cmd/sandbox-host
go build -race -o "$binary_root/sandbox-host-bootstrap" ./cmd/sandbox-host-bootstrap
export AR_SANDBOXCONTROL_BINARY="$binary_root/sandbox-control"
export AR_SANDBOXHOST_BINARY="$binary_root/sandbox-host"
export AR_SANDBOXHOST_BOOTSTRAP_BINARY="$binary_root/sandbox-host-bootstrap"
go test -race -tags=integration ./internal/sandboxcontrol
go test -race -tags=integration ./cmd/sandbox-control
go test -race -tags=integration ./cmd/sandbox-host
