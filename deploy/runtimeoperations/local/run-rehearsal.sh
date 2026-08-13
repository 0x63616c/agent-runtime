#!/usr/bin/env bash
# Runs a disposable local rehearsal of the M5 operations drill. This is not a
# protected run and deliberately creates no evidence artifact.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
compose_file="$repository_root/deploy/runtimeoperations/local/compose.yaml"
migration_root="$repository_root/deploy/production/migrations"
environment_file=$(mktemp)
working_directory=$(mktemp -d)
project_name="agent-runtime-m5-rehearsal-$RANDOM-$RANDOM"
audit_pid=""

cleanup() {
  if [ -n "$audit_pid" ]; then kill "$audit_pid" >/dev/null 2>&1 || true; fi
  docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -f "$environment_file"
  rm -rf "$working_directory"
}
trap cleanup EXIT

umask 077
printf 'AR_M5_LAB_POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 24)" > "$environment_file"
postgres_password=$(awk -F= '/^AR_M5_LAB_POSTGRES_PASSWORD=/{print $2}' "$environment_file")
docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" up --detach --wait

source_port=$(docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" port source 5432 | sed 's/.*://')
restore_port=$(docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" port restore 5432 | sed 's/.*://')
source_dsn="postgres://runtime_lab:${postgres_password}@127.0.0.1:${source_port}/agent_runtime_source?sslmode=disable"
restore_dsn="postgres://runtime_lab:${postgres_password}@127.0.0.1:${restore_port}/agent_runtime_restore?sslmode=disable"

for migration_file in "$migration_root"/runtime-v*.up.sql; do
  docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" exec --no-TTY source \
    psql -v ON_ERROR_STOP=1 -U runtime_lab -d agent_runtime_source < "$migration_file"
done

retention_tenant="m5-local-retention"
pitr_tenant="m5-local-pitr"
retention_authorization="local-rehearsal-retention-authority-0001"
pitr_authorization="local-rehearsal-pitr-authority-00000001"
psql "$source_dsn" --set=ON_ERROR_STOP=1 --command "INSERT INTO runtime.tenants (tenant_id, created_at) VALUES ('$retention_tenant', now()), ('$pitr_tenant', now()); INSERT INTO runtime.runtime_state_snapshots (tenant_id, generation, state, updated_at) VALUES ('$pitr_tenant', 7, '{}', now()); INSERT INTO runtime.tenant_retention_jobs (tenant_id, last_collection_at, next_collection_at, last_authorization_id) VALUES ('$retention_tenant', now() - interval '1 minute', now() + interval '1 day', '$retention_authorization');"

docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" exec --no-TTY restore \
  psql -v ON_ERROR_STOP=1 -U runtime_lab -d agent_runtime_restore --command "CREATE ROLE runtime_state_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; CREATE ROLE runtime_state_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; GRANT runtime_state_app, runtime_state_operator TO runtime_lab;"
docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" exec --no-TTY source \
  pg_dump -U runtime_lab -d agent_runtime_source --format=custom > "$working_directory/source.dump"
docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" exec --no-TTY restore \
  pg_restore -U runtime_lab -d agent_runtime_restore --exit-on-error < "$working_directory/source.dump"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -addext 'subjectAltName=DNS:localhost' \
  -keyout "$working_directory/audit.key" -out "$working_directory/audit.crt" >/dev/null 2>&1
go run "$repository_root/deploy/runtimeoperations/local/audit-sink.go" \
  -certificate "$working_directory/audit.crt" -key "$working_directory/audit.key" -ready-file "$working_directory/audit.address" >"$working_directory/audit.log" 2>&1 &
audit_pid=$!
for _ in $(seq 1 50); do [ -s "$working_directory/audit.address" ] && break; sleep 0.1; done
if [ ! -s "$working_directory/audit.address" ]; then cat "$working_directory/audit.log" >&2; exit 1; fi
audit_address=$(cat "$working_directory/audit.address")

RUNTIME_OPERATIONS_REHEARSAL=local-only \
AR_RUNTIME_OPERATIONS_DATABASE_DSN="$source_dsn" \
AR_RUNTIME_OPERATIONS_PITR_RESTORE_DSN="$restore_dsn" \
AR_RUNTIME_OPERATIONS_AUDIT_SINK_URL="https://localhost:${audit_address##*:}/audit" \
AR_RUNTIME_OPERATIONS_AUDIT_RETENTION_URL="https://localhost:${audit_address##*:}/retention" \
AR_RUNTIME_OPERATIONS_RETENTION_TENANT="$retention_tenant" \
AR_RUNTIME_OPERATIONS_RETENTION_AUTHORIZATION_ID="$retention_authorization" \
AR_RUNTIME_OPERATIONS_PITR_TENANT="$pitr_tenant" \
AR_RUNTIME_OPERATIONS_PITR_AUTHORIZATION_ID="$pitr_authorization" \
AR_RUNTIME_OPERATIONS_PITR_RECOVERY_POINT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
AR_RUNTIME_OPERATIONS_PITR_EXPECTED_GENERATION=7 \
AR_RUNTIME_OPERATIONS_SOURCE_REVISION="$(git -C "$repository_root" rev-parse HEAD)" \
AR_RUNTIME_OPERATIONS_REHEARSAL_CA_FILE="$working_directory/audit.crt" \
go run "$repository_root/cmd/runtime-operations-rehearsal"
