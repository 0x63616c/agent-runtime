#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
compose_file="$repository_root/deploy/runtimeapi/compose.integration.yaml"
migration_root="$repository_root/deploy/production/migrations"
environment_file=$(mktemp)
backup_directory=$(mktemp -d)
project_name="agent-runtime-api-$RANDOM-$RANDOM"

cleanup() {
  docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -f "$environment_file"
  rm -f "$backup_directory/runtime.dump"
  rmdir "$backup_directory" 2>/dev/null || true
}
trap cleanup EXIT

umask 077
printf 'AR_RUNTIME_API_POSTGRES_PASSWORD=%s\nAR_RUNTIME_API_MINIO_USER=agent-runtime-api\nAR_RUNTIME_API_MINIO_PASSWORD=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" > "$environment_file"
docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" up --detach --wait
for migration_file in "$migration_root"/runtime-v*.up.sql; do
  docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" exec --no-TTY postgres \
    psql -v ON_ERROR_STOP=1 -U runtime_api -d agent_runtime < "$migration_file"
done
postgres_port=$(docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" port postgres 5432 | sed 's/.*://')
minio_port=$(docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" port minio 9000 | sed 's/.*://')
postgres_password=$(awk -F= '/^AR_RUNTIME_API_POSTGRES_PASSWORD=/{print $2}' "$environment_file")
minio_password=$(awk -F= '/^AR_RUNTIME_API_MINIO_PASSWORD=/{print $2}' "$environment_file")
export AR_RUNTIME_API_POSTGRES_DSN="postgres://runtime_api:${postgres_password}@127.0.0.1:${postgres_port}/agent_runtime?sslmode=disable"
export AR_RUNTIME_API_MINIO_ENDPOINT="127.0.0.1:${minio_port}"
export AR_RUNTIME_API_MINIO_ACCESS_KEY=agent-runtime-api
export AR_RUNTIME_API_MINIO_SECRET_KEY="$minio_password"
export AR_RUNTIME_API_MINIO_BUCKET=agent-runtime-api-integration

# The restore drill is deliberately operator-side: it uses the disposable
# harness credential only, invokes PostgreSQL clients with argv, and never
# passes a backup handle into a runtime process. Seed before backup, remove
# from the source, then recover into a separately named disposable database.
restore_database="agent_runtime_restore_${RANDOM}${RANDOM}"
backup_file="$backup_directory/runtime.dump"
admin_dsn="postgres://runtime_api:${postgres_password}@127.0.0.1:${postgres_port}/postgres?sslmode=disable"
restore_dsn="postgres://runtime_api:${postgres_password}@127.0.0.1:${postgres_port}/${restore_database}?sslmode=disable"
psql "$AR_RUNTIME_API_POSTGRES_DSN" --set=ON_ERROR_STOP=1 --command "INSERT INTO runtime.tenants (tenant_id, created_at) VALUES ('backup_drill_tenant', now())"
docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" exec --no-TTY postgres \
  pg_dump -U runtime_api -d agent_runtime --format=custom > "$backup_file"
psql "$AR_RUNTIME_API_POSTGRES_DSN" --set=ON_ERROR_STOP=1 --command "DELETE FROM runtime.tenants WHERE tenant_id = 'backup_drill_tenant'"
psql "$admin_dsn" --set=ON_ERROR_STOP=1 --command "CREATE DATABASE ${restore_database}"
docker compose --project-name "$project_name" --env-file "$environment_file" --file "$compose_file" exec --no-TTY postgres \
  pg_restore -U runtime_api -d "$restore_database" --exit-on-error < "$backup_file"
if [ "$(psql "$restore_dsn" --tuples-only --no-align --set=ON_ERROR_STOP=1 --command "SELECT EXISTS(SELECT 1 FROM runtime.tenants WHERE tenant_id = 'backup_drill_tenant')")" != "t" ]; then
  echo 'backup restore drill did not recover the tenant-scoped state' >&2
  exit 1
fi
psql "$admin_dsn" --set=ON_ERROR_STOP=1 --command "DROP DATABASE ${restore_database}"

AR_RUNTIME_POSTGRES_DSN="$AR_RUNTIME_API_POSTGRES_DSN" \
  go test -race -tags=integration ./internal/runtimepostgres -count=1
go test -race -tags=integration ./internal/runtimeapiprocess ./internal/runtimeorchestration -run 'Test(DurablePostgresMinIOAPIProcessSurvivesRestart|CodecEnabledWorkerStartsAgainstDurableDependenciesAndRestarts)' -count=1
