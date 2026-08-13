#!/usr/bin/env bash
# Runs a disposable local rehearsal of the M5 operations drill. The optional
# direct-lab mode retains a separately typed, redacted lab artifact; it is not
# protected-run or production evidence.
set -euo pipefail

direct_report=""
direct_authorized=false
usage() {
  echo "usage: run-rehearsal.sh [--direct-lab-report /absolute/new/report.json --execute-authorized-disposable-lab]" >&2
  exit 2
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --direct-lab-report) direct_report="${2:-}"; shift 2 ;;
    --execute-authorized-disposable-lab) direct_authorized=true; shift ;;
    *) usage ;;
  esac
done
if [[ -n "$direct_report" ]]; then
  [[ "$direct_authorized" == true && "$direct_report" == /* && ! -e "$direct_report" && -d "$(dirname "$direct_report")" ]] || usage
elif [[ "$direct_authorized" == true ]]; then
  usage
fi

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
compose_file="$repository_root/deploy/runtimeoperations/local/compose.yaml"
runner_contract_file="$repository_root/deploy/runtimeoperations/runner-contract.json"
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
runner_contract=$(jq -er '.required_environment_assertions.RUNTIME_OPERATIONS_RUNNER_CONTRACT' "$runner_contract_file")
github_environment=$(jq -er '.github_environment' "$runner_contract_file")
runner_labels=$(jq -er '.runner.required_labels | join(",")' "$runner_contract_file")
workflow_name=$(jq -er '.runner.required_workflow' "$runner_contract_file")
protected_ref_required=$(jq -er '.runner.protected_ref_required' "$runner_contract_file")
if [ "$runner_contract" != "protected-runtime-operations-v1" ] || [ "$github_environment" != "runtime-operations" ] || [ "$workflow_name" != "runtime-operations-drill" ] || [ "$protected_ref_required" != "true" ]; then
  echo "local rehearsal refuses an unexpected protected runner contract" >&2
  exit 1
fi
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

common_environment=(
  "AR_RUNTIME_OPERATIONS_DATABASE_DSN=$source_dsn"
  "AR_RUNTIME_OPERATIONS_PITR_RESTORE_DSN=$restore_dsn"
  "AR_RUNTIME_OPERATIONS_AUDIT_SINK_URL=https://localhost:${audit_address##*:}/audit"
  "AR_RUNTIME_OPERATIONS_AUDIT_RETENTION_URL=https://localhost:${audit_address##*:}/retention"
  "AR_RUNTIME_OPERATIONS_RETENTION_TENANT=$retention_tenant"
  "AR_RUNTIME_OPERATIONS_RETENTION_AUTHORIZATION_ID=$retention_authorization"
  "AR_RUNTIME_OPERATIONS_PITR_TENANT=$pitr_tenant"
  "AR_RUNTIME_OPERATIONS_PITR_AUTHORIZATION_ID=$pitr_authorization"
  "AR_RUNTIME_OPERATIONS_PITR_RECOVERY_POINT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  "AR_RUNTIME_OPERATIONS_PITR_EXPECTED_GENERATION=7"
  "AR_RUNTIME_OPERATIONS_REHEARSAL_CA_FILE=$working_directory/audit.crt"
  "AR_RUNTIME_OPERATIONS_SOURCE_REVISION=$(git -C "$repository_root" rev-parse HEAD)"
)
if [[ -n "$direct_report" ]]; then
  env RUNTIME_OPERATIONS_DIRECT_LAB=authorized-disposable-v1 "${common_environment[@]}" \
    go run "$repository_root/cmd/runtime-operations-direct-lab" -report "$direct_report" -execute-authorized-disposable-lab
  go run "$repository_root/cmd/runtime-operations-direct-lab" -validate "$direct_report"
  echo "direct authorized disposable lab passed; retained redacted lab evidence at $direct_report"
else
  # The default rehearsal uses the protected contract only for a no-write
  # drift check. It cannot create either protected or direct-lab evidence.
  env RUNTIME_OPERATIONS_REHEARSAL=local-only \
    RUNTIME_OPERATIONS_RUNNER_CONTRACT="$runner_contract" \
    GITHUB_ACTIONS=true GITHUB_REF_PROTECTED=true GITHUB_WORKFLOW="$workflow_name" \
    RUNNER_ENVIRONMENT=self-hosted RUNNER_OS=Linux RUNNER_ARCH=X64 \
    RUNTIME_OPERATIONS_GITHUB_ENVIRONMENT="$github_environment" \
    RUNTIME_OPERATIONS_RUNNER_LABELS="$runner_labels" \
    GITHUB_SHA="$(git -C "$repository_root" rev-parse HEAD)" "${common_environment[@]}" \
    go run "$repository_root/cmd/runtime-operations-drill" -preflight
fi
