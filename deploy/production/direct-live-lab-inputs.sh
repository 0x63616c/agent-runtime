#!/usr/bin/env bash
# Validates operator-supplied, short-lived namespace-local secret files without
# reading or printing their values. This is intentionally offline.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="$root/deploy/production/direct-live-lab-manifest.sh"
fail() {
	echo "direct live-lab inputs failed: $*" >&2
	exit 1
}

usage() {
	cat >&2 <<'EOF'
usage:
  direct-live-lab-inputs.sh compose --stack-file /absolute/STACK.json --secrets-dir /absolute/new-DIR
  direct-live-lab-inputs.sh validate --stack-file /absolute/STACK.json --secrets-dir /absolute/DIR

compose creates a new 0700 directory containing only the exact, short-lived
namespace-local Secret input inventory for the rendered direct CI Stack. It
generates synthetic credentials locally, never prints their values, and binds
the two PostgreSQL DSNs to the Stack's in-namespace `state` Service. It is not
a production secret-management command.
EOF
	exit 2
}

file_mode() { stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"; }

compose() {
	local stack="" secrets="" rendered name key state_secret sandbox_state_secret blob_secret orchestration_secret runtime_api_secret state_password blob_user blob_password
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--stack-file)
			stack="${2:-}"
			shift 2
			;;
		--secrets-dir)
			secrets="${2:-}"
			shift 2
			;;
		*) usage ;;
		esac
	done
	[[ "$stack" == /* && -f "$stack" && "$secrets" == /* && ! -e "$secrets" ]] || fail "stack must exist and secrets directory must be a new absolute path"
	"$manifest" validate --stack-file "$stack" >/dev/null
	command -v openssl >/dev/null || fail "openssl is required to generate disposable direct-lab inputs"
	mkdir -m 700 "$secrets"
	rendered="$(go run "$root/cmd/stackctl" render --stack-file "$stack" --profile ci)"
	while IFS=$'\t' read -r name key; do
		mkdir -p "$secrets/$name"
		# Kubernetes --from-file preserves every byte.  In particular, the
		# newline printed by openssl would become part of a database password or
		# S3 access key while the derived DSN/signature omits it.
		openssl rand -hex 32 | tr -d '\n' >"$secrets/$name/$key"
		chmod 600 "$secrets/$name/$key"
	done < <(printf '%s' "$rendered" | jq -r '.resources[]|select(.kind=="secret_reference")|.secret_reference.reference as $name|.secret_reference.keys[]|[$name,.]|@tsv')
	state_secret="$(printf '%s' "$rendered" | jq -er '.resources[]|select(.id == "state-db-secret")|.secret_reference.reference')"
	sandbox_state_secret="$(printf '%s' "$rendered" | jq -er '.resources[]|select(.id == "sandbox-state-secret")|.secret_reference.reference')"
	blob_secret="$(printf '%s' "$rendered" | jq -er '.resources[]|select(.id == "blob-storage-secret")|.secret_reference.reference')"
	orchestration_secret="$(printf '%s' "$rendered" | jq -er '.resources[]|select(.id == "orchestration-payload-blob-secret")|.secret_reference.reference')"
	runtime_api_secret="$(printf '%s' "$rendered" | jq -er '.resources[]|select(.id == "runtime-api-secret")|.secret_reference.reference')"
	# MinIO credentials are also the S3 credentials used by orchestration and
	# the public API.  Use a bounded AWS-compatible access key rather than a
	# generic 64-character random value.
	printf 'ARLAB%s' "$(openssl rand -hex 7 | tr '[:lower:]' '[:upper:]' | tr -d '\n')" >"$secrets/$blob_secret/MINIO_ROOT_USER"
	chmod 600 "$secrets/$blob_secret/MINIO_ROOT_USER"
	state_password="$(<"$secrets/$state_secret/POSTGRES_PASSWORD")"
	blob_user="$(<"$secrets/$blob_secret/MINIO_ROOT_USER")"
	blob_password="$(<"$secrets/$blob_secret/MINIO_ROOT_PASSWORD")"
	printf 'postgres://postgres:%s@state:5432/agent_runtime?sslmode=disable' "$state_password" >"$secrets/$state_secret/STATE_DATABASE_DSN"
	printf 'postgres://postgres:%s@state:5432/agent_runtime?sslmode=disable' "$state_password" >"$secrets/$sandbox_state_secret/SANDBOX_STATE_DSN"
	printf '%s' "$blob_user" >"$secrets/$orchestration_secret/ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY"
	printf '%s' "$blob_password" >"$secrets/$orchestration_secret/ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"
	printf '%s' "$blob_user" >"$secrets/$runtime_api_secret/RUNTIME_API_CONTENT_ACCESS_KEY"
	printf '%s' "$blob_password" >"$secrets/$runtime_api_secret/RUNTIME_API_CONTENT_SECRET_KEY"
	chmod 600 "$secrets/$state_secret/STATE_DATABASE_DSN" "$secrets/$sandbox_state_secret/SANDBOX_STATE_DSN" \
		"$secrets/$orchestration_secret/ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY" "$secrets/$orchestration_secret/ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY" \
		"$secrets/$runtime_api_secret/RUNTIME_API_CONTENT_ACCESS_KEY" "$secrets/$runtime_api_secret/RUNTIME_API_CONTENT_SECRET_KEY"
	validate --stack-file "$stack" --secrets-dir "$secrets" >/dev/null
	echo "composed exact short-lived namespace-local direct-lab inputs; values were not printed"
}

validate() {
	local stack="" secrets="" mode expected actual name keys file
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--stack-file)
			stack="${2:-}"
			shift 2
			;;
		--secrets-dir)
			secrets="${2:-}"
			shift 2
			;;
		*) usage ;;
		esac
	done
	[[ "$stack" == /* && -f "$stack" && "$secrets" == /* && -d "$secrets" ]] || fail "stack and secrets directory must be existing absolute paths"
	"$manifest" validate --stack-file "$stack" >/dev/null
	mode="$(file_mode "$secrets")"
	[[ "$mode" == 700 ]] || fail "secrets directory must have mode 0700"
	expected="$(go run "$root/cmd/stackctl" render --stack-file "$stack" --profile ci | jq -c '[.resources[]|select(.kind=="secret_reference")|{name:.secret_reference.reference,keys:(.secret_reference.keys|sort)}]|sort_by(.name)')"
	actual='[]'
	if find "$secrets" -mindepth 1 -maxdepth 1 ! -type d -print -quit | grep -q .; then
		fail "secrets directory may contain only named secret input directories"
	fi
	while IFS= read -r secret_dir; do
		name="$(basename "$secret_dir")"
		keys='[]'
		while IFS= read -r file; do
			mode="$(file_mode "$file")"
			[[ "$mode" == 600 ]] || fail "secret input file permissions must be 0600"
			[[ -s "$file" ]] || fail "secret input files must be non-empty"
			keys="$(printf '%s' "$keys" | jq --arg key "$(basename "$file")" '.+[$key]')"
		done < <(find "$secret_dir" -maxdepth 1 -type f -print | sort)
		actual="$(printf '%s' "$actual" | jq --arg name "$name" --argjson keys "$keys" '.+[{name:$name,keys:($keys|sort)}]')"
	done < <(find "$secrets" -mindepth 1 -maxdepth 1 -type d -print | sort)
	[[ "$(printf '%s' "$actual" | jq -c 'sort_by(.name)')" == "$expected" ]] || fail "secret name/key inventory differs; values were not read"
	echo "validated short-lived namespace-local secret inputs; values were not read or printed"
}

self_test() {
	local tmp stack secrets name key bad_output rendered state_secret sandbox_state_secret blob_secret orchestration_secret runtime_api_secret
	tmp="$(mktemp -d)"
	trap "rm -rf -- $(printf '%q' "$tmp")" EXIT
	stack="$tmp/stack.json"
	secrets="$tmp/secrets"
	"$manifest" render --name agent-runtime-direct-live-lab-test --context home-server --output "$stack" >/dev/null
	compose --stack-file "$stack" --secrets-dir "$secrets" >/dev/null
	"$0" validate --stack-file "$stack" --secrets-dir "$secrets" >/dev/null
	rendered="$(go run "$root/cmd/stackctl" render --stack-file "$stack" --profile ci)"
	state_secret="$(printf '%s' "$rendered" | jq -er '.resources[]|select(.id == "state-db-secret")|.secret_reference.reference')"
	sandbox_state_secret="$(printf '%s' "$rendered" | jq -er '.resources[]|select(.id == "sandbox-state-secret")|.secret_reference.reference')"
	blob_secret="$(printf '%s' "$rendered" | jq -er '.resources[]|select(.id == "blob-storage-secret")|.secret_reference.reference')"
	orchestration_secret="$(printf '%s' "$rendered" | jq -er '.resources[]|select(.id == "orchestration-payload-blob-secret")|.secret_reference.reference')"
	runtime_api_secret="$(printf '%s' "$rendered" | jq -er '.resources[]|select(.id == "runtime-api-secret")|.secret_reference.reference')"
	[[ "$(<"$secrets/$state_secret/STATE_DATABASE_DSN")" == "postgres://postgres:$(<"$secrets/$state_secret/POSTGRES_PASSWORD")@state:5432/agent_runtime?sslmode=disable" ]] || fail "self-test did not bind the state DSN to its password"
	[[ "$(<"$secrets/$sandbox_state_secret/SANDBOX_STATE_DSN")" == "$(<"$secrets/$state_secret/STATE_DATABASE_DSN")" ]] || fail "self-test did not bind the sandbox DSN to state"
	[[ "$(<"$secrets/$blob_secret/MINIO_ROOT_USER")" =~ ^ARLAB[A-F0-9]{14}$ ]] || fail "self-test did not compose an AWS-compatible MinIO access key"
	cmp -s "$secrets/$blob_secret/MINIO_ROOT_USER" "$secrets/$orchestration_secret/ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY" || fail "self-test did not bind orchestration to MinIO access credentials"
	cmp -s "$secrets/$blob_secret/MINIO_ROOT_PASSWORD" "$secrets/$orchestration_secret/ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY" || fail "self-test did not bind orchestration to MinIO secret credentials"
	cmp -s "$secrets/$blob_secret/MINIO_ROOT_USER" "$secrets/$runtime_api_secret/RUNTIME_API_CONTENT_ACCESS_KEY" || fail "self-test did not bind API content access credentials"
	cmp -s "$secrets/$blob_secret/MINIO_ROOT_PASSWORD" "$secrets/$runtime_api_secret/RUNTIME_API_CONTENT_SECRET_KEY" || fail "self-test did not bind API content secret credentials"

	name="$(go run "$root/cmd/stackctl" render --stack-file "$stack" --profile ci | jq -r '[.resources[] | select(.kind == "secret_reference") | .secret_reference.reference] | first')"
	key="$(go run "$root/cmd/stackctl" render --stack-file "$stack" --profile ci | jq -r --arg name "$name" '.resources[] | select(.kind == "secret_reference" and .secret_reference.reference == $name) | .secret_reference.keys[0]')"
	chmod 644 "$secrets/$name/$key"
	if bad_output="$("$0" validate --stack-file "$stack" --secrets-dir "$secrets" 2>&1)"; then
		fail "self-test accepted an insecure secret file"
	fi
	[[ "$bad_output" != *"values were not read or printed"* ]] || fail "self-test printed a validation success claim for bad permissions"
	chmod 600 "$secrets/$name/$key"
	rm -f -- "$secrets/$name/$key"
	if bad_output="$("$0" validate --stack-file "$stack" --secrets-dir "$secrets" 2>&1)"; then
		fail "self-test accepted an incomplete secret key inventory"
	fi
	[[ "$bad_output" != *"values were not read or printed"* ]] || fail "self-test printed a validation success claim for bad inventory"
	rm -rf -- "$tmp"
	trap - EXIT
	echo "direct live-lab input validator accepts only exact 0700/0600 namespace-local input inventories"
}

command -v jq >/dev/null || fail "jq is required"
command -v go >/dev/null || fail "go is required"
case "${1:-}" in
compose)
	shift
	compose "$@"
	;;
validate)
	shift
	validate "$@"
	;;
--self-test) self_test ;;
*) usage ;;
esac
