#!/usr/bin/env bash
# Validates operator-supplied, short-lived namespace-local secret files without
# reading or printing their values. This is intentionally offline.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="$root/deploy/production/direct-live-lab-manifest.sh"
fail() { echo "direct live-lab inputs failed: $*" >&2; exit 1; }

usage() {
  echo "usage: direct-live-lab-inputs.sh validate --stack-file /absolute/STACK.json --secrets-dir /absolute/DIR" >&2
  exit 2
}

file_mode() { stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"; }

validate() {
  local stack="" secrets="" mode expected actual name keys file
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --stack-file) stack="${2:-}"; shift 2 ;;
      --secrets-dir) secrets="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ "$stack" == /* && -f "$stack" && "$secrets" == /* && -d "$secrets" ]] || fail "stack and secrets directory must be existing absolute paths"
  "$manifest" validate --stack-file "$stack" >/dev/null
  mode="$(file_mode "$secrets")"; [[ "$mode" == 700 ]] || fail "secrets directory must have mode 0700"
  expected="$(go run "$root/cmd/stackctl" render --stack-file "$stack" --profile ci | jq -c '[.resources[]|select(.kind=="secret_reference")|{name:.secret_reference.reference,keys:(.secret_reference.keys|sort)}]|sort_by(.name)')"
  actual='[]'
  if find "$secrets" -mindepth 1 -maxdepth 1 ! -type d -print -quit | grep -q .; then
    fail "secrets directory may contain only named secret input directories"
  fi
  while IFS= read -r secret_dir; do
    name="$(basename "$secret_dir")"
    keys='[]'
    while IFS= read -r file; do
      mode="$(file_mode "$file")"; [[ "$mode" == 600 ]] || fail "secret input file permissions must be 0600"
      [[ -s "$file" ]] || fail "secret input files must be non-empty"
      keys="$(printf '%s' "$keys" | jq --arg key "$(basename "$file")" '.+[$key]')"
    done < <(find "$secret_dir" -maxdepth 1 -type f -print | sort)
    actual="$(printf '%s' "$actual" | jq --arg name "$name" --argjson keys "$keys" '.+[{name:$name,keys:($keys|sort)}]')"
  done < <(find "$secrets" -mindepth 1 -maxdepth 1 -type d -print | sort)
  [[ "$(printf '%s' "$actual" | jq -c 'sort_by(.name)')" == "$expected" ]] || fail "secret name/key inventory differs; values were not read"
  echo "validated short-lived namespace-local secret inputs; values were not read or printed"
}

self_test() {
  local tmp stack secrets name key bad_output
  tmp="$(mktemp -d)"
  trap "rm -rf -- $(printf '%q' "$tmp")" EXIT
  stack="$tmp/stack.json"
  secrets="$tmp/secrets"
  "$manifest" render --name agent-runtime-direct-live-lab-test --context home-server --output "$stack" >/dev/null
  mkdir -m 700 "$secrets"
  # Generate exactly the rendered reference/key inventory.  The placeholder is
  # deliberately value-free and never passed to validate's output.
  while IFS=$'\t' read -r name key; do
    mkdir -p "$secrets/$name"
    printf '\n' >"$secrets/$name/$key"
    chmod 600 "$secrets/$name/$key"
  done < <(go run "$root/cmd/stackctl" render --stack-file "$stack" --profile ci | jq -r '.resources[] | select(.kind == "secret_reference") | .secret_reference.reference as $name | .secret_reference.keys[] | [$name, .] | @tsv')
  "$0" validate --stack-file "$stack" --secrets-dir "$secrets" >/dev/null

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
  validate) shift; validate "$@" ;;
  --self-test) self_test ;;
  *) usage ;;
esac
