#!/usr/bin/env bash
# Establishes audited authority for one disposable CI Stack before Tilt applies
# the reviewed Kubernetes topology. The following reconcile action mutates only
# declared non-Kubernetes providers through that authority.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
stack=""
context=""
for argument in "$@"; do
  case "$argument" in
    --stack=*) stack="${argument#--stack=}" ;;
    --context=*) context="${argument#--context=}" ;;
    *) echo "CI Stack bootstrap accepts only --stack and --context" >&2; exit 1 ;;
  esac
done
if [[ ! "$stack" =~ ^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$ || "$context" != k3d-ar-ci-* ]]; then
  echo "CI Stack bootstrap requires a generated Stack and private k3d context" >&2
  exit 1
fi
if [[ -z "${KUBECONFIG:-}" || "$KUBECONFIG" != /* || "$KUBECONFIG" == *:* || ! -f "$KUBECONFIG" ]]; then
  echo "CI Stack bootstrap requires one absolute generated kubeconfig" >&2
  exit 1
fi

stack_file="$root/.runtime/dev/$stack.stack.json"
capability_file="$root/.runtime/dev/$stack.ci.bootstrap.json"
audit_file="$root/.runtime/dev/$stack.ci.operator-audit.jsonl"
if [[ -e "$stack_file" || -e "$capability_file" || -e "$audit_file" ]]; then
  echo "CI Stack bootstrap refuses existing private state" >&2
  exit 1
fi
umask 077
go run ./tools/dev render --stack="$stack" --output="$stack_file" >/dev/null
common=(--stack-file "$stack_file" --stack "$stack" --profile ci --kubeconfig "$KUBECONFIG" --context "$context" --actor ci-stack-reconcile --audit-file "$audit_file" --migration-root "$root/deploy/production" --bootstrap-capability-file "$capability_file")
go run ./cmd/stackctl bootstrap "${common[@]}" >/dev/null
