#!/usr/bin/env bash
# Applies the deferred Stack phase for one disposable CI Stack. Tilt has applied
# only the initial manifests; stackctl is the sole route that runs migrations
# and creates post-migration Jobs.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
stack=""
context=""
for argument in "$@"; do
  case "$argument" in
    --stack=*) stack="${argument#--stack=}" ;;
    --context=*) context="${argument#--context=}" ;;
    *) echo "CI Stack reconciliation accepts only --stack and --context" >&2; exit 1 ;;
  esac
done
if [[ ! "$stack" =~ ^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$ || "$context" != k3d-ar-ci-* ]]; then
  echo "CI Stack reconciliation requires a generated Stack and private k3d context" >&2
  exit 1
fi
if [[ -z "${KUBECONFIG:-}" || "$KUBECONFIG" != /* || "$KUBECONFIG" == *:* || ! -f "$KUBECONFIG" ]]; then
  echo "CI Stack reconciliation requires one absolute generated kubeconfig" >&2
  exit 1
fi

stack_file="$root/.runtime/dev/$stack.stack.json"
capability_file="$root/.runtime/dev/$stack.ci.bootstrap.json"
audit_file="$root/.runtime/dev/$stack.ci.operator-audit.jsonl"
if [[ ! -f "$stack_file" || ! -f "$capability_file" || ! -f "$audit_file" ]]; then
  echo "CI Stack reconciliation requires existing rendered state and private authority" >&2
  exit 1
fi
umask 077
common=(--stack-file "$stack_file" --stack "$stack" --profile ci --kubeconfig "$KUBECONFIG" --context "$context" --actor ci-stack-reconcile --audit-file "$audit_file" --migration-root "$root/deploy/production" --bootstrap-capability-file "$capability_file")
go run ./cmd/stackctl apply "${common[@]}" >/dev/null
