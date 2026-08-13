#!/usr/bin/env bash
# Build the direct Firecracker runner locally without publishing it. The caller
# must inspect the resulting immutable digest before a separate, explicit push.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: build-direct-kvm-runner-image.sh --tag local/agent-runtime-direct-runner:REV [--load]

Builds deploy/production/Dockerfile.direct-kvm-runner for linux/amd64 from the
current checked-out source. It never logs in, pushes, or reads runtime secrets.
EOF
  exit 2
}

tag=""
load=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="${2:-}"; shift 2 ;;
    --load) load=true; shift ;;
    *) usage ;;
  esac
done
[[ -n "$tag" ]] || usage
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker buildx version >/dev/null

revision="$(git rev-parse --verify HEAD)"
source_date_epoch="$(git show -s --format=%ct HEAD)"
arguments=(
  buildx build
  --platform linux/amd64
  --file deploy/production/Dockerfile.direct-kvm-runner
  --tag "$tag"
  --build-arg "SOURCE_REVISION=$revision"
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch"
  --provenance=false
)
if [[ "$load" == true ]]; then
  arguments+=(--load)
fi
arguments+=(.)
docker "${arguments[@]}"

cat <<EOF
Built direct KVM runner from source revision: $revision
Before publishing, obtain and independently record its linux/amd64 digest:
  docker buildx imagetools inspect "$tag"
EOF
