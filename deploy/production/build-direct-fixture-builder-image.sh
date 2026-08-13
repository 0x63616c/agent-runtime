#!/usr/bin/env bash
# Builds the self-contained Linux/amd64 fixture-builder image locally.  The
# caller must separately inspect and publish a resulting immutable digest.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: build-direct-fixture-builder-image.sh --tag local/agent-runtime-firecracker-fixture-builder:REV [--load]

Builds deploy/production/Dockerfile.direct-fixture-builder from a clean exact
source revision. The image includes a Git bundle of that revision and its Go
module cache, so the disposable direct fixture-builder Job can run with no
network. This command never logs in or pushes an image.
EOF
  exit 2
}

tag=''
load=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="${2:-}"; shift 2 ;;
    --load) load=true; shift ;;
    *) usage ;;
  esac
done
[[ -n "$tag" ]] || usage
command -v docker >/dev/null || { echo 'docker is required' >&2; exit 1; }
docker buildx version >/dev/null

revision="$(git rev-parse --verify HEAD)"
source_date_epoch="$(git show -s --format=%ct HEAD)"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo 'HEAD must be an exact full commit' >&2; exit 1; }
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || { echo 'HEAD must have a numeric commit timestamp' >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo 'fixture-builder image requires a clean checkout' >&2; exit 1; }

workspace_root="$(git rev-parse --show-toplevel)"
staging_root="$(mktemp -d "${TMPDIR:-/tmp}/agent-runtime-fixture-builder.XXXXXX")"
cleanup() { rm -rf -- "$staging_root"; }
trap cleanup EXIT

mkdir -p "$staging_root/deploy/production"
git archive --format=tar "$revision" | tar -x -C "$staging_root"
# The repository production .dockerignore intentionally excludes the fixture
# source and bundle.  This isolated, generated build context needs both.
rm -f "$staging_root/.dockerignore"
# `git bundle create` expects a revision expression which resolves through a
# ref on older Git versions; the full object ID alone can be rejected as an
# empty bundle.  HEAD is safe here because the clean-checkout check above and
# SOURCE_REVISION bind the image to this exact commit.
git bundle create "$staging_root/fixture-source.bundle" HEAD
cp "$workspace_root/deploy/production/Dockerfile.direct-fixture-builder" "$staging_root/deploy/production/Dockerfile.direct-fixture-builder"

arguments=(
  buildx build
  --platform linux/amd64
  --file deploy/production/Dockerfile.direct-fixture-builder
  --tag "$tag"
  --build-arg "SOURCE_REVISION=$revision"
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch"
  --provenance=false
)
if [[ "$load" == true ]]; then
  arguments+=(--load)
fi
arguments+=("$staging_root")
docker "${arguments[@]}"

cat <<EOF
Built direct fixture-builder from source revision: $revision
Before publishing, obtain and independently record its linux/amd64 digest:
  docker buildx imagetools inspect "$tag"
EOF
