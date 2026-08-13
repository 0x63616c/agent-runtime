#!/bin/sh

# Records the exact reviewed builder image digest after independent publication
# and re-download. This cannot build, pull, push, or alter fixture material.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 OUTPUT-MANIFEST BUILDER-IMAGE@sha256:DIGEST" >&2
    exit 2
fi

output=$1
image=$2
if [ -e "$output" ]; then
    echo "OUTPUT-MANIFEST must not already exist" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
builder_dir="$script_dir/rootfs-builder"
"$builder_dir/verify-source.sh"

if ! command -v docker >/dev/null; then
    echo "docker is required to inspect the reviewed builder image" >&2
    exit 2
fi

case "$image" in
    *@sha256:????????????????????????????????????????????????????????????????) ;;
    *) echo "BUILDER-IMAGE must be an exact lowercase sha256 reference" >&2; exit 2 ;;
esac
case "${image#*@sha256:}" in
    *[!0-9a-f]*|'') echo "BUILDER-IMAGE must be an exact lowercase sha256 reference" >&2; exit 2 ;;
esac
if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "BUILDER-IMAGE is not present locally by exact digest; re-download it before recording" >&2
    exit 2
fi
platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")
if [ "$platform" != linux/amd64 ]; then
    echo "BUILDER-IMAGE must be a locally present linux/amd64 image, got $platform" >&2
    exit 2
fi

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
    echo "run from a git checkout of agent-runtime" >&2
    exit 2
}
revision=$(git -C "$repo_root" rev-parse HEAD)
if ! git -C "$repo_root" diff --quiet || ! git -C "$repo_root" diff --cached --quiet; then
    echo "refusing to record builder manifest from a dirty checkout" >&2
    exit 2
fi

dockerfile_sha256=sha256:$(sha256sum "$builder_dir/Dockerfile" | awk '{print $1}')
inputs_sha256=sha256:$(sha256sum "$builder_dir/inputs.lock.json" | awk '{print $1}')
python3 - "$output" "$image" "$revision" "$dockerfile_sha256" "$inputs_sha256" <<'PY'
import json
import sys

path, image, revision, dockerfile_sha256, inputs_sha256 = sys.argv[1:]
value = {
    'schema_version': 'agent-runtime.firecracker.rootfs-builder/v1',
    'image': image,
    'platform': {'os': 'linux', 'architecture': 'amd64'},
    'required_commands': ['awk', 'grep', 'install', 'mke2fs', 'mkdir', 'mktemp', 'readelf', 'rm', 'sha256sum', 'tr', 'truncate', 'wc'],
    'e2fsprogs_version': '1.47.2',
    'binutils_version': '2.44',
    'source_revision': revision,
    'dockerfile_sha256': dockerfile_sha256,
    'inputs_lock_sha256': inputs_sha256,
}
with open(path, 'x', encoding='utf-8') as handle:
    json.dump(value, handle, separators=(',', ':'))
    handle.write('\n')
PY

"$script_dir/validate-rootfs-builder.sh" "$output" "$image"
