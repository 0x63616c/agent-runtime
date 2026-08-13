#!/bin/sh

# Builds the project-owned Linux/amd64 rootfs builder under a caller-selected
# local tag. Publication is deliberately a separate, reviewed action.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 LOCAL-IMAGE-TAG" >&2
    exit 2
fi

image_tag=$1
case "$image_tag" in
    *[!A-Za-z0-9._/:@-]*|'')
        echo "LOCAL-IMAGE-TAG contains unsupported characters" >&2
        exit 2
        ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
builder_dir="$script_dir/rootfs-builder"
"$builder_dir/verify-source.sh"

if ! command -v docker >/dev/null; then
    echo "docker is required to build the rootfs builder" >&2
    exit 2
fi

base_image=$(python3 - "$builder_dir/inputs.lock.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding='utf-8') as handle:
    print(json.load(handle)['base_image'])
PY
)
if ! docker image inspect "$base_image" >/dev/null 2>&1; then
    echo "rootfs builder base image is not present by exact digest; acquire it separately" >&2
    exit 2
fi

exec docker build --pull=false --platform linux/amd64 --file "$builder_dir/Dockerfile" --tag "$image_tag" "$builder_dir"
