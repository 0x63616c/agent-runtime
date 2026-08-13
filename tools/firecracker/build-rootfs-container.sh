#!/bin/sh

# Runs the deterministic rootfs recipe in a pre-reviewed Linux/amd64 container
# image.  This is an assembly aid only: it cannot fetch an image, publish a
# fixture, alter a fixture lock, or start a microVM.
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 BUILDER-IMAGE@sha256:DIGEST STATIC-GUEST-AGENT OUTPUT EXT4-BYTES FIXED-UUID ATTESTATION-JSON" >&2
    exit 2
fi

builder_image=$1
agent=$2
output=$3
size_bytes=$4
uuid=$5
attestation=$6

case "$builder_image" in
    *@sha256:????????????????????????????????????????????????????????????????) ;;
    *)
        echo "BUILDER-IMAGE must be an exact image reference with a lowercase sha256 digest" >&2
        exit 2
        ;;
esac
case "${builder_image#*@sha256:}" in
    *[!0-9a-f]*|'')
        echo "BUILDER-IMAGE must be an exact image reference with a lowercase sha256 digest" >&2
        exit 2
        ;;
esac

if [ -z "${SOURCE_DATE_EPOCH:-}" ] || printf '%s' "$SOURCE_DATE_EPOCH" | grep -q '[^0-9]'; then
    echo "SOURCE_DATE_EPOCH must be a fixed integer for a reproducible rootfs" >&2
    exit 2
fi

if ! command -v docker >/dev/null; then
    echo "docker is required for containerized rootfs assembly" >&2
    exit 2
fi
if [ ! -f "$agent" ]; then
    echo "STATIC-GUEST-AGENT must be a regular file" >&2
    exit 2
fi
if [ -e "$output" ] || [ -e "$attestation" ]; then
    echo "OUTPUT and ATTESTATION-JSON must not already exist" >&2
    exit 2
fi

agent_dir=$(CDPATH= cd -- "$(dirname -- "$agent")" && pwd -P)
output_dir=$(CDPATH= cd -- "$(dirname -- "$output")" && pwd -P)
attestation_dir=$(CDPATH= cd -- "$(dirname -- "$attestation")" && pwd -P)
agent_name=$(basename -- "$agent")
output_name=$(basename -- "$output")
attestation_name=$(basename -- "$attestation")

if [ "$output_dir" != "$attestation_dir" ]; then
    echo "OUTPUT and ATTESTATION-JSON must share one parent directory" >&2
    exit 2
fi

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
    echo "run from a git checkout of agent-runtime" >&2
    exit 2
}

# Do not let Docker resolve or pull a tag. The builder must already be present
# by exact digest, so its review and acquisition are separate from fixture
# assembly and can be recorded alongside the candidate review.
if ! docker image inspect "$builder_image" >/dev/null 2>&1; then
    echo "BUILDER-IMAGE is not present locally by its exact digest; refusing to pull" >&2
    exit 2
fi

image_platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$builder_image")
if [ "$image_platform" != "linux/amd64" ]; then
    echo "BUILDER-IMAGE must be a locally present linux/amd64 image, got $image_platform" >&2
    exit 2
fi

exec docker run --rm --pull=never --platform linux/amd64 --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --mount "type=bind,src=$repo_root,dst=/workspace,readonly" \
    --mount "type=bind,src=$agent_dir,dst=/input,readonly" \
    --mount "type=bind,src=$output_dir,dst=/output" \
    -e "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    "$builder_image" \
    /workspace/tools/firecracker/build-rootfs.sh \
    "/input/$agent_name" "/output/$output_name" "$size_bytes" "$uuid" "/output/$attestation_name"
