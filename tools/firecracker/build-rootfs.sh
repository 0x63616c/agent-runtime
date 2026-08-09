#!/bin/sh

# Builds the deliberately tiny ext4 smoke rootfs from one explicit static init.
# It never downloads a base image, installs packages, enables a NIC, or edits a
# fixture lock. A caller must record the resulting output and build inputs in a
# reviewed firecracker.fixtures/v2 lock before a protected runner can use it.
set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: $0 STATIC-GUEST-AGENT OUTPUT EXT4-BYTES FIXED-UUID ATTESTATION-JSON" >&2
    exit 2
fi

agent=$1
output=$2
size_bytes=$3
uuid=$4
attestation=$5

case "$size_bytes" in
    ''|*[!0-9]*) echo "EXT4-BYTES must be an integer" >&2; exit 2 ;;
esac

if [ ! -f "$agent" ]; then
    echo "STATIC-GUEST-AGENT must be a regular file" >&2
    exit 2
fi

if [ -e "$output" ] || [ -e "$attestation" ]; then
    echo "OUTPUT and ATTESTATION-JSON must not already exist" >&2
    exit 2
fi

if ! readelf -h "$agent" | grep -Eq 'Class:[[:space:]]+ELF64$'; then
    echo "STATIC-GUEST-AGENT must be an ELF64 binary" >&2
    exit 2
fi

if ! readelf -h "$agent" | grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64$'; then
    echo "STATIC-GUEST-AGENT must be Linux/amd64" >&2
    exit 2
fi

if readelf -d "$agent" 2>/dev/null | grep -q '(NEEDED)'; then
    echo "STATIC-GUEST-AGENT must not have dynamic library dependencies" >&2
    exit 2
fi

stage_dir=$(mktemp -d)
cleanup() {
    rm -rf "$stage_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$stage_dir/sbin"
install -m 0755 "$agent" "$stage_dir/sbin/init"
truncate -s "$size_bytes" "$output"
mke2fs -q -t ext4 -F -d "$stage_dir" -U "$uuid" -E lazy_itable_init=0,lazy_journal_init=0 "$output"

agent_size=$(wc -c < "$agent" | tr -d ' ')
rootfs_size=$(wc -c < "$output" | tr -d ' ')
agent_digest=sha256:$(sha256sum "$agent" | awk '{print $1}')
rootfs_digest=sha256:$(sha256sum "$output" | awk '{print $1}')

printf '{"schema_version":"agent-runtime.firecracker.rootfs-attestation/v1","rootfs_sha256":"%s","rootfs_size_bytes":%s,"init_path":"/sbin/init","init_sha256":"%s","init_size_bytes":%s,"platform":{"os":"linux","architecture":"amd64"},"static":true}\n' \
    "$rootfs_digest" "$rootfs_size" "$agent_digest" "$agent_size" > "$attestation"
