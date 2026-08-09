#!/bin/sh

# Builds the deliberately tiny ext4 smoke rootfs from one explicit static init.
# It never downloads a base image, installs packages, enables a NIC, or edits a
# fixture lock. A caller must record the resulting output and build inputs in a
# reviewed firecracker.fixtures/v2 lock before a protected runner can use it.
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 STATIC-GUEST-AGENT OUTPUT EXT4-BYTES FIXED-UUID" >&2
    exit 2
fi

agent=$1
output=$2
size_bytes=$3
uuid=$4

case "$size_bytes" in
    ''|*[!0-9]*) echo "EXT4-BYTES must be an integer" >&2; exit 2 ;;
esac

if [ ! -f "$agent" ]; then
    echo "STATIC-GUEST-AGENT must be a regular file" >&2
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
