#!/bin/sh

# Validates the reviewed builder contract before the rootfs recipe can invoke
# Docker. Image acquisition and publication are intentionally separate.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 BUILDER-MANIFEST BUILDER-IMAGE@sha256:DIGEST" >&2
    exit 2
fi

manifest=$1
builder_image=$2

if [ ! -f "$manifest" ]; then
    echo "BUILDER-MANIFEST must be a regular file" >&2
    exit 2
fi

python3 - "$manifest" "$builder_image" <<'PY'
import json
import re
import sys

manifest_path, requested_image = sys.argv[1:]
image_pattern = re.compile(r'^[^@\s]+@sha256:[a-f0-9]{64}$')
required_commands = ['awk', 'grep', 'install', 'mke2fs', 'mkdir', 'mktemp', 'readelf', 'rm', 'sha256sum', 'tr', 'truncate', 'wc']
expected_keys = {
    'schema_version', 'image', 'platform', 'required_commands',
    'e2fsprogs_version', 'binutils_version',
}

try:
    with open(manifest_path, encoding='utf-8') as handle:
        value = json.load(handle)
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f'BUILDER-MANIFEST must be one valid JSON document: {error}')

if not isinstance(value, dict) or set(value) != expected_keys:
    raise SystemExit('BUILDER-MANIFEST must contain exactly the rootfs builder contract fields')
if value['schema_version'] != 'agent-runtime.firecracker.rootfs-builder/v1':
    raise SystemExit('BUILDER-MANIFEST has an unsupported schema version')
if not isinstance(value['image'], str) or not image_pattern.fullmatch(value['image']):
    raise SystemExit('BUILDER-MANIFEST image must be an exact lowercase sha256 reference')
if value['image'] != requested_image:
    raise SystemExit('BUILDER-IMAGE must equal the reviewed BUILDER-MANIFEST image')
if value['platform'] != {'os': 'linux', 'architecture': 'amd64'}:
    raise SystemExit('BUILDER-MANIFEST must select linux/amd64')
if value['required_commands'] != required_commands:
    raise SystemExit('BUILDER-MANIFEST must declare the complete rootfs command set in canonical order')
for key in ('e2fsprogs_version', 'binutils_version'):
    if not isinstance(value[key], str) or not value[key]:
        raise SystemExit(f'BUILDER-MANIFEST {key} must be a non-empty string')
PY
