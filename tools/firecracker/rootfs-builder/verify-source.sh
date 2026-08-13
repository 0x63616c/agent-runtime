#!/bin/sh

# Validates the complete project-owned source contract before a builder image
# can be built or its published digest can be recorded. It performs no Docker
# operation and has no network side effect.
set -eu

if [ "$#" -ne 0 ]; then
    echo "usage: $0" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
dockerfile="$script_dir/Dockerfile"
inputs="$script_dir/inputs.lock.json"

python3 - "$dockerfile" "$inputs" <<'PY'
import hashlib
import json
import re
import sys

dockerfile_path, inputs_path = sys.argv[1:]
expected_keys = {
    'schema_version', 'base_image', 'platform', 'apk_repository', 'packages',
    'e2fsprogs_version', 'binutils_version',
}
digest = re.compile(r'^docker\.io/library/alpine@sha256:[a-f0-9]{64}$')
version = re.compile(r'^[0-9][A-Za-z0-9.+~-]*$')

try:
    with open(inputs_path, encoding='utf-8') as handle:
        inputs = json.load(handle)
    with open(dockerfile_path, encoding='utf-8') as handle:
        dockerfile = handle.read()
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f'rootfs builder source is unreadable: {error}')

if not isinstance(inputs, dict) or set(inputs) != expected_keys:
    raise SystemExit('rootfs builder inputs must contain exactly the v1 fields')
if inputs['schema_version'] != 'agent-runtime.firecracker.rootfs-builder-inputs/v1':
    raise SystemExit('rootfs builder inputs has an unsupported schema version')
if not isinstance(inputs['base_image'], str) or not digest.fullmatch(inputs['base_image']):
    raise SystemExit('rootfs builder base_image must be an exact lowercase Alpine digest')
if inputs['platform'] != {'os': 'linux', 'architecture': 'amd64'}:
    raise SystemExit('rootfs builder must select linux/amd64')
if inputs['apk_repository'] != 'https://dl-cdn.alpinelinux.org/alpine/v3.22/main':
    raise SystemExit('rootfs builder must use its exact reviewed APK repository')
expected_packages = [('binutils', '2.44-r3'), ('coreutils', '9.7-r1'), ('e2fsprogs', '1.47.2-r2')]
if inputs['packages'] != [{'name': name, 'version': value} for name, value in expected_packages]:
    raise SystemExit('rootfs builder packages must be exact and in canonical order')
if inputs['e2fsprogs_version'] != '1.47.2' or inputs['binutils_version'] != '2.44':
    raise SystemExit('rootfs builder tool versions must match the reviewed package set')

expected_dockerfile = '''# Linux/amd64-only builder for the deterministic Firecracker smoke rootfs.
# The base image and each direct package are pinned in inputs.lock.json and
# checked by verify-source.sh before any build is allowed.
FROM {base_image}

RUN apk add --no-cache \\
    --repository {apk_repository} \\
    binutils={binutils} \\
    coreutils={coreutils} \\
    e2fsprogs={e2fsprogs}
'''.format(
    base_image=inputs['base_image'],
    apk_repository=inputs['apk_repository'],
    binutils=expected_packages[0][1],
    coreutils=expected_packages[1][1],
    e2fsprogs=expected_packages[2][1],
)
if dockerfile != expected_dockerfile:
    raise SystemExit('rootfs builder Dockerfile differs from the reviewed inputs contract')

# Keep the source verifier intentionally strict enough that changing either
# source file requires an explicit review, rather than silently altering what
# a later protected publication would contain.
if not re.fullmatch(r'[\x09\x0a\x0d\x20-\x7e]*', dockerfile):
    raise SystemExit('rootfs builder Dockerfile must be ASCII source')
PY
