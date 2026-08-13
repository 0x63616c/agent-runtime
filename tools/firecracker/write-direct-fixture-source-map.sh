#!/usr/bin/env bash

# Binds one locally staged, reviewed fixture candidate to the direct smoke
# runner. It does not download, build, publish, or execute anything.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 FIXTURE-DIRECTORY OUTPUT-MAP" >&2
  exit 2
fi

fixture_dir=$1
output_map=$2
expected_root=/var/lib/agent-runtime/firecracker-fixtures/home-server
expected_map=/etc/agent-runtime/firecracker-direct-fixtures.json

if [ "$fixture_dir" != "$expected_root" ] || [ "$output_map" != "$expected_map" ]; then
  echo "direct fixture paths do not match the reviewed home-server authority" >&2
  exit 2
fi
if [ -e "$output_map" ]; then
  echo "OUTPUT-MAP must not already exist" >&2
  exit 2
fi
for path in "$fixture_dir/fixtures.lock" "$fixture_dir/input/firecracker-v1.16.1-x86_64.tgz" "$fixture_dir/input/vmlinux" "$fixture_dir/bundles/rootfs-bundle.tar.gz" "$fixture_dir/bundles/guest-agent-bundle.tar.gz"; do
  [ -f "$path" ] || { echo "required direct fixture file is absent: $path" >&2; exit 2; }
  [ "$(stat -c '%u %a' "$path")" = "0 600" ] || { echo "direct fixture file must be root-owned mode 0600: $path" >&2; exit 2; }
done

python3 - "$fixture_dir" "$output_map" <<'PY'
import hashlib, json, os, sys
directory, destination = sys.argv[1:]
lock = os.path.join(directory, 'fixtures.lock')
with open(lock, 'rb') as handle:
    lock_digest = 'sha256:' + hashlib.sha256(handle.read()).hexdigest()
value = {
    'schema_version': 'agent-runtime.firecracker-direct-fixtures/v1',
    'fixture_lock_sha256': lock_digest,
    'sources': {
        'firecracker-release': os.path.join(directory, 'input', 'firecracker-v1.16.1-x86_64.tgz'),
        'kernel': os.path.join(directory, 'input', 'vmlinux'),
        'rootfs': os.path.join(directory, 'bundles', 'rootfs-bundle.tar.gz'),
        'guest-agent': os.path.join(directory, 'bundles', 'guest-agent-bundle.tar.gz'),
    },
}
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w', encoding='utf-8') as handle:
    json.dump(value, handle, sort_keys=True, separators=(',', ':'))
    handle.write('\n')
PY
chown root:root "$output_map"
chmod 0600 "$output_map"
echo "wrote root-owned direct fixture source map: $output_map"
