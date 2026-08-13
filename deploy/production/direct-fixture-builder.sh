#!/usr/bin/env bash
# Renders the one disposable Linux/amd64 Job that assembles the immutable
# Firecracker candidate used by the direct KVM smoke.  Rendering is offline;
# applying this manifest is deliberately an explicit later operator action.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage:
  direct-fixture-builder.sh render \
    --run-id ID \
    --image ghcr.io/0x63616c/agent-runtime-firecracker-fixture-builder@sha256:HEX \
    --revision GIT-SHA \
    --firecracker-version vX.Y.Z \
    --kernel-url HTTPS-URL \
    --kernel-version-id VERSION-ID \
    --source-date-epoch EPOCH --rootfs-bytes BYTES --rootfs-uuid UUID \
    --output /absolute/manifest.yaml
  direct-fixture-builder.sh execute \
    --run-id ID \
    --image ghcr.io/0x63616c/agent-runtime-firecracker-fixture-builder@sha256:HEX \
    --revision GIT-SHA \
    --firecracker-version vX.Y.Z \
    --kernel-url HTTPS-URL \
    --kernel-version-id VERSION-ID \
    --source-date-epoch EPOCH --rootfs-bytes BYTES --rootfs-uuid UUID \
    --kubeconfig /absolute/KUBECONFIG --context CONTEXT \
    --registry-docker-config /absolute/config.json \
    --evidence-file /absolute/EVIDENCE.json \
    --execute-authorized-direct-fixture-build
  direct-fixture-builder.sh --self-test

This command only writes OUTPUT. It never contacts Kubernetes, pulls or
publishes an image, downloads inputs, builds a fixture, or edits a lock.

execute is the sole mutating mode. It requires its literal consent flag and a
Docker registry config JSON file already present at an absolute local path.
It creates a fresh namespace and a namespace-scoped, immutable
`fixture-builder-registry` image-pull secret, then applies the otherwise
suspended Job. The registry config is passed directly to kubectl, never
rendered into YAML, logged, copied into evidence, or retained locally by this
script. execute always attempts to delete and wait for deletion of its unique
namespace after writing bounded, redacted evidence.

The rendered Job is intentionally one-shot and fails closed unless an operator
has already staged these root-owned, immutable inputs on the Linux node:
  /var/lib/agent-runtime/firecracker-fixture-inputs/home-server/firecracker.tgz
  /var/lib/agent-runtime/firecracker-fixture-inputs/home-server/vmlinux
  /var/lib/agent-runtime/firecracker-fixture-inputs/home-server/rootfs-builder.json

The pinned fixture-builder image must contain a clean checkout at /workspace,
Go, Python, tar, sha256sum, and the reviewed Linux/amd64 rootfs toolchain. It
verifies the checked-in rootfs-builder source lock and required tool versions
before it calls the existing rootfs and fixture assembly scripts. The Job has
no network and no Kubernetes API token.

The Job requires an explicitly labelled privileged namespace because a scoped
hostPath is the reviewed publication mechanism. The Job itself is one-shot;
the operator that applies it must delete the uniquely named namespace after
recording its outcome. It refuses a pre-existing published fixture directory
or source map, then atomically publishes the complete staged fixture directory.
EOF
  exit 2
}

fail() { echo "direct fixture builder failed: $*" >&2; exit 1; }
readonly registry_secret_name='fixture-builder-registry'
valid_run_id() { [[ "$1" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && ${#1} -le 24 ]]; }
valid_revision() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }
valid_version() { [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
valid_kernel_version() { [[ "$1" =~ ^[A-Za-z0-9._~-]+$ && "$1" != latest && "$1" != main ]]; }
valid_kernel_url() {
  [[ "$1" == https://*"?versionId=$2" ]] ||
    [[ "$1" =~ ^https://s3\.amazonaws\.com/spec\.ccfc\.min/firecracker-ci/[0-9]{8}-[0-9a-f]{12}-[0-9]+/x86_64/vmlinux-[0-9]+\.[0-9]+\.[0-9]+$ ]]
}
valid_epoch() { [[ "$1" =~ ^[0-9]+$ ]]; }
valid_bytes() { [[ "$1" =~ ^[0-9]+$ && "$1" -ge 1048576 ]]; }
valid_uuid() { [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; }
require_new_absolute() { [[ "$1" == /* && ! -e "$1" && -d "$(dirname "$1")" ]] || fail "$2 must be a new absolute path beneath an existing directory"; }
require_file() { [[ "$1" == /* && -f "$1" ]] || fail "$2 must be an existing absolute regular file"; }
valid_context() { [[ "$1" =~ ^[A-Za-z0-9@._:-]{1,128}$ ]]; }

validate_registry_docker_config() {
  local config="$1"
  python3 - "$config" <<'PY'
import base64
import json
import os
import re
import sys

path = sys.argv[1]
try:
    stat = os.stat(path)
    if stat.st_size <= 0 or stat.st_size > 1024 * 1024:
        raise ValueError('registry Docker config must be between 1 byte and 1 MiB')
    with open(path, encoding='utf-8') as handle:
        value = json.load(handle)
    entry = value['auths']['ghcr.io']
    encoded = entry['auth']
    if not isinstance(encoded, str) or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', encoded):
        raise ValueError('ghcr.io auth must be a base64 basic-auth value')
    decoded = base64.b64decode(encoded, validate=True).decode('utf-8')
    if ':' not in decoded or any(character in decoded for character in '\r\n'):
        raise ValueError('ghcr.io auth must decode to a single basic-auth identity')
except (OSError, KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit('registry Docker config is invalid: %s' % error)
PY
}

redact_logs() {
  python3 - <<'PY'
import re
import sys

text = sys.stdin.read(65536)
text = re.sub(r'(?i)(authorization|token|password|secret|auth)\s*([:=])\s*[^\s]+', r'\1\2[REDACTED]', text)
text = re.sub(r'(?i)bearer\s+[^\s]+', 'Bearer [REDACTED]', text)
text = re.sub(r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])', '[REDACTED]', text)
sys.stdout.write(text)
PY
}

render() {
  local run_id='' image='' revision='' firecracker_version='' kernel_url='' kernel_version_id='' epoch='' rootfs_bytes='' rootfs_uuid='' output=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run-id) run_id=$2; shift 2;; --image) image=$2; shift 2;; --revision) revision=$2; shift 2;;
      --firecracker-version) firecracker_version=$2; shift 2;; --kernel-url) kernel_url=$2; shift 2;;
      --kernel-version-id) kernel_version_id=$2; shift 2;;
      --source-date-epoch) epoch=$2; shift 2;; --rootfs-bytes) rootfs_bytes=$2; shift 2;;
      --rootfs-uuid) rootfs_uuid=$2; shift 2;; --output) output=$2; shift 2;; *) usage;;
    esac
  done
  [[ -n "$run_id" && -n "$image" && -n "$revision" && -n "$firecracker_version" && -n "$kernel_url" && -n "$kernel_version_id" && -n "$epoch" && -n "$rootfs_bytes" && -n "$rootfs_uuid" && -n "$output" ]] || usage
  valid_run_id "$run_id" || fail 'run ID must be a lowercase DNS label of at most 24 characters'
  [[ "$image" =~ ^ghcr\.io/0x63616c/agent-runtime-firecracker-fixture-builder@sha256:[0-9a-f]{64}$ ]] || fail 'image must be the pinned reviewed fixture-builder image'
  valid_revision "$revision" || fail 'revision must be an exact lowercase 40-character commit'
  valid_version "$firecracker_version" || fail 'Firecracker version must be an exact release version'
  valid_kernel_version "$kernel_version_id" || fail 'kernel version ID must be immutable'
  valid_kernel_url "$kernel_url" "$kernel_version_id" || fail 'kernel URL must bind the version ID or use the canonical Firecracker CI object'
  valid_epoch "$epoch" || fail 'source date epoch must be an integer'
  valid_bytes "$rootfs_bytes" || fail 'rootfs bytes must be an integer of at least 1048576'
  valid_uuid "$rootfs_uuid" || fail 'rootfs UUID must be lowercase canonical UUID'
  require_new_absolute "$output" output

  local namespace="agent-runtime-fixture-build-$run_id"
  [[ ${#namespace} -le 63 ]] || fail 'derived namespace is too long'
  cat >"$output" <<EOF
# Generated by direct-fixture-builder.sh. It is an offline-rendered manifest;
# apply only in one explicitly authorised direct home-server operation.
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  labels:
    app.kubernetes.io/part-of: agent-runtime
    agent-runtime.dev/direct-fixture-build: "$run_id"
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  namespace: $namespace
  name: default-deny
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: batch/v1
kind: Job
metadata:
  namespace: $namespace
  name: firecracker-fixture-builder
  labels:
    app.kubernetes.io/part-of: agent-runtime
    agent-runtime.dev/direct-fixture-build: "$run_id"
spec:
  # Rendered manifests cannot pull a private GHCR image accidentally. execute
  # creates this secret first and applies an unsuspended temporary copy.
  suspend: true
  backoffLimit: 0
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels:
        app.kubernetes.io/part-of: agent-runtime
        agent-runtime.dev/direct-fixture-build: "$run_id"
    spec:
      nodeSelector:
        kubernetes.io/os: linux
        kubernetes.io/arch: amd64
      automountServiceAccountToken: false
      imagePullSecrets:
        - name: $registry_secret_name
      restartPolicy: Never
      terminationGracePeriodSeconds: 10
      securityContext: { runAsUser: 0, runAsGroup: 0, fsGroup: 0 }
      containers:
        - name: assemble
          image: $image
          imagePullPolicy: Always
          command: ["/bin/sh", "-ec"]
          args:
            - |
              test "\$(uname -s)" = Linux
              test "\$(uname -m)" = x86_64
              test "\$(git -C /workspace rev-parse HEAD)" = "$revision"
              test -z "\$(git -C /workspace status --porcelain)"
              test ! -e /var/lib/agent-runtime/firecracker-fixtures/home-server
              test ! -e /var/lib/agent-runtime/firecracker-direct/fixture-source-map.json
              for input in firecracker.tgz vmlinux rootfs-builder.json; do
                test -f "/input-parent/home-server/\$input"
                test "\$(stat -c '%u %a' "/input-parent/home-server/\$input")" = '0 600'
              done
              python3 - /input-parent/home-server/rootfs-builder.json "$revision" <<'PY'
              import hashlib, json, pathlib, re, sys
              manifest, revision = sys.argv[1:]
              value = json.load(open(manifest, encoding='utf-8'))
              expected = {'schema_version','image','platform','required_commands','e2fsprogs_version','binutils_version','source_revision','dockerfile_sha256','inputs_lock_sha256'}
              commands = ['awk','grep','install','mke2fs','mkdir','mktemp','readelf','rm','sha256sum','tr','truncate','wc']
              if set(value) != expected or value['schema_version'] != 'agent-runtime.firecracker.rootfs-builder/v1': raise SystemExit('invalid reviewed rootfs builder manifest')
              if not re.fullmatch(r'ghcr\.io/0x63616c/agent-runtime-firecracker-rootfs-builder@sha256:[0-9a-f]{64}', value['image']) or value['platform'] != {'os':'linux','architecture':'amd64'} or value['source_revision'] != revision: raise SystemExit('rootfs builder manifest does not bind the reviewed source contract')
              if value['required_commands'] != commands or value['e2fsprogs_version'] != '1.47.2' or value['binutils_version'] != '2.44': raise SystemExit('rootfs builder manifest does not bind the reviewed toolchain')
              for field, path in [('dockerfile_sha256','/workspace/tools/firecracker/rootfs-builder/Dockerfile'), ('inputs_lock_sha256','/workspace/tools/firecracker/rootfs-builder/inputs.lock.json')]:
                if not re.fullmatch(r'sha256:[0-9a-f]{64}', value[field]) or value[field] != 'sha256:' + hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest(): raise SystemExit('rootfs builder manifest does not bind reviewed '+field)
              PY
              /workspace/tools/firecracker/rootfs-builder/verify-source.sh
              mke2fs -V 2>&1 | grep -F 'mke2fs 1.47.2' >/dev/null
              readelf --version 2>&1 | grep -F '2.44' >/dev/null
              work="\$(mktemp -d /work/fixture.XXXXXX)"
              trap 'rm -rf "\$work"' EXIT
              /workspace/tools/firecracker/build-guest-agent.sh "\$work/guest-agent"
              SOURCE_DATE_EPOCH=$epoch /workspace/tools/firecracker/build-rootfs.sh "\$work/guest-agent" "\$work/rootfs.ext4" $rootfs_bytes $rootfs_uuid "\$work/rootfs-attestation.json"
              /workspace/tools/firecracker/assemble-fixtures.sh "\$work/assembled" $revision $firecracker_version /input-parent/home-server/firecracker.tgz "$kernel_url" $kernel_version_id /input-parent/home-server/vmlinux "\$work/rootfs.ext4" "\$work/rootfs-attestation.json" $epoch
              stage=/var/lib/agent-runtime/firecracker-fixtures/.home-server-$run_id.staged
              test ! -e "\$stage"
              cp -a "\$work/assembled" "\$stage"
              find "\$stage" -type d -exec chown 0:0 {} + -exec chmod 0700 {} +
              find "\$stage" -type f -exec chown 0:0 {} + -exec chmod 0600 {} +
              mv "\$stage" /var/lib/agent-runtime/firecracker-fixtures/home-server
              install -d -o 0 -g 0 -m 0700 /var/lib/agent-runtime/firecracker-direct
              /workspace/tools/firecracker/write-direct-fixture-source-map.sh /var/lib/agent-runtime/firecracker-fixtures/home-server /var/lib/agent-runtime/firecracker-direct/fixture-source-map.json
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"] }
          resources:
            requests: { cpu: "1000m", memory: "1024Mi" }
            limits: { cpu: "2000m", memory: "2048Mi" }
          volumeMounts:
            - { name: work, mountPath: /work }
            - { name: inputs, mountPath: /input-parent, readOnly: true }
            - { name: fixtures, mountPath: /var/lib/agent-runtime/firecracker-fixtures }
            - { name: direct-authority, mountPath: /var/lib/agent-runtime/firecracker-direct }
      volumes:
        - name: work
          emptyDir: { sizeLimit: 2Gi }
        - name: inputs
          hostPath: { path: /var/lib/agent-runtime/firecracker-fixture-inputs, type: Directory }
        - name: fixtures
          hostPath: { path: /var/lib/agent-runtime/firecracker-fixtures, type: DirectoryOrCreate }
        - name: direct-authority
          hostPath: { path: /var/lib/agent-runtime/firecracker-direct, type: DirectoryOrCreate }
EOF
}

execute() {
  local run_id='' image='' revision='' firecracker_version='' kernel_url='' kernel_version_id='' epoch='' rootfs_bytes='' rootfs_uuid='' kubeconfig='' context_value='' registry_docker_config='' evidence='' authorized=false manifest='' active_manifest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run-id) run_id=${2:-}; shift 2;; --image) image=${2:-}; shift 2;; --revision) revision=${2:-}; shift 2;;
      --firecracker-version) firecracker_version=${2:-}; shift 2;; --kernel-url) kernel_url=${2:-}; shift 2;;
      --kernel-version-id) kernel_version_id=${2:-}; shift 2;; --source-date-epoch) epoch=${2:-}; shift 2;;
      --rootfs-bytes) rootfs_bytes=${2:-}; shift 2;; --rootfs-uuid) rootfs_uuid=${2:-}; shift 2;;
      --kubeconfig) kubeconfig=${2:-}; shift 2;; --context) context_value=${2:-}; shift 2;;
      --registry-docker-config) registry_docker_config=${2:-}; shift 2;; --evidence-file) evidence=${2:-}; shift 2;;
      --execute-authorized-direct-fixture-build) authorized=true; shift;; *) usage;;
    esac
  done
  [[ "$authorized" == true && -n "$run_id" && -n "$image" && -n "$revision" && -n "$firecracker_version" && -n "$kernel_url" && -n "$kernel_version_id" && -n "$epoch" && -n "$rootfs_bytes" && -n "$rootfs_uuid" && -n "$kubeconfig" && -n "$context_value" && -n "$registry_docker_config" && -n "$evidence" ]] || usage
  valid_run_id "$run_id" || fail 'run ID must be a lowercase DNS label of at most 24 characters'
  valid_context "$context_value" || fail 'invalid Kubernetes context'
  require_file "$kubeconfig" 'kubeconfig'
  require_file "$registry_docker_config" 'registry Docker config'
  validate_registry_docker_config "$registry_docker_config"
  require_new_absolute "$evidence" 'evidence file'
  command -v kubectl >/dev/null || fail 'kubectl is required'
  command -v jq >/dev/null || fail 'jq is required'

  local namespace="agent-runtime-fixture-build-$run_id" job='firecracker-fixture-builder'
  kubectl --kubeconfig "$kubeconfig" config get-contexts -o name | grep -Fx -- "$context_value" >/dev/null || fail 'explicit context is unavailable'
  [[ -z "$(kubectl --kubeconfig "$kubeconfig" --context "$context_value" get "namespace/$namespace" --ignore-not-found -o name)" ]] || fail 'namespace already exists; fixture builder will not take it over'

  manifest="$(mktemp)"; active_manifest="$(mktemp)"
  rm -f -- "$manifest" "$active_manifest"
  trap 'rm -f -- "${manifest:-}" "${active_manifest:-}"' EXIT
  # The public render path always writes a suspended Job. This private copy is
  # the only one made runnable, and only after the secret exists in its new
  # namespace.
  render --run-id "$run_id" --image "$image" --revision "$revision" --firecracker-version "$firecracker_version" --kernel-url "$kernel_url" --kernel-version-id "$kernel_version_id" --source-date-epoch "$epoch" --rootfs-bytes "$rootfs_bytes" --rootfs-uuid "$rootfs_uuid" --output "$manifest"
  sed 's/^  suspend: true$/  suspend: false/' "$manifest" >"$active_manifest"
  grep -Fqx '  suspend: false' "$active_manifest" || fail 'could not prepare explicit runnable fixture builder manifest'

  local cleanup=true namespace_created=false result=0 status='' logs=''
  trap 'if [[ "${cleanup:-false}" == true && "${namespace_created:-false}" == true ]]; then kubectl --kubeconfig "$kubeconfig" --context "$context_value" delete "namespace/$namespace" --ignore-not-found --wait=false >/dev/null 2>&1 || true; kubectl --kubeconfig "$kubeconfig" --context "$context_value" wait --for=delete "namespace/$namespace" --timeout=180s >/dev/null 2>&1 || echo "fixture builder cleanup failed; delete namespace $namespace" >&2; fi; rm -f -- "${manifest:-}" "${active_manifest:-}"' EXIT
  kubectl --kubeconfig "$kubeconfig" --context "$context_value" create namespace "$namespace" >/dev/null
  namespace_created=true
  kubectl --kubeconfig "$kubeconfig" --context "$context_value" label "namespace/$namespace" \
    app.kubernetes.io/part-of=agent-runtime \
    "agent-runtime.dev/direct-fixture-build=$run_id" \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/audit=privileged \
    pod-security.kubernetes.io/warn=privileged >/dev/null
  kubectl --kubeconfig "$kubeconfig" --context "$context_value" --namespace "$namespace" create secret generic "$registry_secret_name" \
    --type=kubernetes.io/dockerconfigjson \
    --from-file=.dockerconfigjson="$registry_docker_config" \
    --dry-run=client -o yaml | kubectl --kubeconfig "$kubeconfig" --context "$context_value" apply -f - >/dev/null
  kubectl --kubeconfig "$kubeconfig" --context "$context_value" --namespace "$namespace" patch "secret/$registry_secret_name" --type merge -p '{"immutable":true}' >/dev/null
  if ! kubectl --kubeconfig "$kubeconfig" --context "$context_value" apply -f "$active_manifest" >/dev/null; then
    result=1
  elif ! kubectl --kubeconfig "$kubeconfig" --context "$context_value" wait --for=condition=complete "job/$job" --namespace "$namespace" --timeout=900s >/dev/null; then
    result=1
  fi
  status="$(kubectl --kubeconfig "$kubeconfig" --context "$context_value" get "job/$job" --namespace "$namespace" -o jsonpath='{.status.conditions[0].type}' 2>/dev/null || true)"
  logs="$(kubectl --kubeconfig "$kubeconfig" --context "$context_value" logs "job/$job" --namespace "$namespace" --timestamps 2>&1 | redact_logs || true)"
  jq -n --arg namespace "$namespace" --arg job "$job" --arg context "$context_value" --arg image "$image" --arg revision "$revision" --arg status "$status" --arg logs "$logs" --arg registry_secret "$registry_secret_name" --argjson succeeded "$( [[ "$result" == 0 ]] && echo true || echo false )" \
    '{version:1,kind:"agent-runtime.direct-fixture-build/v1",namespace:$namespace,job:$job,context:$context,image:$image,revision:$revision,image_pull_secret:$registry_secret,job_status:$status,succeeded:$succeeded,redacted_logs:$logs,cleanup:"namespace deletion follows this record"}' >"$evidence"
  kubectl --kubeconfig "$kubeconfig" --context "$context_value" delete "namespace/$namespace" --wait=false >/dev/null
  kubectl --kubeconfig "$kubeconfig" --context "$context_value" wait --for=delete "namespace/$namespace" --timeout=180s >/dev/null
  cleanup=false
  [[ "$result" == 0 ]] || fail "fixture builder did not complete; redacted logs are in $evidence"
  echo "fixture builder completed; evidence: $evidence"
}

self_test() {
  local tmp manifest digest invalid_registry
  tmp="$(mktemp -d)"; trap 'rm -rf -- "${tmp:-}"' EXIT
  manifest="$tmp/fixture-builder.yaml"
  invalid_registry="$tmp/invalid-registry.json"
  printf '%s\n' '{"auths":{"ghcr.io":{"auth":"not-base64!"}}}' >"$invalid_registry"
  digest="$(printf 'a%.0s' {1..64})"
  render --run-id fixture-test --image "ghcr.io/0x63616c/agent-runtime-firecracker-fixture-builder@sha256:$digest" --revision "$(git rev-parse HEAD)" --firecracker-version v1.16.1 --kernel-url https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260717-5ac3f5ffdcd7-0/x86_64/vmlinux-6.18.36 --kernel-version-id S8eTJ2TzOZVY__PbUPFfdzt2az2_GIqL --source-date-epoch 1704067200 --rootfs-bytes 16777216 --rootfs-uuid 00000000-0000-0000-0000-000000000001 --output "$manifest"
  grep -Fqx '  policyTypes: [Ingress, Egress]' "$manifest"
  grep -Fqx '      automountServiceAccountToken: false' "$manifest"
  grep -Fqx '  suspend: true' "$manifest"
  grep -Fqx "        - name: $registry_secret_name" "$manifest"
  grep -Fqx '            readOnlyRootFilesystem: true' "$manifest"
  grep -Fqx '            capabilities: { drop: ["ALL"] }' "$manifest"
  grep -Fqx '    pod-security.kubernetes.io/enforce: privileged' "$manifest"
  grep -Fqx '        kubernetes.io/os: linux' "$manifest"
  grep -Fqx '        kubernetes.io/arch: amd64' "$manifest"
  grep -Fqx '          hostPath: { path: /var/lib/agent-runtime/firecracker-fixtures, type: DirectoryOrCreate }' "$manifest"
  grep -Fq '/workspace/tools/firecracker/assemble-fixtures.sh "$work/assembled"' "$manifest"
  grep -Fq '/workspace/tools/firecracker/write-direct-fixture-source-map.sh /var/lib/agent-runtime/firecracker-fixtures/home-server /var/lib/agent-runtime/firecracker-direct/fixture-source-map.json' "$manifest"
  if "$0" render --run-id bad_ID --image "ghcr.io/0x63616c/agent-runtime-firecracker-fixture-builder@sha256:$digest" --revision "$(git rev-parse HEAD)" --firecracker-version v1.16.1 --kernel-url https://example.invalid/vmlinux?versionId=abc --kernel-version-id abc --source-date-epoch 1704067200 --rootfs-bytes 16777216 --rootfs-uuid 00000000-0000-0000-0000-000000000001 --output "$tmp/bad.yaml" >/dev/null 2>&1; then fail 'accepted invalid run ID'; fi
  if "$0" render --run-id fixture-test --image ghcr.io/0x63616c/agent-runtime-firecracker-fixture-builder:latest --revision "$(git rev-parse HEAD)" --firecracker-version v1.16.1 --kernel-url https://example.invalid/vmlinux?versionId=abc --kernel-version-id abc --source-date-epoch 1704067200 --rootfs-bytes 16777216 --rootfs-uuid 00000000-0000-0000-0000-000001 --output "$tmp/bad.yaml" >/dev/null 2>&1; then fail 'accepted unpinned image'; fi
  if "$0" execute --run-id fixture-test --image "ghcr.io/0x63616c/agent-runtime-firecracker-fixture-builder@sha256:$digest" --revision "$(git rev-parse HEAD)" --firecracker-version v1.16.1 --kernel-url https://example.invalid/vmlinux?versionId=abc --kernel-version-id abc --source-date-epoch 1704067200 --rootfs-bytes 16777216 --rootfs-uuid 00000000-0000-0000-0000-000000000001 --kubeconfig /dev/null --context home-server --registry-docker-config /dev/null --evidence-file "$tmp/evidence.json" >/dev/null 2>&1; then fail 'execute accepted no explicit authorization flag'; fi
  if "$0" execute --run-id fixture-test --image "ghcr.io/0x63616c/agent-runtime-firecracker-fixture-builder@sha256:$digest" --revision "$(git rev-parse HEAD)" --firecracker-version v1.16.1 --kernel-url https://example.invalid/vmlinux?versionId=abc --kernel-version-id abc --source-date-epoch 1704067200 --rootfs-bytes 16777216 --rootfs-uuid 00000000-0000-0000-0000-000000000001 --kubeconfig /dev/null --context home-server --registry-docker-config "$invalid_registry" --evidence-file "$tmp/evidence.json" --execute-authorized-direct-fixture-build >/dev/null 2>&1; then fail 'execute accepted an invalid registry config'; fi
  echo 'direct fixture builder renders a suspended, pinned no-network job and refuses implicit execution'
}

case "${1:-}" in
  render) shift; render "$@";;
  execute) shift; execute "$@";;
  --self-test) self_test;;
  *) usage;;
esac
