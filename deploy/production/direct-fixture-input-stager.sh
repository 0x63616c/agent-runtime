#!/usr/bin/env bash
# Renders or explicitly runs the short-lived, privileged input-staging Job for
# the direct home-server Firecracker fixture build.  The fixture builder itself
# remains offline: this is its only reviewed network boundary.
set -euo pipefail

readonly firecracker_url='https://github.com/firecracker-microvm/firecracker/releases/download/v1.16.1/firecracker-v1.16.1-x86_64.tgz'
readonly firecracker_sha256='382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6'
readonly firecracker_size_bytes='7486686'
readonly kernel_url='https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260717-5ac3f5ffdcd7-0/x86_64/vmlinux-6.18.36'
readonly kernel_version_id='S8eTJ2TzOZVY__PbUPFfdzt2az2_GIqL'
readonly kernel_sha256='cd77172a1073b3da1c714496ee02f1f23a70fbd002588071581f14df5be9d22e'
readonly kernel_size_bytes='27680232'
# These platform-specific image manifests are deliberately pinned rather than
# a multi-platform index: the Job only schedules to Linux/amd64.
readonly curl_image='docker.io/curlimages/curl@sha256:88a9abad9d958340e48564f9bdcdaa29916a2984be59314da709f8bbc0eef6f7'
readonly verifier_image='rancher/mirrored-library-busybox@sha256:101b4afd76732482eff9b95cae5f94bcf295e521fbec4e01b69c5421f3f3f3e5'
readonly host_input_parent='/var/lib/agent-runtime/firecracker-fixture-inputs'
readonly host_input_directory='/var/lib/agent-runtime/firecracker-fixture-inputs/home-server'

usage() {
  cat >&2 <<'EOF'
usage:
  direct-fixture-input-stager.sh render \
    --run-id ID --revision GIT-SHA \
    --rootfs-builder-manifest /absolute/rootfs-builder.json \
    --output /absolute/manifest.yaml
  direct-fixture-input-stager.sh execute \
    --run-id ID --revision GIT-SHA \
    --rootfs-builder-manifest /absolute/rootfs-builder.json \
    --kubeconfig /absolute/KUBECONFIG --context CONTEXT \
    --evidence-file /absolute/EVIDENCE.json \
    --execute-authorized-direct-fixture-input-stage
  direct-fixture-input-stager.sh --self-test

render is offline: it only writes a new manifest. execute is the only
mutating mode and requires its literal consent flag. It creates one uniquely
named privileged namespace, downloads only the pinned Firecracker v1.16.1
archive and reviewed kernel over HTTPS, verifies the exact digest, byte size,
and kernel S3 VersionId before atomically publishing root-owned 0600 inputs,
then deletes and waits for deletion of that namespace even on failure.

The sole host path it may create is:
  /var/lib/agent-runtime/firecracker-fixture-inputs/home-server

The following fixed identities are not caller-configurable:
  Firecracker archive SHA-256: 382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6
  Firecracker archive bytes:  7486686
  Kernel SHA-256:             cd77172a1073b3da1c714496ee02f1f23a70fbd002588071581f14df5be9d22e
  Kernel bytes:               27680232
  Kernel VersionId:           S8eTJ2TzOZVY__PbUPFfdzt2az2_GIqL
EOF
  exit 2
}

fail() { echo "direct fixture input stager failed: $*" >&2; exit 1; }
valid_run_id() { [[ "$1" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && ${#1} -le 24 ]]; }
valid_revision() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }
valid_context() { [[ "$1" =~ ^[A-Za-z0-9@._:-]{1,128}$ ]]; }
require_file() { [[ "$1" == /* && -f "$1" ]] || fail "$2 must be an existing absolute regular file"; }
require_new_absolute() { [[ "$1" == /* && ! -e "$1" ]] || fail "$2 must be a new absolute path"; mkdir -p "$(dirname "$1")"; }

identity() {
  local run_id="$1"
  valid_run_id "$run_id" || fail 'run ID must be a lowercase DNS label of at most 24 characters'
  namespace="agent-runtime-fixture-input-$run_id"
  job='firecracker-fixture-input-stager'
  [[ ${#namespace} -le 63 ]] || fail 'derived namespace is too long'
}

validate_rootfs_builder_manifest() {
  local manifest="$1" revision="$2"
  python3 - "$manifest" "$revision" <<'PY'
import json
import re
import sys

path, revision = sys.argv[1:]
expected_keys = {
    'schema_version', 'image', 'platform', 'required_commands',
    'e2fsprogs_version', 'binutils_version', 'source_revision',
    'dockerfile_sha256', 'inputs_lock_sha256',
}
commands = ['awk', 'grep', 'install', 'mke2fs', 'mkdir', 'mktemp', 'readelf', 'rm', 'sha256sum', 'tr', 'truncate', 'wc']
try:
    with open(path, encoding='utf-8') as handle:
        value = json.load(handle)
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit('rootfs builder manifest is unreadable: %s' % error)
if not isinstance(value, dict) or set(value) != expected_keys:
    raise SystemExit('rootfs builder manifest must have exactly the v1 fields')
if value['schema_version'] != 'agent-runtime.firecracker.rootfs-builder/v1':
    raise SystemExit('rootfs builder manifest has an unsupported schema')
if not isinstance(value['image'], str) or not re.fullmatch(r'ghcr\.io/0x63616c/agent-runtime-firecracker-rootfs-builder@sha256:[0-9a-f]{64}', value['image']):
    raise SystemExit('rootfs builder manifest must pin the reviewed project image')
if value['platform'] != {'os': 'linux', 'architecture': 'amd64'}:
    raise SystemExit('rootfs builder manifest must select linux/amd64')
if value['required_commands'] != commands or value['e2fsprogs_version'] != '1.47.2' or value['binutils_version'] != '2.44':
    raise SystemExit('rootfs builder manifest does not bind the reviewed toolchain')
if value['source_revision'] != revision:
    raise SystemExit('rootfs builder manifest source revision does not match this fixture build')
for key in ('dockerfile_sha256', 'inputs_lock_sha256'):
    if not isinstance(value[key], str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', value[key]):
        raise SystemExit('rootfs builder manifest has an invalid %s' % key)
PY
}

render() {
  local run_id='' revision='' builder_manifest='' output='' manifest_contents=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run-id) run_id=${2:-}; shift 2;; --revision) revision=${2:-}; shift 2;;
      --rootfs-builder-manifest) builder_manifest=${2:-}; shift 2;; --output) output=${2:-}; shift 2;;
      *) usage;;
    esac
  done
  [[ -n "$run_id" && -n "$revision" && -n "$builder_manifest" && -n "$output" ]] || usage
  identity "$run_id"; valid_revision "$revision" || fail 'revision must be an exact lowercase 40-character commit'
  require_file "$builder_manifest" 'rootfs builder manifest'
  validate_rootfs_builder_manifest "$builder_manifest" "$revision"
  require_new_absolute "$output" 'output'
  manifest_contents="$(cat "$builder_manifest")"

  cat >"$output" <<EOF
# Generated by direct-fixture-input-stager.sh. Apply only through execute.
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  labels:
    app.kubernetes.io/part-of: agent-runtime
    agent-runtime.dev/direct-fixture-input-stage: "$run_id"
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
---
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: $namespace
  name: rootfs-builder-manifest
immutable: true
data:
  rootfs-builder.json: |
$(printf '%s\n' "$manifest_contents" | sed 's/^/    /')
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
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  namespace: $namespace
  name: stager-egress
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: fixture-input-stager
  policyTypes: [Egress]
  egress:
    - ports:
        - { protocol: TCP, port: 443 }
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
---
apiVersion: batch/v1
kind: Job
metadata:
  namespace: $namespace
  name: $job
  labels:
    app.kubernetes.io/part-of: agent-runtime
    agent-runtime.dev/direct-fixture-input-stage: "$run_id"
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 300
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels:
        app.kubernetes.io/part-of: agent-runtime
        app.kubernetes.io/component: fixture-input-stager
        agent-runtime.dev/direct-fixture-input-stage: "$run_id"
    spec:
      nodeSelector:
        kubernetes.io/os: linux
        kubernetes.io/arch: amd64
      automountServiceAccountToken: false
      hostNetwork: false
      restartPolicy: Never
      terminationGracePeriodSeconds: 10
      initContainers:
        - name: fetch-pinned-inputs
          image: $curl_image
          imagePullPolicy: Always
          command: ["curl"]
          args:
            - --fail
            - --silent
            - --show-error
            - --location
            - --proto
            - =https
            - --tlsv1.2
            - --connect-timeout
            - "15"
            - --max-time
            - "180"
            - --retry
            - "0"
            - --output
            - /download/firecracker.tgz
            - $firecracker_url
            - --dump-header
            - /download/kernel.headers
            - --output
            - /download/vmlinux
            - $kernel_url
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"] }
          resources:
            requests: { cpu: "100m", memory: "128Mi" }
            limits: { cpu: "500m", memory: "256Mi" }
          volumeMounts:
            - { name: download, mountPath: /download }
      containers:
        - name: verify-and-stage
          image: $verifier_image
          imagePullPolicy: Always
          command: ["/bin/sh", "-ec"]
          args:
            - |
              umask 077
              test ! -e $host_input_directory
              test -f /download/firecracker.tgz
              test -f /download/vmlinux
              test -f /download/kernel.headers
              test "\$(sha256sum /download/firecracker.tgz | awk '{print \$1}')" = '$firecracker_sha256'
              test "\$(wc -c < /download/firecracker.tgz | tr -d ' ')" = '$firecracker_size_bytes'
              test "\$(sha256sum /download/vmlinux | awk '{print \$1}')" = '$kernel_sha256'
              test "\$(wc -c < /download/vmlinux | tr -d ' ')" = '$kernel_size_bytes'
              tr -d '\\r' < /download/kernel.headers | grep -E -i '^x-amz-version-id: $kernel_version_id$' >/dev/null
              test -f /rootfs-builder/rootfs-builder.json
              stage=$host_input_parent/.home-server-$run_id.staged
              test ! -e "\$stage"
              mkdir -m 0700 "\$stage"
              cp /download/firecracker.tgz "\$stage/firecracker.tgz"
              cp /download/vmlinux "\$stage/vmlinux"
              cp /rootfs-builder/rootfs-builder.json "\$stage/rootfs-builder.json"
              chown 0:0 "\$stage"/*
              chmod 0600 "\$stage"/*
              for input in firecracker.tgz vmlinux rootfs-builder.json; do
                test "\$(stat -c '%u %a' "\$stage/\$input")" = '0 600'
              done
              mv "\$stage" $host_input_directory
              test "\$(stat -c '%u %a' $host_input_directory)" = '0 700'
              echo 'pinned Firecracker fixture inputs staged'
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            privileged: true
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: true
            capabilities: { drop: ["ALL"] }
          resources:
            requests: { cpu: "100m", memory: "128Mi" }
            limits: { cpu: "500m", memory: "256Mi" }
          volumeMounts:
            - { name: download, mountPath: /download, readOnly: true }
            - { name: rootfs-builder, mountPath: /rootfs-builder, readOnly: true }
            - { name: host-inputs, mountPath: $host_input_parent }
      volumes:
        - name: download
          emptyDir: { sizeLimit: 64Mi }
        - name: rootfs-builder
          configMap: { name: rootfs-builder-manifest }
        - name: host-inputs
          hostPath: { path: $host_input_parent, type: DirectoryOrCreate }
EOF
}

execute() {
  local run_id='' revision='' builder_manifest='' kubeconfig='' context_value='' evidence='' authorized=false manifest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run-id) run_id=${2:-}; shift 2;; --revision) revision=${2:-}; shift 2;;
      --rootfs-builder-manifest) builder_manifest=${2:-}; shift 2;; --kubeconfig) kubeconfig=${2:-}; shift 2;;
      --context) context_value=${2:-}; shift 2;; --evidence-file) evidence=${2:-}; shift 2;;
      --execute-authorized-direct-fixture-input-stage) authorized=true; shift;; *) usage;;
    esac
  done
  [[ "$authorized" == true && -n "$run_id" && -n "$revision" && -n "$builder_manifest" && -n "$kubeconfig" && -n "$context_value" && -n "$evidence" ]] || usage
  identity "$run_id"; valid_revision "$revision" || fail 'revision must be an exact lowercase 40-character commit'; valid_context "$context_value" || fail 'invalid Kubernetes context'
  require_file "$builder_manifest" 'rootfs builder manifest'; validate_rootfs_builder_manifest "$builder_manifest" "$revision"
  require_file "$kubeconfig" 'kubeconfig'; require_new_absolute "$evidence" 'evidence file'
  command -v kubectl >/dev/null || fail 'kubectl is required'; command -v jq >/dev/null || fail 'jq is required'
  kubectl --kubeconfig "$kubeconfig" config get-contexts -o name | grep -Fx -- "$context_value" >/dev/null || fail 'explicit context is unavailable'
  [[ -z "$(kubectl --kubeconfig "$kubeconfig" --context "$context_value" get "namespace/$namespace" --ignore-not-found -o name)" ]] || fail 'namespace already exists; stager will not take it over'
  manifest="$(mktemp)"
  rm -f -- "$manifest"
  trap 'rm -f -- "${manifest:-}"' EXIT
  render --run-id "$run_id" --revision "$revision" --rootfs-builder-manifest "$builder_manifest" --output "$manifest"
  local cleanup=true result=0 status logs
  trap 'if [[ "${cleanup:-false}" == true ]]; then kubectl --kubeconfig "$kubeconfig" --context "$context_value" delete "namespace/$namespace" --ignore-not-found --wait=false >/dev/null || true; kubectl --kubeconfig "$kubeconfig" --context "$context_value" wait --for=delete "namespace/$namespace" --timeout=180s >/dev/null 2>&1 || echo "fixture input-stager cleanup failed; delete namespace $namespace" >&2; fi; rm -f -- "${manifest:-}"' EXIT
  kubectl --kubeconfig "$kubeconfig" --context "$context_value" apply -f "$manifest" >/dev/null
  if ! kubectl --kubeconfig "$kubeconfig" --context "$context_value" wait --for=condition=complete "job/$job" --namespace "$namespace" --timeout=330s >/dev/null; then result=1; fi
  status="$(kubectl --kubeconfig "$kubeconfig" --context "$context_value" get "job/$job" --namespace "$namespace" -o jsonpath='{.status.conditions[0].type}' 2>/dev/null || true)"
  logs="$(kubectl --kubeconfig "$kubeconfig" --context "$context_value" logs "job/$job" --namespace "$namespace" --timestamps 2>&1 | head -c 65536 || true)"
  jq -n --arg namespace "$namespace" --arg job "$job" --arg context "$context_value" --arg status "$status" --arg logs "$logs" --argjson succeeded "$([[ "$result" == 0 ]] && echo true || echo false)" \
    '{version:1,kind:"agent-runtime.direct-fixture-input-stage/v1",namespace:$namespace,job:$job,context:$context,firecracker:{version:"v1.16.1",sha256:"382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6",size_bytes:7486686},kernel:{version_id:"S8eTJ2TzOZVY__PbUPFfdzt2az2_GIqL",sha256:"cd77172a1073b3da1c714496ee02f1f23a70fbd002588071581f14df5be9d22e",size_bytes:27680232},job_status:$status,succeeded:$succeeded,redacted_logs:$logs,cleanup:"namespace deletion follows this record"}' >"$evidence"
  kubectl --kubeconfig "$kubeconfig" --context "$context_value" delete "namespace/$namespace" --wait=false >/dev/null
  kubectl --kubeconfig "$kubeconfig" --context "$context_value" wait --for=delete "namespace/$namespace" --timeout=180s >/dev/null
  cleanup=false
  [[ "$result" == 0 ]] || fail "fixture input-stager did not complete; redacted logs are in $evidence"
  echo "fixture inputs staged; evidence: $evidence"
}

self_test() {
  local tmp manifest rootfs_manifest revision digest
  tmp="$(mktemp -d)"; trap 'rm -rf -- "${tmp:-}"' EXIT
  revision='0123456789abcdef0123456789abcdef01234567'
  digest="$(printf 'a%.0s' {1..64})"
  rootfs_manifest="$tmp/rootfs-builder.json"
  cat >"$rootfs_manifest" <<EOF
{"schema_version":"agent-runtime.firecracker.rootfs-builder/v1","image":"ghcr.io/0x63616c/agent-runtime-firecracker-rootfs-builder@sha256:$digest","platform":{"os":"linux","architecture":"amd64"},"required_commands":["awk","grep","install","mke2fs","mkdir","mktemp","readelf","rm","sha256sum","tr","truncate","wc"],"e2fsprogs_version":"1.47.2","binutils_version":"2.44","source_revision":"$revision","dockerfile_sha256":"sha256:$digest","inputs_lock_sha256":"sha256:$digest"}
EOF
  manifest="$tmp/stager.yaml"
  render --run-id fixture-input-test --revision "$revision" --rootfs-builder-manifest "$rootfs_manifest" --output "$manifest"
  grep -Fqx '    pod-security.kubernetes.io/enforce: privileged' "$manifest"
  grep -Fqx '  policyTypes: [Ingress, Egress]' "$manifest"
  grep -Fqx '      hostNetwork: false' "$manifest"
  grep -Fqx '      automountServiceAccountToken: false' "$manifest"
  grep -Fqx '            runAsUser: 0' "$manifest"
  grep -Fqx '            runAsGroup: 0' "$manifest"
  grep -Fqx "          image: $curl_image" "$manifest"
  grep -Fqx "          image: $verifier_image" "$manifest"
  grep -Fqx "              test \"\$(sha256sum /download/firecracker.tgz | awk '{print \$1}')\" = '$firecracker_sha256'" "$manifest"
  grep -Fqx "              test \"\$(wc -c < /download/vmlinux | tr -d ' ')\" = '$kernel_size_bytes'" "$manifest"
  grep -Fqx "              tr -d '\\r' < /download/kernel.headers | grep -E -i '^x-amz-version-id: $kernel_version_id\$' >/dev/null" "$manifest"
  grep -Fqx "          hostPath: { path: $host_input_parent, type: DirectoryOrCreate }" "$manifest"
  if "$0" render --run-id bad_ID --revision "$revision" --rootfs-builder-manifest "$rootfs_manifest" --output "$tmp/bad.yaml" >/dev/null 2>&1; then fail 'accepted an invalid run ID'; fi
  if "$0" render --run-id fixture-input-test --revision "$revision" --rootfs-builder-manifest "$rootfs_manifest" --output "$tmp/stager.yaml" >/dev/null 2>&1; then fail 'overwrote an existing manifest'; fi
  if "$0" execute --run-id fixture-input-test --revision "$revision" --rootfs-builder-manifest "$rootfs_manifest" --kubeconfig /dev/null --context home-server --evidence-file "$tmp/evidence.json" >/dev/null 2>&1; then fail 'execute accepted no explicit authorization flag'; fi
  echo 'direct fixture input stager renders a pinned, verified, disposable staging job and refuses implicit execution'
}

case "${1:-}" in
  render) shift; render "$@";;
  execute) shift; execute "$@";;
  --self-test) self_test;;
  *) usage;;
esac
