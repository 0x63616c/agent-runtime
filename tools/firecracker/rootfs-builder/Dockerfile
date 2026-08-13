# Linux/amd64-only builder for the deterministic Firecracker smoke rootfs.
# The base image and each direct package are pinned in inputs.lock.json and
# checked by verify-source.sh before any build is allowed.
FROM docker.io/library/alpine@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6

RUN apk add --no-cache \
    --repository https://dl-cdn.alpinelinux.org/alpine/v3.22/main \
    binutils=2.44-r3 \
    coreutils=9.7-r1 \
    e2fsprogs=1.47.2-r2
