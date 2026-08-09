#!/bin/sh

# Builds the project-owned smoke guest agent without downloading a guest image
# or resolving ambient OS packages. The caller records the Go toolchain and
# resulting digest in firecracker.fixtures/v2; this script never edits a lock.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OUTPUT" >&2
    exit 2
fi

output=$1
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
    -trimpath \
    -buildvcs=false \
    -ldflags='-buildid=' \
    -o "$output" \
    ./tools/firecracker/guest-agent
