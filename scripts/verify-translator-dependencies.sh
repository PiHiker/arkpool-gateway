#!/bin/sh
# Input: cargo tree --locked -p translator_sv2 --no-default-features \
#          --edges normal --prefix none --format '{p}'
set -eu
[ "$#" -eq 1 ] && [ -s "$1" ] || { echo 'Missing translator dependency graph' >&2; exit 1; }
# Keep unused HTTP/ASIC telemetry, TLS and protobuf stacks out of this build.
if grep -Eq '^(asic-rs|axum|prometheus|protobuf|quinn|quinn-proto|quinn-udp|reqwest|rustls|rustls-webpki|webpki-roots|webpki-root-certs) v' "$1"; then
    echo 'Unexpected monitoring dependency in translator runtime graph' >&2
    exit 1
fi
grep -Eq '^translator_sv2 v0\.8\.0( |$)' "$1" || { echo 'Unexpected translator source' >&2; exit 1; }
grep -Eq '^tokio v1\.53\.3( |$)' "$1" || { echo 'Patched Tokio missing' >&2; exit 1; }
if grep -E '^tokio v' "$1" | grep -Evq '^tokio v1\.53\.3( |$)'; then
    echo 'Unexpected Tokio version' >&2; exit 1
fi
if grep -E '^anyhow v' "$1" | grep -Evq '^anyhow v1\.0\.103( |$)'; then
    echo 'Unexpected anyhow version' >&2; exit 1
fi
echo 'PASS: bounded translator dependency graph, patched Tokio/anyhow'
