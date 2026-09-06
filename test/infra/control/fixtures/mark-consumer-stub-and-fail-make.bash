#!/usr/bin/env bash
set -euo pipefail

mkdir -p "$(dirname -- "${CONSUMER_STUB_MARKER}")"
: > "${CONSUMER_STUB_MARKER}"
exit 1
