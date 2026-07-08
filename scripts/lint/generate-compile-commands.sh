#!/usr/bin/env bash
set -euo pipefail
# Generate compile_commands.json by wrapping make with Bear.
# Usage: ./generate-compile-commands.sh <build-cmd>
#
# Note: the default build command explicitly targets `build_src` rather than
# relying on GNU make's default goal. Invoking `bear -- make` with no target
# would re-enter whatever the default goal is — which, if it ever happens to
# be `lint-generate-cdb` (the target that calls this script), produces an
# exponential fork bomb under `-j$(nproc)` because every recursive invocation
# also wraps its own recursive invocation in Bear's exec intercept.

BUILD_CMD=${1:-"make build_src -j$(nproc)"}

if ! command -v bear >/dev/null 2>&1; then
  echo "bear is required. Install it (e.g. apt install bear)" >&2
  exit 1
fi

echo "Running: bear -- ${BUILD_CMD}"
rm -f compile_commands.json
bear -- ${BUILD_CMD}
echo "compile_commands.json generated"
