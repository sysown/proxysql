#!/usr/bin/env bash
set -euo pipefail
# Generate compile_commands.json by wrapping make with Bear.
# Usage: ./generate-compile-commands.sh <build-cmd>

BUILD_CMD=${1:-"make -j$(nproc)"}

if ! command -v bear >/dev/null 2>&1; then
  echo "bear is required. Install it (e.g. apt install bear)" >&2
  exit 1
fi

echo "Running: bear -- ${BUILD_CMD}"
rm -f compile_commands.json
bear -- ${BUILD_CMD}
echo "compile_commands.json generated"
