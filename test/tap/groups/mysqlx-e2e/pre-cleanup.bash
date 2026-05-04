#!/usr/bin/env bash
set -e
echo "=== mysqlx-e2e: Cleaning up dbdeployer sandbox ==="

# Find and stop the MySQL 8.4 sandbox. Derive the version from the sandbox
# directory rather than hardcoding a patch level — setup-infras.bash uses
# `--newest`, so the version may be any 8.4.x.
SANDBOX_DIR=$(ls -d $HOME/sandboxes/msb_8_4_*/ 2>/dev/null | head -1)
if [ -n "$SANDBOX_DIR" ]; then
    if [ -f "$SANDBOX_DIR/stop" ]; then
        "$SANDBOX_DIR/stop" 2>/dev/null || true
    fi
    SANDBOX_NAME=$(basename "${SANDBOX_DIR%/}")
    VERSION=$(echo "$SANDBOX_NAME" | sed 's/^msb_//' | tr '_' '.')
    if [ -n "$VERSION" ]; then
        dbdeployer delete single "$VERSION" 2>/dev/null || true
    fi
fi
