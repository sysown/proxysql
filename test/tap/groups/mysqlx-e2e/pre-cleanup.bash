#!/usr/bin/env bash
set -e
echo "=== mysqlx-e2e: Cleaning up dbdeployer sandbox ==="

# Find and stop the MySQL 8.4 sandbox
SANDBOX_DIR=$(ls -d $HOME/sandboxes/msb_8_4_*/ 2>/dev/null | head -1)
if [ -n "$SANDBOX_DIR" ]; then
    if [ -f "$SANDBOX_DIR/stop" ]; then
        "$SANDBOX_DIR/stop" 2>/dev/null || true
    fi
    dbdeployer delete single 8.4.8 2>/dev/null || true
fi
