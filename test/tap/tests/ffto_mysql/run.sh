#!/bin/bash
# test/tap/tests/ffto_mysql/run.sh

# This script orchestrates the MySQL FFTO tests.
# It assumes ProxySQL is built and available.

# Path to the TAP test binary
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TAP_BINARY="${SCRIPT_DIR}/../test_ffto_mysql-t"

if [ ! -f "$TAP_BINARY" ]; then
    echo "Error: TAP binary $TAP_BINARY not found. Build it first with 'make test_ffto_mysql-t'."
    exit 1
fi

# Run the test
"$TAP_BINARY"
