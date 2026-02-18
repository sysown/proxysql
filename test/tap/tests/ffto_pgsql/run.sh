#!/bin/bash
# test/tap/tests/ffto_pgsql/run.sh

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TAP_BINARY="${SCRIPT_DIR}/../test_ffto_pgsql-t"

if [ ! -f "$TAP_BINARY" ]; then
    echo "Error: TAP binary $TAP_BINARY not found. Build it first with 'make test_ffto_pgsql-t'."
    exit 1
fi

"$TAP_BINARY"
