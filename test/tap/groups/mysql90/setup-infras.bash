#!/bin/bash
set -e

# MySQL 9.0 Group Setup Hook
# This hook runs after all backends are running but before tests execute.
# It performs group-specific setup that doesn't belong in the generic test runner.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

# Ensure INFRA_ID is set
if [ -z "${INFRA_ID}" ]; then
    echo "ERROR: INFRA_ID is not set."
    exit 1
fi

PROXY_DATA_DIR="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/proxysql"

# Copy RESTAPI test scripts to ProxySQL data directory (required by reg_test_3223)
if [ -d "${WORKSPACE}/test/tap/tests/reg_test_3223_scripts" ]; then
    echo ">>> [mysql90/setup-infras] Copying RESTAPI test scripts to ProxySQL data directory..."
    mkdir -p "${PROXY_DATA_DIR}/reg_test_3223_scripts"
    cp -r "${WORKSPACE}/test/tap/tests/reg_test_3223_scripts/"* "${PROXY_DATA_DIR}/reg_test_3223_scripts/"
    # Add execute permissions to all scripts EXCEPT script_no_permissions (which tests EACCES)
    find "${PROXY_DATA_DIR}/reg_test_3223_scripts/" -type f ! -name 'script_no_permissions' -exec chmod +x {} \;
    echo ">>> [mysql90/setup-infras] RESTAPI scripts copied successfully"
else
    echo ">>> [mysql90/setup-infras] WARNING: RESTAPI scripts not found at ${WORKSPACE}/test/tap/tests/reg_test_3223_scripts"
fi

echo ">>> [mysql90/setup-infras] Setup complete"
