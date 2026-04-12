#!/bin/bash
set -euo pipefail
#
# Destroy Multiple TAP Groups for a Specific RUN_ID
# Usage:
#   RUN_ID="abc123" ./destroy-multi-group.bash
#
# Optional:
#   TAP_GROUPS="group1 group2"  # Only destroy specific groups for this RUN_ID
#   FORCE=1                      # Skip confirmation
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Configuration
export WORKSPACE="${WORKSPACE:-${REPO_ROOT}}"
RUN_ID="${RUN_ID:-}"
TAP_GROUPS="${TAP_GROUPS:-}"
FORCE="${FORCE:-0}"

# Validate required variables
if [ -z "${RUN_ID}" ]; then
    echo "ERROR: RUN_ID is not set."
    echo "Usage: RUN_ID=<id> [TAP_GROUPS='group1 group2'] ${0}"
    echo ""
    echo "This will destroy all infrastructures matching '*-${RUN_ID}'"
    exit 1
fi

# Determine which groups to destroy
if [ -n "${TAP_GROUPS}" ]; then
    # Use specified groups
    read -ra TARGET_GROUPS <<< "${TAP_GROUPS}"
    MODE="specific"
else
    # Auto-discover groups by finding matching directories
    MODE="auto"
    TARGET_GROUPS=()

    # Look for log directories matching *-${RUN_ID}
    LOGS_PATH="${WORKSPACE}/ci_infra_logs"
    if [ -d "${LOGS_PATH}" ]; then
        for dir in "${LOGS_PATH}"/*; do
            if [ -d "${dir}" ]; then
                dir_name=$(basename "${dir}")
                if [[ "${dir_name}" == *"-${RUN_ID}" ]]; then
                    # Extract group name from INFRA_ID
                    group_name="${dir_name%-${RUN_ID}}"
                    TARGET_GROUPS+=("${group_name}")
                fi
            fi
        done
    fi
fi

TOTAL_GROUPS=${#TARGET_GROUPS[@]}

if [ "${TOTAL_GROUPS}" -eq 0 ]; then
    echo "No groups found to destroy for RUN_ID: ${RUN_ID}"
    echo "Usage: RUN_ID=<id> ${0}"
    exit 0
fi

echo "=========================================="
echo "Destroy Multiple TAP Groups"
echo "=========================================="
echo "RUN_ID: ${RUN_ID}"
echo "MODE: ${MODE}"
echo "TARGET_GROUPS: ${TARGET_GROUPS[*]}"
echo "=========================================="

# Confirmation prompt (unless FORCE=1)
if [ "${FORCE}" -eq 0 ]; then
    echo ""
    echo "This will destroy the following ${TOTAL_GROUPS} infrastructure(s):"
    for group in "${TARGET_GROUPS[@]}"; do
        echo "  - ${group}-${RUN_ID}"
    done
    echo ""
    read -p "Are you sure? [y/N] " -n 1 -r
    echo ""
    if [[ ! ${REPLY} =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# Track results
declare -A DESTROY_RESULTS
SUCCESS_COUNT=0
FAIL_COUNT=0

# Destroy each group's infrastructure
for group in "${TARGET_GROUPS[@]}"; do
    infra_id="${group}-${RUN_ID}"
    echo ""
    echo ">>> Destroying: ${group} (INFRA_ID: ${infra_id})"

    export INFRA_ID="${infra_id}"
    export TAP_GROUP="${group}"

    # First stop ProxySQL
    if "${SCRIPT_DIR}/stop-proxysql-isolated.bash" >/dev/null 2>&1; then
        echo "    Stopped ProxySQL"
    fi

    # Then destroy backends
    if "${SCRIPT_DIR}/destroy-infras.bash" >/dev/null 2>&1; then
        echo "    ✓ ${group} destroyed"
        DESTROY_RESULTS["${group}"]=0
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "    ✗ ${group} failed to destroy (may already be cleaned up)"
        DESTROY_RESULTS["${group}"]=1
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

# Also clean up the multi-group results directory if it exists
MULTI_GROUP_DIR="${WORKSPACE}/ci_infra_logs/multi-group-${RUN_ID}"
if [ -d "${MULTI_GROUP_DIR}" ]; then
    echo ""
    echo ">>> Removing multi-group results directory: ${MULTI_GROUP_DIR}"
    rm -rf "${MULTI_GROUP_DIR}"
    echo "    ✓ Results directory removed"
fi

# Summary
echo ""
echo "=========================================="
echo "           DESTROY SUMMARY              "
echo "=========================================="
echo "TOTAL:   ${TOTAL_GROUPS}"
echo "SUCCESS: ${SUCCESS_COUNT}"
echo "FAILED:  ${FAIL_COUNT}"
echo "=========================================="

if [ "${FAIL_COUNT}" -eq 0 ]; then
    echo ">>> All groups destroyed successfully"
    exit 0
else
    echo ">>> Some groups failed to destroy (may already be cleaned up)"
    exit 0  # Exit 0 since cleanup is best-effort
fi
