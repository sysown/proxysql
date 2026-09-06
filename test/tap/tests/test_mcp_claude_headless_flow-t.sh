#!/usr/bin/env bash
# TAP smoke test for the self-contained MCP headless discovery fixtures.

set -euo pipefail

PLAN=7
DONE=0
FAIL=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/mcp_rules_testing/mcp_test_helpers.sh"

HEADLESS_DIR="${SCRIPT_DIR}/mcp_headless_testing"
STATIC_HARVEST="${HEADLESS_DIR}/static_harvest.sh"
TWO_PHASE="${HEADLESS_DIR}/two_phase_discovery.py"
MCP_CONFIG_PATH="${TAP_CLAUDE_MCP_CONFIG:-${HEADLESS_DIR}/mcp_config.example.json}"
TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
SCHEMA_NAME="${MYSQL_DATABASE:-test}"
RUN_REAL_CLAUDE="${TAP_RUN_REAL_CLAUDE:-0}"
CLAUDE_TIMEOUT_SEC="${TAP_CLAUDE_TIMEOUT:-900}"
ENDPOINT="$(get_endpoint_url query)"
export PROXYSQL_MCP_ENDPOINT="${ENDPOINT}"
RUN_ID=""

tap_plan "${PLAN}"
echo "msg: # === MCP Claude Headless Flow Smoke Test ==="

if require_mcp_prerequisites && require_command python3; then
    tap_ok "headless prerequisites are available"
else
    tap_not_ok "headless prerequisites are available"
fi

if check_proxysql_admin; then
    tap_ok "ProxySQL admin reachable at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
else
    tap_not_ok "ProxySQL admin reachable at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
fi

if check_mcp_server; then
    tap_ok "authenticated MCP server reachable at ${MCP_HOST}:${MCP_PORT}"
else
    tap_not_ok "authenticated MCP server reachable at ${MCP_HOST}:${MCP_PORT}"
fi

if [[ -x "${STATIC_HARVEST}" && -f "${TWO_PHASE}" && -f "${MCP_CONFIG_PATH}" ]]; then
    tap_ok "headless fixtures are staged below test/tap/tests"
else
    tap_not_ok "headless fixtures are staged below test/tap/tests" \
        "Missing ${STATIC_HARVEST}, ${TWO_PHASE}, or ${MCP_CONFIG_PATH}"
fi

set +e
static_out="$("${STATIC_HARVEST}" \
    --endpoint "${ENDPOINT}" \
    --target-id "${TARGET_ID}" \
    --schema "${SCHEMA_NAME}" \
    --notes "tap_claude_headless_flow" 2>&1)"
static_status=$?
set -e
if [[ ${static_status} -eq 0 ]]; then
    RUN_ID="$(sed -n 's/^Run ID:[[:space:]]*\([0-9][0-9]*\)$/\1/p' <<< "${static_out}" | head -n1)"
fi
if [[ -n "${RUN_ID}" ]]; then
    tap_ok "static harvest returns run id ${RUN_ID}"
else
    tap_not_ok "static harvest returns a run id" "${static_out}"
fi

if [[ -n "${RUN_ID}" ]]; then
    set +e
    dry_out="$(python3 "${TWO_PHASE}" \
        --mcp-config "${MCP_CONFIG_PATH}" \
        --target-id "${TARGET_ID}" \
        --schema "${SCHEMA_NAME}" \
        --run-id "${RUN_ID}" \
        --dry-run 2>&1)"
    dry_status=$?
    set -e
    if [[ ${dry_status} -eq 0 ]] && grep -q "\[DRY RUN\]" <<< "${dry_out}" && \
       grep -q "Target ID: ${TARGET_ID}" <<< "${dry_out}"; then
        tap_ok "two-phase dry-run consumes the harvested target and run"
    else
        tap_not_ok "two-phase dry-run consumes the harvested target and run" "${dry_out}"
    fi
else
    tap_skip "two-phase dry-run consumes the harvested target and run" "static harvest failed"
fi

if [[ "${RUN_REAL_CLAUDE}" != "1" ]]; then
    tap_skip "real Claude execution" "set TAP_RUN_REAL_CLAUDE=1 to enable"
elif ! command -v claude >/dev/null 2>&1; then
    tap_not_ok "real Claude execution" "TAP_RUN_REAL_CLAUDE=1 but claude is unavailable"
elif [[ -z "${RUN_ID}" ]]; then
    tap_not_ok "real Claude execution" "static harvest did not produce a run id"
else
    set +e
    if command -v timeout >/dev/null 2>&1; then
        timeout "${CLAUDE_TIMEOUT_SEC}" python3 "${TWO_PHASE}" \
            --mcp-config "${MCP_CONFIG_PATH}" \
            --target-id "${TARGET_ID}" \
            --schema "${SCHEMA_NAME}" \
            --run-id "${RUN_ID}" \
            --dangerously-skip-permissions
        real_status=$?
    else
        python3 "${TWO_PHASE}" \
            --mcp-config "${MCP_CONFIG_PATH}" \
            --target-id "${TARGET_ID}" \
            --schema "${SCHEMA_NAME}" \
            --run-id "${RUN_ID}" \
            --dangerously-skip-permissions
        real_status=$?
    fi
    set -e
    if [[ ${real_status} -eq 0 ]]; then
        tap_ok "real Claude execution"
    else
        tap_not_ok "real Claude execution" "exit_status=${real_status}"
    fi
fi

tap_finish
