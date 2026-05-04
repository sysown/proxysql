#!/usr/bin/env bash
#
# test_mcp_claude_headless_flow-t.sh
#
# TAP smoke test for ClaudeCode_Headless integration artifacts:
# - static_harvest.sh wrapper
# - two_phase_discovery.py orchestration script (dry-run always)
# - optional real Claude execution (opt-in)
#

set -euo pipefail

PLAN=6
DONE=0
FAIL=0

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HEADLESS_DIR="${REPO_ROOT}/scripts/mcp/DiscoveryAgent/ClaudeCode_Headless"
STATIC_HARVEST="${HEADLESS_DIR}/static_harvest.sh"
TWO_PHASE="${HEADLESS_DIR}/two_phase_discovery.py"

# Use actual target_id from local setup
TARGET_ID="${MCP_TARGET_ID:-mysql-127.0.0.1-13306}"
SCHEMA_NAME="${TEST_DB_NAME:-testdb}"
MCP_CONFIG_PATH="${TAP_CLAUDE_MCP_CONFIG:-${HEADLESS_DIR}/mcp_config.example.json}"
RUN_REAL_CLAUDE="${TAP_RUN_REAL_CLAUDE:-0}"
CLAUDE_TIMEOUT_SEC="${TAP_CLAUDE_TIMEOUT:-900}"

RUN_ID=""

tap_ok() {
    DONE=$((DONE + 1))
    echo "msg: ok ${DONE} - $1"
}

tap_not_ok() {
    DONE=$((DONE + 1))
    FAIL=$((FAIL + 1))
    echo "msg: not ok ${DONE} - $1"
    if [[ $# -gt 1 ]]; then
        echo "msg: # $2"
    fi
}

tap_skip() {
    DONE=$((DONE + 1))
    echo "msg: ok ${DONE} - $1 # SKIP $2"
}

echo "msg: 1..${PLAN}"
echo "msg: #"
echo "msg: # === MCP Claude Headless Flow Smoke Test ==="
echo "msg: # This test validates the ClaudeCode_Headless integration artifacts:"
echo "msg: # - static_harvest.sh wrapper for schema introspection"
echo "msg: # - two_phase_discovery.py orchestration script (dry-run mode)"
echo "msg: # - optional real Claude execution (opt-in via TAP_RUN_REAL_CLAUDE=1)"
echo "msg: # The test ensures the headless discovery pipeline scripts exist and"
echo "msg: # can be invoked with proper MCP target configuration."
echo "msg: # ==============================================="
echo "msg: #"

# Enable MCP via Admin
echo "msg: # Enabling MCP and registering targets via Admin interface..."
mysql -u admin -padmin -h 127.0.0.1 -P 6032 <<EOF
UPDATE global_variables SET variable_value='true' WHERE variable_name='mcp-enabled';
UPDATE global_variables SET variable_value='false' WHERE variable_name='mcp-use_ssl';
INSERT OR REPLACE INTO mcp_auth_profiles (auth_profile_id, db_username, db_password) VALUES ('default_mysql', 'root', 'root');
INSERT OR REPLACE INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id) VALUES ('mysql-127.0.0.1-13306', 'mysql', 0, 'default_mysql');
EOF
mysql -u admin -padmin -h 127.0.0.1 -P 6032 -e "LOAD MCP VARIABLES TO RUNTIME"
mysql -u admin -padmin -h 127.0.0.1 -P 6032 -e "LOAD MCP PROFILES TO RUNTIME"

# Use HTTP instead of HTTPS since we disabled SSL
ENDPOINT="http://127.0.0.1:6071/mcp/query"

if [[ -x "${STATIC_HARVEST}" && -f "${TWO_PHASE}" ]]; then
    tap_ok "Claude headless scripts exist"
else
    tap_not_ok "Claude headless scripts exist" "Missing ${STATIC_HARVEST} or ${TWO_PHASE}"
fi

if command -v jq >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    tap_ok "jq and python3 available"
else
    tap_not_ok "jq and python3 available" "jq/python3 required"
fi

echo "msg: # Executing: ${STATIC_HARVEST} --endpoint ${ENDPOINT} --target-id ${TARGET_ID} --schema ${SCHEMA_NAME}"
static_out="$("${STATIC_HARVEST}" --endpoint "${ENDPOINT}" --target-id "${TARGET_ID}" --schema "${SCHEMA_NAME}" --notes "tap_claude_headless_flow" 2>&1 || true)"
RUN_ID="$(echo "${static_out}" | sed -n 's/^Run ID:[[:space:]]*\([0-9][0-9]*\)$/\1/p' | head -n1)"
if [[ -n "${RUN_ID}" ]]; then
    tap_ok "static_harvest.sh returns run id: ${RUN_ID}"
else
    tap_not_ok "static_harvest.sh returns run id" "${static_out}"
fi

echo "msg: # Executing dry-run: python3 ${TWO_PHASE} --mcp-config ${MCP_CONFIG_PATH} --target-id ${TARGET_ID} --run-id ${RUN_ID} --dry-run"
dry_out="$(python3 "${TWO_PHASE}" --mcp-config "${MCP_CONFIG_PATH}" --target-id "${TARGET_ID}" --schema "${SCHEMA_NAME}" --run-id "${RUN_ID}" --dry-run 2>&1 || true)"
if echo "${dry_out}" | grep -q "\[DRY RUN\]" && echo "${dry_out}" | grep -q "Target ID: ${TARGET_ID}"; then
    tap_ok "two_phase_discovery.py dry-run includes target_id and succeeds"
else
    tap_not_ok "two_phase_discovery.py dry-run includes target_id and succeeds" "${dry_out}"
fi

if [[ "${RUN_REAL_CLAUDE}" != "1" ]]; then
    tap_skip "real Claude execution" "set TAP_RUN_REAL_CLAUDE=1 to enable"
else
    if ! command -v claude >/dev/null 2>&1; then
        tap_skip "real Claude execution" "claude CLI not found"
    else
        set +e
        if command -v timeout >/dev/null 2>&1; then
            timeout "${CLAUDE_TIMEOUT_SEC}" python3 "${TWO_PHASE}" \
                --mcp-config "${MCP_CONFIG_PATH}" \
                --target-id "${TARGET_ID}" \
                --schema "${SCHEMA_NAME}" \
                --run-id "${RUN_ID}"
            rc=$?
        else
            python3 "${TWO_PHASE}" \
                --mcp-config "${MCP_CONFIG_PATH}" \
                --target-id "${TARGET_ID}" \
                --schema "${SCHEMA_NAME}" \
                --run-id "${RUN_ID}"
            rc=$?
        fi
        set -e
        if [[ ${rc} -eq 0 ]]; then
            tap_ok "real Claude execution completed"
        else
            tap_not_ok "real Claude execution completed" "exit_code=${rc}"
        fi
    fi
fi

if [[ -f "${MCP_CONFIG_PATH}" ]]; then
    tap_ok "MCP config path exists (${MCP_CONFIG_PATH})"
else
    tap_skip "MCP config path exists" "${MCP_CONFIG_PATH} not present (dry-run still valid)"
fi

if [[ "${FAIL}" -ne 0 ]]; then
    echo "msg: # FAILURES=${FAIL}/${PLAN}"
    exit 1
fi
exit 0
