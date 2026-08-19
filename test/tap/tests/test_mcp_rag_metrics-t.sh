#!/usr/bin/env bash
# TAP integration test for authenticated RAG requests, metrics, and logging.

set -uo pipefail

PLAN=6
DONE=0
FAIL=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAG_TESTS_DIR="${SCRIPT_DIR}/rag_stats_testing"
source "${SCRIPT_DIR}/mcp_rules_testing/mcp_test_helpers.sh"

cleanup_rag_fixture() {
    RAG_DB_PATH="${RAG_DB_PATH:-/var/lib/proxysql/ai_features.db}" \
        bash "${RAG_TESTS_DIR}/prepare_test_db.sh" cleanup >/dev/null 2>&1 || true
}
trap cleanup_rag_fixture EXIT INT TERM

run_nested_test() {
    local name="$1"
    local program="$2"
    local output
    local status
    output="$(bash "${program}" 2>&1)"
    status=$?
    while IFS= read -r line; do
        [[ -n "${line}" ]] && echo "msg: # ${line}"
    done <<< "${output}"
    if [[ ${status} -eq 0 ]]; then
        tap_ok "${name}"
    else
        tap_not_ok "${name}" "nested test exited ${status}"
    fi
}

tap_plan "${PLAN}"
echo "msg: # === MCP RAG Metrics Test Suite ==="

if require_mcp_prerequisites && require_command python3; then
    tap_ok "RAG shell prerequisites are available"
else
    tap_not_ok "RAG shell prerequisites are available"
fi

if check_proxysql_admin; then
    tap_ok "ProxySQL admin reachable at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
else
    tap_not_ok "ProxySQL admin reachable at ${PROXYSQL_ADMIN_HOST}:${PROXYSQL_ADMIN_PORT}"
fi

rag_tools="$(mcp_request rag '{"jsonrpc":"2.0","method":"tools/list","id":1}' 2>/dev/null)"
if jq -e \
    '[.result.tools[].name] | ((index("rag.search_fts") != null) and (index("rag.admin.stats") != null))' \
    >/dev/null 2>&1 <<< "${rag_tools}"; then
    tap_ok "authenticated RAG endpoint publishes its tools"
else
    tap_not_ok "authenticated RAG endpoint publishes its tools" "${rag_tools}"
fi

prepare_output="$(RAG_DB_PATH="${RAG_DB_PATH:-/var/lib/proxysql/ai_features.db}" \
    bash "${RAG_TESTS_DIR}/prepare_test_db.sh" seed 2>&1)"
prepare_status=$?
if [[ ${prepare_status} -eq 0 ]] && grep -q "Documents: 1" <<< "${prepare_output}" && \
   grep -q "FTS entries: 1" <<< "${prepare_output}"; then
    tap_ok "RAG database fixture is seeded through Python stdlib"
else
    tap_not_ok "RAG database fixture is seeded through Python stdlib" "${prepare_output}"
fi

run_nested_test "RAG tool counters increase deterministically" \
    "${RAG_TESTS_DIR}/test_rag_tool_counters.sh"
run_nested_test "RAG searches are logged without clearing shared state" \
    "${RAG_TESTS_DIR}/test_rag_search_log.sh"

tap_finish
