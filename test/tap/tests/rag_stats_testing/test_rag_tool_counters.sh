#!/usr/bin/env bash
# Verify RAG tool counters by measuring deltas without clearing shared stats.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../mcp_rules_testing/mcp_test_helpers.sh"

TOTAL=0
FAILED=0

assertion() {
    TOTAL=$((TOTAL + 1))
    if "$@"; then
        echo "ok ${TOTAL} - ${DESCRIPTION}"
    else
        echo "not ok ${TOTAL} - ${DESCRIPTION}"
        FAILED=$((FAILED + 1))
    fi
}

tool_count() {
    exec_admin_silent \
        "SELECT COALESCE((SELECT count FROM stats_mcp_query_tools_counters WHERE endpoint='RAG' AND tool='$1' AND schema='rag'), 0);"
}

tool_timing() {
    exec_admin_silent \
        "SELECT count, sum_time, min_time, max_time FROM stats_mcp_query_tools_counters WHERE endpoint='RAG' AND tool='$1' AND schema='rag';"
}

call_tool() {
    local name="$1"
    local arguments="$2"
    local id="$3"
    local request
    request="$(jq -cn --arg name "${name}" --argjson arguments "${arguments}" --argjson id "${id}" \
        '{jsonrpc:"2.0",id:$id,method:"tools/call",params:{name:$name,arguments:$arguments}}')"
    mcp_request rag "${request}"
}

response_succeeded() {
    jq -e '((has("error") | not) and (.result.isError != true))' >/dev/null <<< "$1"
}

if ! require_mcp_prerequisites || ! check_proxysql_admin || ! check_mcp_server; then
    echo "RAG counter prerequisites are unavailable" >&2
    exit 1
fi

fts_before="$(tool_count rag.search_fts)"
fts_response="$(call_tool rag.search_fts '{"query":"mysql","k":5}' 1)"
DESCRIPTION="rag.search_fts returns a successful MCP result"
assertion response_succeeded "${fts_response}"

fts_after="$(tool_count rag.search_fts)"
DESCRIPTION="rag.search_fts increments its counter once"
assertion test "$((fts_after - fts_before))" -eq 1

admin_before="$(tool_count rag.admin.stats)"
admin_response="$(call_tool rag.admin.stats '{}' 2)"
DESCRIPTION="rag.admin.stats returns a successful MCP result"
assertion response_succeeded "${admin_response}"

admin_after="$(tool_count rag.admin.stats)"
DESCRIPTION="rag.admin.stats increments its counter once"
assertion test "$((admin_after - admin_before))" -eq 1

multi_before="$(tool_count rag.search_fts)"
for id in 3 4 5; do
    call_tool rag.search_fts '{"query":"mysql","k":3}' "${id}" >/dev/null
done
multi_after="$(tool_count rag.search_fts)"
DESCRIPTION="three additional searches increment the counter three times"
assertion test "$((multi_after - multi_before))" -eq 3

timing="$(tool_timing rag.search_fts)"
IFS=$'\t' read -r count sum_time min_time max_time <<< "${timing}"
DESCRIPTION="RAG timing counters preserve count and ordering"
assertion test "${count:-0}" -ge 4 -a "${sum_time:-0}" -ge "${max_time:-0}" -a "${max_time:-0}" -ge "${min_time:-0}" -a "${min_time:-0}" -ge 0

identity="$(exec_admin_silent \
    "SELECT endpoint || ':' || schema FROM stats_mcp_query_tools_counters WHERE tool='rag.search_fts' AND endpoint='RAG' AND schema='rag' LIMIT 1;")"
DESCRIPTION="RAG counter rows retain endpoint and schema identity"
assertion test "${identity}" = "RAG:rag"

unknown_before="$(tool_count rag.unknown_tool)"
unknown_response="$(call_tool rag.unknown_tool '{}' 99)"
unknown_after="$(tool_count rag.unknown_tool)"
DESCRIPTION="unknown RAG tools return an error and are still counted"
assertion bash -c 'jq -e ".result.isError == true" >/dev/null <<< "$1" && [[ "$2" -eq 1 ]]' \
    bash "${unknown_response}" "$((unknown_after - unknown_before))"

echo "${TOTAL} counter assertions, ${FAILED} failed"
[[ ${FAILED} -eq 0 ]]
