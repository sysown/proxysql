#!/usr/bin/env bash
# Verify RAG search logging with run-unique rows and no global table reset.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../mcp_rules_testing/mcp_test_helpers.sh"

TOTAL=0
FAILED=0
MARKER="tap_rag_${INFRA_ID:-local}_$$_$(date +%s)"
RAG_CATALOG_PATH="${RAG_CATALOG_PATH:-/var/lib/proxysql/mcp_catalog.db}"

assertion() {
    TOTAL=$((TOTAL + 1))
    if "$@"; then
        echo "ok ${TOTAL} - ${DESCRIPTION}"
    else
        echo "not ok ${TOTAL} - ${DESCRIPTION}"
        FAILED=$((FAILED + 1))
    fi
}

call_search() {
    local query="$1"
    local k="$2"
    local filters="$3"
    local id="$4"
    local request
    request="$(jq -cn \
        --arg query "${query}" --argjson k "${k}" --argjson filters "${filters}" --argjson id "${id}" \
        '{jsonrpc:"2.0",id:$id,method:"tools/call",
          params:{name:"rag.search_fts",arguments:{query:$query,k:$k,filters:$filters}}}')"
    mcp_request rag "${request}"
}

response_succeeded() {
    jq -e '((has("error") | not) and (.result.isError != true))' >/dev/null <<< "$1"
}

catalog_query() {
    local sql="$1"
    shift
    python3 - "${RAG_CATALOG_PATH}" "${sql}" "$@" <<'PY'
import sqlite3
import sys

path, sql, *parameters = sys.argv[1:]
with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5) as database:
    for row in database.execute(sql, parameters):
        print("\t".join("" if value is None else str(value) for value in row))
PY
}

log_entry() {
    catalog_query \
        "SELECT log_id, query, k, COALESCE(NULLIF(filters, ''), '{}'), searched_at FROM rag_search_log WHERE query=? ORDER BY log_id DESC LIMIT 1" \
        "$1"
}

log_count_like() {
    catalog_query "SELECT COUNT(*) FROM rag_search_log WHERE query LIKE ?" "$1%"
}

if ! require_mcp_prerequisites || ! check_proxysql_admin || ! check_mcp_server; then
    echo "RAG log prerequisites are unavailable" >&2
    exit 1
fi
if [[ ! -r "${RAG_CATALOG_PATH}" ]]; then
    echo "RAG catalog is unavailable at ${RAG_CATALOG_PATH}" >&2
    exit 1
fi

basic_query="${MARKER}_basic"
basic_response="$(call_search "${basic_query}" 5 '{}' 1)"
DESCRIPTION="logged RAG search returns a successful MCP result"
assertion response_succeeded "${basic_response}"

basic_entry="$(log_entry "${basic_query}")"
IFS=$'\t' read -r basic_id logged_query logged_k logged_filters logged_at <<< "${basic_entry}"
DESCRIPTION="search log stores the run-unique query"
assertion test "${logged_query:-}" = "${basic_query}"

DESCRIPTION="search log stores the requested k value"
assertion test "${logged_k:-}" = "5"

DESCRIPTION="search log stores a timestamp"
assertion bash -c '[[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2} ]]' bash "${logged_at:-}"

filter_query="${MARKER}_filter"
call_search "${filter_query}" 10 '{"source_ids":[909901]}' 2 >/dev/null
filter_entry="$(log_entry "${filter_query}")"
IFS=$'\t' read -r filter_id filter_text filter_k filter_json filter_at <<< "${filter_entry}"
DESCRIPTION="search log stores structured filters"
assertion grep -q 'source_ids' <<< "${filter_json:-}"

multi_before="$(log_count_like "${MARKER}_multi")"
for suffix in 1 2 3; do
    call_search "${MARKER}_multi${suffix}" 3 '{}' "$((suffix + 2))" >/dev/null
done
multi_after="$(log_count_like "${MARKER}_multi")"
DESCRIPTION="three searches append three independent log rows"
assertion test "$((multi_after - multi_before))" -eq 3

call_search "${MARKER}_k20" 20 '{}' 6 >/dev/null
call_search "${MARKER}_k50" 50 '{}' 7 >/dev/null
k20_entry="$(log_entry "${MARKER}_k20")"
k50_entry="$(log_entry "${MARKER}_k50")"
IFS=$'\t' read -r _ _ k20 _ _ <<< "${k20_entry}"
IFS=$'\t' read -r _ _ k50 _ _ <<< "${k50_entry}"
DESCRIPTION="search log distinguishes different k values"
assertion test "${k20:-}" = "20" -a "${k50:-}" = "50"

echo "${TOTAL} logging assertions, ${FAILED} failed"
[[ ${FAILED} -eq 0 ]]
