#!/usr/bin/env bash
#
# test_mcp_static_harvest-t.sh
#
# TAP test for MCP static harvesting (phase A) across:
# - MySQL target_id
# - PostgreSQL target_id
#

set -euo pipefail

PLAN=8
DONE=0
FAIL=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPERS="${SCRIPT_DIR}/mcp_rules_testing/mcp_test_helpers.sh"

if [[ ! -f "${HELPERS}" ]]; then
    echo "msg: 1..1"
    echo "msg: not ok 1 - missing helper ${HELPERS}"
    exit 1
fi
source "${HELPERS}"

if ! require_mcp_prerequisites; then
    tap_plan 1
    tap_not_ok "MCP shell prerequisites are available"
    tap_finish
    exit $?
fi

MCP_MYSQL_TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
MCP_PGSQL_TARGET_ID="${MCP_PGSQL_TARGET_ID:-tap_pgsql_default}"

MYSQL_SEEDED_TABLE="${MYSQL_SEEDED_TABLE:-tap_mysql_static_customers}"
PGSQL_SEEDED_TABLE="${PGSQL_SEEDED_TABLE:-tap_pgsql_static_accounts}"

MYSQL_RUN_ID=""
PGSQL_RUN_ID=""

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

extract_run_id() {
    local payload="$1"
    local norm
    norm="$(echo "${payload}" | sed 's/\\"/"/g')"
    echo "${norm}" | sed -n 's/.*"run_id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1
}

json_has_kv() {
    local payload="$1"
    local key="$2"
    local value="$3"
    local norm
    norm="$(echo "${payload}" | sed 's/\\"/"/g')"
    echo "${norm}" | grep -Eq "\"${key}\"[[:space:]]*:[[:space:]]*\"${value}\""
}

echo "msg: 1..${PLAN}"
echo "msg: #"
echo "msg: # === MCP Static Harvest Test Suite ==="
echo "msg: # This test validates MCP static harvesting (phase A) across protocols:"
echo "msg: # - MySQL target_id: harvests tables from MySQL backend via MCP"
echo "msg: # - PostgreSQL target_id: harvests tables from PgSQL backend via MCP"
echo "msg: # Tests cover:"
echo "msg: # - discovery.run_static: triggers schema introspection"
echo "msg: # - catalog.list_objects: queries harvested objects by run_id"
echo "msg: # - Cross-target isolation: verifies run_ids cannot leak across targets"
echo "msg: # Requires both mysql and pgsql backends to be configured."
echo "msg: # ====================================="
echo "msg: #"

if check_proxysql_admin; then
    tap_ok "ProxySQL admin reachable"
else
    tap_not_ok "ProxySQL admin reachable"
fi

if check_mcp_server; then
    tap_ok "MCP server reachable"
else
    tap_not_ok "MCP server reachable"
fi

targets_resp="$(mcp_request "query" '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_targets","arguments":{}},"id":1}')"
if json_has_kv "${targets_resp}" "target_id" "${MCP_MYSQL_TARGET_ID}" && \
   json_has_kv "${targets_resp}" "target_id" "${MCP_PGSQL_TARGET_ID}"; then
    tap_ok "list_targets contains mysql+pgsql target_id"
else
    tap_not_ok "list_targets contains mysql+pgsql target_id" "${targets_resp}"
fi

mysql_harvest_resp="$(mcp_request "query" "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"discovery.run_static\",\"arguments\":{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"schema_filter\":\"${MYSQL_DATABASE}\",\"notes\":\"tap mysql static harvest\"}},\"id\":2}")"
MYSQL_RUN_ID="$(extract_run_id "${mysql_harvest_resp}")"
if [[ -n "${MYSQL_RUN_ID}" ]] && json_has_kv "${mysql_harvest_resp}" "target_id" "${MCP_MYSQL_TARGET_ID}" && json_has_kv "${mysql_harvest_resp}" "protocol" "mysql"; then
    tap_ok "discovery.run_static mysql target returns run_id/protocol"
else
    tap_not_ok "discovery.run_static mysql target returns run_id/protocol" "${mysql_harvest_resp}"
fi

mysql_catalog_resp="$(mcp_request "query" "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"catalog.list_objects\",\"arguments\":{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"run_id\":\"${MYSQL_RUN_ID}\",\"object_type\":\"table\",\"schema_name\":\"${MYSQL_DATABASE}\",\"page_size\":200}},\"id\":3}")"
if json_has_kv "${mysql_catalog_resp}" "object_name" "${MYSQL_SEEDED_TABLE}"; then
    tap_ok "catalog.list_objects mysql run exposes seeded mysql table"
else
    tap_not_ok "catalog.list_objects mysql run exposes seeded mysql table" "${mysql_catalog_resp}"
fi

pgsql_harvest_resp="$(mcp_request "query" "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"discovery.run_static\",\"arguments\":{\"target_id\":\"${MCP_PGSQL_TARGET_ID}\",\"schema_filter\":\"public\",\"notes\":\"tap pgsql static harvest\"}},\"id\":4}")"
PGSQL_RUN_ID="$(extract_run_id "${pgsql_harvest_resp}")"
if [[ -n "${PGSQL_RUN_ID}" ]] && json_has_kv "${pgsql_harvest_resp}" "target_id" "${MCP_PGSQL_TARGET_ID}" && json_has_kv "${pgsql_harvest_resp}" "protocol" "pgsql"; then
    tap_ok "discovery.run_static pgsql target returns run_id/protocol"
else
    tap_not_ok "discovery.run_static pgsql target returns run_id/protocol" "${pgsql_harvest_resp}"
fi

pgsql_catalog_resp="$(mcp_request "query" "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"catalog.list_objects\",\"arguments\":{\"target_id\":\"${MCP_PGSQL_TARGET_ID}\",\"run_id\":\"${PGSQL_RUN_ID}\",\"object_type\":\"table\",\"schema_name\":\"public\",\"page_size\":200}},\"id\":5}")"
if json_has_kv "${pgsql_catalog_resp}" "object_name" "${PGSQL_SEEDED_TABLE}"; then
    tap_ok "catalog.list_objects pgsql run exposes seeded pgsql table"
else
    tap_not_ok "catalog.list_objects pgsql run exposes seeded pgsql table" "${pgsql_catalog_resp}"
fi

cross_target_resp="$(mcp_request "query" "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"catalog.list_objects\",\"arguments\":{\"target_id\":\"${MCP_PGSQL_TARGET_ID}\",\"run_id\":\"${MYSQL_RUN_ID}\",\"object_type\":\"table\",\"page_size\":10}},\"id\":6}")"
if echo "${cross_target_resp}" | grep -q "\"isError\":true" && echo "${cross_target_resp}" | grep -qi "target_id"; then
    tap_ok "catalog run_id cannot be resolved across target_id boundaries"
else
    tap_not_ok "catalog run_id cannot be resolved across target_id boundaries" "${cross_target_resp}"
fi

tap_finish
