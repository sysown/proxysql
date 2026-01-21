#!/bin/bash
#
# test_mcp_fts_detailed.sh - Detailed FTS validation for MCP /mcp/query endpoint
#
# Tests:
#  - tools/list exposes FTS tools
#  - runtime fts_path change + stress toggling
#  - index/reindex on testdb tables
#  - search returns hits and snippets
#  - list_indexes columns is JSON array
#  - empty query returns error
#  - delete index and verify removal
#  - rebuild all indexes and verify success
#
# Usage:
#   ./test_mcp_fts_detailed.sh [--cleanup]
#
# Env:
#   MCP_HOST (default 127.0.0.1)
#   MCP_PORT (default 6071)
#   USE_SSL  (default false)
#   MYSQL_HOST (default 127.0.0.1)
#   MYSQL_PORT (default 6033)
#   MYSQL_USER (default root)
#   MYSQL_PASSWORD (default root)
#   CREATE_SAMPLE_DATA (default true)
#

set -euo pipefail

MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"
USE_SSL="${USE_SSL:-false}"

MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-6033}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-root}"
CREATE_SAMPLE_DATA="${CREATE_SAMPLE_DATA:-true}"

if [ "${USE_SSL}" = "true" ]; then
  PROTO="https"
  CURL_OPTS="-k"
else
  PROTO="http"
  CURL_OPTS=""
fi

MCP_ENDPOINT="${PROTO}://${MCP_HOST}:${MCP_PORT}/mcp/query"
MCP_CONFIG_ENDPOINT="${PROTO}://${MCP_HOST}:${MCP_PORT}/mcp/config"

CLEANUP=false
if [ "${1:-}" = "--cleanup" ]; then
  CLEANUP=true
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for this test script." >&2
  exit 1
fi

if [ "${CREATE_SAMPLE_DATA}" = "true" ] && ! command -v mysql >/dev/null 2>&1; then
  echo "mysql client is required for CREATE_SAMPLE_DATA=true" >&2
  exit 1
fi

log() {
  echo "[FTS] $1"
}

mysql_exec() {
  local sql="$1"
  mysql -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" -u "${MYSQL_USER}" -p"${MYSQL_PASSWORD}" -e "${sql}"
}

setup_sample_data() {
  log "Setting up sample MySQL data for CI"

  mysql_exec "CREATE DATABASE IF NOT EXISTS fts_test;"

  mysql_exec "DROP TABLE IF EXISTS fts_test.customers;"
  mysql_exec "CREATE TABLE fts_test.customers (id INT PRIMARY KEY, name VARCHAR(100), email VARCHAR(100), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
  mysql_exec "INSERT INTO fts_test.customers (id, name, email) VALUES (1, 'Alice Johnson', 'alice@example.com'), (2, 'Bob Smith', 'bob@example.com'), (3, 'Charlie Brown', 'charlie@example.com');"

  mysql_exec "DROP TABLE IF EXISTS fts_test.orders;"
  mysql_exec "CREATE TABLE fts_test.orders (id INT PRIMARY KEY, customer_id INT, order_date DATE, total DECIMAL(10,2), status VARCHAR(20), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
  mysql_exec "INSERT INTO fts_test.orders (id, customer_id, order_date, total, status) VALUES (1, 1, '2026-01-01', 100.00, 'open'), (2, 2, '2026-01-02', 200.00, 'closed');"

  mysql_exec "DROP TABLE IF EXISTS fts_test.products;"
  mysql_exec "CREATE TABLE fts_test.products (id INT PRIMARY KEY, name VARCHAR(100), category VARCHAR(50), price DECIMAL(10,2), stock INT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
  mysql_exec "INSERT INTO fts_test.products (id, name, category, price, stock) VALUES (1, 'Laptop Pro', 'electronics', 999.99, 10), (2, 'Coffee Mug', 'kitchen', 12.99, 200), (3, 'Desk Lamp', 'home', 29.99, 50);"
}

cleanup_sample_data() {
  if [ "${CREATE_SAMPLE_DATA}" = "true" ]; then
    log "Cleaning up sample MySQL data"
    mysql_exec "DROP DATABASE IF EXISTS fts_test;"
  fi
}

mcp_request() {
  local payload="$1"
  curl ${CURL_OPTS:+"${CURL_OPTS}"} -s -X POST "${MCP_ENDPOINT}" \
    -H "Content-Type: application/json" \
    -d "${payload}"
}

config_request() {
  local payload="$1"
  curl ${CURL_OPTS:+"${CURL_OPTS}"} -s -X POST "${MCP_CONFIG_ENDPOINT}" \
    -H "Content-Type: application/json" \
    -d "${payload}"
}

tool_call() {
  local name="$1"
  local args="$2"
  mcp_request "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"${name}\",\"arguments\":${args}}}"
}

extract_tool_result() {
  local resp="$1"
  local text
  text=$(echo "${resp}" | jq -r '.result.content[0].text // empty')
  if [ -n "${text}" ] && [ "${text}" != "null" ]; then
    echo "${text}"
    return 0
  fi

  echo "${resp}" | jq -c '.result.result // .result'
}

config_call() {
  local name="$1"
  local args="$2"
  config_request "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"${name}\",\"arguments\":${args}}}"
}

ensure_index() {
  local schema="$1"
  local table="$2"
  local columns="$3"
  local pk="$4"

  local list_json
  list_json=$(tool_call "fts_list_indexes" "{}")
  list_json=$(extract_tool_result "${list_json}")

  local exists
  exists=$(echo "${list_json}" | jq -r --arg s "${schema}" --arg t "${table}" \
    '.indexes[]? | select(.schema==$s and .table==$t) | .table' | head -n1)

  if [ -n "${exists}" ]; then
    log "Reindexing ${schema}.${table}"
    local reindex_resp
    reindex_resp=$(tool_call "fts_reindex" "{\"schema\":\"${schema}\",\"table\":\"${table}\"}")
    reindex_resp=$(extract_tool_result "${reindex_resp}")
    echo "${reindex_resp}" | jq -e '.success == true' >/dev/null
  else
    log "Indexing ${schema}.${table}"
    local index_resp
    index_resp=$(tool_call "fts_index_table" "{\"schema\":\"${schema}\",\"table\":\"${table}\",\"columns\":${columns},\"primary_key\":\"${pk}\"}")
    index_resp=$(extract_tool_result "${index_resp}")
    echo "${index_resp}" | jq -e '.success == true' >/dev/null
  fi
}

if [ "${CREATE_SAMPLE_DATA}" = "true" ]; then
  setup_sample_data
fi

log "Checking tools/list contains FTS tools"
tools_json=$(mcp_request '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
for tool in fts_index_table fts_search fts_list_indexes fts_delete_index fts_reindex fts_rebuild_all; do
  echo "${tools_json}" | jq -e --arg t "${tool}" '.result.tools[]? | select(.name==$t)' >/dev/null
  log "Found tool: ${tool}"
done

log "Testing runtime fts_path change"
orig_cfg=$(config_call "get_config" '{"variable_name":"fts_path"}')
orig_cfg=$(extract_tool_result "${orig_cfg}")
orig_path=$(echo "${orig_cfg}" | jq -r '.value')

alt_path="${ALT_FTS_PATH:-/tmp/mcp_fts_runtime_test.db}"
set_resp=$(config_call "set_config" "{\"variable_name\":\"fts_path\",\"value\":\"${alt_path}\"}")
set_resp=$(extract_tool_result "${set_resp}")
echo "${set_resp}" | jq -e '.variable_name == "fts_path" and .value == "'"${alt_path}"'"' >/dev/null

new_cfg=$(config_call "get_config" '{"variable_name":"fts_path"}')
new_cfg=$(extract_tool_result "${new_cfg}")
echo "${new_cfg}" | jq -e --arg v "${alt_path}" '.value == $v' >/dev/null

log "Stress test: toggling fts_path values"
TOGGLE_ITERATIONS="${TOGGLE_ITERATIONS:-10}"
for i in $(seq 1 "${TOGGLE_ITERATIONS}"); do
  tmp_path="/tmp/mcp_fts_runtime_test_${i}.db"
  toggle_resp=$(config_call "set_config" "{\"variable_name\":\"fts_path\",\"value\":\"${tmp_path}\"}")
  toggle_resp=$(extract_tool_result "${toggle_resp}")
  echo "${toggle_resp}" | jq -e '.variable_name == "fts_path" and .value == "'"${tmp_path}"'"' >/dev/null

  verify_resp=$(config_call "get_config" '{"variable_name":"fts_path"}')
  verify_resp=$(extract_tool_result "${verify_resp}")
  echo "${verify_resp}" | jq -e --arg v "${tmp_path}" '.value == $v' >/dev/null
done

log "Restoring original fts_path"
restore_resp=$(config_call "set_config" "{\"variable_name\":\"fts_path\",\"value\":\"${orig_path}\"}")
restore_resp=$(extract_tool_result "${restore_resp}")
echo "${restore_resp}" | jq -e '.variable_name == "fts_path" and .value == "'"${orig_path}"'"' >/dev/null

ensure_index "fts_test" "customers" '["name","email","created_at"]' "id"
ensure_index "fts_test" "orders" '["customer_id","order_date","total","status","created_at"]' "id"

log "Validating list_indexes columns is JSON array"
list_json=$(tool_call "fts_list_indexes" "{}")
list_json=$(extract_tool_result "${list_json}")
echo "${list_json}" | jq -e '.indexes[]? | select(.schema=="fts_test" and .table=="customers") | (.columns|type=="array")' >/dev/null

log "Searching for 'Alice' in fts_test.customers"
search_json=$(tool_call "fts_search" '{"query":"Alice","schema":"fts_test","table":"customers","limit":5,"offset":0}')
search_json=$(extract_tool_result "${search_json}")
echo "${search_json}" | jq -e '.total_matches > 0' >/dev/null

echo "${search_json}" | jq -e '.results[0].snippet | contains("<mark>")' >/dev/null

log "Searching for 'order' across fts_test"
search_json=$(tool_call "fts_search" '{"query":"order","schema":"fts_test","limit":5,"offset":0}')
search_json=$(extract_tool_result "${search_json}")
echo "${search_json}" | jq -e '.total_matches >= 0' >/dev/null

log "Empty query should return error"
empty_json=$(tool_call "fts_search" '{"query":"","schema":"fts_test","limit":5,"offset":0}')
empty_json=$(extract_tool_result "${empty_json}")
echo "${empty_json}" | jq -e '.success == false' >/dev/null

log "Deleting and verifying index removal for fts_test.orders"
delete_resp=$(tool_call "fts_delete_index" '{"schema":"fts_test","table":"orders"}')
delete_resp=$(extract_tool_result "${delete_resp}")
echo "${delete_resp}" | jq -e '.success == true' >/dev/null

list_json=$(tool_call "fts_list_indexes" "{}")
list_json=$(extract_tool_result "${list_json}")
echo "${list_json}" | jq -e '(.indexes | map(select(.schema=="fts_test" and .table=="orders")) | length) == 0' >/dev/null

log "Rebuild all indexes and verify success"
rebuild_resp=$(tool_call "fts_rebuild_all" "{}")
rebuild_resp=$(extract_tool_result "${rebuild_resp}")
echo "${rebuild_resp}" | jq -e '.success == true' >/dev/null
echo "${rebuild_resp}" | jq -e '.total_indexes >= 0' >/dev/null

if [ "${CLEANUP}" = "true" ]; then
  log "Cleanup: deleting fts_test indexes (ignore if not found)"
  delete_resp=$(tool_call "fts_delete_index" '{"schema":"fts_test","table":"customers"}')
  delete_resp=$(extract_tool_result "${delete_resp}")
  echo "${delete_resp}" | jq -e '.success == true' >/dev/null || log "Note: customers index may not exist"

  delete_resp=$(tool_call "fts_delete_index" '{"schema":"fts_test","table":"orders"}')
  delete_resp=$(extract_tool_result "${delete_resp}")
  echo "${delete_resp}" | jq -e '.success == true' >/dev/null || log "Note: orders index may not exist"
fi

cleanup_sample_data

log "Detailed FTS tests completed successfully"
