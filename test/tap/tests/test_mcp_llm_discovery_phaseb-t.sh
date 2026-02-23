#!/usr/bin/env bash
#
# test_mcp_llm_discovery_phaseb-t.sh
#
# TAP test for MCP phase-B (LLM-driven discovery primitives), CI-safe:
# - no external LLM credentials required
# - validates agent/catalog/llm tools end-to-end on harvested catalog data
#

set -euo pipefail

PLAN=12
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

MCP_MYSQL_TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
MYSQL_SCHEMA="${MYSQL_DATABASE:-testdb}"

RUN_ID=""
AGENT_RUN_ID=""
OBJECT_ID=""
UNIQ_KEY="tap_phaseb_$(date +%s)"

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

mcp_tool_call() {
    local tool_name="$1"
    local args_json="$2"
    local req_id="$3"
    local req
    req="$(jq -cn --arg name "${tool_name}" --argjson args "${args_json}" --argjson id "${req_id}" \
        '{jsonrpc:"2.0",id:$id,method:"tools/call",params:{name:$name,arguments:$args}}')"
    mcp_request "query" "${req}"
}

mcp_success_text() {
    local resp="$1"
    if echo "${resp}" | jq -e '.error' >/dev/null 2>&1; then
        return 1
    fi
    if echo "${resp}" | jq -e '.result.isError == true' >/dev/null 2>&1; then
        return 1
    fi
    echo "${resp}" | jq -r '.result.content[0].text // empty'
    return 0
}

echo "msg: 1..${PLAN}"
echo "msg: # MCP Phase-B LLM Discovery Tooling Test Suite"

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

targets_resp="$(mcp_tool_call "list_targets" '{}' 1)"
if echo "${targets_resp}" | grep -q "\"target_id\":\"${MCP_MYSQL_TARGET_ID}\""; then
    tap_ok "MySQL target_id present in list_targets"
else
    tap_not_ok "MySQL target_id present in list_targets" "${targets_resp}"
fi

harvest_resp="$(mcp_tool_call "discovery.run_static" "{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"schema_filter\":\"${MYSQL_SCHEMA}\",\"notes\":\"${UNIQ_KEY}\"}" 2)"
harvest_text=""
if harvest_text="$(mcp_success_text "${harvest_resp}")"; then
    RUN_ID="$(echo "${harvest_text}" | jq -r '.run_id // empty' 2>/dev/null || true)"
fi
if [[ -n "${RUN_ID}" ]]; then
    tap_ok "discovery.run_static returns run_id for phase-B setup"
else
    tap_not_ok "discovery.run_static returns run_id for phase-B setup" "${harvest_resp}"
fi

list_resp="$(mcp_tool_call "catalog.list_objects" "{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"run_id\":\"${RUN_ID}\",\"schema_name\":\"${MYSQL_SCHEMA}\",\"object_type\":\"table\",\"page_size\":20}" 3)"
list_text=""
if list_text="$(mcp_success_text "${list_resp}")"; then
    OBJECT_ID="$(echo "${list_text}" | jq -r '.results[0].object_id // empty' 2>/dev/null || true)"
fi
if [[ -n "${OBJECT_ID}" ]]; then
    tap_ok "catalog.list_objects returns object_id for run"
else
    tap_not_ok "catalog.list_objects returns object_id for run" "${list_resp}"
fi

agent_resp="$(mcp_tool_call "agent.run_start" "{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"run_id\":\"${RUN_ID}\",\"model_name\":\"tap-ci-model\",\"prompt_hash\":\"${UNIQ_KEY}\"}" 4)"
agent_text=""
if agent_text="$(mcp_success_text "${agent_resp}")"; then
    AGENT_RUN_ID="$(echo "${agent_text}" | jq -r '.agent_run_id // empty' 2>/dev/null || true)"
fi
if [[ -n "${AGENT_RUN_ID}" ]]; then
    tap_ok "agent.run_start returns agent_run_id"
else
    tap_not_ok "agent.run_start returns agent_run_id" "${agent_resp}"
fi

summary_payload="$(jq -cn \
    --arg target_id "${MCP_MYSQL_TARGET_ID}" \
    --arg run_id "${RUN_ID}" \
    --argjson object_id "${OBJECT_ID}" \
    --argjson agent_run_id "${AGENT_RUN_ID}" \
    --arg uniq "${UNIQ_KEY}" \
    '{
      target_id:$target_id,
      agent_run_id:$agent_run_id,
      run_id:$run_id,
      object_id:$object_id,
      summary:{
        hypothesis:("phaseb-summary-" + $uniq),
        grain:"one row per entity",
        primary_key:["id"],
        time_columns:[],
        dimensions:[],
        measures:[],
        join_keys:[],
        example_questions:["What is this table used for?"],
        warnings:[]
      },
      confidence:0.75,
      status:"draft",
      sources:{source:"tap-phaseb"}
    }')"
summary_resp="$(mcp_tool_call "llm.summary_upsert" "${summary_payload}" 5)"
if mcp_success_text "${summary_resp}" >/dev/null; then
    tap_ok "llm.summary_upsert succeeds"
else
    tap_not_ok "llm.summary_upsert succeeds" "${summary_resp}"
fi

summary_get_resp="$(mcp_tool_call "llm.summary_get" "{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"run_id\":\"${RUN_ID}\",\"object_id\":${OBJECT_ID},\"latest\":1}" 6)"
summary_get_text=""
if summary_get_text="$(mcp_success_text "${summary_get_resp}")" && echo "${summary_get_text}" | grep -q "phaseb-summary-${UNIQ_KEY}"; then
    tap_ok "llm.summary_get returns persisted summary marker"
else
    tap_not_ok "llm.summary_get returns persisted summary marker" "${summary_get_resp}"
fi

domain_key="tap_domain_${UNIQ_KEY}"
domain_resp="$(mcp_tool_call "llm.domain_upsert" "{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"agent_run_id\":${AGENT_RUN_ID},\"run_id\":\"${RUN_ID}\",\"domain_key\":\"${domain_key}\",\"title\":\"TAP Domain\",\"description\":\"TAP phaseb domain\",\"confidence\":0.7}" 7)"
if mcp_success_text "${domain_resp}" >/dev/null; then
    tap_ok "llm.domain_upsert succeeds"
else
    tap_not_ok "llm.domain_upsert succeeds" "${domain_resp}"
fi

members_json="$(jq -cn --argjson oid "${OBJECT_ID}" '[{object_id:$oid,role:"entity",confidence:0.8}]')"
domain_members_resp="$(mcp_tool_call "llm.domain_set_members" "{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"agent_run_id\":${AGENT_RUN_ID},\"run_id\":\"${RUN_ID}\",\"domain_key\":\"${domain_key}\",\"members\":${members_json}}" 8)"
if mcp_success_text "${domain_members_resp}" >/dev/null; then
    tap_ok "llm.domain_set_members succeeds"
else
    tap_not_ok "llm.domain_set_members succeeds" "${domain_members_resp}"
fi

metric_key="tap_metric_${UNIQ_KEY}"
metric_resp="$(mcp_tool_call "llm.metric_upsert" "{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"agent_run_id\":${AGENT_RUN_ID},\"run_id\":\"${RUN_ID}\",\"metric_key\":\"${metric_key}\",\"title\":\"TAP Metric\",\"description\":\"metric from tap phaseb\",\"domain_key\":\"${domain_key}\",\"grain\":\"daily\",\"unit\":\"count\",\"sql_template\":\"SELECT COUNT(*) FROM ${MYSQL_SCHEMA}.tap_mysql_static_customers\",\"depends\":[],\"confidence\":0.65}" 9)"
if mcp_success_text "${metric_resp}" >/dev/null; then
    tap_ok "llm.metric_upsert succeeds"
else
    tap_not_ok "llm.metric_upsert succeeds" "${metric_resp}"
fi

qt_resp="$(mcp_tool_call "llm.question_template_add" "{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"agent_run_id\":${AGENT_RUN_ID},\"run_id\":\"${RUN_ID}\",\"title\":\"tap question ${UNIQ_KEY}\",\"question_nl\":\"How many static customers exist?\",\"template\":{\"kind\":\"single_metric\"},\"example_sql\":\"SELECT COUNT(*) FROM ${MYSQL_SCHEMA}.tap_mysql_static_customers\",\"related_objects\":[\"tap_mysql_static_customers\"],\"confidence\":0.66}" 10)"
if mcp_success_text "${qt_resp}" >/dev/null; then
    tap_ok "llm.question_template_add succeeds"
else
    tap_not_ok "llm.question_template_add succeeds" "${qt_resp}"
fi

search_resp="$(mcp_tool_call "llm.search" "{\"target_id\":\"${MCP_MYSQL_TARGET_ID}\",\"run_id\":\"${RUN_ID}\",\"query\":\"phaseb-summary-${UNIQ_KEY}\",\"limit\":5}" 11)"
search_text=""
if search_text="$(mcp_success_text "${search_resp}")" && echo "${search_text}" | grep -q "phaseb-summary-${UNIQ_KEY}"; then
    tap_ok "llm.search finds persisted phase-B artifact"
else
    tap_not_ok "llm.search finds persisted phase-B artifact" "${search_resp}"
fi

finish_resp="$(mcp_tool_call "agent.run_finish" "{\"agent_run_id\":${AGENT_RUN_ID},\"status\":\"success\"}" 12)"
if mcp_success_text "${finish_resp}" >/dev/null; then
    tap_ok "agent.run_finish succeeds"
else
    tap_not_ok "agent.run_finish succeeds" "${finish_resp}"
fi

if [[ "${FAIL}" -ne 0 ]]; then
    echo "msg: # FAILURES=${FAIL}/${PLAN}"
    exit 1
fi
exit 0
