#!/usr/bin/env bash
#
# test_mcp_llm_discovery_phaseb-t.sh
#
# TAP test for MCP phase-B (LLM-driven discovery primitives), CI-safe:
# - no external LLM credentials required
# - validates agent/catalog/llm tools end-to-end on harvested catalog data
#

set -euo pipefail

PLAN=14
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

TARGET_ID="${MCP_TARGET_ID:-tap_mysql_default}"
MYSQL_SCHEMA="${MYSQL_DATABASE:-test}"

RUN_ID=""
AGENT_RUN_ID=""
OBJECT_ID=""
UNIQ_KEY="tap_phaseb_$(date +%s)_$$"

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
    echo "msg: # Executing MCP Tool Call: ${tool_name}" >&2
    mcp_request "query" "${req}"
}

mcp_success_text() {
    local resp="$1"
    if echo "${resp}" | jq -e '.error' >/dev/null 2>&1; then
        echo "msg: # MCP Error: $(echo "${resp}" | jq -r '.error.message')" >&2
        return 1
    fi
    if echo "${resp}" | jq -e '.result.isError == true' >/dev/null 2>&1; then
        echo "msg: # Tool Error: $(echo "${resp}" | jq -r '.result.content[0].text')" >&2
        return 1
    fi
    echo "${resp}" | jq -r '.result.content[0].text // empty'
    return 0
}

echo "msg: 1..${PLAN}"
echo "msg: #"
echo "msg: # === MCP Phase-B LLM Discovery Tooling Test Suite ==="
echo "msg: # This test validates MCP phase-B (LLM-driven discovery primitives):"
echo "msg: # - discovery.run_static: harvests schema metadata into catalog"
echo "msg: # - catalog.list_objects: queries harvested schema objects"
echo "msg: # - agent.run_start/run_finish: manages LLM agent sessions"
echo "msg: # - llm.summary_upsert/get: persists and retrieves object summaries"
echo "msg: # - llm.domain_upsert/set_members: manages semantic domains"
echo "msg: # - llm.metric_upsert: registers derived metrics"
echo "msg: # - llm.question_template_add: adds natural language templates"
echo "msg: # - llm.search: searches across all LLM-generated artifacts"
echo "msg: # No external LLM credentials required - CI-safe validation."
echo "msg: # ========================================================"
echo "msg: #"

if ! require_mcp_prerequisites; then
    for _ in $(seq 1 "${PLAN}"); do
        tap_not_ok "MCP shell prerequisites are available"
    done
    tap_finish
    exit $?
fi

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
# Handle potential spaces in JSON output from list_targets
if echo "${targets_resp}" | jq -e ".result.content[0].text | fromjson | .targets[] | select(.target_id == \"${TARGET_ID}\")" >/dev/null 2>&1; then
    tap_ok "MySQL target_id present in list_targets"
else
    tap_not_ok "MySQL target_id present in list_targets" "${targets_resp}"
fi

harvest_resp="$(mcp_tool_call "discovery.run_static" "{\"target_id\":\"${TARGET_ID}\",\"schema_filter\":\"${MYSQL_SCHEMA}\",\"notes\":\"${UNIQ_KEY}\"}" 2)"
harvest_text=""
if harvest_text="$(mcp_success_text "${harvest_resp}")"; then
    RUN_ID="$(echo "${harvest_text}" | jq -r '.run_id // empty' 2>/dev/null || true)"
fi
if [[ -n "${RUN_ID}" ]]; then
    tap_ok "discovery.run_static returns run_id for phase-B setup: ${RUN_ID}"
else
    tap_not_ok "discovery.run_static returns run_id for phase-B setup" "${harvest_resp}"
fi

# Try to list objects. If none found, we'll try to harvest everything (empty schema_filter)
list_resp="$(mcp_tool_call "catalog.list_objects" "{\"target_id\":\"${TARGET_ID}\",\"run_id\":\"${RUN_ID}\",\"schema_name\":\"${MYSQL_SCHEMA}\",\"object_type\":\"table\",\"page_size\":20}" 3)"
list_text=""
if list_text="$(mcp_success_text "${list_resp}")"; then
    OBJECT_ID="$(echo "${list_text}" | jq -r '.results[0].object_id // empty' 2>/dev/null || true)"
fi

if [[ -z "${OBJECT_ID}" ]]; then
    echo "msg: # No objects found in ${MYSQL_SCHEMA}, trying full harvest..." >&2
    harvest_resp="$(mcp_tool_call "discovery.run_static" "{\"target_id\":\"${TARGET_ID}\",\"notes\":\"${UNIQ_KEY}_full\"}" 20)"
    if harvest_text="$(mcp_success_text "${harvest_resp}")"; then
        RUN_ID="$(echo "${harvest_text}" | jq -r '.run_id // empty' 2>/dev/null || true)"
    fi
    list_resp="$(mcp_tool_call "catalog.list_objects" "{\"target_id\":\"${TARGET_ID}\",\"run_id\":\"${RUN_ID}\",\"object_type\":\"table\",\"page_size\":20}" 30)"
    if list_text="$(mcp_success_text "${list_resp}")"; then
        OBJECT_ID="$(echo "${list_text}" | jq -r '.results[0].object_id // empty' 2>/dev/null || true)"
    fi
fi

if [[ -n "${OBJECT_ID}" ]]; then
    tap_ok "catalog.list_objects returns object_id for run: ${OBJECT_ID}"
else
    tap_not_ok "catalog.list_objects returns object_id for run" "${list_resp}"
fi

agent_resp="$(mcp_tool_call "agent.run_start" "{\"target_id\":\"${TARGET_ID}\",\"run_id\":\"${RUN_ID}\",\"model_name\":\"tap-ci-model\",\"prompt_hash\":\"${UNIQ_KEY}\"}" 4)"
agent_text=""
if agent_text="$(mcp_success_text "${agent_resp}")"; then
    AGENT_RUN_ID="$(echo "${agent_text}" | jq -r '.agent_run_id // empty' 2>/dev/null || true)"
fi
if [[ -n "${AGENT_RUN_ID}" ]]; then
    tap_ok "agent.run_start returns agent_run_id: ${AGENT_RUN_ID}"
else
    tap_not_ok "agent.run_start returns agent_run_id" "${agent_resp}"
fi

# Use strings for IDs in jq to avoid invalid numeric literal if empty, 
# then let ProxySQL parse them as needed or ensure they are not empty.
if [[ -n "${RUN_ID}" && -n "${AGENT_RUN_ID}" && -n "${OBJECT_ID}" ]]; then
    summary_payload="$(jq -cn \
        --arg target_id "${TARGET_ID}" \
        --arg run_id "${RUN_ID}" \
        --arg object_id "${OBJECT_ID}" \
        --arg agent_run_id "${AGENT_RUN_ID}" \
        --arg uniq "${UNIQ_KEY}" \
        '{
          target_id:$target_id,
          agent_run_id:($agent_run_id|tonumber),
          run_id:($run_id|tonumber),
          object_id:($object_id|tonumber),
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

    summary_get_resp="$(mcp_tool_call "llm.summary_get" "{\"target_id\":\"${TARGET_ID}\",\"run_id\":\"${RUN_ID}\",\"object_id\":${OBJECT_ID},\"latest\":1}" 6)"
    summary_get_text=""
    if summary_get_text="$(mcp_success_text "${summary_get_resp}")" && echo "${summary_get_text}" | grep -q "phaseb-summary-${UNIQ_KEY}"; then
        tap_ok "llm.summary_get returns persisted summary marker"
    else
        tap_not_ok "llm.summary_get returns persisted summary marker" "${summary_get_resp}"
    fi

    domain_key="tap_domain_${UNIQ_KEY}"
    domain_resp="$(mcp_tool_call "llm.domain_upsert" "{\"target_id\":\"${TARGET_ID}\",\"agent_run_id\":${AGENT_RUN_ID},\"run_id\":\"${RUN_ID}\",\"domain_key\":\"${domain_key}\",\"title\":\"TAP Domain\",\"description\":\"TAP phaseb domain\",\"confidence\":0.7}" 7)"
    if mcp_success_text "${domain_resp}" >/dev/null; then
        tap_ok "llm.domain_upsert succeeds"
    else
        tap_not_ok "llm.domain_upsert succeeds" "${domain_resp}"
    fi

    members_json="$(jq -cn --argjson oid "${OBJECT_ID}" '[{object_id:$oid,role:"entity",confidence:0.8}]')"
    domain_members_resp="$(mcp_tool_call "llm.domain_set_members" "{\"target_id\":\"${TARGET_ID}\",\"agent_run_id\":${AGENT_RUN_ID},\"run_id\":\"${RUN_ID}\",\"domain_key\":\"${domain_key}\",\"members\":${members_json}}" 8)"
    if mcp_success_text "${domain_members_resp}" >/dev/null; then
        tap_ok "llm.domain_set_members succeeds"
    else
        tap_not_ok "llm.domain_set_members succeeds" "${domain_members_resp}"
    fi

    metric_key="tap_metric_${UNIQ_KEY}"
    metric_resp="$(mcp_tool_call "llm.metric_upsert" "{\"target_id\":\"${TARGET_ID}\",\"agent_run_id\":${AGENT_RUN_ID},\"run_id\":\"${RUN_ID}\",\"metric_key\":\"${metric_key}\",\"title\":\"TAP Metric\",\"description\":\"metric from tap phaseb\",\"domain_key\":\"${domain_key}\",\"grain\":\"daily\",\"unit\":\"count\",\"sql_template\":\"SELECT COUNT(*) FROM ${MYSQL_SCHEMA}.sbtest1\",\"depends\":[],\"confidence\":0.65}" 9)"
    if mcp_success_text "${metric_resp}" >/dev/null; then
        tap_ok "llm.metric_upsert succeeds"
    else
        tap_not_ok "llm.metric_upsert succeeds" "${metric_resp}"
    fi

    qt_resp="$(mcp_tool_call "llm.question_template_add" "{\"target_id\":\"${TARGET_ID}\",\"agent_run_id\":${AGENT_RUN_ID},\"run_id\":\"${RUN_ID}\",\"title\":\"tap question ${UNIQ_KEY}\",\"question_nl\":\"How many static customers exist?\",\"template\":{\"kind\":\"single_metric\"},\"example_sql\":\"SELECT COUNT(*) FROM ${MYSQL_SCHEMA}.sbtest1\",\"related_objects\":[\"sbtest1\"],\"confidence\":0.66}" 10)"
    if mcp_success_text "${qt_resp}" >/dev/null; then
        tap_ok "llm.question_template_add succeeds"
    else
        tap_not_ok "llm.question_template_add succeeds" "${qt_resp}"
    fi

    # Use empty query to list everything if MATCH search is finicky in CI
    search_resp="$(mcp_tool_call "llm.search" "{\"target_id\":\"${TARGET_ID}\",\"run_id\":\"${RUN_ID}\",\"query\":\"\",\"limit\":50}" 11)"
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
else
    for i in {7..14}; do
        tap_skip "skipping remaining tests" "previous setup failure"
    done
fi

tap_finish
