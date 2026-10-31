#!/usr/bin/env bash
# Deterministic phase-A discovery wrapper used by the headless TAP smoke test.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../mcp_rules_testing/mcp_test_helpers.sh"

ENDPOINT="${PROXYSQL_MCP_ENDPOINT:-$(get_endpoint_url query)}"
TARGET_ID="${MCP_TARGET_ID:-}"
SCHEMA_FILTER=""
NOTES=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        --target-id)
            TARGET_ID="$2"
            shift 2
            ;;
        --schema)
            SCHEMA_FILTER="$2"
            shift 2
            ;;
        --notes)
            NOTES="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --target-id ID [--schema NAME] [--notes TEXT] [--endpoint URL]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "${TARGET_ID}" ]]; then
    echo "--target-id is required" >&2
    exit 2
fi
if [[ -z "${MCP_AUTH_TOKEN}" ]]; then
    echo "TAP_MCP_AUTH_TOKEN is required" >&2
    exit 2
fi
require_command curl
require_command jq

arguments="$(jq -cn \
    --arg target_id "${TARGET_ID}" \
    --arg schema "${SCHEMA_FILTER}" \
    --arg notes "${NOTES}" \
    '{target_id:$target_id}
     + (if $schema == "" then {} else {schema_filter:$schema} end)
     + (if $notes == "" then {} else {notes:$notes} end)')"
request="$(jq -cn --argjson arguments "${arguments}" \
    '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"discovery.run_static",arguments:$arguments}}')"

echo "=== Phase 1: Static Harvest ==="
echo "Endpoint: ${ENDPOINT}"
echo "Target ID: ${TARGET_ID}"
response="$(mcp_request_url "${ENDPOINT}" "${request}")"
echo "${response}" | jq .

if echo "${response}" | jq -e 'has("error") or (.result.isError == true)' >/dev/null; then
    echo "MCP static harvest returned an error" >&2
    exit 1
fi

inner="$(echo "${response}" | jq -er '.result.content[0].text')"
run_id="$(echo "${inner}" | jq -er '.run_id')"
echo "Run ID: ${run_id}"
