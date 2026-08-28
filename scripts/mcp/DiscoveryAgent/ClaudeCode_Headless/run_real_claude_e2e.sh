#!/usr/bin/env bash
#
# run_real_claude_e2e.sh
#
# Manual end-to-end runner:
# 1) phase-A static harvest
# 2) phase-B real Claude Code execution
#
# This script is intentionally NOT used by default TAP CI.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATIC_HARVEST="${SCRIPT_DIR}/static_harvest.sh"
TWO_PHASE="${SCRIPT_DIR}/two_phase_discovery.py"

TARGET_ID="${MCP_TARGET_ID:-}"
SCHEMA="${TEST_DB_NAME:-}"
MCP_CONFIG="${SCRIPT_DIR}/mcp_config.json"
MODEL="${CLAUDE_MODEL:-claude-3.5-sonnet}"
NOTES="real_claude_e2e"
ENDPOINT="${PROXYSQL_MCP_ENDPOINT:-https://127.0.0.1:6071/mcp/query}"
SKIP_PHASE_A=0

usage() {
    cat <<EOF
Usage: $0 --target-id ID --schema NAME [options]

Required:
  --target-id ID           MCP target_id
  --schema NAME            Schema/database to harvest

Optional:
  --mcp-config PATH        Claude Code MCP config (default: ${SCRIPT_DIR}/mcp_config.json)
  --model NAME             Claude model name (default: ${MODEL})
  --notes TEXT             Notes for static harvest (default: ${NOTES})
  --endpoint URL           MCP query endpoint (default: ${ENDPOINT})
  --skip-phase-a           Skip static harvest and use --run-id
  --run-id N               Existing run_id (required when --skip-phase-a)
  -h, --help               Show this help

Examples:
  $0 --target-id tap_mysql_default --schema testdb --mcp-config ./mcp_config.json
  $0 --target-id tap_pgsql_default --schema public --skip-phase-a --run-id 42
EOF
}

RUN_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-id) TARGET_ID="$2"; shift 2 ;;
        --schema) SCHEMA="$2"; shift 2 ;;
        --mcp-config) MCP_CONFIG="$2"; shift 2 ;;
        --model) MODEL="$2"; shift 2 ;;
        --notes) NOTES="$2"; shift 2 ;;
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --skip-phase-a) SKIP_PHASE_A=1; shift ;;
        --run-id) RUN_ID="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -z "${TARGET_ID}" || -z "${SCHEMA}" ]]; then
    usage
    exit 1
fi

if [[ ! -f "${MCP_CONFIG}" ]]; then
    echo "Error: MCP config file not found: ${MCP_CONFIG}" >&2
    exit 1
fi

if ! command -v claude >/dev/null 2>&1; then
    echo "Error: claude CLI is not installed or not in PATH" >&2
    exit 1
fi

if [[ "${SKIP_PHASE_A}" -eq 0 ]]; then
    echo "[1/2] Running static harvest..."
    out="$("${STATIC_HARVEST}" --endpoint "${ENDPOINT}" --target-id "${TARGET_ID}" --schema "${SCHEMA}" --notes "${NOTES}")"
    echo "${out}"
    RUN_ID="$(echo "${out}" | sed -n 's/^Run ID:[[:space:]]*\([0-9][0-9]*\)$/\1/p' | head -n1)"
    if [[ -z "${RUN_ID}" ]]; then
        echo "Error: could not extract run_id from static harvest output" >&2
        exit 1
    fi
else
    if [[ -z "${RUN_ID}" ]]; then
        echo "Error: --run-id is required when --skip-phase-a is used" >&2
        exit 1
    fi
fi

echo "[2/2] Running real Claude phase-B discovery..."
echo "target_id=${TARGET_ID} schema=${SCHEMA} run_id=${RUN_ID} model=${MODEL}"
python3 "${TWO_PHASE}" \
    --mcp-config "${MCP_CONFIG}" \
    --target-id "${TARGET_ID}" \
    --schema "${SCHEMA}" \
    --run-id "${RUN_ID}" \
    --model "${MODEL}"

echo "Done."
