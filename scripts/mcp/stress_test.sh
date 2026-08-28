#!/bin/bash
#
# stress_test.sh - Concurrent connection stress test for MCP tools
#
# Usage:
#   ./stress_test.sh [options]
#
# Options:
#   -n, --num-requests N   Number of concurrent requests (default: 10)
#   -t, --tool NAME        Tool to test (default: sample_rows)
#   -d, --delay SEC        Delay between requests in ms (default: 0)
#   -v, --verbose          Show individual responses
#   -h, --help             Show help
#

set -e

# Configuration
MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-6071}"
MCP_URL="https://${MCP_HOST}:${MCP_PORT}/query"

# Test options
NUM_REQUESTS="${NUM_REQUESTS:-10}"
TOOL_NAME="${TOOL_NAME:-sample_rows}"
DELAY_MS="${DELAY_MS:-0}"
VERBOSE=false

# Statistics
TOTAL_REQUESTS=0
SUCCESSFUL_REQUESTS=0
FAILED_REQUESTS=0
TOTAL_TIME=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Execute MCP request
mcp_request() {
    local id="$1"

    local payload
    payload=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "${TOOL_NAME}",
    "arguments": {"schema": "testdb", "table": "customers", "limit": 2}
  },
  "id": ${id}
}
EOF
)

    local start_time
    start_time=$(date +%s%N)

    local response
    response=$(curl -k -s -w "\n%{http_code}" -X POST "${MCP_URL}" \
        -H "Content-Type: application/json" \
        -d "${payload}" 2>/dev/null)

    local end_time
    end_time=$(date +%s%N)

    local duration
    duration=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds

    local body
    body=$(echo "$response" | head -n -1)

    local code
    code=$(echo "$response" | tail -n 1)

    echo "${body}|${duration}|${code}"
}

# Run concurrent requests
run_stress_test() {
    log_info "Running stress test with ${NUM_REQUESTS} concurrent requests..."
    log_info "Tool: ${TOOL_NAME}"
    log_info "Target: ${MCP_URL}"
    echo ""

    # Create temp directory for results
    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf ${tmpdir}" EXIT

    local pids=()

    # Launch requests in background
    for i in $(seq 1 "${NUM_REQUESTS}"); do
        (
            if [ -n "${DELAY_MS}" ] && [ "${DELAY_MS}" -gt 0 ]; then
                sleep $(( (RANDOM % ${DELAY_MS}) / 1000 )).$(( (RANDOM % 1000) ))
            fi

            local result
            result=$(mcp_request "${i}")

            local body
            local duration
            local code

            body=$(echo "${result}" | cut -d'|' -f1)
            duration=$(echo "${result}" | cut -d'|' -f2)
            code=$(echo "${result}" | cut -d'|' -f3)

            echo "${body}" > "${tmpdir}/response_${i}.json"
            echo "${duration}" > "${tmpdir}/duration_${i}.txt"
            echo "${code}" > "${tmpdir}/code_${i}.txt"
        ) &
        pids+=($!)
    done

    # Wait for all requests to complete
    local start_time
    start_time=$(date +%s)

    for pid in "${pids[@]}"; do
        wait ${pid} || true
    done

    local end_time
    end_time=$(date +%s)

    local total_wall_time
    total_wall_time=$((end_time - start_time))

    # Collect results
    for i in $(seq 1 "${NUM_REQUESTS}"); do
        TOTAL_REQUESTS=$((TOTAL_REQUESTS + 1))

        local code
        code=$(cat "${tmpdir}/code_${i}.txt" 2>/dev/null || echo "000")

        if [ "${code}" = "200" ]; then
            SUCCESSFUL_REQUESTS=$((SUCCESSFUL_REQUESTS + 1))
        else
            FAILED_REQUESTS=$((FAILED_REQUESTS + 1))
        fi

        local duration
        duration=$(cat "${tmpdir}/duration_${i}.txt" 2>/dev/null || echo "0")
        TOTAL_TIME=$((TOTAL_TIME + duration))

        if [ "${VERBOSE}" = "true" ]; then
            local body
            body=$(cat "${tmpdir}/response_${i}.json" 2>/dev/null || echo "{}")
            echo "Request ${i}: [${code}] ${duration}ms"
            if [ "${code}" != "200" ]; then
                echo "  Response: ${body}"
            fi
        fi
    done

    # Calculate statistics
    local avg_time
    if [ ${TOTAL_REQUESTS} -gt 0 ]; then
        avg_time=$((TOTAL_TIME / TOTAL_REQUESTS))
    else
        avg_time=0
    fi

    local requests_per_second
    if [ ${total_wall_time} -gt 0 ]; then
        requests_per_second=$(awk "BEGIN {printf \"%.2f\", ${NUM_REQUESTS} / ${total_wall_time}}")
    else
        requests_per_second="N/A"
    fi

    # Print summary
    echo ""
    echo "======================================"
    echo "Stress Test Results"
    echo "======================================"
    echo "Concurrent requests:  ${NUM_REQUESTS}"
    echo "Total wall time:      ${total_wall_time}s"
    echo ""
    echo "Total requests:       ${TOTAL_REQUESTS}"
    echo -e "Successful:           ${GREEN}${SUCCESSFUL_REQUESTS}${NC}"
    echo -e "Failed:               ${RED}${FAILED_REQUESTS}${NC}"
    echo ""
    echo "Average response time: ${avg_time}ms"
    echo "Requests/second:       ${requests_per_second}"
    echo ""

    # Calculate success rate
    if [ ${TOTAL_REQUESTS} -gt 0 ]; then
        local success_rate
        success_rate=$(awk "BEGIN {printf \"%.1f\", (${SUCCESSFUL_REQUESTS} * 100) / ${TOTAL_REQUESTS}}")
        echo "Success rate:          ${success_rate}%"
        echo ""

        if [ ${FAILED_REQUESTS} -eq 0 ]; then
            log_info "All requests succeeded!"
            return 0
        else
            log_error "Some requests failed!"
            return 1
        fi
    else
        log_error "No requests were completed!"
        return 1
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--num-requests)
                NUM_REQUESTS="$2"
                shift 2
                ;;
            -t|--tool)
                TOOL_NAME="$2"
                shift 2
                ;;
            -d|--delay)
                DELAY_MS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                cat <<EOF
Usage: $0 [options]

Run concurrent stress test against MCP tools.

Options:
  -n, --num-requests N   Number of concurrent requests (default: 10)
  -t, --tool NAME        Tool to test (default: sample_rows)
  -d, --delay SEC        Delay between requests in ms (default: 0)
  -v, --verbose          Show individual responses
  -h, --help             Show this help

Environment Variables:
  MCP_HOST            MCP server host (default: 127.0.0.1)
  MCP_PORT            MCP server port (default: 6071)

Examples:
  # Run 10 concurrent requests
  $0 -n 10

  # Run 50 concurrent requests with 100ms delay
  $0 -n 50 -d 100

  # Test different tool with verbose output
  $0 -t list_tables -v
EOF
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Main
parse_args "$@"
run_stress_test
