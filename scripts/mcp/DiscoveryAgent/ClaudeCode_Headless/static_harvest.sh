#!/usr/bin/env bash
#
# static_harvest.sh - Wrapper for Phase 1 static discovery
#
# Triggers ProxySQL's deterministic metadata harvest via the MCP endpoint.
# No Claude Code required.
#
# Usage:
#   ./static_harvest.sh --target-id TARGET_ID [--schema SCHEMA] [--notes NOTES] [--endpoint URL]
#
# Examples:
#   ./static_harvest.sh --target-id tap_mysql_default
#   ./static_harvest.sh --target-id tap_mysql_default --schema sales
#   ./static_harvest.sh --target-id tap_pgsql_default --schema public --notes "Prod DB discovery"
#   ./static_harvest.sh --endpoint https://192.168.1.100:6071/mcp/query

set -e

# Default values
ENDPOINT="${PROXYSQL_MCP_ENDPOINT:-https://127.0.0.1:6071/mcp/query}"
SCHEMA_FILTER=""
NOTES=""
TARGET_ID="${MCP_TARGET_ID:-}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --schema)
            SCHEMA_FILTER="$2"
            shift 2
            ;;
        --target-id)
            TARGET_ID="$2"
            shift 2
            ;;
        --notes)
            NOTES="$2"
            shift 2
            ;;
        --endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --target-id TARGET_ID [--schema SCHEMA] [--notes NOTES] [--endpoint URL]"
            echo ""
            echo "Options:"
            echo "  --target-id ID      Logical MCP target_id (required)"
            echo "  --schema SCHEMA    Restrict harvest to one MySQL schema (optional)"
            echo "  --notes NOTES      Optional notes for this discovery run"
            echo "  --endpoint URL     ProxySQL MCP endpoint (default: PROXYSQL_MCP_ENDPOINT env var or https://127.0.0.1:6071/mcp/query)"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  PROXYSQL_MCP_ENDPOINT  Default MCP endpoint URL"
            echo ""
            echo "Examples:"
            echo "  $0 --target-id tap_mysql_default"
            echo "  $0 --target-id tap_mysql_default --schema sales"
            echo "  $0 --target-id tap_pgsql_default --schema public --notes 'Prod DB discovery'"
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

if [[ -z "$TARGET_ID" ]]; then
    echo "Error: --target-id is required"
    echo "Use --help for usage information"
    exit 1
fi

# Build JSON arguments
JSON_ARGS="{}"
JSON_ARGS=$(echo "$JSON_ARGS" | jq --arg target_id "$TARGET_ID" '. + {target_id: $target_id}')

if [[ -n "$SCHEMA_FILTER" ]]; then
    JSON_ARGS=$(echo "$JSON_ARGS" | jq --arg schema "$SCHEMA_FILTER" '. + {schema_filter: $schema}')
fi

if [[ -n "$NOTES" ]]; then
    JSON_ARGS=$(echo "$JSON_ARGS" | jq --arg notes "$NOTES" '. + {notes: $notes}')
fi

# Build the full JSON-RPC request
JSON_REQUEST=$(jq -n \
    --argjson args "$JSON_ARGS" \
    '{
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
            name: "discovery.run_static",
            arguments: $args
        }
    }')

# Display what we're doing
echo "=== Phase 1: Static Harvest ==="
echo "Endpoint: $ENDPOINT"
echo "Target ID: $TARGET_ID"
if [[ -n "$SCHEMA_FILTER" ]]; then
    echo "Schema: $SCHEMA_FILTER"
else
    echo "Schema: all schemas"
fi
if [[ -n "$NOTES" ]]; then
    echo "Notes: $NOTES"
fi
echo ""

# Execute the curl command
# Disable SSL verification (-k) for self-signed certificates
curl_result=$(curl -k -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "$JSON_REQUEST")

# Check for curl errors
if [[ $? -ne 0 ]]; then
    echo "Error: Failed to connect to ProxySQL MCP endpoint at $ENDPOINT"
    echo "Make sure ProxySQL is running with MCP enabled."
    exit 1
fi

# Check for database directory errors
if echo "$curl_result" | grep -q "no such table: fts_objects"; then
    echo ""
    echo "Error: FTS table missing. This usually means the discovery catalog directory doesn't exist."
    echo "Please create it:"
    echo "  sudo mkdir -p /var/lib/proxysql"
    echo "  sudo chown \$USER:\$USER /var/lib/proxysql"
    echo "Then restart ProxySQL."
    exit 1
fi

# Pretty-print the result
echo "$curl_result" | jq .

# Check for JSON-RPC errors
if echo "$curl_result" | jq -e '.error' > /dev/null 2>&1; then
    echo ""
    echo "Error: Server returned an error:"
    echo "$curl_result" | jq -r '.error.message'
    exit 1
fi

# Display summary - extract from nested content[0].text JSON string
echo ""
if echo "$curl_result" | jq -e '.result.content[0].text' > /dev/null 2>&1; then
    # Extract the JSON string from content[0].text and parse it
    INNER_JSON=$(echo "$curl_result" | jq -r '.result.content[0].text' 2>/dev/null)

    if [[ -n "$INNER_JSON" ]]; then
        RUN_ID=$(echo "$INNER_JSON" | jq -r '.run_id // empty')
        OBJECTS_COUNT=$(echo "$INNER_JSON" | jq -r '.objects.table // 0')
        COLUMNS_COUNT=$(echo "$INNER_JSON" | jq -r '.columns // 0')
        INDEXES_COUNT=$(echo "$INNER_JSON" | jq -r '.indexes // 0')
        FKS_COUNT=$(echo "$INNER_JSON" | jq -r '.foreign_keys // 0')

        echo "=== Harvest Summary ==="
        echo "Run ID: $RUN_ID"
        echo "Objects discovered: $OBJECTS_COUNT"
        echo "Columns discovered: $COLUMNS_COUNT"
        echo "Indexes discovered: $INDEXES_COUNT"
        echo "Foreign keys discovered: $FKS_COUNT"
    fi
fi
