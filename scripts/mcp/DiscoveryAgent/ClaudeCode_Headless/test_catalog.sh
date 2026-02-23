#!/usr/bin/env bash
#
# Test catalog tools directly to verify they work
#

set -e

MCP_ENDPOINT="${PROXYSQL_MCP_ENDPOINT:-https://127.0.0.1:6071/mcp/query}"
RUN_ID="${1:-10}"
TARGET_ID="${2:-${MCP_TARGET_ID:-tap_mysql_default}}"

echo "=== Catalog Tools Test ==="
echo "Using MCP endpoint: $MCP_ENDPOINT"
echo "Using run_id: $RUN_ID"
echo "Using target_id: $TARGET_ID"
echo ""

echo "1. Testing catalog.list_objects..."
curl -k -s -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "catalog.list_objects",
      "arguments": {
        "run_id": '$RUN_ID',
        "target_id": "'$TARGET_ID'",
        "order_by": "name",
        "page_size": 5
      }
    }
  }' | jq .

echo ""
echo "2. Testing catalog.get_object..."
curl -k -s -X POST "$MCP_ENDPOINT" \
  -H "Content_type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "catalog.get_object",
      "arguments": {
        "run_id": '$RUN_ID',
        "target_id": "'$TARGET_ID'",
        "object_key": "codebase_community_template.users"
      }
    }
  }' | jq .

echo ""
echo "3. Testing llm.summary_upsert..."
curl -k -s -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "llm.summary_upsert",
      "arguments": {
        "agent_run_id": 1,
        "run_id": '$RUN_ID',
        "target_id": "'$TARGET_ID'",
        "object_id": 55,
        "summary": "{\"hypothesis\":\"Test user table\",\"grain\":\"one row per user\",\"primary_key\":[\"user_id\"],\"time_columns\":[\"created_at\"],\"example_questions\":[\"How many users do we have?\",\"Count users by registration date\"]}",
        "confidence": 0.9,
        "status": "stable",
        "sources": "{\"method\":\"catalog\",\"evidence\":\"schema analysis\"}"
      }
    }
  }' | jq .

echo ""
echo "=== Test Complete ==="
echo ""
echo "If you saw JSON responses above (not errors), catalog tools are working."
echo ""
echo "If you see errors or 'isError': true', check the ProxySQL log for details."
