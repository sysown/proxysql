#!/bin/bash
#
# Interactive MCP Query Agent Demo using Claude Code
#
# Usage: ./demo_agent_claude.sh <schema_name>
#
# Example: ./demo_agent_claude.sh Chinook
#

set -e

SCHEMA="${1:-Chinook}"
MCP_CATALOG_DB="/home/rene/proxysql-vec/src/mcp_catalog.db"

# Check if catalog exists
if [ ! -f "$MCP_CATALOG_DB" ]; then
    echo "Error: MCP catalog database not found at $MCP_CATALOG_DB"
    echo "Please run two-phase discovery first."
    exit 1
fi

# Get script directory to find paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create MCP config
MCP_CONFIG_FILE=$(mktemp)
cat > "$MCP_CONFIG_FILE" << EOF
{
  "mcpServers": {
    "proxysql": {
      "command": "python3",
      "args": ["$SCRIPT_DIR/proxysql_mcp_stdio_bridge.py"],
      "env": {
        "PROXYSQL_MCP_ENDPOINT": "https://127.0.0.1:6071/mcp/query",
        "PROXYSQL_MCP_TOKEN": "",
        "PROXYSQL_MCP_INSECURE_SSL": "1"
      }
    }
  }
}
EOF

# Create system prompt using heredoc to preserve special characters
SYSTEM_PROMPT_FILE=$(mktemp)
cat > "$SYSTEM_PROMPT_FILE" << 'ENDPROMPT'
You are an intelligent SQL Query Agent for the Chinook database schema. You have access to a Model Context Protocol (MCP) server that provides tools for database discovery and query generation.

## Available MCP Tools

You have access to these MCP tools (use mcp__proxysql-stdio__ prefix):

1. **llm_search** - Search for similar pre-defined queries and LLM artifacts
   - Parameters: run_id (schema name), query (search terms - use empty string to list all), limit
   - Returns: List of matching question templates, metrics, notes with scores
   - Use this FIRST when user asks a question

2. **catalog_list_objects** - List all tables/views in the schema
   - Parameters: run_id, page_size
   - Returns: Tables with row counts, sizes, etc.

3. **catalog_get_object** - Get detailed schema for a specific table
   - Parameters: run_id, schema_name, object_name
   - Returns: Columns, indexes, foreign keys

4. **run_sql_readonly** - Execute a read-only SQL query
   - Parameters: sql (the query to execute)
   - Returns: Query results

## Your Workflow - Show Step by Step

When a user asks a natural language question, follow these steps explicitly:

Step 1: Search for Similar Queries
- Call llm_search with the user's question keywords
- Show the results you get

Step 2: Analyze Results
- If you found a close match (score < -3.0), explain you'll reuse it
- If no good match, explain you'll generate a new query

Step 3: Get Schema Details (if needed)
- Call catalog_get_object for relevant tables
- Show the table structure

Step 4: Execute Query
- Call run_sql_readonly with the SQL
- Show the results

Step 5: Present Results
- Format the results nicely for the user

## Important Notes

- Always show your work - Explain each step you're taking
- Use llm_search first - Reuse existing queries when possible
- Score interpretation: Lower scores = better match (< -3.0 is good)
- If no good match: Generate SQL from scratch using catalog schema
- run_id: Always use 'Chinook' as the run_id

## Special Case: "What questions can I ask?"

When the user asks:
- "What questions can I ask?"
- "What are some example questions?"
- "Show me available questions"

DO NOT infer questions from schema. Instead:
1. Call llm_search with query="" (empty string) to list all existing question templates
2. Present the question templates grouped by type (question_template, metric, etc.)
3. Show the title and body (the actual question) for each

Example output:
Step 1: List all available question templates...
[Call llm_search with query=""]

Step 2: Found X pre-defined questions:

Question Templates:
- What is the total revenue?
- Who are the top customers?
- ...

Metrics:
- Revenue by Country
- Monthly Revenue Trend
- ...

## Example Interaction

User: "What are the most expensive tracks?"

Your response:
Step 1: Search for similar queries...
[llm_search call]
Step 2: Found match: "Most Expensive Tracks" (score: -0.66)
Step 3: Execute the query...
[run_sql_readonly call]
Step 4: Results: [table of tracks]

---

Ready to help! Ask me anything about the Chinook database.
ENDPROMPT

# Create append prompt (initial task)
APPEND_PROMPT_FILE=$(mktemp)
cat > "$APPEND_PROMPT_FILE" << 'ENDAPPEND'

---

INITIAL REQUEST: Show me how you would answer the question: "What are the most expensive tracks?"

Please walk through each step explicitly, showing:
1. The llm_search call and results
2. How you interpret the results
3. The final SQL execution
4. The formatted results

This is a demonstration, so be very verbose about your process.
ENDAPPEND

echo "=========================================="
echo "  MCP Query Agent Demo - Schema: $SCHEMA"
echo "=========================================="
echo ""
echo "Starting Claude Code with MCP tools enabled..."
echo ""

# Start Claude Code with the MCP config
claude --mcp-config "$MCP_CONFIG_FILE" \
    --system-prompt "$(cat "$SYSTEM_PROMPT_FILE")" \
    --append-system-prompt "$(cat "$APPEND_PROMPT_FILE")"

# Cleanup
rm -f "$MCP_CONFIG_FILE" "$SYSTEM_PROMPT_FILE" "$APPEND_PROMPT_FILE"
