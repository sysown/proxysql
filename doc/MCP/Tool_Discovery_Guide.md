# MCP Tool Discovery Guide

This guide explains how to discover and interact with MCP tools available on all endpoints, with a focus on the Query endpoint which includes database exploration and two-phase discovery tools.

## Overview

The MCP (Model Context Protocol) Query endpoint provides dynamic tool discovery through the `tools/list` method. This allows clients to:

1. Discover all available tools at runtime
2. Get detailed schemas for each tool (parameters, requirements, descriptions)
3. Dynamically adapt to new tools without code changes

## Endpoint Information

- **URL**: `https://127.0.0.1:6071/mcp/query`
- **Protocol**: JSON-RPC 2.0 over HTTPS
- **Authentication**: Bearer token (optional, if configured)

## Getting the Tool List

### Basic Request

```bash
curl -k -X POST https://127.0.0.1:6071/mcp/query \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 1
  }' | jq
```

### With Authentication

If authentication is configured:

```bash
curl -k -X POST https://127.0.0.1:6071/mcp/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 1
  }' | jq
```

### Using Query Parameter (Alternative)

If header authentication is not available:

```bash
curl -k -X POST "https://127.0.0.1:6071/mcp/query?token=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 1
  }' | jq
```

## Response Format

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "tools": [
      {
        "name": "tool_name",
        "description": "Tool description",
        "inputSchema": {
          "type": "object",
          "properties": {
            "param_name": {
              "type": "string|integer",
              "description": "Parameter description"
            }
          },
          "required": ["param1", "param2"]
        }
      }
    ]
  }
}
```

## Available Query Endpoint Tools

### Inventory Tools

#### list_targets
List logical query targets. Each target identifier maps internally to a ProxySQL hostgroup and routing policy.

Notes:
- Targets are loaded from server-side runtime profile tables and include backend auth mapping.
- MCP clients only use `target_id`; backend credentials are never sent in tool calls.

**Parameters:**
- None

#### list_schemas
List all available schemas/databases.

**Parameters:**
- `page_token` (string, optional) - Pagination token
- `page_size` (integer, optional) - Results per page (default: 50)
- `target_id` (string, optional) - Logical query target identifier

#### list_tables
List tables in a schema.

**Parameters:**
- `schema` (string, **required**) - Schema name
- `page_token` (string, optional) - Pagination token
- `page_size` (integer, optional) - Results per page (default: 50)
- `name_filter` (string, optional) - Filter table names by pattern
- `target_id` (string, optional) - Logical query target identifier

**Routing behavior:**
- Uses `SHOW TABLES` for MySQL targets and `information_schema.tables` for PostgreSQL targets.

### Structure Tools

#### describe_table
Get detailed table schema including columns, types, keys, and indexes.

**Parameters:**
- `schema` (string, **required**) - Schema name
- `table` (string, **required**) - Table name

#### get_constraints
Get constraints (foreign keys, unique constraints, etc.) for a table.

**Parameters:**
- `schema` (string, **required**) - Schema name
- `table` (string, optional) - Table name

### Profiling Tools

#### table_profile
Get table statistics including row count, size estimates, and data distribution.

**Parameters:**
- `schema` (string, **required**) - Schema name
- `table` (string, **required**) - Table name
- `mode` (string, optional) - Profile mode: "quick" or "full" (default: "quick")

#### column_profile
Get column statistics including distinct values, null count, and top values.

**Parameters:**
- `schema` (string, **required**) - Schema name
- `table` (string, **required**) - Table name
- `column` (string, **required**) - Column name
- `max_top_values` (integer, optional) - Maximum top values to return (default: 20)

### Sampling Tools

#### sample_rows
Get sample rows from a table (with hard cap on rows returned).

**Parameters:**
- `schema` (string, **required**) - Schema name
- `table` (string, **required**) - Table name
- `columns` (string, optional) - Comma-separated column names
- `where` (string, optional) - WHERE clause filter
- `order_by` (string, optional) - ORDER BY clause
- `limit` (integer, optional) - Maximum rows (default: 20)

#### sample_distinct
Sample distinct values from a column.

**Parameters:**
- `schema` (string, **required**) - Schema name
- `table` (string, **required**) - Table name
- `column` (string, **required**) - Column name
- `where` (string, optional) - WHERE clause filter
- `limit` (integer, optional) - Maximum values (default: 50)

### Query Tools

#### run_sql_readonly
Execute a read-only SQL query with safety guardrails enforced.

**Parameters:**
- `sql` (string, **required**) - SQL query to execute
- `target_id` (string, optional) - Logical query target identifier
- `max_rows` (integer, optional) - Maximum rows to return (default: 200)
- `timeout_sec` (integer, optional) - Query timeout (default: 2)

**Routing behavior:**
- If `target_id` points to a MySQL target, query executes with MySQL protocol.
- If `target_id` points to a PostgreSQL target, query executes with PostgreSQL protocol.

**Safety rules:**
- Must start with SELECT
- No dangerous keywords (DROP, DELETE, INSERT, UPDATE, etc.)
- SELECT * requires LIMIT clause

#### explain_sql
Explain a query execution plan using EXPLAIN or EXPLAIN ANALYZE.

**Parameters:**
- `sql` (string, **required**) - SQL query to explain
- `target_id` (string, optional) - Logical query target identifier

**Routing behavior:**
- Uses protocol-specific execution based on `target_id` (`mysql` or `pgsql` target).

### Relationship Inference Tools

#### suggest_joins
Suggest table joins based on heuristic analysis of column names and types.

**Parameters:**
- `schema` (string, **required**) - Schema name
- `table_a` (string, **required**) - First table
- `table_b` (string, optional) - Second table (if omitted, checks all)
- `max_candidates` (integer, optional) - Maximum join candidates (default: 5)

#### find_reference_candidates
Find tables that might be referenced by a foreign key column.

**Parameters:**
- `schema` (string, **required**) - Schema name
- `table` (string, **required**) - Table name
- `column` (string, **required**) - Column name
- `max_tables` (integer, optional) - Maximum tables to check (default: 50)

### Catalog Tools (LLM Memory)

#### catalog_upsert
Store or update an entry in the catalog (LLM external memory).

**Parameters:**
- `kind` (string, **required**) - Entry kind (e.g., "table", "relationship", "insight")
- `key` (string, **required**) - Unique identifier
- `document` (string, **required**) - JSON document with data
- `tags` (string, optional) - Comma-separated tags
- `links` (string, optional) - Comma-separated related keys

#### catalog_get
Retrieve an entry from the catalog.

**Parameters:**
- `kind` (string, **required**) - Entry kind
- `key` (string, **required**) - Entry key

#### catalog_search
Search the catalog for entries matching a query.

**Parameters:**
- `query` (string, **required**) - Search query
- `kind` (string, optional) - Filter by kind
- `tags` (string, optional) - Filter by tags
- `limit` (integer, optional) - Maximum results (default: 20)
- `offset` (integer, optional) - Results offset (default: 0)

#### catalog_list
List catalog entries by kind.

**Parameters:**
- `kind` (string, optional) - Filter by kind
- `limit` (integer, optional) - Maximum results (default: 50)
- `offset` (integer, optional) - Results offset (default: 0)

#### catalog_merge
Merge multiple catalog entries into a single consolidated entry.

**Parameters:**
- `keys` (string, **required**) - Comma-separated keys to merge
- `target_key` (string, **required**) - Target key for merged entry
- `kind` (string, optional) - Entry kind (default: "domain")
- `instructions` (string, optional) - Merge instructions

#### catalog_delete
Delete an entry from the catalog.

**Parameters:**
- `kind` (string, **required**) - Entry kind
- `key` (string, **required**) - Entry key

### Two-Phase Discovery Tools

#### discovery.run_static
Run Phase 1 of two-phase discovery: static harvest of database metadata.

**Parameters:**
- `schema_filter` (string, optional) - Filter schemas by name pattern
- `table_filter` (string, optional) - Filter tables by name pattern
- `run_id` (string, optional) - Custom run identifier

**Returns:**
- `run_id` - Unique identifier for this discovery run
- `objects_count` - Number of database objects discovered
- `schemas_count` - Number of schemas processed
- `tables_count` - Number of tables processed
- `columns_count` - Number of columns processed
- `indexes_count` - Number of indexes processed
- `constraints_count` - Number of constraints processed

#### agent.run_start
Start a new agent run for discovery coordination.

**Parameters:**
- `run_id` (string, **required**) - Discovery run identifier
- `agent_id` (string, **required**) - Agent identifier
- `capabilities` (array, optional) - List of agent capabilities

#### agent.run_finish
Mark an agent run as completed.

**Parameters:**
- `run_id` (string, **required**) - Discovery run identifier
- `agent_id` (string, **required**) - Agent identifier
- `status` (string, **required**) - Final status ("success", "error", "timeout")
- `summary` (string, optional) - Summary of work performed

#### agent.event_append
Append an event to an agent run.

**Parameters:**
- `run_id` (string, **required**) - Discovery run identifier
- `agent_id` (string, **required**) - Agent identifier
- `event_type` (string, **required**) - Type of event
- `data` (object, **required**) - Event data
- `timestamp` (string, optional) - ISO8601 timestamp

### LLM Interaction Tools

#### llm.summary_upsert
Store or update a table/column summary generated by LLM.

**Parameters:**
- `schema` (string, **required**) - Schema name
- `table` (string, **required**) - Table name
- `column` (string, optional) - Column name (if column-level summary)
- `summary` (string, **required**) - LLM-generated summary
- `confidence` (number, optional) - Confidence score (0.0-1.0)

#### llm.summary_get
Retrieve LLM-generated summary for a table or column.

**Parameters:**
- `schema` (string, **required**) - Schema name
- `table` (string, **required**) - Table name
- `column` (string, optional) - Column name

#### llm.relationship_upsert
Store or update an inferred relationship between tables.

**Parameters:**
- `source_schema` (string, **required**) - Source schema
- `source_table` (string, **required**) - Source table
- `target_schema` (string, **required**) - Target schema
- `target_table` (string, **required**) - Target table
- `confidence` (number, **required**) - Confidence score (0.0-1.0)
- `description` (string, **required**) - Relationship description
- `type` (string, optional) - Relationship type ("fk", "semantic", "usage")

#### llm.domain_upsert
Store or update a business domain classification.

**Parameters:**
- `domain_id` (string, **required**) - Domain identifier
- `name` (string, **required**) - Domain name
- `description` (string, **required**) - Domain description
- `confidence` (number, optional) - Confidence score (0.0-1.0)
- `tags` (array, optional) - Domain tags

#### llm.domain_set_members
Set the members (tables) of a business domain.

**Parameters:**
- `domain_id` (string, **required**) - Domain identifier
- `members` (array, **required**) - List of table identifiers
- `confidence` (number, optional) - Confidence score (0.0-1.0)

#### llm.metric_upsert
Store or update a business metric definition.

**Parameters:**
- `metric_id` (string, **required**) - Metric identifier
- `name` (string, **required**) - Metric name
- `description` (string, **required**) - Metric description
- `formula` (string, **required**) - SQL formula or description
- `domain_id` (string, optional) - Associated domain
- `tags` (array, optional) - Metric tags

#### llm.question_template_add
Add a question template that can be answered using this data.

**Parameters:**
- `template_id` (string, **required**) - Template identifier
- `question` (string, **required**) - Question template with placeholders
- `answer_plan` (object, **required**) - Steps to answer the question
- `complexity` (string, optional) - Complexity level ("low", "medium", "high")
- `estimated_time` (number, optional) - Estimated time in minutes
- `tags` (array, optional) - Template tags

#### llm.note_add
Add a general note or insight about the data.

**Parameters:**
- `note_id` (string, **required**) - Note identifier
- `content` (string, **required**) - Note content
- `type` (string, optional) - Note type ("insight", "warning", "recommendation")
- `confidence` (number, optional) - Confidence score (0.0-1.0)
- `tags` (array, optional) - Note tags

#### llm.search
Search LLM-generated content and insights.

**Parameters:**
- `query` (string, **required**) - Search query
- `type` (string, optional) - Content type to search ("summary", "relationship", "domain", "metric", "note")
- `schema` (string, optional) - Filter by schema
- `limit` (number, optional) - Maximum results (default: 10)

## Calling a Tool

### Request Format

```bash
curl -k -X POST https://127.0.0.1:6071/mcp/query \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "list_tables",
      "arguments": {
        "schema": "testdb"
      }
    },
    "id": 2
  }' | jq
```

### Response Format

```json
{
  "id": "2",
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "data": [...]
  }
}
```

### Error Response

```json
{
  "id": "2",
  "jsonrpc": "2.0",
  "result": {
    "success": false,
    "error": "Error message"
  }
}
```

## Python Examples

### Basic Tool Discovery

```python
import requests
import json

# Get tool list
response = requests.post(
    "https://127.0.0.1:6071/mcp/query",
    json={
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1
    },
    verify=False  # For self-signed cert
)

tools = response.json()["result"]["tools"]

# Print all tools
for tool in tools:
    print(f"\n{tool['name']}")
    print(f"  Description: {tool['description']}")
    print(f"  Required: {tool['inputSchema'].get('required', [])}")
```

### Calling a Tool

```python
def call_tool(tool_name, arguments):
    response = requests.post(
        "https://127.0.0.1:6071/mcp/query",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            },
            "id": 2
        },
        verify=False
    )
    return response.json()["result"]

# List tables
result = call_tool("list_tables", {"schema": "testdb"})
print(json.dumps(result, indent=2))

# Describe a table
result = call_tool("describe_table", {
    "schema": "testdb",
    "table": "customers"
})
print(json.dumps(result, indent=2))

# Run a query
result = call_tool("run_sql_readonly", {
    "sql": "SELECT * FROM customers LIMIT 10"
})
print(json.dumps(result, indent=2))
```

### Complete Example: Database Discovery

```python
import requests
import json

class MCPQueryClient:
    def __init__(self, host="127.0.0.1", port=6071, token=None):
        self.url = f"https://{host}:{port}/mcp/query"
        self.headers = {
            "Content-Type": "application/json",
            **({"Authorization": f"Bearer {token}"} if token else {})
        }

    def list_tools(self):
        response = requests.post(
            self.url,
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            headers=self.headers,
            verify=False
        )
        return response.json()["result"]["tools"]

    def call_tool(self, name, arguments):
        response = requests.post(
            self.url,
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
                "id": 2
            },
            headers=self.headers,
            verify=False
        )
        return response.json()["result"]

    def explore_schema(self, schema):
        """Explore a schema: list tables and their structures"""
        print(f"\n=== Exploring schema: {schema} ===\n")

        # List tables
        tables = self.call_tool("list_tables", {"schema": schema})
        for table in tables.get("data", []):
            table_name = table["name"]
            print(f"\nTable: {table_name}")
            print(f"  Type: {table['type']}")
            print(f"  Rows: {table.get('row_count', 'unknown')}")

            # Describe table
            schema_info = self.call_tool("describe_table", {
                "schema": schema,
                "table": table_name
            })

            if schema_info.get("success"):
                print(f"  Columns: {', '.join([c['name'] for c in schema_info['data']['columns']])}")

# Usage
client = MCPQueryClient()
client.explore_schema("testdb")
```

## Using the Test Script

The test script provides a convenient way to discover and test tools:

```bash
# List all discovered tools (without testing)
./scripts/mcp/test_mcp_tools.sh --list-only

# Test only query endpoint
./scripts/mcp/test_mcp_tools.sh --endpoint query

# Test specific tool with verbose output
./scripts/mcp/test_mcp_tools.sh --endpoint query --tool list_tables -v

# Test all endpoints
./scripts/mcp/test_mcp_tools.sh
```

## Other Endpoints

The same discovery pattern works for all MCP endpoints:

- **Config**: `/mcp/config` - Configuration management tools
- **Query**: `/mcp/query` - Database exploration, query, and discovery tools
- **Admin**: `/mcp/admin` - Administrative operations
- **Cache**: `/mcp/cache` - Cache management tools
- **Stats**: `/mcp/stats` - Monitoring and metrics tools
- **AI**: `/mcp/ai` - AI and LLM features

Simply change the endpoint URL:

```bash
curl -k -X POST https://127.0.0.1:6071/mcp/config \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

## Related Documentation

- [Architecture.md](Architecture.md) - Overall MCP architecture and endpoint specifications
- [VARIABLES.md](VARIABLES.md) - Configuration variables reference

## Version

- **Last Updated:** 2026-01-19
- **MCP Protocol:** JSON-RPC 2.0 over HTTPS
