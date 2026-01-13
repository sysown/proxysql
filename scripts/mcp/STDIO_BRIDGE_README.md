# ProxySQL MCP stdio Bridge

A bridge that converts between **stdio-based MCP** (for Claude Code) and **ProxySQL's HTTPS MCP endpoint**.

## What It Does

```
┌─────────────┐     stdio      ┌──────────────────┐     HTTPS      ┌──────────┐
│  Claude Code│  ──────────>  │  stdio Bridge    │  ──────────>  │ ProxySQL │
│  (MCP Client)│               │  (this script)   │               │  MCP     │
└─────────────┘               └──────────────────┘               └──────────┘
```

- **To Claude Code**: Acts as an MCP Server (stdio transport)
- **To ProxySQL**: Acts as an MCP Client (HTTPS transport)

## Installation

1. Install dependencies:
```bash
pip install httpx
```

2. Make the script executable:
```bash
chmod +x proxysql_mcp_stdio_bridge.py
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PROXYSQL_MCP_ENDPOINT` | Yes | - | ProxySQL MCP endpoint URL (e.g., `https://127.0.0.1:6071/mcp/query`) |
| `PROXYSQL_MCP_TOKEN` | No | - | Bearer token for authentication (if configured) |
| `PROXYSQL_MCP_INSECURE_SSL` | No | 0 | Set to 1 to disable SSL verification (for self-signed certs) |

### Configure in Claude Code

Add to your Claude Code MCP settings (usually `~/.config/claude-code/mcp_config.json` or similar):

```json
{
  "mcpServers": {
    "proxysql": {
      "command": "python3",
      "args": ["/home/rene/proxysql-vec/scripts/mcp/proxysql_mcp_stdio_bridge.py"],
      "env": {
        "PROXYSQL_MCP_ENDPOINT": "https://127.0.0.1:6071/mcp/query",
        "PROXYSQL_MCP_TOKEN": "your_token_here",
        "PROXYSQL_MCP_INSECURE_SSL": "1"
      }
    }
  }
}
```

### Quick Test from Terminal

```bash
export PROXYSQL_MCP_ENDPOINT="https://127.0.0.1:6071/mcp/query"
export PROXYSQL_MCP_TOKEN="your_token"  # optional
export PROXYSQL_MCP_INSECURE_SSL="1"   # for self-signed certs

python3 proxysql_mcp_stdio_bridge.py
```

Then send a JSON-RPC request via stdin:
```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
```

## Supported MCP Methods

| Method | Description |
|--------|-------------|
| `initialize` | Handshake protocol |
| `tools/list` | List available ProxySQL MCP tools |
| `tools/call` | Call a ProxySQL MCP tool |
| `ping` | Health check |

## Available Tools (from ProxySQL)

Once connected, the following tools will be available in Claude Code:

- `list_schemas` - List databases
- `list_tables` - List tables in a schema
- `describe_table` - Get table structure
- `get_constraints` - Get foreign keys and constraints
- `sample_rows` - Sample data from a table
- `run_sql_readonly` - Execute read-only SQL queries
- `explain_sql` - Get query execution plan
- `table_profile` - Get table statistics
- `column_profile` - Get column statistics
- `catalog_upsert` - Store data in the catalog
- `catalog_get` - Retrieve from the catalog
- `catalog_search` - Search the catalog
- And more...

## Example Usage in Claude Code

Once configured, you can ask Claude:

> "List all tables in the testdb schema"
> "Describe the customers table"
> "Show me 5 rows from the orders table"
> "Run SELECT COUNT(*) FROM customers"

## Logging

For debugging, the bridge writes logs to `/tmp/proxysql_mcp_bridge.log`:

```bash
tail -f /tmp/proxysql_mcp_bridge.log
```

The log shows:
- stdout writes (byte counts and previews)
- tool calls (name, arguments, responses from ProxySQL)
- Any errors or issues

This can help diagnose communication issues between Claude Code, the bridge, and ProxySQL.

## Troubleshooting

### Debug Mode

If tools aren't working, check the bridge log file for detailed information:

```bash
cat /tmp/proxysql_mcp_bridge.log
```

Look for:
- `"tools/call: name=..."` - confirms tool calls are being forwarded
- `"response from ProxySQL:"` - shows what ProxySQL returned
- `"WRITE stdout:"` - confirms responses are being sent to Claude Code

### Connection Refused
Make sure ProxySQL MCP server is running:
```bash
curl -k https://127.0.0.1:6071/mcp/query \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "ping", "id": 1}'
```

### SSL Certificate Errors
Set `PROXYSQL_MCP_INSECURE_SSL=1` to bypass certificate verification.

### Authentication Errors
Check that `PROXYSQL_MCP_TOKEN` matches the token configured in ProxySQL:
```sql
SHOW VARIABLES LIKE 'mcp-query_endpoint_auth';
```

## Requirements

- Python 3.7+
- httpx (`pip install httpx`)
- ProxySQL with MCP enabled
