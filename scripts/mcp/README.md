# MCP Module Testing Suite

This directory contains scripts to test the ProxySQL MCP (Model Context Protocol) module with MySQL connection pool and exploration tools.

## Prerequisites

- ProxySQL must be installed and built with MCP support
- MySQL server (either running or Docker capability)
- `mysql` client installed
- `curl` installed for HTTP testing
- `jq` installed for JSON parsing (optional but recommended)

## Quick Start

```bash
# 1. Start a test MySQL server (Docker)
./setup_test_db.sh start

# 2. Configure ProxySQL MCP module
./configure_mcp.sh

# 3. Run all MCP tool tests
./test_mcp_tools.sh

# 4. Run stress test (optional)
./stress_test.sh

# 5. Stop test MySQL server (Docker)
./setup_test_db.sh stop
```

## Scripts

| Script | Purpose |
|--------|---------|
| `setup_test_db.sh` | Create/start a test MySQL database with sample data |
| `configure_mcp.sh` | Configure ProxySQL MCP module variables |
| `test_mcp_tools.sh` | Test all MCP tools via HTTPS/JSON-RPC |
| `stress_test.sh` | Concurrent connection stress test |
| `test_catalog.sh` | Test catalog (LLM memory) functionality |

## Manual Testing

### Test via curl

```bash
# Test list_schemas
curl -k https://127.0.0.1:6071/query -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {"name": "list_schemas", "arguments": {}},
    "id": 1
  }'

# Test list_tables
curl -k https://127.0.0.1:6071/query -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {"name": "list_tables", "arguments": {"schema": "testdb"}},
    "id": 1
  }'
```

### Test via mysql admin

```sql
-- Connect to ProxySQL admin
mysql -h 127.0.0.1 -P 6032 -u admin -padmin

-- Check MCP configuration
SHOW VARIABLES LIKE 'mcp-%';

-- Check connection pool status
SELECT * FROM stats_mcp_connections;
```

## Expected Results

### Successful Connection Pool Initialization

ProxySQL log should show:
```
MySQL_Tool_Handler: Connected to 127.0.0.1:3307
MySQL_Tool_Handler: Connection pool initialized with 1 connection(s)
MySQL Tool Handler initialized for schema 'testdb'
```

### Successful Tool Response

```json
{
  "jsonrpc": "2.0",
  "result": [
    {"name": "testdb", "table_count": 2},
    {"name": "mysql", "table_count": 0}
  ],
  "id": 1
}
```

## Troubleshooting

### MCP server not starting

Check ProxySQL logs:
```bash
tail -f proxysql.log | grep -i mcp
```

### Connection pool failing

Verify MySQL is accessible:
```bash
mysql -h 127.0.0.1 -P 3307 -u root -ptest testdb -e "SELECT 1"
```

### Certificate errors

The tests use `-k` to skip SSL verification. For production:
```bash
export MCP_CERT=/path/to/cert.pem
export MCP_KEY=/path/to/key.pem
```

## MCP Tools Reference

| Tool | Description |
|------|-------------|
| `list_schemas` | List available databases |
| `list_tables` | List tables in a schema |
| `describe_table` | Get table schema (columns, keys, indexes) |
| `sample_rows` | Sample rows from a table |
| `sample_distinct` | Sample distinct values from a column |
| `run_sql_readonly` | Execute read-only SQL with guardrails |
| `explain_sql` | Get query execution plan |
| `catalog_upsert` | Store entry in LLM catalog |
| `catalog_get` | Retrieve entry from LLM catalog |
| `catalog_search` | Search LLM catalog |

## Default Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `mcp-enabled` | false | Enable MCP server |
| `mcp-port` | 6071 | HTTPS port for MCP |
| `mcp-mysql_hosts` | 127.0.0.1 | MySQL server host(s) |
| `mcp-mysql_ports` | 3306 | MySQL server port(s) |
| `mcp-mysql_user` | (empty) | MySQL username |
| `mcp-mysql_password` | (empty) | MySQL password |
| `mcp-mysql_schema` | (empty) | Default schema |
| `mcp-catalog_path` | /var/lib/proxysql/mcp_catalog.db | Catalog database path |
