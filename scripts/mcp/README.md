# MCP Module Testing Suite

This directory contains scripts to test the ProxySQL MCP (Model Context Protocol) module with MySQL connection pool and exploration tools.

## Prerequisites

- ProxySQL must be installed and built with MCP support
- MySQL server (either running locally or Docker capability)
- `mysql` client installed
- `curl` installed for HTTP testing
- `jq` installed for JSON parsing (optional but recommended)

### Required Environment Variables

Configure these environment variables based on your setup before running the test scripts:

```bash
# ProxySQL Admin Configuration (required by configure_mcp.sh)
export PROXYSQL_ADMIN_HOST=${PROXYSQL_ADMIN_HOST:-127.0.0.1}
export PROXYSQL_ADMIN_PORT=${PROXYSQL_ADMIN_PORT:-6032}
export PROXYSQL_ADMIN_USER=${PROXYSQL_ADMIN_USER:-admin}
export PROXYSQL_ADMIN_PASSWORD=${PROXYSQL_ADMIN_PASSWORD:-admin}

# MySQL Configuration for MCP Tools (required for native MySQL mode)
export MYSQL_HOST=${MYSQL_HOST:-127.0.0.1}
export MYSQL_PORT=${MYSQL_PORT:-3306}
export MYSQL_USER=${MYSQL_USER:-root}
export MYSQL_PASSWORD=${MYSQL_PASSWORD:-}  # Set your MySQL password
export TEST_DB_NAME=${TEST_DB_NAME:-testdb}

# MCP Server Configuration (optional, defaults shown)
export MCP_HOST=${MCP_HOST:-127.0.0.1}
export MCP_PORT=${MCP_PORT:-6071}
```

**Quick Setup - Add to your shell profile:**
```bash
# Add to ~/.bashrc or ~/.zshrc
cat >> ~/.bashrc <<'EOF'

# ProxySQL MCP Testing Environment Variables
export PROXYSQL_ADMIN_PASSWORD=admin        # Your ProxySQL admin password
export MYSQL_PASSWORD=your_mysql_password   # Your MySQL root password
EOF

source ~/.bashrc
```

## Quick Start

### Using Real MySQL (Native Mode)

```bash
# 1. Setup test database on your MySQL server
./setup_test_db.sh --mode native start

# 2. Configure ProxySQL MCP module
./configure_mcp.sh --host 127.0.0.1 --port 3306 --user root --enable

# 3. Run all MCP tool tests
./test_mcp_tools.sh

# 4. Run stress test (optional)
./stress_test.sh

# 5. Clean up (drop test database)
./setup_test_db.sh --mode native reset
```

### Using Docker

```bash
# 1. Start test MySQL container
./setup_test_db.sh --mode docker start

# 2. Configure ProxySQL MCP module
./configure_mcp.sh --host 127.0.0.1 --port 3307 --enable

# 3. Run all MCP tool tests
./test_mcp_tools.sh

# 4. Run stress test (optional)
./stress_test.sh

# 5. Stop test MySQL container
./setup_test_db.sh --mode docker stop
```

### Auto-Detect Mode

The `setup_test_db.sh` script can auto-detect which mode to use:

```bash
# Will try Docker first, then fall back to native MySQL
./setup_test_db.sh start
```

## Scripts

| Script | Purpose |
|--------|---------|
| `setup_test_db.sh` | Setup test database (Docker or native MySQL) |
| `configure_mcp.sh` | Configure ProxySQL MCP module variables |
| `test_mcp_tools.sh` | Test all MCP tools via HTTPS/JSON-RPC |
| `stress_test.sh` | Concurrent connection stress test |
| `test_catalog.sh` | Test catalog (LLM memory) functionality |

### setup_test_db.sh - Test Database Setup

Supports both **Docker** and **native MySQL** modes:

**Commands:**
- `start` - Setup/create test database
- `stop` - Stop Docker container (Docker only)
- `status` - Check database status
- `connect` - Connect to MySQL shell
- `reset` - Drop/recreate test database

**Options:**
```bash
--mode MODE         # docker, native, or auto (default: auto)
--host HOST         # MySQL host for native mode (default: 127.0.0.1)
--port PORT         # MySQL port (default: 3306 native, 3307 docker)
--user USER         # MySQL user (default: root)
--password PASS     # MySQL password
--database DB       # Database name (default: testdb)
```

**Examples:**

```bash
# Auto-detect (tries Docker first, then native)
./setup_test_db.sh start

# Use native MySQL with specific credentials
./setup_test_db.sh --mode native --host localhost --port 3306 --user root start

# Use Docker explicitly
./setup_test_db.sh --mode docker start

# Check status
./setup_test_db.sh --mode native status

# Connect to test database
./setup_test_db.sh --mode native connect

# Drop and recreate test database
./setup_test_db.sh --mode native reset
```

**Environment Variables:**
```bash
export MYSQL_HOST=localhost
export MYSQL_PORT=3306
export MYSQL_USER=root
export MYSQL_PASSWORD=your_password
export TEST_DB_NAME=testdb

./setup_test_db.sh --mode native start
```

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
