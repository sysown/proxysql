# MCP Module Testing Suite

This directory contains scripts to test the ProxySQL MCP (Model Context Protocol) module with MySQL connection pool and exploration tools.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Components](#components)
3. [Testing Flow](#testing-flow)
4. [Quick Start (Copy/Paste)](#quick-start-copypaste)
5. [Detailed Documentation](#detailed-documentation)
6. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### What is MCP?

MCP (Model Context Protocol) is a JSON-RPC 2.0 protocol that allows AI/LLM applications to:
- **Discover** database schemas (list tables, describe columns, view relationships)
- **Explore** data safely (sample rows, run read-only queries with guardrails)
- **Remember** discoveries in an external catalog (SQLite-based memory for LLM)

### Component Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ProxySQL MCP Module                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │         ProxySQL Admin Interface (Port 6032)                 │   │
│  │   Configure: mcp-enabled, mcp-mysql_hosts, mcp-port, etc.    │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                             │                                       │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │         MCP HTTPS Server (Port 6071)                       │   │
│  │                                                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │   │
│  │  │   /config   │  │   /query    │  │    /admin   │       │   │
│  │  │   endpoint  │  │   endpoint  │  │   endpoint  │       │   │
│  │  └──────┬──────┘  └──────┬──────┘  └─────────────┘       │   │
│  └─────────┼─────────────────┼─────────────────────────────────┘   │
│            │                 │                                       │
│  ┌─────────▼─────────────────▼─────────────────────────────────┐   │
│  │              MySQL_Tool_Handler                               │   │
│  │   ┌─────────────────────────────────────────────────────┐   │   │
│  │   │         MySQL Connection Pool                         │   │   │
│  │   │   ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐                   │   │   │
│  │   │   │Conn1│ │Conn2│ │Conn3│ │ ... │ (to MySQL)         │   │   │
│  │   │   └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘                   │   │   │
│  │   │      └──────┴──────┴──────┴──────┘                    │   │   │
│  │   └─────────────────────────────────────────────────────┘   │   │
│  │                                                              │   │
│  │   Tool Methods:                                             │   │
│  │   • list_schemas, list_tables, describe_table              │   │
│  │   • sample_rows, sample_distinct, run_sql_readonly         │   │
│  │   • catalog_upsert, catalog_get, catalog_search            │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              MySQL_Catalog (SQLite Memory)                  │   │
│  │   • LLM discoveries catalog (FTS searchable)                │   │
│  │   • Tables: catalog_entries, catalog_links                 │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    MySQL Server (Port 3306)                          │
│                    • Test Database: testdb                          │
│                    • Tables: customers, orders, products, etc.       │
└──────────────────────────────────────────────────────────────────────┘
```

### MCP Tools Available

| Category | Tools | Purpose |
|----------|-------|---------|
| **Inventory** | `list_schemas`, `list_tables` | Discover available databases and tables |
| **Structure** | `describe_table`, `get_constraints` | Get schema details (columns, keys, indexes) |
| **Sampling** | `sample_rows`, `sample_distinct` | Sample data safely with row limits |
| **Query** | `run_sql_readonly`, `explain_sql` | Execute SELECT queries with guardrails |
| **Catalog** | `catalog_upsert`, `catalog_get`, `catalog_search` | Store/retrieve LLM discoveries |

---

## Components

### 1. ProxySQL MCP Module

**Location:** Built into ProxySQL (`lib/MCP_*.cpp`)

**Purpose:** Exposes HTTPS endpoints that implement JSON-RPC 2.0 protocol for LLM integration.

**Key Configuration Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `mcp-enabled` | false | Enable/disable MCP server |
| `mcp-port` | 6071 | HTTPS port for MCP endpoints |
| `mcp-mysql_hosts` | 127.0.0.1 | MySQL server(s) for tool execution |
| `mcp-mysql_ports` | 3306 | MySQL port(s) |
| `mcp-mysql_user` | (empty) | MySQL username for connections |
| `mcp-mysql_password` | (empty) | MySQL password |
| `mcp-mysql_schema` | (empty) | Default schema for queries |
| `mcp-catalog_path` | mcp_catalog.db | SQLite catalog database path (relative to datadir) |

**Endpoints:**
- `POST https://localhost:6071/config` - Initialize, ping, tools/list
- `POST https://localhost:6071/query` - Execute tools (tools/call)

### 2. MySQL Connection Pool

**Location:** `lib/MySQL_Tool_Handler.cpp`

**Purpose:** Manages reusable connections to backend MySQL servers for tool execution.

**Features:**
- Thread-safe connection pooling with `pthread_mutex_t`
- One connection per configured `host:port` pair
- Automatic connection on first use
- 5-second timeouts for connect/read/write operations

### 3. MySQL Catalog (LLM Memory)

**Location:** `lib/MySQL_Catalog.cpp`

**Purpose:** External memory for LLM to store discoveries with full-text search.

**Features:**
- SQLite-based storage (`mcp_catalog.db`)
- Full-text search (FTS) on document content
- Link tracking between related entries
- Entry kinds: table, domain, column, relationship, pattern

### 4. Test Scripts

| Script | Purpose | What it Does |
|--------|---------|--------------|
| `setup_test_db.sh` | Database setup | Creates test MySQL database with sample data (customers, orders, products) |
| `configure_mcp.sh` | ProxySQL configuration | Sets MCP variables and loads to runtime |
| `test_mcp_tools.sh` | Tool testing | Tests all 15 MCP tools via JSON-RPC |
| `test_catalog.sh` | Catalog testing | Tests catalog CRUD and FTS search |
| `stress_test.sh` | Load testing | Concurrent connection stress test |

---

## Testing Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ Step 1: Setup Test Database                                        │
│ ─────────────────────────────────────────────────────────────────  │
│ ./setup_test_db.sh start --mode native                             │
│                                                                      │
│ → Creates 'testdb' database on your MySQL server                    │
│ → Creates tables: customers, orders, products, order_items          │
│ → Inserts sample data (5 customers, 5 products, 5 orders)           │
│ → Creates view: customer_orders                                     │
│ → Creates stored procedure: get_customer_stats                      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Step 2: Configure ProxySQL MCP Module                               │
│ ─────────────────────────────────────────────────────────────────  │
│ ./configure_mcp.sh --host 127.0.0.1 --port 3306 --user root \       │
│   --password your_password --enable                                 │
│                                                                      │
│ → Sets mcp-mysql_hosts=127.0.0.1                                    │
│ → Sets mcp-mysql_ports=3306                                          │
│ → Sets mcp-mysql_user=root                                           │
│ → Sets mcp-mysql_password=your_password                              │
│ → Sets mcp-mysql_schema=testdb                                        │
│ → Sets mcp-enabled=true                                              │
│ → Loads MCP VARIABLES TO RUNTIME                                    │
│                                                                      │
│ Result:                                                              │
│ → MySQL_Tool_Handler initializes connection pool                      │
│ → Connection established to MySQL server                             │
│ → HTTPS server starts on port 6071                                  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Step 3: Test MCP Tools                                               │
│ ─────────────────────────────────────────────────────────────────  │
│ ./test_mcp_tools.sh                                                  │
│                                                                      │
│ → Sends JSON-RPC requests to https://localhost:6071/query           │
│ → Tests tools: list_schemas, list_tables, describe_table, etc.     │
│ → Verifies responses are valid JSON with expected data               │
│                                                                      │
│ Example Request:                                                     │
│ POST /query                                                          │
│ {                                                                   │
│   "jsonrpc": "2.0",                                                 │
│   "method": "tools/call",                                           │
│   "params": {                                                       │
│     "name": "list_tables",                                          │
│     "arguments": {"schema": "testdb"}                               │
│   },                                                                │
│   "id": 1                                                           │
│ }                                                                   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Step 4: Verify Connection Pool                                      │
│ ─────────────────────────────────────────────────────────────────  │
│ grep "MySQL_Tool_Handler" /path/to/proxysql.log                     │
│                                                                      │
│ Expected logs:                                                       │
│ MySQL_Tool_Handler: Connected to 127.0.0.1:3306                     │
│ MySQL_Tool_Handler: Connection pool initialized with 1 connection(s)│
│ MySQL Tool Handler initialized for schema 'testdb'                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start (Copy/Paste)

### Prerequisites - Set Environment Variables

```bash
# Add to ~/.bashrc or run before testing
export PROXYSQL_ADMIN_PASSWORD=admin        # Your ProxySQL admin password
export MYSQL_PASSWORD=your_mysql_password   # Your MySQL root password
```

### Option A: Using Real MySQL (Recommended)

```bash
cd /home/rene/proxysql-vec/scripts/mcp

# 1. Setup test database on your MySQL server
./setup_test_db.sh start --mode native

# 2. Configure and enable ProxySQL MCP module
./configure_mcp.sh --host 127.0.0.1 --port 3306 --user root --enable

# 3. Run all MCP tool tests
./test_mcp_tools.sh

# 4. Run catalog tests
./test_catalog.sh

# 5. Run stress test (10 concurrent requests)
./stress_test.sh -n 10

# 6. Clean up (drop test database when done)
./setup_test_db.sh reset --mode native
```

### Option B: Using Docker

```bash
cd /home/rene/proxysql-vec/scripts/mcp

# 1. Start test MySQL container
./setup_test_db.sh start --mode docker

# 2. Configure and enable ProxySQL MCP module
./configure_mcp.sh --host 127.0.0.1 --port 3307 --user root --password test123 --enable

# 3. Run all MCP tool tests
./test_mcp_tools.sh

# 4. Stop test MySQL container when done
./setup_test_db.sh stop --mode docker
```

---

## Detailed Documentation

### setup_test_db.sh - Database Setup

**Purpose:** Creates a test MySQL database with sample schema and data for MCP testing.

**What it does:**
- Creates `testdb` database with 4 tables: `customers`, `orders`, `products`, `order_items`
- Inserts sample data (5 customers, 5 products, 5 orders with items)
- Creates a view (`customer_orders`) and stored procedure (`get_customer_stats`)
- Generates `init_testdb.sql` for reproducibility

**Commands:**
```bash
./setup_test_db.sh start [--mode native|docker]    # Create test database
./setup_test_db.sh status [--mode native|docker]   # Check database status
./setup_test_db.sh connect [--mode native|docker]  # Connect to MySQL shell
./setup_test_db.sh reset [--mode native|docker]    # Drop/recreate database
./setup_test_db.sh --help                           # Show help
```

**Native Mode (your MySQL server):**
```bash
# With defaults (127.0.0.1:3306, root user)
./setup_test_db.sh start --mode native

# With custom credentials
./setup_test_db.sh start --mode native --host localhost --port 3307 \
  --user myuser --password mypass
```

**Docker Mode (isolated container):**
```bash
./setup_test_db.sh start --mode docker
# Container port: 3307, root user, password: test123
```

### configure_mcp.sh - ProxySQL Configuration

**Purpose:** Configures ProxySQL MCP module variables via admin interface.

**What it does:**
1. Connects to ProxySQL admin interface (default: 127.0.0.1:6032)
2. Sets MCP configuration variables:
   - `mcp-mysql_hosts` - Where to find MySQL server
   - `mcp-mysql_ports` - MySQL port
   - `mcp-mysql_user` - MySQL username
   - `mcp-mysql_password` - MySQL password
   - `mcp-mysql_schema` - Default database
   - `mcp-enabled` - Enable/disable MCP server
3. Loads variables to RUNTIME (activates the configuration)
4. Optionally tests MCP server connectivity

**Commands:**
```bash
./configure_mcp.sh --enable                 # Enable with defaults
./configure_mcp.sh --disable                # Disable MCP server
./configure_mcp.sh --status                 # Show current configuration
./configure_mcp.sh --help                   # Show help
```

**Options:**
```bash
--host HOST           MySQL host (default: 127.0.0.1)
--port PORT           MySQL port (default: 3307 for Docker, 3306 for native)
--user USER           MySQL user (default: root)
--password PASS       MySQL password
--database DB         Default database (default: testdb)
--mcp-port PORT       MCP HTTPS port (default: 6071)
```

**Full Example:**
```bash
./configure_mcp.sh \
  --host 127.0.0.1 \
  --port 3306 \
  --user root \
  --password your_password \
  --database testdb \
  --enable
```

**What happens when you run `--enable`:**
1. Sets `mcp-mysql_hosts='127.0.0.1'` in ProxySQL
2. Sets `mcp-mysql_ports='3306'` in ProxySQL
3. Sets `mcp-mysql_user='root'` in ProxySQL
4. Sets `mcp-mysql_password='your_password'` in ProxySQL
5. Sets `mcp-mysql_schema='testdb'` in ProxySQL
6. Sets `mcp-enabled='true'` in ProxySQL
7. Runs `LOAD MCP VARIABLES TO RUNTIME`
8. `MySQL_Tool_Handler` initializes connection pool to MySQL
9. HTTPS server starts listening on port 6071

### test_mcp_tools.sh - Tool Testing

**Purpose:** Tests all MCP tools via HTTPS/JSON-RPC to verify the connection pool and tools work.

**What it does:**
- Sends JSON-RPC 2.0 requests to MCP `/query` endpoint
- Tests 15 tools across 5 categories
- Validates JSON responses
- Reports pass/fail statistics

**Tools Tested:**

| Category | Tools | What it Verifies |
|----------|-------|-------------------|
| Inventory | `list_schemas`, `list_tables` | Connection works, can query information_schema |
| Structure | `describe_table`, `get_constraints`, `describe_view` | Can read schema details |
| Profiling | `table_profile`, `column_profile` | Aggregation queries work |
| Sampling | `sample_rows`, `sample_distinct` | Can sample data with limits |
| Query | `run_sql_readonly`, `explain_sql` | Query guardrails and execution |
| Catalog | `catalog_upsert`, `catalog_get`, `catalog_search` | Catalog CRUD works |

**Commands:**
```bash
./test_mcp_tools.sh                           # Test all tools
./test_mcp_tools.sh --tool list_schemas        # Test single tool
./test_mcp_tools.sh --skip-tool catalog_*      # Skip catalog tests
./test_mcp_tools.sh -v                          # Verbose output
```

**Example Test Flow:**
```bash
$ ./test_mcp_tools.sh --tool list_tables

[TEST] Testing tool: list_tables
[INFO] ✓ list_tables

Test Summary
Total tests:   1
Passed:        1
Failed:        0
```

### test_catalog.sh - Catalog Testing

**Purpose:** Tests the SQLite catalog (LLM memory) functionality.

**What it does:**
- Tests catalog CRUD operations (Create, Read, Update, Delete)
- Tests full-text search (FTS)
- Tests entry linking between related discoveries

**Tests:**
1. `CAT001`: Upsert table schema entry
2. `CAT002`: Upsert domain knowledge entry
3. `CAT003`: Get table entry
4. `CAT004`: Get domain entry
5. `CAT005`: Search catalog
6. `CAT006`: List entries by kind
7. `CAT007`: Update existing entry
8. `CAT008`: Verify update
9. `CAT009`: FTS search with wildcard
10. `CAT010`: Delete entry
11. `CAT011`: Verify deletion
12. `CAT012`: Cleanup domain entry

### stress_test.sh - Load Testing

**Purpose:** Tests concurrent connection handling by the connection pool.

**What it does:**
- Launches N concurrent requests to MCP server
- Measures response times
- Reports success rate and requests/second

**Commands:**
```bash
./stress_test.sh -n 10                      # 10 concurrent requests
./stress_test.sh -n 50 -d 100               # 50 requests, 100ms delay
./stress_test.sh -t list_tables -v          # Test specific tool
```

---

## Troubleshooting

### MCP server not starting

**Check ProxySQL logs:**
```bash
tail -f /path/to/proxysql.log | grep -i mcp
```

**Verify configuration:**
```sql
mysql -h 127.0.0.1 -P 6032 -u admin -padmin
SHOW VARIABLES LIKE 'mcp-%';
```

**Expected output:**
```
Variable_name   Value
mcp-enabled     true
mcp-port        6071
mcp-mysql_hosts 127.0.0.1
mcp-mysql_ports 3306
...
```

### Connection pool failing

**Verify MySQL is accessible:**
```bash
mysql -h 127.0.0.1 -P 3306 -u root -pyourpassword testdb -e "SELECT 1"
```

**Check for connection pool errors in logs:**
```bash
grep "MySQL_Tool_Handler" /path/to/proxysql.log
```

**Expected logs on success:**
```
MySQL_Tool_Handler: Connected to 127.0.0.1:3306
MySQL_Tool_Handler: Connection pool initialized with 1 connection(s)
MySQL Tool Handler initialized for schema 'testdb'
```

### Test failures

**Common causes:**
1. **MySQL not accessible** - Check credentials, host, port
2. **Database not created** - Run `./setup_test_db.sh start` first
3. **MCP not enabled** - Run `./configure_mcp.sh --enable`
4. **Wrong port** - Docker uses 3307, native uses 3306
5. **Firewall** - Ensure ports 6032, 6071, and MySQL port are open

**Enable verbose output:**
```bash
./test_mcp_tools.sh -v
```

### Clean slate

**To reset everything and start over:**

```bash
# 1. Disable MCP
./configure_mcp.sh --disable

# 2. Drop test database
./setup_test_db.sh reset --mode native

# 3. Start fresh
./setup_test_db.sh start --mode native
./configure_mcp.sh --enable
```

---

## Default Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `mcp-enabled` | false | Enable MCP server |
| `mcp-port` | 6071 | HTTPS port for MCP |
| `mcp-config_endpoint_auth` | (empty) | Auth token for /config endpoint |
| `mcp-observe_endpoint_auth` | (empty) | Auth token for /observe endpoint |
| `mcp-query_endpoint_auth` | (empty) | Auth token for /query endpoint |
| `mcp-admin_endpoint_auth` | (empty) | Auth token for /admin endpoint |
| `mcp-cache_endpoint_auth` | (empty) | Auth token for /cache endpoint |
| `mcp-timeout_ms` | 30000 | Query timeout in milliseconds |
| `mcp-mysql_hosts` | 127.0.0.1 | MySQL server host(s) |
| `mcp-mysql_ports` | 3306 | MySQL server port(s) |
| `mcp-mysql_user` | (empty) | MySQL username |
| `mcp-mysql_password` | (empty) | MySQL password |
| `mcp-mysql_schema` | (empty) | Default schema |
| `mcp-catalog_path` | mcp_catalog.db | Catalog database path (relative to datadir) |

---

## Environment Variables Reference

```bash
# ProxySQL Admin Configuration (for configure_mcp.sh)
export PROXYSQL_ADMIN_HOST=${PROXYSQL_ADMIN_HOST:-127.0.0.1}
export PROXYSQL_ADMIN_PORT=${PROXYSQL_ADMIN_PORT:-6032}
export PROXYSQL_ADMIN_USER=${PROXYSQL_ADMIN_USER:-admin}
export PROXYSQL_ADMIN_PASSWORD=${PROXYSQL_ADMIN_PASSWORD:-admin}

# MySQL Configuration (for setup_test_db.sh and configure_mcp.sh)
export MYSQL_HOST=${MYSQL_HOST:-127.0.0.1}
export MYSQL_PORT=${MYSQL_PORT:-3306}
export MYSQL_USER=${MYSQL_USER:-root}
export MYSQL_PASSWORD=${MYSQL_PASSWORD:-}
export TEST_DB_NAME=${TEST_DB_NAME:-testdb}

# MCP Server Configuration (for test scripts)
export MCP_HOST=${MCP_HOST:-127.0.0.1}
export MCP_PORT=${MCP_PORT:-6071}
```
