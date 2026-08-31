# MCP Integration

## Table of Contents

- [Overview](#overview)
- [Native HTTP/HTTPS Integration](#native-httphttps-integration)
  - [Configuration](#configuration)
  - [Enabling the MCP Server](#enabling-the-mcp-server)
  - [HTTPS Support](#https-support)
  - [MCP Endpoints](#mcp-endpoints)
  - [Authentication](#authentication)
  - [JSON-RPC 2.0 Protocol](#json-rpc-20-protocol)
- [Claude Code Native HTTP/HTTPS Transport](#claude-code-native-httphttps-transport)
  - [HTTP vs HTTPS with Claude Code](#http-vs-https-with-claude-code)
  - [Configuration](#configuration-1)
  - [Managing Your MCP Server](#managing-your-mcp-server)
  - [Available Tools](#available-tools)
  - [Example Usage](#example-usage)
  - [Troubleshooting](#troubleshooting)
- [STDIO Bridge Integration (for Claude Code)](#stdio-bridge-integration-for-claude-code)
  - [Architecture](#architecture)
  - [Installation](#installation)
  - [Configuration](#configuration-2)
  - [Available Tools in Claude Code](#available-tools-in-claude-code)
  - [Example Usage in Claude Code](#example-usage-in-claude-code)
  - [Debugging](#debugging)
- [Choosing an Integration Approach](#choosing-an-integration-approach)
  - [Quick Decision Guide](#quick-decision-guide)
- [Related Documentation](#related-documentation)

---

## Overview

ProxySQL v4.0 implements the **Model Context Protocol (MCP)** using native HTTP/HTTPS support. This enables AI agents like Claude Code to interact directly with ProxySQL for database discovery, query execution, and configuration management.

There are **three approaches** for connecting to ProxySQL's MCP server:

| Approach | Description | Use Case |
|----------|-------------|----------|
| **Native HTTP** | Direct HTTP connection | Quick local development, trusted networks |
| **Native HTTPS** | Direct HTTPS connection (valid certificates only) | Production with valid SSL certificates |
| **STDIO Bridge** | Python bridge translating stdio to HTTPS | Claude Code with self-signed certificates |

```
┌─────────────────┐      HTTPS      ┌──────────────────────────────────┐
│  Custom AI App  │ ──────────────> │                                  │
└─────────────────┘                 │           ProxySQL MCP           │
                                   │          (HTTP/HTTPS)             │
┌─────────────────┐      HTTPS     │            Server                │
│  Claude Code    │ ──────────────> │                                  │
│  (native http)  │    or HTTP     └──────────────────────────────────┘
└─────────────────┘
┌─────────────────┐      stdio      ┌──────────────────┐     HTTPS      ┌──────────┐
│  Claude Code    │ ──────────────>  │  STDIO Bridge    │  ──────────>  │ ProxySQL │
│  (stdio bridge) │                 │  (Python Script) │               │  MCP     │
└─────────────────┘                 └──────────────────┘               └──────────┘
```

---

## Native HTTP/HTTPS Integration

### Overview

ProxySQL's MCP server is built on **libhttpserver** and supports both HTTP and HTTPS modes. The server exposes multiple endpoints, each with dedicated tools and optional Bearer token authentication.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| [`mcp-enabled`](../references/mcp_variables#mcp-enabled) | `false` | Enable/disable the MCP server |
| [`mcp-port`](../references/mcp_variables#mcp-port) | `6071` | TCP port for MCP connections |
| [`mcp-use_ssl`](../references/mcp_variables#mcp-use_ssl) | `true` | Enable HTTPS (requires SSL certificates) |
| [`mcp-timeout_ms`](../references/mcp_variables#mcp-timeout_ms) | `30000` | Request timeout in milliseconds |

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

### Enabling the MCP Server

```sql
-- Enable the MCP server with HTTPS
SET mcp-enabled='true';
SET mcp-use_ssl='true';
SET mcp-port='6071';
LOAD MCP VARIABLES TO RUNTIME;
```

### HTTPS Support

ProxySQL uses the same SSL certificates configured for the admin interface. When `mcp-use_ssl` is enabled:

- The server only accepts HTTPS connections
- SSL certificates from the `admin-certificates` configuration are used
- Clients must support HTTPS/TLS handshake

### MCP Endpoints

The ProxySQL MCP server implements multiple endpoints, each with its own tool set and authentication:

| Endpoint | Purpose | Auth Variable |
|----------|---------|---------------|
| `/mcp/config` | Configuration management | `mcp-config_endpoint_auth` |
| `/mcp/query` | Database exploration & discovery | `mcp-query_endpoint_auth` |
| `/mcp/admin` | Administrative operations | `mcp-admin_endpoint_auth` |
| `/mcp/cache` | Cache management | `mcp-cache_endpoint_auth` |
| `/mcp/observe` | Observability & monitoring | `mcp-observe_endpoint_auth` |
| `/mcp/ai` | AI & LLM features | `mcp-ai_endpoint_auth` |
| `/mcp/rag` | Retrieval-Augmented Generation | `mcp-rag_endpoint_auth` |

See [MCP Endpoints](mcp_endpoints) for complete endpoint documentation.

### Authentication

Each endpoint supports optional Bearer token authentication:

```sql
-- Set authentication token for the query endpoint
SET mcp-query_endpoint_auth='your_secure_token_here';
LOAD MCP VARIABLES TO RUNTIME;
```

Clients can authenticate via:

1. **Authorization Header**:
   ```http
   Authorization: Bearer your_token_here
   ```

2. **Query Parameter**:
   ```
   https://127.0.0.1:6071/mcp/query?token=your_token_here
   ```

### JSON-RPC 2.0 Protocol

The MCP server implements the JSON-RPC 2.0 protocol. All requests follow this format:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

#### Example: List Available Tools

```bash
curl -k https://127.0.0.1:6071/mcp/query \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_token" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }'
```

#### Example: Call a Tool

```bash
curl -k https://127.0.0.1:6071/mcp/query \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_token" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "list_schemas",
      "arguments": {}
    }
  }'
```

### Python Client Example

```python
import httpx
import json

async def call_proxysql_mcp():
    endpoint = "https://127.0.0.1:6071/mcp/query"
    token = "your_token_here"

    async with httpx.AsyncClient(verify=False) as client:
        # List available tools
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }

        response = await client.post(
            endpoint,
            json=request,
            headers={"Authorization": f"Bearer {token}"}
        )

        print(response.json())

        # Call a tool
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "list_tables",
                "arguments": {"schema": "testdb"}
            }
        }

        response = await client.post(
            endpoint,
            json=request,
            headers={"Authorization": f"Bearer {token}"}
        )

        print(response.json())
```

---

## Claude Code Native HTTP/HTTPS Transport

### Overview

Claude Code supports **native HTTP/HTTPS transport** via the `--transport http` option. This allows direct connection to ProxySQL's MCP server without requiring a stdio bridge.

### HTTP vs HTTPS with Claude Code

| Transport | ProxySQL Setting | Works with Claude Code |
|-----------|------------------|------------------------|
| **HTTP** | `mcp-use_ssl=false` | ✅ Yes |
| **HTTPS (valid cert)** | `mcp-use_ssl=true` with valid certificate | ✅ Yes |
| **HTTPS (self-signed)** | `mcp-use_ssl=true` with self-signed certificate | ❌ No - use STDIO Bridge instead |

:::warning
**Important Limitation**: Claude Code's HTTP transport does **not** support self-signed SSL certificates. If ProxySQL uses a self-signed certificate, you must either:
- Use HTTP (set `mcp-use_ssl=false`)
- Use the [STDIO Bridge](#stdio-bridge-integration-for-claude-code) approach
:::

### Configuration

#### Option 1: Using HTTP (Recommended for Development)

Disable SSL in ProxySQL and use HTTP:

```sql
-- Configure ProxySQL for HTTP
SET mcp-enabled='true';
SET mcp-use_ssl='false';
SET mcp-port='6071';
SET mcp-query_endpoint_auth='';  -- Optional: leave empty for no auth
LOAD MCP VARIABLES TO RUNTIME;
```

Add to Claude Code using the CLI:

```bash
# Add ProxySQL as an HTTP MCP server
claude mcp add --transport http proxysql http://127.0.0.1:6071/mcp/query

# With authentication
claude mcp add --transport http proxysql http://127.0.0.1:6071/mcp/query \
  --header "Authorization: Bearer your_token_here"
```

Or add to `.mcp.json` in your project:

```json
{
  "mcpServers": {
    "proxysql": {
      "type": "http",
      "url": "http://127.0.0.1:6071/mcp/query",
      "headers": {
        "Authorization": "Bearer your_token_here"
      }
    }
  }
}
```

#### Option 2: Using HTTPS (Requires Valid Certificate)

```sql
-- Configure ProxySQL for HTTPS with valid certificate
SET mcp-enabled='true';
SET mcp-use_ssl='true';
SET mcp-port='6071';
SET mcp-query_endpoint_auth='your_token_here';
LOAD MCP VARIABLES TO RUNTIME;
```

Add to Claude Code:

```bash
# Add ProxySQL as an HTTPS MCP server
claude mcp add --transport http proxysql https://127.0.0.1:6071/mcp/query \
  --header "Authorization: Bearer your_token_here"
```

Or in `.mcp.json`:

```json
{
  "mcpServers": {
    "proxysql": {
      "type": "http",
      "url": "https://127.0.0.1:6071/mcp/query",
      "headers": {
        "Authorization": "Bearer your_token_here"
      }
    }
  }
}
```

### Managing Your MCP Server

```bash
# List all configured servers
claude mcp list

# Get details for the ProxySQL server
claude mcp get proxysql

# Remove the server
claude mcp remove proxysql

# Check server status within Claude Code
/mcp
```

### Available Tools

Once connected via HTTP/HTTPS, all MCP tools are available directly in Claude Code. See [Available Tools](#available-tools-in-claude-code) for the complete list.

### Example Usage

```bash
# 1. Configure ProxySQL for HTTP
mysql -h 127.0.0.1 -P 6032 -u admin -padmin
> SET mcp-enabled='true';
> SET mcp-use_ssl='false';
> LOAD MCP VARIABLES TO RUNTIME;

# 2. Add to Claude Code
claude mcp add --transport http proxysql http://127.0.0.1:6071/mcp/query

# 3. Use in Claude Code
> "List all tables in the testdb schema"
> "Show me the structure of the customers table"
> "Run SELECT COUNT(*) FROM orders"
```

### Troubleshooting

**Connection Refused**:
```bash
# Verify ProxySQL MCP is running
curl http://127.0.0.1:6071/mcp/query \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "ping", "id": 1}'
```

**SSL Certificate Error**:
- Claude Code does not support self-signed certificates
- Either use HTTP (`mcp-use_ssl=false`) or use the STDIO Bridge

**Authentication Error**:
```bash
# Check configured token in ProxySQL
mysql -h 127.0.0.1 -P 6032 -u admin -padmin
> SHOW VARIABLES LIKE 'mcp-query_endpoint_auth';
```

---

## STDIO Bridge Integration (for Claude Code)

### Overview

The **STDIO Bridge** is a Python script that translates between stdio-based MCP (used by Claude Code) and ProxySQL's HTTPS MCP endpoint. This enables Claude Code to connect to ProxySQL using its native stdio transport.

### Architecture

```
┌─────────────┐     stdio      ┌──────────────────┐     HTTPS      ┌──────────┐
│  Claude Code│  ──────────>  │  STDIO Bridge    │  ──────────>  │ ProxySQL │
│  (MCP Client)│               │  (Python Script) │               │  MCP     │
└─────────────┘               └──────────────────┘               └──────────┘
```

### Installation

1. **Install dependencies**:

```bash
pip install httpx
```

2. **Locate the bridge script**:

The STDIO bridge is located in the ProxySQL source tree at:
```
/path/to/proxysql-source/scripts/mcp/proxysql_mcp_stdio_bridge.py
```

### Configuration

#### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PROXYSQL_MCP_ENDPOINT` | No | `https://127.0.0.1:6071/mcp/query` | ProxySQL MCP endpoint URL |
| `PROXYSQL_MCP_TOKEN` | No | - | Bearer token for authentication |
| `PROXYSQL_MCP_INSECURE_SSL` | No | `0` | Set to `1` to disable SSL verification |
| `PROXYSQL_MCP_BRIDGE_LOG` | No | `/tmp/proxysql_mcp_bridge.log` | Path to debug log file |

#### Claude Code Configuration

Add to your Claude Code MCP settings (usually `~/.config/claude-code/mcp_config.json` or similar):

```json
{
  "mcpServers": {
    "proxysql": {
      "command": "python3",
      "args": ["/path/to/proxysql-source/scripts/mcp/proxysql_mcp_stdio_bridge.py"],
      "env": {
        "PROXYSQL_MCP_ENDPOINT": "https://127.0.0.1:6071/mcp/query",
        "PROXYSQL_MCP_TOKEN": "your_token_here",
        "PROXYSQL_MCP_INSECURE_SSL": "1"
      }
    }
  }
}
```

### Supported MCP Methods

The STDIO bridge supports the standard MCP methods:

| Method | Description |
|--------|-------------|
| `initialize` | Handshake protocol |
| `tools/list` | List available ProxySQL MCP tools |
| `tools/call` | Call a ProxySQL MCP tool |
| `ping` | Health check |

### Available Tools in Claude Code

Once connected, the following tools will be available in Claude Code through the `/mcp/query` endpoint:

#### Database Exploration Tools

| Tool | Description |
|------|-------------|
| `list_schemas` | List all databases/schemas |
| `list_tables` | List tables in a schema |
| `describe_table` | Get table structure and columns |
| `get_constraints` | Get foreign keys and constraints |
| `sample_rows` | Sample data from a table |
| `sample_distinct` | Sample distinct values from a column |
| `run_sql_readonly` | Execute read-only SQL queries |
| `explain_sql` | Get query execution plan |
| `table_profile` | Get table statistics |
| `column_profile` | Get column statistics |
| `suggest_joins` | Suggest join paths between tables |
| `find_reference_candidates` | Find potential foreign key relationships |

#### Discovery Tools

| Tool | Description |
|------|-------------|
| `discovery.run_static` | Run Phase 1 of two-phase discovery |
| `agent.run_start` | Start a new agent run |
| `agent.run_finish` | Mark an agent run as completed |
| `agent.event_append` | Append an event to an agent run |

#### LLM Interaction Tools

| Tool | Description |
|------|-------------|
| `llm.summary_upsert` | Store/update a table/column summary |
| `llm.summary_get` | Retrieve LLM-generated summary |
| `llm.relationship_upsert` | Store/update an inferred relationship |
| `llm.domain_upsert` | Store/update a business domain |
| `llm.metric_upsert` | Store/update a business metric |
| `llm.question_template_add` | Add a question template |
| `llm.search` | Search LLM-generated content |

#### Catalog Tools

| Tool | Description |
|------|-------------|
| `catalog_upsert` | Store data in the catalog |
| `catalog_get` | Retrieve from the catalog |
| `catalog_search` | Search the catalog |
| `catalog_delete` | Delete entry from the catalog |
| `catalog_list` | List catalog entries by kind |
| `catalog_merge` | Merge catalog entries |

See [MCP Tools](mcp_tools_query) for complete tool documentation.

### Example Usage in Claude Code

Once configured, you can interact with ProxySQL using natural language:

> "List all tables in the testdb schema"
> "Describe the customers table structure"
> "Show me 5 rows from the orders table"
> "Run SELECT COUNT(*) FROM customers GROUP BY country"
> "Find relationships between the orders and customers tables"

### Debugging

The STDIO bridge writes detailed logs to help troubleshoot issues:

```bash
# View the bridge log in real-time
tail -f /tmp/proxysql_mcp_bridge.log
```

The log shows:
- stdout writes (byte counts and previews)
- Tool calls (name, arguments, responses from ProxySQL)
- Any errors or issues

#### Troubleshooting Connection Issues

**Check if ProxySQL MCP is running**:
```bash
curl -k https://127.0.0.1:6071/mcp/query \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "ping", "id": 1}'
```

**Verify authentication token**:
```sql
SHOW VARIABLES LIKE 'mcp-query_endpoint_auth';
```

**Check bridge logs**:
```bash
cat /tmp/proxysql_mcp_bridge.log
```

### Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.7+ |
| httpx | Latest (`pip install httpx`) |
| ProxySQL | v4.0+ with MCP enabled |

---

## Choosing an Integration Approach

### Quick Decision Guide

| Scenario | Recommended Approach |
|----------|---------------------|
| Local development, trusted network | **HTTP** (simplest, `mcp-use_ssl=false`) |
| Production with valid SSL certificate | **HTTPS** (secure, `mcp-use_ssl=true`) |
| Self-signed certificate in production | **STDIO Bridge** (bypass certificate validation) |
| Custom AI application | **HTTP/HTTPS** (use any HTTP client library) |
| Multi-tenant SaaS | **HTTPS** (with proper authentication per endpoint) |

### Use Native HTTP when:

- Quick local development setup
- Trusted network environment (localhost, private network)
- Don't want to deal with SSL certificate configuration
- Building prototypes or proof-of-concepts

```bash
# Simple HTTP setup
claude mcp add --transport http proxysql http://127.0.0.1:6071/mcp/query
```

### Use Native HTTPS when:

- Production environment with valid SSL certificates
- Need encrypted communication
- Connecting over untrusted networks
- Using commercially-signed or Let's Encrypt certificates

```bash
# HTTPS with valid certificate
claude mcp add --transport http proxysql https://your-server.com:6071/mcp/query \
  --header "Authorization: Bearer your_token"
```

### Use STDIO Bridge when:

- ProxySQL uses **self-signed SSL certificates**
- Need to bypass certificate validation in development
- Working in an environment where certificate installation is difficult
- Prefer stdio-based isolation for security

```json
{
  "mcpServers": {
    "proxysql": {
      "command": "python3",
      "args": ["/path/to/proxysql_mcp_stdio_bridge.py"],
      "env": {
        "PROXYSQL_MCP_ENDPOINT": "https://127.0.0.1:6071/mcp/query",
        "PROXYSQL_MCP_TOKEN": "your_token",
        "PROXYSQL_MCP_INSECURE_SSL": "1"
      }
    }
  }
}
```

---

## Related Documentation

- [MCP Server](mcp_server) - MCP server overview
- [MCP Endpoints](mcp_endpoints) - Complete endpoint reference
- [MCP Tools (Query)](mcp_tools_query) - Database exploration tools
- [MCP Tools (RAG)](mcp_tools_rag) - Retrieval-Augmented Generation tools
- [MCP Variables](../references/mcp_variables) - Configuration variables
- [MCP Autodiscovery](mcp_autodiscovery) - Two-phase discovery mechanism
- [NL2SQL](nl2sql) - Natural language to SQL conversion
