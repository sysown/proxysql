# MCP Variables

This document describes all configuration variables for the MCP (Model Context Protocol) module in ProxySQL.

## Overview

The MCP module provides JSON-RPC 2.0 over HTTPS for LLM integration with ProxySQL. It includes endpoints for configuration, observation, querying, administration, caching, and AI features, each with dedicated tool handlers for database exploration and LLM integration.

All variables are stored in the `global_variables` table with the `mcp-` prefix and can be modified at runtime through the admin interface.

## Variable Reference

### Server Configuration

#### `mcp-enabled`
- **Type:** Boolean
- **Default:** `false`
- **Description:** Enable or disable the MCP HTTPS server
- **Runtime:** Yes (requires restart of MCP server to take effect)
- **Example:**
  ```sql
  SET mcp-enabled=true;
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-port`
- **Type:** Integer
- **Default:** `6071`
- **Description:** HTTPS port for the MCP server
- **Range:** 1024-65535
- **Runtime:** Yes (requires restart of MCP server to take effect)
- **Example:**
  ```sql
  SET mcp-port=7071;
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-timeout_ms`
- **Type:** Integer
- **Default:** `30000` (30 seconds)
- **Description:** Request timeout in milliseconds for all MCP endpoints
- **Range:** 1000-300000 (1 second to 5 minutes)
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-timeout_ms=60000;
  LOAD MCP VARIABLES TO RUNTIME;
  ```

### Endpoint Authentication

The following variables control authentication (Bearer tokens) for specific MCP endpoints. If left empty, no authentication is required for that endpoint.

#### `mcp-config_endpoint_auth`
- **Type:** String
- **Default:** `""` (empty)
- **Description:** Bearer token for `/mcp/config` endpoint
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-config_endpoint_auth='my-secret-token';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-observe_endpoint_auth`
- **Type:** String
- **Default:** `""` (empty)
- **Description:** Bearer token for `/mcp/observe` endpoint
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-observe_endpoint_auth='observe-token';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-query_endpoint_auth`
- **Type:** String
- **Default:** `""` (empty)
- **Description:** Bearer token for `/mcp/query` endpoint
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-query_endpoint_auth='query-token';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-admin_endpoint_auth`
- **Type:** String
- **Default:** `""` (empty)
- **Description:** Bearer token for `/mcp/admin` endpoint
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-admin_endpoint_auth='admin-token';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-cache_endpoint_auth`
- **Type:** String
- **Default:** `""` (empty)
- **Description:** Bearer token for `/mcp/cache` endpoint
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-cache_endpoint_auth='cache-token';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-ai_endpoint_auth`
- **Type:** String
- **Default:** `""` (empty)
- **Description:** Bearer token for `/mcp/ai` endpoint
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-ai_endpoint_auth='ai-token';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

### Query Tool Handler Configuration

The Query Tool Handler provides LLM-based tools for MySQL database exploration and two-phase discovery, including:
- **inventory** - List databases and tables
- **targets** - Discover logical routing targets (`list_targets`)
- **structure** - Get table schema
- **profiling** - Analyze query performance
- **sampling** - Sample table data
- **query** - Execute SQL queries
- **relationships** - Infer table relationships
- **catalog** - Catalog operations
- **discovery** - Two-phase discovery tools (static harvest + LLM analysis)
- **agent** - Agent coordination tools
- **llm** - LLM interaction tools

### Dynamic Target Discovery and Routing

Query tools use a logical `target_id` routing model with server-managed credentials:

- Use `list_targets` to retrieve discoverable backend targets.
- Active targets come from `runtime_mcp_target_profiles` joined with `runtime_mcp_auth_profiles`.
- The MCP server maps `target_id -> auth_profile_id` and applies backend credentials internally.
- MCP clients must never send backend credentials in tool arguments.
- Clients should pass `target_id` to query tools instead of host/protocol details.

### Backend Credential Model

Backend credentials are defined in MCP tables, not in client requests:

- `mcp_auth_profiles` / `runtime_mcp_auth_profiles`
- `mcp_target_profiles` / `runtime_mcp_target_profiles`

The in-memory target/auth map is loaded by `MCP_Threads_Handler` from runtime tables and used by the query executor connection pools.

#### `mcp-mysql_hosts`
- **Type:** String (comma-separated)
- **Default:** `"127.0.0.1"`
- **Description:** Legacy POC variable used by non-routed components (for example static harvester defaults). Routed query execution uses MCP profile tables.
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-mysql_hosts='192.168.1.10,192.168.1.11,192.168.1.12';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-mysql_ports`
- **Type:** String (comma-separated)
- **Default:** `"3306"`
- **Description:** Legacy POC variable used by non-routed components (for example static harvester defaults). Routed query execution uses MCP profile tables.
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-mysql_ports='3306,3307,3308';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-mysql_user`
- **Type:** String
- **Default:** `""` (empty)
- **Description:** Legacy POC variable. Routed query execution uses credentials from `mcp_auth_profiles`.
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-mysql_user='mcp_user';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-mysql_password`
- **Type:** String
- **Default:** `""` (empty)
- **Description:** Legacy POC variable. Routed query execution uses credentials from `mcp_auth_profiles`.
- **Runtime:** Yes
- **Note:** Password is stored in plaintext in `global_variables`. Use restrictive MySQL user permissions.
- **Example:**
  ```sql
  SET mcp-mysql_password='secure-password';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

#### `mcp-mysql_schema`
- **Type:** String
- **Default:** `""` (empty)
- **Description:** Legacy POC variable. Routed query execution uses `default_schema` from `mcp_auth_profiles`.
- **Runtime:** Yes
- **Example:**
  ```sql
  SET mcp-mysql_schema='mydb';
  LOAD MCP VARIABLES TO RUNTIME;
  ```

### Catalog Configuration

The catalog database path is **hardcoded** to `mcp_catalog.db` in the ProxySQL datadir and cannot be changed at runtime. The catalog stores:
- Database schemas discovered during two-phase discovery
- LLM memories (summaries, domains, metrics)
- Tool usage statistics
- Search history

## Management Commands

### View Variables

```sql
-- View all MCP variables
SHOW MCP VARIABLES;

-- View specific variable
SELECT variable_name, variable_value
FROM global_variables
WHERE variable_name LIKE 'mcp-%';
```

### Modify Variables

```sql
-- Set a variable
SET mcp-enabled=true;

-- Load to runtime
LOAD MCP VARIABLES TO RUNTIME;

-- Save to disk
SAVE MCP VARIABLES TO DISK;
```

### Profile Commands

Unified command family for MCP backend profiles (auth + target together):

```sql
-- Disk -> Memory
LOAD MCP PROFILES FROM DISK;
LOAD MCP PROFILES TO MEMORY;

-- Memory -> Runtime
LOAD MCP PROFILES TO RUNTIME;
LOAD MCP PROFILES FROM MEMORY;

-- Runtime -> Memory
SAVE MCP PROFILES TO MEMORY;
SAVE MCP PROFILES FROM RUNTIME;

-- Memory -> Disk
SAVE MCP PROFILES TO DISK;
```

### Checksum Commands

```sql
-- Checksum of disk variables
CHECKSUM DISK MCP VARIABLES;

-- Checksum of memory variables
CHECKSUM MEM MCP VARIABLES;

-- Checksum of runtime variables
CHECKSUM MEMORY MCP VARIABLES;
```

## Variable Persistence

Variables can be persisted across three layers:

1. **Disk** (`disk.global_variables`) - Persistent storage
2. **Memory** (`main.global_variables`) - Active configuration
3. **Runtime** (`runtime_global_variables`) - Currently active values

```
LOAD MCP VARIABLES FROM DISK    → Disk to Memory
LOAD MCP VARIABLES TO RUNTIME   → Memory to Runtime
SAVE MCP VARIABLES TO DISK      → Memory to Disk
SAVE MCP VARIABLES FROM RUNTIME → Runtime to Memory
```

## Status Variables

The following read-only status variables are available:

| Variable | Description |
|----------|-------------|
| `mcp_total_requests` | Total number of MCP requests received |
| `mcp_failed_requests` | Total number of failed MCP requests |
| `mcp_active_connections` | Current number of active MCP connections |

To view status variables:

```sql
SELECT * FROM stats_mysql_global WHERE variable_name LIKE 'mcp_%';
```

## Security Considerations

1. **Authentication:** Always set authentication tokens for production environments
2. **HTTPS:** The MCP server uses HTTPS with SSL certificates from the ProxySQL datadir
3. **MySQL Permissions:** Create a dedicated MySQL user with limited permissions for the tool handler:
   - `SELECT` permissions for inventory/structure tools
   - `PROCESS` permission for profiling
   - Limited `SELECT` on specific tables for sampling/query tools
4. **Network Access:** Consider firewall rules to restrict access to `mcp-port`

## Version

- **MCP Thread Version:** 0.1.0
- **Protocol:** JSON-RPC 2.0 over HTTPS
- **Last Updated:** 2026-01-19

## Related Documentation

- [MCP Architecture](Architecture.md) - Module architecture and endpoint specifications
- [Tool Discovery Guide](Tool_Discovery_Guide.md) - Tool discovery and usage documentation
