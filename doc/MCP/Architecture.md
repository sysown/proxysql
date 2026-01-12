# MCP Architecture

This document describes the architecture of the MCP (Model Context Protocol) module in ProxySQL, including endpoint design, tool handler implementation, and future architectural direction.

## Overview

The MCP module implements JSON-RPC 2.0 over HTTPS for LLM (Large Language Model) integration with ProxySQL. It provides multiple endpoints, each designed to serve specific purposes while sharing a single HTTPS server.

### Key Concepts

- **MCP Endpoint**: A distinct HTTPS endpoint (e.g., `/mcp/config`, `/mcp/query`) that implements MCP protocol
- **Tool Handler**: A C++ class that implements specific tools available to LLMs
- **Tool Discovery**: Dynamic discovery via `tools/list` method (MCP protocol standard)
- **Endpoint Authentication**: Per-endpoint Bearer token authentication
- **Connection Pooling**: MySQL connection pooling for efficient database access

## Current Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ProxySQL Process                               │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     MCP_Threads_Handler                               │  │
│  │  - Configuration variables (mcp-*)                                    │  │
│  │  - Status variables                                                   │  │
│  │  - mcp_server (ProxySQL_MCP_Server)                                   │  │
│  │  - mysql_tool_handler (MySQL_Tool_Handler)                            │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│                                    ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     ProxySQL_MCP_Server                               │  │
│  │                      (Single HTTPS Server)                            │  │
│  │                                                                       │  │
│  │  Port: mcp-port (default 6071)                                        │  │
│  │  SSL: Uses ProxySQL's certificates                                    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│              ┌─────────────────────┼─────────────────────┐                 │
│              ▼                     ▼                     ▼                 │
│  ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐         │
│  │   /mcp/config     │ │   /mcp/observe    │ │   /mcp/query      │         │
│  │ MCP_JSONRPC_      │ │ MCP_JSONRPC_      │ │ MCP_JSONRPC_      │         │
│  │ Resource          │ │ Resource          │ │ Resource          │         │
│  └─────────┬─────────┘ └─────────┬─────────┘ └─────────┬─────────┘         │
│            │                     │                     │                     │
│            └─────────────────────┼─────────────────────┘                     │
│                                  ▼                                         │
│           ┌────────────────────────────────────────────┐                    │
│           │      MySQL_Tool_Handler (Shared)           │                    │
│           │                                            │                    │
│           │  Tools:                                    │                    │
│           │  - list_schemas                            │                    │
│           │  - list_tables                             │                    │
│           │  - describe_table                          │                    │
│           │  - get_constraints                         │                    │
│           │  - table_profile                           │                    │
│           │  - column_profile                          │                    │
│           │  - sample_rows                             │                    │
│           │  - run_sql_readonly                        │                    │
│           │  - catalog_* (6 tools)                     │                    │
│           └────────────────────────────────────────────┘                    │
│                                  │                                         │
│                                  ▼                                         │
│           ┌────────────────────────────────────────────┐                    │
│           │         MySQL Backend                      │                    │
│           │    (Connection Pool)                       │                    │
│           └────────────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Current Limitations

1. **All endpoints share the same tool handler** - No differentiation between endpoints
2. **Same tools available everywhere** - No specialized tools per endpoint
3. **Single connection pool** - All queries use the same MySQL connections
4. **No per-endpoint authentication in code** - Variables exist but not implemented

### File Structure

```
include/
├── MCP_Thread.h          # MCP_Threads_Handler class definition
├── MCP_Endpoint.h        # MCP_JSONRPC_Resource class definition
├── MySQL_Tool_Handler.h  # MySQL_Tool_Handler class definition
├── MySQL_Catalog.h       # SQLite catalog for LLM memory
└── ProxySQL_MCP_Server.hpp # ProxySQL_MCP_Server class definition

lib/
├── MCP_Thread.cpp        # MCP_Threads_Handler implementation
├── MCP_Endpoint.cpp      # MCP_JSONRPC_Resource implementation
├── MySQL_Tool_Handler.cpp # MySQL_Tool_Handler implementation
├── MySQL_Catalog.cpp     # SQLite catalog implementation
└── ProxySQL_MCP_Server.cpp # HTTPS server implementation
```

### Request Flow (Current)

```
1. LLM Client → POST /mcp/{endpoint} → HTTPS Server (port 6071)
2. HTTPS Server → MCP_JSONRPC_Resource::render_POST()
3. MCP_JSONRPC_Resource → handle_jsonrpc_request()
4. Route based on JSON-RPC method:
   - initialize/ping → Handled directly
   - tools/list → handle_tools_list()
   - tools/describe → handle_tools_describe()
   - tools/call → handle_tools_call() → MySQL_Tool_Handler
5. MySQL_Tool_Handler → MySQL Backend (via connection pool)
6. Return JSON-RPC response
```

## Future Architecture: Multiple Tool Handlers

### Goal

Each MCP endpoint will have its own dedicated tool handler with specific tools designed for that endpoint's purpose. This allows for:

- **Specialized tools** - Different tools for different purposes
- **Isolated resources** - Separate connection pools per endpoint
- **Independent authentication** - Per-endpoint credentials
- **Clear separation of concerns** - Each endpoint has a well-defined purpose

### Target Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ProxySQL Process                               │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     MCP_Threads_Handler                               │  │
│  │  - Configuration variables                                            │  │
│  │  - Status variables                                                   │  │
│  │  - mcp_server                                                         │  │
│  │  - config_tool_handler  (NEW)                                         │  │
│  │  - query_tool_handler   (NEW)                                         │  │
│  │  - admin_tool_handler   (NEW)                                         │  │
│  │  - cache_tool_handler   (NEW)                                         │  │
│  │  - observe_tool_handler (NEW)                                         │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│                                    ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     ProxySQL_MCP_Server                               │  │
│  │                      (Single HTTPS Server)                            │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│    ┌──────────────┬──────────────┼──────────────┬──────────────┬─────────┐  │
│    ▼              ▼              ▼              ▼              ▼         ▼  │
│ ┌────┐        ┌────┐         ┌────┐         ┌────┐         ┌────┐    ┌───┐│
│ │conf│        │obs │         │qry │         │adm │         │cach│    │cat││
│ │TH  │        │TH  │         │TH  │         │TH  │         │TH  │    │log│││
│ └─┬──┘        └─┬──┘         └─┬──┘         └─┬──┘         └─┬──┘    └─┬─┘│
│   │             │               │               │               │        │  │
│   │             │               │               │               │        │  │
│ Tools:         Tools:         Tools:         Tools:         Tools:      │  │
│ - get_config   - list_        - list_        - admin_       - get_      │  │
│ - set_config    stats          schemas       - set_          cache      │  │
│ - reload       - show_        - list_        - reload       - set_      │  │
│                 metrics        tables                       - invalidate │  │
│                               - query                                  │  │
│                                                                         │  │
└─────────────────────────────────────────────────────────────────────────────┘
```

Where:
- `TH` = Tool Handler

### Endpoint Specifications

#### `/mcp/config` - Configuration Endpoint

**Purpose**: Runtime configuration and management of ProxySQL

**Tools**:
- `get_config` - Get current configuration values
- `set_config` - Modify configuration values
- `reload_config` - Reload configuration from disk/memory
- `list_variables` - List all available variables
- `get_status` - Get server status information

**Use Cases**:
- LLM assistants that need to configure ProxySQL
- Automated configuration management
- Dynamic tuning based on workload

**Authentication**: `mcp-config_endpoint_auth` (Bearer token)

---

#### `/mcp/observe` - Observability Endpoint

**Purpose**: Real-time metrics, statistics, and monitoring data

**Tools**:
- `list_stats` - List available statistics
- `get_stats` - Get specific statistics
- `show_connections` - Show active connections
- `show_queries` - Show query statistics
- `get_health` - Get health check information
- `show_metrics` - Show performance metrics

**Use Cases**:
- LLM assistants for monitoring and observability
- Automated alerting and health checks
- Performance analysis

**Authentication**: `mcp-observe_endpoint_auth` (Bearer token)

---

#### `/mcp/query` - Query Endpoint

**Purpose**: Safe database exploration and query execution

**Tools**:
- `list_schemas` - List databases
- `list_tables` - List tables in schema
- `describe_table` - Get table structure
- `get_constraints` - Get foreign keys and constraints
- `sample_rows` - Get sample data
- `run_sql_readonly` - Execute read-only SQL
- `explain_sql` - Explain query execution plan

**Use Cases**:
- LLM assistants for database exploration
- Data analysis and discovery
- Query optimization assistance

**Authentication**: `mcp-query_endpoint_auth` (Bearer token)

---

#### `/mcp/admin` - Administration Endpoint

**Purpose**: Administrative operations

**Tools**:
- `admin_list_users` - List MySQL users
- `admin_create_user` - Create MySQL user
- `admin_grant_permissions` - Grant permissions
- `admin_show_processes` - Show running processes
- `admin_kill_query` - Kill a running query
- `admin_flush_cache` - Flush various caches
- `admin_reload` - Reload users/servers

**Use Cases**:
- LLM assistants for administration tasks
- Automated user management
- Emergency operations

**Authentication**: `mcp-admin_endpoint_auth` (Bearer token, most restrictive)

---

#### `/mcp/cache` - Cache Endpoint

**Purpose**: Query cache management

**Tools**:
- `get_cache_stats` - Get cache statistics
- `invalidate_cache` - Invalidate cache entries
- `set_cache_ttl` - Set cache TTL
- `clear_cache` - Clear all cache
- `warm_cache` - Warm up cache with queries
- `get_cache_entries` - List cached queries

**Use Cases**:
- LLM assistants for cache optimization
- Automated cache management
- Performance tuning

**Authentication**: `mcp-cache_endpoint_auth` (Bearer token)

---

### Tool Discovery Flow

MCP clients should discover available tools dynamically:

```
1. Client → POST /mcp/config → {"method": "tools/list", ...}
2. Server → {"result": {"tools": [
      {"name": "get_config", "description": "..."},
      {"name": "set_config", "description": "..."},
      ...
   ]}}

3. Client → POST /mcp/query → {"method": "tools/list", ...}
4. Server → {"result": {"tools": [
      {"name": "list_schemas", "description": "..."},
      {"name": "list_tables", "description": "..."},
      ...
   ]}}
```

**Example Discovery**:

```bash
# Discover tools on /mcp/query endpoint
curl -k -X POST https://127.0.0.1:6071/mcp/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

### Tool Handler Base Class

All tool handlers will inherit from a common base class:

```cpp
class MCP_Tool_Handler {
public:
    virtual ~MCP_Tool_Handler() = default;

    // Tool discovery
    virtual json get_tool_list() = 0;
    virtual json get_tool_description(const std::string& tool_name) = 0;
    virtual json execute_tool(const std::string& tool_name, const json& arguments) = 0;

    // Lifecycle
    virtual int init() = 0;
    virtual void close() = 0;
};
```

### Per-Endpoint Authentication

Each endpoint validates its own Bearer token:

```cpp
bool MCP_JSONRPC_Resource::authenticate_request(const http_request& req) {
    std::string auth_header = req.get_header("Authorization");

    // Get expected token for this endpoint
    std::string* expected_token = nullptr;
    if (endpoint_name == "config") {
        expected_token = handler->variables.mcp_config_endpoint_auth;
    } else if (endpoint_name == "query") {
        expected_token = handler->variables.mcp_query_endpoint_auth;
    }
    // ... etc

    // Validate token
    if (!expected_token || strlen(expected_token) == 0) {
        return true; // No auth configured
    }

    // Extract and validate Bearer token
    // ...
}
```

### Connection Pooling Strategy

Each tool handler manages its own connection pool:

```cpp
class Config_Tool_Handler : public MCP_Tool_Handler {
private:
    std::vector<MYSQL*> config_connection_pool;  // For ProxySQL admin
    pthread_mutex_t pool_lock;
};
```

## Implementation Roadmap

### Phase 1: Base Infrastructure

1. Create `MCP_Tool_Handler` base class
2. Create stub implementations for all 5 tool handlers
3. Update `MCP_Threads_Handler` to manage all handlers
4. Update `ProxySQL_MCP_Server` to pass handlers to endpoints

### Phase 2: Tool Implementation

1. Implement Config_Tool_Handler tools
2. Implement Query_Tool_Handler tools (move from MySQL_Tool_Handler)
3. Implement Admin_Tool_Handler tools
4. Implement Cache_Tool_Handler tools
5. Implement Observe_Tool_Handler tools

### Phase 3: Authentication & Testing

1. Implement per-endpoint authentication
2. Update test scripts to use dynamic tool discovery
3. Add integration tests for each endpoint
4. Documentation updates

## Migration Strategy

### Backward Compatibility

The migration to multiple tool handlers will maintain backward compatibility:

1. The existing `mysql_tool_handler` will be renamed to `query_tool_handler`
2. Existing tools will continue to work on `/mcp/query`
3. New endpoints will be added incrementally
4. Deprecation warnings for accessing tools on wrong endpoints

### Gradual Migration

```
Step 1: Add new base class and stub handlers (no behavior change)
Step 2: Implement /mcp/config endpoint (new functionality)
Step 3: Move MySQL tools to /mcp/query (existing tools migrate)
Step 4: Implement /mcp/admin (new functionality)
Step 5: Implement /mcp/cache (new functionality)
Step 6: Implement /mcp/observe (new functionality)
Step 7: Enable per-endpoint auth
```

## Related Documentation

- [VARIABLES.md](VARIABLES.md) - Configuration variables reference
- [README.md](README.md) - Module overview and setup

## Version

- **MCP Thread Version:** 0.1.0
- **Architecture Version:** 1.0 (design document)
- **Last Updated:** 2025-01-12
