# MCP Architecture

This document describes the architecture of the MCP (Model Context Protocol) module in ProxySQL, including endpoint design and tool handler implementation.

## Overview

The MCP module implements JSON-RPC 2.0 over HTTPS for LLM (Large Language Model) integration with ProxySQL. It provides multiple endpoints, each designed to serve specific purposes while sharing a single HTTPS server.

### Key Concepts

- **MCP Endpoint**: A distinct HTTPS endpoint (e.g., `/mcp/config`, `/mcp/query`) that implements MCP protocol
- **Tool Handler**: A C++ class that implements specific tools available to LLMs
- **Tool Discovery**: Dynamic discovery via `tools/list` method (MCP protocol standard)
- **Endpoint Authentication**: Per-endpoint Bearer token authentication
- **Connection Pooling**: MySQL connection pooling for efficient database access

## Implemented Architecture

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
│  │  - config_tool_handler  (NEW)                                         │  │
│  │  - query_tool_handler   (NEW)                                         │  │
│  │  - admin_tool_handler   (NEW)                                         │  │
│  │  - cache_tool_handler   (NEW)                                         │  │
│  │  - stats_tool_handler   (NEW)                                         │  │
│  │  - ai_tool_handler      (NEW)                                         │  │
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
│    ┌──────────────┬──────────────┼──────────────┬──────────────┬─────────┐  │
│    ▼              ▼              ▼              ▼              ▼         ▼  │
│ ┌────┐        ┌────┐         ┌────┐         ┌────┐         ┌────┐    ┌───┐│
│ │conf│        │sts │         │qry │         │adm │         │cach│    │ai ││
│ │TH  │        │TH  │         │TH  │         │TH  │         │TH  │    │TH ││
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
│           ┌────────────────────────────────────────────┐                 │
│           │         MySQL Backend                      │                 │
│           │    (Connection Pool)                       │                 │
│           └────────────────────────────────────────────┘                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

Where:
- `TH` = Tool Handler

### File Structure

```
include/
├── MCP_Thread.h          # MCP_Threads_Handler class definition
├── MCP_Endpoint.h        # MCP_JSONRPC_Resource class definition
├── MCP_Tool_Handler.h    # Base class for all tool handlers
├── Config_Tool_Handler.h # Configuration endpoint tool handler
├── Query_Tool_Handler.h  # Query endpoint tool handler (includes discovery tools)
├── Admin_Tool_Handler.h  # Administration endpoint tool handler
├── Cache_Tool_Handler.h  # Cache endpoint tool handler
├── Stats_Tool_Handler.h # Stats endpoint tool handler
├── AI_Tool_Handler.h     # AI endpoint tool handler
├── Discovery_Schema.h    # Discovery catalog implementation
├── Static_Harvester.h    # Static database harvester for discovery
└── ProxySQL_MCP_Server.hpp # ProxySQL_MCP_Server class definition

lib/
├── MCP_Thread.cpp        # MCP_Threads_Handler implementation
├── MCP_Endpoint.cpp      # MCP_JSONRPC_Resource implementation
├── MCP_Tool_Handler.cpp  # Base class implementation
├── Config_Tool_Handler.cpp # Configuration endpoint implementation
├── Query_Tool_Handler.cpp # Query endpoint implementation
├── Admin_Tool_Handler.cpp # Administration endpoint implementation
├── Cache_Tool_Handler.cpp # Cache endpoint implementation
├── Stats_Tool_Handler.cpp # Stats endpoint implementation
├── AI_Tool_Handler.cpp   # AI endpoint implementation
├── Discovery_Schema.cpp  # Discovery catalog implementation
├── Static_Harvester.cpp  # Static database harvester implementation
└── ProxySQL_MCP_Server.cpp # HTTPS server implementation
```

### Request Flow (Implemented)

```
1. LLM Client → POST /mcp/{endpoint} → HTTPS Server (port 6071)
2. HTTPS Server → MCP_JSONRPC_Resource::render_POST()
3. MCP_JSONRPC_Resource → handle_jsonrpc_request()
4. Route based on JSON-RPC method:
   - initialize/ping → Handled directly
   - tools/list → handle_tools_list()
   - tools/describe → handle_tools_describe()
   - tools/call → handle_tools_call() → Dedicated Tool Handler
5. Dedicated Tool Handler → MySQL Backend (via connection pool)
6. Return JSON-RPC response
```

## Implemented Endpoint Specifications

### Overview

Each MCP endpoint has its own dedicated tool handler with specific tools designed for that endpoint's purpose. This allows for:

- **Specialized tools** - Different tools for different purposes
- **Isolated resources** - Separate connection pools per endpoint
- **Independent authentication** - Per-endpoint credentials
- **Clear separation of concerns** - Each endpoint has a well-defined purpose

### Endpoint Specifications

#### `/mcp/config` - Configuration Endpoint

**Purpose**: Runtime configuration and management of ProxySQL

**Tools**:
- `get_config` - Get current configuration values
- `set_config` - Modify configuration values
- `reload_config` - Reload configuration from disk/memory
- `list_variables` - List all available variables
- `get_status` - Get server status information
- `query` - Execute constrained SQL against the admin/config database

**Query policy**:
- Allows read/write SQL that starts with `SELECT`, `WITH`, `INSERT`, `UPDATE`, `DELETE`, `REPLACE`, or `VALUES`
- Rejects DDL and dangerous control statements, including `PRAGMA`, `ATTACH`, `DETACH`, `LOAD_EXTENSION`, transaction control, and schema-altering statements
- Rejects multi-statement input
- Returns structured JSON with the SQL text, `rows_affected`, `row_count`, `columns`, and `rows`

**Use Cases**:
- LLM assistants that need to configure ProxySQL
- Automated configuration management
- Dynamic tuning based on workload

**Authentication**: `mcp-config_endpoint_auth` (Bearer token)

---

#### `/mcp/stats` - Observability Endpoint

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

**Authentication**: `mcp-stats_endpoint_auth` (Bearer token)

---

#### `/mcp/query` - Query Endpoint

**Purpose**: Safe database exploration and query execution

**Tools**:
- `list_targets` - List logical backend targets (hostgroup-backed routing handles)
- `list_schemas` - List databases
- `list_tables` - List tables in schema
- `describe_table` - Get table structure
- `get_constraints` - Get foreign keys and constraints
- `sample_rows` - Get sample data
- `run_sql_readonly` - Execute read-only SQL
- `explain_sql` - Explain query execution plan
- `suggest_joins` - Suggest join paths between tables
- `find_reference_candidates` - Find potential foreign key relationships
- `table_profile` - Get table statistics and data distribution
- `column_profile` - Get column statistics and data distribution
- `sample_distinct` - Get distinct values from a column
- `catalog_get` - Get entry from discovery catalog
- `catalog_upsert` - Insert or update entry in discovery catalog
- `catalog_delete` - Delete entry from discovery catalog
- `catalog_search` - Search entries in discovery catalog
- `catalog_list` - List all entries in discovery catalog
- `catalog_clear` - Clear all entries from discovery catalog
- `discovery.run_static` - Run static database discovery (Phase 1)
- `agent.*` - Agent coordination tools for discovery
- `llm.*` - LLM interaction tools for discovery

**Use Cases**:
- LLM assistants for database exploration
- Data analysis and discovery
- Query optimization assistance
- Two-phase discovery (static harvest + LLM analysis)
- Multi-backend routing via opaque `target_id` values instead of direct host/protocol details

**Authentication**: `mcp-query_endpoint_auth` (Bearer token)

#### Query Target Routing Model

`/mcp/query` now supports a dynamic routing model based on logical targets:

- Clients call `list_targets` to discover routable targets.
- Each target exposes:
  - `target_id` (opaque identifier)
  - `description` (human-readable summary)
  - `capabilities` (for example `inventory`, `readonly_sql`, `explain`)
- Query tools (for example `run_sql_readonly`, `explain_sql`, `list_tables`) accept an optional `target_id`.
- If `target_id` is omitted, the server uses a default executable target when available.

Internally, the server resolves each `target_id` to runtime hostgroup metadata, a configured auth profile, and protocol-specific execution paths.

Credential separation model:

- MCP endpoint authentication (Bearer token) identifies and authorizes the MCP client.
- Backend database credentials are server-managed in MCP runtime profile tables:
  - `runtime_mcp_target_profiles`
  - `runtime_mcp_auth_profiles`
- Query execution pools are keyed by `target_id + auth_profile_id`.

Current execution support:

- `mysql` targets: `list_tables`, `run_sql_readonly`, `explain_sql`
- `pgsql` targets: `list_tables`, `run_sql_readonly`, `explain_sql`

#### MCP Query Rules and Stats

MCP query rules support routing-aware filters so one endpoint can enforce different policies per logical target:

- `username`: backend DB username from the resolved auth profile
- `target_id`: logical MCP target selected by the client (or resolved default target)
- `schemaname`: optional schema/database context
- `tool_name`: MCP tool name (for example `run_sql_readonly`)

The runtime and stats views expose these fields:

- `runtime_mcp_query_rules`: includes `username` and `target_id` columns
- `stats_mcp_query_rules`: includes `rule_id`, `username`, `target_id`, `hits`

This allows policy verification and hit analysis per logical route without exposing backend host/protocol details to MCP clients.

#### `/mcp/rag` - Retrieval Endpoint

**Purpose**: RAG search, retrieval, and source re-fetch operations

**Tools**:
- `rag.search_fts` - Keyword search over chunked content
- `rag.search_vector` - Semantic search over embeddings
- `rag.search_hybrid` - Combined FTS + vector search
- `rag.get_chunks` - Fetch chunk content by `chunk_id`
- `rag.get_docs` - Fetch document content by `doc_id`
- `rag.fetch_from_source` - Re-fetch authoritative rows from the configured source backend
- `rag.admin.stats` - Operational statistics for the RAG subsystem

**Fetch policy**:
- Looks up each requested `doc_id` from the vector database metadata tables
- Uses the source row's `backend_type` to connect to MySQL or PostgreSQL backends
- Reconstructs the source `SELECT` from the stored `table_name`, primary-key metadata, and optional `where_sql`
- Returns one result row per requested document, with per-row errors when a document is missing or the backend cannot be reached
- Rejects unsupported backend types instead of guessing a connection path

**Use Cases**:
- LLM assistants that need indexed retrieval over documents
- Semantic search and chunk inspection
- Operational recovery by re-reading source-of-truth rows

**Authentication**: `mcp-rag_endpoint_auth` (Bearer token)

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

#### `/mcp/ai` - AI Endpoint

**Purpose**: AI and LLM features

**Tools**:
- `llm.query` - Query LLM with database context
- `llm.analyze` - Analyze data with LLM
- `llm.generate` - Generate content with LLM
- `anomaly.detect` - Detect anomalies in data
- `anomaly.list` - List detected anomalies
- `recommendation.get` - Get AI recommendations

**Use Cases**:
- LLM-powered data analysis
- Anomaly detection
- AI-driven recommendations

**Authentication**: `mcp-ai_endpoint_auth` (Bearer token)

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

Each endpoint validates its own Bearer token. The implementation is complete and supports:

- **Bearer token** from `Authorization` header
- **Query parameter fallback** (`?token=xxx`) for simple testing
- **No authentication** when token is not configured (backward compatible)

```cpp
bool MCP_JSONRPC_Resource::authenticate_request(const http_request& req) {
    // Get the expected auth token for this endpoint
    char* expected_token = nullptr;

    if (endpoint_name == "config") {
        expected_token = handler->variables.mcp_config_endpoint_auth;
    } else if (endpoint_name == "stats") {
        expected_token = handler->variables.mcp_stats_endpoint_auth;
    } else if (endpoint_name == "query") {
        expected_token = handler->variables.mcp_query_endpoint_auth;
    } else if (endpoint_name == "admin") {
        expected_token = handler->variables.mcp_admin_endpoint_auth;
    } else if (endpoint_name == "cache") {
        expected_token = handler->variables.mcp_cache_endpoint_auth;
    }

    // If no auth token is configured, allow the request
    if (!expected_token || strlen(expected_token) == 0) {
        return true; // No authentication required
    }

    // Try to get Bearer token from Authorization header
    std::string auth_header = req.get_header("Authorization");

    if (auth_header.empty()) {
        // Fallback: try getting from query parameter
        const std::map<std::string, std::string, http::arg_comparator>& args = req.get_args();
        auto it = args.find("token");
        if (it != args.end()) {
            auth_header = "Bearer " + it->second;
        }
    }

    if (auth_header.empty()) {
        return false; // No authentication provided
    }

    // Check if it's a Bearer token
    const std::string bearer_prefix = "Bearer ";
    if (auth_header.length() <= bearer_prefix.length() ||
        auth_header.compare(0, bearer_prefix.length(), bearer_prefix) != 0) {
        return false; // Invalid format
    }

    // Extract and validate token
    std::string provided_token = auth_header.substr(bearer_prefix.length());
    // Trim whitespace
    size_t start = provided_token.find_first_not_of(" \t\n\r");
    size_t end = provided_token.find_last_not_of(" \t\n\r");
    if (start != std::string::npos && end != std::string::npos) {
        provided_token = provided_token.substr(start, end - start + 1);
    }

    return (provided_token == expected_token);
}
```

**Status:** ✅ **Implemented** (lib/MCP_Endpoint.cpp)

### Connection Pooling Strategy

Each tool handler manages its own connection pool:

```cpp
class Config_Tool_Handler : public MCP_Tool_Handler {
private:
    std::vector<MYSQL*> config_connection_pool;  // For ProxySQL admin
    pthread_mutex_t pool_lock;
};
```

## Implementation Status

### Phase 1: Base Infrastructure ✅ COMPLETED

1. ✅ Create `MCP_Tool_Handler` base class
2. ✅ Create implementations for all 6 tool handlers (config, query, admin, cache, stats, ai)
3. ✅ Update `MCP_Threads_Handler` to manage all handlers
4. ✅ Update `ProxySQL_MCP_Server` to pass handlers to endpoints

### Phase 2: Tool Implementation ✅ COMPLETED

1. ✅ Implement Config_Tool_Handler tools
2. ✅ Implement Query_Tool_Handler tools (includes MySQL tools and discovery tools)
3. ✅ Implement Admin_Tool_Handler tools
4. ✅ Implement Cache_Tool_Handler tools
5. ✅ Implement Stats_Tool_Handler tools
6. ✅ Implement AI_Tool_Handler tools

### Phase 3: Authentication & Testing ✅ MOSTLY COMPLETED

1. ✅ Implement per-endpoint authentication
2. ⚠️ Update test scripts to use dynamic tool discovery
3. ⚠️ Add integration tests for each endpoint
4. ✅ Documentation updates (this document)

## Migration Status ✅ COMPLETED

### Backward Compatibility Maintained

The migration to multiple tool handlers has been completed while maintaining backward compatibility:

1. ✅ The existing `mysql_tool_handler` has been replaced by `query_tool_handler`
2. ✅ Existing tools continue to work on `/mcp/query`
3. ✅ New endpoints have been added incrementally
4. ✅ Deprecation warnings are provided for accessing tools on wrong endpoints

### Migration Steps Completed

```
✅ Step 1: Add new base class and stub handlers (no behavior change)
✅ Step 2: Implement /mcp/config endpoint (new functionality)
✅ Step 3: Move MySQL tools to /mcp/query (existing tools migrate)
✅ Step 4: Implement /mcp/admin (new functionality)
✅ Step 5: Implement /mcp/cache (new functionality)
✅ Step 6: Implement /mcp/stats (new functionality)
✅ Step 7: Enable per-endpoint auth
✅ Step 8: Add /mcp/ai endpoint (new AI functionality)
```

## Related Documentation

- [VARIABLES.md](VARIABLES.md) - Configuration variables reference
- [README.md](README.md) - Module overview and setup

## Version

- **MCP Thread Version:** 0.1.0
- **Architecture Version:** 1.0 (design document)
- **Last Updated:** 2026-01-19
