# MCP Full-Text Search (FTS) - User Guide

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Configuration](#configuration)
4. [FTS Tools Reference](#fts-tools-reference)
5. [Usage Examples](#usage-examples)
6. [API Endpoints](#api-endpoints)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)
9. [Detailed Test Script](#detailed-test-script)

---

## Overview

The MCP Full-Text Search (FTS) module provides fast, indexed search capabilities for MySQL table data. It uses SQLite's FTS5 extension with BM25 ranking, allowing AI agents to quickly find relevant data before making targeted queries to the MySQL backend.

### Key Benefits

- **Fast Discovery**: Search millions of rows in milliseconds
- **BM25 Ranking**: Results ranked by relevance
- **Snippet Highlighting**: Search terms highlighted in results
- **Cross-Table Search**: Search across multiple indexed tables
- **Selective Indexing**: Index specific columns with optional WHERE filters
- **AI Agent Optimized**: Reduces LLM query overhead by finding relevant IDs first

### How It Works

```text
Traditional Query Flow:
LLM Agent → Full Table Scan → Millions of Rows → Slow Response

FTS-Optimized Flow:
LLM Agent → FTS Search (ms) → Top N IDs → Targeted MySQL Query → Fast Response
```

---

## Architecture

### Components

```text
┌─────────────────────────────────────────────────────────────┐
│                     MCP Query Endpoint                     │
│                   (JSON-RPC 2.0 over HTTPS)                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  Query_Tool_Handler                         │
│  - Routes tool calls to MySQL_Tool_Handler                 │
│  - Provides 6 FTS tools via MCP protocol                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  MySQL_Tool_Handler                         │
│  - Wraps MySQL_FTS class                                   │
│  - Provides execute_query() for MySQL access               │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
┌─────────────────────┐         ┌─────────────────┐
│    MySQL_FTS        │         │   MySQL Backend │
│  (SQLite FTS5)      │         │   (Actual Data) │
│                     │         │                 │
│ ┌─────────────────┐ │         │                 │
│ │ fts_indexes     │ │         │                 │
│ │ (metadata)      │ │         │                 │
│ └─────────────────┘ │         │                 │
│                     │         │                 │
│ ┌─────────────────┐ │         │                 │
│ │ fts_data_*      │ │         │                 │
│ │ (content store) │ │         │                 │
│ └─────────────────┘ │         │                 │
│                     │         │                 │
│ ┌─────────────────┐ │         │                 │
│ │ fts_search_*    │ │         │                 │
│ │ (FTS5 virtual)  │ │         │                 │
│ └─────────────────┘ │         │                 │
└─────────────────────┘         └─────────────────┘
```

### Data Flow

1. **Index Creation**:
   ```text
   MySQL Table → SELECT → JSON Parse → SQLite Insert → FTS5 Index
   ```

2. **Search**:
   ```text
   Query → FTS5 MATCH → BM25 Ranking → Results + Snippets → JSON Response
   ```

---

## Configuration

### Admin Interface Variables

Configure FTS via the ProxySQL admin interface (port 6032):

```sql
-- Enable/disable MCP module
SET mcp-enabled = true;

-- Configure FTS database path
SET mcp-fts_path = '/var/lib/proxysql/mcp_fts.db';

-- Configure server-side auth and logical target routing
INSERT INTO mcp_auth_profiles (auth_profile_id, db_username, db_password, default_schema, use_ssl, ssl_mode, comment)
VALUES ('fts_mysql_auth', 'root', 'password', 'mydb', 0, '', 'FTS MySQL auth profile');

INSERT INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id, description, max_rows, timeout_ms, allow_explain, allow_discovery, active, comment)
VALUES ('fts_mysql_target', 'mysql', 9100, 'fts_mysql_auth', 'FTS MySQL backend', 200, 5000, 1, 1, 1, 'FTS target');

-- Apply changes
LOAD MCP VARIABLES TO RUNTIME;
LOAD MCP PROFILES TO RUNTIME;
```

### Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `mcp-fts_path` | `mcp_fts.db` | Path to SQLite FTS database |
| `mcp_auth_profiles` | N/A | Server-side DB credentials keyed by `auth_profile_id` |
| `mcp_target_profiles` | N/A | Logical `target_id` to protocol/hostgroup/auth mapping |

### File System Requirements

The FTS database file will be created at the configured path. Ensure:

1. The directory exists and is writable by ProxySQL
2. Sufficient disk space for indexes (typically 10-50% of source data size)
3. Regular backups if data persistence is required

---

### Quick Start (End-to-End)

1. Start ProxySQL with MCP enabled and a valid `mcp-fts_path`.
2. Create an index on a table.
3. Run a search and use returned IDs for a targeted SQL query.

Example (JSON-RPC via curl):

```bash
curl -s -X POST http://127.0.0.1:6071/mcp/query \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "fts_index_table",
      "arguments": {
        "schema": "testdb",
        "table": "customers",
        "columns": ["name", "email", "created_at"],
        "primary_key": "id"
      }
    }
  }'
```

Then search:

```bash
curl -s -X POST http://127.0.0.1:6071/mcp/query \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "fts_search",
      "arguments": {
        "query": "Alice",
        "schema": "testdb",
        "table": "customers",
        "limit": 5,
        "offset": 0
      }
    }
  }'
```

### Response Envelope (MCP JSON-RPC)

The MCP endpoint returns tool results inside the JSON-RPC response. Depending on client/server configuration, the tool result may appear in:

- `result.content[0].text` (stringified JSON), or
- `result.result` (JSON object)

If your client expects MCP “content blocks”, parse `result.content[0].text` as JSON.

---

## FTS Tools Reference

### 1. fts_index_table

Create and populate a full-text search index for a MySQL table.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `schema` | string | Yes | Schema name |
| `table` | string | Yes | Table name |
| `columns` | array (or JSON string) | Yes | Column names to index |
| `primary_key` | string | Yes | Primary key column name |
| `where_clause` | string | No | Optional WHERE clause for filtering |

**Response:**
```json
{
  "success": true,
  "schema": "sales",
  "table": "orders",
  "row_count": 15000,
  "indexed_at": 1736668800
}
```

**Example:**
```json
{
  "name": "fts_index_table",
  "arguments": {
    "schema": "sales",
    "table": "orders",
    "columns": ["order_id", "customer_name", "notes", "status"],
    "primary_key": "order_id",
    "where_clause": "created_at >= '2024-01-01'"
  }
}
```

**Notes:**
- If an index already exists, the tool returns an error
- Use `fts_reindex` to refresh an existing index
- Column values are concatenated for full-text search
- Original row data is stored as JSON metadata
- The primary key is always fetched to populate `primary_key_value`

---

### 2. fts_search

Search indexed data using FTS5 with BM25 ranking.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `query` | string | Yes | FTS5 search query |
| `schema` | string | No | Filter by schema |
| `table` | string | No | Filter by table |
| `limit` | integer | No | Max results (default: 100) |
| `offset` | integer | No | Pagination offset (default: 0) |

**Response:**
```json
{
  "success": true,
  "query": "urgent customer",
  "total_matches": 234,
  "results": [
    {
      "schema": "sales",
      "table": "orders",
      "primary_key_value": "12345",
      "snippet": "Customer has <mark>urgent</mark> <mark>customer</mark> complaint...",
      "metadata": {"order_id":12345,"customer_name":"John Smith"}
    }
  ]
}
```

**Example:**
```json
{
  "name": "fts_search",
  "arguments": {
    "query": "urgent customer complaint",
    "limit": 10
  }
}
```

**FTS5 Query Syntax:**
- Simple terms: `urgent`
- Phrases: `"customer complaint"`
- Boolean: `urgent AND pending`
- Wildcards: `cust*`
- Prefix: `^urgent`

**Notes:**
- Results are ranked by BM25 relevance score
- Snippets highlight matching terms with `<mark>` tags
- Without schema/table filters, searches across all indexes

---

### 3. fts_list_indexes

List all FTS indexes with metadata.

**Parameters:**
None

**Response:**
```json
{
  "success": true,
  "indexes": [
    {
      "schema": "sales",
      "table": "orders",
      "columns": ["order_id","customer_name","notes"],
      "primary_key": "order_id",
      "where_clause": "created_at >= '2024-01-01'",
      "row_count": 15000,
      "indexed_at": 1736668800
    }
  ]
}
```

**Example:**
```json
{
  "name": "fts_list_indexes",
  "arguments": {}
}
```

---

### 4. fts_delete_index

Remove an FTS index and all associated data.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `schema` | string | Yes | Schema name |
| `table` | string | Yes | Table name |

**Response:**
```json
{
  "success": true,
  "schema": "sales",
  "table": "orders",
  "message": "Index deleted successfully"
}
```

**Example:**
```json
{
  "name": "fts_delete_index",
  "arguments": {
    "schema": "sales",
    "table": "orders"
  }
}
```

**Warning:**
- This permanently removes the index and all search data
- Does not affect the original MySQL table

---

### 5. fts_reindex

Refresh an index with fresh data from MySQL (full rebuild).

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `schema` | string | Yes | Schema name |
| `table` | string | Yes | Table name |

**Response:**
```json
{
  "success": true,
  "schema": "sales",
  "table": "orders",
  "row_count": 15200,
  "indexed_at": 1736670000
}
```

**Example:**
```json
{
  "name": "fts_reindex",
  "arguments": {
    "schema": "sales",
    "table": "orders"
  }
}
```

**Use Cases:**
- Data has been added/modified in MySQL
- Scheduled index refresh
- Index corruption recovery

---

### 6. fts_rebuild_all

Rebuild ALL FTS indexes with fresh data.

**Parameters:**
None

**Response:**
```json
{
  "success": true,
  "rebuilt_count": 5,
  "failed": [],
  "total_indexes": 5,
  "indexes": [
    {
      "schema": "sales",
      "table": "orders",
      "row_count": 15200,
      "status": "success"
    }
  ]
}
```

**Example:**
```json
{
  "name": "fts_rebuild_all",
  "arguments": {}
}
```

**Use Cases:**
- Scheduled maintenance
- Bulk data updates
- Index recovery after failures

---

## Usage Examples

### Example 1: Basic Index Creation and Search

```bash
# Create index
curl -k -X POST "https://127.0.0.1:6071/mcp/query" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "fts_index_table",
      "arguments": {
        "schema": "sales",
        "table": "orders",
        "columns": ["order_id", "customer_name", "notes"],
        "primary_key": "order_id"
      }
    },
    "id": 1
  }'

# Search
curl -k -X POST "https://127.0.0.1:6071/mcp/query" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "fts_search",
      "arguments": {
        "query": "urgent",
        "schema": "sales",
        "table": "orders",
        "limit": 10
      }
    },
    "id": 2
  }'
```

### Example 2: AI Agent Workflow

```python
# AI Agent using FTS for efficient data discovery

# 1. Fast FTS search to find relevant orders
fts_results = mcp_tool("fts_search", {
    "query": "urgent customer complaint",
    "limit": 10
})

# 2. Extract primary keys from FTS results
order_ids = [r["primary_key_value"] for r in fts_results["results"]]

# 3. Targeted MySQL query for full data
full_orders = mcp_tool("run_sql_readonly", {
    "sql": f"SELECT * FROM sales.orders WHERE order_id IN ({','.join(order_ids)})"
})

# Result: Fast discovery without scanning millions of rows
```

### Example 3: Cross-Table Search

```bash
# Search across all indexed tables
curl -k -X POST "https://127.0.0.1:6071/mcp/query" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "fts_search",
      "arguments": {
        "query": "payment issue",
        "limit": 20
      }
    },
    "id": 3
  }'
```

### Example 4: Scheduled Index Refresh

```bash
# Daily cron job to refresh all indexes
#!/bin/bash
curl -k -X POST "https://127.0.0.1:6071/mcp/query" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "fts_rebuild_all",
      "arguments": {}
    },
    "id": 1
  }'
```

---

## API Endpoints

### Base URL
```text
https://<host>:6071/mcp/query
```

### Authentication

Authentication is optional. If `mcp_query_endpoint_auth` is empty, requests are allowed without a token. When set, use Bearer token auth:

```bash
curl -k -X POST "https://127.0.0.1:6071/mcp/query" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{...}'
```

### JSON-RPC 2.0 Format

All requests follow JSON-RPC 2.0 specification:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "<tool_name>",
    "arguments": { ... }
  },
  "id": 1
}
```

### Response Format

**Success (MCP content wrapper):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"success\": true,\n  ...\n}"
      }
    ]
  },
  "id": 1
}
```

**Error (MCP content wrapper):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Error message"
      }
    ],
    "isError": true
  },
  "id": 1
}
```

---

## Best Practices

### 1. Index Strategy

**DO:**
- Index columns frequently searched together (e.g., title + content)
- Use WHERE clauses to index subsets of data
- Index text-heavy columns (VARCHAR, TEXT)
- Keep indexes focused on searchable content

**DON'T:**
- Index all columns unnecessarily
- Index purely numeric/ID columns (use standard indexes)
- Include large BLOB/JSON columns unless needed

### 2. Query Patterns

**Effective Queries:**
```json
{"query": "urgent"}              // Single term
{"query": "\"customer complaint\""}  // Exact phrase
{"query": "urgent AND pending"}    // Boolean AND
{"query": "error OR issue"}        // Boolean OR
{"query": "cust*"}                 // Wildcard prefix
```

**Ineffective Queries:**
```json
{"query": ""}                     // Empty - will fail
{"query": "a OR b OR c OR d"}      // Too broad - slow
{"query": "NOT relevant"}          // NOT queries - limited support
```

### 3. Performance Tips

1. **Batch Indexing**: Index large tables in batches (automatic in current implementation)
2. **Regular Refreshes**: Set up scheduled reindex for frequently changing data
3. **Monitor Index Size**: FTS indexes can grow to 10-50% of source data size
4. **Use Limits**: Always use `limit` parameter to control result size
5. **Targeted Queries**: Combine FTS with targeted MySQL queries using returned IDs

### 4. Maintenance

```sql
-- Check index metadata
SELECT * FROM fts_indexes ORDER BY indexed_at DESC;

-- Monitor index count (via SQLite)
SELECT COUNT(*) FROM fts_indexes;

-- Rebuild all indexes (via MCP)
-- See Example 4 above
```

---

## Troubleshooting

### Common Issues

#### Issue: "FTS not initialized"

**Cause**: FTS database path not configured or inaccessible

**Solution**:
```sql
SET mcp-fts_path = '/var/lib/proxysql/mcp_fts.db';
LOAD MCP VARIABLES TO RUNTIME;
```

#### Issue: "Index already exists"

**Cause**: Attempting to create duplicate index

**Solution**: Use `fts_reindex` to refresh existing index

#### Issue: "No matches found"

**Cause**:
- Index doesn't exist
- Query doesn't match indexed content
- Case sensitivity (FTS5 is case-insensitive for ASCII)

**Solution**:
```bash
# List indexes
fts_list_indexes

# Try simpler query
fts_search {"query": "single_word"}

# Check if index exists
```

#### Issue: Search returns unexpected results

**Cause**: FTS5 tokenization and ranking behavior

**Solution**:
- Use quotes for exact phrases: `"exact phrase"`
- Check indexed columns (search only indexed content)
- Verify WHERE clause filter (if used during indexing)

#### Issue: Slow indexing

**Cause**: Large table, MySQL latency

**Solution**:
- Use WHERE clause to index subset
- Index during off-peak hours
- Consider incremental indexing (future feature)

### Debugging

Enable verbose logging:

```bash
# With test script
./scripts/mcp/test_mcp_fts.sh -v

# Check ProxySQL logs
tail -f /var/log/proxysql.log | grep FTS
```

---

## Detailed Test Script

For a full end-to-end validation of the FTS stack (tools/list, indexing, search/snippet, list_indexes structure, empty query handling), run:

```bash
scripts/mcp/test_mcp_fts_detailed.sh
```

Optional cleanup of created indexes:

```bash
scripts/mcp/test_mcp_fts_detailed.sh --cleanup
```

---

## Appendix

### FTS5 Query Syntax Reference

| Syntax | Example | Description |
|--------|---------|-------------|
| Term | `urgent` | Match word |
| Phrase | `"urgent order"` | Match exact phrase |
| AND | `urgent AND pending` | Both terms |
| OR | `urgent OR critical` | Either term |
| NOT | `urgent NOT pending` | Exclude term |
| Prefix | `urg*` | Words starting with prefix |
| Column | `content:urgent` | Search in specific column |

### BM25 Ranking

FTS5 uses BM25 ranking algorithm:
- Rewards term frequency in documents
- Penalizes common terms across corpus
- Results ordered by relevance (lower score = more relevant)

### Database Schema

```sql
-- Metadata table
CREATE TABLE fts_indexes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  columns TEXT NOT NULL,
  primary_key TEXT NOT NULL,
  where_clause TEXT,
  row_count INTEGER DEFAULT 0,
  indexed_at INTEGER DEFAULT (strftime('%s', 'now')),
  UNIQUE(schema_name, table_name)
);

-- Per-index tables (created dynamically)
CREATE TABLE fts_data_<schema>_<table> (
  rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  primary_key_value TEXT NOT NULL,
  content TEXT NOT NULL,
  metadata TEXT
);

CREATE VIRTUAL TABLE fts_search_<schema>_<table> USING fts5(
  content, metadata,
  content='fts_data_<schema>_<table>',
  content_rowid='rowid',
  tokenize='porter unicode61'
);
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2025-01 | Initial implementation |

---

## Support

For issues, questions, or contributions:
- GitHub: [ProxySQL/proxysql-vec](https://github.com/ProxySQL/proxysql-vec)
- Documentation: `/doc/MCP/` directory
