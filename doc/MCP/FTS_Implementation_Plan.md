# Full Text Search (FTS) Implementation Plan

## Overview

This document describes the implementation of Full Text Search (FTS) capabilities for the ProxySQL MCP Query endpoint. The FTS system enables AI agents to quickly search indexed data before querying the full MySQL database, using SQLite's FTS5 extension.

## Requirements

1. **Indexing Strategy**: Optional WHERE clauses, no incremental updates (full rebuild on reindex)
2. **Search Scope**: Agent decides - single table or cross-table search
3. **Storage**: All rows (no limits)
4. **Catalog Integration**: Cross-reference between FTS and catalog - agent can use FTS to get top N IDs, then query real database
5. **Use Case**: FTS as another tool in the agent's toolkit

## Architecture

### Components

```
MCP Query Endpoint
    ↓
Query_Tool_Handler (routes tool calls)
    ↓
MySQL_Tool_Handler (implements tools)
    ↓
MySQL_FTS (new class - manages FTS database)
    ↓
SQLite FTS5 (mcp_fts.db)
```

### Database Design

**Separate SQLite database**: `mcp_fts.db` (configurable via `mcp-ftspath` variable)

**Tables**:
- `fts_indexes` - Metadata for all indexes
- `fts_data_<sanitized_name>` - Content tables (one per index)
- `fts_search_<sanitized_name>` - FTS5 virtual tables (one per index)

## Tools (6 total)

### 1. fts_index_table

Create and populate an FTS index for a MySQL table.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| schema | string | Yes | Schema name |
| table | string | Yes | Table name |
| columns | string | Yes | JSON array of column names to index |
| primary_key | string | Yes | Primary key column name |
| where_clause | string | No | Optional WHERE clause for filtering |

**Response**:
```json
{
  "success": true,
  "schema": "sales",
  "table": "orders",
  "row_count": 15000,
  "indexed_at": 1736668800
}
```

**Implementation Logic**:
1. Validate parameters (table exists, columns are valid)
2. Check if index already exists
3. Create dynamic tables: `fts_data_<schema>_<table>` and `fts_search_<schema>_<table>`
4. Fetch all rows from MySQL using `execute_query()`
5. For each row:
   - Concatenate indexed column values into searchable content
   - Store original row data as JSON metadata
   - Insert into data table (triggers sync to FTS)
6. Update `fts_indexes` metadata
7. Return result

### 2. fts_search

Search indexed data using FTS5.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| query | string | Yes | FTS5 search query |
| schema | string | No | Filter by schema |
| table | string | No | Filter by table |
| limit | integer | No | Max results (default: 100) |
| offset | integer | No | Pagination offset (default: 0) |

**Response**:
```json
{
  "success": true,
  "query": "urgent order",
  "total_matches": 234,
  "results": [
    {
      "schema": "sales",
      "table": "orders",
      "primary_key_value": "12345",
      "snippet": "Customer has <mark>urgent</mark> <mark>order</mark>...",
      "metadata": "{\"order_id\":12345,\"customer_id\":987,...}"
    }
  ]
}
```

**Implementation Logic**:
1. Build FTS5 query with MATCH syntax
2. Apply schema/table filters if specified
3. Execute search with ranking (bm25)
4. Return results with snippets highlighting matches
5. Support pagination

### 3. fts_list_indexes

List all FTS indexes with metadata.

**Parameters**: None

**Response**:
```json
{
  "success": true,
  "indexes": [
    {
      "schema": "sales",
      "table": "orders",
      "columns": ["order_id", "customer_name", "notes"],
      "primary_key": "order_id",
      "row_count": 15000,
      "indexed_at": 1736668800
    }
  ]
}
```

**Implementation Logic**:
1. Query `fts_indexes` table
2. Return all indexes with metadata

### 4. fts_delete_index

Remove an FTS index.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| schema | string | Yes | Schema name |
| table | string | Yes | Table name |

**Response**:
```json
{
  "success": true,
  "schema": "sales",
  "table": "orders",
  "message": "Index deleted successfully"
}
```

**Implementation Logic**:
1. Validate index exists
2. Drop FTS search table
3. Drop data table
4. Remove metadata from `fts_indexes`

### 5. fts_reindex

Refresh an index with fresh data (full rebuild).

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| schema | string | Yes | Schema name |
| table | string | Yes | Table name |

**Response**: Same as `fts_index_table`

**Implementation Logic**:
1. Fetch existing index metadata from `fts_indexes`
2. Delete existing data from tables
3. Call `index_table()` logic with stored metadata
4. Update `indexed_at` timestamp

### 6. fts_rebuild_all

Rebuild ALL FTS indexes with fresh data.

**Parameters**: None

**Response**:
```json
{
  "success": true,
  "rebuilt_count": 5,
  "failed": [],
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

**Implementation Logic**:
1. Get all indexes from `fts_indexes` table
2. For each index:
   - Call `reindex()` with stored metadata
   - Track success/failure
3. Return summary with rebuilt count and any failures

## Database Schema

### fts_indexes (metadata table)
```sql
CREATE TABLE IF NOT EXISTS fts_indexes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  columns TEXT NOT NULL,        -- JSON array of column names
  primary_key TEXT NOT NULL,
  where_clause TEXT,
  row_count INTEGER DEFAULT 0,
  indexed_at INTEGER DEFAULT (strftime('%s', 'now')),
  UNIQUE(schema_name, table_name)
);

CREATE INDEX IF NOT EXISTS idx_fts_indexes_schema ON fts_indexes(schema_name);
CREATE INDEX IF NOT EXISTS idx_fts_indexes_table ON fts_indexes(table_name);
```

### Per-Index Tables (created dynamically)

For each indexed table, create:
```sql
-- Data table (stores actual content)
CREATE TABLE fts_data_<sanitized_schema>_<sanitized_table> (
  rowid INTEGER PRIMARY KEY,
  content TEXT NOT NULL,       -- Concatenated searchable text
  metadata TEXT                -- JSON with original row data
);

-- FTS5 virtual table (external content)
CREATE VIRTUAL TABLE fts_search_<sanitized_schema>_<sanitized_table> USING fts5(
  content,
  metadata,
  content='fts_data_<sanitized_schema>_<sanitized_table>',
  content_rowid='rowid',
  tokenize='porter unicode61'
);

-- Triggers for automatic sync
CREATE TRIGGER fts_ai_<sanitized> AFTER INSERT ON fts_data_<sanitized> BEGIN
  INSERT INTO fts_search_<sanitized>(rowid, content, metadata)
  VALUES (new.rowid, new.content, new.metadata);
END;

CREATE TRIGGER fts_ad_<sanitized> AFTER DELETE ON fts_data_<sanitized> BEGIN
  INSERT INTO fts_search_<sanitized>(fts_search_<sanitized>, rowid, content, metadata)
  VALUES ('delete', old.rowid, old.content, old.metadata);
END;

CREATE TRIGGER fts_au_<sanitized> AFTER UPDATE ON fts_data_<sanitized> BEGIN
  INSERT INTO fts_search_<sanitized>(fts_search_<sanitized>, rowid, content, metadata)
  VALUES ('delete', old.rowid, old.content, old.metadata);
  INSERT INTO fts_search_<sanitized>(rowid, content, metadata)
  VALUES (new.rowid, new.content, new.metadata);
END;
```

## Implementation Steps

### Phase 1: Foundation

**Step 1: Create MySQL_FTS class**
- Create `include/MySQL_FTS.h` - Class header with method declarations
- Create `lib/MySQL_FTS.cpp` - Implementation
- Follow `MySQL_Catalog` pattern for SQLite management

**Step 2: Add configuration variable**
- Modify `include/MCP_Thread.h` - Add `mcp_fts_path` to variables struct
- Modify `lib/MCP_Thread.cpp` - Add to `mcp_thread_variables_names` array
- Handle `fts_path` in get/set variable functions
- Default value: `"mcp_fts.db"`

**Step 3: Integrate FTS into MySQL_Tool_Handler**
- Add `MySQL_FTS* fts` member to `include/MySQL_Tool_Handler.h`
- Initialize in constructor with `fts_path`
- Clean up in destructor
- Add FTS tool method declarations

### Phase 2: Core Indexing

**Step 4: Implement fts_index_table tool**
```cpp
// In MySQL_FTS class
std::string index_table(
    const std::string& schema,
    const std::string& table,
    const std::string& columns,  // JSON array
    const std::string& primary_key,
    const std::string& where_clause,
    MySQL_Tool_Handler* mysql_handler
);
```

Logic:
- Parse columns JSON array
- Create sanitized table name (replace dots/underscores)
- Create `fts_data_*` and `fts_search_*` tables
- Fetch data: `mysql_handler->execute_query(sql)`
- Build content by concatenating column values
- Insert in batches for performance
- Update metadata

**Step 5: Implement fts_list_indexes tool**
```cpp
std::string list_indexes();
```
Query `fts_indexes` and return JSON array.

**Step 6: Implement fts_delete_index tool**
```cpp
std::string delete_index(const std::string& schema, const std::string& table);
```
Drop tables and remove metadata.

### Phase 3: Search Functionality

**Step 7: Implement fts_search tool**
```cpp
std::string search(
    const std::string& query,
    const std::string& schema,
    const std::string& table,
    int limit,
    int offset
);
```

SQL query template:
```sql
SELECT
  d.schema_name,
  d.table_name,
  d.primary_key_value,
  snippet(fts_search, 2, '<mark>', '</mark>', '...', 30) as snippet,
  d.metadata
FROM fts_search s
JOIN fts_data d ON s.rowid = d.rowid
WHERE fts_search MATCH ?
ORDER BY bm25(fts_search)
LIMIT ? OFFSET ?
```

**Step 8: Implement fts_reindex tool**
```cpp
std::string reindex(
    const std::string& schema,
    const std::string& table,
    MySQL_Tool_Handler* mysql_handler
);
```
Fetch metadata, delete old data, rebuild.

**Step 9: Implement fts_rebuild_all tool**
```cpp
std::string rebuild_all(MySQL_Tool_Handler* mysql_handler);
```
Loop through all indexes and rebuild each.

### Phase 4: Tool Registration

**Step 10: Register tools in Query_Tool_Handler**
- Modify `lib/Query_Tool_Handler.cpp`
- Add to `get_tool_list()`:
  ```cpp
  tools.push_back(create_tool_schema(
      "fts_index_table",
      "Create/populate FTS index for a table",
      {"schema", "table", "columns", "primary_key"},
      {{"where_clause", "string"}}
  ));
  // Repeat for all 6 tools
  ```
- Add routing in `execute_tool()`:
  ```cpp
  else if (tool_name == "fts_index_table") {
      std::string schema = get_json_string(arguments, "schema");
      std::string table = get_json_string(arguments, "table");
      std::string columns = get_json_string(arguments, "columns");
      std::string primary_key = get_json_string(arguments, "primary_key");
      std::string where_clause = get_json_string(arguments, "where_clause");
      result_str = mysql_handler->fts_index_table(schema, table, columns, primary_key, where_clause);
  }
  // Repeat for other tools
  ```

**Step 11: Update ProxySQL_MCP_Server**
- Modify `lib/ProxySQL_MCP_Server.cpp`
- Pass `fts_path` when creating MySQL_Tool_Handler
- Initialize FTS: `mysql_handler->get_fts()->init()`

### Phase 5: Build and Test

**Step 12: Update build system**
- Modify `Makefile`
- Add `lib/MySQL_FTS.cpp` to compilation sources
- Verify link against sqlite3

**Step 13: Testing**
- Test all 6 tools via MCP endpoint
- Verify JSON responses
- Test with actual MySQL data
- Test cross-table search
- Test WHERE clause filtering

## Critical Files

### New Files to Create
- `include/MySQL_FTS.h` - FTS class header
- `lib/MySQL_FTS.cpp` - FTS class implementation

### Files to Modify
- `include/MySQL_Tool_Handler.h` - Add FTS member and tool method declarations
- `lib/MySQL_Tool_Handler.cpp` - Add FTS tool wrappers, initialize FTS
- `lib/Query_Tool_Handler.cpp` - Register and route FTS tools
- `include/MCP_Thread.h` - Add `mcp_fts_path` variable
- `lib/MCP_Thread.cpp` - Handle `fts_path` configuration
- `lib/ProxySQL_MCP_Server.cpp` - Pass `fts_path` to MySQL_Tool_Handler
- `Makefile` - Add MySQL_FTS.cpp to build

## Code Patterns to Follow

### MySQL_FTS Class Structure (similar to MySQL_Catalog)

```cpp
class MySQL_FTS {
private:
    SQLite3DB* db;
    std::string db_path;

    int init_schema();
    int create_tables();
    int create_index_tables(const std::string& schema, const std::string& table);
    std::string get_data_table_name(const std::string& schema, const std::string& table);
    std::string get_fts_table_name(const std::string& schema, const std::string& table);

public:
    MySQL_FTS(const std::string& path);
    ~MySQL_FTS();

    int init();
    void close();

    // Tool methods
    std::string index_table(...);
    std::string search(...);
    std::string list_indexes();
    std::string delete_index(...);
    std::string reindex(...);
    std::string rebuild_all(...);

    bool index_exists(const std::string& schema, const std::string& table);
    SQLite3DB* get_db() { return db; }
};
```

### Error Handling Pattern

```cpp
json result;
result["success"] = false;
result["error"] = "Descriptive error message";
return result.dump();

// Logging
proxy_error("FTS error: %s\n", error_msg);
proxy_info("FTS index created: %s.%s\n", schema.c_str(), table.c_str());
```

### SQLite Operations Pattern

```cpp
db->wrlock();
// Write operations
db->wrunlock();

db->rdlock();
// Read operations
db->rdunlock();

// Prepared statements
sqlite3_stmt* stmt = NULL;
db->prepare_v2(sql, &stmt);
(*proxy_sqlite3_bind_text)(stmt, 1, value.c_str(), -1, SQLITE_TRANSIENT);
SAFE_SQLITE3_STEP2(stmt);
(*proxy_sqlite3_finalize)(stmt);
```

### JSON Response Pattern

```cpp
// Use nlohmann/json
json result;
result["success"] = true;
result["data"] = data_array;
return result.dump();
```

## Configuration Variable

| Variable | Default | Description |
|----------|---------|-------------|
| `mcp-ftspath` | `mcp_fts.db` | Path to FTS SQLite database (relative or absolute) |

**Usage**:
```sql
SET mcp-ftspath='/var/lib/proxysql/mcp_fts.db';
```

## Agent Workflow Example

```python
# Agent narrows down results using FTS
fts_results = call_tool("fts_search", {
    "query": "urgent customer complaint",
    "limit": 10
})

# Extract primary keys from FTS results
order_ids = [r["primary_key_value"] for r in fts_results["results"]]

# Query MySQL for full data
full_data = call_tool("run_sql_readonly", {
    "sql": f"SELECT * FROM orders WHERE order_id IN ({','.join(order_ids)})"
})
```

## Threading Considerations

- SQLite3DB provides thread-safe read-write locks
- Use `wrlock()` for writes (index operations)
- Use `rdlock()` for reads (search operations)
- Follow the catalog pattern for locking

## Performance Considerations

1. **Batch inserts**: When indexing, insert rows in batches (100-1000 at a time)
2. **Table naming**: Sanitize schema/table names for SQLite table names
3. **Memory usage**: Large tables may require streaming results
4. **Index size**: Monitor FTS database size

## Testing Checklist

- [ ] Create index on single table
- [ ] Create index with WHERE clause
- [ ] Search single table
- [ ] Search across all tables
- [ ] List indexes
- [ ] Delete index
- [ ] Reindex single table
- [ ] Rebuild all indexes
- [ ] Test with NULL values
- [ ] Test with special characters in data
- [ ] Test pagination
- [ ] Test schema/table filtering

## Notes

- Follow existing patterns from `MySQL_Catalog` for SQLite management
- Use SQLite3DB read-write locks for thread safety
- Return JSON responses using nlohmann/json library
- Handle NULL values properly (use empty string as in execute_query)
- Use prepared statements for SQL safety
- Log errors using `proxy_error()` and info using `proxy_info()`
- Table name sanitization: replace `.` and special chars with `_`
