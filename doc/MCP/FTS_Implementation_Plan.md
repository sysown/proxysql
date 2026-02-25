# Full Text Search (FTS) Implementation Status

## Overview

This document describes the current implementation of Full Text Search (FTS) capabilities in ProxySQL MCP. The FTS system enables AI agents to quickly search indexed database metadata and LLM-generated artifacts using SQLite's FTS5 extension.

**Status: IMPLEMENTED** ✅

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
Discovery_Schema (manages FTS database)
    ↓
SQLite FTS5 (mcp_catalog.db)
```

### Database Design

**Integrated with Discovery Schema**: FTS functionality is built into the existing `mcp_catalog.db` database.

**FTS Tables**:
- `fts_objects` - FTS5 index over database objects (contentless)
- `fts_llm` - FTS5 index over LLM-generated artifacts (with content)


## Tools (Integrated with Discovery Tools)

### 1. catalog_search

Search indexed data using FTS5 across both database objects and LLM artifacts.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| query | string | Yes | FTS5 search query |
| include_objects | boolean | No | Include detailed object information (default: false) |
| object_limit | integer | No | Max objects to return when include_objects=true (default: 50) |

**Response**:
```json
{
  "success": true,
  "query": "customer order",
  "results": [
    {
      "kind": "table",
      "key": "sales.orders",
      "schema_name": "sales",
      "object_name": "orders",
      "content": "orders table with columns: order_id, customer_id, order_date, total_amount",
      "rank": 0.5
    }
  ]
}
```

**Implementation Logic**:
1. Search both `fts_objects` and `fts_llm` tables using FTS5
2. Combine results with ranking
3. Optionally fetch detailed object information
4. Return ranked results

### 2. llm.search

Search LLM-generated content and insights using FTS5.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| query | string | Yes | FTS5 search query |
| type | string | No | Content type to search ("summary", "relationship", "domain", "metric", "note") |
| schema | string | No | Filter by schema |
| limit | integer | No | Maximum results (default: 10) |

**Response**:
```json
{
  "success": true,
  "query": "customer segmentation",
  "results": [
    {
      "kind": "domain",
      "key": "customer_segmentation",
      "content": "Customer segmentation based on purchase behavior and demographics",
      "rank": 0.8
    }
  ]
}
```

**Implementation Logic**:
1. Search `fts_llm` table using FTS5
2. Apply filters if specified
3. Return ranked results with content

### 3. catalog_search (Detailed)

Search indexed data using FTS5 across both database objects and LLM artifacts with detailed object information.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| query | string | Yes | FTS5 search query |
| include_objects | boolean | No | Include detailed object information (default: false) |
| object_limit | integer | No | Max objects to return when include_objects=true (default: 50) |

**Response**:
```json
{
  "success": true,
  "query": "customer order",
  "results": [
    {
      "kind": "table",
      "key": "sales.orders",
      "schema_name": "sales",
      "object_name": "orders",
      "content": "orders table with columns: order_id, customer_id, order_date, total_amount",
      "rank": 0.5,
      "details": {
        "object_id": 123,
        "object_type": "table",
        "schema_name": "sales",
        "object_name": "orders",
        "row_count_estimate": 15000,
        "has_primary_key": true,
        "has_foreign_keys": true,
        "has_time_column": true,
        "columns": [
          {
            "column_name": "order_id",
            "data_type": "int",
            "is_nullable": false,
            "is_primary_key": true
          }
        ]
      }
    }
  ]
}
```

**Implementation Logic**:
1. Search both `fts_objects` and `fts_llm` tables using FTS5
2. Combine results with ranking
3. Optionally fetch detailed object information from `objects`, `columns`, `indexes`, `foreign_keys` tables
4. Return ranked results with detailed information when requested

## Database Schema

### fts_objects (contentless FTS5 table)
```sql
CREATE VIRTUAL TABLE fts_objects USING fts5(
    schema_name,
    object_name,
    object_type,
    content,
    content='',
    content_rowid='object_id'
);
```

### fts_llm (FTS5 table with content)
```sql
CREATE VIRTUAL TABLE fts_llm USING fts5(
    kind,
    key,
    content
);
```

## Implementation Status

### Phase 1: Foundation ✅ COMPLETED

**Step 1: Integrate FTS into Discovery_Schema**
- FTS functionality built into `lib/Discovery_Schema.cpp`
- Uses existing `mcp_catalog.db` database
- No separate configuration variable needed

**Step 2: Create FTS tables**
- `fts_objects` for database objects (contentless)
- `fts_llm` for LLM artifacts (with content)

### Phase 2: Core Indexing ✅ COMPLETED

**Step 3: Implement automatic indexing**
- Objects automatically indexed during static harvest
- LLM artifacts automatically indexed during upsert operations

### Phase 3: Search Functionality ✅ COMPLETED

**Step 4: Implement search tools**
- `catalog_search` tool in Query_Tool_Handler
- `llm.search` tool in Query_Tool_Handler

### Phase 4: Tool Registration ✅ COMPLETED

**Step 5: Register tools**
- Tools registered in Query_Tool_Handler::get_tool_list()
- Tools routed in Query_Tool_Handler::execute_tool()

## Critical Files

### Files Modified
- `include/Discovery_Schema.h` - Added FTS methods
- `lib/Discovery_Schema.cpp` - Implemented FTS functionality
- `lib/Query_Tool_Handler.cpp` - Added FTS tool routing
- `include/Query_Tool_Handler.h` - Added FTS tool declarations

## Current Implementation Details

### FTS Integration Pattern

```cpp
class Discovery_Schema {
private:
    // FTS methods
    int create_fts_tables();
    int rebuild_fts_index(int run_id);
    json search_fts(const std::string& query, bool include_objects = false, int object_limit = 50);
    json search_llm_fts(const std::string& query, const std::string& type = "", 
                       const std::string& schema = "", int limit = 10);
    
public:
    // FTS is automatically maintained during:
    // - Object insertion (static harvest)
    // - LLM artifact upsertion
    // - Catalog rebuild operations
};
```

### Error Handling Pattern

```cpp
json result;
result["success"] = false;
result["error"] = "Descriptive error message";
return result;

// Logging
proxy_error("FTS error: %s\n", error_msg);
proxy_info("FTS search completed: %zu results\n", result_count);
```

### SQLite Operations Pattern

```cpp
db->wrlock();
// Write operations (indexing)
db->wrunlock();

db->rdlock();
// Read operations (search)
db->rdunlock();

// Prepared statements
sqlite3_stmt* stmt = NULL;
db->prepare_v2(sql, &stmt);
(*proxy_sqlite3_bind_text)(stmt, 1, value.c_str(), -1, SQLITE_TRANSIENT);
SAFE_SQLITE3_STEP2(stmt);
(*proxy_sqlite3_finalize)(stmt);
```

## Agent Workflow Example

```python
# Agent searches for relevant objects
search_results = call_tool("catalog_search", {
    "query": "customer orders with high value",
    "include_objects": True,
    "object_limit": 20
})

# Agent searches for LLM insights
llm_results = call_tool("llm.search", {
    "query": "customer segmentation",
    "type": "domain"
})

# Agent uses results to build understanding
for result in search_results["results"]:
    if result["kind"] == "table":
        # Get detailed table information
        table_details = call_tool("catalog_get_object", {
            "schema": result["schema_name"],
            "object": result["object_name"]
        })
```

## Performance Considerations

1. **Contentless FTS**: `fts_objects` uses contentless indexing for performance
2. **Automatic Maintenance**: FTS indexes automatically maintained during operations
3. **Ranking**: Results ranked using FTS5 bm25 algorithm
4. **Pagination**: Large result sets automatically paginated

## Testing Status ✅ COMPLETED

- [x] Search database objects using FTS
- [x] Search LLM artifacts using FTS
- [x] Combined search with ranking
- [x] Detailed object information retrieval
- [x] Filter by content type
- [x] Filter by schema
- [x] Performance with large catalogs
- [x] Error handling

## Notes

- FTS5 requires SQLite with FTS5 extension enabled
- Contentless FTS for objects provides fast search without duplicating data
- LLM artifacts stored directly in FTS table for full content search
- Automatic FTS maintenance ensures indexes are always current
- Ranking uses FTS5's built-in bm25 algorithm for relevance scoring

## Version

- **Last Updated:** 2026-01-19
- **Implementation Date:** January 2026
- **Status:** Fully implemented and tested
