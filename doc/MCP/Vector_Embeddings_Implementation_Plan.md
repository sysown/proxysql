# Vector Embeddings Implementation Plan (NOT YET IMPLEMENTED)

## Overview

This document describes the planned implementation of Vector Embeddings capabilities for the ProxySQL MCP Query endpoint. The Embeddings system will enable AI agents to perform semantic similarity searches on database content using sqlite-vec for vector storage and sqlite-rembed for embedding generation.

**Status: PLANNED** ⏳

## Requirements

1. **Embedding Generation**: Use sqlite-rembed (placeholder for future GenAI module)
2. **Vector Storage**: Use sqlite-vec extension (already compiled into ProxySQL)
3. **Search Type**: Semantic similarity search using vector distance
4. **Integration**: Work alongside FTS and Catalog for comprehensive search
5. **Use Case**: Find semantically similar content, not just keyword matches

## Architecture

```
MCP Query Endpoint (JSON-RPC 2.0 over HTTPS)
    ↓
Query_Tool_Handler (routes tool calls)
    ↓
Discovery_Schema (manages embeddings database)
    ↓
SQLite with sqlite-vec (mcp_catalog.db)
    ↓
LLM_Bridge (embedding generation)
    ↓
External APIs (OpenAI, Ollama, Cohere, etc.)
```

## Database Design

### Integrated with Discovery Schema
**Path**: `mcp_catalog.db` (uses existing catalog database)

### Schema

#### embedding_indexes (metadata table)
```sql
CREATE TABLE IF NOT EXISTS embedding_indexes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  columns TEXT NOT NULL,              -- JSON array: ["col1", "col2"]
  primary_key TEXT NOT NULL,          -- PK column name for identification
  where_clause TEXT,                  -- Optional WHERE filter
  model_name TEXT NOT NULL,           -- e.g., "text-embedding-3-small"
  vector_dim INTEGER NOT NULL,        -- e.g., 1536 for OpenAI small
  embedding_strategy TEXT NOT NULL,   -- "concat", "average", "separate"
  row_count INTEGER DEFAULT 0,
  indexed_at INTEGER DEFAULT (strftime('%s', 'now')),
  UNIQUE(schema_name, table_name)
);

CREATE INDEX IF NOT EXISTS idx_embedding_indexes_schema ON embedding_indexes(schema_name);
CREATE INDEX IF NOT EXISTS idx_embedding_indexes_table ON embedding_indexes(table_name);
CREATE INDEX IF NOT EXISTS idx_embedding_indexes_model ON embedding_indexes(model_name);
```

#### Per-Index vec0 Tables (created dynamically)

For each indexed table, create a sqlite-vec virtual table:

```sql
-- For OpenAI text-embedding-3-small (1536 dimensions)
CREATE VIRTUAL TABLE embeddings_<sanitized_schema>_<sanitized_table> USING vec0(
  vector float[1536],
  pk_value TEXT,
  metadata TEXT
);
```

**Table Components**:
- `vector` - The embedding vector (required by vec0)
- `pk_value` - Primary key value for MySQL lookup
- `metadata` - JSON with original row data

**Sanitization**:
- Replace `.` and special characters with `_`
- Example: `testdb.orders` → `embeddings_testdb_orders`

## Tools (6 total)

### 1. embed_index_table

Generate embeddings and create a vector index for a MySQL table.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| schema | string | Yes | Schema name |
| table | string | Yes | Table name |
| columns | string | Yes | JSON array of column names to embed |
| primary_key | string | Yes | Primary key column name |
| where_clause | string | No | Optional WHERE clause for filtering rows |
| model | string | Yes | Embedding model name (e.g., "text-embedding-3-small") |
| strategy | string | No | Embedding strategy: "concat" (default), "average", "separate" |

**Embedding Strategies**:

| Strategy | Description | When to Use |
|----------|-------------|-------------|
| `concat` | Concatenate all columns with spaces, generate one embedding | Most common, semantic meaning of combined content |
| `average` | Generate embedding per column, average them | Multiple independent columns |
| `separate` | Store embeddings separately per column | Need column-specific similarity |

**Response**:
```json
{
  "success": true,
  "schema": "testdb",
  "table": "orders",
  "model": "text-embedding-3-small",
  "vector_dim": 1536,
  "row_count": 5000,
  "indexed_at": 1736668800
}
```

**Implementation Logic**:
1. Validate parameters (table exists, columns valid)
2. Check if index already exists
3. Create vec0 table: `embeddings_<sanitized_schema>_<sanitized_table>`
4. Get vector dimension from model (or default to 1536)
5. Configure sqlite-rembed client (if not already configured)
6. Fetch all rows from MySQL using `execute_query()`
7. For each row:
   - Build content string based on strategy
   - Call `rembed()` to generate embedding
   - Store vector + metadata in vec0 table
8. Update `embedding_indexes` metadata
9. Return result

**Code Example (concat strategy)**:
```sql
-- Configure rembed client
INSERT INTO temp.rembed_clients(name, format, model, key)
VALUES ('mcp_embeddings', 'openai', 'text-embedding-3-small', 'sk-...');

-- Generate and insert embeddings
INSERT INTO embeddings_testdb_orders(rowid, vector, pk_value, metadata)
SELECT
    ROWID,
    rembed('mcp_embeddings',
           COALESCE(customer_name, '') || ' ' ||
           COALESCE(product_name, '') || ' ' ||
           COALESCE(notes, '')) as vector,

## Implementation Status

### Phase 1: Foundation ⏳ PLANNED

**Step 1: Integrate Embeddings into Discovery_Schema**
- Embeddings functionality to be built into `lib/Discovery_Schema.cpp`
- Will use existing `mcp_catalog.db` database
- Will require new configuration variable `mcp-embeddingpath`

**Step 2: Create Embeddings tables**
- `embedding_indexes` for metadata
- `embedding_data_<schema>_<table>` for vector storage
- Integration with sqlite-vec extension

### Phase 2: Core Indexing ⏳ PLANNED

**Step 3: Implement embedding generation**
- Integration with LLM_Bridge for embedding generation
- Support for multiple embedding models
- Batch processing for performance

### Phase 3: Search Functionality ⏳ PLANNED

**Step 4: Implement search tools**
- `embedding_search` tool in Query_Tool_Handler
- Semantic similarity search with ranking

### Phase 4: Tool Registration ⏳ PLANNED

**Step 5: Register tools**
- Tools to be registered in Query_Tool_Handler::get_tool_list()
- Tools to be routed in Query_Tool_Handler::execute_tool()

## Critical Files (PLANNED)

### Files to Create
- `include/MySQL_Embeddings.h` - Embeddings class header
- `lib/MySQL_Embeddings.cpp` - Embeddings class implementation

### Files to Modify
- `include/Discovery_Schema.h` - Add Embeddings methods
- `lib/Discovery_Schema.cpp` - Implement Embeddings functionality
- `lib/Query_Tool_Handler.cpp` - Add Embeddings tool routing
- `include/Query_Tool_Handler.h` - Add Embeddings tool declarations
- `include/MCP_Thread.h` - Add `mcp_embedding_path` variable
- `lib/MCP_Thread.cpp` - Handle `embedding_path` configuration
- `lib/ProxySQL_MCP_Server.cpp` - Pass `embedding_path` to components
- `Makefile` - Add MySQL_Embeddings.cpp to build

## Future Implementation Details

### Embeddings Integration Pattern

```cpp
class Discovery_Schema {
private:
    // Embeddings methods (PLANNED)
    int create_embedding_tables();
    int generate_embeddings(int run_id);
    json search_embeddings(const std::string& query, const std::string& schema = "", 
                          const std::string& table = "", int limit = 10);
    
public:
    // Embeddings to be maintained during:
    // - Object processing (static harvest)
    // - LLM artifact creation
    // - Catalog rebuild operations
};
```

## Agent Workflow Example (PLANNED)

```python
# Agent performs semantic search
semantic_results = call_tool("embedding_search", {
    "query": "find tables related to customer purchases",
    "limit": 10
})

# Agent combines with FTS results
fts_results = call_tool("catalog_search", {
    "query": "customer order"
})

# Agent uses combined results for comprehensive understanding
```

## Future Performance Considerations

1. **Batch Processing**: Generate embeddings in batches for performance
2. **Model Selection**: Support multiple embedding models with different dimensions
3. **Caching**: Cache frequently used embeddings
4. **Indexing**: Use ANN (Approximate Nearest Neighbor) for large vector sets

## Implementation Prerequisites

- [ ] sqlite-vec extension compiled into ProxySQL
- [ ] sqlite-rembed integration with LLM_Bridge
- [ ] Configuration variable support
- [ ] Tool handler integration

## Notes

- Vector embeddings will complement FTS for comprehensive search
- Integration with existing catalog for unified search experience
- Support for multiple embedding models and providers
- Automatic embedding generation during discovery processes

## Version

- **Last Updated:** 2026-01-19
- **Status:** Planned feature, not yet implemented
