# Vector Embeddings Implementation Plan

## Overview

This document describes the implementation of Vector Embeddings capabilities for the ProxySQL MCP Query endpoint. The Embeddings system enables AI agents to perform semantic similarity searches on database content using sqlite-vec for vector storage and sqlite-rembed for embedding generation.

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
MySQL_Tool_Handler (implements tools)
    ↓
MySQL_Embeddings (new class - manages embeddings database)
    ↓
SQLite with sqlite-vec (mcp_embeddings.db)
    ↓
sqlite-rembed (embedding generation)
    ↓
External APIs (OpenAI, Ollama, Cohere, etc.)
```

## Database Design

### Separate SQLite Database
**Path**: `mcp_embeddings.db` (configurable via `mcp-embeddingpath` variable)

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
    CAST(order_id AS TEXT) as pk_value,
    json_object(
        'order_id', order_id,
        'customer_name', customer_name,
        'notes', notes
    ) as metadata
FROM testdb.orders
WHERE active = 1;
```

### 2. embed_search

Perform semantic similarity search using vector embeddings.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| query | string | Yes | Search query text |
| schema | string | No | Filter by schema |
| table | string | No | Filter by table |
| limit | integer | No | Max results (default: 10) |
| min_distance | float | No | Maximum distance threshold (default: 1.0) |

**Response**:
```json
{
  "success": true,
  "query": "customer complaining about late delivery",
  "query_embedding_dim": 1536,
  "total_matches": 25,
  "results": [
    {
      "schema": "testdb",
      "table": "orders",
      "primary_key_value": "12345",
      "distance": 0.234,
      "metadata": {
        "order_id": 12345,
        "customer_name": "John Doe",
        "notes": "Customer upset about delivery delay"
      }
    }
  ]
}
```

**Implementation Logic**:
1. Generate embedding for query text using `rembed()`
2. Build SQL with vector similarity search
3. Apply schema/table filters if specified
4. Execute KNN search with distance threshold
5. Return ranked results with metadata

**SQL Query Template**:
```sql
SELECT
    e.pk_value as primary_key_value,
    e.distance,
    e.metadata
FROM embeddings_testdb_orders e
WHERE e.vector MATCH rembed('mcp_embeddings', ?)
  AND e.distance < ?
ORDER BY e.distance ASC
LIMIT ?;
```

**Distance Metrics** (sqlite-vec supports):
- L2 (Euclidean) - default
- Cosine - for normalized vectors
- Hamming - for binary vectors

### 3. embed_list_indexes

List all embedding indexes with metadata.

**Parameters**: None

**Response**:
```json
{
  "success": true,
  "indexes": [
    {
      "schema": "testdb",
      "table": "orders",
      "columns": ["customer_name", "product_name", "notes"],
      "primary_key": "order_id",
      "model": "text-embedding-3-small",
      "vector_dim": 1536,
      "strategy": "concat",
      "row_count": 5000,
      "indexed_at": 1736668800
    }
  ]
}
```

**Implementation Logic**:
1. Query `embedding_indexes` table
2. Return all indexes with metadata

### 4. embed_delete_index

Remove an embedding index.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| schema | string | Yes | Schema name |
| table | string | Yes | Table name |

**Response**:
```json
{
  "success": true,
  "schema": "testdb",
  "table": "orders",
  "message": "Embedding index deleted successfully"
}
```

**Implementation Logic**:
1. Validate index exists
2. Drop vec0 table
3. Remove metadata from `embedding_indexes`

### 5. embed_reindex

Refresh an embedding index with fresh data (full rebuild).

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| schema | string | Yes | Schema name |
| table | string | Yes | Table name |

**Response**: Same as `embed_index_table`

**Implementation Logic**:
1. Fetch existing index metadata from `embedding_indexes`
2. Drop existing vec0 table
3. Re-create vec0 table
4. Call `embed_index_table` logic with stored metadata
5. Update `indexed_at` timestamp

### 6. embed_rebuild_all

Rebuild ALL embedding indexes with fresh data.

**Parameters**: None

**Response**:
```json
{
  "success": true,
  "rebuilt_count": 3,
  "failed": [
    {
      "schema": "testdb",
      "table": "products",
      "error": "API rate limit exceeded"
    }
  ],
  "indexes": [
    {
      "schema": "testdb",
      "table": "orders",
      "row_count": 5100,
      "status": "success"
    }
  ]
}
```

**Implementation Logic**:
1. Get all indexes from `embedding_indexes` table
2. For each index:
   - Call `reindex()` with stored metadata
   - Track success/failure
3. Return summary with rebuilt count and any failures

## Implementation Steps

### Phase 1: Foundation

**Step 1: Create MySQL_Embeddings class**
- Create `include/MySQL_Embeddings.h` - Class header with method declarations
- Create `lib/MySQL_Embeddings.cpp` - Implementation
- Follow `MySQL_FTS` and `MySQL_Catalog` patterns

**Step 2: Add configuration variable**
- Modify `include/MCP_Thread.h` - Add `mcp_embedding_path` to variables struct
- Modify `lib/MCP_Thread.cpp` - Add to `mcp_thread_variables_names` array
- Handle `embedding_path` in get/set variable functions
- Default value: `"mcp_embeddings.db"`

**Step 3: Integrate Embeddings into MySQL_Tool_Handler**
- Add `MySQL_Embeddings* embeddings` member to `include/MySQL_Tool_Handler.h`
- Initialize in constructor with `embedding_path`
- Clean up in destructor
- Add Embeddings tool method declarations

### Phase 2: Core Indexing

**Step 4: Implement embed_index_table tool**
```cpp
// In MySQL_Embeddings class
std::string index_table(
    const std::string& schema,
    const std::string& table,
    const std::string& columns,      // JSON array
    const std::string& primary_key,
    const std::string& where_clause,
    const std::string& model,
    const std::string& strategy,
    MySQL_Tool_Handler* mysql_handler
);
```

Key implementation details:
- Parse columns JSON array
- Create sanitized table name
- Create vec0 table with appropriate dimensions
- Configure sqlite-rembed client if needed
- Fetch data from MySQL
- Generate embeddings using `rembed()` function
- Insert into vec0 table
- Update metadata

**GenAI Module Placeholder**:
```cpp
// For future GenAI module integration
// Currently uses sqlite-rembed
std::vector<float> generate_embedding(
    const std::string& text,
    const std::string& model
) {
    // PLACEHOLDER: Will call GenAI module when merged
    // Currently: Use sqlite-rembed

    char* error = NULL;
    std::string sql = "SELECT rembed('mcp_embeddings', ?) as embedding";

    // Execute query, parse JSON array
    // Return std::vector<float>
}
```

**Step 5: Implement embed_list_indexes tool**
```cpp
std::string list_indexes();
```
Query `embedding_indexes` and return JSON array.

**Step 6: Implement embed_delete_index tool**
```cpp
std::string delete_index(const std::string& schema, const std::string& table);
```
Drop vec0 table and remove metadata.

### Phase 3: Search Functionality

**Step 7: Implement embed_search tool**
```cpp
std::string search(
    const std::string& query,
    const std::string& schema,
    const std::string& table,
    int limit,
    float min_distance
);
```

SQL query template:
```sql
SELECT
    e.pk_value,
    e.distance,
    e.metadata
FROM embeddings_<sanitized> e
WHERE e.vector MATCH rembed('mcp_embeddings', ?)
  AND e.distance < ?
ORDER BY e.distance ASC
LIMIT ?;
```

**Step 8: Implement embed_reindex tool**
```cpp
std::string reindex(
    const std::string& schema,
    const std::string& table,
    MySQL_Tool_Handler* mysql_handler
);
```
Fetch metadata, rebuild embeddings.

**Step 9: Implement embed_rebuild_all tool**
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
      "embed_index_table",
      "Generate embeddings and create vector index for a table",
      {"schema", "table", "columns", "primary_key", "model"},
      {{"where_clause", "string"}, {"strategy", "string"}}
  ));
  // Repeat for all 6 tools
  ```
- Add routing in `execute_tool()`:
  ```cpp
  else if (tool_name == "embed_index_table") {
      std::string schema = get_json_string(arguments, "schema");
      std::string table = get_json_string(arguments, "table");
      std::string columns = get_json_string(arguments, "columns");
      std::string primary_key = get_json_string(arguments, "primary_key");
      std::string where_clause = get_json_string(arguments, "where_clause");
      std::string model = get_json_string(arguments, "model");
      std::string strategy = get_json_string(arguments, "strategy", "concat");
      result_str = mysql_handler->embed_index_table(schema, table, columns, primary_key, where_clause, model, strategy);
  }
  // Repeat for other tools
  ```

**Step 11: Update ProxySQL_MCP_Server**
- Modify `lib/ProxySQL_MCP_Server.cpp`
- Pass `embedding_path` when creating MySQL_Tool_Handler
- Initialize Embeddings: `mysql_handler->get_embeddings()->init()`

### Phase 5: Build and Test

**Step 12: Update build system**
- Modify `Makefile`
- Add `lib/MySQL_Embeddings.cpp` to compilation sources
- Verify link against sqlite3 (already includes vec.o)

**Step 13: Testing**
- Test all 6 embed tools via MCP endpoint
- Verify JSON responses
- Test with actual MySQL data
- Test cross-table semantic search
- Test different embedding strategies
- Test with sqlite-rembed configured

## Critical Files

### New Files to Create
- `include/MySQL_Embeddings.h` - Embeddings class header
- `lib/MySQL_Embeddings.cpp` - Embeddings class implementation

### Files to Modify
- `include/MySQL_Tool_Handler.h` - Add embeddings member and tool method declarations
- `lib/MySQL_Tool_Handler.cpp` - Add embeddings tool wrappers, initialize embeddings
- `lib/Query_Tool_Handler.cpp` - Register and route embeddings tools
- `include/MCP_Thread.h` - Add `mcp_embedding_path` variable
- `lib/MCP_Thread.cpp` - Handle `embedding_path` configuration
- `lib/ProxySQL_MCP_Server.cpp` - Pass `embedding_path` to MySQL_Tool_Handler
- `Makefile` - Add MySQL_Embeddings.cpp to build

## Code Patterns to Follow

### MySQL_Embeddings Class Structure

```cpp
class MySQL_Embeddings {
private:
    SQLite3DB* db;
    std::string db_path;

    // Schema management
    int init_schema();
    int create_tables();
    int create_embedding_table(const std::string& schema,
                                const std::string& table,
                                int vector_dim);
    std::string get_table_name(const std::string& schema,
                               const std::string& table);

    // Embedding generation (placeholder for GenAI)
    std::vector<float> generate_embedding(const std::string& text,
                                          const std::string& model);

    // Content building strategies
    std::string build_content(const json& row,
                             const std::vector<std::string>& columns,
                             const std::string& strategy);

public:
    MySQL_Embeddings(const std::string& path);
    ~MySQL_Embeddings();

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

### sqlite-rembed Configuration

```cpp
// Configure rembed client during initialization
int MySQL_Embeddings::init() {
    // ... open database ...

    // Check if mcp rembed client exists
    char* error = NULL;
    std::string check_sql = "SELECT name FROM temp.rembed_clients WHERE name='mcp_embeddings'";

    // If not exists, create default client
    // (Requires API key to be configured separately by user)

    return 0;
}
```

### Vector Insert Example

```cpp
// Insert embedding with content concatenation
std::string sql =
    "INSERT INTO embeddings_testdb_orders(rowid, vector, pk_value, metadata) "
    "SELECT "
    "  ROWID, "
    "  rembed('mcp_embeddings', ?) as vector, "
    "  CAST(order_id AS TEXT) as pk_value, "
    "  json_object('order_id', order_id, 'customer_name', customer_name) as metadata "
    "FROM testdb.orders "
    "WHERE active = 1";

// Execute with prepared statement
sqlite3_stmt* stmt;
db->prepare_v2(sql.c_str(), &stmt);
(*proxy_sqlite3_bind_text)(stmt, 1, content.c_str(), -1, SQLITE_TRANSIENT);
SAFE_SQLITE3_STEP2(stmt);
(*proxy_sqlite3_finalize)(stmt);
```

### Similarity Search Example

```cpp
// Generate query embedding
std::vector<float> query_vec = generate_embedding(query_text, model_name);
std::string query_vec_json = vector_to_json(query_vec);

// Build search SQL
std::ostringstream sql;
sql << "SELECT pk_value, distance, metadata "
    << "FROM embeddings_testdb_orders "
    << "WHERE vector MATCH " << query_vec_json << " "
    << "AND distance < " << min_distance << " "
    << "ORDER BY distance ASC "
    << "LIMIT " << limit;

// Execute and return results
```

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `mcp-embeddingpath` | `mcp_embeddings.db` | Path to embeddings SQLite database |
| `mcp-rembed-client` | (none) | Default sqlite-rembed client name (user must configure) |

**sqlite-rembed Configuration** (must be done by user):
```sql
-- Configure OpenAI client
INSERT INTO temp.rembed_clients(name, format, model, key)
VALUES ('mcp_embeddings', 'openai', 'text-embedding-3-small', 'sk-...');

-- Or local Ollama
INSERT INTO temp.rembed_clients(name, format, model, key)
VALUES ('mcp_embeddings', 'ollama', 'nomic-embed-text', '');

-- Or Cohere
INSERT INTO temp.rembed_clients(name, format, model, key)
VALUES ('mcp_embeddings', 'cohere', 'embed-english-v3.0', '...');
```

## Model Support

### Common Embedding Models

| Model | Dimensions | Provider | Format |
|-------|------------|----------|--------|
| text-embedding-3-small | 1536 | OpenAI | openai |
| text-embedding-3-large | 3072 | OpenAI | openai |
| nomic-embed-text-v1.5 | 768 | Nomic | nomic |
| all-MiniLM-L6-v2 | 384 | Local (Ollama) | ollama |
| mxbai-embed-large-v1 | 1024 | MixedBread (Ollama) | ollama |

### Vector Dimension Reference

```cpp
// Map model names to dimensions
std::map<std::string, int> model_dimensions = {
    {"text-embedding-3-small", 1536},
    {"text-embedding-3-large", 3072},
    {"nomic-embed-text-v1.5", 768},
    {"all-MiniLM-L6-v2", 384},
    {"mxbai-embed-large-v1", 1024}
};
```

## Agent Workflow Examples

### Example 1: Semantic Search

```python
# Agent finds semantically similar content
embed_results = call_tool("embed_search", {
    "query": "customer unhappy with shipping delay",
    "limit": 10
})

# Extract primary keys
order_ids = [r["primary_key_value"] for r in embed_results["results"]]

# Query MySQL for full data
full_orders = call_tool("run_sql_readonly", {
    "sql": f"SELECT * FROM orders WHERE order_id IN ({','.join(order_ids)})"
})
```

### Example 2: Combined FTS + Embeddings

```python
# FTS for exact keyword match
keyword_results = call_tool("fts_search", {
    "query": "refund request",
    "limit": 50
})

# Embeddings for semantic similarity
semantic_results = call_tool("embed_search", {
    "query": "customer wants money back",
    "limit": 50
})

# Combine and deduplicate for best results
all_ids = set(
    [r["primary_key_value"] for r in keyword_results["results"]] +
    [r["primary_key_value"] for r in semantic_results["results"]]
)
```

### Example 3: RAG (Retrieval Augmented Generation)

```python
# 1. Search for relevant documents
docs = call_tool("embed_search", {
    "query": user_question,
    "table": "knowledge_base",
    "limit": 5
})

# 2. Build context from retrieved documents
context = "\n".join([d["metadata"]["content"] for d in docs["results"]])

# 3. Generate answer using context
answer = call_llm({
    "prompt": f"Context: {context}\n\nQuestion: {user_question}\n\nAnswer:"
})
```

## Comparison: FTS vs Embeddings

| Aspect | FTS (fts_*) | Embeddings (embed_*) |
|--------|-------------|---------------------|
| **Search Type** | Lexical (keyword matching) | Semantic (similarity matching) |
| **Query Example** | "urgent order" | "customer complaint about late delivery" |
| **Technology** | SQLite FTS5 | sqlite-vec |
| **Storage** | Text content | Vector embeddings (float arrays) |
| **External API** | None | sqlite-rembed / GenAI module |
| **Speed** | Very fast | Fast (but API call latency) |
| **Use Cases** | Exact phrase matching, filters | Similar content, semantic understanding |
| **Strengths** | Fast, precise, works offline | Finds related content, handles synonyms |
| **Weaknesses** | Misses semantic matches | Requires API, slower, needs setup |

## Performance Considerations

### Embedding Generation
- **API Rate Limits**: OpenAI has rate limits (e.g., 3000 RPM)
- **Batch Processing**: sqlite-rembed doesn't support batching yet
- **Latency**: Each embedding = 1 HTTP call (50-500ms)
- **Cost**: OpenAI charges per token (e.g., $0.00002/1K tokens)

### Vector Storage
- **Storage**: 1536 floats × 4 bytes = ~6KB per embedding
- **10,000 rows** = ~60MB for embeddings
- **Memory**: sqlite-vec loads vectors into memory for search

### Search Performance
- **KNN Search**: O(n × d) where n=rows, d=dimensions
- **Typical**: < 100ms for 10K rows, < 1s for 1M rows
- **Limit**: Use LIMIT or `k = ?` constraint (required by vec0)

## Best Practices

### When to Use Embeddings
- **Semantic search**: Find similar meanings, not just keywords
- **Content recommendation**: "Users who liked X also liked Y"
- **Duplicate detection**: Find similar documents
- **Categorization**: Cluster similar content
- **RAG**: Retrieve relevant context for LLM

### When to Use FTS
- **Exact matching**: Log search, code search
- **Filters**: Combined with WHERE clauses
- **Speed critical**: Sub-millisecond response needed
- **Offline**: No external API access

### Column Selection
- **Choose meaningful columns**: Text that captures semantic meaning
- **Avoid IDs/numbers**: Order ID, timestamps (low semantic value)
- **Combine textually**: `title + description + notes`
- **Preprocess**: Remove HTML, special characters

### Strategy Selection
- **concat**: Default, works for most use cases
- **average**: When columns have independent meaning
- **separate**: When need column-specific similarity

## Testing Checklist

### Basic Functionality
- [ ] Create embedding index (single table)
- [ ] Create embedding index with WHERE clause
- [ ] Create embedding index with average strategy
- [ ] Search single table
- [ ] Search across all tables
- [ ] List indexes
- [ ] Delete index
- [ ] Reindex single table
- [ ] Rebuild all indexes

### Edge Cases
- [ ] Empty result sets
- [ ] NULL values in columns
- [ ] Special characters in text
- [ ] Very long text (>10K chars)
- [ ] Non-ASCII text (Unicode)
- [ ] API rate limiting
- [ ] API errors
- [ ] Invalid model names

### Integration
- [ ] Works alongside FTS
- [ ] Works with catalog
- [ ] SQLite-vec extension loaded
- [ ] sqlite-rembed client configured
- [ ] Cross-table semantic search

## GenAI Module Integration (Future)

### Placeholder Interface

```cpp
// When GenAI module is merged, replace sqlite-rembed calls
#ifdef HAVE_GENAI_MODULE
    #include "GenAI_Module.h"
#endif

std::vector<float> MySQL_Embeddings::generate_embedding(
    const std::string& text,
    const std::string& model
) {
#ifdef HAVE_GENAI_MODULE
    // Use GenAI module
    return GenAI_Module::generate_embedding(text, model);
#else
    // Use sqlite-rembed
    std::string sql = "SELECT rembed('mcp_embeddings', ?) as embedding";
    // ... execute and parse ...
    return parse_vector_from_json(result);
#endif
}
```

### Configuration for GenAI

When GenAI module is available, add configuration variable:
```sql
SET mcp-genai-provider='local';  -- or 'openai', 'ollama', etc.
SET mcp-genai-model='nomic-embed-text-v1.5';
```

## Troubleshooting

### Common Issues

**Issue**: "Error: no such table: temp.rembed_clients"
- **Cause**: sqlite-rembed extension not loaded
- **Fix**: Ensure sqlite-rembed is compiled and auto-registered

**Issue**: "Error: rembed client not found"
- **Cause**: sqlite-rembed client not configured
- **Fix**: Run INSERT into temp.rembed_clients

**Issue**: "Error: vector dimension mismatch"
- **Cause**: Model output doesn't match vec0 table dimensions
- **Fix**: Ensure vector_dim matches model output

**Issue**: API rate limit exceeded
- **Cause**: Too many embedding requests
- **Fix**: Add delays, batch processing (when available), or use local model

## Notes

- Follow existing patterns from `MySQL_FTS` and `MySQL_Catalog` for SQLite management
- Use SQLite3DB read-write locks for thread safety
- Return JSON responses using nlohmann/json library
- Handle NULL values properly (use empty string as in execute_query)
- Use prepared statements for SQL safety
- Log errors using `proxy_error()` and info using `proxy_info()`
- Table name sanitization: replace `.` and special chars with `_`
- Always use LIMIT or `k = ?` in vec0 KNN queries (sqlite-vec requirement)
- Configure sqlite-rembed client before indexing
- Consider API costs and rate limits when planning bulk indexing
