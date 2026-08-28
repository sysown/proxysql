# RAG Subsystem Doxygen Documentation

## Overview

The RAG (Retrieval-Augmented Generation) subsystem provides a comprehensive set of tools for semantic search and document retrieval through the MCP (Model Context Protocol). This documentation details the Doxygen-style comments added to the RAG implementation.

## Main Classes

### RAG_Tool_Handler

The primary class that implements all RAG functionality through the MCP protocol.

#### Class Definition
```cpp
class RAG_Tool_Handler : public MCP_Tool_Handler
```

#### Constructor
```cpp
/**
 * @brief Constructor
 * @param ai_mgr Pointer to AI_Features_Manager for database access and configuration
 *
 * Initializes the RAG tool handler with configuration parameters from GenAI_Thread
 * if available, otherwise uses default values.
 *
 * Configuration parameters:
 * - k_max: Maximum number of search results (default: 50)
 * - candidates_max: Maximum number of candidates for hybrid search (default: 500)
 * - query_max_bytes: Maximum query length in bytes (default: 8192)
 * - response_max_bytes: Maximum response size in bytes (default: 5000000)
 * - timeout_ms: Operation timeout in milliseconds (default: 2000)
 */
RAG_Tool_Handler(AI_Features_Manager* ai_mgr);
```

#### Public Methods

##### get_tool_list()
```cpp
/**
 * @brief Get list of available RAG tools
 * @return JSON object containing tool definitions and schemas
 *
 * Returns a comprehensive list of all available RAG tools with their
 * input schemas and descriptions. Tools include:
 * - rag.search_fts: Keyword search using FTS5
 * - rag.search_vector: Semantic search using vector embeddings
 * - rag.search_hybrid: Hybrid search combining FTS and vectors
 * - rag.get_chunks: Fetch chunk content by chunk_id
 * - rag.get_docs: Fetch document content by doc_id
 * - rag.fetch_from_source: Refetch authoritative data from source
 * - rag.admin.stats: Operational statistics
 */
json get_tool_list() override;
```

##### execute_tool()
```cpp
/**
 * @brief Execute a RAG tool with arguments
 * @param tool_name Name of the tool to execute
 * @param arguments JSON object containing tool arguments
 * @return JSON response with results or error information
 *
 * Executes the specified RAG tool with the provided arguments. Handles
 * input validation, parameter processing, database queries, and result
 * formatting according to MCP specifications.
 *
 * Supported tools:
 * - rag.search_fts: Full-text search over documents
 * - rag.search_vector: Vector similarity search
 * - rag.search_hybrid: Hybrid search with two modes (fuse, fts_then_vec)
 * - rag.get_chunks: Retrieve chunk content by ID
 * - rag.get_docs: Retrieve document content by ID
 * - rag.fetch_from_source: Refetch data from authoritative source
 * - rag.admin.stats: Get operational statistics
 */
json execute_tool(const std::string& tool_name, const json& arguments) override;
```

#### Private Helper Methods

##### Database and Query Helpers

```cpp
/**
 * @brief Execute database query and return results
 * @param query SQL query string to execute
 * @return SQLite3_result pointer or NULL on error
 *
 * Executes a SQL query against the vector database and returns the results.
 * Handles error checking and logging. The caller is responsible for freeing
 * the returned SQLite3_result.
 */
SQLite3_result* execute_query(const char* query);

/**
 * @brief Validate and limit k parameter
 * @param k Requested number of results
 * @return Validated k value within configured limits
 *
 * Ensures the k parameter is within acceptable bounds (1 to k_max).
 * Returns default value of 10 if k is invalid.
 */
int validate_k(int k);

/**
 * @brief Validate and limit candidates parameter
 * @param candidates Requested number of candidates
 * @return Validated candidates value within configured limits
 *
 * Ensures the candidates parameter is within acceptable bounds (1 to candidates_max).
 * Returns default value of 50 if candidates is invalid.
 */
int validate_candidates(int candidates);

/**
 * @brief Validate query length
 * @param query Query string to validate
 * @return true if query is within length limits, false otherwise
 *
 * Checks if the query string length is within the configured query_max_bytes limit.
 */
bool validate_query_length(const std::string& query);
```

##### JSON Parameter Extraction

```cpp
/**
 * @brief Extract string parameter from JSON
 * @param j JSON object to extract from
 * @param key Parameter key to extract
 * @param default_val Default value if key not found
 * @return Extracted string value or default
 *
 * Safely extracts a string parameter from a JSON object, handling type
 * conversion if necessary. Returns the default value if the key is not
 * found or cannot be converted to a string.
 */
static std::string get_json_string(const json& j, const std::string& key,
                                   const std::string& default_val = "");

/**
 * @brief Extract int parameter from JSON
 * @param j JSON object to extract from
 * @param key Parameter key to extract
 * @param default_val Default value if key not found
 * @return Extracted int value or default
 *
 * Safely extracts an integer parameter from a JSON object, handling type
 * conversion from string if necessary. Returns the default value if the
 * key is not found or cannot be converted to an integer.
 */
static int get_json_int(const json& j, const std::string& key, int default_val = 0);

/**
 * @brief Extract bool parameter from JSON
 * @param j JSON object to extract from
 * @param key Parameter key to extract
 * @param default_val Default value if key not found
 * @return Extracted bool value or default
 *
 * Safely extracts a boolean parameter from a JSON object, handling type
 * conversion from string or integer if necessary. Returns the default
 * value if the key is not found or cannot be converted to a boolean.
 */
static bool get_json_bool(const json& j, const std::string& key, bool default_val = false);

/**
 * @brief Extract string array from JSON
 * @param j JSON object to extract from
 * @param key Parameter key to extract
 * @return Vector of extracted strings
 *
 * Safely extracts a string array parameter from a JSON object, filtering
 * out non-string elements. Returns an empty vector if the key is not
 * found or is not an array.
 */
static std::vector<std::string> get_json_string_array(const json& j, const std::string& key);

/**
 * @brief Extract int array from JSON
 * @param j JSON object to extract from
 * @param key Parameter key to extract
 * @return Vector of extracted integers
 *
 * Safely extracts an integer array parameter from a JSON object, handling
 * type conversion from string if necessary. Returns an empty vector if
 * the key is not found or is not an array.
 */
static std::vector<int> get_json_int_array(const json& j, const std::string& key);
```

##### Scoring and Normalization

```cpp
/**
 * @brief Compute Reciprocal Rank Fusion score
 * @param rank Rank position (1-based)
 * @param k0 Smoothing parameter
 * @param weight Weight factor for this ranking
 * @return RRF score
 *
 * Computes the Reciprocal Rank Fusion score for hybrid search ranking.
 * Formula: weight / (k0 + rank)
 */
double compute_rrf_score(int rank, int k0, double weight);

/**
 * @brief Normalize scores to 0-1 range (higher is better)
 * @param score Raw score to normalize
 * @param score_type Type of score being normalized
 * @return Normalized score in 0-1 range
 *
 * Normalizes various types of scores to a consistent 0-1 range where
 * higher values indicate better matches. Different score types may
 * require different normalization approaches.
 */
double normalize_score(double score, const std::string& score_type);
```

## Tool Specifications

### rag.search_fts
Keyword search over documents using FTS5.

#### Parameters
- `query` (string, required): Search query string
- `k` (integer): Number of results to return (default: 10, max: 50)
- `offset` (integer): Offset for pagination (default: 0)
- `filters` (object): Filter criteria for results
- `return` (object): Return options for result fields

#### Filters
- `source_ids` (array of integers): Filter by source IDs
- `source_names` (array of strings): Filter by source names
- `doc_ids` (array of strings): Filter by document IDs
- `min_score` (number): Minimum score threshold
- `post_type_ids` (array of integers): Filter by post type IDs
- `tags_any` (array of strings): Filter by any of these tags
- `tags_all` (array of strings): Filter by all of these tags
- `created_after` (string): Filter by creation date (after)
- `created_before` (string): Filter by creation date (before)

#### Return Options
- `include_title` (boolean): Include title in results (default: true)
- `include_metadata` (boolean): Include metadata in results (default: true)
- `include_snippets` (boolean): Include snippets in results (default: false)

### rag.search_vector
Semantic search over documents using vector embeddings.

#### Parameters
- `query_text` (string, required): Text to search semantically
- `k` (integer): Number of results to return (default: 10, max: 50)
- `filters` (object): Filter criteria for results
- `embedding` (object): Embedding model specification
- `query_embedding` (object): Precomputed query embedding
- `return` (object): Return options for result fields

### rag.search_hybrid
Hybrid search combining FTS and vector search.

#### Parameters
- `query` (string, required): Search query for both FTS and vector
- `k` (integer): Number of results to return (default: 10, max: 50)
- `mode` (string): Search mode: 'fuse' or 'fts_then_vec'
- `filters` (object): Filter criteria for results
- `fuse` (object): Parameters for fuse mode
- `fts_then_vec` (object): Parameters for fts_then_vec mode

#### Fuse Mode Parameters
- `fts_k` (integer): Number of FTS results for fusion (default: 50)
- `vec_k` (integer): Number of vector results for fusion (default: 50)
- `rrf_k0` (integer): RRF smoothing parameter (default: 60)
- `w_fts` (number): Weight for FTS scores (default: 1.0)
- `w_vec` (number): Weight for vector scores (default: 1.0)

#### FTS Then Vector Mode Parameters
- `candidates_k` (integer): FTS candidates to generate (default: 200)
- `rerank_k` (integer): Candidates to rerank with vector search (default: 50)
- `vec_metric` (string): Vector similarity metric (default: 'cosine')

### rag.get_chunks
Fetch chunk content by chunk_id.

#### Parameters
- `chunk_ids` (array of strings, required): List of chunk IDs to fetch
- `return` (object): Return options for result fields

### rag.get_docs
Fetch document content by doc_id.

#### Parameters
- `doc_ids` (array of strings, required): List of document IDs to fetch
- `return` (object): Return options for result fields

### rag.fetch_from_source
Refetch authoritative data from source database.

#### Parameters
- `doc_ids` (array of strings, required): List of document IDs to refetch
- `columns` (array of strings): List of columns to fetch
- `limits` (object): Limits for the fetch operation

### rag.admin.stats
Get operational statistics for RAG system.

#### Parameters
None

## Database Schema

The RAG subsystem uses the following tables in the vector database:

1. `rag_sources`: Ingestion configuration and source metadata
2. `rag_documents`: Canonical documents with stable IDs
3. `rag_chunks`: Chunked content for retrieval
4. `rag_fts_chunks`: FTS5 contentless index for keyword search
5. `rag_vec_chunks`: sqlite3-vec virtual table for vector similarity search
6. `rag_sync_state`: Sync state tracking for incremental ingestion
7. `rag_chunk_view`: Convenience view for debugging

## Security Features

1. **Input Validation**: Strict validation of all parameters and filters
2. **Query Limits**: Maximum limits on query length, result count, and candidates
3. **Timeouts**: Configurable operation timeouts to prevent resource exhaustion
4. **Column Whitelisting**: Strict column filtering for refetch operations
5. **Row and Byte Limits**: Maximum limits on returned data size
6. **Parameter Binding**: Safe parameter binding to prevent SQL injection

## Performance Features

1. **Prepared Statements**: Efficient query execution with prepared statements
2. **Connection Management**: Proper database connection handling
3. **SQLite3-vec Integration**: Optimized vector operations
4. **FTS5 Integration**: Efficient full-text search capabilities
5. **Indexing Strategies**: Proper database indexing for performance
6. **Result Caching**: Efficient result processing and formatting

## Configuration Variables

1. `genai_rag_enabled`: Enable RAG features
2. `genai_rag_k_max`: Maximum k for search results (default: 50)
3. `genai_rag_candidates_max`: Maximum candidates for hybrid search (default: 500)
4. `genai_rag_query_max_bytes`: Maximum query length in bytes (default: 8192)
5. `genai_rag_response_max_bytes`: Maximum response size in bytes (default: 5000000)
6. `genai_rag_timeout_ms`: RAG operation timeout in ms (default: 2000)