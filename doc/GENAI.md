# GenAI Module Documentation

## Overview

The **GenAI (Generative AI) Module** in ProxySQL provides asynchronous, non-blocking access to embedding generation and document reranking services. It enables ProxySQL to interact with LLM services (like llama-server) for vector embeddings and semantic search operations without blocking MySQL threads.

## Version

- **Module Version**: 0.1.0
- **Last Updated**: 2025-01-10
- **Branch**: v3.1-vec_genAI_module

## Architecture

### Async Design

The GenAI module uses a **non-blocking async architecture** based on socketpair IPC and epoll event notification:

```
┌─────────────────┐         socketpair         ┌─────────────────┐
│  MySQL_Session  │◄────────────────────────────►│  GenAI Module   │
│  (MySQL Thread) │  fds[0]              fds[1]  │  Listener Loop  │
└────────┬────────┘                            └────────┬────────┘
         │                                               │
         │ epoll                                         │ queue
         │                                               │
         └── epoll_wait() ────────────────────────────────┘
                     (GenAI Response Ready)
```

### Key Components

1. **MySQL_Session** - Client-facing interface that receives GENAI: queries
2. **GenAI Listener Thread** - Monitors socketpair fds via epoll for incoming requests
3. **GenAI Worker Threads** - Thread pool that processes requests (blocking HTTP calls)
4. **Socketpair Communication** - Bidirectional IPC between MySQL and GenAI modules

### Communication Protocol

#### Request Format (MySQL → GenAI)

```c
struct GenAI_RequestHeader {
    uint64_t request_id;      // Client's correlation ID
    uint32_t operation;       // GENAI_OP_EMBEDDING, GENAI_OP_RERANK, or GENAI_OP_JSON
    uint32_t query_len;       // Length of JSON query that follows
    uint32_t flags;           // Reserved (must be 0)
    uint32_t top_n;           // For rerank: max results (0 = all)
};
// Followed by: JSON query (query_len bytes)
```

#### Response Format (GenAI → MySQL)

```c
struct GenAI_ResponseHeader {
    uint64_t request_id;        // Echo of client's request ID
    uint32_t status_code;       // 0 = success, >0 = error
    uint32_t result_len;        // Length of JSON result that follows
    uint32_t processing_time_ms;// Time taken by GenAI worker
    uint64_t result_ptr;        // Reserved (must be 0)
    uint32_t result_count;      // Number of results
    uint32_t reserved;          // Reserved (must be 0)
};
// Followed by: JSON result (result_len bytes)
```

## Configuration Variables

### Thread Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `genai-threads` | int | 4 | Number of GenAI worker threads (1-256) |

### Service Endpoints

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `genai-embedding_uri` | string | `http://127.0.0.1:8013/embedding` | Embedding service endpoint |
| `genai-rerank_uri` | string | `http://127.0.0.1:8012/rerank` | Reranking service endpoint |

### Timeouts

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `genai-embedding_timeout_ms` | int | 30000 | Embedding request timeout (100-300000ms) |
| `genai-rerank_timeout_ms` | int | 30000 | Reranking request timeout (100-300000ms) |

### Admin Commands

```sql
-- Load/Save GenAI variables
LOAD GENAI VARIABLES TO RUNTIME;
SAVE GENAI VARIABLES FROM RUNTIME;
LOAD GENAI VARIABLES FROM DISK;
SAVE GENAI VARIABLES TO DISK;

-- Set variables
SET genai-threads = 8;
SET genai-embedding_uri = 'http://localhost:8080/embed';
SET genai-rerank_uri = 'http://localhost:8081/rerank';

-- View variables
SELECT @@genai-threads;
SHOW VARIABLES LIKE 'genai-%';

-- Checksum
CHECKSUM GENAI VARIABLES;
```

## Query Syntax

### GENAI: Query Format

GenAI queries use the special `GENAI:` prefix followed by JSON:

```sql
GENAI: {"type": "embed", "documents": ["text1", "text2"]}
GENAI: {"type": "rerank", "query": "search text", "documents": ["doc1", "doc2"]}
```

### Supported Operations

#### 1. Embedding

Generate vector embeddings for documents:

```sql
GENAI: {
    "type": "embed",
    "documents": [
        "Machine learning is a subset of AI.",
        "Deep learning uses neural networks."
    ]
}
```

**Response:**
```
+------------------------------------------+
| embedding                                |
+------------------------------------------+
| 0.123, -0.456, 0.789, ...               |
| 0.234, -0.567, 0.890, ...               |
+------------------------------------------+
```

#### 2. Reranking

Rerank documents by relevance to a query:

```sql
GENAI: {
    "type": "rerank",
    "query": "What is machine learning?",
    "documents": [
        "Machine learning is a subset of artificial intelligence.",
        "The capital of France is Paris.",
        "Deep learning uses neural networks."
    ],
    "top_n": 2,
    "columns": 3
}
```

**Parameters:**
- `query` (required): Search query text
- `documents` (required): Array of documents to rerank
- `top_n` (optional): Maximum results to return (0 = all, default: all)
- `columns` (optional): 2 = {index, score}, 3 = {index, score, document} (default: 3)

**Response:**
```
+-------+-------+----------------------------------------------+
| index | score | document                                    |
+-------+-------+----------------------------------------------+
| 0     | 0.95  | Machine learning is a subset of AI...        |
| 2     | 0.82  | Deep learning uses neural networks...        |
+-------+-------+----------------------------------------------+
```

### Response Format

All GenAI queries return results in MySQL resultset format with:
- `columns`: Array of column names
- `rows`: Array of row data

**Success:**
```json
{
    "columns": ["index", "score", "document"],
    "rows": [
        [0, 0.95, "Most relevant document"],
        [2, 0.82, "Second most relevant"]
    ]
}
```

**Error:**
```json
{
    "error": "Error message describing what went wrong"
}
```

## Usage Examples

### Basic Embedding

```sql
-- Generate embedding for a single document
GENAI: {"type": "embed", "documents": ["Hello, world!"]};

-- Batch embedding for multiple documents
GENAI: {
    "type": "embed",
    "documents": ["doc1", "doc2", "doc3"]
};
```

### Basic Reranking

```sql
-- Find most relevant documents
GENAI: {
    "type": "rerank",
    "query": "database optimization techniques",
    "documents": [
        "How to bake a cake",
        "Indexing strategies for MySQL",
        "Python programming basics",
        "Query optimization in ProxySQL"
    ]
};
```

### Top N Results

```sql
-- Get only top 3 most relevant documents
GENAI: {
    "type": "rerank",
    "query": "best practices for SQL",
    "documents": ["doc1", "doc2", "doc3", "doc4", "doc5"],
    "top_n": 3
};
```

### Index and Score Only

```sql
-- Get only relevance scores (no document text)
GENAI: {
    "type": "rerank",
    "query": "test query",
    "documents": ["doc1", "doc2"],
    "columns": 2
};
```

## Integration with ProxySQL

### Session Lifecycle

1. **Session Start**: MySQL session creates `genai_epoll_fd_` for monitoring GenAI responses
2. **Query Received**: `GENAI:` query detected in `handler___status_WAITING_CLIENT_DATA___STATE_SLEEP()`
3. **Async Send**: Socketpair created, request sent, returns immediately
4. **Main Loop**: `check_genai_events()` called on each iteration
5. **Response Ready**: `handle_genai_response()` processes response
6. **Result Sent**: MySQL result packet sent to client
7. **Cleanup**: Socketpair closed, resources freed

### Main Loop Integration

The GenAI event checking is integrated into the main MySQL handler loop:

```cpp
handler_again:
    switch (status) {
        case WAITING_CLIENT_DATA:
            handler___status_WAITING_CLIENT_DATA();
#ifdef epoll_create1
            // Check for GenAI responses before processing new client data
            if (check_genai_events()) {
                goto handler_again;  // Process more responses
            }
#endif
            break;
    }
```

## Backend Services

### llama-server Integration

The GenAI module is designed to work with [llama-server](https://github.com/ggerganov/llama.cpp), a high-performance C++ inference server for LLaMA models.

#### Starting llama-server

```bash
# Start embedding server
./llama-server \
    --model /path/to/nomic-embed-text-v1.5.gguf \
    --port 8013 \
    --embedding \
    --ctx-size 512

# Start reranking server (using same model)
./llama-server \
    --model /path/to/nomic-embed-text-v1.5.gguf \
    --port 8012 \
    --ctx-size 512
```

#### API Compatibility

The GenAI module expects:
- **Embedding endpoint**: `POST /embedding` with JSON request
- **Rerank endpoint**: `POST /rerank` with JSON request

Compatible with:
- llama-server
- OpenAI-compatible embedding APIs
- Custom services with matching request/response format

## Testing

### TAP Test Suite

Comprehensive TAP tests are available in `test/tap/tests/genai_async-t.cpp`:

```bash
cd test/tap/tests
make genai_async-t
./genai_async-t
```

**Test Coverage:**
- Single async requests
- Sequential requests (embedding and rerank)
- Batch requests (10+ documents)
- Mixed embedding and rerank
- Request/response matching
- Error handling (invalid JSON, missing fields)
- Special characters (quotes, unicode, etc.)
- Large documents (5KB+)
- `top_n` and `columns` parameters
- Concurrent connections

### Manual Testing

```sql
-- Test embedding
mysql> GENAI: {"type": "embed", "documents": ["test document"]};

-- Test reranking
mysql> GENAI: {
    ->   "type": "rerank",
    ->   "query": "test query",
    ->   "documents": ["doc1", "doc2", "doc3"]
    -> };
```

## Performance Characteristics

### Non-Blocking Behavior

- **MySQL threads**: Return immediately after sending request (~1ms)
- **GenAI workers**: Handle blocking HTTP calls (10-100ms typical)
- **Throughput**: Limited by GenAI service capacity and worker thread count

### Resource Usage

- **Per request**: 1 socketpair (2 file descriptors)
- **Memory**: Request metadata + pending response storage
- **Worker threads**: Configurable via `genai-threads` (default: 4)

### Scalability

- **Concurrent requests**: Limited by `genai-threads` and GenAI service capacity
- **Request queue**: Unlimited (pending requests stored in session map)
- **Recommended**: Set `genai-threads` to match expected concurrency

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `Failed to create GenAI communication channel` | Socketpair creation failed | Check system limits (ulimit -n) |
| `Failed to register with GenAI module` | GenAI module not initialized | Run `LOAD GENAI VARIABLES TO RUNTIME` |
| `Failed to send request to GenAI module` | Write error on socketpair | Check connection stability |
| `GenAI module not initialized` | GenAI threads not started | Set `genai-threads > 0` and reload |

### Timeout Handling

Requests exceeding `genai-embedding_timeout_ms` or `genai-rerank_timeout_ms` will fail with:
- Status code > 0 in response header
- Error message in JSON result
- Socketpair cleanup

## Monitoring

### Status Variables

```sql
-- Check GenAI module status (not yet implemented, planned)
SHOW STATUS LIKE 'genai-%';
```

**Planned status variables:**
- `genai_threads_initialized`: Number of worker threads running
- `genai_active_requests`: Currently processing requests
- `genai_completed_requests`: Total successful requests
- `genai_failed_requests`: Total failed requests

### Logging

GenAI operations log at debug level:

```bash
# Enable GenAI debug logging
SET mysql-debug = 1;

# Check logs
tail -f proxysql.log | grep GenAI
```

## Limitations

### Current Limitations

1. **document_from_sql**: Not yet implemented (requires MySQL connection handling in workers)
2. **Shared memory**: Result pointer field reserved for future optimization
3. **Request size**: Limited by socket buffer size (typically 64KB-256KB)

### Platform Requirements

- **Epoll support**: Linux systems (kernel 2.6+)
- **Socketpair**: Unix domain sockets
- **Threading**: POSIX threads (pthread)

## Future Enhancements

### Planned Features

1. **document_from_sql**: Execute SQL to retrieve documents for reranking
2. **Shared memory**: Zero-copy result transfer for large responses
3. **Connection pooling**: Reuse HTTP connections to GenAI services
4. **Metrics**: Enhanced monitoring and statistics
5. **Batch optimization**: Better support for large document batches
6. **Streaming**: Progressive result delivery for large operations

## Related Documentation

- [SQLite3 Server Documentation](./SQLite3-Server.md) - SQLite3 backend integration

## Source Files

### Core Implementation

- `include/GenAI_Thread.h` - GenAI module interface and structures
- `lib/GenAI_Thread.cpp` - Implementation of listener and worker loops
- `include/MySQL_Session.h` - Session integration (GenAI async state)
- `lib/MySQL_Session.cpp` - Async handlers and main loop integration
- `include/Base_Session.h` - Base session GenAI members

### Tests

- `test/tap/tests/genai_module-t.cpp` - Admin commands and variables
- `test/tap/tests/genai_embedding_rerank-t.cpp` - Basic embedding/reranking
- `test/tap/tests/genai_async-t.cpp` - Async architecture tests

## License

Same as ProxySQL - See LICENSE file for details.

## Contributing

For contributions and issues:
- GitHub: https://github.com/sysown/proxysql
- Branch: `v3.1-vec_genAI_module`

---

*Last Updated: 2025-01-10*
*Module Version: 0.1.0*
