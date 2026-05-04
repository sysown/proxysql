# RAG (Retrieval-Augmented Generation) in ProxySQL

## Overview

ProxySQL's RAG subsystem provides retrieval capabilities for LLM-powered applications. It allows you to:

- Store documents and their embeddings in a SQLite-based vector database
- Perform keyword search (FTS), semantic search (vector), and hybrid search
- Fetch document and chunk content
- Refetch authoritative data from source databases
- Monitor RAG system statistics

## Configuration

To enable RAG functionality, you need to enable the GenAI module and RAG features:

```sql
-- Enable GenAI module
SET genai.enabled = true;

-- Enable RAG features
SET genai.rag_enabled = true;

-- Configure RAG parameters (optional)
SET genai.rag_k_max = 50;
SET genai.rag_candidates_max = 500;
SET genai.rag_timeout_ms = 2000;
```

## Available MCP Tools

The RAG subsystem provides the following MCP tools via the `/mcp/rag` endpoint:

### Search Tools

1. **rag.search_fts** - Keyword search using FTS5
   ```json
   {
     "query": "search terms",
     "k": 10
   }
   ```

2. **rag.search_vector** - Semantic search using vector embeddings
   ```json
   {
     "query_text": "semantic search query",
     "k": 10
   }
   ```

3. **rag.search_hybrid** - Hybrid search combining FTS and vectors
   ```json
   {
     "query": "search query",
     "mode": "fuse",  // or "fts_then_vec"
     "k": 10
   }
   ```

### Fetch Tools

4. **rag.get_chunks** - Fetch chunk content by chunk_id
   ```json
   {
     "chunk_ids": ["chunk1", "chunk2"],
     "return": {
       "include_title": true,
       "include_doc_metadata": true,
       "include_chunk_metadata": true
     }
   }
   ```

5. **rag.get_docs** - Fetch document content by doc_id
   ```json
   {
     "doc_ids": ["doc1", "doc2"],
     "return": {
       "include_body": true,
       "include_metadata": true
     }
   }
   ```

6. **rag.fetch_from_source** - Refetch authoritative data from source database
   ```json
   {
     "doc_ids": ["doc1"],
     "columns": ["Id", "Title", "Body"],
     "limits": {
       "max_rows": 10,
       "max_bytes": 200000
     }
   }
   ```

### Admin Tools

7. **rag.admin.stats** - Get operational statistics for RAG system
   ```json
   {}
   ```

## Database Schema

The RAG subsystem uses the following tables in the vector database (`/var/lib/proxysql/ai_features.db`):

- **rag_sources** - Control plane for ingestion configuration
- **rag_documents** - Canonical documents
- **rag_chunks** - Retrieval units (chunked content)
- **rag_fts_chunks** - FTS5 index for keyword search
- **rag_vec_chunks** - Vector index for semantic search
- **rag_sync_state** - Sync state for incremental ingestion
- **rag_chunk_view** - Convenience view for debugging

## Testing

You can test the RAG functionality using the provided test scripts:

```bash
# Test RAG functionality via MCP endpoint
./scripts/mcp/test_rag.sh

# Test RAG database schema
cd test/rag
make test_rag_schema
./test_rag_schema
```

## Security

The RAG subsystem includes several security features:

- Input validation and sanitization
- Query length limits
- Result size limits
- Timeouts for all operations
- Column whitelisting for refetch operations
- Row and byte limits for all operations

## Performance

Recommended performance settings:

- Set appropriate timeouts (250-2000ms)
- Limit result sizes (k_max=50, candidates_max=500)
- Use connection pooling for source database connections
- Monitor resource usage and adjust limits accordingly