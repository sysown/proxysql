# RAG Source Configuration Guide: `chunking_json` and `embedding_json`

This guide explains how to configure document chunking and vector embedding generation in the ProxySQL RAG ingestion system.

---

## Table of Contents

- [Overview](#overview)
- [chunking_json](#chunking_json)
- [embedding_json](#embedding_json)
- [Complete Examples](#complete-examples)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Overview

The `rag_sources` table stores configuration for ingesting data into the RAG index. Two key JSON columns control how documents are processed:

| Column | Purpose | Required |
|--------|---------|----------|
| `chunking_json` | Controls how documents are split into chunks | Yes |
| `embedding_json` | Controls how vector embeddings are generated | No |

Both columns accept JSON objects with specific fields that define the behavior of the ingestion pipeline.

---

## chunking_json

The `chunking_json` column defines how documents are split into smaller pieces (chunks) for indexing. Chunking is important because:

- **Retrieval precision**: Smaller chunks allow more precise matching
- **Context management**: LLMs work better with focused, sized appropriately content
- **Indexing efficiency**: FTS and vector search perform better on sized units

### Schema

```sql
CREATE TABLE rag_sources (
    -- ...
    chunking_json TEXT NOT NULL,  -- REQUIRED
    -- ...
);
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable chunking. When `false`, entire document is a single chunk. |
| `unit` | string | `"chars"` | Unit of measurement. **Only `"chars"` is supported in v0.** |
| `chunk_size` | integer | `4000` | Maximum size of each chunk (in characters). |
| `overlap` | integer | `400` | Number of characters shared between consecutive chunks. |
| `min_chunk_size` | integer | `800` | Minimum size for the last chunk. If smaller, merges with previous chunk. |

### Validation Rules

| Condition | Action |
|-----------|--------|
| `chunk_size <= 0` | Reset to `4000` |
| `overlap < 0` | Reset to `0` |
| `overlap >= chunk_size` | Reset to `chunk_size / 4` |
| `min_chunk_size < 0` | Reset to `0` |
| `unit != "chars"` | Warning logged, falls back to `"chars"` |

### Chunking Algorithm

The chunker uses a sliding window approach:

```
Document: "A long document text that needs to be split..."

With chunk_size=20, overlap=5:

Chunk 0: [0-19]   "A long document tex"
Chunk 1: [15-34]  "ment text that needs "
Chunk 2: [30-49]  "to be split..."
```

**Algorithm steps:**

1. If `enabled=false`, return entire document as single chunk
2. If document size <= `chunk_size`, return as single chunk
3. Calculate step: `step = chunk_size - overlap`
4. Slide window across document by `step` characters
5. For final chunk: if size < `min_chunk_size`, append to previous chunk

### Examples

#### Example 1: Disable Chunking

```json
{
  "enabled": false
}
```

**Use case:** Small documents (posts, comments) that don't need splitting.

#### Example 2: Default Configuration

```json
{
  "enabled": true,
  "unit": "chars",
  "chunk_size": 4000,
  "overlap": 400,
  "min_chunk_size": 800
}
```

**Use case:** General-purpose content like articles, documentation.

#### Example 3: Smaller Chunks for Code

```json
{
  "enabled": true,
  "unit": "chars",
  "chunk_size": 1500,
  "overlap": 200,
  "min_chunk_size": 500
}
```

**Use case:** Code or technical content where smaller, more focused chunks improve retrieval.

#### Example 4: Large Chunks for Long-form Content

```json
{
  "enabled": true,
  "unit": "chars",
  "chunk_size": 8000,
  "overlap": 800,
  "min_chunk_size": 2000
}
```

**Use case:** Books, long reports where maintaining more context per chunk is beneficial.

### Visual Example

For a 10,000 character document with `chunk_size=4000`, `overlap=400`, `min_chunk_size=800`:

```
Chunk 0: chars 0-3999     (4000 chars)
Chunk 1: chars 3600-7599  (4000 chars, overlaps by 400)
Chunk 2: chars 7200-9999  (2799 chars - kept since > min_chunk_size)
```

Result: **3 chunks**

With a 7,500 character document:

```
Chunk 0: chars 0-3999     (4000 chars)
Chunk 1: chars 3600-7499  (3899 chars - final chunk merged)
```

Result: **2 chunks** (last 101 chars merged into Chunk 1 since < min_chunk_size)

---

## embedding_json

The `embedding_json` column defines how vector embeddings are generated for semantic search. Embeddings convert text into numerical vectors that capture semantic meaning.

### Schema

```sql
CREATE TABLE rag_sources (
    -- ...
    embedding_json TEXT,  -- OPTIONAL (can be NULL)
    -- ...
);
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable/disable embedding generation. |
| `dim` | integer | `1536` | Vector dimension (must match model output). |
| `model` | string | `"unknown"` | Model name/identifier (for observability). |
| `provider` | string | `"stub"` | Embedding service: `"openai"` or `"stub"`. |
| `api_base` | string | (empty) | API endpoint URL. |
| `api_key` | string | (empty) | API authentication key. |
| `batch_size` | integer | `16` | Number of chunks processed per API request. |
| `timeout_ms` | integer | `20000` | HTTP request timeout in milliseconds. |
| `input` | object | (see below) | Specifies how to build embedding input text. |

### Validation Rules

| Condition | Action |
|-----------|--------|
| `dim <= 0` | Reset to `1536` |
| `batch_size <= 0` | Reset to `16` |
| `timeout_ms <= 0` | Reset to `20000` |

### Provider Types

#### 1. `stub` Provider

Generates deterministic pseudo-embeddings by hashing input text. Used for testing without API calls.

```json
{
  "enabled": true,
  "provider": "stub",
  "dim": 1536
}
```

**Benefits:**
- No network dependency
- No API costs
- Fast execution
- Deterministic output

**Use case:** Development, testing, CI/CD pipelines.

#### 2. `openai` Provider

Connects to OpenAI or OpenAI-compatible APIs (e.g., Azure OpenAI, local LLM servers).

```json
{
  "enabled": true,
  "provider": "openai",
  "api_base": "https://api.openai.com/v1",
  "api_key": "sk-your-api-key",
  "model": "text-embedding-3-small",
  "dim": 1536,
  "batch_size": 16,
  "timeout_ms": 30000
}
```

**Benefits:**
- High-quality semantic embeddings
- Batch processing support
- Wide model compatibility

**Use case:** Production semantic search.

### The `input` Field

The `input` field defines what text is sent to the embedding model. It uses a **concat specification** to combine:

- Column values from source row: `{"col": "ColumnName"}`
- Literal strings: `{"lit": "text"}`
- Chunk body: `{"chunk_body": true}`

#### Default Behavior

If `input` is not specified, only the chunk body is embedded.

#### Custom Input Example

```json
{
  "enabled": true,
  "provider": "openai",
  "dim": 1536,
  "input": {
    "concat": [
      {"col": "Title"},
      {"lit": "\nTags: "},
      {"col": "Tags"},
      {"lit": "\n\n"},
      {"chunk_body": true}
    ]
  }
}
```

**Result:** Embeds: `{Title}\nTags: {Tags}\n\n{ChunkBody}`

This typically improves semantic recall by including title and tags in the embedding.

#### Input Builder Algorithm

```cpp
// Simplified representation
if (input_spec contains "concat") {
    result = ""
    for each part in concat:
        if part has "col":   result += row[part.col]
        if part has "lit":   result += part.lit
        if part has "chunk_body" && true: result += chunk_body
    return result
}
return chunk_body  // fallback
```

### Batching Behavior

Embeddings are generated in batches to reduce API calls:

```
With batch_size=16 and 100 chunks:

Without batching: 100 API calls
With batching:    7 API calls (16+16+16+16+16+16+4)
```

**Batch process:**
1. Collect up to `batch_size` chunks
2. Call embedding API once with all inputs
3. Store all resulting vectors
4. Repeat until all chunks processed

### Examples

#### Example 1: Disabled (FTS Only)

```json
{
  "enabled": false
}
```

Or leave `embedding_json` as `NULL`. Only full-text search will be available.

#### Example 2: Stub for Testing

```json
{
  "enabled": true,
  "provider": "stub",
  "dim": 1536
}
```

#### Example 3: OpenAI with Defaults

```json
{
  "enabled": true,
  "provider": "openai",
  "api_base": "https://api.openai.com/v1",
  "api_key": "sk-your-key",
  "model": "text-embedding-3-small",
  "dim": 1536
}
```

#### Example 4: OpenAI with Custom Input

```json
{
  "enabled": true,
  "provider": "openai",
  "api_base": "https://api.openai.com/v1",
  "api_key": "sk-your-key",
  "model": "text-embedding-3-small",
  "dim": 1536,
  "batch_size": 32,
  "timeout_ms": 45000,
  "input": {
    "concat": [
      {"col": "Title"},
      {"lit": "\n"},
      {"chunk_body": true}
    ]
  }
}
```

#### Example 5: Local LLM Server

```json
{
  "enabled": true,
  "provider": "openai",
  "api_base": "http://localhost:8080/v1",
  "api_key": "dummy",
  "model": "nomic-embed-text",
  "dim": 768,
  "batch_size": 8,
  "timeout_ms": 60000
}
```

---

## Complete Examples

### Example 1: Basic StackOverflow Posts Source

```sql
INSERT INTO rag_sources (
    source_id, name, enabled, backend_type,
    backend_host, backend_port, backend_user, backend_pass, backend_db,
    table_name, pk_column,
    doc_map_json,
    chunking_json,
    embedding_json
) VALUES (
    1, 'stack_posts', 1, 'mysql',
    '127.0.0.1', 3306, 'root', 'root', 'stackdb',
    'posts', 'Id',
    '{
        "doc_id": {"format": "posts:{Id}"},
        "title": {"concat": [{"col": "Title"}]},
        "body": {"concat": [{"col": "Body"}]},
        "metadata": {"pick": ["Id", "Tags", "Score"]}
    }',
    '{
        "enabled": true,
        "unit": "chars",
        "chunk_size": 4000,
        "overlap": 400,
        "min_chunk_size": 800
    }',
    '{
        "enabled": true,
        "provider": "openai",
        "api_base": "https://api.openai.com/v1",
        "api_key": "sk-your-key",
        "model": "text-embedding-3-small",
        "dim": 1536,
        "batch_size": 16,
        "timeout_ms": 30000,
        "input": {
            "concat": [
                {"col": "Title"},
                {"lit": "\nTags: "},
                {"col": "Tags"},
                {"lit": "\n\n"},
                {"chunk_body": true}
            ]
        }
    }'
);
```

### Example 2: Documentation Articles (Small Chunks, Stub Embeddings)

```sql
INSERT INTO rag_sources (
    source_id, name, enabled, backend_type,
    backend_host, backend_port, backend_user, backend_pass, backend_db,
    table_name, pk_column,
    doc_map_json,
    chunking_json,
    embedding_json
) VALUES (
    2, 'docs', 1, 'mysql',
    '127.0.0.1', 3306, 'root', 'root', 'docsdb',
    'articles', 'article_id',
    '{
        "doc_id": {"format": "docs:{article_id}"},
        "title": {"concat": [{"col": "title"}]},
        "body": {"concat": [{"col": "content"}]},
        "metadata": {"pick": ["category", "author"]}
    }',
    '{
        "enabled": true,
        "unit": "chars",
        "chunk_size": 1500,
        "overlap": 200,
        "min_chunk_size": 500
    }',
    '{
        "enabled": true,
        "provider": "stub",
        "dim": 1536
    }'
);
```

### Example 3: GitHub Issues (No Chunking, Real Embeddings)

```sql
INSERT INTO rag_sources (
    source_id, name, enabled, backend_type,
    backend_host, backend_port, backend_user, backend_pass, backend_db,
    table_name, pk_column,
    doc_map_json,
    chunking_json,
    embedding_json
) VALUES (
    3, 'github_issues', 1, 'mysql',
    '127.0.0.1', 3306, 'root', 'root', 'githubdb',
    'issues', 'id',
    '{
        "doc_id": {"format": "issues:{id}"},
        "title": {"concat": [{"col": "title"}]},
        "body": {"concat": [{"col": "body"}]},
        "metadata": {"pick": ["number", "state", "labels"]}
    }',
    '{
        "enabled": false
    }',
    '{
        "enabled": true,
        "provider": "openai",
        "api_base": "https://api.openai.com/v1",
        "api_key": "sk-your-key",
        "model": "text-embedding-3-small",
        "dim": 1536,
        "input": {
            "concat": [
                {"col": "title"},
                {"lit": "\n\n"},
                {"chunk_body": true}
            ]
        }
    }'
);
```

---

## Best Practices

### Chunking

1. **Match content to chunk size:**
   - Short posts/comments: Disable chunking (`enabled: false`)
   - Articles/docs: 3000-5000 characters
   - Code: 1000-2000 characters
   - Books: 6000-10000 characters

2. **Set overlap to 10-20% of chunk size:**
   - Provides context continuity
   - Helps avoid cutting important information

3. **Set min_chunk_size to 20-25% of chunk size:**
   - Prevents tiny trailing chunks
   - Reduces noise in search results

4. **Consider your embedding token limit:**
   - OpenAI: ~8191 tokens per input
   - If using embeddings, ensure `chunk_size` doesn't exceed this

### Embeddings

1. **Use stub provider for development:**
   - Faster iteration
   - No API costs
   - Deterministic output

2. **Optimize batch_size for your API:**
   - OpenAI: max 16-2048 (depending on endpoint)
   - Local servers: typically lower (4-16)
   - Larger batches = fewer API calls but more memory

3. **Include relevant context in input:**
   - Title, tags, category improve semantic quality
   - Don't include numeric metadata (scores, IDs)
   - Keep input focused and clean

4. **Set appropriate timeouts:**
   - OpenAI: 20-30 seconds usually sufficient
   - Local servers: may need 60+ seconds
   - Consider retries for failed requests

5. **Match dimension to model:**
   - `text-embedding-3-small`: 1536
   - `text-embedding-3-large`: 3072
   - `nomic-embed-text`: 768
   - Custom models: check documentation

### Common Pitfalls

1. **Too large chunks:** Reduces retrieval precision
2. **Too small chunks:** Loses context, increases noise
3. **No overlap:** Misses information at chunk boundaries
4. **Too large overlap:** Increases index size, redundancy
5. **Wrong dimension:** Causes vector insertion failures
6. **Forgetting API key:** Silent failures in some configs

---

## Troubleshooting

### Chunking Issues

#### Problem: Too many small chunks

**Symptoms:** High chunk count, many chunks under 500 characters

**Solution:** Increase `min_chunk_size` or decrease `chunk_size`

```json
{
  "chunk_size": 3000,
  "min_chunk_size": 1000
}
```

#### Problem: Important context split between chunks

**Symptoms:** Search misses information that spans chunk boundaries

**Solution:** Increase `overlap`

```json
{
  "chunk_size": 4000,
  "overlap": 800
}
```

### Embedding Issues

#### Problem: "embedding dimension mismatch"

**Cause:** `dim` field doesn't match actual model output

**Solution:** Verify model dimension and update config

```json
{
  "model": "text-embedding-3-small",
  "dim": 1536  // Must match model
}
```

#### Problem: Timeout errors

**Symptoms:** Embedding requests fail after timeout

**Solutions:**
1. Increase `timeout_ms`
2. Decrease `batch_size`
3. Check network connectivity

```json
{
  "timeout_ms": 60000,
  "batch_size": 8
}
```

#### Problem: API rate limit errors

**Symptoms:** HTTP 429 errors from embedding service

**Solutions:**
1. Decrease `batch_size`
2. Add delay between batches (requires code change)
3. Upgrade API tier

```json
{
  "batch_size": 4
}
```

#### Problem: "embedding api_base is empty"

**Cause:** Using `openai` provider without setting `api_base`

**Solution:** Set `api_base` to your endpoint

```json
{
  "provider": "openai",
  "api_base": "https://api.openai.com/v1",
  "api_key": "sk-your-key"
}
```

### Verification Queries

```sql
-- Check current configuration
SELECT
    source_id,
    name,
    chunking_json,
    embedding_json
FROM rag_sources
WHERE enabled = 1;

-- Count chunks per document
SELECT
    d.source_id,
    AVG((SELECT COUNT(*) FROM rag_chunks c WHERE c.doc_id = d.doc_id)) as avg_chunks
FROM rag_documents d
GROUP BY d.source_id;

-- Check vector counts
SELECT
    source_id,
    COUNT(*) as vector_count
FROM rag_vec_chunks
GROUP BY source_id;

-- Verify dimensions match
SELECT
    source_id,
    COUNT(*) as count,
    -- This would need a custom query to extract vector length
    'Verify dim in rag_sources.embedding_json matches model' as check
FROM rag_vec_chunks
GROUP BY source_id;
```

---

## Quick Reference

### Minimum Configurations

```sql
-- FTS only (no embeddings)
INSERT INTO rag_sources (..., chunking_json, embedding_json) VALUES (
    ...,
    '{"enabled": false}',
    NULL
);

-- Chunking + stub embeddings (testing)
INSERT INTO rag_sources (..., chunking_json, embedding_json) VALUES (
    ...,
    '{"enabled":true,"chunk_size":4000,"overlap":400}',
    '{"enabled":true,"provider":"stub","dim":1536}'
);

-- Chunking + OpenAI embeddings (production)
INSERT INTO rag_sources (..., chunking_json, embedding_json) VALUES (
    ...,
    '{"enabled":true,"chunk_size":4000,"overlap":400}',
    '{"enabled":true,"provider":"openai","api_base":"https://api.openai.com/v1","api_key":"sk-...","model":"text-embedding-3-small","dim":1536}'
);
```

### Common Model Dimensions

| Model | Dimension |
|-------|-----------|
| `text-embedding-3-small` | 1536 |
| `text-embedding-3-large` | 3072 |
| `text-embedding-ada-002` | 1536 |
| `nomic-embed-text` | 768 |
| `all-MiniLM-L6-v2` | 384 |

---

## Related Documentation

- [INGEST_USAGE_GUIDE.md](INGEST_USAGE_GUIDE.md) - Complete ingestion tool usage
- [embeddings-design.md](embeddings-design.md) - Embedding architecture design
- [schema.sql](schema.sql) - Database schema reference
