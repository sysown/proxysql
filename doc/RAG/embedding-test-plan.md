# Embedding Testing Plan (MySQL Protocol Version)

## Prerequisites

1. **ProxySQL SQLite3 Server** running on port 6030
2. **MySQL server** (backend data source) running with test database
3. OpenAI-compatible embedding service accessible

## Quick Start

```bash
# From repository root
cd RAG_POC

# Step 1: Set your embedding service credentials
export OPENAI_API_BASE="https://your-embedding-service.com/v1"
export OPENAI_API_KEY="your-api-key-here"
export OPENAI_MODEL="your-model-name"
export OPENAI_EMBEDDING_DIM=1536  # Adjust based on your model

# Step 2: Run the test
./test_rag_ingest_sqlite_server.sh
```

---

## Configuration Options

### OpenAI API
```bash
export OPENAI_API_BASE="https://api.openai.com/v1"
export OPENAI_API_KEY="sk-your-openai-key"
export OPENAI_MODEL="text-embedding-3-small"
export OPENAI_EMBEDDING_DIM=1536
```

### Azure OpenAI
```bash
export OPENAI_API_BASE="https://your-resource.openai.azure.com/openai/deployments/your-deployment"
export OPENAI_API_KEY="your-azure-key"
export OPENAI_MODEL="text-embedding-ada-002"  # Your deployment name
export OPENAI_EMBEDDING_DIM=1536
```

### Other OpenAI-compatible services
```bash
# Any service with OpenAI-compatible API
export OPENAI_API_BASE="https://your-service.com/v1"
export OPENAI_API_KEY="your-key"
export OPENAI_MODEL="model-name"
export OPENAI_EMBEDDING_DIM=dim  # e.g., 768, 1536, 3072
```

---

## What the Test Does

**Phase 4** (Embeddings with stub provider):
1. Initializes RAG database schema via MySQL protocol
2. Configures stub embedding provider
3. Ingests 10 documents from MySQL backend
4. Generates pseudo-embeddings instantly
5. Verifies:
   - 10 documents created
   - 10 chunks created
   - **10 embeddings created**
   - Vector self-match works (search finds itself)

To test with real embeddings, set the environment variables above and modify the test script to use `"provider":"openai"` instead of `"provider":"stub"`.

---

## Expected Output

```
========================================
Phase 4: Enable Embeddings (Stub)
========================================
Done source mysql_posts ingested_docs=10 skipped_docs=0
OK: rag_vec_chunks (embeddings enabled) = 10
OK: Vector self-match = posts:1#0
OK: Vector embeddings and search working
```

---

## Verification Queries

After the test, manually verify via MySQL protocol:

```bash
mysql -h 127.0.0.1 -P 6030 -u root -proot test_rag -e "
-- All chunks have embeddings?
SELECT 'Missing embeddings: ' || COUNT(*) FROM rag_chunks c
LEFT JOIN rag_vec_chunks v ON c.chunk_id = v.chunk_id
WHERE v.chunk_id IS NULL;
-- Expected: 0

-- Sample embeddings
SELECT chunk_id, length(embedding) as embedding_bytes
FROM rag_vec_chunks LIMIT 5;
-- Expected: 6144 bytes per embedding (1536 floats * 4 bytes)

-- Vector similarity test
SELECT chunk_id, distance
FROM rag_vec_chunks
WHERE embedding MATCH (
    SELECT embedding FROM rag_vec_chunks WHERE chunk_id='posts:1#0' LIMIT 1
)
ORDER BY distance LIMIT 3;
"
```

---

## Architecture

```
┌─────────────┐                    ┌──────────────────┐                    ┌─────────────┐
│ rag_ingest  │───MySQL Protocol──→│ ProxySQL         │───FTS5/vec0───→│   SQLite    │
│             │    (port 6030)     │ SQLite3 Server   │                 │   Backend   │
└──────┬──────┘                    └──────────────────┘                    └─────────────┘
       │
       │ MySQL Protocol
       ↓
┌──────────────────┐
│ Backend MySQL    │
│ (port 3306)      │
│                  │
│  • Source tables │
└──────────────────┘
```

**Data flow:**
1. `rag_ingest` connects to **SQLite3 Server** (port 6030) via MySQL protocol
2. Stores RAG index (documents, chunks, FTS, vectors) in **SQLite backend**
3. Fetches source data from separate **MySQL backend** (port 3306)
4. Generates embeddings via **HTTP API** (OpenAI-compatible)

---

## Troubleshooting

### Error: "MySQL connect failed" (SQLite3 Server)
- Verify ProxySQL is running: `ps aux | grep proxysql`
- Check port 6030 is listening: `netstat -an | grep 6030`
- Verify credentials: `mysql -h 127.0.0.1 -P 6030 -u root -proot`

### Error: "MySQL query failed" (backend MySQL)
- Verify backend MySQL is running: `mysql -h 127.0.0.1 -P 3306 -u root -proot`
- Check `rag_sources` configuration: `SELECT * FROM rag_sources WHERE enabled=1;`

### Error: "Failed to generate embeddings"
- Check `OPENAI_API_BASE` is correct
- Check `OPENAI_API_KEY` is valid
- Check `OPENAI_MODEL` exists in your service
- Check network connectivity to embedding service

### Error: "Dimension mismatch" (vec0)
- Set `OPENAI_EMBEDDING_DIM` to match your model
- Common dimensions: 768, 1536, 3072
- Verify schema has correct vector dimension: `SELECT sql FROM sqlite_master WHERE name='rag_vec_chunks';`

### Timeout errors
- The default timeout is 30 seconds (configurable in embedding_json)
- Check network connectivity to embedding service
- Reduce batch_size if needed

---

## Testing Different Batch Sizes

To test the batching implementation, modify the test script temporarily:

```bash
# Edit test_rag_ingest_sqlite_server.sh, find the embedding_json configuration
# Change from:
#   "provider":"stub"
# To:
#   "provider":"openai",
#   "batch_size": 32
```

Then observe the number of API calls in your embedding service dashboard.

---

## Manual Testing

For interactive testing:

```bash
# 1. Initialize database
./rag_ingest init -h 127.0.0.1 -P 6030 -u root -p root -D test_embeddings

# 2. Configure source with embeddings
mysql -h 127.0.0.1 -P 6030 -u root -proot test_embeddings -e "
UPDATE rag_sources
SET embedding_json = '{
    \"enabled\": true,
    \"provider\": \"openai\",
    \"api_base\": \"https://api.openai.com/v1\",
    \"api_key\": \"sk-your-key\",
    \"model\": \"text-embedding-3-small\",
    \"dim\": 1536,
    \"batch_size\": 16
}'
WHERE source_id = 1;
"

# 3. Run ingestion
./rag_ingest ingest -h 127.0.0.1 -P 6030 -u root -p root -D test_embeddings

# 4. Verify
mysql -h 127.0.0.1 -P 6030 -u root -proot test_embeddings -e "
SELECT COUNT(*) as embeddings FROM rag_vec_chunks;
"
```

---

## Testing Vector Search

After embeddings are generated:

```bash
mysql -h 127.0.0.1 -P 6030 -u root -proot test_embeddings -e "
-- Find similar chunks to posts:1#0
SELECT
    c.chunk_id,
    substr(c.body, 1, 60) as content,
    v.distance
FROM rag_vec_chunks v
JOIN rag_chunks c ON c.chunk_id = v.chunk_id
WHERE v.embedding MATCH (
    SELECT embedding FROM rag_vec_chunks WHERE chunk_id='posts:1#0' LIMIT 1
)
ORDER BY v.distance
LIMIT 5;
"
```

Expected output:
- `posts:1#0` with distance 0.0 (exact match)
- Other chunks with increasing distances
