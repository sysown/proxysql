# Embedding Testing Plan

## Prerequisites

1. MySQL server running with test database
2. OpenAI-compatible embedding service accessible

## Quick Start

```bash
cd /home/rene/pr5312/proxysql/RAG_POC

# Step 1: Set your embedding service credentials
export OPENAI_API_BASE="https://your-embedding-service.com/v1"
export OPENAI_API_KEY="your-api-key-here"
export OPENAI_MODEL="your-model-name"
export OPENAI_EMBEDDING_DIM=1536  # Adjust based on your model

# Step 2: Run the test
./test_rag_ingest.sh
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

**Phase 4** (runs automatically with OPENAI_ variables set):
1. Creates RAG database with schema
2. Configures embedding with your credentials
3. Ingests 10 documents from MySQL
4. Generates embeddings via your service
5. Verifies:
   - 10 documents created
   - 10 chunks created
   - **10 embeddings created**
   - Vector self-match works (search finds itself)

---

## Expected Output

```
==> embedding_json: {"enabled":true,"provider":"openai","api_base":"https://...","api_key":"***","model":"...","dim":1536,"input":{"concat":[{"col":"Title"},{"lit":"\n"},{"chunk_body":true}]}}
Ingesting source_id=1 name=test_source backend=mysql table=posts
Done source test_source ingested_docs=10 skipped_docs=0
OK: rag_documents (embeddings enabled) = 10
OK: rag_chunks (embeddings enabled) = 10
OK: rag_vec_chunks (embeddings enabled) = 10
OK: vec self-match (posts:1#0) = posts:1#0
```

---

## Verification Queries

After the test, manually verify:

```bash
sqlite3 rag_ingest_test_openai.db <<SQL
.load ../deps/sqlite3/sqlite3/vec0.so

-- All chunks have embeddings?
SELECT 'Missing embeddings: ' || COUNT(*) FROM rag_chunks c
LEFT JOIN rag_vec_chunks v ON c.chunk_id = v.chunk_id
WHERE v.chunk_id IS NULL;
-- Expected: 0

-- Sample embeddings
SELECT chunk_id, substr(hex(substr(embedding,1,4)),1,8) AS vec_prefix
FROM rag_vec_chunks LIMIT 5;
```

---

## Troubleshooting

### Error: "Failed to generate embeddings"
- Check `OPENAI_API_BASE` is correct
- Check `OPENAI_API_KEY` is valid
- Check `OPENAI_MODEL` exists in your service

### Error: "Dimension mismatch"
- Set `OPENAI_EMBEDDING_DIM` to match your model
- Common dimensions: 768, 1536, 3072

### Timeout errors
- The test uses 20-second timeout (configurable in embedding_json)
- Check network connectivity to embedding service

---

## Testing Different Batch Sizes

To test the batching implementation, you can modify the test temporarily:

```bash
# Edit test_rag_ingest.sh, line ~339, add batch_size:
# {"enabled":true,"provider":"openai",...,"batch_size":32}
```

Then observe the number of API calls in your embedding service dashboard.
