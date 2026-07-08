# ProxySQL RAG Index — Embeddings & Vector Retrieval Design (Chunk-Level) (v0→v1 Blueprint)

This document specifies how embeddings should be produced, stored, updated, and queried for chunk-level vector search in ProxySQL’s RAG index. It is intended as an implementation blueprint.

It assumes:
- Chunking is already implemented (`rag_chunks`).
- ProxySQL includes **sqlite3-vec** and uses a `vec0(...)` virtual table (`rag_vec_chunks`).
- Retrieval is exposed primarily via MCP tools (`mcp-tools.md`).

---

## 1. Design objectives

1. **Chunk-level embeddings**
   - Each chunk receives its own embedding for retrieval precision.

2. **Deterministic embedding input**
   - The text embedded is explicitly defined per source, not inferred.

3. **Model agility**
   - The system can change embedding models/dimensions without breaking stored data or APIs.

4. **Efficient updates**
   - Only recompute embeddings for chunks whose embedding input changed.

5. **Operational safety**
   - Bound cost and latency (embedding generation can be expensive).
   - Allow asynchronous embedding jobs if needed later.

---

## 2. What to embed (and what not to embed)

### 2.1 Embed text that improves semantic retrieval
Recommended embedding input per chunk:

- Document title (if present)
- Tags (as plain text)
- Chunk body

Example embedding input template:
```
{Title}
Tags: {Tags}

{ChunkBody}
```

This typically improves semantic recall significantly for knowledge-base-like content (StackOverflow posts, docs, tickets, runbooks).

### 2.2 Do NOT embed numeric metadata by default
Do not embed fields like `Score`, `ViewCount`, `OwnerUserId`, timestamps, etc. These should remain structured and be used for:
- filtering
- boosting
- tie-breaking
- result shaping

Embedding numeric metadata into text typically adds noise and reduces semantic quality.

### 2.3 Code and HTML considerations
If your chunk body contains HTML or code:
- **v0**: embed raw text (works, but may be noisy)
- **v1**: normalize to improve quality:
  - strip HTML tags (keep text content)
  - preserve code blocks as text, but consider stripping excessive markup
  - optionally create specialized “code-only” chunks for code-heavy sources

Normalization should be source-configurable.

---

## 3. Where embedding input rules are defined

Embedding input rules must be explicit and stored per source.

### 3.1 `rag_sources.embedding_json`
Recommended schema:
```json
{
  "enabled": true,
  "model": "text-embedding-3-large",
  "dim": 1536,
  "input": {
    "concat": [
      {"col":"Title"},
      {"lit":"\nTags: "}, {"col":"Tags"},
      {"lit":"\n\n"},
      {"chunk_body": true}
    ]
  },
  "normalize": {
    "strip_html": true,
    "collapse_whitespace": true
  }
}
```

**Semantics**
- `enabled`: whether to compute/store embeddings for this source
- `model`: logical name (for observability and compatibility checks)
- `dim`: vector dimension
- `input.concat`: how to build embedding input text
- `normalize`: optional normalization steps

---

## 4. Storage schema and model/versioning

### 4.1 Current v0 schema: single vector table
`rag_vec_chunks` stores:
- embedding vector
- chunk_id
- doc_id/source_id convenience columns
- updated_at

This is appropriate for v0 when you assume a single embedding model/dimension.

### 4.2 Recommended v1 evolution: support multiple models
In a product setting, you may want multiple embedding models (e.g. general vs code-centric).

Two ways to support this:

#### Option A: include model identity columns in `rag_vec_chunks`
Add columns:
- `model TEXT`
- `dim INTEGER` (optional if fixed per model)

Then allow multiple rows per `chunk_id` (unique key becomes `(chunk_id, model)`).
This may require schema change and a different vec0 design (some vec0 configurations support metadata columns, but uniqueness must be handled carefully).

#### Option B: one vec table per model (recommended if vec0 constraints exist)
Create:
- `rag_vec_chunks_1536_v1`
- `rag_vec_chunks_1024_code_v1`
etc.

Then MCP tools select the table based on requested model or default configuration.

**Recommendation**
Start with Option A only if your sqlite3-vec build makes it easy to filter by model. Otherwise, Option B is operationally cleaner.

---

## 5. Embedding generation pipeline

### 5.1 When embeddings are created
Embeddings are created during ingestion, immediately after chunk creation, if `embedding_json.enabled=true`.

This provides a simple, synchronous pipeline:
- ingest row → create chunks → compute embedding → store vector

### 5.2 When embeddings should be updated
Embeddings must be recomputed if the *embedding input string* changes. That depends on:
- title changes
- tags changes
- chunk body changes
- normalization rules changes (strip_html etc.)
- embedding model changes

Therefore, update logic should be based on a **content hash** of the embedding input.

---

## 6. Content hashing for efficient updates (v1 recommendation)

### 6.1 Why hashing is needed
Without hashing, you might recompute embeddings unnecessarily:
- expensive
- slow
- prevents incremental sync from being efficient

### 6.2 Recommended approach
Store `embedding_input_hash` per chunk per model.

Implementation options:

#### Option A: Store hash in `rag_chunks.metadata_json`
Example:
```json
{
  "chunk_index": 0,
  "embedding_hash": "sha256:...",
  "embedding_model": "text-embedding-3-large"
}
```

Pros: no schema changes.  
Cons: JSON parsing overhead.

#### Option B: Dedicated side table (recommended)
Create `rag_chunk_embedding_state`:

```sql
CREATE TABLE rag_chunk_embedding_state (
  chunk_id   TEXT NOT NULL,
  model      TEXT NOT NULL,
  dim        INTEGER NOT NULL,
  input_hash TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(chunk_id, model)
);
```

Pros: fast lookups; avoids JSON parsing.  
Cons: extra table.

**Recommendation**
Use Option B for v1.

---

## 7. Embedding model integration options

### 7.1 External embedding service (recommended initially)
ProxySQL calls an embedding service:
- OpenAI-compatible endpoint, or
- local service (e.g. llama.cpp server), or
- vendor-specific embedding API

Pros:
- easy to iterate on model choice
- isolates ML runtime from ProxySQL process

Cons:
- network latency; requires caching and timeouts

### 7.2 Embedded model runtime inside ProxySQL
ProxySQL links to an embedding runtime (llama.cpp, etc.)

Pros:
- no network dependency
- predictable latency if tuned

Cons:
- increases memory footprint
- needs careful resource controls

**Recommendation**
Start with an external embedding provider and keep a modular interface that can be swapped later.

---

## 8. Query embedding generation

Vector search needs a query embedding. Do this in the MCP layer:

1. Take `query_text`
2. Apply query normalization (optional but recommended)
3. Compute query embedding using the same model used for chunks
4. Execute vector search SQL with a bound embedding vector

**Do not**
- accept arbitrary embedding vectors from untrusted callers without validation
- allow unbounded query lengths

---

## 9. Vector search semantics

### 9.1 Distance vs similarity
Depending on the embedding model and vec search primitive, vector search may return:
- cosine distance (lower is better)
- cosine similarity (higher is better)
- L2 distance (lower is better)

**Recommendation**
Normalize to a “higher is better” score in MCP responses:
- if distance: `score_vec = 1 / (1 + distance)` or similar monotonic transform

Keep raw distance in debug fields if needed.

### 9.2 Filtering
Filtering should be supported by:
- `source_id` restriction
- optional metadata filters (doc-level or chunk-level)

In v0, filter by `source_id` is easiest because `rag_vec_chunks` stores `source_id` as metadata.

---

## 10. Hybrid retrieval integration

Embeddings are one leg of hybrid retrieval. Two recommended hybrid modes are described in `mcp-tools.md`:

1. **Fuse**: top-N FTS and top-N vector, merged by chunk_id, fused by RRF
2. **FTS then vector**: broad FTS candidates then vector rerank within candidates

Embeddings support both:
- Fuse mode needs global vector search top-N.
- Candidate mode needs vector search restricted to candidate chunk IDs.

Candidate mode is often cheaper and more precise when the query includes strong exact tokens.

---

## 11. Operational controls

### 11.1 Resource limits
Embedding generation must be bounded by:
- max chunk size embedded
- max chunks embedded per document
- per-source embedding rate limit
- timeouts when calling embedding provider

### 11.2 Batch embedding
To improve throughput, embed in batches:
- collect N chunks
- send embedding request for N inputs
- store results

### 11.3 Backpressure and async embedding
For v1, consider decoupling embedding generation from ingestion:
- ingestion stores chunks
- embedding worker processes “pending” chunks and fills vectors

This allows:
- ingestion to remain fast
- embedding to scale independently
- retries on embedding failures

In this design, store a state record:
- pending / ok / error
- last error message
- retry count

---

## 12. Recommended implementation steps (coding agent checklist)

### v0 (synchronous embedding)
1. Implement `embedding_json` parsing in ingester
2. Build embedding input string for each chunk
3. Call embedding provider (or use a stub in development)
4. Insert vector rows into `rag_vec_chunks`
5. Implement `rag.search_vector` MCP tool using query embedding + vector SQL

### v1 (efficient incremental embedding)
1. Add `rag_chunk_embedding_state` table
2. Store `input_hash` per chunk per model
3. Only re-embed if hash changed
4. Add async embedding worker option
5. Add metrics for embedding throughput and failures

---

## 13. Summary

- Compute embeddings per chunk, not per document.
- Define embedding input explicitly in `rag_sources.embedding_json`.
- Store vectors in `rag_vec_chunks` (vec0).
- For production, add hash-based update detection and optional async embedding workers.
- Normalize vector scores in MCP responses and keep raw distance for debugging.

