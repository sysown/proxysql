# MCP Tooling for ProxySQL RAG Engine (v0 Blueprint)

This document defines the MCP tool surface for querying ProxySQL’s embedded RAG index. It is intended as a stable interface for AI agents. Internally, these tools query the SQLite schema described in `schema.sql` and the retrieval logic described in `architecture-runtime-retrieval.md`.

**Design goals**
- Stable tool contracts (do not break agents when internals change)
- Strict bounds (prevent unbounded scans / large outputs)
- Deterministic schemas (agents can reliably parse outputs)
- Separation of concerns:
  - Retrieval returns identifiers and scores
  - Fetch returns content
  - Optional refetch returns authoritative source rows

---

## 1. Conventions

### 1.1 Identifiers
- `doc_id`: stable document identifier (e.g. `posts:12345`)
- `chunk_id`: stable chunk identifier (e.g. `posts:12345#0`)
- `source_id` / `source_name`: corresponds to `rag_sources`

### 1.2 Scores
- FTS score: `score_fts` (bm25; lower is better in SQLite’s bm25 by default)
- Vector score: `score_vec` (distance or similarity, depending on implementation)
- Hybrid score: `score` (normalized fused score; higher is better)

**Recommendation**
Normalize scores in MCP layer so:
- higher is always better for agent ranking
- raw internal ranking can still be returned as `score_fts_raw`, `distance_raw`, etc. if helpful

### 1.3 Limits and budgets (recommended defaults)
All tools should enforce caps, regardless of caller input:
- `k_max = 50`
- `candidates_max = 500`
- `query_max_bytes = 8192`
- `response_max_bytes = 5_000_000`
- `timeout_ms` (per tool): 250–2000ms depending on tool type

Tools must return a `truncated` boolean if limits reduce output.

---

## 2. Shared filter model

Many tools accept the same filter structure. This is intentionally simple in v0.

### 2.1 Filter object
```json
{
  "source_ids": [1,2],
  "source_names": ["stack_posts"],
  "doc_ids": ["posts:12345"],
  "min_score": 5,
  "post_type_ids": [1],
  "tags_any": ["mysql","json"],
  "tags_all": ["mysql","json"],
  "created_after": "2022-01-01T00:00:00Z",
  "created_before": "2025-01-01T00:00:00Z"
}
```

**Notes**
- In v0, most filters map to `metadata_json` values. Implementation can:
  - filter in SQLite if JSON functions are available, or
  - filter in MCP layer after initial retrieval (acceptable for small k/candidates)
- For production, denormalize hot filters into dedicated columns for speed.

### 2.2 Filter behavior
- If both `source_ids` and `source_names` are provided, treat as intersection.
- If no source filter is provided, default to all enabled sources **but** enforce a strict global budget.

---

## 3. Tool: `rag.search_fts`

Keyword search over `rag_fts_chunks`.

### 3.1 Request schema
```json
{
  "query": "json_extract mysql",
  "k": 10,
  "offset": 0,
  "filters": { },
  "return": {
    "include_title": true,
    "include_metadata": true,
    "include_snippets": false
  }
}
```

### 3.2 Semantics
- Executes FTS query (MATCH) over indexed content.
- Returns top-k chunk matches with scores and identifiers.
- Does not return full chunk bodies unless `include_snippets` is requested (still bounded).

### 3.3 Response schema
```json
{
  "results": [
    {
      "chunk_id": "posts:12345#0",
      "doc_id": "posts:12345",
      "source_id": 1,
      "source_name": "stack_posts",
      "score_fts": 0.73,
      "title": "How to parse JSON in MySQL 8?",
      "metadata": { "Tags": "<mysql><json>", "Score": "12" }
    }
  ],
  "truncated": false,
  "stats": {
    "k_requested": 10,
    "k_returned": 10,
    "ms": 12
  }
}
```

---

## 4. Tool: `rag.search_vector`

Semantic search over `rag_vec_chunks`.

### 4.1 Request schema (text input)
```json
{
  "query_text": "How do I extract JSON fields in MySQL?",
  "k": 10,
  "filters": { },
  "embedding": {
    "model": "text-embedding-3-large"
  }
}
```

### 4.2 Request schema (precomputed vector)
```json
{
  "query_embedding": {
    "dim": 1536,
    "values_b64": "AAAA..."  // float32 array packed and base64 encoded
  },
  "k": 10,
  "filters": { }
}
```

### 4.3 Semantics
- If `query_text` is provided, ProxySQL computes embedding internally (preferred for agents).
- If `query_embedding` is provided, ProxySQL uses it directly (useful for advanced clients).
- Returns nearest chunks by distance/similarity.

### 4.4 Response schema
```json
{
  "results": [
    {
      "chunk_id": "posts:9876#1",
      "doc_id": "posts:9876",
      "source_id": 1,
      "source_name": "stack_posts",
      "score_vec": 0.82,
      "title": "Query JSON columns efficiently",
      "metadata": { "Tags": "<mysql><json>", "Score": "8" }
    }
  ],
  "truncated": false,
  "stats": {
    "k_requested": 10,
    "k_returned": 10,
    "ms": 18
  }
}
```

---

## 5. Tool: `rag.search_hybrid`

Hybrid search combining FTS and vectors. Supports two modes:

- **Mode A**: parallel FTS + vector, fuse results (RRF recommended)
- **Mode B**: broad FTS candidate generation, then vector rerank

### 5.1 Request schema (Mode A: fuse)
```json
{
  "query": "json_extract mysql",
  "k": 10,
  "filters": { },
  "mode": "fuse",
  "fuse": {
    "fts_k": 50,
    "vec_k": 50,
    "rrf_k0": 60,
    "w_fts": 1.0,
    "w_vec": 1.0
  }
}
```

### 5.2 Request schema (Mode B: candidates + rerank)
```json
{
  "query": "json_extract mysql",
  "k": 10,
  "filters": { },
  "mode": "fts_then_vec",
  "fts_then_vec": {
    "candidates_k": 200,
    "rerank_k": 50,
    "vec_metric": "cosine"
  }
}
```

### 5.3 Semantics (Mode A)
1. Run FTS top `fts_k`
2. Run vector top `vec_k`
3. Merge candidates by `chunk_id`
4. Compute fused score (RRF recommended)
5. Return top `k`

### 5.4 Semantics (Mode B)
1. Run FTS top `candidates_k`
2. Compute vector similarity within those candidates
   - either by joining candidate chunk_ids to stored vectors, or
   - by embedding candidate chunk text on the fly (not recommended)
3. Return top `k` reranked results
4. Optionally return debug info about candidate stages

### 5.5 Response schema
```json
{
  "results": [
    {
      "chunk_id": "posts:12345#0",
      "doc_id": "posts:12345",
      "source_id": 1,
      "source_name": "stack_posts",
      "score": 0.91,
      "score_fts": 0.74,
      "score_vec": 0.86,
      "title": "How to parse JSON in MySQL 8?",
      "metadata": { "Tags": "<mysql><json>", "Score": "12" },
      "debug": {
        "rank_fts": 3,
        "rank_vec": 6
      }
    }
  ],
  "truncated": false,
  "stats": {
    "mode": "fuse",
    "k_requested": 10,
    "k_returned": 10,
    "ms": 27
  }
}
```

---

## 6. Tool: `rag.get_chunks`

Fetch chunk bodies by chunk_id. This is how agents obtain grounding text.

### 6.1 Request schema
```json
{
  "chunk_ids": ["posts:12345#0", "posts:9876#1"],
  "return": {
    "include_title": true,
    "include_doc_metadata": true,
    "include_chunk_metadata": true
  }
}
```

### 6.2 Response schema
```json
{
  "chunks": [
    {
      "chunk_id": "posts:12345#0",
      "doc_id": "posts:12345",
      "title": "How to parse JSON in MySQL 8?",
      "body": "<p>I tried JSON_EXTRACT...</p>",
      "doc_metadata": { "Tags": "<mysql><json>", "Score": "12" },
      "chunk_metadata": { "chunk_index": 0 }
    }
  ],
  "truncated": false,
  "stats": { "ms": 6 }
}
```

**Hard limit recommendation**
- Cap total returned chunk bytes to a safe maximum (e.g. 1–2 MB).

---

## 7. Tool: `rag.get_docs`

Fetch full canonical documents by doc_id (not chunks). Useful for inspection or compact docs.

### 7.1 Request schema
```json
{
  "doc_ids": ["posts:12345"],
  "return": {
    "include_body": true,
    "include_metadata": true
  }
}
```

### 7.2 Response schema
```json
{
  "docs": [
    {
      "doc_id": "posts:12345",
      "source_id": 1,
      "source_name": "stack_posts",
      "pk_json": { "Id": 12345 },
      "title": "How to parse JSON in MySQL 8?",
      "body": "<p>...</p>",
      "metadata": { "Tags": "<mysql><json>", "Score": "12" }
    }
  ],
  "truncated": false,
  "stats": { "ms": 7 }
}
```

---

## 8. Tool: `rag.fetch_from_source`

Refetch authoritative rows from the source DB using `doc_id` (via pk_json).

### 8.1 Request schema
```json
{
  "doc_ids": ["posts:12345"],
  "columns": ["Id","Title","Body","Tags","Score"],
  "limits": {
    "max_rows": 10,
    "max_bytes": 200000
  }
}
```

### 8.2 Semantics
- Look up doc(s) in `rag_documents` to get `source_id` and `pk_json`
- Resolve source connection from `rag_sources`
- Execute a parameterized query by primary key
- Return requested columns only
- Enforce strict limits

### 8.3 Response schema
```json
{
  "rows": [
    {
      "doc_id": "posts:12345",
      "source_name": "stack_posts",
      "row": {
        "Id": 12345,
        "Title": "How to parse JSON in MySQL 8?",
        "Score": 12
      }
    }
  ],
  "truncated": false,
  "stats": { "ms": 22 }
}
```

**Security note**
- This tool must not allow arbitrary SQL.
- Only allow fetching by primary key and a whitelist of columns.

---

## 9. Tool: `rag.admin.stats` (recommended)

Operational visibility for dashboards and debugging.

### 9.1 Request
```json
{}
```

### 9.2 Response
```json
{
  "sources": [
    {
      "source_id": 1,
      "source_name": "stack_posts",
      "docs": 123456,
      "chunks": 456789,
      "last_sync": null
    }
  ],
  "stats": { "ms": 5 }
}
```

---

## 10. Tool: `rag.admin.sync` (optional in v0; required in v1)

Kicks ingestion for a source or all sources. In v0, ingestion may run as a separate process; in ProxySQL product form, this would trigger an internal job.

### 10.1 Request
```json
{
  "source_names": ["stack_posts"]
}
```

### 10.2 Response
```json
{
  "accepted": true,
  "job_id": "sync-2026-01-19T10:00:00Z"
}
```

---

## 11. Implementation notes (what the coding agent should implement)

1. **Input validation and caps** for every tool.
2. **Consistent filtering** across FTS/vector/hybrid.
3. **Stable scoring semantics** (higher-is-better recommended).
4. **Efficient joins**:
   - vector search returns chunk_ids; join to `rag_chunks`/`rag_documents` for metadata.
5. **Hybrid modes**:
   - Mode A (fuse): implement RRF
   - Mode B (fts_then_vec): candidate set then vector rerank
6. **Error model**:
   - return structured errors with codes (e.g. `INVALID_ARGUMENT`, `LIMIT_EXCEEDED`, `INTERNAL`)
7. **Observability**:
   - return `stats.ms` in responses
   - track tool usage counters and latency histograms

---

## 12. Summary

These MCP tools define a stable retrieval interface:

- Search: `rag.search_fts`, `rag.search_vector`, `rag.search_hybrid`
- Fetch: `rag.get_chunks`, `rag.get_docs`, `rag.fetch_from_source`
- Admin: `rag.admin.stats`, optionally `rag.admin.sync`

