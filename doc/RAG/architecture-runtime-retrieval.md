# ProxySQL RAG Engine — Runtime Retrieval Architecture (v0 Blueprint)

This document describes how ProxySQL becomes a **RAG retrieval engine** at runtime. The companion document (Data Model & Ingestion) explains how content enters the SQLite index. This document explains how content is **queried**, how results are **returned to agents/applications**, and how **hybrid retrieval** works in practice.

It is written as an implementation blueprint for ProxySQL (and its MCP server) and assumes the SQLite schema contains:

- `rag_sources` (control plane)
- `rag_documents` (canonical docs)
- `rag_chunks` (retrieval units)
- `rag_fts_chunks` (FTS5)
- `rag_vec_chunks` (sqlite3-vec vectors)

---

## 1. The runtime role of ProxySQL in a RAG system

ProxySQL becomes a RAG runtime by providing four capabilities in one bounded service:

1. **Retrieval Index Host**
   - Hosts the SQLite index and search primitives (FTS + vectors).
   - Offers deterministic query semantics and strict budgets.

2. **Orchestration Layer**
   - Implements search flows (FTS, vector, hybrid, rerank).
   - Applies filters, caps, and result shaping.

3. **Stable API Surface (MCP-first)**
   - LLM agents call MCP tools (not raw SQL).
   - Tool contracts remain stable even if internal storage changes.

4. **Authoritative Row Refetch Gateway**
   - After retrieval returns `doc_id` / `pk_json`, ProxySQL can refetch the authoritative row from the source DB on-demand (optional).
   - This avoids returning stale or partial data when the full row is needed.

In production terms, this is not “ProxySQL as a general search engine.” It is a **bounded retrieval service** colocated with database access logic.

---

## 2. High-level query flow (agent-centric)

A typical RAG flow has two phases:

### Phase A — Retrieval (fast, bounded, cheap)
- Query the index to obtain a small number of relevant chunks (and their parent doc identity).
- Output includes `chunk_id`, `doc_id`, `score`, and small metadata.

### Phase B — Fetch (optional, authoritative, bounded)
- If the agent needs full context or structured fields, it refetches the authoritative row from the source DB using `pk_json`.
- This avoids scanning large tables and avoids shipping huge payloads in Phase A.

**Canonical flow**
1. `rag.search_hybrid(query, filters, k)` → returns top chunk ids and scores
2. `rag.get_chunks(chunk_ids)` → returns chunk text for prompt grounding/citations
3. Optional: `rag.fetch_from_source(doc_id)` → returns full row or selected columns

---

## 3. Runtime interfaces: MCP vs SQL

ProxySQL should support two “consumption modes”:

### 3.1 MCP tools (preferred for AI agents)
- Strict limits and predictable response schemas.
- Tools return structured results and avoid SQL injection concerns.
- Agents do not need direct DB access.

### 3.2 SQL access (for standard applications / debugging)
- Applications may connect to ProxySQL’s SQLite admin interface (or a dedicated port) and issue SQL.
- Useful for:
  - internal dashboards
  - troubleshooting
  - non-agent apps that want retrieval but speak SQL

**Principle**
- MCP is the stable, long-term interface.
- SQL is optional and may be restricted to trusted callers.

---

## 4. Retrieval primitives

### 4.1 FTS retrieval (keyword / exact match)

FTS5 is used for:
- error messages
- identifiers and function names
- tags and exact terms
- “grep-like” queries

**Typical output**
- `chunk_id`, `score_fts`, optional highlights/snippets

**Ranking**
- `bm25(rag_fts_chunks)` is the default. It is fast and effective for term queries.

### 4.2 Vector retrieval (semantic similarity)

Vector search is used for:
- paraphrased questions
- semantic similarity (“how to do X” vs “best way to achieve X”)
- conceptual matching that is poor with keyword-only search

**Typical output**
- `chunk_id`, `score_vec` (distance/similarity), plus join metadata

**Important**
- Vectors are generally computed per chunk.
- Filters are applied via `source_id` and joins to `rag_chunks` / `rag_documents`.

---

## 5. Hybrid retrieval patterns (two recommended modes)

Hybrid retrieval combines FTS and vector search for better quality than either alone. Two concrete modes should be implemented because they solve different problems.

### Mode 1 — “Best of both” (parallel FTS + vector; fuse results)
**Use when**
- the query may contain both exact tokens (e.g. error messages) and semantic intent

**Flow**
1. Run FTS top-N (e.g. N=50)
2. Run vector top-N (e.g. N=50)
3. Merge results by `chunk_id`
4. Score fusion (recommended): Reciprocal Rank Fusion (RRF)
5. Return top-k (e.g. k=10)

**Why RRF**
- Robust without score calibration
- Works across heterogeneous score ranges (bm25 vs cosine distance)

**RRF formula**
- For each candidate chunk:
  - `score = w_fts/(k0 + rank_fts) + w_vec/(k0 + rank_vec)`
  - Typical: `k0=60`, `w_fts=1.0`, `w_vec=1.0`

### Mode 2 — “Broad FTS then vector refine” (candidate generation + rerank)
**Use when**
- you want strong precision anchored to exact term matches
- you want to avoid vector search over the entire corpus

**Flow**
1. Run broad FTS query top-M (e.g. M=200)
2. Fetch chunk texts for those candidates
3. Compute vector similarity of query embedding to candidate embeddings
4. Return top-k

This mode behaves like a two-stage retrieval pipeline:
- Stage 1: cheap recall (FTS)
- Stage 2: precise semantic rerank within candidates

---

## 6. Filters, constraints, and budgets (blast-radius control)

A RAG retrieval engine must be bounded. ProxySQL should enforce limits at the MCP layer and ideally also at SQL helper functions.

### 6.1 Hard caps (recommended defaults)
- Maximum `k` returned: 50
- Maximum candidates for broad-stage: 200–500
- Maximum query length: e.g. 2–8 KB
- Maximum response bytes: e.g. 1–5 MB
- Maximum execution time per request: e.g. 50–250 ms for retrieval, 1–2 s for fetch

### 6.2 Filter semantics
Filters should be applied consistently across retrieval modes.

Common filters:
- `source_id` or `source_name`
- tag include/exclude (via metadata_json parsing or pre-extracted tag fields later)
- post type (question vs answer)
- minimum score
- time range (creation date / last activity)

Implementation note:
- v0 stores metadata in JSON; filtering can be implemented in MCP layer or via SQLite JSON functions (if enabled).
- For performance, later versions should denormalize key metadata into dedicated columns or side tables.

---

## 7. Result shaping and what the caller receives

A retrieval response must be designed for downstream LLM usage:

### 7.1 Retrieval results (Phase A)
Return a compact list of “evidence candidates”:

- `chunk_id`
- `doc_id`
- `scores` (fts, vec, fused)
- short `title`
- minimal metadata (source, tags, timestamp, etc.)

Do **not** return full bodies by default; that is what `rag.get_chunks` is for.

### 7.2 Chunk fetch results (Phase A.2)
`rag.get_chunks(chunk_ids)` returns:

- `chunk_id`, `doc_id`
- `title`
- `body` (chunk text)
- optionally a snippet/highlight for display

### 7.3 Source refetch results (Phase B)
`rag.fetch_from_source(doc_id)` returns:
- either the full row
- or a selected subset of columns (recommended)

This is the “authoritative fetch” boundary that prevents stale/partial index usage from being a correctness problem.

---

## 8. SQL examples (runtime extraction)

These are not the preferred agent interface, but they are crucial for debugging and for SQL-native apps.

### 8.1 FTS search (top 10)
```sql
SELECT
  f.chunk_id,
  bm25(rag_fts_chunks) AS score_fts
FROM rag_fts_chunks f
WHERE rag_fts_chunks MATCH 'json_extract mysql'
ORDER BY score_fts
LIMIT 10;
```

Join to fetch text:
```sql
SELECT
  f.chunk_id,
  bm25(rag_fts_chunks) AS score_fts,
  c.doc_id,
  c.body
FROM rag_fts_chunks f
JOIN rag_chunks c ON c.chunk_id = f.chunk_id
WHERE rag_fts_chunks MATCH 'json_extract mysql'
ORDER BY score_fts
LIMIT 10;
```

### 8.2 Vector search (top 10)
Vector syntax depends on how you expose query vectors. A typical pattern is:

1) Bind a query vector into a function / parameter
2) Use `rag_vec_chunks` to return nearest neighbors

Example shape (conceptual):
```sql
-- Pseudocode: nearest neighbors for :query_embedding
SELECT
  v.chunk_id,
  v.distance
FROM rag_vec_chunks v
WHERE v.embedding MATCH :query_embedding
ORDER BY v.distance
LIMIT 10;
```

In production, ProxySQL MCP will typically compute the query embedding and call SQL internally with a bound parameter.

---

## 9. MCP tools (runtime API surface)

This document does not define full schemas (that is in `mcp-tools.md`), but it defines what each tool must do.

### 9.1 Retrieval
- `rag.search_fts(query, filters, k)`
- `rag.search_vector(query_text | query_embedding, filters, k)`
- `rag.search_hybrid(query, mode, filters, k, params)`
  - Mode 1: parallel + RRF fuse
  - Mode 2: broad FTS candidates + vector rerank

### 9.2 Fetch
- `rag.get_chunks(chunk_ids)`
- `rag.get_docs(doc_ids)`
- `rag.fetch_from_source(doc_ids | pk_json, columns?, limits?)`

**MCP-first principle**
- Agents do not see SQLite schema or SQL.
- MCP tools remain stable even if you move index storage out of ProxySQL later.

---

## 10. Operational considerations

### 10.1 Dedicated ProxySQL instance
Run GenAI retrieval in a dedicated ProxySQL instance to reduce blast radius:
- independent CPU/memory budgets
- independent configuration and rate limits
- independent failure domain

### 10.2 Observability and metrics (minimum)
- count of docs/chunks per source
- query counts by tool and source
- p50/p95 latency for:
  - FTS
  - vector
  - hybrid
  - refetch
- dropped/limited requests (rate limit hit, cap exceeded)
- error rate and error categories

### 10.3 Safety controls
- strict upper bounds on `k` and candidate sizes
- strict timeouts
- response size caps
- optional allowlists for sources accessible to agents
- tenant boundaries via filters (strongly recommended for multi-tenant)

---

## 11. Recommended “v0-to-v1” evolution checklist

### v0 (PoC)
- ingestion to docs/chunks
- FTS search
- vector search (if embedding pipeline available)
- simple hybrid search
- chunk fetch
- manual/limited source refetch

### v1 (product hardening)
- incremental sync checkpoints (`rag_sync_state`)
- update detection (hashing/versioning)
- delete handling
- robust hybrid search:
  - RRF fuse
  - candidate-generation rerank
- stronger filtering semantics (denormalized metadata columns)
- quotas, rate limits, per-source budgets
- full MCP tool contracts + tests

---

## 12. Summary

At runtime, ProxySQL RAG retrieval is implemented as:

- **Index query** (FTS/vector/hybrid) returning a small set of chunk IDs
- **Chunk fetch** returning the text that the LLM will ground on
- Optional **authoritative refetch** from the source DB by primary key
- Strict limits and consistent filtering to keep the service bounded

