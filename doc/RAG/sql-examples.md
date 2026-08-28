# ProxySQL RAG Index — SQL Examples (FTS, Vectors, Hybrid)

This file provides concrete SQL examples for querying the ProxySQL-hosted SQLite RAG index directly (for debugging, internal dashboards, or SQL-native applications).

The **preferred interface for AI agents** remains MCP tools (`mcp-tools.md`). SQL access should typically be restricted to trusted callers.

Assumed tables:
- `rag_documents`
- `rag_chunks`
- `rag_fts_chunks` (FTS5)
- `rag_vec_chunks` (sqlite3-vec vec0 table)

---

## 0. Common joins and inspection

### 0.1 Inspect one document and its chunks
```sql
SELECT * FROM rag_documents WHERE doc_id = 'posts:12345';
SELECT * FROM rag_chunks WHERE doc_id = 'posts:12345' ORDER BY chunk_index;
```

### 0.2 Use the convenience view (if enabled)
```sql
SELECT * FROM rag_chunk_view WHERE doc_id = 'posts:12345' ORDER BY chunk_id;
```

---

## 1. FTS5 examples

### 1.1 Basic FTS search (top 10)
```sql
SELECT
  f.chunk_id,
  bm25(rag_fts_chunks) AS score_fts_raw
FROM rag_fts_chunks f
WHERE rag_fts_chunks MATCH 'json_extract mysql'
ORDER BY score_fts_raw
LIMIT 10;
```

### 1.2 Join FTS results to chunk text and document metadata
```sql
SELECT
  f.chunk_id,
  bm25(rag_fts_chunks) AS score_fts_raw,
  c.doc_id,
  COALESCE(c.title, d.title) AS title,
  c.body AS chunk_body,
  d.metadata_json AS doc_metadata_json
FROM rag_fts_chunks f
JOIN rag_chunks c ON c.chunk_id = f.chunk_id
JOIN rag_documents d ON d.doc_id = c.doc_id
WHERE rag_fts_chunks MATCH 'json_extract mysql'
  AND c.deleted = 0 AND d.deleted = 0
ORDER BY score_fts_raw
LIMIT 10;
```

### 1.3 Apply a source filter (by source_id)
```sql
SELECT
  f.chunk_id,
  bm25(rag_fts_chunks) AS score_fts_raw
FROM rag_fts_chunks f
JOIN rag_chunks c ON c.chunk_id = f.chunk_id
WHERE rag_fts_chunks MATCH 'replication lag'
  AND c.source_id = 1
ORDER BY score_fts_raw
LIMIT 20;
```

### 1.4 Phrase queries, boolean operators (FTS5)
```sql
-- phrase
SELECT chunk_id FROM rag_fts_chunks
WHERE rag_fts_chunks MATCH '"group replication"'
LIMIT 20;

-- boolean: term1 AND term2
SELECT chunk_id FROM rag_fts_chunks
WHERE rag_fts_chunks MATCH 'mysql AND deadlock'
LIMIT 20;

-- boolean: term1 NOT term2
SELECT chunk_id FROM rag_fts_chunks
WHERE rag_fts_chunks MATCH 'mysql NOT mariadb'
LIMIT 20;
```

---

## 2. Vector search examples (sqlite3-vec)

Vector SQL varies slightly depending on sqlite3-vec build and how you bind vectors.
Below are **two patterns** you can implement in ProxySQL.

### 2.1 Pattern A (recommended): ProxySQL computes embeddings; SQL receives a bound vector
In this pattern, ProxySQL:
1) Computes the query embedding in C++
2) Executes SQL with a bound parameter `:qvec` representing the embedding

A typical “nearest neighbors” query shape is:

```sql
-- PSEUDOCODE: adapt to sqlite3-vec's exact operator/function in your build.
SELECT
  v.chunk_id,
  v.distance AS distance_raw
FROM rag_vec_chunks v
WHERE v.embedding MATCH :qvec
ORDER BY distance_raw
LIMIT 10;
```

Then join to chunks:
```sql
-- PSEUDOCODE: join with content and metadata
SELECT
  v.chunk_id,
  v.distance AS distance_raw,
  c.doc_id,
  c.body AS chunk_body,
  d.metadata_json AS doc_metadata_json
FROM (
  SELECT chunk_id, distance
  FROM rag_vec_chunks
  WHERE embedding MATCH :qvec
  ORDER BY distance
  LIMIT 10
) v
JOIN rag_chunks c ON c.chunk_id = v.chunk_id
JOIN rag_documents d ON d.doc_id = c.doc_id;
```

### 2.2 Pattern B (debug): store a query vector in a temporary table
This is useful when you want to run vector queries manually in SQL without MCP support.

```sql
CREATE TEMP TABLE tmp_query_vec(qvec BLOB);
-- Insert the query vector (float32 array blob). The insertion is usually done by tooling, not manually.
-- INSERT INTO tmp_query_vec VALUES (X'...');

-- PSEUDOCODE: use tmp_query_vec.qvec as the query embedding
SELECT
  v.chunk_id,
  v.distance
FROM rag_vec_chunks v, tmp_query_vec t
WHERE v.embedding MATCH t.qvec
ORDER BY v.distance
LIMIT 10;
```

---

## 3. Hybrid search examples

Hybrid retrieval is best implemented in the MCP layer because it mixes ranking systems and needs careful bounding.
However, you can approximate hybrid behavior using SQL to validate logic.

### 3.1 Hybrid Mode A: Parallel FTS + Vector then fuse (RRF)

#### Step 1: FTS top 50 (ranked)
```sql
WITH fts AS (
  SELECT
    f.chunk_id,
    bm25(rag_fts_chunks) AS score_fts_raw
  FROM rag_fts_chunks f
  WHERE rag_fts_chunks MATCH :fts_query
  ORDER BY score_fts_raw
  LIMIT 50
)
SELECT * FROM fts;
```

#### Step 2: Vector top 50 (ranked)
```sql
WITH vec AS (
  SELECT
    v.chunk_id,
    v.distance AS distance_raw
  FROM rag_vec_chunks v
  WHERE v.embedding MATCH :qvec
  ORDER BY v.distance
  LIMIT 50
)
SELECT * FROM vec;
```

#### Step 3: Fuse via Reciprocal Rank Fusion (RRF)
In SQL you need ranks. SQLite supports window functions in modern builds.

```sql
WITH
fts AS (
  SELECT
    f.chunk_id,
    bm25(rag_fts_chunks) AS score_fts_raw,
    ROW_NUMBER() OVER (ORDER BY bm25(rag_fts_chunks)) AS rank_fts
  FROM rag_fts_chunks f
  WHERE rag_fts_chunks MATCH :fts_query
  LIMIT 50
),
vec AS (
  SELECT
    v.chunk_id,
    v.distance AS distance_raw,
    ROW_NUMBER() OVER (ORDER BY v.distance) AS rank_vec
  FROM rag_vec_chunks v
  WHERE v.embedding MATCH :qvec
  LIMIT 50
),
merged AS (
  SELECT
    COALESCE(fts.chunk_id, vec.chunk_id) AS chunk_id,
    fts.rank_fts,
    vec.rank_vec,
    fts.score_fts_raw,
    vec.distance_raw
  FROM fts
  FULL OUTER JOIN vec ON vec.chunk_id = fts.chunk_id
),
rrf AS (
  SELECT
    chunk_id,
    score_fts_raw,
    distance_raw,
    rank_fts,
    rank_vec,
    (1.0 / (60.0 + COALESCE(rank_fts, 1000000))) +
    (1.0 / (60.0 + COALESCE(rank_vec, 1000000))) AS score_rrf
  FROM merged
)
SELECT
  r.chunk_id,
  r.score_rrf,
  c.doc_id,
  c.body AS chunk_body
FROM rrf r
JOIN rag_chunks c ON c.chunk_id = r.chunk_id
ORDER BY r.score_rrf DESC
LIMIT 10;
```

**Important**: SQLite does not support `FULL OUTER JOIN` directly in all builds.
For production, implement the merge/fuse in C++ (MCP layer). This SQL is illustrative.

### 3.2 Hybrid Mode B: Broad FTS then vector rerank (candidate generation)

#### Step 1: FTS candidate set (top 200)
```sql
WITH candidates AS (
  SELECT
    f.chunk_id,
    bm25(rag_fts_chunks) AS score_fts_raw
  FROM rag_fts_chunks f
  WHERE rag_fts_chunks MATCH :fts_query
  ORDER BY score_fts_raw
  LIMIT 200
)
SELECT * FROM candidates;
```

#### Step 2: Vector rerank within candidates
Conceptually:
- Join candidates to `rag_vec_chunks` and compute distance to `:qvec`
- Keep top 10

```sql
WITH candidates AS (
  SELECT
    f.chunk_id
  FROM rag_fts_chunks f
  WHERE rag_fts_chunks MATCH :fts_query
  ORDER BY bm25(rag_fts_chunks)
  LIMIT 200
),
reranked AS (
  SELECT
    v.chunk_id,
    v.distance AS distance_raw
  FROM rag_vec_chunks v
  JOIN candidates c ON c.chunk_id = v.chunk_id
  WHERE v.embedding MATCH :qvec
  ORDER BY v.distance
  LIMIT 10
)
SELECT
  r.chunk_id,
  r.distance_raw,
  ch.doc_id,
  ch.body
FROM reranked r
JOIN rag_chunks ch ON ch.chunk_id = r.chunk_id;
```

As above, the exact `MATCH :qvec` syntax may need adaptation to your sqlite3-vec build; implement vector query execution in C++ and keep SQL as internal glue.

---

## 4. Common “application-friendly” queries

### 4.1 Return doc_id + score + title only (no bodies)
```sql
SELECT
  f.chunk_id,
  c.doc_id,
  COALESCE(c.title, d.title) AS title,
  bm25(rag_fts_chunks) AS score_fts_raw
FROM rag_fts_chunks f
JOIN rag_chunks c ON c.chunk_id = f.chunk_id
JOIN rag_documents d ON d.doc_id = c.doc_id
WHERE rag_fts_chunks MATCH :q
ORDER BY score_fts_raw
LIMIT 20;
```

### 4.2 Return top doc_ids (deduplicate by doc_id)
```sql
WITH ranked_chunks AS (
  SELECT
    c.doc_id,
    bm25(rag_fts_chunks) AS score_fts_raw
  FROM rag_fts_chunks f
  JOIN rag_chunks c ON c.chunk_id = f.chunk_id
  WHERE rag_fts_chunks MATCH :q
  ORDER BY score_fts_raw
  LIMIT 200
)
SELECT doc_id, MIN(score_fts_raw) AS best_score
FROM ranked_chunks
GROUP BY doc_id
ORDER BY best_score
LIMIT 20;
```

---

## 5. Practical guidance

- Use SQL mode mainly for debugging and internal tooling.
- Prefer MCP tools for agent interaction:
  - stable schemas
  - strong guardrails
  - consistent hybrid scoring
- Implement hybrid fusion in C++ (not in SQL) to avoid dialect limitations and to keep scoring correct.
