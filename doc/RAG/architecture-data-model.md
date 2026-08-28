# ProxySQL RAG Index — Data Model & Ingestion Architecture (v0 Blueprint)

This document explains the SQLite data model used to turn relational tables (e.g. MySQL `posts`) into a retrieval-friendly index hosted inside ProxySQL. It focuses on:

- What each SQLite table does
- How tables relate to each other
- How `rag_sources` defines **explicit mapping rules** (no guessing)
- How ingestion transforms rows into documents and chunks
- How FTS and vector indexes are maintained
- What evolves later for incremental sync and updates

---

## 1. Goal and core idea

Relational databases are excellent for structured queries, but RAG-style retrieval needs:

- Fast keyword search (error messages, identifiers, tags)
- Fast semantic search (similar meaning, paraphrased questions)
- A stable way to “refetch the authoritative data” from the source DB

The model below implements a **canonical document layer** inside ProxySQL:

1. Ingest selected rows from a source database (MySQL, PostgreSQL, etc.)
2. Convert each row into a **document** (title/body + metadata)
3. Split long bodies into **chunks**
4. Index chunks in:
   - **FTS5** for keyword search
   - **sqlite3-vec** for vector similarity
5. Serve retrieval through stable APIs (MCP or SQL), independent of where indexes physically live in the future

---

## 2. The SQLite tables (what they are and why they exist)

### 2.1 `rag_sources` — control plane: “what to ingest and how”

**Purpose**
- Defines each ingestion source (a table or view in an external DB)
- Stores *explicit* transformation rules:
  - which columns become `title`, `body`
  - which columns go into `metadata_json`
  - how to build `doc_id`
- Stores chunking strategy and embedding strategy configuration

**Key columns**
- `backend_*`: how to connect (v0 connects directly; later may be “via ProxySQL”)
- `table_name`, `pk_column`: what to ingest
- `where_sql`: optional restriction (e.g. only questions)
- `doc_map_json`: mapping rules (required)
- `chunking_json`: chunking rules (required)
- `embedding_json`: embedding rules (optional)

**Important**: `rag_sources` is the **only place** that defines mapping logic.  
A general-purpose ingester must never “guess” which fields belong to `body` or metadata.

---

### 2.2 `rag_documents` — canonical documents: “one per source row”

**Purpose**
- Represents the canonical document created from a single source row.
- Stores:
  - a stable identifier (`doc_id`)
  - a refetch pointer (`pk_json`)
  - document text (`title`, `body`)
  - structured metadata (`metadata_json`)

**Why store full `body` here?**
- Enables re-chunking later without re-fetching from the source DB.
- Makes debugging and inspection easier.
- Supports future update detection and diffing.

**Key columns**
- `doc_id` (PK): stable across runs and machines (e.g. `"posts:12345"`)
- `source_id`: ties back to `rag_sources`
- `pk_json`: how to refetch the authoritative row later (e.g. `{"Id":12345}`)
- `title`, `body`: canonical text
- `metadata_json`: non-text signals used for filters/boosting
- `updated_at`, `deleted`: lifecycle fields for incremental sync later

---

### 2.3 `rag_chunks` — retrieval units: “one or many per document”

**Purpose**
- Stores chunked versions of a document’s text.
- Retrieval and embeddings are performed at the chunk level for better quality.

**Why chunk at all?**
- Long bodies reduce retrieval quality:
  - FTS returns large documents where only a small part is relevant
  - Vector embeddings of large texts smear multiple topics together
- Chunking yields:
  - better precision
  - better citations (“this chunk”) and smaller context
  - cheaper updates (only re-embed changed chunks later)

**Key columns**
- `chunk_id` (PK): stable, derived from doc_id + chunk index (e.g. `"posts:12345#0"`)
- `doc_id` (FK): parent document
- `source_id`: convenience for filtering without joining documents
- `chunk_index`: 0..N-1
- `title`, `body`: chunk text (often title repeated for context)
- `metadata_json`: optional chunk-level metadata (offsets, “has_code”, section label)
- `updated_at`, `deleted`: lifecycle for later incremental sync

---

### 2.4 `rag_fts_chunks` — FTS5 index (contentless)

**Purpose**
- Keyword search index for chunks.
- Best for:
  - exact terms
  - identifiers
  - error messages
  - tags and code tokens (depending on tokenization)

**Design choice: contentless FTS**
- The FTS virtual table does not automatically mirror `rag_chunks`.
- The ingester explicitly inserts into FTS as chunks are created.
- This makes ingestion deterministic and avoids surprises when chunk bodies change later.

**Stored fields**
- `chunk_id` (unindexed, acts like a row identifier)
- `title`, `body` (indexed)

---

### 2.5 `rag_vec_chunks` — vector index (sqlite3-vec)

**Purpose**
- Semantic similarity search over chunks.
- Each chunk has a vector embedding.

**Key columns**
- `embedding float[DIM]`: embedding vector (DIM must match your model)
- `chunk_id`: join key to `rag_chunks`
- Optional metadata columns:
  - `doc_id`, `source_id`, `updated_at`
  - These help filtering and joining and are valuable for performance.

**Note**
- The ingester decides what text is embedded (chunk body alone, or “Title + Tags + Body chunk”).

---

### 2.6 Optional convenience objects
- `rag_chunk_view`: joins `rag_chunks` with `rag_documents` for debugging/inspection
- `rag_sync_state`: reserved for incremental sync later (not used in v0)

---

## 3. Table relationships (the graph)

Think of this as a data pipeline graph:

```text
rag_sources
   (defines mapping + chunking + embedding)
        |
        v
rag_documents  (1 row per source row)
        |
        v
rag_chunks     (1..N chunks per document)
     /     \
    v       v
rag_fts    rag_vec
```

**Cardinality**
- `rag_sources (1) -> rag_documents (N)`
- `rag_documents (1) -> rag_chunks (N)`
- `rag_chunks (1) -> rag_fts_chunks (1)` (insertion done by ingester)
- `rag_chunks (1) -> rag_vec_chunks (0/1+)` (0 if embeddings disabled; 1 typically)

---

## 4. How mapping is defined (no guessing)

### 4.1 Why `doc_map_json` exists
A general-purpose system cannot infer that:
- `posts.Body` should become document body
- `posts.Title` should become title
- `Score`, `Tags`, `CreationDate`, etc. should become metadata
- Or how to concatenate fields

Therefore, `doc_map_json` is required.

### 4.2 `doc_map_json` structure (v0)
`doc_map_json` defines:

- `doc_id.format`: string template with `{ColumnName}` placeholders
- `title.concat`: concatenation spec
- `body.concat`: concatenation spec
- `metadata.pick`: list of column names to include in metadata JSON
- `metadata.rename`: mapping of old key -> new key (useful for typos or schema differences)

**Concatenation parts**
- `{"col":"Column"}` — appends the column value (if present)
- `{"lit":"..."} ` — appends a literal string

Example (posts-like):

```json
{
  "doc_id": { "format": "posts:{Id}" },
  "title":  { "concat": [ { "col": "Title" } ] },
  "body":   { "concat": [ { "col": "Body" } ] },
  "metadata": {
    "pick": ["Id","PostTypeId","Tags","Score","CreaionDate"],
    "rename": {"CreaionDate":"CreationDate"}
  }
}
```

---

## 5. Chunking strategy definition

### 5.1 Why chunking is configured per source
Different tables need different chunking:
- StackOverflow `Body` may be long -> chunking recommended
- Small “reference” tables may not need chunking at all

Thus chunking is stored in `rag_sources.chunking_json`.

### 5.2 `chunking_json` structure (v0)
v0 supports **chars-based** chunking (simple, robust).

```json
{
  "enabled": true,
  "unit": "chars",
  "chunk_size": 4000,
  "overlap": 400,
  "min_chunk_size": 800
}
```

**Behavior**
- If `body.length <= chunk_size` -> one chunk
- Else chunks of `chunk_size` with `overlap`
- Avoid tiny final chunks by appending the tail to the previous chunk if below `min_chunk_size`

**Why overlap matters**
- Prevents splitting a key sentence or code snippet across boundaries
- Improves both FTS and semantic retrieval consistency

---

## 6. Embedding strategy definition (where it fits in the model)

### 6.1 Why embeddings are per chunk
- Better retrieval precision
- Smaller context per match
- Allows partial updates later (only re-embed changed chunks)

### 6.2 `embedding_json` structure (v0)
```json
{
  "enabled": true,
  "dim": 1536,
  "model": "text-embedding-3-large",
  "input": { "concat": [
    {"col":"Title"},
    {"lit":"\nTags: "}, {"col":"Tags"},
    {"lit":"\n\n"},
    {"chunk_body": true}
  ]}
}
```

**Meaning**
- Build embedding input text from:
  - title
  - tags (as plain text)
  - chunk body

This improves semantic retrieval for question-like content without embedding numeric metadata.

---

## 7. Ingestion lifecycle (step-by-step)

For each enabled `rag_sources` entry:

1. **Connect** to source DB using `backend_*`
2. **Select rows** from `table_name` (and optional `where_sql`)
   - Select only needed columns determined by `doc_map_json` and `embedding_json`
3. For each row:
   - Build `doc_id` using `doc_map_json.doc_id.format`
   - Build `pk_json` from `pk_column`
   - Build `title` using `title.concat`
   - Build `body` using `body.concat`
   - Build `metadata_json` using `metadata.pick` and `metadata.rename`
4. **Skip** if `doc_id` already exists (v0 behavior)
5. Insert into `rag_documents`
6. Chunk `body` using `chunking_json`
7. For each chunk:
   - Insert into `rag_chunks`
   - Insert into `rag_fts_chunks`
   - If embeddings enabled:
     - Build embedding input text using `embedding_json.input`
     - Compute embedding
     - Insert into `rag_vec_chunks`
8. Commit (ideally in a transaction for performance)

---

## 8. What changes later (incremental sync and updates)

v0 is “insert-only and skip-existing.”  
Product-grade ingestion requires:

### 8.1 Detecting changes
Options:
- Watermark by `LastActivityDate` / `updated_at` column
- Hash (e.g. `sha256(title||body||metadata)`) stored in documents table
- Compare chunk hashes to re-embed only changed chunks

### 8.2 Updating and deleting
Needs:
- Upsert documents
- Delete or mark `deleted=1` when source row deleted
- Rebuild chunks and indexes when body changes
- Maintain FTS rows:
  - delete old chunk rows from FTS
  - insert updated chunk rows

### 8.3 Checkpoints
Use `rag_sync_state` to store:
- last ingested timestamp
- GTID/LSN for CDC
- or a monotonic PK watermark

The current schema already includes:
- `updated_at` and `deleted`
- `rag_sync_state` placeholder

So incremental sync can be added without breaking the data model.

---

## 9. Practical example: mapping `posts` table

Given a MySQL `posts` row:

- `Id = 12345`
- `Title = "How to parse JSON in MySQL 8?"`
- `Body = "<p>I tried JSON_EXTRACT...</p>"`
- `Tags = "<mysql><json>"`
- `Score = 12`

With mapping:

- `doc_id = "posts:12345"`
- `title = Title`
- `body = Body`
- `metadata_json` includes `{ "Tags": "...", "Score": "12", ... }`
- chunking splits body into:
  - `posts:12345#0`, `posts:12345#1`, etc.
- FTS is populated with the chunk text
- vectors are stored per chunk

---

## 10. Summary

This data model separates concerns cleanly:

- `rag_sources` defines *policy* (what/how to ingest)
- `rag_documents` defines canonical *identity and refetch pointer*
- `rag_chunks` defines retrieval *units*
- `rag_fts_chunks` defines keyword search
- `rag_vec_chunks` defines semantic search

This separation makes the system:
- general purpose (works for many schemas)
- deterministic (no magic inference)
- extensible to incremental sync, external indexes, and richer hybrid retrieval

