-- ============================================================
-- ProxySQL RAG Index Schema (SQLite)
-- v0: documents + chunks + FTS5 + sqlite3-vec embeddings
-- ============================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;

-- ============================================================
-- 1) rag_sources: control plane
-- Defines where to fetch from + how to transform + chunking.
-- ============================================================
CREATE TABLE IF NOT EXISTS rag_sources (
  source_id        INTEGER PRIMARY KEY,
  name             TEXT NOT NULL UNIQUE,     -- e.g. "stack_posts"
  enabled          INTEGER NOT NULL DEFAULT 1,

  -- Where to retrieve from (PoC: connect directly; later can be "via ProxySQL")
  backend_type     TEXT NOT NULL,            -- "mysql" | "postgres" | ...
  backend_host     TEXT NOT NULL,
  backend_port     INTEGER NOT NULL,
  backend_user     TEXT NOT NULL,
  backend_pass     TEXT NOT NULL,
  backend_db       TEXT NOT NULL,            -- database/schema name

  table_name       TEXT NOT NULL,            -- e.g. "posts"
  pk_column        TEXT NOT NULL,            -- e.g. "Id"

  -- Optional: restrict ingestion; appended to SELECT as WHERE <where_sql>
  where_sql        TEXT,                     -- e.g. "PostTypeId IN (1,2)"

  -- REQUIRED: mapping from source row -> rag_documents fields
  -- JSON spec describing doc_id, title/body concat, metadata pick/rename, etc.
  doc_map_json     TEXT NOT NULL,

  -- REQUIRED: chunking strategy (enabled, chunk_size, overlap, etc.)
  chunking_json    TEXT NOT NULL,

  -- Optional: embedding strategy (how to build embedding input text)
  -- In v0 you can keep it NULL/empty; define later without schema changes.
  embedding_json   TEXT,

  created_at       INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at       INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_rag_sources_enabled
  ON rag_sources(enabled);

CREATE INDEX IF NOT EXISTS idx_rag_sources_backend
  ON rag_sources(backend_type, backend_host, backend_port, backend_db, table_name);


-- ============================================================
-- 2) rag_documents: canonical documents
-- One document per source row (e.g. one per posts.Id).
-- ============================================================
CREATE TABLE IF NOT EXISTS rag_documents (
  doc_id         TEXT PRIMARY KEY,          -- stable: e.g. "posts:12345"
  source_id      INTEGER NOT NULL REFERENCES rag_sources(source_id),
  source_name    TEXT NOT NULL,             -- copy of rag_sources.name for convenience
  pk_json        TEXT NOT NULL,             -- e.g. {"Id":12345}

  title          TEXT,
  body           TEXT,
  metadata_json  TEXT NOT NULL DEFAULT '{}', -- JSON object

  updated_at     INTEGER NOT NULL DEFAULT (unixepoch()),
  deleted        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_rag_documents_source_updated
  ON rag_documents(source_id, updated_at);

CREATE INDEX IF NOT EXISTS idx_rag_documents_source_deleted
  ON rag_documents(source_id, deleted);


-- ============================================================
-- 3) rag_chunks: chunked content
-- The unit we index in FTS and vectors.
-- ============================================================
CREATE TABLE IF NOT EXISTS rag_chunks (
  chunk_id       TEXT PRIMARY KEY,          -- e.g. "posts:12345#0"
  doc_id         TEXT NOT NULL REFERENCES rag_documents(doc_id),
  source_id      INTEGER NOT NULL REFERENCES rag_sources(source_id),

  chunk_index    INTEGER NOT NULL,          -- 0..N-1
  title          TEXT,
  body           TEXT NOT NULL,

  -- Optional per-chunk metadata (e.g. offsets, has_code, section label)
  metadata_json  TEXT NOT NULL DEFAULT '{}',

  updated_at     INTEGER NOT NULL DEFAULT (unixepoch()),
  deleted        INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_rag_chunks_doc_idx
  ON rag_chunks(doc_id, chunk_index);

CREATE INDEX IF NOT EXISTS idx_rag_chunks_source_doc
  ON rag_chunks(source_id, doc_id);

CREATE INDEX IF NOT EXISTS idx_rag_chunks_deleted
  ON rag_chunks(deleted);


-- ============================================================
-- 4) rag_fts_chunks: FTS5 index (contentless)
-- Maintained explicitly by the ingester.
-- Notes:
--   - chunk_id is stored but UNINDEXED.
--   - Use bm25(rag_fts_chunks) for ranking.
-- ============================================================
CREATE VIRTUAL TABLE IF NOT EXISTS rag_fts_chunks
USING fts5(
  chunk_id UNINDEXED,
  title,
  body,
  tokenize = 'unicode61'
);


-- ============================================================
-- 5) rag_vec_chunks: sqlite3-vec index
-- Stores embeddings per chunk for vector search.
--
-- IMPORTANT:
--   - dimension must match your embedding model (example: 1536).
--   - metadata columns are included to help join/filter.
-- ============================================================
CREATE VIRTUAL TABLE IF NOT EXISTS rag_vec_chunks
USING vec0(
  embedding  float[1536],   -- change if you use another dimension
  chunk_id   TEXT,          -- join key back to rag_chunks
  doc_id     TEXT,          -- optional convenience
  source_id  INTEGER,       -- optional convenience
  updated_at INTEGER        -- optional convenience
);

-- Optional: convenience view for debugging / SQL access patterns
CREATE VIEW IF NOT EXISTS rag_chunk_view AS
SELECT
  c.chunk_id,
  c.doc_id,
  c.source_id,
  d.source_name,
  d.pk_json,
  COALESCE(c.title, d.title) AS title,
  c.body,
  d.metadata_json AS doc_metadata_json,
  c.metadata_json AS chunk_metadata_json,
  c.updated_at
FROM rag_chunks c
JOIN rag_documents d ON d.doc_id = c.doc_id
WHERE c.deleted = 0 AND d.deleted = 0;


-- ============================================================
-- 6) (Optional) sync state placeholder for later incremental ingestion
-- Not used in v0, but reserving it avoids later schema churn.
-- ============================================================
CREATE TABLE IF NOT EXISTS rag_sync_state (
  source_id     INTEGER PRIMARY KEY REFERENCES rag_sources(source_id),
  mode          TEXT NOT NULL DEFAULT 'poll', -- 'poll' | 'cdc'
  cursor_json   TEXT NOT NULL DEFAULT '{}',   -- watermark/checkpoint
  last_ok_at    INTEGER,
  last_error    TEXT
);

