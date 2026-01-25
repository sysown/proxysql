# RAG Ingestion Tool - Usage Guide

## Overview

`rag_ingest` reads data from MySQL, transforms it, chunks documents, builds full-text search indexes, and optionally generates vector embeddings for semantic search.

---

## Quick Start

```bash
# 1. Build the tool (from repository root)
cd RAG_POC
make

# 2. Create a RAG database with schema
./rag_ingest /path/to/rag.db  # First run creates schema automatically

# 3. Configure your data source (via SQL)
sqlite3 /path/to/rag.db < setup_source.sql

# 4. Run ingestion
./rag_ingest /path/to/rag.db
```

---

## Step-by-Step Guide

### Step 1: Create the RAG Database

```bash
# From repository root
cd RAG_POC

# Create empty database and load schema
sqlite3 rag_index.db < schema.sql

# Verify schema loaded
sqlite3 rag_index.db ".tables"
# Expected output:
# rag_chunks           rag_fts_chunks       rag_sources
# rag_documents        rag_sync_state       rag_vec_chunks
```

### Step 2: Configure Your Data Source

Insert a source configuration into `rag_sources`:

```sql
-- Minimal configuration (no chunking, no embeddings)
INSERT INTO rag_sources (
    name,
    enabled,
    backend_type,
    host,
    port,
    user,
    pass,
    db,
    table_name,
    pk_column
) VALUES (
    'my_mysql_data',      -- Human-readable name
    1,                    -- enabled (1=enabled, 0=disabled)
    'mysql',              -- backend type (only 'mysql' supported)
    '127.0.0.1',          -- MySQL host
    3306,                 -- MySQL port
    'root',               -- MySQL username
    'mypassword',         -- MySQL password
    'my_database',        -- MySQL database name
    'posts',              -- Table name to read from
    'Id'                  -- Primary key column
);
```

### Step 3: Run Ingestion

```bash
./rag_ingest rag_index.db
```

**What happens:**
1. Connects to MySQL using credentials from `rag_sources`
2. Executes `SELECT * FROM posts`
3. For each row:
   - Creates a document in `rag_documents`
   - Creates a chunk in `rag_chunks` (1 per document when chunking disabled)
   - Creates FTS entry in `rag_fts_chunks`
4. Updates `rag_sync_state` with the max primary key value

---

## Common Configurations

### Configuration 1: Basic Ingestion (No Chunking, No Embeddings)

```sql
INSERT INTO rag_sources (name, enabled, backend_type, host, port, user, pass, db, table_name, pk_column)
VALUES ('basic_source', 1, 'mysql', '127.0.0.1', 3306, 'root', 'pass', 'mydb', 'posts', 'Id');

-- chunking_json and embedding_json default to disabled
```

**Result:** 1 chunk per document, FTS only, no vectors.

---

### Configuration 2: Enable Chunking

Chunking splits long documents into smaller pieces for better retrieval precision.

```sql
INSERT INTO rag_sources (name, enabled, backend_type, host, port, user, pass, db, table_name, pk_column, chunking_json)
VALUES (
    'chunked_source',
    1,
    'mysql',
    '127.0.0.1',
    3306,
    'root',
    'pass',
    'mydb',
    'posts',
    'Id',
    '{
        "enabled": true,
        "unit": "chars",
        "chunk_size": 4000,
        "overlap": 400,
        "min_chunk_size": 800
    }'
);
```

**Result:** Documents split into ~4000-character chunks with 400-character overlap.

---

### Configuration 3: Enable Chunking + Embeddings (Stub)

For testing without an external embedding service.

```sql
INSERT INTO rag_sources (name, enabled, backend_type, host, port, user, pass, db, table_name, pk_column, chunking_json, embedding_json)
VALUES (
    'embedded_source_stub',
    1,
    'mysql',
    '127.0.0.1',
    3306,
    'root',
    'pass',
    'mydb',
    'posts',
    'Id',
    '{
        "enabled": true,
        "unit": "chars",
        "chunk_size": 4000,
        "overlap": 400,
        "min_chunk_size": 800
    }',
    '{
        "enabled": true,
        "provider": "stub",
        "dim": 1536
    }'
);
```

**Result:** Pseudo-embeddings generated instantly (no API call). Good for testing.

---

### Configuration 4: Enable Chunking + Real Embeddings

With an OpenAI-compatible embedding service.

```sql
INSERT INTO rag_sources (name, enabled, backend_type, host, port, user, pass, db, table_name, pk_column, chunking_json, embedding_json)
VALUES (
    'embedded_source_real',
    1,
    'mysql',
    '127.0.0.1',
    3306,
    'root',
    'pass',
    'mydb',
    'posts',
    'Id',
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
        "api_key": "sk-your-api-key",
        "model": "text-embedding-3-small",
        "dim": 1536,
        "batch_size": 16,
        "timeout_ms": 20000
    }'
);
```

**Result:** Real embeddings generated via OpenAI API in batches of 16.

---

## Configuration Reference

### chunking_json

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable chunking |
| `unit` | string | `"chars"` | Unit of measurement (only `"chars"` supported) |
| `chunk_size` | integer | `4000` | Target size of each chunk |
| `overlap` | integer | `400` | Overlap between consecutive chunks |
| `min_chunk_size` | integer | `800` | Minimum size to avoid tiny tail chunks |

### embedding_json

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable/disable embedding generation |
| `provider` | string | `"stub"` | `"stub"` or `"openai"` |
| `model` | string | `"unknown"` | Model name (for observability) |
| `dim` | integer | `1536` | Vector dimension |
| `api_base` | string | - | API base URL (for `provider="openai"`) |
| `api_key` | string | - | API authentication key |
| `batch_size` | integer | `16` | Maximum chunks per API call |
| `timeout_ms` | integer | `20000` | Request timeout in milliseconds |
| `input` | object | - | Embedding input template (optional) |

### embedding_json.input (Advanced)

Controls what text is embedded. Example:

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

---

## Document Transformation (doc_map_json)

By default, all columns from the source table are available. To map columns to document fields:

```sql
INSERT INTO rag_sources (name, enabled, backend_type, host, port, user, pass, db, table_name, pk_column, doc_map_json)
VALUES (
    'mapped_source',
    1,
    'mysql',
    '127.0.0.1',
    3306,
    'root',
    'pass',
    'mydb',
    'posts',
    'Id',
    '{
        "title": {"expr": "concat(Title, '' - '', Subtitle)"},
        "body": {"col": "Content"},
        "metadata": {"expr": "json_object(''id''', Id, ''score'', Score, ''tags'', Tags)"}
    }'
);
```

**Result:** Custom mapping from MySQL columns to document fields.

---

## Filtering (where_sql)

Only ingest rows matching a WHERE clause:

```sql
UPDATE rag_sources
SET where_sql = 'Score >= 7 AND CreationDate >= ''2024-01-01'''
WHERE source_id = 1;
```

---

## Running Ingestion

### Single Run

```bash
./rag_ingest rag_index.db
```

### Incremental Runs (Watermark)

The tool tracks the last processed primary key value in `rag_sync_state`. Subsequent runs only fetch new rows.

```bash
# First run: ingests all rows
./rag_ingest rag_index.db

# Second run: only ingests new rows
./rag_ingest rag_index.db
```

---

## Monitoring Progress

```bash
# Progress is printed to stderr
./rag_ingest rag_index.db
# Output:
# Ingesting source_id=1 name=my_source backend=mysql table=posts
#   progress: ingested_docs=1000 skipped_docs=50
#   progress: ingested_docs=2000 skipped_docs=100
# Done source my_source ingested_docs=2500 skipped_docs=120
```

---

## Verification

```bash
sqlite3 rag_index.db <<SQL
.load ../deps/sqlite3/sqlite3/vec0.so

-- Check counts
SELECT 'documents' AS type, COUNT(*) FROM rag_documents
UNION ALL
SELECT 'chunks', COUNT(*) FROM rag_chunks
UNION ALL
SELECT 'fts_entries', COUNT(*) FROM rag_fts_chunks
UNION ALL
SELECT 'vectors', COUNT(*) FROM rag_vec_chunks;

-- Check sync state
SELECT source_id, mode, cursor_json FROM rag_sync_state;
SQL
```

---

## Common Workflows

### Workflow 1: Initial Setup

```bash
# 1. Create database
sqlite3 rag.db < schema.sql

# 2. Add source
sqlite3 rag.db "INSERT INTO rag_sources (name, enabled, backend_type, host, port, user, pass, db, table_name, pk_column, chunking_json)
VALUES ('my_data', 1, 'mysql', 'localhost', 3306, 'root', 'pass', 'mydb', 'posts', 'Id', '{\"enabled\":true,\"chunk_size\":4000,\"overlap\":400}');"

# 3. Ingest
./rag_ingest rag.db
```

### Workflow 2: Re-run with New Configuration

```bash
# 1. Update source configuration
sqlite3 rag.db "UPDATE rag_sources SET chunking_json='{\"enabled\":true,\"chunk_size\":2000}' WHERE source_id=1;"

# 2. Clear existing data (optional - to re-chunk with new settings)
sqlite3 rag.db "DELETE FROM rag_vec_chunks; DELETE FROM rag_fts_chunks; DELETE FROM rag_chunks; DELETE FROM rag_documents; DELETE FROM rag_sync_state;"

# 3. Re-ingest
./rag_ingest rag.db
```

### Workflow 3: Add Embeddings to Existing Data

```bash
# 1. Enable embeddings on existing source
sqlite3 rag.db "UPDATE rag_sources SET embedding_json='{\"enabled\":true,\"provider\":\"stub\",\"dim\":1536}' WHERE source_id=1;"

# 2. Clear sync state (so it re-processes all rows)
sqlite3 rag.db "DELETE FROM rag_sync_state WHERE source_id=1;"

# 3. Clear vectors only (keep documents and chunks)
sqlite3 rag.db "DELETE FROM rag_vec_chunks;"

# 4. Re-ingest (will skip existing documents, but generate embeddings)
./rag_ingest rag.db
```

**Note:** v0 skips documents that already exist. To regenerate embeddings, clear `rag_documents` or use `WHERE` clause.

---

## Troubleshooting

### "MySQL query failed"

- Verify MySQL credentials in `rag_sources`
- Check MySQL server is running
- Verify table and column names exist

### "Failed to load vec0 extension"

- Ensure `RAG_VEC0_EXT` environment variable points to valid `vec0.so`
- Or run: `export RAG_VEC0_EXT=/path/to/vec0.so`

### "Failed to generate embeddings"

- Check `embedding_json` configuration
- For `provider="openai"`: verify `api_base`, `api_key`, `model`
- Check network connectivity to embedding service
- Increase `timeout_ms` if needed

### "No enabled sources found"

- Run: `SELECT * FROM rag_sources WHERE enabled = 1;`
- Ensure `enabled = 1` for your source
