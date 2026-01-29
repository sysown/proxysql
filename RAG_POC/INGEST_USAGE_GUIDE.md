# RAG Ingestion Tool - Usage Guide (MySQL Protocol Version)

## Overview

`rag_ingest` reads data from MySQL, transforms it, chunks documents, builds full-text search indexes, and optionally generates vector embeddings for semantic search.

**This version connects via MySQL protocol to a server that has SQLite as backend** (ProxySQL SQLite3 Server on port 6030). All SQLite queries, FTS5, and vec0 extensions work transparently through the gateway.

---

## Quick Start

```bash
# 1. Build the tool (from repository root)
cd RAG_POC
make

# 2. Initialize the RAG database schema
./rag_ingest init --host=127.0.0.1 --port=6030 --user=root --password=root --database=rag_db

# 3. Configure your data source (via MySQL protocol)
mysql -h 127.0.0.1 -P 6030 -u root -proot rag_db < setup_source.sql

# 4. Run ingestion
./rag_ingest ingest --host=127.0.0.1 --port=6030 --user=root --password=root --database=rag_db

# 5. For detailed logging (optional)
./rag_ingest ingest --log-level=debug --host=127.0.0.1 -P 6030 -u root -p root -D rag_db
```

---

## Step-by-Step Guide

### Step 1: Initialize the RAG Database

```bash
# Using MySQL-style long options
./rag_ingest init \
  --host=127.0.0.1 \
  --port=6030 \
  --user=root \
  --password=root \
  --database=rag_index

# Using short options
./rag_ingest init -h 127.0.0.1 -P 6030 -u root -p root -D rag_index

# Using defaults (host=127.0.0.1, port=6030)
./rag_ingest init -u root -p root -D rag_index
```

**What happens:**
- Connects to SQLite3 Server via MySQL protocol (default: 127.0.0.1:6030)
- Creates RAG schema tables if they don't exist
- Creates FTS5 full-text search indexes
- Creates vec0 vector similarity search indexes

### Step 2: Configure Your Data Source

Insert a source configuration into `rag_sources`:

```sql
-- Minimal configuration (no chunking, no embeddings)
INSERT INTO rag_sources (
    name,
    enabled,
    backend_type,
    backend_host,
    backend_port,
    backend_user,
    backend_pass,
    backend_db,
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
./rag_ingest ingest --host=127.0.0.1 --port=6030 --user=root --password=root --database=rag_index
```

**What happens:**
1. Connects to MySQL backend using credentials from `rag_sources`
2. Executes `SELECT * FROM posts`
3. For each row:
   - Creates a document in `rag_documents` (via MySQL protocol to SQLite backend)
   - Creates a chunk in `rag_chunks` (1 per document when chunking disabled)
   - Creates FTS entry in `rag_fts_chunks`
4. Updates `rag_sync_state` with the max primary key value

---

## Command-Line Options

### Logging

Control log verbosity with `--log-level` (available for all commands):

```bash
--log-level=LEVEL
```

| Level | Output | Use Case |
|-------|--------|----------|
| `error` | Only errors | Production scripts, minimal logging |
| `warn` | Warnings + errors | Detect issues without verbose output |
| `info` | **Default** | Progress, statistics, key events |
| `debug` | Detailed info | SQL queries, configuration values, diagnostics |
| `trace` | Everything | Fine-grained function entry/exit, development |

**Examples:**
```bash
# Minimal output (errors only)
./rag_ingest ingest --log-level=error --host=127.0.0.1 --port=6030 --user=root --password=root --database=rag_db

# Default (info level)
./rag_ingest ingest --host=127.0.0.1 --port=6030 --user=root --password=root --database=rag_db

# Detailed debugging
./rag_ingest ingest --log-level=debug --host=127.0.0.1 --port=6030 --user=root --password=root --database=rag_db

# Maximum verbosity
./rag_ingest ingest --log-level=trace --host=127.0.0.1 --port=6030 --user=root --password=root --database=rag_db
```

**Output Format:**
- Timestamps: `[YYYY-MM-DD HH:MM:SS]`
- Log levels: `[ERROR]`, `[WARN]`, `[INFO]`, `[DEBUG]`, `[TRACE]`
- Color-coded (ANSI colors for terminal output)

### init

Initialize database schema.

```bash
./rag_ingest init [OPTIONS]

Common Options:
  -h, --host=name     Connect to host (default: 127.0.0.1)
  -P, --port=#        Port number to use (default: 6030)
  -u, --user=name     User for login
  -p, --password=name Password to use
  -D, --database=name Database to use (required)
  -?, --help          Show this help message

Logging Options:
  --log-level=LEVEL  Log verbosity: error, warn, info, debug, trace (default: info)

Init Options:
  --vec-dim=#        Vector dimension for rag_vec_chunks table (default: 1536)
```

### ingest

Run ingestion from configured sources.

```bash
./rag_ingest ingest [OPTIONS]

Common Options:
  -h, --host=name     Connect to host (default: 127.0.0.1)
  -P, --port=#        Port number to use (default: 6030)
  -u, --user=name     User for login
  -p, --password=name Password to use
  -D, --database=name Database to use (required)
  -?, --help          Show this help message

Logging Options:
  --log-level=LEVEL  Log verbosity: error, warn, info, debug, trace (default: info)
```

### query

Vector similarity search using embeddings.

```bash
./rag_ingest query [OPTIONS]

Common Options:
  -h, --host=name     Connect to host (default: 127.0.0.1)
  -P, --port=#        Port number to use (default: 6030)
  -u, --user=name     User for login
  -p, --password=name Password to use
  -D, --database=name Database to use (required)
  -?, --help          Show this help message

Logging Options:
  --log-level=LEVEL  Log verbosity: error, warn, info, debug, trace (default: info)

Query Options:
  -t, --text=text     Query text to search for (required)
  -s, --source-id=#   Source ID to search (default: all enabled sources)
  -l, --limit=#       Maximum results to return (default: 5)
```

---

## Common Configurations

### Configuration 1: Basic Ingestion (No Chunking, No Embeddings)

```sql
INSERT INTO rag_sources (
    name, enabled, backend_type,
    backend_host, backend_port, backend_user, backend_pass, backend_db,
    table_name, pk_column
)
VALUES (
    'basic_source', 1, 'mysql',
    '127.0.0.1', 3306, 'root', 'pass', 'mydb',
    'posts', 'Id'
);

-- chunking_json and embedding_json default to disabled
```

**Result:** 1 chunk per document, FTS only, no vectors.

---

### Configuration 2: Enable Chunking

Chunking splits long documents into smaller pieces for better retrieval precision.

```sql
INSERT INTO rag_sources (
    name, enabled, backend_type,
    backend_host, backend_port, backend_user, backend_pass, backend_db,
    table_name, pk_column, chunking_json
)
VALUES (
    'chunked_source', 1, 'mysql',
    '127.0.0.1', 3306, 'root', 'pass', 'mydb',
    'posts', 'Id',
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
INSERT INTO rag_sources (
    name, enabled, backend_type,
    backend_host, backend_port, backend_user, backend_pass, backend_db,
    table_name, pk_column, chunking_json, embedding_json
)
VALUES (
    'embedded_source_stub', 1, 'mysql',
    '127.0.0.1', 3306, 'root', 'pass', 'mydb',
    'posts', 'Id',
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
INSERT INTO rag_sources (
    name, enabled, backend_type,
    backend_host, backend_port, backend_user, backend_pass, backend_db,
    table_name, pk_column, chunking_json, embedding_json
)
VALUES (
    'embedded_source_real', 1, 'mysql',
    '127.0.0.1', 3306, 'root', 'pass', 'mydb',
    'posts', 'Id',
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
INSERT INTO rag_sources (
    name, enabled, backend_type,
    backend_host, backend_port, backend_user, backend_pass, backend_db,
    table_name, pk_column, doc_map_json
)
VALUES (
    'mapped_source', 1, 'mysql',
    '127.0.0.1', 3306, 'root', 'pass', 'mydb',
    'posts', 'Id',
    '{
        "doc_id": {"format": "posts:{Id}"},
        "title": {"concat": [{"col": "Title"}]},
        "body": {"concat": [{"col": "Content"}]},
        "metadata": {"pick": ["Id", "Score", "Tags"]}
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
./rag_ingest ingest -h 127.0.0.1 -P 6030 -u root -p root -D rag_index
```

### Incremental Runs (Watermark)

The tool tracks the last processed primary key value in `rag_sync_state`. Subsequent runs only fetch new rows.

```bash
# First run: ingests all rows
./rag_ingest ingest -h 127.0.0.1 -P 6030 -u root -p root -D rag_index

# Second run: only ingests new rows
./rag_ingest ingest -h 127.0.0.1 -P 6030 -u root -p root -D rag_index
```

---

## Transaction Handling

### Per-Source Commits

Each data source is processed in its own transaction:

```text
Source 1: BEGIN IMMEDIATE → ingest data → COMMIT  ✅
Source 2: BEGIN IMMEDIATE → ingest data → ROLLBACK ❌ (error occurred)
Source 3: BEGIN IMMEDIATE → ingest data → COMMIT  ✅
```

**Benefits:**
- **Isolated failures**: If source 2 fails, sources 1 and 3 are still committed
- **Shorter locks**: Each table is only locked during its own ingestion
- **Better recovery**: Partial progress is preserved on failures
- **Lower memory**: Changes are flushed per source instead of held until end

### Transaction Logging

```bash
./rag_ingest ingest -h 127.0.0.1 -P 6030 -u root -p root -D rag_index
# Output:
[INFO] Processing source 1 of 3
[DEBUG] Starting transaction for source 1...
[INFO] Committing source 1...

[INFO] Processing source 2 of 3
[DEBUG] Starting transaction for source 2...
[WARN] Rolling back source 2 due to errors

[INFO] Processing source 3 of 3
[DEBUG] Starting transaction for source 3...
[INFO] Committing source 3...

[INFO] === 'ingest' command complete ===
  Succeeded: 2
  Failed: 1
```

### Multiple Sources Example

```sql
-- Configure multiple sources
INSERT INTO rag_sources (name, enabled, backend_type, ...)
VALUES
  ('stack_overflow', 1, 'mysql', '127.0.0.1', 3306, ...),
  ('github_issues', 1, 'mysql', '127.0.0.1', 3306, ...),
  ('discussions', 1, 'mysql', '127.0.0.1', 3306, ...);
```

If `github_issues` fails (e.g., connection timeout), the other two sources are still ingested successfully.

---

## Monitoring Progress

### Default Logging (INFO level)

```bash
./rag_ingest ingest -h 127.0.0.1 -P 6030 -u root -p root -D rag_index
# Output:
[2026-01-28 12:34:56] [INFO] === RAG Ingestion Tool Starting ===
[2026-01-28 12:34:56] [INFO] Loaded 1 enabled source(s)
[2026-01-28 12:34:57] [INFO] === Starting ingestion for source_id=1, name=my_source ===
[2026-01-28 12:34:58] [INFO] Backend query returned 10000 row(s) to process
[2026-01-28 12:35:00] [INFO] Progress: ingested_docs=1000, skipped_docs=50, chunks=4000
[2026-01-28 12:35:02] [INFO] Progress: ingested_docs=2000, skipped_docs=100, chunks=8000
[2026-01-28 12:35:10] [INFO] === Source ingestion complete: my_source ===
[2026-01-28 12:35:10] [INFO]   ingested_docs=9850, skipped_docs=150, total_chunks=39400
[2026-01-28 12:35:10] [INFO]   embedding_batches=2463
```

### Detailed Logging (DEBUG level)

```bash
./rag_ingest ingest --log-level=debug -h 127.0.0.1 -P 6030 -u root -p root -D rag_index
# Output includes:
# - Connection parameters
# - SQL queries executed
# - Configuration parsing (chunking, embeddings)
# - Per-document operations
# - Chunk counts per document
# - Embedding batch operations
# - Sync state updates
```

### Maximum Verbosity (TRACE level)

```bash
./rag_ingest ingest --log-level=trace -h 127.0.0.1 -P 6030 -u root -p root -D rag_index
# Output includes EVERYTHING:
# - Function entry/exit
# - Individual SQL statement execution
# - Per-chunk operations
# - Internal state changes
```

### Progress Indicators

| Interval | Trigger | Output |
|----------|---------|--------|
| Per-command | Start/end | `=== RAG Ingestion Tool Starting ===` |
| Per-source | Start/end | `=== Starting ingestion for source_id=X, name=Y ===` |
| Every 1000 docs | During processing | `Progress: ingested_docs=1000, skipped_docs=50, chunks=4000` |
| Per-batch | Embeddings | `Generating embeddings for batch of 16 chunks...` |
| End of source | Summary | `ingested_docs=9850, skipped_docs=150, total_chunks=39400` |

### Understanding the Output

- **ingested_docs**: New documents added to the index
- **skipped_docs**: Documents already in the index (not re-processed)
- **total_chunks**: Total chunks created across all ingested documents
- **embedding_batches**: Number of embedding API calls made (for embedding-enabled sources)

---

## Verification

```bash
# Connect to SQLite3 Server via MySQL protocol
mysql -h 127.0.0.1 -P 6030 -u root -proot rag_index -e "
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
"
```

---

## Common Workflows

### Workflow 1: Initial Setup

```bash
# 1. Initialize database
./rag_ingest init -h 127.0.0.1 -P 6030 -u root -p root -D rag

# 2. Add source
mysql -h 127.0.0.1 -P 6030 -u root -proot rag -e "
INSERT INTO rag_sources (name, enabled, backend_type,
    backend_host, backend_port, backend_user, backend_pass, backend_db,
    table_name, pk_column, chunking_json)
VALUES ('my_data', 1, 'mysql',
    'localhost', 3306, 'root', 'pass', 'mydb',
    'posts', 'Id',
    '{\"enabled\":true,\"chunk_size\":4000,\"overlap\":400}');
"

# 3. Ingest
./rag_ingest ingest -h 127.0.0.1 -P 6030 -u root -p root -D rag
```

### Workflow 2: Re-run with New Configuration

```bash
# 1. Update source configuration
mysql -h 127.0.0.1 -P 6030 -u root -proot rag -e "
UPDATE rag_sources
SET chunking_json='{\"enabled\":true,\"chunk_size\":2000}'
WHERE source_id=1;
"

# 2. Clear existing data (optional - to re-chunk with new settings)
mysql -h 127.0.0.1 -P 6030 -u root -proot rag -e "
DELETE FROM rag_vec_chunks WHERE source_id = 1;
DELETE FROM rag_sync_state WHERE source_id = 1;
DELETE FROM rag_chunks WHERE source_id = 1;
DELETE FROM rag_documents WHERE source_id = 1;
"

# 3. Re-ingest
./rag_ingest ingest -h 127.0.0.1 -P 6030 -u root -p root -D rag
```

### Workflow 3: Add Embeddings to Existing Data

```bash
# 1. Enable embeddings on existing source
mysql -h 127.0.0.1 -P 6030 -u root -proot rag -e "
UPDATE rag_sources
SET embedding_json='{\"enabled\":true,\"provider\":\"stub\",\"dim\":1536}'
WHERE source_id=1;
"

# 2. Clear sync state (so it re-processes all rows)
mysql -h 127.0.0.1 -P 6030 -u root -proot rag -e "
DELETE FROM rag_sync_state WHERE source_id=1;
"

# 3. Clear vectors only (keep documents and chunks)
mysql -h 127.0.0.1 -P 6030 -u root -proot rag -e "
DELETE FROM rag_vec_chunks WHERE source_id=1;
"

# 4. Re-ingest (will skip existing documents, but generate embeddings)
./rag_ingest ingest -h 127.0.0.1 -P 6030 -u root -p root -D rag
```

**Note:** v0 skips documents that already exist. To regenerate embeddings, clear `rag_documents` or use `WHERE` clause.

---

## Troubleshooting

### "MySQL connect failed"

- Verify SQLite3 Server is running on port 6030
- Check credentials are correct
- Ensure database exists

### "MySQL query failed" (backend)

- Verify backend MySQL credentials in `rag_sources`
- Check backend MySQL server is running (default: 127.0.0.1:3306)
- Verify table and column names exist

### "No enabled sources found"

- Run: `SELECT * FROM rag_sources WHERE enabled = 1;` via MySQL protocol
- Ensure `enabled = 1` for your source

### "Failed to generate embeddings"

- Check `embedding_json` configuration
- For `provider="openai"`: verify `api_base`, `api_key`, `model`
- Check network connectivity to embedding service
- Increase `timeout_ms` if needed

### Too much / too little output

- Use `--log-level=error` for production scripts (minimal output)
- Use `--log-level=info` for normal operation (default)
- Use `--log-level=debug` to see SQL queries and configuration values
- Use `--log-level=trace` for development and deep troubleshooting

### Debugging SQL queries

```bash
# Use --log-level=debug to see all SQL queries being executed
./rag_ingest ingest --log-level=debug -h 127.0.0.1 -P 6030 -u root -p root -D rag_db
# Output will include:
# - SELECT queries to rag_sources, rag_sync_state, rag_documents
# - INSERT statements for documents, chunks, FTS entries
# - Backend SELECT query being built and executed
```

### Checking configuration values

```bash
# Use --log-level=debug to see parsed configuration
./rag_ingest ingest --log-level=debug -h 127.0.0.1 -P 6030 -u root -p root -D rag_db
# Output includes:
# - Chunking config: enabled=yes, chunk_size=4000, overlap=400
# - Embedding config: enabled=yes, provider=openai, model=text-embedding-3-small
# - Watermark/resync values
```

### Performance issues

- Use `--log-level=debug` to see embedding batch operations
- Check `embedding_batches` count in final summary
- Reduce `batch_size` in `embedding_json` if API timeouts occur
- Increase `timeout_ms` for slower embedding services

---

## Architecture Notes

### MySQL Protocol Gateway

This version uses ProxySQL's SQLite3 Server as a gateway:

```
rag_ingest --[MySQL Protocol]--> ProxySQL SQLite3 Server (port 6030) --> SQLite Backend
                                     |
                                     +-- FTS5 Full-Text Search
                                     +-- vec0 Vector Similarity
                                     +-- Standard SQL Queries
```

**Benefits:**
- No local SQLite file dependencies
- Centralized RAG index database
- Concurrent access from multiple clients
- Same schema and queries work transparently

### Backend Data Source

The tool connects to a separate MySQL/MariaDB server to fetch source data:

```
rag_ingest --[MySQL Protocol]--> Backend MySQL (port 3306) --> Source Tables
```

This is configured via `rag_sources` table (`backend_host`, `backend_port`, etc.).
