# RAG Ingest Tool (`rag_ingest`)

## Overview

The `rag_ingest` tool is a command-line utility that automates the ingestion of data into ProxySQL's RAG (Retrieval-Augmented Generation) index. It connects to the **SQLite3 Server** (port 6030) via the MySQL protocol, extracts data from backend **MySQL** sources, chunks text content, builds full-text search indexes, and optionally generates vector embeddings for semantic search.

:::info

`rag_ingest` uses the **MySQL protocol** (mariadb client) to communicate with SQLite3 Server. It does **not** directly access SQLite database files. This architecture allows for centralized RAG index management with proper authentication and access control.

:::

---

## Architecture

```
┌─────────────┐      MySQL Protocol       ┌──────────────────┐
│ rag_ingest  │ ──────────────────────────▶ │ SQLite3 Server   │
│   (CLI)     │      Port 6030             │   (Port 6030)    │
└─────────────┘                            └────────┬─────────┘
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │  RAG Database   │
                                            │  (rag_sources,  │
                                            │   rag_documents,│
                                            │   rag_chunks,   │
                                            │   rag_fts,      │
                                            │   rag_vec)      │
                                            └─────────────────┘
                                                     ▲
                                                     │
                                            ┌────────┴─────────┐
                                            │  Backend MySQL   │
                                            │  (Data Source)   │
                                            └──────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| **rag_ingest CLI** | Command-line tool that orchestrates data ingestion |
| **SQLite3 Server** | ProxySQL's MySQL-to-SQLite gateway (port 6030) |
| **RAG Database** | SQLite database containing FTS5 index and vector embeddings |
| **Backend Source** | MySQL database containing source data |

---

## Installation

The `rag_ingest` tool is built as part of the ProxySQL build process. After compilation, the binary is located in the same directory as the source code:

```bash
# From the RAG_POC directory
./RAG_POC/rag_ingest
```

### Build Dependencies

- **mysqlclient / mariadb-client**: For MySQL protocol connections
- **libcurl**: For HTTP-based embedding providers (OpenAI-compatible)
- **nlohmann/json**: Single-header JSON library (json.hpp)

---

## Connectivity

### Connection Parameters

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--host` | `-h` | SQLite3 Server hostname | `127.0.0.1` |
| `--port` | `-P` | SQLite3 Server port | `6030` |
| `--user` | `-u` | MySQL username (from `mysql_users`) | Required |
| `--password` | `-p` | MySQL password | Required |
| `--database` | `-D` | SQLite3 database name | Ignored (currently unused) |
| `--log-level` | - | Logging level: `error`, `warn`, `info`, `debug`, `trace` | `info` |

### Connection Example

```bash
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass --database main
```

:::info

**Note**: The `--database` parameter is required by the CLI but is currently ignored by SQLite3 Server. All RAG tables are created in the default database.

:::

:::warning

`rag_ingest` connects to **SQLite3 Server** (default port 6030), **NOT** the Admin interface (port 6032). Connecting to the wrong interface will result in errors.

:::

---

## Commands

### 1. Initialize RAG Schema

The `init` command creates the necessary RAG database schema:

```bash
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass --database main \
  init --vec-dim 1536
```

#### Init Options

| Option | Description | Default |
|--------|-------------|---------|
| `--vec-dim` | Vector dimension for `rag_vec_chunks` table | `1536` |

**Tables created:**
- `rag_sources` - Configuration for data sources
- `rag_documents` - Document metadata
- `rag_chunks` - Text chunks for indexing
- `rag_fts_chunks` - FTS5 full-text search index
- `rag_vec_chunks` - Vector embeddings (vec0 virtual table)
- `rag_sync_state` - Sync cursor (watermark) tracking
- `rag_chunk_view` - Convenience view joining chunks with documents

---

### 2. Ingest Data

The `ingest` command processes data from backend sources and populates the RAG index:

```bash
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass --database main \
  ingest
```

The `ingest` command:
1. Loads all **enabled** sources from `rag_sources` table
2. For each source, connects to the backend MySQL database
3. Fetches data using configurable SELECT queries with incremental filtering
4. Transforms rows using `doc_map_json` specification
5. Chunks document bodies using `chunking_json` configuration
6. Inserts into `rag_documents`, `rag_chunks`, `rag_fts_chunks` (FTS5)
7. If embedding enabled: generates and inserts embeddings into `rag_vec_chunks`
8. Updates sync cursor in `rag_sync_state` for incremental ingestion

:::info

**Incremental Ingestion**: `rag_ingest` uses sync cursors (watermarks) stored in `rag_sync_state` to track the last processed primary key value. On subsequent runs, it only processes **new** rows (where the primary key is greater than the stored watermark), skipping documents that already exist in `rag_documents`.

**Important**: The sync cursor **currently does not detect record modifications**. If a source row changes (title/body/metadata), the existing `rag_documents`/`rag_chunks` are not updated. To reflect changes, you must delete the affected documents from `rag_documents` and re-run ingestion.

:::

---

### 3. Query the RAG Index

The `query` command performs vector similarity search:

```bash
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass --database main \
  query --text "your search text here" --source-id 1 --limit 5
```

#### Query Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--text` | `-t` | Search query text (required) | - |
| `--source-id` | `-s` | Source ID to search within | All enabled sources |
| `--limit` | `-l` | Number of results to return | `5` |

The `query` command:
1. Loads the source configuration to get embedding settings
2. Generates an embedding for the query text using the configured provider
3. Performs a KNN search using `vec0` vector similarity
4. Returns matching chunks with distance scores

---

## Data Source Configuration

Before running ingestion, you must configure a data source in the `rag_sources` table.

### rag_sources Schema

```sql
CREATE TABLE rag_sources (
  source_id        INTEGER PRIMARY KEY,
  name             TEXT NOT NULL UNIQUE,
  enabled          INTEGER NOT NULL DEFAULT 1,
  backend_type     TEXT NOT NULL,           -- Currently only "mysql" supported
  backend_host     TEXT NOT NULL,
  backend_port     INTEGER NOT NULL,
  backend_user     TEXT NOT NULL,
  backend_pass     TEXT NOT NULL,
  backend_db       TEXT NOT NULL,
  table_name       TEXT NOT NULL,
  pk_column        TEXT NOT NULL,
  where_sql        TEXT,                    -- Optional WHERE clause
  doc_map_json     TEXT NOT NULL,           -- Document mapping specification
  chunking_json    TEXT NOT NULL,           -- Chunking configuration
  embedding_json   TEXT,                    -- Embedding configuration (optional)
  created_at       INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at       INTEGER NOT NULL DEFAULT (unixepoch())
);
```

### Configuration Example

```sql
-- Connect to SQLite3 Server
mysql -h 127.0.0.1 -P 6030 -u myuser -p

-- Configure a data source
INSERT INTO rag_sources (
  name, enabled,
  backend_type, backend_host, backend_port, backend_user, backend_pass, backend_db,
  table_name, pk_column, where_sql,
  doc_map_json,
  chunking_json,
  embedding_json
) VALUES (
  'blog_posts', 1,
  'mysql', '127.0.0.1', 3306, 'blog_user', 'blog_password', 'blog_db',
  'posts', 'Id', 'Published = 1',
  '{
    "doc_id": {"format": "posts:{Id}"},
    "title": {"concat": [{"col": "Title"}]},
    "body": {"concat": [{"col": "Body"}]},
    "metadata": {
      "pick": ["Tags", "Score"],
      "rename": {"Tags": "tags", "Score": "score"}
    }
  }',
  '{"enabled":true,"unit":"chars","chunk_size":1000,"overlap":100}',
  '{
    "enabled":true,
    "provider":"openai",
    "api_base":"https://api.openai.com/v1",
    "api_key":"sk-xxx",
    "model":"text-embedding-3-small",
    "dim":1536,
    "batch_size":16,
    "timeout_ms":20000,
    "input":{"concat":[{"col":"Title"},{"lit":"\\n"},{"chunk_body":true}]}
  }'
);
```

### Configuration Fields

| Field | Description |
|-------|-------------|
| `name` | Logical name for the source (unique) |
| `enabled` | Set to `1` to enable, `0` to disable |
| `backend_type` | Backend type - currently only `mysql` is supported |
| `backend_host` | Backend MySQL hostname |
| `backend_port` | Backend MySQL port |
| `backend_user` | Backend MySQL username |
| `backend_pass` | Backend MySQL password |
| `backend_db` | Backend MySQL database name |
| `table_name` | Backend table to read from |
| `pk_column` | Primary key column name |
| `where_sql` | Optional SQL WHERE clause for filtering rows |
| `doc_map_json` | JSON document mapping specification |
| `chunking_json` | JSON chunking configuration |
| `embedding_json` | JSON embedding configuration (optional) |

---

## Document Mapping (`doc_map_json`)

The `doc_map_json` field specifies how to transform backend rows into RAG documents.

```json
{
  "doc_id": {
    "format": "posts:{Id}"
  },
  "title": {
    "concat": [
      {"col": "Title"}
    ]
  },
  "body": {
    "concat": [
      {"col": "Body"}
    ]
  },
  "metadata": {
    "pick": ["Tags", "Score", "CreatedAt"],
    "rename": {
      "Tags": "tags",
      "Score": "score"
    }
  }
}
```

### Document Mapping Fields

| Field | Description |
|-------|-------------|
| `doc_id.format` | Format string for document ID (use `{col}` for column values) |
| `title.concat` | Array of column references and literals for title |
| `body.concat` | Array of column references and literals for body |
| `metadata.pick` | Array of column names to include in metadata |
| `metadata.rename` | Map of column name → metadata key name |

### Concat Array Elements

| Element | Description |
|---------|-------------|
| `{"col": "ColumnName"}` | Reference a column value |
| `{"lit": "literal text"}` | Literal string value |
| `{"chunk_body": true}` | Reference the chunk body (for embedding input only) |

---

## Chunking Configuration (`chunking_json`)

The `chunking_json` field configures how text is split into chunks.

```json
{
  "enabled": true,
  "unit": "chars",
  "chunk_size": 1000,
  "overlap": 100
}
```

### Chunking Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `enabled` | Enable/disable chunking | `true` |
| `unit` | Chunking unit - currently only `chars` is supported | `chars` |
| `chunk_size` | Target chunk size in characters | `4000` |
| `overlap` | Overlap between chunks in characters | `400` |
| `min_chunk_size` | Minimum chunk size (smaller chunks merge with previous) | `800` |

:::info

**Supported Chunking**: Currently only character-based chunking (`unit="chars"`) is supported. Other units are not implemented in v0.2.

:::

---

## Embedding Configuration (`embedding_json`)

The `embedding_json` field configures vector embedding generation.

```json
{
  "enabled": true,
  "dim": 1536,
  "model": "text-embedding-3-small",
  "provider": "openai",
  "api_base": "https://api.openai.com/v1",
  "api_key": "sk-your-api-key",
  "batch_size": 16,
  "timeout_ms": 20000,
  "input": {
    "concat": [
      {"col": "Title"},
      {"lit": "\n"},
      {"chunk_body": true}
    ]
  }
}
```

### Embedding Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `enabled` | Enable/disable embeddings | `false` |
| `dim` | Vector dimension | `1536` |
| `model` | Embedding model name | `unknown` |
| `provider` | Provider: `openai` or `stub` | `stub` |
| `api_base` | API endpoint URL | - |
| `api_key` | API authentication key | - |
| `batch_size` | Chunks per API call | `16` |
| `timeout_ms` | Request timeout in milliseconds | `20000` |
| `input.concat` | Array of column/literal/chunk_body for embedding input | - |

### Supported Providers

| Provider | Description |
|----------|-------------|
| `stub` | Pseudo-embeddings for testing (no API call) |
| `openai` | OpenAI-compatible API (OpenAI, Azure, local models) |

:::info

**Provider Support**: Currently only `stub` (for testing) and `openai` (OpenAI-compatible APIs) are supported. Other providers are not implemented.

:::

---

## Vector Dimensions

Common embedding model dimensions:

| Model | Dimensions |
|-------|------------|
| `text-embedding-3-small` | 1536 |
| `text-embedding-3-large` | 3072 |
| `text-embedding-ada-002` | 1536 |

:::info

The vector dimension specified in `embedding_json.dim` must match the output dimension of your embedding model, and must be consistent with the `--vec-dim` value used during `init`.

:::

---

## Bulk Embedding Generation

The `batch_size` parameter in `embedding_json` controls how many chunks are sent in a single API call:

```json
{
  "batch_size": 16
}
```

### Batching Benefits

- **Reduced API calls**: Fewer HTTP requests
- **Lower latency**: Less network overhead
- **Example**: With `batch_size=16`, 100 chunks require only 7 API calls (16+16+16+16+16+16+4) instead of 100

---

## Incremental Ingestion (Watermarks)

`rag_ingest` supports incremental ingestion using sync cursors stored in the `rag_sync_state` table:

```sql
SELECT source_id, mode, cursor_json, last_ok_at, last_error
FROM rag_sync_state;
```

The sync cursor tracks:
- **column**: The column used for watermarking (default: primary key)
- **value**: The last processed value (numeric or string)

On each ingestion run, `rag_ingest`:
1. Loads the sync cursor for each source
2. Filters the SELECT query with `WHERE watermark_column > watermark_value`
3. Processes only new rows
4. Updates the cursor with the maximum watermark value seen

:::info

Documents that already exist in `rag_documents` (matching `doc_id`) are automatically skipped, regardless of watermark position.

:::

---

## Complete Workflow Example

### Step 1: Initialize the RAG Schema

```bash
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass --database main \
  init --vec-dim 1536
```

### Step 2: Configure the Data Source

```sql
mysql -h 127.0.0.1 -P 6030 -u myuser -p

INSERT INTO rag_sources (
  name, enabled,
  backend_type, backend_host, backend_port, backend_user, backend_pass, backend_db,
  table_name, pk_column, where_sql,
  doc_map_json, chunking_json, embedding_json
) VALUES (
  'blog_posts', 1,
  'mysql', '127.0.0.1', 3306, 'blog_user', 'blog_password', 'blog_db',
  'posts', 'Id', 'Published = 1',
  '{
    "doc_id": {"format": "posts:{Id}"},
    "title": {"concat": [{"col": "Title"}]},
    "body": {"concat": [{"col": "Body"}]},
    "metadata": {"pick": ["Tags"], "rename": {"Tags": "tags"}}
  }',
  '{"enabled":true,"unit":"chars","chunk_size":1000,"overlap":100}',
  '{
    "enabled":true,
    "provider":"openai",
    "api_base":"https://api.openai.com/v1",
    "api_key":"sk-xxx",
    "model":"text-embedding-3-small",
    "dim":1536,
    "batch_size":16,
    "timeout_ms":20000,
    "input":{"concat":[{"col":"Title"},{"lit":"\\n"},{"chunk_body":true}]}
  }'
);
```

### Step 3: Run Ingestion

```bash
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass --database main \
  ingest
```

### Step 4: Query the Index

```bash
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass --database main \
  query --text "database proxy configuration" --source-id 1 --limit 5
```

---

## Logging

`rag_ingest` supports configurable logging levels to help troubleshoot issues and monitor progress.

### Log Levels

| Level | Description |
|-------|-------------|
| `error` | Only error messages |
| `warn` | Warnings and errors |
| `info` | Informational messages (default) - shows progress and key events |
| `debug` | Detailed debugging information |
| `trace` | Very detailed trace-level logging |

### Usage

```bash
# Set log level to debug for more verbose output
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass --database main \
  --log-level debug \
  ingest

# Use trace for maximum verbosity
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass --database main \
  --log-level trace \
  ingest
```

---

## Security Considerations

### Authentication

`rag_ingest` uses standard MySQL authentication. Ensure the user exists in ProxySQL's `mysql_users` table:

```sql
-- In ProxySQL Admin (port 6032)
INSERT INTO mysql_users (username, password, default_hostgroup)
VALUES ('myuser', 'mypassword', 0);
LOAD MYSQL USERS TO RUNTIME;
```

### Network Isolation

It is recommended to bind `sqliteserver-mysql_ifaces` to `127.0.0.1` unless remote access is explicitly required:

```sql
-- In ProxySQL Admin
SET sqliteserver-mysql_ifaces = '127.0.0.1:6030';
LOAD SQLITESERVER VARIABLES TO RUNTIME;
```

:::warning

**No SSL Support**: `rag_ingest` does not currently support SSL/TLS connections. Use network isolation or SSH tunneling for secure connections.

:::

---

## Troubleshooting

### "Not a SQLite3 Server" Error

```
========================================
ERROR: Not connected to SQLite Server!
========================================

rag_ingest writes RAG index data to ProxySQL SQLite3 Server.
The server you connected to does not appear to be a SQLite Server.

SQLite Server identification failed: sqlite_master table not found.

Please ensure you are connecting to:
  - ProxySQL SQLite3 Server (default port: 6030)
  - NOT a regular MySQL/MariaDB server (port: 3306)

Connection details:
  - Host: ...
  - Server info: ...
========================================
```

**Solution**: Ensure you are connecting to port 6030 (SQLite3 Server), not port 6032 (Admin) or port 3306 (MySQL backend).

### "RAG schema not found" Error

```
Error: RAG schema not found. Please run 'init' command first:
  rag_ingest init -h 127.0.0.1 -P 6030 -u myuser -p mypass -D main
```

**Solution**: Run the `init` command first to create the schema:
```bash
rag_ingest init -h 127.0.0.1 -P 6030 -u myuser -p mypass -D main
```

### "No enabled sources found" Message

```
No enabled sources found in rag_sources.
```

**Solution**: Ensure at least one row in `rag_sources` has `enabled = 1`.

### "Embeddings not configured" Error

```
Error: Embeddings not configured for source 1
```

**Solution**: Add `embedding_json` configuration to the source in `rag_sources`:
```sql
UPDATE rag_sources
SET embedding_json = '{"enabled":true,"provider":"openai","api_base":"https://api.openai.com/v1","api_key":"sk-xxx","model":"text-embedding-3-small","dim":1536}'
WHERE source_id = 1;
```

### "Embeddings not enabled" Error

```
Error: Embeddings not enabled for source 1
```

**Solution**: Set `"enabled":true` in the `embedding_json` configuration for the source.

### "Failed to generate embedding for query" Error

```
Error: Failed to generate embedding for query
```

**Solution**: Verify that:
- The embedding provider is properly configured (`provider`, `api_base`, `api_key`)
- The embedding model is accessible (network connectivity, API quotas)
- The `embedding_json` configuration is valid JSON

### "backend_type not supported" Warning

```
Skipping: backend_type not supported in v0.
```

**Solution**: Ensure `backend_type` is set to `mysql` in `rag_sources`. Other backend types are not currently supported.

### "vec0 table creation failed" Warning

```
Warning: vec0 table creation failed (sqlite-vec extension not available). Vector embeddings will be disabled.
```

**Solution**: Ensure the `sqlite-vec` extension is loaded in SQLite3 Server. Vector embeddings will be disabled without this extension.

### "Parameter required" Errors

```
Error: Required parameter missing: --database is required
Error: --text is required for query command
Error: --vec-dim must be positive
```

**Solution**: Provide the required parameters:
- `--database` (or `-D`) is required for all commands (note: currently ignored by SQLite3 Server)
- `--text` (or `-t`) is required for the `query` command
- `--vec-dim` must be a positive integer

### Backend Connection Failures

```
MySQL connect failed: Access denied for user 'blog_user'@'localhost'
```

**Solution**: Check that the `backend_user`, `backend_pass`, `backend_host`, and `backend_port` in `rag_sources` are correct.

---

## Related Documentation

- [SQLite3 Server](../features/sqlite3_server.md) - Gateway architecture and configuration
- [RAG Tools](./mcp_tools_rag.md) - MCP endpoint tools for querying the RAG index
- [Full-Text Search](./mcp_fts.md) - FTS5 search capabilities
- [MCP Catalog](./mcp_catalog.md) - RAG database schema reference
