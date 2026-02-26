# SQLite3 Server

## Overview

ProxySQL v4.0 includes a built-in **SQLite3 Server** that acts as a transparent gateway between the MySQL protocol and the SQLite3 engine. This unique feature allows standard MySQL clients (and AI agents) to interact with a high-performance SQLite database using standard MySQL commands.

This feature is distinct from the **ProxySQL Admin** interface (port 6032). While Admin uses SQLite to manage ProxySQL's internal state, the SQLite3 Server provides a sandbox environment for user data, vector storage, and AI-powered workflows.

---

## Connectivity

The SQLite3 Server is optional and must be enabled at startup.

- **Default Port**: `6030`
- **Protocol**: MySQL Protocol
- **Startup Flag**: `--sqlite3-server`
- **Default Database**: `main`

### Connecting
You can connect using any standard MySQL client:

```bash
mysql -h 127.0.0.1 -P 6030 -u your_mysql_user -p
```

Authentication is handled via the standard `mysql_users` table in the ProxySQL Admin configuration.

---

## Key Features

### 1. Vector Search (`sqlite-vec`)
The SQLite3 Server includes native support for vector similarity search. This allows you to store LLM-generated embeddings and perform high-speed nearest-neighbor searches directly via SQL.

```sql
-- Create a vector table
CREATE VECTOR TABLE my_embeddings (embedding float[1536]);

-- Search for similar vectors
SELECT rowid, distance FROM my_embeddings 
WHERE embedding MATCH json('[0.1, 0.2, ...]');
```

### 2. Remote Embeddings (`sqlite-rembed`)
ProxySQL integrates with various AI providers to generate embeddings on-the-fly using the `rembed()` function.

```sql
-- Register an API client
INSERT INTO temp.rembed_clients(name, format, model, key)
VALUES ('openai', 'openai', 'text-embedding-3-small', 'your-api-key');

-- Generate and store an embedding
INSERT INTO my_embeddings(rowid, embedding)
VALUES (1, rembed('openai', 'Your document text here'));
```

Supported providers include **OpenAI**, **Anthropic**, **Ollama** (local), **Cohere**, and **Nomic**.

### 3. Full-Text Search (FTS5)
Standard SQLite FTS5 capabilities are available for high-speed keyword searching over text data.

### 4. RAG Index Management

For automated ingestion of data into the RAG index, ProxySQL provides the **`rag_ingest`** command-line tool. This tool connects to SQLite3 Server via the MySQL protocol and orchestrates the extraction, chunking, embedding generation, and indexing of data from backend **MySQL** sources.

Key features of `rag_ingest`:
- **MySQL Protocol Connection**: Connects via standard MySQL protocol to port 6030
- **Automated Chunking**: Character-based text splitting with configurable size and overlap
- **Embedding Generation**: Support for `stub` (testing) and `openai` (OpenAI-compatible APIs)
- **Bulk Processing**: Batch embedding generation for efficiency
- **Incremental Ingestion**: Watermark-based updates for large datasets

:::tip

See the **[RAG Ingest CLI](../genai/rag_ingest)** documentation for detailed usage instructions, configuration examples, and workflow guides.

:::

---

## Configuration & Management

The SQLite3 server behavior is controlled by specific variables prefixed with `sqliteserver-`. See the **[SQLite3 Server Variables](../references/sqliteserver_variables)** reference for more details.

### Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `sqliteserver-mysql_ifaces` | `0.0.0.0:6030` | Network interfaces to listen on for MySQL-to-SQLite traffic. |
| `sqliteserver-read_only` | `false` | When true, only read-only operations are permitted. |

### Commands
Like other ProxySQL modules, these variables are managed via [Admin Commands](../the_admin_schemas/admin_commands):

- `LOAD SQLITESERVER VARIABLES TO RUNTIME`
- `SAVE SQLITESERVER VARIABLES TO DISK`

---

## Security

- **Authentication**: Users must exist in the `mysql_users` table.
- **Isolation**: The SQLite3 server only provides access to the `main` schema. It cannot access `main`, `disk`, `stats`, or `monitor` databases used by ProxySQL Admin.
- **Interface**: It is highly recommended to bind `sqliteserver-mysql_ifaces` to `127.0.0.1` unless remote access is explicitly required.
