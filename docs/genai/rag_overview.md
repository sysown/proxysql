---
title: RAG Overview
sidebar_position: 1
---

# ProxySQL RAG Overview

**ProxySQL RAG** (Retrieval-Augmented Generation) is a powerful feature that enables AI-powered search and retrieval over your database content. It combines full-text search with semantic vector search to provide intelligent, context-aware querying capabilities.

## What is RAG?

Retrieval-Augmented Generation (RAG) is an AI technique that enhances language models by providing relevant context from a knowledge base. ProxySQL RAG implements this by:

1. **Indexing** your database content (documents, articles, posts, etc.)
2. **Splitting** content into searchable chunks
3. **Creating** both keyword (FTS) and semantic (vector) indexes
4. **Querying** with natural language to find relevant information

## Key Features

### Dual Search Modes

- **Full-Text Search (FTS)**: Fast keyword-based search using SQLite FTS5
  - Perfect for finding exact terms, identifiers, error messages
  - Uses BM25 ranking algorithm

- **Vector Search**: Semantic similarity search using embeddings
  - Understands meaning and context
  - Finds related content even with different wording

- **Hybrid Search**: Combines both approaches for optimal results
  - Reciprocal Rank Fusion (RRF) for balanced ranking
  - Configurable weights for FTS and vector scores

### Flexible Data Sources

Ingest data from external databases:
- **MySQL/MariaDB**: Direct connection and ingestion
- Future: PostgreSQL, other databases

### Intelligent Document Processing

- **Automatic Chunking**: Split long documents into optimal-sized pieces
- **Configurable Mappings**: Transform source data into search-ready documents
- **Metadata Extraction**: Preserve structured information (tags, scores, dates)
- **Filtering**: Select specific rows with WHERE clauses

### MCP Integration

ProxySQL RAG exposes tools through the Model Context Protocol (MCP):
- Seamless integration with AI agents (Claude, OpenAI, etc.)
- REST API endpoints for programmatic access
- Standardized tool interfaces

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent / User Query                    │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          │ MCP Protocol / REST API
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    ProxySQL RAG Engine                      │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐ │
│   │ FTS5     │  │ Vector   │  │ Hybrid   │  │ Fetch &     │ │
│   │ Search   │  │ Search   │  │ RRF      │  │ Refetch     │ │
│   └───┬──────┘  └────┬─────┘  └─────┬────┘  └──────┬──────┘ │
└───────┼──────────────┼──────────────┼──────────────┼────────┘
        │              │              │              │
        ▼              ▼              ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│              SQLite3 RAG Database (Port 6030)               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │rag_documents │  │rag_chunks    │  │rag_fts_chunks│       │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤       │
│  │rag_sources   │  │rag_vec_chunks│  │rag_sync_state│       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          │ Ingestion (rag_ingest)
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              Backend Source Database                        │
│         (MySQL/MariaDB with source data)                    │
└─────────────────────────────────────────────────────────────┘
```

## RAG Components

### 1. Data Ingestion (`rag_ingest`)

The `rag_ingest` tool automates the process of loading data into your RAG index:

**Key Capabilities:**
- Connects to source databases via MySQL protocol
- Transforms data using JSON mapping specifications
- Splits documents into chunks for better retrieval
- Generates vector embeddings (with OpenAI-compatible APIs)
- Supports incremental updates with watermark tracking

**Usage:**
```bash
# Initialize RAG schema
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass -D main \
  init --vec-dim 1536

# Run ingestion
rag_ingest --host 127.0.0.1 --port 6030 --user myuser --password mypass -D main \
  ingest
```

:::tip

See [RAG Ingest CLI](./rag_ingest.md) for complete usage instructions, configuration examples, and troubleshooting.

:::

### 2. MCP Tools (`/mcp/rag`)

The RAG MCP endpoint provides tools for AI agents to query the index:

**Search Tools:**
- `rag.search_fts`: Full-text keyword search
- `rag.search_vector`: Semantic vector search
- `rag.search_hybrid`: Combined hybrid search

**Data Retrieval:**
- `rag.get_chunks`: Fetch chunk content
- `rag.get_docs`: Fetch full documents
- `rag.fetch_from_source`: Refetch from original source

**Management:**
- `rag.admin.stats`: Operational statistics and metrics

:::tip

See [RAG Tools](./mcp_tools_rag.md) for tool specifications and usage examples.

:::

### 3. SQLite3 Server

SQLite3 Server functions as the persistent storage backend for the RAG system. When rag_ingest processes data from external MySQL databases, it connects to SQLite3 Server via the MySQL protocol on port 6030 to store the transformed documents, chunks, and search indexes. The SQLite3 Server then serves these indexed documents to the MCP tools, enabling efficient retrieval through both full-text search (FTS5) and vector similarity search (sqlite-vec).

:::tip

See [SQLite3 Server](../features/sqlite3_server.md) for server configuration and management.

:::

## Getting Started

### Prerequisites

1. **ProxySQL v4.0+** with RAG features enabled
2. **OpenAI-compatible embedding API** (optional, for vector search)
3. **MySQL/MariaDB database** with source data

### Step 1: Configure GenAI and RAG Settings

Configure the embedding provider, vector database path, and enable RAG functionality:

```sql
-- In ProxySQL Admin (port 6032)

-- Configure embedding provider
SET genai-embedding_uri='https://api.openai.com/v1/embeddings';  -- OpenAI-compatible embedding service
SET genai-embedding_model='text-embedding-3-small';              -- Embedding model
SET genai-vector_db_path='/var/lib/proxysql/sqlite3server.db';   -- $DATADIR/sqlite3server.db
SET genai-vector_dimension=1536;                                 -- Vector embedding dimension
SET genai-rag-enabled=true;
SET genai-enabled=true;
LOAD GENAI VARIABLES TO RUNTIME;

-- Configure and enable MCP server
SET mcp-use_ssl=true;   -- Set to false for local development only
SET mcp-enabled=true;
LOAD MCP VARIABLES TO RUNTIME;
```

### Step 2: Configure Your Data Source

Define where to fetch data and how to transform it:

```sql
-- Connect to SQLite3 Server
mysql -h 127.0.0.1 -P 6030 -u myuser -p

-- Configure a source
INSERT INTO rag_sources (
  name, enabled,
  backend_type, backend_host, backend_port,
  backend_user, backend_pass, backend_db,
  table_name, pk_column, where_sql,
  doc_map_json,
  chunking_json,
  embedding_json
) VALUES (
  'my_documents', 1,
  'mysql', '127.0.0.1', 3306,
  'doc_user', 'doc_password', 'my_database',
  'documents', 'id', 'published = 1',
  '{
    "doc_id": {"format": "docs:{id}"},
    "title": {"concat": [{"col": "title"}]},
    "body": {"concat": [{"col": "content"}]},
    "metadata": {
      "pick": ["tags", "created_at", "author"],
      "rename": {"tags": "tags"}
    }
  }',
  '{"enabled":true,"unit":"chars","chunk_size":4000,"overlap":400}',
  '{
    "enabled":true,
    "provider":"openai",
    "api_base":"https://api.openai.com/v1",
    "api_key":"sk-your-key",
    "model":"text-embedding-3-small",
    "dim":1536,
    "batch_size":16
  }'
);
```

### Step 3: Initialize and Ingest Data

```bash
# Initialize the RAG schema
rag_ingest init -h 127.0.0.1 -P 6030 -u myuser -p mypass -D main

# Ingest your data
rag_ingest ingest -h 127.0.0.1 -P 6030 -u myuser -p mypass -D main
```

### Step 4: Query Your Data

Using MCP tools via REST API:

```bash
# Full-text search
curl -X POST https://127.0.0.1:6071/mcp/rag/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "rag.search_fts",
    "arguments": {
      "query": "database performance",
      "k": 10,
      "return": {"include_metadata": true}
    }
  }'

# Vector search
curl -X POST https://127.0.0.1:6071/mcp/rag/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "rag.search_vector",
    "arguments": {
      "query_text": "How do I optimize slow queries?",
      "k": 10
    }
  }'
```

## AI Agent Integration

For AI agents (Claude, OpenAI, etc.), use the provided system prompt:

The [`rag_system_prompt.md`](https://github.com/sysown/proxysql/blob/v4.0/RAG_POC/rag_system_prompt.md) file provides a standardized system prompt for AI agents interacting with ProxySQL RAG. It includes:

- **Phase 1**: Domain discovery using direct database sampling
- **Phase 2**: Multi-path search (FTS, Vector, Hybrid)
- **Phase 3**: Answer synthesis with attribution

## Advanced Features

### Incremental Ingestion

RAG supports incremental updates using watermark-based tracking:

- Only processes new records (based on primary key)
- Skips documents that already exist
- Maintains sync state in `rag_sync_state` table

To re-process documents, clear the sync state:

```sql
DELETE FROM rag_sync_state WHERE source_id = 1;
```

### Filtering and Metadata

Use metadata for advanced filtering:

```sql
-- Filter by tags during search
curl -X POST https://127.0.0.1:6071/mcp/rag/call \
  -d '{
    "name": "rag.search_hybrid",
    "arguments": {
      "query": "performance",
      "filters": {
        "tags_any": ["mysql", "database"],
        "created_after": "2024-01-01"
      },
      "k": 10
    }
  }'
```

### Hybrid Search Tuning

Adjust RRF parameters for optimal ranking:

```json
{
  "name": "rag.search_hybrid",
  "arguments": {
    "query": "database optimization",
    "mode": "fuse",
    "fuse": {
      "fts_k": 50,
      "vec_k": 50,
      "rrf_k0": 60,
      "w_fts": 1.0,
      "w_vec": 1.0
    }
  }
}
```

## Use Cases

### 1. Knowledge Base Search

Index your documentation, FAQs, or support tickets and enable intelligent search:

```json
{
  "name": "knowledge_base",
  "table_name": "articles",
  "where_sql": "status = 'published'",
  "chunking_json": {
    "enabled": true,
    "chunk_size": 4000,
    "overlap": 400
  }
}
```

### 2. Customer Support

Search through support tickets, emails, and chat logs to find relevant solutions:

```json
{
  "name": "support_tickets",
  "table_name": "tickets",
  "where_sql": "resolved = 1",
  "metadata": {
    "pick": ["category", "priority", "customer_id"]
  }
}
```

### 3. Code Documentation

Index code documentation and examples for semantic search:

```json
{
  "name": "code_docs",
  "table_name": "function_docs",
  "embedding_json": {
    "enabled": true,
    "input": {
      "concat": [
        {"col": "function_name"},
        {"lit": "\n"},
        {"col": "description"}
      ]
    }
  }
}
```

## Related Documentation

- [RAG Ingest CLI](./rag_ingest.md) - Data ingestion configuration and usage
- [RAG Tools](./mcp_tools_rag.md) - MCP tool specifications
- [Full-Text Search](./mcp_fts.md) - FTS5 search capabilities
- [SQLite3 Server](../features/sqlite3_server.md) - Server configuration
- [MCP Server](./mcp_server.md) - Protocol and endpoint configuration
- [MCP Variables](../references/mcp_variables) - Configuration reference