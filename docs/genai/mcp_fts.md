# Full-Text Search (FTS)

## Overview

ProxySQL v4.0 includes a high-performance **Full-Text Search (FTS)** engine integrated directly into the MCP server. This allows AI agents to perform rapid, keyword-based discovery across large volumes of indexed documentation, logs, or database metadata stored in the [MCP Catalog](./mcp_catalog).

The FTS implementation is based on **SQLite FTS5** and is a foundational component of the ProxySQL [RAG (Retrieval-Augmented Generation)](./mcp_tools_rag) capabilities.

---

## Populating the FTS Index

To create and populate the FTS index with your data, use the **[`rag_ingest`](./rag_ingest)** command-line tool. This tool:

- Connects to SQLite3 Server via the MySQL protocol
- Extracts data from backend MySQL sources
- Chunks text according to configurable strategies
- Embeds chunks into the FTS5 index for fast retrieval

:::tip

See the **[RAG Ingest Tool](./rag_ingest)** documentation for step-by-step instructions on configuring and running data ingestion.

:::

## Key Features

### 1. BM25 Ranking
ProxySQL uses the industry-standard **BM25 (Best Matching 25)** algorithm to rank search results. This ensures that the most relevant documents appear at the top based on term frequency and document length.

### 2. Advanced Filtering
FTS queries can be combined with metadata filters to narrow down results. Supported filters include:
- **Source Filtering**: Limit search to specific data sources (e.g., specific database clusters).
- **Temporal Filtering**: Search for data created before or after specific timestamps.
- **Tagging**: Filter by arbitrary tags or categories assigned during indexing.

### 3. Integrated Snippets
The FTS engine can return "snippets" of the matching text, highlighting the search terms in context. This helps AI agents quickly identify which parts of a document are most relevant to the user's question.

---

## How to Use FTS

AI agents interact with the FTS engine via the `rag.search_fts` tool on the `/mcp/rag` endpoint.

### Example Tool Call

```json
{
  "method": "tools/call",
  "params": {
    "name": "rag.search_fts",
    "arguments": {
      "query": "connection pool timeout",
      "k": 5,
      "filters": {
        "source_names": ["documentation_v3", "release_notes"]
      },
      "return": {
        "include_snippets": true
      }
    }
  }
}
```

### Response Structure
The response returns an array of matching "chunks," including the raw FTS score, the matching text body, and any requested metadata.

---

## Search Syntax

The `query` parameter supports the standard SQLite FTS5 search syntax, including:
- **Boolean Operators**: `AND`, `OR`, `NOT`.
- **Phrase Searches**: `"connection pool"`.
- **Prefix Searches**: `proxy*` (matches `proxy`, `proxysql`, `proxies`).
- **Proximity Searches**: `NEAR(connection timeout, 5)` (finds terms within 5 words of each other).

---

## Internal Tables

The FTS engine utilizes several specialized tables in the MCP Catalog:
- `rag_fts_chunks`: The virtual FTS5 table containing the search index.
- `rag_chunks`: The physical storage for text segments.
- `rag_documents`: Metadata for the indexed files or objects.

## Security

FTS queries are subject to **MCP Query Rules**. Administrators can restrict search access based on tool name (`rag.search_fts`), specific keywords, or targeted data sources.
