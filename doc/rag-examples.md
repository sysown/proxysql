# RAG Tool Examples

This document provides examples of how to use the RAG tools via the MCP endpoint.

## Prerequisites

Make sure ProxySQL is running with GenAI and RAG enabled:

```sql
-- In ProxySQL admin interface
SET genai.enabled = true;
SET genai.rag_enabled = true;
LOAD genai VARIABLES TO RUNTIME;
```

## Tool Discovery

### List all RAG tools

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":"1"}' \
  https://127.0.0.1:6071/mcp/rag
```

### Get tool description

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/describe","params":{"name":"rag.search_fts"},"id":"1"}' \
  https://127.0.0.1:6071/mcp/rag
```

## Search Tools

### FTS Search

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.search_fts","arguments":{"query":"mysql performance","k":5}},"id":"1"}' \
  https://127.0.0.1:6071/mcp/rag
```

### Vector Search

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.search_vector","arguments":{"query_text":"database optimization techniques","k":5}},"id":"1"}' \
  https://127.0.0.1:6071/mcp/rag
```

### Hybrid Search

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.search_hybrid","arguments":{"query":"sql query optimization","mode":"fuse","k":5}},"id":"1"}' \
  https://127.0.0.1:6071/mcp/rag
```

## Fetch Tools

### Get Chunks

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.get_chunks","arguments":{"chunk_ids":["chunk1","chunk2"]}},"id":"1"}' \
  https://127.0.0.1:6071/mcp/rag
```

### Get Documents

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.get_docs","arguments":{"doc_ids":["doc1","doc2"]}},"id":"1"}' \
  https://127.0.0.1:6071/mcp/rag
```

## Admin Tools

### Get Statistics

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rag.admin.stats"},"id":"1"}' \
  https://127.0.0.1:6071/mcp/rag
```