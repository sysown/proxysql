# RAG Tools (`/mcp/rag`)

The tools available at the `/mcp/rag` endpoint are designed for Retrieval Augmented Generation (RAG) workflows, including advanced search and source data retrieval.

## Search Tools

| Tool | Description |
| :--- | :--- |
| `rag.search_fts` | Performs a full-text search across indexed documents. |
| `rag.search_vector` | Executes a vector-based semantic search. |
| `rag.search_hybrid` | Combines full-text and vector search for more relevant results. |

## Data Retrieval Tools

| Tool | Description |
| :--- | :--- |
| `rag.get_chunks` | Retrieves specific chunks of text from indexed documents. |
| `rag.get_docs` | Fetches metadata or full content for specified documents. |
| `rag.fetch_from_source` | Retrieves the original source data for a given document or chunk. |

## Management & Monitoring

| Tool | Description |
| :--- | :--- |
| `rag.admin.stats` | Provides detailed statistics on RAG index usage and performance. |
