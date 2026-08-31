# MCP Endpoints

The ProxySQL MCP server exposes several HTTP/HTTPS endpoints, each serving a specific set of Model Context Protocol capabilities. All endpoints are prefixed with `/mcp`.

## List of Endpoints

| Endpoint | Status | Handler | Purpose |
| :--- | :--- | :--- | :--- |
| `/mcp/query` | **Supported** | Query Tool Handler | Schema discovery, search, and data retrieval. |
| `/mcp/rag` | **Supported** | RAG Tool Handler | Retrieval Augmented Generation utilities. |
| `/mcp/config` | Under Development | Config Tool Handler | Manage ProxySQL configuration via AI. |
| `/mcp/admin` | Under Development | Admin Tool Handler | Administrative tasks and node management. |
| `/mcp/cache` | Under Development | Cache Tool Handler | Query cache inspection and management. |
| `/mcp/observe` | Under Development | Observe Tool Handler | Real-time monitoring and metrics. |
| `/mcp/ai` | Under Development | AI Tool Handler | LLM bridge and anomaly detection. |

## Supported Endpoints

### The Query Endpoint (`/mcp/query`)

The `/mcp/query` endpoint is the primary interface for AI agents. It implements the standard MCP `tools/call` method, allowing agents to execute database-related tools. For a full list of tools available here, see [Query Tools](./mcp_tools_query).

### The RAG Endpoint (`/mcp/rag`)

The `/mcp/rag` endpoint provides specialized tools for Retrieval Augmented Generation, including full-text and vector search capabilities. For a full list of tools available here, see [RAG Tools](./mcp_tools_rag).

## Connectivity & Authentication

### Protocol Details
- **Method**: `POST`
- **Content-Type**: `application/json`
- **Request Format**: JSON-RPC 2.0

### Authentication
Authentication is enforced via Bearer tokens configured in the [MCP Variables](../references/mcp_variables).

```http
POST /mcp/query HTTP/1.1
Host: localhost:6071
Authorization: Bearer <mcp-query_endpoint_auth>
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "list_tables",
    "arguments": {
      "schema": "main"
    }
  },
  "id": 1
}
```

## Security & Rules

All requests to any endpoint are filtered through the [MCP Query Rules](../main_runtime/mcp_tables). This ensures that even if an agent has a valid token, it can only perform actions permitted by the ProxySQL administrator.