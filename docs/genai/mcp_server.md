# MCP Server

## Overview

ProxySQL v4.0 introduces native support for the **Model Context Protocol (MCP)**. This feature allows ProxySQL to act as an MCP server, enabling AI agents (like Claude, ChatGPT, or custom LLM-based applications) to interact directly with ProxySQL to discover database schemas, execute queries, and manage configuration through a standardized protocol.

By exposing ProxySQL as an MCP server, you can provide LLMs with deep context about your database infrastructure, including:
- Real-time schema definitions.
- Query execution capabilities with built-in safety rules.
- Performance metrics and query digests.
- Configuration management.

## Connectivity

The MCP server in ProxySQL operates over HTTP/HTTPS and supports JSON-RPC 2.0 as defined by the Model Context Protocol specification.

- **Default Port**: `6071`
- **Protocol**: HTTP (can be upgraded to HTTPS with SSL)
- **Authentication**: Bearer tokens per endpoint.

## Key Features

### 1. Standardized Interaction
AI agents can use standard MCP clients to "talk" to ProxySQL. This eliminates the need for custom database connectors for every AI application.

### 2. Built-in Safety (MCP Query Rules)
Just like MySQL and PostgreSQL traffic, MCP requests are subject to **MCP Query Rules**. This allows administrators to restrict which tools or queries an AI agent can execute, preventing accidental data modification or unauthorized access.

### 3. Autodiscovery
ProxySQL can automatically discover the schemas, tables, and relationships within your backend MySQL/PostgreSQL servers and present them as "Context" to the LLM.

### 4. Tooling
The MCP server exposes a set of **Tools** that agents can call. These include:
- `query`: Execute a SQL query.
- `get_schema`: Retrieve table definitions.
- `list_tables`: List available tables.
- (And more...)

## Getting Started

To enable the MCP server, you need to set the `mcp-enabled` global variable to `true`:

```sql
SET mcp-enabled='true';
LOAD MCP VARIABLES TO RUNTIME;
```

For more details on configuration, see the [MCP Variables](../references/mcp_variables) and [MCP Configuration Tables](../main_runtime/mcp_tables) sections.
