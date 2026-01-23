# MCP Autodiscovery

ProxySQL v4.0 features a deterministic "Two-Phase Discovery" mechanism that allows LLMs to understand the database structure with high accuracy.

## How it works

The discovery process is typically triggered by an AI agent using the `discovery.run_static` tool. This process iterates through the backend MySQL/PostgreSQL servers and populates the **MCP Catalog**.

### Phase 1: Static Harvesting
ProxySQL connects to the configured backend servers and extracts:
- Schema names.
- Table and View definitions.
- Column metadata (types, nullability, defaults).
- Index definitions.
- Foreign key relationships.

### Phase 2: Metadata Enrichment
Once the basic structure is harvested, ProxySQL (optionally with LLM assistance) can:
- Inferred relationships between tables.
- Generate summaries for complex views or tables.
- Track "Agent Runs" to maintain context between different LLM sessions.

## Deterministic Run IDs

Every discovery execution is assigned a unique `run_id`. This allows ProxySQL to maintain a history of the schema state. AI agents can bind themselves to a specific `run_id` to ensure consistency even if the schema changes while they are processing a request.

## Storage (The MCP Catalog)

The harvested metadata is stored in a local SQLite database named `mcp_catalog.db`, located in ProxySQL's data directory. This catalog powers the search and retrieval tools used by the MCP server.

For a detailed look at the catalog structure, see the [MCP Catalog](./mcp_catalog) documentation.
