# Query Tools (`/mcp/query`)

The tools available at the `/mcp/query` endpoint focus on database exploration, schema discovery, and data retrieval.

## Core Database Tools

| Tool | Description |
| :--- | :--- |
| `list_schemas` | Lists all available database schemas. |
| `list_tables` | Lists all tables in a specific schema. |
| `get_constraints` | Retrieves primary and foreign key constraints. |
| `run_sql_readonly` | Executes a SQL query in read-only mode. |
| `explain_sql` | Generates an execution plan for a SQL query. |

## Discovery & Catalog Tools

| Tool | Description |
| :--- | :--- |
| `discovery.run_static` | Triggers a harvest of database metadata. |
| `catalog.init` | Initializes the MCP catalog. |
| `catalog.search` | Full-text search over discovered tables and columns. |
| `catalog.get_object` | Fetches details for a specific table or view. |
| `catalog.list_objects` | Lists all discovered objects in the catalog. |
| `catalog.get_relationships` | Lists relationships between tables. |

## LLM Context & Agent Management

| Tool | Description |
| :--- | :--- |
| `agent.run_start` | Starts a new tracking run for an AI agent. |
| `agent.run_finish` | Marks an agent run as complete. |
| `agent.event_append` | Appends a log event to an agent run. |
| `llm.summary_upsert` | Stores an LLM-generated summary for a database object. |
| `llm.note_add` | Adds a specific note or observation about the schema. |
| `llm.search` | Semantic search over LLM-generated summaries and notes. |

## Specialized Tools

| Tool | Description |
| :--- | :--- |
| `suggest_joins` | Suggests potential joins between tables based on catalog metadata. |
| `stats.get_tool_usage` | Retrieves performance statistics for MCP tools. |
