# Natural Language to SQL (NL2SQL)

## Overview

ProxySQL v4.0 implements **Natural Language to SQL (NL2SQL)** using an **Agentic Architecture**. Instead of ProxySQL internally translating queries, it acts as a powerful **Semantic Infrastructure** for AI agents (like Claude Code, ChatGPT, or custom LLM agents).

By exposing database metadata and execution capabilities via the [Model Context Protocol (MCP)](./mcp_server), ProxySQL enables agents to discover schemas, find relevant business logic, execute safe queries, and **learn** from every interaction.

---

## The Agentic Workflow

The NL2SQL process is driven by an AI agent following a deterministic, four-step workflow defined in its system prompt.

### 1. Semantic Search & Discovery
When a user asks a question, the agent first calls the `llm_search` tool.
- **Input**: The user's natural language question.
- **Process**: ProxySQL performs a full-text and semantic search over the [MCP Catalog](./mcp_catalog).
- **Optimization**: The agent uses the `include_objects=true` parameter to retrieve both matching query templates AND the complete table schemas (columns, indexes, types) in a single request.

### 2. Analysis & Reasoning
The agent analyzes the search results:
- **Template Match**: If a highly similar question (score < -3.0) already exists in the catalog, the agent reuses the pre-validated `example_sql`.
- **Schema Synthesis**: If no match is found, the agent uses the retrieved table schemas to reason about the data and generate a new, optimized SQL query.

### 3. Safe Execution
The agent executes the SQL using the `run_sql_readonly` tool.
- **Protocol**: The request is sent via the `/mcp/query` endpoint.
- **Security**: The generated SQL is automatically validated against [MCP Query Rules](../main_runtime/mcp_tables) to prevent unauthorized access or resource-heavy queries.

### 4. Continuous Learning
If the agent generated a **new** query that successfully answered the user's question, it "teaches" ProxySQL by calling `llm.question_template_add`.
- **Persistence**: The new question, its SQL translation, and the relevant metadata are stored in the catalog.
- **Instant Reuse**: The next time any user asks a similar question, the agent will find it in Step 1 and answer instantly without re-generating the SQL.

---

## Key Advantages

### Context-Rich Intelligence
Traditional NL2SQL often fails because the LLM doesn't know your specific schema or business logic. ProxySQL provides the agent with the **entire catalog context**, including natural language summaries and notes attached to tables.

### High Efficiency
By grouping schema retrieval with semantic search (`include_objects=true`), ProxySQL minimizes round-trips to the server, making the interaction feel snappy and responsive.

### Governance & Safety
Because the agent interacts via the MCP server, every action is logged and governed by ProxySQL's robust security layer. Administrators can see exactly what the AI is doing via [MCP Stats](./mcp_stats).

---

## Practical Example

**User**: "Who are our top 5 customers by spend in 2023?"

**Agent Workflow**:
1.  **Call `llm_search`**: Finds no existing template, but retrieves `Customers` and `Invoices` schemas.
2.  **Generate SQL**: Generates `SELECT ... JOIN ... WHERE date LIKE '2023%' ... LIMIT 5`.
3.  **Execute**: Calls `run_sql_readonly` and gets the data.
4.  **Learn**: Calls `llm.question_template_add` to save this "Top Customers by Year" logic for the next user.
5.  **Respond**: "Here are the top 5 customers for 2023..."

---

## Configuration

To set up an NL2SQL agent:
1.  **Enable MCP**: Set `mcp-enabled='true'`.
2.  **Prepare Catalog**: Run `discovery.run_static` via the MCP server to harvest metadata.
3.  **Deploy Agent**: Use a script like `/scripts/mcp/demo_agent_claude.sh` to launch your AI agent with the correct system prompts.