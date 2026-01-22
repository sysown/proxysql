# MCP Stats

ProxySQL v4.0 provides detailed statistics for all traffic handled by the Model Context Protocol (MCP) server. These stats allow administrators to monitor AI agent behavior, performance, and rule effectiveness.

## List of MCP Stats Tables

| Tablename | Description |
| :--- | :--- |
| [stats_mcp_query_digest](#stats_mcp_query_digest) | Aggregated statistics for MCP queries and tool calls |
| [stats_mcp_query_digest_reset](#stats_mcp_query_digest_reset) | Same as above, but resets on query |
| [stats_mcp_query_tools_counters](#stats_mcp_query_tools_counters) | Counters for tool usage per schema |

---

### stats_mcp_query_digest

This table is the MCP equivalent of `stats_mysql_query_digest`. It aggregates requests based on the tool name and the normalized query text (digest).

**Table Definition:**

```sql
CREATE TABLE stats_mcp_query_digest (
    tool_name VARCHAR NOT NULL,
    run_id INT,
    digest VARCHAR NOT NULL,
    digest_text VARCHAR NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    sum_time INTEGER NOT NULL,
    min_time INTEGER NOT NULL,
    max_time INTEGER NOT NULL,
    PRIMARY KEY(tool_name, run_id, digest)
);
```

**Fields Description:**

- **tool_name**: The MCP tool that was called (e.g., `query`).
- **digest**: The hash of the normalized query or tool input.
- **digest_text**: The human-readable normalized text.
- **count_star**: Total number of times this specific digest was executed.
- **sum_time**: Total execution time in microseconds.
- **min_time / max_time**: Minimum and maximum execution times observed.

### stats_mcp_query_tools_counters

This table provides a high-level overview of which tools are being used and how they perform across different database schemas.

```sql
CREATE TABLE stats_mcp_query_tools_counters (
    tool VARCHAR NOT NULL,
    schema VARCHAR NOT NULL,
    count INT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    sum_time INTEGER NOT NULL,
    min_time INTEGER NOT NULL,
    max_time INTEGER NOT NULL,
    PRIMARY KEY (tool, schema)
);
```
