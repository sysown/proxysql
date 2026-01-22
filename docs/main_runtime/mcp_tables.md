# MCP Tables

This section documents the tables used to configure and monitor the Model Context Protocol (MCP) server.

## List of MCP Tables

| Tablename | Description |
| :--- | :--- |
| [mcp_query_rules](#mcp_query_rules) | Routing and security rules for MCP requests |
| [runtime_mcp_query_rules](#runtime_mcp_query_rules) | Active MCP query rules in memory |
| [stats_mcp_query_rules](#stats_mcp_query_rules) | Hit statistics for MCP query rules |

---

### mcp_query_rules

The `mcp_query_rules` table defines security and routing policies for requests coming through the MCP server. It is similar in design to `mysql_query_rules`.

**Table Definition:**

```sql
CREATE TABLE mcp_query_rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0,
    username VARCHAR,
    schemaname VARCHAR,
    tool_name VARCHAR,
    match_pattern VARCHAR,
    negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0,
    re_modifiers VARCHAR DEFAULT 'CASELESS',
    flagIN INT NOT NULL DEFAULT 0,
    flagOUT INT CHECK (flagOUT >= 0),
    replace_pattern VARCHAR,
    timeout_ms INT CHECK (timeout_ms >= 0),
    error_msg VARCHAR,
    OK_msg VARCHAR,
    log INT CHECK (log IN (0,1)),
    apply INT CHECK (apply IN (0,1)) NOT NULL DEFAULT 1,
    comment VARCHAR
);
```

**Fields Description:**

- **rule_id**: Unique identifier for the rule. Rules are processed in `rule_id` order.
- **active**: Only rules with `active=1` are loaded into runtime.
- **username**: Filters requests based on the MCP username.
- **schemaname**: Filters requests based on the targeted database schema.
- **tool_name**: Filters requests based on the specific MCP Tool being called (e.g., `query`, `get_schema`).
- **match_pattern**: Regular expression to match against the query text or tool arguments.
- **negate_match_pattern**: If set to 1, the rule matches only if `match_pattern` does *not* match.
- **flagIN / flagOUT**: Used for chaining rules, similar to MySQL query rules.
- **replace_pattern**: Pattern to rewrite the query or tool arguments.
- **timeout_ms**: Per-rule execution timeout.
- **error_msg**: If matched, ProxySQL will block the request and return this error message to the AI agent.
- **apply**: If set to 1, no further rules are evaluated after this one matches.

### runtime_mcp_query_rules

This table shows the active MCP query rules currently in memory. It has the same schema as `mcp_query_rules`.

### stats_mcp_query_rules

This table tracks how many times each MCP rule has been triggered.

```sql
CREATE TABLE stats_mcp_query_rules (
    rule_id INTEGER PRIMARY KEY,
    hits INT NOT NULL
);
```
