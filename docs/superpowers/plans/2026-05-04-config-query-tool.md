# Config Query Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a server-enforced SQL query tool to `/mcp/config` so MCP clients can inspect and modify ProxySQL configuration without a growing pile of dedicated verbs.

**Architecture:** Keep the `/mcp/config` endpoint as the admin/config surface, but add a single `query` tool that executes SQL against the admin database through `admindb->execute_statement()`. The MCP server will reject unsafe statements before execution using a local policy gate that blocks DDL, attachment, pragma, and other hazardous statements while still allowing controlled reads and writes.

**Tech Stack:** C++17, `SQLite3DB`, `nlohmann::json`, existing MCP tool-handler framework, TAP tests.

---

### Task 1: Add the config query tool contract

**Files:**
- Modify: `plugins/genai/include/Config_Tool_Handler.h`
- Modify: `plugins/genai/src/tool_handlers/Config_Tool_Handler.cpp`

- [ ] **Step 1: Update the tool list and dispatch**

Add a new `query` tool to `/mcp/config` with this input schema:

```cpp
tools.push_back(create_tool_description(
	"query",
	"Execute constrained SQL against the ProxySQL admin/config database",
	{
		{"type", "object"},
		{"properties", {
			{"sql", {
				{"type", "string"},
				{"description", "Single SQL statement to execute"}
			}},
			{"limit", {
				{"type", "integer"},
				{"description", "Optional row limit for result sets"}
			}}
		}},
		{"required", {"sql"}}
	}
));
```

Route `execute_tool("query", ...)` to a new private helper that validates the SQL text, runs it through `GloAdmin->admindb`, and returns a structured result.

- [ ] **Step 2: Add the execution helper**

Implement a helper in `Config_Tool_Handler.cpp` that:

```cpp
json handle_query(const std::string& sql, int limit);
```

The helper should:

- reject empty SQL
- reject multi-statement SQL
- reject forbidden statement classes
- execute the statement with `GloAdmin->admindb->execute_statement(...)`
- convert any resultset with `MCP_Tool_Handler::resultset_to_json(...)`
- return a JSON object containing at least:
  - `sql`
  - `rows_affected`
  - `columns`
  - `rows`
  - `message` for non-row statements

- [ ] **Step 3: Keep existing config verbs intact**

Leave `get_config`, `set_config`, `list_variables`, and `get_status` in place for convenience. Keep `reload_config` for now, but do not expand it in this task.

- [ ] **Step 4: Commit**

```bash
git add plugins/genai/include/Config_Tool_Handler.h plugins/genai/src/tool_handlers/Config_Tool_Handler.cpp
git commit -m "feat(genai): add constrained config query tool"
```

### Task 2: Enforce SQL safety on the server side

**Files:**
- Modify: `plugins/genai/src/tool_handlers/Config_Tool_Handler.cpp`

- [ ] **Step 1: Add a SQL policy helper**

Implement a local helper that validates the SQL string before execution. The first pass should reject:

```cpp
PRAGMA
ATTACH
DETACH
DROP
ALTER
CREATE
TRUNCATE
VACUUM
REINDEX
LOAD_EXTENSION
```

Also reject:

- empty statements
- semicolon-separated multi-statements
- leading SQL comments that hide a forbidden first token

The helper should accept controlled DML and queries such as `SELECT`, `WITH`, `INSERT`, `UPDATE`, `DELETE`, and `REPLACE`.

```cpp
bool is_allowed_config_sql(const std::string& sql, std::string& error);
```

- [ ] **Step 2: Add execution guardrails**

Before execution, apply the policy helper and return an error response when the SQL is blocked. Use a clear error message that names the blocked token/class so the client can adapt.

Also apply a hard row cap to result sets if the caller passes a `limit`, and clamp the value to a sane upper bound inside the handler.

- [ ] **Step 3: Commit**

```bash
git add plugins/genai/src/tool_handlers/Config_Tool_Handler.cpp
git commit -m "feat(genai): enforce config query sql policy"
```

### Task 3: Add tests for allowed and blocked SQL

**Files:**
- Create: `test/tap/tests/unit/genai_config_tool_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

- [ ] **Step 1: Write the unit test**

Add a unit test that instantiates `Config_Tool_Handler` with a minimal MCP handler and checks these cases:

```cpp
ok(handler.execute_tool("query", json{{"sql", "SELECT variable_name FROM global_variables LIMIT 1"}})["success"] == true,
   "SELECT is allowed");
ok(handler.execute_tool("query", json{{"sql", "UPDATE global_variables SET variable_value='1' WHERE variable_name='x'"}})["success"] == true,
   "UPDATE is allowed");
ok(handler.execute_tool("query", json{{"sql", "PRAGMA journal_mode"}})["success"] == false,
   "PRAGMA is blocked");
ok(handler.execute_tool("query", json{{"sql", "DROP TABLE global_variables"}})["success"] == false,
   "DROP is blocked");
ok(handler.execute_tool("query", json{{"sql", "SELECT 1; SELECT 2"}})["success"] == false,
   "multi-statement input is blocked");
```

- [ ] **Step 2: Build and run the test**

Run the targeted unit test binary from `test/tap/tests/unit/Makefile` and verify the new assertions pass.

- [ ] **Step 3: Commit**

```bash
git add test/tap/tests/unit/genai_config_tool_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "test(genai): cover config query policy"
```

### Task 4: Verify the endpoint contract end to end

**Files:**
- Modify: `plugins/genai/src/ProxySQL_MCP_Server.cpp` only if the config tool name or endpoint wiring needs adjustment
- Test: existing MCP integration tests or a new TAP integration test under `test/tap/tests/`

- [ ] **Step 1: Verify endpoint registration**

Confirm `/mcp/config` still registers through the existing server wiring and that the new `query` tool appears in `tools/list`.

- [ ] **Step 2: Add an integration smoke test**

Add a TAP test that:

```cpp
handler.execute_tool("get_config", json{{"variable_name", "mcp_enabled"}});
handler.execute_tool("query", json{{"sql", "SELECT variable_name FROM global_variables LIMIT 1"}});
handler.execute_tool("query", json{{"sql", "PRAGMA journal_mode"}});
```

and checks that the first two succeed and the last one is rejected.

- [ ] **Step 3: Commit**

```bash
git add plugins/genai/src/ProxySQL_MCP_Server.cpp test/tap/tests/<new-or-existing-integration-test>
git commit -m "test(genai): verify config query endpoint"
```

---

### Coverage Check

- `/mcp/config` query tool: Task 1
- Server-side SQL policy: Task 2
- Regression coverage: Task 3
- End-to-end endpoint behavior: Task 4

