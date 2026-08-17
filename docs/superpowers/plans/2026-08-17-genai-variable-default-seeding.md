# GenAI Plugin Variable Default Seeding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore persistent, non-destructive startup seeding for all MCP and GenAI plugin variables tracked by issue #6099.

**Architecture:** During `genai_start()`, collect names and constructor-default values from the two plugin-owned handlers, then insert missing rows into the persistent config database and in-memory Admin database before loading runtime state. A single database writer handles both variable families and uses one transaction plus `INSERT OR IGNORE`, so existing operator values win and partial installations are repaired idempotently.

**Tech Stack:** C++17, ProxySQL plugin ABI, `SQLite3DB`, bundled SQLite prepared-statement API, TAP unit tests, GNU Make.

## Global Constraints

- Persist defaults in both configdb and admindb; do not implement a memory-only fix.
- Preserve every existing operator value with `INSERT OR IGNORE`; never use `REPLACE` in the seeding path.
- Seed variables before `mcp_load_variables_from_admindb()` and `genai_load_variables_from_admindb()` run.
- Keep `runtime_global_variables` out of this change; issue #6100 owns runtime projection.
- Do not change variable names, compiled defaults, validation, plugin ABI, endpoint authentication, or CI workflow definitions.
- Leave `CI-unit-tests-asan-coverage` unchanged.

---

## File map

- `test/tap/tests/unit/genai_plugin_load_unit-t.cpp`: extend the real plugin lifecycle test with fresh/partial-install persistence and preservation assertions.
- `plugins/genai/src/plugin_main.cpp`: collect handler defaults, seed both databases transactionally, and call the seeding path before runtime loads.
- `docs/superpowers/specs/2026-08-17-genai-variable-default-seeding-design.md`: approved design; no further edits expected unless implementation exposes a contradiction.

### Task 1: Add the failing lifecycle regression

**Files:**
- Modify: `test/tap/tests/unit/genai_plugin_load_unit-t.cpp:20-110`

**Interfaces:**
- Consumes: existing `ProxySQL_PluginManager::init_all()` / `start_all()` lifecycle and `SQLite3DB::return_one_int()`.
- Produces: a 57-assertion lifecycle test that requires exactly 14 persisted MCP variables and 32 persisted GenAI variables in each database while preserving pre-existing values.

- [ ] **Step 1: Give configdb the minimal schema used by the seeding contract**

Extract the existing `global_variables` DDL into a helper and invoke it for both database handles. Keep the MCP table DDLs Admin-only:

```cpp
void setup_global_variables_schema(SQLite3DB* db) {
	db->execute("CREATE TABLE IF NOT EXISTS global_variables ("
	            " variable_name TEXT PRIMARY KEY, variable_value TEXT)");
}

void setup_admindb_schema(SQLite3DB* db) {
	setup_global_variables_schema(db);
	// Existing mcp_auth_profiles, mcp_target_profiles, runtime tables,
	// and mcp_query_rules DDLs remain here unchanged.
}
```

After opening the three in-memory databases, initialize both schemas:

```cpp
setup_admindb_schema(g_admindb);
setup_global_variables_schema(g_configdb);
```

- [ ] **Step 2: Model persisted operator values before plugin startup**

Immediately after schema setup, seed a partial configuration into both databases. These values deliberately differ from constructor defaults:

```cpp
for (SQLite3DB* db : {g_configdb, g_admindb}) {
	if (!db->execute(
		"INSERT INTO global_variables(variable_name, variable_value) VALUES"
		" ('mcp-port','7123'),('genai-threads','7')")) {
		BAIL_OUT("failed to seed persisted GenAI plugin variables");
	}
}
```

- [ ] **Step 3: Add post-start persistence and preservation assertions**

Change `plan(45)` to `plan(57)`. Immediately after `start_all()` succeeds, run six assertions for each database:

```cpp
struct VariableDatabase {
	SQLite3DB* db;
	const char* name;
};

for (const VariableDatabase& target : {
	VariableDatabase{g_configdb, "configdb"},
	VariableDatabase{g_admindb, "admindb"}
}) {
	const int mcp_count = target.db->return_one_int(
		"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'mcp-%'");
	const int genai_count = target.db->return_one_int(
		"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'genai-%'");

	ok(mcp_count == 14, "%s contains all 14 MCP variables (got %d)",
	   target.name, mcp_count);
	ok(genai_count == 32, "%s contains all 32 GenAI variables (got %d)",
	   target.name, genai_count);
	ok(target.db->return_one_int(
		"SELECT COUNT(*) FROM global_variables"
		" WHERE variable_name='mcp-port' AND variable_value='7123'") == 1,
	   "%s preserves persisted mcp-port", target.name);
	ok(target.db->return_one_int(
		"SELECT COUNT(*) FROM global_variables"
		" WHERE variable_name='genai-threads' AND variable_value='7'") == 1,
	   "%s preserves persisted genai-threads", target.name);
	ok(target.db->return_one_int(
		"SELECT COUNT(*) FROM global_variables"
		" WHERE variable_name='mcp-timeout_ms' AND variable_value='30000'") == 1,
	   "%s persists missing mcp-timeout_ms default", target.name);
	ok(target.db->return_one_int(
		"SELECT COUNT(*) FROM global_variables"
		" WHERE variable_name='genai-rag_timeout_ms' AND variable_value='2000'") == 1,
	   "%s persists missing genai-rag_timeout_ms default", target.name);
}
```

The primary key on `variable_name` and exact counts jointly prove that startup creates one row per supported variable without duplicates.

- [ ] **Step 4: Build and run the test to establish RED**

Run:

```bash
make -C test/tap/tests/unit genai_plugin_load_unit-t
test/tap/tests/unit/genai_plugin_load_unit-t
```

Expected: the existing 45 lifecycle assertions remain successful; the new row-count and missing-default assertions fail because each database still contains only the two pre-seeded rows. The four preservation assertions pass, proving the failure is specifically missing default seeding.

### Task 2: Seed both variable families transactionally at plugin start

**Files:**
- Modify: `plugins/genai/src/plugin_main.cpp:50-100`
- Modify: `plugins/genai/src/plugin_main.cpp:675-698`

**Interfaces:**
- Consumes: `MCP_Threads_Handler::get_variables_list()`, `get_variable_string()`, `GenAI_Threads_Handler::get_variables_list()`, `get_variable()`, and plugin-service `get_admindb()` / `get_configdb()`.
- Produces: anonymous-namespace helpers `collect_variable_defaults(GenAIPluginContext&, VariableDefaults&)`, `seed_variable_defaults(SQLite3DB*, const VariableDefaults&, const char*)`, and `seed_plugin_variable_defaults(GenAIPluginContext&)`.

- [ ] **Step 1: Add a value type and a single variable-list cleanup helper**

Add `<utility>` and `<vector>` explicitly, then define these anonymous-namespace utilities near `embed_query_via_glogath`:

```cpp
using VariableDefaults = std::vector<std::pair<std::string, std::string>>;

void free_variable_names(char** names) {
	if (names == nullptr) return;
	for (int i = 0; names[i] != nullptr; ++i) free(names[i]);
	free(names);
}
```

- [ ] **Step 2: Collect the complete MCP and GenAI default set before touching either database**

Implement one collector that appends qualified names and current constructor values. On any read/allocation failure, free owned memory and return false without starting a transaction:

```cpp
bool collect_variable_defaults(GenAIPluginContext& ctx, VariableDefaults& defaults) {
	if (ctx.mcp == nullptr || GloGATH == nullptr) return false;

	char** mcp_names = ctx.mcp->get_variables_list();
	if (mcp_names == nullptr) return false;
	for (int i = 0; mcp_names[i] != nullptr; ++i) {
		std::string value;
		if (!ctx.mcp->get_variable_string(mcp_names[i], value)) {
			free_variable_names(mcp_names);
			return false;
		}
		defaults.emplace_back(std::string("mcp-") + mcp_names[i], std::move(value));
	}
	free_variable_names(mcp_names);

	char** genai_names = GloGATH->get_variables_list();
	if (genai_names == nullptr) return false;
	for (int i = 0; genai_names[i] != nullptr; ++i) {
		char* value = GloGATH->get_variable(genai_names[i]);
		defaults.emplace_back(
			std::string("genai-") + genai_names[i], value != nullptr ? value : "");
		free(value);
	}
	free_variable_names(genai_names);
	return true;
}
```

- [ ] **Step 3: Implement the transactional `INSERT OR IGNORE` writer**

Prepare exactly this statement so existing rows can never be replaced:

```cpp
"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(?1, ?2)"
```

`seed_variable_defaults()` must:

1. reject a null database;
2. prepare the statement and log the database label plus SQLite return code on failure;
3. begin one transaction;
4. bind the qualified name and value with `SQLITE_TRANSIENT`;
5. require `proxy_sqlite3_step()` to return `SQLITE_DONE`;
6. clear bindings and reset after every row;
7. roll back and log the failing variable on any bind, step, clear, reset, or commit failure;
8. return true only after commit succeeds.

Use the bundled function pointers already used by `mcp_save_variables_to_admindb()`:

```cpp
(*proxy_sqlite3_bind_text)(statement, 1, item.first.c_str(), -1, SQLITE_TRANSIENT);
(*proxy_sqlite3_bind_text)(statement, 2, item.second.c_str(), -1, SQLITE_TRANSIENT);
(*proxy_sqlite3_step)(statement);
(*proxy_sqlite3_clear_bindings)(statement);
(*proxy_sqlite3_reset)(statement);
```

Do not use `SAFE_SQLITE3_STEP2` here: the seeding path must roll back and return a controlled plugin-start failure rather than assert.

- [ ] **Step 4: Seed configdb and admindb before runtime loads**

Implement the orchestration helper:

```cpp
bool seed_plugin_variable_defaults(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr ||
	    ctx.services->get_configdb == nullptr ||
	    ctx.services->get_admindb == nullptr) {
		return false;
	}

	VariableDefaults defaults;
	if (!collect_variable_defaults(ctx, defaults)) return false;

	SQLite3DB* configdb = ctx.services->get_configdb();
	SQLite3DB* admindb = ctx.services->get_admindb();
	return seed_variable_defaults(configdb, defaults, "configdb") &&
	       seed_variable_defaults(admindb, defaults, "admindb");
}
```

At the start of `genai_start()`, after `ctx.started = true` and before `mcp_load_variables_from_admindb(ctx)`, call the helper. On failure, log `genai plugin: failed to seed MCP/GenAI variable defaults`, reset `ctx.started`, and return false.

- [ ] **Step 5: Rebuild and verify GREEN**

Run:

```bash
make -C test/tap/tests/unit genai_plugin_load_unit-t
test/tap/tests/unit/genai_plugin_load_unit-t
```

Expected: `1..57`, all 57 assertions pass, and the process exits 0.

- [ ] **Step 6: Review the diff and commit the behavior with its regression**

Run:

```bash
git diff --check
git diff -- plugins/genai/src/plugin_main.cpp test/tap/tests/unit/genai_plugin_load_unit-t.cpp
```

Confirm the diff contains no `REPLACE`, no `runtime_global_variables`, and no workflow changes. Then commit:

```bash
git add plugins/genai/src/plugin_main.cpp test/tap/tests/unit/genai_plugin_load_unit-t.cpp
git commit -m "fix(genai): persist missing plugin variable defaults"
```

### Task 3: Verify #6099 and prepare the branch for review

**Files:**
- Verify only; no planned source changes.

**Interfaces:**
- Consumes: the completed lifecycle regression and branch diff.
- Produces: fresh build/test evidence and a reviewable three-commit branch (design, plan, then implementation).

- [ ] **Step 1: Force a clean targeted rebuild**

Run:

```bash
make -C plugins/genai clean
make -C test/tap/tests/unit -B genai_plugin_load_unit-t
test/tap/tests/unit/genai_plugin_load_unit-t
```

Expected: clean plugin rebuild succeeds and all 57 assertions pass.

- [ ] **Step 2: Run adjacent GenAI handler unit tests**

Run:

```bash
make -C test/tap/tests/unit genai_mcp_thread_unit-t genai_thread_unit-t
test/tap/tests/unit/genai_mcp_thread_unit-t
test/tap/tests/unit/genai_thread_unit-t
```

Expected: both binaries exit 0 with no TAP failures.

- [ ] **Step 3: Verify repository and scope state**

Run:

```bash
git status --short --branch
git diff origin/v3.0...HEAD --check
git diff --stat origin/v3.0...HEAD
git log --oneline origin/v3.0..HEAD
```

Expected: the worktree is clean; the branch contains the design, plan, and implementation commits; changed paths are limited to the design, plan, `plugin_main.cpp`, and `genai_plugin_load_unit-t.cpp`.

- [ ] **Step 4: Apply completion verification before publishing**

Invoke `superpowers:verification-before-completion`, re-read the fresh command outputs, and report any unverified integration behavior explicitly. Do not claim that the full AI TAP shards pass until GitHub Actions runs them.
