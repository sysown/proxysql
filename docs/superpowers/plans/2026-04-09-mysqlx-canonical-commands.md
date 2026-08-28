# MySQLX Canonical Admin Commands Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `PLUGIN MYSQLX LOAD ...` commands with canonical `LOAD MYSQLX ... TO RUNTIME` / `SAVE MYSQLX ... TO MEMORY` syntax matching the existing MYSQL/PGSQL convention.

**Architecture:** Remove the `PLUGIN ` prefix gate from the plugin manager. Add first-class MYSQLX command alias vectors and dispatch blocks in `Admin_Handler.cpp`. Add SAVE command handlers to the mysqlx plugin. The plugin manager's registration and dispatch APIs stay the same — only the prefix check is removed.

**Tech Stack:** C++17, ProxySQL admin framework, SQLite3

---

### Task 1: Remove `PLUGIN` prefix gate from ProxySQL_PluginManager

**Files:**
- Modify: `lib/ProxySQL_PluginManager.cpp`

- [ ] **Step 1: Remove prefix constants and helper**

Delete the `kPluginCommandPrefix[]` constant and the `has_plugin_command_prefix()` function from the anonymous namespace (lines 17 and 150-156):

```cpp
// DELETE this line:
constexpr char kPluginCommandPrefix[] = "PLUGIN ";

// DELETE this entire function:
bool has_plugin_command_prefix(const std::string& sql) {
	if (sql.empty()) {
		return false;
	}

	return strncasecmp(sql.c_str(), kPluginCommandPrefix, sizeof(kPluginCommandPrefix) - 1) == 0;
}
```

- [ ] **Step 2: Remove prefix check from `register_command`**

In `register_command()` (line ~426), remove the prefix check:

```cpp
// BEFORE:
	const std::string canonical_sql = canonicalize_plugin_command(sql);
	if (canonical_sql.empty() || !has_plugin_command_prefix(canonical_sql)) {
		return false;
	}

// AFTER:
	const std::string canonical_sql = canonicalize_plugin_command(sql);
	if (canonical_sql.empty()) {
		return false;
	}
```

- [ ] **Step 3: Remove prefix check from `dispatch_admin_command`**

In `dispatch_admin_command()` (lines 331-334), remove the prefix gate:

```cpp
// BEFORE:
	const std::string canonical_sql = canonicalize_plugin_command(sql);
	if (!has_plugin_command_prefix(canonical_sql)) {
		return false;
	}

// AFTER:
	const std::string canonical_sql = canonicalize_plugin_command(sql);
```

- [ ] **Step 4: Commit**

```bash
git add lib/ProxySQL_PluginManager.cpp
git commit -m "refactor: remove PLUGIN prefix gate from command registration and dispatch"
```

---

### Task 2: Update plugin_registry_unit-t test

**Files:**
- Modify: `test/tap/tests/unit/plugin_registry_unit-t.cpp`

- [ ] **Step 1: Replace `PLUGIN MYSQLX` with canonical `LOAD MYSQLX` syntax**

In the test file, replace all `PLUGIN MYSQLX LOAD USERS TO RUNTIME` strings with `LOAD MYSQLX USERS TO RUNTIME`. Also fix the "unnamespaced" test — a bare `SELECT 1` is still rejected because it doesn't match any registered command. The test description changes to "non-registered SQL dispatch returns false".

Update the full test (lines 59-76):

```cpp
	ok(!mgr.register_command_for_test("SELECT 1"), "non-plugin SQL is rejected by register_command_for_test (returns false because no cb)");
	ok(mgr.register_command("LOAD MYSQLX USERS TO RUNTIME", &fake_plugin_command), "canonical command registration succeeds");
	ok(!mgr.register_command("LOAD MYSQLX USERS TO RUNTIME", &fake_plugin_command), "duplicate command is rejected");
	ok(!mgr.register_command("LOAD   MYSQLX   USERS TO RUNTIME ;", &fake_plugin_command), "canonical duplicate command is rejected");
	ok(mgr.has_command_for_test("LOAD MYSQLX USERS TO RUNTIME"), "registered command is discoverable");

	ProxySQL_PluginCommandResult result { 1, 0, "" };
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   result.rows_affected == 7 &&
	   result.message == "mysqlx users loaded",
	   "registered command dispatches callback result");
	ok(mgr.dispatch_admin_command(ctx, "LOAD   MYSQLX   USERS TO RUNTIME ;", result) &&
	   result.error_code == 0 &&
	   result.rows_affected == 7 &&
	   result.message == "mysqlx users loaded",
	   "dispatch canonicalizes whitespace and trailing semicolons");
```

Note: `register_command_for_test` on line 59 calls `register_command` internally, which canonicalizes the SQL. A `SELECT 1` canonicalizes to `SELECT 1` (not empty), so it will now succeed because the prefix check is gone. But `register_command_for_test` wraps it with `ignored_test_command`, so it returns true. We need to change the assertion — instead of testing rejection, test that it succeeds (since any command string is now accepted). OR, keep testing that `dispatch_admin_command` does not match `SELECT 1` (it won't, because no command is registered for it). The simplest fix:

```cpp
	ok(mgr.register_command_for_test("SELECT 1"), "any SQL is accepted for command registration");
```

- [ ] **Step 2: Commit**

```bash
git add test/tap/tests/unit/plugin_registry_unit-t.cpp
git commit -m "test: update plugin_registry_unit to use canonical LOAD MYSQLX syntax"
```

---

### Task 3: Add SAVE handlers to mysqlx_admin_schema.cpp

**Files:**
- Modify: `plugins/mysqlx/src/mysqlx_admin_schema.cpp`

- [ ] **Step 1: Add reverse `copy_table` direction and three SAVE handlers**

After the existing `load_backend_endpoints_to_runtime` function (line ~165), add SAVE handlers. The existing `copy_table` already works in either direction — we just need new command functions that swap source/target:

```cpp
ProxySQL_PluginCommandResult save_users_from_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx users save requires admin db");
	}
	if (!copy_table(*ctx.admindb, kRuntimeMysqlxUsersTable, kMysqlxUsersTable)) {
		return command_failure("failed to copy mysqlx users from runtime");
	}

	ProxySQL_PluginCommandResult result {0, 0, ""};
	result.rows_affected = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_users");
	result.message = "mysqlx users saved from runtime";
	return result;
}

ProxySQL_PluginCommandResult save_routes_from_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx routes save requires admin db");
	}
	if (!copy_table(*ctx.admindb, kRuntimeMysqlxRoutesTable, kMysqlxRoutesTable)) {
		return command_failure("failed to copy mysqlx routes from runtime");
	}

	ProxySQL_PluginCommandResult result {0, 0, ""};
	result.rows_affected = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_routes");
	result.message = "mysqlx routes saved from runtime";
	return result;
}

ProxySQL_PluginCommandResult save_backend_endpoints_from_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx backend endpoints save requires admin db");
	}
	if (!copy_table(*ctx.admindb, kRuntimeMysqlxBackendEndpointsTable, kMysqlxBackendEndpointsTable)) {
		return command_failure("failed to copy mysqlx backend endpoints from runtime");
	}

	ProxySQL_PluginCommandResult result {0, 0, ""};
	result.rows_affected = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_backend_endpoints");
	result.message = "mysqlx backend endpoints saved from runtime";
	return result;
}
```

- [ ] **Step 2: Register canonical command names + SAVE commands**

Replace the three `services.register_command` calls at the end of `mysqlx_register_admin_schema()` (lines 262-264):

```cpp
	// BEFORE:
	services.register_command("PLUGIN MYSQLX LOAD USERS TO RUNTIME", &load_users_to_runtime);
	services.register_command("PLUGIN MYSQLX LOAD ROUTES TO RUNTIME", &load_routes_to_runtime);
	services.register_command("PLUGIN MYSQLX LOAD BACKEND ENDPOINTS TO RUNTIME", &load_backend_endpoints_to_runtime);

	// AFTER:
	services.register_command("LOAD MYSQLX USERS TO RUNTIME", &load_users_to_runtime);
	services.register_command("SAVE MYSQLX USERS TO MEMORY", &save_users_from_runtime);
	services.register_command("LOAD MYSQLX ROUTES TO RUNTIME", &load_routes_to_runtime);
	services.register_command("SAVE MYSQLX ROUTES TO MEMORY", &save_routes_from_runtime);
	services.register_command("LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", &load_backend_endpoints_to_runtime);
	services.register_command("SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY", &save_backend_endpoints_from_runtime);
```

- [ ] **Step 3: Commit**

```bash
git add plugins/mysqlx/src/mysqlx_admin_schema.cpp
git commit -m "feat: add SAVE MYSQLX handlers and register canonical LOAD/SAVE command names"
```

---

### Task 4: Add first-class MYSQLX dispatch in Admin_Handler.cpp

**Files:**
- Modify: `lib/Admin_Handler.cpp`

- [ ] **Step 1: Add MYSQLX alias vectors**

After the TSDB alias vectors (line 315) and before the COREDUMP vectors (line 317), add:

```cpp
// MySQLX plugin
const std::vector<std::string> LOAD_MYSQLX_USERS_FROM_MEMORY = {
	"LOAD MYSQLX USERS FROM MEMORY" ,
	"LOAD MYSQLX USERS FROM MEM" ,
	"LOAD MYSQLX USERS TO RUNTIME" ,
	"LOAD MYSQLX USERS TO RUN" };

const std::vector<std::string> SAVE_MYSQLX_USERS_TO_MEMORY = {
	"SAVE MYSQLX USERS TO MEMORY" ,
	"SAVE MYSQLX USERS TO MEM" ,
	"SAVE MYSQLX USERS FROM RUNTIME" ,
	"SAVE MYSQLX USERS FROM RUN" };

const std::vector<std::string> LOAD_MYSQLX_ROUTES_FROM_MEMORY = {
	"LOAD MYSQLX ROUTES FROM MEMORY" ,
	"LOAD MYSQLX ROUTES FROM MEM" ,
	"LOAD MYSQLX ROUTES TO RUNTIME" ,
	"LOAD MYSQLX ROUTES TO RUN" };

const std::vector<std::string> SAVE_MYSQLX_ROUTES_TO_MEMORY = {
	"SAVE MYSQLX ROUTES TO MEMORY" ,
	"SAVE MYSQLX ROUTES TO MEM" ,
	"SAVE MYSQLX ROUTES FROM RUNTIME" ,
	"SAVE MYSQLX ROUTES FROM RUN" };

const std::vector<std::string> LOAD_MYSQLX_BACKEND_ENDPOINTS_FROM_MEMORY = {
	"LOAD MYSQLX BACKEND ENDPOINTS FROM MEMORY" ,
	"LOAD MYSQLX BACKEND ENDPOINTS FROM MEM" ,
	"LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME" ,
	"LOAD MYSQLX BACKEND ENDPOINTS TO RUN" };

const std::vector<std::string> SAVE_MYSQLX_BACKEND_ENDPOINTS_TO_MEMORY = {
	"SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY" ,
	"SAVE MYSQLX BACKEND ENDPOINTS TO MEM" ,
	"SAVE MYSQLX BACKEND ENDPOINTS FROM RUNTIME" ,
	"SAVE MYSQLX BACKEND ENDPOINTS FROM RUN" };
```

- [ ] **Step 2: Add dispatch blocks**

Find the existing plugin fallback dispatch block (lines 5299-5305):

```cpp
	if (run_query && sess->session_type == PROXYSQL_SESSION_ADMIN) {
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (SPA->dispatch_plugin_admin_command(sess, query_no_space)) {
			run_query=false;
			goto __run_query;
		}
	}
```

Replace it with first-class MYSQLX command dispatch blocks:

```cpp
	if (run_query && sess->session_type == PROXYSQL_SESSION_ADMIN) {
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (
			is_admin_command_or_alias(LOAD_MYSQLX_USERS_FROM_MEMORY, query_no_space, query_no_space_length) ||
			is_admin_command_or_alias(SAVE_MYSQLX_USERS_TO_MEMORY, query_no_space, query_no_space_length) ||
			is_admin_command_or_alias(LOAD_MYSQLX_ROUTES_FROM_MEMORY, query_no_space, query_no_space_length) ||
			is_admin_command_or_alias(SAVE_MYSQLX_ROUTES_TO_MEMORY, query_no_space, query_no_space_length) ||
			is_admin_command_or_alias(LOAD_MYSQLX_BACKEND_ENDPOINTS_FROM_MEMORY, query_no_space, query_no_space_length) ||
			is_admin_command_or_alias(SAVE_MYSQLX_BACKEND_ENDPOINTS_TO_MEMORY, query_no_space, query_no_space_length)
		) {
			if (SPA->dispatch_plugin_admin_command(sess, query_no_space)) {
				run_query=false;
				return false;
			}
		}
	}
```

This uses the same pattern as LOAD MYSQL USERS (dispatch + `return false`). The `dispatch_plugin_admin_command` method already handles canonicalization and response sending.

- [ ] **Step 3: Commit**

```bash
git add lib/Admin_Handler.cpp
git commit -m "feat: add first-class LOAD/SAVE MYSQLX command dispatch in admin handler"
```

---

### Task 5: Update test_mysqlx_admin_tables-t.cpp

**Files:**
- Modify: `test/tap/tests/test_mysqlx_admin_tables-t.cpp`

- [ ] **Step 1: Replace PLUGIN MYSQLX with canonical LOAD MYSQLX**

Replace lines 152-166. Change the three dispatch calls and their description strings:

```cpp
	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_users") == 1 &&
	   select_string(admin_db, "SELECT backend_auth_mode FROM runtime_mysqlx_users WHERE username='alice'") == "pass_through",
	   "LOAD MYSQLX USERS TO RUNTIME copies mysqlx user rows");
	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX ROUTES TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_routes") == 1 &&
	   admin_db.return_one_int("SELECT destination_hostgroup FROM runtime_mysqlx_routes WHERE name='rw'") == 42,
	   "LOAD MYSQLX ROUTES TO RUNTIME copies route rows");
	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_backend_endpoints") == 1 &&
	   admin_db.return_one_int("SELECT mysqlx_port FROM runtime_mysqlx_backend_endpoints WHERE hostname='db1.internal' AND mysql_port=3306") == 33060,
	   "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME copies endpoint rows");
```

- [ ] **Step 2: Add SAVE command tests**

Increase the plan count from 20 to 23 and add three SAVE tests after the existing LOAD tests (before the cleanup block):

```cpp
	// SAVE tests
	ok(mgr.dispatch_admin_command(ctx, "SAVE MYSQLX USERS TO MEMORY", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_users") == 1,
	   "SAVE MYSQLX USERS TO MEMORY copies runtime rows back to config");
	ok(mgr.dispatch_admin_command(ctx, "SAVE MYSQLX ROUTES TO MEMORY", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_routes") == 1,
	   "SAVE MYSQLX ROUTES TO MEMORY copies runtime rows back to config");
	ok(mgr.dispatch_admin_command(ctx, "SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_backend_endpoints") == 1,
	   "SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY copies runtime rows back to config");
```

Update `plan(20)` to `plan(23)` at the start of `main()`.

- [ ] **Step 3: Commit**

```bash
git add test/tap/tests/test_mysqlx_admin_tables-t.cpp
git commit -m "test: update mysqlx admin table tests for canonical LOAD/SAVE syntax"
```

---

### Task 6: Update wrap-up documentation

**Files:**
- Modify: `docs/superpowers/status/2026-04-07-mysqlx-plugin-wrapup.md`

- [ ] **Step 1: Update command listing**

Replace the Admin Commands section (lines 45-47):

```markdown
## Admin Commands

- `LOAD MYSQLX USERS TO RUNTIME` (aliases: `TO RUN`, `FROM MEMORY`, `FROM MEM`)
- `SAVE MYSQLX USERS TO MEMORY` (aliases: `TO MEM`, `FROM RUNTIME`, `FROM RUN`)
- `LOAD MYSQLX ROUTES TO RUNTIME` (aliases: same pattern)
- `SAVE MYSQLX ROUTES TO MEMORY` (aliases: same pattern)
- `LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME` (aliases: same pattern)
- `SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY` (aliases: same pattern)
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/status/2026-04-07-mysqlx-plugin-wrapup.md
git commit -m "docs: update mysqlx wrap-up with canonical LOAD/SAVE command names"
```
