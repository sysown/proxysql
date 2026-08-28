# Visible Feedback for Rejected mysql-* Variables Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `LOAD <module> VARIABLES TO RUNTIME` report a `Records: N Updated: X Rejected: Y Unknown: Z` summary in the OK packet's `info` field, so users see when their `UPDATE global_variables` value was rejected and silently reset.

**Architecture:** Add a `FlushVariableStats` struct that the generic flush helper returns. Plumb it up through the six module-specific flush wrappers and the three inline `load_*_variables_to_runtime` helpers. The admin handler formats the info string and passes it to the existing `send_ok_msg_to_client`. The pgsql flush helper has its own duplicated loop and gets the same treatment.

**Tech Stack:** C++17, SQLite3 (admin DB), MySQL/PostgreSQL OK packet info field, TAP test framework.

---

## File Structure

| File | Change |
|------|--------|
| `include/proxysql_admin.h` | Add `FlushVariableStats` struct; change return types of `flush_GENERIC_variables__process__database_to_runtime` and 7 module wrappers; change 3 inline `load_*_variables_to_runtime` helpers to return the struct |
| `lib/Admin_FlushVariables.cpp` | Add counters in the generic process function; add counters in the duplicated pgsql loop; update 6 generic wrappers to return the struct |
| `lib/Admin_Handler.cpp` | Format the info string in 3 call sites (mysql, pgsql, ldap) and pass to `send_ok_msg_to_client` |
| `test/tap/tests/reg_test_1288-load-mysql-variables-feedback-t.cpp` | New TAP test for the mysql module |
| `test/tap/tests/reg_test_1288-load-pgsql-variables-feedback-t.cpp` | New TAP test for the pgsql module |
| `test/tap/groups/groups.json` | Register the 2 new tests in the appropriate infra groups |

---

## Task 1: Add `FlushVariableStats` struct and change return types in header

**Files:**
- Modify: `include/proxysql_admin.h:513-573` (function signatures) and `include/proxysql_admin.h:757, 841, 870` (inline helpers)

- [ ] **Step 1: Add the struct definition**

In `include/proxysql_admin.h`, immediately after the `ProxySQL_Admin` class opening brace (or wherever other public structs are declared in this class), add:

```cpp
struct FlushVariableStats {
    int records  = 0;
    int updated  = 0;
    int rejected = 0;
    int unknown  = 0;
};
```

- [ ] **Step 2: Change the signature of `flush_GENERIC_variables__process__database_to_runtime`**

In `include/proxysql_admin.h:518-526`, change the return type from `void` to `FlushVariableStats`:

```cpp
    FlushVariableStats flush_GENERIC_variables__process__database_to_runtime(
        const std::string& modname, SQLite3DB *db, SQLite3_result* resultset,
        const bool& lock, const bool& replace,
        const std::unordered_set<std::string>& variables_read_only,
        const std::unordered_set<std::string>& variables_to_delete_silently,
        const std::unordered_set<std::string>& variables_deprecated,
        const std::unordered_set<std::string>& variables_special_values,
        std::function<void(const std::string&, const char *, SQLite3DB *)> special_variable_action = nullptr
    );
```

- [ ] **Step 3: Change the 6 generic wrappers to return `FlushVariableStats`**

In `include/proxysql_admin.h`, update each of:

```cpp
    FlushVariableStats flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum = "", const time_t epoch = 0);   // was: void
    FlushVariableStats flush_admin_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum = "", const time_t epoch = 0, bool lock = true);  // was: void
    FlushVariableStats flush_sqliteserver_variables___database_to_runtime(SQLite3DB *db, bool replace);  // was: void
    FlushVariableStats flush_ldap_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum = "", const time_t epoch = 0);  // was: void
```

`flush_tsdb_variables___database_to_runtime` is inside `#ifdef PROXYSQLTSDB`; update the same way.

`flush_clickhouse_variables___database_to_runtime` is inside `#ifdef PROXYSQLCLICKHOUSE`; update the same way.

- [ ] **Step 4: Change the pgsql wrapper to return `FlushVariableStats`**

In `include/proxysql_admin.h:565`, change:

```cpp
    FlushVariableStats flush_pgsql_variables___database_to_runtime(SQLite3DB* db, bool replace, const std::string& checksum = "", const time_t epoch = 0);  // was: void
```

- [ ] **Step 5: Change the 3 inline `load_*_variables_to_runtime` helpers to return the struct**

In `include/proxysql_admin.h:757, 841, 870`, change each from `void` to `FlushVariableStats`:

```cpp
    FlushVariableStats load_mysql_variables_to_runtime(const std::string& checksum = "", const time_t epoch = 0) { return flush_mysql_variables___database_to_runtime(admindb, true, checksum, epoch); }
    FlushVariableStats load_ldap_variables_to_runtime(const std::string& checksum = "", const time_t epoch = 0) { return flush_ldap_variables___database_to_runtime(admindb, true, checksum, epoch); }
    FlushVariableStats load_pgsql_variables_to_runtime(const std::string& checksum = "", const time_t epoch = 0) { return flush_pgsql_variables___database_to_runtime(admindb, true, checksum, epoch); }
```

- [ ] **Step 6: Commit**

```bash
git add include/proxysql_admin.h
git commit -m "refactor(admin): introduce FlushVariableStats and change flush_*_variables signatures"
```

Note: the build is now broken. That is expected; Task 2 fixes the implementations.

---

## Task 2: Update `flush_GENERIC_variables__process__database_to_runtime` to track and return stats

**Files:**
- Modify: `lib/Admin_FlushVariables.cpp:178-263` (function body)

- [ ] **Step 1: Replace the function signature and add counter increments**

In `lib/Admin_FlushVariables.cpp:178`, change the signature:

```cpp
FlushVariableStats ProxySQL_Admin::flush_GENERIC_variables__process__database_to_runtime(
```

(keep all the parameters unchanged)

- [ ] **Step 2: Add `stats.records++` at the top of the loop**

In `lib/Admin_FlushVariables.cpp:187-188`, before the `bool rc = false;` line, add:

```cpp
        SQLite3_row *r=*it;
        stats.records++;
        bool rc = false;
```

- [ ] **Step 3: Increment `stats.updated++` on success**

In `lib/Admin_FlushVariables.cpp:254` (the `else` branch's `proxy_debug` line, just before it), the success path is the `if (rc==false) ... else {` block. In the `else` branch, before the existing `proxy_debug` line that says "Set variable %s with value %s", add:

```cpp
        } else {
            stats.updated++;
            proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
```

- [ ] **Step 4: Increment `stats.rejected++` for known-bad-value and read-only rows**

In the `if (rc==false)` branch, the `if (val)` block (line 230) covers "we know about this variable but rejected the value". Before the `snprintf(q, ...)` line, add `stats.rejected++;`:

```cpp
                    if (val) {
                        if (variables_read_only.count(v) > 0) {
                            proxy_warning("Impossible to set read-only variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
                        } else {
                            proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
                        }
                        stats.rejected++;
                        snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"%s-%s\",\"%s\")", modname.c_str(), r->fields[0], val);
                        db->execute(q);
                        free(val);
```

- [ ] **Step 5: Increment `stats.rejected++` for `variables_to_delete_silently` and `variables_deprecated`**

In the `else` branch (the `else` of `if (val)`, line 239), add the counters:

```cpp
                    } else {
                        if (variables_to_delete_silently.count(v) > 0) {
                            stats.rejected++;
                            snprintf(q, sizeof(q), "DELETE FROM disk.global_variables WHERE variable_name=\"%s-%s\"", modname.c_str(), r->fields[0]);
                            db->execute(q);
                        } else if (variables_deprecated.count(v) > 0) {
                            proxy_error("Global variable %s-%s is deprecated.\n", modname.c_str(), r->fields[0]);
                            stats.rejected++;
                            snprintf(q, sizeof(q), "DELETE FROM disk.global_variables WHERE variable_name=\"%s-%s\"", modname.c_str(), r->fields[0]);
                            db->execute(q);
                        } else {
                            proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0],r->fields[1]);
                            stats.unknown++;
                        }
                        snprintf(q, sizeof(q), "DELETE FROM global_variables WHERE variable_name=\"%s-%s\"", modname.c_str(), r->fields[0]);
                        db->execute(q);
                    }
```

- [ ] **Step 6: Add `return stats;` at the end of the function**

At `lib/Admin_FlushVariables.cpp:262` (the closing `}` of the for loop), after the loop, add:

```cpp
    return stats;
}
```

(The closing `}` at line 263 stays.)

- [ ] **Step 7: Update the 6 generic wrappers to return the struct**

In `lib/Admin_FlushVariables.cpp`, update each of these wrappers' return statements to use the struct. The bodies do the work and then fall through; we need to capture and return.

For `flush_admin_variables___database_to_runtime` (line 265), change the call site:

```cpp
        FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("admin", db, resultset, lock, replace, {"version"}, {"debug"}, {}, {});
        if (resultset) delete resultset;
        return stats;
    }
```

(`resultset` is deleted after the existing checks; keep the existing structure, just save and return `stats`.)

For `flush_mysql_variables___database_to_runtime` (line 453), the wrapper is much longer and does charset/collation post-processing. The pattern:

```cpp
void ProxySQL_Admin::flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum, const time_t epoch) {
```

becomes:

```cpp
FlushVariableStats ProxySQL_Admin::flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum, const time_t epoch) {
```

The existing call to `flush_GENERIC_variables__process__database_to_runtime` at line 465 needs to be captured:

```cpp
        FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("mysql", db, resultset, false, replace, {}, {"session_debug"}, {"forward_autocommit"},
            { ... existing special_values set ... },
            [](const std::string& varname, const char *varvalue, SQLite3DB* db) { ... existing lambda ... }
        );
```

The function continues with charset/collation post-processing. Just before the final `if (resultset) delete resultset;` (line 660) and the function's closing `}`, add:

```cpp
        return stats;
    }
    if (resultset) delete resultset;
    return FlushVariableStats{};
}
```

(The early-return for empty resultset at line 450 needs to be `return FlushVariableStats{};` as well — see the existing `delete resultset; return;` path.)

For `flush_sqliteserver_variables___database_to_runtime` (line 663):

```cpp
FlushVariableStats ProxySQL_Admin::flush_sqliteserver_variables___database_to_runtime(SQLite3DB *db, bool replace) {
    // ... existing body, including the early return for sqlite3_server disabled ...
    if (flush_GENERIC_variables__retrieve__database_to_runtime("sqliteserver", error, cols, affected_rows, resultset) == true) {
        GloSQLite3Server->wrlock();
        FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("sqliteserver", db, resultset, false, replace, {}, {"session_debug"}, {}, {});
        //GloClickHouse->commit();
        GloSQLite3Server->wrunlock();
        if (resultset) delete resultset;
        return stats;
    }
    if (resultset) delete resultset;
    return FlushVariableStats{};
}
```

For `flush_tsdb_variables___database_to_runtime` (line 686, inside `#ifdef PROXYSQLTSDB`):

```cpp
FlushVariableStats ProxySQL_Admin::flush_tsdb_variables___database_to_runtime(SQLite3DB *db, bool replace) {
    // ... existing body, including the early return for GloProxyStats == NULL ...
    if (flush_GENERIC_variables__retrieve__database_to_runtime("tsdb", error, cols, affected_rows, resultset) == true) {
        FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("tsdb", db, resultset, false, replace, {}, {}, {}, {});
        flush_tsdb_variables___runtime_to_database(admindb, false, false, false, true);
        if (resultset) delete resultset;
        return stats;
    }
    if (resultset) delete resultset;
    return FlushVariableStats{};
}
```

For `flush_clickhouse_variables___database_to_runtime` (line 791, inside `#ifdef PROXYSQLCLICKHOUSE`):

```cpp
FlushVariableStats ProxySQL_Admin::flush_clickhouse_variables___database_to_runtime(SQLite3DB *db, bool replace) {
    // ... existing body ...
    if (flush_GENERIC_variables__retrieve__database_to_runtime("clickhouse", error, cols, affected_rows, resultset) == true) {
        GloClickHouseServer->wrlock();
        FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("clickhouse", db, resultset, false, replace, {}, {"session_debug"}, {}, {});
        //GloClickHouse->commit();
        GloClickHouseServer->wrunlock();
        if (resultset) delete resultset;
        return stats;
    }
    if (resultset) delete resultset;
    return FlushVariableStats{};
}
```

For `flush_ldap_variables___database_to_runtime` (line 1111, called from `init_ldap_variables` and the `load_ldap_variables_to_runtime` inline helper):

```cpp
FlushVariableStats ProxySQL_Admin::flush_ldap_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum, const time_t epoch) {
    // ... existing body, including early return for GloMyLdapAuth == NULL ...
    if (flush_GENERIC_variables__retrieve__database_to_runtime("ldap", error, cols, affected_rows, resultset) == true) {
        GloMyLdapAuth->wrlock();
        FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime(/* NOTE: existing call passes "admin" hardcoded — keeping that pre-existing typo, see issue spec §"Out of scope" */ "admin", db, resultset, false, replace, {}, {}, {}, {});
        GloMyLdapAuth->wrunlock();

        // ... existing checksum block ...
    }
    if (resultset) delete resultset;
    return FlushVariableStats{};
}
```

- [ ] **Step 8: Commit**

```bash
git add lib/Admin_FlushVariables.cpp
git commit -m "feat(admin): track Records/Updated/Rejected/Unknown in generic flush path"
```

---

## Task 3: Update `flush_pgsql_variables___database_to_runtime` to track and return stats

**Files:**
- Modify: `lib/Admin_FlushVariables.cpp:870-911` (the duplicated pgsql loop)

- [ ] **Step 1: Change the function signature**

In `lib/Admin_FlushVariables.cpp:870`, change:

```cpp
FlushVariableStats ProxySQL_Admin::flush_pgsql_variables___database_to_runtime(SQLite3DB* db, bool replace, const std::string& checksum, const time_t epoch) {
```

(keep all parameters unchanged)

- [ ] **Step 2: Add a local stats struct at the top of the function**

Immediately after `proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing PgSQL variables. Replace:%d\n", replace);`, add:

```cpp
    FlushVariableStats stats;
```

- [ ] **Step 3: Increment `stats.records++` and `stats.updated++` / `stats.rejected++` / `stats.unknown++` in the loop**

In the loop at line 884-951, add the counters. The structure mirrors the generic helper but has its own special cases (session_debug, forward_autocommit, default_charset/collation, show_processlist_extended). Edit the loop body:

```cpp
    GloPTH->wrlock();
    for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
        SQLite3_row* r = *it;
        const char* value = r->fields[1];
        stats.records++;
        bool rc = GloPTH->set_variable(r->fields[0], value);
        if (rc == false) {
            proxy_debug(PROXY_DEBUG_ADMIN, 4, "Impossible to set variable %s with value \"%s\"\n", r->fields[0], value);
            if (replace) {
                char* val = GloPTH->get_variable(r->fields[0]);
                char q[1000];
                if (val) {
                    if (strcmp(val, value)) {
                        proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0], value, val);
                        snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-%s\",\"%s\")", r->fields[0], val);
                        db->execute(q);
                    }
                    free(val);
                    stats.rejected++;
                }
                else {
                    if (strcmp(r->fields[0], (char*)"session_debug") == 0) {
                        snprintf(q, sizeof(q), "DELETE FROM disk.global_variables WHERE variable_name=\"pgsql-%s\"", r->fields[0]);
                        db->execute(q);
                        stats.rejected++;
                    }
                    else {
                        if (strcmp(r->fields[0], (char*)"forward_autocommit") == 0) {
                            if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
                                proxy_error("Global variable pgsql-forward_autocommit is deprecated. See issue #3253\n");
                            }
                            snprintf(q, sizeof(q), "DELETE FROM disk.global_variables WHERE variable_name=\"pgsql-%s\"", r->fields[0]);
                            db->execute(q);
                            stats.rejected++;
                        }
                        else {
                            proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0],r->fields[1]);
                            stats.unknown++;
                        }
                    }
                    snprintf(q, sizeof(q), "DELETE FROM global_variables WHERE variable_name=\"pgsql-%s\"", r->fields[0]);
                    db->execute(q);
                }
            }
        }
        else {
            stats.updated++;
            // ... rest of the existing success block unchanged ...
        }
    }
```

The success block (rc==true) handles default_charset/collation warnings, show_processlist_extended, etc. — those stay exactly as they are, just with `stats.updated++;` added at the top of the `else` branch.

- [ ] **Step 4: Add `return stats;` at the end of the function**

Find the end of `flush_pgsql_variables___database_to_runtime` (around line 1010-1100, just before the `if (resultset) delete resultset;` and the closing `}`). Just before the final `if (resultset) delete resultset;` and the function's closing `}`, add:

```cpp
    if (resultset) delete resultset;
    return stats;
}
```

The error path (the `if (error) { proxy_error(...); free(error); return; }` at line 878-881) becomes:

```cpp
    if (error) {
        proxy_error("Error on %s : %s\n", q, error);
        free(error);
        if (resultset) delete resultset;
        return FlushVariableStats{};
    }
```

- [ ] **Step 5: Commit**

```bash
git add lib/Admin_FlushVariables.cpp
git commit -m "feat(admin): track Records/Updated/Rejected/Unknown in pgsql flush path"
```

---

## Task 4: Update `Admin_Handler.cpp` to format and send the info string

**Files:**
- Modify: `lib/Admin_Handler.cpp:1925-1935` (ldap), `:2028-2035` (pgsql), `:2038-2044` (mysql)

- [ ] **Step 1: Update the mysql call site**

In `lib/Admin_Handler.cpp:2038-2044`, replace:

```cpp
                if (is_admin_command_or_alias(LOAD_MYSQL_VARIABLES_FROM_MEMORY, query_no_space, query_no_space_length)) {
                    ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
                    SPA->load_mysql_variables_to_runtime();
                    proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables to RUNTIME\n");
                    SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
                    return false;
            }
```

with:

```cpp
                if (is_admin_command_or_alias(LOAD_MYSQL_VARIABLES_FROM_MEMORY, query_no_space, query_no_space_length)) {
                    ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
                    FlushVariableStats stats = SPA->load_mysql_variables_to_runtime();
                    proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables to RUNTIME\n");
                    char info[160];
                    snprintf(info, sizeof(info),
                        "Records: %d Updated: %d Rejected: %d Unknown: %d",
                        stats.records, stats.updated, stats.rejected, stats.unknown);
                    SPA->send_ok_msg_to_client(sess, info, 0, query_no_space);
                    return false;
            }
```

- [ ] **Step 2: Update the pgsql call site**

In `lib/Admin_Handler.cpp:2028-2036`, apply the same change to the pgsql branch:

```cpp
            if (is_pgsql) {
                if (is_admin_command_or_alias(LOAD_PGSQL_VARIABLES_FROM_MEMORY, query_no_space, query_no_space_length)) {
                    ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
                    FlushVariableStats stats = SPA->load_pgsql_variables_to_runtime();
                    proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded pgsql variables to RUNTIME\n");
                    proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables to RUNTIME\n");
                    char info[160];
                    snprintf(info, sizeof(info),
                        "Records: %d Updated: %d Rejected: %d Unknown: %d",
                        stats.records, stats.updated, stats.rejected, stats.unknown);
                    SPA->send_ok_msg_to_client(sess, info, 0, query_no_space);
                    return false;
                }
            }
```

- [ ] **Step 3: Update the ldap call site**

In `lib/Admin_Handler.cpp:1925-1935`, apply the same change to the ldap branch:

```cpp
                proxy_info("Received %s command\n", query_no_space);
                ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
                FlushVariableStats stats = SPA->load_ldap_variables_to_runtime();
                proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded ldap variables to RUNTIME\n");
                char info[160];
                snprintf(info, sizeof(info),
                    "Records: %d Updated: %d Rejected: %d Unknown: %d",
                    stats.records, stats.updated, stats.rejected, stats.unknown);
                SPA->send_ok_msg_to_client(sess, info, 0, query_no_space);
                return false;
            }
```

- [ ] **Step 4: Add a shared helper to keep the formatting DRY**

To avoid the same `snprintf` 3 times, add a small private static helper to `Admin_Handler.cpp` near the top of the file (after the existing helper templates, around line 460):

```cpp
template <typename S>
static void send_flush_stats_ok(S* sess, const FlushVariableStats& stats, const char* query) {
    char info[160];
    snprintf(info, sizeof(info),
        "Records: %d Updated: %d Rejected: %d Unknown: %d",
        stats.records, stats.updated, stats.rejected, stats.unknown);
    ProxySQL_Admin* SPA = GloAdmin;
    SPA->send_ok_msg_to_client(sess, info, 0, query);
}
```

Then the 3 call sites become:

```cpp
                ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
                FlushVariableStats stats = SPA->load_mysql_variables_to_runtime();
                proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables to RUNTIME\n");
                send_flush_stats_ok(sess, stats, query_no_space);
                return false;
```

(do the same in pgsql and ldap branches)

If the helper feels like over-abstraction for a 6-line block, leave the 3 call sites with the inline `snprintf` and skip this step. The PR reviewer's preference wins.

- [ ] **Step 5: Commit**

```bash
git add lib/Admin_Handler.cpp
git commit -m "feat(admin): surface flush stats in OK packet info field"
```

---

## Task 5: Build and verify compilation

**Files:** none

- [ ] **Step 1: Build the release binary**

Run: `make -j$(nproc) proxysql 2>&1 | tail -40`
Expected: build succeeds with no errors. There may be warnings about unused variable `stats` if the helper approach wasn't taken; those are fine, ignore them.

- [ ] **Step 2: If the build failed**

If the build failed with a signature mismatch, the error message will name the file and line. Fix the call site, rebuild. Repeat until clean.

Common things to double-check:
- The 6 generic wrappers' return statements match the new `FlushVariableStats` signature.
- The 3 inline `load_*_variables_to_runtime` helpers' bodies use `return` instead of bare invocation.
- The 3 Admin_Handler.cpp call sites use `auto stats = ...` (or `FlushVariableStats stats = ...`) and pass the stats through.

- [ ] **Step 3: Smoke-test the binary starts and the admin port responds**

Run: `./src/proxysql --version`
Expected: prints the version string.

Run: `timeout 5 ./src/proxysql -f -c /tmp/empty.cnf 2>&1 | head -20` (with an empty config file at `/tmp/empty.cnf`)

If this is too disruptive in the current environment, skip and trust the build. The TAP test in Task 6 exercises a live binary.

---

## Task 6: Write the TAP test for the mysql module

**Files:**
- Create: `test/tap/tests/reg_test_1288-load-mysql-variables-feedback-t.cpp`
- Modify: `test/tap/groups/groups.json` (add a new entry near the existing `reg_test_*` entries)

- [ ] **Step 1: Create the test file**

Write `test/tap/tests/reg_test_1288-load-mysql-variables-feedback-t.cpp` with this content:

```cpp
/**
 * @file reg_test_1288-load-mysql-variables-feedback-t.cpp
 * @brief Verify that LOAD MYSQL VARIABLES TO RUNTIME surfaces a Records/Updated/Rejected/Unknown
 *        summary in the OK packet's info field. See issue #1288.
 */

#include <stdio.h>
#include <string>
#include <string.h>
#include "mysql.h"
#include "mysqld_error.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

static int restore_var(MYSQL* admin, const char* name, const char* default_sql_value) {
	std::string q = std::string("UPDATE global_variables SET variable_value='") +
		default_sql_value + "' WHERE variable_name='" + name + "'";
	return mysql_query(admin, q.c_str());
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(4);

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	// Capture the original values so we can restore at the end.
	// Use a value that is known to be valid for each variable to ensure cleanup works.
	const char* kMaxConnOriginal  = "10000";
	const char* kPingIntOriginal  = "2000";
	const char* kStmtsCacheOrig   = "1000";

	// Save originals (best-effort: in case the row doesn't exist, INSERT it).
	{
		MYSQL_QUERY(admin,
			"INSERT OR REPLACE INTO global_variables(variable_name, variable_value) "
			"VALUES "
			"('mysql-max_connections', '10000'), "
			"('mysql-monitor_ping_interval', '2000'), "
			"('mysql-max_stmts_cache', '1000')");
	}

	// Scenario 1: all-invalid (1 rejected value, 1 unknown variable, 1 valid)
	MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='0' WHERE variable_name='mysql-max_connections'");
	MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='foo' WHERE variable_name='mysql-monitor_ping_interval'");
	MYSQL_QUERY(admin, "UPDATE global_variables SET variable_value='1' WHERE variable_name='mysql-bogus_var_xyz'");

	// mysql_query returns 0 on success and the info field is populated on the OK packet.
	if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
		diag("LOAD MYSQL VARIABLES TO RUNTIME failed: %s", mysql_error(admin));
		return exit_status();
	}
	const char* info = mysql_info(admin);
	diag("LOAD (mixed) info: %s", info ? info : "(null)");

	bool has_records_3    = info && strstr(info, "Records: 3")    != NULL;
	bool has_updated_1    = info && strstr(info, "Updated: 1")    != NULL;
	bool has_rejected_1   = info && strstr(info, "Rejected: 1")   != NULL;
	bool has_unknown_1    = info && strstr(info, "Unknown: 1")    != NULL;
	ok(has_records_3 && has_updated_1 && has_rejected_1 && has_unknown_1,
	   "LOAD MYSQL VARIABLES TO RUNTIME info='%s' reports Records: 3 Updated: 1 Rejected: 1 Unknown: 1",
	   info ? info : "(null)");

	// Verify the rejected value was reset to the runtime default.
	MYSQL_QUERY(admin, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-max_connections'");
	MYSQL_RES* res = mysql_store_result(admin);
	ok(res != NULL, "runtime_global_variables query returned a result set");
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		ok(row && row[0] && strcmp(row[0], "0") != 0,
		   "runtime mysql-max_connections was reset to a non-zero value (got '%s')",
		   row && row[0] ? row[0] : "(null)");
		mysql_free_result(res);
	}

	// Restore.
	restore_var(admin, "mysql-max_connections",        kMaxConnOriginal);
	restore_var(admin, "mysql-monitor_ping_interval",  kPingIntOriginal);
	restore_var(admin, "mysql-max_stmts_cache",        kStmtsCacheOrig);
	MYSQL_QUERY(admin, "DELETE FROM global_variables WHERE variable_name='mysql-bogus_var_xyz'");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);
	return exit_status();
}
```

- [ ] **Step 2: Register the test in `groups.json`**

In `test/tap/groups/groups.json`, add a new line alphabetically near the other `reg_test_*` entries (e.g. after `reg_test_1133_*` if present, otherwise at the right alphabetical position). Use the same group list as `reg_test_4072-show-warnings-t`:

```json
  "reg_test_1288-load-mysql-variables-feedback-t" : [ "legacy-g2","mysql-auto_increment_delay_multiplex=0-g2","mysql-multiplexing=false-g2","mysql-query_digests=0-g2","mysql-query_digests_keep_comment=1-g2","mysql84-g2","mysql90-g2","mysql95-g2" ],
```

- [ ] **Step 3: Build the test**

Run: `make -j$(nproc) reg_test_1288-load-mysql-variables-feedback-t 2>&1 | tail -20`
Expected: build succeeds, produces `reg_test_1288-load-mysql-variables-feedback-t` binary in `test/tap/tests/`.

If the build fails with `command_line.h not found`, the test framework was not set up; rerun `make build_tap_tests` first.

- [ ] **Step 4: Run the test against a live ProxySQL**

Per `CLAUDE.md`, do NOT manually start containers. Use the isolated runner:

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=mysql84-g2 test/infra/control/run-tests-isolated.bash
```

The runner sets up the infra, starts ProxySQL, runs the test, and tears down. Expected: the test prints TAP output ending with `1..4` and `ok` for all 4 assertions. If only some pass, the failed assertion shows which format string the implementation got wrong.

- [ ] **Step 5: Commit**

```bash
git add test/tap/tests/reg_test_1288-load-mysql-variables-feedback-t.cpp test/tap/groups/groups.json
git commit -m "test(tap): verify LOAD MYSQL VARIABLES TO RUNTIME reports flush stats (issue #1288)"
```

---

## Task 7: Write the TAP test for the pgsql module

**Files:**
- Create: `test/tap/tests/reg_test_1288-load-pgsql-variables-feedback-t.cpp`
- Modify: `test/tap/groups/groups.json`

- [ ] **Step 1: Create the test file**

Write `test/tap/tests/reg_test_1288-load-pgsql-variables-feedback-t.cpp`:

```cpp
/**
 * @file reg_test_1288-load-pgsql-variables-feedback-t.cpp
 * @brief Verify that LOAD PGSQL VARIABLES TO RUNTIME surfaces a Records/Updated/Rejected/Unknown
 *        summary in the OK packet's info field. The pgsql path uses a separate flush helper with
 *        its own duplicated loop. See issue #1288.
 */

#include <stdio.h>
#include <string>
#include <string.h>
#include "mysql.h"
#include "mysqld_error.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(2);

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	// Set up: a known-good pgsql variable, an out-of-range one, and an unknown one.
	MYSQL_QUERY(admin,
		"INSERT OR REPLACE INTO global_variables(variable_name, variable_value) "
		"VALUES "
		"('pgsql-max_connections', '1000'), "
		"('pgsql-bogus_var_xyz', 'something')");

	// Scenario: 1 valid + 1 unknown. (pgsql-max_connections has a range that we don't probe here
	// to keep the test resilient across versions; pgsql-bogus_var_xyz is reliably unknown.)
	if (mysql_query(admin, "LOAD PGSQL VARIABLES TO RUNTIME")) {
		diag("LOAD PGSQL VARIABLES TO RUNTIME failed: %s", mysql_error(admin));
		return exit_status();
	}
	const char* info = mysql_info(admin);
	diag("LOAD PGSQL info: %s", info ? info : "(null)");

	bool has_records_2  = info && strstr(info, "Records: 2")  != NULL;
	bool has_updated_1  = info && strstr(info, "Updated: 1")  != NULL;
	bool has_unknown_1  = info && strstr(info, "Unknown: 1")  != NULL;
	ok(has_records_2 && has_updated_1 && has_unknown_1,
	   "LOAD PGSQL VARIABLES TO RUNTIME info='%s' reports Records: 2 Updated: 1 Unknown: 1",
	   info ? info : "(null)");

	// Clean up.
	MYSQL_QUERY(admin, "DELETE FROM global_variables WHERE variable_name='pgsql-bogus_var_xyz'");
	MYSQL_QUERY(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

	mysql_close(admin);
	return exit_status();
}
```

- [ ] **Step 2: Register the test in `groups.json`**

Add a new line near the existing pgsql tests (search for `pgsql16-g` to find the right neighbourhood):

```json
  "reg_test_1288-load-pgsql-variables-feedback-t" : [ "pgsql16-g1" ],
```

(If the project has more pgsql infra groups like `pgsql15-g1` or `pgsql17-g1`, add them too — check `groups.json` for the pgsql section.)

- [ ] **Step 3: Build and run the test**

```bash
make -j$(nproc) reg_test_1288-load-pgsql-variables-feedback-t
```

Then run via the isolated runner against a pgsql group:

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=pgsql16-g1 test/infra/control/run-tests-isolated.bash
```

Expected: `1..2` with both assertions passing.

- [ ] **Step 4: Commit**

```bash
git add test/tap/tests/reg_test_1288-load-pgsql-variables-feedback-t.cpp test/tap/groups/groups.json
git commit -m "test(tap): verify LOAD PGSQL VARIABLES TO RUNTIME reports flush stats (issue #1288)"
```

---

## Task 8: Final full build and lint

**Files:** none

- [ ] **Step 1: Full build**

Run: `make -j$(nproc) 2>&1 | tail -20`
Expected: clean build, no errors.

- [ ] **Step 2: Build TAP test binaries**

Run: `make -j$(nproc) build_tap_tests 2>&1 | tail -20`
Expected: clean build, all TAP test binaries compile.

- [ ] **Step 3: Verify no untracked files or stray edits**

Run: `git status`
Expected: working tree is clean apart from the commits made in Tasks 1-7.

- [ ] **Step 4: Re-read the spec and self-review**

Open `docs/superpowers/specs/2026-06-14-mysql-variables-validation-feedback-design.md` and check each requirement against the implementation:

| Spec requirement | Where it lives in the code |
|------------------|----------------------------|
| Generic path counters track 4 cases (records, updated, rejected, unknown) | `flush_GENERIC_variables__process__database_to_runtime` in `lib/Admin_FlushVariables.cpp` |
| 6 generic wrappers return `FlushVariableStats` | mysql, admin, sqliteserver, tsdb, clickhouse, ldap wrappers in same file |
| pgsql wrapper returns `FlushVariableStats` | `flush_pgsql_variables___database_to_runtime` |
| 3 inline `load_*_variables_to_runtime` return the struct | header inlines for mysql, pgsql, ldap |
| 3 admin handler call sites format and send info string | `lib/Admin_Handler.cpp` mysql, pgsql, ldap |
| TAP test for mysql: 4 assertions, includes the issue reproduction | `reg_test_1288-load-mysql-variables-feedback-t.cpp` |
| TAP test for pgsql: 2 assertions | `reg_test_1288-load-pgsql-variables-feedback-t.cpp` |
| Existing log lines and reset/delete semantics unchanged | verify by `git diff` of `lib/Admin_FlushVariables.cpp` |

If any row above is empty or wrong, fix it before declaring done.

---

## Self-Review

**Spec coverage:** All 8 spec requirements are mapped to tasks above. The "Out of Scope" items (disk path, `SET` shortcut, `SHOW WARNINGS`, log duplication) are deliberately not tasks.

**Placeholder scan:** No "TBD" / "TODO" / "fill in later" in the code. The only flexibility is Task 4 Step 4 (DRY helper) which the implementer can take or leave.

**Type consistency:** `FlushVariableStats` is defined once in `include/proxysql_admin.h` and used by name in every file. The four fields (`records`, `updated`, `rejected`, `unknown`) are spelled consistently. The `info` buffer is `char[160]` in every call site, sized to fit "Records: 99999 Updated: 99999 Rejected: 99999 Unknown: 99999" (52 chars + NUL) with headroom.

**Risk:** The pgsql flush helper's loop has its own control flow (special cases for `session_debug`, `forward_autocommit`, `default_charset`, `default_collation_connection`, `show_processlist_extended`, `session_idle_show_processlist`, `processlist_max_query_length`). Task 3 places `stats.updated++` and `stats.rejected++` / `stats.unknown++` at the right points but preserves the rest of the logic. Reviewer should pay extra attention to the pgsql commit's diff against the original loop.
