# Real-Traffic TAP Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make MySQL protocol and query-cache coverage come from functional TAP tests that prove real client traffic took the intended ProxySQL path.

**Architecture:** Keep protocol production code unchanged. Strengthen the existing two-client EOF/OK cache test with runtime counters, then add or extend TAP executables that use only MariaDB/MySQL C APIs and verify result values, metadata, and backend-visible effects.

**Tech Stack:** C++17, ProxySQL TAP helpers, MariaDB/MySQL C client APIs, ProxySQL admin SQL, Docker Ubuntu 24 build/test infrastructure.

## Global Constraints

- Use real client-library traffic; do not manually construct normal protocol packets.
- Use explicit cache flushes and counter deltas; do not use elapsed time to establish a cache transition.
- Do not modify ProxySQL production protocol implementation to raise coverage.
- Register every new TAP source in `test/tap/groups/groups.json`.
- Compile through the Ubuntu 24 TAP container with the linked-worktree Git metadata mount.

---

### Task 1: Prove EOF/OK query-cache conversions are cache hits

**Files:**
- Modify: `test/tap/tests_with_deps/deprecate_eof_support/deprecate_eof_cache-t.cpp`

**Interfaces:**
- Consumes: `fwd_eof_query` and `fwd_eof_ok_query` real C-client executables.
- Produces: Assertions on `stats_mysql_global.Query_Cache_count_GET_OK` and `Query_Cache_count_SET` for both conversion directions.

- [x] **Step 1: Add test helpers and assertions**

Add a scalar `stats_mysql_global` reader and a direction helper that performs:

```cpp
MYSQL_QUERY(proxy_admin, "PROXYSQL FLUSH MYSQL QUERY CACHE");
const long long get_before = read_global_counter(proxy_admin, "Query_Cache_count_GET_OK");
const long long set_before = read_global_counter(proxy_admin, "Query_Cache_count_SET");
// first real client fills; incompatible real client reads
ok(read_global_counter(proxy_admin, "Query_Cache_count_SET") == set_before + 1, "first query stores cache entry");
ok(read_global_counter(proxy_admin, "Query_Cache_count_GET_OK") == get_before + 1, "second query reads cache entry");
```

- [x] **Step 2: Remove timing dependence**

Set `cache_ttl` to 10 seconds and replace the 110 ms `usleep` expiration with an explicit admin cache flush before the reverse direction.

- [x] **Step 3: Compile and run focused cache TAP**

Compiled through the vendored client dependency and ran the focused executable in the isolated MySQL 8.4 group: all 1,151 assertions passed. The TAP log proves both cache directions with exact `Query_Cache_count_SET` and `Query_Cache_count_GET_OK` deltas.

### Task 2: Exercise COM_FIELD_LIST through a normal client

**Files:**
- Create: `test/tap/tests/mysql-com_field_list-t.cpp`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: `mysql_list_fields(MYSQL*, const char*, const char*)` from the standard MySQL C client API.
- Produces: Metadata assertions and one translated backend-digest assertion.

- [x] **Step 1: Add the functional TAP**

Create a `test` table with integer, varchar, decimal, and timestamp columns. Connect through ProxySQL and call:

```cpp
MYSQL_RES* fields = mysql_list_fields(proxy, "test.com_field_list_coverage", nullptr);
ok(fields != nullptr, "mysql_list_fields succeeds through ProxySQL");
MYSQL_FIELD* field = mysql_fetch_field(fields);
ok(strcmp(field->name, "id") == 0 && field->type == MYSQL_TYPE_LONG, "id metadata is returned");
```

Assert the complete field list and the corresponding translated `SELECT` in `stats_mysql_query_digest`.

- [x] **Step 2: Register and compile**

Register `mysql-com_field_list-t` in the normal legacy and MySQL TAP group-1 matrices, then compile it through `test/tap/tests/Makefile`.

### Task 3: Cover unexercised special-query modes

**Files:**
- Modify: `test/tap/tests/mysql-last_insert_id-t.cpp`
- Modify: `test/tap/tests/mysql-select_version_without_backend-t.cpp`

**Interfaces:**
- Consumes: ordinary `mysql_query` requests for `@@IDENTITY`, `@@VERSION`, and `VERSION()`.
- Produces: coverage for all declared identity variants and all four select-version forwarding modes.

- [x] **Step 1: Execute the missing identity variant**

Change the query loop bound to the actual array length, update the TAP plan by one result assertion, and verify plain `SELECT @@IDENTITY` returns the just-inserted identifier.

- [x] **Step 2: Add all no-backend forwarding modes**

With no backend configured, issue ordinary `SELECT @@VERSION` and `SELECT VERSION()` traffic in each documented forwarding mode. Modes 0 and 2 must return the configured internal version; modes 1 and 3 must return a non-zero client error because they require backend forwarding.

```cpp
ok(observed == expected_internal_version, "internal mode returns configured version");
```

This avoids a fragile assertion about thread-local backend-pool state while preserving functional coverage of every mode's actual client-visible behavior.

- [x] **Step 3: Compile and run the focused tests**

Compile both TAP binaries and run their registered isolated group.

### Task 4: Extend prepared-statement traffic

**Files:**
- Modify: `test/tap/tests/test_ps_no_store-t.cpp`

**Interfaces:**
- Consumes: `mysql_stmt_prepare`, `mysql_stmt_execute`, and a second ordinary backend connection.
- Produces: prepared-statement tests for a long lock-clause query and metadata refresh after `ALTER TABLE`.

- [x] **Step 1: Add the lock-clause scenario**

Prepare and execute a valid `SELECT ... FOR UPDATE /* comment */` statement whose lock clause occurs in the final 128 bytes. The trailing comment bypasses the direct suffix matcher, so assert the long-query classification counter increases exactly once as well as the returned row and successful commit.

- [x] **Step 2: Add metadata-refresh scenario**

Prepare `SELECT *` on a uniquely named table, execute it, alter that table through a second connection, execute again, and assert `mysql_stmt_result_metadata()` exposes the new column count.

- [x] **Step 3: Compile and run the focused prepared-statement TAP**

Compile the changed executable and run its existing isolated group.

### Task 5: Verify and publish

**Files:**
- Modify: only the test sources and `groups.json` above.

- [x] **Step 1: Validate registration and formatting**

Run:

```bash
python3 test/tap/groups/lint_groups_json.py
python3 test/tap/groups/check_groups.py --source
```

- [x] **Step 2: Run the changed functional tests**

Run their registered groups against the isolated ProxySQL/MySQL environment and retain exact TAP logs.

- [ ] **Step 3: Check collected coverage**

Confirm the resulting LCOV/Codecov data contains hits in `MySQL_Query_Cache.cpp`, `MySQL_Protocol.cpp`, `MySQL_Session.cpp`, and `MySQL_PreparedStatement.cpp` at the named paths.

- [ ] **Step 4: Commit and open the dedicated PR**

Commit the test-only changes on `feature/real-traffic-coverage`, push it, and open a dedicated PR targeting `v3.0`.
