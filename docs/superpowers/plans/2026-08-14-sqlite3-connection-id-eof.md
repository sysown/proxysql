# SQLite3 CONNECTION_ID EOF Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Return a valid SQLite3-listener `CONNECTION_ID()` result for clients
with and without `CLIENT_DEPRECATE_EOF`.

**Architecture:** The SQLite3 session handler will generate the one-column
result directly, matching the established `MySQL_Session` special-query packet
sequence. The current TAP test remains the externally observable regression
coverage across the two EOF settings and two multi-statement settings.

**Tech Stack:** C++17, ProxySQL MySQL wire protocol, TAP/libmariadb.

## Global Constraints

- Preserve the exact, case-insensitive `SELECT CONNECTION_ID()` matcher.
- Return `sess->thread_session_id` as an unsigned 64-bit MySQL result value.
- Use EOF only for clients that did not negotiate `CLIENT_DEPRECATE_EOF`.
- Do not alter SQLite query execution, connection-ID allocation, or handshake logic.

---

### Task 1: Emit a capability-aware native CONNECTION_ID result

**Files:**
- Modify: `src/SQLite3_Server.cpp:818-826`
- Test: `test/tap/tests/test_sqlite3_special_queries.cpp:102-126`

**Interfaces:**
- Consumes: `MySQL_Session::thread_session_id`,
  `MySQL_Data_Stream::myconn->options.client_flag`, and `MySQL_Protocol` packet
  generators.
- Produces: a standard text-protocol resultset named `CONNECTION_ID()` with
  one row containing the frontend session ID.

- [ ] **Step 1: Establish the failing regression state**

The existing TAP assertion is the regression test. It performs
`mysql_query("SELECT CONNECTION_ID()")`, retrieves the one-row result, and
requires a nonzero number equal to `mysql_thread_id(proxy)` for each generated
option pair.

Run: inspect CI runs `31807431795` and `31807431885` for
`test_sqlite3_special_queries_libmariadb-t`.

Expected: cases 28 and 40 fail when `cflags` is `CLIENT_DEPRECATE_EOF`, while
cases 4 and 16 pass without it.

- [ ] **Step 2: Replace the SQLite-query rewrite with the minimal protocol response**

At the exact-query matcher, generate the response using this packet sequence:

```cpp
char connection_id[32];
snprintf(connection_id, sizeof(connection_id), "%u", sess->thread_session_id);
const bool deprecate_eof_active =
    sess->client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
```

Emit column count and a `MYSQL_TYPE_LONGLONG` field named `CONNECTION_ID()`.
If `deprecate_eof_active` is false, emit the intermediate EOF; emit the row;
then emit either the deprecated-EOF OK terminator or the normal EOF terminator.
Set the data-stream state to `STATE_SLEEP`, set `run_query` to false, and jump
to the existing `__run_query` cleanup path. Do not call `RequestEnd()` or free
the inbound packet: SQLite3-server direct responses follow the handler's
existing lifecycle instead.

- [ ] **Step 3: Compile the focused TAP binary**

Run:

```bash
make -C test/tap/tests PROXYSQL_PATH="$PWD" test_sqlite3_special_queries_libmariadb-t
```

Expected: the focused binary compiles successfully.

- [ ] **Step 4: Run the four-mode regression against a matching daemon**

Run the compiled `test_sqlite3_special_queries_libmariadb-t` through the TAP
runner or against a daemon built from the same worktree.

Expected: all 48 TAP assertions pass, including the two
`CLIENT_DEPRECATE_EOF` `CONNECTION_ID()` assertions.

- [ ] **Step 5: Commit the implementation**

```bash
git add src/SQLite3_Server.cpp
git commit -m "fix: handle SQLite3 CONNECTION_ID with deprecated EOF"
```
