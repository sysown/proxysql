# DuckDB Review Fixes and Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the remaining valid PR 6133 review findings and publish a website-ready DuckDB plugin documentation set in the repository.

**Architecture:** Keep the wire-protocol decisions in the DuckDB session layer, reject oversized compatibility rows at the existing `SQLite3_result::add_row` boundary, and exercise both with focused TAP unit tests. Make `doc/duckdb/` the canonical operator documentation, while retaining short developer-facing READMEs next to the plugin and vendored dependency.

**Tech Stack:** C++17, DuckDB 1.4.5 C/C++ APIs, PostgreSQL v3 wire protocol, GNU Make, TAP, Markdown.

**Spec:** Approved documentation structure in the PR 6133 review conversation; implementation background in `docs/superpowers/specs/2026-08-26-duckdb-server-plugin-design.md`.

## Global Constraints

- DuckDB remains a PROXYSQL40/v4.0-only runtime plugin.
- PostgreSQL extended-query execution remains unsupported; rejection must follow PostgreSQL error resynchronization semantics.
- `enable_external_access` remains false by default.
- User documentation belongs in `doc/duckdb/`; `docs/superpowers/` remains internal design/plan material.
- Run focused unit or syntax checks only; do not run a broad repository build.
- Do not commit or push unless the user separately requests it.

---

### Task 1: Reject oversized sized rows

**Files:**
- Modify: `include/sqlite3db.h`
- Modify: `lib/sqlite3db.cpp`
- Test: `test/tap/tests/unit/sqlite3db_unit-t.cpp`

**Interfaces:**
- Produces: `bool SQLite3_row::add_fields(char **fields, const unsigned long *sizes)`.
- Produces: `SQLite3_result::add_row(fields, sizes)` returning `SQLITE_TOOBIG` without appending a row when a field or complete row cannot fit the existing `int` representation.

- [ ] **Step 1: Write the failing boundary tests**

```cpp
char byte = 'x';
char* fields[] = { &byte, &byte };
unsigned long one_too_large[] = { static_cast<unsigned long>(INT_MAX) + 1UL, 0UL };
unsigned long cumulative_overflow[] = { static_cast<unsigned long>(INT_MAX), 1UL };

SQLite3_result result(2);
ok(result.add_row(fields, one_too_large) == SQLITE_TOOBIG && result.rows_count == 0,
   "a field larger than INT_MAX is rejected without adding a row");
ok(result.add_row(fields, cumulative_overflow) == SQLITE_TOOBIG && result.rows_count == 0,
   "a cumulative row larger than INT_MAX is rejected without adding a row");
```

- [ ] **Step 2: Run the focused test and confirm the new assertions fail for the overflow bug**

Run: `cd test/tap/tests/unit && make sqlite3db_unit-t -j2 && ./sqlite3db_unit-t`

Expected: the new boundary case fails or aborts before the implementation change.

- [ ] **Step 3: Validate before narrowing or allocating**

```cpp
bool SQLite3_row::add_fields(char **fields, const unsigned long *input_sizes) {
    unsigned long long total = 0;
    for (int i = 0; i < cnt; ++i) {
        if (fields[i] == nullptr) continue;
        if (input_sizes[i] > static_cast<unsigned long>(INT_MAX) ||
            total + input_sizes[i] + 1ULL > static_cast<unsigned long long>(INT_MAX)) {
            return false;
        }
        total += input_sizes[i] + 1ULL;
    }
    // Existing copy logic, now using validated lengths.
    return true;
}
```

Delete the temporary row and return `SQLITE_TOOBIG` from `SQLite3_result::add_row` when validation fails.

- [ ] **Step 4: Re-run the focused test and confirm all assertions pass**

Run: `cd test/tap/tests/unit && make sqlite3db_unit-t -j2 && ./sqlite3db_unit-t`

Expected: TAP exits zero with the two new overflow assertions passing.

### Task 2: Reject multi-statement SET NAMES

**Files:**
- Modify: `plugins/duckdb/src/duckdb_session.cpp`
- Test: `test/tap/tests/unit/duckdb_session_unit-t.cpp`

**Interfaces:**
- Consumes: normalized compatibility statements from `duckdb_classify_query`.
- Produces: `DuckDBIntercept::none` for `SET NAMES ...; <second statement>` so DuckDB's prepare path rejects it rather than returning a no-op success.

- [ ] **Step 1: Add the failing classifier assertion**

```cpp
ok(classify("SET NAMES utf8; SELECT 1") == DuckDBIntercept::none,
   "SET NAMES followed by another statement is not swallowed as a compatibility no-op");
```

- [ ] **Step 2: Run the focused test and confirm the assertion fails**

Run: `cd test/tap/tests/unit && make duckdb_session_unit-t -j2 && ./duckdb_session_unit-t`

Expected: the new assertion reports `not ok` because the prefix matcher returns `ok_noop`.

- [ ] **Step 3: Require the normalized SET NAMES command to contain no remaining semicolon**

```cpp
return q.rfind("SET NAMES ", 0) == 0 && q.find(';') == std::string::npos;
```

- [ ] **Step 4: Re-run the focused session test**

Run: `cd test/tap/tests/unit && make duckdb_session_unit-t -j2 && ./duckdb_session_unit-t`

Expected: TAP exits zero.

### Task 3: Implement PostgreSQL extended-query error resynchronization

**Files:**
- Modify: `plugins/duckdb/include/duckdb_session.h`
- Modify: `plugins/duckdb/src/duckdb_session.cpp`
- Modify: `lib/PgSQL_Session.cpp`
- Test: `test/tap/tests/unit/duckdb_session_unit-t.cpp`
- Test: `test/tap/tests/test_duckdb_e2e_pgsql-t.cpp`

**Interfaces:**
- Produces: `DuckDBPgsqlAction duckdb_pgsql_message_action(DuckDBSessionState&, char)` with `process`, `discard`, `send_error`, and `send_ready` outcomes.
- Extends: `DuckDBSessionState` with `bool pgsql_extended_error`.
- Produces: an ErrorResponse without ReadyForQuery on the first unsupported extended message, discarding subsequent messages until Sync, then exactly one ReadyForQuery.

- [ ] **Step 1: Add failing state-machine unit assertions**

```cpp
DuckDBSessionState state;
ok(duckdb_pgsql_message_action(state, 'P') == DuckDBPgsqlAction::send_error,
   "the first extended-query message emits one error");
ok(duckdb_pgsql_message_action(state, 'B') == DuckDBPgsqlAction::discard,
   "messages after an extended-query error are discarded until Sync");
ok(duckdb_pgsql_message_action(state, 'S') == DuckDBPgsqlAction::send_ready,
   "Sync ends extended-query error recovery with ReadyForQuery");
ok(duckdb_pgsql_message_action(state, 'Q') == DuckDBPgsqlAction::process,
   "simple queries resume after Sync");
```

- [ ] **Step 2: Run the unit test and confirm the missing interface fails to compile**

Run: `cd test/tap/tests/unit && make duckdb_session_unit-t -j2`

Expected: compile failure naming the missing action type/function.

- [ ] **Step 3: Implement the pure state transition and split ErrorResponse from ReadyForQuery emission**

```cpp
enum class DuckDBPgsqlAction { process, discard, send_error, send_ready };

DuckDBPgsqlAction duckdb_pgsql_message_action(DuckDBSessionState& state, char type) {
    if (state.pgsql_extended_error) {
        if (type == 'S') {
            state.pgsql_extended_error = false;
            return DuckDBPgsqlAction::send_ready;
        }
        return DuckDBPgsqlAction::discard;
    }
    if (type == 'P' || type == 'B' || type == 'C' || type == 'D' || type == 'E') {
        state.pgsql_extended_error = true;
        return DuckDBPgsqlAction::send_error;
    }
    if (type == 'S') return DuckDBPgsqlAction::send_ready;
    return DuckDBPgsqlAction::process;
}
```

Route `S` to the plugin for SQLite sessions in `PgSQL_Session.cpp`. Keep simple-query errors on the existing ErrorResponse-plus-ReadyForQuery path.

- [ ] **Step 4: Strengthen the raw-protocol test**

Send `P`, `B`, and `S` on one connection and assert the response type sequence is `E`, then `Z`, with no second `E`.

- [ ] **Step 5: Run focused unit and non-linking syntax checks**

Run: `cd test/tap/tests/unit && make duckdb_session_unit-t -j2 && ./duckdb_session_unit-t`

Run: `g++ -std=c++17 -fsyntax-only` using the include flags printed by the existing unit target for `test_duckdb_e2e_pgsql-t.cpp` when a live listener is unavailable.

Expected: unit TAP exits zero and both changed translation units parse.

### Task 4: Harden tests and correct remaining reviewed prose

**Files:**
- Modify: `test/tap/tests/test_duckdb_admin_tables-t.cpp`
- Modify: `test/tap/tests/test_duckdb_e2e_pgsql-t.cpp`
- Modify: `test/tap/tests/unit/duckdb_engine_unit-t.cpp`
- Modify: `test/tap/tests/unit/duckdb_admin_schema_unit-t.cpp`
- Modify: `doc/PLUGIN_API.md`
- Modify: `deps/duckdb/README.md`

**Interfaces:**
- Produces: deterministic tests that prove transitions and fail safely on lost PostgreSQL connections.
- Produces: accurate ABI and vendoring reference text.

- [ ] **Step 1: Make the Admin edit value differ from the observed runtime value**

Use `threads_edit_value = threads_before_edit == "7" ? "6" : "7"`, interpolate it into the update, and assert the loaded runtime value equals it.

- [ ] **Step 2: Centralize checked libpq execution**

```cpp
PGresult* exec_or_bail(PGconn* conn, const char* sql) {
    PGresult* result = PQexec(conn, sql);
    if (result == nullptr) BAIL_OUT("DuckDB PostgreSQL connection lost while executing: %s", sql);
    return result;
}
```

Guard a null result from `PQconnectdb` before `PQstatus` or `PQfinish`.

- [ ] **Step 3: Use a secure temporary CSV fixture**

Replace the predictable filename with `mkstemp`, write through `fdopen`, and unlink the generated path after the assertion. Change literal-only `/tmp` status fixtures to non-temporary example database paths so Sonar does not mistake inert JSON data for file creation.

- [ ] **Step 4: Correct existing reference prose**

Document the ABI layout version separately from `PROXYSQL_PLUGIN_ABI_DEBUG_BIT`, state the exact DEBUG-tag match rule, and remove the claim that DuckDB copied an existing libssl/re2 LFS/checksum/verifier pattern.

- [ ] **Step 5: Run targeted compile/static checks**

Run focused test targets where available, followed by `git diff --check` and searches for the obsolete ABI/vendoring claims.

### Task 5: Publish modular user documentation

**Files:**
- Create: `doc/duckdb/index.md`
- Create: `doc/duckdb/quickstart.md`
- Create: `doc/duckdb/installation.md`
- Create: `doc/duckdb/user-guide.md`
- Create: `doc/duckdb/configuration-reference.md`
- Create: `doc/duckdb/admin-reference.md`
- Create: `doc/duckdb/protocol-compatibility.md`
- Create: `doc/duckdb/security.md`
- Create: `doc/duckdb/operations.md`
- Create: `doc/duckdb/troubleshooting.md`
- Modify: `plugins/duckdb/README.md`
- Modify: `doc/README.md`

**Interfaces:**
- Produces: one canonical Markdown page per future website section with relative links.
- Produces: a concise plugin developer README linking to canonical operator docs.

- [ ] **Step 1: Create the landing page and five-minute quickstart**

Document v4.0 availability, prerequisites, plugin loading, the default MySQL/PostgreSQL ports, one table lifecycle, and the next-page routes.

- [ ] **Step 2: Create installation and user-guide pages**

Separate source-build/plugin-loading material from day-to-day SQL, connection, persistence, and client examples.

- [ ] **Step 3: Create complete configuration and Admin references**

For all eight variables, record default, accepted form, validation, security impact, and whether LOAD applies it live or requires restart. Document both tables, the runtime view, commands, aliases, startup disk-to-memory behavior, and fresh-install empty-table behavior.

- [ ] **Step 4: Create compatibility, security, operations, and troubleshooting pages**

State text-only result metadata, single-statement/simple-query limitations, MySQL/PostgreSQL client behavior, external-access risks, monitoring/status, persistence/backup, resource planning, and symptom-based recovery steps.

- [ ] **Step 5: Replace the monolithic plugin README with a developer entry point**

Keep build artifact and maintainer links locally; link every operator topic to `doc/duckdb/` rather than duplicating it.

- [ ] **Step 6: Validate navigation and claims**

Check every relative Markdown link, search for obsolete ports/paths and contradictory variable behavior, and run `git diff --check`.

### Task 6: Final verification

**Files:**
- Verify all files above.

- [ ] **Step 1: Run focused unit tests serially**

Run the affected unit binaries, avoiding concurrent archive rebuilds.

- [ ] **Step 2: Run syntax and whitespace checks**

Run non-linking syntax checks for changed C++ not covered by a runnable test and `git diff --check`.

- [ ] **Step 3: Review the final diff against every approved review item and documentation page**

Confirm the unsafe `conn->internal_ptr` suggestion was not applied and optional style-only changes were not mixed into the patch.
