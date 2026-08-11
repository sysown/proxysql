# MySQL Processlist Idle-Session Boolean Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make textual `true` enable idle MySQL sessions in `stats_mysql_processlist` after `LOAD MYSQL VARIABLES TO RUNTIME`, with an end-to-end TAP regression test.

**Architecture:** Preserve the existing `processlist_config_t` boundary. Correct the MySQL admin-side processlist copy when the special variable callback receives boolean text, then exercise the complete admin/config/session/processlist path through TAP.

**Tech Stack:** C++17, ProxySQL admin variable loading, MariaDB client TAP tests, `groups.json` CI registration.

## Global Constraints

- Only the MySQL processlist synchronization path is changed.
- The test must use the textual `true` value and `LOAD MYSQL VARIABLES TO RUNTIME`.
- The test must prove both the disabled and enabled visibility states for an idle client session.
- Existing user changes outside this branch remain untouched.

---

### Task 1: Add the failing TAP regression test

**Files:**
- Create: `test/tap/tests/reg_test_processlist_idle_boolean-t.cpp`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: `CommandLine`, TAP helpers, MariaDB client API, ProxySQL admin `SET`/`LOAD` commands, and `stats_mysql_processlist`.
- Produces: A registered TAP binary named `reg_test_processlist_idle_boolean-t` that fails on the current `atoi("true")` implementation.

- [ ] **Step 1: Write the test source before changing production code**

  Implement one test that:

  1. Reads TAP connection settings and opens admin and frontend MySQL connections.
  2. Sets `mysql-session_idle_ms=1` and `mysql-session_idle_show_processlist=false`, then loads MySQL variables to runtime.
  3. Opens a frontend session and records `mysql_thread_id()` without issuing another query.
  4. Sleeps long enough for the session to move to an idle maintenance thread.
  5. Queries `SELECT COUNT(*) FROM stats_mysql_processlist WHERE SessionID=<id>` and asserts zero rows while the flag is false.
  6. Executes `SET mysql-session_idle_show_processlist=true` followed by `LOAD MYSQL VARIABLES TO RUNTIME`.
  7. Queries the same count and asserts one row while the flag is the textual `true`.
  8. Closes the frontend session and restores `mysql-session_idle_show_processlist=true` and `mysql-session_idle_ms=1` through a final load.

  The test must use TAP `plan()`/`ok()` assertions, free every stored result, and report query failures with `diag()` before returning a nonzero exit status.

- [ ] **Step 2: Register the test in every standard MySQL g1 group**

  Add the test name to the same group list used by `kill_connection3-t`:

  ```json
  "reg_test_processlist_idle_boolean-t" : [ "legacy-g1","mariadb10-galera-g1","mysql-auto_increment_delay_multiplex=0-g1","mysql-multiplexing=false-g1","mysql-query_digests=0-g1","mysql-query_digests_keep_comment=1-g1","mysql84-g1","mysql84-gr-g1","mysql90-g1","mysql90-gr-g1","mysql93-g1","mysql93-gr-g1","mysql95-g1","mysql95-gr-g1" ]
  ```

- [ ] **Step 3: Build and run only the new test to verify the expected failure**

  Run:

  ```bash
  make -C test/tap/tests reg_test_processlist_idle_boolean-t
  ./test/tap/tests/reg_test_processlist_idle_boolean-t
  ```

  Expected: compilation succeeds when TAP dependencies are available, and the enabled assertion fails against the current implementation because `atoi("true")` leaves the admin-side flag disabled. If infrastructure or generated dependencies are unavailable, capture that exact limitation and use the source-level red/green validation below.

### Task 2: Fix boolean synchronization

**Files:**
- Modify: `lib/Admin_FlushVariables.cpp:498-500`

**Interfaces:**
- Consumes: `varvalue` supplied by `flush_GENERIC_variables__process__database_to_runtime()` after `GloMTH->set_variable()` validates the MySQL variable.
- Produces: Correct `GloAdmin->variables.mysql_processlist.show_idle_session` values for `true`, `false`, `1`, and `0`.

- [ ] **Step 1: Replace the numeric-only conversion**

  Change the MySQL callback assignment from:

  ```cpp
  GloAdmin->variables.mysql_processlist.show_idle_session = atoi(varvalue);
  ```

  to a boolean conversion equivalent to:

  ```cpp
  GloAdmin->variables.mysql_processlist.show_idle_session =
      strcasecmp(varvalue, "true") == 0 || strcasecmp(varvalue, "1") == 0;
  ```

  Keep the callback in the existing special-value list and do not alter the PostgreSQL processlist path in this focused fix.

- [ ] **Step 2: Rebuild and rerun the regression test**

  Run:

  ```bash
  make -C lib -j2
  make -C src -j2
  make -C test/tap/tests reg_test_processlist_idle_boolean-t
  ./test/tap/tests/reg_test_processlist_idle_boolean-t
  ```

  Expected: the disabled assertion remains zero and the textual-`true` assertion reports the idle session.

### Task 3: Validate repository integration

**Files:**
- Validate: `lib/Admin_FlushVariables.cpp`, `test/tap/tests/reg_test_processlist_idle_boolean-t.cpp`, `test/tap/groups/groups.json`

- [ ] **Step 1: Run TAP registration and formatting checks**

  ```bash
  python3 test/tap/groups/lint_groups_json.py
  python3 test/tap/groups/check_groups.py --source
  git diff --check
  ```

- [ ] **Step 2: Inspect the final diff and status**

  ```bash
  git diff --stat
  git diff -- lib/Admin_FlushVariables.cpp test/tap/tests/reg_test_processlist_idle_boolean-t.cpp test/tap/groups/groups.json
  git status --short --branch
  ```

  Confirm only the intended production file, TAP test, group registration, and implementation documents are present.

- [ ] **Step 3: Commit the implementation**

  ```bash
  git add lib/Admin_FlushVariables.cpp test/tap/tests/reg_test_processlist_idle_boolean-t.cpp test/tap/groups/groups.json
  git commit -m "fix: parse idle processlist boolean values"
  ```

- [ ] **Step 4: Run the final available verification commands**

  Repeat the targeted test/build commands that are supported by the environment and record any dependency or infrastructure limitation explicitly before requesting review and opening the PR.
