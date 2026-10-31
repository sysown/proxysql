# Backend `CLIENT_DEPRECATE_EOF` Negotiation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ProxySQL request backend `CLIENT_DEPRECATE_EOF` through the Connector/C connect-call flags, while retaining the server greeting as the only source of actual support.

**Architecture:** The connector patch evaluates its already-merged effective `client_flag`, not the persistent `MYSQL::options.client_flag`. ProxySQL sets the outgoing local flags argument instead of mutating Connector/C configuration. SQLite3 Server self-loop tests independently cover servers that advertise and omit the capability.

**Tech Stack:** C++17, MariaDB Connector/C 3.3.8 vendor patch, ProxySQL TAP tests, SQLite3 Server on port 6030, GitHub Actions g9 test jobs.

## Global Constraints

- Never synthesize `CLIENT_DEPRECATE_EOF` in `mysql->server_capabilities`; preserve the server greeting.
- Preserve the fast-forward requirement that frontend negotiation and frontend advertised capability both permit the request.
- Restore all modified global MySQL variables and test configuration on every test exit path.
- Cover the exact public Connector/C `mysql_real_connect(..., client_flags)` route that caused PR #6076's g9 failure.
- Add detailed Doxygen comments to ProxySQL code and explanatory comments to the vendor patch.
- Update PR #6076's body with the handshake-state explanation and test matrix.

---

### Task 1: Make the direct Connector/C regression observable

**Files:**
- Modify: `test/tap/tests/test_sqlite3_special_queries.cpp:15-130`
- Test: `test/tap/tests/test_sqlite3_special_queries_libmariadb-t`

**Interfaces:**
- Consumes: admin connection values supplied by `CommandLine`; SQLite3 Server listener at port `6030`; `mysql-enable_client_deprecate_eof`.
- Produces: a test matrix that connects through `mysql_real_connect(..., CLIENT_DEPRECATE_EOF)` when SQLite3 Server advertises the capability and when it does not.

- [ ] **Step 1: Add a failing direct-connect capability matrix**

  Add helpers which set and restore `mysql-enable_client_deprecate_eof` through the admin interface.  For each state, connect with `CLIENT_DEPRECATE_EOF`, assert the corresponding `MYSQL::server_capabilities` bit, then run `SELECT CONNECTION_ID()` and assert one numeric row equal to `mysql_thread_id()`.

  The test cases must be named as follows:

  ```cpp
  ok(server_supports_deprecate_eof == expected_server_capability,
     "SQLite3 advertised CLIENT_DEPRECATE_EOF as configured");
  ok(connection_id_rc == 0 && valid_connection_id && connection_id == expected_connection_id,
     "SELECT CONNECTION_ID() parses with the negotiated backend EOF mode");
  ```

- [ ] **Step 2: Run the MariaDB-linked TAP binary and verify RED**

  Run:

  ```bash
  TAP_QUIET_ENVLOAD=1 test/tap/tests/test_sqlite3_special_queries_libmariadb-t
  ```

  Expected: the advertised-capability case fails before the Connector/C patch because the library receives a deprecated-EOF result yet has cleared the greeting bit after `mysql_real_connect(..., client_flags)`.

- [ ] **Step 3: Keep the existing public API call shape**

  Do not assign `CLIENT_DEPRECATE_EOF` to `MYSQL::options.client_flag` in the test.  The final `mysql_real_connect()` argument is the regression surface.

- [ ] **Step 4: Commit the test-only RED change**

  ```bash
  git add test/tap/tests/test_sqlite3_special_queries.cpp
  git commit -m "test: cover backend deprecate EOF negotiation"
  ```

### Task 2: Correct the connector decision and ProxySQL outbound request

**Files:**
- Modify: `deps/mariadb-client-library/client_deprecate_eof.patch:493-501`
- Modify: `lib/mysql_connection.cpp:903-956`
- Test: `test/tap/tests/test_sqlite3_special_queries_libmariadb-t`

**Interfaces:**
- Consumes: Connector/C's local `client_flag` after it has been OR-ed with `mysql->options.client_flag`; ProxySQL's `client_flags` reference passed to `mysql_real_connect_start()`.
- Produces: a requested capability in the outgoing connect call and a `mysql->server_capabilities` value that reflects only the backend greeting.

- [ ] **Step 1: Change the vendor-patch condition**

  Replace the persistent-options check with the effective connection flags:

  ```c
  if ((client_flag & CLIENT_DEPRECATE_EOF) == 0) {
    mysql->server_capabilities &= ~CLIENT_DEPRECATE_EOF;
  }
  ```

  Document in the patch that `client_flag` includes both the public connect-call argument and persistent options, and that the condition only clears a missing request; it never adds a server capability.

- [ ] **Step 2: Move ProxySQL's request into the local outgoing flags**

  In `MySQL_Connection::connect_start_SetClientFlag`, set or clear `CLIENT_DEPRECATE_EOF` in `client_flags`.  Do not write `mysql->options.client_flag` for this capability.  The normal path requests it when `mysql-enable_server_deprecate_eof` is enabled or session tracking is enforced.  The fast-forward path clears the local bit, then re-adds it only when the frontend actually negotiated and was advertised the capability.

  Add a Doxygen block immediately above the decision documenting all three states:

  ```cpp
  /**
   * @brief Select the backend CLIENT_DEPRECATE_EOF request for this connect attempt.
   * @details The local connect-call flags express a client preference only.  Connector/C
   *          records actual support from the backend greeting in server_capabilities;
   *          a backend that does not advertise the bit remains a legacy-EOF backend.
   */
  ```

- [ ] **Step 3: Run the direct regression test and verify GREEN**

  Run:

  ```bash
  TAP_QUIET_ENVLOAD=1 test/tap/tests/test_sqlite3_special_queries_libmariadb-t
  ```

  Expected: both advertised and non-advertised cases return a valid `CONNECTION_ID()` row; `server_capabilities` is set only in the advertised case.

- [ ] **Step 4: Review the actual diff and commit the functional correction**

  ```bash
  git diff --check
  git diff -- deps/mariadb-client-library/client_deprecate_eof.patch lib/mysql_connection.cpp
  git add deps/mariadb-client-library/client_deprecate_eof.patch lib/mysql_connection.cpp
  git commit -m "fix: preserve backend deprecate EOF negotiation"
  ```

### Task 3: Exercise ProxySQL's backend connect path through SQLite3 Server

**Files:**
- Modify: `test/tap/tests/test_match_eof_conn_cap.cpp:1-975`
- Test: `test/tap/tests/test_match_eof_conn_cap-t`

**Interfaces:**
- Consumes: existing self-loop hostgroup pointing to `127.0.0.1:6030`, `apply_proxy_conf()`, and its cleanup that reloads global configuration from disk.
- Produces: a real row-returning query through a ProxySQL backend connection for both server-advertised capability states.

- [ ] **Step 1: Add a failing backend-result assertion**

  Extend the existing connection-acquisition path after backend creation.  Execute a row-returning query through hostgroup `SQLITE3_HG` and assert that exactly one row with the expected value is returned.  Run it for the two required states:

  ```cpp
  { .cli_depr_eof = true,  .srv_depr_eof = true, .force_mismatch = false },
  { .cli_depr_eof = false, .srv_depr_eof = true, .force_mismatch = false },
  ```

  The latter proves a request does not fabricate server support: the SQLite3 greeting omits the bit, and the result must still parse as legacy EOF.

- [ ] **Step 2: Run the focused self-loop TAP test**

  Run:

  ```bash
  TAP_QUIET_ENVLOAD=1 test/tap/tests/test_match_eof_conn_cap-t
  ```

  Expected: the row assertions and existing connection-count and cleanup assertions pass with the Task 2 connect-call refactor.  The direct Connector/C test in Task 1 remains the RED regression proof; this test verifies the separate ProxySQL outbound-connect path.

- [ ] **Step 3: Add test-local documentation**

  Update the test's Doxygen file description to explain the asymmetric cases: `mysql-enable_server_deprecate_eof` requests the capability on the outbound connect call, while `mysql-enable_client_deprecate_eof` controls what the SQLite3 backend greeting advertises.

- [ ] **Step 4: Commit the end-to-end regression coverage**

  ```bash
  git add test/tap/tests/test_match_eof_conn_cap.cpp
  git commit -m "test: verify backend deprecate EOF negotiation"
  ```

### Task 4: Verify and document the important compatibility correction

**Files:**
- Modify: PR #6076 body
- Test: focused MariaDB-linked special-query test; self-loop TAP test; relevant g9 CI jobs

**Interfaces:**
- Consumes: the two regression suites and the final commits.
- Produces: a reviewable PR description and an explicit compatibility-oriented commit description.

- [ ] **Step 1: Run final local verification**

  Run:

  ```bash
  git diff --check
  TAP_QUIET_ENVLOAD=1 test/tap/tests/test_sqlite3_special_queries_libmariadb-t
  TAP_QUIET_ENVLOAD=1 test/tap/tests/test_match_eof_conn_cap-t
  ```

  Expected: both TAP commands exit zero, direct connection tests cover both greeting states, and the diff has no whitespace errors.

- [ ] **Step 2: Update the PR body**

  Document:

  1. why `MYSQL::options.client_flag` was not a safe source of truth for the `mysql_real_connect(..., client_flags)` API;
  2. why ProxySQL now requests through the local connect-call flags;
  3. why a missing backend greeting bit still produces legacy EOF parsing;
  4. the SQLite3 self-loop test matrix and local/CI verification commands.

- [ ] **Step 3: Make the final commit description explicit**

  Use a commit message/body equivalent to:

  ```text
  fix: preserve backend deprecate EOF negotiation

  Request CLIENT_DEPRECATE_EOF through the mysql_real_connect flags rather
  than mutating Connector/C's persistent options.  Retain the capability only
  when the backend greeting advertises it, so legacy backends continue to use
  legacy EOF parsing.  Add direct Connector/C and SQLite3 self-loop coverage.
  ```

- [ ] **Step 4: Push the commits and inspect the g9 checks**

  Push the PR branch, then inspect the g9 test jobs that previously failed.  Report any unrelated failures separately from this regression.
