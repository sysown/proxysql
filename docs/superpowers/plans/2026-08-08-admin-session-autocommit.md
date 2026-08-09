# Admin Session Autocommit Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Connector/Python's `SET @@session.autocommit = ON|OFF` complete successfully on ProxySQL's classic Admin interface.

**Architecture:** The Admin handler already has a connect-setup compatibility block that replies with an OK packet and no result set for bare `SET AUTOCOMMIT`. Extend that same block with the Connector/Python spelling, preserving the Admin interface's existing no-op semantics. Extend its focused TAP regression test with exact Connector/Python payloads.

**Tech Stack:** C++17, ProxySQL classic Admin protocol, TAP/libmysqlclient regression test, GNU Make.

## Global Constraints

- Keep the scope to connection-setup compatibility; do not add Admin transaction-state support.
- Match `SET @@session.autocommit` case-insensitively after leading SQL comments are stripped.
- Return the existing OK/no-result-set response and do not modify `global_variables`.
- Build from a clean worktree with `make clean` followed by `make` using a bounded parallelism level derived from available CPUs and memory.
- Preserve normal red/green CI semantics; do not mask the Connector/Python 26.7.0 soak failure.

---

### Task 1: Establish the Admin compatibility regression

**Files:**
- Modify: `test/tap/tests/mysql-reg_test_5786_admin_strip_leading_sql_comments-t.cpp:39-55`
- Test: `test/tap/tests/mysql-reg_test_5786_admin_strip_leading_sql_comments-t.cpp`

**Interfaces:**
- Consumes: the existing `ACCEPT_CASES` array; each entry is sent via `mysql_query()` to the classic Admin interface.
- Produces: three failing, exact Connector/Python compatibility assertions that become green only when the Admin handler sends an OK packet.

- [ ] **Step 1: Add the precise failing connection-setup cases**

  Add these three entries immediately after the existing bare `SET AUTOCOMMIT=1` cases:

  ```cpp
  "SET @@session.autocommit = OFF",                    // Connector/Python pure-Python post-connect setup
  "SET @@session.autocommit = ON",                     // setter's opposite state uses the same syntax
  "/*connector-python*/ SET @@session.autocommit = OFF", // comment-stripping compatibility path
  ```

- [ ] **Step 2: Build and run the regression test before the handler change**

  Determine `build_jobs` as the smaller of the available CPU count and 8, then use it consistently:

  ```bash
  build_jobs=$(nproc)
  [ "$build_jobs" -gt 8 ] && build_jobs=8
  make clean
  make -j"$build_jobs"
  make -C test/tap/tests -j"$build_jobs" mysql-reg_test_5786_admin_strip_leading_sql_comments-t
  ```

  Run only the focused test through its normal isolated harness and clean up its
  uniquely named infrastructure on exit:

  ```bash
  export INFRA_ID="admin-session-autocommit-red-$(date +%s)"
  export TAP_GROUP=legacy-g1
  export TEST_PY_TAP_INCL='mysql-reg_test_5786_admin_strip_leading_sql_comments-t'
  export SKIP_CLUSTER_START=1
  trap 'test/infra/control/stop-proxysql-isolated.bash || true; test/infra/control/destroy-infras.bash || true' EXIT
  test/infra/control/ensure-infras.bash
  test/infra/control/run-tests-isolated.bash
  ```

  The new cases must fail with `ERROR: Unknown global variable:
  '@@session.autocommit'.`; retain the failing TAP output as the red-phase
  evidence.

- [ ] **Step 3: Commit the regression test**

  ```bash
  git add test/tap/tests/mysql-reg_test_5786_admin_strip_leading_sql_comments-t.cpp
  git commit -m "test: cover admin session autocommit setup"
  ```

### Task 2: Accept the Connector/Python session spelling as an Admin setup no-op

**Files:**
- Modify: `lib/Admin_Handler.cpp:4065-4088`
- Test: `test/tap/tests/mysql-reg_test_5786_admin_strip_leading_sql_comments-t.cpp`

**Interfaces:**
- Consumes: `mb`, the comment-stripped command pointer in `admin_session_handler()`.
- Produces: an OK packet through `SPA->send_ok_msg_to_client()` for `SET @@session.autocommit`, with no SQLite query or ProxySQL global-variable update.

- [ ] **Step 1: Extend only the existing compatibility predicate**

  Add one branch next to the existing `SET AUTOCOMMIT` condition:

  ```cpp
  ||
  (!strncasecmp("SET @@session.autocommit", mb, strlen("SET @@session.autocommit")))
  ```

  Do not change `admin_handler_command_set()`: the command must be consumed before it reaches the global-variable translator.

- [ ] **Step 2: Rebuild cleanly and verify the focused TAP test is green**

  ```bash
  build_jobs=$(nproc)
  [ "$build_jobs" -gt 8 ] && build_jobs=8
  make clean
  make -j"$build_jobs"
  make -C test/tap/tests -j"$build_jobs" mysql-reg_test_5786_admin_strip_leading_sql_comments-t
  ```

  Run the focused group using the same exact isolated-harness command as the
  red phase, with a new `INFRA_ID` ending in `-green`. Confirm all old and new
  accept cases receive an OK packet with no result set, then run:

  ```bash
  git diff --check
  ```

- [ ] **Step 3: Commit the minimal handler fix**

  ```bash
  git add lib/Admin_Handler.cpp test/tap/tests/mysql-reg_test_5786_admin_strip_leading_sql_comments-t.cpp
  git commit -m "fix(admin): accept session autocommit setup"
  ```

### Task 3: Verify the real Connector/Python 26.7.0 path and publish

**Files:**
- Modify: no additional source files
- Test: `test/scripts/mysqlx/behavioral_validation.py` through the existing `mysqlx-soak-g1` harness

**Interfaces:**
- Consumes: the image built with `MYSQL_CONNECTOR_PYTHON_VERSION=26.7.0` and the existing behavioral-validation Admin connection.
- Produces: evidence that the connector reaches its Admin delete/reload actions rather than failing during post-connect setup.

- [ ] **Step 1: Build the test image with the compatibility connector version**

  ```bash
  docker build --network host \
    --build-arg MYSQL_CONNECTOR_PYTHON_VERSION=26.7.0 \
    -t proxysql-ci-base:mysqlx-connector-26.7.0 \
    -f test/infra/docker-base/Dockerfile test/infra/docker-base
  ```

- [ ] **Step 2: Run the existing MySQLX soak harness against that image**

  The isolation scripts consume `proxysql-ci-base:latest`, so temporarily
  point that local compatibility alias at the versioned image, run only the
  behavioral test, and restore the 9.7.0 alias afterwards:

  ```bash
  docker tag proxysql-ci-base:mysqlx-connector-26.7.0 proxysql-ci-base:latest
  export INFRA_ID="admin-session-autocommit-mysqlx-$(date +%s)"
  export TAP_GROUP=mysqlx-soak-g1
  export TEST_PY_TAP_INCL='test_mysqlx_soak_behavioral-t'
  export SKIP_CLUSTER_START=1
  trap 'test/infra/control/stop-proxysql-isolated.bash || true; test/infra/control/destroy-infras.bash || true; docker tag proxysql-ci-base:mysqlx-connector-9.7.0 proxysql-ci-base:latest' EXIT
  test/infra/control/ensure-infras.bash
  test/infra/control/run-tests-isolated.bash
  ```

  Verify that `mysql.connector.connect()` reaches the Admin delete/reload
  actions instead of emitting `Unknown global variable:
  '@@session.autocommit'`; assess any subsequent route-reload result
  separately.

- [ ] **Step 3: Publish the focused branch as a pull request**

  Rebase or merge the current `origin/v3.0` only if it has advanced, run `git diff --check`, push `fix/admin-session-autocommit`, and open a PR targeting `v3.0`. The PR description must state the pure-Python Connector/Python fallback mechanism, the Admin no-op behavior, focused TAP evidence, and that #5984 must land before CI can exercise the 26.7.0 soak matrix.
