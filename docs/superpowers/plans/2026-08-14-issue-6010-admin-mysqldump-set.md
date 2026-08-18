# Issue #6010 Admin mysqldump SET Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let MySQL 8 `mysqldump --set-gtid-purged=OFF --column-statistics=0` complete an Admin backup by accepting its scoped client-timeout `SET` statement.

**Architecture:** Preserve Admin configuration updates on the existing `SET`-to-`UPDATE global_variables` path. Add a narrow parser ahead of that path: scope-qualified assignments whose names appear in `mysql_variables.ignore_vars` are successful Admin no-ops; the mysqldump two-timeout statement therefore returns an OK packet without persistent state. Strip an optional `SESSION`, `LOCAL`, or `GLOBAL` token before the legacy single-assignment validation so scope text is never incorporated into a variable name.

**Tech Stack:** C++17, ProxySQL Admin handler, MariaDB C client TAP test, Docker-backed TAP infrastructure.

## Global Constraints

- Support only the documented MySQL 8 dump command with `--set-gtid-purged=OFF --column-statistics=0`.
- Do not add `@@GLOBAL.gtid_executed` or `information_schema.COLUMN_STATISTICS` compatibility in this issue.
- Scoped ignored variables are no-ops and must not create or modify `global_variables` rows.
- Preserve the current error path for unknown variables and the current translation for configured Admin variables.
- Keep the test in `mysql84-g1`, matching the affected MySQL 8 client path.

---

## File Structure

- `lib/Admin_Handler.cpp` — recognizes scope tokens and the existing MySQL ignored-variable set while handling Admin `SET` commands.
- `test/tap/tests/reg_test_6010_admin_mysqldump_set-t.cpp` — exercises the real Admin protocol behavior required by mysqldump.
- `test/tap/groups/groups.json` — schedules the regression test in the MySQL 8 TAP group.

### Task 1: Add a failing Admin compatibility regression

**Files:**

- Create: `test/tap/tests/reg_test_6010_admin_mysqldump_set-t.cpp`
- Modify: `test/tap/groups/groups.json: near the other admin tests`

**Interfaces:**

- Consumes: `CommandLine`, `mysql_query_t`, `tap.h`, and the Admin endpoint supplied by the TAP infrastructure.
- Produces: `reg_test_6010_admin_mysqldump_set-t`, a standalone TAP binary with five assertions.

- [ ] **Step 1: Write the failing regression source**

```cpp
#include <cstdlib>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

static long long count_timeout_rows(MYSQL* admin) {
    const char* query =
        "SELECT COUNT(*) FROM global_variables "
        "WHERE variable_name IN ('net_read_timeout', 'net_write_timeout')";
    if (mysql_query_t(admin, query) != 0) return -1;
    MYSQL_RES* result = mysql_store_result(admin);
    MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
    const long long count = row ? atoll(row[0]) : -1;
    if (result) mysql_free_result(result);
    return count;
}

int main() {
    CommandLine cl;
    if (cl.getEnv()) return EXIT_FAILURE;

    MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port,
        cl.admin_username, cl.admin_password, false, false);
    if (!admin) return EXIT_FAILURE;

    plan(5);
    const long long before = count_timeout_rows(admin);
    ok(before == 0, "timeout variables are not Admin global variables before SET");

    const int dump_set_rc = mysql_query_t(admin,
        "SET SESSION NET_READ_TIMEOUT=86400, SESSION NET_WRITE_TIMEOUT=86400");
    ok(dump_set_rc == 0, "mysqldump timeout SET succeeds");

    const long long after = count_timeout_rows(admin);
    ok(after == before, "mysqldump timeout SET has no persistent Admin side effect");

    const int single_set_rc = mysql_query_t(admin,
        "SET SESSION net_read_timeout=86400");
    ok(single_set_rc == 0, "a scoped ignored timeout SET succeeds alone");

    const int unknown_set_rc = mysql_query_t(admin,
        "SET SESSION issue_6010_unknown_variable=1");
    ok(unknown_set_rc != 0, "unknown scoped SET remains an error");

    mysql_close(admin);
    return exit_status();
}
```

Add this scheduling entry in alphabetical position in `groups.json`:

```json
"reg_test_6010_admin_mysqldump_set-t" : [ "mysql84-g1" ],
```

- [ ] **Step 2: Build and run the regression before the handler change**

Run:

```bash
make -C test/tap/tests reg_test_6010_admin_mysqldump_set-t
export WORKSPACE=$PWD
export INFRA_ID="issue6010-before-$(date +%s)"
export TAP_GROUP="mysql84-g1"
export TEST_PY_TAP_INCL="reg_test_6010_admin_mysqldump_set-t"
export SKIP_CLUSTER_START=1
source test/infra/common/env.sh
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
./test/infra/control/stop-proxysql-isolated.bash
```

Expected: the second assertion fails because Admin reports `Unknown global variable: 'SESSION NET_READ_TIMEOUT'`.

- [ ] **Step 3: Commit the test-only red state**

```bash
git add test/tap/tests/reg_test_6010_admin_mysqldump_set-t.cpp test/tap/groups/groups.json
git commit -m "test: reproduce Admin mysqldump SET failure"
```

### Task 2: Recognize scoped ignored MySQL variables in the Admin handler

**Files:**

- Modify: `lib/Admin_Handler.cpp: include block and admin_handler_command_set`
- Test: `test/tap/tests/reg_test_6010_admin_mysqldump_set-t.cpp`

**Interfaces:**

- Consumes: `mysql_variables.ignore_vars` declared by `MySQL_Protocol.h`; its members include `net_read_timeout` and `net_write_timeout`.
- Produces: `admin_handler_command_set()` sends an Admin OK packet and returns `false` when every comma-separated assignment is a `SESSION` or `LOCAL` ignored MySQL variable; it otherwise follows the existing validation/update path.

- [ ] **Step 1: Add focused parser helpers above `admin_handler_command_set`**

Include `MySQL_Protocol.h`, then add helpers with these responsibilities:

```cpp
enum class admin_set_scope { implicit, session, local, global };

static admin_set_scope strip_admin_set_scope(char*& variable_name) {
    // Skip leading spaces, compare SESSION/LOCAL/GLOBAL case-insensitively,
    // move variable_name past a matched token and its following spaces, and
    // return the matched scope. Return implicit when no token is present.
}

static bool is_ignored_mysql_variable(const char* variable_name) {
    return std::any_of(mysql_variables.ignore_vars.cbegin(),
        mysql_variables.ignore_vars.cend(), [variable_name](const std::string& ignored) {
            return strcasecmp(ignored.c_str(), variable_name) == 0;
        });
}

static bool is_ignored_scoped_set(char* assignments) {
    // Split only on commas between assignments, split each assignment once at
    // '=', trim its left side, strip its scope, and return true only when the
    // input contains at least one assignment and every assignment has SESSION
    // or LOCAL scope and names an ignored MySQL variable.
}
```

Use a local mutable copy of the assignment text in `is_ignored_scoped_set`;
the original query remains available for the legacy handler. The comma loop
must consume both timeout assignments, not stop after the first `=`.

- [ ] **Step 2: Route scoped ignored assignments to an OK packet**

Immediately after logging in `admin_handler_command_set`, classify the text
after `SET `:

```cpp
if (is_ignored_scoped_set(query_no_space + sizeof("SET ") - 1)) {
    pa->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
    return false;
}
```

For the existing one-assignment path, call
`strip_admin_set_scope(var_name)` after
`trim_spaces_in_place(untrimmed_var_name)` and before
`is_sensitive_set_variable_name()` or `is_valid_global_variable()`. This
lets `SET GLOBAL mysql-...=...` reach the current Admin variable validation
while leaving unscoped Admin behavior unchanged. The unknown-variable error
branch remains unchanged.

- [ ] **Step 3: Rebuild the changed server and focused TAP binary**

Run:

```bash
make -j2 build_src_debug
make -C test/tap/tests reg_test_6010_admin_mysqldump_set-t
```

Expected: both commands finish successfully; `src/proxysql` and the focused
TAP binary exist.

- [ ] **Step 4: Run the focused TAP regression against the changed server**

Run:

```bash
export WORKSPACE=$PWD
export INFRA_ID="issue6010-after-$(date +%s)"
export TAP_GROUP="mysql84-g1"
export TEST_PY_TAP_INCL="reg_test_6010_admin_mysqldump_set-t"
export SKIP_CLUSTER_START=1
source test/infra/common/env.sh
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
./test/infra/control/stop-proxysql-isolated.bash
```

Expected: all five TAP assertions pass. On a failure, inspect
`ci_infra_logs/$INFRA_ID/tests/proxysql-tester.py/tests/reg_test_6010_admin_mysqldump_set-t.log.gz`.

- [ ] **Step 5: Commit the handler implementation**

```bash
git add lib/Admin_Handler.cpp
git commit -m "fix: accept mysqldump session timeout SETs in Admin"
```

### Task 3: Verify the intended scope and final diff

**Files:**

- Modify: no additional source files expected
- Test: `test/tap/tests/reg_test_6010_admin_mysqldump_set-t.cpp`

**Interfaces:**

- Consumes: the focused TAP test and the new Admin handler classification.
- Produces: evidence that this branch implements only the flagged mysqldump compatibility path.

- [ ] **Step 1: Confirm excluded functionality has not been added**

Run:

```bash
git diff origin/v3.0...HEAD -- lib/Admin_Handler.cpp test/tap/tests/reg_test_6010_admin_mysqldump_set-t.cpp test/tap/groups/groups.json
rg -n 'gtid_executed|COLUMN_STATISTICS' lib/Admin_Handler.cpp test/tap/tests/reg_test_6010_admin_mysqldump_set-t.cpp
```

Expected: the diff is limited to scoped ignored-`SET` handling and the
regression test. No new GTID or `COLUMN_STATISTICS` compatibility behavior is
present.

- [ ] **Step 2: Check formatting and repository state**

Run:

```bash
git diff --check origin/v3.0...HEAD
git status --short --branch
git log --oneline origin/v3.0..HEAD
```

Expected: no whitespace errors, a clean worktree, and the design, test, and
implementation commits on `fix/6010-admin-mysqldump-set`.

- [ ] **Step 3: Commit only if verification requires a correction**

For a needed correction, stage the exact changed files and use this message:

```bash
git commit -m "test: finalize issue 6010 coverage"
```
