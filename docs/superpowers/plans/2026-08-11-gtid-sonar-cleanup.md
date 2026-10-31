# GTID Sonar Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clear all five open SonarCloud findings on PR #6035 without changing GTID behavior, then push the verified head once to retrigger full CI.

**Architecture:** Keep the existing raw-pointer `gtid_map` contract, but use scoped ownership while creating records and extract connection setup into private manager helpers. Use the existing malloc-aware smart-pointer utility in the unit test, and decompose the integration test into phase helpers sharing a small context while retaining its exact query order, cleanup, and 14 TAP assertions.

**Tech Stack:** C++17, pthread/libev, ProxySQL TAP tests, GNU Make, GitHub Actions, SonarCloud.

## Global Constraints

- Do not enable `OWN_GTID` in production; consume GTIDs only when an OK packet already contains one.
- Preserve endpoint-wide `hostname:port` GTID sharing, inactive-reader eligibility, lock ordering, and reconnect behavior.
- Preserve all 14 integration TAP assertions and cleanup/restoration semantics.
- Do not suppress Sonar findings or convert the whole `gtid_map` to smart-pointer ownership.
- Push once, after local verification, so the new head triggers a single fresh CI cycle.

---

### Task 1: Flatten GTID record and reader setup

**Files:**
- Modify: `include/MySQL_HostGroups_Manager.h:1237`
- Modify: `lib/MySQL_HostGroups_Manager.cpp:1751-1804`
- Test: `test/tap/tests/unit/gtid_server_data_unit-t.cpp`

**Interfaces:**
- Consumes: the existing `gtid_map`, `gtid_missing_nodes`, `new_connect_watcher()`, `MyHGM->gtid_ev_loop`, and the caller-held `gtid_rwlock` write lock.
- Produces: private methods `GTID_Server_Data* get_or_create_gtid_server_data(MySrvC*, const std::string&)` and `void start_gtid_reader_if_needed(MySrvC*, GTID_Server_Data*)`.

- [ ] **Step 1: Record the static-analysis red state**

Run:

```bash
curl -fsS 'https://sonarcloud.io/api/issues/search?componentKeys=sysown_proxysql&pullRequest=6035&ps=100' \
  | jq '[.issues[] | select(.status=="OPEN" and .component=="sysown_proxysql:lib/MySQL_HostGroups_Manager.cpp") | {key,line,message}]'
```

Expected: three findings at the GTID generation loop: two excessive-nesting findings and one direct-`new` finding.

- [ ] **Step 2: Add the focused private interfaces**

Add under the class's final `private:` section:

```cpp
GTID_Server_Data* get_or_create_gtid_server_data(MySrvC* server, const std::string& endpoint);
void start_gtid_reader_if_needed(MySrvC* server, GTID_Server_Data* gtid_data);
```

- [ ] **Step 3: Implement scoped record construction and flat reader startup**

Add `<memory>` explicitly to `MySQL_HostGroups_Manager.cpp`. Implement record lookup/construction with this ownership sequence:

```cpp
GTID_Server_Data* MySQL_HostGroups_Manager::get_or_create_gtid_server_data(
    MySrvC* server, const std::string& endpoint) {
    auto existing = gtid_map.find(endpoint);
    if (existing != gtid_map.end() && existing->second != nullptr) {
        return existing->second;
    }
    if (existing != gtid_map.end()) {
        gtid_map.erase(existing);
    }

    auto owned_data = std::make_unique<GTID_Server_Data>(
        nullptr, server->address, server->gtid_port, server->port);
    owned_data->active = false;
    GTID_Server_Data* data = owned_data.get();
    gtid_map.emplace(endpoint, data);
    owned_data.release();
    return data;
}
```

Implement reader startup with early returns:

```cpp
void MySQL_HostGroups_Manager::start_gtid_reader_if_needed(
    MySrvC* server, GTID_Server_Data* data) {
    if (data->active || server->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
        return;
    }
    ev_io* watcher = new_connect_watcher(server->address, server->gtid_port, server->port);
    if (watcher == nullptr) {
        gtid_missing_nodes = true;
        return;
    }
    data->w = watcher;
    data->active = true;
    watcher->data = static_cast<void*>(data);
    ev_io_start(MyHGM->gtid_ev_loop, watcher);
}
```

- [ ] **Step 4: Replace nested loop bodies with guard clauses and helpers**

Inside `generate_mysql_gtid_executed_tables()`, retain the two hostgroup/server loops but skip servers without `gtid_port` immediately:

```cpp
if (server->gtid_port == 0) {
    continue;
}
std::string endpoint = server->address;
endpoint.append(":");
endpoint.append(std::to_string(server->port));
stale_server.erase(endpoint);
GTID_Server_Data* data = get_or_create_gtid_server_data(server, endpoint);
start_gtid_reader_if_needed(server, data);
```

Do not move either manager lock or alter stale-record cleanup.

- [ ] **Step 5: Build and run the GTID manager characterization test**

Run:

```bash
make -j8 debug
make -C test/tap/tests/unit gtid_server_data_unit-t
test/tap/tests/unit/gtid_server_data_unit-t
```

Expected: build exit 0 and TAP plan `1..109` with no `not ok` lines.

---

### Task 2: Give the unexpected connect watcher scoped test ownership

**Files:**
- Modify: `test/tap/tests/unit/gtid_server_data_unit-t.cpp:15-24,451-464`

**Interfaces:**
- Consumes: `mf_unique_ptr<T>` and `free_deleter` from `proxysql_utils.h`.
- Produces: no new public interface; only test-local scoped ownership.

- [ ] **Step 1: Confirm the direct-free red finding**

Run:

```bash
curl -fsS 'https://sonarcloud.io/api/issues/search?componentKeys=sysown_proxysql&pullRequest=6035&ps=100' \
  | jq '[.issues[] | select(.status=="OPEN" and .component=="sysown_proxysql:test/tap/tests/unit/gtid_server_data_unit-t.cpp") | {key,line,message}]'
```

Expected: one finding asking to remove the direct `free()` call.

- [ ] **Step 2: Use the repository malloc-aware owner**

Include `proxysql_utils.h`, then replace the raw cleanup branch with:

```cpp
mf_unique_ptr<ev_io> watcher(new_connect_watcher(invalid_address, 3307, 3306));
if (watcher != nullptr) {
    all_failed = false;
    close(watcher->fd);
}
```

The smart pointer must stay inside the loop so every unexpected watcher is released before the next attempt.

- [ ] **Step 3: Rebuild and rerun the focused unit test**

Run:

```bash
make -C test/tap/tests/unit gtid_server_data_unit-t
test/tap/tests/unit/gtid_server_data_unit-t
```

Expected: TAP plan `1..109`, zero failures, and the file-descriptor count unchanged.

---

### Task 3: Decompose the GTID OK-packet integration scenario

**Files:**
- Modify: `test/tap/tests/test_gtid_from_ok-t.cpp:368-653`

**Interfaces:**
- Consumes: existing SQL/query helpers, `TestConnections`, and `CleanupGuard`.
- Produces: test-local `TestContext` plus eight `bool` phase helpers; `run_test()` remains the only caller and retains its `int` return contract.

- [ ] **Step 1: Confirm the cognitive-complexity red finding and baseline behavior**

Run:

```bash
curl -fsS 'https://sonarcloud.io/api/issues/search?componentKeys=sysown_proxysql&pullRequest=6035&ps=100' \
  | jq '[.issues[] | select(.status=="OPEN" and .component=="sysown_proxysql:test/tap/tests/test_gtid_from_ok-t.cpp") | {key,line,message}]'
```

Expected: one finding reporting `run_test()` complexity 78 versus 25 allowed. The already-recorded isolated baseline is `PASS 1/4`, `FAIL 0/4`, with three filtered skips.

- [ ] **Step 2: Add the shared test context**

Place after `CleanupGuard`:

```cpp
struct TestContext {
    CommandLine& cl;
    MYSQL* admin;
    TestConnections& connections;
    CleanupGuard& cleanup;
    std::string address;
    int mysql_port = 0;

    std::string endpoint_filter() const {
        return " hostname=" + sql_quote(admin, address) +
            " AND port=" + std::to_string(mysql_port);
    }
};
```

- [ ] **Step 3: Extract endpoint discovery and clean-state checks**

Create:

```cpp
static bool resolve_writer_endpoint(TestContext& context);
static bool verify_endpoint_absent(TestContext& context);
```

`resolve_writer_endpoint()` owns the `BINLOG_WHG` parsing, writer query, numeric resolution, TAP assertion 1, diagnostic, and `cleanup.set_endpoint()`. `verify_endpoint_absent()` performs assertions 2 and 3 against runtime servers and GTID stats using `context.endpoint_filter()`.

- [ ] **Step 4: Extract routing and variable setup**

Create:

```cpp
static bool install_dedicated_routing(TestContext& context);
static bool configure_gtid_variables(TestContext& context);
```

Move the two server rows, three query rules, saved variables, capability parsing, runtime variable changes, and all three `LOAD ... TO RUNTIME` statements without changing their order. Mark server/rule cleanup only after the corresponding insert succeeds.

- [ ] **Step 5: Extract backend preparation**

Create:

```cpp
static bool prepare_backend_and_empty_record(TestContext& context);
```

This helper must save and temporarily set the backend global `session_track_gtids`, recreate the table, close the direct connection, emit assertion 4, poll the inactive record, and emit assertion 5. It must not enable session tracking in ProxySQL production code.

- [ ] **Step 6: Extract disabled and untracked phases**

Create:

```cpp
static bool verify_disabled_ingestion(TestContext& context);
static bool verify_untracked_insert(TestContext& context);
```

The disabled helper performs the tracked row-1 insert and assertions 6-7, pins its backend, then enables `mysql-update_gtid_from_ok`. The untracked helper opens a fresh connection, verifies `session_track_gtids=OFF`, inserts row 2, emits assertions 8-10, verifies the endpoint set remains empty, then closes/unpins both connections in the current order.

- [ ] **Step 7: Extract tracked ingestion and causal read**

Create:

```cpp
static bool verify_tracked_causal_read(TestContext& context);
```

Move the row-3 tracked insert, GTID poll, reader-hostgroup query counter, causal read, and assertions 11-14 unchanged. Return true only when the causal read succeeds and the reader-hostgroup counter increases.

- [ ] **Step 8: Reduce `run_test()` to phase orchestration**

Use explicit early returns so failures stop at the same point:

```cpp
static int run_test(CommandLine& cl, MYSQL* admin,
    TestConnections& connections, CleanupGuard& cleanup) {
    TestContext context { cl, admin, connections, cleanup };
    if (!resolve_writer_endpoint(context) ||
        !verify_endpoint_absent(context) ||
        !install_dedicated_routing(context) ||
        !configure_gtid_variables(context) ||
        !prepare_backend_and_empty_record(context) ||
        !verify_disabled_ingestion(context) ||
        !verify_untracked_insert(context) ||
        !verify_tracked_causal_read(context)) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
```

- [ ] **Step 9: Compile the integration target**

Run:

```bash
make -C test/tap/tests test_gtid_from_ok-t
```

Expected: exit 0 with no compiler errors or warnings introduced by the refactor.

---

### Task 4: Final verification, commit, push, and CI retrigger

**Files:**
- Verify: all files modified in Tasks 1-3
- Commit: the production/test refactor as the final implementation commit

**Interfaces:**
- Consumes: the exact binaries produced by Tasks 1-3 and unified isolated test infrastructure.
- Produces: one pushed PR head with fresh SonarCloud and full-CI check suites.

- [ ] **Step 1: Run the complete focused local verification**

Run:

```bash
make -j8 debug
test/tap/tests/unit/gtid_server_data_unit-t
test/tap/tests/unit/gtid_set_unit-t
test/tap/tests/unit/gtid_trxid_interval_unit-t
```

Expected: debug build exit 0; TAP plans `1..109`, `1..67`, and `1..48`, with zero `not ok` lines.

- [ ] **Step 2: Run the isolated customer-path regression**

Run with a unique, explicit namespace:

```bash
export INFRA_ID='pr6035-sonar-final'
export TAP_GROUP='legacy-binlog-g1'
export TEST_PY_TAP_INCL='test_gtid_from_ok-t'
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
```

Expected: `SUMMARY: 'tests' PASS 1/4 : FAIL 0/4 : SKIP 3/4`.

Then remove only that namespace's containers/network using the documented isolated-infrastructure cleanup scripts.

- [ ] **Step 3: Audit the final diff**

Run:

```bash
git diff --check HEAD~1..HEAD || git diff --check
git status --short
git diff --stat origin/v3.0...HEAD
```

Expected: no whitespace errors and only the approved files changed.

- [ ] **Step 4: Commit the implementation**

Run:

```bash
git add include/MySQL_HostGroups_Manager.h \
  lib/MySQL_HostGroups_Manager.cpp \
  test/tap/tests/unit/gtid_server_data_unit-t.cpp \
  test/tap/tests/test_gtid_from_ok-t.cpp
git commit -m "refactor(gtid): clear Sonar findings"
```

- [ ] **Step 5: Re-run the lightweight post-commit gate**

Run:

```bash
git status --short
git diff --check origin/v3.0...HEAD
test/tap/tests/unit/gtid_server_data_unit-t
```

Expected: clean worktree, clean diff, and `1..109` with zero failures.

- [ ] **Step 6: Push once and confirm exact-head checks**

Run:

```bash
git push origin HEAD:feature/gtid-from-ok-packets
gh pr view 6035 --repo sysown/proxysql --json headRefOid,mergeable,mergeStateStatus
gh pr checks 6035 --repo sysown/proxysql --watch=false
```

Expected: remote PR head equals local HEAD and new SonarCloud, CI-builds/trigger, lint, and automated-review checks are created for that SHA.

- [ ] **Step 7: Verify the new Sonar analysis**

After the exact-head Sonar scan completes, run:

```bash
curl -fsS 'https://sonarcloud.io/api/project_pull_requests/list?project=sysown_proxysql' \
  | jq '.pullRequests[] | select(.key=="6035") | {status,analysisDate}'
curl -fsS 'https://sonarcloud.io/api/issues/search?componentKeys=sysown_proxysql&pullRequest=6035&ps=100' \
  | jq '[.issues[] | select(.status=="OPEN")] | {open:length,issues:map({component,line,message})}'
```

Expected: quality gate `OK`, zero bugs, zero vulnerabilities, and zero open issues from this PR analysis.
