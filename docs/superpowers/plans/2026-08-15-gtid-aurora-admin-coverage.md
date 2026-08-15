# GTID, Aurora, and Admin Coverage Implementation Plan

> For agentic workers: REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

Goal: Execute the existing GTID causal workload in GCOV CI and add behaviorally asserted Aurora and Admin TAP workloads for previously unexecuted coverage paths.

Architecture: No production code changes. Register the existing GTID TAP in the MySQL 8.4 coverage group only after a focused proof run. Add one Aurora simulator-group TAP that supplies deterministic monitor state and sends normal libmysql traffic through ProxySQL, plus one MySQL 8.4 TAP for live Admin commands.

Tech Stack: C++17 TAP/libmysqlclient, ProxySQL admin SQL, existing cluster simulator, groups.json, GCOV/fastcov.

## Global Constraints

- Use normal libmysql client traffic for every ProxySQL request; no handcrafted client protocol packets.
- Use TEST_AURORA only to supply Aurora monitor state; assert endpoint selection and status effects from the frontend query.
- Restore Admin state through LOAD ... FROM DISK and LOAD ... TO RUNTIME.
- Add tests only to mysql84-g5 and cluster_sim_aurora-g1.
- Do not modify dead-after-return, debug-only, or command-31 FIXME paths.

---

### Task 1: Prove and register the existing GTID causal workload

Files:

- Modify: test/tap/groups/groups.json line 420
- Test: test/tap/tests/test_gtid_from_ok-t.cpp

Interfaces:

- Consumes: the existing causal min_gtid SELECT workload and MySQL 8.4 group.
- Produces: GCOV execution of the existing TAP in mysql84-g5.

- [ ] Step 1: Build the unchanged GTID TAP with GCOV

~~~
make -j"$(nproc)" WITHGCOV=1 testall
make -C test/tap -j"$(nproc)" WITHGCOV=1 tap
make -C test/tap/tests -j"$(nproc)" WITHGCOV=1 test_gtid_from_ok-t
~~~

Expected: the existing test binary is built with the same objects used by the MySQL 8.4 GCOV workflow.

- [ ] Step 2: Run only the existing GTID TAP

~~~
export INFRA_ID=coverage-gtid-proof
export TAP_GROUP=mysql84-g5
export TEST_PY_TAP_INCL='test_gtid_from_ok-t'
export COVERAGE=1
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
~~~

Expected: TAP passes and the LCOV report marks the GTID candidate lines in lib/MyHGC.cpp executed.

- [ ] Step 3: Register the proven workload

Change the entry to:

~~~
"test_gtid_from_ok-t" : [ "legacy-binlog-g1", "mysql84-binlog-g1", "mysql84-g5", "mysql90-binlog-g1", "mysql95-binlog-g1" ]
~~~

- [ ] Step 4: Validate and commit

~~~
python3 -m json.tool test/tap/groups/groups.json >/dev/null
python3 test/infra/control/lint_group_coverage.py test/tap/groups/groups.json .github/workflows
git add test/tap/groups/groups.json
git commit -m "test: run GTID causal reads in GCOV suite"
~~~

### Task 2: Add a deterministic Aurora real-traffic TAP

Files:

- Create: test/tap/tests/test_aurora_query_routing-t.cpp
- Create: test/deps/cluster_simulator/tests/aurora_traffic_payloads/query_routing.json
- Modify: test/tap/groups/groups.json
- Test: cluster_sim_aurora-g1

Interfaces:

- Consumes: cluster_sim_runner.h, AURORA_HOSTNAME, AURORA_PORT, the aurora1 user, and the backend-address response from SELECT @@version_comment.
- Produces: frontend traffic with max_lag_ms=10, an eligible-replica response from 127.0.1.12, an incremented Aurora skip counter, and no writer selection.

- [ ] Step 1: Write the failing fixture and TAP

The fixture creates writer host.1.11 at lag 0, reader host.1.12 at lag 4, reader host.1.13 at lag 50, monitor threshold above 50, and aurora_max_lag_ms_only_read_from_replicas=1. The TAP starts from that fixture, connects as aurora1 to the normal frontend, and issues:

~~~
/* ;max_lag_ms=10;create_new_connection=1 */ SELECT @@version_comment LIMIT 1
~~~

It must assert the result identifies 127.0.1.12 and that aws_aurora_replicas_skipped_during_query increased.

- [ ] Step 2: Verify red before complete implementation

~~~
make -C test/tap/tests -j"$(nproc)" WITHGCOV=1 test_aurora_query_routing-t
~~~

Expected: first the target is absent; after the initial TAP exists but before monitor-state synchronization is implemented, it fails to prove the endpoint and counter.

- [ ] Step 3: Implement synchronization and assertions

Use the existing cluster-simulator runner to configure state. Wait for expected runtime_mysql_servers rows instead of a guessed sleep. Read stats_mysql_global with a scalar helper that fails on query/result errors. Consume all resultsets and close admin, control, and frontend connections on every exit path.

- [ ] Step 4: Register and prove the focused simulator test

Add:

~~~
"test_aurora_query_routing-t" : [ "cluster_sim_aurora-g1" ]
~~~

Run:

~~~
export INFRA_ID=coverage-aurora-routing
export TAP_GROUP=cluster_sim_aurora-g1
export TEST_PY_TAP_INCL='test_aurora_query_routing-t'
export COVERAGE=1
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
~~~

Expected: TAP passes and LCOV marks lag filtering and replica-only writer removal in lib/MyHGC.cpp executed.

- [ ] Step 5: Commit

~~~
git add test/tap/tests/test_aurora_query_routing-t.cpp test/deps/cluster_simulator/tests/aurora_traffic_payloads/query_routing.json test/tap/groups/groups.json
git commit -m "test: cover Aurora routing with frontend traffic"
~~~

### Task 3: Cover live Admin built-in commands in GCOV CI

Files:

- Create: test/tap/tests/test_admin_builtin_coverage-t.cpp
- Modify: test/tap/groups/groups.json
- Test: mysql84-g5

Interfaces:

- Consumes: CommandLine admin credentials, PROXYSQLTEST 1/2/3/6/12/13/16, stats_mysql_query_digest, and mysql_query_rules_fast_routing.
- Produces: behavioral proof of digest snapshot/reset/asynchronous purge and fast-routing generation/load, with runtime state restored.

- [ ] Step 1: Write the failing Admin TAP

The test drives:

~~~
PROXYSQLTEST 1 1
PROXYSQLTEST 2
PROXYSQLTEST 3
PROXYSQLTEST 6 0
PROXYSQLTEST 12 64
PROXYSQLTEST 13 2
PROXYSQLTEST 16 64
~~~

It asserts digest rows are populated then reset/purged, command 12 produces 64 non-empty-username rows in config and runtime, and command 16 produces 64 empty-username rows in config and runtime. An RAII guard reloads rules from disk and runtime on all exits.

- [ ] Step 2: Verify red before complete implementation

~~~
make -C test/tap/tests -j"$(nproc)" WITHGCOV=1 test_admin_builtin_coverage-t
~~~

Expected: first the target is absent; the initial test fails if an expected postcondition is missing, rather than merely accepting command success.

- [ ] Step 3: Implement async-purge polling and cleanup

Poll stats_mysql_query_digest with a bounded timeout after command 6. Check mysql_affected_rows for commands 12 and 16 and query both config and runtime fast-routing tables. Cleanup runs before closing the admin connection.

- [ ] Step 4: Register and run in the GCOV group

Add:

~~~
"test_admin_builtin_coverage-t" : [ "mysql84-g5" ]
~~~

Run:

~~~
export INFRA_ID=coverage-admin-builtins
export TAP_GROUP=mysql84-g5
export TEST_PY_TAP_INCL='test_admin_builtin_coverage-t'
export COVERAGE=1
./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
~~~

Expected: TAP passes and LCOV includes cases 2, 3, 6, 12, 13, and 16 in lib/ProxySQL_Admin_Tests2.cpp.

- [ ] Step 5: Commit

~~~
git add test/tap/tests/test_admin_builtin_coverage-t.cpp test/tap/groups/groups.json
git commit -m "test: cover live admin built-in commands"
~~~

### Task 4: Final verification and coverage evidence

Files:

- Verify: all changes from Tasks 1-3.

Interfaces:

- Consumes: focused TAP outputs and generated LCOV reports.
- Produces: evidence that every new or re-registered test reaches its intended production path.

- [ ] Step 1: Validate repository state

~~~
git diff origin/v3.0...HEAD --check
python3 -m json.tool test/tap/groups/groups.json >/dev/null
python3 test/infra/control/lint_group_coverage.py test/tap/groups/groups.json .github/workflows
~~~

Expected: no whitespace errors, valid JSON, and no group-registration failure.

- [ ] Step 2: Inspect focused coverage

~~~
rg -n 'MyHGC\.cpp|ProxySQL_Admin_Tests2\.cpp' ci_infra_logs/*/coverage-report/*.info
~~~

Expected: GTID/Aurora reports contain their MyHGC.cpp paths and the Admin report contains the live switch cases.

- [ ] Step 3: Confirm final diff

~~~
git status --short
git diff --check
~~~

Expected: only intentional coverage changes and documentation commits are present.

