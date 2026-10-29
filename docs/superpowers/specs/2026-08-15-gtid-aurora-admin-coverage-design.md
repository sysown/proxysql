# GTID, Aurora, and Admin Coverage Design

## Goal

Increase meaningful GCOV coverage of `MyHGC.cpp` and `ProxySQL_Admin_Tests2.cpp` by executing observable production paths through TAP tests.

## Decisions

### GTID causal routing

`test_gtid_from_ok-t` already performs a real write followed by a `min_gtid` causal read and verifies the reader-hostgroup query count. It is currently registered only in binlog groups that do not upload GCOV data. First run that unchanged TAP in the MySQL 8.4 GCOV environment. If it passes and its coverage report includes the GTID candidate branch, add `mysql84-g5` to its group registration. Do not duplicate the workload or replace it with a unit test.

### Aurora query routing

Stock MySQL cannot supply the Aurora-only `REPLICA_HOST_STATUS` monitor source. The existing `TEST_AURORA` simulator is therefore required only to control monitor state. A new TAP will:

1. Set a three-node Aurora state consisting of a writer, an eligible replica, and a replica above the query's `max_lag_ms` annotation.
2. Wait until ProxySQL has incorporated that state while keeping the high-lag server online at the monitor threshold.
3. Issue a normal libmysql query through ProxySQL's frontend, with a `max_lag_ms` query annotation and a new backend connection.
4. Assert the backend identity returned by the existing server endpoint, that the high-lag skip counter increases, and that the writer is excluded when `aurora_max_lag_ms_only_read_from_replicas` is enabled.

The simulator is control-plane test infrastructure; it does not construct the client traffic or act as a raw-wire client helper. The test is registered in `cluster_sim_aurora-g1`, which is a GCOV-uploading workflow.

### Built-in Admin tests

`PROXYSQLTEST` is already invoked by existing TAPs. Extend their behavioral coverage rather than blindly dispatching every number:

- Digest path: test commands 2, 3, and 6 after explicitly populating the digest map; assert snapshot behavior, reset behavior, and completion of asynchronous purge.
- Fast-routing path: test commands 12, 13, and 16; assert the generated row count and that the generated table is loaded into runtime. Restore rules from disk at teardown.

Do not try to cover command 31 modes 2/3 until their existing FIXME is investigated. Code after unconditional early returns and code under `#ifdef DEBUG` is not a live normal-GCOV target; making it covered requires a production-code or build-matrix decision, not an extra TAP command.

## Alternatives considered

1. New unit tests for all three areas: rejected. They bypass the routing and admin session interfaces whose integration coverage is missing.
2. A new GTID TAP: rejected. The existing test already has the required real causal workload; its lack of GCOV execution is the defect.
3. Vanilla MySQL as an Aurora source: rejected. It lacks `REPLICA_HOST_STATUS`, so it cannot cause ProxySQL to assign the Aurora lag fields under test.

## Verification

Each changed TAP must run in its owning isolated group. The focused MySQL 8.4 GTID run must produce LCOV showing the GTID candidate lines in `MyHGC.cpp`; the Aurora group must produce LCOV showing its lag-filter and writer-removal paths. `groups.json` is validated with the repository linter and all changed files pass `git diff --check`.
