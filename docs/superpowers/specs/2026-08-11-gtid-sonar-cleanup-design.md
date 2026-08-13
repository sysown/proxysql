# GTID PR Sonar Cleanup Design

## Goal

Clear the five open SonarCloud findings on PR #6035 without changing GTID behavior, then push the verified result once to retrigger the full CI pipeline.

## Scope

The change is limited to three areas:

1. `MySQL_HostGroups_Manager::generate_mysql_gtid_executed_tables()`
   - Extract endpoint-record creation and reader-connection startup into focused helpers.
   - Construct a new `GTID_Server_Data` with `std::make_unique`, transferring ownership to the existing raw-pointer map only after insertion succeeds.
   - Use early exits in the helpers to remove excessive nesting while preserving the existing locks, endpoint key, inactive-record behavior, and reconnect logic.

2. `gtid_server_data_unit-t.cpp`
   - Replace the test's direct `free()` call with the repository's malloc-aware smart-pointer type.
   - Continue closing the watcher's socket before its memory is released.

3. `test_gtid_from_ok-t.cpp`
   - Split `run_test()` into small phase helpers sharing a lightweight test context.
   - Preserve the existing 14 TAP assertions, cleanup guard, routing, variable restoration, and the rule that ProxySQL never enables `OWN_GTID`; it only consumes a GTID when one is present in an OK packet.

No Sonar suppression, feature expansion, GTID freshness policy, or wholesale conversion of `gtid_map` ownership is included.

## Verification

The current five open Sonar findings are the static-analysis red state. After refactoring:

- build the debug target;
- run all three focused GTID unit binaries (224 assertions total);
- run the isolated `legacy-binlog-g1` `test_gtid_from_ok-t` integration case;
- confirm a clean diff and worktree;
- commit locally, push the new head once, and verify that SonarCloud and the full CI checks are newly created for that head.

The existing full-CI failure is environmental: the Ubuntu 24 self-hosted runner could not clean root-owned MariaDB build files during checkout. No repository code change is proposed for that runner contamination; the new push will retrigger the workflow after its cleanup guard restored ownership.
