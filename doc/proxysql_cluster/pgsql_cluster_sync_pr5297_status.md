# PostgreSQL Cluster Sync Parity Branch Status

## Purpose

This document explains what the `fix/postgresql-cluster-sync_2` branch and PR
`#5297` are trying to achieve, what was actually implemented, and why the branch
should still be treated as work in progress.

The goal of the branch is PostgreSQL cluster-sync parity with the existing MySQL
cluster-sync framework. In practical terms, the branch extends ProxySQL cluster
monitoring, checksum handling, peer selection, pull/apply logic, admin
variables, and TAP coverage so PostgreSQL configuration can be synchronized
between cluster nodes with the same overall model already used for MySQL.

## Current Status

As of 2026-03-18:

- PR `#5297` is still open against `v3.0`.
- GitHub reports `mergeStateStatus: DIRTY`.
- GitHub reports `reviewDecision: REVIEW_REQUIRED`.
- The latest pushed branch head on GitHub is commit `5c7e616f9`
  (`PR5297: resolve remaining actionable review findings for PGSQL checksum sync and TAP assertions`).
- The local branch also contains additional unpushed follow-up commits beyond
  `5c7e616f9`, including:
  - `bf9fc81f4` (`test: strengthen pgsql cluster sync TAP follow-up`)
  - `d702e7d3e` (`doc: summarize pgsql cluster sync branch status`)

This means the branch is functionally substantial, but it is not yet in a clean
and finished state for merge.

## Non-CI TODO

This TODO intentionally excludes the failing CI jobs, which are being worked on
separately.

- [x] resolve the immediate merge conflict against `v3.0` locally and verify
  mergeability by simulation
- [x] harden the PostgreSQL TAP follow-up so optional replica validation covers
  `pgsql_servers_v2`, `pgsql_users`, and `pgsql_query_rules`
- [x] write a maintainer-facing status document for PR `#5297`
- [x] add a module-by-module implementation summary for the PostgreSQL sync
  paths
- [x] add a non-CI merge checklist to make branch handoff easier
- [ ] push the local follow-up commits so GitHub reflects the current branch
  state
- [ ] run end-to-end PostgreSQL multi-node validation with a real replica
  topology and both `save_to_disk=true` and `save_to_disk=false`
- [ ] get final maintainer review on whether this should merge as one branch or
  be split into smaller follow-ups

## What The Branch Adds

The branch changes the following tracked files compared to `v3.0`:

- `include/ProxySQL_Cluster.hpp`
- `include/proxysql_admin.h`
- `include/proxysql_glovars.hpp`
- `lib/Admin_FlushVariables.cpp`
- `lib/PgSQL_Variables_Validator.cpp`
- `lib/ProxySQL_Admin.cpp`
- `lib/ProxySQL_Cluster.cpp`
- `test/tap/tap/Makefile`
- `test/tap/tests/test_cluster_sync_pgsql-t.cpp`

At a high level, the branch adds PostgreSQL support in the same cluster-sync
areas where MySQL already had support:

- checksum tracking
- diff counters and sync thresholds
- peer selection
- configuration pull/apply flows
- optional save-to-disk behavior
- admin variable exposure
- TAP coverage

## PostgreSQL Modules Covered

The implementation is centered around these PostgreSQL cluster-sync modules:

- `pgsql_query_rules`
- `pgsql_servers`
- `pgsql_servers_v2`
- `pgsql_users`
- `pgsql_variables`

An important architectural point is that `pgsql_replication_hostgroups` and
`pgsql_hostgroup_attributes` are not treated as independent cluster modules.
They are synchronized as part of the broader PostgreSQL servers flow and are
included in the combined checksum and apply logic for PostgreSQL servers.

## Cluster Query And Pull Support

The branch adds PostgreSQL cluster query definitions and pull paths for:

- `runtime_pgsql_servers`
- `pgsql_servers_v2`
- `pgsql_users`
- `pgsql_query_rules`
- `pgsql_query_rules_fast_routing`
- `pgsql_variables`
- `pgsql_replication_hostgroups`
- `pgsql_hostgroup_attributes`

Relevant entry points now present in the code include:

- `pull_runtime_pgsql_servers_from_peer()`
- `pull_pgsql_servers_v2_from_peer()`
- `pull_pgsql_users_from_peer()`
- `pull_pgsql_query_rules_from_peer()`
- `pull_pgsql_variables_from_peer()`

The servers path is the most complex one. It fetches and validates:

- `pgsql_servers_v2`
- `pgsql_replication_hostgroups`
- `pgsql_hostgroup_attributes`
- `runtime_pgsql_servers` when runtime sync is requested

This is important because PostgreSQL server sync is not just one table copy. It
needs the related topology and hostgroup metadata to move together.

## Checksum And Admin Variable Integration

The branch extends cluster state and admin state so PostgreSQL modules participate
in the same synchronization decision process as MySQL modules.

### Added PostgreSQL diff controls

- `cluster_pgsql_query_rules_diffs_before_sync`
- `cluster_pgsql_servers_diffs_before_sync`
- `cluster_pgsql_users_diffs_before_sync`
- `cluster_pgsql_variables_diffs_before_sync`

### Added PostgreSQL persistence controls

- `cluster_pgsql_query_rules_save_to_disk`
- `cluster_pgsql_servers_save_to_disk`
- `cluster_pgsql_users_save_to_disk`
- `cluster_pgsql_variables_save_to_disk`

### Added PostgreSQL checksum gate

- `checksum_pgsql_variables`

This checksum gate became important during review. Later fixes ensured that
disabling `checksum_pgsql_variables` resets all PostgreSQL
`*_diffs_before_sync` thresholds rather than leaving stale non-zero sync
triggers behind.

## Runtime Checksum Visibility

The branch also makes PostgreSQL checksums visible through
`runtime_checksums_values`, including:

- `pgsql_query_rules`
- `pgsql_servers`
- `pgsql_servers_v2`
- `pgsql_users`
- `pgsql_variables`

Without this, cluster nodes can not reason correctly about PostgreSQL module
drift using the existing cluster monitoring loop.

## Module-By-Module Implementation Summary

This section describes the actual PostgreSQL synchronization behavior now
present in the code.

### `pgsql_users`

Synchronization source:

- `CLUSTER_QUERY_PGSQL_USERS`
- runtime table: `runtime_pgsql_users`

Checksum behavior:

- the fetched resultset is checksummed with `get_mysql_users_checksum()`
- the resulting hash is compared to the peer checksum before any apply step

Apply behavior:

- the code reuses `update_mysql_users_mutex`
- the accepted resultset is converted to `SQLite3_result`
- `GloAdmin->init_pgsql_users(..., expected_checksum, epoch)` loads the runtime
  PostgreSQL users state
- when `cluster_pgsql_users_save_to_disk` is enabled, the branch calls
  `flush_pgsql_users__from_memory_to_disk()`

### `pgsql_variables`

Synchronization source:

- `CLUSTER_QUERY_PGSQL_VARIABLES`
- runtime table: `runtime_pgsql_variables`

Checksum behavior:

- the fetched resultset is checksummed with `mysql_raw_checksum()`
- the computed checksum must match the peer checksum before variables are loaded

Apply behavior:

- the code reuses `update_mysql_variables_mutex`
- current `pgsql-%` rows are deleted from `global_variables`
- when `cluster_sync_interfaces` is disabled, interface-related PostgreSQL
  variables listed in `CLUSTER_SYNC_INTERFACES_PGSQL` are preserved
- accepted rows are inserted into `global_variables`
- `GloAdmin->load_pgsql_variables_to_runtime(expected_checksum, epoch)` applies
  them to runtime
- when `cluster_pgsql_variables_save_to_disk` is enabled, the branch calls
  `flush_pgsql_variables__from_memory_to_disk()`

### `pgsql_query_rules`

Synchronization source:

- `CLUSTER_QUERY_PGSQL_QUERY_RULES`
- `CLUSTER_QUERY_PGSQL_QUERY_RULES_FAST_ROUTING`
- runtime tables:
  - `runtime_pgsql_query_rules`
  - `runtime_pgsql_query_rules_fast_routing`

Checksum behavior:

- both resultsets are fetched
- each resultset gets a raw checksum
- those raw checksums are combined with `SpookyHash`
- the final combined checksum must match the peer checksum before apply

Apply behavior:

- the code reuses `update_mysql_query_rules_mutex`
- the loader path is `GloAdmin->load_pgsql_query_rules_to_runtime(nullptr, nullptr, expected_checksum, epoch)`
- when `cluster_pgsql_query_rules_save_to_disk` is enabled, the branch calls
  `flush_GENERIC__from_to("pgsql_query_rules", "memory_to_disk")`

### `runtime_pgsql_servers`

Synchronization source:

- `CLUSTER_QUERY_RUNTIME_PGSQL_SERVERS`
- runtime table: `runtime_pgsql_servers`

Checksum behavior:

- the fetched runtime rows are checked with `mysql_raw_checksum()`
- the computed runtime checksum is compared with the peer runtime checksum

Apply behavior:

- the code reuses `update_runtime_mysql_servers_mutex`
- accepted rows are converted to `SQLite3_result`
- `PgHGM->servers_add(...)` loads them into the incoming manager state
- `PgHGM->commit(..., only_commit_runtime_pgsql_servers=true)` applies runtime
  PostgreSQL server state
- when `cluster_pgsql_servers_save_to_disk` is enabled, runtime state is first
  persisted through `save_pgsql_servers_runtime_to_database(false)` and then
  written to disk through `flush_GENERIC__from_to(ClusterModules::PGSQL_SERVERS, "memory_to_disk")`

### `pgsql_servers_v2` plus dependent PostgreSQL server tables

Synchronization source:

- `CLUSTER_QUERY_PGSQL_SERVERS_V2`
- `CLUSTER_QUERY_PGSQL_REPLICATION_HOSTGROUPS`
- `CLUSTER_QUERY_PGSQL_HOSTGROUP_ATTRIBUTES`
- optionally `CLUSTER_QUERY_RUNTIME_PGSQL_SERVERS`

Checksum behavior:

- the branch fetches the static PostgreSQL server resultset plus the dependent
  topology tables
- those resultsets are checked together using
  `compute_servers_tables_raw_checksum(...)`
- when runtime PostgreSQL server rows are fetched in the same operation, the
  runtime checksum is also checked before apply

Apply behavior:

- the code reuses `update_mysql_servers_v2_mutex`
- resultsets are converted with `convert_pgsql_servers_resultsets(...)`
- `GloAdmin->load_pgsql_servers_to_runtime(...)` applies:
  - `pgsql_servers_v2`
  - `pgsql_replication_hostgroups`
  - `pgsql_hostgroup_attributes`
  - optional runtime PostgreSQL server state
- when `cluster_pgsql_servers_save_to_disk` is enabled, the accepted state is
  persisted through `flush_GENERIC__from_to(ClusterModules::PGSQL_SERVERS, "memory_to_disk")`

## Refactoring Done In The Branch

This branch is not just a feature patch. It also performs a large refactor of
cluster synchronization internals while PostgreSQL support is being added.

Major refactoring themes:

- large sections of repetitive checksum handling were replaced with
  data-driven tables and loops
- multiple `get_peer_to_sync_*()` paths were unified
- a generic pull framework was introduced for module synchronization
- repetitive memory management patterns were replaced with helper utilities
- many string literals were moved into central constant namespaces

These refactors reduced code duplication and made it easier to insert
PostgreSQL modules into the same control flow as MySQL modules, but they also
increase the review burden because the branch changes behavior and structure at
the same time.

## Review-Driven Fixes Already Applied

The branch history shows repeated follow-up commits that addressed review
feedback and reproducible defects. Examples include:

- fixing PostgreSQL checksum field usage
- fixing the `CLUSTER_QUERY_RUNTIME_PGSQL_SERVERS` status handling
- fixing review findings around `checksum_pgsql_variables`
- restoring active PostgreSQL variable checksum generation in
  `Admin_FlushVariables`
- making TAP checksum-loop failure paths emit explicit failing assertions
- correcting the PostgreSQL servers TAP tuple shape

By February 23, 2026, the branch had already gone through several rounds of
review cleanup rather than remaining in its original implementation shape.

## TAP And Build Work

The branch includes two separate testing/build-related efforts.

### 1. PostgreSQL cluster-sync TAP coverage

`test/tap/tests/test_cluster_sync_pgsql-t.cpp` started as a basic presence and
accessibility test. It was later extended to cover:

- PostgreSQL checksum presence in `runtime_checksums_values`
- accessibility of PostgreSQL admin tables
- optional replica-based synchronization checks

The local follow-up commit `bf9fc81f4` extends that further by:

- documenting the test more accurately
- adding safer backup/restore helpers for temporary table mutation
- checking optional replica sync for:
  - `pgsql_servers_v2`
  - `pgsql_users`
  - `pgsql_query_rules`
- checking disk persistence on the replica when the corresponding
  `admin-cluster_pgsql_*_save_to_disk` flag is enabled
- failing the TAP assertions when those admin flags can not be read

### 2. TAP library archive handling

`test/tap/tap/Makefile` was updated in this branch to avoid stale static archive
members being reused in `libtap*.a`, which had caused linker problems in TAP
builds. A local follow-up also resolves the `v3.0` merge conflict in this file
while keeping the stale-archive workaround in a separate helper rule so the
branch remains mergeable into `v3.0`.

## Why The Branch Is Not Finished Yet

Even though the implementation is broad and many review items were already
fixed, the branch should still be treated as incomplete.

Reasons:

- the PR is still open
- GitHub still marks it `DIRTY`
- GitHub still requires review
- the local follow-up commits that improve mergeability and TAP validation have
  not yet been pushed

Separately, local validation in this workspace is limited by missing vendored
dependencies, so not every verification step can be reproduced here.

## Recommended Remaining Work

Before this branch should be considered complete, the following should happen:

1. Push the local follow-up commits so the branch on GitHub matches the working
   tree used for current analysis.
2. Re-check mergeability into `v3.0` after the latest follow-up is pushed.
3. Run end-to-end PostgreSQL cluster-sync validation in an environment with the
   required dependencies and replica topology available.
4. Get another maintainer review now that the branch has both feature work and
   refactoring work.

## Non-CI Merge Checklist

Use this list when finishing the branch, ignoring the unrelated CI breakage that
is being handled in parallel:

1. Push the local follow-up commits.
2. Confirm the branch merges cleanly into `v3.0`.
3. Verify PostgreSQL sync for:
   - `pgsql_users`
   - `pgsql_query_rules`
   - `pgsql_servers_v2`
   - `runtime_pgsql_servers`
   - `pgsql_variables`
4. Verify both `save_to_disk=true` and `save_to_disk=false` behaviors.
5. Verify `checksum_pgsql_variables=false` disables all PostgreSQL
   `*_diffs_before_sync` triggers.
6. Re-read the TAP test and Makefile diffs and confirm the branch still carries
   the intended local fixes after the final rebase or merge refresh.

## Bottom Line

This branch is no longer a partial experiment. It already contains the core
PostgreSQL cluster-sync implementation and a significant amount of review-driven
hardening. However, it is still not complete from a release or merge
perspective.

The right current description is:

- feature-complete in intent
- substantially implemented in code
- still unfinished operationally and procedurally

That is why it should be continued as a work-in-progress branch rather than
treated as closed work.
