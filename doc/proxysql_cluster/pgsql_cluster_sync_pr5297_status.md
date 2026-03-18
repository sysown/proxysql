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
- The local branch contains one additional unpushed follow-up commit,
  `bf9fc81f4` (`test: strengthen pgsql cluster sync TAP follow-up`).

This means the branch is functionally substantial, but it is not yet in a clean
and finished state for merge.

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
- the last visible CI run on 2026-02-23 still had failures:
  - `CI-repltests / tests (mysql57)`
  - `CI-shuntest / tests (mysql57)`
  - `SonarCloud Code Analysis`
- the local follow-up commits that improve mergeability and TAP validation have
  not yet been pushed

Separately, local validation in this workspace is limited by missing vendored
dependencies, so not every verification step can be reproduced here.

## Recommended Remaining Work

Before this branch should be considered complete, the following should happen:

1. Push the local follow-up commits so the branch on GitHub matches the working
   tree used for current analysis.
2. Re-check mergeability into `v3.0` after the latest follow-up is pushed.
3. Investigate the failing CI jobs and determine whether they are unrelated
   legacy failures or branch regressions.
4. Run end-to-end PostgreSQL cluster-sync validation in an environment with the
   required dependencies and replica topology available.
5. Get another maintainer review now that the branch has both feature work and
   refactoring work.

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
