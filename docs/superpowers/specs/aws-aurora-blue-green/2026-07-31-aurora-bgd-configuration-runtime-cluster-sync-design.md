# Aurora BGD Configuration, Runtime Status, and Cluster Sync Design

**Date:** 2026-07-31

**Branch:** `plan/aurora-bgd`

**Status:** Design draft; configuration decisions locked

**Scope:** Configuration and runtime integration of Aurora MySQL blue/green
deployment handling with the existing `mysql_aws_aurora_hostgroups` subsystem.

**Related designs:**

- [Aurora BGD Monitor Loop and FSM](2026-07-31-aurora-bgd-monitor-fsm-design.md)
- [Aurora BGD Cluster Simulator and Testing](2026-07-31-aurora-bgd-cluster-simulator-testing-design.md)

## Spec Boundary

This specification owns the public configuration contract, the runtime-only
`bgd_status` contract, load/save and schema-upgrade behavior, and ProxySQL
Cluster synchronization. It treats the worker state machine as a consumer and
publisher through the interface defined here; membership discovery, routing
actions, and FSM internals belong to the monitor/FSM specification.

## 1. Decision Summary

Aurora blue/green handling is part of the existing Aurora monitor. It does not
require an entry in `mysql_aws_rds_bgd_hostgroups`.

Two nullable columns are added to `mysql_aws_aurora_hostgroups` and
`runtime_mysql_aws_aurora_hostgroups`:

```sql
green_writer_hostgroup INT DEFAULT NULL
green_reader_hostgroup INT DEFAULT NULL
```

The columns provide explicit staging hostgroups when configured. When both are
NULL, the existing global variable
`mysql-aws_blue_green_deployment_auto_discovery` controls automatic Aurora BGD
discovery.

No separate Aurora BGD enable column is added.

The runtime table adds one runtime-only observability column:

```sql
bgd_status VARCHAR NOT NULL DEFAULT 'NONE'
```

It reports the Aurora worker's local BGD FSM state. It is not configuration and
is excluded from persistence and ProxySQL Cluster synchronization.

## 2. Table Schema

The configuration table uses the following column order:

```text
writer_hostgroup
reader_hostgroup
green_writer_hostgroup
green_reader_hostgroup
active
aurora_port
domain_name
max_lag_ms
check_interval_ms
check_timeout_ms
writer_is_also_reader
new_reader_weight
add_lag_ms
min_lag_ms
lag_num_checks
autopurge_missing_checks
comment
```

The runtime table uses the same order and appends:

```text
bgd_status
```

The new column definitions are:

```sql
green_writer_hostgroup INT DEFAULT NULL
    CHECK (green_writer_hostgroup IS NULL OR green_writer_hostgroup >= 0),

green_reader_hostgroup INT DEFAULT NULL
    CHECK (green_reader_hostgroup IS NULL OR green_reader_hostgroup >= 0)
```

Both columns are nullable in the configuration and runtime tables. Their NULL
state is meaningful and must be preserved by every load, save, export, import,
and cluster-synchronization path.

The runtime table mirrors these configured fields and adds only `bgd_status`.
This design does not add an `auto_generated` column because the existing Aurora
row is the owner of both normal Aurora monitoring and BGD monitoring. It also
does not add a runtime `mode` column; effective mode remains derived from the
configured green hostgroups and the global auto-discovery variable.

## 3. Configuration Modes

The effective mode for an active Aurora row is determined as follows:

| Green hostgroup columns | `aws_blue_green_deployment_auto_discovery` | Effective behavior |
|---|---:|---|
| Both non-NULL | `0` or `1` | Explicit Aurora BGD monitoring |
| Both NULL | `1` | Automatic Aurora BGD monitoring |
| Both NULL | `0` | Aurora monitoring without BGD discovery |
| Exactly one NULL | `0` or `1` | Invalid configuration |
| Any values with `active=0` | `0` or `1` | Neither normal Aurora nor BGD monitoring is active |

### 3.1 Explicit mode

A row is in explicit mode when both green hostgroups are non-NULL.

In explicit mode:

- BGD monitoring is enabled independently of the global auto-discovery value.
- The target cluster writer is associated with `green_writer_hostgroup`.
- All target cluster readers are associated with `green_reader_hostgroup`.
- Target membership still comes from the target cluster's
  `REPLICA_HOST_STATUS`; configured green `mysql_servers` rows are not the
  membership source of truth.
- The green hostgroups provide optional user-visible staging/routing pools in
  addition to the internal BGD member map.

### 3.2 Automatic mode

A row is in automatic mode when both green hostgroups are NULL and
`mysql-aws_blue_green_deployment_auto_discovery=true` at runtime.

In automatic mode:

- The existing Aurora monitor detects BGD topology for the row.
- The monitor discovers the target writer and all target readers through
  `REPLICA_HOST_STATUS`.
- The complete target member map and cached IPs remain internal.
- No green hostgroups or green `mysql_servers` rows are generated.
- Post-processing pinning covers the writer and every reader despite the green
  hostgroup columns being NULL.

Automatic mode therefore does not use the writer-only fallback or reader
shun/unshun policy from the Multi-AZ instance implementation.

### 3.3 BGD disabled for the row

When both green hostgroups are NULL and
`mysql-aws_blue_green_deployment_auto_discovery=false`, the worker continues its
existing Aurora role and lag monitoring but does not start discovery of a new
BGD deployment.

Disabling global auto-discovery while an automatically discovered switchover is
already active must not abandon that switchover. The worker completes pin
cleanup and enters topology-drain wait before disabling discovery for the row.
The variable gates the start of new automatic BGD state machines, not safe
completion of one already in progress.

## 4. Validation Rules

For each `mysql_aws_aurora_hostgroups` row:

1. `green_writer_hostgroup` and `green_reader_hostgroup` must either both be
   NULL or both be non-NULL.
2. When non-NULL, all four hostgroups must be distinct:

   ```text
   writer_hostgroup
   reader_hostgroup
   green_writer_hostgroup
   green_reader_hostgroup
   ```

3. A hostgroup assigned to one Aurora row must not conflict with any blue or
   green role in another active Aurora row.
4. Existing writer-hostgroup primary-key and reader-hostgroup uniqueness rules
   remain in effect.
5. Invalid rows must be rejected or excluded from runtime loading with a clear
   admin error identifying the writer hostgroup and conflicting fields.

Validation must occur before publishing the new Aurora monitor resultset so a
bad row cannot partially reconfigure a running monitor worker.

## 5. Runtime Ownership

`AWS_Aurora_Info`, keyed by `writer_hostgroup`, remains the runtime owner of the
cluster configuration. It is extended with optional integer fields:

```text
green_writer_hostgroup = -1 when SQL NULL
green_reader_hostgroup = -1 when SQL NULL
```

The existing Aurora monitor worker remains one worker per active writer
hostgroup. The worker owns the BGD FSM and publishes each transition to the
runtime row's `bgd_status`. Its effective BGD mode is derived from:

```text
AWS_Aurora_Info.active
green_writer_hostgroup
green_reader_hostgroup
mysql_thread___aws_blue_green_deployment_auto_discovery
```

No Aurora configuration is copied into `mysql_aws_rds_bgd_hostgroups`, and no
second BGD worker is started for the same Aurora writer hostgroup.

Following RDS BGD, the Hostgroups Manager's internal Aurora table is the source
used to materialize `runtime_mysql_aws_aurora_hostgroups`. It stores the
configured fields plus `bgd_status`. Its runtime dump includes all of those
fields; paths that write back to configuration explicitly project away
`bgd_status`.

## 6. LOAD Behavior

`LOAD MYSQL SERVERS TO RUNTIME` must:

1. Read both new columns from `mysql_aws_aurora_hostgroups`.
2. Preserve SQL NULL as the internal unset value rather than converting it to
   hostgroup `0`.
3. Validate paired NULL/non-NULL and hostgroup-conflict rules.
4. Update or create the `AWS_Aurora_Info` entry.
5. Include both fields in the Aurora monitor resultset checksum.
6. Restart/refresh only the affected Aurora writer-hostgroup worker when either
   green hostgroup changes.
7. Preserve an active BGD FSM safely across an unrelated configuration refresh.
8. Initialize `bgd_status` to `NONE` for a newly published runtime row.
9. Preserve the existing `bgd_status` when merging an existing
   writer-hostgroup runtime row, following the RDS BGD table-reload behavior.
   The Aurora worker separately preserves the underlying FSM state required by
   the monitor/FSM specification.
10. Remove `bgd_status` with a removed runtime row; active-operation teardown
    follows the existing RDS BGD worker-removal cleanup pattern.

Changing the green hostgroups during an active switchover must not lose cached
member identities, applied DNS pins, or completion-latch state. The worker must
apply the refreshed explicit staging configuration without restarting the BGD
operation from `NONE`.

`LOAD MYSQL VARIABLES TO RUNTIME` makes a change to
`aws_blue_green_deployment_auto_discovery` visible to Aurora monitor workers.
The variable controls admission of new automatic BGD operations as described in
Section 3.3.

## 7. Runtime Table Behavior

`runtime_mysql_aws_aurora_hostgroups` exposes both new columns in the same
positions as the configuration table and appends the runtime-only
`bgd_status` column.

`bgd_status` exposes the internal Aurora BGD FSM state, not merely the last raw
AWS status string. Its values are:

```text
NONE
AVAILABLE
SWITCHOVER_INITIATED
SWITCHOVER_IN_PROGRESS
SWITCHOVER_IN_POST_PROCESSING
SWITCHOVER_COMPLETED
```

The worker updates this column as its FSM changes, following the existing RDS
BGD runtime-status mechanism wherever applicable. `SWITCHOVER_COMPLETED` is the
terminal rearm latch: all routing cleanup has already completed, and the status
remains visible until `mysql.rds_topology` drains. A successful empty/absent
topology result then changes it to `NONE`. Query or connection errors while
latched do not reset the status or repeat cleanup.

An Aurora row that is not handling a BGD deployment reports `NONE`, including
ordinary Aurora monitoring when automatic discovery is disabled.

Examples:

Explicit mode:

```sql
INSERT INTO mysql_aws_aurora_hostgroups (
    writer_hostgroup,
    reader_hostgroup,
    green_writer_hostgroup,
    green_reader_hostgroup,
    domain_name
) VALUES (10, 20, 11, 21, '.cluster-example.eu-north-1.rds.amazonaws.com');
```

Automatic mode:

```sql
INSERT INTO mysql_aws_aurora_hostgroups (
    writer_hostgroup,
    reader_hostgroup,
    green_writer_hostgroup,
    green_reader_hostgroup,
    domain_name
) VALUES (10, 20, NULL, NULL, '.cluster-example.eu-north-1.rds.amazonaws.com');

SET mysql-aws_blue_green_deployment_auto_discovery = 'true';
```

The BGD FSM state is operational monitor state, not user configuration.
`bgd_status` provides its runtime observability without changing the
explicit/automatic mode contract defined here.

## 8. Persistence and Synchronization

Both green hostgroup columns must be supported by:

- admin-memory table creation;
- runtime table creation;
- disk database schema and online upgrade;
- `LOAD MYSQL SERVERS TO RUNTIME`;
- `SAVE MYSQL SERVERS FROM RUNTIME`;
- `SAVE MYSQL SERVERS TO DISK`;
- ProxySQL configuration-file import and export;
- ProxySQL Cluster fetch, insert, checksum, and conflict handling;
- `dump_table_mysql("mysql_aws_aurora_hostgroups")`;
- test/bootstrap table definitions.

ProxySQL Cluster synchronization must include the two configured values. NULL
must remain NULL on the receiving peer.

Every configuration-bearing path must use an explicit configured-column
projection rather than `SELECT *`. In particular:

- `SAVE MYSQL SERVERS FROM RUNTIME` copies the configured Aurora columns and
  excludes `bgd_status`;
- the ProxySQL Cluster fetch/query, checksum, and insert paths include the two
  green hostgroups and exclude `bgd_status`;
- disk saves and configuration-file export never persist `bgd_status`.

BGD's `bgd_status`, transient member map, cached IPs, and pins are node-local
runtime state and are not cluster-synced as configuration.

## 9. Schema Upgrade

A new Aurora hostgroups schema version must add the two nullable columns while
preserving every existing row and column value.

Existing rows are migrated with:

```text
green_writer_hostgroup = NULL
green_reader_hostgroup = NULL
```

After upgrade, existing active Aurora rows follow the global variable:

- with auto-discovery enabled, they are eligible for automatic BGD discovery;
- with auto-discovery disabled, they retain existing Aurora monitoring only.

This is backward-compatible at the table-data level because no green
hostgroups are invented during migration.

`bgd_status` requires no disk-schema migration because it exists only in the
runtime table. The runtime table is created with the new column, and every row
starts at `NONE` until its local Aurora worker publishes another state.

## 10. Non-Goals of This Configuration Change

This configuration design does not:

- add an Aurora-specific configuration table;
- create Aurora rows in `mysql_aws_rds_bgd_hostgroups`;
- require explicit green `mysql_servers` rows in automatic mode;
- add a second per-cluster monitor worker;
- add a separate `bgd_enabled` column;
- add a runtime `mode` or `auto_generated` column;
- persist transient BGD FSM state to disk;
- alter the existing RDS Multi-AZ BGD configuration contract.

## 11. Required Configuration Tests

1. Both green hostgroups NULL load successfully.
2. Both green hostgroups non-NULL load successfully.
3. Mixed NULL/non-NULL values are rejected.
4. Duplicate or overlapping blue/green hostgroups are rejected.
5. Explicit mode operates with global auto-discovery disabled.
6. Automatic mode starts only when global auto-discovery is enabled.
7. Disabling auto-discovery does not abort an active automatic switchover.
8. NULL values survive memory-to-runtime, runtime-to-memory, disk, config-file,
   and cluster synchronization round trips.
9. Online upgrade preserves existing rows and initializes both new fields to
   NULL.
10. Changing either green hostgroup refreshes only the affected Aurora worker.
11. Unrelated LOAD operations preserve active BGD pins and terminal-latch state.
12. New runtime rows initialize `bgd_status` to `NONE`.
13. Runtime `bgd_status` follows every Aurora FSM transition.
14. `SWITCHOVER_COMPLETED` remains visible until topology drain and then changes
    to `NONE`.
15. Reloading an existing Aurora row preserves its `bgd_status` and active FSM
    state.
16. `SAVE MYSQL SERVERS FROM RUNTIME`, disk/config export, and ProxySQL Cluster
    synchronization exclude `bgd_status`.
17. ProxySQL Cluster peers retain their own node-local `bgd_status` values.
18. Existing Multi-AZ BGD configuration and tests remain unchanged.

## 12. Acceptance Criteria

The configuration/runtime integration is complete when:

1. Aurora BGD explicit mode is configured solely by the two green hostgroup
   columns on `mysql_aws_aurora_hostgroups`.
2. Aurora BGD automatic mode is controlled by the existing
   `aws_blue_green_deployment_auto_discovery` variable when both columns are
   NULL.
3. All load, save, disk, config-file, upgrade, and cluster-sync paths preserve
   the fields and their NULL values.
4. Exactly one Aurora monitor worker owns normal Aurora and BGD handling for a
   writer hostgroup.
5. No Aurora automatic-discovery row is generated in
   `mysql_aws_rds_bgd_hostgroups`.
6. `runtime_mysql_aws_aurora_hostgroups.bgd_status` exposes the local Aurora BGD
   FSM state without being saved, exported, or cluster-synchronized.
