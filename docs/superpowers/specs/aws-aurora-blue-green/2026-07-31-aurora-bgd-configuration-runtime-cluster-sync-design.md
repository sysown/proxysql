# Aurora BGD Configuration, Runtime Status, and Cluster Sync Design

**Date:** 2026-07-31

**Branch:** `spec/aws-aurora-bgd`

**Status:** Design approved

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

The columns provide staging hostgroups when configured. When both are NULL, the
existing global variable `mysql-aws_blue_green_deployment_auto_discovery`
controls whether the worker may start BGD discovery for the row.

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
Every Aurora row is user-created. There is no BGD mode or generated-row concept
in this table, so no `mode` or `auto_generated` column is present.

## 3. Green Hostgroup Configuration and BGD Admission

An active Aurora row behaves as follows:

| Green hostgroup columns | `mysql-aws_blue_green_deployment_auto_discovery` | Behavior |
|---|---:|---|
| Both non-NULL | `0` or `1` | BGD discovery is admitted |
| Both NULL | `1` | BGD discovery is admitted |
| Both NULL | `0` | Aurora monitoring without BGD discovery |
| Exactly one NULL | `0` or `1` | Invalid configuration |
| Any values with `active=0` | `0` or `1` | Neither normal Aurora nor BGD monitoring is active |

Changing `active` from `1` to `0` uses the worker-removal cleanup contract in
the monitor/FSM specification before the worker exits: remove every applied
pin, drain and purge affected production-hostname pools, restore safe writer
placement, release suspended monitoring, clear any terminal latch and retained
fingerprint, and publish `bgd_status=NONE`. The configuration and
`mysql_servers` rows remain user-owned and are not deleted by this cleanup.

### 3.1 Green hostgroups configured

When both green hostgroups are non-NULL:

- BGD monitoring is enabled independently of the global auto-discovery value.
- The target cluster writer is associated with `green_writer_hostgroup`.
- All target cluster readers are associated with `green_reader_hostgroup`.
- Target membership still comes from the target cluster's
  `REPLICA_HOST_STATUS`; configured green `mysql_servers` rows are not the
  membership source of truth.
- The green hostgroups provide optional user-visible staging/routing pools in
  addition to the internal BGD member map.

### 3.2 Green hostgroups not configured

When both green hostgroups are NULL and
`mysql-aws_blue_green_deployment_auto_discovery=true` at runtime:

- The existing Aurora monitor detects BGD topology for the row.
- The monitor discovers the target writer and all target readers through
  `REPLICA_HOST_STATUS`.
- The complete target member map and cached IPs remain internal.
- No green hostgroups or green `mysql_servers` rows are generated.
- Post-processing pinning covers the writer and every reader despite the green
  hostgroup columns being NULL.

This path does not use the writer-only fallback or reader shun/unshun policy
from the Multi-AZ instance implementation.

### 3.3 BGD disabled for the row

When both green hostgroups are NULL and
`mysql-aws_blue_green_deployment_auto_discovery=false`, the worker continues its
existing Aurora role and lag monitoring but does not start discovery of a new
BGD deployment.

Disabling global auto-discovery after a switchover has started must not abandon
that switchover. The worker completes pin cleanup and enters the terminal latch
before disabling discovery for the row. The variable gates the start of a new
BGD state machine, not safe completion of one already in progress.

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
5. Invalid rows use per-row isolation: each invalid row is excluded from runtime
   loading, while the valid rows from the same LOAD remain eligible to publish.
   The admin error identifies the rejected writer hostgroup, the conflicting
   fields and values, and the other writer hostgroup involved in a cross-row
   conflict.

Validation of the complete candidate result set must finish before publishing
the filtered valid result set. Valid rows publish together only after that
validation succeeds and atomically replace the prior runtime configuration. A
rejected row contributes no new fields; if it previously owned a runtime
worker, its absence from the replacement triggers the worker-removal cleanup
contract rather than applying a mixture of old and invalid fields.

## 5. Runtime Ownership

`AWS_Aurora_Info`, keyed by `writer_hostgroup`, remains the runtime owner of the
cluster configuration. It is extended with optional integer fields:

```text
green_writer_hostgroup = -1 when SQL NULL
green_reader_hostgroup = -1 when SQL NULL
```

The existing Aurora monitor worker remains one worker per active writer
hostgroup. The worker owns the BGD FSM and publishes each transition to the
runtime row's `bgd_status`. BGD admission and configured staging references are
determined from:

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

Configuration materialization and worker status publication use the same
Hostgroups Manager write-locked update path. Reload merges configured fields
into an existing writer-hostgroup row without writing its `bgd_status`; the
worker status API updates only `bgd_status` under that lock. A reload that began
from an older snapshot therefore cannot overwrite a transition published while
the reload is being applied.

## 6. LOAD Behavior

`LOAD MYSQL SERVERS TO RUNTIME` must:

1. Read both new columns from `mysql_aws_aurora_hostgroups`.
2. Preserve SQL NULL as the internal unset value rather than converting it to
   hostgroup `0`.
3. Validate paired NULL/non-NULL and hostgroup-conflict rules.
4. Update or create the `AWS_Aurora_Info` entry.
5. Include both fields in the Aurora monitor result set checksum.
6. Refresh the affected Aurora writer-hostgroup worker in place when either
   green hostgroup changes. Apply only configuration-derived fields and staging
   references; do not replace the worker-owned FSM object.
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
apply the refreshed staging configuration without restarting the BGD operation
from `NONE`.

`LOAD MYSQL VARIABLES TO RUNTIME` makes a change to
`mysql-aws_blue_green_deployment_auto_discovery` visible to Aurora monitor
workers.
The variable controls admission of new BGD operations for rows without green
hostgroups, as described in Section 3.3.

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
ordinary Aurora monitoring when BGD discovery is not admitted.

Examples:

Green hostgroups configured:

```sql
INSERT INTO mysql_aws_aurora_hostgroups (
    writer_hostgroup,
    reader_hostgroup,
    green_writer_hostgroup,
    green_reader_hostgroup,
    domain_name
) VALUES (10, 20, 11, 21, '.cluster-example.eu-north-1.rds.amazonaws.com');
```

Green hostgroups not configured:

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
`bgd_status` provides its runtime observability without introducing a BGD mode
into the configuration contract.

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

- with auto-discovery enabled, they are eligible for BGD discovery;
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
- require green `mysql_servers` rows when green hostgroups are not configured;
- add a second per-cluster monitor worker;
- add a separate `bgd_enabled` column;
- add a `mode` or `auto_generated` column;
- persist transient BGD FSM state to disk;
- alter the existing RDS Multi-AZ BGD configuration contract.

## 11. Required Configuration Tests

1. Both green hostgroups NULL load successfully.
2. Both green hostgroups non-NULL load successfully.
3. Mixed NULL/non-NULL values are rejected.
4. Duplicate or overlapping blue/green hostgroups are rejected.
5. A LOAD containing valid and invalid rows excludes each invalid row, reports
   its writer hostgroup and conflicting fields, and atomically publishes the
   filtered valid result set. A previously active rejected row follows the safe
   worker-removal cleanup path rather than receiving a partial update.
6. Configured green hostgroups admit BGD discovery with global auto-discovery
   disabled.
7. A row without green hostgroups starts BGD discovery only when global
   auto-discovery is enabled.
8. Disabling auto-discovery does not abort an active switchover.
9. Changing an active row to `active=0` removes pins, restores safe placement,
   clears the latch and fingerprint, publishes `NONE`, and stops the worker
   without deleting user configuration.
10. NULL values survive memory-to-runtime, runtime-to-memory, disk, config-file,
   and cluster synchronization round trips.
11. Online upgrade preserves existing rows and initializes both new fields to
   NULL.
12. Changing either green hostgroup refreshes only the affected Aurora worker
    in place.
13. Unrelated LOAD operations preserve active BGD pins and terminal-latch state.
14. A LOAD concurrent with an FSM transition cannot overwrite the newer
    `bgd_status`.
15. New runtime rows initialize `bgd_status` to `NONE`.
16. Runtime `bgd_status` follows every Aurora FSM transition.
17. `SWITCHOVER_COMPLETED` remains visible until topology drain and then changes
    to `NONE`.
18. Reloading an existing Aurora row preserves its `bgd_status` and active FSM
    state.
19. `SAVE MYSQL SERVERS FROM RUNTIME`, disk/config export, and ProxySQL Cluster
    synchronization exclude `bgd_status`.
20. ProxySQL Cluster peers retain their own node-local `bgd_status` values.
21. Existing Multi-AZ BGD configuration and tests remain unchanged.

## 12. Acceptance Criteria

The configuration/runtime integration is complete when:

1. Every Aurora configuration row is user-created, and its two green hostgroup
   columns are either both configured or both NULL.
2. Configured green hostgroups admit BGD discovery independently of the global
   variable; when both are NULL, the existing
   `mysql-aws_blue_green_deployment_auto_discovery` variable controls admission.
3. All load, save, disk, config-file, upgrade, and cluster-sync paths preserve
   the fields and their NULL values.
4. Exactly one Aurora monitor worker owns normal Aurora and BGD handling for a
   writer hostgroup.
5. No Aurora row is generated in `mysql_aws_rds_bgd_hostgroups`.
6. `runtime_mysql_aws_aurora_hostgroups.bgd_status` exposes the local Aurora BGD
   FSM state without being saved, exported, or cluster-synchronized.
