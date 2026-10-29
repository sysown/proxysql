# AWS RDS Blue/Green Monitor

**Document status:** FEATURE CONTRACT; IMPLEMENTED

**Applies to:** Amazon RDS Multi-AZ DB instance blue/green deployment
monitoring

**Primary implementation:** `include/MySQL_Monitor.hpp` and
`lib/MySQL_Monitor.cpp`

**Simulator specification:** [RDS_BGD_Simulator.md](RDS_BGD_Simulator.md)

## Purpose And Scope

This document defines the operational contract for ProxySQL monitoring of
Amazon RDS Multi-AZ DB instance blue/green deployments. It describes the AWS
topology observations consumed by the monitor, the resulting ProxySQL state
transitions and external effects, configuration and worker lifetime,
connection-retirement and cleanup semantics, and the verification surface for
the feature introduced by
[PR #5861](https://github.com/sysown/proxysql/pull/5861).

The contract distinguishes among behavior defined by AWS, behavior observed in
a bounded deployment trace, intentional ProxySQL policy, and implementation
mechanics. A scoped observation is not promoted to a universal AWS guarantee,
and a ProxySQL policy is not presented as an AWS property.

The monitor contract covers:

- Detection of blue/green topology through `mysql.rds_topology`.
- Interpretation of source and target roles and switchover statuses.
- Mapping of configured blue writer and reader servers to green servers.
- Green address resolution and direct topology probing.
- Writer and reader switchover handling.
- DNS pinning, hostgroup placement, reader shunning, and connection draining.
- Successful completion, cancellation rollback, and topology disappearance.
- Explicit and automatic green-hostgroup configuration.
- In-place configuration refresh, worker detach and recreation, and process
  restart.
- The simulator, TAP, unit-test, and CI surface used to verify the contract.
- Documented configuration limitations and administrator responsibilities.

This document does not define:

- Amazon Aurora, Group Replication, Galera, or PostgreSQL monitoring.
- RDS behavior that is not consumed by this monitor.
- A durable effect ledger or a replacement controller architecture.
- Persistence of in-progress BGD state across a ProxySQL process restart.
- Detailed simulator implementation, which is specified in
  [RDS_BGD_Simulator.md](RDS_BGD_Simulator.md).

## Contract Basis

The external behavior in this contract is based on:

- An
  [AWS-provided RDS topology metadata document](https://github.com/user-attachments/files/30019110/RDS_Topology_metadata.md)
  describing `mysql.rds_topology`, roles, statuses, switchover stages, traffic
  availability, and polling guidance.
- A
  [timestamped topology trace](https://github.com/user-attachments/files/30019175/aws-rds-topology-watch.txt)
  from one complete switchover, sampled at approximately 250 ms.
- A separately observed cancellation and operational observations supplied by
  the feature author.
- The source implementation and tests referenced in this document.

The captured deployment used RDS MySQL 8.4.x, a Multi-AZ DB instance with two
read replicas, and `eu-north-1`. Timing and row-lifecycle statements derived
only from this trace apply to that observation. They do not establish fixed
timing or universal AWS behavior.

The following language identifies the authority for a statement:

| Wording | Meaning |
|---|---|
| **AWS defines** | The AWS-provided metadata document specifies the behavior. |
| **The supplied trace observed** | The behavior occurred in the bounded trace described above. |
| **The author observed** | The feature author supplied an operational observation outside that trace. |
| **ProxySQL policy** | The behavior is an intentional product decision, including a decision made where AWS does not provide a stronger guarantee. |
| **The implementation** | The statement describes the source behavior on the feature branch. |

## Terminology

| Term | Meaning |
|---|---|
| Blue | The source deployment before switchover. |
| Green | The target deployment before switchover. |
| Topology observation | The result of one `mysql.rds_topology` existence check or metadata query. |
| Blue/green pair | A configured blue server and its name-matched green counterpart, together with the connection attributes needed by the monitor. |
| Direct probe | A topology query sent to the resolved green writer IP rather than to a configured blue hostname. |
| Topology drain | A successful metadata query returning no rows, or the topology table becoming unavailable. |
| Rollback cleanup | One-shot cleanup invoked for topology drain outside the reader phase, a recognized backward transition, configuration refresh at or after post-processing, or worker exit from any active phase. |
| Successful cleanup | One-shot cleanup selected when topology drains after the monitor has observed writer completion. |
| Configuration refresh | An in-place update of a running worker after its deployment checksum changes. |
| Worker detach | Termination of a worker because the deployment is disabled, removed, or no longer has an eligible blue writer. |

## Configuration Model

Each active deployment identifies a blue writer hostgroup and a blue reader
hostgroup. It also carries `writer_is_also_reader`, a baseline check interval,
and a check timeout. One worker owns the monitor state for one blue writer
hostgroup.

Green hostgroup nullability depends on the origin of the row. It is not a
user-selectable mixed configuration:

| Row origin and storage | Green writer hostgroup | Green reader hostgroup | Semantics |
|---|---|---|---|
| User row in persistent Admin configuration | Required | Required | Explicit green-hostgroup mode. The persistent table declares both columns `NOT NULL`. |
| User row materialized into runtime/HGM | Value | Value | The configured values are retained with `auto_generated=0`. |
| Runtime row created by automatic discovery | `NULL` | `NULL` | Automatic mode. The row carries `auto_generated=1` and exists only in runtime/HGM state. |
| User row with one or both values missing | Invalid | Invalid | A user cannot select automatic handling for only one green role. |

The runtime Admin and Hostgroup Manager schemas permit nullable green
hostgroups so that they can represent automatically generated rows. This
runtime representation does not make a `NULL` green hostgroup valid in the
persistent user table.

Saving runtime BGD configuration to the persistent Admin table skips every row
whose runtime `auto_generated` value is nonzero. An automatically generated row
with two `NULL` green hostgroups is therefore never inserted into the
persistent `NOT NULL` columns. User rows contain both values and are saved
normally.

`OFFLINE_SOFT` and `OFFLINE_HARD` servers are not eligible for blue/green
mapping or for connection-drain actions. An explicit green writer in either
offline state is not selected as the active green endpoint.

## AWS Topology

### Topology Recognition

`parse_aws_rds_topology()` classifies a result as blue/green topology from the
first fetched row. The result is classified as blue/green when the `role` and
`status` columns exist and both first-row cells are non-`NULL`. Empty strings
still satisfy this non-`NULL` test. Later rows do not change the initial
classification.

AWS defines the following blue/green role values:

```text
BLUE_GREEN_DEPLOYMENT_SOURCE
BLUE_GREEN_DEPLOYMENT_TARGET
```

AWS defines the following target status values:

```text
AVAILABLE
SWITCHOVER_INITIATED
SWITCHOVER_IN_PROGRESS
SWITCHOVER_IN_POST_PROCESSING
SWITCHOVER_COMPLETED
```

If the query returns no rows, either column is absent, or either first-row cell
is `NULL`, `blue_green` remains false. The parser is shared with the Multi-AZ
Cluster discovery path, so other RDS topology shapes may be handled outside the
BGD state machine.

### Observed Lifecycle

The supplied trace observed this row and status sequence:

```text
Two rows:
  SOURCE = blue
  TARGET = green
  status = AVAILABLE

Two rows:
  repeated SWITCHOVER_INITIATED observations
    -> repeated SWITCHOVER_IN_PROGRESS observations
    -> repeated SWITCHOVER_IN_POST_PROCESSING observations

One row:
  TARGET = green
  repeated SWITCHOVER_COMPLETED observations

Zero rows:
  observed approximately 44 seconds after SWITCHOVER_COMPLETED
```

Both rows carried the same status while both were present in the supplied
trace. The trace establishes that this occurred in the captured deployment; it
does not establish source/target status equality as a universal AWS guarantee.

The trace also observed monotonic forward transitions and repeated observations
within each phase. At `SWITCHOVER_COMPLETED`, the source row disappeared and
the target row remained for approximately 44 seconds before the table became
empty. The 44-second duration is not fixed. The table remained present in
`information_schema`; the trace did not observe `ER_NO_SUCH_TABLE`.

### AWS Completion And Cancellation Boundaries

AWS defines `SWITCHOVER_COMPLETED` as completion of writer DNS propagation: the
original source endpoint points to the promoted target.

AWS permits cancellation during `SWITCHOVER_INITIATED` and
`SWITCHOVER_IN_PROGRESS`. Rollback is no longer allowed after the deployment
enters `SWITCHOVER_IN_POST_PROCESSING`. The author separately observed a
cancellation returning the deployment to `AVAILABLE`.

The author observed that the green hostname stopped resolving after completion
while the promoted IP remained reachable. The monitor consequently retains a
complete direct-probe target while direct probing is required rather than
depending on the continued resolvability of the green hostname.

### Reader-Completion Policy

The metadata table describes writer topology; it does not expose a reader
switchover status. The supplied trace did not measure reader DNS propagation
directly. The author observed reader errors before the table drained and normal
reader behavior afterward.

ProxySQL therefore uses the following explicit policy:

- `SWITCHOVER_COMPLETED` is the writer-completion signal.
- A topology drain after writer completion is the reader-cleanup signal.
- A topology drain before writer completion is a cancellation or rollback
  signal.

Using topology drain as the reader-cleanup signal is an accepted operational
correlation. It is not an AWS guarantee that an empty topology result proves
reader DNS propagation.

### Topology Outcomes

The worker distinguishes the following query outcomes:

| Outcome | Detection | Monitor behavior |
|---|---|---|
| Table absent | The existence query returns no rows. | Apply phase-specific topology-drain handling. |
| Table vanished | A metadata query returns `ER_NO_SUCH_TABLE`. | Reset the query state to the table check, restore the baseline interval, and apply phase-specific topology-drain handling. |
| Table empty | A successful metadata query returns no rows. | Apply phase-specific topology-drain handling. |
| Metadata available | A successful metadata query returns rows. | Parse and pass the topology to the BGD state machine. |
| Query failure | The connection, timeout, existence query, or metadata query fails for another reason. | Log the error and retain the state for a later poll. A generic query failure is not a completion or cancellation signal. |

Table absence and an empty table remain diagnostically distinct. ProxySQL
intentionally applies the same phase boundary to both because only the empty
table was present in the supplied lifecycle trace.

## Monitor Architecture

### Worker And Polling Model

The dispatcher creates one BGD worker for each active deployment that has an
eligible blue writer. The worker keeps its state on its own stack and performs
the following polling cycle:

```text
check whether mysql.rds_topology exists
  -> fetch topology metadata
  -> classify the observation
  -> update the deployment state machine
  -> apply phase actions
  -> wait for the effective check interval
```

After the table has been observed, the worker normally continues with metadata
fetches. `ER_NO_SUCH_TABLE` returns it to the table-existence check.

The configured check interval is the baseline. The state machine uses 250 ms
while the deployment is `AVAILABLE` and 100 ms during the active writer
switchover phases. It returns to the configured baseline after writer
completion or state cleanup.

### Blue/Green Mapping

The worker builds a `bg_map` from current runtime configuration and the
discovered topology:

- The blue writer is matched to the target writer using the RDS green-hostname
  naming relationship.
- In explicit mode, eligible configured green readers are name-matched to blue
  readers.
- The topology contains writer endpoints only, so complete reader mapping is
  not assumed.
- Blue readers without a mapped green counterpart are handled independently
  and may be shunned during post-processing.
- `OFFLINE_SOFT` and `OFFLINE_HARD` servers do not participate.

Each pair retains the blue hostname and connection attributes, the green
hostname, the resolved green IP and its expiry, and whether DNS pinning and
connection draining have already completed for that pair.

### Direct-Probe Tuple

The direct green-writer probe always uses one coherent host, port, and TLS
tuple derived from the matched writer pair:

| Mode | Host or IP | Port | TLS |
|---|---|---|---|
| Automatic | Resolved IP of the target endpoint from `mysql.rds_topology`. | Configured port of the matched blue writer. | `use_ssl` from the matched blue writer. |
| Explicit | Resolved IP of the exact configured target writer. | Configured port of the matched blue writer. | `use_ssl` from the exact eligible green writer row. |

The monitor does not consume or validate the target topology row's port.
Source/target pairs that use different ports are unsupported. This is a
ProxySQL constraint, not an AWS guarantee that the ports are always equal.
Different configured pairs may use different ports.

Automatic mode has no independent green `mysql_servers` row from which to
derive TLS configuration, so it uses the matched blue writer's value.

Explicit mode selects the green writer by exact target hostname and the
matched-blue port. It copies `use_ssl` from an existing eligible row. If
discovery creates a missing row or restores an `OFFLINE_HARD` row, the
successful add path obtains `use_ssl` from the resulting exact row after
hostgroup defaults are applied. An `OFFLINE_SOFT` row remains ineligible.

### Direct-Probe Lifetime

The worker resolves each eligible green endpoint through the DNS cache or a
live DNS lookup. Once the green writer IP is available, the worker directs
subsequent topology polls to that IP. This keeps the observation path available
through the source connectivity gap and the retirement of the green DNS name.

The worker retries unresolved pairs on every eligible equal-phase observation
from `AVAILABLE` through `WRITER_SWITCHOVER_POST_PROCESSING`. During repeated
post-processing observations, it pins and drains only pairs whose green IP is
available and whose `green_ip_pinned` flag is false. A completed pair is not
drained again during that worker lifetime; unresolved pairs remain eligible
for a later retry.

If three consecutive topology polls to the direct green IP fail, the worker
clears the direct target, removes its mapped blue DNS pins, purges the
corresponding monitor connections, and falls back to polling through the blue
configuration.

## ProxySQL State Machine

The monitor uses the following ordered states:

```text
NONE
  -> AVAILABLE
  -> WRITER_SWITCHOVER_INITIATED
  -> WRITER_SWITCHOVER_IN_PROGRESS
  -> WRITER_SWITCHOVER_POST_PROCESSING
  -> WRITER_SWITCHOVER_COMPLETED
  -> READER_SWITCHOVER_IN_PROGRESS
  -> SWITCHOVER_COMPLETED
  -> NONE
```

The five states from `AVAILABLE` through
`WRITER_SWITCHOVER_COMPLETED` correspond to AWS target statuses.
`READER_SWITCHOVER_IN_PROGRESS` and `SWITCHOVER_COMPLETED` are ProxySQL states:

- `READER_SWITCHOVER_IN_PROGRESS` records that writer completion has been
  observed and defers reader cleanup until topology drains.
- `SWITCHOVER_COMPLETED` is a short-lived successful-cleanup state before the
  worker returns to `NONE`.

The arrows show nominal lifecycle order, not mandatory predecessor edges.
Forward transitions may skip states. A worker that first observes
`SWITCHOVER_IN_POST_PROCESSING`, for example, builds the required mapping and
performs post-processing setup directly.

### Phase Actions

| State or observation | Action |
|---|---|
| `AVAILABLE` | Set the next-check interval to 250 ms, build the blue/green map, resolve green IPs, and optionally add the green writer to its configured hostgroup. |
| `WRITER_SWITCHOVER_INITIATED` | Set the interval to 100 ms, rebuild the map, resolve green IPs, optionally add the green writer, and suppress ordinary read-only monitoring for the deployment servers. |
| `WRITER_SWITCHOVER_IN_PROGRESS` | Perform initiated-phase setup, sustain read-only suppression, and demote the mapped blue writer to read-only. |
| `WRITER_SWITCHOVER_POST_PROCESSING` | Perform setup even after late entry, sustain read-only suppression, pin mapped blue names to resolved green IPs, retire matching connections, configure writer placement, and shun unmapped blue readers. |
| `WRITER_SWITCHOVER_COMPLETED` | Advance immediately to `READER_SWITCHOVER_IN_PROGRESS`, remove the writer DNS-cache entry, retain mapped reader pins, and restore the baseline check interval. |
| Topology drain in `READER_SWITCHOVER_IN_PROGRESS` | Run successful cleanup, transition briefly through `SWITCHOVER_COMPLETED`, and return to `NONE`. |
| Topology drain in another active state | Run rollback cleanup and return to `NONE`. |
| Worker exit in an active state | Run rollback cleanup before discarding worker-local state. |

### Equal And Repeated Phases

When the converted target status equals the stored state, the worker does not
rebuild the configuration-derived map or repeat the complete phase action.
It performs only the eligible same-phase reconciliation:

- Retry unresolved green IPs from `AVAILABLE` through post-processing.
- During post-processing, pin and drain newly resolved pairs once.
- Ignore repeated raw `SWITCHOVER_COMPLETED` observations after the local state
  has advanced to `READER_SWITCHOVER_IN_PROGRESS`.

### Backward And Unrecognized Phases

A recognized target status whose enum value is lower than the stored state is a
backward transition. The worker runs rollback cleanup. If the new status is
`AVAILABLE`, it then re-enters `AVAILABLE`, restores the 250 ms interval, and
rebuilds mapping, resolution, and optional green-writer placement. Other
backward statuses leave the worker in `NONE`.

An unknown nonempty target status maps to `NONE`. From an active higher state,
that value follows the backward-transition path and invokes rollback. An empty
target status, a missing target row, or a topology result not classified as
blue/green sets the phase to `NONE` and resets the interval without calling the
rollback helper. The latter path does not perform the rollback helper's map,
DNS, connection, or reader cleanup.

## Switchover Effects

### DNS Pinning And Reader Handling

During writer post-processing, ProxySQL pins each mapped blue hostname to the
resolved green IP and retires existing connections for that blue endpoint.
New connections through the stable blue hostname then reach the green
instance.

The metadata topology does not provide a complete reader mapping. During
post-processing, ProxySQL identifies eligible blue readers with no mapped
green counterpart and marks them `SHUNNED_AWS_BGD`. If shunning all blue
readers would leave the reader hostgroup empty, the worker temporarily makes
the writer available to the reader hostgroup. Final cleanup restores placement
according to `writer_is_also_reader` and unshuns the readers recorded by that
worker.

After writer completion, the writer DNS-cache entry is removed immediately so
normal DNS resolution can resume for the stable writer name. Reader pins remain
until the topology drains and successful cleanup runs.

### Connection Retirement

`MySrvConnList::mark_connections_unhealthy()` deletes matching free
connections immediately. It marks matching used connections with
`healthy=false` and `reusable=false`; those connections finish their current
ownership and are destroyed when released.

The retirement state flow is:

```text
ACTIVE_BACKEND
  healthy=true, reusable=true
        |
        | BGD drain selects a used connection
        v
RETIRE_ON_RELEASE
  healthy=false, reusable=false
        |
        | optional connection or session reset
        | healthy remains false
        v
POOL_RETURN
        |
        +--> push_MyConn_local: unhealthy -> global destruction path
        |
        `--> push_MyConn_to_pool: unhealthy -> delete

No transition returns RETIRE_ON_RELEASE to a local or global free pool.
```

`MySQL_Connection::reset()` resets session state without restoring
`healthy=true`. `MySQL_Thread::push_MyConn_local()` rejects an unhealthy
connection before adding it to the thread-local cache.
`MySQL_HostGroups_Manager::push_MyConn_to_pool()` removes the connection from
the used list and destroys it before any free-pool insertion. Array pool return
is covered because reusable entries delegate to the same global return path,
while the existing non-reusable branch destroys the connection directly.

These paths read `healthy` using ProxySQL's existing unlocked
connection-field convention. The feature accepts that project-level race model
and does not introduce a separate retirement flag or a broader locking policy.

## Completion And Rollback

### Phase Selection

`aws_rds_bgd_handle_topology_absent()` selects cleanup from the last monitor
state:

```text
topology drains
  |
  +--> state is READER_SWITCHOVER_IN_PROGRESS
  |      -> successful cleanup
  |
  +--> state is another non-NONE state
  |      -> rollback cleanup
  |
  `--> state is NONE
         -> no cleanup
```

The same rollback helper also runs for a recognized backward phase and for
worker exit from an active state.

### Rollback Cleanup

Rollback performs the following one-shot actions:

- Restore a blue writer demoted during
  `WRITER_SWITCHOVER_IN_PROGRESS` or
  `WRITER_SWITCHOVER_POST_PROCESSING`.
- Reconcile writer membership in the reader hostgroup according to
  `writer_is_also_reader`.
- Unshun readers recorded by the worker.
- Remove DNS-cache entries and purge monitor-pool connections for recorded
  shunned readers and mapped blue endpoints.
- Purge direct-probe monitor connections keyed by resolved green IPs.
- Clear worker mapping, probe, interval, and phase bookkeeping.
- Invoke read-only suppression cleanup and return to `NONE`.

Rollback intentionally does not:

- Drain application connections in configured green hostgroups.
- Remove green DNS entries.
- Change green server status.
- Remove user-configured or automatically added green rows.

Purging a direct-probe monitor connection keyed by a green IP cleans up the
monitor's observation channel. It is not equivalent to draining application
connections from a green hostgroup.

### Successful Cleanup

Successful cleanup does not restore the obsolete blue writer. It reconciles
writer membership in the reader hostgroup according to
`writer_is_also_reader`, unshuns the readers recorded by the worker, removes
mapped and recorded-reader DNS entries, purges the corresponding monitor-pool
connections, invokes read-only suppression cleanup, and clears worker
bookkeeping. It also drains application connections for every eligible server
in the configured green writer and reader hostgroups and removes those green
hostnames from the DNS and monitor connection caches.

`OFFLINE_SOFT` and `OFFLINE_HARD` green servers are excluded from that drain.
Successful cleanup leaves every green server row and status unchanged.
Green-hostgroup membership remains runtime configuration until an
administrator removes it, including membership added automatically by the BGD
monitor.

### One-Shot Cleanup Policy

Cleanup is best effort and one shot. The worker does not maintain a per-effect
completion ledger, does not verify every external postcondition, and clears its
local state after invoking the cleanup operations.

This is an intentional ProxySQL policy. Process termination or an individual
operation failure can prevent the monitor from proving that every action
completed. The feature does not require a retained cleanup executor or durable
effect ownership.

The final interval depends on the caller:

- `ER_NO_SUCH_TABLE` restores the baseline interval before cleanup.
- Successful and rollback cleanup reset the interval.
- Topology absence observed while already in `NONE` performs no cleanup and
  does not independently reset an existing interval override.

## Worker And Configuration Lifetime

### Deployment Checksum

The dispatcher calculates a per-deployment checksum from the active BGD row and
eligible blue and green runtime server rows. An Admin `mysql_servers` commit
refreshes that checksum.

A checksum change for an active deployment signals the existing worker through
`AWS_RDS_BGD_Worker::current_checksum`. The worker captures a consistent
candidate configuration and applies it in place. A checksum change alone does
not stop, join, or replace the worker thread.

The checksum is a configuration-generation signal. It is not an effect ledger
and is not the mechanism used to retry transient DNS resolution. Runtime
publishes initiated by the BGD worker do not refresh the checksum, preventing
the worker's own hostgroup actions from triggering a configuration refresh.

### In-Place Refresh

Refresh behavior depends on the phase:

1. Before `WRITER_SWITCHOVER_POST_PROCESSING`, the worker preserves its phase,
   applies the candidate scalar and hostgroup configuration, clears the direct
   probe and failure counter, and marks the map for reconstruction. The next
   topology result rebuilds configuration-derived state.
2. If the reader hostgroup changes while read-only suppression is active, the
   worker clears suppression for the old hostgroup and enables it for the new
   hostgroup.
3. During `WRITER_SWITCHOVER_IN_PROGRESS`, map reconstruction restores a
   replaced old writer and demotes the newly mapped writer.
4. At or after `WRITER_SWITCHOVER_POST_PROCESSING`, replacing only the map
   cannot safely reconcile existing DNS pins, reader shuns, monitor
   connections, and placement. The same worker runs one-shot rollback, applies
   the candidate configuration, resets topology polling to the table check,
   and restarts the state machine from `NONE`.

The fourth case is rollback and state-machine restart within the same worker,
not worker replacement.

### Worker Detach And Recreation

If a deployment is disabled, removed, or loses its eligible blue writer, the
dispatcher requests worker stop. A worker exiting from a non-`NONE` state runs
one-shot rollback before discarding its local map, reader list, probe target,
and phase.

If configuration later makes the deployment eligible again, the dispatcher
creates a new worker with fresh state. A fresh worker does not recover the
prior worker's effects or cleanup results. If its first observation is
`SWITCHOVER_COMPLETED`, it enters `READER_SWITCHOVER_IN_PROGRESS` without
reconstructing a prior map and waits for topology drain.

### Process Restart

A full ProxySQL process restart is a fresh start:

- Worker state, blue/green maps, direct-probe targets, suppression state, and
  cleanup bookkeeping are recreated empty.
- DNS cache and connection pools are recreated.
- Runtime placement and status are rebuilt from administrator configuration.
- User-configured BGD and server rows reload through the normal configuration
  path.
- An automatically added runtime-only green row disappears unless it was
  independently configured or synchronized into another restart input.

No durable BGD progress or effect-ownership state is recovered. A
simulator-driven full process-restart fixture is not required by this contract.

## Read-Only Suppression

BGD suppresses ordinary read-only monitoring while it intentionally changes
writer and reader placement. Suppression is keyed by
`hostname:::port` in the shared `aws_rds_bgd_server_status` map.

The required lifetime is:

```text
UNSUPPRESSED
  |
  | BGD enters INITIATED, IN_PROGRESS, or POST_PROCESSING
  | record every endpoint key owned by this deployment
  v
SUPPRESSED
  |
  +--> new read-only work for an owned key is not admitted
  |
  +--> an earlier result revalidates suppression before applying placement
  |
  | BGD returns to NONE or changes configuration
  v
OWNED_KEYS_REMOVED
  |
  `--> other deployments' keys remain unchanged
```

Suppression ownership is deployment-specific. Cleanup must erase the exact keys
inserted for that deployment even if the corresponding server has already been
removed from its current hostgroup. Concurrent deployments using distinct
endpoints must not clear each other's keys.

Each server endpoint must belong to only one active blue/green deployment.
Administrators are responsible for avoiding overlapping endpoint assignments;
the monitor does not validate or protect against this unsupported configuration.

Before a read-only result changes placement through
`read_only_action_v2()`, result application must revalidate that the endpoint is
not suppressed for an active BGD transition. Admission-time validation alone
is insufficient because a task may have been admitted before suppression was
enabled.

## Verification

The BGD verification surface consists of:

- The SQLite3-server simulator compiled under `TEST_RDS_BGD`.
- The `cluster_sim_rds_bgd-g1` TAP group registered in
  `test/tap/groups/groups.json`.
- The 22 `test_rds_bgd_*-t` scenario binaries under `test/tap/tests`.
- `connection_unhealthy_unit-t`, which verifies terminal retirement across
  reset, local pool return, and global pool return.
- `.github/workflows/CI-cluster-simulator.yml`, which discovers registered
  simulator groups, builds the combined simulator flavor, and runs each group
  as an automatic pull-request check.

The scenario suite covers:

- Explicit startup and automatic discovery.
- Probe destination and TLS selection.
- Writer and reader switchover.
- Late entry into writer phases and first observation at completion.
- Cancellation, rollback, topology empty/absent, and query errors.
- Green membership persistence and green-pool cleanup.
- Offline server exclusions and reader policy.
- Configuration persistence, in-place refresh, disablement, removal, and
  worker hostgroup changes.
- Repeated deployments and concurrent deployment isolation.

The simulator cannot reproduce mutable DNS failure followed by recovery, so
same-phase DNS recovery is verified by source review rather than a mutable-DNS
simulator case. Full ProxySQL process restart is an accepted fresh-start
assumption and intentionally has no simulator fixture.

## Implementation Anchors

The monitor behavior is primarily implemented by:

- `parse_aws_rds_topology()`
- `monitor_RDS_BGD_thread_HG()`
- `handle_aws_rds_bgd()`
- `aws_rds_bgd_resolve_green_ips()`
- `aws_rds_bgd_refresh_worker_config()`
- `aws_rds_bgd_config_refresh_action()`
- `aws_rds_bgd_handle_topology_absent()`
- `handle_aws_rds_bgd_post_switchover()`
- `aws_rds_bgd_drain_green_hg()`

The broader configuration and effect surface includes:

- `include/DNS_Cache.hpp` and `lib/DNS_Cache.cpp`
- `include/MySQL_HostGroups_Manager.h` and
  `lib/MySQL_HostGroups_Manager.cpp`
- `include/mysql_connection.h` and `lib/mysql_connection.cpp`
- `lib/MySrvConnList.cpp`
- `lib/ProxySQL_Admin.cpp`
- `lib/ProxySQL_Config.cpp`
- `include/ProxySQL_Admin_Tables_Definitions.h`

Changes to these entry points or their state, configuration, DNS, hostgroup, or
connection semantics should be reviewed against this contract and the
simulator specification.
