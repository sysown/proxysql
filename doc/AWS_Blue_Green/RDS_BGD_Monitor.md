# AWS RDS Blue/Green Monitor

**Document status:** AUTHOR VALIDATION COMPLETE; PR2 SIMULATOR FOUNDATION
COMPLETE; IMPLEMENTATION CONFORMANCE OPEN

**Applies to:** Amazon RDS Multi-AZ DB instance blue/green deployment monitoring

**Primary monitor entry points:** `include/MySQL_Monitor.hpp`,
`lib/MySQL_Monitor.cpp`

**Simulator design:** [RDS_BGD_Simulator.md](RDS_BGD_Simulator.md)

**Related implementation:** `include/DNS_Cache.hpp`, `lib/DNS_Cache.cpp`,
`include/MySQL_HostGroups_Manager.h`, `lib/MySQL_HostGroups_Manager.cpp`,
`include/mysql_connection.h`, `lib/mysql_connection.cpp`,
`lib/MySrvConnList.cpp`, `lib/ProxySQL_Admin.cpp`, `lib/ProxySQL_Config.cpp`, and
`include/ProxySQL_Admin_Tables_Definitions.h`. This is the non-exhaustive
side-effect/configuration surface referenced by later `SOURCE-CODE` sections.

## Purpose

This document defines the AWS observations, current ProxySQL behavior, and
safety requirements for the AWS RDS blue/green deployment monitor introduced
by [PR #5861](https://github.com/sysown/proxysql/pull/5861).

The document is intentionally explicit about evidence. AWS behavior for which
this review has not recorded author evidence is not presented as an operational
guarantee. This evidence status does not imply that the author originally
inferred, assumed, or failed to observe the behavior.

## Evidence Labels

| Label | Dimension | Meaning |
|---|---|---|
| `SOURCE-CODE` | Provenance | Direct description of current implementation; it does not validate an external AWS claim. |
| `AUTHOR-VALIDATED` | External evidence | AWS behavior confirmed by the feature author. The statement must identify whether it is an AWS-provided contract or scoped observation. |
| `AUTHOR-ACCEPTED-POLICY` | Intent | ProxySQL behavior explicitly accepted by the feature author, including a deliberate policy choice made under an external uncertainty. |
| `REVIEW-VALIDATION-PENDING` | Review evidence | An external claim present in the PR, source comments, or implementation contract for which this review has not yet recorded the author's evidence or correction. It does not characterize how the author derived the claim. |
| `IMPLEMENTATION-CONFORMANCE-OPEN` | Review finding | The evidence or policy decision is resolved, but current source does not implement it or lacks verification. |
| `PROPOSED-POLICY` | Intent | Reviewer-proposed hardening that is not part of the current implementation or an author-accepted production contract unless separately promoted to `AUTHOR-ACCEPTED-POLICY`. |

Labels may be combined. `SOURCE-CODE, REVIEW-VALIDATION-PENDING` means the
current code or comments encode an external claim whose supporting evidence has
not yet been recorded in this review. `SOURCE-CODE` alone must be used only for
internal mechanics and never promotes an external claim.

A `REVIEW-VALIDATION-PENDING` claim must be promoted to `AUTHOR-VALIDATED`,
replaced by an explicit `AUTHOR-ACCEPTED-POLICY`, or corrected before the
author-validation gate closes. Closing that evidence gate does not imply that
the implementation conforms to the recorded decision or that a reviewer has
accepted the operational risk.

## Author Evidence Record

The feature author supplied the following evidence in the
[author-validation response](https://github.com/sysown/proxysql/pull/5934#issuecomment-4972444890):

- An [AWS-provided RDS topology metadata document](https://github.com/user-attachments/files/30019110/RDS_Topology_metadata.md)
  describing the `mysql.rds_topology` schema, roles, statuses, switchover
  stages, traffic availability, and polling guidance.
- A [timestamped topology trace](https://github.com/user-attachments/files/30019175/aws-rds-topology-watch.txt)
  from one complete switchover, polled at approximately 250 ms.
- Source-code references and additional author observations for cancellation,
  reader behavior, and green-hostname retirement.

The captured deployment used RDS MySQL 8.4.x, a Multi-AZ DB instance with two
read replicas, and `eu-north-1`. The trace covers one complete switchover; the
author separately observed one cancellation. A statement supported only by
that trace or an unrecorded author observation is scoped accordingly and is not
promoted to a universal AWS guarantee.

The author then answered the eight remaining decisions in the
[counter-review response](https://github.com/sysown/proxysql/pull/5934#issuecomment-4989347968).
That response explicitly:

- Defines the matched blue writer's configured port as the direct green-probe
  port and accepts that a source/target pair using different ports is not
  supported.
- Defines explicit-mode TLS from the matched green writer's `mysql_servers`
  row and automatic-mode TLS from the matched blue writer's row.
- Makes green hostgroup membership persistent until an administrator removes
  it, including membership created automatically at runtime.
- Accepts one-shot cleanup and loss of per-effect completion state rather than
  a retained or durable cleanup ledger.
- Accepts the current same-phase DNS-resolution failure for this PR and commits
  to a later per-pair reconciliation change.
- Accepts cleanup-on-worker-exit followed by fresh worker state, and a
  no-persistence fresh start after a full ProxySQL process restart.

The source changes reviewed with that response are commits `7d272074c` through
`ac4167cd0`, based on `0a37316c9`. A stated policy is recorded as resolved even
when implementation conformance is still open; those cases are called out
explicitly below.

The author subsequently clarified two ProxySQL-internal contracts during the
review:

- User configuration in the persistent `mysql_aws_rds_bgd_hostgroups` table
  requires both green hostgroup values. Nullable green hostgroups belong only
  to runtime rows generated by automatic discovery; those rows carry
  `auto_generated=1` and are skipped when runtime state is saved back to the
  persistent configuration table.
- Reads of connection state without an additional per-connection lock are an
  accepted project-level risk. For BGD connection retirement, `healthy=false`
  is to become a terminal marker: `MySQL_Connection::reset()` must not restore
  it, and both local and global pool-return paths must destroy an unhealthy
  connection instead of caching it.

The BGD test foundation uses ProxySQL's SQLite3 server, compiled under
`TEST_RDS_BGD` and controlled directly by each TAP test. The simulator
foundation and the BGD scenario suite are deliberately separate follow-up PRs.
Registration in `groups.json` is not considered CI integration by itself; the
BGD simulator group must be executed by an automatic PR check.

## Scope

This document covers:

- Detection of blue/green topology through `mysql.rds_topology`.
- Mapping of configured blue writer and reader servers to green servers.
- Green address resolution and direct topology probing.
- Writer and reader switchover handling.
- DNS pinning, hostgroup changes, and backend connection draining.
- Successful finalization, cancellation rollback, and worker replacement.
- Explicit and automatic green-hostgroup configuration.

This document does not define Aurora monitoring, Group Replication monitoring,
Galera monitoring, or PostgreSQL behavior.

## Terminology

The table includes current implementation terms and proposed hardening
concepts; proposed concepts are explicitly labeled.

| Term | Definition |
|---|---|
| Blue | The source deployment before switchover. |
| Green | The target deployment before switchover. |
| Observation | The result of one topology query or lifecycle event. |
| Controller state | `PROPOSED-POLICY`: ProxySQL's progress and policy across observations. |
| External effect | A DNS, hostgroup, monitor, or connection change visible outside controller bookkeeping. |
| Effect ledger | `PROPOSED-POLICY`: The identities and results of external effects requiring retry or cleanup. |
| Finalization | `PROPOSED-POLICY`: Cleanup on the proposed successful-completion path after observed writer completion and the accepted reader-completion signal. |
| Rollback | `PROPOSED-POLICY`: Restoration after cancellation or topology disappearance before observed writer completion. |

## Topology Shape

`SOURCE-CODE`: `parse_aws_rds_topology` sets `blue_green` once, from the first
fetched row, when the role and status columns exist and that row's cells for
both columns are non-NULL. Empty strings still meet this current non-NULL test.
Later rows do not re-evaluate or reverse the classification.

`SOURCE-CODE, AUTHOR-VALIDATED (AWS-PROVIDED CONTRACT)`: Actual RDS blue/green
rows use the source and target role values and recognized target status values
listed below. The AWS-provided metadata document defines these values, and all
five statuses appeared in the supplied trace.

Role values:

```text
BLUE_GREEN_DEPLOYMENT_SOURCE
BLUE_GREEN_DEPLOYMENT_TARGET
```

Target status values:

```text
AVAILABLE
SWITCHOVER_INITIATED
SWITCHOVER_IN_PROGRESS
SWITCHOVER_IN_POST_PROCESSING
SWITCHOVER_COMPLETED
```

`SOURCE-CODE`: If there is no row, either column is absent, or either first-row
cell is NULL, `blue_green` remains false. Later malformed rows do not change a
true first-row classification. Other RDS topology shapes may be processed by
the Multi-AZ Cluster discovery path.

`AUTHOR-VALIDATED (SCOPED OBSERVATION)`: While both rows were present in the
supplied trace, the source and target rows carried the same status. The trace
does not by itself establish that equality as a universal contract.

## Observation Model

`PROPOSED-POLICY`: The hardened controller design distinguishes the following
observation and lifecycle-event vocabulary. `SOURCE-CODE`: The
`TOPOLOGY_ABSENT` inputs correspond to the current table-existence query and
`ER_NO_SUCH_TABLE` metadata-fetch paths, but these observations are not the
current implementation state enum.

| Observation | Meaning |
|---|---|
| `TOPOLOGY_ABSENT` | The existence query returns zero rows, or a metadata fetch reports `ER_NO_SUCH_TABLE`. The table is not available; this is not a generic failure. |
| `TOPOLOGY_EMPTY` | A successful metadata query returns zero topology rows. |
| `AVAILABLE` | The target reports the recognized `AVAILABLE` status. |
| `WRITER_INITIATED` | The target reports the recognized `SWITCHOVER_INITIATED` status. |
| `WRITER_IN_PROGRESS` | The target reports the recognized `SWITCHOVER_IN_PROGRESS` status. |
| `WRITER_POST_PROCESSING` | The target reports the recognized `SWITCHOVER_IN_POST_PROCESSING` status. |
| `WRITER_COMPLETED` | The target reports the recognized `SWITCHOVER_COMPLETED` status. |
| `UNKNOWN_STATUS` | The target has a non-empty, unrecognized status. |
| `MALFORMED_TOPOLOGY` | The target, endpoint, role, status, or required identity is missing. |
| `QUERY_FAILED` | The query times out, the connection fails, or SQL reports an error other than documented absence. |
| `CONFIG_CHANGED` | The monitor result-set checksum or generation changes and may replace the worker without losing deployment state. |
| `CONFIG_DISABLED` | The deployment remains configured but is disabled; outstanding effects require phase-appropriate settlement. |
| `CONFIG_REMOVED` | The deployment configuration is removed; outstanding effects require phase-appropriate settlement before the context is removed. |
| `WORKER_RESTARTED` | A replacement worker attaches to and resumes the existing context. |

`PROPOSED-POLICY`: `TOPOLOGY_ABSENT`, `TOPOLOGY_EMPTY`, and `QUERY_FAILED` are
not interchangeable. Query failure never proves cancellation or completion.

## Validated Lifecycle Evidence

`SOURCE-CODE, AUTHOR-VALIDATED (AWS-PROVIDED CONTRACT AND SCOPED OBSERVATION)`:
The AWS-provided metadata document defines the five forward phases. The supplied
trace observed the following row lifecycle:

```text
Two rows:
  SOURCE = blue
  TARGET = green
  status = AVAILABLE

Two rows:
  repeated observations of SWITCHOVER_INITIATED
    -> repeated observations of SWITCHOVER_IN_PROGRESS
    -> repeated observations of SWITCHOVER_IN_POST_PROCESSING

One target row:
  repeated observations of SWITCHOVER_COMPLETED

Zero rows:
  observed approximately 44 seconds after SWITCHOVER_COMPLETED in this trace
```

`AUTHOR-VALIDATED (AWS-PROVIDED CONTRACT)`: `SWITCHOVER_COMPLETED` means writer
DNS propagation completed and the original source endpoint points to the
target. The status sequence permits cancellation during `SWITCHOVER_INITIATED`
and `SWITCHOVER_IN_PROGRESS`; rollback is no longer allowed in
`SWITCHOVER_IN_POST_PROCESSING`.

`AUTHOR-VALIDATED (SCOPED OBSERVATION)`: The trace observed monotonic forward
phase changes, with repeated identical observations while each phase remained
active. At `SWITCHOVER_COMPLETED`, the source row disappeared and the target
row remained for approximately 44 seconds before the table became empty. The
duration is not fixed. The table remained present in `information_schema`; an
`ER_NO_SUCH_TABLE` outcome was not observed.

`AUTHOR-ACCEPTED-POLICY`: After writer completion has been observed,
`TOPOLOGY_EMPTY` is the accepted reader-cleanup signal. The author observed
reader errors before the table drained and normal reader behavior afterward.
The metadata table contains writer topology only, the trace did not measure
reader DNS timing, and AWS does not document table emptiness as proof of reader
DNS propagation. This policy therefore records an explicitly accepted
operational correlation, not an AWS guarantee.

`AUTHOR-ACCEPTED-POLICY`: `TOPOLOGY_ABSENT` remains distinct from
`TOPOLOGY_EMPTY` in diagnostics but selects the same phase-specific policy:
rollback before observed writer completion and reader cleanup afterward. Only
the empty-table outcome was observed.

## Current ProxySQL State Machine

`SOURCE-CODE`: This is the nominal ordering encoded by the enum names and the
lifecycle currently described by the implementation. The arrows are not
enforced transition edges:

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

`SOURCE-CODE`: The current handler converts the target status and compares enum
ordering with the stored status. A lower value is treated as a backward
transition: the handler runs the current rollback cleanup, and only an observed
`AVAILABLE` phase is then re-entered and initialized. Forward transitions do
not require their immediate predecessor, so a worker can still first observe
`WRITER_SWITCHOVER_POST_PROCESSING` and perform setup in that phase.

`SOURCE-CODE`: An unknown non-empty target status converts to `NONE`. From an
active higher-valued state this is treated as a backward transition and invokes
rollback cleanup. An empty target status takes an earlier path that directly
sets `NONE` and does not invoke rollback cleanup. A special guard ignores a
repeated raw `WRITER_SWITCHOVER_COMPLETED` while local state is
`READER_SWITCHOVER_IN_PROGRESS`. A newly observed
`WRITER_SWITCHOVER_COMPLETED` is first stored and then immediately advanced to
`READER_SWITCHOVER_IN_PROGRESS` in the same handler call.

`SOURCE-CODE`: `READER_SWITCHOVER_IN_PROGRESS` and `SWITCHOVER_COMPLETED` are
ProxySQL-inferred and cleanup states, not raw AWS status strings.

`SOURCE-CODE`: Phase transitions currently perform these actions:

| Phase or observation | Current action |
|---|---|
| `AVAILABLE` | Set the next-check interval to 250 ms; build the blue/green mapping; resolve green IPs; optionally add the green writer to its configured hostgroup. |
| `WRITER_SWITCHOVER_INITIATED` | On transition, set the next-check interval to 100 ms; invoke mapping, green-IP resolution, and optional green-writer setup; suppress read-only checks for the deployment hostgroups. |
| `WRITER_SWITCHOVER_IN_PROGRESS` | On transition, set the next-check interval to 100 ms; invoke the same setup; suppress read-only checks; demote the mapped blue writer to read-only. |
| `WRITER_SWITCHOVER_POST_PROCESSING` | On transition, set the next-check interval to 100 ms; invoke the same setup; enable or sustain read-only suppression; pin mapped blue names to resolved green IPs; drain matching connections; configure writer placement; shun unmapped readers. |
| `WRITER_SWITCHOVER_COMPLETED` | Enter the inferred reader phase; remove the writer DNS-cache entry; retain mapped reader pins until the topology drains; reset the next-check interval override to the baseline value of `0`. |
| `READER_SWITCHOVER_IN_PROGRESS` plus empty or absent topology | Run successful cleanup: reconcile configured writer membership in the reader hostgroup; unshun recorded readers; remove DNS-cache entries and purge monitor-pool connections for recorded shunned readers and all mapped pairs; drain configured green hostgroups; clear worker bookkeeping; transition through `SWITCHOVER_COMPLETED` to `NONE`. |
| Empty or absent topology from any other non-`NONE` state | Run rollback cleanup: conditionally restore a writer demoted during `WRITER_SWITCHOVER_IN_PROGRESS` or `WRITER_SWITCHOVER_POST_PROCESSING`; reconcile blue reader membership and shuns; remove blue DNS-cache entries; purge related blue monitor-pool connections; leave green rows, statuses, DNS entries, and connections unchanged; clear worker bookkeeping; then enter `NONE`. |
| Recognized backward status transition | Run rollback cleanup. If the new raw status is `AVAILABLE`, re-enter `AVAILABLE`, set the 250 ms interval, and rebuild mapping, resolution, and optional green-writer placement. Other backward statuses leave the worker in `NONE` after cleanup. |
| Worker exit with non-`NONE` state | Run rollback cleanup before destroying the worker-local state. A replacement worker starts with a new state instance. |

### Current Probe Tuple

`SOURCE-CODE, AUTHOR-ACCEPTED-POLICY`: When direct probing is active, the
worker takes the port from the writer pair in `bg_map`, not from an arbitrary
blue polling row. That pair records the configured blue writer's port. The
implementation does not consume or validate the TARGET topology row's port;
the author explicitly accepts that a matched source/target pair with different
ports is unsupported.

`SOURCE-CODE, AUTHOR-ACCEPTED-POLICY`: Automatic mode has no independent green
`mysql_servers` row from which to read TLS configuration, so it intentionally
uses the matched blue writer's `use_ssl` value.

`SOURCE-CODE, AUTHOR-ACCEPTED-POLICY`: Explicit mode selects an eligible green
writer row by exact TARGET hostname and the matched blue writer's port. Map
construction copies `use_ssl` from an existing row. When discovery creates a
missing row or restores an `OFFLINE_HARD` row, the successful add path copies
the exact row's resolved `use_ssl` after hostgroup defaults are applied. A
valid initially empty configured green writer hostgroup produces no warning.
An `OFFLINE_SOFT` row remains ineligible and retains the matched-blue TLS
fallback. Simulator coverage for both row paths is assigned to PR6.

### Current Phase-Equality Behavior

`SOURCE-CODE`: After status conversion, the handler returns immediately when
the converted status equals the stored status. Phase actions run on transition,
not on every observation. Consequently, a transient mapping or DNS failure is
not retried while the same phase continues.

`AUTHOR-ACCEPTED-POLICY`: The author accepts this failure mode for the current
feature PR. In particular, a first DNS failure in
`WRITER_SWITCHOVER_POST_PROCESSING` can leave a pair unpinned and its old
connections undrained for the remainder of that phase. A subsequent PR is to
add worker-local, per-pair reconciliation that retries unresolved addresses
and applies pin/drain once, rather than rerunning the entire phase action.

### Current Connection-Retirement Behavior

`SOURCE-CODE`: `MySrvConnList::mark_connections_unhealthy()` marks every used
connection selected by a BGD drain with both `healthy=false` and
`reusable=false`. Free connections are deleted immediately. The intended used
connection lifecycle is therefore retirement after its current owner releases
it, not cancellation of an in-flight query solely because the drain began.

`SOURCE-CODE`: `MySQL_Connection::reset()` currently assigns both
`healthy=true` and `reusable=true`. The author observes that the two backend
reset call sites, `handler_again___status_RESETTING_CONNECTION` and
`handler_again___status_CHANGING_USER_SERVER`, are surrounded by logic that
destroys rather than reuses the affected backend connection. That observation
reduces the known exposure, but the terminal nature of a BGD drain remains
implicit and distributed across callers.

`AUTHOR-ACCEPTED-POLICY, IMPLEMENTATION-CONFORMANCE-OPEN`: The follow-up uses
the existing `healthy` field rather than introducing a second retirement flag:

1. `MySQL_Connection::reset()` resets session state but does not change
   `healthy` from false to true.
2. `MySQL_Thread::push_MyConn_local()` checks `healthy` before adding a
   connection to the thread-local cache. An unhealthy connection is sent to
   the global destruction path and cannot enter `cached_connections`.
3. `MySQL_HostGroups_Manager::push_MyConn_to_pool()` checks `healthy` after
   removing the connection from `ConnectionsUsed` and destroys an unhealthy
   connection before any optimization or insertion into `ConnectionsFree`.
4. `push_MyConn_to_pool_array()` remains covered because reusable entries
   delegate to `push_MyConn_to_pool()`; the existing `reusable=false` branch
   already destroys a drained connection directly.

The accepted state flow is:

```text
ACTIVE_BACKEND
  healthy=true, reusable=true
        |
        | BGD drain marks a used connection
        v
RETIRE_ON_RELEASE
  healthy=false, reusable=false
        |
        | optional connection/session reset
        | (healthy remains false)
        v
POOL_RETURN
        |
        +--> push_MyConn_local: unhealthy -> global destruction path
        |
        `--> push_MyConn_to_pool: unhealthy -> delete

No transition returns RETIRE_ON_RELEASE to a free or local pool.
```

`AUTHOR-ACCEPTED-POLICY`: Reads of `healthy` in these paths use the same
unlocked connection-field convention used elsewhere in ProxySQL. The author
accepts that race model for this focused fix. This decision does not assert
that a C++ data race is generally safe or introduce a broader locking policy.

### Current Topology-Absence Behavior

`SOURCE-CODE`: If local state is `READER_SWITCHOVER_IN_PROGRESS`,
`aws_rds_bgd_handle_topology_absent` runs the full current successful cleanup.
For every other non-`NONE` state, it calls the same cleanup helper with
`rollback=true`.

`SOURCE-CODE`: Rollback conditionally moves a writer demoted during
`WRITER_SWITCHOVER_IN_PROGRESS` or `WRITER_SWITCHOVER_POST_PROCESSING` back to
the writer role. It then runs the common completion hostgroup action, unshuns
recorded readers, removes DNS-cache entries and purges monitor-pool connections
for recorded shunned readers and all mapped blue pairs, clears the worker
bookkeeping, and enters `NONE`, which clears read-only suppression. Rollback
does not drain green connections, remove green DNS entries, change green
statuses, or remove green rows.

`SOURCE-CODE, AUTHOR-ACCEPTED-POLICY`: Successful cleanup drains connections
for every server in the configured green writer and reader hostgroups except
`OFFLINE_SOFT` and `OFFLINE_HARD` servers. It also removes those green
hostnames from the DNS and monitor connection caches. It leaves all green
server rows and statuses unchanged. The author assigns membership cleanup to
the administrator, including for a row automatically added to runtime by BGD.

`SOURCE-CODE`: The current rollback is a one-shot best-effort procedure. Its
effect operations do not return an action result to this controller, there is no
owned effect ledger, and the worker state is cleared even when external state
has not been verified.

`AUTHOR-ACCEPTED-POLICY`: This loss of per-effect completion and retry state is
intentional. The author accepts the possibility that process termination during
cleanup prevents the controller from proving that every intended postcondition
was reached. The retained-ledger design below remains a reviewer proposal, not
accepted follow-up work.

`SOURCE-CODE`: The interval result depends on the caller path:

- A metadata fetch reporting `ER_NO_SUCH_TABLE` sets
  `next_check_interval_ms` to `0` before calling the helper.
- Successful or rollback cleanup resets the interval as part of state cleanup.
- If the helper is called while state is already `NONE`, it performs no cleanup;
  an existence query or successful empty metadata query does not independently
  reset an existing interval override in that case.

`SOURCE-CODE`: PR 1 documents this current behavior. PR 1 does not change this.

### Current Worker Lifetime

`SOURCE-CODE`: State lives on the per-writer-hostgroup worker stack. The worker
and dispatcher compare a generation checksum that combines eligible blue and
green runtime rows. An Admin `mysql_servers` commit refreshes the checksum;
when its value changes, the old worker exits and the dispatcher creates a
replacement. If old state is non-`NONE`, the exit path runs one-shot rollback
cleanup before discarding it. The mapping, shunned-reader records, probe
target, and cleanup identities are not transferred; the replacement starts
with fresh state and rebuilds its map from current runtime configuration.

`SOURCE-CODE`: The combined checksum fixes the earlier case in which an Admin
commit adding an eligible green row could leave a nonempty partial map alive.
It is a configuration-generation signal, not a per-effect result ledger and
not a retry trigger for DNS recovery. In-process BGD calls to
`publish_mysql_servers_to_runtime()` do not refresh this generation checksum;
that permits the current worker's own hostgroup actions to continue without
self-replacement.

`AUTHOR-ACCEPTED-POLICY`: Cleanup-on-detach followed by fresh worker state is
the selected worker-replacement contract. A replacement whose first
observation is `SWITCHOVER_COMPLETED` does not reconstruct the prior worker's
map or effect ownership; it enters `READER_SWITCHOVER_IN_PROGRESS` and waits
for topology drain.

### Current Source Anchors

`SOURCE-CODE`: The source entry points for the current mechanics are
`parse_aws_rds_topology`, `handle_aws_rds_bgd`,
`aws_rds_bgd_handle_topology_absent`,
`handle_aws_rds_bgd_post_switchover`, and `monitor_RDS_BGD_thread_HG`. These
entry points should be reviewed with this document whenever behavior changes.

## External Effects And Cleanup Ledger

`PROPOSED-POLICY`: This section records the reviewer's stronger recovery model
for comparison and possible future reconsideration. The author explicitly
selected one-shot cleanup, worker-local state, and no durable BGD ledger. None
of the ledger states or invariants below is therefore an accepted requirement
for PR #5861 or the accepted same-phase reconciliation follow-up.

`PROPOSED-POLICY`: Every externally visible effect must have a stable identity
and a cleanup record before the effect is considered applied.

`PROPOSED-POLICY`: Every mutable effect uses the same stable ownership key:
deployment ID, deployment generation, action ID, and resource ID. The resource
ID identifies the effect-specific resource and does not change when its value
changes. Mutable result data is recorded separately and includes the before
value, intended or applied value, last observed value, and command result. In
particular, a resolved IP, its resolution source, and its expiry are result
data, not stable identity.

`PROPOSED-POLICY`: An effect has one of these states:

- `PENDING`: The intended value is not yet verified as applied.
- `APPLIED`: The intended value is verified, but cleanup or handoff remains.
- `REVERTED`: Compare-and-restore verified the owned effect was undone.
- `COMMITTED`: An irreversible effect was verified complete, or ownership of a
  retained effect was explicitly handed off to desired runtime configuration.
- `CONFLICT`: The resource no longer has the value applied by this owner, so
  automatic restoration would overwrite a newer value or owner.

`PROPOSED-POLICY`: The active cleanup ledger contains only unsettled,
controller-owned effects in `PENDING`, `APPLIED`, or `CONFLICT`. `REVERTED` and
`COMMITTED` entries leave the active ledger; they may remain as audit
tombstones outside it.

`PROPOSED-POLICY`: Cleanup uses compare-and-restore. An inverse action is
applied only when the resource still equals the applied value owned by the
ledger entry. Otherwise the effect becomes `CONFLICT`, remains in the active
ledger, and exposes `FAULTED`; cleanup does not overwrite newer configuration
or another owner.

`PROPOSED-POLICY`: A transitional effect superseded by the accepted desired
post-success state becomes `COMMITTED` only after the controller verifies an
explicit handoff of the resource and its intended value into desired runtime
configuration. A conflict or permanent inability to complete that handoff
enters `FAULTED` with the active ledger retained.

| Effect | Required identity | Successful postcondition | Required recovery |
|---|---|---|---|
| Blue/green mapping | Common owner key; resource identity is the blue endpoint, green endpoint, and role within the deployment. | All required endpoints are mapped; endpoint and role values are recorded as result data. | Clear the owned mapping or reconstruct it from a new complete observation. |
| Green resolution | Common owner key; resource identity is the green hostname and probe purpose. | A complete writer probe target is available; resolved IP, source, and expiry are recorded as result data. | Retry resolution or clear the incomplete owned result. |
| Direct probe | Common owner key; resource identity is the deployment probe slot, with host or IP, port, and SSL mode recorded as intended and applied result data. | Topology checks use the mapped writer endpoint. | Compare-and-restore the configured blue probe candidates. |
| Green writer placement | Common owner key; resource identity is the hostgroup and server. | The intended server is present with the mapped options, recorded as the applied value. | Compare-and-restore the prior placement, or mark `COMMITTED` only after explicit handoff of the retained placement into desired runtime configuration. |
| Monitor suppression | Common owner key; resource identity is the affected hostgroup and monitor scope. | Read-only monitoring skips only the intended servers. | Compare-and-restore the prior suppression value. |
| Blue writer demotion | Common owner key; resource identity is the server and affected placement; original and applied role and placement are result data. | The temporary role and placement are visible. | During rollback, compare-and-restore the original role and placement. After observed writer completion, successful finalization or `SAFE_TEARDOWN` reconciles and hands off the role and placement to accepted desired post-switchover runtime configuration, then marks the effect `COMMITTED`; it never restores obsolete blue solely because completion was observed or configuration was removed. A conflict or permanent inability to settle enters `FAULTED` with the active ledger retained. |
| DNS pin | Common owner key; resource identity is the hostname; pinned IP is applied result data. | Lookup returns the owned pinned IP. | Compare-and-restore only when the action owner still owns the pin. |
| Connection drain | Common owner key; resource identity is the server and drain generation. | Every connection predating the drain generation is verified retired and cannot be reused. | Never revert; mark `COMMITTED` only after every connection predating the generation is verified retired. |
| Reader shun | Common owner key; resource identity is the hostgroup, hostname, and port; previous status is before-value result data. | The intended reader is `SHUNNED_AWS_BGD`. | Compare-and-restore the recorded prior status. |
| Writer reader-hostgroup membership | Common owner key; resource identity is the writer server and reader hostgroup; original and applied membership are result data. | Membership matches the transition policy. | Compare-and-restore the configured membership. |

`PROPOSED-POLICY`: The effect ledger is stored as keyed sets or maps. Repeated
observations cannot create duplicate records or ambiguous effect ownership.

## Required Controller Invariants

`PROPOSED-POLICY`: The hardened controller must maintain the following safety
and liveness invariants. They describe intended behavior, not the current
implementation.

### Safety

1. `IDLE` has no unsettled temporary effects in the active cleanup ledger;
   settled audit tombstones may remain outside it.
2. Every visible controller-owned effect remains in the active cleanup ledger
   until it is `REVERTED` or `COMMITTED`.
3. Worker termination cannot destroy the only cleanup record for an effect.
4. Repeated observations retry incomplete actions.
5. Completed actions are not reapplied without a new action generation.
6. An unknown or malformed observation, or a query failure, preserves the last
   safe state and causes no destructive transition.
7. Topology disappearance before observed writer completion selects rollback.
8. Successful finalization requires observed writer completion.
9. A drained connection cannot become reusable.
10. A direct target includes the writer host or IP, port, and SSL mode.
11. Persistent configuration, runtime configuration, the hostgroup manager,
    and exported configuration agree on nullability.
12. Rollback and successful finalization are idempotent.
13. A stale worker cannot apply a result to a newer deployment generation.
14. No deployment-registry lock is held during DNS, SQLite, hostgroup-manager,
    connection-pool, or socket operations.

### Liveness

`PROPOSED-POLICY`: Liveness holds under fair scheduling, eventual recovery of
retryable dependencies, and unchanged effect ownership. A permanent failure or
ownership conflict converges to externally visible `FAULTED` with the active
ledger retained, rather than an unsafe overwrite or infinite silent retry.

1. Transient DNS failure remains retryable.
2. Under these liveness conditions, a cancelled deployment eventually restores
   the blue configuration; a permanent failure or ownership conflict instead
   exposes `FAULTED` while retaining its active ledger.
3. Under these liveness conditions, successful completion eventually removes
   temporary pins and shuns; a permanent failure or ownership conflict instead
   exposes `FAULTED` while retaining its active ledger.
4. Worker replacement resumes the deployment or safely rolls it back.
5. Failure for one blue/green pair does not hide other pairs.
6. Fast polling is bounded and has an observable reason.
7. Configuration removal cannot abandon outstanding effects.

## Proposed Controller Model

`PROPOSED-POLICY`: Controller state is separate from the raw AWS status. The
following state diagram is a reviewer-proposed alternative; it is not the
current implementation enum or an author-accepted implementation contract.

```text
IDLE
  -> TRACKING
  -> PREPARING
  -> CUTOVER
  -> REPOINTING
  -> AWAITING_READER_DNS
  -> FINALIZING_SUCCESS
  -> IDLE only when the active cleanup ledger is settled and empty

Any active state + topology disappears before observed writer completion
  -> ROLLING_BACK
  -> IDLE only when the active cleanup ledger is settled and empty

Any state at or after observed writer completion + configuration removal
  -> SAFE_TEARDOWN
  -> IDLE only when the active cleanup ledger is settled and empty

Any state + permanent failure or unrecoverable inconsistency
  -> FAULTED with the active cleanup ledger and deployment context retained
```

### Observation-Driven Transitions

`PROPOSED-POLICY`: The controller applies the following transitions from
observations and lifecycle events. The accepted reader-completion signal is a
symbolic policy input pending author validation; it may ultimately be defined
as empty or absent topology after observed writer completion.

`PROPOSED-POLICY`: Each deployment context has a configuration-management mode
orthogonal to its raw AWS phase. `ACTIVE` means validated configuration still
manages the deployment. `CONFIG_DISABLED` is the explicit-disable form of the
existing `CONFIG_REMOVED` lifecycle event. Either event latches
`REMOVAL_REQUESTED` as a cleanup request. Raw topology observations never clear
`REMOVAL_REQUESTED`. Only an explicit, validated re-add or re-enable of the
same deployment under a new configuration generation may request a return to
`ACTIVE`, and only after ownership and configuration reconciliation succeeds.

`PROPOSED-POLICY`: Permanent-failure and ownership-conflict rules have highest
precedence. The latched management mode and `ROLLING_BACK` rules are evaluated
next, before repeated, regressed, or generic forward-phase mappings. An
eligible forward-mapping state therefore excludes `ROLLING_BACK`, `FAULTED`,
`FINALIZING_SUCCESS`, and `SAFE_TEARDOWN`.

`PROPOSED-POLICY`: The normal recognized-phase mappings below apply only to an
initial or forward observation. An observation equal to the recorded phase
uses the repeated-phase rule. An observation lower than the highest trusted
completion evidence uses the regression rule and never causes a reverse
transition. For a newly observed deployment, its initial `IDLE` context is a
pre-completion nonterminal context for these mappings.

| Controller state and input | Required transition or action |
|---|---|
| Any + permanent failure or ownership conflict | Enter `FAULTED` with the active ledger and deployment context retained. |
| Any + `QUERY_FAILED` | Preserve state and effects, then retry. |
| Any + `UNKNOWN_STATUS` or `MALFORMED_TOPOLOGY` | Preserve state, expose the input, and make no destructive transition; action-result or error policy may enter `FAULTED` when the condition is classified permanent. |
| `ROLLING_BACK` + any pre-completion recognized phase | Remain in `ROLLING_BACK` and record the observation for diagnostics; do not resume cutover unless validated configuration explicitly re-enables the deployment and ownership reconciliation accepts it. |
| `ROLLING_BACK` + `WRITER_COMPLETED` | Stop or cancel pending rollback commands that would restore obsolete blue or remove the promoted target, latch writer-completion evidence, and enter `SAFE_TEARDOWN` when management mode is `REMOVAL_REQUESTED`; otherwise select an author-validated post-completion recovery or finalization path. |
| `ROLLING_BACK` + `TOPOLOGY_ABSENT` or `TOPOLOGY_EMPTY` | Remain in `ROLLING_BACK` and continue reconciling rollback effects. |
| `REMOVAL_REQUESTED` + any observation at or after writer completion | Enter or remain in `SAFE_TEARDOWN`; never apply a generic `AWAITING_READER_DNS` transition or restore blue solely from the raw phase. |
| Any + repeated observation of the same phase | Keep the controller state and reconcile incomplete effects. |
| Any + a regressed recognized phase | Preserve the highest trusted completion evidence and active effects, expose the regression, and make no reverse destructive transition until an author-validated policy decides how to handle it. |
| `IDLE` or `TRACKING` + `AVAILABLE` | Enter or remain in `TRACKING`; reconcile mapping, resolution, and preparation without applying cutover effects. |
| Any eligible forward-mapping state + `WRITER_INITIATED` | Enter `PREPARING`; record the latest observation and reconstruct or reconcile prerequisites. |
| Any eligible forward-mapping state + `WRITER_IN_PROGRESS` | Enter `CUTOVER`; record the latest observation and reconstruct or reconcile prerequisites and required cutover actions. |
| Any eligible forward-mapping state + `WRITER_POST_PROCESSING` | Enter `REPOINTING`; record the latest observation and reconstruct or reconcile all unmet prerequisites and repoint actions. |
| Any eligible forward-mapping state + `WRITER_COMPLETED` | Enter `AWAITING_READER_DNS`; record writer-completion evidence, then reconstruct and verify every unmet prerequisite effect or establish that it is obsolete under an author-validated policy; never infer that a skipped action succeeded. |
| Any pre-completion state + `TOPOLOGY_ABSENT` or `TOPOLOGY_EMPTY` | Enter `ROLLING_BACK`. |
| `ACTIVE` + `AWAITING_READER_DNS` + `ACCEPTED_READER_COMPLETION_SIGNAL` | Enter `FINALIZING_SUCCESS`. |
| `ACTIVE` + `CONFIG_CHANGED` | Preserve the deployment context and active ledger, then reconcile validated new configuration. |
| Any pre-completion state + `CONFIG_REMOVED` or `CONFIG_DISABLED` | Latch `REMOVAL_REQUESTED` and enter `ROLLING_BACK`. |
| Any state at or after observed writer completion + `CONFIG_REMOVED` or `CONFIG_DISABLED` | Latch `REMOVAL_REQUESTED` and enter `SAFE_TEARDOWN`; never restore blue solely because configuration was removed or disabled. |
| `REMOVAL_REQUESTED` + ordinary `CONFIG_CHANGED` or raw topology | Preserve `REMOVAL_REQUESTED`; do not resume generic forward processing. |
| `REMOVAL_REQUESTED` + explicit validated re-add or re-enable | Start a new configuration generation, reconcile ownership and configuration, and return to `ACTIVE` at the controller state appropriate to retained trusted evidence only after reconciliation accepts ownership. |
| Any + `WORKER_RESTARTED` | Attach the new worker generation to the same deployment context, state, and active ledger. |
| `ROLLING_BACK` + active ledger settled and empty | Enter `IDLE`. |
| `FINALIZING_SUCCESS` or `SAFE_TEARDOWN` + active ledger settled and empty | Enter `IDLE`. |

`PROPOSED-POLICY`: Every action execution returns one classified result:

- `SUCCEEDED`: The command changed the owned resource and verification observed
  the intended value.
- `ALREADY_SATISFIED`: Verification found the owned intended value without
  needing to repeat the command.
- `RETRYABLE_FAILURE`: The effect remains pending for a later reconciliation.
- `PERMANENT_FAILURE`: Policy cannot safely complete or retry the effect; enter
  `FAULTED` with the active ledger retained.
- `OWNERSHIP_CONFLICT`: The resource does not equal the value applied by this
  owner; retain the entry as `CONFLICT` and enter `FAULTED` without overwriting
  it.
- `STALE_RESULT`: The result belongs to an older deployment or worker
  generation and must not mutate current state or effects.

`PROPOSED-POLICY`: Repetition count alone does not make a failure permanent.
The executor classification and author-validated error policy determine
whether a failure is retryable or permanent.

### Reconciliation

`PROPOSED-POLICY`: Phase changes update controller status and emit an
observable log record, but actions are reconciled on every poll.
Actions returning `RETRYABLE_FAILURE` remain pending. Completed actions return
`ALREADY_SATISFIED` instead of repeating the effect, and stale results are
discarded. Advancing an observation does not prove that its actions completed.

### Successful Finalization

`PROPOSED-POLICY`: Successful finalization is selected only when management
mode remains `ACTIVE` after observed writer completion and the controller has
the reader-completion signal accepted by policy after author validation. It
then removes temporary DNS pins, reconciles reader status and writer
reader-hostgroup membership, reconciles writer role and placement with the
accepted desired post-switchover runtime configuration, drains obsolete
green-hostgroup connections, clears the direct probe and monitor suppression,
and clears mapping and resolution records. Successfully restored reversible
entries become `REVERTED`. Connection drains become `COMMITTED` only after
every connection predating the drain generation is verified retired. Any
retained green placement becomes `COMMITTED` only after explicit handoff into
desired runtime configuration. The blue-writer-demotion record becomes
`COMMITTED` only after the controller verifies handoff of writer role and
placement into the accepted desired post-switchover runtime configuration; it
never restores obsolete blue solely after observed writer completion. A
conflict or permanent inability to complete that handoff enters `FAULTED` with
the active ledger retained. The controller enters `IDLE` only when the active
cleanup ledger is settled and empty; settled audit tombstones may remain
outside it.

`PROPOSED-POLICY`: Successful finalization uses the ordered per-effect
settlement checklist in **Safe Teardown** wherever it applies. Its terminal
desired configuration is the accepted `ACTIVE` post-switchover configuration,
rather than removal intent, but it uses the same evidence gate, ownership
checks, dependency ordering, and `FAULTED` behavior.

### Safe Teardown

`PROPOSED-POLICY`: `SAFE_TEARDOWN` is selected when management mode is
`REMOVAL_REQUESTED` at or after observed writer completion. It settles effects
against the accepted terminal post-switchover removal intent and never restores
blue merely because configuration was removed or disabled.

`PROPOSED-POLICY`: Reader-related DNS pins, reader shuns, writer
reader-hostgroup membership, and direct-probe protection cannot be cleared
before the accepted reader-completion evidence or an author-validated
equivalent is observed. The dispatcher-owned cleanup executor continues
observing through a retained complete probe target and deployment context even
after the configured worker is removed. If accepted evidence cannot be
obtained, or an effect cannot be settled safely because of permanent failure or
ownership conflict, the controller enters externally visible `FAULTED`,
retains the active ledger and context, and does not clear effects merely to
reach `IDLE`.

`PROPOSED-POLICY`: After the evidence gate is satisfied, the controller settles
effects in this order:

1. DNS pins: Remove each pin only when the action owner still owns its applied
   value.
2. Reader shuns: Compare-and-restore each prior value or hand it off to the
   accepted terminal desired configuration. A missing resource that removal
   intent deliberately deleted may be `ALREADY_SATISFIED` only after ownership
   validation.
3. Writer reader-hostgroup membership, blue writer demotion, and
   green writer placement: Reconcile and hand them off to the accepted terminal
   post-switchover configuration or removal intent, then mark them `COMMITTED`.
   An ownership conflict or permanent settlement failure enters `FAULTED`.
4. Monitor suppression: Clear it only after DNS, reader, and routing-placement
   protection are settled.
5. Direct probe: Clear it only after it is no longer needed to obtain evidence
   or complete cleanup.
6. Connection drain: Mark it `COMMITTED` only after every connection predating
   the drain generation is verified retired.
7. Blue/green mapping and green resolution records: Commit or clear them only
   after every dependent effect is settled.

`PROPOSED-POLICY`: The deployment context enters `IDLE` and becomes eligible
for removal only when the active cleanup ledger is empty.

### Cancellation Rollback

`PROPOSED-POLICY`: Topology absence before observed writer completion enters
rollback. Rollback removes owned DNS pins; restores the configured blue probe
candidates, recorded reader statuses, and recorded hostgroup placement;
compare-and-restores the original blue writer role and placement; clears
monitor suppression; removes temporary green placement according to the
validated placement policy; and clears mapping and resolution records. The
controller marks a reversible entry `REVERTED` only after compare-and-restore
verifies the inverse. An irreversible drain or explicitly handed-off retained
placement becomes `COMMITTED` under the ledger rules. The controller enters
`IDLE` only when the active cleanup ledger is settled and empty; a conflict
instead retains the active ledger in `FAULTED`.

### Query And Data Errors

`PROPOSED-POLICY`: Query and data errors select the following recovery
behavior; they do not imply successful completion.

| Condition | Required controller behavior |
|---|---|
| Query timeout or connection failure | Preserve state and retry. |
| Unknown status | Preserve state, expose the unknown value, and make no destructive transition. |
| Malformed topology | Preserve state, expose the malformed input, and make no destructive transition. |
| DNS failure | Keep the resolution action pending. |
| Required mapping missing | Keep the mapping action pending. |
| One reader action fails | Retain completed reader actions and retry the failed reader action. |
| Permanent action failure | Enter `FAULTED` with the active cleanup ledger retained. |
| Ownership conflict | Enter `FAULTED` with the conflicting entry and active ledger retained; do not overwrite the resource. |
| Repeated rollback failure | Remain in `ROLLING_BACK` while classified retryable, or enter `FAULTED` when classified permanent; repetition count alone is not permanent, and the controller never enters `IDLE` with an unsettled entry. |

## Worker And Configuration Lifetime

`PROPOSED-POLICY`: Controller state and its effect ledger have deployment
lifetime, not worker-stack lifetime.

```text
dispatcher creates or retrieves deployment context
  -> worker generation N attaches
  -> configuration checksum changes
  -> generation N detaches; deployment context remains
  -> worker generation N+1 attaches and resumes reconciliation
```

`PROPOSED-POLICY`: Configuration changes update the deployment context without
clearing it. Disabling or removing configuration before observed writer
completion latches `REMOVAL_REQUESTED` and requests rollback. At or after
observed writer completion, removal latches `REMOVAL_REQUESTED` and enters
`SAFE_TEARDOWN`, including when `FINALIZING_SUCCESS` had already begun; it never
restores blue solely because configuration was removed.

`PROPOSED-POLICY`: Post-completion configuration removal follows the evidence
gate and ordered settlement checklist in **Safe Teardown**. The terminal desired
configuration reflects validated removal intent. The same checklist reconciles
writer role and placement and marks the demotion record `COMMITTED` only after
verified handoff; it never compare-and-restores obsolete blue after observed
writer completion.

`PROPOSED-POLICY`: When a configuration worker is removed, the dispatcher
retains or starts an independent cleanup executor until the active ledger is
settled or an externally visible `FAULTED` state is reached. The dispatcher
removes the deployment context only after it reaches `IDLE` with a settled,
empty active ledger. It does not erase a context in `FAULTED`.

`PROPOSED-POLICY`: Durable SQLite persistence is unnecessary only if every
controller-owned effect is proven to disappear, revert, or be reconstructable
after a full ProxySQL process restart. This includes DNS pins, runtime shuns,
monitor suppression, backend connections and their drain generations,
green writer placement, blue writer demotion,
writer reader-hostgroup membership, and the direct probe target. If any effect
does not meet that condition, the controller persists its ledger or provides
deterministic startup recovery.
The author instead accepts a no-persistence fresh start and the loss of
per-effect ownership across process restart. The condition above is therefore
a reviewer hardening criterion, not a pending author-validation question or a
guarantee of current behavior.

## Configuration Model

The feature has blue writer and reader hostgroups. Green hostgroup nullability
depends on row origin; it is not a user-selectable mixed-mode configuration.

| Row origin and storage | Green writer hostgroup | Green reader hostgroup | Semantics |
|---|---|---|---|
| User row in persistent Admin configuration | Value required | Value required | Explicit green hostgroups. The persistent schema declares both columns `NOT NULL`; a user `NULL` insert is rejected by SQLite. |
| User row materialized into runtime/HGM | Value | Value | The values from persistent configuration are retained with `auto_generated=0`. |
| Runtime row created by automatic discovery | `NULL` | `NULL` | Automatic green handling. The row carries `auto_generated=1` and exists only in runtime/HGM state. |
| Any user mixed combination | Invalid | Invalid | A user row cannot select automatic handling for only one green role. |

`SOURCE-CODE, AUTHOR-VALIDATED`: The runtime Admin and HGM schemas allow the
two green columns to be nullable because they must represent auto-generated
rows. That storage capability does not make `NULL` valid in the persistent
user table. Defensive `NULL` binding while materializing or dumping HGM rows
likewise does not expand the user configuration contract.

`SOURCE-CODE, AUTHOR-VALIDATED`: Saving runtime BGD hostgroups to the persistent
Admin table skips every row whose runtime `auto_generated` field is nonzero.
Consequently, a runtime auto-generated row with two `NULL` green hostgroups is
not inserted into the persistent `NOT NULL` table. User rows have both values
and are saved normally.

`PROPOSED-POLICY`: Configuration updates have generations. Configuration
removal latches `REMOVAL_REQUESTED`. Re-adding or re-enabling the deployment
creates a new validated generation and must reconcile ownership before
resuming controller processing.

## Author Validation Checklist

The author response is recorded below. `RESOLVED` means the external evidence
has been scoped correctly or the author explicitly accepted the policy or
limitation. An implementation can still fail to conform to a resolved policy;
that is tracked separately rather than reopening the evidence decision.

| ID | Recorded author evidence or decision | Review disposition |
|---|---|---|
| AWS-01a | One trace and the AWS examples show the source row present through all pre-completion phases. | `RESOLVED`: This is scoped observation, not a universal prohibition. Missing source identity remains `MALFORMED_TOPOLOGY` and causes no destructive transition. |
| AWS-01b | The trace shows the source row disappearing at `SWITCHOVER_COMPLETED`, leaving one target row. | `RESOLVED`: Source-row absence after completion is expected in the observed lifecycle but is not independently the reader-completion signal. |
| AWS-01c | One trace and the AWS examples show the target row present in every nonempty result. | `RESOLVED`: This is scoped observation. A missing target remains `MALFORMED_TOPOLOGY`. |
| AWS-01d | `TOPOLOGY_EMPTY` was observed only after writer completion. | `RESOLVED`: The author accepts rollback before completion and reader cleanup afterward. The pre-completion impossibility is not stated as an AWS guarantee. |
| AWS-01e | `TOPOLOGY_ABSENT` was not observed; the table remained present and empty. | `RESOLVED AS POLICY`: Preserve the distinct observation but select the same phase boundary as `TOPOLOGY_EMPTY`. |
| AWS-02a | The AWS-provided contract permits rollback during initiated and in-progress; the author separately observed cancellation returning to `AVAILABLE`. | `RESOLVED`: Pre-completion cancellation selects the current one-shot rollback path. Retained settlement is a reviewer proposal, not accepted policy. |
| AWS-02b | The AWS-provided contract says rollback is no longer allowed during post-processing. | `RESOLVED`: At or after writer completion, never restore obsolete blue solely because of cancellation or removal. |
| AWS-03 | The author accepts the same phase-specific policy for empty and absent topology while retaining distinct diagnostics. | `RESOLVED AS POLICY`. |
| AWS-04 | The contract defines `SWITCHOVER_COMPLETED` as writer DNS completion; the trace observes source-row removal in that completed snapshot. | `RESOLVED`: Use the status, not row count alone, as writer-DNS evidence. |
| AWS-05a | The target existed through every phase and lingered about 44 seconds after completion in one trace. | `RESOLVED`: Record the duration only as variable, single-observation evidence. |
| AWS-05b | The author accepts `TOPOLOGY_EMPTY` after observed writer completion as the reader-cleanup signal despite no AWS guarantee or direct reader-DNS timestamp. | `RESOLVED AS AUTHOR-ACCEPTED POLICY`: The observational risk is explicit. |
| AWS-06 | The author observed the green hostname stop resolving after completion while the promoted IP survived. | `RESOLVED AS SCOPED OBSERVATION`: Retain a complete probe target while it is needed. |
| AWS-07 | The author agrees the evidence does not establish universal source/target port equality. Commit `20247dcf0` takes the probe port from the matched blue writer pair. Pair-specific port mismatch is explicitly unsupported; different pairs may use different ports. | `RESOLVED AS AUTHOR-ACCEPTED POLICY`: Use the matched blue writer's configured port and accept failure for a target using a different port. Do not present equality as an AWS guarantee. |
| AWS-08 | The author agrees `use_ssl` is ProxySQL configuration. Automatic mode uses the matched blue writer's value; explicit mode must use the matched green writer row's value. | `RESOLVED AS AUTHOR-ACCEPTED POLICY; IMPLEMENTED`: Existing rows are selected by exact TARGET hostname and matched-blue port; successfully created or restored rows supply their resolved `use_ssl`. Simulator coverage remains assigned to PR6. |
| AWS-09 | The topology contains writer endpoints only; incomplete explicit reader mapping is expected and unmatched blue readers are shunned. | `RESOLVED AS POLICY`: Track and reconcile readers independently. |
| AWS-10 | Commits `cdffd77ee` and `ac4167cd0` retain auto-added and user-configured green rows on rollback and success. Rollback leaves green connections untouched; success drains eligible green connections but leaves rows and statuses unchanged. | `RESOLVED AS AUTHOR-ACCEPTED POLICY`: Green membership is persistent runtime configuration, not a temporary owned effect. Administrative cleanup is required even for an auto-added row. |
| AWS-11a | The author explicitly chooses one-shot worker-exit/configuration-change cleanup and no retained retry ledger. | `RESOLVED AS AUTHOR-ACCEPTED POLICY`: Loss of the cleanup context, including when a process terminates during cleanup, is accepted. The stronger retained rollback model is not PR2 scope. |
| AWS-11b | The author explicitly applies the same one-shot choice after completion and relies on the current phase-specific cleanup path. | `RESOLVED AS AUTHOR-ACCEPTED POLICY`: No retained `SAFE_TEARDOWN` executor or per-effect settlement record is required. This acceptance does not prove each one-shot operation succeeds. |
| AWS-12a | Commits `727b2166b` and `d45c953d2` combine eligible blue/green rows into the worker generation checksum and refresh it after Admin `mysql_servers` commits. The author accepts that DNS recovery alone does not retry a failed same-phase setup. | `RESOLVED AS AUTHOR-ACCEPTED POLICY AND FOLLOW-UP`: Current PR may leave a POST_PROCESSING pair unpinned and undrained after first-resolution failure. A subsequent PR must implement per-pair retry and exactly-once pin/drain behavior. |
| AWS-12b | The author selects cleanup-on-worker-exit and fresh replacement state. Persistent green membership and rollback-time green connections have no worker ownership under AWS-10. | `RESOLVED AS AUTHOR-ACCEPTED POLICY`: A replacement first observing COMPLETED may enter the inferred reader phase without reconstructing the prior map or effects. |
| AWS-13 | The author separates worker replacement from full restart. Replacement performs one-shot rollback then starts fresh. Full restart rebuilds DNS cache, pools, suppression, maps, probe target, and FSM; configured state reloads, while an unsynchronized auto-added runtime green row disappears. | `RESOLVED AS AUTHOR-ACCEPTED POLICY`: No durable BGD progress or ownership persistence is required. This is an accepted fresh-start contract, not a traced per-effect guarantee. |
| CFG-01a | User-configured rows require both green hostgroup values. The persistent Admin table declares both columns `NOT NULL`. | `RESOLVED AS AUTHOR-VALIDATED PROXYSQL CONTRACT`: A user `NULL` or mixed row is invalid; no configuration-nullability follow-up is required. |
| CFG-01b | Automatic discovery creates runtime/HGM rows with both green hostgroups `NULL` and `auto_generated=1`; runtime-to-persistent save skips those rows. | `RESOLVED AS AUTHOR-VALIDATED PROXYSQL CONTRACT`: Runtime nullability is intentional and does not conflict with persistent user constraints. |

### Probe Target Validation Matrix

| Mode | Host/IP source | Port source | SSL source | Author decision/evidence |
|---|---|---|---|---|
| Automatic | `AUTHOR-VALIDATED`: Resolved IP of the TARGET endpoint from `mysql.rds_topology`. | `AUTHOR-ACCEPTED-POLICY`: Matched blue writer's configured port. A different TARGET port is unsupported and is not forbidden by the recorded AWS evidence. | `AUTHOR-ACCEPTED-POLICY`: Matched blue writer's `use_ssl`, because no independent green row exists. | Policy resolved and implemented by writer-pair selection in `20247dcf0`. |
| Explicit | `AUTHOR-VALIDATED`: Resolved IP of the TARGET endpoint from `mysql.rds_topology`; the configured green writer must identify that target. | `AUTHOR-ACCEPTED-POLICY`: Matched blue writer's configured port. A different TARGET or explicit-green port is unsupported. | `AUTHOR-ACCEPTED-POLICY`: Exact matching green writer row's resolved `use_ssl`. | Policy resolved and implemented; PR6 owns simulator coverage. |

`AUTHOR-ACCEPTED-POLICY`: A direct probe target is a complete host or IP, port,
and SSL tuple derived from the matched writer pair, never from an arbitrary
monitor row. The author accepts the blue-port constraint above. Explicit TLS
must be looked up by exact green writer identity, including the supported port,
rather than by applying a blue-to-green matcher to two green names.

### Restart Validation Matrix

`AUTHOR-ACCEPTED-POLICY`: Worker replacement and full process restart are
different fresh-start events. Neither recovers a durable BGD ledger. The table
records the selected behavior, not a claim that every one-shot operation has
been traced or verified under crash injection.

| Effect | Worker replacement in the same process | Full ProxySQL process restart |
|---|---|---|
| Blue DNS pins | The exiting worker attempts to remove mapped blue DNS entries and purge their monitor-pool connections before discarding state. No result is retained for the replacement. | DNS cache and monitor connection pools are recreated; no BGD pin ownership is recovered. |
| Reader shuns | The exiting worker attempts to unshun only readers recorded in its local `shunned_readers` list. The replacement receives no list. | Runtime-only BGD shuns are discarded; server status is rebuilt from administrator configuration. |
| Monitor suppression | Entering `NONE` clears the worker's in-progress suppression entries for its current hostgroup members. | Suppression state is recreated empty. |
| Active connections and drains | Rollback purges mapped blue and recorded-reader monitor-pool connections. Green connections are intentionally untouched. No drain generation or completion result transfers. | Connection pools are recreated; no connection or drain-generation record survives. |
| Green placement | Auto-added and administrator-configured green rows remain in same-process runtime state. They are intentionally not worker-owned. | Administrator-configured rows reload. An auto-added runtime-only row disappears unless independently configured or synchronized into restart input. |
| Blue demotion | Exit cleanup attempts to restore a writer demoted in `WRITER_SWITCHOVER_IN_PROGRESS` or `WRITER_SWITCHOVER_POST_PROCESSING`. The replacement trusts current runtime placement. | Writer status and placement rebuild from administrator configuration. |
| Writer reader-hostgroup membership | Exit cleanup runs the current completion hostgroup action using local map and configuration values, then discards the map. | Membership rebuilds from administrator configuration. |
| Direct probe | The local direct-probe IP and failure counter are discarded. The replacement derives a new target from its first observation and current map, except that a first COMPLETED observation does not rebuild prior effects. | Probe state is recreated empty and derived from newly observed topology. |
| Mapping and resolution | Local pairs and resolved IPs are discarded after one-shot exit cleanup. The replacement builds a new map when its observed phase runs setup. | Pair map and resolution results are recreated from configuration and topology. |

`AUTHOR-ACCEPTED-POLICY`: If the process terminates during cleanup, no durable
record proves which operations completed. The author accepts that uncertainty
because the relevant in-memory structures are expected to be rebuilt at full
restart. This explicitly rejects the stronger recovery requirement proposed in
**External Effects And Cleanup Ledger** for the current feature and accepted
follow-up scope.

## Test Mapping For Later PRs

The six response commits add no automated test. The following cases exercise
the code and policy changed by those commits without assuming the declined
durable-ledger design.

| Requirement | Named unit/simulator case | Named Admin/TAP case | Observable postcondition |
|---|---|---|---|
| Matched writer probe destination | `writer_tuple_not_first_poll_row` | `matched_writer_destination` | With a reader first in the polling result and every endpoint at port 3306, the direct probe uses the mapped green writer destination and never `hpa[0]`. |
| Automatic TLS source | `auto_green_inherits_writer_ssl` | `automatic_green_tls` | With no explicit green row, the direct probe and auto-added green writer use the matched blue writer's `use_ssl`. |
| Explicit TLS source | `explicit_green_ssl_override` | `explicit_green_tls_differs_from_blue` | With every endpoint at port 3306, blue `use_ssl=0`, and explicit green `use_ssl=1`, the direct IP probe enables TLS. This guards the exact explicit-green TLS selection. |
| Eligible green generation checksum | `green_checksum_matrix` | `admin_green_add_remove_ssl_status` | Add/remove, `use_ssl`, and transitions into or out of `OFFLINE_SOFT`/`OFFLINE_HARD` change the checksum and replace workers; irrelevant changes do not. |
| Admin commit during active phase | `config_change_exits_worker` | `load_mysql_servers_mid_switchover` | The old worker runs one-shot rollback, the dispatcher joins it, and the replacement builds a new map from the committed runtime rows. |
| Green membership persistence | `green_row_persists_cancel_and_success` | `green_row_lifecycle` | Auto-added and user rows remain after rollback and success; no existing status is changed. |
| Green drain policy | `green_drain_status_matrix` | `green_hg_cleanup` | Rollback drains no green connections. Success drains `ONLINE`, `SHUNNED`, and `SHUNNED_AWS_BGD` green servers while leaving `OFFLINE_SOFT` and `OFFLINE_HARD` untouched. Rows remain present. |
| Offline status exclusions | `offline_servers_not_acted_on` | `offline_soft_hard_servers` | Blue servers in either offline status do not participate in mapping or unmatched-reader shunning; green servers in either status are not drained. |
| Terminal connection retirement | `unhealthy_survives_reset` | `drained_used_connection_not_repooled` | After a drain marks a used connection unhealthy, reset does not revive it and neither local nor global pool return can place it in a free cache. |
| Persistent/user green hostgroups | `user_green_hostgroups_not_null` | `user_configuration_requires_both_green_hgs` | Persistent user inserts with either green hostgroup `NULL` fail; a row with both values loads with `auto_generated=0`. |
| Automatic runtime row persistence | `auto_generated_null_green_hgs` | `save_runtime_skips_auto_generated_bgd` | Auto-discovery creates a runtime row with both green hostgroups `NULL` and `auto_generated=1`; saving runtime to memory/disk does not persist that row. |
| First observation COMPLETED | `fresh_worker_first_completed` | `replace_worker_at_completed` | Fresh state advances to the inferred reader phase without reconstructing a prior map, then finishes on topology drain. |
| Full restart fresh start | `restart_discards_bgd_state` | `proxysql_restart_fixture` | DNS cache, pools, suppression, mapping, probe target, and FSM are recreated; configured rows reload; an unsynchronized auto-added runtime-only green row does not. |
| Same-phase DNS retry follow-up | `dns_retry_same_post_per_pair` | — | Future resolver/unit coverage only: the unresolved pair retries while phase is unchanged; successful pairs are not redrained; the recovered pair is pinned and drained exactly once. Mutable DNS is outside simulator/TAP scope. |
| Partial pair progress follow-up | `one_pair_fails` | `multiple_reader_fixture` | Accepted follow-up only: successful pair state is retained worker-locally and only the failed pair retries. |

`PROPOSED-POLICY`: The simulator cases previously proposed for durable effect
ownership, compare-and-restore, retained `FAULTED` state, cleanup across stale
worker generations, and a persistent restart ledger remain useful reviewer
hardening ideas. They are not author-accepted follow-up requirements after AWS-11a,
AWS-11b, AWS-12b, and AWS-13. Implementing them would require a new policy
decision rather than treating this document as approval.

## Review Gate

The author has answered all 23 validation IDs. No external
`REVIEW-VALIDATION-PENDING` claim remains. The evidence gate is therefore
closed, with observational scope and accepted operational risks preserved in
the checklist rather than promoted to AWS guarantees.

The source review remains open on implementation and verification:

1. **COMPLETED:** Select explicit green TLS from the exact supported writer row,
   including a row created or restored during discovery. Simulator coverage
   for the existing-row and discovered-row paths remains part of PR6.
2. **COMPLETED:** Make unhealthy connection retirement terminal across reset,
   local pool return, and global pool return. The follow-up uses the existing
   `healthy` field and does not add a second flag. `connection_unhealthy_unit-t`
   verifies that unhealthy connections remain terminal across reset and cannot
   enter either free pool.
3. Track the author-accepted same-phase DNS failure as required follow-up work
   with focused resolver/unit coverage rather than simulator/TAP integration.
   Until per-pair reconciliation exists, a transient first resolution failure
   in POST_PROCESSING can leave traffic unpinned and old connections undrained.
   Acceptance documents the risk; it does not make the failure safe.
4. Add focused simulator and TAP coverage for the response commits and these
   follow-ups. Registration in `test/tap/groups/groups.json` is insufficient:
   an automatic PR check must build the BGD test flavor and execute the BGD
   simulator group.

### Follow-up PR Sequence

PR #5861 remains the live umbrella PR into `v3.0`. Every implementation and
test follow-up below targets `feature/aws-rds-monitor`, so each accepted change
becomes part of #5861 rather than replacing or closing it. The originally
proposed broad durable-ledger/controller PR is not part of this sequence.

| Review PR | Scope | Dependency and completion signal |
|---|---|---|
| PR1: #5934 | This document only: evidence, accepted risks, current behavior, and follow-up contract. | Ready for author approval; merge into `feature/aws-rds-monitor` before implementation follow-ups so their scope is stable. |
| PR2: BGD simulator foundation — COMPLETED | Add the TAP-controlled SQLite3-server simulator defined in [RDS_BGD_Simulator.md](RDS_BGD_Simulator.md): the `TEST_RDS_BGD` build mode, IP-keyed topology responses, common and BGD TAP helpers, a simulator group, and an end-to-end acceptance smoke test. | Completed after the isolated local Docker group passed. Provides the reusable harness required by PR6; automatic GitHub Actions execution remains separate follow-up work under the review gate above. |
| PR3: probe target and explicit TLS (**complete**) | Correct AWS-08 by selecting the exact supported explicit green writer row and its resolved `use_ssl`, including a row created or restored during discovery, while retaining the matched blue writer port and automatic-mode blue TLS fallback. | **Completed:** production behavior conforms to AWS-08. Existing-row and discovered-row simulator coverage remains part of PR6. |
| PR4: terminal connection retirement (**complete**) | Preserve `healthy=false` across `MySQL_Connection::reset()` and destroy unhealthy connections in local and global pool-return paths. Do not introduce another flag or a new locking policy. | **Completed:** `connection_unhealthy_unit-t` proves a drained used connection cannot enter either free pool after reset or release. |
| PR5: same-phase per-pair reconciliation | Replace phase-equality no-op behavior with worker-local reconciliation for incomplete map/resolution/pin/drain work. Retry only incomplete pairs and never redrain a pair already completed in the current worker generation. | Depends on the accepted one-shot worker model; it must not introduce durable ownership or restart recovery. |
| PR6: simulator-driven BGD scenario suite | Use PR2's simulator to cover configuration and discovery order, automatic and explicit rows, worker replacement, normal lifecycle, late entry, cancellation and rollback, topology drain, direct probe destination/TLS for existing and discovered explicit green rows, offline exclusions, and terminal connection retirement where observable. | Depends on PR2 and should normally follow PR3-PR4 so the suite validates final behavior rather than encoding known failures. All payloads run in the automatic BGD simulator CI group. |

Any retained cleanup ledger, durable restart ownership, or alternative
controller state machine requires a new author policy decision. The simulator
contract and integration design consumed by PR2 and PR6 are defined in
[RDS_BGD_Simulator.md](RDS_BGD_Simulator.md).
