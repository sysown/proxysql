# Aurora BGD Monitor Loop and FSM Design

**Date:** 2026-07-31

**Branch:** `spec/aws-aurora-bgd`

**Status:** Design approved

**Scope:** Aurora MySQL blue/green deployments exposed through
`mysql.rds_topology` and `INFORMATION_SCHEMA.REPLICA_HOST_STATUS`.

**Evidence basis:** The AWS-team-provided *RDS Topology metadata – Overview*
document defines the routing semantics of the switchover statuses. A
timestamped live-Aurora switchover observation captured on 2026-07-30
corroborates those semantics and supplies the observed Aurora-specific details.
Section 3 separates the supplied status contract, observed behavior, and design
policy.

**Related designs:**

- [Aurora BGD Configuration, Runtime Status, and Cluster Sync](2026-07-31-aurora-bgd-configuration-runtime-cluster-sync-design.md)
- [Aurora BGD Cluster Simulator and Testing](2026-07-31-aurora-bgd-cluster-simulator-testing-design.md)

## Spec Boundary

This specification owns the Aurora worker loop, probe ownership and cadence,
target-membership discovery, cached member identity and IP state, DNS and pool
actions, the BGD FSM, rollback, reload continuity, and completion-latch
behavior. Public table schemas, persistence, and cluster synchronization belong
to the configuration/runtime specification. Simulator mechanics and the
executable coverage matrix belong to the simulator/testing specification.

## 1. Decision Summary

Aurora BGD is part of the existing Aurora monitor. Each active, user-created
`mysql_aws_aurora_hostgroups` row continues to own one worker keyed by
`writer_hostgroup`. Every Aurora configuration row is user-created, and the
design starts no second BGD worker for it.

The worker owns three logically separate probes:

1. the existing production Aurora membership/lag probe;
2. an Aurora BGD `mysql.rds_topology` probe;
3. a target `REPLICA_HOST_STATUS` membership probe.

The worker follows existing RDS BGD parsing, status publication, DNS pinning,
connection draining, writer-placement, rollback, reload, and cleanup patterns
where their semantics match. Aurora-specific behavior is retained where RDS
Multi-AZ instance behavior does not apply:

- membership comes from the target Aurora cluster;
- the topology probe rotates across reachable target members instead of being
  pinned to the target writer IP;
- normal Aurora probing is suspended during the active switchover phases;
- every current writer and reader must be mapped before traffic changes;
- readers are not shunned or unshunned;
- TARGET completion cleans up writer and reader routing immediately;
- topology drain is only the terminal-latch rearm signal.

An Aurora row either has both green hostgroups configured or has neither. This
document describes the distinction only as green hostgroups configured or not
configured. The existing
`mysql-aws_blue_green_deployment_auto_discovery` variable remains only an
admission gate for starting BGD discovery when green hostgroups are not
configured, as defined by the configuration/runtime specification.

## 2. Terminology

- **Production cluster:** The source/current Aurora cluster before switchover
  and the promoted target after completion.
- **Target cluster:** The Aurora cluster identified by the TARGET row before
  promotion.
- **Canonical identifier:** The original production `SERVER_ID`, without the
  temporary AWS `-green-<suffix>` component.
- **Target identifier:** A pre-promotion target `SERVER_ID` containing the
  temporary `-green-<suffix>` component.
- **Production hostname:** The canonical instance hostname already configured
  in the production writer or reader hostgroup.
- **Target hostname:** A hostname constructed from a target `SERVER_ID` and the
  RDS domain suffix.
- **Traffic pin:** A permanent ProxySQL DNS-cache mapping from a production
  hostname to the cached IP of its target counterpart.
- **Complete target snapshot:** Exactly one current target writer plus a unique
  target counterpart for every current production member, with all target IPs
  resolved.
- **Effect-driven cleanup:** The idempotent RDS BGD pattern that reconciles
  placement and removes transient routing state from the worker's existing
  member map. A member-scoped operation is a no-op when its map input is absent.
- **Deployment fingerprint:** TARGET topology identity retained after cleanup
  to recognize repeated results. At minimum it contains TARGET `id`, endpoint,
  and port.

## 3. Evidence and AWS/Aurora Behavioral Contract

### 3.1 AWS-provided status semantics

The AWS-team-provided *RDS Topology metadata – Overview* document defines these
traffic-routing semantics for `mysql.rds_topology` during switchover:

| Status | AWS-provided meaning | Write traffic | Read traffic |
|---|---|---|---|
| `SWITCHOVER_INITIATED` | Switchover was triggered, but no modifications have occurred and rollback remains possible. | Source | Source |
| `SWITCHOVER_IN_PROGRESS` | Source writes are disabled while target replication catches up; rollback remains possible. | Nowhere | Source |
| `SWITCHOVER_IN_POST_PROCESSING` | The target is promoted and can receive writes; rollback is no longer possible. | Target | Target |
| `SWITCHOVER_COMPLETED` | DNS propagation is complete and the original source endpoint points to the target. | Target | Target |

The implementation treats these meanings as the AWS-supplied behavioral
contract for routing decisions. In particular, POST_PROCESSING definitively
means that the promoted target can accept write traffic; target readiness is
not inferred solely from one observed run.

[AWS's Aurora switchover documentation](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/blue-green-deployments-switching.html)
also states that a DB cluster included in a switchover cannot be modified while
the switchover is running. The production and target member sets are therefore
fixed from INITIATED until the first COMPLETED observation. Membership can
change while the deployment is AVAILABLE, when the normal production probe
and target-membership probe remain active and refresh their snapshots.

### 3.2 Directly observed behavior

The 2026-07-30 run observed:

1. `mysql.rds_topology` progressed through:

   ```text
   AVAILABLE
     -> SWITCHOVER_INITIATED
     -> SWITCHOVER_IN_PROGRESS
     -> SWITCHOVER_IN_POST_PROCESSING
     -> TARGET-only SWITCHOVER_COMPLETED
   ```

2. The target cluster endpoint returned exactly one writer and all current
   readers through `REPLICA_HOST_STATUS`.
3. The writer row used `SESSION_ID='MASTER_SESSION_ID'`; reader rows used
   distinct session identifiers.
4. During post-processing, target `SERVER_ID` values changed from temporary
   green identifiers to canonical production identifiers.
5. Reader `SESSION_ID` values remained unchanged across that rename.
6. The production topology became `SWITCHOVER_IN_PROGRESS` at `T+9.864s`; the
   source writer became read-only at `T+10.398s`.
7. The target writer became writable at `T+14.438s`; target post-processing was
   observed at `T+15.795s`.
8. Every target member had a canonical `SERVER_ID` by `T+21.380s`.
9. TARGET completion was visible at `T+40.655s`; the topology table drained at
   `T+65.730s`.

The run corroborates the AWS-provided status semantics. Details learned only
from the observation, including timings, target-member rename behavior, and
table-drain timing, are implementation evidence rather than a formal AWS
compatibility guarantee. Tests must simulate the observed changes, and
unexpected or ambiguous metadata must fail closed.

### 3.3 Design policy derived from the contract and observation

- POST_PROCESSING is the routing barrier because the AWS-provided semantics say
  that the promoted target can receive writes at that status; no additional
  target-writability query gates traffic pinning.
- Normal monitoring refreshes membership while the deployment is AVAILABLE.
  INITIATED freezes the last complete production snapshot for the duration of
  the switchover, matching AWS's cluster-modification restriction.
- TARGET completion means Aurora writer and reader routing cleanup can occur
  immediately.
- Table drain is not a reader-availability barrier for Aurora.
- A query error, incomplete membership result, or ambiguous identity does not
  advance routing actions or cause rollback.

## 4. Worker Ownership and Probe Model

### 4.1 Single worker owner

The existing Aurora worker for a `writer_hostgroup` is the sole owner of normal
Aurora monitoring and the BGD FSM. It owns all per-deployment state and
serializes the three probes and their actions. A separate Aurora BGD worker must
not be started for the same row because it would duplicate queries and race on
hostgroup state.

### 4.2 Production Aurora probe

This is the existing random-host `REPLICA_HOST_STATUS` probe used for Aurora
role, lag, and autopurge decisions.

- It runs normally in `NONE` and `AVAILABLE`.
- It stops issuing queries in `SWITCHOVER_INITIATED`,
  `SWITCHOVER_IN_PROGRESS`, and `SWITCHOVER_IN_POST_PROCESSING`.
- It resumes after completion cleanup enters `SWITCHOVER_COMPLETED`, or
  immediately after rollback.

Suspension means the query itself is skipped. Running the query while
discarding all role, lag, and autopurge actions provides no FSM input because
the target-membership probe owns target discovery.

### 4.3 Topology probe

In `NONE`, the topology probe uses the existing Aurora random-host selection:
choose a random reachable production member and fall back across the remaining
members when ping or connection setup fails.

After the TARGET endpoint has bootstrapped a complete target member list, the
topology probe applies the same selection algorithm across the current target
members. It is not pinned to the target writer and does not use a dedicated
cached-IP probe pin. When `REPLICA_HOST_STATUS` reports renamed identifiers,
the target probe-host list is refreshed to the corresponding canonical
hostnames.

After completion cleanup, topology probing returns to random reachable
canonical production members while the terminal latch waits for table drain.

### 4.4 Target-membership probe

The TARGET cluster endpoint from `mysql.rds_topology` bootstraps a separate
`REPLICA_HOST_STATUS` query. Its result is parsed only into the BGD target
snapshot. It must not be passed to normal Aurora evaluation before cutover,
because doing so could prematurely move or add target members in production
hostgroups.

The target-membership probe continues through AVAILABLE, INITIATED, IN_PROGRESS,
and POST_PROCESSING. It stops after completion cleanup or rollback has removed
the need for target-side discovery.

### 4.5 Cadence

| FSM state | Topology probe | Target-membership probe | Production Aurora probe |
|---|---|---|---|
| `NONE` | Configured `check_interval_ms` when BGD discovery is admitted | Off | Configured interval |
| `AVAILABLE` | Configured `check_interval_ms` | Configured interval | Configured interval |
| `SWITCHOVER_INITIATED` | Fast, 100 ms | Fast, 100 ms | Suspended |
| `SWITCHOVER_IN_PROGRESS` | Fast, 100 ms | Fast, 100 ms | Suspended |
| `SWITCHOVER_IN_POST_PROCESSING` | Fast, 100 ms | Fast, 100 ms | Suspended |
| `SWITCHOVER_COMPLETED` | Configured interval | Off | Configured interval |

The 100 ms active cadence follows the existing RDS BGD worker. Query duration
is accounted for so a slow query does not create an additional full-interval
sleep.

## 5. Discovery Bootstrap and Admission

For an eligible row in `NONE`:

1. Probe `information_schema.TABLES` for `mysql.rds_topology`, following the
   RDS BGD table-check state.
2. When the table exists, fetch and parse `SELECT * FROM mysql.rds_topology` so
   AWS column-set differences remain tolerated by the shared parser.
3. Require a structurally valid BGD result with a TARGET row and non-empty
   TARGET `id`, status, endpoint, and port. Construct the deployment fingerprint
   from at least that validated `id`, endpoint, and port.
4. Map the observed TARGET status to an Aurora FSM state, publish it to
   `bgd_status`, and leave `NONE` before starting membership discovery.
5. Use the TARGET cluster endpoint to bootstrap target membership after that
   state transition.
6. After target membership is available, rotate topology probes across target
   members.

A membership failure does not undo a valid observed status. It prevents any
membership-dependent routing action and is retried at the cadence for the
current phase. Missing, empty, or malformed topology does not create a new
deployment.

Raw topology statuses map to Aurora runtime states as follows:

| Raw TARGET status | Aurora FSM and `bgd_status` value |
|---|---|
| `AVAILABLE` | `AVAILABLE` |
| `SWITCHOVER_INITIATED` | `SWITCHOVER_INITIATED` |
| `SWITCHOVER_IN_PROGRESS` | `SWITCHOVER_IN_PROGRESS` |
| `SWITCHOVER_IN_POST_PROCESSING` | `SWITCHOVER_IN_POST_PROCESSING` |
| `SWITCHOVER_COMPLETED` in a valid TARGET-only result | `SWITCHOVER_COMPLETED` terminal latch |

`NONE` is an internal baseline and rearm state, not an arbitrary raw status.
An unsupported or unknown raw status is invalid metadata: a worker already in
an active or terminal state retains that state, and a worker in `NONE` remains
there. The value is never copied verbatim into `bgd_status`. Aurora does not use
the RDS Multi-AZ inferred `READER_SWITCHOVER_IN_PROGRESS` state; TARGET
completion maps directly to the Aurora terminal latch after cleanup.

If green hostgroups are configured, BGD discovery is admitted for the
user-created Aurora row. If neither is configured, the existing global
auto-discovery variable gates admission of a new deployment. Changing that
variable after a deployment has started does not abandon the active FSM.

## 6. Target Membership and Pair Mapping

### 6.1 Query and current rows

The target query must include at least:

```sql
SELECT
    SERVER_ID,
    SESSION_ID,
    LAST_UPDATE_TIMESTAMP,
    IS_CURRENT
FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS
ORDER BY SERVER_ID;
```

The implementation may retain the existing lag and CPU columns. Only rows
identified as current are eligible. The writer is the sole current row whose
`SESSION_ID` is `MASTER_SESSION_ID`; all other eligible rows are readers.

### 6.2 Complete-snapshot rule

A new snapshot replaces the last complete snapshot only when:

1. it contains exactly one current target writer;
2. each current production member has exactly one target counterpart;
3. no target member maps to more than one production member;
4. no production member maps to more than one target member;
5. every target hostname has a resolved IP.

A target writer-only snapshot is valid only when the current production
snapshot also contains no readers. Query errors, empty results, multiple
writers, missing readers, duplicate identities, and unresolved IPs do not
replace the last complete snapshot. They also must not be reinterpreted as a
reader-less deployment.

The production snapshot is refreshed by normal Aurora monitoring throughout
AVAILABLE. When the worker first accepts INITIATED, that last complete snapshot
becomes the fixed production membership for the switchover. The normal
production probe remains suspended while AWS prevents changes to either
included cluster; the frozen snapshot and continuously refreshed target
snapshot therefore require no separate member-set generation.

POST_PROCESSING actions require a complete snapshot. If none exists, the
worker holds the current status, performs no partial traffic cutover, and
retries both active probes.

### 6.3 Constructing member hostnames

The TARGET cluster endpoint has the form:

```text
<target-cluster>.cluster-<rds-domain-suffix>
```

A target member hostname is:

```text
<SERVER_ID>.<rds-domain-suffix>
```

Each target member stores its role, current `SERVER_ID`, `SESSION_ID`, current
hostname, port, resolved IP, normalized canonical identifier, matching
production hostname, and per-action flags.

### 6.4 Identity across rename

Pair every target member to production by its normalized `SERVER_ID`:

- before promotion, remove the AWS-added `-green-<suffix>` component;
- after promotion, leave the already canonical identifier unchanged.

For readers, `SESSION_ID` is an additional continuity check. A reader whose
`SERVER_ID` changes but whose session identifier matches the cached pair is the
same target reader. A session mismatch or a conflict between normalized name
and cached session identity makes the new snapshot ambiguous.

For the writer, `MASTER_SESSION_ID` is only a role marker. It must not be used
as a unique instance identity. The sole writer is paired by normalized
`SERVER_ID`; no cached-IP writer identity rule is required.

### 6.5 Cached IPs

During AVAILABLE and every active switchover phase, resolve all target member
hostnames and retain the last complete set of IPs independently of DNS TTL
expiry. Membership discovery continues through post-processing so renamed
identifiers refresh the host list, but pre-rename cached IPs remain valid
traffic-pin values.

Cached target IPs are used for traffic redirection only. They do not pin the
topology probe to a particular member.

## 7. Worker-Owned State

The runtime owner for a writer hostgroup must retain:

```text
current FSM status
deployment fingerprint
last production membership snapshot
last complete target snapshot
normalized production/target member pairs
cached target IP per pair
traffic-pin-applied flag per pair
production-probe-suspended flag
configured green hostgroup identifiers, when present
```

Per-member flags make repeated observations idempotent. The fingerprint keeps a
repeated completed row from starting cleanup again after the active map has
been released.

## 8. State Machine

### 8.1 States

```text
NONE
AVAILABLE
SWITCHOVER_INITIATED
SWITCHOVER_IN_PROGRESS
SWITCHOVER_IN_POST_PROCESSING
SWITCHOVER_COMPLETED
```

`runtime_mysql_aws_aurora_hostgroups.bgd_status` exposes these worker states.
The final state is a terminal rearm latch, not a separate reader-switchover
phase.

### 8.2 Topology row-shape predicates

The worker validates the complete topology result before publishing a new
status or running an FSM action:

- An active deployment result contains exactly one SOURCE row and one TARGET
  row. Both rows have non-empty `id`, endpoint, role, status, and a valid port;
  both expose the same supported pre-completion status.
- A completion result contains exactly one TARGET row, has the validated
  deployment-fingerprint fields, and reports `SWITCHOVER_COMPLETED`.
- A successful empty result or confirmed table absence is the explicit
  cancellation or terminal-drain observation described below.
- SOURCE-only results, TARGET-only pre-completion results, duplicate SOURCE or
  TARGET rows, extra or unknown roles, mismatched statuses, missing required
  fields, and unsupported statuses are invalid or incomplete observations.

Invalid or incomplete observations do not publish a new status, trigger
cleanup, release pins, or resume suspended monitoring. A worker in `NONE`
remains there; an active or latched worker retains its existing state and
retries. This validation is distinct from a successful empty or absent
topology, which has the explicit state-dependent meaning in the transition
table.

### 8.3 Transition summary

| Valid observation | Required transition and action |
|---|---|
| No deployment in `NONE` | Remain `NONE`; continue admitted discovery at configured cadence. |
| `AVAILABLE` | Enter/retain `AVAILABLE`; build target membership and cache IPs without changing production routing. |
| `SWITCHOVER_INITIATED` | Suspend production Aurora probing, capture rollback state, and switch BGD probes to fast cadence. |
| `SWITCHOVER_IN_PROGRESS` | Move the production writer to the reader hostgroup; do not route to target yet. |
| First `SWITCHOVER_IN_POST_PROCESSING` | With a complete snapshot, pin every production member, drain old connections, and restore the canonical writer to the writer hostgroup. |
| Repeated POST_PROCESSING | Retry only incomplete idempotent member actions. |
| First TARGET-only `SWITCHOVER_COMPLETED` | Run immediate effect-driven cleanup, resume normal Aurora monitoring, and enter the completed latch. |
| Repeated same completed TARGET | No-op while latched. |
| Successful empty/absent topology while latched | Release the fingerprint and return to `NONE`. |
| Earlier valid status before completion | Run rollback, then enter the earlier state. |
| Successful empty/absent topology before completion | Treat as cancellation and run rollback. |
| Query/connect error in any state | Retain state and retry; never infer rollback or table drain. |
| Different valid fingerprint while latched | Rearm and process the new deployment. |

## 9. Phase Actions

### 9.1 `AVAILABLE`

On entry and repeated observations:

1. Publish `bgd_status=AVAILABLE`.
2. Run normal production Aurora monitoring unchanged.
3. Build or refresh the last complete target snapshot.
4. Resolve and retain every target IP.
5. Keep all production DNS, pools, and hostgroup placement unchanged.

Configured green hostgroups, when present, remain user configuration and are
not the target-membership source of truth. When they are absent, the complete
target map remains worker-local. No Aurora configuration row is generated in
either case.

### 9.2 `SWITCHOVER_INITIATED`

On entry:

1. Publish `bgd_status=SWITCHOVER_INITIATED`.
2. Capture production writer placement and other state required for rollback.
3. Suspend the normal production Aurora probe.
4. Switch topology and target-membership probes to 100 ms.
5. Continue refreshing target membership and IPs.
6. Make no traffic-routing or hostgroup-placement change.

### 9.3 `SWITCHOVER_IN_PROGRESS`

On the first valid observation:

1. Publish `bgd_status=SWITCHOVER_IN_PROGRESS`.
2. Retain fast BGD probes and the suspended production probe.
3. Move the current production writer to the reader hostgroup using the same
   writer-demotion behavior as RDS BGD.
4. Retain the member map for writer-placement reconciliation during completion
   or rollback.
5. Do not redirect any production hostname to target yet.

The move is idempotent. A repeated observation does not repeat a completed
hostgroup action.

### 9.4 `SWITCHOVER_IN_POST_PROCESSING`

POST_PROCESSING is the only pre-completion traffic-redirection boundary.

Before applying any action, require a complete target snapshot. Then:

1. Publish `bgd_status=SWITCHOVER_IN_POST_PROCESSING`.
2. Do not issue an additional target-writability probe.
3. For every writer and reader pair, install:

   ```text
   production hostname -> cached target IP
   ```

4. Reuse the RDS BGD connection-drain behavior for each production hostname:
   drop free backend connections immediately and mark used connections
   unhealthy/non-reusable.
5. Purge the corresponding monitor connection-pool entries so new connections
   resolve through the traffic pin.
6. After the writer pin is installed, restore the canonical writer to the
   writer hostgroup. Its placement in the reader hostgroup follows the existing
   `writer_is_also_reader` configuration.
7. Keep canonical readers eligible in the reader hostgroup. Do not shun or
   unshun them.

Every pair records that its pin-and-retirement action was applied after the DNS
pin, free-connection deletion, used-connection unhealthy/non-reusable marking,
and monitor-pool purge calls return. This flag does not mean that every used
connection has physically closed: destruction happens asynchronously when the
connection is released and is not a completion prerequisite. Repeated
POST_PROCESSING results retry only unapplied actions and do not reapply
retirement to an already transitioned member.

### 9.5 `SWITCHOVER_COMPLETED`

On the first TARGET-only completed result, run effect-driven cleanup
immediately, before publishing the terminal latch:

1. If the existing member map contains a writer, reconcile that writer into
   the writer hostgroup and apply its reader placement according to
   `writer_is_also_reader`. This restores a writer moved during IN_PROGRESS when
   POST_PROCESSING was not observed, and is a no-op when the writer is already
   restored or the map is empty.
2. For every mapped pair, remove the production-hostname DNS entry and purge
   the corresponding monitor-pool entries so normal DNS resolution resumes.
   Removing an absent pin or pool entry is a no-op.
3. Do not reapply connection retirement, wait for marked connections to close,
   wait for topology drain, or perform a separate DNS verification.
4. Drain only obsolete pools belonging to configured green hostgroups, subject
   to the configured OFFLINE-status preservation policy.
5. Preserve every user-created configuration and `mysql_servers` row.
6. Clear any installed switchover guard and resume normal Aurora monitoring.
7. Move topology probing back to random reachable canonical production members
   and the configured interval.
8. Release the active member map after retaining the deployment fingerprint.
9. Publish and enter the internal `SWITCHOVER_COMPLETED` latch.

The cleanup path is the same regardless of the prior phase. It acts only on the
available member map and worker state, so absent inputs naturally produce
no-ops. Completion never replays a skipped phase or waits for earlier actions.

While latched:

- the same TARGET completed result is ignored;
- query/connect errors do not rollback, repin, or repeat cleanup;
- a successful empty result or confirmed table absence returns the worker to
  `NONE`;
- a different valid deployment fingerprint rearms discovery.

The topology drain is therefore only an FSM rearm signal.

## 10. Rollback and Error Handling

### 10.1 Rollback before completion

A successful, structurally valid result for the same deployment with an
earlier status follows the existing RDS BGD backward-transition behavior. A
successful empty result or confirmed table absence before completion is treated
as cancellation. Either condition runs effect-driven cleanup in rollback mode:

1. Remove every traffic pin that was applied.
2. Drain/purge affected production-hostname pools so subsequent connections use
   restored canonical DNS.
3. Reconcile the mapped production writer into the writer hostgroup. This is a
   no-op if the writer is already there or the map is empty.
4. Restore its reader placement according to `writer_is_also_reader`.
5. Resume normal production Aurora monitoring.
6. Return topology probing to production members and the appropriate cadence.
7. Preserve user-created green-hostgroup and server rows.
8. If AWS returned to AVAILABLE, rebuild target discovery in AVAILABLE; if the
   topology disappeared, clear the deployment and return to `NONE`.

Rollback does not drain configured green-hostgroup pools merely because an
attempt was cancelled.

### 10.2 Errors and incomplete data

- A topology or membership query/connect error retains the current state.
- An invalid or incomplete target snapshot retains the last complete snapshot.
- No error is interpreted as an empty table, reader-less cluster, cancellation,
  or successful completion.
- No routing action runs without its state-specific prerequisites.
- Errors in the completed latch do not release or restart it.

## 11. Late Entry, Reload, Removal, and Concurrency

### 11.1 Late entry

A worker that first observes INITIATED, IN_PROGRESS, or POST_PROCESSING rebuilds
all prerequisites before applying that phase's actions. In particular,
POST_PROCESSING cannot pin traffic until it has a complete target snapshot.

A worker that first observes TARGET-only completion has an empty member map.
Its member-scoped completion actions are consequently no-ops. The worker
retains the fingerprint and enters the terminal latch without manufacturing or
replaying earlier phase actions.

### 11.2 Configuration and variable refresh

An unrelated `LOAD MYSQL SERVERS TO RUNTIME` or variable refresh must preserve
the FSM status, deployment fingerprint, complete snapshots, cached IPs, applied
pin flags, probe-suspension state, and terminal latch.

Changing configured green hostgroups refreshes the staging/pool references but
does not restart an active deployment from `NONE`. Disabling the global
auto-discovery variable prevents admission of a new no-green-hostgroup
deployment; it does not abort one already active.

### 11.3 Row removal and worker exit

Removing or deactivating the owning Aurora row follows the existing RDS BGD
worker-removal cleanup pattern: remove applied pins, restore safe production
writer placement where possible, release suspended monitoring state, and then
terminate the worker. No user configuration row is deleted as a side effect.

### 11.4 Concurrent deployments

All state is keyed by production `writer_hostgroup`. Probes, fingerprints,
snapshots, pins, writer placement, reloads, rollback, and completion for one
Aurora row must not mutate another row's state.

## 12. Separation from RDS Multi-AZ Instance Logic

The following RDS Multi-AZ instance behaviors must not drive the Aurora branch:

- pinning the topology probe to a single green writer IP;
- treating TARGET completion as writer-only completion;
- entering `READER_SWITCHOVER_IN_PROGRESS`;
- retaining reader pins until topology drain;
- shunning unmapped production readers;
- routing an empty reader hostgroup through the promoted writer as a missing-map
  fallback.

Aurora reuses the RDS machinery only where the behavior matches the contracts
in this specification.

## 13. Current Implementation Gaps

The existing RDS builder assumes the TARGET topology endpoint is an instance
writer and discovers readers from configured RDS green hostgroups. Aurora's
TARGET is a cluster endpoint and its complete membership comes from
`REPLICA_HOST_STATUS`.

The Aurora implementation therefore requires:

1. three logical probes in the existing per-writer-hostgroup worker;
2. target-cluster membership parsing separate from normal Aurora evaluation;
3. normalized `SERVER_ID` pairing plus reader `SESSION_ID` continuity;
4. complete-snapshot validation and cached per-member IPs;
5. normal-probe suspension during the active switchover;
6. RDS-style writer demotion, DNS pinning, pool draining, rollback, and status
   publication;
7. Aurora-specific all-member POST_PROCESSING and immediate completion cleanup;
8. completion-fingerprint retention until topology drain.

The existing RDS Multi-AZ builder and FSM remain unchanged.

## 14. Required Tests

### 14.1 Probe ownership and cadence

- One Aurora worker owns all three logical probes.
- NONE and AVAILABLE use configured cadence and continue normal Aurora probes.
- INITIATED, IN_PROGRESS, and POST_PROCESSING use 100 ms BGD probes and issue no
  normal Aurora query.
- Topology selection rotates across target members and falls back when a member
  is unreachable.
- No target-writer IP probe pin is installed.
- COMPLETED resumes normal probing and production-member topology selection.

### 14.2 Membership and mapping

- Target cluster membership yields one writer and multiple reader pairs.
- No configured green hostgroups still produces a complete in-memory map.
- Green-suffixed `SERVER_ID`s normalize to production identifiers.
- Reader `SESSION_ID`s preserve identity after canonical rename.
- The writer is paired by normalized `SERVER_ID`, not `MASTER_SESSION_ID` or IP.
- A genuine no-reader cluster accepts a writer-only snapshot.
- Empty, failed, duplicate-writer, ambiguous, unresolved, and incomplete results
  retain the last complete snapshot or defer actions.
- SOURCE-only, duplicate-role, mismatched-status, unknown-status, and
  TARGET-only pre-completion topology results fail closed without publishing or
  transitioning; only TARGET-only completion is accepted.

### 14.3 FSM and routing

- AVAILABLE discovers and resolves every member without routing changes.
- INITIATED suspends normal Aurora probing without moving servers.
- IN_PROGRESS moves the production writer to the reader hostgroup exactly once.
- POST_PROCESSING requires a complete snapshot.
- First POST_PROCESSING pins and drains every member and restores the writer.
- No target-writability query gates POST_PROCESSING.
- Readers remain eligible and are never shunned.
- Repeated POST_PROCESSING retries only unapplied work.
- The per-pair action flag records application of pinning and retirement
  marking, not asynchronous physical connection closure.
- First TARGET completion runs immediate effect-driven cleanup using the
  existing map and worker state.
- Direct completion with an empty map performs no production-member routing or
  retirement action and enters the completed latch.
- Completion after IN_PROGRESS restores the writer even when POST_PROCESSING
  was not observed.
- Completion after POST_PROCESSING removes applied pins without reapplying
  connection retirement or waiting for marked connections to close.
- Completion performs no DNS verification and does not wait for table drain.
- Repeated completion is a no-op while latched.
- Empty/absent topology releases the latch and returns to `NONE`.

### 14.4 Resilience and lifecycle

- Backward status and pre-completion topology disappearance run rollback.
- Query errors never run rollback or release the completed latch.
- Rollback removes pins, restores writer placement, and resumes normal probes.
- Late entry at every active state reconstructs prerequisites before acting.
- Reload preserves active and terminal state.
- Changing or removing the owning row runs safe, isolated cleanup.
- Disabling auto-discovery does not abort an admitted deployment.
- Concurrent writer hostgroups remain isolated.
- Configured green pools are drained only on successful completion, with user
  rows and statuses preserved.

## 15. Acceptance Criteria

The Aurora monitor/FSM design is satisfied when:

1. One existing Aurora worker owns the three probes and all state for its
   writer hostgroup.
2. Every production member is mapped from target `REPLICA_HOST_STATUS` before
   traffic changes, regardless of whether green hostgroups are configured.
3. Normal Aurora queries stop during the three active switchover phases and
   resume after completion or rollback.
4. IN_PROGRESS demotes the production writer using the RDS BGD behavior.
5. POST_PROCESSING redirects writer and reader traffic using cached target IPs,
   drains old connections, and never shuns readers.
6. TARGET completion removes every traffic pin and finishes routing cleanup
   without waiting for topology drain.
7. Repeated results, errors, reloads, late entry, rollback, worker removal, and
   concurrent deployments behave idempotently and remain isolated.
8. The terminal completed state persists only until a successful topology drain
   observation rearms the FSM.
9. RDS Multi-AZ instance behavior and tests remain unchanged.
