# Aurora BGD Monitor Loop and FSM Design

**Date:** 2026-07-31

**Branch:** `plan/aurora-bgd`

**Status:** Design draft

**Scope:** Aurora MySQL blue/green deployments exposed through
`mysql.rds_topology` and `INFORMATION_SCHEMA.REPLICA_HOST_STATUS`.

**Evidence basis:** An observed Aurora switchover captured on 2026-07-30. The
relevant timings and behavioral conclusions are summarized in Section 3 so the
specification is self-contained.

**Related designs:**

- [Aurora BGD Configuration, Runtime Status, and Cluster Sync](2026-07-31-aurora-bgd-configuration-runtime-cluster-sync-design.md)
- [Aurora BGD Cluster Simulator and Testing](2026-07-31-aurora-bgd-cluster-simulator-testing-design.md)

## Spec Boundary

This specification owns the Aurora worker loop, topology and membership
discovery, cached member identity and IP state, DNS and pool actions, the BGD
FSM, rollback, and completion-latch behavior. Public table schemas,
persistence, and cluster synchronization belong to the configuration/runtime
specification. Simulator mechanics and the executable coverage matrix belong
to the simulator/testing specification.

## 1. Purpose

Provide a low-disruption ProxySQL switchover path for Aurora MySQL blue/green
deployments. ProxySQL discovers the complete target Aurora cluster before the
switchover, caches its member IPs, redirects the configured production
hostnames to those IPs during post-processing, and returns to normal DNS routing
as soon as AWS reports the target switchover complete.

This is an Aurora-specific state machine. It does not replace the existing RDS
Multi-AZ instance behavior, where target `SWITCHOVER_COMPLETED` may describe only
the writer and reader cleanup must wait for a later topology-table drain.

## 2. Terminology

- **Blue:** The source/current production Aurora cluster before switchover.
- **Green:** The target Aurora cluster before promotion.
- **Canonical hostname/identifier:** The normal production instance name without
  AWS's temporary `-green-<suffix>` component.
- **Green hostname/identifier:** The target instance name containing
  `-green-<suffix>`.
- **Target cluster endpoint:** The TARGET endpoint returned by
  `mysql.rds_topology`. For Aurora, this is a cluster endpoint, not an individual
  writer endpoint.
- **Traffic pin:** A permanent ProxySQL DNS-cache mapping from a canonical blue
  instance hostname to its cached green instance IP.
- **Probe pin:** The cached green writer/cluster IP used by the BGD monitor to
  keep querying topology while canonical blue endpoints are unavailable.
- **Deployment fingerprint:** The TARGET topology identity retained after
  cleanup to suppress repeated handling of the same completed row. At minimum,
  it contains TARGET `id`, endpoint, and port.

## 3. AWS/Aurora Behavioral Contract

The Aurora implementation relies on these properties:

1. `mysql.rds_topology` exposes SOURCE and TARGET cluster endpoints and a
   monotonic status progression:

   ```text
   AVAILABLE
     -> SWITCHOVER_INITIATED
     -> SWITCHOVER_IN_PROGRESS
     -> SWITCHOVER_IN_POST_PROCESSING
     -> TARGET-only SWITCHOVER_COMPLETED
   ```

2. Querying `REPLICA_HOST_STATUS` through the target cluster endpoint returns
   all current target members: exactly one writer and every Aurora reader.
3. The writer is the row whose `SESSION_ID` is `MASTER_SESSION_ID`; the other
   current rows are readers.
4. During post-processing, target `SERVER_ID` values change from temporary
   green identifiers to the canonical production identifiers. Reader
   `SESSION_ID` values remain stable across the rename.
5. `SWITCHOVER_IN_POST_PROCESSING` is the AWS routing barrier. ProxySQL may
   redirect traffic at this status without an additional target-writability
   check.
6. TARGET `SWITCHOVER_COMPLETED` means canonical Aurora writer and reader DNS
   cutover has completed. ProxySQL may remove all traffic pins without a
   separate DNS-resolution verification.
7. The TARGET-only completed row can remain in `mysql.rds_topology` after
   routing cleanup. Repeated completed rows describe the same completed
   deployment and must be ignored until the table drains.

The observed Aurora run supported these assumptions:

- target writer writable: `T+14.438s`;
- target post-processing: `T+15.795s`;
- all target members had canonical `SERVER_ID`s: `T+21.380s`;
- canonical writer/readers accepted fresh connections: by `T+31.212s`;
- TARGET `SWITCHOVER_COMPLETED`: `T+40.655s`;
- topology table drained: `T+65.730s`.

Thus, member cutover completed before TARGET completion; table drain was not a
reader-cutover barrier for Aurora.

## 4. Aurora Detection

The Aurora state machine must be selected only for an Aurora deployment.
Detection must establish both of the following:

1. The TARGET topology endpoint is an Aurora cluster endpoint.
2. `REPLICA_HOST_STATUS` membership discovery succeeds through that endpoint.

The existing Multi-AZ state machine remains active for non-Aurora TARGET
endpoints.

## 5. Membership Discovery

### 5.1 Source of truth

`REPLICA_HOST_STATUS` is the source of truth for target Aurora membership.
Configured green hostgroups are not the source of membership and are not
required for automatic mode.

The discovery query must include at least:

```sql
SELECT
    SERVER_ID,
    SESSION_ID,
    LAST_UPDATE_TIMESTAMP,
    IS_CURRENT
FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS
ORDER BY SERVER_ID;
```

The implementation may retain the existing lag and CPU columns used by the
Aurora monitor.

Only current rows are eligible for the active member snapshot.

### 5.2 Constructing target instance hostnames

The target cluster endpoint has the form:

```text
<green-cluster>.cluster-<rds-domain-suffix>
```

A member hostname is formed as:

```text
<SERVER_ID>.<rds-domain-suffix>
```

For example:

```text
aurora-mysql-1-green-jkpanw.cluster-c1yqcg0ie39o.eu-north-1.rds.amazonaws.com

aurora-mysql-1-writer-green-drodij.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com
```

### 5.3 Building blue/green pairs

For every target member, maintain:

```text
target SERVER_ID
SESSION_ID
role: writer or reader
green hostname
green IP
canonical blue hostname
port
configured blue server attributes
```

Before AWS renames the members, the canonical identifier is obtained by
removing the `-green-<suffix>` component. After AWS renames them, the returned
`SERVER_ID` is already canonical.

The writer pair is correlated by its unique writer role and cached IP. Reader
pairs are additionally correlated across renaming by their stable
`SESSION_ID`s.

There must be exactly one writer pair. Every configured/current blue Aurora
reader must have a corresponding target reader pair before traffic pinning is
performed.

### 5.4 Auto-generated configuration

When `green_writer_hostgroup` and `green_reader_hostgroup` are `NULL`, the BGD
worker must still discover and map the target writer and all target readers in
memory.

The absence of explicit green hostgroups means "no user-managed staging
hostgroups"; it does not mean "no green readers."

The Aurora auto-generated path must not depend on green `mysql_servers` rows and
must not use the writer-only fallback as its normal reader policy.

If the target cluster actually has no readers, the snapshot naturally contains
only the writer. If a membership query fails or yields a transient incomplete
snapshot for a cluster expected to have readers, retain the last complete
snapshot or defer the phase action. Do not reinterpret a failed/incomplete
query as a reader-less deployment.

## 6. IP Resolution and Cached State

During `AVAILABLE`, `SWITCHOVER_INITIATED`, and `SWITCHOVER_IN_PROGRESS`, the
worker must:

1. Query target `REPLICA_HOST_STATUS`.
2. Build or refresh the complete member snapshot.
3. Resolve every green-suffixed member hostname.
4. Cache every member IP independently of DNS TTL expiry during the active
   switchover.
5. Pin topology probing to the cached target writer/cluster IP so monitoring
   survives the canonical endpoint outage and later retirement of green DNS.

Discovery and identity refresh should continue during post-processing because
`SERVER_ID`s are renamed in that phase. Cached pre-rename IPs remain the traffic
pin values.

Worker restart or configuration refresh must preserve enough state to avoid
losing:

- the deployment fingerprint;
- the complete member snapshot;
- cached target IPs;
- applied traffic-pin flags;
- the probe pin;
- terminal completed/drain-wait state.

## 7. Aurora State Machine

### 7.1 States

```text
NONE
AVAILABLE
SWITCHOVER_INITIATED
SWITCHOVER_IN_PROGRESS
SWITCHOVER_IN_POST_PROCESSING
SWITCHOVER_COMPLETED
```

TARGET `SWITCHOVER_COMPLETED` is an event that performs routing cleanup and
enters the internal `SWITCHOVER_COMPLETED` terminal latch; it is not a separate
reader-switchover phase. The runtime
`runtime_mysql_aws_aurora_hostgroups.bgd_status` column exposes these internal
states.

### 7.2 State transitions and actions

| Current observation | Required action | Polling cadence |
|---|---|---|
| No deployment | Remain `NONE`. | Normal discovery cadence |
| `AVAILABLE` | Build complete target membership, resolve all IPs, establish probe pin. | Normal/configured cadence |
| `SWITCHOVER_INITIATED` | Refresh membership/IPs, enable BGD in-progress protection. | Fast cadence |
| `SWITCHOVER_IN_PROGRESS` | Refresh membership/IPs and retain probe pin. | Fast cadence |
| First `SWITCHOVER_IN_POST_PROCESSING` | Apply all traffic pins and drain blue pools. | Fast cadence |
| Repeated `SWITCHOVER_IN_POST_PROCESSING` | Retry only unresolved/unapplied idempotent pair actions. | Fast cadence |
| First TARGET `SWITCHOVER_COMPLETED` | Remove all pins and perform immediate routing cleanup; enter the internal `SWITCHOVER_COMPLETED` latch. | Return to normal/slower cadence |
| Repeated same TARGET `SWITCHOVER_COMPLETED` while waiting | No-op. | Normal/slower cadence |
| Empty/absent table while waiting | Clear terminal fingerprint and return to `NONE`. | Normal discovery cadence |
| Different deployment fingerprint while waiting | Rearm and process the new deployment. | Appropriate new-state cadence |

"Slower cadence" means a larger interval/lower polling frequency than the
active switchover cadence.

## 8. Post-Processing Traffic Redirection

On the first valid, monotonic TARGET
`SWITCHOVER_IN_POST_PROCESSING` observation:

1. Require a complete cached writer/reader map with resolved target IPs.
2. Do **not** issue or wait for an additional writer `read_only` probe.
3. For every pair, pin:

   ```text
   canonical blue hostname -> cached green IP
   ```

4. Drain server connections for every pinned canonical blue hostname.
5. Purge free blue-host connection-pool entries so the next backend connection
   uses the pinned target IP.
6. Keep mapped reader rows eligible in their existing reader hostgroup.

Pinning, draining, and purging must be idempotent per member. A repeated
post-processing observation must not repeatedly drain an already transitioned
member.

### 8.1 Reader policy

The Aurora path must not shun and later unshun readers as part of a normal
switchover. All Aurora readers are discovered from `REPLICA_HOST_STATUS`, mapped,
and pinned together with the writer.

The current writer-fallback behavior for missing green reader pairs remains a
Multi-AZ/instance policy; it is not the Aurora auto-configuration policy.

The BGD in-progress marker must continue to suppress ordinary read-only monitor
actions that would conflict with this state machine.

## 9. Completion and Immediate Cleanup

On the first TARGET-only `SWITCHOVER_COMPLETED` observation, ProxySQL must trust
AWS's completion state and immediately:

1. Remove the DNS-cache pin for every canonical writer and reader hostname.
   `dns_cache->remove()` must invalidate the pinned/local entry so normal DNS
   resolution resumes.
2. Remove the topology probe pin.
3. Stop fast switchover polling.
4. Clear BGD in-progress/read-only-monitor protection.
5. Drain obsolete pools belonging to explicit green hostgroups, subject to the
   configured OFFLINE status preservation policy.
6. Preserve configured `mysql_servers` rows; cleanup concerns runtime routing
   state and pools, not user configuration deletion.
7. Clear the active mapping/resolution state after retaining the minimal
   terminal deployment fingerprint.
8. Enter the internal `SWITCHOVER_COMPLETED` latch.

The completion path must **not**:

- perform a new DNS-resolution verification before removing pins;
- wait for `mysql.rds_topology` to become empty;
- enter `READER_SWITCHOVER_IN_PROGRESS`;
- shun or unshun Aurora readers;
- process the same completed TARGET row more than once.

## 10. `SWITCHOVER_COMPLETED` Terminal Latch

The internal `SWITCHOVER_COMPLETED` state is a terminal latch, not an active
routing phase. All routing cleanup has already completed. It shares the AWS
event name intentionally but persists as ProxySQL runtime state while waiting
for topology drain.

The worker retains only the deployment fingerprint and enough status to
recognize repeated results. While latched:

- the same TARGET `SWITCHOVER_COMPLETED` result is ignored;
- query/connect errors do not cause rollback, repinning, or repeated cleanup;
- polling runs at the normal/slower cadence;
- successful empty results or confirmed table absence release the latch and
  return the worker to `NONE`;
- a different deployment fingerprint may release/reinitialize the latch for a
  new deployment.

Table drain is therefore only the FSM rearm signal. It is not a writer or reader
availability signal for Aurora.

## 11. Rollback Before Completion

If AWS moves backward to `AVAILABLE`, cancels, or otherwise rolls back before
TARGET `SWITCHOVER_COMPLETED`, ProxySQL must undo only actions already applied:

1. Remove applied traffic pins.
2. Remove the probe pin when target monitoring is no longer required.
3. Drain/purge affected canonical pools so subsequent connections follow the
   restored canonical DNS path.
4. Clear BGD in-progress protection.
5. Restore normal hostgroup placement without deleting configured green rows.
6. Clear the active snapshot and rebuild it from the returned topology state.

Rollback actions must be idempotent. Once the worker has entered the internal
`SWITCHOVER_COMPLETED` latch, transient query errors must not be treated as a
rollback.

## 12. Separation from Multi-AZ Instance Logic

The following existing behaviors remain valid for Multi-AZ instance BGD but
must not drive the Aurora branch:

- treating TARGET `SWITCHOVER_COMPLETED` as writer-only completion;
- retaining reader pins until topology drains;
- inferring `READER_SWITCHOVER_IN_PROGRESS`;
- shunning unmapped blue readers;
- routing an empty reader hostgroup through the promoted writer as the normal
  auto-generated fallback.

Aurora has complete cluster membership through `REPLICA_HOST_STATUS`; its
writer and readers are switched and renamed as one cluster operation before the
TARGET completed state.

## 13. Current Implementation Gaps

The existing `aws_rds_bgd_build_map()` assumes the TARGET topology endpoint is
the green writer hostname and adds reader pairs only from an explicitly
configured green reader hostgroup. That assumption does not hold for Aurora:
its TARGET is a cluster endpoint.

The Aurora implementation therefore needs a membership-driven map builder that:

1. connects to the TARGET cluster endpoint;
2. queries `REPLICA_HOST_STATUS`;
3. constructs all member hostnames;
4. creates writer and reader pairs independently of green hostgroup
   configuration;
5. retains stable reader identity across the post-processing rename;
6. applies the Aurora completion/terminal-latch FSM described above.

The existing Multi-AZ builder and reader-cleanup FSM should remain available for
non-Aurora deployments.

## 14. Required Tests

### 14.1 Membership and mapping

- Target cluster endpoint produces one writer and multiple reader pairs.
- Auto mode with NULL green hostgroups still maps all target members.
- Green-suffixed `SERVER_ID`s map to canonical blue hostnames.
- Reader `SESSION_ID`s preserve pair identity after canonical rename.
- A target cluster with no readers produces a valid writer-only snapshot.
- Failed/incomplete membership queries retain the previous complete snapshot or
  defer actions.

### 14.2 FSM

- `AVAILABLE -> INITIATED -> IN_PROGRESS` resolves all target IPs without
  changing traffic.
- First POST_PROCESSING pins and drains every pair exactly once.
- Repeated POST_PROCESSING retries only incomplete pairs.
- No additional writer-writability query gates pinning.
- Mapped readers remain eligible and are not shunned.
- First TARGET COMPLETED removes all pins and performs cleanup immediately.
- Completion does not perform a DNS verification.
- Repeated TARGET COMPLETED is a no-op while drain-wait is latched.
- Empty/absent topology releases the latch and returns to `NONE`.
- Query errors during drain-wait do not rollback or repin.
- A new deployment fingerprint can rearm discovery.

### 14.3 Pool and DNS behavior

- Each canonical blue hostname is pinned to the corresponding target IP.
- Pinning drains/purges old blue connections.
- Removing pins invalidates the local DNS-cache entry.
- Explicit green pools are drained at completion according to status policy.
- Configured rows are preserved.

### 14.4 Resilience

- Worker restart during each active phase preserves cached IPs, pins, and the
  deployment fingerprint.
- Configuration refresh does not lose BGD in-progress protection.
- Rollback before completion removes all applied pins and restores normal
  routing.
- Late entry at POST_PROCESSING builds a complete target snapshot before
  pinning.
- Late entry at TARGET COMPLETED performs cleanup once and enters drain-wait
  without first applying traffic pins.

## 15. Acceptance Criteria

The Aurora implementation is complete when:

1. Auto mode discovers and maps every target Aurora member without configured
   green hostgroups.
2. POST_PROCESSING redirects writer and reader traffic to cached target IPs
   without reader shun/unshun actions.
3. TARGET COMPLETED removes all traffic/probe pins and completes routing cleanup
   without waiting for topology drain.
4. Repeated completed rows cannot retrigger cleanup.
5. Empty/absent topology only rearms the FSM.
6. Multi-AZ instance behavior and tests remain unchanged.
7. TAP coverage verifies normal, repeated, rollback, late-entry, config-refresh,
   and worker-restart paths.
