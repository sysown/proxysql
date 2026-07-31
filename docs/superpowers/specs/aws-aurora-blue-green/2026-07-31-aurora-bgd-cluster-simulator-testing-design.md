# Aurora BGD Cluster Simulator and Testing Design

**Date:** 2026-07-31

**Branch:** `plan/aurora-bgd`

**Status:** Design draft

**Related designs:**

- [Aurora BGD Configuration, Runtime Status, and Cluster Sync](2026-07-31-aurora-bgd-configuration-runtime-cluster-sync-design.md)
- [Aurora BGD Monitor Loop and FSM](2026-07-31-aurora-bgd-monitor-fsm-design.md)

## Spec Boundary

This specification owns the simulator capabilities and executable test coverage
needed to validate the other two specifications. It does not redefine public
configuration or FSM behavior. When a test expectation depends on those
contracts, the corresponding sibling specification is authoritative.

## 1. Purpose

Provide deterministic coverage for Aurora MySQL blue/green deployments without
requiring live AWS infrastructure. The test environment must be able to drive
the complete BGD observation sequence, publish target Aurora membership,
simulate member renaming, inject failures, observe monitor probes, and verify
ProxySQL runtime and routing effects.

The design must preserve both existing regression suites:

- the ordinary Aurora cluster simulator continues validating Aurora role,
  membership, lag, failover, and autopurge behavior;
- the RDS Multi-AZ BGD suite continues validating its existing instance-based
  mapping and reader-cleanup FSM.

## 2. Architecture Decision

Aurora BGD FSM tests extend the existing interactive RDS BGD simulator used by
`cluster_sim_rds_bgd-g1`. They do not add BGD sequencing to the legacy JSON
Aurora simulator.

This is the preferred design because the RDS BGD simulator already provides:

- per-backend `mysql.rds_topology` responses;
- empty, absent, and error topology modes;
- read-only controls;
- ordered probe logging;
- fixed AWS-style hostname-to-loopback mappings;
- TAP-driven, phase-by-phase transitions;
- the build and CI integration required for BGD tests.

Aurora adds a target-cluster membership service and Aurora-specific TAP helpers
on top of that base. Shared topology, transaction, endpoint, TLS, read-only,
probe-wait, and cleanup behavior remains common.

### Alternatives not selected

1. Extending the JSON Aurora simulator with a long sequence of BGD states would
   overload a batch-oriented two-state model and make late entry, retry,
   rollback, and concurrent timing difficult to control.
2. Creating a third standalone simulator group would duplicate the existing RDS
   BGD topology service, host maps, helpers, build flavor, and CI wiring.
3. Using only unit tests would not exercise monitor threads, DNS pins,
   connection-pool drains, runtime status publication, or config reloads.

## 3. Simulator Service Contract

The `TEST_RDS_BGD` SQLite3-server flavor remains the executable backend for the
interactive suite. It is extended to recognize the Aurora membership query in
addition to the existing topology and read-only queries.

All simulated responses are keyed by the backend address and port on which the
SQLite3 server accepted the monitor connection. This preserves isolation when
multiple deployments or multiple target endpoints are active concurrently.

### 3.1 Existing topology service

The existing service remains authoritative for:

```text
mysql.rds_topology table presence
SOURCE and TARGET rows
deployment fingerprint fields
AWS status strings
configured topology errors
ordered table-check and metadata probe logs
```

Aurora TARGET rows contain a cluster endpoint. Multi-AZ TARGET rows continue to
contain an instance endpoint. The simulator must not infer deployment type from
test configuration; production detection consumes the endpoint shape and the
membership-query result.

### 3.2 Aurora membership service

The simulator adds per-backend control and row storage for
`INFORMATION_SCHEMA.REPLICA_HOST_STATUS`.

Each membership row contains at least:

```text
row_order
SERVER_ID
SESSION_ID
LAST_UPDATE_TIMESTAMP
IS_CURRENT
CPU
REPLICA_LAG_IN_MILLISECONDS
```

`SESSION_ID='MASTER_SESSION_ID'` identifies the writer. Other current rows are
readers. `row_order` makes response ordering deterministic while allowing tests
to prove that ProxySQL does not rely on writer-first or lexical membership
ordering.

The control state supports:

- a successful complete membership result;
- a successful writer-only result;
- an intentionally incomplete result;
- an empty result;
- table absence/error 1146;
- an arbitrary MySQL error code and message.

Membership updates are atomic per supplied set of backends. A test must not
expose a partially rewritten snapshot unless it explicitly selects the
incomplete-result mode.

### 3.3 Probe log

The existing BGD probe log adds an Aurora-membership probe kind. Every topology
table check, topology metadata query, and target membership query records:

```text
monotonic sequence
accepted backend IP
accepted backend port
probe kind
TLS state
```

Tests use the log to verify probe destination, ordering, cadence class, TLS,
probe-pin retention, and return to canonical probing. They must not use fixed
sleeps when an observable probe or runtime state can serve as the wait
condition.

### 3.4 Error isolation

Topology and membership errors are independent. A scenario can publish valid
topology with failed membership, or valid membership with failed topology.
Clearing one error source must not silently clear the other.

Simulator cleanup removes topology, membership, read-only, and probe-log state
in one operation so each TAP binary begins from a known baseline.

## 4. TAP Helper Model

Aurora-specific helpers extend, rather than fork, the RDS BGD helper model.
They provide test-facing representations for:

- a blue Aurora cluster and its canonical instance endpoints;
- a target cluster endpoint;
- one target writer and zero or more target readers;
- stable member session identities;
- pre-rename green `SERVER_ID` values;
- post-rename canonical `SERVER_ID` values;
- explicit and automatic Aurora hostgroup configuration;
- expected runtime `bgd_status` values.

The helper API exposes operations equivalent to:

```text
publish topology status
publish target membership snapshot
publish renamed membership snapshot
publish empty/absent topology
inject topology or membership error
record and wait for probes
query Aurora runtime row and bgd_status
query runtime server placement and status
query connection-pool state
open backend traffic and identify accepted simulator IP
clean up ProxySQL and simulator state
```

Helper methods perform control operations only. Individual test scenarios own
the sequence of AWS observations and all expected ProxySQL outcomes.

## 5. Endpoint and DNS Model

The `cluster_sim_rds_bgd-g1` fixed host map is extended with Aurora cluster
endpoints and member endpoints. Each hostname maps to a distinct loopback
address accepted by the same SQLite3 server.

The map includes, per test cluster:

- canonical blue writer and reader instance names;
- the green target cluster endpoint returned by `mysql.rds_topology`;
- green-suffixed target writer and reader instance names;
- canonical post-rename member names;
- a second target deployment for repeated-switchover coverage;
- additional clusters for concurrency coverage.

Green and canonical names used for identity-renaming tests may resolve to the
same target-member loopback IP where that models AWS's post-processing rename.
Canonical blue DNS remains static in the container; DNS-cache pin behavior is
verified through accepted backend addresses and explicit pin removal, not by
claiming that the simulator reproduces mutable Route 53 propagation.

## 6. Test Layers

### 6.1 Schema and unit coverage

Fast tests cover deterministic contracts that do not require monitor threads:

- configuration and runtime table definitions and column order;
- paired-NULL and hostgroup-conflict validation;
- SQL NULL preservation in bind/extract helpers;
- config-file import and export;
- disk schema upgrade defaults;
- runtime `bgd_status` string mapping;
- configured-column cluster query and checksum projection;
- exclusion of `bgd_status` from SAVE and cluster synchronization;
- Aurora simulator JSON parsing of the two optional green hostgroups.

### 6.2 Admin and cluster-sync integration coverage

Admin/TAP tests cover:

- memory-to-runtime and runtime-to-memory round trips;
- runtime-to-disk and config-file round trips;
- new runtime rows starting at `NONE`;
- reload preservation of `bgd_status` and active worker state;
- removal and deactivation behavior;
- peer synchronization of both green hostgroups, including NULL;
- proof that peers retain independent node-local `bgd_status` values;
- unchanged RDS Multi-AZ BGD cluster synchronization.

### 6.3 Interactive Aurora BGD coverage

The interactive suite covers the observable behavior of the monitor/FSM spec:

1. `AVAILABLE` discovers exactly one writer and every reader, resolves each
   member, and establishes only the probe state required by the design.
2. Automatic mode with NULL green hostgroups maps all target members without
   generating green hostgroups or `mysql_servers` rows.
3. Explicit mode uses configured green hostgroups as staging pools but still
   treats `REPLICA_HOST_STATUS` as membership truth.
4. Initiated and in-progress observations retain the complete snapshot and
   engage BGD/read-only-monitor protection.
5. The first post-processing observation pins and drains each writer/reader pair
   once; repeated observations retry only incomplete member actions.
6. Member `SERVER_ID` rename preserves reader identity through stable
   `SESSION_ID` values and does not change cached target IPs.
7. The first TARGET `SWITCHOVER_COMPLETED` removes all traffic and probe pins,
   performs cleanup once, and publishes `bgd_status='SWITCHOVER_COMPLETED'`.
8. Repeated completed rows are no-ops; successful topology drain changes the
   runtime status to `NONE` and rearms discovery.
9. A different deployment fingerprint can rearm from the terminal latch without
   inheriting stale members, pins, probes, or completion flags.

### 6.4 Resilience and edge coverage

Scenarios also cover:

- membership row ordering and zero-reader target clusters;
- incomplete membership retaining the last complete snapshot;
- topology and membership query failures in every phase;
- rollback from initiated, in-progress, and post-processing observations;
- late entry at initiated, in-progress, post-processing, and completed states;
- config refresh and hostgroup refresh during active phases;
- worker restart/respawn with preserved fingerprint, members, IPs, pins, and
  terminal latch;
- disabling automatic discovery during an active automatic deployment;
- deleting or deactivating an Aurora row during a switchover;
- explicit green-pool cleanup with ONLINE, SHUNNED, OFFLINE_SOFT, and
  OFFLINE_HARD members;
- TLS selection for topology and membership probes;
- multiple concurrent Aurora deployments with independent state;
- simultaneous Aurora BGD and RDS Multi-AZ BGD deployments.

## 7. Regression Coverage

The existing `test_cluster_sim_aurora-t` JSON payload suite remains responsible
for ordinary Aurora behavior. Its schema accepts the two new green hostgroup
fields as optional values but old payloads remain valid and preserve their
existing results.

The complete existing `test_rds_bgd_*` suite remains unchanged in semantics.
Aurora membership support is additive to the shared simulator and must not
alter instance TARGET handling, reader shun/unshun policy, writer fallback, or
Multi-AZ completion/drain behavior.

Regression runs must include:

```text
ordinary Aurora cluster simulator group
RDS Multi-AZ BGD simulator group
new Aurora BGD TAP binaries in cluster_sim_rds_bgd-g1
configuration/unit tests
ProxySQL Cluster synchronization tests
```

## 8. Determinism and Timing

Tests synchronize on observable state: runtime `bgd_status`, probe sequence,
server placement, pool counters, and successful simulator control commits.
Timeouts are derived from configured monitor intervals with bounded slack.

Fixed sleeps are allowed only for negative assertions where no event can be
awaited directly, and must be shorter than the overall TAP timeout. Every wait
failure reports the last runtime row, relevant server/pool state, and probes
observed since the scenario checkpoint.

Each scenario uses unique hostgroups or performs complete cleanup. Concurrent
tests use disjoint endpoints and deployment fingerprints.

## 9. Build and CI Contract

The existing `test_rds_bgd` build remains the focused local build. The combined
cluster-simulator build continues compiling both `TEST_AURORA` and
`TEST_RDS_BGD` support.

New interactive TAP binaries register in `cluster_sim_rds_bgd-g1`, which keeps
the existing fixed-host injection, SQLite3-server startup, no-backend-infra
model, CI matrix discovery, and log collection. No new workflow or simulator
group is required.

## 10. Non-Goals

The simulator does not claim to validate:

- AWS control-plane APIs or real AWS timing;
- mutable Route 53 propagation;
- application-level latency or packet loss;
- cross-process persistence of transient FSM state;
- behavior of Aurora versions that violate the AWS contract in the monitor/FSM
  specification.

Live-AWS evidence remains a separate validation layer for assumptions about
status ordering, member rename, writability, and DNS completion.

## 11. Acceptance Criteria

The simulator/testing design is satisfied when:

1. Tests can independently control topology and target membership per backend.
2. The full Aurora BGD FSM can be driven without live AWS infrastructure.
3. Runtime status, routing, pool, DNS-pin, probe, reload, and cluster-sync
   contracts have deterministic assertions.
4. Automatic and explicit modes both cover writer and all-reader membership.
5. Rename, rollback, late-entry, error, refresh, repeated, and concurrent paths
   are covered.
6. Existing ordinary Aurora and RDS Multi-AZ BGD suites retain their semantics.
7. The suite runs through existing cluster-simulator build and CI plumbing with
   no new infrastructure group.
