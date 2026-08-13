# AWS Aurora Blue/Green Cluster Simulator and Testing Design

**Date:** 2026-07-31

**Branch:** `spec/aws-aurora-bgd`

**Status:** Design approved

**Related designs:**

- [Aurora BGD Configuration, Runtime Status, and Cluster Sync](2026-07-31-aurora-bgd-configuration-runtime-cluster-sync-design.md)
- [Aurora BGD Monitor Loop and FSM](2026-07-31-aurora-bgd-monitor-fsm-design.md)

## 1. Scope

This specification defines the simulator services, test controllers, endpoint
model, and executable coverage for AWS Aurora MySQL blue/green deployments.
The related designs remain authoritative for configuration, runtime status,
cluster synchronization, monitor scheduling, FSM transitions, and routing
behavior.

The test environment drives the complete Aurora BGD lifecycle without live AWS
infrastructure and retains regression coverage for ordinary Aurora monitoring
and RDS Multi-AZ BGD.

## 2. Test Architecture

The `cluster_sim_aurora` group contains two complementary test styles:

- `test_cluster_sim_aurora-t` runs JSON-defined ordinary Aurora scenarios
  through the standalone `cluster_simulator` controller;
- interactive TAP binaries drive Aurora BGD phases through the
  `BGD_Simulator` helper.

RDS Multi-AZ BGD TAP binaries remain in `cluster_sim_rds_bgd`. A simulator
group is an execution and CI bucket; simulator capabilities come from the
ProxySQL build, SQLite-server handlers, control tables, and TAP helpers.
Only one test binary controls a given ProxySQL instance at a time, and every
binary owns setup and cleanup for its simulator state.

The group runner enforces that ownership by starting one registered binary,
waiting for it to exit, and only then starting the next binary in sorted order.
Aurora BGD registration checks must retain that serial execution contract. If a
future runner executes binaries concurrently, each binary must receive an
isolated ProxySQL instance and simulator database.

The build contract is:

- `TEST_AURORA` enables ordinary Aurora and Aurora BGD simulation;
- `TEST_RDS_BGD` enables RDS Multi-AZ BGD simulation;
- AWS BGD topology services are available under either flag;
- Aurora replica services are available under `TEST_AURORA`;
- read-only simulation is available to Aurora BGD, RDS BGD, and focused
  read-only simulator builds;
- no separate BGD simulator flag is used.

Aurora monitor queries in simulator builds are the same production queries used
against AWS. The SQLite server identifies the simulated backend from the local
IP and port on which it accepted the monitor connection, then returns the state
assigned to that address.

## 3. AWS BGD Topology Service

Aurora BGD and RDS Multi-AZ BGD use the same simulated
`mysql.rds_topology` service.

### 3.1 `AWS_BGD_CONTROL`

One row controls topology behavior for one backend:

```text
backend_ip TEXT NOT NULL
backend_port INTEGER NOT NULL
topology_present INTEGER NOT NULL DEFAULT 0
    CHECK (topology_present IN (0, 1))
error_code INTEGER NOT NULL DEFAULT 0
error_msg TEXT NOT NULL DEFAULT ''
PRIMARY KEY (backend_ip, backend_port)
```

`topology_present` is restricted to zero or one. A missing control row and a
row with `topology_present=0` both represent an absent topology table. Query
precedence is evaluated independently:

| Query | Control state | Result |
|---|---|---|
| Table check | No row or `topology_present=0` | Successful empty result; `error_code` is ignored. |
| Table check | `topology_present=1` | Successful one-row result; `error_code` is ignored. |
| Metadata | No row | MySQL error 1146. |
| Metadata | `error_code!=0` | Configured MySQL error, including the defensive `topology_present=0` combination. |
| Metadata | `error_code=0`, `topology_present=0` | MySQL error 1146. |
| Metadata | `error_code=0`, `topology_present=1` | Ordered rows, including a successful empty result. |

The helper normally publishes only consistent combinations: error 1146 marks
the table absent, and other errors retain a present table. The defensive matrix
keeps direct control-table writes deterministic.

### 3.2 `AWS_BGD_TOPOLOGY`

Successful topology results are stored as:

```text
backend_ip TEXT NOT NULL
backend_port INTEGER NOT NULL
row_order INTEGER NOT NULL
id TEXT NOT NULL
endpoint TEXT NOT NULL
topology_port INTEGER NOT NULL
role TEXT NOT NULL
status TEXT NOT NULL
PRIMARY KEY (backend_ip, backend_port, row_order)
```

`row_order` makes the result deterministic. Aurora TARGET rows contain a
cluster endpoint; RDS Multi-AZ TARGET rows contain an instance endpoint. The
production monitor identifies the deployment type from the AWS metadata and
membership result rather than from simulator configuration.

### 3.3 `AWS_BGD_PROBE_LOG`

Every topology table check and metadata query records:

```text
sequence_id INTEGER PRIMARY KEY AUTOINCREMENT
backend_ip TEXT NOT NULL
backend_port INTEGER NOT NULL
probe_kind TEXT NOT NULL       # table_check or metadata
encrypted INTEGER NOT NULL
    CHECK (encrypted IN (0, 1))
```

`encrypted` is restricted to zero or one. The monotonic sequence supports
deterministic waits and ordering assertions.

## 4. AWS Aurora Replica Service

### 4.1 Membership sets

`REPLICA_HOST_STATUS` stores each Aurora membership snapshot once:

```text
REPLICA_SET_ID TEXT NOT NULL
SERVER_ID VARCHAR NOT NULL
SESSION_ID VARCHAR NOT NULL
CPU REAL NOT NULL
LAST_UPDATE_TIMESTAMP VARCHAR NOT NULL
REPLICA_LAG_IN_MILLISECONDS REAL NOT NULL
IS_CURRENT INTEGER NOT NULL DEFAULT 1
    CHECK (IS_CURRENT IN (0, 1))
PRIMARY KEY (REPLICA_SET_ID, SERVER_ID)
```

`IS_CURRENT` is restricted to zero or one. It models the AWS column used by the
Aurora BGD membership query to exclude stale or decommissioned members.
Ordinary Aurora payloads default it to one.

`REPLICA_SET_ID` is simulator-only and is never returned to ProxySQL. It groups
one membership snapshot independently of `DOMAIN_NAME`. The simulated table
does not contain `DOMAIN_NAME`; domain configuration remains in
`mysql_aws_aurora_hostgroups` and in the ordinary Aurora JSON input, where it
is used to construct member hostnames.

Blue and green members share the same RDS domain suffix, so a BGD scenario uses
distinct replica-set identifiers for its blue and green snapshots. Multiple
backend addresses can map to the same set. A cluster with N members therefore
stores N membership rows plus lightweight backend mappings, rather than one
copy of the N rows per backend.

### 4.2 `AWS_AURORA_REPLICA_CONTROL`

One row maps a backend address to its replica set and controls the query
response:

```text
backend_ip TEXT NOT NULL
backend_port INTEGER NOT NULL
replica_set_id TEXT NOT NULL
replica_table_present INTEGER NOT NULL DEFAULT 0
    CHECK (replica_table_present IN (0, 1))
error_code INTEGER NOT NULL DEFAULT 0
error_msg TEXT NOT NULL DEFAULT ''
PRIMARY KEY (backend_ip, backend_port)
```

`replica_table_present` is restricted to zero or one. Absence takes precedence
over a configured error. Response behavior is:

- no control row or `replica_table_present=0`: MySQL error 1146, regardless of
  `error_code`;
- present table and nonzero `error_code`: the configured MySQL error;
- present table, no error, and matching rows: return that set;
- present table, no error, and no matching rows: return a successful empty
  result.

Writer-only and intentionally incomplete snapshots are represented directly by
the rows stored for the selected set. No response-mode column is required.
Topology and replica errors remain independent because their controls are in
separate tables.

### 4.3 `AWS_AURORA_REPLICA_PROBE_LOG`

Every intercepted production `REPLICA_HOST_STATUS` query records:

```text
sequence_id INTEGER PRIMARY KEY AUTOINCREMENT
backend_ip TEXT NOT NULL
backend_port INTEGER NOT NULL
replica_set_id TEXT NULL
encrypted INTEGER NOT NULL
    CHECK (encrypted IN (0, 1))
```

The accepted address is logged even when no control mapping exists or the query
returns an error. `replica_set_id` is NULL when the backend has no mapping.

### 4.4 Query handling

Ordinary Aurora and Aurora BGD issue their production-shaped
`REPLICA_HOST_STATUS` queries under `TEST_AURORA`. For a recognized monitor
query, the SQLite handler:

1. reads the accepted backend IP and port;
2. records the probe;
3. reads the matching `AWS_AURORA_REPLICA_CONTROL` row;
4. returns the configured error or rewrites the query to select the mapped
   replica set;
5. preserves the production query's result columns, filtering, and ordering.

The ordinary Aurora query retains its timestamp, lag, and writer filtering.
The Aurora BGD query retains `IS_CURRENT` and `SERVER_ID` ordering. Other SQL
against the simulator tables executes normally so controllers can publish
state.

## 5. State Publication

### 5.1 Ordinary Aurora controller

Ordinary Aurora JSON files retain their current schema. For each Aurora cluster,
the standalone `cluster_simulator` controller:

1. uses the JSON `DOMAIN_NAME` value as the replica-set identifier;
2. constructs each member hostname from `SERVER_ID` and `DOMAIN_NAME`;
3. reads `CLUSTER_SIM_HOST_FILE` to resolve those fixed simulator hostnames to
   loopback IPs;
4. writes the membership rows with a current timestamp and `IS_CURRENT=1`;
5. maps every backend that can serve the cluster membership to the same set in
   `AWS_AURORA_REPLICA_CONTROL`;
6. commits the membership replacement and complete backend mapping atomically.

The group environment already supplies `CLUSTER_SIM_HOST_FILE`; test
infrastructure uses it to populate the ProxySQL container's host map, and the
controller uses the same file as the authoritative hostname-to-IP mapping. A
configured or discovered member missing from that map is a test-setup failure.

### 5.2 Aurora BGD controller

Interactive Aurora BGD TAP tests publish state through `BGD_Simulator`. Each
membership publication supplies:

- one stable replica-set identifier;
- one membership snapshot;
- every cluster endpoint or member backend that must return that snapshot.

The helper replaces the set rows and complete backend mapping in one
transaction. Blue and green use separate identifiers. Tests do not store a
blue/green flag and do not infer environment identity from hostnames.

The same helper publishes topology rows, topology errors, replica errors,
read-only state, and probe-log checkpoints. Non-1146 errors change only control
state, so clearing them exposes the retained data. An absent topology table
clears topology rows for the addressed backend, matching the topology service's
backend-scoped storage. An absent replica table preserves its shared membership
set because other backend mappings may still serve that set.

### 5.3 Helper boundaries

`BGD_Simulator` owns cross-service mechanics: SQL transactions, topology and
replica controls, read-only controls, probe-log reads and waits, endpoint
predicates, and cleanup.

Deployment models remain engine-specific. `RDS_BGD_Cluster` and related RDS
types describe RDS instance topology. Aurora types describe cluster endpoints,
members, replica sets, rename identity, and expected runtime placement.

### 5.4 Cleanup

Set-scoped operations remove only the supplied replica set and backend
mappings. Full scenario cleanup clears:

```text
READONLY_STATUS
AWS_BGD_CONTROL
AWS_BGD_TOPOLOGY
AWS_BGD_PROBE_LOG
AWS_AURORA_REPLICA_CONTROL
AWS_AURORA_REPLICA_PROBE_LOG
REPLICA_HOST_STATUS
```

Each TAP binary begins and ends with full cleanup. Sequential group execution
is expected, but correctness does not depend on a later test overwriting stale
state.

## 6. Endpoint Model

`cluster_sim_aurora/add-hosts` contains fixed aliases for:

- canonical blue cluster members;
- the green target cluster endpoint returned by `mysql.rds_topology`;
- green target writer and reader members;
- canonical post-switchover member names;
- repeated deployments and concurrent test clusters.

Independently controlled backends use distinct loopback IPs. Green and
canonical aliases may share an IP where the scenario represents AWS resource
renaming. Response selection always uses the accepted IP and port, not the
requested hostname.

The fixed host map does not model mutable Route 53 propagation. DNS-related
tests assert cached-IP pins, accepted backend addresses, connection-pool
behavior, and explicit pin removal.

## 7. Test Coverage

### 7.1 Simulator contracts

Focused tests cover:

- table schemas, primary keys, defaults, and value constraints;
- topology and replica routing by accepted backend address;
- several backend addresses sharing one replica set;
- independent blue and green sets with overlapping `SERVER_ID` values;
- production-query result shape, filtering, and ordering;
- atomic membership and mapping replacement;
- successful complete, writer-only, incomplete, and empty results;
- missing tables and arbitrary MySQL errors;
- table-present/error precedence matrices for topology table-check, topology
  metadata, and replica membership queries;
- independence of topology and replica errors;
- TLS state and ordered probe logging;
- `CLUSTER_SIM_HOST_FILE` parsing and missing-host failures;
- set-scoped deletion and full cleanup.

### 7.2 Configuration, runtime, and cluster synchronization

Tests owned by the configuration design cover:

- configuration and runtime table schemas and column order;
- paired-NULL and hostgroup-conflict validation;
- config-file, memory, runtime, and disk round trips;
- runtime-only `bgd_status` initialization and preservation;
- exclusion of `bgd_status` from SAVE and cluster synchronization;
- synchronization of the configured green hostgroups, including NULL;
- independent node-local runtime status on cluster peers.

### 7.3 Interactive Aurora BGD scenarios

Interactive TAP tests cover:

1. `AVAILABLE` discovery of the target writer and all current readers through
   a complete target membership snapshot.
2. Green hostgroups configured and green hostgroups not configured, with all
   Aurora hostgroup rows created by the test.
3. Independent topology, target-membership, and ordinary Aurora probes with the
   cadence and on/off behavior defined by the monitor/FSM design, including
   random blue-member topology probes and random green-member target probes.
4. `SWITCHOVER_INITIATED`, `SWITCHOVER_IN_PROGRESS`, and
   `SWITCHOVER_IN_POST_PROCESSING` state retention and retry behavior.
5. Source-writer read-only observation and the corresponding writer-to-reader
   placement.
6. Target member `SERVER_ID` rename with stable reader `SESSION_ID` identity
   and retained cached IPs.
7. Idempotent per-member pinning, placement, and pool-drain actions.
8. The first TARGET-only `SWITCHOVER_COMPLETED`, immediate cleanup, terminal
   latch, and runtime `bgd_status='SWITCHOVER_COMPLETED'`.
9. Repeated completion observations, successful topology drain to `NONE`, and
   rearming for a different deployment fingerprint.

### 7.4 Resilience and lifecycle scenarios

Coverage also includes:

- zero-reader targets and membership row ordering;
- incomplete snapshots retaining the last complete target set;
- topology, replica, and read-only query failures in each relevant phase;
- rollback from initiated, in-progress, and post-processing states;
- late entry at initiated, in-progress, post-processing, and completed states;
- configuration and hostgroup refresh during an active deployment;
- in-place worker configuration refresh with retained deployment state;
- deleting or deactivating an Aurora row during switchover;
- ONLINE, SHUNNED, OFFLINE_SOFT, and OFFLINE_HARD staging-pool members;
- TLS selection for topology and replica probes;
- repeated and concurrent Aurora deployments with isolated state.

### 7.5 Regression suites

The complete ordinary Aurora JSON suite runs through the production query path
and retains its role, failover, lag, autodiscovery, and autopurge expectations.

The RDS Multi-AZ BGD TAP suite retains its instance-target, reader policy,
writer fallback, completion, and topology-drain expectations while using the
shared `BGD_Simulator` and `AWS_BGD_*` services.

## 8. Determinism and Diagnostics

Tests synchronize on observable state: probe sequence, runtime `bgd_status`,
server placement, pool counters, and committed simulator controls. Timeouts are
derived from configured monitor intervals with bounded slack.

Fixed sleeps are permitted only for bounded negative assertions with no event
that can be awaited directly. A failed wait reports the latest runtime row,
relevant server and pool state, and probes observed since the scenario
checkpoint.

Random probe-selection tests do not assert one exact random order. They assert
that every observed destination belongs to the scenario's eligible set and
that fallback reaches another eligible member within a bounded number of
attempts. Failure diagnostics include the complete probe sequence since the
scenario checkpoint, so production randomness cannot make the expected result
order-dependent.

Scenarios use disjoint hostgroups, endpoints, replica-set identifiers, and
deployment fingerprints, or perform full cleanup before reuse.

## 9. Build and CI Contract

`make testaurora` produces the focused Aurora simulator build, including the
Aurora replica, shared BGD topology, and read-only services. `make test_rds_bgd`
produces the focused RDS BGD build. The combined `testall` build enables both
families.

Ordinary Aurora and Aurora BGD binaries register in
`cluster_sim_aurora-g1`. RDS Multi-AZ BGD binaries register in
`cluster_sim_rds_bgd-g1`. Central simulator CI discovers groups and binaries
from `groups.json`, so no additional workflow, simulator group family, or CI
infrastructure is required.

CI must continue to invoke the group through the serial group runner described
in Section 2. Registration coverage verifies that every Aurora BGD binary is in
that group and is not scheduled simultaneously against the same ProxySQL
instance.

## 10. Non-Goals

The simulator does not validate:

- AWS control-plane APIs or real AWS timing;
- mutable Route 53 propagation;
- application-level latency or packet loss;
- cross-process persistence of transient FSM state;
- Aurora versions that violate the AWS-provided topology-status contract.

The AWS-provided topology metadata semantics define the status-to-routing
contract. Live-AWS evidence remains the validation layer for observed status
ordering, member rename, DNS completion, and corroboration of the writability
transition.

## 11. Acceptance Criteria

The design is satisfied when:

1. Ordinary Aurora and Aurora BGD use production monitor queries and the same
   backend-address-to-replica-set service.
2. Blue and green membership snapshots are stored once and returned from every
   mapped backend.
3. The complete Aurora BGD FSM and its failure paths run deterministically
   without live AWS infrastructure.
4. Runtime status, routing, pools, cached IPs, probes, refresh, and cluster-sync
   contracts have observable assertions.
5. Ordinary Aurora and RDS Multi-AZ BGD regressions retain their semantics.
6. The suite uses the existing Aurora and RDS simulator CI groups without a
   separate feature flag or simulator family.
