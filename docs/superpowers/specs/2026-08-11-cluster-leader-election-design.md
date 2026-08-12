# ProxySQL Cluster Leader Election — Design

Date: 2026-08-11
Status: approved for planning
Scope: first deliverable of the "cluster as a single entity" effort — liveness,
deterministic leader election, and read-only config steering.

## Motivation

Users increasingly want a ProxySQL cluster to behave as a single entity:
query stats for all nodes in one place, configure all nodes at once, and have
nodes be aware of each other (e.g. split a cluster-wide `max_connections`
budget across N proxies).

Most building blocks already exist:

- **ProxySQL Cluster** propagates configuration (pull-based, checksum/epoch,
  highest-epoch-wins) and gives nodes awareness of each other
  (`proxysql_servers`, per-peer monitor threads).
- **TSDB** stores time-series stats per node; every node exposes a
  Prometheus `/metrics` endpoint.
- **Admin read-only mode** (`admin_read_only`, `PROXYSQL READONLY` /
  `PROXYSQL READWRITE`) refuses admin writes while cluster sync — which
  writes through `GloAdmin->admindb` internally, not through an admin
  session — is unaffected by construction. It was designed for exactly this
  role and only needed the glue.

The missing glue is a **leader**: one node that is by convention the
configuration write point and (in a follow-up) the stats aggregator.

## Decision: no Raft / no consensus

The cluster stays AP (available under partition), by explicit requirement:
an operator must always be able to log into any reachable node and repair or
tear down a broken cluster. Quorum-based consensus (Raft) would refuse
writes on a minority side — hostile to the recovery story — and would break
the very common 2-node deployment (no quorum after a single failure).

None of the target problems needs consensus:

- Config propagation already tolerates forks and reconciles via epochs.
- Stats aggregation is read-only fan-in.
- Quota division needs membership/liveness, not agreement.

Therefore: **deterministic, ballot-free, locally-computed leader election**,
advisory in nature, with epochs remaining the reconciliation mechanism.
During partitions, transient multi-leader (or no-leader) states are accepted;
the consequences are bounded to today's semantics (both sides writable) or a
safe state (all read-only, operator can override).

## Design

### 1. Liveness / membership

- Each node already polls every peer with `SELECT GLOBAL_CHECKSUM()` every
  `admin-cluster_check_interval_ms` from its per-peer monitor thread
  (`lib/ProxySQL_Cluster.cpp`, monitor loop). Record the outcome:
  `ProxySQL_Node_Entry` gains a `last_success_at` timestamp (monotonic,
  updated on every successful poll).
- A peer is **alive** iff `now - last_success_at <
  admin-cluster_leader_node_timeout_ms`. Self is always alive.
- Membership candidates = rows of `runtime_proxysql_servers` (already a
  cluster-synced module, so the candidate set converges). A node not listed
  there can never become leader.
- No new network traffic, threads, or protocol messages, except for one
  extra round-trip per connection establishment: after the version/announce
  handshake, the monitor thread issues `SELECT GLOBAL_UUID()` on the peer to
  learn its UUID (used as the election tiebreaker).

### 2. Election

- **Leader = the alive candidate with the highest `weight` in
  `proxysql_servers`; ties broken by lowest UUID.** The `weight` column
  (synced, exposed, currently semantics-free) finally gets meaning. Existing
  deployments have weight 0 everywhere, degenerating to UUID ordering —
  deterministic, if arbitrary; operators who care set weights.
- Each node computes the leader **locally** from its own membership view.
  No ballots, no votes, no election messages, no persistent election state.
- An election evaluation tick runs from the Admin main loop (same pattern as
  the TSDB loops). Hysteresis: a leadership *change* takes effect only after
  the new result has been stable for `admin-cluster_leader_grace_ms`
  (protects against poll blips and monitor-thread scheduling jitter).
- Transient disagreement between nodes during churn is accepted. Bounded
  consequences: two nodes briefly effective-RW (today's permanent state), or
  all nodes briefly effective-RO (safe; operator override exists).
- **Opt-in**: `admin-cluster_leader_election` defaults to `false`. Off means
  bit-for-bit today's behavior. Rolling upgrade story: upgrade all nodes,
  then enable the variable cluster-wide (it is part of the synced
  `admin_variables` module).

### 3. Read-only steering

Admin read-only becomes a tri-state `admin_ro_mode`: `AUTO` / `FORCED_RO` /
`FORCED_RW`.

- **Effective read-only** = (`AUTO` && election enabled && not leader)
  || `FORCED_RO`.
- With election disabled, `AUTO` means read-write — existing semantics
  unchanged (today's boolean default is read-write).
- Election transitions only influence the effective value while in `AUTO`;
  they never touch a `FORCED_*` state. An operator's override therefore
  survives election ticks — required for partition-recovery scenarios.
- Commands:
  - `PROXYSQL READWRITE` → `FORCED_RW` (the recovery escape hatch)
  - `PROXYSQL READONLY`  → `FORCED_RO`
  - `PROXYSQL READONLY AUTO` (new) → `AUTO` (return control to election)
  - Restart resets to `AUTO`, unless `admin-read_only=true` maps the boot to
    `FORCED_RO` (see below).
- The existing `admin-read_only` boot variable maps onto the tri-state:
  `true` → boot in `FORCED_RO`, `false` (default) → boot in `AUTO`. Its
  current semantics (boot read-only until an operator lifts it) are
  preserved exactly.
- Boot with election enabled: start in `AUTO` (effective-RO) until the first
  election settles; a standalone or election-disabled node boots effective-RW
  as today.

**Enforcement gap closed.** Today `get_read_only()` is only enforced on the
generic admin-session SQL path (`PRAGMA query_only = ON` wrapper in
`lib/Admin_Handler.cpp`); `LOAD ... TO RUNTIME` and `SAVE ... TO DISK` are
not gated — yet `LOAD ... TO RUNTIME` is precisely the epoch-bumping
operation that creates sync conflicts. Effective read-only additionally
refuses all `LOAD <module> TO RUNTIME` and `SAVE <module> TO DISK` admin
commands with an error naming the current leader (hostname:port), e.g.:

    ERROR 1045: Admin is in read-only mode (follower). Current leader is
    10.0.0.5:6032. Use PROXYSQL READWRITE to override.

Cluster-initiated pulls are unaffected: they write via `GloAdmin->admindb`
directly from `pull_*_from_peer()` and never traverse the admin session
handler.

### 4. Observability

- **Implement `stats_proxysql_servers_status`** (schema defined since v1.4,
  never populated; `include/ProxySQL_Admin_Tables_Definitions.h:289`). One
  row per candidate node, from this node's local view: `hostname`, `port`,
  `weight`, `master` (`'YES'`/`'NO'` — the long-dormant column becomes the
  leader flag), `global_version`, `check_age_us` (time since last successful
  poll), `ping_time_us`, `checks_OK`, `checks_ERR`. Add a `uuid VARCHAR`
  column (stats tables are not persisted; schema change is safe) since UUID
  is the election tiebreaker.
- Prometheus: gauge `proxysql_cluster_leader_status` (1 if this node
  considers itself leader, else 0); per-peer `alive` gauge on the existing
  dynamic cluster-node families; counter
  `proxysql_cluster_leader_changes_total`.
- `proxy_info` on every leadership transition and every state change of
  `admin_ro_mode`; `proxy_warning` on every refused write/LOAD/SAVE in
  effective-RO (rate-limited).

### 5. New variables and gating

| Variable | Default | Notes |
|---|---|---|
| `admin-cluster_leader_election` | `false` | Master switch. Registered only under `#ifdef PROXYSQL31`. |
| `admin-cluster_leader_node_timeout_ms` | `3000` | Liveness horizon; floor 1000. Should be ≥ 3× `cluster_check_interval_ms` in practice (documented, not enforced). |
| `admin-cluster_leader_grace_ms` | `3000` | Stability window before acting on a leadership change. |

**Tier gating strategy:** all election/liveness/tri-state code compiles
unconditionally in every tier; only the **registration of
`admin-cluster_leader_election`** (and its config-file/default handling) is
wrapped in `#ifdef PROXYSQL31`. In the Stable tier the variable does not
exist, so the feature cannot be enabled. Rationale: keeps the `#ifdef`
surface to a few lines, avoids the FFTO-style stale-object/tier-mismatch
link failures, and keeps the election logic unit-testable in all tiers.
The two tuning variables are registered unconditionally (harmless without
the master switch).

### 6. Edge cases

- **Fully isolated node**: sees only itself alive; if it is a candidate it
  elects itself → effective-RW. Deliberate: a partitioned node degrades to
  standalone ProxySQL behavior. Two partitioned halves each elect a leader;
  healed by epoch reconciliation exactly as today.
- **All peers alive but node is not in `proxysql_servers`**: it cannot be
  leader; it follows whichever candidate it computes as leader.
- **`proxysql_servers` empty or cluster credentials unset**: election
  short-circuits; node behaves as standalone (`AUTO` → effective-RW).
- **Mixed versions during rolling upgrade**: old nodes ignore the new
  variables; the cluster already refuses to sync across differing versions
  (`SELECT @@version` gate), so no compatibility machinery is needed.
- **Operator changes `weight` at runtime**: takes effect on the next
  election tick after the `proxysql_servers` change syncs; grace window
  applies, so a planned leader move is: raise weight on the target, load to
  runtime on the current leader, wait one grace period.

### 7. Testing

- **Unit test** (`test/tap/tests/unit/`, against `libproxysql.a`): the pure
  election function — (candidate set, liveness map, weights, UUIDs) →
  leader — including ties, empty candidate set, self-not-candidate, and
  timeout boundary conditions.
- **TAP test** (isolated infra, 3-node ProxySQL cluster):
  1. Enable election; assert exactly one leader converges and
     `stats_proxysql_servers_status` agrees on all three nodes.
  2. Followers refuse `INSERT`, `LOAD MYSQL SERVERS TO RUNTIME`,
     `SAVE MYSQL SERVERS TO DISK`; leader accepts all three.
  3. Kill the leader container; next-ranked node becomes leader within
     `node_timeout + grace`; config writes succeed there.
  4. `PROXYSQL READWRITE` on a follower sticks across ≥ 2 election ticks;
     `PROXYSQL READONLY AUTO` restores follower-RO.
  5. Restart the old leader; since it retains the highest `weight`, it
     retakes leadership on rejoin (weight-priority retake) — the previous
     leader's replacement steps back down to follower, no flapping.
  6. Election disabled: all nodes effective-RW (regression guard).

## Out of scope (each needs its own design round)

1. **Stats aggregation into the leader's TSDB** — next deliverable. The
   leader scrapes peers' `/metrics` (or `stats_*` tables over the existing
   admin connections) and ingests into TSDB with a per-node label; the TSDB
   query API already supports arbitrary label filters.
2. **Distributed quotas** (cluster-wide `max_connections` split by the
   alive-count) — needs hysteresis/flapping design on the admission path.
3. **Leader-only backend monitoring** (semantic checks on the leader,
   local reachability checks everywhere) — has availability-path
   implications (correlated failures, vantage-point loss, cold-start of a
   new leader's monitor) that require dedicated design.
