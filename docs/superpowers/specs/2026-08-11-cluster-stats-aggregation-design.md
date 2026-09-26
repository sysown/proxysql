# Cluster Stats Aggregation into the Leader's TSDB — Design

Date: 2026-08-11
Status: approved for planning
Depends on: cluster leader election (PR #6034, `docs/superpowers/specs/2026-08-11-cluster-leader-election-design.md`). Branch stacked on `feat/cluster-leader-election`; rebase onto `v3.0` after #6034 merges.

## Motivation

Second deliverable of the "cluster as a single entity" effort: query statistics
for all proxies in one place. The leader (from the election feature) becomes
the stats aggregator — a single pane of glass over the whole cluster — without
making any node's local metrics depend on who leads.

## Decision: TSDB replication over the admin channel (pull + watermark)

Chosen over (a) HTTP scraping of peers' `/metrics` (live-only view: history
starts at leadership acquisition, partitions leave permanent gaps, requires
the REST API enabled everywhere and a new HTTP-client path) and (b) follower
push (multi-writer leader DB, follower-side buffering for catch-up, deposed
leader keeps receiving writes). Pull + watermark is idempotent and
restart-safe: leadership changes, restarts, and network blips all reduce to
"catch up from where the table says I am."

Load-bearing verified fact: a peer's TSDB tables are directly queryable over
the existing authenticated admin channel as `stats_history.tsdb_metrics`
(the `proxysql_stats.db` file is attached to admin sessions as the
`stats_history` schema).

**Durability promise (user requirement):** replicated history. Every node
keeps sampling its own TSDB locally (7-day retention, leader-independent);
the leader's aggregated view backfills from peers' local retention, so a
leader failover produces no gaps in the cluster view.

## Design

### 1. Architecture

- Local TSDB pipeline (5s sampler → `tsdb_metrics`, hourly rollups,
  retention) is untouched on every node and remains the durable source of
  truth.
- New component: **TSDB aggregator** in `ProxySQL_Statistics`, active only
  while `GloProxyCluster->is_leader()` AND election enabled AND
  `tsdb-enabled` AND `tsdb-cluster_aggregation=true`.
- Runs on a **dedicated thread** (pulls can take seconds during backfill).
  The Admin main-loop tick only starts/stops the thread on leadership or
  variable transitions (same `*_timetoget` pattern as the other TSDB loops
  for the transition checks).
- All code inside the existing `#ifdef PROXYSQLTSDB` region — no new tier
  surface. (PROXYSQL31 implies PROXYSQLTSDB.)

### 2. Data flow

Per cycle (every `tsdb-cluster_interval` seconds), for each node listed in
`runtime_proxysql_servers`:

- **Watermark** = `MAX(timestamp)` already replicated for that node in
  `tsdb_metrics_cluster`; if none, initialized to
  `now − tsdb-cluster_backfill_hours`. Recovered from the table itself on
  restart/re-election — no separate persistent state.
- **Peers**: dedicated MySQL connection per cycle (cluster credentials, same
  SSL-enforce and connect-timeout settings as the cluster monitor threads):
  `SELECT timestamp, metric_name, labels, value FROM
  stats_history.tsdb_metrics WHERE timestamp >= ? ORDER BY timestamp LIMIT
  <tsdb-cluster_batch_rows>`, looped until caught up or the per-cycle cap is
  reached (bounds leader load; catch-up resumes next cycle). `>=` (not `>`):
  a previous cycle's `LIMIT` can cut in the middle of a same-timestamp
  group, so the boundary group is re-fetched every cycle until fully
  replicated; `INSERT OR IGNORE` plus the `(node, timestamp, metric_name,
  labels)` primary key make the re-fetch idempotent and loss-free.
- **Self**: no self-connection — a local `INSERT ... SELECT` from the
  leader's own `tsdb_metrics` through the same watermark logic, so the
  leader appears in the cluster view identically to every other node.
- Rows inserted in batched transactions, tagged with the node's
  `hostname:port` exactly as it appears in `proxysql_servers` (operator-
  facing identity, stable across `--initial` re-inits; UUID is not used).

### 3. Storage

New table in `statsdb_disk` (sibling of `tsdb_metrics`):

```sql
CREATE TABLE tsdb_metrics_cluster (
  node VARCHAR NOT NULL,
  timestamp INT NOT NULL,
  metric_name VARCHAR NOT NULL,
  labels VARCHAR NOT NULL DEFAULT '',
  value REAL,
  PRIMARY KEY (node, timestamp, metric_name, labels)
) WITHOUT ROWID
```

plus an index mirroring the local table's query pattern
(`(node, metric_name, timestamp)`).

Rationale for a separate table (vs folding a node label into `labels`): no
double-counting against the local sampler's rows, uniform treatment of the
leader itself, and independent retention. Pruned by the existing retention
loop using `tsdb-cluster_retention_days`. v1 replicates raw samples only,
not peers' hourly rollups (follow-up if long-horizon cluster trends are
wanted). The PK makes replication idempotent — duplicates are structurally
impossible (`INSERT OR IGNORE` on ingest — replicated samples are immutable).

### 4. Variables (TSDB family, `LOAD TSDB VARIABLES TO RUNTIME`)

| Variable | Default | Range | |
|---|---|---|---|
| `tsdb-retention_days` | `2` | 1–3650 | local raw-sample (`tsdb_metrics`) retention |
| `tsdb-cluster_aggregation` | `true` | bool | master switch (election is the real opt-in) |
| `tsdb-cluster_interval` | `10` | 5–300 s | pull cadence |
| `tsdb-cluster_backfill_hours` | `24` | 0–168 | horizon for a fresh watermark |
| `tsdb-cluster_retention_days` | `1` | 1–30 | cluster-table retention |
| `tsdb-cluster_batch_rows` | `10000` | 1000–100000 | per-cycle per-peer cap |
| `tsdb-hourly_retention_days` | `365` | 1–3650 | `tsdb_metrics_hour` rollup retention |

**Defaults are set from a measured floor, not a placeholder.** On an idle
single node at the default 5s sample interval, the sampler emits 268
distinct series/tick, i.e. ~4.6M rows/day/node (~450 MB/day/node) into the
raw `tsdb_metrics` table. At that rate the old defaults implied multi-GB
embedded stats DBs (7-day raw ≈ 3 GB/node; a 3-node cluster's leader-side
`tsdb_metrics_cluster` at the old 3-day retention ≈ 4 GB). Since the raw
tiers dominate storage while carrying the least query value beyond a couple
of days, they get short retention — local raw down to 2 days, cluster raw
down to 1 day (the leader already multiplies that cost by N nodes) — and
long-horizon trending is pushed onto the hourly rollup tier, which is now
governed by its own variable, `tsdb-hourly_retention_days` (default `365`,
unchanged from the previous hardcoded 1-year prune).

This figure is a floor, not a ceiling: it was measured on an idle node with
no backends, hostgroups, or connection pools generating additional
per-object series, so a loaded production node will emit more series/tick
and correspondingly more rows/day. The forthcoming duplication-tool lab
(replaying realistic multi-hostgroup traffic) will refine these defaults
with loaded-node numbers before GA.

### 5. Query surface

- `/api/tsdb/query` gains `node=<hostname:port>` — routes the query to
  `tsdb_metrics_cluster`; `node=*` spans all nodes (existing `agg`
  semantics apply across them).
- New `/api/tsdb/nodes`: nodes present in the cluster table, each with its
  watermark age — an instant health view of the aggregation itself.
- `/api/tsdb/status` extended with aggregator state: leader or not, per-node
  watermark lag, rows replicated, whether the batch cap was hit on the last
  cycle.
- Dashboard: minimal v1 — a node selector fed by `/api/tsdb/nodes`; no
  layout redesign.

### 6. Edge cases

- **Not leader / election off**: aggregator thread idle; behavior bit-for-bit
  as today. A deposed leader stops pulling; its cluster table goes stale and
  ages out via retention — and is correct again if re-elected (watermarks
  resume from the table).
- **Peer with TSDB disabled**: query returns 0 rows; logged once per peer
  state-change; watermark simply doesn't advance.
- **Mixed versions**: impossible — the cluster already refuses to exchange
  with a different-version peer, so the remote schema always matches.
- **Clock skew**: timestamps are peer-local. In steady state, per-peer
  watermarks are immune to skew — they're re-derived from `MAX(timestamp)`
  of already-replicated (peer-stamped) rows, not from the leader's clock.
  The one exception is cold start: a never-replicated peer's initial horizon
  is `now - backfill_hours` computed on the *leader's* local clock, so
  leader-peer clock offset affects only the initial backfill depth for that
  peer, not steady-state behavior. Cross-node comparison quality still
  depends on NTP — documented, not compensated.
- **Volume / overload**: worst case ~N× the leader's own sample write rate.
  Bounded by the batch cap and separate retention. The aggregator logs a
  warning when it cannot keep up (cap hit on consecutive cycles for the
  same peer).
- **Follower write-refusal interaction**: the aggregator writes only to the
  leader's own `statsdb_disk` via internal handles — admin read-only mode
  (a follower concern anyway) never applies to it.

### 7. Testing

**Synthetic history is mandatory** (user requirement): a few seconds of live
sampling proves the loop, not the promise. The E2E test pre-seeds each
node's `stats_history.tsdb_metrics` with generated history — on the order of
3 metric names × 6h at 5s spacing ≈ 13k rows/node with distinct per-node
values — inserted over the admin connection before election converges (or
under `PROXYSQL READWRITE`), since followers refuse writes once election
engages.

- **Unit test** (pure logic, against `libproxysql.a`): the watermark/batch
  planner — given (current watermark, backfill horizon, fetched row
  timestamps, batch cap) → (rows to insert, new watermark, caught-up flag),
  covering: fresh-watermark horizon computation, cap-hit continuation,
  empty fetch, and idempotent re-fetch.
- **E2E TAP** (extends the 3-node self-spawned pattern from #6034; election
  + tsdb enabled, 1s local sampling, `tsdb-cluster_interval` minimal,
  `tsdb-cluster_batch_rows` lowered to force multi-cycle catch-up,
  `tsdb-cluster_backfill_hours=2` against 6h of synthetic data):
  1. Leader's `tsdb_metrics_cluster` gains rows for all 3 nodes including
     itself; followers' cluster tables stay empty.
  2. **Horizon**: no replicated row older than the backfill horizon —
     asserts the window trim against the deeper synthetic set.
  3. **Batch cap**: replication completes incrementally across multiple
     cycles (observed row count strictly increases over ≥2 polls before
     reaching the final value).
  4. **Exactness**: per-node replicated count equals the synthetic count
     within the horizon (plus live samples) — proves no loss, no dupes.
  5. **Failover**: kill the leader; the new leader backfills rows predating
     its leadership (synthetic rows present in its cluster table) — the
     durability promise asserted directly.
  6. `node=` query API returns per-node series; `/api/tsdb/nodes` lists all
     three with sane watermark ages.
  7. Diagnostic (non-assert): log `tsdb_metrics_cluster` size via
     `page_count × page_size` for future default-sizing work.

## Out of scope

- Replicating hourly rollups / long-horizon cluster trends (follow-up).
- Dashboard redesign beyond a node selector.
- Distributed quotas and leader-only monitoring (later deliverables of the
  roadmap).
- Default tuning — deliberately deferred until sizing data exists (§4).
