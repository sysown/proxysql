# TSDB Sizing Lab — Seed Capture, Duplication Tool, CI — Design

Date: 2026-08-13
Status: approved for planning
Depends on: cluster leader election + TSDB cluster aggregation (PR #6034).
Branch: stacked on `feat/cluster-leader-election`; rebase onto `v3.0` after #6034 merges.

## Motivation

TSDB defaults were chosen without storage data. A measurement on an idle
single node (default 5s sampling) found **268 distinct series per tick** ≈
**4.6M rows/day/node ≈ 450 MB/day/node** — a floor, since a loaded node with
backends, hostgroups and pools has more series. That measurement already
drove retention changes in #6034 (`tsdb-retention_days` 7→2,
`tsdb-cluster_retention_days` 3→1, hourly prune made configurable).

What is still missing is an instrument: a repeatable way to produce a
**realistically shaped** TSDB at multi-day depth, so we can measure
bytes/row, growth rate, rollup behaviour and query latency — and re-measure
when the metric set changes.

**Core requirement (explicit):** do not fabricate synthetic metrics.
Duplicate *real* ones. Real metric names and label sets are what determine
row cost, because SQLite stores both verbatim in every row (no interning);
synthetic 3-metric fixtures understate storage badly.

## Decision: capture once, expand anywhere

A one-off lab produces a small fixture of real metrics; a duplication tool
expands that fixture into a full-size database on demand. CI runs the
expansion, never the lab. Alternatives rejected: generating the seed inside
CI (needs sysbench + backends per run, slow, non-deterministic), and
measure-and-extrapolate (says nothing about rollup or query latency at
depth).

**Fidelity: structural, not analytical.** Row shapes, names, label
cardinality and volume are real; counters restart at each duplicated block
seam (they are not offset to remain monotonic). This is sufficient for
sizing, replication load and query cost. Analytical fidelity (monotonic
counters across seams, for dashboard/rate realism) is a possible later
layer on the same insert path — out of scope here.

## Design

### 1. Seed capture (`test/tsdb-lab/capture.bash`) — run rarely, by a human

- Stands up 3 ProxySQL instances forming a cluster, one backend registered
  in two hostgroups, and sysbench at *variable* load (alternating rates and
  think-times; load variety matters for series/value realism, stress does
  not).
- TSDB enabled (`tsdb-enabled=1`, default 5s sampling), leader election
  enabled so the cluster table is populated too.
- After ~10 minutes, dumps one node's `tsdb_metrics` rows for the window to
  `test/tsdb-lab/fixtures/seed-10min.csv.gz`
  (columns: `timestamp,metric_name,labels,value`).
- Expected size: ~400 series × 120 ticks ≈ 48k rows; gzip compresses the
  repeated names/labels heavily — expected low hundreds of KB, small enough
  to commit. **If the compressed fixture exceeds 2 MB, stop and reconsider**
  (options: shorter window, or generate in CI) rather than committing a
  large binary.
- The script stays in-repo so the fixture can be regenerated whenever the
  metric set changes; the fixture header records the ProxySQL version and
  capture date.

### 2. Duplication tool (`test/tsdb-lab/expand.py`)

Writes directly into a target `proxysql_stats.db` **with the instance
stopped** — no admin round-trips, no `PRAGMA query_only` gate, orders of
magnitude faster than SQL over the admin port.

- `--raw-window <duration>` (default `24h`): tiles the 10-minute block
  forward (`timestamp + k*600`) until the window ending at "now" is filled.
  At measured density this is ~4.6M rows.
- `--span <duration>` (default `14d`): for the period older than the raw
  window, writes **hourly buckets directly** into `tsdb_metrics_hour`
  (bucket, metric_name, labels, avg/max/min/count aggregated from the
  block). ~90k rows. Raw is deliberately not materialized there — retention
  would prune it immediately, and the tiered shape is what a real node looks
  like under the new defaults.
- `--nodes N` (default `0` = skip): writes the same expansion into
  `tsdb_metrics_cluster` under N synthetic node identities
  (`10.0.0.<i>:6032`), so the leader-side footprint is measurable.
- `--db <path>`: target stats DB (must exist with schema; the tool refuses
  to create tables — it is a data tool, not a schema tool).
- Idempotence: inserts use `INSERT OR IGNORE` so a re-run over the same
  target is safe (the PKs already dedupe).
- Header comment documents the counter-sawtooth caveat.

### 3. CI workflow (`.github/workflows/CI-tsdb-sizing.yml`)

Nightly / manual dispatch — **not** per-PR (it is a measurement job, not a
gate on every change).

1. Build ProxySQL (debug or release, `PROXYSQL31=1`).
2. Create a datadir, start ProxySQL once to materialize the stats schema,
   stop it.
3. Run `expand.py` with the CI profile (`--raw-window 24h --span 14d
   --nodes 3`).
4. Start ProxySQL; wait for it to settle.
5. Measure and print a table:
   - bytes per row (per table: `tsdb_metrics`, `tsdb_metrics_hour`,
     `tsdb_metrics_cluster`), computed from row counts and page usage;
   - total DB size;
   - rollup catch-up duration (time from start until `tsdb_metrics_hour`
     stops growing — i.e. the first downsample pass, which holds `wrlock`);
   - latency of two representative queries: raw last-1h for one metric, and
     hourly 14d for one metric.
6. **Report always; fail only on a coarse guard** — bytes/row drifting more
   than 25% from the baseline recorded in
   `test/tsdb-lab/baseline.json` (committed, updated deliberately). This
   catches schema/row bloat regressions without becoming a flaky perf gate.

### 4. Tests for the tool itself

`test/tsdb-lab/test_expand.py` (or a TAP test if the repo prefers): expand a
tiny inline fixture (2 series × 3 ticks) into a temp DB and assert:
exact raw row count for a given `--raw-window`; timestamp bounds inside the
window; no gap larger than the sample interval at block seams; hourly bucket
count and aggregate arithmetic (avg/max/min/count) for a known block;
`--nodes N` produces N× rows in the cluster table under distinct node ids;
re-running is a no-op (idempotence).

### 5. Deliberate non-goals

- Analytical fidelity (monotonic counters across seams).
- Running the lab in CI.
- Asserting query-latency thresholds (reported, not gated — hardware-dependent).
- Changing product defaults: this instrument *informs* default choices; any
  change lands as its own reviewed commit.

## Follow-ups this instrument enables

- Cluster rollup tier (`tsdb_metrics_cluster_hour`) — needs a 14-day cluster
  table to test against.
- Chunked downsample catch-up — the CI job's rollup-duration measurement is
  the reproduction of the unbounded first pass under `wrlock`.
- Refining `tsdb-*` defaults with loaded-node series counts rather than the
  idle-node floor.

## Measured results (2026-08-13, ProxySQL 3.1.11-579-geaa0c9b)

First full-scale local run of the CI-sized profile, against a release
(`PROXYSQL31=1`, no debug flags) build at commit `eaa0c9bdd`. Flow: start
once (`--initial`) to create the schema, stop, `expand.py --raw-window 24h
--span 14d --nodes 3` (the profile originally planned for
`CI-tsdb-sizing.yml`), start again, `measure.py`, then `SET tsdb-enabled='1';
LOAD TSDB VARIABLES TO RUNTIME` while polling
`stats_history.tsdb_metrics_hour`'s row count every 1s until 5 consecutive
reads agreed. Datadir was scratch space under `/data` (341 GB free
beforehand), ports 16392/16393; the 5.9 GB scratch datadir was removed
afterward and `df -h /data` confirmed the space was released (345G → 351G
avail — the extra 6G includes some unrelated background churn on the shared
host, consistent with the ~5.9 GB DB).

| Metric | Value |
|---|---|
| Expansion wall-clock (`expand.py`) | 113.1s (86.82s user + 26.12s sys, 99% CPU) |
| Raw rows (`tsdb_metrics`) | 7,144,960 over 24h (1 node) |
| Hourly rows (`tsdb_metrics_hour`) | 130,104 over the 13d preceding the raw window (10,008/day = 24×417 series) |
| Cluster rows (`tsdb_metrics_cluster`) | 21,434,880 across 3 nodes (7,144,960/node, same 24h window as raw) |
| Bytes/row — raw / hourly / cluster | 91.36 / 91.38 / 104.36 (0.0% drift vs `baseline.json`, i.e. confirmed scale-invariant between the 1h/1d and 24h/14d profiles) |
| Tiered payload (raw+hourly+cluster) | 2,767.29 MB |
| Whole-file DB size | 6,006.27 MB (page_count=1,537,605 × page_size=4096) ≈ 5.87 GB |
| File-size / tiered-payload overhead ratio | ≈2.17× (indexes + page/journal overhead) |
| Raw last-1h query | 15.3ms (rows=27,600) — was 13.5ms at the small profile |
| Hourly full-span query | 5.6ms (rows=12,480) — was 0.4ms at the small profile |
| Rollup catch-up: `tsdb_metrics_hour` growth | 130,104 → 139,695 rows (+9,591 = 23 complete hourly buckets × 417 series — the entire 24h raw backlog, caught up in one pass) |
| Rollup catch-up: single blocking pass | ≈38.6s (the poll issued immediately after enabling TSDB blocked for that long before returning, i.e. `wrlock` held that whole time) |
| Rollup catch-up: poll-detected total | 43.8s (1s poll interval, 5 consecutive stable reads required) |

**(a) Do the new retention defaults (raw 2d local, cluster 1d, hourly 365d —
`lib/ProxySQL_Statistics.cpp`) hold up against measured per-day cost?** Yes,
comfortably, for the local (non-cluster) tiers: raw costs 622.55 MB/day/node
payload, so 2 days retained is ≈1.22 GB/node; hourly costs only ≈0.87
MB/day (24 buckets/day vs 17,280 raw samples/day — a ~720× row-count
reduction), so even 365 days retained is ≈318 MB — the long hourly window is
essentially free. Projecting onto real on-disk bytes with the measured
≈2.17× payload-to-file-size overhead, a non-leader node's raw+hourly
footprint is ≈(1245+318)×2.17 ≈ 3.4 GB. That is a real but tractable
footprint, and a large improvement over the pre-#6034 defaults (7d raw / 3d
cluster), which this same math scales up ≈3.5× for the raw tier alone.

**(b) What does the cluster tier cost the leader per node?** The measured
3-node cluster tier is 2,133.4 MB payload for one day (the cluster window
tracked equals the raw window, 24h, which is exactly the default
`tsdb-cluster_retention_days=1`), i.e. 711.1 MB/day of payload *per tracked
node* (2133.4/3), retained on the leader only. That is the dominant single
cost on a leader: a leader tracking 3 peers carries ≈2.08 GB of cluster
payload (≈4.5 GB projected on-disk) on top of its own raw+hourly tiers,
versus a follower's ≈1.53 GB payload (≈3.3 GB projected on-disk). The cost
scales linearly with cluster size at ≈711 MB/day/node retained — a 10-node
cluster would put ≈7.1 GB of cluster-tier payload alone on the leader at the
1-day default, which is worth remembering before growing cluster sizes past
what's been measured here.

**(c) Does the rollup catch-up duration justify chunking (project 3)?** Yes.
A single, unbounded first-pass downsample — the exact scenario project 3
targets — held `wrlock` for ≈38.6s while aggregating one node's full 24h raw
backlog (7.14M rows, 417 series, 23 hourly buckets) into 9,591 hourly rows,
on a 32-core dev machine with no contention. Every other read or write that
shares `wrlock` blocks for the same interval; in production this pass runs
after any restart or `tsdb-enabled` toggle that needs to catch up whatever
raw window has accumulated, and a loaded node has materially more series
than this fixture's idle-node-derived 417 (see Motivation), so the real
worst case is plausibly minutes, not tens of seconds. That is a real,
reproduced availability cost — this measurement is the concrete justification
for chunking the downsample pass rather than running it as one unbounded
pass.

**CI workflow adjustment.** The originally planned CI profile
(`--raw-window 24h --span 14d --nodes 3`, measured above) produces a 6.0 GB
`proxysql_stats.db`, which combined with the repo's own build artifacts
(>1.4 GB) leaves too little headroom on a standard GitHub-hosted runner's
disk. `CI-tsdb-sizing.yml` was changed to `--raw-window 4h --span 7d --nodes
3` instead — since bytes/row is confirmed scale-invariant, this gives the
same sizing signal (still exercises multi-hour rollup catch-up and the
3-node cluster leader cost) at a projected ≈1 GB DB and ≈20-30s expand time
(scaled from the measured rates: 7,144,960 raw rows/24h/node, 10,008 hourly
rows/day, and the same per-node rate for the cluster tier). `timeout-minutes`
was set to 150 (down from the previous unexamined 180): comparable
from-scratch full builds elsewhere in this repo (`CI-package-*-v31.yml`,
build+package) budget 120 minutes, this job only builds (no packaging), and
the lab steps themselves are now measured to be small (expand ≈20-30s
projected, rollup wait already bounded at 10 minutes, measure <5s) plus
checkout/apt/artifact overhead (≈3 min) — 120 + 10 + ≈4 ≈ 134 min, so 150
keeps a deliberate margin without carrying forward a blind guess.
