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
