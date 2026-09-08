# TSDB Sizing Lab

The TSDB sizing lab populates a ProxySQL stats database with realistically shaped time-series data, enabling measurement of:

- **Storage sizing**: How much disk space a TSDB retains at different retention windows and rollup depths.
- **Replication load**: How many writes per second the replication layer must handle.
- **Query cost**: Latency and throughput of analytical queries over full history.

## Structural Fidelity

The lab uses a **real captured metrics fixture** — metric names, label sets, cardinality, and volume are authentic. However, **fidelity is STRUCTURAL, not analytical**. The fixture block repeats, so counter values restart at each seam. This is **fine for sizing** (storage/replication/query characteristics do not depend on counter realism) but **NOT suitable for dashboards or rate() calculations** (which require monotonic growth).

## Workflow

### 1. Regenerate the fixture (optional)

The default fixture is `fixtures/seed-10min.csv.gz` (captured from a real 3-node ProxySQL cluster under sysbench load; see `fixtures/seed-10min.README` for provenance). To refresh it:

```bash
# Spins up its own 3-node ProxySQL cluster (leader election) against a
# harness-managed MySQL backend, drives 10 minutes of variable-rate sysbench
# load through the leader, and dumps its stats_history.tsdb_metrics window.
bash test/tsdb-lab/capture.bash

# Quick smoke run with a shorter window:
DURATION_S=90 bash test/tsdb-lab/capture.bash
```

`capture.bash` is a human-run script (not CI): it brings up the `legacy-g5`
backend infra via `test/infra/control/ensure-infras.bash`, spawns 3
`src/proxysql` instances on 127.0.0.1 admin ports 16362/16372/16382, wires
them into two hostgroups (writer/reader) against that backend, enables TSDB,
drives load through the elected leader (falling back to a plain mysql-client
SELECT/INSERT loop if `sysbench` isn't installed), and writes the gzip-
compressed CSV plus a provenance `.README` file. It refuses to commit a
fixture over 2 MB compressed. The backend infra is left running afterward
(harness-owned); only the 3 capture-only ProxySQL instances are shut down.

### 2. Expand into a stats database

Create a fresh stats database and populate it with sized data:

```bash
# Single instance, 24h of raw metrics + 14d of rollups
python3 test/tsdb-lab/expand.py \
  --db /tmp/proxysql_stats.db \
  --seed test/tsdb-lab/fixtures/seed-10min.csv.gz \
  --raw-window 24h \
  --span 14d

# Multi-node: same metrics on each node (N copies)
python3 test/tsdb-lab/expand.py \
  --db /tmp/proxysql_stats.db \
  --nodes 5
```

### 3. Measure and analyze

Run queries against the expanded database using `measure.py`. It opens the
database **read-only** (`file:...?mode=ro`), so it is safe to run against either a
stopped instance's file or (via a separate copy) one that's still running.

```bash
python3 test/tsdb-lab/measure.py --db /tmp/proxysql_stats.db
```

For each of `tsdb_metrics`, `tsdb_metrics_hour` and `tsdb_metrics_cluster` (a table
absent from the schema, e.g. a pre-aggregation build, is printed as `(absent)` and
skipped), it reports:

- row count and **bytes/row**, derived from a portable payload-size proxy
  (`SUM(LENGTH(metric_name) + LENGTH(labels) + 16)`, plus `LENGTH(node)` for the
  cluster table) rather than `dbstat`, which may not be compiled into the linked
  sqlite3 library.
- the whole-file size (`page_count * page_size`) — this total includes **all**
  tables in the database plus index/page overhead, not just the three tiers above.
- the **whole-file overhead ratio**: `(page_count * page_size) / (summed payload
  bytes across the three tiers above)`. Measured 2.17 and confirmed scale-invariant
  between the small and full profiles.
- two representative query timings: a raw last-1h lookup and an hourly full-span
  lookup, both for whichever `metric_name` is most frequent in `tsdb_metrics`.

It then compares each table's bytes/row, and the whole-file overhead ratio, against
`baseline.json` and exits non-zero **only** if any of those drifts exceeds
`--drift-pct` in either direction (default 25); a table or ratio missing from the
baseline is reported `NEW` and never fails the run. The file total and the query
timings are reported only — they are never gated.

**What each gate actually covers, and what it doesn't:**

- **bytes/row** guards fixture/tooling consistency: it is a near-pure function of
  the committed fixture's text (`LENGTH(metric_name)+LENGTH(labels)+16`, averaged),
  computable before any database exists. It does **not** detect a product change
  that adds or lengthens labels — that only shows up once a human re-runs
  `capture.bash` and commits a refreshed fixture (see "Maintenance" below).
- **file/payload overhead ratio** guards schema/index bloat: since it divides the
  whole-file size (which includes every index and every table) by the tiers'
  payload bytes, a new column or index inflates `page_count` while payload stays
  flat, moving the ratio even though bytes/row does not.
- **file size and query timings** are printed for visibility but are not gated —
  file size is a derived total of the (already gated) per-tier numbers plus
  non-tsdb overhead, and query latency is hardware-dependent (see the design
  spec's non-goals).

```
--db PATH          proxysql_stats.db to measure (required; opened read-only)
--baseline PATH    baseline.json to diff bytes/row and file/payload ratio against (default: test/tsdb-lab/baseline.json)
--drift-pct PCT    fail if bytes/row or the file/payload ratio drifts beyond +/- this percent from baseline (default: 25)
```

`baseline.json` was generated by running the Step 1–3 flow above with the small
local profile (`--raw-window 1h --span 1d --nodes 3`) once and copying the printed
bytes/row and file/payload-ratio values in. Regenerate it the same way if a
structural change to the schema or fixture legitimately shifts the numbers.

### Maintenance: re-run `capture.bash` to catch product-side metric growth

The bytes/row gate cannot see product changes on its own — it is derived entirely
from the committed fixture (`fixtures/seed-10min.csv.gz`), not from a live
ProxySQL. If a product change adds a label, widens a metric name, or adds new
series, `measure.py` will keep reporting the *old* bytes/row until someone:

1. Re-runs `bash test/tsdb-lab/capture.bash` against current ProxySQL to capture a
   fresh fixture.
2. Commits the refreshed `fixtures/seed-10min.csv.gz` (and its `.README`).
3. Re-runs the Step 1–3 flow to regenerate `baseline.json`'s bytes/row (and
   file/payload-ratio) values against the new fixture.

Until that happens, growth in per-metric/per-label size is invisible to CI. The
whole-file overhead ratio gate is complementary, not a substitute: it catches
schema/index bloat, not growth in the metrics/labels themselves.

### 4. Nightly CI measurement

`.github/workflows/CI-tsdb-sizing.yml` runs this flow on a nightly schedule (and
`workflow_dispatch`) — **not** on every PR, since it's a measurement job, not a
gate. It builds ProxySQL (`PROXYSQL31=1`), creates the schema, expands the fixture
with the CI profile (`--raw-window 4h --span 7d --nodes 3`), starts
ProxySQL again and waits (bounded, reporting the duration) for
`tsdb_metrics_hour` to stop growing — i.e. for the hourly rollup to catch up the
newly-written raw window — then stops it, runs `measure.py --baseline
test/tsdb-lab/baseline.json`, and uploads the printed report as a job artifact.
The originally planned `--raw-window 24h --span 14d --nodes 3` profile was
measured once (2026-08-13, see the design spec's "Measured results" section):
~28.7M rows, a 6.0 GB `proxysql_stats.db`, 113s to expand. That is too tight a
disk margin on a standard GitHub-hosted runner on top of the repo build
(>1.4 GB), so CI uses the smaller profile above instead — bytes/row is
confirmed scale-invariant, so it gives the same sizing signal at a fraction of
the disk/time cost.
The job goes red only when `measure.py` detects bytes/row or file/payload-ratio
drift beyond the threshold — see "What each gate actually covers, and what it
doesn't" above for exactly what that guards (and does not guard).

### After merge: first-run validation checklist

`schedule` and `workflow_dispatch` only take effect once a workflow file is on
the repo's default branch — until then, `CI-tsdb-sizing.yml` cannot actually
run, which means several things in it are unverified claims until someone
checks them post-merge. This is an owner action, not a hope:

- [ ] **Dispatch the job manually once** (`workflow_dispatch` from the Actions
      tab) and confirm it completes within `timeout-minutes` (150).
- [ ] **Confirm the 4h/7d/3-node profile itself**, not just its 24h/14d
      projection: check the uploaded report's row counts / DB size / expand
      time against the ≈1 GB / ≈20-30s projection in the design spec's
      "CI workflow adjustment" section, and correct the comment there if the
      real numbers differ.
- [ ] **Replace the 120-minute build-time term** in `timeout-minutes`'s
      breakdown (see the comment above the `timeout-minutes:` line in the
      workflow) with the job's actual measured build wall-clock — it is
      currently an analogy from other from-scratch package builds, not a
      measurement of this job.
- [ ] **Confirm the runner had disk headroom** for the whole run (build +
      datadir + expanded DB) rather than assuming it from the projection.

## expand.py API

### Functions

- `parse_duration(s: str) -> int` — Parse `'30m'` / `'24h'` / `'14d'` to seconds.
- `read_seed(path: str) -> (rows, block_start, block_end)` — Load compressed fixture; rows sorted by timestamp.
- `table_exists(conn, name: str) -> bool` — Check if a tier's target table exists.
- `expand_raw(conn, rows, block_start, block_end, window_start, window_end) -> int` — Tile raw metrics forward; return rows inserted.
- `expand_hourly(conn, rows, block_start, block_end, span_start, span_end) -> int` — Aggregate into hourly buckets.
- `expand_cluster(conn, rows, block_start, block_end, window_start, window_end, nodes) -> int` — Tile raw metrics into `tsdb_metrics_cluster` under `nodes` synthetic node identities (no rollup/aggregation — same raw tiling as `expand_raw`, just fanned out per node).

### Tiling Arithmetic

The block repeats with stride = `(block_end - block_start) + sample_interval`, where `sample_interval` is the smallest positive time gap between consecutive timestamps in the fixture. This avoids seam duplication and gaps.

Example: fixture spans `[1000, 1010]` with 5s samples (stride = 15s). A 60s window holds 4 tiles = 24 rows.

### Command-line options

```
--db PATH               target proxysql_stats.db (required; instance must be STOPPED)
--seed PATH             fixture path (default: fixtures/seed-10min.csv.gz)
--raw-window DURATION   keep raw (5s) metrics for this long (default: 24h)
--span DURATION         total retention (raw + rollups; default: 14d)
--nodes N               replicate metric set N times for multi-node sizing (default: 0 = single node)
```

## Important: Instance Must Be Stopped

**The target ProxySQL instance MUST be stopped before running expand.py.** The tool directly writes to `proxysql_stats.db`, and a running instance will conflict and corrupt the file.

```bash
# Start fresh
systemctl stop proxysql
python3 test/tsdb-lab/expand.py --db /var/lib/proxysql/proxysql_stats.db --span 14d
systemctl start proxysql
```

## Files

- `expand.py` — Tiling engine, CLI, duration parser, seed reader.
- `test_expand.py` — 15 tests: duration parsing (2), seed loading (1), raw expansion (5), table detection (1), hourly aggregation (4), cluster expansion (2).
- `fixtures/seed-10min.csv.gz` — Real captured metrics (5s samples, 417 series, ~10 minutes).
- `capture.bash` — Fixture regeneration script.
- `measure.py` — Query harness, storage/query analytics, and the bytes/row + file/payload-ratio baseline drift checks.
- `baseline.json` — Recorded bytes/row per tier and the whole-file overhead ratio from the local small-profile run; `measure.py`'s drift baseline.
- `../../.github/workflows/CI-tsdb-sizing.yml` — Nightly build-expand-measure workflow.

## References

- CLAUDE.md: ProxySQL build, test, and architecture overview.
- doc/agents/project-conventions.md: Agent task patterns.
