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

Run queries against the expanded database using `measure.py` (Task 4):

```bash
python3 test/tsdb-lab/measure.py --db /tmp/proxysql_stats.db
```

## expand.py API

### Functions

- `parse_duration(s: str) -> int` — Parse `'30m'` / `'24h'` / `'14d'` to seconds.
- `read_seed(path: str) -> (rows, block_start, block_end)` — Load compressed fixture; rows sorted by timestamp.
- `table_exists(conn, name: str) -> bool` — Check if a tier's target table exists.
- `expand_raw(conn, rows, block_start, block_end, window_start, window_end) -> int` — Tile raw metrics forward; return rows inserted.
- `expand_hourly(conn, rows, block_start, block_end, window_start, window_end) -> int` — Aggregate into hourly buckets (Task 2).
- `expand_cluster(conn, rows, block_start, block_end, window_start, window_end) -> int` — Per-cluster rollup (Task 2).

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
- `fixtures/seed-10min.csv.gz` — Real captured metrics (5s samples, ~2 series, ~10 minutes).
- `capture.bash` — Fixture regeneration script (Task 3).
- `measure.py` — Query harness and analytics (Task 4).

## References

- CLAUDE.md: ProxySQL build, test, and architecture overview.
- doc/agents/project-conventions.md: Agent task patterns.
