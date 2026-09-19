# TSDB Sizing Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a realistically-shaped multi-day TSDB from a small fixture of REAL captured metrics, so storage/rollup/query behaviour can be measured repeatably, per spec `docs/superpowers/specs/2026-08-13-tsdb-sizing-lab-design.md`.

**Architecture:** Capture once (human-run lab → committed gzipped CSV fixture of real metrics), expand anywhere (`expand.py` writes raw + hourly + cluster rows straight into a stopped instance's `proxysql_stats.db`), measure in CI (nightly workflow prints a sizing table and guards only against gross bytes/row drift).

**Tech Stack:** Python 3 (stdlib only — `sqlite3`, `gzip`, `csv`, `argparse`), bash, Docker via existing `test/infra`, GitHub Actions.

## Global Constraints

- Branch: `feat/tsdb-sizing-lab`, created from `feat/cluster-leader-election` (the `tsdb_metrics_cluster` table exists only there). Rebase onto `v3.0` after #6034 merges.
- **Python: standard library only.** No pip installs — CI must run the tool with the runner's stock `python3`. Target 3.8+ (no match statements, no `datetime.UTC`).
- **Fidelity is structural, not analytical** (explicit user decision): real metric names/labels/cardinality and realistic volume; counters restart at each duplicated block seam. Every tool that duplicates data must say so in its header comment.
- Measured baseline that motivates this work (idle node, 5s sampling): **268 series/tick ≈ 4.6M rows/day/node ≈ 450 MB/day/node**. Do not re-derive; it is the spec's stated basis.
- Current retention defaults (set in #6034): `tsdb-retention_days=2`, `tsdb-cluster_retention_days=1`, `tsdb-hourly_retention_days=365`.
- Table schemas the tool writes (exact, from `include/ProxySQL_Statistics.hpp`):
  - `tsdb_metrics(timestamp, metric_name, labels, value)` PK `(timestamp, metric_name, labels)`
  - `tsdb_metrics_hour(bucket, metric_name, labels, avg_value, max_value, min_value, count)`
  - `tsdb_metrics_cluster(node, timestamp, metric_name, labels, value)` PK `(node, timestamp, metric_name, labels)`
- All inserts use `INSERT OR IGNORE` (idempotent re-runs; PKs dedupe).
- The tool **never creates tables**. If a target table is missing it skips that tier with a warning (so it still works against a pre-aggregation DB).
- If the compressed fixture would exceed **2 MB**, stop and report instead of committing it (spec's abort condition).
- Commit after every task.

---

### Task 1: Expansion tool core (raw tier) + tests

**Files:**
- Create: `test/tsdb-lab/expand.py`
- Create: `test/tsdb-lab/test_expand.py`
- Create: `test/tsdb-lab/README.md`

**Interfaces:**
- Consumes: nothing.
- Produces (used by Tasks 2, 3, 4):
  - `read_seed(path) -> (rows, block_start, block_end)` where `rows` is a list of `(timestamp:int, metric_name:str, labels:str, value:float)` sorted by timestamp, and the two bounds are ints (min/max timestamp in the fixture).
  - `expand_raw(conn, rows, block_start, block_end, window_start, window_end) -> int` — tiles the block forward over `[window_start, window_end)`, inserting into `tsdb_metrics`; returns rows inserted (attempted, i.e. `len(rows) * tiles`).
  - `table_exists(conn, name) -> bool`
  - CLI: `python3 expand.py --db PATH [--seed PATH] [--raw-window 24h] [--span 14d] [--nodes N]`
  - Duration parser `parse_duration(s) -> int` accepting `Nm`, `Nh`, `Nd` (minutes/hours/days) → seconds.

- [ ] **Step 1: Write the failing tests**

Create `test/tsdb-lab/test_expand.py` (stdlib `unittest`, no pytest dependency):

```python
#!/usr/bin/env python3
"""Tests for the TSDB sizing-lab expansion tool."""

import gzip
import os
import sqlite3
import tempfile
import unittest

import expand

RAW_DDL = (
    "CREATE TABLE tsdb_metrics (timestamp INTEGER NOT NULL, metric_name VARCHAR NOT NULL, "
    "labels VARCHAR NOT NULL DEFAULT '{}', value REAL, "
    "PRIMARY KEY (timestamp, metric_name, labels)) WITHOUT ROWID"
)

# A 3-tick block, 2 series, 5s apart: timestamps 1000, 1005, 1010.
SEED_LINES = [
    "timestamp,metric_name,labels,value",
    "1000,metric_a,{},1.0",
    "1000,metric_b,{\"hg\":\"1\"},10.0",
    "1005,metric_a,{},2.0",
    "1005,metric_b,{\"hg\":\"1\"},20.0",
    "1010,metric_a,{},3.0",
    "1010,metric_b,{\"hg\":\"1\"},30.0",
]


def write_seed(path):
    with gzip.open(path, "wt", newline="") as f:
        f.write("\n".join(SEED_LINES) + "\n")


class TestParseDuration(unittest.TestCase):
    def test_units(self):
        self.assertEqual(expand.parse_duration("30m"), 1800)
        self.assertEqual(expand.parse_duration("24h"), 86400)
        self.assertEqual(expand.parse_duration("14d"), 1209600)

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            expand.parse_duration("14")
        with self.assertRaises(ValueError):
            expand.parse_duration("2w")


class TestReadSeed(unittest.TestCase):
    def test_reads_rows_and_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "seed.csv.gz")
            write_seed(p)
            rows, start, end = expand.read_seed(p)
            self.assertEqual(len(rows), 6)
            self.assertEqual(start, 1000)
            self.assertEqual(end, 1010)
            self.assertEqual(rows[0][1], "metric_a")


class TestExpandRaw(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "stats.db")
        self.conn = sqlite3.connect(self.db)
        self.conn.execute(RAW_DDL)
        self.seed = os.path.join(self.tmp.name, "seed.csv.gz")
        write_seed(self.seed)
        self.rows, self.start, self.end = expand.read_seed(self.seed)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_tiles_fill_the_window(self):
        # Block spans 1000..1010 -> stride = (1010-1000) + 5 = 15s per tile.
        # Window of 60s therefore holds 4 tiles = 24 rows.
        expand.expand_raw(self.conn, self.rows, self.start, self.end, 100000, 100060)
        n = self.conn.execute("SELECT COUNT(*) FROM tsdb_metrics").fetchone()[0]
        self.assertEqual(n, 24)

    def test_timestamps_stay_inside_the_window(self):
        expand.expand_raw(self.conn, self.rows, self.start, self.end, 100000, 100060)
        lo, hi = self.conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM tsdb_metrics").fetchone()
        self.assertGreaterEqual(lo, 100000)
        self.assertLess(hi, 100060)

    def test_no_gap_larger_than_the_sample_interval(self):
        expand.expand_raw(self.conn, self.rows, self.start, self.end, 100000, 100060)
        ts = [r[0] for r in self.conn.execute(
            "SELECT DISTINCT timestamp FROM tsdb_metrics ORDER BY timestamp")]
        gaps = {b - a for a, b in zip(ts, ts[1:])}
        self.assertTrue(max(gaps) <= 5, "seam gap exceeds the 5s sample interval: %s" % sorted(gaps))

    def test_idempotent(self):
        expand.expand_raw(self.conn, self.rows, self.start, self.end, 100000, 100060)
        first = self.conn.execute("SELECT COUNT(*) FROM tsdb_metrics").fetchone()[0]
        expand.expand_raw(self.conn, self.rows, self.start, self.end, 100000, 100060)
        second = self.conn.execute("SELECT COUNT(*) FROM tsdb_metrics").fetchone()[0]
        self.assertEqual(first, second)


class TestTableExists(unittest.TestCase):
    def test_detects_presence_and_absence(self):
        with tempfile.TemporaryDirectory() as d:
            conn = sqlite3.connect(os.path.join(d, "x.db"))
            conn.execute(RAW_DDL)
            self.assertTrue(expand.table_exists(conn, "tsdb_metrics"))
            self.assertFalse(expand.table_exists(conn, "tsdb_metrics_cluster"))
            conn.close()


if __name__ == "__main__":
    unittest.main()
```

Note the tiling arithmetic the tests pin down: **stride = (block_end - block_start) + sample_interval**, where `sample_interval` is inferred from the fixture as the smallest positive difference between consecutive distinct timestamps (5s here). Using the raw span without adding one interval would duplicate the seam timestamp and leave a visible gap.

- [ ] **Step 2: Run tests, verify they fail**

```bash
cd /data/rene/proxysql7/proxysql/test/tsdb-lab && python3 -m unittest test_expand -v
```
Expected: `ModuleNotFoundError: No module named 'expand'` (or AttributeError once the file exists but is empty).

- [ ] **Step 3: Implement the raw tier**

Create `test/tsdb-lab/expand.py`:

```python
#!/usr/bin/env python3
"""Expand a small fixture of REAL captured TSDB metrics into a realistically
shaped stats database.

Fidelity is STRUCTURAL, not analytical: metric names, label sets, cardinality
and volume are real, but the fixture block is repeated, so counters restart at
every block seam. That is fine for storage sizing, replication load and query
cost; it is NOT suitable for rate()/dashboard realism.

Run against a STOPPED ProxySQL instance's proxysql_stats.db.
"""

import argparse
import gzip
import csv
import os
import sqlite3
import sys
import time

SEED_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "seed-10min.csv.gz")


def parse_duration(s):
    """'30m' / '24h' / '14d' -> seconds. Raises ValueError on anything else."""
    if not s or len(s) < 2:
        raise ValueError("bad duration: %r" % s)
    unit = s[-1]
    mult = {"m": 60, "h": 3600, "d": 86400}.get(unit)
    if mult is None:
        raise ValueError("bad duration unit in %r (use m/h/d)" % s)
    return int(s[:-1]) * mult


def read_seed(path):
    """Returns (rows, block_start, block_end); rows sorted by timestamp."""
    rows = []
    with gzip.open(path, "rt", newline="") as f:
        for rec in csv.DictReader(f):
            rows.append((int(rec["timestamp"]), rec["metric_name"], rec["labels"], float(rec["value"])))
    if not rows:
        raise ValueError("seed fixture %s has no rows" % path)
    rows.sort(key=lambda r: r[0])
    return rows, rows[0][0], rows[-1][0]


def sample_interval(rows):
    """Smallest positive gap between consecutive distinct timestamps."""
    ts = sorted({r[0] for r in rows})
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    return min(gaps) if gaps else 1


def table_exists(conn, name):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return row is not None


def expand_raw(conn, rows, block_start, block_end, window_start, window_end):
    stride = (block_end - block_start) + sample_interval(rows)
    inserted = 0
    offset = window_start - block_start
    batch = []
    while True:
        tile_start = block_start + offset
        if tile_start >= window_end:
            break
        for (ts, name, labels, value) in rows:
            new_ts = ts + offset
            if new_ts < window_start or new_ts >= window_end:
                continue
            batch.append((new_ts, name, labels, value))
            if len(batch) >= 20000:
                conn.executemany(
                    "INSERT OR IGNORE INTO tsdb_metrics (timestamp, metric_name, labels, value) VALUES (?,?,?,?)",
                    batch)
                inserted += len(batch)
                batch = []
        offset += stride
    if batch:
        conn.executemany(
            "INSERT OR IGNORE INTO tsdb_metrics (timestamp, metric_name, labels, value) VALUES (?,?,?,?)",
            batch)
        inserted += len(batch)
    conn.commit()
    return inserted


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True, help="target proxysql_stats.db (instance must be stopped)")
    ap.add_argument("--seed", default=SEED_DEFAULT)
    ap.add_argument("--raw-window", default="24h")
    ap.add_argument("--span", default="14d")
    ap.add_argument("--nodes", type=int, default=0)
    args = ap.parse_args(argv)

    if not os.path.exists(args.db):
        sys.exit("target db does not exist: %s (start ProxySQL once to create the schema)" % args.db)
    rows, block_start, block_end = read_seed(args.seed)
    now = int(time.time())
    raw_window = parse_duration(args.raw_window)
    span = parse_duration(args.span)
    if raw_window > span:
        sys.exit("--raw-window (%s) cannot exceed --span (%s)" % (args.raw_window, args.span))

    conn = sqlite3.connect(args.db)
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA journal_mode=MEMORY")
    t0 = time.time()
    if table_exists(conn, "tsdb_metrics"):
        n = expand_raw(conn, rows, block_start, block_end, now - raw_window, now)
        print("raw: %d rows over %s" % (n, args.raw_window))
    else:
        print("WARNING: tsdb_metrics missing, skipping raw tier")
    print("elapsed: %.1fs" % (time.time() - t0))
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
cd /data/rene/proxysql7/proxysql/test/tsdb-lab && python3 -m unittest test_expand -v
```
Expected: all tests OK.

- [ ] **Step 5: README + commit**

Create `test/tsdb-lab/README.md` covering: what the lab is for (sizing/rollup/query measurement with real metric shapes), the structural-fidelity caveat, how to regenerate the fixture (points at `capture.bash`, added in Task 3), example invocations, and the warning that the target instance must be stopped.

```bash
git add test/tsdb-lab/
git commit -m "feat(tsdb-lab): expansion tool core with raw-tier tiling"
```

---

### Task 2: Hourly and cluster tiers

**Files:**
- Modify: `test/tsdb-lab/expand.py`
- Modify: `test/tsdb-lab/test_expand.py`

**Interfaces:**
- Consumes: Task 1 (`read_seed`, `sample_interval`, `table_exists`, `expand_raw`, `parse_duration`).
- Produces (used by Tasks 3, 4):
  - `expand_hourly(conn, rows, block_start, block_end, span_start, span_end) -> int` — writes aggregated buckets into `tsdb_metrics_hour` for whole hours in `[span_start, span_end)`; returns rows inserted.
  - `expand_cluster(conn, rows, block_start, block_end, window_start, window_end, nodes) -> int` — same tiling as raw, into `tsdb_metrics_cluster`, under node identities `10.0.0.<i>:6032` for `i` in `1..nodes`.

- [ ] **Step 1: Write the failing tests**

Append to `test/tsdb-lab/test_expand.py`:

```python
HOUR_DDL = (
    "CREATE TABLE tsdb_metrics_hour (bucket INTEGER NOT NULL, metric_name VARCHAR NOT NULL, "
    "labels VARCHAR NOT NULL DEFAULT '{}', avg_value REAL, max_value REAL, min_value REAL, "
    "count INTEGER, PRIMARY KEY (bucket, metric_name, labels)) WITHOUT ROWID"
)
CLUSTER_DDL = (
    "CREATE TABLE tsdb_metrics_cluster (node VARCHAR NOT NULL, timestamp INTEGER NOT NULL, "
    "metric_name VARCHAR NOT NULL, labels VARCHAR NOT NULL DEFAULT '{}', value REAL, "
    "PRIMARY KEY (node, timestamp, metric_name, labels)) WITHOUT ROWID"
)


class TestExpandHourly(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(os.path.join(self.tmp.name, "stats.db"))
        self.conn.execute(HOUR_DDL)
        seed = os.path.join(self.tmp.name, "seed.csv.gz")
        write_seed(seed)
        self.rows, self.start, self.end = expand.read_seed(seed)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_one_row_per_series_per_bucket(self):
        # 3 whole hours, 2 series -> 6 rows.
        expand.expand_hourly(self.conn, self.rows, self.start, self.end, 3600 * 100, 3600 * 103)
        n = self.conn.execute("SELECT COUNT(*) FROM tsdb_metrics_hour").fetchone()[0]
        self.assertEqual(n, 6)

    def test_buckets_are_hour_aligned(self):
        expand.expand_hourly(self.conn, self.rows, self.start, self.end, 3600 * 100, 3600 * 103)
        buckets = [r[0] for r in self.conn.execute("SELECT DISTINCT bucket FROM tsdb_metrics_hour")]
        self.assertTrue(all(b % 3600 == 0 for b in buckets), buckets)

    def test_aggregates_match_the_block(self):
        expand.expand_hourly(self.conn, self.rows, self.start, self.end, 3600 * 100, 3600 * 101)
        row = self.conn.execute(
            "SELECT avg_value, max_value, min_value, count FROM tsdb_metrics_hour "
            "WHERE metric_name='metric_a'").fetchone()
        # metric_a values in the block are 1.0, 2.0, 3.0
        self.assertAlmostEqual(row[0], 2.0)
        self.assertAlmostEqual(row[1], 3.0)
        self.assertAlmostEqual(row[2], 1.0)
        self.assertEqual(row[3], 3)

    def test_idempotent(self):
        expand.expand_hourly(self.conn, self.rows, self.start, self.end, 3600 * 100, 3600 * 103)
        a = self.conn.execute("SELECT COUNT(*) FROM tsdb_metrics_hour").fetchone()[0]
        expand.expand_hourly(self.conn, self.rows, self.start, self.end, 3600 * 100, 3600 * 103)
        b = self.conn.execute("SELECT COUNT(*) FROM tsdb_metrics_hour").fetchone()[0]
        self.assertEqual(a, b)


class TestExpandCluster(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(os.path.join(self.tmp.name, "stats.db"))
        self.conn.execute(CLUSTER_DDL)
        seed = os.path.join(self.tmp.name, "seed.csv.gz")
        write_seed(seed)
        self.rows, self.start, self.end = expand.read_seed(seed)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_rows_scale_with_node_count(self):
        expand.expand_cluster(self.conn, self.rows, self.start, self.end, 100000, 100060, 3)
        n = self.conn.execute("SELECT COUNT(*) FROM tsdb_metrics_cluster").fetchone()[0]
        self.assertEqual(n, 24 * 3)

    def test_distinct_node_identities(self):
        expand.expand_cluster(self.conn, self.rows, self.start, self.end, 100000, 100060, 3)
        nodes = sorted(r[0] for r in self.conn.execute(
            "SELECT DISTINCT node FROM tsdb_metrics_cluster"))
        self.assertEqual(nodes, ["10.0.0.1:6032", "10.0.0.2:6032", "10.0.0.3:6032"])
```

- [ ] **Step 2: Run tests, verify the new ones fail**

```bash
cd /data/rene/proxysql7/proxysql/test/tsdb-lab && python3 -m unittest test_expand -v
```
Expected: the Task-1 tests still pass; the new classes fail with `AttributeError: module 'expand' has no attribute 'expand_hourly'`.

- [ ] **Step 3: Implement both tiers**

Add to `test/tsdb-lab/expand.py`:

```python
def _block_aggregates(rows):
    """(metric_name, labels) -> (avg, max, min, count) over the fixture block."""
    acc = {}
    for (_ts, name, labels, value) in rows:
        key = (name, labels)
        cur = acc.get(key)
        if cur is None:
            acc[key] = [value, value, value, 1]  # sum, max, min, count
        else:
            cur[0] += value
            if value > cur[1]:
                cur[1] = value
            if value < cur[2]:
                cur[2] = value
            cur[3] += 1
    return {k: (v[0] / v[3], v[1], v[2], v[3]) for k, v in acc.items()}


def expand_hourly(conn, rows, block_start, block_end, span_start, span_end):
    """Write one aggregated bucket per series per whole hour in [span_start, span_end)."""
    aggs = _block_aggregates(rows)
    first_bucket = ((span_start + 3599) // 3600) * 3600
    batch = []
    inserted = 0
    bucket = first_bucket
    while bucket < span_end:
        for (name, labels), (avg_v, max_v, min_v, cnt) in aggs.items():
            batch.append((bucket, name, labels, avg_v, max_v, min_v, cnt))
        if len(batch) >= 20000:
            conn.executemany(
                "INSERT OR IGNORE INTO tsdb_metrics_hour (bucket, metric_name, labels, "
                "avg_value, max_value, min_value, count) VALUES (?,?,?,?,?,?,?)", batch)
            inserted += len(batch)
            batch = []
        bucket += 3600
    if batch:
        conn.executemany(
            "INSERT OR IGNORE INTO tsdb_metrics_hour (bucket, metric_name, labels, "
            "avg_value, max_value, min_value, count) VALUES (?,?,?,?,?,?,?)", batch)
        inserted += len(batch)
    conn.commit()
    return inserted


def expand_cluster(conn, rows, block_start, block_end, window_start, window_end, nodes):
    stride = (block_end - block_start) + sample_interval(rows)
    inserted = 0
    batch = []
    for i in range(1, nodes + 1):
        node = "10.0.0.%d:6032" % i
        offset = window_start - block_start
        while True:
            if block_start + offset >= window_end:
                break
            for (ts, name, labels, value) in rows:
                new_ts = ts + offset
                if new_ts < window_start or new_ts >= window_end:
                    continue
                batch.append((node, new_ts, name, labels, value))
                if len(batch) >= 20000:
                    conn.executemany(
                        "INSERT OR IGNORE INTO tsdb_metrics_cluster (node, timestamp, metric_name, "
                        "labels, value) VALUES (?,?,?,?,?)", batch)
                    inserted += len(batch)
                    batch = []
            offset += stride
    if batch:
        conn.executemany(
            "INSERT OR IGNORE INTO tsdb_metrics_cluster (node, timestamp, metric_name, "
            "labels, value) VALUES (?,?,?,?,?)", batch)
        inserted += len(batch)
    conn.commit()
    return inserted
```

Wire both into `main()` after the raw block, each guarded by `table_exists` (warn-and-skip when absent), printing the row counts:

```python
    if table_exists(conn, "tsdb_metrics_hour"):
        n = expand_hourly(conn, rows, block_start, block_end, now - span, now - raw_window)
        print("hourly: %d rows over %s" % (n, args.span))
    else:
        print("WARNING: tsdb_metrics_hour missing, skipping hourly tier")
    if args.nodes > 0:
        if table_exists(conn, "tsdb_metrics_cluster"):
            n = expand_cluster(conn, rows, block_start, block_end, now - raw_window, now, args.nodes)
            print("cluster: %d rows across %d nodes" % (n, args.nodes))
        else:
            print("WARNING: tsdb_metrics_cluster missing (pre-aggregation build?), skipping cluster tier")
```

- [ ] **Step 4: Run tests — expect PASS (all classes)**

- [ ] **Step 5: Commit**

```bash
git add test/tsdb-lab/
git commit -m "feat(tsdb-lab): hourly and cluster tier expansion"
```

---

### Task 3: Seed capture script + fixture

**Files:**
- Create: `test/tsdb-lab/capture.bash`
- Create: `test/tsdb-lab/fixtures/seed-10min.csv.gz` (generated artifact)
- Modify: `test/tsdb-lab/README.md`

**Interfaces:**
- Consumes: nothing from earlier tasks at runtime (it produces the fixture Task 1's `read_seed` consumes: gzipped CSV with header `timestamp,metric_name,labels,value`).
- Produces: the committed fixture used by Tasks 4 and by every future expansion.

- [ ] **Step 1: Write the capture script**

Create `test/tsdb-lab/capture.bash` — a human-run script (not CI). It must:

1. Take `WORKSPACE` (repo root, default `$(git rev-parse --show-toplevel)`) and `DURATION_S` (default 600).
2. Bring up a MySQL backend using the existing harness rather than hand-rolled Docker: `WORKSPACE=$WORKSPACE INFRA_ID=tsdb-lab TAP_GROUP=legacy-g5 test/infra/control/ensure-infras.bash` (per CLAUDE.md, never create containers manually). Export `COMPOSE_PROJECT=placeholder` first (known `ensure-infras` bug on already-running backends).
3. Spawn **3 ProxySQL instances** from `src/proxysql` on 127.0.0.1 admin ports 16362/16372/16382 (mysql +1), each with its own datadir under `test/tsdb-lab/.capture/nodeN`, cluster credentials `cluster1/secret1pass`, all three listed in `proxysql_servers`, `admin-cluster_leader_election="true"`. Use the `exec`-prefixed `sh -c` spawn form so signals reach proxysql (see `test/tap/tests/test_cluster_leader_election-t.cpp`).
4. Register the backend in **two hostgroups** (e.g. 0 and 1) on each node, add a `testuser` mysql user, and `LOAD MYSQL SERVERS/USERS TO RUNTIME` — doing this while nodes are still `PROXYSQL READWRITE`, then `PROXYSQL READONLY AUTO` (followers refuse writes once election converges).
5. Enable TSDB on all three (`SET tsdb-enabled='1'; LOAD TSDB VARIABLES TO RUNTIME;`).
6. Drive **variable** sysbench load through node 1's mysql port for `DURATION_S`, alternating rate every 60s (e.g. `--rate=20` / `--rate=200` / `--rate=60`) — the point is series/value variety, not stress. If `sysbench` is not installed, print a clear message and fall back to a simple mysql client loop issuing mixed SELECT/INSERT statements, so the script still produces a usable fixture.
7. After the run, dump the leader's window:
   `SELECT timestamp, metric_name, labels, value FROM stats_history.tsdb_metrics WHERE timestamp >= <start> ORDER BY timestamp` → CSV → gzip → `fixtures/seed-10min.csv.gz`. Include a `#` comment line? **No** — `read_seed` uses `csv.DictReader` with a plain header, so write only the header plus data rows. Record provenance (ProxySQL version, capture date, node/series counts) in `fixtures/seed-10min.README` instead.
8. Print the resulting fixture size and **abort with a clear message if it exceeds 2 MB** (spec's abort condition) rather than committing it.
9. Tear down: `PROXYSQL SHUTDOWN` all three, verify no listener remains on 16362/16372/16382, and leave the backend infra running (the harness owns it).

- [ ] **Step 2: Run the capture**

```bash
cd /data/rene/proxysql7/proxysql && bash test/tsdb-lab/capture.bash
```
Expected: a fixture at `test/tsdb-lab/fixtures/seed-10min.csv.gz`, well under 2 MB, plus the provenance file. Record in the report: series count, row count, compressed size.

- [ ] **Step 3: Verify the fixture round-trips through the tool**

```bash
cd test/tsdb-lab && python3 -c "
import expand
rows, s, e = expand.read_seed('fixtures/seed-10min.csv.gz')
print('rows', len(rows), 'span', e - s, 'series', len({(r[1], r[2]) for r in rows}), 'interval', expand.sample_interval(rows))
"
```
Expected: several tens of thousands of rows, span ≈ 600s, a few hundred series, interval 5.

- [ ] **Step 4: Commit**

```bash
git add test/tsdb-lab/capture.bash test/tsdb-lab/fixtures/ test/tsdb-lab/README.md
git commit -m "feat(tsdb-lab): capture script and real-metric seed fixture"
```

---

### Task 4: Measurement script + CI workflow

**Files:**
- Create: `test/tsdb-lab/measure.py`
- Create: `test/tsdb-lab/baseline.json`
- Create: `.github/workflows/CI-tsdb-sizing.yml`
- Modify: `test/tsdb-lab/README.md`

**Interfaces:**
- Consumes: Tasks 1–3 (`expand.py` CLI, the committed fixture).
- Produces: `measure.py --db PATH [--baseline PATH] [--drift-pct 25]` printing a table and exiting non-zero only on bytes/row drift beyond the threshold.

- [ ] **Step 1: Write the measurement script**

Create `test/tsdb-lab/measure.py` (stdlib only). It must:

1. Open the DB read-only (`file:...?mode=ro` URI).
2. For each of `tsdb_metrics`, `tsdb_metrics_hour`, `tsdb_metrics_cluster` (skipping absent tables): row count, and total bytes of the stored payload as a portable proxy —
   `SELECT SUM(LENGTH(metric_name) + LENGTH(labels) + 16) FROM <table>` (plus `LENGTH(node)` for the cluster table) — reported alongside `page_count * page_size` for the whole file, since `dbstat` may not be compiled in. Derive **bytes/row** per table from the payload sum, and note in the output that the file total includes all tables plus index/page overhead.
3. Time two representative queries with `time.perf_counter()`:
   - raw last-1h for a single metric: `SELECT COUNT(*), AVG(value) FROM tsdb_metrics WHERE metric_name=? AND timestamp >= ?`
   - hourly full-span for the same metric: `SELECT COUNT(*), AVG(avg_value) FROM tsdb_metrics_hour WHERE metric_name=?`
   Pick the metric as the most frequent `metric_name` in the raw table.
4. Print a fixed-width table (table, rows, bytes/row, total payload MB) plus the two query timings and the file size.
5. Compare bytes/row per table against `baseline.json` (`{"tsdb_metrics": {"bytes_per_row": N}, ...}`); exit 1 if any exceeds `±drift-pct`; exit 0 otherwise. If a table is missing from the baseline, print it as `NEW` and do not fail.

- [ ] **Step 2: Create the baseline**

Run the full local flow once to generate real numbers, then write `baseline.json` from the measured values:

```bash
cd /data/rene/proxysql7/proxysql
rm -rf /tmp/tsdb-lab-check && mkdir -p /tmp/tsdb-lab-check
printf 'datadir="/tmp/tsdb-lab-check"\nadmin_variables = { admin_credentials="admin:admin"; mysql_ifaces="0.0.0.0:16392" }\nmysql_variables = { threads=2; interfaces="0.0.0.0:16393" }\n' > /tmp/tsdb-lab-check/n.cnf
src/proxysql --initial -f -c /tmp/tsdb-lab-check/n.cnf -D /tmp/tsdb-lab-check &
sleep 4 && mysql -uadmin -padmin -h127.0.0.1 -P16392 -e "PROXYSQL SHUTDOWN"; sleep 2
python3 test/tsdb-lab/expand.py --db /tmp/tsdb-lab-check/proxysql_stats.db --raw-window 1h --span 1d --nodes 3
python3 test/tsdb-lab/measure.py --db /tmp/tsdb-lab-check/proxysql_stats.db
```
(Use the small `1h`/`1d` profile locally; the CI profile is bigger.) Record the printed bytes/row values into `baseline.json`.

- [ ] **Step 3: Write the CI workflow**

Create `.github/workflows/CI-tsdb-sizing.yml`, modeled on the simple structure of `CI-lint-groups-json.yml` (checkout, ubuntu-latest, explicit timeout), with `on: [workflow_dispatch, schedule (nightly cron)]` — **not** `pull_request`, since it is a measurement job. Steps: checkout → build ProxySQL (`PROXYSQL31=1 make -j$(nproc)`; reuse whatever build action the other workflows use if one exists, else plain make) → start once to create the schema and stop → `python3 test/tsdb-lab/expand.py --db <datadir>/proxysql_stats.db --raw-window 24h --span 14d --nodes 3` → start ProxySQL, wait until `tsdb_metrics_hour` stops growing (bounded wait, report the duration — this is the rollup catch-up measurement) → stop → `python3 test/tsdb-lab/measure.py --db ... --baseline test/tsdb-lab/baseline.json` → upload the printed report as a job artifact.

- [ ] **Step 4: Validate the workflow file**

```bash
python3 -c "import sys,yaml" 2>/dev/null && python3 -c "
import yaml, sys
d = yaml.safe_load(open('.github/workflows/CI-tsdb-sizing.yml'))
print('jobs:', list(d['jobs']))
" || echo "PyYAML unavailable — validate by eye against CI-lint-groups-json.yml structure"
```
Expected: parses, one job. (If PyYAML is absent, do the structural comparison manually — do not add a dependency.)

- [ ] **Step 5: Commit**

```bash
git add test/tsdb-lab/measure.py test/tsdb-lab/baseline.json .github/workflows/CI-tsdb-sizing.yml test/tsdb-lab/README.md
git commit -m "feat(tsdb-lab): measurement script, baseline and nightly CI workflow"
```

---

### Task 5: Full-scale local run and findings

**Files:**
- Modify: `docs/superpowers/specs/2026-08-13-tsdb-sizing-lab-design.md` (append a "Measured results" section)

**Interfaces:** consumes everything; produces the numbers that inform projects 2 and 3.

- [ ] **Step 1: Run the CI profile locally**

Same flow as Task 4 Step 2 but with the real profile (`--raw-window 24h --span 14d --nodes 3`) against a fresh datadir. Record: expansion wall-clock, raw/hourly/cluster row counts, bytes/row per table, total DB size, and `measure.py`'s query timings.

- [ ] **Step 2: Measure rollup catch-up under load**

Start ProxySQL on the expanded datadir with `tsdb-enabled=1` and time how long `tsdb_metrics_hour` keeps growing (poll `SELECT COUNT(*)` every second until stable for 5s). This is the unbounded first-pass downsample holding `wrlock` — the reproduction for project 3. Record the duration.

- [ ] **Step 3: Append findings to the spec**

Add a "Measured results (YYYY-MM-DD, ProxySQL <version>)" section with a table of the recorded numbers, and one short paragraph per implication: whether the new retention defaults hold up, how much the cluster tier costs per node, and whether the rollup catch-up duration justifies chunking (project 3).

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-08-13-tsdb-sizing-lab-design.md
git commit -m "docs(tsdb-lab): record first full-scale measurement results"
```
