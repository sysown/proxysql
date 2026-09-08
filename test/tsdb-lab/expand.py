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
    print("elapsed: %.1fs" % (time.time() - t0))
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
