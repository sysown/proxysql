#!/usr/bin/env python3
"""Measure storage and query-cost characteristics of an expanded TSDB
sizing-lab database (see expand.py).

Opens proxysql_stats.db READ-ONLY (the target instance may be running or
stopped; this script never writes to it) and reports, per tier table:

  - row count
  - bytes/row, derived from a portable payload-size proxy (SUM of the
    variable-length column lengths + a fixed per-row overhead), NOT the
    `dbstat` virtual table (which may not be compiled into the linked
    sqlite3 library).
  - total payload size in MB

It also times two representative queries (raw last-1h point lookup, hourly
full-span rollup lookup) and reports the whole-file size via
page_count * page_size (this total includes ALL tables in the database
plus index and page overhead, not just the three TSDB tables measured
here).

Exit status: 0 unless a table's bytes/row has drifted more than
--drift-pct from the value recorded for it in --baseline (default
test/tsdb-lab/baseline.json), in which case it exits 1. A table with no
entry in the baseline is reported as NEW and never fails the run.

Python standard library only.
"""

import argparse
import json
import os
import sqlite3
import sys
import time

DEFAULT_BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")

# table -> (payload SQL expression summed over all rows, extra columns beyond
# the ones common to every tier).
PAYLOAD_EXPR = {
    "tsdb_metrics": "LENGTH(metric_name) + LENGTH(labels) + 16",
    "tsdb_metrics_hour": "LENGTH(metric_name) + LENGTH(labels) + 16",
    "tsdb_metrics_cluster": "LENGTH(metric_name) + LENGTH(labels) + 16 + LENGTH(node)",
}

TABLES = ("tsdb_metrics", "tsdb_metrics_hour", "tsdb_metrics_cluster")


def connect_ro(db_path):
    if not os.path.exists(db_path):
        sys.exit("db does not exist: %s" % db_path)
    uri = "file:%s?mode=ro" % os.path.abspath(db_path)
    return sqlite3.connect(uri, uri=True)


def table_exists(conn, name):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return row is not None


def measure_table(conn, name):
    """Returns dict(rows, payload_bytes, bytes_per_row) or None if the table
    is absent or empty."""
    if not table_exists(conn, name):
        return None
    expr = PAYLOAD_EXPR[name]
    row = conn.execute("SELECT COUNT(*), SUM(%s) FROM %s" % (expr, name)).fetchone()
    rows, payload = row[0], row[1]
    if not rows:
        return {"rows": 0, "payload_bytes": 0, "bytes_per_row": 0.0}
    payload = payload or 0
    return {"rows": rows, "payload_bytes": payload, "bytes_per_row": payload / float(rows)}


def file_size(conn):
    page_count = conn.execute("PRAGMA page_count").fetchone()[0]
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    return page_count, page_size, page_count * page_size


def most_frequent_metric(conn):
    if not table_exists(conn, "tsdb_metrics"):
        return None
    row = conn.execute(
        "SELECT metric_name, COUNT(*) c FROM tsdb_metrics GROUP BY metric_name "
        "ORDER BY c DESC LIMIT 1").fetchone()
    return row[0] if row else None


def time_query(conn, sql, params):
    t0 = time.perf_counter()
    row = conn.execute(sql, params).fetchone()
    elapsed = time.perf_counter() - t0
    return elapsed, row


def run_query_timings(conn):
    """Returns a list of (label, elapsed_seconds_or_None, detail_string)."""
    results = []
    metric = most_frequent_metric(conn)
    if metric is None:
        results.append(("raw last-1h", None, "skipped: no rows in tsdb_metrics"))
        results.append(("hourly full-span", None, "skipped: no rows in tsdb_metrics"))
        return results

    now = int(time.time())
    if table_exists(conn, "tsdb_metrics"):
        elapsed, row = time_query(
            conn,
            "SELECT COUNT(*), AVG(value) FROM tsdb_metrics WHERE metric_name=? AND timestamp >= ?",
            (metric, now - 3600))
        results.append(("raw last-1h (metric=%s)" % metric, elapsed,
                         "rows=%s avg=%s" % (row[0], row[1])))
    else:
        results.append(("raw last-1h", None, "skipped: tsdb_metrics absent"))

    if table_exists(conn, "tsdb_metrics_hour"):
        elapsed, row = time_query(
            conn,
            "SELECT COUNT(*), AVG(avg_value) FROM tsdb_metrics_hour WHERE metric_name=?",
            (metric,))
        results.append(("hourly full-span (metric=%s)" % metric, elapsed,
                         "rows=%s avg=%s" % (row[0], row[1])))
    else:
        results.append(("hourly full-span", None, "skipped: tsdb_metrics_hour absent"))
    return results


def load_baseline(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def compare_to_baseline(table, bytes_per_row, baseline, drift_pct):
    """Returns (status_str, is_drift_failure)."""
    entry = baseline.get(table)
    if entry is None:
        return "NEW", False
    base = entry.get("bytes_per_row")
    if not base:
        return "NEW", False
    drift = (bytes_per_row - base) / float(base) * 100.0
    status = "%+.1f%%" % drift
    return status, abs(drift) > drift_pct


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True, help="proxysql_stats.db to measure (opened read-only)")
    ap.add_argument("--baseline", default=DEFAULT_BASELINE,
                     help="baseline.json to compare bytes/row against (default: %(default)s)")
    ap.add_argument("--drift-pct", type=float, default=25.0,
                     help="fail if bytes/row drifts beyond +/- this percent from baseline (default: 25)")
    args = ap.parse_args(argv)

    conn = connect_ro(args.db)
    baseline = load_baseline(args.baseline)

    measurements = {}
    for table in TABLES:
        measurements[table] = measure_table(conn, table)

    page_count, page_size, total_bytes = file_size(conn)
    query_timings = run_query_timings(conn)

    print("TSDB Sizing Measurement")
    print("========================")
    print("DB: %s" % os.path.abspath(args.db))
    print("File size: %.2f MB (page_count=%d * page_size=%d bytes)" %
          (total_bytes / (1024.0 * 1024.0), page_count, page_size))
    print("  NOTE: file size includes ALL tables in the database plus index")
    print("  and page overhead, not just the tsdb_* tables measured below.")
    print()

    header = "%-24s %12s %14s %16s %14s" % (
        "table", "rows", "bytes/row", "payload MB", "vs baseline")
    print(header)
    print("-" * len(header))

    any_drift_failure = False
    for table in TABLES:
        m = measurements[table]
        if m is None:
            print("%-24s %12s" % (table, "(absent)"))
            continue
        payload_mb = m["payload_bytes"] / (1024.0 * 1024.0)
        status, is_failure = compare_to_baseline(table, m["bytes_per_row"], baseline, args.drift_pct)
        if is_failure:
            any_drift_failure = True
        print("%-24s %12d %14.2f %16.3f %14s" % (
            table, m["rows"], m["bytes_per_row"], payload_mb, status))

    print()
    print("Query timings:")
    for label, elapsed, detail in query_timings:
        if elapsed is None:
            print("  %-40s %s" % (label, detail))
        else:
            print("  %-40s %8.4fs  (%s)" % (label, elapsed, detail))

    print()
    if any_drift_failure:
        print("RESULT: FAIL (bytes/row drift exceeded +/-%.1f%% threshold)" % args.drift_pct)
    else:
        print("RESULT: OK (drift threshold +/-%.1f%%)" % args.drift_pct)

    conn.close()
    return 1 if any_drift_failure else 0


if __name__ == "__main__":
    sys.exit(main())
