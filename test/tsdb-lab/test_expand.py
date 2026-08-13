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
        attempted = expand.expand_raw(self.conn, self.rows, self.start, self.end, 100000, 100060)
        n = self.conn.execute("SELECT COUNT(*) FROM tsdb_metrics").fetchone()[0]
        self.assertEqual(n, 24)
        self.assertEqual(attempted, 24, "return value (attempted inserts) must equal len(rows) * tiles = 6 * 4")

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

    def test_stride_produces_exact_tile_boundaries(self):
        # Stride = (1010-1000) + 5 = 15s. Window 100000..100060 has 4 tiles at offsets 0, 15, 30, 45.
        # Fixture block at [1000,1005,1010]. Offsets produce [100000,100005,100010], [100015,100020,100025], etc.
        # Expected distinct timestamps within [100000,100060): [100000,100005,100010, 100015,100020,100025, 100030,100035,100040, 100045,100050,100055]
        expand.expand_raw(self.conn, self.rows, self.start, self.end, 100000, 100060)
        ts = sorted([r[0] for r in self.conn.execute(
            "SELECT DISTINCT timestamp FROM tsdb_metrics ORDER BY timestamp")])
        expected = [100000, 100005, 100010, 100015, 100020, 100025, 100030, 100035, 100040, 100045, 100050, 100055]
        self.assertEqual(ts, expected, "stride must produce exact tile offsets: got %s" % ts)


class TestTableExists(unittest.TestCase):
    def test_detects_presence_and_absence(self):
        with tempfile.TemporaryDirectory() as d:
            conn = sqlite3.connect(os.path.join(d, "x.db"))
            conn.execute(RAW_DDL)
            self.assertTrue(expand.table_exists(conn, "tsdb_metrics"))
            self.assertFalse(expand.table_exists(conn, "tsdb_metrics_cluster"))
            conn.close()


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


if __name__ == "__main__":
    unittest.main()
