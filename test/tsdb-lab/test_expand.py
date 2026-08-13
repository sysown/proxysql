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
