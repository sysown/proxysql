/**
 * mysqlx_stats_unit-t.cpp
 *
 * Unit tests for MysqlxStatsStore and stats_mysqlx_routes table flush.
 */

#include "mysqlx_stats.h"
#include "sqlite3db.h"
#include "tap.h"

#include <atomic>
#include <string>
#include <thread>
#include <vector>

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(26);
	diag("=== mysqlx_stats_unit-t starting ===");

	// Test 1-3: Stats counters.
	{
		MysqlxStatsStore store;
		store.record_conn_ok("rw_route", 0);
		store.record_conn_ok("rw_route", 0);
		store.record_conn_err("rw_route", 0);
		store.record_conn_ok("ro_route", 0);

		ok(store.get_conn_ok("rw_route") == 2, "rw_route conn_ok is 2");
		ok(store.get_conn_err("rw_route") == 1, "rw_route conn_err is 1");
		ok(store.get_conn_ok("ro_route") == 1, "ro_route conn_ok is 1");
	}

	// Test 4-7: Flush to SQLite.
	{
		SQLite3DB statsdb;
		statsdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		statsdb.execute(
			"CREATE TABLE stats_mysqlx_routes ("
			" name VARCHAR NOT NULL,"
			" destination_hostgroup INT NOT NULL DEFAULT 0,"
			" ConnOK INT NOT NULL DEFAULT 0,"
			" ConnERR INT NOT NULL DEFAULT 0,"
			" ConnUsed INT NOT NULL DEFAULT 0,"
			" Bytes_data_sent BIGINT NOT NULL DEFAULT 0,"
			" Bytes_data_recv BIGINT NOT NULL DEFAULT 0)"
		);

		MysqlxStatsStore store;
		store.record_conn_ok("test_route", 0);
		store.record_conn_ok("test_route", 0);
		store.record_conn_err("test_route", 0);

		store.flush_to_sqlite(statsdb);

		int row_count = statsdb.return_one_int("SELECT COUNT(*) FROM stats_mysqlx_routes");
		ok(row_count == 1, "one route row flushed to stats table");

		int conn_ok = statsdb.return_one_int(
			"SELECT ConnOK FROM stats_mysqlx_routes WHERE name='test_route'");
		ok(conn_ok == 2, "flushed ConnOK is 2");

		int conn_err = statsdb.return_one_int(
			"SELECT ConnERR FROM stats_mysqlx_routes WHERE name='test_route'");
		ok(conn_err == 1, "flushed ConnERR is 1");

		// Flush again — should replace, not accumulate.
		store.record_conn_ok("test_route", 0);
		store.flush_to_sqlite(statsdb);
		int conn_ok2 = statsdb.return_one_int(
			"SELECT ConnOK FROM stats_mysqlx_routes WHERE name='test_route'");
		ok(conn_ok2 == 3, "re-flush updates ConnOK to 3");
	}

	// --- Counter edge cases (Tests 8-12) ---

	{
		MysqlxStatsStore store;
		ok(store.get_conn_ok("nonexistent_route") == 0,
		   "get_conn_ok on nonexistent route returns 0");
	}
	{
		MysqlxStatsStore store;
		ok(store.get_conn_err("nonexistent_route") == 0,
		   "get_conn_err on nonexistent route returns 0");
	}
	{
		MysqlxStatsStore store;
		store.record_conn_ok("triple_route", 0);
		store.record_conn_ok("triple_route", 0);
		store.record_conn_ok("triple_route", 0);
		ok(store.get_conn_ok("triple_route") == 3,
		   "three record_conn_ok calls yields get_conn_ok == 3");
	}
	{
		MysqlxStatsStore store;
		store.record_conn_ok("mixed_route", 0);
		store.record_conn_ok("mixed_route", 0);
		store.record_conn_err("mixed_route", 0);
		ok(store.get_conn_ok("mixed_route") == 2 &&
		   store.get_conn_err("mixed_route") == 1,
		   "conn_ok and conn_err on same route are independent");
	}
	{
		MysqlxStatsStore store;
		store.record_conn_ok("route-with-dashes_v2", 0);
		ok(store.get_conn_ok("route-with-dashes_v2") == 1,
		   "route name with special characters works");
	}

	// --- SQLite flush edge cases (Tests 13-17) ---

	{
		SQLite3DB statsdb;
		statsdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		statsdb.execute(
			"CREATE TABLE stats_mysqlx_routes ("
			" name VARCHAR NOT NULL,"
			" destination_hostgroup INT NOT NULL DEFAULT 0,"
			" ConnOK INT NOT NULL DEFAULT 0,"
			" ConnERR INT NOT NULL DEFAULT 0,"
			" ConnUsed INT NOT NULL DEFAULT 0,"
			" Bytes_data_sent BIGINT NOT NULL DEFAULT 0,"
			" Bytes_data_recv BIGINT NOT NULL DEFAULT 0)"
		);

		MysqlxStatsStore store;
		store.flush_to_sqlite(statsdb);
		int row_count = statsdb.return_one_int("SELECT COUNT(*) FROM stats_mysqlx_routes");
		ok(row_count == 0, "flush with empty stats store yields 0 rows");
	}
	{
		SQLite3DB statsdb;
		statsdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		statsdb.execute(
			"CREATE TABLE stats_mysqlx_routes ("
			" name VARCHAR NOT NULL,"
			" destination_hostgroup INT NOT NULL DEFAULT 0,"
			" ConnOK INT NOT NULL DEFAULT 0,"
			" ConnERR INT NOT NULL DEFAULT 0,"
			" ConnUsed INT NOT NULL DEFAULT 0,"
			" Bytes_data_sent BIGINT NOT NULL DEFAULT 0,"
			" Bytes_data_recv BIGINT NOT NULL DEFAULT 0)"
		);
		statsdb.execute(
			"INSERT INTO stats_mysqlx_routes (name, ConnOK) VALUES ('stale', 999)");

		MysqlxStatsStore store;
		store.record_conn_ok("route_a", 0);
		store.record_conn_ok("route_b", 0);
		store.flush_to_sqlite(statsdb);

		int row_count = statsdb.return_one_int("SELECT COUNT(*) FROM stats_mysqlx_routes");
		ok(row_count == 2, "flush replaces previous rows");
	}
	{
		SQLite3DB statsdb;
		statsdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		statsdb.execute(
			"CREATE TABLE stats_mysqlx_routes ("
			" name VARCHAR NOT NULL,"
			" destination_hostgroup INT NOT NULL DEFAULT 0,"
			" ConnOK INT NOT NULL DEFAULT 0,"
			" ConnERR INT NOT NULL DEFAULT 0,"
			" ConnUsed INT NOT NULL DEFAULT 0,"
			" Bytes_data_sent BIGINT NOT NULL DEFAULT 0,"
			" Bytes_data_recv BIGINT NOT NULL DEFAULT 0)"
		);

		MysqlxStatsStore store;
		store.record_conn_ok("route'name", 0);
		store.flush_to_sqlite(statsdb);

		int row_count = statsdb.return_one_int("SELECT COUNT(*) FROM stats_mysqlx_routes WHERE name='route''name'");
		ok(row_count == 1, "flush handles route name with single quote");
	}
	{
		SQLite3DB statsdb;
		statsdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		statsdb.execute(
			"CREATE TABLE stats_mysqlx_routes ("
			" name VARCHAR NOT NULL,"
			" destination_hostgroup INT NOT NULL DEFAULT 0,"
			" ConnOK INT NOT NULL DEFAULT 0,"
			" ConnERR INT NOT NULL DEFAULT 0,"
			" ConnUsed INT NOT NULL DEFAULT 0,"
			" Bytes_data_sent BIGINT NOT NULL DEFAULT 0,"
			" Bytes_data_recv BIGINT NOT NULL DEFAULT 0)"
		);

		MysqlxStatsStore store;
		store.record_conn_ok("route_a", 0);
		store.record_conn_ok("route_b", 0);
		store.flush_to_sqlite(statsdb);

		int has_a = statsdb.return_one_int("SELECT COUNT(*) FROM stats_mysqlx_routes WHERE name='route_a'");
		int has_b = statsdb.return_one_int("SELECT COUNT(*) FROM stats_mysqlx_routes WHERE name='route_b'");
		ok(has_a == 1 && has_b == 1, "flush with multiple routes: both rows present");
	}
	{
		SQLite3DB statsdb;
		statsdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		statsdb.execute(
			"CREATE TABLE stats_mysqlx_routes ("
			" name VARCHAR NOT NULL,"
			" destination_hostgroup INT NOT NULL DEFAULT 0,"
			" ConnOK INT NOT NULL DEFAULT 0,"
			" ConnERR INT NOT NULL DEFAULT 0,"
			" ConnUsed INT NOT NULL DEFAULT 0,"
			" Bytes_data_sent BIGINT NOT NULL DEFAULT 0,"
			" Bytes_data_recv BIGINT NOT NULL DEFAULT 0)"
		);

		MysqlxStatsStore store;
		for (int i = 0; i < 10000; ++i) {
			store.record_conn_ok("big_route", 0);
		}
		store.flush_to_sqlite(statsdb);

		int conn_ok = statsdb.return_one_int(
			"SELECT ConnOK FROM stats_mysqlx_routes WHERE name='big_route'");
		ok(conn_ok == 10000, "flush with large counter value: ConnOK == 10000");
	}

	// --- Concurrent increment (Tests 18-22) ---

	{
		MysqlxStatsStore store;
		std::vector<std::thread> threads;
		for (int t = 0; t < 4; ++t) {
			threads.emplace_back([&store]() {
				for (int i = 0; i < 1000; ++i) {
					store.record_conn_ok("stress_route", 0);
				}
			});
		}
		for (auto& t : threads) t.join();
		ok(store.get_conn_ok("stress_route") == 4000,
		   "4 threads x 1000 record_conn_ok yields 4000");
	}
	{
		MysqlxStatsStore store;
		std::vector<std::thread> threads;
		for (int t = 0; t < 4; ++t) {
			threads.emplace_back([&store]() {
				for (int i = 0; i < 500; ++i) {
					store.record_conn_ok("mix_route", 0);
				}
				for (int i = 0; i < 500; ++i) {
					store.record_conn_err("mix_route", 0);
				}
			});
		}
		for (auto& t : threads) t.join();
		ok(store.get_conn_ok("mix_route") == 2000 &&
		   store.get_conn_err("mix_route") == 2000,
		   "4 threads mixed ok/err: ok=2000, err=2000");
	}
	{
		MysqlxStatsStore store;
		std::thread ta([&store]() {
			for (int i = 0; i < 1000; ++i)
				store.record_conn_ok("route_A", 0);
		});
		std::thread tb([&store]() {
			for (int i = 0; i < 1000; ++i)
				store.record_conn_ok("route_B", 0);
		});
		ta.join();
		tb.join();
		ok(store.get_conn_ok("route_A") == 1000 &&
		   store.get_conn_ok("route_B") == 1000,
		   "2 threads on different routes: each counter is 1000");
	}
	{
		MysqlxStatsStore store;
		SQLite3DB statsdb;
		statsdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		statsdb.execute(
			"CREATE TABLE stats_mysqlx_routes ("
			" name VARCHAR NOT NULL,"
			" destination_hostgroup INT NOT NULL DEFAULT 0,"
			" ConnOK INT NOT NULL DEFAULT 0,"
			" ConnERR INT NOT NULL DEFAULT 0,"
			" ConnUsed INT NOT NULL DEFAULT 0,"
			" Bytes_data_sent BIGINT NOT NULL DEFAULT 0,"
			" Bytes_data_recv BIGINT NOT NULL DEFAULT 0)"
		);

		std::atomic<bool> done { false };
		std::vector<std::thread> threads;
		for (int t = 0; t < 2; ++t) {
			threads.emplace_back([&store, &done]() {
				while (!done.load()) {
					for (int i = 0; i < 50; ++i)
						store.record_conn_ok("flush_race", 0);
				}
			});
		}
		std::thread flusher([&store, &statsdb, &done]() {
			for (int i = 0; i < 10; ++i)
				store.flush_to_sqlite(statsdb);
			done.store(true);
		});
		for (auto& t : threads) t.join();
		flusher.join();
		ok(true, "concurrent record_conn_ok while flush_to_sqlite: no crash");
	}
	{
		MysqlxStatsStore store;
		std::atomic<bool> writer_done { false };
		std::atomic<uint64_t> min_read { UINT64_MAX };

		std::thread writer([&store, &writer_done]() {
			for (int i = 0; i < 1000; ++i)
				store.record_conn_ok("reader_route", 0);
			writer_done.store(true);
		});
		std::thread reader([&store, &writer_done, &min_read]() {
			while (!writer_done.load()) {
				uint64_t v = store.get_conn_ok("reader_route");
				if (v < min_read.load())
					min_read.store(v);
			}
		});
		writer.join();
		reader.join();
		ok(true, "concurrent get_conn_ok while record_conn_ok: no crash");
	}

	// Test 23-26: bytes_sent / bytes_recv accumulation (P0 of #5691).
	{
		MysqlxStatsStore store;
		store.record_bytes_sent("rw", 1, 100);
		store.record_bytes_sent("rw", 1, 250);
		store.record_bytes_sent("ro", 2, 42);
		store.record_bytes_recv("rw", 1, 1000);
		store.record_bytes_recv("rw", 1, 1500);
		store.record_bytes_recv("ro", 2, 7);
		// Zero-sized payload increments must be a no-op.
		store.record_bytes_sent("rw", 1, 0);
		store.record_bytes_recv("rw", 1, 0);

		// Mix in a conn_used so the row carries multiple counters.
		store.record_conn_used("rw", 1);

		SQLite3DB statsdb;
		statsdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		statsdb.execute(
			"CREATE TABLE stats_mysqlx_routes ("
			" name TEXT PRIMARY KEY,"
			" destination_hostgroup INT NOT NULL DEFAULT 0,"
			" ConnOK INT NOT NULL DEFAULT 0,"
			" ConnERR INT NOT NULL DEFAULT 0,"
			" ConnUsed INT NOT NULL DEFAULT 0,"
			" Bytes_data_sent BIGINT NOT NULL DEFAULT 0,"
			" Bytes_data_recv BIGINT NOT NULL DEFAULT 0)"
		);
		store.flush_to_sqlite(statsdb);

		int rw_sent = statsdb.return_one_int(
			"SELECT Bytes_data_sent FROM stats_mysqlx_routes WHERE name='rw'");
		int ro_sent = statsdb.return_one_int(
			"SELECT Bytes_data_sent FROM stats_mysqlx_routes WHERE name='ro'");
		ok(rw_sent == 350 && ro_sent == 42,
		   "bytes_sent accumulates per route (rw=%d ro=%d)", rw_sent, ro_sent);

		int rw_recv = statsdb.return_one_int(
			"SELECT Bytes_data_recv FROM stats_mysqlx_routes WHERE name='rw'");
		int ro_recv = statsdb.return_one_int(
			"SELECT Bytes_data_recv FROM stats_mysqlx_routes WHERE name='ro'");
		ok(rw_recv == 2500 && ro_recv == 7,
		   "bytes_recv accumulates per route (rw=%d ro=%d)", rw_recv, ro_recv);

		int rw_used = statsdb.return_one_int(
			"SELECT ConnUsed FROM stats_mysqlx_routes WHERE name='rw'");
		ok(rw_used == 1, "ConnUsed flushes to SQLite alongside bytes counters");

		int ro_hg = statsdb.return_one_int(
			"SELECT destination_hostgroup FROM stats_mysqlx_routes WHERE name='ro'");
		ok(ro_hg == 2, "destination_hostgroup carried through bytes-only flush");
	}

	return exit_status();
}
