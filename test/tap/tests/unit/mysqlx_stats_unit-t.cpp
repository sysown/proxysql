/**
 * mysqlx_stats_unit-t.cpp
 *
 * Unit tests for MysqlxStatsStore and stats_mysqlx_routes table flush.
 */

#include "mysqlx_stats.h"
#include "sqlite3db.h"
#include "tap.h"

#include <string>

int main() {
	plan(7);

	// Test 1-3: Stats counters.
	{
		MysqlxStatsStore store;
		store.record_conn_ok("rw_route");
		store.record_conn_ok("rw_route");
		store.record_conn_err("rw_route");
		store.record_conn_ok("ro_route");

		ok(store.get_conn_ok("rw_route") == 2, "rw_route conn_ok is 2");
		ok(store.get_conn_err("rw_route") == 1, "rw_route conn_err is 1");
		ok(store.get_conn_ok("ro_route") == 1, "ro_route conn_ok is 1");
	}

	// Test 4-7: Flush to SQLite.
	{
		SQLite3DB statsdb;
		statsdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
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
		store.record_conn_ok("test_route");
		store.record_conn_ok("test_route");
		store.record_conn_err("test_route");

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
		store.record_conn_ok("test_route");
		store.flush_to_sqlite(statsdb);
		int conn_ok2 = statsdb.return_one_int(
			"SELECT ConnOK FROM stats_mysqlx_routes WHERE name='test_route'");
		ok(conn_ok2 == 3, "re-flush updates ConnOK to 3");
	}

	return exit_status();
}
