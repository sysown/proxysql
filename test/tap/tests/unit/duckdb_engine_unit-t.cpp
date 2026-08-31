#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "tap.h"

#include <cstdio>
#include <string>

int main() {
	plan(11);

	DuckDBConfigStore cfg;
	std::string err;

	DuckDBEngine engine;
	ok(engine.is_open() == false, "engine starts closed");

	ok(engine.open(cfg, err), "open with defaults (:memory:) succeeds");
	if (!engine.is_open()) {
		diag("open error: %s", err.c_str());
		BAIL_OUT("engine must open before connection assertions");
	}
	ok(engine.is_open(), "is_open reports true after open");

	duckdb_connection conn = nullptr;
	err.clear();
	ok(engine.connect(&conn, err) && conn != nullptr, "connect yields a connection");
	ok(engine.open_connections() == 1, "open_connections counts the connection");

	// A query must actually run, otherwise "open" proves nothing.
	duckdb_result res;
	const bool q_ok = (duckdb_query(conn, "SELECT 42 AS answer", &res) == DuckDBSuccess);
	ok(q_ok, "a trivial query executes on the connection");
	if (q_ok) duckdb_destroy_result(&res);

	// I1 fix: DuckDB's own default for enable_external_access is true
	// (deps/duckdb/duckdb/src/include/duckdb/main/config.hpp), which would
	// let any mysql_users/pgsql_users credential read/write arbitrary local
	// files as the ProxySQL process user. DuckDBEngine::open() must
	// override that default; assert it on the *default* DuckDBConfigStore
	// (cfg above, untouched) so this test fails if the override is ever
	// dropped, not just if someone explicitly sets the variable wrong.
	{
		const char* tmp_csv = "/tmp/duckdb_engine_unit_test_external_access.csv";
		FILE* f = std::fopen(tmp_csv, "w");
		if (f == nullptr) {
			BAIL_OUT("could not create the external-access CSV fixture");
		}
		std::fputs("a,b\n1,2\n", f);
		std::fclose(f);

		const std::string q = std::string("SELECT * FROM read_csv('") + tmp_csv + "')";
		duckdb_result ext_res;
		const bool denied = (duckdb_query(conn, q.c_str(), &ext_res) != DuckDBSuccess);
		ok(denied, "read_csv of a local file is denied with the default configuration "
		           "(enable_external_access=false)");
		duckdb_destroy_result(&ext_res);
		std::remove(tmp_csv);
	}

	engine.disconnect(&conn);
	ok(conn == nullptr, "disconnect nulls the caller's handle");
	ok(engine.open_connections() == 0, "open_connections drops back to zero");

	engine.close();
	ok(engine.is_open() == false, "close makes the engine closed");

	// close() must be idempotent: stop() can run without start().
	engine.close();
	ok(engine.is_open() == false, "close is idempotent");

	return exit_status();
}
