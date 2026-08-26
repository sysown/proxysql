#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "tap.h"

#include <string>

int main() {
	plan(10);

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
