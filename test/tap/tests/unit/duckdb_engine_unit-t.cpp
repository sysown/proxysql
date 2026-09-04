#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "tap.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

int main() {
	plan(12);

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
		duckdb_result ext_res;
		const bool denied = (duckdb_query(conn,
			"SELECT * FROM read_csv('/proxysql-duckdb-external-access-probe.csv')",
			&ext_res) != DuckDBSuccess);
		const char* ext_error = duckdb_result_error(&ext_res);
		const bool disabled_by_configuration = denied && ext_error != nullptr &&
			std::string(ext_error).find("disabled by configuration") != std::string::npos;
		ok(disabled_by_configuration,
		   "read_csv of a local file is denied with the default configuration "
		   "(enable_external_access=false)");
		if (!disabled_by_configuration) {
			diag("unexpected read_csv result: %s", ext_error != nullptr ? ext_error : "success");
		}
		duckdb_destroy_result(&ext_res);
	}

	engine.disconnect(&conn);
	ok(conn == nullptr, "disconnect nulls the caller's handle");
	ok(engine.open_connections() == 0, "open_connections drops back to zero");

	engine.close();
	ok(engine.is_open() == false, "close makes the engine closed");

	// close() must be idempotent: stop() can run without start().
	engine.close();
	ok(engine.is_open() == false, "close is idempotent");

	{
		err.clear();
		if (!engine.open(cfg, err)) {
			diag("reopen error: %s", err.c_str());
			BAIL_OUT("engine must reopen for interrupt_all");
		}
		duckdb_connection ic = nullptr;
		err.clear();
		if (!engine.connect(&ic, err) || ic == nullptr) {
			BAIL_OUT("interrupt test needs a live connection");
		}
		std::atomic<int> rc{-1};
		std::atomic<bool> started{false};
		std::atomic<bool> done{false};
		std::thread t([&] {
			started.store(true);
			duckdb_result r;
			rc.store(duckdb_query(ic, "SELECT sum(i) FROM range(10000000000) t(i)", &r));
			duckdb_destroy_result(&r);
			done.store(true);
		});
		const auto start_deadline = std::chrono::steady_clock::now() +
			std::chrono::seconds(1);
		while (!started.load() && std::chrono::steady_clock::now() < start_deadline) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		if (!started.load()) {
			BAIL_OUT("interrupt worker did not start within one second");
		}
		// Give duckdb_query() a chance to enter execution after publishing
		// `started`, then interrupt it and bound the shutdown wait.
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
		engine.interrupt_all();
		const auto done_deadline = std::chrono::steady_clock::now() +
			std::chrono::seconds(5);
		while (!done.load() && std::chrono::steady_clock::now() < done_deadline) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		if (!done.load()) {
			BAIL_OUT("interrupt_all did not stop the query within five seconds");
		}
		t.join();
		ok(rc.load() != DuckDBSuccess, "interrupt_all stops an in-flight query");
		engine.disconnect(&ic);
		engine.close();
	}

	return exit_status();
}
