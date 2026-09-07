#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "tap.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <optional>
#include <string>
#include <thread>

namespace {

std::string setting(duckdb_connection conn, const char* name) {
	duckdb_result res;
	const std::string sql = std::string("SELECT current_setting('") + name + "')::VARCHAR";
	if (duckdb_query(conn, sql.c_str(), &res) != DuckDBSuccess) {
		duckdb_destroy_result(&res);
		return {};
	}
	const char* value = duckdb_value_varchar(&res, 0, 0);
	const std::string out = value != nullptr ? value : "";
	duckdb_free(const_cast<char*>(value));
	duckdb_destroy_result(&res);
	return out;
}

} // namespace

int main() {
	plan(25);

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

	DuckDBEffectiveSettings initial;
	err.clear();
	ok(engine.effective_settings(initial, err) && initial.threads == 2 &&
	   !initial.enable_external_access && initial.database_path == ":memory:",
	   "effective settings are read from the opened engine");

	duckdb_connection second = nullptr;
	err.clear();
	ok(engine.connect(&second, err) && second != nullptr,
	   "a second connection can remain open across live configuration changes");

	DuckDBLiveSettings live;
	live.memory_limit = "512MB";
	live.threads = 4;
	live.max_connections = 3;
	err.clear();
	ok(engine.apply_live_settings(live, err),
	   "memory_limit, threads, and max_connections apply live");
	ok(setting(conn, "threads") == "4" && setting(second, "threads") == "4",
	   "a live threads change is visible through both existing connections");
	ok(setting(conn, "memory_limit") == "488.2 MiB" &&
	   setting(second, "memory_limit") == "488.2 MiB",
	   "a live memory change is canonical and visible through both existing connections");

	DuckDBEffectiveSettings changed;
	err.clear();
	ok(engine.effective_settings(changed, err) && changed.threads == 4 &&
	   changed.memory_limit == "488.2 MiB" && changed.max_connections == 3,
	   "effective settings report DuckDB readback and admission state");

	DuckDBLiveSettings invalid;
	invalid.memory_limit = "not-a-memory-limit";
	invalid.threads = 7;
	err.clear();
	ok(!engine.apply_live_settings(invalid, err) && setting(conn, "threads") == "4",
	   "a mixed invalid change is rejected before its valid setting applies");

	DuckDBLiveSettings loosen;
	loosen.enable_external_access = true;
	err.clear();
	ok(!engine.apply_live_settings(loosen, err) &&
	   err.find("cannot be enabled") != std::string::npos,
	   "external access cannot be enabled on an open database");

	engine.disconnect(&second);

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

	ok(engine.try_reserve_connection() && engine.try_reserve_connection() &&
	   engine.try_reserve_connection(), "the applied connection limit admits three reservations");
	engine.set_max_connections(1);
	ok(!engine.try_reserve_connection(),
	   "lowering max_connections preserves existing reservations but rejects new admission");
	engine.release_connection();
	engine.release_connection();
	engine.release_connection();

	engine.close();
	ok(engine.is_open() == false, "close makes the engine closed");

	// close() must be idempotent: stop() can run without start().
	engine.close();
	ok(engine.is_open() == false, "close is idempotent");

	{
		DuckDBConfigStore permissive_cfg;
		err.clear();
		if (!permissive_cfg.set("enable_external_access", "true", err)) {
			BAIL_OUT("external-access test configuration must be valid");
		}
		DuckDBEngine permissive_engine;
		err.clear();
		if (!permissive_engine.open(permissive_cfg, err)) {
			diag("permissive open error: %s", err.c_str());
			BAIL_OUT("external-access test engine must open");
		}
		DuckDBEffectiveSettings permissive;
		err.clear();
		ok(permissive_engine.effective_settings(permissive, err) &&
		   permissive.enable_external_access,
		   "external access can be enabled when the database opens");

		duckdb_connection existing = nullptr;
		err.clear();
		if (!permissive_engine.connect(&existing, err) || existing == nullptr) {
			BAIL_OUT("external-access test needs an existing connection");
		}
		DuckDBLiveSettings tighten;
		tighten.enable_external_access = false;
		err.clear();
		ok(permissive_engine.apply_live_settings(tighten, err),
		   "external access can be disabled live");
		DuckDBEffectiveSettings tightened;
		err.clear();
		ok(permissive_engine.effective_settings(tightened, err) &&
		   !tightened.enable_external_access &&
		   setting(existing, "enable_external_access") == "false",
		   "the irreversible tightening is visible to an existing connection and readback");
		permissive_engine.disconnect(&existing);
		permissive_engine.close();
	}

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
