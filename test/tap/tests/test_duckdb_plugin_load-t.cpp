#include "ProxySQL_PluginManager.h"
#include "tap.h"

#include <cstring>
#include <string>

#ifndef PROXYSQL_DUCKDB_PLUGIN_PATH
#define PROXYSQL_DUCKDB_PLUGIN_PATH "../../../plugins/duckdb/ProxySQL_DuckDB_Plugin.so"
#endif

int main() {
	plan(5);

	ProxySQL_PluginManager mgr;
	std::string err {};

	const bool loaded = mgr.load(PROXYSQL_DUCKDB_PLUGIN_PATH, err);
	ok(loaded, "load duckdb plugin succeeds");
	if (!loaded) {
		diag("load error: %s", err.c_str());
		BAIL_OUT("duckdb plugin must load before further assertions");
	}

	const bool schemas_ok = mgr.invoke_register_schemas_phase(err);
	ok(schemas_ok, "register_schemas phase succeeds");
	if (!schemas_ok) diag("register_schemas error: %s", err.c_str());

	const bool init_ok = mgr.init_all(err);
	ok(init_ok, "init_all succeeds");
	if (!init_ok) diag("init error: %s", err.c_str());

	const bool stop_ok = mgr.stop_all();
	ok(stop_ok, "stop_all succeeds without start_all");

	// Reloading the same path must be refused, proving the manager tracked it.
	std::string dup_err {};
	const bool dup = mgr.load(PROXYSQL_DUCKDB_PLUGIN_PATH, dup_err);
	ok(dup == false, "loading the same plugin path twice is refused");

	return exit_status();
}
