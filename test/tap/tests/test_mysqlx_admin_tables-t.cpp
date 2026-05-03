// test_mysqlx_admin_tables-t
//
// Verifies the LOAD/SAVE admin-command pipeline introduced by the mysqlx
// plugin chassis restructure. Under the new architecture:
//
//   * `LOAD MYSQLX <X> TO RUNTIME` populates an in-memory `MysqlxConfigStore`
//     (inside the plugin .so), reading from the editable admin tables
//     `mysqlx_<X>` plus the cross-module canonical tables `runtime_mysql_users`
//     / `runtime_mysql_servers`. It does NOT write to `runtime_mysqlx_<X>`;
//     that table is an admin-side projection refreshed on demand by the
//     chassis register_runtime_view callbacks (which only fire on an admin
//     SELECT through the admin handler, not via raw SQLite3DB::execute).
//
//   * `SAVE MYSQLX <X> TO MEMORY` dumps the in-memory store contents into the
//     editable `mysqlx_<X>` table. It does NOT read `runtime_mysqlx_<X>`.
//
// This test loads the actual mysqlx plugin .so via dlopen, so admin commands
// dispatch through the plugin's real `mysqlx_context().config_store`. The
// test executable cannot reach the store directly (RTLD_LOCAL hides the
// plugin's symbols at link time), so assertions about store state are made
// indirectly by round-tripping LOAD -> DELETE editable -> SAVE -> inspect
// editable. If SAVE re-materializes the rows, the data really lived in the
// in-memory store between LOAD and SAVE.
//
// Cross-module seeding: `install_users_from_admin` joins
// `runtime_mysql_users WHERE active=1 AND frontend=1` with
// `mysqlx_users WHERE active=1` and silently drops any mysqlx user with no
// canonical row. `install_endpoints_from_admin` reads
// `runtime_mysql_servers WHERE UPPER(status)='ONLINE'` for the per-hostgroup
// resolved view. Both tables must exist (and, where appropriate, be seeded)
// for the install path to find rows.

#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "sqlite3db.h"
#include "tap.h"
#include "test_init.h"

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#ifndef PROXYSQL_MYSQLX_PLUGIN_PATH
#error "PROXYSQL_MYSQLX_PLUGIN_PATH must be defined"
#endif

namespace {

SQLite3DB* g_admin_db = nullptr;
SQLite3DB* g_config_db = nullptr;
SQLite3DB* g_stats_db = nullptr;

const ProxySQL_PluginTableDef* find_table(
	const std::vector<ProxySQL_PluginTableDef>& tables,
	const char* name
) {
	for (const auto& table : tables) {
		if (table.table_name != nullptr &&
		    name != nullptr &&
		    std::strcmp(table.table_name, name) == 0) {
			return &table;
		}
	}
	return nullptr;
}

bool build_registered_tables(SQLite3DB& db, const std::vector<ProxySQL_PluginTableDef>& tables) {
	diag(">>> %s", __func__);
	for (const auto& table : tables) {
		if (table.table_name == nullptr || table.table_def == nullptr) {
			return false;
		}
		if (!db.check_and_build_table(const_cast<char*>(table.table_name),
		                              const_cast<char*>(table.table_def))) {
			return false;
		}
	}
	return true;
}

// Seed the cross-module canonical tables required by the mysqlx install
// pipeline:
//
//   * runtime_mysql_users provides password / default_hostgroup /
//     max_connections for each frontend identity. Without a matching
//     active=1, frontend=1 row, install_users_from_admin drops the
//     mysqlx user silently.
//   * runtime_mysql_servers feeds install_endpoints_from_admin's
//     per-hostgroup view (`SELECT ... WHERE UPPER(status)='ONLINE'`).
//
// The schema strings come straight from include/ProxySQL_Admin_Tables_
// Definitions.h so any future column changes propagate here automatically.
void seed_canonical_tables(SQLite3DB& db) {
	diag(">>> %s", __func__);
	db.execute(ADMIN_SQLITE_RUNTIME_MYSQL_USERS);
	db.execute(ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS);
}

void seed_canonical_user(SQLite3DB& db, const char* username, int default_hostgroup) {
	std::string sql =
		"INSERT INTO runtime_mysql_users "
		"(username, password, active, use_ssl, default_hostgroup, default_schema, "
		"schema_locked, transaction_persistent, fast_forward, backend, frontend, "
		"max_connections, attributes, comment) VALUES ('";
	sql += username;
	sql += "', 'pw', 1, 0, ";
	sql += std::to_string(default_hostgroup);
	sql += ", NULL, 0, 1, 0, 0, 1, 25, '', 'canonical')";
	db.execute(sql.c_str());
}

void seed_canonical_server(SQLite3DB& db, int hostgroup_id, const char* hostname, int port) {
	std::string sql = "INSERT INTO runtime_mysql_servers "
		"(hostgroup_id, hostname, port, status, weight, use_ssl) VALUES (";
	sql += std::to_string(hostgroup_id);
	sql += ", '";
	sql += hostname;
	sql += "', ";
	sql += std::to_string(port);
	sql += ", 'ONLINE', 1, 0)";
	db.execute(sql.c_str());
}

std::string select_string(SQLite3DB& db, const char* sql) {
	char* error = nullptr;
	std::unique_ptr<SQLite3_result> result { db.execute_statement(sql, &error) };
	std::string value {};
	if (error == nullptr &&
	    result != nullptr &&
	    result->rows_count > 0 &&
	    !result->rows.empty() &&
	    result->rows[0] != nullptr &&
	    result->rows[0]->fields[0] != nullptr) {
		value = result->rows[0]->fields[0];
	}
	if (error != nullptr) {
		free(error);
	}
	return value;
}

} // namespace

SQLite3DB* proxysql_plugin_get_admindb() {
	return g_admin_db;
}

SQLite3DB* proxysql_plugin_get_configdb() {
	return g_config_db;
}

SQLite3DB* proxysql_plugin_get_statsdb() {
	return g_stats_db;
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(45);
	diag("=== test_mysqlx_admin_tables-t starting ===");

	ok(test_init_minimal() == 0, "minimal test globals initialize");

	SQLite3DB admin_db {};
	SQLite3DB config_db {};
	SQLite3DB stats_db {};
	ok(admin_db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX) == 0,
	   "admin sqlite opens");
	ok(config_db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX) == 0,
	   "config sqlite opens");
	ok(stats_db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX) == 0,
	   "stats sqlite opens");

	g_admin_db = &admin_db;
	g_config_db = &config_db;
	g_stats_db = &stats_db;

	ProxySQL_PluginManager mgr;
	std::string err {};

	const bool loaded = mgr.load(PROXYSQL_MYSQLX_PLUGIN_PATH, err);
	ok(loaded, "mysqlx plugin loads for admin table test");
	if (!loaded) {
		diag("load error: %s", err.c_str());
		BAIL_OUT("mysqlx plugin must load before admin table assertions");
	}

	// Schema registration moved from init() to register_schemas() (Phase B)
	// as part of the four-phase plugin lifecycle. Admin command registration
	// still happens in init() (Phase D).
	ok(mgr.invoke_register_schemas_phase(err),
	   "mysqlx plugin register_schemas publishes admin tables");
	if (!err.empty()) {
		diag("register_schemas error: %s", err.c_str());
	}
	ok(mgr.init_all(err), "mysqlx plugin init completes after register_schemas");
	if (!err.empty()) {
		diag("init error: %s", err.c_str());
	}

	const auto& admin_tables = mgr.tables(ProxySQL_PluginDBKind::admin_db);
	const auto& config_tables = mgr.tables(ProxySQL_PluginDBKind::config_db);
	const ProxySQL_PluginTableDef* mysqlx_users = find_table(admin_tables, "mysqlx_users");
	const ProxySQL_PluginTableDef* runtime_mysqlx_users = find_table(admin_tables, "runtime_mysqlx_users");
	const ProxySQL_PluginTableDef* mysqlx_routes = find_table(admin_tables, "mysqlx_routes");
	const ProxySQL_PluginTableDef* runtime_mysqlx_routes = find_table(admin_tables, "runtime_mysqlx_routes");
	const ProxySQL_PluginTableDef* mysqlx_backend_endpoints = find_table(admin_tables, "mysqlx_backend_endpoints");
	const ProxySQL_PluginTableDef* runtime_mysqlx_backend_endpoints = find_table(admin_tables, "runtime_mysqlx_backend_endpoints");

	ok(mysqlx_users != nullptr, "mysqlx_users is registered in admin_db");
	ok(runtime_mysqlx_users != nullptr, "runtime_mysqlx_users is registered in admin_db");
	ok(mysqlx_routes != nullptr, "mysqlx_routes is registered in admin_db");
	ok(runtime_mysqlx_routes != nullptr, "runtime_mysqlx_routes is registered in admin_db");
	ok(mysqlx_backend_endpoints != nullptr, "mysqlx_backend_endpoints is registered in admin_db");
	ok(runtime_mysqlx_backend_endpoints != nullptr, "runtime_mysqlx_backend_endpoints is registered in admin_db");

	if (runtime_mysqlx_users == nullptr ||
	    runtime_mysqlx_routes == nullptr ||
	    runtime_mysqlx_backend_endpoints == nullptr) {
		BAIL_OUT("mysqlx runtime tables must exist before load-to-runtime behavior can be verified");
	}

	ok(build_registered_tables(admin_db, admin_tables), "registered admin tables materialize in sqlite");
	ok(build_registered_tables(config_db, config_tables), "registered config tables materialize in sqlite");

	// Seed cross-module canonical state. install_users_from_admin requires
	// the `runtime_mysql_users` row(s) for any user it should keep; without
	// these the user is silently dropped from the store. Endpoint LOAD needs
	// at least one ONLINE row in `runtime_mysql_servers` for the destination
	// hostgroup, otherwise hostgroup_endpoints_ ends up empty and the SAVE
	// roundtrip would project zero servers back even though the per-host
	// override row in mysqlx_backend_endpoints persists.
	seed_canonical_tables(admin_db);
	seed_canonical_user(admin_db, "alice", 42);
	seed_canonical_server(admin_db, 42, "db1.internal", 3306);

	ok(admin_db.execute("INSERT INTO mysqlx_users (username, active, allowed_auth_methods, default_route, backend_auth_mode, attributes, comment) "
	                    "VALUES ('alice', 1, 'PLAIN', 'rw', 'pass_through', '', 'frontend user')"),
	   "seed mysqlx_users row");
	ok(admin_db.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active, comment) "
	                    "VALUES ('rw', '127.0.0.1:6603', 42, 43, 'first_available', 1, 'route row')"),
	   "seed mysqlx_routes row");
	ok(admin_db.execute("INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port, comment) "
	                    "VALUES ('db1.internal', 3306, 33060, 'endpoint row')"),
	   "seed mysqlx_backend_endpoints row");

	ProxySQL_PluginCommandContext ctx { &admin_db, &config_db, &stats_db };
	ProxySQL_PluginCommandResult result { 1, 0, "" };

	// LOAD ... TO RUNTIME populates the in-memory store. We can't read the
	// store directly from this binary (RTLD_LOCAL), so we verify the store
	// state by SAVE-ing back to the editable mysqlx_<X> table after deleting
	// it: if SAVE re-materializes the rows we seeded, they really did live
	// in the in-memory store between LOAD and SAVE. The plugin's
	// load_users_to_runtime callback also returns rows_affected = number of
	// rows it consumed from mysqlx_users WHERE active=1, which we use as a
	// secondary check on the source side.
	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   result.rows_affected == 1,
	   "LOAD MYSQLX USERS TO RUNTIME consumes one active mysqlx_users row into the store");
	admin_db.execute("DELETE FROM mysqlx_users");
	ok(mgr.dispatch_admin_command(ctx, "SAVE MYSQLX USERS TO MEMORY", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_users WHERE active=1") == 1 &&
	   select_string(admin_db, "SELECT backend_auth_mode FROM mysqlx_users WHERE username='alice' AND active=1") == "pass_through",
	   "SAVE MYSQLX USERS TO MEMORY round-trips the in-memory store back to mysqlx_users with the seeded backend_auth_mode");

	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX ROUTES TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   result.rows_affected == 1,
	   "LOAD MYSQLX ROUTES TO RUNTIME consumes one active mysqlx_routes row into the store");
	admin_db.execute("DELETE FROM mysqlx_routes");
	ok(mgr.dispatch_admin_command(ctx, "SAVE MYSQLX ROUTES TO MEMORY", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_routes WHERE active=1") == 1 &&
	   admin_db.return_one_int("SELECT destination_hostgroup FROM mysqlx_routes WHERE name='rw' AND active=1") == 42,
	   "SAVE MYSQLX ROUTES TO MEMORY round-trips the in-memory store back to mysqlx_routes");

	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", result) &&
	   result.error_code == 0 &&
	   result.rows_affected == 1,
	   "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME consumes one mysqlx_backend_endpoints override into the store");
	admin_db.execute("DELETE FROM mysqlx_backend_endpoints");
	ok(mgr.dispatch_admin_command(ctx, "SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY", result) &&
	   result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_backend_endpoints") == 1 &&
	   admin_db.return_one_int("SELECT mysqlx_port FROM mysqlx_backend_endpoints WHERE hostname='db1.internal' AND mysql_port=3306") == 33060,
	   "SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY round-trips the in-memory override back to mysqlx_backend_endpoints");

	// Re-seed mysqlx_users / mysqlx_routes / mysqlx_backend_endpoints from
	// the just-completed SAVE roundtrip so the rest of the test sees a
	// canonical "alice/rw/db1.internal" set in the editable tables.

	// ---- LOAD edge cases (7) ----

	// Empty-source LOAD: with the canonical tables seeded but completely
	// empty, LOAD must succeed and leave the store empty. We verify this
	// by SAVE-ing afterwards: with an empty store, SAVE should mark every
	// existing row as active=0 (users/routes) or DELETE everything
	// (endpoints), so the editable table ends up with zero active rows.
	{
		SQLite3DB fresh_admin {};
		SQLite3DB fresh_config {};
		SQLite3DB fresh_stats {};
		fresh_admin.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		fresh_config.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		fresh_stats.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		build_registered_tables(fresh_admin, admin_tables);
		build_registered_tables(fresh_config, config_tables);
		seed_canonical_tables(fresh_admin);
		ProxySQL_PluginCommandContext fresh_ctx { &fresh_admin, &fresh_config, &fresh_stats };
		ProxySQL_PluginCommandResult fresh_result { 1, 0, "" };
		ok(mgr.dispatch_admin_command(fresh_ctx, "LOAD MYSQLX USERS TO RUNTIME", fresh_result) &&
		   fresh_result.error_code == 0 &&
		   fresh_result.rows_affected == 0,
		   "LOAD MYSQLX USERS TO RUNTIME with empty mysqlx_users — succeeds, rows_affected==0");
		mgr.dispatch_admin_command(fresh_ctx, "SAVE MYSQLX USERS TO MEMORY", fresh_result);
		ok(fresh_result.error_code == 0 &&
		   fresh_admin.return_one_int("SELECT COUNT(*) FROM mysqlx_users WHERE active=1") == 0,
		   "after empty LOAD, SAVE leaves zero active mysqlx_users rows (store was empty)");

		ok(mgr.dispatch_admin_command(fresh_ctx, "LOAD MYSQLX ROUTES TO RUNTIME", fresh_result) &&
		   fresh_result.error_code == 0 &&
		   fresh_result.rows_affected == 0,
		   "LOAD MYSQLX ROUTES TO RUNTIME with empty mysqlx_routes — succeeds, rows_affected==0");

		ok(mgr.dispatch_admin_command(fresh_ctx, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", fresh_result) &&
		   fresh_result.error_code == 0 &&
		   fresh_result.rows_affected == 0,
		   "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME with empty mysqlx_backend_endpoints — succeeds, rows_affected==0");
	}

	// Re-LOAD the original ctx so the store reflects the original admin_db
	// again (the fresh_admin block above swapped the global store to point
	// at fresh_admin's empty contents).
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result);
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX ROUTES TO RUNTIME", result);
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", result);

	// LOAD twice: replace, not merge. Add bob to mysqlx_users + canonical
	// table, LOAD, then SAVE with mysqlx_users wiped; the rebuilt editable
	// table should contain exactly the post-replace store contents (alice +
	// bob, both active), not stale rows.
	seed_canonical_user(admin_db, "bob", 43);
	admin_db.execute("INSERT INTO mysqlx_users (username, active, allowed_auth_methods, default_route, backend_auth_mode, attributes, comment) "
	                 "VALUES ('bob', 1, 'MYSQL41', 'ro', 'mapped', '', 'second user')");
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result);
	admin_db.execute("DELETE FROM mysqlx_users");
	mgr.dispatch_admin_command(ctx, "SAVE MYSQLX USERS TO MEMORY", result);
	ok(result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_users WHERE active=1") == 2,
	   "LOAD twice — second LOAD replaces store contents (post-roundtrip count is 2 not stale)");

	// LOAD after modifying config: the in-memory store reflects the new
	// value. Verified by SAVE roundtrip — the editable table should hold
	// the modified `backend_auth_mode='service_account'` for alice after
	// LOAD->SAVE. Note: only the three canonical enum values
	// (mapped/service_account/pass_through) survive the roundtrip;
	// mysqlx_backend_auth_mode_from_string normalises anything else to
	// `mapped`, so we cannot use an arbitrary string here.
	admin_db.execute("UPDATE mysqlx_users SET backend_auth_mode='service_account' WHERE username='alice'");
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result);
	admin_db.execute("DELETE FROM mysqlx_users");
	mgr.dispatch_admin_command(ctx, "SAVE MYSQLX USERS TO MEMORY", result);
	ok(result.error_code == 0 &&
	   select_string(admin_db, "SELECT backend_auth_mode FROM mysqlx_users WHERE username='alice' AND active=1") == "service_account",
	   "LOAD after modifying config — in-memory store reflects the new value (verified by SAVE roundtrip)");

	{
		ProxySQL_PluginCommandContext null_ctx { nullptr, &config_db, &stats_db };
		ProxySQL_PluginCommandResult null_result { 0, 0, "" };
		mgr.dispatch_admin_command(null_ctx, "LOAD MYSQLX USERS TO RUNTIME", null_result);
		ok(null_result.error_code != 0,
		   "LOAD with null admindb in context — returns error_code != 0");
	}

	// LOAD with multiple rows: seed three mysqlx_users and three matching
	// canonical rows, LOAD, then SAVE-back. After roundtrip the editable
	// table should hold three active rows.
	{
		SQLite3DB multi_admin {};
		SQLite3DB multi_config {};
		SQLite3DB multi_stats {};
		multi_admin.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		multi_config.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		multi_stats.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		build_registered_tables(multi_admin, admin_tables);
		build_registered_tables(multi_config, config_tables);
		seed_canonical_tables(multi_admin);
		seed_canonical_user(multi_admin, "u1", 10);
		seed_canonical_user(multi_admin, "u2", 11);
		seed_canonical_user(multi_admin, "u3", 12);
		multi_admin.execute("INSERT INTO mysqlx_users (username, active, allowed_auth_methods, backend_auth_mode, attributes, comment) "
		                    "VALUES ('u1', 1, 'PLAIN', 'mapped', '', '')");
		multi_admin.execute("INSERT INTO mysqlx_users (username, active, allowed_auth_methods, backend_auth_mode, attributes, comment) "
		                    "VALUES ('u2', 1, 'MYSQL41', 'mapped', '', '')");
		multi_admin.execute("INSERT INTO mysqlx_users (username, active, allowed_auth_methods, backend_auth_mode, attributes, comment) "
		                    "VALUES ('u3', 1, 'PLAIN', 'native', '', '')");
		ProxySQL_PluginCommandContext multi_ctx { &multi_admin, &multi_config, &multi_stats };
		ProxySQL_PluginCommandResult multi_result { 1, 0, "" };
		ok(mgr.dispatch_admin_command(multi_ctx, "LOAD MYSQLX USERS TO RUNTIME", multi_result) &&
		   multi_result.error_code == 0 &&
		   multi_result.rows_affected == 3,
		   "LOAD with three active mysqlx_users rows + matching canonical rows — rows_affected==3");
		multi_admin.execute("DELETE FROM mysqlx_users");
		mgr.dispatch_admin_command(multi_ctx, "SAVE MYSQLX USERS TO MEMORY", multi_result);
		ok(multi_result.error_code == 0 &&
		   multi_admin.return_one_int("SELECT COUNT(*) FROM mysqlx_users WHERE active=1") == 3,
		   "SAVE roundtrip after multi-row LOAD — editable table has three active rows");
	}

	// Re-LOAD original ctx so subsequent tests see the original store state.
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result);
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX ROUTES TO RUNTIME", result);
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", result);

	// ---- SAVE data integrity (4) ----

	// Operator edits to the runtime view do NOT survive SAVE. Under the new
	// architecture, runtime_mysqlx_<X> is a projection of the in-memory
	// store, refreshed on demand. Direct mutations to it are not consulted
	// by SAVE (which reads only the store). We seed alice with
	// backend_auth_mode='pass_through' in the store via LOAD, then write a
	// different value into runtime_mysqlx_users, then SAVE: the editable
	// mysqlx_users must reflect the STORE's value ('pass_through'), not
	// the runtime-view mutation ('sha256'). This is the post-PR-#5688
	// contract. We use 'pass_through' (a canonical enum value) so that
	// the store round-trips it verbatim — non-canonical strings are
	// normalised to 'mapped' by mysqlx_backend_auth_mode_from_string.
	admin_db.execute("UPDATE mysqlx_users SET backend_auth_mode='pass_through' WHERE username='alice'");
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result);
	// Populate runtime_mysqlx_users with a divergent value so the test
	// actually exercises a mutation (an UPDATE with no matching row would
	// be a no-op and tell us nothing). The store now holds 'pass_through';
	// the runtime view holds 'sha256'. SAVE must follow the store, not
	// the view.
	admin_db.execute("DELETE FROM runtime_mysqlx_users");
	admin_db.execute("INSERT INTO runtime_mysqlx_users (username, active, backend_auth_mode, attributes, comment) "
	                 "VALUES ('alice', 1, 'sha256', '', '')");
	admin_db.execute("DELETE FROM mysqlx_users");
	mgr.dispatch_admin_command(ctx, "SAVE MYSQLX USERS TO MEMORY", result);
	ok(result.error_code == 0 &&
	   select_string(admin_db, "SELECT backend_auth_mode FROM mysqlx_users WHERE username='alice' AND active=1") == "pass_through",
	   "SAVE reads the in-memory store, NOT runtime_mysqlx_users — operator edits to the runtime view are not preserved");

	// SAVE picks up new rows added to the editable mysqlx_<X> table only
	// after a fresh LOAD: insert a new route, LOAD to refresh the store,
	// wipe mysqlx_routes, SAVE, and verify the new route round-tripped.
	admin_db.execute("DELETE FROM mysqlx_routes");
	admin_db.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active, comment) "
	                 "VALUES ('ro', '127.0.0.1:6604', 44, 'round_robin', 1, 'new route')");
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX ROUTES TO RUNTIME", result);
	admin_db.execute("DELETE FROM mysqlx_routes");
	mgr.dispatch_admin_command(ctx, "SAVE MYSQLX ROUTES TO MEMORY", result);
	ok(result.error_code == 0 &&
	   admin_db.return_one_int("SELECT COUNT(*) FROM mysqlx_routes WHERE active=1") == 1 &&
	   select_string(admin_db, "SELECT name FROM mysqlx_routes WHERE name='ro' AND active=1") == "ro",
	   "SAVE after editable INSERT + LOAD — config table has the new row after roundtrip");

	// SAVE with an empty store: insert a route, LOAD it, then LOAD again
	// after wiping mysqlx_routes — the second LOAD swaps the store to
	// empty. SAVE then leaves no active rows in the editable table.
	{
		SQLite3DB empty_admin {};
		SQLite3DB empty_config {};
		SQLite3DB empty_stats {};
		empty_admin.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		empty_config.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		empty_stats.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		build_registered_tables(empty_admin, admin_tables);
		build_registered_tables(empty_config, config_tables);
		seed_canonical_tables(empty_admin);
		empty_admin.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active, comment) "
		                    "VALUES ('x', '0.0.0.0:1', 1, 'first_available', 1, 'temp')");
		ProxySQL_PluginCommandContext empty_ctx { &empty_admin, &empty_config, &empty_stats };
		ProxySQL_PluginCommandResult empty_result { 1, 0, "" };
		mgr.dispatch_admin_command(empty_ctx, "LOAD MYSQLX ROUTES TO RUNTIME", empty_result);
		empty_admin.execute("DELETE FROM mysqlx_routes");
		// Second LOAD of empty mysqlx_routes swaps the store empty.
		mgr.dispatch_admin_command(empty_ctx, "LOAD MYSQLX ROUTES TO RUNTIME", empty_result);
		mgr.dispatch_admin_command(empty_ctx, "SAVE MYSQLX ROUTES TO MEMORY", empty_result);
		ok(empty_result.error_code == 0 &&
		   empty_admin.return_one_int("SELECT COUNT(*) FROM mysqlx_routes WHERE active=1") == 0,
		   "LOAD-then-empty-LOAD-then-SAVE — editable mysqlx_routes has zero active rows (store became empty)");
	}

	// SAVE then LOAD roundtrip: SAVE the current store back to mysqlx_routes,
	// replace mysqlx_routes with a different row, LOAD again, then SAVE-and-
	// inspect to confirm the store now reflects the replaced row.
	{
		SQLite3DB rt_admin {};
		SQLite3DB rt_config {};
		SQLite3DB rt_stats {};
		rt_admin.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		rt_config.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		rt_stats.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		build_registered_tables(rt_admin, admin_tables);
		build_registered_tables(rt_config, config_tables);
		seed_canonical_tables(rt_admin);
		rt_admin.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active, comment) "
		                 "VALUES ('rt1', '0.0.0.0:3307', 10, 'first_available', 1, 'rt test')");
		ProxySQL_PluginCommandContext rt_ctx { &rt_admin, &rt_config, &rt_stats };
		ProxySQL_PluginCommandResult rt_result { 1, 0, "" };
		mgr.dispatch_admin_command(rt_ctx, "LOAD MYSQLX ROUTES TO RUNTIME", rt_result);
		mgr.dispatch_admin_command(rt_ctx, "SAVE MYSQLX ROUTES TO MEMORY", rt_result);
		rt_admin.execute("DELETE FROM mysqlx_routes");
		rt_admin.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active, comment) "
		                 "VALUES ('rt2', '0.0.0.0:3308', 20, 'round_robin', 1, 'changed')");
		mgr.dispatch_admin_command(rt_ctx, "LOAD MYSQLX ROUTES TO RUNTIME", rt_result);
		// After the second LOAD the store should hold only 'rt2'. SAVE-and-
		// inspect-editable confirms the store contents indirectly.
		rt_admin.execute("DELETE FROM mysqlx_routes");
		mgr.dispatch_admin_command(rt_ctx, "SAVE MYSQLX ROUTES TO MEMORY", rt_result);
		ok(rt_result.error_code == 0 &&
		   rt_admin.return_one_int("SELECT COUNT(*) FROM mysqlx_routes WHERE active=1") == 1 &&
		   select_string(rt_admin, "SELECT name FROM mysqlx_routes WHERE active=1") == "rt2",
		   "SAVE then LOAD roundtrip — store now holds rt2 (verified by SAVE-back to editable)");
	}

	// Restore the original store state so the alias-dispatch tests below
	// see a non-empty, well-formed store. Re-LOAD all three entities.
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX USERS TO RUNTIME", result);
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX ROUTES TO RUNTIME", result);
	mgr.dispatch_admin_command(ctx, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", result);

	// ---- Alias dispatch (8) ----

	ok(mgr.dispatch_admin_command(ctx, "load mysqlx users to runtime", result) &&
	   result.error_code == 0,
	   "lowercase 'load mysqlx users to runtime' dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "LOAD  MYSQLX  USERS  TO  RUNTIME", result) &&
	   result.error_code == 0,
	   "extra whitespace 'LOAD  MYSQLX  USERS  TO  RUNTIME' dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, " load mysqlx users to runtime ", result) &&
	   result.error_code == 0,
	   "leading/trailing whitespace dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "save mysqlx users to memory", result) &&
	   result.error_code == 0,
	   "lowercase 'save mysqlx users to memory' dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX ROUTES TO RUNTIME", result) &&
	   result.error_code == 0,
	   "LOAD MYSQLX ROUTES TO RUNTIME dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "load mysqlx routes to runtime", result) &&
	   result.error_code == 0,
	   "lowercase 'load mysqlx routes to runtime' dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", result) &&
	   result.error_code == 0,
	   "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME dispatches correctly");

	ok(mgr.dispatch_admin_command(ctx, "save  mysqlx  backend  endpoints  to  memory", result) &&
	   result.error_code == 0,
	   "whitespace-normalized 'save mysqlx backend endpoints to memory' dispatches correctly");

	g_admin_db = nullptr;
	g_config_db = nullptr;
	g_stats_db = nullptr;
	test_cleanup_minimal();
	return exit_status();
}
