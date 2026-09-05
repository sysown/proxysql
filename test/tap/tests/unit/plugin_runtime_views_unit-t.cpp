// Unit tests for the chassis runtime-view registration + dispatch added in
// PR #5688: ProxySQL_PluginManager::register_runtime_view and
// refresh_runtime_views_for_query.
//
// This is the only test that drives the chassis surface directly without
// the plugin loader, so it can exercise:
//   - registration rejection (null cb, empty name, duplicate)
//   - case-insensitive whole-identifier substring match
//   - per-query dispatch fan-out (only matching callbacks fire)
//   - no-op for queries that reference no registered view
//
// Without these tests a regression that, say, replaced the careful
// whole-identifier match with a plain strstr() would silently start firing
// the wrong projection callback on substring-overlap table names.

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"

#include <atomic>
#include <cstdio>
#include <string>
#include <vector>

namespace {

struct CallbackProbe {
	const char* tag;
	std::atomic<int>* counter;
};

void probe_refresh_cb(SQLite3DB* /*admindb*/, void* opaque) {
	auto* probe = static_cast<CallbackProbe*>(opaque);
	if (probe && probe->counter) probe->counter->fetch_add(1);
}

void noop_cb(SQLite3DB*, void*) {}

SQLite3DB* const any_db = reinterpret_cast<SQLite3DB*>(0xFF);

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(42);
	diag("=== plugin_runtime_views_unit-t starting ===");

	// ---- Registration validation ----

	{
		diag(">>> register_runtime_view rejects null callback / empty name / duplicate");
		ProxySQL_PluginManager mgr;

		ok(mgr.register_runtime_view({nullptr, &noop_cb, nullptr, ProxySQL_PluginDBKind::admin_db}) == false,
		   "register_runtime_view rejects null table_name");
		ok(mgr.register_runtime_view({"", &noop_cb, nullptr, ProxySQL_PluginDBKind::admin_db}) == false,
		   "register_runtime_view rejects empty table_name");
		ok(mgr.register_runtime_view({"runtime_x", nullptr, nullptr, ProxySQL_PluginDBKind::admin_db}) == false,
		   "register_runtime_view rejects null refresh callback");

		ok(mgr.register_runtime_view({"runtime_x", &noop_cb, nullptr, ProxySQL_PluginDBKind::admin_db}) == true,
		   "first registration of runtime_x succeeds");
		ok(mgr.register_runtime_view({"runtime_x", &noop_cb, nullptr, ProxySQL_PluginDBKind::admin_db}) == false,
		   "duplicate registration of runtime_x is rejected");
		ok(mgr.register_runtime_view({"RUNTIME_X", &noop_cb, nullptr, ProxySQL_PluginDBKind::admin_db}) == false,
		   "duplicate registration with different case is also rejected");
	}

	// ---- Dispatch: matching queries fire the callback ----

	{
		diag(">>> refresh_runtime_views_for_query fires only matching callbacks");

		std::atomic<int> users_fires{0};
		std::atomic<int> routes_fires{0};
		CallbackProbe users_probe{"users", &users_fires};
		CallbackProbe routes_probe{"routes", &routes_fires};

		ProxySQL_PluginManager mgr;
		ok(mgr.register_runtime_view({"runtime_mysqlx_users",  &probe_refresh_cb, &users_probe,  ProxySQL_PluginDBKind::admin_db}) == true,
		   "registered runtime_mysqlx_users callback");
		ok(mgr.register_runtime_view({"runtime_mysqlx_routes", &probe_refresh_cb, &routes_probe, ProxySQL_PluginDBKind::admin_db}) == true,
		   "registered runtime_mysqlx_routes callback");

		// Query references only one of the registered views.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mysqlx_users WHERE active=1", any_db, nullptr, nullptr);
		ok(users_fires.load() == 1 && routes_fires.load() == 0,
		   "users-only query fires users (got %d) and not routes (got %d)",
		   users_fires.load(), routes_fires.load());

		// Query references both.
		mgr.refresh_runtime_views_for_query(
			"SELECT u.username FROM runtime_mysqlx_users u JOIN runtime_mysqlx_routes r ON u.default_route=r.name",
any_db, nullptr, nullptr);
		ok(users_fires.load() == 2 && routes_fires.load() == 1,
		   "join query fires both (users=%d, routes=%d)",
		   users_fires.load(), routes_fires.load());

		// Query references neither.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM mysql_users", any_db, nullptr, nullptr);
		ok(users_fires.load() == 2 && routes_fires.load() == 1,
		   "unrelated query fires nothing (users=%d, routes=%d)",
		   users_fires.load(), routes_fires.load());

		// Case-insensitive match on the table name.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM RUNTIME_MYSQLX_USERS", any_db, nullptr, nullptr);
		ok(users_fires.load() == 3,
		   "uppercase table name still matches (users=%d)", users_fires.load());

		// Backtick-quoted identifier — backtick is not an identifier char so
		// the whole-identifier match still succeeds.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM `runtime_mysqlx_users`", any_db, nullptr, nullptr);
		ok(users_fires.load() == 4,
		   "backtick-quoted identifier still matches (users=%d)", users_fires.load());
	}

	// ---- Whole-identifier match: prefix and suffix overlaps must NOT match ----

	{
		diag(">>> sql_references_table_ci respects identifier boundaries");

		std::atomic<int> fires{0};
		CallbackProbe probe{"x", &fires};

		ProxySQL_PluginManager mgr;
		ok(mgr.register_runtime_view({"runtime_mysqlx_users", &probe_refresh_cb, &probe, ProxySQL_PluginDBKind::admin_db}) == true,
		   "registered runtime_mysqlx_users callback");

		// Substring overlap that's part of a longer identifier — must NOT match.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mysqlx_users_extra", any_db, nullptr, nullptr);
		ok(fires.load() == 0,
		   "longer-identifier overlap does not match (fires=%d)", fires.load());

		// Suffix overlap.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM stats_runtime_mysqlx_users", any_db, nullptr, nullptr);
		ok(fires.load() == 0,
		   "left-side identifier prefix does not match (fires=%d)", fires.load());

		// Embedded inside a longer word, no boundary on either side.
		mgr.refresh_runtime_views_for_query(
			"SELECT 'xruntime_mysqlx_usersy' FROM dual", any_db, nullptr, nullptr);
		ok(fires.load() == 0,
		   "embedded-in-string-literal does not match (fires=%d)", fires.load());

		// Real reference: should match.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mysqlx_users", any_db, nullptr, nullptr);
		ok(fires.load() == 1,
		   "exact identifier match fires the callback (fires=%d)", fires.load());

		// Identifier at end of string (no trailing whitespace).
		mgr.refresh_runtime_views_for_query(
			"DESC runtime_mysqlx_users", any_db, nullptr, nullptr);
		ok(fires.load() == 2,
		   "identifier at end-of-string still matches (fires=%d)", fires.load());

		// Identifier at start of string.
		mgr.refresh_runtime_views_for_query(
			"runtime_mysqlx_users", any_db, nullptr, nullptr);
		ok(fires.load() == 3,
		   "identifier at start-of-string still matches (fires=%d)", fires.load());
	}

	// ---- db_kind dispatch: correct DB handle passed ----
	{
		diag(">>> refresh_runtime_views_for_query dispatches correct DB by db_kind");

		SQLite3DB* admin_ptr = reinterpret_cast<SQLite3DB*>(0x1);
		SQLite3DB* config_ptr = reinterpret_cast<SQLite3DB*>(0x2);
		SQLite3DB* stats_ptr = reinterpret_cast<SQLite3DB*>(0x3);

		SQLite3DB* received_db = nullptr;

		auto db_probe_cb = [](SQLite3DB* db, void* opaque) {
			*static_cast<SQLite3DB**>(opaque) = db;
		};

		ProxySQL_PluginManager mgr;
		ok(mgr.register_runtime_view({"stats_mcp_test", db_probe_cb, &received_db, ProxySQL_PluginDBKind::stats_db}) == true,
		   "registered stats_mcp_test with db_kind=stats_db");

		mgr.refresh_runtime_views_for_query("SELECT * FROM stats_mcp_test", admin_ptr, config_ptr, stats_ptr);
		ok(received_db == stats_ptr,
		   "stats_db view receives statsdb handle (got %p, expected %p)", received_db, stats_ptr);

		received_db = nullptr;
		SQLite3DB* admin_received = nullptr;
		ok(mgr.register_runtime_view({"runtime_mcp_test", db_probe_cb, &admin_received, ProxySQL_PluginDBKind::admin_db}) == true,
		   "registered runtime_mcp_test with db_kind=admin_db");

		mgr.refresh_runtime_views_for_query("SELECT * FROM runtime_mcp_test", admin_ptr, config_ptr, stats_ptr);
		ok(admin_received == admin_ptr,
		   "admin_db view receives admindb handle (got %p, expected %p)", admin_received, admin_ptr);

		// config_db dispatch
		SQLite3DB* config_received = nullptr;
		ok(mgr.register_runtime_view({"config_mcp_test", db_probe_cb, &config_received, ProxySQL_PluginDBKind::config_db}) == true,
		   "registered config_mcp_test with db_kind=config_db");

		mgr.refresh_runtime_views_for_query("SELECT * FROM config_mcp_test", admin_ptr, config_ptr, stats_ptr);
		ok(config_received == config_ptr,
		   "config_db view receives configdb handle (got %p, expected %p)", config_received, config_ptr);

		// Null handle skipping: when configdb is null, config_db views are silently skipped
		std::atomic<int> config_fires{0};
		CallbackProbe config_null_probe{"config_null", &config_fires};
		ok(mgr.register_runtime_view({"config_null_test", probe_refresh_cb, &config_null_probe, ProxySQL_PluginDBKind::config_db}) == true,
		   "registered config_null_test with db_kind=config_db for null-handle test");

		mgr.refresh_runtime_views_for_query("SELECT * FROM config_null_test", admin_ptr, nullptr, stats_ptr);
		ok(config_fires.load() == 0,
		   "config_db view is skipped when configdb is null (fires=%d)", config_fires.load());

		// stats_db still fires even when configdb is null
		std::atomic<int> stats_fires{0};
		CallbackProbe stats_probe{"stats_notnull", &stats_fires};
		ok(mgr.register_runtime_view({"stats_notnull_test", probe_refresh_cb, &stats_probe, ProxySQL_PluginDBKind::stats_db}) == true,
		   "registered stats_notnull_test with db_kind=stats_db for mixed-null test");

		mgr.refresh_runtime_views_for_query("SELECT * FROM stats_notnull_test", admin_ptr, nullptr, stats_ptr);
		ok(stats_fires.load() == 1,
		   "stats_db view still fires when configdb is null (fires=%d)", stats_fires.load());
	}

	// ---- Restore of plugin config_db tables from disk (issue #6167) ----
	//
	// Admin's disk->memory bootstrap is a hardcoded list of core tables, so
	// plugin-registered config_db tables were written to disk by their
	// "SAVE <X> TO DISK" verbs and never read back at startup: a plugin's
	// variables survived a restart (they live in global_variables) while its
	// own tables came back empty. proxysql_restore_plugin_config_tables_from_
	// disk() is the seam Admin now calls to close that gap; drive it directly
	// with an in-memory admindb + an ATTACHed `disk` so the behaviour is
	// verified without standing up the whole Admin module.
	{
		diag(">>> plugin config_db tables are restored from disk into main");

		SQLite3DB db;
		char in_memory_db[] = ":memory:";
		db.open(in_memory_db,
		        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		ok(db.execute("ATTACH DATABASE ':memory:' AS disk"),
		   "attached an in-memory `disk` database");

		// Two persisted tables (main+disk pair, as register_table_pair does)
		// and one runtime projection that exists only in main -- the runtime
		// one must not be touched, since it is not a config_db table.
		ok(db.execute("CREATE TABLE main.plug_users (id INTEGER PRIMARY KEY, name TEXT)") &&
		   db.execute("CREATE TABLE disk.plug_users (id INTEGER PRIMARY KEY, name TEXT)") &&
		   db.execute("CREATE TABLE main.plug_routes (id INTEGER PRIMARY KEY, target TEXT)") &&
		   db.execute("CREATE TABLE disk.plug_routes (id INTEGER PRIMARY KEY, target TEXT)") &&
		   db.execute("CREATE TABLE main.runtime_plug_users (id INTEGER PRIMARY KEY, name TEXT)"),
		   "created plugin table fixtures");

		// State a restart would leave behind: rows on disk, main empty.
		ok(db.execute("INSERT INTO disk.plug_users VALUES(1,'alice'),(2,'bob')") &&
		   db.execute("INSERT INTO disk.plug_routes VALUES(7,'hg7')"),
		   "seeded disk tables");
		ok(db.return_one_int("SELECT COUNT(*) FROM main.plug_users") == 0,
		   "main.plug_users starts empty, as after a restart");

		std::vector<ProxySQL_PluginTableDef> config_tables {
			{ProxySQL_PluginDBKind::config_db, "plug_users",  "unused"},
			{ProxySQL_PluginDBKind::config_db, "plug_routes", "unused"},
		};

		proxysql_restore_plugin_config_tables_from_disk(&db, config_tables);

		ok(db.return_one_int("SELECT COUNT(*) FROM main.plug_users") == 2,
		   "main.plug_users restored from disk (got %d)",
		   db.return_one_int("SELECT COUNT(*) FROM main.plug_users"));
		ok(db.return_one_int("SELECT COUNT(*) FROM main.plug_routes WHERE target='hg7'") == 1,
		   "main.plug_routes restored from disk with its column values intact");
		ok(db.return_one_int("SELECT COUNT(*) FROM main.runtime_plug_users") == 0,
		   "runtime projection table is left alone (not a config_db table)");

		// INSERT OR REPLACE, not DELETE+INSERT: a row already present in main
		// under the same key is overwritten by the disk copy, and a main-only
		// row that disk does not know about is left in place. This matches how
		// every core table is restored in
		// __insert_or_replace_maintable_select_disktable().
		ok(db.execute("INSERT INTO main.plug_users VALUES(3,'carol')") &&
		   db.execute("UPDATE main.plug_users SET name='stomped' WHERE id=1"),
		   "added a main-only row and stomped a restored one");
		proxysql_restore_plugin_config_tables_from_disk(&db, config_tables);
		ok(db.return_one_int(
			"SELECT COUNT(*) FROM main.plug_users WHERE id=1 AND name='alice'") == 1,
		   "re-running the restore overwrites a stomped row from disk");
		ok(db.return_one_int(
			"SELECT COUNT(*) FROM main.plug_users WHERE id=3") == 1,
		   "re-running the restore leaves main-only rows in place");

		// Robustness: a null handle, an empty name, and a config_db table with
		// no admin_db twin must all be survivable -- startup must not abort.
		proxysql_restore_plugin_config_tables_from_disk(nullptr, config_tables);
		std::vector<ProxySQL_PluginTableDef> bad_tables {
			{ProxySQL_PluginDBKind::config_db, nullptr,     "unused"},
			{ProxySQL_PluginDBKind::config_db, "",          "unused"},
			{ProxySQL_PluginDBKind::config_db, "no_such_t", "unused"},
		};
		proxysql_restore_plugin_config_tables_from_disk(&db, bad_tables);
		ok(db.return_one_int("SELECT COUNT(*) FROM main.plug_users") == 3,
		   "null handle / empty name / missing table are survived without damage");

		// With no active plugin manager the ..._configured_... wrapper is a
		// no-op rather than a crash (the unit harness never publishes one).
		proxysql_restore_configured_plugin_config_tables(&db);
		ok(db.return_one_int("SELECT COUNT(*) FROM main.plug_users") == 3,
		   "restore via the active-manager wrapper is a no-op with no manager");
	}

	return exit_status();
}
