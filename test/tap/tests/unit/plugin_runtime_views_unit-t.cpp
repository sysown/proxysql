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
	plan(30);
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

	return exit_status();
}
