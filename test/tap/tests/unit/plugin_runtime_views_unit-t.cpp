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

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(20);
	diag("=== plugin_runtime_views_unit-t starting ===");

	// ---- Registration validation ----

	{
		diag(">>> register_runtime_view rejects null callback / empty name / duplicate");
		ProxySQL_PluginManager mgr;

		ok(mgr.register_runtime_view({nullptr, &noop_cb, nullptr}) == false,
		   "register_runtime_view rejects null table_name");
		ok(mgr.register_runtime_view({"", &noop_cb, nullptr}) == false,
		   "register_runtime_view rejects empty table_name");
		ok(mgr.register_runtime_view({"runtime_x", nullptr, nullptr}) == false,
		   "register_runtime_view rejects null refresh callback");

		ok(mgr.register_runtime_view({"runtime_x", &noop_cb, nullptr}) == true,
		   "first registration of runtime_x succeeds");
		ok(mgr.register_runtime_view({"runtime_x", &noop_cb, nullptr}) == false,
		   "duplicate registration of runtime_x is rejected");
		ok(mgr.register_runtime_view({"RUNTIME_X", &noop_cb, nullptr}) == false,
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
		ok(mgr.register_runtime_view({"runtime_mysqlx_users",  &probe_refresh_cb, &users_probe})  == true,
		   "registered runtime_mysqlx_users callback");
		ok(mgr.register_runtime_view({"runtime_mysqlx_routes", &probe_refresh_cb, &routes_probe}) == true,
		   "registered runtime_mysqlx_routes callback");

		// Query references only one of the registered views.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mysqlx_users WHERE active=1", nullptr);
		ok(users_fires.load() == 1 && routes_fires.load() == 0,
		   "users-only query fires users (got %d) and not routes (got %d)",
		   users_fires.load(), routes_fires.load());

		// Query references both.
		mgr.refresh_runtime_views_for_query(
			"SELECT u.username FROM runtime_mysqlx_users u JOIN runtime_mysqlx_routes r ON u.default_route=r.name",
			nullptr);
		ok(users_fires.load() == 2 && routes_fires.load() == 1,
		   "join query fires both (users=%d, routes=%d)",
		   users_fires.load(), routes_fires.load());

		// Query references neither.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM mysql_users", nullptr);
		ok(users_fires.load() == 2 && routes_fires.load() == 1,
		   "unrelated query fires nothing (users=%d, routes=%d)",
		   users_fires.load(), routes_fires.load());

		// Case-insensitive match on the table name.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM RUNTIME_MYSQLX_USERS", nullptr);
		ok(users_fires.load() == 3,
		   "uppercase table name still matches (users=%d)", users_fires.load());

		// Backtick-quoted identifier — backtick is not an identifier char so
		// the whole-identifier match still succeeds.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM `runtime_mysqlx_users`", nullptr);
		ok(users_fires.load() == 4,
		   "backtick-quoted identifier still matches (users=%d)", users_fires.load());
	}

	// ---- Whole-identifier match: prefix and suffix overlaps must NOT match ----

	{
		diag(">>> sql_references_table_ci respects identifier boundaries");

		std::atomic<int> fires{0};
		CallbackProbe probe{"x", &fires};

		ProxySQL_PluginManager mgr;
		ok(mgr.register_runtime_view({"runtime_mysqlx_users", &probe_refresh_cb, &probe}) == true,
		   "registered runtime_mysqlx_users callback");

		// Substring overlap that's part of a longer identifier — must NOT match.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mysqlx_users_extra", nullptr);
		ok(fires.load() == 0,
		   "longer-identifier overlap does not match (fires=%d)", fires.load());

		// Suffix overlap.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM stats_runtime_mysqlx_users", nullptr);
		ok(fires.load() == 0,
		   "left-side identifier prefix does not match (fires=%d)", fires.load());

		// Embedded inside a longer word, no boundary on either side.
		mgr.refresh_runtime_views_for_query(
			"SELECT 'xruntime_mysqlx_usersy' FROM dual", nullptr);
		ok(fires.load() == 0,
		   "embedded-in-string-literal does not match (fires=%d)", fires.load());

		// Real reference: should match.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mysqlx_users", nullptr);
		ok(fires.load() == 1,
		   "exact identifier match fires the callback (fires=%d)", fires.load());

		// Identifier at end of string (no trailing whitespace).
		mgr.refresh_runtime_views_for_query(
			"DESC runtime_mysqlx_users", nullptr);
		ok(fires.load() == 2,
		   "identifier at end-of-string still matches (fires=%d)", fires.load());

		// Identifier at start of string.
		mgr.refresh_runtime_views_for_query(
			"runtime_mysqlx_users", nullptr);
		ok(fires.load() == 3,
		   "identifier at start-of-string still matches (fires=%d)", fires.load());
	}

	return exit_status();
}
