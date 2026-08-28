// Step 2 ABI extension test: pre-execution query hook.
//
// Exercises the manager-level register/dispatch pair AND the global
// dispatcher (proxysql_dispatch_configured_plugin_query_hook) that the
// MySQL_Session / PgSQL_Session hot path will call once Commit 2 lands.
// Hot-path call sites themselves are tested separately.

#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Plugin.h"
#include "tap.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

namespace {

char g_fake_admin_db = '\0';
char g_fake_config_db = '\0';
char g_fake_stats_db = '\0';

ProxySQL_PluginQueryHookResult always_allow_hook(const ProxySQL_PluginQueryHookPayload&) {
	return {ProxySQL_PluginQueryHookAction::allow, ""};
}

ProxySQL_PluginQueryHookResult always_deny_hook(const ProxySQL_PluginQueryHookPayload&) {
	return {ProxySQL_PluginQueryHookAction::deny, "blocked"};
}

ProxySQL_PluginQueryHookResult echo_hook(const ProxySQL_PluginQueryHookPayload& p) {
	std::string body(p.query_text, p.query_len);
	return {ProxySQL_PluginQueryHookAction::allow,
	        std::string(p.user) + "/" + p.client_ip + "/" + p.schema + ":" + body};
}

ProxySQL_PluginQueryHookPayload payload_for(const char* user, const char* ip,
                                            const char* schema, const char* query) {
	return ProxySQL_PluginQueryHookPayload {
		user, ip, schema, query, static_cast<uint32_t>(std::strlen(query))
	};
}

} // namespace

SQLite3DB* proxysql_plugin_get_admindb()  { return reinterpret_cast<SQLite3DB*>(&g_fake_admin_db); }
SQLite3DB* proxysql_plugin_get_configdb() { return reinterpret_cast<SQLite3DB*>(&g_fake_config_db); }
SQLite3DB* proxysql_plugin_get_statsdb()  { return reinterpret_cast<SQLite3DB*>(&g_fake_stats_db); }

static void test_unregistered_protocols_have_no_hook() {
	ProxySQL_PluginManager mgr;
	ok(!mgr.has_query_hook(ProxySQL_PluginProtocol::mysql),
	   "fresh manager has no MySQL hook");
	ok(!mgr.has_query_hook(ProxySQL_PluginProtocol::pgsql),
	   "fresh manager has no PgSQL hook");
	ProxySQL_PluginQueryHookResult r {ProxySQL_PluginQueryHookAction::deny, "x"};
	auto p = payload_for("u", "ip", "s", "select 1");
	ok(!mgr.dispatch_query_hook(ProxySQL_PluginProtocol::mysql, p, r),
	   "dispatch returns false on protocol with no hook");
	ok(r.action == ProxySQL_PluginQueryHookAction::deny && r.message == "x",
	   "dispatch leaves caller's result struct untouched on no-hook miss");
}

static void test_register_and_dispatch_allow() {
	ProxySQL_PluginManager mgr;
	ok(mgr.register_query_hook(ProxySQL_PluginProtocol::mysql, &always_allow_hook),
	   "register MySQL allow hook");
	ok(mgr.has_query_hook(ProxySQL_PluginProtocol::mysql),
	   "MySQL hook now present");

	ProxySQL_PluginQueryHookResult r {ProxySQL_PluginQueryHookAction::deny, "init"};
	auto p = payload_for("alice", "10.0.0.1", "test", "select 1");
	ok(mgr.dispatch_query_hook(ProxySQL_PluginProtocol::mysql, p, r),
	   "dispatch returns true (hook fired)");
	ok(r.action == ProxySQL_PluginQueryHookAction::allow,
	   "hook returned ALLOW");
	ok(r.message.empty(),
	   "ALLOW carries empty message");
}

static void test_register_and_dispatch_deny() {
	ProxySQL_PluginManager mgr;
	ok(mgr.register_query_hook(ProxySQL_PluginProtocol::mysql, &always_deny_hook),
	   "register MySQL deny hook");
	ProxySQL_PluginQueryHookResult r {ProxySQL_PluginQueryHookAction::allow, ""};
	auto p = payload_for("eve", "10.0.0.99", "prod", "drop table users");
	ok(mgr.dispatch_query_hook(ProxySQL_PluginProtocol::mysql, p, r),
	   "dispatch returns true");
	ok(r.action == ProxySQL_PluginQueryHookAction::deny,
	   "hook returned DENY");
	ok(r.message == "blocked",
	   "DENY message propagated to caller");
}

static void test_register_null_callback_rejected() {
	ProxySQL_PluginManager mgr;
	ok(!mgr.register_query_hook(ProxySQL_PluginProtocol::mysql, nullptr),
	   "null callback rejected for MySQL");
	ok(!mgr.register_query_hook(ProxySQL_PluginProtocol::pgsql, nullptr),
	   "null callback rejected for PgSQL");
	ok(!mgr.has_query_hook(ProxySQL_PluginProtocol::mysql),
	   "no hook stored after rejection (MySQL)");
	ok(!mgr.has_query_hook(ProxySQL_PluginProtocol::pgsql),
	   "no hook stored after rejection (PgSQL)");
}

static void test_duplicate_hook_rejected() {
	ProxySQL_PluginManager mgr;
	ok(mgr.register_query_hook(ProxySQL_PluginProtocol::mysql, &always_allow_hook),
	   "first MySQL registration succeeds");
	ok(!mgr.register_query_hook(ProxySQL_PluginProtocol::mysql, &always_deny_hook),
	   "second MySQL registration rejected (one hook per protocol per manager)");
	// Verify the first hook is still in effect
	ProxySQL_PluginQueryHookResult r {ProxySQL_PluginQueryHookAction::deny, "x"};
	auto p = payload_for("u", "ip", "s", "q");
	mgr.dispatch_query_hook(ProxySQL_PluginProtocol::mysql, p, r);
	ok(r.action == ProxySQL_PluginQueryHookAction::allow,
	   "original hook still in effect after rejected duplicate");
}

static void test_protocols_independent() {
	ProxySQL_PluginManager mgr;
	ok(mgr.register_query_hook(ProxySQL_PluginProtocol::mysql, &always_allow_hook),
	   "MySQL hook registers");
	ok(mgr.register_query_hook(ProxySQL_PluginProtocol::pgsql, &always_deny_hook),
	   "PgSQL hook registers independently");

	ProxySQL_PluginQueryHookResult r {ProxySQL_PluginQueryHookAction::deny, ""};
	auto p = payload_for("u", "ip", "s", "q");
	mgr.dispatch_query_hook(ProxySQL_PluginProtocol::mysql, p, r);
	ok(r.action == ProxySQL_PluginQueryHookAction::allow,
	   "MySQL dispatch routes to MySQL hook (allow)");
	mgr.dispatch_query_hook(ProxySQL_PluginProtocol::pgsql, p, r);
	ok(r.action == ProxySQL_PluginQueryHookAction::deny,
	   "PgSQL dispatch routes to PgSQL hook (deny)");
}

static void test_payload_threaded_through() {
	ProxySQL_PluginManager mgr;
	mgr.register_query_hook(ProxySQL_PluginProtocol::mysql, &echo_hook);
	ProxySQL_PluginQueryHookResult r {ProxySQL_PluginQueryHookAction::deny, ""};
	auto p = payload_for("alice", "10.1.2.3", "shop", "SELECT id FROM orders");
	ok(mgr.dispatch_query_hook(ProxySQL_PluginProtocol::mysql, p, r),
	   "dispatch fires echo hook");
	ok(r.message == "alice/10.1.2.3/shop:SELECT id FROM orders",
	   "all payload fields reach the hook intact (got: '%s')", r.message.c_str());
}

static void test_global_dispatcher_no_active_manager() {
	// Make sure no manager is active (defensive — earlier tests may have
	// left state behind, but we never set the active pointer in this test).
	ok(proxysql_get_plugin_manager() == nullptr,
	   "global manager is null at start");
	ok(!proxysql_has_configured_plugin_query_hook(ProxySQL_PluginProtocol::mysql),
	   "has_hook helper returns false with no active manager");
	ProxySQL_PluginQueryHookResult r {ProxySQL_PluginQueryHookAction::deny, "untouched"};
	auto p = payload_for("u", "ip", "s", "q");
	ok(!proxysql_dispatch_configured_plugin_query_hook(ProxySQL_PluginProtocol::mysql, p, r),
	   "dispatcher returns false with no active manager");
	ok(r.message == "untouched",
	   "dispatcher leaves caller's result untouched on miss");
}

static void test_global_dispatcher_with_active_manager() {
	setenv("PROXYSQL_FAKE_PLUGIN_REGISTER_QUERY_HOOK", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins(mgr.get(), err),
	   "load fake plugin (which registers a MySQL query hook)");
	ok(proxysql_has_configured_plugin_query_hook(ProxySQL_PluginProtocol::mysql),
	   "has_hook helper reports a MySQL hook is now active");
	ok(!proxysql_has_configured_plugin_query_hook(ProxySQL_PluginProtocol::pgsql),
	   "has_hook helper reports no PgSQL hook (fake plugin only registered MySQL)");

	ProxySQL_PluginQueryHookResult r {ProxySQL_PluginQueryHookAction::deny, ""};
	auto p = payload_for("u", "ip", "s", "select 42");
	ok(proxysql_dispatch_configured_plugin_query_hook(ProxySQL_PluginProtocol::mysql, p, r),
	   "global dispatcher routes to fake hook");
	ok(r.action == ProxySQL_PluginQueryHookAction::allow,
	   "hook returned ALLOW (no DENY env set)");
	ok(r.message == "select 42",
	   "fake hook echoed the SQL through the result message (got: '%s')", r.message.c_str());

	// Now flip to DENY and re-dispatch
	setenv("PROXYSQL_FAKE_PLUGIN_HOOK_DENY", "1", 1);
	ProxySQL_PluginQueryHookResult r2 {ProxySQL_PluginQueryHookAction::allow, ""};
	ok(proxysql_dispatch_configured_plugin_query_hook(ProxySQL_PluginProtocol::mysql, p, r2),
	   "second dispatch with DENY env still fires");
	ok(r2.action == ProxySQL_PluginQueryHookAction::deny,
	   "hook now returns DENY");
	ok(r2.message == "denied: select 42",
	   "DENY message includes the offending SQL (got: '%s')", r2.message.c_str());

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_REGISTER_QUERY_HOOK");
	unsetenv("PROXYSQL_FAKE_PLUGIN_HOOK_DENY");

	// After stop, neither helper should report a hook.
	ok(!proxysql_has_configured_plugin_query_hook(ProxySQL_PluginProtocol::mysql),
	   "has_hook helper returns false after stop");
	ProxySQL_PluginQueryHookResult r3 {ProxySQL_PluginQueryHookAction::deny, "still-here"};
	ok(!proxysql_dispatch_configured_plugin_query_hook(ProxySQL_PluginProtocol::mysql, p, r3),
	   "dispatcher returns false after stop");
}

// query_text is a pointer+length pair, not a C string.  The hook must
// use `query_len` to bound reads; plugins that strlen() the pointer will
// truncate at the first embedded NUL (and leak data to plugins they
// shouldn't see, if length is shorter than NUL offset).  This test pins
// the contract on the dispatch side.
static void test_embedded_nul_in_query_text() {
	ProxySQL_PluginManager mgr;
	mgr.register_query_hook(ProxySQL_PluginProtocol::mysql, &echo_hook);

	const char raw[] = "SELECT\0id FROM t";   // 16 bytes incl. trailing \0
	ProxySQL_PluginQueryHookPayload p {
		"u", "ip", "s", raw, static_cast<uint32_t>(sizeof(raw) - 1)
	};
	ProxySQL_PluginQueryHookResult r {ProxySQL_PluginQueryHookAction::deny, ""};
	ok(mgr.dispatch_query_hook(ProxySQL_PluginProtocol::mysql, p, r),
	   "dispatch handles a payload with an embedded NUL in query_text");
	ok(r.message.size() == std::string("u/ip/s:").size() + sizeof(raw) - 1,
	   "hook received all %zu bytes — not truncated at the embedded NUL", sizeof(raw) - 1);
}

// A hook callback that itself calls dispatch_query_hook for the OTHER
// protocol must not deadlock or crash.  The manager's dispatch path
// takes no lock, so re-entry is safe; this test locks that down.
static ProxySQL_PluginManager* g_reentrant_mgr = nullptr;
static int g_reentrant_inner_calls = 0;
ProxySQL_PluginQueryHookResult reentrant_outer_hook(const ProxySQL_PluginQueryHookPayload& outer) {
	ProxySQL_PluginQueryHookResult inner {ProxySQL_PluginQueryHookAction::deny, ""};
	// Re-enter from mysql hook into the pgsql protocol's hook.
	if (g_reentrant_mgr != nullptr) {
		auto p = payload_for("u", "ip", "s", "inner");
		if (g_reentrant_mgr->dispatch_query_hook(ProxySQL_PluginProtocol::pgsql, p, inner)) {
			g_reentrant_inner_calls++;
		}
	}
	return {ProxySQL_PluginQueryHookAction::allow, std::string("outer:") + std::string(outer.query_text, outer.query_len)};
}

static void test_reentrant_dispatch_across_protocols() {
	ProxySQL_PluginManager mgr;
	g_reentrant_mgr = &mgr;
	g_reentrant_inner_calls = 0;
	mgr.register_query_hook(ProxySQL_PluginProtocol::mysql, &reentrant_outer_hook);
	mgr.register_query_hook(ProxySQL_PluginProtocol::pgsql, &always_allow_hook);

	auto p = payload_for("u", "ip", "s", "outer");
	ProxySQL_PluginQueryHookResult r {ProxySQL_PluginQueryHookAction::deny, ""};
	ok(mgr.dispatch_query_hook(ProxySQL_PluginProtocol::mysql, p, r),
	   "re-entrant dispatch (mysql hook → pgsql hook) returns without deadlock");
	ok(g_reentrant_inner_calls == 1,
	   "inner (pgsql) hook fired exactly once during outer (mysql) hook");
	ok(r.action == ProxySQL_PluginQueryHookAction::allow,
	   "outer hook's ALLOW propagated to caller despite re-entry");
	g_reentrant_mgr = nullptr;
}

int main() {
	plan(46);

	test_unregistered_protocols_have_no_hook();
	test_register_and_dispatch_allow();
	test_register_and_dispatch_deny();
	test_register_null_callback_rejected();
	test_duplicate_hook_rejected();
	test_protocols_independent();
	test_payload_threaded_through();
	test_embedded_nul_in_query_text();
	test_reentrant_dispatch_across_protocols();
	test_global_dispatcher_no_active_manager();
	test_global_dispatcher_with_active_manager();

	return exit_status();
}
