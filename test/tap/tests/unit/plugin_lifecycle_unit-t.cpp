// Step 2.2 (chassis): four-phase plugin lifecycle test.
//
// Exercises the new register_schemas (Phase B) ABI field and verifies:
//   * both register_schemas and init run when the plugin sets both;
//     register_schemas runs first, init second (ordering contract).
//   * plugins with a null register_schemas field skip Phase B and go
//     straight to init (pre-existing two-phase behavior preserved).
//   * during Phase B, the DB handle getters in services return nullptr.
//     Plugins that call them observe null and must handle it.
//
// The fake_plugin.cpp test helper is the plugin under test; it selects
// between two static ProxySQL_PluginDescriptor layouts based on the
// PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B env var, mirroring the descriptor-
// version-selection pattern a real plugin would use.

#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Plugin.h"
#include "ProxySQL_PluginListenerGate.h"
#include "tap.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif
#ifndef PROXYSQL_FAKE_PLUGIN2_PATH
#error "PROXYSQL_FAKE_PLUGIN2_PATH must be defined"
#endif

namespace {

char g_fake_admin_db  = '\0';
char g_fake_config_db = '\0';
char g_fake_stats_db  = '\0';

std::string g_log_path {};

void make_log_path() {
	char tpl[] = "/tmp/proxysql_plugin_lifecycle_log.XXXXXX";
	int fd = mkstemp(tpl);
	if (fd >= 0) close(fd);
	g_log_path = tpl;
	setenv("PROXYSQL_FAKE_PLUGIN_LOG", g_log_path.c_str(), 1);
	setenv("PROXYSQL_FAKE_PLUGIN2_LOG", g_log_path.c_str(), 1);
}

void clear_log() {
	if (g_log_path.empty()) return;
	// See plugin_manager_unit-t.cpp for the SonarCloud rationale.
	std::ofstream truncate_handle(g_log_path, std::ios::trunc);
	(void)truncate_handle;
}

void append_log(const char* event) {
	if (g_log_path.empty()) return;
	std::ofstream log(g_log_path, std::ios::app);
	log << event << '\n';
}

std::string read_log() {
	if (g_log_path.empty()) return "";
	std::ifstream s(g_log_path);
	return std::string((std::istreambuf_iterator<char>(s)), std::istreambuf_iterator<char>());
}

void cleanup_log() {
	if (g_log_path.empty()) return;
	std::remove(g_log_path.c_str());
	unsetenv("PROXYSQL_FAKE_PLUGIN_LOG");
	unsetenv("PROXYSQL_FAKE_PLUGIN2_LOG");
}

bool contains_in_order(const std::string& haystack, const char* first, const char* second) {
	size_t pos_first = haystack.find(first);
	if (pos_first == std::string::npos) return false;
	size_t pos_second = haystack.find(second, pos_first + 1);
	return pos_second != std::string::npos;
}

} // namespace

// Symbols the plugin manager pulls from the core.  In this test harness we
// hand it fake, non-null pointers so init() sees "live" handles -- which
// is what matters for the contrast against Phase B's nullptrs.
SQLite3DB* proxysql_plugin_get_admindb()  { return reinterpret_cast<SQLite3DB*>(&g_fake_admin_db); }
SQLite3DB* proxysql_plugin_get_configdb() { return reinterpret_cast<SQLite3DB*>(&g_fake_config_db); }
SQLite3DB* proxysql_plugin_get_statsdb()  { return reinterpret_cast<SQLite3DB*>(&g_fake_stats_db); }

// Case 1: plugin sets both register_schemas AND init.  Both must fire.
// register_schemas must fire strictly before init (the lifecycle contract
// that lets plugins count on admin module materialization between them).
static void test_phase_b_and_init_both_fire() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins(mgr.get(), err),
	   "load-then-register_schemas-then-init succeeds (err='%s')", err.c_str());

	const std::string log = read_log();
	ok(log.find("fake_plugin:phase_b") != std::string::npos,
	   "register_schemas callback fired (log contains phase_b marker)");
	ok(log.find("fake_plugin:init") != std::string::npos,
	   "init callback fired (log contains init marker)");
	ok(contains_in_order(log, "fake_plugin:phase_b", "fake_plugin:init"),
	   "register_schemas ran strictly before init");

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
}

static void test_duplicate_descriptor_names_are_rejected() {
	char alias_path[] = "/tmp/proxysql_duplicate_plugin.XXXXXX"; // NOSONAR: mkstemp creates it atomically.
	const int fd = mkstemp(alias_path);
	if (fd >= 0) close(fd);
	if (fd >= 0) std::remove(alias_path);
	const bool linked = fd >= 0 && symlink(PROXYSQL_FAKE_PLUGIN_PATH, alias_path) == 0;
	ProxySQL_PluginManager manager;
	std::string error;
	const bool first_loaded = manager.load(PROXYSQL_FAKE_PLUGIN_PATH, error);
	const bool duplicate_rejected = linked && !manager.load(alias_path, error) &&
		error.find("duplicate plugin descriptor name") != std::string::npos;
	ok(first_loaded && duplicate_rejected,
		"different modules cannot publish the same listener-gate owner name (err='%s')",
		error.c_str());
	if (linked) std::remove(alias_path);
}

// An early-action-capable plugin must run after Admin is live but before its
// normal init/start lifecycle. The production regression this catches is
// inserting the action phase before schema/Admin setup or after init/start.
static void test_early_action_runs_between_admin_and_init() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_EARLY_ACTION", "continue", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_discover_configured_plugins(mgr, paths, err),
	   "plugin discovery succeeds before CLI registration (err='%s')", err.c_str());
	ez::ezOptionParser parser;
	ok(proxysql_register_configured_plugin_cli(mgr.get(), parser, err),
	   "plugin CLI registration succeeds before schema registration (err='%s')", err.c_str());
	const char* argv[] { "proxysql", "--fake-plugin-action", "continue" };
	parser.parse(3, argv);
	ok(proxysql_register_configured_plugin_schemas(mgr.get(), err),
	   "schema registration succeeds before Admin is live (err='%s')", err.c_str());
	append_log("core:admin_ready");
	ProxySQL_PluginParsedOptionContext parsed_options(parser);
	const auto action = proxysql_run_configured_plugin_early_actions(
		mgr.get(), parsed_options.early_action_context("test.cnf", "test-datadir"), err);
	ok(action == ProxySQL_PluginEarlyActionResult::not_requested ||
	   action == ProxySQL_PluginEarlyActionResult::continue_startup,
	   "early action permits normal startup (err='%s')", err.c_str());
	ok(proxysql_init_configured_plugins(mgr.get(), err) &&
	   proxysql_start_configured_plugins(mgr.get(), err),
	   "normal init and start succeed after the action phase (err='%s')", err.c_str());

	const std::string log = read_log();
	ok(log.find("fake_plugin:early_action") != std::string::npos,
	   "early action callback fired (log='%s')", log.c_str());
	ok(contains_in_order(log, "fake_plugin:phase_b", "core:admin_ready") &&
	   contains_in_order(log, "core:admin_ready", "fake_plugin:early_action") &&
	   contains_in_order(log, "fake_plugin:early_action", "fake_plugin:init") &&
	   contains_in_order(log, "fake_plugin:init", "fake_plugin:start"),
	   "CLI registration/schema/Admin/action/init/start lifecycle is ordered (log='%s')", log.c_str());

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_EARLY_ACTION");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
}

static ProxySQL_PluginEarlyActionResult run_fake_early_action(
	const char* requested_action, std::string& err) {
	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	if (!proxysql_discover_configured_plugins(mgr, paths, err)) {
		return ProxySQL_PluginEarlyActionResult::exit_failure;
	}
	ez::ezOptionParser parser;
	if (!proxysql_register_configured_plugin_cli(mgr.get(), parser, err) ||
		!proxysql_register_configured_plugin_schemas(mgr.get(), err)) {
		return ProxySQL_PluginEarlyActionResult::exit_failure;
	}
	const char* argv[] { "proxysql", "--fake-plugin-action", requested_action };
	parser.parse(3, argv);
	ProxySQL_PluginParsedOptionContext parsed_options(parser);
	const auto result = proxysql_run_configured_plugin_early_actions(
		mgr.get(), parsed_options.early_action_context("test.cnf", "test-datadir"), err);
	std::string stop_error;
	(void)proxysql_stop_configured_plugins(mgr, stop_error);
	return result;
}

// The production regressions this catches are translating a requested early
// exit into normal startup, or invoking init/start after an action requested
// process termination.
static void test_early_action_exit_results_skip_normal_lifecycle() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_EARLY_ACTION", "1", 1);
	std::string err;

	clear_log();
	const auto success = run_fake_early_action("exit_success", err);
	ok(success == ProxySQL_PluginEarlyActionResult::exit_success,
	   "exit_success is returned for a successful one-shot action (err='%s')", err.c_str());
	const std::string success_log = read_log();
	ok(success_log.find("fake_plugin:early_action") != std::string::npos &&
	   success_log.find("fake_plugin:init") == std::string::npos &&
	   success_log.find("fake_plugin:start") == std::string::npos,
	   "exit_success omits init and start (log='%s')", success_log.c_str());

	clear_log();
	const auto failure = run_fake_early_action("exit_failure", err);
	ok(failure == ProxySQL_PluginEarlyActionResult::exit_failure,
	   "exit_failure is returned for a failed one-shot action (err='%s')", err.c_str());
	const std::string failure_log = read_log();
	ok(failure_log.find("fake_plugin:early_action") != std::string::npos &&
	   failure_log.find("fake_plugin:init") == std::string::npos &&
	   failure_log.find("fake_plugin:start") == std::string::npos,
	   "exit_failure omits init and start (log='%s')", failure_log.c_str());

	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_EARLY_ACTION");
}

// The production regression this catches is allowing a plugin exception to
// escape startup, or including parsed option values in the failure message.
static void test_early_action_exception_is_a_sanitized_failure() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_EARLY_ACTION", "1", 1);
	clear_log();
	std::string err;
	const auto result = run_fake_early_action("throw", err);
	ok(result == ProxySQL_PluginEarlyActionResult::exit_failure,
	   "an early-action exception becomes exit_failure");
	ok(err.find("fake_plugin") != std::string::npos && err.find("throw") == std::string::npos,
	   "exception failure names the plugin but not the option value (err='%s')", err.c_str());
	ok(read_log().find("fake_plugin:init") == std::string::npos &&
	   read_log().find("fake_plugin:start") == std::string::npos,
	   "an exception omits init and start");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_EARLY_ACTION");
}

bool test_action_is_set(void*, const char*) { return true; }

bool test_action_get_string(void* opaque, const char*, std::string& value) {
	value = *static_cast<std::string*>(opaque);
	return true;
}

// The production regression this catches is continuing through later actions
// after an earlier configured plugin asked the process to exit.
static void test_first_early_exit_short_circuits_later_plugins() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_EARLY_ACTION", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN2_ENABLE_EARLY_ACTION", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths {
		PROXYSQL_FAKE_PLUGIN_PATH, PROXYSQL_FAKE_PLUGIN2_PATH
	};
	std::string err;
	ok(proxysql_discover_configured_plugins(mgr, paths, err),
	   "two early-action plugins load in configured order (err='%s')", err.c_str());
	std::string requested_action = "exit_success";
	const ProxySQL_PluginEarlyActionContext context {
		&requested_action, &test_action_is_set, &test_action_get_string,
		"test.cnf", "test-datadir", nullptr
	};
	const auto result = proxysql_run_configured_plugin_early_actions(mgr.get(), context, err);
	ok(result == ProxySQL_PluginEarlyActionResult::exit_success,
	   "the first configured exit result is returned");
	const std::string log = read_log();
	ok(log.find("fake_plugin:early_action") != std::string::npos &&
	   log.find("fake_plugin2:early_action") == std::string::npos,
	   "the first exit short-circuits the later plugin action (log='%s')", log.c_str());

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN2_ENABLE_EARLY_ACTION");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_EARLY_ACTION");
}

// ABI 5 descriptors end at register_schemas. The production regression this
// catches is reading the ABI-6 early_action tail from an older plugin.
static void test_abi5_skips_early_action_tail() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_ABI5_TAIL_GUARD", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr(new ProxySQL_PluginManager());
	std::string err;
	ok(mgr->load(PROXYSQL_FAKE_PLUGIN_PATH, err), "ABI 5 fake plugin loads");
	ez::ezOptionParser parser;
	ProxySQL_PluginParsedOptionContext parsed_options(parser);
	const auto result = proxysql_run_configured_plugin_early_actions(
		mgr.get(), parsed_options.early_action_context("test.cnf", "test-datadir"), err);
	ok(result == ProxySQL_PluginEarlyActionResult::not_requested,
	   "ABI 5 descriptor skips the ABI 6 early-action tail (err='%s')", err.c_str());
	ok(read_log().find("fake_plugin:early_action") == std::string::npos,
	   "ABI 5 plugin did not run an early action");

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_ABI5_TAIL_GUARD");
}

// ABI-7 descriptors include the secret-service era prefix but do not have the
// ABI-8 runtime_ready field. The production regression is reading that tail
// unconditionally during phase 3.
static void test_abi7_skips_runtime_ready_tail() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_ABI7_TAIL_GUARD", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr(new ProxySQL_PluginManager());
	std::string err;
	ok(mgr->load(PROXYSQL_FAKE_PLUGIN_PATH, err) && mgr->init_all(err) && mgr->start_all(err),
		"ABI 7 plugin reaches started state without an ABI 8 descriptor tail");
	ProxySQL_PluginRuntimeContext context { nullptr, 4321 };
	ok(proxysql_runtime_ready_configured_plugins(mgr.get(), context, err),
		"ABI 7 plugin is skipped by runtime-ready dispatch (err='%s')", err.c_str());
	ok(read_log().find("fake_plugin:runtime_ready") == std::string::npos,
		"ABI 7 plugin did not read or invoke the ABI 8 runtime-ready tail");
	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_ABI7_TAIL_GUARD");
}

// Case 2: plugin sets only init (register_schemas field is null).
// Phase B is skipped; init still runs.  This is the compat path for
// plugins built against the pre-2.2 descriptor layout.
static void test_only_init_skips_phase_b() {
	// ENABLE_PHASE_B unset -> descriptor returned omits register_schemas.
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins(mgr.get(), err),
	   "load+init succeeds with no register_schemas set (err='%s')", err.c_str());

	const std::string log = read_log();
	ok(log.find("fake_plugin:phase_b") == std::string::npos,
	   "register_schemas NOT invoked when descriptor field is null");
	ok(log.find("fake_plugin:init") != std::string::npos,
	   "init still fires on the legacy two-phase path");

	(void)proxysql_stop_configured_plugins(mgr, err);
}

// Case 3: register_schemas tries to call DB handle getters.
//
// Contract: during Phase B the services struct passed to the plugin MUST
// have the DB-handle getters wired to non-null stub functions that return
// nullptr.  Two regressions this test has to catch:
//   (a) loader passes the live `services_` (get_admindb() returns the
//       real, non-null admin DB)
//   (b) loader sets services_phase_b_.get_admindb = nullptr (plugins that
//       call the getter unconditionally would crash)
//
// The fake plugin emits one of three markers depending on which state it
// observes; the correct marker is phase_b_handles_null.  This test only
// passes when the marker is present AND the two failure markers are
// absent.  The harness itself returns non-null fakes from
// proxysql_plugin_get_admindb(); if the loader mistakenly used the live
// services, the fake plugin would log phase_b_handles_live.
static void test_phase_b_db_handles_are_null() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_TOUCH_HANDLES", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins(mgr.get(), err),
	   "load succeeds even though plugin peeked at DB handles in Phase B");

	const std::string log = read_log();
	ok(log.find("fake_plugin:phase_b_handles_null") != std::string::npos,
	   "DB handle getters returned nullptr during register_schemas (log='%s')",
	   log.c_str());
	ok(log.find("fake_plugin:phase_b_handles_live") == std::string::npos,
	   "DB handles were NOT live during Phase B (contract)");
	ok(log.find("fake_plugin:phase_b_getter_null") == std::string::npos,
	   "Phase-B getters are non-null stubs, not nullptr pointers (contract)");

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_TOUCH_HANDLES");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
}

// ABI-7 secret callbacks are callable in Phase B but must reject the request:
// configdb and the core-owned secret table do not exist until Admin is live.
static void test_phase_b_secret_services_are_not_available() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_TEST_SECRETS", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err),
	   "Phase-B secret-service probe does not fail schema registration (err='%s')", err.c_str());
	const std::string log = read_log();
	ok(log.find("fake_plugin:phase_b_secrets_not_available") != std::string::npos,
	   "Phase-B secret callbacks report not_available and clear supplied output");

	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_TEST_SECRETS");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
}

// Case 4: a failing register_schemas aborts the load and init() is NOT
// called.  Verifies the loader treats Phase-B failure as a hard error.
static void test_phase_b_failure_aborts_init() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_FAIL", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(!proxysql_load_configured_plugins(mgr, paths, err),
	   "load fails when register_schemas returns false");
	ok(!err.empty() && err.find("register_schemas") != std::string::npos,
	   "error message names the failing phase (err='%s')", err.c_str());

	const std::string log = read_log();
	ok(log.find("fake_plugin:phase_b_fail") != std::string::npos,
	   "register_schemas actually ran and logged its failure");
	ok(log.find("fake_plugin:init") == std::string::npos,
	   "init was NOT called after register_schemas failed");
	ok(mgr == nullptr,
	   "schema-registration failure tears down the discovered manager");
	ok(proxysql_get_plugin_manager() == nullptr,
	   "schema-registration failure unpublishes the active manager");

	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_FAIL");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
}

// Case 4b: register_schemas registers a table, then returns false.
// The loader MUST roll back the partial registration so a subsequent
// retry (with the bug fixed) doesn't trip on a duplicate table
// registration.  This is the contract that keeps reload-after-failure
// viable: the registry is transactional per-plugin.
static void test_phase_b_partial_failure_rolls_back() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_PARTIAL_THEN_FAIL", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr1;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(!proxysql_load_configured_plugins(mgr1, paths, err),
	   "first load fails when register_schemas returns false after partial registration");
	ok(read_log().find("fake_plugin:phase_b_partial_then_fail") != std::string::npos,
	   "plugin actually registered a table before returning false");

	// Retry with the toggle cleared.  If the loader didn't roll back
	// the partial registration, we'd expect either a duplicate-table
	// error or a dirty registry.  With rollback, load+init succeeds.
	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_PARTIAL_THEN_FAIL");
	clear_log();
	std::unique_ptr<ProxySQL_PluginManager> mgr2;
	std::string err2;
	ok(proxysql_load_configured_plugins(mgr2, paths, err2) && proxysql_init_configured_plugins(mgr2.get(), err2),
	   "retry succeeds — partial registration from the failed attempt was rolled back (err='%s')", err2.c_str());

	(void)proxysql_stop_configured_plugins(mgr2, err2);
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
}

// Case 5: init() succeeds but start() fails.  stop() MUST still be
// called for teardown symmetry — anything init() allocated would otherwise
// leak.  This is the "init pairs with stop" contract.
static void test_stop_runs_when_start_fails() {
	setenv("PROXYSQL_FAKE_PLUGIN_START_FAIL", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) && proxysql_init_configured_plugins(mgr.get(), err),
	   "load + init succeed on the plugin whose start will later fail");
	ok(!proxysql_start_configured_plugins(mgr.get(), err),
	   "start fails when plugin's start() returns false");

	(void)proxysql_stop_configured_plugins(mgr, err);

	const std::string log = read_log();
	ok(log.find("fake_plugin:init") != std::string::npos,
	   "init did run (necessary precondition for the stop contract)");
	ok(log.find("fake_plugin:start_fail") != std::string::npos,
	   "start_fail marker confirms start() was called and returned false");
	ok(log.find("fake_plugin:stop") != std::string::npos,
	   "stop() was called for init-success/start-fail plugin (teardown symmetry)");

	unsetenv("PROXYSQL_FAKE_PLUGIN_START_FAIL");
}

// Runtime readiness is deliberately separate from start(): its callback must
// run only after phase 3 has the HGM/Auth/QPro/MTH core dependencies, and a
// failed first reconciliation must leave the process able to start listeners.
static void test_runtime_ready_runs_before_listeners_and_teardown_removes_gates() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_RUNTIME_READY", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) &&
		proxysql_init_configured_plugins(mgr.get(), err) &&
		proxysql_start_configured_plugins(mgr.get(), err),
		"runtime-ready plugin reaches the started state (err='%s')", err.c_str());
	append_log("core:hgm_auth_qpro_mth_ready");
	ProxySQL_PluginRuntimeContext context { nullptr, 1234 };
	ok(proxysql_runtime_ready_configured_plugins(mgr.get(), context, err),
		"successful runtime-ready reconciliation does not degrade the plugin (err='%s')", err.c_str());
	append_log("core:listeners_started");
	const std::string log = read_log();
	ok(contains_in_order(log, "core:hgm_auth_qpro_mth_ready", "fake_plugin:runtime_ready") &&
		contains_in_order(log, "fake_plugin:runtime_ready", "core:listeners_started"),
		"runtime_ready is ordered after core prerequisites and before listeners (log='%s')", log.c_str());
	ok(proxysql_plugin_listener_gate_lookup("127.0.0.1", 6450).has_value(),
		"runtime-ready plugin installs its listener gate through ABI 8 services");
	(void)proxysql_stop_configured_plugins(mgr, err);
	ok(!proxysql_plugin_listener_gate_lookup("127.0.0.1", 6450).has_value(),
		"manager teardown removes gates owned by its plugin");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_RUNTIME_READY");
}

static void test_runtime_ready_failure_degrades_without_aborting_listener_start() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_RUNTIME_READY", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_RUNTIME_READY_INSTALL_READY", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) &&
		proxysql_init_configured_plugins(mgr.get(), err) &&
		proxysql_start_configured_plugins(mgr.get(), err),
		"plugin start succeeds before its runtime-ready reconciliation");
	ProxySQL_PluginRuntimeContext context { nullptr, 5678 };
	ok(proxysql_runtime_ready_configured_plugins(mgr.get(), context, err),
		"runtime readiness can first leave the plugin listener ready (err='%s')", err.c_str());
	auto listener_gate = proxysql_plugin_listener_gate_lookup("127.0.0.1", 6450);
	ok(listener_gate && listener_gate->state == ProxySQL_PluginListenerState::ready,
		"the callback starts its second reconciliation with a ready gate");
	setenv("PROXYSQL_FAKE_PLUGIN_RUNTIME_READY_FAIL", "1", 1);
	ok(!proxysql_runtime_ready_configured_plugins(mgr.get(), context, err),
		"a failed runtime-ready callback reports a degraded plugin");
	listener_gate = proxysql_plugin_listener_gate_lookup("127.0.0.1", 6450);
	ok(listener_gate && listener_gate->state == ProxySQL_PluginListenerState::closed &&
		listener_gate->reason == "runtime readiness degraded",
		"a false callback closes its previously ready gates with a sanitized reason");
	append_log("core:listeners_started");
	const std::string log = read_log();
	ok(log.find("fake_plugin:runtime_ready_fail") != std::string::npos &&
		contains_in_order(log, "fake_plugin:runtime_ready_fail", "core:listeners_started"),
		"runtime-ready failure does not prevent listeners from starting (log='%s')", log.c_str());
	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_RUNTIME_READY_FAIL");
	unsetenv("PROXYSQL_FAKE_PLUGIN_RUNTIME_READY_INSTALL_READY");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_RUNTIME_READY");
}

static void test_runtime_ready_exception_closes_ready_gates() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_RUNTIME_READY", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_RUNTIME_READY_INSTALL_READY", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_RUNTIME_READY_THROW", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) &&
		proxysql_init_configured_plugins(mgr.get(), err) &&
		proxysql_start_configured_plugins(mgr.get(), err),
		"plugin start succeeds before its runtime-ready exception");
	ProxySQL_PluginRuntimeContext context { nullptr, 6789 };
	ok(!proxysql_runtime_ready_configured_plugins(mgr.get(), context, err),
		"a throwing runtime-ready callback reports a degraded plugin");
	const auto listener_gate = proxysql_plugin_listener_gate_lookup("127.0.0.1", 6450);
	ok(listener_gate && listener_gate->state == ProxySQL_PluginListenerState::closed &&
		listener_gate->reason == "runtime readiness degraded",
		"an exception closes its newly ready gate with a sanitized reason");
	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN_RUNTIME_READY_THROW");
	unsetenv("PROXYSQL_FAKE_PLUGIN_RUNTIME_READY_INSTALL_READY");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_RUNTIME_READY");
}

static void test_runtime_ready_callbacks_receive_isolated_contexts() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_RUNTIME_READY", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_RUNTIME_READY_MUTATE_CONTEXT", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN2_ENABLE_RUNTIME_READY", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH, PROXYSQL_FAKE_PLUGIN2_PATH };
	std::string err;
	ok(proxysql_load_configured_plugins(mgr, paths, err) &&
		proxysql_init_configured_plugins(mgr.get(), err) &&
		proxysql_start_configured_plugins(mgr.get(), err),
		"two runtime-ready plugins start before their callbacks run");
	ProxySQL_PluginRuntimeContext context { nullptr, 7890 };
	ok(proxysql_runtime_ready_configured_plugins(mgr.get(), context, err),
		"a callback mutating its context cannot degrade the following plugin (err='%s')", err.c_str());
	const std::string log = read_log();
	ok(contains_in_order(log, "fake_plugin:runtime_ready_mutated_context", "fake_plugin2:runtime_ready"),
		"the second runtime-ready callback received an unpoisoned context (log='%s')", log.c_str());
	(void)proxysql_stop_configured_plugins(mgr, err);
	unsetenv("PROXYSQL_FAKE_PLUGIN2_ENABLE_RUNTIME_READY");
	unsetenv("PROXYSQL_FAKE_PLUGIN_RUNTIME_READY_MUTATE_CONTEXT");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_RUNTIME_READY");
}

// Case 6: plugin returns a descriptor with an unknown abi_version.  The
// loader MUST refuse to load such a plugin rather than read past the end
// of its own (compiled-against) struct definition.  This is the test that
// keeps the tail-append pattern honest across plugin/core ABI skew.
static void test_bogus_abi_version_rejected() {
	setenv("PROXYSQL_FAKE_PLUGIN_FORCE_BOGUS_ABI", "1", 1);
	clear_log();

	std::unique_ptr<ProxySQL_PluginManager> mgr;
	std::vector<std::string> paths { PROXYSQL_FAKE_PLUGIN_PATH };
	std::string err;
	ok(!proxysql_load_configured_plugins(mgr, paths, err),
	   "load fails when plugin declares an unsupported ABI version");
	ok(!err.empty() && err.find("ABI") != std::string::npos,
	   "error message names the ABI mismatch (err='%s')", err.c_str());

	const std::string log = read_log();
	ok(log.find("fake_plugin:init") == std::string::npos,
	   "init was NOT called on a plugin rejected by the ABI check");

	unsetenv("PROXYSQL_FAKE_PLUGIN_FORCE_BOGUS_ABI");
}

int main() {
	plan(72);

	ok(PROXYSQL_PLUGIN_ABI_VERSION <= PROXYSQL_PLUGIN_ABI_VERSION_MAX,
		"the loader accepts the current additive ABI");

	make_log_path();
	test_duplicate_descriptor_names_are_rejected();

	test_phase_b_and_init_both_fire();
	test_early_action_runs_between_admin_and_init();
	test_early_action_exit_results_skip_normal_lifecycle();
	test_early_action_exception_is_a_sanitized_failure();
	test_first_early_exit_short_circuits_later_plugins();
	test_abi5_skips_early_action_tail();
	test_abi7_skips_runtime_ready_tail();
	test_only_init_skips_phase_b();
	test_phase_b_db_handles_are_null();
	test_phase_b_secret_services_are_not_available();
	test_phase_b_failure_aborts_init();
	test_phase_b_partial_failure_rolls_back();
	test_stop_runs_when_start_fails();
	test_runtime_ready_runs_before_listeners_and_teardown_removes_gates();
	test_runtime_ready_failure_degrades_without_aborting_listener_start();
	test_runtime_ready_exception_closes_ready_gates();
	test_runtime_ready_callbacks_receive_isolated_contexts();
	test_bogus_abi_version_rejected();

	cleanup_log();
	return exit_status();
}
