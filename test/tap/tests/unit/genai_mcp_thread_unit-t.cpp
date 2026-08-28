/**
 * @file genai_mcp_thread_unit-t.cpp
 * @brief Unit tests for MCP_Threads_Handler variable/config management.
 *
 * Tests the variable management layer in lib/MCP_Thread.cpp:
 *   - Constructor default values
 *   - set_variable() / get_variable() round-trips for every variable
 *   - set_variable() validation (boolean parsing, port range, timeout range,
 *     max_rows bounds)
 *   - has_variable() for known and unknown names
 *   - get_variables_list() completeness
 *   - Null-pointer safety in get_variable() / set_variable() / has_variable()
 *   - get_variable_string() clears stale output on miss
 *   - get_target_auth_context() with empty map
 *   - get_all_target_auth_contexts() with empty map
 *
 * Built with all v4.0 plugins under PROXYSQL40=1 (auto-detected from libproxysql.a).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

#ifdef PROXYSQL40

#include "MCP_Thread.h"

#include <cstring>
#include <string>
#include <set>
#include <vector>

/* ------------------------------------------------------------------ */
/*  Helper: get a variable value as std::string                        */
/* ------------------------------------------------------------------ */
static std::string get_var(MCP_Threads_Handler& h, const char* name) {
	std::string value;
	if (!h.get_variable_string(name, value)) return "__ERROR__";
	return value;
}

/* ================================================================== */
/*  Test groups                                                        */
/* ================================================================== */

/**
 * @brief Verify constructor sets documented default values.
 */
static void test_constructor_defaults(MCP_Threads_Handler& h) {
	ok(get_var(h, "enabled") == "false",
	   "default enabled = false");
	ok(get_var(h, "port") == "6071",
	   "default port = 6071");
	ok(get_var(h, "use_ssl") == "true",
	   "default use_ssl = true");
	ok(get_var(h, "timeout_ms") == "30000",
	   "default timeout_ms = 30000");
	ok(get_var(h, "stats_show_queries_max_rows") == "200",
	   "default stats_show_queries_max_rows = 200");
	ok(get_var(h, "stats_show_processlist_max_rows") == "200",
	   "default stats_show_processlist_max_rows = 200");
	ok(get_var(h, "stats_enable_debug_tools") == "false",
	   "default stats_enable_debug_tools = false");

	/* Endpoint auth strings default to empty */
	const char* auth_vars[] = {
		"config_endpoint_auth", "stats_endpoint_auth",
		"query_endpoint_auth", "admin_endpoint_auth",
		"cache_endpoint_auth", "ai_endpoint_auth",
		"rag_endpoint_auth", nullptr
	};
	for (int i = 0; auth_vars[i]; i++) {
		ok(get_var(h, auth_vars[i]) == "",
		   "default %s = empty string", auth_vars[i]);
	}

	/* Status variables */
	ok(h.status_variables.total_requests == 0,
	   "default total_requests = 0");
	ok(h.status_variables.failed_requests == 0,
	   "default failed_requests = 0");
	ok(h.status_variables.active_connections == 0,
	   "default active_connections = 0");

	/* Pointers */
	ok(h.mcp_server == nullptr, "default mcp_server = nullptr");
	ok(h.mysql_tool_handler == nullptr, "default mysql_tool_handler = nullptr");
	ok(h.config_tool_handler == nullptr, "default config_tool_handler = nullptr");
	ok(h.query_tool_handler == nullptr, "default query_tool_handler = nullptr");
	ok(h.admin_tool_handler == nullptr, "default admin_tool_handler = nullptr");
	ok(h.cache_tool_handler == nullptr, "default cache_tool_handler = nullptr");
	ok(h.stats_tool_handler == nullptr, "default stats_tool_handler = nullptr");
	ok(h.ai_tool_handler == nullptr, "default ai_tool_handler = nullptr");
	ok(h.rag_tool_handler == nullptr, "default rag_tool_handler = nullptr");
}

/**
 * @brief Boolean variable set/get for "enabled", "use_ssl", "stats_enable_debug_tools".
 */
static void test_boolean_variables(MCP_Threads_Handler& h) {
	const char* bool_vars[] = { "enabled", "use_ssl", "stats_enable_debug_tools", nullptr };

	for (int i = 0; bool_vars[i]; i++) {
		const char* vname = bool_vars[i];

		/* Accept "true" / "false" (case-insensitive) and "1" / "0" */
		ok(h.set_variable(vname, "true") == 0,
		   "set %s = true succeeds", vname);
		ok(get_var(h, vname) == "true",
		   "get %s after set true", vname);

		ok(h.set_variable(vname, "false") == 0,
		   "set %s = false succeeds", vname);
		ok(get_var(h, vname) == "false",
		   "get %s after set false", vname);

		ok(h.set_variable(vname, "1") == 0,
		   "set %s = 1 succeeds", vname);
		ok(get_var(h, vname) == "true",
		   "get %s after set 1", vname);

		ok(h.set_variable(vname, "0") == 0,
		   "set %s = 0 succeeds", vname);
		ok(get_var(h, vname) == "false",
		   "get %s after set 0", vname);

		ok(h.set_variable(vname, "TRUE") == 0,
		   "set %s = TRUE (case-insensitive)", vname);
		ok(get_var(h, vname) == "true",
		   "get %s after set TRUE", vname);

		ok(h.set_variable(vname, "FALSE") == 0,
		   "set %s = FALSE (case-insensitive)", vname);
		ok(get_var(h, vname) == "false",
		   "get %s after set FALSE", vname);

		/* Invalid boolean values */
		ok(h.set_variable(vname, "yes") == -1,
		   "set %s = yes rejected", vname);
		ok(h.set_variable(vname, "no") == -1,
		   "set %s = no rejected", vname);
		ok(h.set_variable(vname, "2") == -1,
		   "set %s = 2 rejected", vname);
		ok(h.set_variable(vname, "") == -1,
		   "set %s = empty rejected", vname);
	}
}

/**
 * @brief Port variable validation (1..65535).
 */
static void test_port_variable(MCP_Threads_Handler& h) {
	ok(h.set_variable("port", "8080") == 0,
	   "set port = 8080 succeeds");
	ok(get_var(h, "port") == "8080",
	   "get port = 8080");

	ok(h.set_variable("port", "1") == 0,
	   "set port = 1 (min valid)");
	ok(get_var(h, "port") == "1",
	   "get port = 1");

	ok(h.set_variable("port", "65535") == 0,
	   "set port = 65535 (max valid)");
	ok(get_var(h, "port") == "65535",
	   "get port = 65535");

	/* Invalid port values */
	ok(h.set_variable("port", "0") == -1,
	   "set port = 0 rejected");
	ok(h.set_variable("port", "-1") == -1,
	   "set port = -1 rejected");
	ok(h.set_variable("port", "65536") == -1,
	   "set port = 65536 rejected");
	ok(h.set_variable("port", "99999") == -1,
	   "set port = 99999 rejected");
	ok(h.set_variable("port", "abc") == -1,
	   "set port = abc rejected (atoi returns 0)");
}

/**
 * @brief Timeout variable (>= 0).
 */
static void test_timeout_variable(MCP_Threads_Handler& h) {
	ok(h.set_variable("timeout_ms", "5000") == 0,
	   "set timeout_ms = 5000");
	ok(get_var(h, "timeout_ms") == "5000",
	   "get timeout_ms = 5000");

	ok(h.set_variable("timeout_ms", "0") == 0,
	   "set timeout_ms = 0 (minimum)");
	ok(get_var(h, "timeout_ms") == "0",
	   "get timeout_ms = 0");

	ok(h.set_variable("timeout_ms", "999999") == 0,
	   "set timeout_ms = 999999 (large)");
	ok(get_var(h, "timeout_ms") == "999999",
	   "get timeout_ms = 999999");

	/* Negative timeout rejected */
	ok(h.set_variable("timeout_ms", "-1") == -1,
	   "set timeout_ms = -1 rejected");
}

/**
 * @brief stats_show_queries_max_rows / stats_show_processlist_max_rows (1..1000).
 */
static void test_max_rows_variables(MCP_Threads_Handler& h) {
	const char* max_row_vars[] = {
		"stats_show_queries_max_rows",
		"stats_show_processlist_max_rows",
		nullptr
	};

	for (int i = 0; max_row_vars[i]; i++) {
		const char* vname = max_row_vars[i];

		ok(h.set_variable(vname, "1") == 0,
		   "set %s = 1 (minimum)", vname);
		ok(get_var(h, vname) == "1",
		   "get %s = 1", vname);

		ok(h.set_variable(vname, "500") == 0,
		   "set %s = 500", vname);
		ok(get_var(h, vname) == "500",
		   "get %s = 500", vname);

		ok(h.set_variable(vname, "1000") == 0,
		   "set %s = 1000 (maximum)", vname);
		ok(get_var(h, vname) == "1000",
		   "get %s = 1000", vname);

		/* Out-of-range */
		ok(h.set_variable(vname, "0") == -1,
		   "set %s = 0 rejected", vname);
		ok(h.set_variable(vname, "-1") == -1,
		   "set %s = -1 rejected", vname);
		ok(h.set_variable(vname, "1001") == -1,
		   "set %s = 1001 rejected", vname);
		ok(h.set_variable(vname, "99999") == -1,
		   "set %s = 99999 rejected", vname);
	}
}

/**
 * @brief String (auth) variables accept arbitrary values.
 */
static void test_string_variables(MCP_Threads_Handler& h) {
	const char* str_vars[] = {
		"config_endpoint_auth", "stats_endpoint_auth",
		"query_endpoint_auth", "admin_endpoint_auth",
		"cache_endpoint_auth", "ai_endpoint_auth",
		"rag_endpoint_auth", nullptr
	};

	for (int i = 0; str_vars[i]; i++) {
		const char* vname = str_vars[i];

		ok(h.set_variable(vname, "my_secret_token") == 0,
		   "set %s = my_secret_token", vname);
		ok(get_var(h, vname) == "my_secret_token",
		   "get %s = my_secret_token", vname);

		ok(h.set_variable(vname, "") == 0,
		   "set %s = empty string", vname);
		ok(get_var(h, vname) == "",
		   "get %s = empty string", vname);

		ok(h.set_variable(vname, "Bearer abc123!@#$%^&*()") == 0,
		   "set %s = complex string with special chars", vname);
		ok(get_var(h, vname) == "Bearer abc123!@#$%^&*()",
		   "get %s = complex string roundtrip", vname);
	}
}

/**
 * @brief has_variable() for known and unknown names.
 */
static void test_has_variable(MCP_Threads_Handler& h) {
	/* Known variables */
	ok(h.has_variable("enabled") == true,
	   "has_variable(enabled) = true");
	ok(h.has_variable("port") == true,
	   "has_variable(port) = true");
	ok(h.has_variable("use_ssl") == true,
	   "has_variable(use_ssl) = true");
	ok(h.has_variable("timeout_ms") == true,
	   "has_variable(timeout_ms) = true");
	ok(h.has_variable("config_endpoint_auth") == true,
	   "has_variable(config_endpoint_auth) = true");
	ok(h.has_variable("stats_show_queries_max_rows") == true,
	   "has_variable(stats_show_queries_max_rows) = true");
	ok(h.has_variable("stats_show_processlist_max_rows") == true,
	   "has_variable(stats_show_processlist_max_rows) = true");
	ok(h.has_variable("stats_enable_debug_tools") == true,
	   "has_variable(stats_enable_debug_tools) = true");

	/* Unknown variables */
	ok(h.has_variable("nonexistent") == false,
	   "has_variable(nonexistent) = false");
	ok(h.has_variable("") == false,
	   "has_variable(empty) = false");
	ok(h.has_variable("mcp_enabled") == false,
	   "has_variable(mcp_enabled) = false (no prefix)");
	ok(h.has_variable("PORT") == false,
	   "has_variable(PORT) = false (case-sensitive)");

	/* Null pointer */
	ok(h.has_variable(nullptr) == false,
	   "has_variable(nullptr) = false");
}

/**
 * @brief get_variables_list() returns all known variable names.
 */
static void test_get_variables_list(MCP_Threads_Handler& h) {
	char** list = h.get_variables_list();
	ok(list != nullptr, "get_variables_list returns non-null");

	if (!list) return;

	/* Count and collect into a set */
	std::set<std::string> names;
	int count = 0;
	for (int i = 0; list[i]; i++) {
		names.insert(list[i]);
		count++;
	}

	ok(count == 14, "get_variables_list returns 14 variables (got %d)", count);

	/* Verify all expected names are present */
	const char* expected[] = {
		"enabled", "port", "use_ssl",
		"config_endpoint_auth", "stats_endpoint_auth",
		"query_endpoint_auth", "admin_endpoint_auth",
		"cache_endpoint_auth", "ai_endpoint_auth", "rag_endpoint_auth",
		"timeout_ms",
		"stats_show_queries_max_rows",
		"stats_show_processlist_max_rows",
		"stats_enable_debug_tools",
		nullptr
	};
	for (int i = 0; expected[i]; i++) {
		ok(names.count(expected[i]) == 1,
		   "variables_list contains '%s'", expected[i]);
	}

	/* Free the list */
	for (int i = 0; list[i]; i++) {
		free(list[i]);
	}
	free(list);
}

/**
 * @brief Null-pointer safety for get_variable / set_variable.
 */
static void test_null_safety(MCP_Threads_Handler& h) {
	char buf[256];

	ok(h.get_variable(nullptr, buf, sizeof(buf)) == -1,
	   "get_variable(nullptr, buf) = -1");
	ok(h.get_variable("enabled", nullptr, sizeof(buf)) == -1,
	   "get_variable(enabled, nullptr) = -1");
	ok(h.get_variable("enabled", buf, 0) == -1,
	   "get_variable(enabled, buf, 0) = -1");
	ok(h.get_variable(nullptr, nullptr, 0) == -1,
	   "get_variable(nullptr, nullptr) = -1");

	ok(h.set_variable(nullptr, "true") == -1,
	   "set_variable(nullptr, true) = -1");
	ok(h.set_variable("enabled", nullptr) == -1,
	   "set_variable(enabled, nullptr) = -1");
	ok(h.set_variable(nullptr, nullptr) == -1,
	   "set_variable(nullptr, nullptr) = -1");
}

/**
 * @brief Bounded get_variable() rejects values that would be truncated.
 */
static void test_bounded_get_variable(MCP_Threads_Handler& h) {
	const std::string long_value(4096, 'x');
	ok(h.set_variable("config_endpoint_auth", long_value.c_str()) == 0,
	   "set long config_endpoint_auth value");

	char buf[16];
	memset(buf, 'x', sizeof(buf));
	ok(h.get_variable("config_endpoint_auth", buf, sizeof(buf)) == -1 && buf[0] == '\0',
	   "get_variable rejects and clears a truncated value");

	ok(h.set_variable("config_endpoint_auth", "") == 0,
	   "reset config_endpoint_auth after bounded read test");
}

/**
 * @brief get_variable_string() should overwrite stale output.
 */
static void test_get_variable_string_contract(MCP_Threads_Handler& h) {
	std::string out = "stale";
	ok(h.get_variable_string("nonexistent", out) == false && out.empty(),
	   "get_variable_string(nonexistent) clears stale output");
	ok(h.get_variable_string("enabled", out) == true && out == "false",
	   "get_variable_string(enabled) returns current value");
}

/**
 * @brief get_variable for unknown name returns -1.
 */
static void test_get_unknown_variable(MCP_Threads_Handler& h) {
	char buf[256];
	ok(h.get_variable("nonexistent", buf, sizeof(buf)) == -1,
	   "get_variable(nonexistent) = -1");
	ok(h.get_variable("", buf, sizeof(buf)) == -1,
	   "get_variable(empty) = -1");
}

/**
 * @brief set_variable for unknown name returns -1.
 */
static void test_set_unknown_variable(MCP_Threads_Handler& h) {
	ok(h.set_variable("nonexistent", "value") == -1,
	   "set_variable(nonexistent) = -1");
	ok(h.set_variable("", "value") == -1,
	   "set_variable(empty) = -1");
}

/**
 * @brief Target auth context methods on an empty map.
 */
static void test_target_auth_empty(MCP_Threads_Handler& h) {
	MCP_Threads_Handler::MCP_Target_Auth_Context ctx;
	ok(h.get_target_auth_context("nonexistent", ctx) == false,
	   "get_target_auth_context on empty map returns false");

	std::vector<MCP_Threads_Handler::MCP_Target_Auth_Context> all = h.get_all_target_auth_contexts();
	ok(all.empty(), "get_all_target_auth_contexts on empty map returns empty vector");
}

/**
 * @brief load_target_auth_map with null resultset returns -1.
 */
static void test_load_target_auth_null(MCP_Threads_Handler& h) {
	ok(h.load_target_auth_map(nullptr) == -1,
	   "load_target_auth_map(nullptr) = -1");
}

/**
 * @brief Verify wrlock/wrunlock do not deadlock on a single thread.
 */
static void test_wrlock_wrunlock(MCP_Threads_Handler& h) {
	h.wrlock();
	h.wrunlock();
	ok(true, "wrlock/wrunlock round-trip without deadlock");
}

/* ================================================================== */
/*  Test count                                                         */
/* ================================================================== */

/*
 * Constructor defaults:  7 scalars + 7 auth + 3 status + 8 pointers = 25
 * Boolean variables:     3 vars * 16 tests each = 48
 * Port variable:         10
 * Timeout variable:      7
 * Max rows variables:    2 vars * 10 tests each = 20
 * String variables:      7 vars * 6 tests each = 42
 * has_variable:          13
 * get_variables_list:    2 + 14 = 16
 * Null safety:           7
 * Bounded get_variable:  3
 * get_variable_string:   2
 * Get unknown:           2
 * Set unknown:           2
 * Target auth empty:     2
 * Load target auth null: 1
 * wrlock/wrunlock:       1
 * -------------------------------------------------
 * Total:                 203
 */
static const int TOTAL_TESTS = 203;

int main() {
	plan(TOTAL_TESTS);
	test_init_minimal();

	MCP_Threads_Handler handler;

	test_constructor_defaults(handler);
	test_boolean_variables(handler);
	test_port_variable(handler);
	test_timeout_variable(handler);
	test_max_rows_variables(handler);
	test_string_variables(handler);
	test_has_variable(handler);
	test_get_variables_list(handler);
	test_null_safety(handler);
	test_bounded_get_variable(handler);
	test_get_variable_string_contract(handler);
	test_get_unknown_variable(handler);
	test_set_unknown_variable(handler);
	test_target_auth_empty(handler);
	test_load_target_auth_null(handler);
	test_wrlock_wrunlock(handler);

	test_cleanup_minimal();
	return exit_status();
}

#else /* !PROXYSQL40 */

int main() {
	plan(1);
	ok(true, "PROXYSQL40 not enabled -- skipping MCP_Thread unit tests");
	return exit_status();
}

#endif /* PROXYSQL40 */
