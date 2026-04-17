/**
 * @file test_greeting_capabilities-t.cpp
 * @brief Verifies the capability flags that ProxySQL advertises in the server
 *        'Greeting' packet during the initial MySQL handshake.
 *
 * @details
 * Background
 * ----------
 * When a MySQL client connects to ProxySQL, ProxySQL answers with the initial
 * handshake packet (a.k.a. "Server Greeting"). Embedded in that packet is a
 * 32-bit capability bitmask that tells the client which protocol features the
 * server supports (see MySQL Client/Server Protocol documentation).
 *
 * A subset of those capability bits are controlled by runtime ProxySQL
 * variables and can therefore be toggled at will:
 *
 *   - CLIENT_DEPRECATE_EOF    -> `mysql-enable_client_deprecate_eof`
 *   - CLIENT_SESSION_TRACKING -> `mysql-enable_client_session_tracking`
 *
 * This test exercises all four combinations of those two toggles and checks
 * the resulting capability bitmask returned by ProxySQL.
 *
 * Test strategy
 * -------------
 * For each combination `{deprecate_eof, session_tracking}` in
 * `{off,off} / {on,on} / {on,off} / {off,on}`:
 *
 *  1. Set the two variables on the ProxySQL admin interface.
 *  2. Apply the variables to runtime (`LOAD MYSQL VARIABLES TO RUNTIME`).
 *  3. Open a fresh client connection against ProxySQL (mysql_real_connect).
 *  4. Read `mysql->server_capabilities` (populated by libmariadb from the
 *     greeting packet).
 *  5. Check that every capability in the expectation's `present_caps` is set
 *     and every capability in `absent_caps` is cleared.
 *  6. Emit a single TAP `ok()` with a verbose message and `diag()` traces for
 *     every intermediate value so a failure can be debugged without attaching
 *     a protocol analyzer.
 *
 * The suite keeps running after a failure so that a single run surfaces every
 * broken scenario at once.
 */

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::pair;
using std::string;
using std::vector;

/**
 * @struct cap_entry_t
 * @brief  One entry in the capability-name dictionary.
 *
 * The test is more useful if failures log capability *names* rather than raw
 * integers. `KNOWN_CAPS` is a table of (bit, textual_name) pairs used by
 * @ref caps_to_string to produce human readable diagnostics.
 */
struct cap_entry_t {
	uint64_t    bit;   ///< Single-bit capability mask (e.g. CLIENT_PLUGIN_AUTH).
	const char* name;  ///< Mnemonic shown in diagnostics.
};

/**
 * @brief Dictionary used to decode a capability bitmask into readable form.
 *
 * Only contains the bits actually referenced by the test or by the handshake
 * code path — it does not need to be exhaustive, but missing bits will simply
 * appear as `0x<hex>` in `caps_to_string`.
 */
static const cap_entry_t KNOWN_CAPS[] = {
	{ CLIENT_MYSQL,                           "CLIENT_MYSQL" },
	{ CLIENT_FOUND_ROWS,                      "CLIENT_FOUND_ROWS" },
	{ CLIENT_LONG_FLAG,                       "CLIENT_LONG_FLAG" },
	{ CLIENT_CONNECT_WITH_DB,                 "CLIENT_CONNECT_WITH_DB" },
	{ CLIENT_NO_SCHEMA,                       "CLIENT_NO_SCHEMA" },
	{ CLIENT_COMPRESS,                        "CLIENT_COMPRESS" },
	{ CLIENT_ODBC,                            "CLIENT_ODBC" },
	{ CLIENT_LOCAL_FILES,                     "CLIENT_LOCAL_FILES" },
	{ CLIENT_IGNORE_SPACE,                    "CLIENT_IGNORE_SPACE" },
	{ CLIENT_PROTOCOL_41,                     "CLIENT_PROTOCOL_41" },
	{ CLIENT_INTERACTIVE,                     "CLIENT_INTERACTIVE" },
	{ CLIENT_SSL,                             "CLIENT_SSL" },
	{ CLIENT_IGNORE_SIGPIPE,                  "CLIENT_IGNORE_SIGPIPE" },
	{ CLIENT_TRANSACTIONS,                    "CLIENT_TRANSACTIONS" },
	{ CLIENT_RESERVED,                        "CLIENT_RESERVED" },
	{ CLIENT_SECURE_CONNECTION,               "CLIENT_SECURE_CONNECTION" },
	{ CLIENT_MULTI_STATEMENTS,                "CLIENT_MULTI_STATEMENTS" },
	{ CLIENT_MULTI_RESULTS,                   "CLIENT_MULTI_RESULTS" },
	{ CLIENT_PS_MULTI_RESULTS,                "CLIENT_PS_MULTI_RESULTS" },
	{ CLIENT_PLUGIN_AUTH,                     "CLIENT_PLUGIN_AUTH" },
	{ CLIENT_CONNECT_ATTRS,                   "CLIENT_CONNECT_ATTRS" },
	{ CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,  "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA" },
	{ CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS,    "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS" },
	{ CLIENT_SESSION_TRACKING,                "CLIENT_SESSION_TRACKING" },
	{ CLIENT_DEPRECATE_EOF,                   "CLIENT_DEPRECATE_EOF" },
	{ CLIENT_ZSTD_COMPRESSION,                "CLIENT_ZSTD_COMPRESSION" },
	{ CLIENT_SSL_VERIFY_SERVER_CERT,          "CLIENT_SSL_VERIFY_SERVER_CERT" },
	{ CLIENT_REMEMBER_OPTIONS,                "CLIENT_REMEMBER_OPTIONS" },
};

/**
 * @brief Build a human readable list of the bits set in @p caps.
 *
 * Every bit mentioned in @ref KNOWN_CAPS is emitted by name; every remaining
 * bit not covered by the dictionary is printed as `0x<hex>` so nothing is
 * silently dropped.
 *
 * @param caps Raw 32-bit capability bitmask (as returned by the server).
 * @return     Formatted string, e.g.
 *             `CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | 0x04000000`.
 *             Returns the literal `"<none>"` if @p caps == 0.
 */
static string caps_to_string(uint64_t caps) {
	if (caps == 0) {
		return "<none>";
	}

	std::ostringstream oss;
	bool first = true;
	uint64_t remaining = caps;

	for (const cap_entry_t& e : KNOWN_CAPS) {
		if ((caps & e.bit) != 0) {
			if (!first) oss << " | ";
			oss << e.name;
			first = false;
			remaining &= ~e.bit;
		}
	}

	if (remaining != 0) {
		char buf[32];
		snprintf(buf, sizeof(buf), "0x%08llx",
				 static_cast<unsigned long long>(remaining));
		if (!first) oss << " | ";
		oss << buf;
	}

	return oss.str();
}

/**
 * @brief Capability bits ProxySQL MUST advertise in every greeting, regardless
 *        of any runtime toggle.
 *
 * These match what a real MySQL 8.x server advertises in its Server Greeting
 * and are relied upon by several clients (JDBC in particular — see issue
 * #4023). Regressing any of them typically manifests as
 * `java.lang.ArrayIndexOutOfBoundsException` on the client side.
 *
 * This list is checked against every scenario via @ref verify_caps.
 */
static const vector<uint64_t> BASELINE_PRESENT_CAPS = {
	CLIENT_MULTI_STATEMENTS,
	CLIENT_MULTI_RESULTS,
	CLIENT_PS_MULTI_RESULTS,
	CLIENT_PLUGIN_AUTH,
	CLIENT_REMEMBER_OPTIONS,
};

/**
 * @struct caps_expectation_t
 * @brief  Expected state of the toggle-controlled capability bits in a scenario.
 *
 * A test scenario supplies one `caps_expectation_t` describing ONLY the bits
 * it cares to toggle. Bits in @ref present_caps MUST be set in
 * `mysql->server_capabilities`; bits in @ref absent_caps MUST be cleared. Bits
 * appearing in neither list are ignored here because ProxySQL's baseline
 * greeting also flips bits like `CLIENT_COMPRESS`, `CLIENT_SSL`, etc. whose
 * values depend on global configuration unrelated to the scenario.
 *
 * In addition to the scenario-specific expectation, @ref BASELINE_PRESENT_CAPS
 * is always checked — see @ref verify_caps.
 */
struct caps_expectation_t {
	vector<uint64_t> present_caps; ///< Bits that MUST be set (scenario-specific).
	vector<uint64_t> absent_caps;  ///< Bits that MUST be clear (scenario-specific).
};

/**
 * @brief Compare actual vs expected capability bits and emit diagnostics.
 *
 * Verifies three things against @p actual_caps (coming from
 * `mysql->server_capabilities`):
 *   1. Every bit in @ref BASELINE_PRESENT_CAPS is set.
 *   2. Every bit in `exp.present_caps` is set.
 *   3. Every bit in `exp.absent_caps` is cleared.
 *
 * The function never stops on the first mismatch: every deviation is reported
 * via `diag()` so one failed run produces a complete picture of what is wrong.
 *
 * @param actual_caps Bitmask returned by the server (already 32 bit wide).
 * @param exp         Expectation describing required/forbidden bits
 *                    specific to the scenario (on top of the baseline).
 * @return            `true` if every required bit is set and every forbidden
 *                    bit is clear; `false` otherwise.
 */
static bool verify_caps(uint64_t actual_caps, const caps_expectation_t& exp) {
	bool ok_flag = true;

	for (const uint64_t bit : BASELINE_PRESENT_CAPS) {
		const bool has = (actual_caps & bit) != 0;
		diag("  [baseline      ] %-40s -> %s",
			 caps_to_string(bit).c_str(), has ? "OK" : "MISSING");
		if (!has) ok_flag = false;
	}

	for (const uint64_t bit : exp.present_caps) {
		const bool has = (actual_caps & bit) != 0;
		diag("  [expect present] %-40s -> %s",
			 caps_to_string(bit).c_str(), has ? "OK" : "MISSING");
		if (!has) ok_flag = false;
	}

	for (const uint64_t bit : exp.absent_caps) {
		const bool has = (actual_caps & bit) != 0;
		diag("  [expect absent ] %-40s -> %s",
			 caps_to_string(bit).c_str(), has ? "UNEXPECTED" : "OK");
		if (has) ok_flag = false;
	}

	return ok_flag;
}

/**
 * @brief Apply the two runtime toggles under test and reload them.
 *
 * Runs three admin statements:
 *   - `SET mysql-enable_client_deprecate_eof = <0|1>`
 *   - `SET mysql-enable_client_session_tracking = <0|1>`
 *   - `LOAD MYSQL VARIABLES TO RUNTIME`
 *
 * @param admin            Already-connected admin MYSQL* handle.
 * @param deprecate_eof    Desired value for `mysql-enable_client_deprecate_eof`.
 * @param session_tracking Desired value for `mysql-enable_client_session_tracking`.
 * @return                 `true` on success, `false` if any statement failed
 *                         (the error is printed via `diag()` before returning).
 */
static bool apply_runtime_toggles(MYSQL* admin, bool deprecate_eof, bool session_tracking) {
	char stmt[256];

	snprintf(stmt, sizeof(stmt),
			 "SET mysql-enable_client_deprecate_eof=%d", deprecate_eof ? 1 : 0);
	diag("  admin> %s", stmt);
	if (mysql_query(admin, stmt)) {
		diag("  admin query failed: %s", mysql_error(admin));
		return false;
	}

	snprintf(stmt, sizeof(stmt),
			 "SET mysql-enable_client_session_tracking=%d", session_tracking ? 1 : 0);
	diag("  admin> %s", stmt);
	if (mysql_query(admin, stmt)) {
		diag("  admin query failed: %s", mysql_error(admin));
		return false;
	}

	const char* reload = "LOAD MYSQL VARIABLES TO RUNTIME";
	diag("  admin> %s", reload);
	if (mysql_query(admin, reload)) {
		diag("  admin query failed: %s", mysql_error(admin));
		return false;
	}

	return true;
}

/**
 * @brief Open a fresh client connection to ProxySQL and log the outcome.
 *
 * The returned handle is already connected via `mysql_real_connect`. The
 * caller owns it and MUST `mysql_close` it. On failure the function logs the
 * mariadb client error and returns `nullptr`.
 *
 * @param cl          Parsed CommandLine describing host/port/user/password.
 * @param client_flag Bitmask passed as `options.client_flag` *before*
 *                    `mysql_real_connect`. Used to mirror what a regular
 *                    client would advertise (e.g. `CLIENT_DEPRECATE_EOF`).
 * @return            Connected MYSQL* on success; `nullptr` on failure.
 */
static MYSQL* open_client(const CommandLine& cl, uint64_t client_flag) {
	MYSQL* proxy = mysql_init(NULL);
	if (proxy == NULL) {
		diag("  mysql_init returned NULL");
		return NULL;
	}

	if (client_flag != 0) {
		proxy->options.client_flag |= client_flag;
		diag("  client advertises flag(s): %s", caps_to_string(client_flag).c_str());
	}

	diag("  connecting to %s:%d as '%s'", cl.host, cl.port, cl.username);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password,
							NULL, cl.port, NULL, 0)) {
		diag("  mysql_real_connect failed: %s", mysql_error(proxy));
		mysql_close(proxy);
		return NULL;
	}

	return proxy;
}

/**
 * @struct scenario_t
 * @brief  One permutation of the runtime toggles plus its expectation.
 *
 * Keeping the four scenarios in a table makes the main loop small and the
 * list of cases easy to extend: adding a fifth scenario only requires a new
 * row here, not more code.
 */
struct scenario_t {
	const char*        name;                ///< Short label used in TAP + diag.
	bool               deprecate_eof;       ///< Value of the runtime toggle.
	bool               session_tracking;    ///< Value of the runtime toggle.
	uint64_t           client_flag;         ///< Extra `client_flag` the client advertises before connect.
	caps_expectation_t expectation;         ///< Bits required/forbidden in the greeting.
};

/**
 * @brief Execute every scenario once, emitting one TAP assertion per run.
 *
 * The function:
 *   - calls @ref apply_runtime_toggles to push the variables,
 *   - calls @ref open_client to connect,
 *   - reads `proxy->server_capabilities`,
 *   - prints a full before/after trace via `diag()`,
 *   - calls @ref verify_caps and forwards the verdict to `ok()`.
 *
 * @param cl    Parsed CommandLine (host/port/credentials).
 * @param admin Already-connected admin MYSQL* handle.
 * @return      `EXIT_SUCCESS` if every connection attempt succeeded (the TAP
 *              framework tracks per-assertion pass/fail separately).
 */
static int run_scenarios(const CommandLine& cl, MYSQL* admin) {
	const scenario_t scenarios[] = {
		{
			"both_off",
			/* deprecate_eof    */ false,
			/* session_tracking */ false,
			/* client_flag      */ 0,
			/* expectation      */ {
				/* present */ {},
				/* absent  */ { CLIENT_DEPRECATE_EOF, CLIENT_SESSION_TRACKING },
			},
		},
		{
			"both_on",
			/* deprecate_eof    */ true,
			/* session_tracking */ true,
			/* client_flag      */ CLIENT_DEPRECATE_EOF,
			/* expectation      */ {
				/* present */ { CLIENT_DEPRECATE_EOF, CLIENT_SESSION_TRACKING },
				/* absent  */ {},
			},
		},
		{
			"eof_on_tracking_off",
			/* deprecate_eof    */ true,
			/* session_tracking */ false,
			/* client_flag      */ CLIENT_DEPRECATE_EOF,
			/* expectation      */ {
				/* present */ { CLIENT_DEPRECATE_EOF },
				/* absent  */ { CLIENT_SESSION_TRACKING },
			},
		},
		{
			"eof_off_tracking_on",
			/* deprecate_eof    */ false,
			/* session_tracking */ true,
			/* client_flag      */ 0,
			/* expectation      */ {
				/* present */ { CLIENT_SESSION_TRACKING },
				/* absent  */ { CLIENT_DEPRECATE_EOF },
			},
		},
	};

	int scenario_idx = 0;
	for (const scenario_t& s : scenarios) {
		++scenario_idx;
		diag("================================================================");
		diag("Scenario %d/%zu: %s  (deprecate_eof=%d, session_tracking=%d)",
			 scenario_idx,
			 sizeof(scenarios) / sizeof(scenarios[0]),
			 s.name, s.deprecate_eof ? 1 : 0, s.session_tracking ? 1 : 0);
		diag("================================================================");

		if (!apply_runtime_toggles(admin, s.deprecate_eof, s.session_tracking)) {
			ok(false, "scenario '%s': failed to apply runtime toggles", s.name);
			continue;
		}

		MYSQL* proxy = open_client(cl, s.client_flag);
		if (proxy == NULL) {
			ok(false, "scenario '%s': failed to connect to ProxySQL", s.name);
			continue;
		}

		const uint64_t caps = proxy->server_capabilities;
		diag("  server_capabilities (raw): 0x%08llx (%llu)",
			 static_cast<unsigned long long>(caps),
			 static_cast<unsigned long long>(caps));
		diag("  server_capabilities (decoded): %s", caps_to_string(caps).c_str());

		const bool verdict = verify_caps(caps, s.expectation);

		ok(verdict,
		   "scenario '%s' (deprecate_eof=%d, session_tracking=%d): greeting capabilities match expectation",
		   s.name, s.deprecate_eof ? 1 : 0, s.session_tracking ? 1 : 0);

		mysql_close(proxy);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Test entry point.
 *
 * Establishes the admin connection once, plans the TAP counter, then hands
 * over to @ref run_scenarios. Admin handle is closed before returning.
 */
int main(int argc, char** argv) {
	(void) argc;
	(void) argv;

	CommandLine cl;

	plan(4);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	diag("ProxySQL connection target: %s:%d (user=%s)",
		 cl.host, cl.port, cl.username);
	diag("ProxySQL admin target:      %s:%d (user=%s)",
		 cl.admin_host, cl.admin_port, cl.admin_username);

	MYSQL* admin = mysql_init(NULL);
	if (admin == NULL) {
		diag("mysql_init for admin returned NULL");
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username,
							cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("admin mysql_real_connect failed: %s", mysql_error(admin));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	run_scenarios(cl, admin);

	mysql_close(admin);
	return exit_status();
}
