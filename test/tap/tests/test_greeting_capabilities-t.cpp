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
 * Most of those bits are hard-coded to always-on values that match what a
 * real MySQL server advertises — see @ref BASELINE_PRESENT_CAPS. One bit,
 * `CLIENT_DEPRECATE_EOF`, is controlled at runtime by
 * `mysql-enable_client_deprecate_eof`, because enabling it changes the wire
 * protocol (no EOF packets) and not every client is ready for that.
 *
 * Regression protection
 * ---------------------
 * The hard-coded bits were accidentally dropped during the zstd support
 * refactor (commit `8c6a6444d`, shipped in v3.0.7). This regression manifested
 * as `java.lang.ArrayIndexOutOfBoundsException` on JDBC clients relying on
 * `CLIENT_SESSION_TRACKING` (see issues #4023 and #5621). The baseline check
 * in @ref verify_caps is specifically designed to catch any future removal of
 * those bits early.
 *
 * Test strategy
 * -------------
 * The test runs two scenarios covering the `mysql-enable_client_deprecate_eof`
 * toggle (`on` / `off`). Each scenario:
 *
 *  1. Sets the variable on the ProxySQL admin interface.
 *  2. Applies it to runtime (`LOAD MYSQL VARIABLES TO RUNTIME`).
 *  3. Opens a fresh client connection against ProxySQL (`mysql_real_connect`).
 *  4. Reads `mysql->server_capabilities` (populated by libmariadb from the
 *     greeting packet).
 *  5. Checks that every bit in @ref BASELINE_PRESENT_CAPS is set, plus the
 *     scenario-specific expectation on `CLIENT_DEPRECATE_EOF`.
 *  6. Emits a TAP `ok()` plus `diag()` traces for every intermediate value so
 *     a failure can be debugged without attaching a protocol analyzer.
 *
 * The suite keeps running after a failure so a single run surfaces every
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
 * @brief Capability bits ProxySQL MUST advertise in every greeting.
 *
 * These are hard-coded into the `extended_capabilities` local in
 * `MySQL_Protocol::generate_pkt_initial_handshake` and match what a real
 * MySQL 8.x server advertises. Several clients rely on them — in particular
 * JDBC needs `CLIENT_SESSION_TRACKING` to parse GTID data from OK packets,
 * and PS_MULTI_RESULTS is required for stored procedures returning multiple
 * result sets.
 *
 * These bits are intentionally NOT configurable through
 * `mysql-server_capabilities`: that admin variable is OR-combined with the
 * greeting, so it can only *add* bits, never remove them — precisely so a
 * misconfigured runtime cannot strip protocol-critical capabilities.
 *
 * Regressing any of these bits typically manifests as
 * `java.lang.ArrayIndexOutOfBoundsException` on JDBC clients (issue #4023)
 * or as clients silently losing session-tracking data (issue #5621).
 */
static const vector<uint64_t> BASELINE_PRESENT_CAPS = {
	CLIENT_MULTI_STATEMENTS,
	CLIENT_MULTI_RESULTS,
	CLIENT_PS_MULTI_RESULTS,
	CLIENT_PLUGIN_AUTH,
	CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
	CLIENT_SESSION_TRACKING,
	CLIENT_REMEMBER_OPTIONS,
};

/**
 * @struct caps_expectation_t
 * @brief  Expected state of the toggle-controlled capability bits in a scenario.
 *
 * A test scenario supplies one `caps_expectation_t` describing ONLY the bits
 * it cares to toggle. Bits in @ref present_caps MUST be set in
 * `mysql->server_capabilities`; bits in @ref absent_caps MUST be cleared.
 * Bits appearing in neither list are ignored here because ProxySQL's baseline
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
 * @brief Apply the `mysql-enable_client_deprecate_eof` toggle and reload.
 *
 * Runs two admin statements:
 *   - `SET mysql-enable_client_deprecate_eof = <0|1>`
 *   - `LOAD MYSQL VARIABLES TO RUNTIME`
 *
 * @param admin         Already-connected admin MYSQL* handle.
 * @param deprecate_eof Desired value for `mysql-enable_client_deprecate_eof`.
 * @return              `true` on success, `false` if any statement failed
 *                      (the error is printed via `diag()` before returning).
 */
static bool apply_deprecate_eof(MYSQL* admin, bool deprecate_eof) {
	char stmt[256];

	snprintf(stmt, sizeof(stmt),
			 "SET mysql-enable_client_deprecate_eof=%d", deprecate_eof ? 1 : 0);
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
 * @brief  One permutation of the `deprecate_eof` toggle plus its expectation.
 *
 * Keeping the scenarios in a table makes the main loop small and the list of
 * cases easy to extend: adding a new row here is all that's needed.
 */
struct scenario_t {
	const char*        name;                ///< Short label used in TAP + diag.
	bool               deprecate_eof;       ///< Value of the runtime toggle.
	uint64_t           client_flag;         ///< Extra `client_flag` the client advertises before connect.
	caps_expectation_t expectation;         ///< Bits required/forbidden in the greeting.
};

/**
 * @brief Execute every scenario once, emitting one TAP assertion per run.
 *
 * The function:
 *   - calls @ref apply_deprecate_eof to push the variable,
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
			"deprecate_eof_off",
			/* deprecate_eof */ false,
			/* client_flag   */ 0,
			/* expectation   */ {
				/* present */ {},
				/* absent  */ { CLIENT_DEPRECATE_EOF },
			},
		},
		{
			"deprecate_eof_on",
			/* deprecate_eof */ true,
			/* client_flag   */ CLIENT_DEPRECATE_EOF,
			/* expectation   */ {
				/* present */ { CLIENT_DEPRECATE_EOF },
				/* absent  */ {},
			},
		},
	};

	int scenario_idx = 0;
	for (const scenario_t& s : scenarios) {
		++scenario_idx;
		diag("================================================================");
		diag("Scenario %d/%zu: %s  (deprecate_eof=%d)",
			 scenario_idx,
			 sizeof(scenarios) / sizeof(scenarios[0]),
			 s.name, s.deprecate_eof ? 1 : 0);
		diag("================================================================");

		if (!apply_deprecate_eof(admin, s.deprecate_eof)) {
			ok(false, "scenario '%s': failed to apply runtime toggle", s.name);
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
		   "scenario '%s' (deprecate_eof=%d): greeting capabilities match expectation",
		   s.name, s.deprecate_eof ? 1 : 0);

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

	plan(2);

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
