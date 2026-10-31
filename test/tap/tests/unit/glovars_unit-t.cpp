/**
 * @file glovars_unit-t.cpp
 * @brief Unit tests for ProxySQL_GlobalVariables (GloVars) and related types.
 *
 * Covers:
 *   - Constructor default values for GloVars fields
 *   - ProxySQL_Checksum_Value construction, set_checksum, destructor
 *   - generate_global_checksum() determinism and range
 *   - Command-line parsing via parse() / process_opts_pre() / process_opts_post()
 *   - install_signal_handler()
 *
 * Note: Tests avoid directly modifying GloVars.checksums_values members
 * because the anonymous struct layout may differ between translation units
 * when conditional features (GenAI, FFTO, etc.) add extra fields to the
 * enclosing class. Local ProxySQL_Checksum_Value objects are used instead.
 *
 * @see lib/ProxySQL_GloVars.cpp
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "proxysql_utils.h"
#include "ezOptionParser.hpp"

#include <cstring>
#include <string>

static std::string rendered_usage(ez::ezOptionParser* options) {
	std::string usage;
	options->getUsage(usage);
	return usage;
}

static void test_option_registration_tier() {
	const std::string usage = rendered_usage(GloVars.opt);
#ifdef PROXYSQL40
	ok(usage.find("--bootstrap") == std::string::npos,
		"ProxySQL 4.0 core does not register legacy bootstrap options");
	ok(usage.find("--account-create") == std::string::npos,
		"ProxySQL 4.0 core does not register legacy account options");
#else
	ok(usage.find("--bootstrap") != std::string::npos,
		"ProxySQL 3.x retains legacy bootstrap options");
#endif
}

// ============================================================
// Constructor default values
// ============================================================

/**
 * @brief Verify that GloVars has expected default values after construction.
 */
static void test_constructor_defaults() {
	ok(GloVars.opt != nullptr,
		"Constructor: opt (ezOptionParser) is allocated");
	ok(GloVars.confFile != nullptr,
		"Constructor: confFile is allocated");

	ok(GloVars.epoch_version == 0,
		"Constructor: epoch_version is 0");

	ok(GloVars.global.sqlite3_server == false,
		"Constructor: global.sqlite3_server is false");
	ok(GloVars.global.data_packets_history_size == 0,
		"Constructor: global.data_packets_history_size is 0");
#ifndef PROXYSQL40
	ok(GloVars.global.gr_bootstrap_mode == 0,
		"Constructor: global.gr_bootstrap_mode is 0");
	ok(GloVars.global.gr_bootstrap_conf_base_port == 0,
		"Constructor: global.gr_bootstrap_conf_base_port is 0");
	ok(GloVars.global.gr_bootstrap_conf_use_sockets == false,
		"Constructor: global.gr_bootstrap_conf_use_sockets is false");
	ok(GloVars.global.gr_bootstrap_conf_skip_tcp == false,
		"Constructor: global.gr_bootstrap_conf_skip_tcp is false");
#endif /* !PROXYSQL40 */
	ok(GloVars.global.ssl_keylog_enabled == false,
		"Constructor: global.ssl_keylog_enabled is false");
	ok(GloVars.global.tls_load_count == 0,
		"Constructor: global.tls_load_count is 0");
	ok(GloVars.global.tls_last_load_timestamp == 0,
		"Constructor: global.tls_last_load_timestamp is 0");
	ok(GloVars.global.tls_last_load_ok == false,
		"Constructor: global.tls_last_load_ok is false");

	ok(GloVars.execute_on_exit_failure == nullptr,
		"Constructor: execute_on_exit_failure is nullptr");
	ok(GloVars.ldap_auth_plugin == nullptr,
		"Constructor: ldap_auth_plugin is nullptr");
	ok(GloVars.web_interface_plugin == nullptr,
		"Constructor: web_interface_plugin is nullptr");
	ok(GloVars.sqlite3_plugin == nullptr,
		"Constructor: sqlite3_plugin is nullptr");

	ok(GloVars.statuses.stack_memory_mysql_threads == 0,
		"Constructor: statuses.stack_memory_mysql_threads is 0");
	ok(GloVars.statuses.stack_memory_admin_threads == 0,
		"Constructor: statuses.stack_memory_admin_threads is 0");
	ok(GloVars.statuses.stack_memory_cluster_threads == 0,
		"Constructor: statuses.stack_memory_cluster_threads is 0");

	ok(GloVars.cluster_sync_interfaces == false,
		"Constructor: cluster_sync_interfaces is false");

	ok(GloVars.configfile_open == false,
		"Constructor: configfile_open is false");

	ok(GloVars.__cmd_proxysql_initial == false,
		"Constructor: __cmd_proxysql_initial is false");
	ok(GloVars.__cmd_proxysql_reload == false,
		"Constructor: __cmd_proxysql_reload is false");
}

// ============================================================
// ProxySQL_Checksum_Value
// ============================================================

static void test_checksum_value_defaults() {
	ProxySQL_Checksum_Value cv;

	ok(cv.version == 0, "Checksum_Value: default version is 0");
	ok(cv.epoch == 0, "Checksum_Value: default epoch is 0");
	ok(cv.in_shutdown == false, "Checksum_Value: default in_shutdown is false");
	ok(cv.checksum != nullptr, "Checksum_Value: checksum buffer is allocated");

	bool all_zero = true;
	for (int i = 0; i < ProxySQL_Checksum_Value_LENGTH; i++) {
		if (cv.checksum[i] != '\0') {
			all_zero = false;
			break;
		}
	}
	ok(all_zero, "Checksum_Value: checksum buffer is zero-filled on construction");
}

static void test_checksum_value_set() {
	ProxySQL_Checksum_Value cv;

	char input[] = "0x1234567890ABCDE1";
	cv.set_checksum(input);

	ok(cv.checksum[0] == '0', "set_checksum: first char preserved");
	ok(cv.checksum[1] == 'x', "set_checksum: second char preserved");
	ok(cv.checksum[2] == '1', "set_checksum: third char preserved");

	// Test with embedded NUL bytes at positions 2-17
	ProxySQL_Checksum_Value cv2;
	char input2[ProxySQL_Checksum_Value_LENGTH];
	memset(input2, 0, sizeof(input2));
	input2[0] = 'A';
	input2[1] = 'B';
	cv2.set_checksum(input2);

	ok(cv2.checksum[0] == 'A', "set_checksum(zeros): pos 0 preserved");
	ok(cv2.checksum[1] == 'B', "set_checksum(zeros): pos 1 preserved");
	bool zeros_replaced = true;
	for (int i = 2; i < 18; i++) {
		if (cv2.checksum[i] != '0') {
			zeros_replaced = false;
			break;
		}
	}
	ok(zeros_replaced, "set_checksum(zeros): positions 2-17 all replaced with '0'");

	// Test with spaces in checksum
	ProxySQL_Checksum_Value cv3;
	char input3[ProxySQL_Checksum_Value_LENGTH];
	memset(input3, ' ', sizeof(input3));
	input3[0] = 'X';
	input3[1] = 'Y';
	cv3.set_checksum(input3);
	ok(cv3.checksum[0] == 'X', "set_checksum(spaces): pos 0 preserved");
	ok(cv3.checksum[1] == 'Y', "set_checksum(spaces): pos 1 preserved");
	bool spaces_replaced = true;
	for (int i = 2; i < 18; i++) {
		if (cv3.checksum[i] != '0') {
			spaces_replaced = false;
			break;
		}
	}
	ok(spaces_replaced, "set_checksum(spaces): positions 2-17 all replaced with '0'");
}

static void test_checksum_value_short_input() {
	ProxySQL_Checksum_Value cv;
	struct {
		char input[5];
		char guard[15];
	} source;
	memcpy(source.input, "0x12", sizeof(source.input));
	memset(source.guard, 'X', sizeof(source.guard));

	cv.set_checksum(source.input);

	bool zero_padded = true;
	for (int i = 4; i < 18; i++) {
		if (cv.checksum[i] != '0') {
			zero_padded = false;
			break;
		}
	}
	ok(zero_padded,
		"set_checksum(short input): zero-pads without reading beyond the source string");
}

static void test_checksum_value_shutdown_flag() {
	// Normal destruction (in_shutdown == false): no crash
	{
		ProxySQL_Checksum_Value cv;
		cv.set_checksum((char *)"0xABCDEF123456789A");
	}
	ok(true, "Checksum_Value: normal destruction (in_shutdown=false) doesn't crash");

	// Destruction with in_shutdown == true: checksum is NOT freed (intentional leak)
	{
		ProxySQL_Checksum_Value cv;
		cv.in_shutdown = true;
		cv.set_checksum((char *)"0xABCDEF123456789A");
	}
	ok(true, "Checksum_Value: shutdown destruction (in_shutdown=true) doesn't crash");
}

// ============================================================
// ProxySQL_Checksum_Value version/epoch interaction
// ============================================================

static void test_checksum_value_version_interaction() {
	ProxySQL_Checksum_Value cv;
	cv.set_checksum((char *)"0xDEADBEEF1234567A");
	cv.version = 1;

	ok(cv.version == 1, "Checksum_Value: version can be set to 1");
	ok(cv.epoch == 0, "Checksum_Value: epoch stays 0 after set_checksum");
	ok(cv.checksum[0] == '0', "Checksum_Value: checksum data preserved after version set");

	cv.version = 42;
	ok(cv.version == 42, "Checksum_Value: version can be updated to 42");

	cv.epoch = 1234567890;
	ok(cv.epoch == 1234567890, "Checksum_Value: epoch can be set");

	// Setting version doesn't affect checksum content
	ProxySQL_Checksum_Value cv2;
	cv2.set_checksum((char *)"0xCAFEBABE1234567A");
	char saved = cv2.checksum[5];
	cv2.version = 999;
	ok(cv2.checksum[5] == saved,
		"Checksum_Value: setting version doesn't modify checksum content");
}

/**
 * @brief Test multiple set_checksum calls overwrite previous values.
 */
static void test_checksum_value_overwrite() {
	ProxySQL_Checksum_Value cv;

	cv.set_checksum((char *)"0xAAAAAAAAAAAAAAAA");
	ok(cv.checksum[2] == 'A', "set_checksum overwrite: first set stores 'A'");

	cv.set_checksum((char *)"0xBBBBBBBBBBBBBBBB");
	ok(cv.checksum[2] == 'B', "set_checksum overwrite: second set stores 'B'");

	cv.set_checksum((char *)"0xCCCCCCCCCCCCCCCC");
	ok(cv.checksum[2] == 'C', "set_checksum overwrite: third set stores 'C'");
}

// ============================================================
// generate_global_checksum()
// ============================================================

/**
 * @brief Test generate_global_checksum() with default (zero) versions.
 *
 * All versions are 0 from construction, so no checksum data is hashed.
 * The result should be deterministic and within LLONG_MAX range.
 */
static void test_generate_global_checksum() {
	uint64_t h1 = GloVars.generate_global_checksum();
	uint64_t h2 = GloVars.generate_global_checksum();

	ok(h1 == h2,
		"generate_global_checksum: deterministic when all versions are 0");

	// The code does h1 = h1/2 to keep result within LLONG_MAX
	ok(h1 <= (uint64_t)LLONG_MAX,
		"generate_global_checksum: result <= LLONG_MAX (divided by 2)");
}

// ============================================================
// Command-line parsing
// ============================================================

/**
 * @brief Test command-line parsing with multiple flags at once.
 */
static void test_parse_combined() {
	bool orig_initial = GloVars.__cmd_proxysql_initial;
	bool orig_reload = GloVars.__cmd_proxysql_reload;
	bool orig_version_check = GloVars.global.version_check;
	bool orig_sqlite3 = GloVars.global.sqlite3_server;
	char *orig_datadir = GloVars.__cmd_proxysql_datadir;
#ifndef PROXYSQL40
	char *orig_uri = GloVars.global.gr_bootstrap_uri;
	int orig_mode = GloVars.global.gr_bootstrap_mode;
	uint64_t orig_port = GloVars.global.gr_bootstrap_conf_base_port;
#endif /* !PROXYSQL40 */

	const char *argv[] = {
		"proxysql",
		"--initial",
		"--reload",
		"--no-version-check",
		"--sqlite3-server",
		"-D", "/tmp/unit_test_datadir",
#ifndef PROXYSQL40
		"--bootstrap", "mysql://user:pass@host:3306",
		"--conf-base-port", "6033",
#endif /* !PROXYSQL40 */
	};
	int argc = sizeof(argv) / sizeof(argv[0]);

	GloVars.parse(argc, argv);
	GloVars.process_opts_pre();

	ok(GloVars.__cmd_proxysql_initial == true,
		"parse: --initial sets __cmd_proxysql_initial");
	ok(GloVars.__cmd_proxysql_reload == true,
		"parse: --reload sets __cmd_proxysql_reload");
	ok(GloVars.global.version_check == false,
		"parse: --no-version-check disables version_check");
	ok(GloVars.global.sqlite3_server == true,
		"parse: --sqlite3-server enables sqlite3_server");
	ok(GloVars.__cmd_proxysql_datadir != nullptr,
		"parse: -D sets __cmd_proxysql_datadir");
	if (GloVars.__cmd_proxysql_datadir) {
		ok(strcmp(GloVars.__cmd_proxysql_datadir, "/tmp/unit_test_datadir") == 0,
			"parse: -D value is correct");
	} else {
		ok(false, "parse: -D value is correct (was null)");
	}
#ifndef PROXYSQL40
	ok(GloVars.global.gr_bootstrap_mode == 1,
		"parse: --bootstrap sets gr_bootstrap_mode to 1");
	ok(GloVars.global.gr_bootstrap_uri != nullptr,
		"parse: --bootstrap sets gr_bootstrap_uri");
	if (GloVars.global.gr_bootstrap_uri) {
		ok(strcmp(GloVars.global.gr_bootstrap_uri, "mysql://user:pass@host:3306") == 0,
			"parse: --bootstrap URI value is correct");
	} else {
		ok(false, "parse: --bootstrap URI value is correct (was null)");
	}
	ok(GloVars.global.gr_bootstrap_conf_base_port == 6033,
		"parse: --conf-base-port sets gr_bootstrap_conf_base_port");
#endif /* !PROXYSQL40 */

	// Restore
	GloVars.__cmd_proxysql_initial = orig_initial;
	GloVars.__cmd_proxysql_reload = orig_reload;
	GloVars.global.version_check = orig_version_check;
	GloVars.global.sqlite3_server = orig_sqlite3;
	if (GloVars.__cmd_proxysql_datadir != orig_datadir) {
		free(GloVars.__cmd_proxysql_datadir);
		GloVars.__cmd_proxysql_datadir = orig_datadir;
	}
#ifndef PROXYSQL40
	if (GloVars.global.gr_bootstrap_uri != orig_uri) {
		free(GloVars.global.gr_bootstrap_uri);
		GloVars.global.gr_bootstrap_uri = orig_uri;
	}
	GloVars.global.gr_bootstrap_mode = orig_mode;
	GloVars.global.gr_bootstrap_conf_base_port = orig_port;
#endif /* !PROXYSQL40 */
}

/**
 * @brief Test process_opts_post() for -n, -f, -M flags.
 */
static void test_parse_post_opts() {
	bool orig_nostart = GloVars.global.nostart;
	int orig_cmd_nostart = GloVars.__cmd_proxysql_nostart;
	bool orig_foreground = GloVars.global.foreground;
	bool orig_my_monitor = GloVars.global.my_monitor;
	bool orig_pg_monitor = GloVars.global.pg_monitor;

	const char *argv[] = { "proxysql", "-n", "-f", "-M" };
	int argc = sizeof(argv) / sizeof(argv[0]);

	GloVars.parse(argc, argv);
	GloVars.process_opts_post();

	ok(GloVars.global.nostart == true,
		"parse post: -n sets global.nostart");
	ok(GloVars.__cmd_proxysql_nostart == 1,
		"parse post: -n sets __cmd_proxysql_nostart to 1");
	ok(GloVars.global.foreground == true,
		"parse post: -f sets global.foreground");
	ok(GloVars.global.my_monitor == false,
		"parse post: -M disables my_monitor");
	ok(GloVars.global.pg_monitor == false,
		"parse post: -M disables pg_monitor");

	// Restore
	GloVars.global.nostart = orig_nostart;
	GloVars.__cmd_proxysql_nostart = orig_cmd_nostart;
	GloVars.global.foreground = orig_foreground;
	GloVars.global.my_monitor = orig_my_monitor;
	GloVars.global.pg_monitor = orig_pg_monitor;
}

// ============================================================
// Miscellaneous
// ============================================================

static void test_install_signal_handler() {
	GloVars.install_signal_handler();
	ok(true, "install_signal_handler: does not crash");
}

static void test_checksum_value_length() {
	ok(ProxySQL_Checksum_Value_LENGTH == 20,
		"ProxySQL_Checksum_Value_LENGTH is 20");
}

static void test_prometheus_registry() {
	ok(GloVars.prometheus_registry != nullptr,
		"Constructor: prometheus_registry is initialized");
}

static void test_set_thread_name_default() {
	ok(GloVars.set_thread_name == true,
		"Constructor: set_thread_name defaults to true");
}

/**
 * @brief Test replace_checksum_zeros utility directly.
 */
static void test_replace_checksum_zeros() {
	char buf[ProxySQL_Checksum_Value_LENGTH];

	// All zeros
	memset(buf, 0, sizeof(buf));
	replace_checksum_zeros(buf);
	ok(buf[0] == '\0', "replace_checksum_zeros: pos 0 not touched (null)");
	ok(buf[1] == '\0', "replace_checksum_zeros: pos 1 not touched (null)");
	bool inner_ok = true;
	for (int i = 2; i < 18; i++) {
		if (buf[i] != '0') { inner_ok = false; break; }
	}
	ok(inner_ok, "replace_checksum_zeros: positions 2-17 replaced with '0'");
	ok(buf[18] == '\0', "replace_checksum_zeros: pos 18 not touched");
	ok(buf[19] == '\0', "replace_checksum_zeros: pos 19 not touched");

	// Mix of spaces and valid chars
	memset(buf, 0, sizeof(buf));
	buf[0] = 'H';
	buf[1] = 'I';
	buf[2] = ' ';
	buf[3] = 'Z';
	buf[17] = ' ';
	replace_checksum_zeros(buf);
	ok(buf[2] == '0', "replace_checksum_zeros: space at pos 2 replaced");
	ok(buf[3] == 'Z', "replace_checksum_zeros: non-zero non-space preserved");
	ok(buf[17] == '0', "replace_checksum_zeros: space at pos 17 replaced");
}

int main() {
#ifdef PROXYSQL40
	plan(73);
#else
	plan(80);
#endif

	test_init_minimal();
	test_option_registration_tier();

	// Constructor defaults (24 tests)
	test_constructor_defaults();

	// Checksum value (16 tests)
	test_checksum_value_defaults();        // 5
	test_checksum_value_set();             // 9
	test_checksum_value_short_input();    // 1
	test_checksum_value_shutdown_flag();   // 2

	// Checksum value version/epoch (6 tests)
	test_checksum_value_version_interaction();

	// Checksum value overwrite (3 tests)
	test_checksum_value_overwrite();

	// Global checksum generation (2 tests)
	test_generate_global_checksum();

	// Miscellaneous (12 tests)
	test_checksum_value_length();           // 1
	test_prometheus_registry();             // 1
	test_set_thread_name_default();         // 1
	test_install_signal_handler();          // 1
	test_replace_checksum_zeros();          // 8

	// Command-line parsing (15 tests)
	test_parse_combined();                  // 10
	test_parse_post_opts();                 // 5

	test_cleanup_minimal();
	return exit_status();
}
