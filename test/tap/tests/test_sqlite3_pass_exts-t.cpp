/**
 * @file test_sqlite3_pass_exts-t.cpp
 * @brief Tests the SQLite3 extensions in the Admin interface and it's MySQL compatibility.
 * @details The test perform the following operations:
 *   1. Create MySQL users with random pass and check pass reproduction for:
 *       - 'mysql_native_password'
 *       - 'caching_sha2_password'
 *   2. Stress password creation, ensure that start and length matches expected.
 *   3. End-to-end password generation testing:
 *       1. Create passwords in both MySQL and ProxySQL using buit-in Admin function for hash generation.
 *       2. Connect to ProxySQL and force a new backend connection using these passwords.
 */

#include <cassert>
#include <ctime>
#include <string>
#include <vector>
#include <utility>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

// Additional env variables
uint32_t TAP_MYSQL8_BACKEND_HG = 30;

using std::string;
using std::vector;
using std::pair;

// Global flag for MySQL version check
static bool g_mysql_supports_random_password = false;
static bool g_mysql_version_checked = false;
// MySQL 9.0 removed the 'mysql_native_password' server plugin. CREATE USER
// IDENTIFIED WITH 'mysql_native_password' returns ER_PLUGIN_IS_NOT_LOADED on
// 9.x backends. This flag gates the backend-side native_password fixtures
// (Phase 2 hash compat + Phase 3 end-to-end). ProxySQL's internal
// MYSQL_NATIVE_PASSWORD() SQLite3 extension is unaffected — hash generation
// is pure computation and still works.
static bool g_mysql_supports_native_password = true;

/**
 * @brief Check if MySQL server supports 'BY RANDOM PASSWORD' syntax (MySQL 8.0+)
 * @param mysql MySQL connection handle
 * @return true if MySQL 8.0+, false otherwise
 */
bool check_mysql_random_password_support(MYSQL* mysql) {
	if (g_mysql_version_checked) {
		return g_mysql_supports_random_password;
	}

	g_mysql_version_checked = true;

	// Query MySQL version
	if (mysql_query(mysql, "SELECT @@version") != 0) {
		diag("Failed to query MySQL version: %s", mysql_error(mysql));
		return false;
	}

	MYSQL_RES* res = mysql_store_result(mysql);
	if (!res) {
		diag("Failed to store MySQL version result");
		return false;
	}

	MYSQL_ROW row = mysql_fetch_row(res);
	if (!row || !row[0]) {
		mysql_free_result(res);
		diag("Failed to fetch MySQL version row");
		return false;
	}

	string version(row[0]);
	mysql_free_result(res);

	// Check if version starts with 8.or higher
	diag("MySQL server version: %s", version.c_str());

	// MariaDB check
	if (version.find("MariaDB") != string::npos) {
		g_mysql_supports_random_password = false;
		diag("MySQL server supports 'BY RANDOM PASSWORD': no (MariaDB detected)");
		return false;
	}

	// Parse semantic version
	int major = 0, minor = 0, patch = 0;
	sscanf(version.c_str(), "%d.%d.%d", &major, &minor, &patch);

	// MySQL 8.0.18+ required
	if (major > 8 || (major == 8 && minor > 0) || (major == 8 && minor == 0 && patch >= 18)) {
		g_mysql_supports_random_password = true;
	} else {
		g_mysql_supports_random_password = false;
	}

	diag("MySQL server supports 'BY RANDOM PASSWORD': %s", g_mysql_supports_random_password ? "yes" : "no");

	return g_mysql_supports_random_password;
}

struct user_def_t {
	string name;
	string auth;
	string pass;
	string hash;
	string salt;
};

struct user_creds_t {
	string name;
	string auth;
	string pass;
};

#define MYSQL_QUERY_T_(mysql, query) \
	do { \
		if (mysql_query_t(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql)); \
			return { EXIT_FAILURE, user_def_t {} }; \
		} \
	} while(0)

int create_mysql_user(MYSQL* mysql, const user_creds_t& creds) {
	const string CREATE_USER {
		"CREATE USER '" + creds.name + "'@'%' IDENTIFIED WITH"
			" '" + creds.auth + "' BY '" + creds.pass + "'"
	};
	const string GRANT_USER_PRIVS { "GRANT ALL on *.* to '" + creds.name + "'@'%'" };
	const string DROP_USER { "DROP USER IF EXISTS '" + creds.name + "'"};

	MYSQL_QUERY_T(mysql, DROP_USER.c_str());
	MYSQL_QUERY_T(mysql, CREATE_USER.c_str());
	MYSQL_QUERY_T(mysql, GRANT_USER_PRIVS.c_str());

	return EXIT_SUCCESS;
}

int config_proxysql_user(MYSQL* admin, const user_creds_t& creds) {
	const string DEF_HG { std::to_string(TAP_MYSQL8_BACKEND_HG) };

	MYSQL_QUERY_T(admin, ("DELETE FROM mysql_users WHERE username='" + creds.name + "'").c_str());

	// Ensure cleanup of previously cached clear_text 'caching_sha2' passwords
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	const string insert_query {
		"INSERT INTO mysql_users (username,password,default_hostgroup) "
			"VALUES ('" + creds.name + "'," + creds.auth + "('" + creds.pass + "')," + DEF_HG + ")"
	};

	MYSQL_QUERY_T(admin, insert_query.c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	return EXIT_SUCCESS;
}

pair<int,user_def_t> create_mysql_user_rnd_creds(MYSQL* mysql, const string& name, const string& auth) {
	diag("Creating user with random pass   user:'%s'", name.c_str());

	// Check MySQL version for 'BY RANDOM PASSWORD' support
	if (!check_mysql_random_password_support(mysql)) {
		diag("Skipping user creation: 'BY RANDOM PASSWORD' requires MySQL 8.0+");
		diag("Current MySQL server does not support this feature");
		return { EXIT_FAILURE, user_def_t {} };
	}

	const string CREATE_USER {
		"CREATE USER '" + name + "'@'%' IDENTIFIED WITH '" + auth + "' BY RANDOM PASSWORD"
	};
	const string EXT_NATIVE_AUTH {
		"SELECT authentication_string FROM mysql.user WHERE user='" + name + "'"
	};
	const string EXT_SHA2_AUTH {
		"SELECT HEX(authentication_string), HEX(SUBSTR(authentication_string, 8, 20)) AS salt"
			" FROM mysql.user WHERE user='" + name + "'"
	};
	const string DROP_USER { "DROP USER IF EXISTS '" + name + "'"};
	string pass {};
	string hash {};
	string salt {};

	// DROP/CREATE and extract new password
	{
		MYSQL_QUERY_T_(mysql, DROP_USER.c_str());
		MYSQL_QUERY_T_(mysql, CREATE_USER.c_str());

		MYSQL_RES* myres = mysql_store_result(mysql);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[2]) {
			pass = string { myrow[2] };
		}

		mysql_free_result(myres);
	}

	// Extract 'authentication_string' and 'salt'
	if (auth == "mysql_native_password") {
		MYSQL_QUERY_T_(mysql, EXT_NATIVE_AUTH.c_str());
		MYSQL_RES* myres = mysql_store_result(mysql);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[0]) {
			hash = string { myrow[0] };
		} else {
			assert(!"Received malformed result");
		}

		mysql_free_result(myres);
	} else if (auth == "caching_sha2_password") {
		MYSQL_QUERY_T_(mysql, EXT_SHA2_AUTH.c_str());

		MYSQL_RES* myres = mysql_store_result(mysql);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[0] && myrow[1]) {
			hash = string { myrow[0] };
			salt = string { myrow[1] };
		} else {
			assert(!"Received malformed result");
		}

		mysql_free_result(myres);
	} else {
		assert(!"Invalid auth method");
	}

	diag(
		"Created user   user:'%s', pass:'%s', hash: '%s', salt:'%s'",
		name.c_str(), pass.c_str(), hash.c_str(), salt.c_str()
	);

	return { EXIT_SUCCESS, user_def_t { name, auth, pass, hash, salt } };
}

int test_pass_match(MYSQL* admin, const user_def_t& def) {
	diag(
		"Test MySQL/Admin pass match    user:'%s', auth:'%s', pass:'%s', hash: '%s', salt:'%s'",
		def.name.c_str(), def.auth.c_str(), def.pass.c_str(), def.hash.c_str(), def.salt.c_str()
	);

	if (def.auth == "mysql_native_password") {
		const string GEN_NATIVE_PASS {
			"SELECT MYSQL_NATIVE_PASSWORD('" + def.pass + "')"
		};
		MYSQL_QUERY_T(admin, GEN_NATIVE_PASS.c_str());

		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		string admin_hash { myrow[0] };

		ok(
			def.hash == admin_hash,
			"MySQL hash should match ProxySQL generated   mysql:'%s', admin:'%s'",
			def.hash.c_str(), admin_hash.c_str()
		);

		mysql_free_result(myres);
	} else if (def.auth == "caching_sha2_password") {
		const string GEN_SHA2_PASS {
			"SELECT HEX(CACHING_SHA2_PASSWORD('" + def.pass + "', UNHEX('" + def.salt + "')))"
		};
		MYSQL_QUERY_T(admin, GEN_SHA2_PASS.c_str());

		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		string admin_hash { myrow[0] };

		ok(
			def.hash == admin_hash,
			"MySQL hash should match ProxySQL generated   mysql:'%s', admin:'%s'",
			def.hash.c_str(), admin_hash.c_str()
		);

		mysql_free_result(myres);
	}

	return EXIT_SUCCESS;
}

int test_pass_gen(MYSQL* admin, const string& auth, const string& pass, const string& salt) {
	diag("Test Admin pass hash gen    auth:'%s',pass:'%s'", auth.c_str(), pass.c_str());

	if (auth == "mysql_native_password") {
		const string GEN_NATIVE_PASS { "SELECT MYSQL_NATIVE_PASSWORD('" + pass + "')" };
		MYSQL_QUERY_T(admin, GEN_NATIVE_PASS.c_str());

		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (pass.size() > 0) {
			const string admin_hash { myrow[0] };
			bool valid_hash = admin_hash.size() == 41 && admin_hash[0] == '*';

			ok(
				valid_hash,
				"Gen hash should be wellformed   size:'%lu', hash:'%s'",
				admin_hash.size(), admin_hash.c_str()
			);
		} else {
			const string act_msg { myrow[0] };
			const string exp_msg { "Invalid argument size" };

			ok(
				exp_msg == act_msg,
				"Args verf should have failed   exp_msg:'%s', act_msg:'%s'",
				exp_msg.c_str(), act_msg.c_str()
			);
		}

		mysql_free_result(myres);
	} else if (auth == "caching_sha2_password") {
		const string GEN_SHA2_PASS { "SELECT CACHING_SHA2_PASSWORD('" + pass + "', '" + salt + "')" };
		MYSQL_QUERY_T(admin, GEN_SHA2_PASS.c_str());

		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (pass.size() > 0 && salt.size() > 0 && salt.size() <= 20) {
			const string admin_hash { myrow[0] };
			const string hash_start { "$A$005$" + salt };

			bool valid_hash =
				(admin_hash.size() == 50 + salt.size()) &&
				admin_hash.rfind(hash_start, 0) == 0;

			ok(
				valid_hash,
				"Gen hash should be wellformed   size:'%lu', salt_size:'%lu', hash:'%s'",
				admin_hash.size(), salt.size(), admin_hash.c_str()
			);
		} else {
			const string act_msg { myrow[0] };
			const string exp_msg { "Invalid argument size" };

			ok(
				exp_msg == act_msg,
				"Args verf should have failed   exp_msg:'%s', act_msg:'%s'",
				exp_msg.c_str(), act_msg.c_str()
			);
		}

		mysql_free_result(myres);
	}

	return EXIT_SUCCESS;
}

pair<int,string> get_query_res(MYSQL* mysql, const string& query) {
	string res {};

	int rc = mysql_query_t(mysql, query.c_str());

	if (rc) {
		return { rc, mysql_error(mysql) };
	} else {
		MYSQL_RES* myres = mysql_store_result(mysql);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[0]) {
			res = myrow[0];
		} else {
			rc = 1;
			res = "Invalid resultset received";
		}

		mysql_free_result(myres);
	}

	return { rc, res };
}

struct inv_input_t {
	string query;
	int err;
	string msg;
};

// NOTE: If modified, set even numbers
const uint32_t USER_GEN_COUNT = 100;
const uint32_t PASS_GEN_COUNT = 1000;
const uint32_t RAND_USERS_GEN = 100;

const vector<inv_input_t> INV_INPUTS {
	{
		"SELECT MYSQL_NATIVE_PASSWORD()", 1,
		"ProxySQL Admin Error: wrong number of arguments to function MYSQL_NATIVE_PASSWORD()"
	},
	{
		"SELECT MYSQL_NATIVE_PASSWORD('00', '00')", 1,
		"ProxySQL Admin Error: wrong number of arguments to function MYSQL_NATIVE_PASSWORD()"
	},
	{ "SELECT MYSQL_NATIVE_PASSWORD('')", 0, "Invalid argument size" },
	{ "SELECT MYSQL_NATIVE_PASSWORD(2)", 0, "Invalid argument type" },

	{
		"SELECT CACHING_SHA2_PASSWORD()", 1,
		"ProxySQL Admin Error: wrong number of arguments to function CACHING_SHA2_PASSWORD()"
	},
	{
		"SELECT CACHING_SHA2_PASSWORD('00', '00', '00')", 1,
		"ProxySQL Admin Error: wrong number of arguments to function CACHING_SHA2_PASSWORD()"
	},
	{ "SELECT CACHING_SHA2_PASSWORD('', '')", 0, "Invalid argument size" },
	{ "SELECT CACHING_SHA2_PASSWORD('', '000000000000000000000')", 0, "Invalid argument size" },
	{ "SELECT CACHING_SHA2_PASSWORD(2, '00')", 0, "Invalid argument type" },
	{ "SELECT CACHING_SHA2_PASSWORD('00', 2)", 0, "Invalid argument type" },
};


int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	TAP_MYSQL8_BACKEND_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

	// Verbose test header
	diag("================================================================================");
	diag("Test: test_sqlite3_pass_exts-t");
	diag("================================================================================");
	diag("This test verifies SQLite3 password extension functions in the ProxySQL Admin");
	diag("interface, testing compatibility with MySQL authentication methods.");
	diag("%s", "");
	diag("Test scenarios:");
	diag("  - MYSQL_NATIVE_PASSWORD: MySQL 4.1+ native password hashing");
	diag("  - CACHING_SHA2_PASSWORD: MySQL 8.0+ caching SHA2 password hashing");
	diag("  - Random password generation and hash verification");
	diag("  - End-to-end connection testing with generated passwords");
	diag("%s", "");
	diag("Connection parameters:");
	diag("  - MySQL Host: %s", cl.mysql_host);
	diag("  - MySQL Port: %d", cl.mysql_port);
	diag("  - MySQL User: %s", cl.mysql_username);
	diag("  - Admin Host: %s", cl.admin_host);
	diag("  - Admin Port: %d", cl.admin_port);
	diag("================================================================================");
	diag("%s", "");

	MYSQL* mysql = mysql_init(NULL);

	diag("Attempting to connect to MySQL backend at %s:%d", cl.mysql_host, cl.mysql_port);
	if (!mysql_real_connect(mysql, cl.mysql_host, cl.mysql_username, cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
		diag("Failed to connect to MySQL backend: Error: %s", mysql_error(mysql));
		diag("Connection details: host=%s, port=%d, username=%s", cl.mysql_host, cl.mysql_port, cl.mysql_username);
		return EXIT_FAILURE;
	}
	diag("Successfully connected to MySQL backend");
	diag("%s", "");

	// Check MySQL version before calling plan() so we can set the correct test count
	// MySQL 8.0+ supports 'BY RANDOM PASSWORD' syntax, MySQL 5.7 does not
	check_mysql_random_password_support(mysql);

	// Detect whether the 'mysql_native_password' server plugin is usable.
	// MySQL 9.0 removed it; we skip the native_password halves of Phase 2
	// (MySQL/Admin hash compat) and Phase 3 (end-to-end) on 9.x backends.
	unsigned long server_version = mysql_get_server_version(mysql);
	if (server_version >= 90000) {
		g_mysql_supports_native_password = false;
		diag("Backend MySQL %lu: 'mysql_native_password' plugin not loadable. "
			"Skipping native_password backend-side fixtures.", server_version);
	}

	// Calculate the actual number of tests based on MySQL version
	uint32_t actual_test_count =
		INV_INPUTS.size() +           // Always run
		PASS_GEN_COUNT * 2 +           // Always run (ProxySQL Admin SQLite3 extensions)
		2;                             // EXTRA: Two extra correctness tests

	if (g_mysql_supports_random_password) {
		// Phase 2: MySQL/Admin hash compatibility tests (USER_GEN_COUNT total,
		// half native + half sha2). On 9.x only the sha2 half runs.
		actual_test_count +=
			(g_mysql_supports_native_password ? USER_GEN_COUNT : USER_GEN_COUNT / 2);

		// Phase 3: End-to-end connection tests (RAND_USERS_GEN total, same split).
		actual_test_count +=
			(g_mysql_supports_native_password ? RAND_USERS_GEN : RAND_USERS_GEN / 2);

		actual_test_count += 1;                   // Connection count check
	}

	diag("MySQL version supports 'BY RANDOM PASSWORD': %s", g_mysql_supports_random_password ? "yes" : "no");
	diag("MySQL server supports 'mysql_native_password' plugin: %s", g_mysql_supports_native_password ? "yes" : "no");
	diag("Planned test count: %u", actual_test_count);

	plan(actual_test_count);


	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Tests functions input verification
	{
		for (const inv_input_t& inv_input : INV_INPUTS) {
			const pair<int,string> res { get_query_res(admin, inv_input.query) };

			if (res.first && inv_input.err == 0) {
				diag("Query on Admin unexpectedly failed   rc:'%d', err:'%s'", res.first, res.second.c_str());
				goto cleanup;
			} else {
				ok(
					inv_input.msg == res.second,
					"Expected failure should match actual   exp:'%s', act:'%s'",
					inv_input.msg.c_str(), res.second.c_str()
				);
			}
		}
	}

	// Tests MySQL/Admin hashes compatibility (requires MySQL 8.0+)
	if (g_mysql_supports_random_password) {
		vector<user_def_t> users {};

		if (g_mysql_supports_native_password) {
			for (size_t i = 0; i < USER_GEN_COUNT/2; i++) {
				const string name { "rndextuser" + std::to_string(i) };
				pair<int,user_def_t> user_def {
					create_mysql_user_rnd_creds(mysql, name, "mysql_native_password")
				};

				if (user_def.first) {
					diag("User creation failed   user:'%s'", name.c_str());
					goto cleanup;
				} else {
					users.push_back(user_def.second);
				}
			}
		}

		for (size_t i = 50; i < USER_GEN_COUNT; i++) {
			const string name { "rndextuser" + std::to_string(i) };
			pair<int,user_def_t> user_def {
				create_mysql_user_rnd_creds(mysql, name, "caching_sha2_password")
			};

			if (user_def.first) {
				diag("User creation failed   user:'%s'", name.c_str());
				goto cleanup;
			} else {
				users.push_back(user_def.second);
			}
		}

		for (const user_def_t& def : users) {
			test_pass_match(admin, def);
		}
	} else {
		diag("Skipping MySQL/Admin hashes compatibility tests: requires MySQL 8.0+");
		diag("Current MySQL server does not support 'BY RANDOM PASSWORD' syntax");
		// Note: These tests are not included in the plan for MySQL 5.7, so no skip() needed
	}

	// Tests correctness of randomly generated hashes
	{
		std::srand(static_cast<unsigned int>(std::time(nullptr)));

		// EXTRA: Two extra correctness tests; forcing randomness
		test_pass_gen(admin, "mysql_native_password", "randpass0", "");
		test_pass_gen(admin, "caching_sha2_password", "randpass0", "00000000000000000000");

		for (size_t i = 0; i < PASS_GEN_COUNT; i++) {
			const uint32_t pass_len = rand() % 150;
			const string pass { random_string(pass_len) };

			test_pass_gen(admin, "mysql_native_password", pass, "");
		}

		for (size_t i = 0; i < PASS_GEN_COUNT; i++) {
			const uint32_t pass_len = rand() % 150;
			const uint32_t salt_len = rand() % 20;
			const string pass { random_string(pass_len) };
			const string salt { random_string(pass_len) };

			test_pass_gen(admin, "caching_sha2_password", pass, salt);
		}
	}

	// Tests end-to-end connection with MySQL using same gen passwords (requires MySQL 8.0+ for caching_sha2_password)
	if (g_mysql_supports_random_password) {
		const string TAP_MYSQL8_BACKEND_HG_S { std::to_string(TAP_MYSQL8_BACKEND_HG) };
		const string RAND_USERS_GEN_S { std::to_string(RAND_USERS_GEN) };

		diag("Cleaning up previous backend connections...");
		MYSQL_QUERY(admin,
			("UPDATE mysql_servers SET max_connections=0 "
				"WHERE hostgroup_id=" + TAP_MYSQL8_BACKEND_HG_S).c_str()
		);
		MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

		const string COND_CONN_CLEANUP {
			"SELECT IIF((SELECT SUM(ConnUsed + ConnFree) FROM stats.stats_mysql_connection_pool"
				" WHERE hostgroup=" + TAP_MYSQL8_BACKEND_HG_S + ")=0, 'TRUE', 'FALSE')"
		};
		int w_res = wait_for_cond(admin, COND_CONN_CLEANUP, 10);
		if (w_res) {
			diag("Waiting for backend connections failed   res:'%d'", w_res);
			goto cleanup;
		}

		// Just in case a low connection limit is set by default
		diag("Setup new connection limit   max_connections='2000'");
		MYSQL_QUERY(admin,
			("UPDATE mysql_servers SET max_connections=2000 "
				"WHERE hostgroup_id=" + TAP_MYSQL8_BACKEND_HG_S).c_str()
		);
		MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

		// On MySQL 9.x the native_password plugin is unavailable on the backend,
		// so skip the first RAND_USERS_GEN/2 iterations (those are the native ones).
		uint32_t rand_users_start = g_mysql_supports_native_password ? 0 : (RAND_USERS_GEN / 2);
		for (uint32_t i = rand_users_start; i < RAND_USERS_GEN; i++) {
			const string name { "username_" + std::to_string(i) };
			const string pass { random_string(20) };
			const string auth { i < 50 ? "MYSQL_NATIVE_PASSWORD" : "CACHING_SHA2_PASSWORD" };
			const user_creds_t user_creds { name, auth, pass };

			// TODO: Current 'auth_switch' limitation. Set 'caching_sha2_password' as default-auth method.
			if (i < 50) {
				MYSQL_QUERY(admin, "SET mysql-default_authentication_plugin='mysql_native_password'");
				MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
			} else {
				MYSQL_QUERY(admin, "SET mysql-default_authentication_plugin='caching_sha2_password'");
				MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
			}

			diag(
				"Testing Client-to-MySQL with SQLite3 created hashes   user:'%s', pass:'%s', auth:'%s'",
				name.c_str(), pass.c_str(), auth.c_str()
			);

			if (create_mysql_user(mysql, user_creds)) {
				diag("Failed to create MySQL user. Aborting further testing");
				goto cleanup;
			}

			if (config_proxysql_user(admin, user_creds)) {
				diag("Failed to create ProxySQL user. Aborting further testing");
				goto cleanup;
			}

			diag(
				"Creating connection to ProxySQL   user:'%s', pass:'%s', auth:'%s'",
				name.c_str(), pass.c_str(), auth.c_str()
			);

			MYSQL* proxy = mysql_init(NULL);
			mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);

			if (
				!mysql_real_connect(
					proxy, cl.host, name.c_str(), pass.c_str(), NULL, cl.port, NULL, CLIENT_SSL
				)
			) {
				diag("Failed to connect to ProxySQL   error:'%s'", mysql_error(proxy));
				goto cleanup;
			}

			int rc = mysql_query(proxy, "/* create_new_connection=1 */ DO 1");
			ok(rc == 0, "End-to-end connection should succeed   rc:'%d', err:'%s'", rc, mysql_error(proxy));

			mysql_close(proxy);
		}

		// Only the iterations we actually ran produce backend connections.
		// When the native_password half is skipped (MySQL 9.x), expected
		// count is halved.
		const uint32_t expected_conns =
			g_mysql_supports_native_password ? RAND_USERS_GEN : (RAND_USERS_GEN / 2);
		const string EXPECTED_CONNS_S { std::to_string(expected_conns) };

		const string SEL_POOL_CONNS {
			"SELECT SUM(ConnUsed + ConnFree) FROM stats.stats_mysql_connection_pool"
				" WHERE hostgroup=" + TAP_MYSQL8_BACKEND_HG_S
		};
		const string COND_CONN_CREATION {
			"SELECT IIF((" + SEL_POOL_CONNS + ")=" + EXPECTED_CONNS_S + ", 'TRUE', 'FALSE')"
		};
		wait_for_cond(admin, COND_CONN_CREATION, 10);

		ext_val_t<uint64_t> cur_conns { mysql_query_ext_val(admin, SEL_POOL_CONNS, uint64_t(0)) };

		if (cur_conns.err) {
			const string err { get_ext_val_err(admin, cur_conns) };
			diag("Fetching conn count from pool failed   err:'%s'", err.c_str());
		}

		ok(
			expected_conns == cur_conns.val,
			"Number of backend conns created should match conn attempts   exp:'%u', act:'%lu'",
			expected_conns, cur_conns.val
		);
	}

cleanup:

	mysql_close(mysql);
	mysql_close(admin);

	return exit_status();
}
