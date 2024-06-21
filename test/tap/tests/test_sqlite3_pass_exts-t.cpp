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
		const std::string time { get_formatted_time() }; \
		fprintf(stderr, "# %s: Issuing query `%s` to ('%s':%d)\n", time.c_str(), query, mysql->host, mysql->port); \
		if (mysql_query(mysql, query)) { \
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

	plan(
		INV_INPUTS.size() +
		USER_GEN_COUNT +
		PASS_GEN_COUNT * 2 +
		2 + // EXTRA: Two extra correctness tests; forcing randomness
		RAND_USERS_GEN +
		1 // EXTRA: Conn count after 'RAND_USERS_GEN'; consistency check
	);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	TAP_MYSQL8_BACKEND_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

	MYSQL* mysql = mysql_init(NULL);

	if (!mysql_real_connect(mysql, cl.host, cl.mysql_username, cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return EXIT_FAILURE;
	}


	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
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

	// Tests MySQL/Admin hashes compatibility
	{
		vector<user_def_t> users {};

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

	// Tests end-to-end connection with MySQL using same gen passwords
	{
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

		for (uint32_t i = 0; i < RAND_USERS_GEN; i++) {
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

		const string SEL_POOL_CONNS {
			"SELECT SUM(ConnUsed + ConnFree) FROM stats.stats_mysql_connection_pool"
				" WHERE hostgroup=" + TAP_MYSQL8_BACKEND_HG_S
		};
		const string COND_CONN_CREATION {
			"SELECT IIF((" + SEL_POOL_CONNS + ")=" + RAND_USERS_GEN_S + ", 'TRUE', 'FALSE')"
		};
		wait_for_cond(admin, COND_CONN_CREATION, 10);

		ext_val_t<uint64_t> cur_conns { mysql_query_ext_val(admin, SEL_POOL_CONNS, uint64_t(0)) };

		if (cur_conns.err) {
			const string err { get_ext_val_err(admin, cur_conns) };
			diag("Fetching conn count from pool failed   err:'%s'", err.c_str());
		}

		ok(
			RAND_USERS_GEN == cur_conns.val,
			"Number of backend conns created should match conn attempts   exp:'%u', act:'%lu'",
			RAND_USERS_GEN, cur_conns.val
		);
	}

cleanup:

	mysql_close(mysql);
	mysql_close(admin);

	return exit_status();
}
