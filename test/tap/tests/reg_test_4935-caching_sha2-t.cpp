/**
 * @file reg_test_4935-caching_sha2-t
 * @brief Regression tests checking that info send during handshake like:
 * 	 - character_set
 * 	 - default_schema
 * 	 - ...
 * 	Is preserved after authentication has taken place.
 */

#include <cstring>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"

#include "utils.h"
#include "utils_auth.h"

using std::string;
using std::vector;

#define TAP_NAME "TAP_REG_TEST_4935_CACHING_SHA2___"

uint32_t MYSQL8_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

const vector<user_def_t> backend_users {
	{ "dualpass1", MF_CHAR_("newpass1"), MF_CHAR_(nullptr),    "mysql_native_password", MYSQL8_HG, TAP_NAME"schema1" },
	{ "dualpass2", MF_CHAR_("newpass2"), MF_CHAR_("oldpass2"), "mysql_native_password", MYSQL8_HG, TAP_NAME"schema2" },

	{ "dualpass3", MF_CHAR_("newpass3"), MF_CHAR_(nullptr),    "caching_sha2_password", MYSQL8_HG, TAP_NAME"schema1" },
	{ "dualpass4", MF_CHAR_("newpass4"), MF_CHAR_("oldpass4"), "caching_sha2_password", MYSQL8_HG, TAP_NAME"schema2" },
};

const vector<test_creds_t> tests_creds {
	{ "dualpass1", MF_CHAR_("newpass1"), { PASS_TYPE::PRIMARY, "mysql_native_password" } },
	{ "dualpass2", MF_CHAR_("newpass2"), { PASS_TYPE::PRIMARY, "mysql_native_password" } },
	{ "dualpass2", MF_CHAR_("oldpass2"), { PASS_TYPE::ADDITIONAL, "mysql_native_password" } },

	{ "dualpass3", MF_CHAR_("newpass3"), { PASS_TYPE::PRIMARY, "caching_sha2_password" } },
	{ "dualpass4", MF_CHAR_("newpass4"), { PASS_TYPE::PRIMARY, "caching_sha2_password" } },
	{ "dualpass4", MF_CHAR_("oldpass4"), { PASS_TYPE::ADDITIONAL, "caching_sha2_password"} }
};

int config_proxy_conn(const CommandLine& cl, const test_conf_t& conf, MYSQL* proxy) {
	unsigned long cflags = 0;
	mysql_options(proxy, MYSQL_DEFAULT_AUTH, conf.req_auth.c_str());

	if (conf.req_auth == "mysql_clear_password") {
		bool enable_cleartext = true;
		mysql_options(proxy, MYSQL_ENABLE_CLEARTEXT_PLUGIN, &enable_cleartext);
	}

	if (conf.use_ssl) {
		mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);
		cflags |= CLIENT_SSL;
	}

	if (conf.use_comp) {
		cflags |= CLIENT_COMPRESS;
	}

	return cflags;
}

vector<pair<string,string>> get_conns_opts_combs(
	const vector<string> charsets, const vector<string> schemas
) {
	vector<pair<string,string>> res {};

	for (const string& charset : charsets) {
		for (const string& schema : schemas) {
			res.push_back({charset, schema});
		}
	}

	return res;
}

/**
 * @brief Logic borrowed from 'test_auth_methods-t.cpp'
 */
bool exp_first_login_failure(const test_creds_t& creds, const test_conf_t& conf) {
	return
		(!conf.use_ssl && conf.hashed_pass && creds.info.auth == "caching_sha2_password")
		||
		(
			!conf.use_ssl && conf.hashed_pass && creds.info.auth == "mysql_native_password"
			&& conf.req_auth == "caching_sha2_password" && conf.def_auth == "caching_sha2_password"
		)
		||
		(
			conf.use_ssl && conf.hashed_pass && creds.info.auth == "caching_sha2_password"
			&& conf.req_auth != "caching_sha2_password"
		)
		||
		(
			conf.use_ssl && conf.hashed_pass && creds.info.auth == "caching_sha2_password"
			&& conf.req_auth == "caching_sha2_password" && conf.def_auth != "caching_sha2_password"
		);
}

int main(int argc, char** argv) {
	plan(864);

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL* mysql = mysql_init(NULL);

	if (!mysql_real_connect(mysql, cl.host, cl.mysql_username, cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return EXIT_FAILURE;
	}


	const auto cbres { config_mysql_backend_users(mysql, ::backend_users) };
	if (cbres.first) { return EXIT_FAILURE; }

	mysql_close(mysql);

	MYSQL_QUERY_T(admin, "SET mysql-have_ssl=1");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	const vector<string> def_auths {
		"mysql_native_password",
		"caching_sha2_password"
	};
	const vector<string> req_auhts {
		"mysql_clear_password",
		"mysql_native_password",
		"caching_sha2_password"
	};
	const vector<bool> hash_pass { false, true };
	const vector<bool> use_ssl { false, true };
	const vector<bool> use_comp { false, true };

	// Sequential access tests; exercising full logic
	const vector<test_conf_t> all_conf_combs {
		get_auth_conf_combs(def_auths, req_auhts, hash_pass, use_ssl, use_comp)
	};

	for (const test_conf_t& conf : all_conf_combs) {
		diag("Starting new testing conf   conf=\"%s\"", to_string(conf).c_str());
		int cres = config_proxysql_users(admin, conf, cbres.second);
		if (cres) { return EXIT_FAILURE; }

		diag("%s", ("Switching to '" + conf.def_auth + "' on ProxySQL side").c_str());
		MYSQL_QUERY_T(admin, ("SET mysql-default_authentication_plugin='" + conf.def_auth + "'").c_str());
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

		const vector<string> charsets { "latin2", "latin1" };
		const vector<string> schemas { TAP_NAME"schema1", TAP_NAME"schema2" };

		auto conns_opts { get_conns_opts_combs(charsets, schemas) };

		for (const test_creds_t& creds : tests_creds) {
			for (const auto& c_opts : conns_opts) {
				if (exp_first_login_failure(creds, conf)) {
					continue;
				}

				MYSQL* proxy = mysql_init(NULL);
				int cflags = config_proxy_conn(cl, conf, proxy);

				diag(
					"Configuring conn opts   charset=\"%s\" auth=\"%s\"",
					c_opts.first.c_str(), creds.info.auth.c_str()
				);
				if (mysql_options(proxy, MYSQL_SET_CHARSET_NAME, c_opts.first.c_str())) {
					fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
					return exit_status();
				}

				diag(
					"Performing connection attempt   creds=\"%s\" charset:\"%s\" schema=\"%s\"",
					to_string(creds).c_str(), c_opts.first.c_str(), c_opts.second.c_str()
				);
				if (
					!mysql_real_connect(
						proxy,
						cl.host,
						creds.name.c_str(),
						creds.pass.get(),
						c_opts.second.c_str(),
						cl.port,
						NULL,
						cflags
					)
				) {
					fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
					return EXIT_FAILURE;
				}

				int rc = mysql_query_t(proxy, "SELECT @@character_set_client, database()");
				if (rc) {
					diag("Query failed, unable to continue testing   error=\"%s\"", mysql_error(proxy));
					return EXIT_FAILURE;
				}

				MYSQL_RES* myres = mysql_store_result(proxy);
				MYSQL_ROW myrow = mysql_fetch_row(myres);

				ok(
					strcasecmp(c_opts.first.c_str(), myrow[0]) == 0
					&& strcasecmp(c_opts.second.c_str(), myrow[1]) == 0,
					"Conn properties should match expected   "
						"exp_charset=\"%s\" act_charset=\"%s\" exp_db=\"%s\" act_db=\"%s\"",
					c_opts.first.c_str(), myrow[0], c_opts.second.c_str(), myrow[1]
				);

				mysql_free_result(myres);
				mysql_close(proxy);
			}
		}
	}

	mysql_close(admin);

	return exit_status();
}
