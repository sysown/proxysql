/**
 * @file test_mysql-tls_version-t.cpp
 * @brief Test for checking 'mysql-tls_version'.
 * @details The test tries to set all the possible valid combinations for 'mysql-tls_version'
 *   using mixed case, for later try to open connections using the valid specified versions
 *   and the invalid not specified ones. It also tries to set several invalid values.
 */

#include <cstring>
#include <cmath>
#include <vector>
#include <string>

#include <mysql.h>
#include <mysql/errmsg.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;
using std::array;

/*
 * @brief This test requires to be compiled against 'libmysqlclient'. Because some testing utilities are
 *   bounded to 'libmariadbclient' the following MACRO needs to be included to make definitions and solve
 *   linker issues.
 */
LIBMARIADB_REQUIRED_DEFINITIONS

/**
 * @brief Copy of the supported 'tls_versions' by ProxySQL. But
 *   writed in mixed-case, to force all the generated subsets
 *   for these tests to also use mixed case. To make sure that
 *   the support properly handles case-insensitive 'tls versions'.
 */
const array<const char*, 4> valid_tls_versions { "tlSv1", "TlSv1.1", "tLsv1.2", "tlSv1.3" };

/**
 * @brief Duplicated function from 'gen_utils.h'. Header file can't be included itself due to inclusion of
 *   'libmariadb' specific headers. This can be changed in the future.
 */
vector<string> str_split(const string& s, char delimiter) {
	vector<string> tokens {};
	string token {};
	std::istringstream tokenStream(s);

	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(token);
	}

	return tokens;
}

/**
 * @brief Helper function to generate some random invalid TLS values.
 * @return A bunch of invalid 'tls_versions' for testing.
 */
vector<string> invalid_ssl_versions() {
	vector<string> result {
		"",
		"TLSv0",
		"TLSv4.1",
		"TLSv1,TLSv1.2,TLSv1.3,TLSv1.4",
		"TLSv1,TLSv1.5,TLSv1.3,TLSv1.4",
		"TLSv1,TLSv1.5,TLSv1.3,TLSv1.4",
		"TLSv1TLSv1.2"
	};

	for (int i = 0; i < 10; i++) {
		string rnd_str { random_string(20) };
		result.push_back(rnd_str);
	}

	return result;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(281 + invalid_ssl_versions().size());

	// Check that the variables 'mysql-tls_version' is properly being set and doesn't accept invalid values.

	// Initialize Admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	// Connnect to ProxySQL Admin
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Enable SSL for MySQL connections
	MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl='true'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Check that the 'mysql-tls_version' variable is supported and contains the right default
	MYSQL_QUERY(proxysql_admin, "SELECT * FROM global_variables WHERE variable_name='mysql-tls_version'");
	MYSQL_RES* tls_ver_res = mysql_store_result(proxysql_admin);
	int num_rows = mysql_num_rows(tls_ver_res);

	ok(num_rows == 1, "'mysql-tls_version' variable should be present.");

	mysql_free_result(tls_ver_res);

	const vector<string> deprecated_tls_versions { "TLSv1", "TLSv1.1" };
	vector<string> v_valid_tls_versions(valid_tls_versions.begin(), valid_tls_versions.end());

	for (const auto& valid_tls_subset : get_power_set(v_valid_tls_versions)) {
		for (const auto& valid_tls_combination : get_permutations(valid_tls_subset)) {
			if (valid_tls_combination.empty()) { continue; }

			string valid_tls_versions =
				accumulate(
					valid_tls_combination.begin(), valid_tls_combination.end(), string {},
					[](const string& a, const string& b) -> string {
						return a + (a.length() > 0 ? "," : "") + b;
					}
				);

			// construct the query
			string t_query { "SET mysql-tls_version='%s'" };
			string query {};
			string_format(t_query, query, valid_tls_versions.c_str());

			// perform the query
			mysql_query(proxysql_admin, query.c_str());
			tls_ver_res = mysql_store_result(proxysql_admin);
			mysql_free_result(tls_ver_res);

			// load to runtime
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
			// check that the variable has been set properly
			MYSQL_QUERY(proxysql_admin, "SELECT * FROM global_variables WHERE variable_name='mysql-tls_version'");
			tls_ver_res = mysql_store_result(proxysql_admin);
			int num_rows = mysql_num_rows(tls_ver_res);
			int num_fields = mysql_num_fields(tls_ver_res);
			MYSQL_ROW row = nullptr;

			string tls_ver_cur_val {};
			while ((row = mysql_fetch_row(tls_ver_res))) {
				unsigned long *lengths;
				lengths = mysql_fetch_lengths(tls_ver_res);
				for(int i = 0; i < num_fields; i++) {
					tls_ver_cur_val = row[i];
				}
			}

			mysql_free_result(tls_ver_res);

			ok(
				strcasecmp(valid_tls_versions.c_str(), tls_ver_cur_val.c_str()) == 0,
				"Setting 'mysql-tls_version' variable to value '%s' should succeed: (exp_val:'%s' == cur_val:'%s')",
				valid_tls_versions.c_str(), valid_tls_versions.c_str(), tls_ver_cur_val.c_str()
			);

			// Test that the connection is valid for each of the specified versions
			vector<string> non_present_versions {};
			copy_if(
				v_valid_tls_versions.begin(),
				v_valid_tls_versions.end(),
				back_inserter(non_present_versions),
				[&valid_tls_combination] (const string& version) {
					return find(
						valid_tls_combination.begin(),
						valid_tls_combination.end(),
						version
					) == end(valid_tls_combination);
				}
			);

			vector<string> bigger_non_present_versions {};
			vector<string> all_present_versions(
				valid_tls_combination.begin(),
				valid_tls_combination.end()
			);
			// sort all the present versions in a case-insensitive way
			sort(
				all_present_versions.begin(),
				all_present_versions.end(),
				[](const string& v1, const string& v2) {
					const auto result =
						mismatch_(v1.cbegin(), v1.cend(), v2.cbegin(), v2.cend(),
							[](const unsigned char lhs, const unsigned char rhs) {
								return tolower(lhs) == tolower(rhs);
							}
						);

					return
						result.second != v2.cend() &&
						(
							result.first == v1.cend() ||
							tolower(*result.first) < tolower(*result.second)
						);
				}
			);
			string biggest_present_version { all_present_versions.back() };

			for (const auto& version : non_present_versions) {
				if (strcasecmp(version.c_str(), biggest_present_version.c_str()) > 0) {
					bigger_non_present_versions.push_back(version);
				}
			}

			// Try to connect with all the valid 'tls versions'
			for (const auto& valid_tls_version : valid_tls_combination) {
				vector<string> non_formatted_tls_versions = str_split(valid_tls_version, ',');
				vector<string> formatted_tls_version {};

				for (const string& c_tls_version : non_formatted_tls_versions) {
					string tls_version  = c_tls_version;
					tls_version.replace(0, 4, "TLSv");
					formatted_tls_version.push_back(tls_version);
				}

				string final_tls_version =
					accumulate(
						formatted_tls_version.begin(), formatted_tls_version.end(), string {},
						[](const string& a, const string& b) -> string {
						    return a + (a.length() > 0 ? "," : "") + b;
						}
					);

				MYSQL* proxysql = mysql_init(NULL);
				mysql_options(proxysql, MYSQL_OPT_TLS_VERSION, final_tls_version.c_str());
				mysql_ssl_set(proxysql, NULL, NULL, NULL, NULL, NULL);

				proxysql =
					mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0);

				if (proxysql == NULL) {
					fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Connection failure");
				}

				ok(
					proxysql != NULL,
					"Connection should be succesfull for the valid 'tls_version:%s' with error_code:'%d'",
					final_tls_version.c_str(), mysql_errno(proxysql)
				);

				mysql_close(proxysql);
			}

			// Try to connect with all the invalid 'tls versions'
			for (const auto& invalid_tls_version : bigger_non_present_versions) {
				// Replace the case-insensitive version with a case-sensitive one for 'mariadbclient'
				string formatted_tls_version = invalid_tls_version;
				formatted_tls_version.replace(0, 4, "TLSv");

				MYSQL* proxysql = mysql_init(NULL);
				mysql_options(proxysql, MYSQL_OPT_TLS_VERSION, formatted_tls_version.c_str());
				mysql_ssl_set(proxysql, NULL, NULL, NULL, NULL, NULL);

				MYSQL* failure =
					mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0);

				ok(
					(failure == NULL) && (mysql_errno(proxysql) == CR_SSL_CONNECTION_ERROR),
					"Connection should fail for the invalid 'tls_version:%s' with error_code:'%d'",
					formatted_tls_version.c_str(),
					CR_SSL_CONNECTION_ERROR
				);

				mysql_close(proxysql);
			}

		}
	}

	// try setting invalid 'tls_versions'
	for (const auto& invalid_tls_version : invalid_ssl_versions()){
		string query {};
		string_format("SET mysql-tls_version='%s'", query, invalid_tls_version.c_str());

		// perform the query
		mysql_query(proxysql_admin, query.c_str());
		tls_ver_res = mysql_store_result(proxysql_admin);
		mysql_free_result(tls_ver_res);

		// load to runtime
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		// check that the variable has been set properly
		MYSQL_QUERY(proxysql_admin, "SELECT * FROM global_variables WHERE variable_name='mysql-tls_version'");
		tls_ver_res = mysql_store_result(proxysql_admin);
		int num_rows = mysql_num_rows(tls_ver_res);
		int num_fields = mysql_num_fields(tls_ver_res);
		MYSQL_ROW row = nullptr;

		string tls_ver_cur_val {};
		while ((row = mysql_fetch_row(tls_ver_res))) {
			unsigned long *lengths;
			lengths = mysql_fetch_lengths(tls_ver_res);
			for(int i = 0; i < num_fields; i++) {
				tls_ver_cur_val = row[i];
			}
		}

		mysql_free_result(tls_ver_res);

		ok(
			invalid_tls_version != tls_ver_cur_val,
			"Setting 'mysql-tls_version' variable to value '%s' should fail: (exp_val:'%s' != cur_val:'%s')",
			invalid_tls_version.c_str(),
			invalid_tls_version.c_str(),
			tls_ver_cur_val.c_str()
		);
	}

	mysql_close(proxysql_admin);

	return exit_status();
}

