/**
 * @file admin_set_credentials_logging-t.cpp
 * @brief Tests that sensitive admin variables are not logged in plaintext.
 * 
 * This test suite verifies that updates to sensitive admin variables, such as
 * credentials, are properly sanitized in the ProxySQL logs. It ensures that
 * only an audit message indicating the update occurs, rather than the plaintext
 * credentials themselves.
 */
#include <fstream>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::fstream;
using std::string;

static constexpr int MAX_LOG_CHECK_ATTEMPTS = 20;
static constexpr useconds_t LOG_CHECK_RETRY_DELAY_US = 100000;

static string escape_sql_string(MYSQL* mysql, const string& value) {
	if (value.empty()) {
		return "";
	}
	string escaped(value.size() * 2 + 1, '\0');
	unsigned long escaped_len = mysql_real_escape_string(mysql, &escaped[0], value.c_str(), value.size());
	escaped.resize(escaped_len);
	return escaped;
}

int main() {
	CommandLine cl;

	plan(7);

	if (cl.getEnv()) {
		return exit_status();
	}

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		diag("Failed to initialize admin connection");
		return exit_status();
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	string original_admin_credentials {};
	int show_res = show_admin_global_variable(admin, "admin-admin_credentials", original_admin_credentials);
	ok(show_res == 0, "Fetched original admin-admin_credentials");

	const string log_dir { get_env("REGULAR_INFRA_DATADIR") };
	ok(!log_dir.empty(), "REGULAR_INFRA_DATADIR is set");
	const string log_path { log_dir + "/proxysql.log" };
	fstream proxysql_log {};
	int log_res = log_dir.empty() ? EXIT_FAILURE : open_file_and_seek_end(log_path, proxysql_log);
	ok(log_res == EXIT_SUCCESS, "Opened ProxySQL log");

	bool leaked_secret = false;
	bool logged_sensitive_set = false;
	if (show_res == 0 && log_res == EXIT_SUCCESS) {
		struct timespec ts {};
		clock_gettime(CLOCK_REALTIME, &ts);
		const string unique_secret {
			"admin-test-secret-" + std::to_string(getpid()) + "-" + std::to_string(ts.tv_sec) +
			"-" + std::to_string(ts.tv_nsec)
		};
		const string updated_admin_credentials { original_admin_credentials + ";copilot:" + unique_secret };
		const string set_query {
			"SET admin-admin_credentials='" + escape_sql_string(admin, updated_admin_credentials) + "'"
		};

		int set_res = mysql_query(admin, set_query.c_str());
		ok(set_res == 0, "Updated admin-admin_credentials");

		string stored_admin_credentials {};
		if (set_res == 0) {
			show_res = show_admin_global_variable(admin, "admin-admin_credentials", stored_admin_credentials);
		}
		ok(show_res == 0 && stored_admin_credentials.find(unique_secret) != string::npos,
			"Stored admin-admin_credentials contains the new secret");

		string log_line {};
		for (int attempt = 0; attempt < MAX_LOG_CHECK_ATTEMPTS; ++attempt) {
			proxysql_log.clear(proxysql_log.rdstate() & ~std::ios_base::eofbit & ~std::ios_base::failbit);
			while (getline(proxysql_log, log_line)) {
				if (log_line.find(unique_secret) != string::npos) {
					leaked_secret = true;
				}
				if (log_line.find("Received SET command for admin-admin_credentials") != string::npos) {
					logged_sensitive_set = true;
				}
			}
			if (leaked_secret || logged_sensitive_set) {
				break;
			}
			usleep(LOG_CHECK_RETRY_DELAY_US);
		}
	} else {
		ok(false, "Updated admin-admin_credentials");
		ok(false, "Stored admin-admin_credentials contains the new secret");
	}

	ok(!leaked_secret, "ProxySQL log does not contain the updated admin credential secret");
	ok(logged_sensitive_set, "ProxySQL logs the sanitized SET audit message");

	if (!original_admin_credentials.empty()) {
		const string restore_query {
			"UPDATE global_variables SET variable_value='" + escape_sql_string(admin, original_admin_credentials) +
			"' WHERE variable_name='admin-admin_credentials'"
		};
		MYSQL_QUERY_err(admin, restore_query.c_str());
	}

	if (proxysql_log.is_open()) {
		proxysql_log.close();
	}
	mysql_close(admin);

	return exit_status();
}
