/**
 * @file test_cacert_load_and_verify_duration-t.cpp
 * @brief Test for OpenSSL performance regression on certificate loading.
 * @details This test uses an internal ProxySQL test checking the following OpenSSL regression regarding
 *  certificate loading https://github.com/openssl/openssl/issues/18814. Experimental results from the test
 *  using different OpenSSL versions:
 *    - openssl="3.4.1" openssl_num=30400010 time='5239 ms'
 *    - openssl="3.2.0" openssl_num=30200000 time='5407 ms'
 *    - openssl="3.1.8" openssl_num=30100080 time='9152 ms'
 *    - openssl="3.1.0" openssl_num=30100000 time='9481 ms'
 *    - openssl="3.0.16" openssl_num=30400010 time='18979 ms'
 *    - openssl="3.0.10" openssl_num=300000 time='21212 ms'
 *    - openssl="3.0.2" openssl_num=30000020 time='47756 ms'
 */

#include <string>
#include <string.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

CommandLine cl;

int main() {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	const char* p_infra_datadir = std::getenv("REGULAR_INFRA_DATADIR");
	if (p_infra_datadir == NULL) {
		// quick exit
		plan(1);
		ok(0, "REGULAR_INFRA_DATADIR not defined");
		return exit_status();
	}

	plan(1);

	int32_t WASAN = get_env_int("WITHASAN", 0);
	MYSQL* proxysql_admin = mysql_init(NULL);

	// Initialize connection
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	const string select_query {
		"SELECT variable_value FROM stats.stats_mysql_global WHERE variable_name='OpenSSL_Version_Num'"
	}; ext_val_t<int64_t> ssl_ver_ext { mysql_query_ext_val(proxysql_admin, select_query, int64_t(-1)) };
    if (ssl_ver_ext.err) {
        const string err { get_ext_val_err(proxysql_admin, ssl_ver_ext) };
        diag("Failed query   query:`%s`, err:`%s`", select_query.c_str(), err.c_str());
        return EXIT_FAILURE;
    }

	// OPENSSL_VERSION_NUMBER: 0xMNN00PP0L
	// https://docs.openssl.org/master/man3/OpenSSL_version/
	const string major { std::to_string(ssl_ver_ext.val >> 28) };
	const string minor { std::to_string((ssl_ver_ext.val & 0x0FF00000L) >> 20) };
	const string patch { std::to_string((ssl_ver_ext.val & 0x00000FF0L) >> 4) };
	const string version { major + "." + minor + "." + patch };

	diag("Detected env   openssl=\"%s\" openssl_num=%lx ASAN=%d", version.c_str(), ssl_ver_ext.val, WASAN);

	// Double the value of previously failed ASAN run, previous known time '89415ms'
	int32_t EXP_TIME = 0;
	const int64_t OPENSSL_3_0_0 { 0x30000000L };
	const int64_t OPENSSL_3_2_0 { 0x30200000L };

	if (ssl_ver_ext.val > OPENSSL_3_0_0 && ssl_ver_ext.val < OPENSSL_3_2_0) {
		diag("OpenSSL version *AFFECTED* by perf regression (https://github.com/openssl/openssl/issues/18814).");
		// Based on previous run with '61392 ms'. Extra marging for versions with perf-regressions.
		EXP_TIME = 80000;
	} else if (ssl_ver_ext.val >= OPENSSL_3_2_0) {
		diag("OpenSSL version *NOT* affected by perf regression");
		EXP_TIME = 20000;
	}

	if (WASAN) {
		diag("Running under ASAN, doubling expected time");
		EXP_TIME *= 2;
	}

	diag("Computed threshold for test runtime   exp_time=%d", EXP_TIME);

	const std::string& ca_full_path = std::string(p_infra_datadir) + "/cert-bundle-rnd.pem";
	diag("Setting mysql-ssl_p2s_ca to '%s'", ca_full_path.c_str());
	const std::string& set_ssl_p2s_ca = "SET mysql-ssl_p2s_ca='" + ca_full_path + "'";
	MYSQL_QUERY(proxysql_admin, set_ssl_p2s_ca.c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	diag("Running ProxySQL Test...");
	if (mysql_query(proxysql_admin, "PROXYSQLTEST 54 1000")) {
		const std::string& error_msg = mysql_error(proxysql_admin);
		if (error_msg.find("Invalid test") != std::string::npos) {
			ok(true, "ProxySQL is not compiled in Debug mode. Skipping test");
		} else {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, error_msg.c_str());
		}
	} else {
		const std::string& msg = mysql_info(proxysql_admin);
		const std::size_t start_pos = msg.find("Took ");
		const std::size_t end_pos = msg.find("ms ");
		if (start_pos != std::string::npos &&
			end_pos != std::string::npos) {
			uint64_t time = std::stoull(msg.substr(start_pos + 5, end_pos - (start_pos + 5)));
			ok(time < EXP_TIME, "Total duration is '%lu ms' should be less than %d Seconds", time, EXP_TIME/1000);
		}
	}
	mysql_close(proxysql_admin);
	return exit_status();
}
