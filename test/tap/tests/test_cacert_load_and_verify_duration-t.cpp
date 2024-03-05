#include <string>
#include <string.h>
#include "mysql.h"
#include "mysqld_error.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

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
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, error_msg);
		}
	} else {
		const std::string& msg = mysql_info(proxysql_admin);
		const std::size_t start_pos = msg.find("Took ");
		const std::size_t end_pos = msg.find("ms ");
		if (start_pos != std::string::npos &&
			end_pos != std::string::npos) {
			uint64_t time = std::stoull(msg.substr(start_pos + 5, end_pos - (start_pos + 5)));
			ok(time < 20000, "Total duration is '%llu ms' should be less than 20 Seconds", time);
		}
	}
	mysql_close(proxysql_admin);
	return exit_status();
}
