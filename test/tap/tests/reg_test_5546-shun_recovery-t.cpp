/**
 * @file reg_test_5546-shun_recovery-t.cpp
 * @brief Regression test for #5546: monitor ping shun must not recover before the next ping window.
 *
 * The test creates a dummy unreachable backend, configures monitor ping failures to shun it after one
 * failed check, and uses a recovery time much shorter than the monitor ping interval. After the server is
 * shunned, a query routed to the dummy hostgroup exercises the server-selection unshun path. The server must
 * remain SHUNNED instead of becoming ONLINE before the monitor has had enough time to re-check it.
 */

#include <string>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using std::string;

constexpr int kHostgroup = 5546;
constexpr int kBackendPort = 3305;
constexpr int kMonitorPingIntervalMs = 5000;
constexpr int kShunRecoverySec = 1;
constexpr int kPollIntervalMs = 100;
constexpr int kShunWaitTimeoutMs = 10000;
constexpr const char* kBackendHost = "127.0.0.1";

string get_runtime_server_status(MYSQL* admin) {
	const string query =
		"SELECT COALESCE((SELECT status FROM runtime_mysql_servers WHERE hostgroup_id=" +
		std::to_string(kHostgroup) + " AND hostname='" + kBackendHost + "' AND port=" +
		std::to_string(kBackendPort) + "), 'MISSING')";
	ext_val_t<string> status { mysql_query_ext_val(admin, query, string { "ERROR" }) };
	if (status.err != EXIT_SUCCESS) {
		diag("Failed to fetch runtime status: %s", get_ext_val_err(admin, status).c_str());
		return "ERROR";
	}
	return status.val;
}

bool wait_for_server_status(MYSQL* admin, const string& expected_status, int timeout_ms) {
	for (int waited_ms = 0; waited_ms <= timeout_ms; waited_ms += kPollIntervalMs) {
		const string status = get_runtime_server_status(admin);
		if (status == expected_status) {
			diag("Server reached expected status   hostgroup=%d host=%s port=%d status=%s waited_ms=%d",
				kHostgroup, kBackendHost, kBackendPort, status.c_str(), waited_ms);
			return true;
		}
		usleep(kPollIntervalMs * 1000);
	}

	diag("Timed out waiting for status %s; last status=%s", expected_status.c_str(), get_runtime_server_status(admin).c_str());
	return false;
}

void cleanup(MYSQL* admin) {
	const string delete_query =
		"DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(kHostgroup) +
		" AND hostname='" + kBackendHost + "' AND port=" + std::to_string(kBackendPort);
	run_q(admin, delete_query.c_str());
	run_q(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	run_q(admin, "SET mysql-monitor_enabled='true'");
	run_q(admin, "SET mysql-monitor_ping_interval='8000'");
	run_q(admin, "SET mysql-monitor_ping_max_failures='3'");
	run_q(admin, "SET mysql-shun_recovery_time_sec='10'");
	run_q(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

void setup(MYSQL* admin) {
	cleanup(admin);
	run_q(admin, "SET mysql-monitor_enabled='true'");
	run_q(admin, ("SET mysql-monitor_ping_interval='" + std::to_string(kMonitorPingIntervalMs) + "'").c_str());
	run_q(admin, "SET mysql-monitor_ping_max_failures='1'");
	run_q(admin, ("SET mysql-shun_recovery_time_sec='" + std::to_string(kShunRecoverySec) + "'").c_str());
	run_q(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	const string insert_query =
		"INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, max_connections, comment) VALUES (" +
		std::to_string(kHostgroup) + ", '" + kBackendHost + "', " + std::to_string(kBackendPort) +
		", 'ONLINE', 100, 'reg_test_5546')";
	run_q(admin, insert_query.c_str());
	run_q(admin, "LOAD MYSQL SERVERS TO RUNTIME");
}

int main(int argc, char** argv) {
	plan(2);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	MYSQL* proxy = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	setup(admin);

	const bool shunned = wait_for_server_status(admin, "SHUNNED", kShunWaitTimeoutMs);
	ok(shunned, "Unreachable backend is SHUNNED after one monitor ping failure");

	bool stayed_shunned = shunned;
	if (shunned) {
		const string routed_query = "DO /* ;hostgroup=" + std::to_string(kHostgroup) + " */ 1";
		const int sleep_ms = kShunRecoverySec * 1000;
		for (int waited_ms = 0; waited_ms < kMonitorPingIntervalMs; waited_ms += sleep_ms) {
			sleep(kShunRecoverySec);

			const int query_rc = mysql_query(proxy, routed_query.c_str());
			diag("Routed query after recovery window returned rc=%d errno=%d error=\"%s\" waited_ms=%d",
				query_rc, mysql_errno(proxy), mysql_error(proxy), waited_ms + sleep_ms);

			const string status = get_runtime_server_status(admin);
			diag("Observed status during one ping interval   waited_ms=%d status=%s",
				waited_ms + sleep_ms, status.c_str());
			stayed_shunned = status == "SHUNNED";
			if (!stayed_shunned) {
				diag("Server changed status after recovery-window selection   status=%s", status.c_str());
				break;
			}
		}
	}
	ok(stayed_shunned, "SHUNNED backend does not become ONLINE before the next monitor ping window (#5546)");

	cleanup(admin);

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
