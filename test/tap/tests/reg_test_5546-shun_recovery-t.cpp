/**
 * @file reg_test_5546-shun_recovery-t.cpp
 * @brief Regression test for #5546: a SHUNNED backend must not recover before the next monitor ping.
 *
 * A SHUNNED backend must remain SHUNNED for at least 2x monitor_ping_interval, even when
 * shun_recovery_time_sec is shorter than monitor_ping_interval. Once 2x monitor_ping_interval
 * elapses, the server-selection path may bring it back ONLINE.
 *
 * Test flow:
 *   1. Add an unreachable backend
 *   2. Configure the monitor to shun it after one failed ping, and set shun_recovery_time_sec
 *      shorter than monitor_ping_interval
 *   3. Disable the monitor immediately after the server is SHUNNED. This prevents the monitor
 *      from further extending `time_last_detected_error`
 *   4. Execute two queries to trigger the server-selection/unshun path:
 *       i. Before 2x monitor_ping_interval elapses - assert the server stays SHUNNED
 *      ii. After 2x monitor_ping_interval elapses - assert the server becomes ONLINE
 */

#include <string>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using std::string;

// ProxySQL config
constexpr const char* kBackendHost = "127.0.0.1";
constexpr int kBackendPort = 3305;
constexpr int kHostgroup = 5546;
constexpr int kMonitorPingIntervalMs = 5000;
constexpr int kShunRecoverySec = 1;

// sleep intervals
constexpr int kFirstPingIntervalSleepSec = 7;
constexpr int kSecondPingIntervalSleepSec = 6;

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

bool wait_for_server_status(MYSQL* admin, const string& expected_status) {
    int poll_interval_ms = 100;
    int poll_timeout_ms = 10000;

	for (int waited_ms = 0; waited_ms <= poll_timeout_ms; waited_ms += poll_interval_ms) {
		const string status = get_runtime_server_status(admin);
		if (status == expected_status) {
			diag("Server reached expected status: hostgroup=%d host=%s port=%d status=%s waited_ms=%d",
				kHostgroup, kBackendHost, kBackendPort, status.c_str(), waited_ms);
			return true;
		}
		usleep(poll_interval_ms * 1000);
	}

	diag("Timed out waiting for status %s; last status=%s", expected_status.c_str(), get_runtime_server_status(admin).c_str());
	return false;
}

void cleanup(MYSQL* admin) {
	const string delete_query = "DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(kHostgroup);
	run_q(admin, delete_query.c_str());
	run_q(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	run_q(admin, "SET mysql-monitor_enabled='true'");
	run_q(admin, "SET mysql-monitor_ping_interval='8000'");
	run_q(admin, "SET mysql-monitor_ping_max_failures='3'");
	run_q(admin, "SET mysql-shun_recovery_time_sec='10'");
	run_q(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

void setup(MYSQL* admin, const CommandLine& cl) {
	run_q(admin, "SET mysql-monitor_enabled='true'");
	run_q(admin, ("SET mysql-monitor_ping_interval='" + std::to_string(kMonitorPingIntervalMs) + "'").c_str());
	run_q(admin, "SET mysql-monitor_ping_max_failures='1'");
	run_q(admin, ("SET mysql-shun_recovery_time_sec='" + std::to_string(kShunRecoverySec) + "'").c_str());
	run_q(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// We add two servers to HG 5546,
	// - cl.mysql_host                              - VALID
	// - kBackendHost:kBackendPort (127.0.0.1:3305) - INVALID (unreachable)
	// 
	// While the test is based on server 127.0.0.1:3305, we add cl.mysql_host to the test HG
	// so that ProxySQL will not trigger the "desperate" unshun logic at lib/MyHGC.cpp:L186-L242
	// - https://github.com/sysown/proxysql/blob/9cc20a8775f6c194335a940ed0ca12001166522a/lib/MyHGC.cpp#L186-L242 
	const string insert_srv1 =
		"INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, max_connections, comment) VALUES (" +
		std::to_string(kHostgroup) + ", '" + kBackendHost + "', " + std::to_string(kBackendPort) +
		", 'ONLINE', 100, 'reg_test_5546')";
	const string insert_srv2 =
		"INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, max_connections, comment) VALUES (" +
		std::to_string(kHostgroup) + ", '" + cl.mysql_host + "', " + std::to_string(cl.mysql_port) +
		", 'ONLINE', 100, 'reg_test_5546')";

	run_q(admin, insert_srv1.c_str());
	run_q(admin, insert_srv2.c_str());
	run_q(admin, "LOAD MYSQL SERVERS TO RUNTIME");
}

int main(int argc, char** argv) {
	plan(3);

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

	setup(admin, cl);

	const bool shunned = wait_for_server_status(admin, "SHUNNED");
	ok(shunned, "Unreachable backend is SHUNNED after one monitor ping failure");

	// Disable the monitor so subsequent pings do not refresh time_last_detected_error
	// while the test waits out 2x of monitor_ping_interval.
	run_q(admin, "SET mysql-monitor_enabled='false'");
	run_q(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	const string query = "DO /* ;hostgroup=" + std::to_string(kHostgroup) + " */ 1";

	string status = "NOT_CHECKED";
	bool shunned_past_1x_ping_interval = false;
	if (shunned) {
		sleep(kFirstPingIntervalSleepSec);

		const int query_rc = mysql_query(proxy, query.c_str());
		diag("Routed query after first wait returned rc=%d errno=%d error=\"%s\" sleep_sec=%d",
			query_rc, mysql_errno(proxy), mysql_error(proxy), kFirstPingIntervalSleepSec);

		status = get_runtime_server_status(admin);
		diag("Status after first wait   sleep_sec=%d status=%s",
			kFirstPingIntervalSleepSec, status.c_str());
		shunned_past_1x_ping_interval = status == "SHUNNED";
	}
	ok(shunned_past_1x_ping_interval,
		"Backend stays SHUNNED before 2x of monitor_ping_interval elapses: expected='%s' got='%s'",
		"SHUNNED", status.c_str());

	status = "NOT_CHECKED";
	bool online_after_2x_ping_interval = false;
	if (shunned) {
		sleep(kSecondPingIntervalSleepSec);

		const int query_rc = mysql_query(proxy, query.c_str());
		const int total_sleep_sec = kFirstPingIntervalSleepSec + kSecondPingIntervalSleepSec;
		diag("Routed query after second wait returned rc=%d errno=%d error=\"%s\" total_sleep_sec=%d",
			query_rc, mysql_errno(proxy), mysql_error(proxy), total_sleep_sec);

		status = get_runtime_server_status(admin);
		diag("Status after second wait   total_sleep_sec=%d status=%s",
			total_sleep_sec, status.c_str());
		online_after_2x_ping_interval = status == "ONLINE";
	}
	ok(online_after_2x_ping_interval,
		"Backend becomes ONLINE after 2x of monitor_ping_interval elapses: expected='%s' got='%s'",
		"ONLINE", status.c_str());

	cleanup(admin);

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
