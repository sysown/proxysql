/**
 * @file mysql-select_version_without_backend-t.cpp
 * @brief Exercise every mysql-select_version_forwarding mode with real
 * SELECT @@VERSION and SELECT VERSION() client traffic and no backends.
 */

#include <cstdio>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "noise_utils.h"
#include "utils.h"

using std::string;

#define MYSQL_TEST_SERVER_VERSION "8.4.6-proxysql-tap"
#define MYSQL_SET_SERVER_VERSION_QUERY "SET mysql-server_version='" MYSQL_TEST_SERVER_VERSION "'"

namespace {

MYSQL* init_mysql_conn(char* host, char* user, char* pass, int port) {
	MYSQL* mysql = mysql_init(nullptr);
	if (!mysql) {
		return nullptr;
	}
	if (!mysql_real_connect(mysql, host, user, pass, nullptr, port, nullptr, 0)) {
		diag("Connection to %s:%d failed: %s", host, port, mysql_error(mysql));
		mysql_close(mysql);
		return nullptr;
	}
	return mysql;
}

int run_query(MYSQL* mysql, const char* query) {
	return mysql_query(mysql, query);
}

int test_mode(MYSQL* admin, MYSQL* proxy, int mode, bool expect_success) {
	char set_mode_query[128];
	snprintf(set_mode_query, sizeof(set_mode_query), "SET mysql-select_version_forwarding=%d", mode);
	MYSQL_QUERY_T(admin, set_mode_query);
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Each mode starts with no possible backend connection. The client still
	// sends ordinary COM_QUERY requests through ProxySQL.
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_servers");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	const char* version_queries[] = { "SELECT @@VERSION", "SELECT VERSION()" };
	for (const char* query : version_queries) {
		MYSQL_ROW row = nullptr;
		string result_version;
		const int query_rc = run_query(proxy, query);
		if (query_rc == 0) {
			MYSQL_RES* result = mysql_store_result(proxy);
			if (result) {
				row = mysql_fetch_row(result);
				if (row && row[0]) {
					result_version = row[0];
				}
				mysql_free_result(result);
			}
		}

		if (expect_success) {
			ok(
				query_rc == 0 && row && result_version == MYSQL_TEST_SERVER_VERSION,
				"Mode %d: %s returns internal version '%s' (received '%s')",
				mode, query, MYSQL_TEST_SERVER_VERSION, result_version.c_str()
			);
		} else {
			ok(
				query_rc != 0,
				"Mode %d: %s fails without a backend (error %u: %s)",
				mode, query, mysql_errno(proxy), mysql_error(proxy)
			);
		}
	}
	return 0;
}

} // namespace

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	spawn_internal_noise(cl, internal_noise_random_stats_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});
	spawn_internal_noise(cl, internal_noise_pgsql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});

	if (cl.use_noise) {
		plan(8 + 3);
	} else {
		plan(8);
	}

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_username, cl.admin_password, cl.admin_port);
	if (!admin) {
		return exit_status();
	}

	MYSQL_QUERY_T(admin, MYSQL_SET_SERVER_VERSION_QUERY);
	// A per-interface override takes precedence over the scalar on feature-tier
	// builds. UPDATE is also valid on stable builds, where it simply matches no
	// rows, keeping this regression focused on scalar forwarding semantics.
	MYSQL_QUERY_T(admin,
		"UPDATE global_variables SET variable_value='{}' "
		"WHERE variable_name='mysql-server_version_by_interface'");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Frontend versions are pinned at accept time, so connect only after the
	// scalar-only runtime configuration above has been published.
	MYSQL* proxy = init_mysql_conn(cl.host, cl.username, cl.password, cl.port);
	if (!proxy) {
		mysql_close(admin);
		return exit_status();
	}

	// Mode 0 is internal-only; mode 1 always attempts backend forwarding.
	// Modes 2 and 3 retain the existing smart-fallback coverage.
	test_mode(admin, proxy, 0, true);
	test_mode(admin, proxy, 1, false);
	test_mode(admin, proxy, 2, true);
	test_mode(admin, proxy, 3, false);

	// The test changes only runtime state, but restore it here so focused local
	// runs remain isolated just as the full runner's reconfiguration does.
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES FROM DISK");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS FROM DISK");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	mysql_close(proxy);
	mysql_close(admin);
	return exit_status();
}
