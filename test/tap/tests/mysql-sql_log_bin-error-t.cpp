#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "noise_utils.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	diag("Test: mysql-sql_log_bin-error-t");
	diag("This test verifies ProxySQL's behavior when an unprivileged user");
	diag("attempts to execute 'SET sql_log_bin=0'.");
	diag("The test expects that this unauthorized action should lead to a failure");
	diag("in the subsequent query, likely because the connection should be terminated");
	diag("or an error state should be triggered.");

	spawn_internal_noise(cl, internal_noise_random_stats_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});
	spawn_internal_noise(cl, internal_noise_pgsql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});

	if (cl.use_noise) {
		plan(1 + 3);
	} else {
		plan(1);
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();

	diag("Connecting to ProxySQL as unprivileged user 'sbtest1'...");
	if (!mysql_real_connect(mysql, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}
	diag("Connected successfully.");

	diag("Attempting 'SET sql_log_bin=0' as 'sbtest1' (should fail or cause issues)");
	int set_res = mysql_query(mysql, "SET sql_log_bin=0");
	if (set_res == 0) {
		diag("'SET sql_log_bin=0' unexpectedly SUCCEEDED.");
	} else {
		diag("'SET sql_log_bin=0' FAILED as expected. Error: %s", mysql_error(mysql));
	}

	diag("Executing 'SELECT 1' to verify connection state...");
	int query_res = mysql_query(mysql, "SELECT 1");
	if (query_res == 0) {
		diag("'SELECT 1' unexpectedly SUCCEEDED.");
		MYSQL_RES *res = mysql_store_result(mysql);
		if (res) mysql_free_result(res);
	} else {
		diag("'SELECT 1' FAILED as expected. Error: %s", mysql_error(mysql));
	}

	ok(query_res!=0, "Query \"SELECT 1\" should fail. Error: %s", (query_res == 0 ? "None" : mysql_error(mysql))); 


	mysql_close(mysql);

	return exit_status();
}

