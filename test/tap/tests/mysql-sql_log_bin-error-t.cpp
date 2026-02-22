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

	if (!mysql_real_connect(mysql, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}

	diag("Running 'SET sql_log_bin=0' for a not privileged user: sbtest1");
	MYSQL_QUERY(mysql, "SET sql_log_bin=0");


	int query_res = mysql_query(mysql, "SELECT 1");
	ok(query_res!=0, "Query \"SELECT 1\" should fail. Error: %s", (query_res == 0 ? "None" : mysql_error(mysql))); 


	mysql_close(mysql);

	return exit_status();
}

