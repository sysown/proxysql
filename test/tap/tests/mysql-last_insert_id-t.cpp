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


std::string queries[5] = {
	"SELECT LAST_INSERT_ID() LIMIT 1",
	"SELECT LAST_INSERT_ID() FROM DUAL",
	"SELECT LAST_INSERT_ID()",
	"SELECT @@IDENTITY LIMIT 1",
	"SELECT @@IDENTITY"
};



int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	spawn_internal_noise(cl, internal_noise_mysql_traffic);
	spawn_internal_noise(cl, internal_noise_random_stats_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});
	spawn_internal_noise(cl, internal_noise_pgsql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});

	if (cl.use_noise) {
		plan(8 + 4);
	} else {
		plan(8);
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}


	if (create_table_test_sbtest1(500,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}
	diag("Waiting few seconds for replication...");
	sleep(2);
	MYSQL_QUERY(mysql, "USE test");
	MYSQL_QUERY(mysql, "INSERT INTO sbtest1 (id) VALUES (NULL)");


	MYSQL_RES *res;
	for (int i=0; i<4; i++) {
		diag("Running query: %s", queries[i].c_str());
		MYSQL_QUERY(mysql, queries[i].c_str());
		res = mysql_store_result(mysql);
		MYSQL_ROW row;
		unsigned long long num_rows = mysql_num_rows(res);
		ok(num_rows == 1, "mysql_num_rows() , expected: 1 , actual: %llu", num_rows);
		while ((row = mysql_fetch_row(res))) {
				ok(strcmp(row[0],"501")==0, "row: expected: \"501\" , actual: \"%s\"", row[0]);
		}	
		mysql_free_result(res);
	}

	mysql_close(mysql);

	return exit_status();
}

