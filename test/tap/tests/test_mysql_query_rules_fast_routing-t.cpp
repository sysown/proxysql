#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <random>

#include <unistd.h>

#include <string>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<> dis(100000, 1000000);

	if(cl.getEnv())
		return exit_status();

	plan(6);
	diag("Testing query rules fast routing");

	MYSQL* mysqlAdmin = mysql_init(NULL);
	if (!mysqlAdmin) return exit_status();
	if (!mysql_real_connect(mysqlAdmin, cl.host, "admin", "admin", NULL, 6032, NULL, 0)) return exit_status();

	const auto NUM_REPS=3;
	char query[1024] = {0};
	for (auto i=0; i<NUM_REPS; i++) {
		int gen_rows = dis(gen);
		MYSQL_QUERY(mysqlAdmin, "DELETE FROM mysql_query_rules_fast_routing");
		snprintf(query, sizeof(query), "PROXYSQLTEST 11 %d", gen_rows);
		MYSQL_QUERY(mysqlAdmin, query);
		auto affected_rows = mysql_affected_rows(mysqlAdmin);
		ok(affected_rows == affected_rows, "Number of affected rows expected [%d], actual [%d]", gen_rows, affected_rows);

		if (mysql_query(mysqlAdmin, "LOAD MYSQL QUERY RULES TO RUNTIME")) return exit_status();

		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 14 1");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 17 1");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 14 11");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 17 11");

		MYSQL_QUERY(mysqlAdmin, "DELETE FROM mysql_query_rules_fast_routing");
		gen_rows = dis(gen);
		snprintf(query, sizeof(query), "PROXYSQLTEST 15 %d", gen_rows);
		MYSQL_QUERY(mysqlAdmin, query);
		affected_rows = mysql_affected_rows(mysqlAdmin);
		ok(affected_rows == affected_rows, "Number of affected rows expected [%d], actual [%d]", gen_rows, affected_rows);

		if (mysql_query(mysqlAdmin, "LOAD MYSQL QUERY RULES TO RUNTIME")) return exit_status();

		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 14 1");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 17 1");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 14 11");
		MYSQL_QUERY(mysqlAdmin, "PROXYSQLTEST 17 11");
	}


	if (mysql_query(mysqlAdmin, "load mysql query rules from disk")) return exit_status();
	if (mysql_query(mysqlAdmin, "load mysql query rules to runtime")) return exit_status();

	mysql_close(mysqlAdmin);

	return exit_status();
}

