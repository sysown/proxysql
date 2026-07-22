#ifndef TAP_TESTS_RDS_BGD_TAP_H
#define TAP_TESTS_RDS_BGD_TAP_H

#include <cstdlib>
#include <string>
#include <vector>

#include "rds_bgd_simulator.h"
#include "tap.h"

using namespace std;

inline RDS_BGD_Cluster bgd_cluster_init() {
	return {
		{ "db-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.11", 3306 },
		{ "db-1-green-iqu47r.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.14", 3306 },
		{
			{ "db-1-reader-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.12", 3306 },
			{ "db-1-reader-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.13", 3306 },
		},
		{
			{ "db-1-reader-1-green-dlzky7.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.15", 3306 },
			{ "db-1-reader-2-green-3fpjuu.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.16", 3306 },
		},
	};
}

inline int execute_all(MYSQL* admin, vector<string> queries) {
	for (string& query : queries) {
		if (mysql_query(admin, query.c_str()) != 0) {
			diag("Admin query failed (%u): %s; query: %s", mysql_errno(admin), mysql_error(admin), query.c_str());
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

#endif  // TAP_TESTS_RDS_BGD_TAP_H
