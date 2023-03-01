/**
 * @file test_max_transaction_time-t.cpp
 * @brief This test verifies that 'max_transaction_time' behaves properly.
 *
 * @details It verifies that connection with many transactions does not get
 * killed by the max_transaction_time implementation if each individual
 * transaction takes shorter than max_transaction_time.
 */

#include "mysql.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

#include <iostream>

using std::string;

#include "json.hpp"

#define NUMQUERIES	15

using nlohmann::json;

using namespace std;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

// This test was previously failing due to replication not catching up quickly enough when doing
int main(int, char**) {
	CommandLine cl;

	plan(NUMQUERIES*2-1);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	unsigned long long prev_transaction_started_at = 0;

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	diag("Configure ProxySQL to test mysql-max_transaction_time");
	MYSQL_QUERY_T(
		admin,
		"UPDATE global_variables SET variable_value = 10000 "
		"WHERE variable_name = 'mysql-max_transaction_time'"
	);
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	diag("Run %d 1-second transactions:", NUMQUERIES);
	MYSQL_RES* myres;
	for (int i = 0; i < NUMQUERIES; i++) {
		MYSQL_QUERY_T(proxy, "BEGIN");

		MYSQL_QUERY_T(proxy, "SELECT SLEEP(1)");
		myres = mysql_store_result(proxy);
		if (myres == nullptr) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		}
		mysql_free_result(myres);

		json j = {};
		MYSQL_QUERY_T(proxy, "PROXYSQL INTERNAL SESSION");
		myres = mysql_store_result(proxy);
		parse_result_json_column(myres, j);
		mysql_free_result(myres);
		int active_transactions = atoi(j["active_transactions"].dump().c_str());
		unsigned long long transaction_started_at = atoll(j["transaction_started_at"].dump().c_str());
		unsigned long long lapse_time = transaction_started_at - prev_transaction_started_at;
		lapse_time /= 1000;
		prev_transaction_started_at = transaction_started_at;
		ok(active_transactions==1, "active_transactions = %d", active_transactions);
		if (i != 0) {
			ok (lapse_time >= 900 && lapse_time <= 1200, "Transaction time: %llu ms" , lapse_time);
		}
		MYSQL_QUERY_T(proxy, "COMMIT");
	}

	mysql_close(proxy);

	return exit_status();
}
