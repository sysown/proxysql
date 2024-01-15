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

#include <unistd.h>
#include <iostream>

using std::string;

#include "json.hpp"

#define NUMQUERIES	15

using nlohmann::json;

using namespace std;

CommandLine cl;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

// This test was previously failing due to replication not catching up quickly enough when doing
int main(int, char**) {

	plan(2+2 + NUMQUERIES*2+1);

	MYSQL* admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == admin->net.compress, "Compression: (%d)", admin->net.compress);
	}

	diag("Configure ProxySQL to test mysql-max_transaction_time");
	MYSQL_QUERY_T(
		admin,
		"UPDATE global_variables SET variable_value = 4000 "
		"WHERE variable_name = 'mysql-max_transaction_time'"
	);
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);

	MYSQL* proxy = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxy, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxy);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxy->net.compress, "Compression: (%d)", proxy->net.compress);
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
		unsigned long long transaction_time_ms = atoll(j["transaction_time_ms"].dump().c_str());
		transaction_time_ms /= 1000;
		ok(active_transactions==1, "active_transactions = %d", active_transactions);
		ok(transaction_time_ms >= 900 && transaction_time_ms <= 1200, "Transaction time: %llu ms" , transaction_time_ms);
		MYSQL_QUERY_T(proxy, "COMMIT");
	}


	MYSQL_QUERY_T(proxy, "BEGIN");
	diag("Sleeping for 10 seconds so that the transaction times out");
	sleep(10);
	diag("Issuing PROXYSQL INTERNAL SESSION : it should fail");
	int query_err = mysql_query(proxy, "PROXYSQL INTERNAL SESSION");
	ok(query_err != 0 && mysql_errno(proxy) == 2013 , "Failed with error code %d : %s" , mysql_errno(proxy), mysql_error(proxy));
	if (query_err == 0) {
		json j = {};
		myres = mysql_store_result(proxy);
		parse_result_json_column(myres, j);
		mysql_free_result(myres);
		int active_transactions = atoi(j["active_transactions"].dump().c_str());
		unsigned long long transaction_time_ms = atoll(j["transaction_time_ms"].dump().c_str());
		transaction_time_ms /= 1000;
		diag("active_transactions = %d", active_transactions);
		diag("Transaction time: %llu ms" , transaction_time_ms);
	}
	mysql_close(proxy);

	return exit_status();
}
