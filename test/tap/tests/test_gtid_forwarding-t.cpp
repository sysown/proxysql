/**
 * @file test_gtid_forwarding-t.cpp
 * @brief This test file checks several simple functionalities:
 *  - That GTIDs are properly forwarded to the client.
 *  - That GTIDs format is valid.
 *  - That GTIDs incremental sequence number is indeed incremental.
 *  - That resulsets from simple queries is not broken.
 */

#include <vector>
#include <string>
#include <iostream>

#include <stdio.h>
#include <string.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "proxysql_utils.h"
#include "re2/re2.h"

int main(int, char**) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* proxysql_mysql = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}

	MYSQL_QUERY(proxysql_mysql, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(proxysql_mysql, "CREATE TABLE IF NOT EXISTS test.gtid_forwarding_test (id INT NOT NULL)");
	MYSQL_QUERY(proxysql_mysql, "SET SESSION_TRACK_GTIDS=OWN_GTID");

	uint last_id { 0 };

	for (uint32_t i = 0; i < 1000; i++) {
		// Simple select to verify resultset is being returned properly
		MYSQL_QUERY(proxysql_mysql, "SELECT 1");
		MYSQL_RES* select_res = mysql_store_result(proxysql_mysql);
		int field_count = mysql_field_count(proxysql_mysql);
		int row_count = mysql_num_rows(select_res);

		if (field_count == 1 && row_count == 1) {
			MYSQL_ROW row = mysql_fetch_row(select_res);
			ok(atoi(row[0]) == 1, "Resulset from simple query 'SELECT 1' should be well-formed.");
		} else {
			ok(false, "Resultset from simple query 'SELECT 1' query have an invalid number of fields.");
		}

		mysql_free_result(select_res);

		const char* t_insert_query = "INSERT INTO test.gtid_forwarding_test VALUES (%i)";
		std::string insert_query {};
		string_format(t_insert_query, insert_query, i);
		MYSQL_QUERY(proxysql_mysql, insert_query.c_str());

		std::string s_gtid_uuid {};

		// Read the returned GTID
		if (proxysql_mysql->server_status & SERVER_SESSION_STATE_CHANGED) {
			const char *data { nullptr };
			size_t length { 0 };
			char gtid_uuid[128] = { 0 };

			if (mysql_session_track_get_first(proxysql_mysql, SESSION_TRACK_GTIDS, &data, &length) == 0) {
				if (length >= (sizeof(gtid_uuid) - 1)) {
					length = sizeof(gtid_uuid) - 1;
				}
				if (memcmp(gtid_uuid, data, length)) {
					memcpy(gtid_uuid, data, length);
					gtid_uuid[length] = 0;
				}
			}

			if (gtid_uuid[0] != 0) {
				s_gtid_uuid = gtid_uuid;
			}
		}

		// Verify the received GTID
		if (!s_gtid_uuid.empty()) {
			std::string s_id {};
			ok(re2::RE2::FullMatch(s_gtid_uuid, "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:([0-9]*)", &s_id), "'UIID' should have a valid format - %s", s_gtid_uuid.c_str());

			// Check the incremental id.
			uint new_id = (std::atoi(s_id.c_str()));
			ok(last_id < new_id, "Last incremental id must be smaller than newer one: %d < %d", last_id, new_id);

			last_id = new_id;
		} else {
			ok(false, "'UUID' Should never be empty");
			break;
		}
	}

	MYSQL_QUERY(proxysql_mysql, "DROP TABLE test.gtid_forwarding_test");
	mysql_close(proxysql_mysql);

	return exit_status();
}
