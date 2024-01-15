/**
 * @file test_csharp_connector_support-t.cpp
 * @brief This test verifies the new added queries for supporting C# connector for the 'Admin module'.
 */

#include <vector>
#include <string>
#include <stdio.h>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

int main(int argc, char** argv) {

	plan(2 + 4);

	MYSQL* proxysql_admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_admin->net.compress, "Compression: (%d)", proxysql_admin->net.compress);
	}

	// Test the new introduced query "SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())"
	int query_res = mysql_query(proxysql_admin, "SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())");
	ok(
		query_res == 0,
		"Query \"SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())\" should succeed."
	);

	if (query_res == 0) {
		MYSQL_RES* select_res = mysql_store_result(proxysql_admin);
		unsigned int num_fields = mysql_num_fields(select_res);
		MYSQL_ROW select_row = mysql_fetch_row(select_res);

		if (select_row && num_fields == 1) {
			std::string select_row_str { select_row[0] };
			bool exp_concat_res = true;

			ok(exp_concat_res, "Output received for \"SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())\" was: %s", select_row_str.c_str());
		}

		mysql_free_result(select_res);
	} else {
		ok(false, "Query result for \"SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())\" should be 0. Was: %d", query_res);
	}

	MYSQL_RES* select_res = NULL;
	int max_allowed_packet = 0;
	std::string character_set_client {};
	std::string character_set_connection {};
	std::string license {};
	std::string sql_mode {};
	std::string lower_case_table_names {};

	// Test the new introduced query "SELECT @@max_allowed_packet, @@character_set_client, @@character_set_connection, @@license, @@sql_mode, @@lower_case_table_names"
	query_res = mysql_query(proxysql_admin, "SELECT @@max_allowed_packet, @@character_set_client, @@character_set_connection, @@license, @@sql_mode, @@lower_case_table_names");
	ok(
		query_res == 0,
		"Query \"SELECT @@max_allowed_packet, @@character_set_client, @@character_set_connection, @@license, @@sql_mode, @@lower_case_table_names\" should succeed."
	);

	if (query_res == 0) {
		select_res = mysql_store_result(proxysql_admin);
		unsigned int select_num_fields = mysql_num_fields(select_res);

		if (select_res && select_num_fields == 6) {
			MYSQL_ROW select_row = mysql_fetch_row(select_res);

			max_allowed_packet = atoi(select_row[0]);
			character_set_client = select_row[1];
			character_set_connection = select_row[2];
			license = select_row[3];
			sql_mode = select_row[4];
			lower_case_table_names = select_row[5];

			bool expected_values =
				max_allowed_packet == 67108864 &&
				character_set_client == "utf8" &&
				character_set_connection == "utf8" &&
				license == "" &&
				sql_mode == "" &&
				lower_case_table_names == "";

			ok(
				expected_values,
				"Query result for \"SELECT @@max_allowed_packet, @@character_set_client, @@character_set_connection, @@license, @@sql_mode, @@lower_case_table_names\" should match the expected hardcoded values:\n"
				" (expected=(@@max_allowed_packet:67108864, @@character_set_client:'utf8', @@character_set_connection='utf8', @@license='', @@sql_mode='', @@lower_case_table_names=''),\n"
				" (actual=(@@max_allowed_packet:%d, @@character_set_client:'%s', @@character_set_connection='%s', @@license='%s', @@sql_mode='%s', @@lower_case_table_names='%s')))",
				max_allowed_packet,
				character_set_client.c_str(),
				character_set_connection.c_str(),
				license.c_str(),
				sql_mode.c_str(),
				lower_case_table_names.c_str()
			);

		} else {
			ok(false, "Invalid resulset. Expected 'num_fields' = 6, not %d", select_num_fields);
		}
	}

	mysql_free_result(select_res);

	return exit_status();
}
