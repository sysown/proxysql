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

#include "mysql.h"
#include "mysqld_error.h"

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

	diag("=== test_gtid_forwarding-t: START ===");
	diag("Connecting to ProxySQL: host=%s, port=%d, user=%s", cl.host, cl.port, cl.username);

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

	diag("Connected. server_capabilities=0x%lx, CLIENT_SESSION_TRACKING=%s",
		proxysql_mysql->server_capabilities,
		(proxysql_mysql->server_capabilities & CLIENT_SESSION_TRACKING) ? "YES" : "NO");

	// Check ProxySQL's default_session_track_gtids via admin (separate connection, doesn't affect test)
	// Ensure CLIENT_SESSION_TRACKING is advertised by ProxySQL so the client
	// library can parse GTID session tracking data from OK packets.
	{
		MYSQL* admin = mysql_init(NULL);
		if (admin && mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
			// Read current server_capabilities and enable CLIENT_SESSION_TRACKING if not set
			if (mysql_query(admin, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-server_capabilities'") == 0) {
				MYSQL_RES* res = mysql_store_result(admin);
				if (res) {
					MYSQL_ROW row = mysql_fetch_row(res);
					if (row && row[0]) {
						uint32_t caps = (uint32_t)strtoul(row[0], NULL, 10);
						if (!(caps & CLIENT_SESSION_TRACKING)) {
							caps |= CLIENT_SESSION_TRACKING;
							std::string q = "SET mysql-server_capabilities=" + std::to_string(caps);
							diag("Enabling CLIENT_SESSION_TRACKING: %s", q.c_str());
							mysql_query(admin, q.c_str());
							mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
						} else {
							diag("CLIENT_SESSION_TRACKING already enabled in server_capabilities");
						}
					}
					mysql_free_result(res);
				}
			}
			mysql_close(admin);
		}
	}

	// Reconnect after capabilities change so the new greeting is used
	mysql_close(proxysql_mysql);
	proxysql_mysql = mysql_init(NULL);
	if (!proxysql_mysql || !mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			proxysql_mysql ? mysql_error(proxysql_mysql) : "mysql_init failed");
		return -1;
	}
	diag("Reconnected. server_capabilities=0x%lx, CLIENT_SESSION_TRACKING=%s",
		proxysql_mysql->server_capabilities,
		(proxysql_mysql->server_capabilities & CLIENT_SESSION_TRACKING) ? "YES" : "NO");

	MYSQL_QUERY(proxysql_mysql, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(proxysql_mysql, "CREATE TABLE IF NOT EXISTS test.gtid_forwarding_test (id INT NOT NULL)");

	diag("Issuing: SET SESSION_TRACK_GTIDS=OWN_GTID");
	MYSQL_QUERY(proxysql_mysql, "SET SESSION_TRACK_GTIDS=OWN_GTID");
	diag("SET done. server_status=0x%x", proxysql_mysql->server_status);

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

		if (i < 5) {
			diag("[i=%u] Executing INSERT...", i);
		}

		MYSQL_QUERY(proxysql_mysql, insert_query.c_str());

		if (i < 5) {
			diag("[i=%u] server_status=0x%x, SESSION_STATE_CHANGED=%s",
				i, proxysql_mysql->server_status,
				(proxysql_mysql->server_status & SERVER_SESSION_STATE_CHANGED) ? "YES" : "NO");
		}

		std::string s_gtid_uuid {};

		// Read the returned GTID
		if (proxysql_mysql->server_status & SERVER_SESSION_STATE_CHANGED) {
			const char *data { nullptr };
			size_t length { 0 };
			char gtid_uuid[128] = { 0 };

			int rc = mysql_session_track_get_first(proxysql_mysql, SESSION_TRACK_GTIDS, &data, &length);
			if (i < 5) {
				diag("[i=%u] session_track_get_first(GTIDS) rc=%d, length=%zu, data='%.*s'",
					i, rc, length, (data && length > 0) ? (int)length : 3, (data && length > 0) ? data : "n/a");
			}

			if (rc == 0) {
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
		} else if (i < 5) {
			diag("[i=%u] SESSION_STATE_CHANGED NOT set after INSERT", i);
		}

		// Verify the received GTID
		if (!s_gtid_uuid.empty()) {
			std::string s_id {};
			// Accept both RFC 4122 UUIDs and dbdeployer-style synthetic UUIDs
			// (e.g. "00003306-1111-1111-1111-111111111111")
			ok(re2::RE2::FullMatch(s_gtid_uuid, "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:([0-9]*)", &s_id), "'UUID' should have a valid format - %s", s_gtid_uuid.c_str());

			// Check the incremental id.
			uint new_id = (std::atoi(s_id.c_str()));
			ok(last_id < new_id, "Last incremental id must be smaller than newer one: %d < %d", last_id, new_id);

			last_id = new_id;
		} else {
			diag("[i=%u] UUID IS EMPTY — GTID not forwarded by ProxySQL", i);
			ok(false, "'UUID' Should never be empty");
			break;
		}
	}

	MYSQL_QUERY(proxysql_mysql, "DROP TABLE test.gtid_forwarding_test");
	mysql_close(proxysql_mysql);

	diag("=== test_gtid_forwarding-t: DONE ===");
	return exit_status();
}
