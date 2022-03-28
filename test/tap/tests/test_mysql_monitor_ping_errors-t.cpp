/**
 * @file test_mysql_monitor_ping_errors-t.cpp
 * @brief This tests the behavior of server status resulting from mysql monitor ping errors
 * 
 * @details The following tests are performed :
 *  1. Invalid host for mysql server should produce a monitor error and NOT be status ONLINE
 *  2. Access denied error for the monitor user should result in the server still being ONLINE
 *  3. Password expiration error should should result in the server still being ONLINE
 *  4. Exceeding max_user_connections should should result in the server still being ONLINE
 *
 * @date 2022-03-03
 */

#include <algorithm>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::to_string;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(4);

	// How many seconds to wait for the monitor to check. 2 seconds should be plenty if using 100ms minimums 
	const uint32_t wait_sec = 2;

	MYSQL* proxysql_admin = mysql_init(NULL);
	MYSQL* backend = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_admin || !backend) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Connnect to local proxysql
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	/*  
	 * Very short intervals and max failures are set for the monitor so the test 
	 * code doesn't have to wait long before checking the result.
	 * 
	 * @note: Time is in miliseconds and set at the minimum values
	 */
	MYSQL_QUERY(proxysql_admin, "SET mysql-monitor_connect_interval=100");
	MYSQL_QUERY(proxysql_admin, "SET mysql-monitor_connect_timeout=100");
	MYSQL_QUERY(proxysql_admin, "SET mysql-monitor_ping_interval=100");	
	MYSQL_QUERY(proxysql_admin, "SET mysql-monitor_ping_timeout=100");
	MYSQL_QUERY(proxysql_admin, "SET mysql-monitor_ping_max_failures=1"); // Shun after a single unacceptable error
	
	MYSQL_RES* result{nullptr};
	MYSQL_ROW row{nullptr};
	
	// Previous values for server so they can be restored after change and to connect 
	int64_t prev_hostgroup_id{0};
	string prev_hostname;
	uint16_t prev_port{0};

	string monitor_user;
	string monitor_pass;
	string server_status;

	// Test 1: Invalid host for mysql server should produce a monitor error and NOT be status ONLINE
	{
		// Get an online backend, and invalidate its IP so it can't connect/ping resulting in error. 
		int64_t lookup_row_count = 0;
		MYSQL_QUERY(proxysql_admin, "SELECT hostgroup_id, hostname, port FROM runtime_mysql_servers WHERE status='ONLINE'");
		result = mysql_store_result(proxysql_admin);
		row = mysql_fetch_row(result);

		// Store previous backend primary key info to be restored after the test
		prev_hostgroup_id = strtol(row[0], nullptr, 10);
		prev_hostname = row[1];
		prev_port = strtoul(row[2], nullptr, 10);
		
		mysql_free_result(result);

		string invalid_hostname = "invalidhost.wontconnect";

		// Invalidate the hostname
		string invalid_host_query = "UPDATE mysql_servers SET hostname='" + invalid_hostname + "' WHERE hostgroup_id=" + to_string(prev_hostgroup_id);
		invalid_host_query += " AND hostname='" + prev_hostname + "' AND port=" + to_string(prev_port);
		MYSQL_QUERY(proxysql_admin, invalid_host_query.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD mysql servers to RUN");

		// Wait long enough for monitor connect/ping, then check the status
		sleep(wait_sec);
		string select_server_query = "SELECT status FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(prev_hostgroup_id);
		select_server_query += " AND hostname='" + invalid_hostname + "' AND port=" + to_string(prev_port);
		MYSQL_QUERY(proxysql_admin, select_server_query.c_str());
		result = mysql_store_result(proxysql_admin);
		row = mysql_fetch_row(result);

		server_status = row[0];

		mysql_free_result(result);

		// @TODO: Should the ping log be checked, error field should not be null?

		ok(
			server_status != "ONLINE",
			"Server status should not be 'ONLINE' if hostname is invalid after monitor checks it. Status: %s",
			server_status.c_str()
		);

		// Reset backend settings
		string reset_backend_query = "UPDATE mysql_servers SET hostname='" + prev_hostname + "' WHERE hostgroup_id=" + to_string(prev_hostgroup_id);
		reset_backend_query += " AND port=" + to_string(prev_port) + " AND hostname='" + invalid_hostname + "'";
		MYSQL_QUERY(proxysql_admin, reset_backend_query.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD mysql servers to RUN");
	}

	// Test 2: Access denied error for the monitor user should result in the server still being ONLINE
	{
		// Get the monitor user and backend user
		MYSQL_QUERY(proxysql_admin, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-monitor_password'");
		result = mysql_store_result(proxysql_admin);
		row = mysql_fetch_row(result);

		monitor_pass = row[0];
		mysql_free_result(result);

		// Invalidate the monitor users's password to produce an access denied
		MYSQL_QUERY(proxysql_admin, "UPDATE global_variables SET variable_value='invalid_monitor_password' WHERE variable_name='mysql-monitor_password'");
		MYSQL_QUERY(proxysql_admin, "LOAD mysql variables to RUN");
		
		// Wait for monitor connect/ping
		sleep(2);

		// @TODO: Should this check the ping log, error should be like 'Access denied for user%'?

		// Check server status, it should still be ONLINE
		string select_server_query = "SELECT status FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(prev_hostgroup_id);
		select_server_query += " AND hostname='" + prev_hostname + "' AND port=" + to_string(prev_port);
		MYSQL_QUERY(proxysql_admin, select_server_query.c_str());
		result = mysql_store_result(proxysql_admin);
		row = mysql_fetch_row(result);

		server_status = row[0];
		mysql_free_result(result);

		ok(
			server_status == "ONLINE",
			"Server status should be 'ONLINE' after monitor user gets access denied. Status: %s",
			server_status.c_str()
		);

		// @TODO: Reset the monitor password
	}

	// Test 3: Password expiration error should not shun the server
	{
		// Get monitor username
		MYSQL_QUERY(proxysql_admin, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-monitor_username'");
		result = mysql_store_result(proxysql_admin);
		row = mysql_fetch_row(result);

		string monitor_username = row[0];
		mysql_free_result(result);

		//  Get backend server username/password. 
		MYSQL_QUERY(proxysql_admin, ("SELECT username, password FROM mysql_users WHERE default_hostgroup=" + to_string(prev_hostgroup_id)).c_str());
		result = mysql_store_result(proxysql_admin);
		row = mysql_fetch_row(result);

		string backend_user = row[0];
		string backend_pass = row[1];
		mysql_free_result(result);

		// Connnect to backend server
		
		if (!mysql_real_connect(backend, prev_hostname.c_str(), backend_user.c_str(), backend_pass.c_str(), NULL, prev_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		}

		// Change the monitor user's password then alter the user to expire the temporary password
		// This should result in a 'Your password has expired' error
		auto set_temp_pass_query = "ALTER USER '" + monitor_user + "'@'%' IDENTIFIED BY 'new_temporary_password'";
		MYSQL_QUERY(backend, set_temp_pass_query.c_str());
		auto expire_pass_query = "ALTER USER '" + monitor_username + "'@'%' PASSWORD EXPIRE";
		MYSQL_QUERY(backend, expire_pass_query.c_str());

		// Wait for monitor to check
		sleep(wait_sec);

		// @TODO: Should log be checked? A 'Your password has expired' error should have occurred

		// Check server status, should still be ONLINE
		string select_server_query = "SELECT status FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(prev_hostgroup_id);
		select_server_query += " AND hostname='" + prev_hostname + "' AND port=" + to_string(prev_port);
		MYSQL_QUERY(proxysql_admin, select_server_query.c_str());
		result = mysql_store_result(proxysql_admin);
		row = mysql_fetch_row(result);

		server_status = row[0];
		mysql_free_result(result);

		ok(
			server_status == "ONLINE",
			"Server status should be 'ONLINE' after monitor user gets password expired error. Status: %s",
			server_status.c_str()
		);

		// Alter the monitor user to un-expire the password
		string reset_pass_query = "ALTER USER '" + monitor_user + "'@'%' IDENTIFIED BY '" + monitor_pass + "'";
		MYSQL_QUERY(backend, reset_pass_query.c_str());
		string unexpire_pass_query = "ALTER USER '" + monitor_user + "'@'%' PASSWORD NEVER EXPIRE";
		MYSQL_QUERY(backend, unexpire_pass_query.c_str());

		// Keeping the backend connected for Test 4
	}
	

	// Test 4: Exceeding max_user_connections should should result in the server still being ONLINE
	{
		// On the backend, modify user to set max_user_connections to 1. 
		string max_conn_query = "ALTER USER '" + monitor_user + "'@'%' WITH MAX_USER_CONNECTIONS 1";
		MYSQL_QUERY(backend, max_conn_query.c_str());
		mysql_close(backend);

		// Connect to backend with the monitor user to use up the max connections
		if (!mysql_real_connect(backend, prev_hostname.c_str(), monitor_user.c_str(), monitor_pass.c_str(), NULL, prev_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		}

		// Wait for the monitor to check, this should result in the error: "User ... has exceeded ... 'max_user_connections'"
		sleep(wait_sec);

		// @TODO: Should log be checked? A "User ... has exceeded ... 'max_user_connections'" error should have occurred.

		// @TODO: Check the status of the server, it should still be ONLINE
		string select_server_query = "SELECT status FROM runtime_mysql_servers WHERE hostgroup_id=" + to_string(prev_hostgroup_id);
		select_server_query += " AND hostname='" + prev_hostname + "' AND port=" + to_string(prev_port);
		MYSQL_QUERY(proxysql_admin, select_server_query.c_str());
		result = mysql_store_result(proxysql_admin);
		row = mysql_fetch_row(result);

		server_status = row[0];
		mysql_free_result(result);

		ok(
			server_status == "ONLINE",
			"Server status should be 'ONLINE' after monitor user exceeds max_user_connections. Status: %s",
			server_status.c_str()
		);

		mysql_close(backend);
	}

	return exit_status();
}
