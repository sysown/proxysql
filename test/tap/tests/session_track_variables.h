/**
 * @file session_track_variables.h
 * @brief Shared utility functions for session_track_variables tests.
 *
 * This header provides common helper functions used across the different
 * session_track_variables test variants (optional, optional_mysql56, enforced,
 * and their fast_forward counterparts).
 */

#ifndef SESSION_TRACK_VARIABLES_H
#define SESSION_TRACK_VARIABLES_H

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "json.hpp"
#include "mysql.h"
#include "utils.h"

/**
 * @brief Retrieves the MySQL server major and minor version numbers.
 * @param proxy An active MYSQL connection.
 * @param[out] major The major version number.
 * @param[out] minor The minor version number.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
inline int get_server_version(MYSQL* proxy, int& major, int& minor) {
	MYSQL_QUERY_T(proxy, "SELECT @@version");
	MYSQL_RES* result = mysql_store_result(proxy);
	if (!result) {
		return EXIT_FAILURE;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	if (!row) {
		mysql_free_result(result);
		return EXIT_FAILURE;
	}

	if (sscanf(row[0], "%d.%d", &major, &minor) != 2) {
		mysql_free_result(result);
		return EXIT_FAILURE;
	}

	mysql_free_result(result);
	return EXIT_SUCCESS;
}

/**
 * @brief Extracts a tracked session variable value from the last query result.
 *
 * Iterates through session tracking data to find the specified variable name
 * and extract its value.
 *
 * @param proxy An active MYSQL connection after executing a query.
 * @param var_name The session variable name to look for.
 * @param[out] tracked_value The extracted integer value, or -1 if not found.
 * @return EXIT_SUCCESS if the variable was found and extracted, EXIT_FAILURE otherwise.
 */
inline int extract_sess_var_mysql_pkt(MYSQL* proxy, const char* var_name, int& tracked_value) {
	tracked_value = -1;

	if ((proxy != nullptr)
		&& (proxy->net.last_errno == 0)
		&& (proxy->server_status & SERVER_SESSION_STATE_CHANGED)) {
		const char *data;
		size_t length;

		if (mysql_session_track_get_first(proxy, SESSION_TRACK_SYSTEM_VARIABLES, &data, &length) == 0) {
			std::string current_var_name(data, length);
			// get_first() returns a variable_name
			// get_next() will return the value
			bool expect_value = true;

			while (mysql_session_track_get_next(proxy, SESSION_TRACK_SYSTEM_VARIABLES, &data, &length) == 0) {
				if (expect_value) {
					// This is the value for current_var_name
					if (current_var_name == var_name) {
						std::string value_str(data, length);
						tracked_value = atoi(value_str.c_str());
						return EXIT_SUCCESS;
					}
					// got a value in this iteration
					// in the next iteration, we have to expect a variable_name
					expect_value = false;
				} else {
					current_var_name = std::string(data, length);
					// got a variable_name in this iteration
					// in the next iteration, we have to expect the value of this variable
					expect_value = true;
				}
			}
		}
	}

	return EXIT_FAILURE;
}

/**
 * @brief Creates a stored procedure that sets innodb_lock_wait_timeout to a
 *   random value (50-149), calls it, and retrieves the actual value.
 *
 * This is the common setup shared by both fast_forward and non-fast_forward
 * test variants. After the CALL, callers should extract tracked values using
 * their own method before calling this function's returned set_value.
 *
 * @param proxy An active MYSQL connection.
 * @param[out] set_value The actual value of innodb_lock_wait_timeout after the procedure call.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
inline int set_session_variable(MYSQL* proxy, int& set_value) {
	set_value = -1;

	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_T(proxy, "SELECT 1");
	mysql_free_result(mysql_store_result(proxy));

	MYSQL_QUERY_T(proxy, "DROP PROCEDURE IF EXISTS test.set_innodb_lock_wait_timeout");
	const char* create_proc =
		"CREATE PROCEDURE test.set_innodb_lock_wait_timeout() "
		"BEGIN "
		"  SET innodb_lock_wait_timeout = CAST(FLOOR(50 + (RAND() * 100)) AS UNSIGNED); "
		"END";

	MYSQL_QUERY_T(proxy, create_proc);

	MYSQL_QUERY_T(proxy, "CALL test.set_innodb_lock_wait_timeout()");

	return EXIT_SUCCESS;
}

/**
 * @brief Retrieves the actual value of innodb_lock_wait_timeout from the server.
 *
 * @param proxy An active MYSQL connection.
 * @param[out] set_value The actual value of innodb_lock_wait_timeout.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
inline int select_sess_var_value(MYSQL* proxy, int& set_value) {
	set_value = -1;

	MYSQL_QUERY_T(proxy, "SELECT @@innodb_lock_wait_timeout");
	MYSQL_RES* result = mysql_store_result(proxy);
	if (result) {
		MYSQL_ROW row = mysql_fetch_row(result);
		if (row) {
			set_value = atoi(row[0]);
		}
		mysql_free_result(result);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Extracts tracked variable values from the PROXYSQL INTERNAL SESSION
 *   JSON output.
 *
 * @param proxy An active MYSQL connection.
 * @param[out] backend_value The value from the backend connection's variable list, or -1 if not found.
 * @param[out] client_value The value from the client connection's variable list, or -1 if not found.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
inline int extract_sess_var_proxy_internal(MYSQL* proxy, int& backend_value, int& client_value) {
	backend_value = -1;
	client_value = -1;

	MYSQL_QUERY(proxy, "PROXYSQL INTERNAL SESSION");
	MYSQL_RES* result = mysql_store_result(proxy);
	if (!result) {
		return EXIT_FAILURE;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	if (!row) {
		mysql_free_result(result);
		return EXIT_FAILURE;
	}

	auto j_session = nlohmann::json::parse(row[0]);
	mysql_free_result(result);

	if (j_session.contains("backends")) {
		for (auto& backend : j_session["backends"]) {
			if (backend != nullptr && backend.contains("conn")) {
				if (backend["conn"].contains("innodb_lock_wait_timeout")) {
					backend_value = std::stoi(backend["conn"]["innodb_lock_wait_timeout"].get<std::string>());
					break;
				}
			}
		}
	}

	if (j_session.contains("conn")) {
		if (j_session["conn"].contains("innodb_lock_wait_timeout")) {
			client_value = std::stoi(j_session["conn"]["innodb_lock_wait_timeout"].get<std::string>());
		}
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Tests session variable tracking in fast_forward mode.
 *
 * Sets a random innodb_lock_wait_timeout via stored procedure and extracts
 * the tracked value from the client-side session tracking API
 * (mysql_session_track_get_first/next). Used for fast_forward tests where
 * ProxySQL does not parse packets.
 *
 * @param proxy An active MYSQL connection.
 * @param[out] set_value The actual value of innodb_lock_wait_timeout after the procedure call.
 * @param[out] tracked_value The value extracted from session tracking, or -1 if not tracked.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
inline int test_session_variables_ff(MYSQL* proxy, int& set_value, int& tracked_value) {
	tracked_value = -1;

	if (set_session_variable(proxy, set_value) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	// Extract tracked value from the session tracking API (must be done
	// immediately after CALL, before any other query resets the state)
	extract_sess_var_mysql_pkt(proxy, "innodb_lock_wait_timeout", tracked_value);

	return select_sess_var_value(proxy, set_value);
}

/**
 * @brief Tests session variable tracking in normal (non-fast_forward) proxy mode.
 *
 * Sets a random innodb_lock_wait_timeout via stored procedure and extracts
 * the tracked values from the PROXYSQL INTERNAL SESSION JSON output. Used for
 * non-fast_forward tests where ProxySQL parses packets and tracks session
 * variables internally.
 *
 * @param proxy An active MYSQL connection.
 * @param[out] set_value The actual value of innodb_lock_wait_timeout after the procedure call.
 * @param[out] backend_value The value from the backend connection's variable list, or -1 if not found.
 * @param[out] client_value The value from the client connection's variable list, or -1 if not found.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
inline int test_session_variables(MYSQL* proxy, int& set_value, int& backend_value, int& client_value) {
	if (set_session_variable(proxy, set_value) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	if (select_sess_var_value(proxy, set_value) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	return extract_sess_var_proxy_internal(proxy, backend_value, client_value);
}

#endif // SESSION_TRACK_VARIABLES_H
