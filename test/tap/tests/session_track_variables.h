/**
 * @file session_track_variables.h
 * @brief Shared utility functions for session_track_variables tests.
 *
 * This header provides common helper functions used across the different
 * session_track_variables test variants (optional, optional_mysql56, enforced,
 * and their fast_forward counterparts).
 *
 * === Parameterized tracked-variable design ===
 *
 * The helpers below are parameterized over a 'tracked_var_spec' so that every
 * test variant can exercise session tracking against multiple variables in a
 * single run:
 *
 *   - 'innodb_lock_wait_timeout' -- integer, covers the numeric happy path.
 *   - 'time_zone'                -- string, covers the non-integer extraction
 *                                   path in 'MySQL_Session::handler_rc0_Process_Variables'.
 *   - 'sql_mode'                 -- string, commonly tracked in production.
 *
 * All values returned by the helpers are strings: session tracking reports
 * values as raw strings in the OK-packet tracking payload, so comparing on
 * strings avoids encoding assumptions (e.g. "+01:00" for time_zone).
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
 * @brief Specification of a single tracked variable used by the test helpers.
 *
 * A 'tracked_var_spec' bundles the name of the variable to exercise together
 * with a SQL expression that produces a random-but-deterministic new value.
 * The helpers build a transient stored procedure from these fields, so the
 * expression must be valid as the right-hand side of a 'SET @@session.<name>
 * = <set_expr>' statement on the target server.
 *
 * @field name      Session variable name (without the '@@session.' prefix).
 * @field set_expr  SQL expression evaluated per call to pick a new value.
 */
struct tracked_var_spec {
	const char* name;
	const char* set_expr;
};

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
 * Iterates through the session tracking payload produced by the backend on
 * the most recent query and returns the value associated with @p var_name as
 * a string. This is the fast-forward / client-visible extraction path: it
 * consumes the tracker on the MYSQL* handle the test owns, so callers must
 * invoke it immediately after the CALL that is expected to mutate the
 * variable -- any subsequent query resets the tracker state.
 *
 * @param proxy An active MYSQL connection.
 * @param var_name The session variable name to look for.
 * @param[out] tracked_value The extracted value, or empty string if not found.
 * @return EXIT_SUCCESS if the variable was found, EXIT_FAILURE otherwise.
 */
inline int extract_sess_var_mysql_pkt(MYSQL* proxy, const char* var_name, std::string& tracked_value) {
	tracked_value.clear();

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
						tracked_value.assign(data, length);
						return EXIT_SUCCESS;
					}
					// got a value in this iteration
					// in the next iteration, we have to expect a variable_name
					expect_value = false;
				} else {
					current_var_name.assign(data, length);
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
 * @brief Produces the stored-procedure name that 'set_session_variable()'
 *   will create for a given variable.
 *
 * The name is derived from the tracked variable so multiple specs can
 * coexist without one clobbering another's procedure across sequential
 * calls. Kept purely local/inline to avoid leaking into the test binary's
 * public surface.
 */
inline std::string proc_name_for(const tracked_var_spec& var) {
	return std::string("test.set_session_track_") + var.name;
}

/**
 * @brief Creates a stored procedure that assigns a random value to @p var and
 *   invokes it, leaving the CALL as the most recent query on the connection.
 *
 * The CALL must be the last statement executed before any tracking extraction
 * call, otherwise the session tracker on the connection is reset by the next
 * query. This function guarantees that ordering: the only statement that runs
 * after the procedure is created is the CALL itself.
 *
 * @param proxy An active MYSQL connection.
 * @param var   Tracked-variable specification describing which variable to set
 *              and how to compute the new value.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 *
 * @note The procedure is left on the server (named via 'proc_name_for(var)')
 *   to avoid emitting DDL between CALL and extraction on subsequent runs.
 *   Call 'drop_session_variable_proc()' in test teardown when isolation matters.
 */
inline int set_session_variable(MYSQL* proxy, const tracked_var_spec& var) {
	const std::string proc = proc_name_for(var);
	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");

	// Dropping/recreating the procedure on every call keeps each run independent
	// of any stale definition left by a previous test that used a different
	// 'set_expr' for the same variable.
	std::string drop_q = "DROP PROCEDURE IF EXISTS " + proc;
	MYSQL_QUERY_T(proxy, drop_q.c_str());

	std::string create_q =
		"CREATE PROCEDURE " + proc + "() "
		"BEGIN "
		"  SET @@session." + var.name + " = " + var.set_expr + "; "
		"END";
	MYSQL_QUERY_T(proxy, create_q.c_str());

	std::string call_q = "CALL " + proc + "()";
	MYSQL_QUERY_T(proxy, call_q.c_str());

	return EXIT_SUCCESS;
}

/**
 * @brief Drops the per-variable stored procedure created by 'set_session_variable'.
 *
 * Provided as a separate helper so tests can skip cleanup when they want to
 * preserve the 'CALL' as the last statement on the connection (cleanup queries
 * would otherwise reset the session tracker). Safe to call after extraction.
 */
inline int drop_session_variable_proc(MYSQL* proxy, const tracked_var_spec& var) {
	std::string drop_q = "DROP PROCEDURE IF EXISTS " + proc_name_for(var);
	MYSQL_QUERY_T(proxy, drop_q.c_str());
	return EXIT_SUCCESS;
}

/**
 * @brief Retrieves the current value of @p var from the server as a string.
 *
 * Issues 'SELECT @@session.<var.name>'. Used by tests to obtain the ground
 * truth they will compare the tracked value against. Values that MySQL
 * returns as NULL (e.g. certain engine-dependent variables on unsupported
 * builds) produce an empty string.
 *
 * @param proxy An active MYSQL connection.
 * @param var   Tracked-variable specification.
 * @param[out] set_value The actual value of the variable.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
inline int select_sess_var_value(MYSQL* proxy, const tracked_var_spec& var, std::string& set_value) {
	set_value.clear();

	std::string q = std::string("SELECT @@session.") + var.name;
	MYSQL_QUERY_T(proxy, q.c_str());
	MYSQL_RES* result = mysql_store_result(proxy);
	if (!result) {
		return EXIT_FAILURE;
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	if (row && row[0]) {
		set_value.assign(row[0]);
	}
	mysql_free_result(result);
	return EXIT_SUCCESS;
}

/**
 * @brief Extracts tracked variable values from the PROXYSQL INTERNAL SESSION JSON.
 *
 * Used by the non-fast-forward tests to verify that ProxySQL propagated the
 * tracked change to both its backend and client variable maps. Reads from the
 * 'backends[].conn' and 'conn' JSON subtrees and looks up @p var.name in each.
 *
 * @param proxy An active MYSQL connection.
 * @param var   Tracked-variable specification.
 * @param[out] backend_value Backend-side value, or empty if not found.
 * @param[out] client_value  Client-side value, or empty if not found.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
inline int extract_sess_var_proxy_internal(MYSQL* proxy, const tracked_var_spec& var,
	std::string& backend_value, std::string& client_value) {
	backend_value.clear();
	client_value.clear();

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
				if (backend["conn"].contains(var.name)) {
					backend_value = backend["conn"][var.name].get<std::string>();
					break;
				}
			}
		}
	}

	if (j_session.contains("conn")) {
		if (j_session["conn"].contains(var.name)) {
			client_value = j_session["conn"][var.name].get<std::string>();
		}
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Tests session variable tracking in fast_forward mode for a single variable.
 *
 * Sets a random value for @p var via stored procedure, then extracts the
 * tracked value from the client-visible session tracking payload. The
 * extraction must happen before any other query runs on the connection.
 *
 * @param proxy An active MYSQL connection.
 * @param var   Tracked-variable specification to exercise.
 * @param[out] set_value   Actual server-side value after the CALL.
 * @param[out] tracked_value Value observed via session tracking, empty if
 *                            not tracked.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
inline int test_session_variables_ff(MYSQL* proxy, const tracked_var_spec& var,
	std::string& set_value, std::string& tracked_value) {
	tracked_value.clear();
	set_value.clear();

	if (set_session_variable(proxy, var) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	// Extract tracked value from the session tracking payload. This MUST run
	// immediately after the CALL in 'set_session_variable' -- any query that
	// runs in between (including a SELECT for ground-truth) would reset the
	// tracker state on this MYSQL* handle.
	extract_sess_var_mysql_pkt(proxy, var.name, tracked_value);

	return select_sess_var_value(proxy, var, set_value);
}

/**
 * @brief Tests session variable tracking in normal (non-fast-forward) mode
 *   for a single variable.
 *
 * Sets a random value for @p var via stored procedure, queries the server
 * for the ground-truth value, and reads ProxySQL's internal backend+client
 * variable maps out of 'PROXYSQL INTERNAL SESSION'. All three should agree.
 *
 * @param proxy An active MYSQL connection.
 * @param var   Tracked-variable specification to exercise.
 * @param[out] set_value     Actual value on the server after the CALL.
 * @param[out] backend_value Backend-side value tracked by ProxySQL, empty if
 *                            not tracked.
 * @param[out] client_value  Client-side value tracked by ProxySQL, empty if
 *                            not tracked.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
inline int test_session_variables(MYSQL* proxy, const tracked_var_spec& var,
	std::string& set_value, std::string& backend_value, std::string& client_value) {
	if (set_session_variable(proxy, var) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	if (select_sess_var_value(proxy, var, set_value) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	return extract_sess_var_proxy_internal(proxy, var, backend_value, client_value);
}

/**
 * @brief Default set of tracked-variable specs exercised by the session
 *   tracking tests.
 *
 * Covers three angles:
 *   1. Integer variable ('innodb_lock_wait_timeout') -- the original case;
 *      verifies the numeric-value extraction path.
 *   2. String variable ('time_zone')                 -- exercises the string
 *      path with a small enum-like value space that is portable across
 *      MySQL versions.
 *   3. String variable with complex value ('sql_mode') -- representative of
 *      how production workloads commonly see session tracking used.
 *
 * The 'set_expr' values use only server-side functions so no client-side
 * randomization logic is involved; each CALL produces a fresh value.
 */
inline const tracked_var_spec session_track_default_vars[] = {
	{ "innodb_lock_wait_timeout", "CAST(FLOOR(50 + (RAND() * 100)) AS UNSIGNED)" },
	{ "time_zone",                "ELT(FLOOR(1 + (RAND() * 3)), '+00:00', '+01:00', '-05:00')" },
	{ "sql_mode",                 "ELT(FLOOR(1 + (RAND() * 3)), 'TRADITIONAL', 'ANSI', 'STRICT_ALL_TABLES')" },
};
inline const size_t session_track_default_vars_count =
	sizeof(session_track_default_vars) / sizeof(session_track_default_vars[0]);

#endif // SESSION_TRACK_VARIABLES_H
