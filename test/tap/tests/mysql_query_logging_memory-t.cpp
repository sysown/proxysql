/**
 * @file mysql_query_logging_memory-t.cpp
 * @brief This file contains a TAP test for testing query memory logging
 */

// TODO: we also need to add checks for stats_mysql_errors

#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>
#include <regex>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

/** @brief Expected DDL for the stats_mysql_query_events table. */
const std::string expected_stats_mysql_query_events = R"(CREATE TABLE stats_mysql_query_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER,
    username TEXT,
    schemaname TEXT,
    start_time INTEGER,
    end_time INTEGER,
    query_digest TEXT,
    query TEXT,
    server TEXT,
    client TEXT,
    event_type INTEGER,
    hid INTEGER,
    extra_info TEXT,
    affected_rows INTEGER,
    last_insert_id INTEGER,
    rows_sent INTEGER,
    client_stmt_id INTEGER,
    gtid TEXT,
    errno INT,
    error TEXT))";

/** @brief Expected DDL for the history_mysql_query_events table. */
const std::string expected_history_mysql_query_events = R"(CREATE TABLE history_mysql_query_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER,
    username TEXT,
    schemaname TEXT,
    start_time INTEGER,
    end_time INTEGER,
    query_digest TEXT,
    query TEXT,
    server TEXT,
    client TEXT,
    event_type INTEGER,
    hid INTEGER,
    extra_info TEXT,
    affected_rows INTEGER,
    last_insert_id INTEGER,
    rows_sent INTEGER,
    client_stmt_id INTEGER,
    gtid TEXT,
    errno INT,
    error TEXT))";

/**
 * @brief Removes multiple spaces from a string, replacing them with a single space.
 * 
 * @param str The input string.
 * @return The string with multiple spaces replaced by single spaces.
 */
std::string removeMultipleSpacesRegex(std::string str) {
    std::replace(str.begin(), str.end(), '\n', ' '); //Replace newlines first
    std::regex multipleSpaces("\\s+"); // Matches one or more whitespace characters
    std::string result = std::regex_replace(str, multipleSpaces, " ");
    return result;
}

/**
 * @brief Checks if the structure of a table matches the expected DDL.
 * 
 * @param conn The MySQL connection.
 * @param schemaname The name of the schema.
 * @param table_name The name of the table.
 * @param expected_ddl The expected DDL for the table.
 * @return True if the table structure matches, false otherwise.
 */
bool runAndCheckTable(MYSQL* conn, const std::string& schemaname, const std::string& table_name, std::string expected_ddl) {
    std::string query = "SHOW CREATE TABLE " + schemaname + "." + table_name;
    if (mysql_query(conn, query.c_str())) {
        diag("Error querying table '%s': %s", table_name.c_str(), mysql_error(conn));
        return false;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (!result) {
        diag("Error storing result for table '%s': %s", table_name.c_str(), mysql_error(conn));
        return false;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (!row || row[1] == nullptr) {
        diag("Unexpected result for table '%s'", table_name.c_str());
        mysql_free_result(result);
        return false;
    }

    std::string actual_ddl(row[1]);
    mysql_free_result(result);
    size_t pos = actual_ddl.find('\n');
    while (pos != std::string::npos) {
        actual_ddl.replace(pos, 1, " ");
        pos = actual_ddl.find('\n', pos + 1);
    }

	actual_ddl = removeMultipleSpacesRegex(actual_ddl);
	expected_ddl = removeMultipleSpacesRegex(expected_ddl);

    bool success = (actual_ddl == expected_ddl);
    ok(success, "Table '%s' structure %s match expectation", table_name.c_str(), (success ? "matches" : "does not match"));
	if (success == false) {
		diag("Table structure actual  : %s", actual_ddl.c_str());
		diag("Table structure expected: %s", expected_ddl.c_str());
	}
    return success;
}


/**
 * @brief Checks the result of a query against expected results.
 * 
 * @param conn The MySQL connection.
 * @param query The query to execute.
 * @param expectedResults The expected results as a map of errno to count.
 * @return True if the query results match the expected results, false otherwise.
 */
bool checkQueryResult(MYSQL* conn, const std::string& query, const std::map<int, int>& expectedResults) {
    if (mysql_query(conn, query.c_str())) {
        diag("Error executing query '%s': %s", query.c_str(), mysql_error(conn));
        return false;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (!result) {
        diag("Error storing result for query '%s': %s", query.c_str(), mysql_error(conn));
        return false;
    }

    std::map<int, int> actualResults;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        actualResults[std::stoi(row[0])] = std::stoi(row[1]);
    }
    mysql_free_result(result);

	bool ret = false;
	ret = (actualResults == expectedResults);
	if (ret == false) {
		diag("Query: %s", query.c_str());
		diag("ExpectedResult:");
		for (std::map<int, int>::const_iterator it = expectedResults.begin() ; it != expectedResults.end() ; it++) {
			diag("  %d : %d", it->first, it->second);
		}
		diag("ActualResult:");
		for (std::map<int, int>::const_iterator it = actualResults.begin() ; it != actualResults.end() ; it++) {
			diag("  %d : %d", it->first, it->second);
		}
	}
	return ret;
}


int main() {


    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    const unsigned int num_selects = 200; // Number of "SELECT 1" queries to run
    unsigned int p = 2; // Number of tests for table structure checks
    p += num_selects/10; // Number of tests for SELECT 1 queries (one every 10 iterations)
    p += 1; // Number of tests for syntax error
    p += 1; // Number of tests for empty hostgroup error
    p += 1; // Number of tests for non-existing schema error
    p += 2; // Number of tests for checking query results in stats and history tables
	plan(p);

    MYSQL* admin_conn = mysql_init(nullptr);
    if (!admin_conn) {
        diag("Failed to initialize MySQL connection.");
        return -1;
    }

    if (!mysql_real_connect(admin_conn, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
        diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin_conn));
        mysql_close(admin_conn);
        return -1;
    }

	// Check table structures
	runAndCheckTable(admin_conn, "stats", "stats_mysql_query_events", expected_stats_mysql_query_events);
	runAndCheckTable(admin_conn, "stats_history", "history_mysql_query_events", expected_history_mysql_query_events);

    // Prepare for testing
	MYSQL_QUERY(admin_conn, "SET mysql-eventslog_buffer_history_size=1000000");
	MYSQL_QUERY(admin_conn, "SET mysql-eventslog_default_log=1");
	MYSQL_QUERY(admin_conn, "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(admin_conn, "DUMP EVENTSLOG FROM BUFFER TO BOTH");
	MYSQL_QUERY(admin_conn, "DELETE FROM stats_mysql_query_events");
	MYSQL_QUERY(admin_conn, "DELETE FROM history_mysql_query_events");



    MYSQL* proxy = mysql_init(NULL);
    if (!proxy) {
        diag("Failed to initialize MySQL connection to ProxySQL.");
        mysql_close(admin_conn); //Close admin connection before exiting.
        return -1;
    }

    if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        diag("Failed to connect to ProxySQL: %s", mysql_error(proxy));
        mysql_close(admin_conn);
        mysql_close(proxy);
        return -1;
    }


    // Run num_selects "SELECT 1" queries
    for (int i = 0; i < num_selects; ++i) {
        if (mysql_query(proxy, "SELECT 1")) {
            diag("Error executing 'SELECT 1' query (iteration %d): %s", i, mysql_error(proxy));
            mysql_close(admin_conn);
            mysql_close(proxy);
            return -1;
        }
        MYSQL_RES *result = mysql_store_result(proxy);
        if (result) mysql_free_result(result); //Clean up result if it exists
		if ((i+1)%10 == 0) { // avoid too much logging
        	ok(1, "SELECT 1 query successful (iteration %d)", i+1);
		}
    }

    // Test syntax error
    if (mysql_query(proxy, "SELEEEEECT 1")) {
        //Check if we received a syntax error (adjust error code as needed for your MySQL version).  
        int error_code = mysql_errno(proxy);
        ok(error_code == 1064, "Syntax error detected correctly (error code: %d)", error_code); //1064 is a common syntax error code
    } else {
        diag("Expected syntax error, but query succeeded.");
        mysql_close(admin_conn);
        mysql_close(proxy);
        return -1;
    }

    // Test hostgroup error
    if (mysql_query(proxy, "SELECT /* hostgroup=1234 */ 1")) {
        int error_code = mysql_errno(proxy);
        ok(error_code == 9001, "Hostgroup error detected correctly (error code: %d)", error_code);
    } else {
        diag("Expected hostgroup error (error code 9001), but query succeeded.");
        mysql_close(admin_conn);
        mysql_close(proxy);
        return -1;
    }

    // Test connection to non-existent schema with query
    MYSQL* nonExistentSchemaConn = mysql_init(NULL);
    if (!nonExistentSchemaConn) {
        diag("Failed to initialize MySQL connection for non-existent schema test.");
        mysql_close(admin_conn);
        mysql_close(proxy);
        return -1;
    }

    // Replace 'nonexistent_schema' with the actual name of a non-existent schema.
    if (!mysql_real_connect(nonExistentSchemaConn, cl.host, cl.username, cl.password, "nonexistent_schema", cl.port, NULL, 0)) {
        diag("Failed to connect to non-existent schema 'nonexistent_schema': %s", mysql_error(nonExistentSchemaConn));
        mysql_close(nonExistentSchemaConn);
        mysql_close(admin_conn);
        mysql_close(proxy);
        return -1;
    }

    if (mysql_query(nonExistentSchemaConn, "SELECT /* create_new_connection=1 */ 1")) {
        int error_code = mysql_errno(nonExistentSchemaConn);
        ok(error_code == 1044, "Query on non-existent schema returned expected error (1044): %d", error_code);
    } else {
        diag("Query on non-existent schema succeeded unexpectedly.");
        mysql_close(nonExistentSchemaConn);
        mysql_close(admin_conn);
        mysql_close(proxy);
        return -1;
    }

	// dump eventslog
	MYSQL_QUERY(admin_conn, "DUMP EVENTSLOG FROM BUFFER TO BOTH");


    // Expected results for both queries
    std::map<int, int> expectedResults = {
        {0, num_selects},
        {1064, 1},
        {9001, 1},
        {9002, 1}
    };

    // Test history_mysql_query_events
    bool historyCheck = checkQueryResult(admin_conn, "SELECT errno, COUNT(*) FROM history_mysql_query_events GROUP BY errno ORDER BY errno", expectedResults);
    ok(historyCheck, "history_mysql_query_events query results match expectation");

    // Test stats_mysql_query_events
    bool statsCheck = checkQueryResult(admin_conn, "SELECT errno, COUNT(*) FROM stats_mysql_query_events GROUP BY errno ORDER BY errno", expectedResults);
    ok(statsCheck, "stats_mysql_query_events query results match expectation");

    mysql_close(nonExistentSchemaConn);
    mysql_close(proxy);
    mysql_close(admin_conn);
    return exit_status();
}
