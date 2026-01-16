/**
 * @file reg_test_5233_set_warning-t.cpp
 * @brief Test for issue #5233: "Unable to parse multi-statements command with SET statement"
 * @details Tests that UPDATE statements with SET clauses don't trigger false SET statement warnings
 *
 * The issue is that queries like:
 *   UPDATE setting SET value = '3.5' WHERE setting_id = 'foo'; SELECT ROW_COUNT();
 * Trigger warning: "Unable to parse multi-statements command with SET statement"
 *
 * This happens because the code checks if digest_text starts with "SET ", but for
 * UPDATE statements, the digest text might start with "SET " after normalization.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using namespace std;

/**
 * @brief Get the digest text for a query from stats_mysql_query_digest
 * @param admin MySQL connection to admin interface
 * @param digest_text_to_find The digest text to look for
 * @return The actual digest text found, or empty string if not found
 */
string get_digest_text_from_stats(MYSQL* admin, const string& partial_digest) {
    string query = "SELECT digest_text FROM stats_mysql_query_digest WHERE digest_text LIKE '%" + partial_digest + "%'";

    if (mysql_query(admin, query.c_str())) {
        diag("Failed to query stats_mysql_query_digest: %s", mysql_error(admin));
        return "";
    }

    MYSQL_RES* res = mysql_store_result(admin);
    if (!res) {
        diag("Failed to store result for digest text query");
        return "";
    }

    string found_digest = "";
    MYSQL_ROW row;
    if ((row = mysql_fetch_row(res))) {
        found_digest = row[0] ? row[0] : "";
    }

    mysql_free_result(res);
    return found_digest;
}

int main(int argc, char** argv) {
    // Plan: 3 tests
    // 1. Test that warning appears (confirming bug exists)
    // 2. Check digest text in stats table
    // 3. Test with actual SET statement for comparison
    plan(3);

    CommandLine cl;

    if (cl.getEnv())
        return exit_status();

    // Get connections
    MYSQL* admin = mysql_init(NULL);
    if (!admin) {
        diag("Failed to initialize admin connection");
        return exit_status();
    }

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin));
        mysql_close(admin);
        return exit_status();
    }

    // Connect to MySQL proxy interface with multi-statements enabled
    MYSQL* proxy = mysql_init(NULL);
    if (!proxy) {
        diag("Failed to initialize proxy connection");
        mysql_close(admin);
        return exit_status();
    }

    // Enable multi-statements
    if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, "test", cl.port, NULL, CLIENT_MULTI_STATEMENTS)) {
        diag("Failed to connect to ProxySQL proxy: %s", mysql_error(proxy));
        mysql_close(admin);
        return exit_status();
    }

    // Get the log file path
    const string log_path { get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };
    diag("Using log file: %s", log_path.c_str());

    // Create test database and table
    MYSQL_QUERY(proxy, "CREATE DATABASE IF NOT EXISTS test");
    MYSQL_QUERY(proxy, "USE test");
    MYSQL_QUERY(proxy, "CREATE TABLE IF NOT EXISTS setting (setting_id VARCHAR(100) PRIMARY KEY, value VARCHAR(100))");
    MYSQL_QUERY(proxy, "INSERT IGNORE INTO setting (setting_id, value) VALUES ('foo', '1.0')");

    // Clear stats to start fresh
    MYSQL_QUERY(admin, "PROXYSQL FLUSH STATS");

    // Test 1: Execute the problematic UPDATE statement with multi-statement
    diag("Test 1: Executing problematic UPDATE statement with multi-statement");
    const string test_query = "UPDATE setting SET value = '3.5' WHERE setting_id = 'foo'; SELECT ROW_COUNT()";

    int rc = mysql_query(proxy, test_query.c_str());
    bool query_executed = (rc == 0);

    if (!query_executed) {
        diag("Query execution failed: %s", mysql_error(proxy));
        // Continue anyway - warning might still be logged during parsing
    } else {
        // Consume all results
        do {
            MYSQL_RES* result = mysql_store_result(proxy);
            if (result) {
                mysql_free_result(result);
            }
        } while (mysql_next_result(proxy) == 0);
    }

    // Wait for warning to be written to log
    usleep(500000); // 500ms

    // Check for the warning in the log
    const string warning_regex { ".*Unable to parse multi-statements command with SET statement.*" };
    const auto& [match_count, warning_lines] = get_matching_lines_from_filename(log_path, warning_regex, true, 50);

    // This is the bug: warning should NOT appear for UPDATE statements
    // But currently it does, so we expect match_count > 0
    bool warning_found = (match_count > 0);
    ok(warning_found, "UPDATE statement triggers SET warning (bug confirmed) - match_count: %zu", match_count);

    if (warning_found && match_count > 0) {
        for (const auto& match : warning_lines) {
            const string& line = get<1>(match);
            diag("Found warning: %s", line.c_str());
        }
    }

    // Test 2: Check digest text in stats table
    diag("Test 2: Checking digest text in stats table");

    // Wait a bit for stats to be updated
    usleep(200000); // 200ms

    // Get digest text for the UPDATE query
    string digest_text = get_digest_text_from_stats(admin, "setting");

    if (!digest_text.empty()) {
        diag("Found digest text: %s", digest_text.c_str());

        // Check if digest text starts with "SET "
        bool starts_with_set = (digest_text.size() >= 4 &&
                               (digest_text[0] == 'S' || digest_text[0] == 's') &&
                               (digest_text[1] == 'E' || digest_text[1] == 'e') &&
                               (digest_text[2] == 'T' || digest_text[2] == 't') &&
                               digest_text[3] == ' ');

        ok(starts_with_set, "Digest text starts with 'SET ' (explains the bug)");

        if (starts_with_set) {
            diag("BUG CONFIRMED: UPDATE statement digest text starts with 'SET ': '%s'", digest_text.c_str());
        } else {
            diag("Digest text doesn't start with 'SET ', something else is causing the warning");
        }
    } else {
        diag("Could not find digest text in stats table");
        ok(0, "Could not find digest text in stats table");
    }

    // Test 3: Execute actual SET statement for comparison
    diag("Test 3: Executing actual SET statement for comparison");

    // Clear stats again
    MYSQL_QUERY(admin, "PROXYSQL FLUSH STATS");

    // Execute a real multi-statement SET command
    const string set_query = "SET @test_var = 1; SELECT 1";
    rc = mysql_query(proxy, set_query.c_str());

    if (rc == 0) {
        // Consume results
        do {
            MYSQL_RES* result = mysql_store_result(proxy);
            if (result) {
                mysql_free_result(result);
            }
        } while (mysql_next_result(proxy) == 0);
    }

    // Wait for warning
    usleep(500000);

    // Check for warning again
    const auto& [set_match_count, set_warning_lines] = get_matching_lines_from_filename(log_path, warning_regex, true, 50);
    bool set_warning_found = (set_match_count > match_count); // Should have new warnings

    ok(set_warning_found, "Actual SET statement also triggers warning (expected) - new matches: %zu", set_match_count - match_count);

    // Cleanup
    MYSQL_QUERY(proxy, "DROP TABLE IF EXISTS test.setting");

    mysql_close(proxy);
    mysql_close(admin);

    return exit_status();
}