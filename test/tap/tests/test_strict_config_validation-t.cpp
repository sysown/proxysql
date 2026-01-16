/**
 * @file test_strict_config_validation-t.cpp
 * @brief Test --strict flag configuration validation at runtime
 *
 * This test validates the configuration validation framework including:
 * - Detection of unknown configuration fields (with typo suggestions)
 * - Invalid regex pattern detection
 * - Runtime validation for LOAD ... FROM CONFIG commands
 */

#include <cstddef>
#include <cstring>
#include <string>
#include <fstream>
#include <unistd.h>
#include "mysql.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using std::string;
using std::fstream;

// Helper function to create config file with content
void create_config_file(const string& config_file_path, const string& config_content) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    config_file << config_content;
    config_file.close();
}

// Config with typo in mysql_servers (adddress instead of address)
const char* config_server_typo = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

mysql_servers:
(
    {
        adddress = "127.0.0.1"
        port = 3306
        hostgroup_id = 1
        weight = 100
        max_connections = 1000
        status = "ONLINE"
        comment = "Server with typo"
    }
)
)";

// Config with typo in mysql_query_rules (mathc_pattern instead of match_pattern)
const char* config_query_rule_typo = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

mysql_query_rules:
(
    {
        rule_id = 1
        active = 1
        match_digest = "^SELECT.*FOR UPDATE"
        destination_hostgroup = 1
        apply = 1
    },
    {
        rule_id = 100
        active = 1
        mathc_pattern = "SELECT"
        destination_hostgroup = 1
        apply = 1
    }
)
)";

// Config with invalid regex patterns
const char* config_invalid_regex = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

mysql_query_rules:
(
    {
        rule_id = 1
        active = 1
        match_pattern = "(?unclosed"
        destination_hostgroup = 1
        apply = 1
    },
    {
        rule_id = 2
        active = 1
        match_pattern = "[unclosed"
        destination_hostgroup = 1
        apply = 1
    },
    {
        rule_id = 3
        active = 1
        match_pattern = "SELECT.*FROM"  // Valid regex
        destination_hostgroup = 1
        apply = 1
    }
)
)";

// Valid config for comparison
const char* config_valid_servers = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

mysql_servers:
(
    {
        address = "127.0.0.1"
        port = 3306
        hostgroup_id = 1
        weight = 100
        max_connections = 1000
        status = "ONLINE"
        comment = "Server 1"
    },
    {
        address = "127.0.0.2"
        port = 3306
        hostgroup_id = 1
        weight = 100
        max_connections = 1000
        status = "ONLINE"
        comment = "Server 2"
    }
)
)";

// Valid query rules config
const char* config_valid_query_rules = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

mysql_query_rules:
(
    {
        rule_id = 1
        active = 1
        match_digest = "^SELECT.*FOR UPDATE"
        destination_hostgroup = 1
        apply = 1
    },
    {
        rule_id = 2
        active = 1
        match_pattern = "SELECT.*FROM"
        destination_hostgroup = 1
        apply = 1
    }
)
)";

int main(int argc, char** argv) {
    CommandLine cl;

    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }

    // Plan: 10 tests total
    plan(10);

    MYSQL* admin = mysql_init(NULL);
    if (!admin) {
        diag("Failed to initialize MySQL client");
        return exit_status();
    }

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin));
        mysql_close(admin);
        return exit_status();
    }

    string config_file = "/tmp/proxysql_strict_validation_test.cfg";

    // ====================================================================
    // Test Group 1: Valid Configuration Tests
    // ====================================================================
    diag("Test Group 1: Valid configuration should load successfully");

    create_config_file(config_file, config_valid_servers);

    string set_config_cmd = "PROXYSQL SET CONFIG FILE '" + config_file + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    // Clean up existing entries
    MYSQL_QUERY_T(admin, "DELETE FROM mysql_servers");

    // Load valid config - should succeed
    int result = mysql_query(admin, "LOAD MYSQL SERVERS FROM CONFIG");
    ok(result == 0, "Valid mysql_servers config loads successfully");

    // Verify entries were loaded
    if (result == 0) {
        MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM mysql_servers");
        MYSQL_RES* res = mysql_store_result(admin);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            int count = row ? atoi(row[0]) : 0;
            ok(count == 2, "Correct number of servers loaded: %d", count);
            mysql_free_result(res);
        } else {
            ok(false, "Failed to query mysql_servers");
        }
    } else {
        skip(1, "Previous test failed");
    }

    MYSQL_QUERY_T(admin, "DELETE FROM mysql_servers");

    // ====================================================================
    // Test Group 2: Typo Detection Tests
    // ====================================================================
    diag("Test Group 2: Typos should be detected with warnings");

    create_config_file(config_file, config_server_typo);
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    // In non-strict mode, should succeed but with warning
    result = mysql_query(admin, "LOAD MYSQL SERVERS FROM CONFIG");
    const char* error = mysql_error(admin);

    // The LOAD command should succeed (warning only, not error)
    ok(result == 0, "Config with typo loads with warning in non-strict mode");

    // Check that no servers were loaded (invalid entry skipped)
    MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM mysql_servers");
    MYSQL_RES* res = mysql_store_result(admin);
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        int count = row ? atoi(row[0]) : 0;
        ok(count == 0, "Invalid entry not loaded: %d servers", count);
        mysql_free_result(res);
    } else {
        ok(false, "Failed to query mysql_servers");
    }

    // ====================================================================
    // Test Group 3: Query Rule Typo Detection
    // ====================================================================
    diag("Test Group 3: Query rule typos should be detected");

    MYSQL_QUERY_T(admin, "DELETE FROM mysql_query_rules");

    create_config_file(config_file, config_query_rule_typo);
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    result = mysql_query(admin, "LOAD MYSQL QUERY RULES FROM CONFIG");
    ok(result == 0, "Query rules with typo load with warning");

    // Verify only the valid rule was loaded
    MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM mysql_query_rules");
    res = mysql_store_result(admin);
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        int count = row ? atoi(row[0]) : 0;
        ok(count == 1, "Only valid rule loaded, invalid skipped: %d rules", count);
        mysql_free_result(res);
    } else {
        ok(false, "Failed to query mysql_query_rules");
    }

    MYSQL_QUERY_T(admin, "DELETE FROM mysql_query_rules");

    // ====================================================================
    // Test Group 4: Invalid Regex Pattern Detection
    // ====================================================================
    diag("Test Group 4: Invalid regex patterns should be detected");

    create_config_file(config_file, config_invalid_regex);
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    result = mysql_query(admin, "LOAD MYSQL QUERY RULES FROM CONFIG");
    ok(result == 0, "Query rules with invalid regex load with warnings");

    // Verify only the valid rule was loaded
    MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM mysql_query_rules");
    res = mysql_store_result(admin);
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        int count = row ? atoi(row[0]) : 0;
        ok(count == 1, "Only valid regex rule loaded: %d rules", count);
        mysql_free_result(res);
    } else {
        ok(false, "Failed to query mysql_query_rules");
    }

    MYSQL_QUERY_T(admin, "DELETE FROM mysql_query_rules");

    // ====================================================================
    // Test Group 5: Valid Query Rules
    // ====================================================================
    diag("Test Group 5: Valid query rules should load correctly");

    create_config_file(config_file, config_valid_query_rules);
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    result = mysql_query(admin, "LOAD MYSQL QUERY RULES FROM CONFIG");
    ok(result == 0, "Valid query rules load successfully");

    MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM mysql_query_rules");
    res = mysql_store_result(admin);
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        int count = row ? atoi(row[0]) : 0;
        ok(count == 2, "All valid rules loaded: %d rules", count);
        mysql_free_result(res);
    } else {
        ok(false, "Failed to query mysql_query_rules");
    }

    MYSQL_QUERY_T(admin, "DELETE FROM mysql_query_rules");

    // Cleanup
    unlink(config_file.c_str());
    mysql_close(admin);

    return exit_status();
}
