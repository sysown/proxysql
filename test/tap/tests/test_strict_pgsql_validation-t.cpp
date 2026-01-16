/**
 * @file test_strict_pgsql_validation-t.cpp
 * @brief Test PostgreSQL configuration validation
 *
 * This test validates the configuration validation framework for PostgreSQL:
 * - Detection of unknown configuration fields
 * - Runtime validation for LOAD PGSQL ... FROM CONFIG commands
 *
 * Note: These tests are mode-agnostic - they test observable behavior
 * (invalid entries are skipped, valid entries are loaded) regardless of
 * whether ProxySQL is running in strict mode or not.
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

// Valid pgsql_servers config
const char* config_valid_pgsql_servers = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

pgsql_servers:
(
    {
        address = "127.0.0.1"
        port = 5432
        hostgroup_id = 1
        weight = 100
        max_connections = 1000
        status = "ONLINE"
        comment = "PostgreSQL server 1"
    },
    {
        address = "127.0.0.2"
        port = 5432
        hostgroup_id = 1
        weight = 100
        max_connections = 1000
        status = "ONLINE"
        comment = "PostgreSQL server 2"
    }
)
)";

// Config with typo in pgsql_servers
const char* config_pgsql_server_typo = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

pgsql_servers:
(
    {
        adddress = "127.0.0.1"
        port = 5432
        hostgroup_id = 1
        weight = 100
        max_connections = 1000
        status = "ONLINE"
        comment = "Server with typo"
    }
)
)";

// Valid pgsql_users config
const char* config_valid_pgsql_users = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

pgsql_users:
(
    {
        username = "postgres"
        password = "postgres"
        default_hostgroup = 1
        default_schema = "postgres"
        backend = 1
        frontend = 1
    },
    {
        username = "testuser"
        password = "testpass"
        default_hostgroup = 1
        default_schema = "testdb"
        backend = 1
        frontend = 1
    }
)
)";

// Config with typo in pgsql_users
const char* config_pgsql_user_typo = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

pgsql_users:
(
    {
        usrename = "postgres"
        password = "postgres"
        default_hostgroup = 1
        backend = 1
        frontend = 1
    }
)
)";

// Valid pgsql_query_rules config
const char* config_valid_pgsql_query_rules = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

pgsql_query_rules:
(
    {
        rule_id = 1
        active = 1
        match_pattern = "SELECT.*FOR UPDATE"
        destination_hostgroup = 1
        apply = 1
    },
    {
        rule_id = 2
        active = 1
        match_digest = "^SELECT.*FROM"
        destination_hostgroup = 1
        apply = 1
    }
)
)";

// Config with typo in pgsql_query_rules
const char* config_pgsql_query_rule_typo = R"(
datadir="/tmp"
errorlog="/tmp/proxysql_test.log"

pgsql_query_rules:
(
    {
        rule_id = 1
        active = 1
        match_pattern = "SELECT.*FOR UPDATE"
        destination_hostgroup = 1
        apply = 1
    },
    {
        rule_id = 2
        active = 1
        mathc_pattern = "SELECT"
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

    // Plan: 12 tests total
    plan(12);

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

    string config_file = "/tmp/proxysql_pgsql_validation_test.cfg";

    // ====================================================================
    // Test Group 1: Valid pgsql_servers Configuration
    // ====================================================================
    diag("Test Group 1: Valid pgsql_servers configuration");

    create_config_file(config_file, config_valid_pgsql_servers);

    string set_config_cmd = "PROXYSQL SET CONFIG FILE '" + config_file + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_servers");

    int result = mysql_query(admin, "LOAD PGSQL SERVERS FROM CONFIG");
    diag("LOAD PGSQL SERVERS FROM CONFIG result: %d", result);

    // Check behavior based on result
    if (result == 0) {
        MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM pgsql_servers");
        MYSQL_RES* res = mysql_store_result(admin);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            int count = row ? atoi(row[0]) : 0;
            ok(count == 2, "Valid config: 2 pgsql servers loaded, got %d", count);
            mysql_free_result(res);
        } else {
            ok(false, "Failed to query pgsql_servers");
        }
    } else {
        MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM pgsql_servers");
        MYSQL_RES* res = mysql_store_result(admin);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            int count = row ? atoi(row[0]) : 0;
            ok(count == 0, "Strict mode: load failed, 0 pgsql servers loaded, got %d", count);
            mysql_free_result(res);
        } else {
            ok(false, "Failed to query pgsql_servers");
        }
    }

    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_servers");

    // ====================================================================
    // Test Group 2: pgsql_servers Typo Detection
    // ====================================================================
    diag("Test Group 2: pgsql_servers with typo - invalid entry skipped");

    create_config_file(config_file, config_pgsql_server_typo);
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    result = mysql_query(admin, "LOAD PGSQL SERVERS FROM CONFIG");
    diag("LOAD PGSQL SERVERS FROM CONFIG result: %d", result);

    // Verify invalid entry was not loaded
    MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM pgsql_servers");
    MYSQL_RES* res = mysql_store_result(admin);
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        int count = row ? atoi(row[0]) : 0;
        ok(count == 0, "Config with typo: 0 pgsql servers loaded (invalid entry skipped), got %d", count);
        mysql_free_result(res);
    } else {
        ok(false, "Failed to query pgsql_servers");
    }

    // ====================================================================
    // Test Group 3: Valid pgsql_users Configuration
    // ====================================================================
    diag("Test Group 3: Valid pgsql_users configuration");

    create_config_file(config_file, config_valid_pgsql_users);
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_users");

    result = mysql_query(admin, "LOAD PGSQL USERS FROM CONFIG");
    diag("LOAD PGSQL USERS FROM CONFIG result: %d", result);

    if (result == 0) {
        MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM pgsql_users");
        res = mysql_store_result(admin);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            int count = row ? atoi(row[0]) : 0;
            ok(count == 2, "Valid config: 2 pgsql users loaded, got %d", count);
            mysql_free_result(res);
        } else {
            ok(false, "Failed to query pgsql_users");
        }
    } else {
        MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM pgsql_users");
        res = mysql_store_result(admin);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            int count = row ? atoi(row[0]) : 0;
            ok(count == 0, "Strict mode: load failed, 0 pgsql users loaded, got %d", count);
            mysql_free_result(res);
        } else {
            ok(false, "Failed to query pgsql_users");
        }
    }

    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_users");

    // ====================================================================
    // Test Group 4: pgsql_users Typo Detection
    // ====================================================================
    diag("Test Group 4: pgsql_users with typo - invalid entry skipped");

    create_config_file(config_file, config_pgsql_user_typo);
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    result = mysql_query(admin, "LOAD PGSQL USERS FROM CONFIG");
    diag("LOAD PGSQL USERS FROM CONFIG result: %d", result);

    MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM pgsql_users");
    res = mysql_store_result(admin);
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        int count = row ? atoi(row[0]) : 0;
        ok(count == 0, "Config with typo: 0 pgsql users loaded (invalid entry skipped), got %d", count);
        mysql_free_result(res);
    } else {
        ok(false, "Failed to query pgsql_users");
    }

    // ====================================================================
    // Test Group 5: Valid pgsql_query_rules Configuration
    // ====================================================================
    diag("Test Group 5: Valid pgsql_query_rules configuration");

    create_config_file(config_file, config_valid_pgsql_query_rules);
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_query_rules");

    result = mysql_query(admin, "LOAD PGSQL QUERY RULES FROM CONFIG");
    diag("LOAD PGSQL QUERY RULES FROM CONFIG result: %d", result);

    if (result == 0) {
        MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM pgsql_query_rules");
        res = mysql_store_result(admin);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            int count = row ? atoi(row[0]) : 0;
            ok(count == 2, "Valid config: 2 pgsql rules loaded, got %d", count);
            mysql_free_result(res);
        } else {
            ok(false, "Failed to query pgsql_query_rules");
        }
    } else {
        MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM pgsql_query_rules");
        res = mysql_store_result(admin);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            int count = row ? atoi(row[0]) : 0;
            ok(count == 0, "Strict mode: load failed, 0 pgsql rules loaded, got %d", count);
            mysql_free_result(res);
        } else {
            ok(false, "Failed to query pgsql_query_rules");
        }
    }

    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_query_rules");

    // ====================================================================
    // Test Group 6: pgsql_query_rules Typo Detection
    // ====================================================================
    diag("Test Group 6: pgsql_query_rules with typo - mixed valid/invalid");

    create_config_file(config_file, config_pgsql_query_rule_typo);
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    result = mysql_query(admin, "LOAD PGSQL QUERY RULES FROM CONFIG");
    diag("LOAD PGSQL QUERY RULES FROM CONFIG result: %d", result);

    // Verify only the valid rule was loaded
    MYSQL_QUERY_T(admin, "SELECT COUNT(*) FROM pgsql_query_rules");
    res = mysql_store_result(admin);
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        int count = row ? atoi(row[0]) : 0;
        ok(count == 1, "Mixed config: 1 valid pgsql rule loaded (invalid skipped), got %d", count);
        mysql_free_result(res);
    } else {
        ok(false, "Failed to query pgsql_query_rules");
    }

    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_query_rules");

    // Cleanup
    unlink(config_file.c_str());
    mysql_close(admin);

    return exit_status();
}
