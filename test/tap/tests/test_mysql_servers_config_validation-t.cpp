/**
 * @file test_mysql_servers_config_validation-t.cpp
 * @brief Test pre-validation for PK violations in LOAD MYSQL SERVERS FROM CONFIG
 * 
 * This test validates the changes made to prevent primary key violations
 * when loading MySQL servers from configuration file. It tests:
 * 1. Duplicate primary key detection (hostgroup_id + hostname + port)
 * 2. Mandatory field validation (hostname, hostgroup_id)
 * 3. Proper error responses for validation failures
 * 4. Atomic operation behavior
 */

#include <cstring>
#include <string>
#include <fstream>
#include <unistd.h>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using std::string;
using std::vector;
using std::fstream;

/**
 * Create a config file with duplicate primary keys to test validation
 */
void create_invalid_config_file_with_duplicates(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "mysql_servers:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=3306\n";
    config_file << "        hostgroup=0\n";
    config_file << "        weight=900\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n"; // Same address
    config_file << "        port=3306\n";            // Same port
    config_file << "        hostgroup=0\n";          // Same hostgroup - DUPLICATE!
    config_file << "        weight=800\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Create a valid config file for testing successful loading
 */
void create_valid_config_file(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "mysql_servers:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=3306\n";
    config_file << "        hostgroup=0\n";
    config_file << "        weight=900\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=3307\n";            // Different port - VALID
    config_file << "        hostgroup=0\n";
    config_file << "        weight=800\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        address=\"192.168.1.1\"\n"; // Different address - VALID
    config_file << "        port=3306\n";
    config_file << "        hostgroup=0\n";
    config_file << "        weight=700\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Create a config file with missing mandatory fields
 */
void create_invalid_config_file_missing_fields(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "mysql_servers:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=3306\n";
    config_file << "        hostgroup=0\n";
    config_file << "        weight=900\n";
    config_file << "    },\n";
    config_file << "    {\n";
    // Missing address field - should cause validation error
    config_file << "        port=3307\n";
    config_file << "        hostgroup=1\n";
    config_file << "        weight=800\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Test that duplicate primary keys are properly detected and rejected
 */
int test_duplicate_pk_validation(MYSQL* admin, const string& config_file_path) {
    diag("Testing duplicate primary key validation");
    
    // Create config file with duplicate entries
    create_invalid_config_file_with_duplicates(config_file_path);
    
    // Set the config file path
    string set_config_cmd = "SET mysql-config_file='" + config_file_path + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    // Attempt to load servers from config - should fail
    int query_result = mysql_query(admin, "LOAD MYSQL SERVERS FROM CONFIG");
    
    // Should return error (non-zero)
    ok(query_result != 0, "LOAD MYSQL SERVERS FROM CONFIG should fail with duplicate PK");
    
    if (query_result != 0) {
        const char* error_msg = mysql_error(admin);
        diag("Error message: %s", error_msg);
        
        // Check that error message contains validation failure information
        ok(strstr(error_msg, "validation failed") != nullptr || 
           strstr(error_msg, "Configuration validation failed") != nullptr,
           "Error message should indicate validation failure");
    } else {
        // If query succeeded when it shouldn't have, fail the test
        ok(false, "Error message should indicate validation failure");
    }
    
    return EXIT_SUCCESS;
}

/**
 * Test that missing mandatory fields are properly detected
 */
int test_missing_fields_validation(MYSQL* admin, const string& config_file_path) {
    diag("Testing missing mandatory fields validation");
    
    // Create config file with missing fields
    create_invalid_config_file_missing_fields(config_file_path);
    
    // Set the config file path
    string set_config_cmd = "SET mysql-config_file='" + config_file_path + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    // Attempt to load servers from config - should fail
    int query_result = mysql_query(admin, "LOAD MYSQL SERVERS FROM CONFIG");
    
    // Should return error (non-zero)
    ok(query_result != 0, "LOAD MYSQL SERVERS FROM CONFIG should fail with missing mandatory fields");
    
    if (query_result != 0) {
        const char* error_msg = mysql_error(admin);
        diag("Error message: %s", error_msg);
        
        // Check that error message contains validation failure information
        ok(strstr(error_msg, "validation failed") != nullptr || 
           strstr(error_msg, "Configuration validation failed") != nullptr,
           "Error message should indicate validation failure");
    } else {
        // If query succeeded when it shouldn't have, fail the test
        ok(false, "Error message should indicate validation failure");
    }
    
    return EXIT_SUCCESS;
}

/**
 * Test that valid configuration loads successfully
 */
int test_valid_config_loading(MYSQL* admin, const string& config_file_path) {
    diag("Testing valid configuration loading");
    
    // Create valid config file
    create_valid_config_file(config_file_path);
    
    // Set the config file path
    string set_config_cmd = "SET mysql-config_file='" + config_file_path + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    // Clear existing servers first
    MYSQL_QUERY_T(admin, "DELETE FROM mysql_servers");
    MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");
    
    // Load servers from config - should succeed
    int query_result = mysql_query(admin, "LOAD MYSQL SERVERS FROM CONFIG");
    
    // Should succeed (return 0)
    ok(query_result == 0, "LOAD MYSQL SERVERS FROM CONFIG should succeed with valid config");
    
    if (query_result == 0) {
        // Verify that servers were actually loaded
        MYSQL_QUERY_T(admin, "SELECT * FROM mysql_servers");
        MYSQL_RES* result = mysql_store_result(admin);
        int num_rows = mysql_num_rows(result);
        mysql_free_result(result);
        
        ok(num_rows == 3, "Should have loaded 3 servers from valid config");
        diag("Loaded %d servers from config", num_rows);
    } else {
        const char* error_msg = mysql_error(admin);
        diag("Unexpected error: %s", error_msg);
        ok(false, "Should have loaded 3 servers from valid config");
    }
    
    return EXIT_SUCCESS;
}

/**
 * Test atomic operation behavior - either all entries load or none do
 */
int test_atomic_operation(MYSQL* admin, const string& config_file_path) {
    diag("Testing atomic operation behavior");
    
    // Clear existing servers
    MYSQL_QUERY_T(admin, "DELETE FROM mysql_servers");
    MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");
    
    // Verify no servers exist
    MYSQL_QUERY_T(admin, "SELECT * FROM mysql_servers");
    MYSQL_RES* result = mysql_store_result(admin);
    int initial_count = mysql_num_rows(result);
    mysql_free_result(result);
    
    ok(initial_count == 0, "Should start with no servers");
    
    // Create config file with duplicate entries
    create_invalid_config_file_with_duplicates(config_file_path);
    
    string set_config_cmd = "SET mysql-config_file='" + config_file_path + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    // Attempt to load - should fail
    int query_result = mysql_query(admin, "LOAD MYSQL SERVERS FROM CONFIG");
    ok(query_result != 0, "Config loading should fail due to validation errors");
    
    // Verify that NO servers were added (atomic operation)
    MYSQL_QUERY_T(admin, "SELECT * FROM mysql_servers");
    result = mysql_store_result(admin);
    int final_count = mysql_num_rows(result);
    mysql_free_result(result);
    
    ok(final_count == 0, "No servers should be added when validation fails (atomic operation)");
    diag("Server count after failed load: %d", final_count);
    
    return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
    CommandLine cl;
    
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }
    
    plan(9); // Expecting 9 test assertions
    
    MYSQL* mysql = mysql_init(NULL);
    if (!mysql) {
        fprintf(stderr, "Failed to initialize MySQL client\n");
        return exit_status();
    }
    
    if (!mysql_real_connect(mysql, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
        return exit_status();
    }
    
    string config_file_path = "/tmp/test_proxysql_config.cnf";
    
    // Test 1: Duplicate primary key validation
    test_duplicate_pk_validation(mysql, config_file_path);
    
    // Test 2: Missing mandatory fields validation  
    test_missing_fields_validation(mysql, config_file_path);
    
    // Test 3: Valid configuration loading
    test_valid_config_loading(mysql, config_file_path);
    
    // Test 4: Atomic operation behavior
    test_atomic_operation(mysql, config_file_path);
    
    // Clean up
    unlink(config_file_path.c_str());
    mysql_close(mysql);
    
    return exit_status();
}