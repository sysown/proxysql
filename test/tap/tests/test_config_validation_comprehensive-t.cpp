/**
 * @file test_config_validation_comprehensive-t.cpp
 * @brief Comprehensive test for all config validation changes
 * 
 * This test validates the comprehensive changes made to prevent primary key violations
 * and mandatory field validation across all config sections:
 * 1. MySQL Servers validation (original fix)
 * 2. MySQL Users validation  
 * 3. ProxySQL Servers validation
 * 4. PostgreSQL Servers validation
 * 5. PostgreSQL Users validation
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
 * Create config file with duplicate MySQL users to test validation
 */
void create_invalid_mysql_users_config(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "mysql_users:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        username=\"testuser\"\n";
    config_file << "        password=\"testpass\"\n";
    config_file << "        backend=1\n";
    config_file << "        default_hostgroup=0\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        username=\"testuser\"\n";   // Same username
    config_file << "        password=\"different\"\n";
    config_file << "        backend=1\n";              // Same backend - DUPLICATE!
    config_file << "        default_hostgroup=1\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Create config file with missing username in MySQL users
 */
void create_invalid_mysql_users_missing_username(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "mysql_users:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        username=\"validuser\"\n";
    config_file << "        password=\"testpass\"\n";
    config_file << "        backend=1\n";
    config_file << "        default_hostgroup=0\n";
    config_file << "    },\n";
    config_file << "    {\n";
    // Missing username field - should cause validation error
    config_file << "        password=\"testpass2\"\n";
    config_file << "        backend=2\n";
    config_file << "        default_hostgroup=1\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Create config file with duplicate ProxySQL servers
 */
void create_invalid_proxysql_servers_config(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "proxysql_servers:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=6032\n";
    config_file << "        weight=1000\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";  // Same address
    config_file << "        port=6032\n";             // Same port - DUPLICATE!
    config_file << "        weight=900\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Create config file with missing port in ProxySQL servers
 */
void create_invalid_proxysql_servers_missing_port(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "proxysql_servers:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=6032\n";
    config_file << "        weight=1000\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        address=\"192.168.1.1\"\n";
    // Missing port field - should cause validation error
    config_file << "        weight=900\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Create config file with duplicate PostgreSQL servers
 */
void create_invalid_pgsql_servers_config(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "pgsql_servers:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=5432\n";
    config_file << "        hostgroup=0\n";
    config_file << "        weight=1000\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";  // Same address
    config_file << "        port=5432\n";             // Same port  
    config_file << "        hostgroup=0\n";          // Same hostgroup - DUPLICATE!
    config_file << "        weight=900\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Create config file with missing hostgroup in PostgreSQL servers
 */
void create_invalid_pgsql_servers_missing_hostgroup(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "pgsql_servers:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=5432\n";
    config_file << "        hostgroup=0\n";
    config_file << "        weight=1000\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        address=\"192.168.1.1\"\n";
    config_file << "        port=5433\n";
    // Missing hostgroup field - should cause validation error
    config_file << "        weight=900\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Create config file with duplicate PostgreSQL users
 */
void create_invalid_pgsql_users_config(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "pgsql_users:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        username=\"pguser\"\n";
    config_file << "        password=\"pgpass\"\n";
    config_file << "        backend=1\n";
    config_file << "        default_hostgroup=0\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        username=\"pguser\"\n";   // Same username
    config_file << "        password=\"different\"\n";
    config_file << "        backend=1\n";           // Same backend - DUPLICATE!
    config_file << "        default_hostgroup=1\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Create config file with missing username in PostgreSQL users
 */
void create_invalid_pgsql_users_missing_username(const string& config_file_path) {
    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    
    config_file << "datadir=\"/tmp\"\n";
    config_file << "errorlog=\"/tmp/proxysql.log\"\n";
    config_file << "\n";
    config_file << "pgsql_users:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        username=\"validpguser\"\n";
    config_file << "        password=\"pgpass\"\n";
    config_file << "        backend=1\n";
    config_file << "        default_hostgroup=0\n";
    config_file << "    },\n";
    config_file << "    {\n";
    // Missing username field - should cause validation error
    config_file << "        password=\"pgpass2\"\n";
    config_file << "        backend=2\n";
    config_file << "        default_hostgroup=1\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Create valid config file with all sections
 */
void create_valid_comprehensive_config(const string& config_file_path) {
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
    config_file << "        port=3307\n";  // Different port - VALID
    config_file << "        hostgroup=0\n";
    config_file << "        weight=800\n";
    config_file << "    }\n";
    config_file << ")\n";
    config_file << "\n";
    config_file << "mysql_users:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        username=\"user1\"\n";
    config_file << "        password=\"pass1\"\n";
    config_file << "        backend=1\n";
    config_file << "        default_hostgroup=0\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        username=\"user2\"\n";  // Different username - VALID
    config_file << "        password=\"pass2\"\n";
    config_file << "        backend=1\n";
    config_file << "        default_hostgroup=0\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        username=\"user1\"\n";  // Same username
    config_file << "        password=\"pass3\"\n";
    config_file << "        backend=2\n";          // Different backend - VALID
    config_file << "        default_hostgroup=1\n";
    config_file << "    }\n";
    config_file << ")\n";
    config_file << "\n";
    config_file << "proxysql_servers:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=6032\n";
    config_file << "        weight=1000\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        address=\"192.168.1.1\"\n";  // Different address - VALID
    config_file << "        port=6032\n";
    config_file << "        weight=900\n";
    config_file << "    }\n";
    config_file << ")\n";
    config_file << "\n";
    config_file << "pgsql_servers:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=5432\n";
    config_file << "        hostgroup=0\n";
    config_file << "        weight=1000\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        address=\"127.0.0.1\"\n";
    config_file << "        port=5433\n";  // Different port - VALID
    config_file << "        hostgroup=0\n";
    config_file << "        weight=900\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        address=\"192.168.1.1\"\n";  // Different address - VALID
    config_file << "        port=5432\n";
    config_file << "        hostgroup=1\n";  // Different hostgroup - VALID
    config_file << "        weight=800\n";
    config_file << "    }\n";
    config_file << ")\n";
    config_file << "\n";
    config_file << "pgsql_users:\n";
    config_file << "(\n";
    config_file << "    {\n";
    config_file << "        username=\"pguser1\"\n";
    config_file << "        password=\"pgpass1\"\n";
    config_file << "        backend=1\n";
    config_file << "        default_hostgroup=0\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        username=\"pguser2\"\n";  // Different username - VALID
    config_file << "        password=\"pgpass2\"\n";
    config_file << "        backend=1\n";
    config_file << "        default_hostgroup=0\n";
    config_file << "    },\n";
    config_file << "    {\n";
    config_file << "        username=\"pguser1\"\n";  // Same username
    config_file << "        password=\"pgpass3\"\n";
    config_file << "        backend=2\n";          // Different backend - VALID
    config_file << "        default_hostgroup=1\n";
    config_file << "    }\n";
    config_file << ")\n";
    
    config_file.close();
}

/**
 * Test MySQL users validation
 */
int test_mysql_users_validation(MYSQL* admin, const string& config_file_path) {
    diag("Testing MySQL users validation");
    
    // Test duplicate users
    create_invalid_mysql_users_config(config_file_path);
    
    string set_config_cmd = "SET mysql-config_file='" + config_file_path + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    int query_result = mysql_query(admin, "LOAD MYSQL USERS FROM CONFIG");
    ok(query_result != 0, "LOAD MYSQL USERS FROM CONFIG should fail with duplicate users");
    
    if (query_result != 0) {
        const char* error_msg = mysql_error(admin);
        diag("Error message: %s", error_msg);
        ok(strstr(error_msg, "validation failed") != nullptr || 
           strstr(error_msg, "Configuration validation failed") != nullptr ||
           strstr(error_msg, "duplicate user entry") != nullptr,
           "Error message should indicate user validation failure");
    } else {
        ok(false, "Error message should indicate user validation failure");
    }
    
    // Test missing username
    create_invalid_mysql_users_missing_username(config_file_path);
    
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    query_result = mysql_query(admin, "LOAD MYSQL USERS FROM CONFIG");
    ok(query_result != 0, "LOAD MYSQL USERS FROM CONFIG should fail with missing username");
    
    return EXIT_SUCCESS;
}

/**
 * Test ProxySQL servers validation
 */
int test_proxysql_servers_validation(MYSQL* admin, const string& config_file_path) {
    diag("Testing ProxySQL servers validation");
    
    // Test duplicate servers
    create_invalid_proxysql_servers_config(config_file_path);
    
    string set_config_cmd = "SET mysql-config_file='" + config_file_path + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    int query_result = mysql_query(admin, "LOAD PROXYSQL SERVERS FROM CONFIG");
    ok(query_result != 0, "LOAD PROXYSQL SERVERS FROM CONFIG should fail with duplicate servers");
    
    if (query_result != 0) {
        const char* error_msg = mysql_error(admin);
        diag("Error message: %s", error_msg);
        ok(strstr(error_msg, "validation failed") != nullptr || 
           strstr(error_msg, "Configuration validation failed") != nullptr ||
           strstr(error_msg, "duplicate server entry") != nullptr,
           "Error message should indicate server validation failure");
    } else {
        ok(false, "Error message should indicate server validation failure");
    }
    
    // Test missing port
    create_invalid_proxysql_servers_missing_port(config_file_path);
    
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    query_result = mysql_query(admin, "LOAD PROXYSQL SERVERS FROM CONFIG");
    ok(query_result != 0, "LOAD PROXYSQL SERVERS FROM CONFIG should fail with missing port");
    
    return EXIT_SUCCESS;
}

/**
 * Test PostgreSQL servers validation
 */
int test_pgsql_servers_validation(MYSQL* admin, const string& config_file_path) {
    diag("Testing PostgreSQL servers validation");
    
    // Test duplicate servers
    create_invalid_pgsql_servers_config(config_file_path);
    
    string set_config_cmd = "SET mysql-config_file='" + config_file_path + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    int query_result = mysql_query(admin, "LOAD PGSQL SERVERS FROM CONFIG");
    ok(query_result != 0, "LOAD PGSQL SERVERS FROM CONFIG should fail with duplicate servers");
    
    if (query_result != 0) {
        const char* error_msg = mysql_error(admin);
        diag("Error message: %s", error_msg);
        ok(strstr(error_msg, "validation failed") != nullptr || 
           strstr(error_msg, "Configuration validation failed") != nullptr ||
           strstr(error_msg, "duplicate entry") != nullptr,
           "Error message should indicate server validation failure");
    } else {
        ok(false, "Error message should indicate server validation failure");
    }
    
    // Test missing hostgroup
    create_invalid_pgsql_servers_missing_hostgroup(config_file_path);
    
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    query_result = mysql_query(admin, "LOAD PGSQL SERVERS FROM CONFIG");
    ok(query_result != 0, "LOAD PGSQL SERVERS FROM CONFIG should fail with missing hostgroup");
    
    return EXIT_SUCCESS;
}

/**
 * Test PostgreSQL users validation
 */
int test_pgsql_users_validation(MYSQL* admin, const string& config_file_path) {
    diag("Testing PostgreSQL users validation");
    
    // Test duplicate users
    create_invalid_pgsql_users_config(config_file_path);
    
    string set_config_cmd = "SET mysql-config_file='" + config_file_path + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    int query_result = mysql_query(admin, "LOAD PGSQL USERS FROM CONFIG");
    ok(query_result != 0, "LOAD PGSQL USERS FROM CONFIG should fail with duplicate users");
    
    if (query_result != 0) {
        const char* error_msg = mysql_error(admin);
        diag("Error message: %s", error_msg);
        ok(strstr(error_msg, "validation failed") != nullptr || 
           strstr(error_msg, "Configuration validation failed") != nullptr ||
           strstr(error_msg, "duplicate user entry") != nullptr,
           "Error message should indicate user validation failure");
    } else {
        ok(false, "Error message should indicate user validation failure");
    }
    
    // Test missing username
    create_invalid_pgsql_users_missing_username(config_file_path);
    
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    query_result = mysql_query(admin, "LOAD PGSQL USERS FROM CONFIG");
    ok(query_result != 0, "LOAD PGSQL USERS FROM CONFIG should fail with missing username");
    
    return EXIT_SUCCESS;
}

/**
 * Test that comprehensive valid config loads successfully
 */
int test_comprehensive_valid_config(MYSQL* admin, const string& config_file_path) {
    diag("Testing comprehensive valid configuration loading");
    
    create_valid_comprehensive_config(config_file_path);
    
    string set_config_cmd = "SET mysql-config_file='" + config_file_path + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());
    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    // Clear existing data first
    MYSQL_QUERY_T(admin, "DELETE FROM mysql_servers");
    MYSQL_QUERY_T(admin, "DELETE FROM mysql_users");
    MYSQL_QUERY_T(admin, "DELETE FROM proxysql_servers");
    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_servers");
    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_users");
    MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");
    MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");
    MYSQL_QUERY_T(admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
    MYSQL_QUERY_T(admin, "LOAD PGSQL SERVERS TO RUNTIME");
    MYSQL_QUERY_T(admin, "LOAD PGSQL USERS TO RUNTIME");
    
    // Load MySQL servers
    int query_result = mysql_query(admin, "LOAD MYSQL SERVERS FROM CONFIG");
    ok(query_result == 0, "LOAD MYSQL SERVERS FROM CONFIG should succeed with valid config");
    
    // Load MySQL users
    query_result = mysql_query(admin, "LOAD MYSQL USERS FROM CONFIG");
    ok(query_result == 0, "LOAD MYSQL USERS FROM CONFIG should succeed with valid config");
    
    // Load ProxySQL servers
    query_result = mysql_query(admin, "LOAD PROXYSQL SERVERS FROM CONFIG");
    ok(query_result == 0, "LOAD PROXYSQL SERVERS FROM CONFIG should succeed with valid config");
    
    // Load PostgreSQL servers
    query_result = mysql_query(admin, "LOAD PGSQL SERVERS FROM CONFIG");
    ok(query_result == 0, "LOAD PGSQL SERVERS FROM CONFIG should succeed with valid config");
    
    // Load PostgreSQL users
    query_result = mysql_query(admin, "LOAD PGSQL USERS FROM CONFIG");
    ok(query_result == 0, "LOAD PGSQL USERS FROM CONFIG should succeed with valid config");
    
    // Verify data was loaded
    MYSQL_QUERY_T(admin, "SELECT * FROM mysql_servers");
    MYSQL_RES* result = mysql_store_result(admin);
    int server_count = mysql_num_rows(result);
    mysql_free_result(result);
    ok(server_count == 2, "Should have loaded 2 MySQL servers");
    
    MYSQL_QUERY_T(admin, "SELECT * FROM mysql_users");
    result = mysql_store_result(admin);
    int user_count = mysql_num_rows(result);
    mysql_free_result(result);
    ok(user_count == 3, "Should have loaded 3 MySQL users");
    
    MYSQL_QUERY_T(admin, "SELECT * FROM proxysql_servers");
    result = mysql_store_result(admin);
    int proxysql_count = mysql_num_rows(result);
    mysql_free_result(result);
    ok(proxysql_count == 2, "Should have loaded 2 ProxySQL servers");
    
    MYSQL_QUERY_T(admin, "SELECT * FROM pgsql_servers");
    result = mysql_store_result(admin);
    int pgsql_server_count = mysql_num_rows(result);
    mysql_free_result(result);
    ok(pgsql_server_count == 3, "Should have loaded 3 PostgreSQL servers");
    
    MYSQL_QUERY_T(admin, "SELECT * FROM pgsql_users");
    result = mysql_store_result(admin);
    int pgsql_user_count = mysql_num_rows(result);
    mysql_free_result(result);
    ok(pgsql_user_count == 3, "Should have loaded 3 PostgreSQL users");
    
    return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
    CommandLine cl;
    
    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }
    
    plan(23); // Expecting 23 test assertions
    
    MYSQL* mysql = mysql_init(NULL);
    if (!mysql) {
        fprintf(stderr, "Failed to initialize MySQL client\n");
        return exit_status();
    }
    
    if (!mysql_real_connect(mysql, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
        return exit_status();
    }
    
    string config_file_path = "/tmp/test_comprehensive_config.cnf";
    
    // Test MySQL users validation
    test_mysql_users_validation(mysql, config_file_path);
    
    // Test ProxySQL servers validation
    test_proxysql_servers_validation(mysql, config_file_path);
    
    // Test PostgreSQL servers validation
    test_pgsql_servers_validation(mysql, config_file_path);
    
    // Test PostgreSQL users validation
    test_pgsql_users_validation(mysql, config_file_path);
    
    // Test comprehensive valid configuration
    test_comprehensive_valid_config(mysql, config_file_path);
    
    // Clean up
    unlink(config_file_path.c_str());
    mysql_close(mysql);
    
    return exit_status();
}