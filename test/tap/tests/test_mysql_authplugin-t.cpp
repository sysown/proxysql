/**
 * @file test_auth_plugin-t.cpp
 * @brief Tests for the per-user authentication plugin framework
 * @details Tests the ProxySQL_Auth_Plugin interface with the static auth plugin:
 *   - Plugin loading verification
 *   - Authentication with correct password
 *   - Authentication with wrong password (should fail)
 *   - Backend username mapping via attributes
 *   - Fallback to normal auth when no auth_plugin attribute
 *
 * Prerequisites:
 *   - ProxySQL running with auth_plugins="/path/to/auth_static.so"
 *   - MySQL/MariaDB backend accessible
 *
 * Environment variables:
 *   TAP_ADMINUSERNAME, TAP_ADMINPASSWORD, TAP_ADMINPORT (default: admin/admin/6032)
 *   TAP_HOST, TAP_PORT (default: 127.0.0.1/6033)
 *   TAP_MYSQLUSERNAME, TAP_MYSQLPASSWORD, TAP_MYSQLPORT (default: root/root/3306)
 */

#include <cstring>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "mysql.h"
#include "tap.h"

using std::string;

// Simple getenv with default
const char* getenv_default(const char* name, const char* def) {
    const char* val = getenv(name);
    return val ? val : def;
}

int getenv_int(const char* name, int def) {
    const char* val = getenv(name);
    return val ? atoi(val) : def;
}

/**
 * @brief Helper to execute admin query with error handling
 */
int admin_query(MYSQL* admin, const char* query) {
    diag("Running: %s", query);
    int rc = mysql_query(admin, query);
    if (rc != 0) {
        diag("Query failed: %s", mysql_error(admin));
    }
    return rc;
}

/**
 * @brief Setup test users for auth plugin testing
 */
int setup_test_users(MYSQL* admin) {
    // Clean up existing test users
    admin_query(admin, "DELETE FROM mysql_users WHERE username IN ('auth_plugin_user', 'normal_user', 'backend_user')");

    // Add backend-only user (frontend=0, backend=1) with password for connecting to MySQL
    const char* backend_user_sql =
        "INSERT INTO mysql_users (username, password, default_hostgroup, frontend, backend) "
        "VALUES ('backend_user', 'backend_pass', 1, 0, 1)";
    if (admin_query(admin, backend_user_sql) != 0) return -1;

    // Add frontend user with static auth plugin (frontend=1, backend=0)
    const char* auth_plugin_user_sql =
        "INSERT INTO mysql_users (username, password, default_hostgroup, frontend, backend, attributes) "
        "VALUES ('auth_plugin_user', '', 1, 1, 0, "
        "'{\"auth_plugin\": \"static\", \"static_password\": \"plugin_secret\", \"backend_username\": \"backend_user\"}')";
    if (admin_query(admin, auth_plugin_user_sql) != 0) return -1;

    // Add normal user without auth_plugin (uses standard ProxySQL auth)
    const char* normal_user_sql =
        "INSERT INTO mysql_users (username, password, default_hostgroup, frontend, backend) "
        "VALUES ('normal_user', 'normal_pass', 1, 1, 1)";
    if (admin_query(admin, normal_user_sql) != 0) return -1;

    // Load users to runtime
    if (admin_query(admin, "LOAD MYSQL USERS TO RUNTIME") != 0) return -1;

    return 0;
}

/**
 * @brief Setup MySQL backend server
 */
int setup_backend_server(MYSQL* admin, const char* mysql_host, int mysql_port) {
    char query[512];

    // Clean and add backend server
    admin_query(admin, "DELETE FROM mysql_servers WHERE hostgroup_id=1");
    snprintf(query, sizeof(query),
        "INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (1, '%s', %d)",
        mysql_host, mysql_port);
    if (admin_query(admin, query) != 0) return -1;
    if (admin_query(admin, "LOAD MYSQL SERVERS TO RUNTIME") != 0) return -1;

    return 0;
}

/**
 * @brief Create test users on the MySQL backend
 */
int setup_mysql_backend_users(MYSQL* mysql_admin) {
    // Create backend_user on MySQL
    admin_query(mysql_admin, "DROP USER IF EXISTS 'backend_user'@'%'");
    admin_query(mysql_admin, "CREATE USER 'backend_user'@'%' IDENTIFIED BY 'backend_pass'");
    admin_query(mysql_admin, "GRANT ALL ON *.* TO 'backend_user'@'%'");

    // Create normal_user on MySQL
    admin_query(mysql_admin, "DROP USER IF EXISTS 'normal_user'@'%'");
    admin_query(mysql_admin, "CREATE USER 'normal_user'@'%' IDENTIFIED BY 'normal_pass'");
    admin_query(mysql_admin, "GRANT ALL ON *.* TO 'normal_user'@'%'");

    admin_query(mysql_admin, "FLUSH PRIVILEGES");

    return 0;
}

/**
 * @brief Test connection attempt and return success/failure
 */
bool test_connection(const char* host, int port, const char* user, const char* pass, string& out_user) {
    MYSQL* conn = mysql_init(NULL);
    if (!conn) return false;

    // Use mysql_clear_password for auth plugin users (sends cleartext)
    mysql_options(conn, MYSQL_DEFAULT_AUTH, "mysql_clear_password");

    // Enable cleartext plugin
    my_bool enable_cleartext = 1;
    mysql_options(conn, MYSQL_ENABLE_CLEARTEXT_PLUGIN, &enable_cleartext);

    bool success = false;
    if (mysql_real_connect(conn, host, user, pass, NULL, port, NULL, 0)) {
        // Query current user to verify backend mapping
        if (mysql_query(conn, "SELECT CURRENT_USER()") == 0) {
            MYSQL_RES* res = mysql_store_result(conn);
            if (res) {
                MYSQL_ROW row = mysql_fetch_row(res);
                if (row && row[0]) {
                    out_user = row[0];
                }
                mysql_free_result(res);
            }
        }
        success = true;
    }

    mysql_close(conn);
    return success;
}

int main(int argc, char** argv) {
    // Configuration from environment
    const char* admin_host = getenv_default("TAP_ADMINHOST", "127.0.0.1");
    int admin_port = getenv_int("TAP_ADMINPORT", 6032);
    const char* admin_user = getenv_default("TAP_ADMINUSERNAME", "admin");
    const char* admin_pass = getenv_default("TAP_ADMINPASSWORD", "admin");

    const char* proxy_host = getenv_default("TAP_HOST", "127.0.0.1");
    int proxy_port = getenv_int("TAP_PORT", 6033);

    const char* mysql_host = getenv_default("TAP_MYSQLHOST", "127.0.0.1");
    int mysql_port = getenv_int("TAP_MYSQLPORT", 3306);
    const char* mysql_user = getenv_default("TAP_MYSQLUSERNAME", "root");
    const char* mysql_pass = getenv_default("TAP_MYSQLPASSWORD", "root");

    // Total number of tests
    plan(6);

    // Connect to ProxySQL admin
    MYSQL* admin = mysql_init(NULL);
    if (!mysql_real_connect(admin, admin_host, admin_user, admin_pass,
                            NULL, admin_port, NULL, 0)) {
        fprintf(stderr, "Failed to connect to ProxySQL admin: %s\n", mysql_error(admin));
        return EXIT_FAILURE;
    }

    // Connect to MySQL backend to create test users
    MYSQL* mysql_admin = mysql_init(NULL);
    if (!mysql_real_connect(mysql_admin, mysql_host, mysql_user, mysql_pass,
                            NULL, mysql_port, NULL, 0)) {
        fprintf(stderr, "Failed to connect to MySQL backend: %s\n", mysql_error(mysql_admin));
        diag("Skipping tests - cannot connect to MySQL backend at %s:%d", mysql_host, mysql_port);
        skip(6, "MySQL backend not available");
        mysql_close(admin);
        return exit_status();
    }

    // Setup backend server in ProxySQL
    if (setup_backend_server(admin, mysql_host, mysql_port) != 0) {
        diag("Failed to setup backend server");
        skip(6, "Backend server setup failed");
        mysql_close(mysql_admin);
        mysql_close(admin);
        return exit_status();
    }

    // Setup users on MySQL backend
    if (setup_mysql_backend_users(mysql_admin) != 0) {
        diag("Failed to setup MySQL backend users");
        skip(6, "MySQL user setup failed");
        mysql_close(mysql_admin);
        mysql_close(admin);
        return exit_status();
    }
    mysql_close(mysql_admin);

    // Setup test users in ProxySQL
    if (setup_test_users(admin) != 0) {
        diag("Failed to setup ProxySQL test users");
        skip(6, "ProxySQL user setup failed");
        mysql_close(admin);
        return exit_status();
    }

    string backend_user;

    // Test 1: Auth plugin user with correct password should succeed
    diag("Testing auth_plugin_user with correct password...");
    bool auth_success = test_connection(proxy_host, proxy_port, "auth_plugin_user", "plugin_secret", backend_user);
    ok(auth_success, "Auth plugin user with correct password should connect successfully");

    // Test 2: Backend username mapping should work
    if (auth_success) {
        ok(backend_user.find("backend_user") != string::npos,
           "Backend username mapping: expected 'backend_user', got '%s'", backend_user.c_str());
    } else {
        ok(false, "Backend username mapping - skipped due to connection failure");
    }

    // Test 3: Auth plugin user with wrong password should fail
    diag("Testing auth_plugin_user with wrong password...");
    bool wrong_pass = test_connection(proxy_host, proxy_port, "auth_plugin_user", "wrong_password", backend_user);
    ok(!wrong_pass, "Auth plugin user with wrong password should be rejected");

    // Test 4: Normal user (no auth_plugin) with correct password should succeed
    diag("Testing normal_user with correct password...");
    bool normal_success = test_connection(proxy_host, proxy_port, "normal_user", "normal_pass", backend_user);
    ok(normal_success, "Normal user with correct password should connect successfully");

    // Test 5: Normal user with wrong password should fail
    diag("Testing normal_user with wrong password...");
    bool normal_wrong = test_connection(proxy_host, proxy_port, "normal_user", "wrong_pass", backend_user);
    ok(!normal_wrong, "Normal user with wrong password should be rejected");

    // Test 6: Non-existent user should fail
    diag("Testing non-existent user...");
    bool nonexistent = test_connection(proxy_host, proxy_port, "nonexistent_user", "any_pass", backend_user);
    ok(!nonexistent, "Non-existent user should be rejected");

    // Cleanup
    admin_query(admin, "DELETE FROM mysql_users WHERE username IN ('auth_plugin_user', 'normal_user', 'backend_user')");
    admin_query(admin, "LOAD MYSQL USERS TO RUNTIME");

    mysql_close(admin);

    return exit_status();
}
