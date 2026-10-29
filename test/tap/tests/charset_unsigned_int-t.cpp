#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
    CommandLine cl;

    if(cl.getEnv())
        return exit_status();

    plan(6);
    diag("=== Charset Unsigned Int Test ===");
    diag("This test verifies that ProxySQL correctly handles character set and collation");
    diag("assignments, especially for collations with IDs > 255 (unsigned int).");
    diag("It tests:");
    diag("  1. 'SET NAMES' with high-numbered collations (e.g., utf8mb4_croatian_ci).");
    diag("  2. Dynamic reconfiguration of 'mysql-default_charset' via Admin interface.");
    diag("  3. Client connection options (MYSQL_SET_CHARSET_NAME) and their effect on session state.");
    diag("====================================");

    std::string var_collation_connection = "collation_connection";
    std::string var_value;

    MYSQL* mysqlAdmin = mysql_init(NULL);
    if (!mysqlAdmin) return exit_status();
    
    diag("Connecting to ProxySQL Admin: %s:%d as %s", cl.host, cl.admin_port, cl.admin_username);
    if (!mysql_real_connect(mysqlAdmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection 1 failed: %s", mysql_error(mysqlAdmin));
        return exit_status();
    }

    set_admin_global_variable(mysqlAdmin, "mysql-handle_unknown_charset", "1");
    set_admin_global_variable(mysqlAdmin, "mysql-default_charset", "utf8mb4");
    set_admin_global_variable(mysqlAdmin, "mysql-default_character_set_client", "utf8mb4");
    set_admin_global_variable(mysqlAdmin, "mysql-default_character_set_results", "utf8mb4");
    set_admin_global_variable(mysqlAdmin, "mysql-default_character_set_connection", "utf8mb4");
    set_admin_global_variable(mysqlAdmin, "mysql-default_character_set_database", "utf8mb4");
    set_admin_global_variable(mysqlAdmin, "mysql-default_collation_connection", "utf8mb4_general_ci");
    
    if (mysql_query(mysqlAdmin, "load mysql variables to runtime")) { diag("LOAD failed: %s", mysql_error(mysqlAdmin)); return exit_status(); }
    if (mysql_query(mysqlAdmin, "save mysql variables to disk")) { diag("SAVE failed: %s", mysql_error(mysqlAdmin)); return exit_status(); }

    MYSQL* mysql = mysql_init(NULL);
    if (!mysql) return exit_status();
    
    diag("Connecting to ProxySQL Frontend: %s:%d as %s", cl.host, cl.port, cl.username);
    if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        diag("Client connection failed: %s", mysql_error(mysql));
        return exit_status();
    }

    // Get version early for version-specific charset checks.
    //
    // Read it with `SHOW VARIABLES LIKE 'version'` rather than `SELECT @@version`: the
    // charset checks below issue `SET NAMES ...` and `SHOW VARIABLES LIKE
    // 'collation_connection'`, both of which route to the default (writer) hostgroup. A
    // bare `SELECT @@version` matches the `^SELECT` query rules and is routed to the
    // reader hostgroup instead. In multi-backend groups such as legacy-g1 the reader pool
    // is a different server/engine than the writer (e.g. MariaDB 10 readers in front of a
    // MySQL 5.7 writer), so a version sampled via @@version does not necessarily describe
    // the backend that actually answers the charset queries, yielding a spurious
    // expected-vs-actual collation mismatch (#5884). Sampling the version through the same
    // `SHOW VARIABLES` path keeps version detection and the charset checks on one backend.
    std::string version;
    show_variable(mysql, std::string("version"), version);
    int major = 0, minor = 0;
    sscanf(version.c_str(), "%d.%d", &major, &minor);
    bool is_mysql_84_plus = (major > 8) || (major == 8 && minor >= 4);

    if (mysql_query(mysql, "set names 'utf8'")) return exit_status();
    show_variable(mysql, var_collation_connection, var_value);
    if (is_mysql_84_plus) {
        ok(var_value.compare("utf8mb3_general_ci") == 0, "MySQL 8.4+ Initial client character set. Actual %s", var_value.c_str());
    } else {
        ok(var_value.compare("utf8_general_ci") == 0, "Initial client character set. Actual %s", var_value.c_str());
    }

    if (mysql_query(mysql, "set names utf8mb4 collate utf8mb4_croatian_ci")) return exit_status();
    show_variable(mysql, var_collation_connection, var_value);
    if (version.data()[0] == '5') {
        ok(var_value.compare("utf8mb4_general_ci") == 0, "Backend is mysql version < 8.0. Actual collation %s", var_value.c_str());
    } else {
        ok(var_value.compare("utf8mb4_croatian_ci") == 0, "Backend is mysql version >= 8.0. Actual collation %s",var_value.c_str());
    }

    mysql_close(mysql);

    std::string var_name="mysql-default_charset";
    MYSQL * mysql_a = mysql_init(NULL);
    if (!mysql_a) return exit_status();
    
    diag("Connecting to ProxySQL Admin 2: %s:%d as %s", cl.host, cl.admin_port, cl.admin_username);
    if (!mysql_real_connect(mysql_a, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connection 2 failed: %s", mysql_error(mysql_a));
        return exit_status();
    }

    if (mysql_query(mysql_a, "update global_variables set variable_value='latin1' where variable_name='mysql-default_charset'")) { diag("Update to latin1 failed: %s", mysql_error(mysql_a)); return exit_status(); }
    if (mysql_query(mysql_a, "load mysql variables to runtime")) { diag("LOAD failed: %s", mysql_error(mysql_a)); return exit_status(); }
    if (mysql_query(mysql_a, "save mysql variables to disk")) { diag("SAVE failed: %s", mysql_error(mysql_a)); return exit_status(); }

    show_admin_global_variable(mysql_a, var_name, var_value);
    ok(var_value.compare("latin1") == 0, "Default charset latin1 is set in admin");

    MYSQL* mysql_b = mysql_init(NULL);
    if (!mysql_b) return exit_status();
    
    if (!mysql_real_connect(mysql_b, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        diag("Client connection B failed: %s", mysql_error(mysql_b));
        return exit_status();
    }

    get_server_version(mysql_b, version);
    if (version.data()[0] == '5') {
        show_variable(mysql_b, var_collation_connection, var_value);
        ok(var_value.compare("latin1_swedish_ci") == 0, "Collation <255 is set. Actual %s", var_value.c_str());
    }
    else {
        show_variable(mysql_b, var_collation_connection, var_value);
        ok(var_value.compare("latin1_swedish_ci") == 0, "Collation >255 is set. Actual %s", var_value.c_str());
    }
    mysql_close(mysql_b);

    if (mysql_query(mysql_a, "update global_variables set variable_value='utf8mb4' where variable_name='mysql-default_charset'")) { diag("Update to utf8mb4 failed: %s", mysql_error(mysql_a)); return exit_status(); }
    if (mysql_query(mysql_a, "load mysql variables to runtime")) { diag("LOAD failed: %s", mysql_error(mysql_a)); return exit_status(); }
    if (mysql_query(mysql_a, "save mysql variables to disk")) { diag("SAVE failed: %s", mysql_error(mysql_a)); return exit_status(); }

    show_admin_global_variable(mysql_a, var_name, var_value);
    ok(var_value.compare("utf8mb4") == 0, "Default charset utf8mb4 is set in admin. Actual %s", var_value.c_str());

    mysql_close(mysql_a);

    MYSQL* mysql_c = mysql_init(NULL);
    if (!mysql_c) return exit_status();
    if (mysql_options(mysql_c, MYSQL_SET_CHARSET_NAME, "utf8mb4")) return exit_status();
    if (!mysql_real_connect(mysql_c, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        diag("Client connection C failed: %s", mysql_error(mysql_c));
        return exit_status();
    }

    if (get_server_version(mysql_c, version)) return exit_status();
    if (version.data()[0] == '5') {
        show_variable(mysql_c, var_collation_connection, var_value);
        ok(var_value.compare("utf8mb4_general_ci") == 0, "Collation <255 is set. Actual %s", var_value.c_str());
    }
    else {
        show_variable(mysql_c, var_collation_connection, var_value);
        ok(var_value.compare("utf8mb4_general_ci") == 0, "Collation >255 is set. %s", var_value.c_str());
    }

    mysql_close(mysql_c);
    mysql_close(mysqlAdmin);

    return exit_status();
}
