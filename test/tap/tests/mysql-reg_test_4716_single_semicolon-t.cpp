 /**
  * @file mysql-reg_test_4716_single_semicolon-t.cpp
  * @brief  This test aims to verify that ProxySQL handles a lone semicolon (;) input
  * crashing. The expected behavior is for ProxySQL to either ignore the input or return an
  * appropriate error message, rather than crashing or becoming unresponsive.
  */

#include <string>
#include <sstream>

#include "mysql.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

enum ConnType {
    ADMIN,
    BACKEND
};

int main(int argc, char** argv) {

    std::vector<const char*> queries = { ";", " ", "", ";  ", "  ;" };

    plan(queries.size() + 1); // Total number of tests planned

    if (cl.getEnv())
        return exit_status();

    // Initialize Admin connection
    MYSQL* proxysql_admin = mysql_init(NULL);
    if (!proxysql_admin) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return -1;
    }

    // Connnect to ProxySQL Admin
    if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return -1;
    }

    for (const char* query : queries) {
        MYSQL_QUERY_err(proxysql_admin, query);
        const int _errorno = mysql_errno(proxysql_admin);
        ok(_errorno > 0, "Error Code:%d, Message:%s", _errorno, mysql_error(proxysql_admin));
    }

    // Test a valid query to ensure the connection is working
    if (mysql_query(proxysql_admin, "SELECT 1") == 0) {
        MYSQL_RES* res = mysql_store_result(proxysql_admin);
        ok(res != nullptr, "Query executed successfully. %s", mysql_error(proxysql_admin));
        mysql_free_result(res);
    }
    else {
        ok(false, "Error executing query. %s", mysql_error(proxysql_admin));
    }

    mysql_close(proxysql_admin);

    return exit_status();
}
