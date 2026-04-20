#include <cstring>
#include <unistd.h>
#include <vector>
#include <string>
#include <stdio.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

std::string get_admin_mysql_ifaces(MYSQL *admin) {
    std::string ret = "";
    const char * query = (const char *)"SELECT variable_value FROM runtime_global_variables WHERE variable_name='admin-mysql_ifaces';";
    diag("Running query: %s", query);
    int rc = mysql_query(admin, query);
    ok(rc==0,"Query: %s . Error: %s", query, (rc == 0 ? "None" : mysql_error(admin)));
    if (rc == 0 ) {
        MYSQL_RES* res = mysql_store_result(admin);
        int num_rows = static_cast<int>(mysql_num_rows(res));
        ok(num_rows==1,"1 row expected when querying admin-mysql_ifaces. Returned: %d", num_rows);
        if (num_rows == 0) {
            diag("Fatal error in line %d: No result", __LINE__);
        } else if (num_rows > 1) {
            diag("Fatal error in line %d: returned rows more than 1: %d", __LINE__, num_rows);
        } else {
            MYSQL_ROW row = nullptr;
            while (( row = mysql_fetch_row(res) )) {
                ret = std::string(row[0]);
            }
        }
        mysql_free_result(res);
    }
    return ret;
}

int main(int argc, char** argv) {
    CommandLine cl;
    plan(13);

    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return -1;
    }

    const char* d_env = getenv("REGULAR_INFRA_DATADIR");
    string socket_path = (d_env ? string(d_env) : "/tmp");
    if (socket_path.back() != '/') socket_path += '/';
    socket_path += "proxysql_admin.sock";

    MYSQL* proxysql_admin = mysql_init(NULL);

    if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return EXIT_FAILURE;
    }
    {
        std::string current = get_admin_mysql_ifaces(proxysql_admin);
        ok((current.empty() == false), "Line: %d , Current admin-mysql_ifaces = %s .", __LINE__, current.c_str());
    }

    string ifaces_with_sock = string("0.0.0.0:6032;") + socket_path;
    diag("Changing admin-mysql_ifaces to: %s", ifaces_with_sock.c_str());
    
    string set_query = string("SET admin-mysql_ifaces=\"") + ifaces_with_sock + string("\"");
    MYSQL_QUERY(proxysql_admin, set_query.c_str());
    MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");
    MYSQL_QUERY(proxysql_admin, "SAVE ADMIN VARIABLES FROM RUNTIME");

    {
        std::string current = get_admin_mysql_ifaces(proxysql_admin);
        ok(current == ifaces_with_sock, "Line: %d , Current admin-mysql_ifaces = %s . Expected = %s", __LINE__, current.c_str(), ifaces_with_sock.c_str());
    }

    sleep(1);

    {
        diag("Connecting on Unix Socket: %s", socket_path.c_str());
        MYSQL* proxysql_admin2 = mysql_init(NULL);
        if (!mysql_real_connect(proxysql_admin2, NULL, cl.admin_username, cl.admin_password, NULL, 0, socket_path.c_str(), 0)) {
            fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin2));
            return EXIT_FAILURE;
        }
        std::string current = get_admin_mysql_ifaces(proxysql_admin2);
        ok(current == ifaces_with_sock, "Line: %d , Current admin-mysql_ifaces = %s . Expected = %s", __LINE__, current.c_str(), ifaces_with_sock.c_str());
        mysql_close(proxysql_admin2);
    }

    diag("Changing admin-mysql_ifaces to: 0.0.0.0:6032");
    MYSQL_QUERY(proxysql_admin, "SET admin-mysql_ifaces=\"0.0.0.0:6032\"");
    MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");
    MYSQL_QUERY(proxysql_admin, "SAVE ADMIN VARIABLES FROM RUNTIME");

    sleep(1);
    {
        std::string current = get_admin_mysql_ifaces(proxysql_admin);
        string expected = "0.0.0.0:6032";
        ok(current == expected, "Line: %d , Current admin-mysql_ifaces = %s . Expected = %s", __LINE__, current.c_str(), expected.c_str());
    }

    {
        diag("Connecting on Unix Socket. It should fail: %s", socket_path.c_str());
        MYSQL* proxysql_admin2 = mysql_init(NULL);
        MYSQL * ret = mysql_real_connect(proxysql_admin2, NULL, cl.admin_username, cl.admin_password, NULL, 0, socket_path.c_str(), 0);
        ok(ret == NULL, "Connection to Unix Socket should fail with error: %s", mysql_error(proxysql_admin2));
    }

    mysql_close(proxysql_admin);
    return exit_status();
}
