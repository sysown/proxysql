#include <unistd.h>
#include <string>
#include <sstream>
#include "pg_lite_client.h" // must precede mysql.h: mariadb_version.h #defines
                            // PROTOCOL_VERSION, colliding with PgConnection's
                            // static member of the same name (see
                            // test_ffto_pgsql_pipeline-t.cpp / _stmt_portal-t.cpp)
#include <mysql.h>          // admin interface is reached via the MySQL client
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

// Admin connection (MySQL protocol) used to flip pgsql-authentication_method.
static MYSQL* admin_connect() {
    MYSQL* conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.admin_host, cl.admin_username, cl.admin_password,
                            NULL, cl.admin_port, NULL, 0)) {
        diag("admin connect failed: %s", mysql_error(conn));
        mysql_close(conn);
        return NULL;
    }
    return conn;
}

static bool set_frontend_auth_method(MYSQL* admin, int method) {
    std::string q = "SET pgsql-authentication_method=" + std::to_string(method);
    if (mysql_query(admin, q.c_str())) { diag("SET failed: %s", mysql_error(admin)); return false; }
    if (mysql_query(admin, "LOAD PGSQL VARIABLES TO RUNTIME")) { diag("LOAD failed: %s", mysql_error(admin)); return false; }
    return true;
}

// Attempts a frontend login with pg_lite_client, running a query to prove the
// session is usable. On success, observed_auth_type = the challenge type ProxySQL
// presented (3=cleartext, 5=md5, 10=scram). Returns true on successful auth+query.
static bool try_frontend_login(const std::string& user, const std::string& password,
                               int& observed_auth_type) {
    observed_auth_type = 0;
    try {
        PgConnection c(2000);
        c.connect(cl.pgsql_host, cl.pgsql_port, user /*dbname==user in this infra*/, user, password);
        observed_auth_type = c.getLastAuthType();
        c.execute("SELECT 1");           // #5865 runs NO queries; proving the session works is our value-add
        c.consumeInputUntilReady();      // actually round-trip the query (execute() only sends): wait for ReadyForQuery
        c.disconnect();
        return true;
    } catch (const PgException& e) {
        diag("login threw: %s", e.what());
        return false;
    }
}

int main(int argc, char** argv) {
    if (cl.getEnv()) return exit_status();

    // Per method: (login succeeds + query runs) AND (observed challenge type matches floor).
    // Task 1 lands cleartext only (2 assertions); Tasks 2-3 add md5, scram, and failures.
    plan(2);

    MYSQL* admin = admin_connect();
    if (!admin) BAIL_OUT("cannot reach admin");

    // --- Cleartext floor (method = 1) -> expect challenge type 3 on the wire ---
    if (!set_frontend_auth_method(admin, 1))   // affects NEW frontend connections
        BAIL_OUT("could not configure cleartext auth floor (admin SET/LOAD failed)");
    int auth_type = 0;
    bool logged_in = try_frontend_login(cl.pgsql_username, cl.pgsql_password, auth_type);
    ok(logged_in, "cleartext floor: login + query succeed");
    ok(auth_type == 3, "cleartext floor: ProxySQL presented challenge type 3 (got %d)", auth_type);

    // restore default before exit
    set_frontend_auth_method(admin, 3);
    mysql_close(admin);
    return exit_status();
}
