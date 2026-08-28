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

// Every floor switch is a PRECONDITION for the assertions that follow it: if the
// SET/LOAD silently fails, the previous floor is still in effect and the next
// assertions test the wrong thing -- e.g. a "scram floor" check would actually be
// exercising md5, and a wrong-password rejection could pass for the wrong reason.
// So a failed switch aborts the test rather than being ignored.
static void require_auth_method(MYSQL* admin, int method) {
    if (!set_frontend_auth_method(admin, method)) {
        BAIL_OUT("could not configure pgsql-authentication_method=%d (admin SET/LOAD failed)", method);
    }
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
    plan(9);

    MYSQL* admin = admin_connect();
    if (!admin) BAIL_OUT("cannot reach admin");

    // --- Cleartext floor (method = 1) -> expect challenge type 3 on the wire ---
    require_auth_method(admin, 1);   // affects NEW frontend connections
    int auth_type = 0;
    bool logged_in = try_frontend_login(cl.pgsql_username, cl.pgsql_password, auth_type);
    ok(logged_in, "cleartext floor: login + query succeed");
    ok(auth_type == 3, "cleartext floor: ProxySQL presented challenge type 3 (got %d)", auth_type);

    // --- MD5 floor (method = 2) -> expect challenge type 5 on the wire ---
    require_auth_method(admin, 2);
    int md5_auth = 0;
    ok(try_frontend_login(cl.pgsql_username, cl.pgsql_password, md5_auth),
       "md5 floor: login + query succeed");
    ok(md5_auth == 5, "md5 floor: ProxySQL presented challenge type 5 (got %d)", md5_auth);

    // --- SCRAM floor (method = 3) -> expect challenge type 10 on the wire ---
    require_auth_method(admin, 3);
    int scram_auth = 0;
    ok(try_frontend_login(cl.pgsql_username, cl.pgsql_password, scram_auth),
       "scram floor: login + query succeed");
    ok(scram_auth == 10, "scram floor: ProxySQL presented SASL/SCRAM challenge type 10 (got %d)", scram_auth);

    // --- Wrong-password failure paths, one per floor (challenge type irrelevant) ---
    int ignore = 0;
    require_auth_method(admin, 1);
    ok(!try_frontend_login(cl.pgsql_username, "wrong-pw", ignore), "cleartext floor: wrong password rejected");
    require_auth_method(admin, 2);
    ok(!try_frontend_login(cl.pgsql_username, "wrong-pw", ignore), "md5 floor: wrong password rejected");
    require_auth_method(admin, 3);
    ok(!try_frontend_login(cl.pgsql_username, "wrong-pw", ignore), "scram floor: wrong password rejected");

    // Restore the default floor before exit. Not a BAIL_OUT -- every assertion has
    // already run -- but it must not be silent either: leaving the instance on a
    // non-default auth floor would corrupt whichever test in this group runs next.
    if (!set_frontend_auth_method(admin, 3)) {
        diag("WARNING: failed to restore pgsql-authentication_method=3; "
             "the instance is left on a non-default auth floor");
    }
    mysql_close(admin);
    return exit_status();
}
