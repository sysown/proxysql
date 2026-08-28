/**
 * @file pgsql-scram_cache_invalidation-t.cpp
 * @brief Tests that the SCRAM verifier cache is correctly invalidated
 *        when pgsql_users are reloaded with a changed password.
 *
 *        ProxySQL caches SCRAM-SHA-256 verifiers for plaintext passwords
 *        to avoid repeated PBKDF2 (4096 HMAC iterations). A generation
 *        counter ensures stale entries are discarded on user reload.
 *
 *        Test sequence:
 *        1. Create user with password "pass1", load to runtime
 *        2. Connect/disconnect loop with "pass1" — populates cache
 *        3. Change password to "pass2", reload users (invalidates cache)
 *        4. Connect/disconnect loop with "pass2" — must succeed
 *        5. Connect with "pass1" — must fail (stale cache cleared)
 *        6. Cleanup
 */

#include <string>
#include <sstream>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

static const char* TEST_USER = "scram_cache_test_user";
static const char* PASS_1 = "pass1_old";
static const char* PASS_2 = "pass2_new";
static const int CONNECT_LOOPS = 10;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

PGConnPtr createAdminConn() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_admin_host
       << " port=" << cl.pgsql_admin_port
       << " user=" << cl.admin_username
       << " password=" << cl.admin_password;
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

PGConnPtr createDataConn(const char* username, const char* password, bool with_ssl) {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host
       << " port=" << cl.pgsql_port
       << " user=" << username
       << " password=" << password
       << " dbname=" << cl.pgsql_username
       << (with_ssl ? " sslmode=require" : " sslmode=disable");
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

bool execAdmin(PGconn* admin, const char* query) {
    PGresult* res = PQexec(admin, query);
    bool ok = (PQresultStatus(res) == PGRES_COMMAND_OK ||
               PQresultStatus(res) == PGRES_TUPLES_OK);
    if (!ok) {
        diag("Admin query failed: %s -- %s", query, PQerrorMessage(admin));
    }
    PQclear(res);
    return ok;
}

int main(int argc, char** argv) {
    plan(6);

    if (cl.getEnv())
        return exit_status();

    // Test 1: Admin connection
    auto admin = createAdminConn();
    ok(admin && PQstatus(admin.get()) == CONNECTION_OK,
       "Admin connection established");
    if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
        BAIL_OUT("Cannot proceed without admin connection");
        return exit_status();
    }

    // Cleanup any leftover test user
    {
        std::stringstream q;
        q << "DELETE FROM pgsql_users WHERE username='" << TEST_USER << "';";
        execAdmin(admin.get(), q.str().c_str());
        execAdmin(admin.get(), "LOAD PGSQL USERS TO RUNTIME;");
    }
    usleep(100000);

    // Test 2: Create user with pass1 and load to runtime
    {
        std::stringstream q;
        q << "INSERT INTO pgsql_users (username, password, active, default_hostgroup) "
          << "VALUES ('" << TEST_USER << "', '" << PASS_1 << "', 1, 0);";
        bool ins = execAdmin(admin.get(), q.str().c_str());
        bool load = execAdmin(admin.get(), "LOAD PGSQL USERS TO RUNTIME;");
        ok(ins && load, "User created with pass1 and loaded to runtime");
    }
    usleep(100000);

    // Test 3: Connect/disconnect loop with pass1 — populates SCRAM cache
    {
        bool all_ok = true;
        for (int i = 0; i < CONNECT_LOOPS; i++) {
            auto conn = createDataConn(TEST_USER, PASS_1, true);
            if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
                all_ok = false;
                diag("pass1 connect failed at iteration %d: %s",
                     i, conn ? PQerrorMessage(conn.get()) : "null conn");
                break;
            }
        }
        ok(all_ok, "pass1: %d connect/disconnect cycles succeeded (cache populated)", CONNECT_LOOPS);
    }

    // Test 4: Change password to pass2 and reload (triggers scram_cache_invalidate)
    {
        std::stringstream q;
        q << "UPDATE pgsql_users SET password='" << PASS_2
          << "' WHERE username='" << TEST_USER << "';";
        bool upd = execAdmin(admin.get(), q.str().c_str());
        bool load = execAdmin(admin.get(), "LOAD PGSQL USERS TO RUNTIME;");
        ok(upd && load, "Password changed to pass2 and reloaded to runtime");
    }
    usleep(100000);

    // Test 5: Connect/disconnect loop with pass2 — must succeed (cache invalidated)
    {
        bool all_ok = true;
        for (int i = 0; i < CONNECT_LOOPS; i++) {
            auto conn = createDataConn(TEST_USER, PASS_2, true);
            if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
                all_ok = false;
                diag("pass2 connect failed at iteration %d: %s",
                     i, conn ? PQerrorMessage(conn.get()) : "null conn");
                break;
            }
        }
        ok(all_ok, "pass2: %d connect/disconnect cycles succeeded (cache invalidated)", CONNECT_LOOPS);
    }

    // Test 6: Connect with old password pass1 — must fail
    {
        auto conn = createDataConn(TEST_USER, PASS_1, true);
        bool failed = (conn && PQstatus(conn.get()) != CONNECTION_OK);
        if (failed) {
            ok(true, "pass1 correctly rejected after password change");
        } else {
            ok(false, "pass1 should be rejected after password change, but connection succeeded");
        }
    }

    // Cleanup
    {
        std::stringstream q;
        q << "DELETE FROM pgsql_users WHERE username='" << TEST_USER << "';";
        execAdmin(admin.get(), q.str().c_str());
        execAdmin(admin.get(), "LOAD PGSQL USERS TO RUNTIME;");
    }

    return exit_status();
}
