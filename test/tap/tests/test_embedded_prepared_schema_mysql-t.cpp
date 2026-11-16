#include "prepared_owned_fixture.h"
#include "tap.h"
#include <cstdlib>
#include <cstring>
#include <mysql.h>
#include <string>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct Endpoint {
    const char *label, *host, *user, *password;
    unsigned port;
    bool admin;
};
static const char *required(const char *name) {
    const char *v = std::getenv(name);
    if (!v || !*v)
        BAIL_OUT("%s is required", name);
    return v;
}
static MYSQL *connect(const Endpoint &e) {
    MYSQL *c = mysql_init(nullptr);
    if (!c)
        return nullptr;
    mysql_options(c, MYSQL_SET_CHARSET_NAME, "utf8mb4");
    if (!mysql_real_connect(c, e.host, e.user, e.password, nullptr, e.port, nullptr, 0)) {
        diag("%s connect failed: %s", e.label, mysql_error(c));
        mysql_close(c);
        return nullptr;
    }
    return c;
}
static bool query(MYSQL *c, const std::string &q) {
    if (mysql_query(c, q.c_str())) {
        diag("query failed: %s: %u %s", q.c_str(), mysql_errno(c), mysql_error(c));
        return false;
    }
    MYSQL_RES *r = mysql_store_result(c);
    if (r)
        mysql_free_result(r);
    return true;
}
static MYSQL_STMT *prepare(MYSQL *c, const std::string &q) {
    MYSQL_STMT *s = mysql_stmt_init(c);
    if (!s)
        return nullptr;
    if (mysql_stmt_prepare(s, q.data(), q.size())) {
        diag("prepare failed: %u %s", mysql_stmt_errno(s), mysql_stmt_error(s));
        mysql_stmt_close(s);
        return nullptr;
    }
    return s;
}
static unsigned fields(MYSQL_STMT *s) {
    MYSQL_RES *r = mysql_stmt_result_metadata(s);
    if (!r)
        return 0;
    unsigned n = mysql_num_fields(r);
    mysql_free_result(r);
    return n;
}
struct Fixture {
    MYSQL *conn;
    std::string name;
    bool view;
    bool created = false;
    ~Fixture() {
        if (created)
            query(conn, std::string("DROP ") + (view ? "VIEW " : "TABLE ") + name);
    }
};
static void run(const Endpoint &e, const std::string &suffix) {
    MYSQL *c = connect(e);
    ok(c != nullptr, "%s connect", e.label);
    if (!c)
        return;
    {
        Fixture f{c, "proxysql_schema_lifecycle_" + suffix, e.admin};
        std::string create =
            e.admin ? "CREATE VIEW " + f.name + " AS SELECT hostgroup_id FROM mysql_servers"
                    : "CREATE TABLE " + f.name + " (a INTEGER)";
        f.created = query(c, create);
        ok(f.created, "%s create owned fixture", e.label);
        if (e.admin && !f.created) {
            diag("Admin schema-change fixture N/A: owned CREATE VIEW was refused; no managed "
                 "schema was changed");
        } else {
            if (f.created) {
                if (!e.admin)
                    ok(query(c, "INSERT INTO " + f.name + " VALUES (42)"), "%s insert fixture",
                       e.label);
                const std::string select = "SELECT * FROM " + f.name + " WHERE ? = ?";
                MYSQL_STMT *s = prepare(c, select);
                ok(s && fields(s) == 1, "%s original one-column metadata", e.label);
                int val = 42;
                MYSQL_BIND b[2]{};
                for (auto &x : b) {
                    x.buffer_type = MYSQL_TYPE_LONG;
                    x.buffer = &val;
                }
                bool bound = s && !mysql_stmt_bind_param(s, b);
                ok(bound, "%s bind old statement", e.label);
                bool changed;
                if (e.admin) {
                    changed = query(c, "DROP VIEW " + f.name);
                    if (changed) {
                        f.created = false;
                        changed = query(c, "CREATE VIEW " + f.name +
                                               " AS SELECT hostgroup_id, port FROM mysql_servers");
                        f.created = changed;
                    }
                } else
                    changed = query(c, "ALTER TABLE " + f.name + " ADD COLUMN b INTEGER");
                ok(changed, "%s change owned schema", e.label);
                if (s && bound && changed) {
                    int rc = mysql_stmt_execute(s);
                    unsigned code = mysql_stmt_errno(s);
                    diag("%s old statement execute rc=%d errno=%u state=%s message=%s", e.label, rc,
                         code, mysql_stmt_sqlstate(s), mysql_stmt_error(s));
                    ok(rc != 0 && code == 1615, "%s schema change fails before rows with 1615",
                       e.label);
                } else
                    ok(false, "%s schema change fails before rows with 1615", e.label);
                if (s)
                    mysql_stmt_close(s);
                s = changed ? prepare(c, select) : nullptr;
                ok(s && fields(s) == 2, "%s reprepare reports fresh two-column metadata", e.label);
                if (s) {
                    bool twice = !mysql_stmt_bind_param(s, b) && !mysql_stmt_execute(s) &&
                                 !mysql_stmt_store_result(s);
                    if (twice) {
                        mysql_stmt_free_result(s);
                        val = 7;
                        twice = !mysql_stmt_bind_param(s, b) && !mysql_stmt_execute(s) &&
                                !mysql_stmt_store_result(s);
                    }
                    ok(twice, "%s reprepare executes repeated binds", e.label);
                    mysql_stmt_close(s);
                } else
                    ok(false, "%s reprepare executes repeated binds", e.label);
                MYSQL *live = connect(e);
                MYSQL_STMT *leaked = live ? prepare(live, select) : nullptr;
                ok(leaked != nullptr, "%s prepare live statement before disconnect", e.label);
                if (live) {
                    shutdown(mysql_get_socket(live), SHUT_RDWR);
                    mysql_close(live);
                } // Abrupt transport loss leaves the server handle live until teardown.
                MYSQL *next = connect(e);
                bool readable = next && query(next, "SELECT * FROM " + f.name);
                ok(readable, "%s reconnect reads fixture after live-statement disconnect", e.label);
                if (next)
                    mysql_close(next);
            }
        }
    }
    mysql_close(c);
}
int main() {
    prepared_owned_fixture::Fixture fixture;
    plan(NO_PLAN);
    const char *host = required("TAP_HOST");
    Endpoint endpoints[] = {
        {"SQLite", host, required("TAP_USERNAME"), required("TAP_PASSWORD"),
         unsigned(std::strtoul(required("TAP_SQLITE_PORT"), nullptr, 10)), false},
        {"DuckDB", host, required("TAP_USERNAME"), required("TAP_PASSWORD"),
         unsigned(std::strtoul(required("TAP_DUCKDB_MYSQL_PORT"), nullptr, 10)), false},
        {"Admin", host, required("TAP_ADMINUSERNAME"), required("TAP_ADMINPASSWORD"),
         unsigned(std::strtoul(required("TAP_ADMINPORT"), nullptr, 10)), true}};
    timespec now{};
    clock_gettime(CLOCK_REALTIME, &now);
    std::string suffix = std::to_string(getpid()) + "_" + std::to_string(now.tv_sec) + "_" +
                         std::to_string(now.tv_nsec);
    for (const auto &e : endpoints)
        run(e, suffix);
    return exit_status();
}
