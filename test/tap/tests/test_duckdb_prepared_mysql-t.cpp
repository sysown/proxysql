#include "mysql.h"
#include "tap.h"
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

static std::string last_error;
static unsigned int last_errno;
static MYSQL_STMT *prepare(MYSQL *c, const char *sql) {
    MYSQL_STMT *s = mysql_stmt_init(c);
    if (!s)
        BAIL_OUT("stmt init failed");
    if (mysql_stmt_prepare(s, sql, strlen(sql))) {
        last_error = mysql_stmt_error(s);
        last_errno = mysql_stmt_errno(s);
        diag("prepare failed (%u/%s): %s; SQL: %s", mysql_stmt_errno(s), mysql_stmt_sqlstate(s),
             mysql_stmt_error(s), sql);
        mysql_stmt_close(s);
        return nullptr;
    }
    return s;
}
int main() {
    plan(NO_PLAN);
    const char *host = getenv("TAP_HOST"), *port = getenv("TAP_DUCKDB_MYSQL_PORT"),
               *user = getenv("TAP_USERNAME"), *pass = getenv("TAP_PASSWORD");
    if (!user || !*user || !pass)
        BAIL_OUT("TAP_USERNAME and TAP_PASSWORD are required");
    MYSQL *c = mysql_init(nullptr);
    if (!c || !mysql_real_connect(c, host && *host ? host : "127.0.0.1", user, pass, nullptr,
                                  port && *port ? atoi(port) : 6031, nullptr, 0))
        BAIL_OUT("connect failed: %s", c ? mysql_error(c) : "mysql_init");
    diag("client charset before selection: %s", mysql_character_set_name(c));
    ok(!mysql_set_character_set(c, "utf8mb4", 45), "select UTF8 client charset: %s",
       mysql_error(c));
    MYSQL_STMT *s =
        prepare(c, "SELECT CASE WHEN ? = 42 THEN 42 ELSE -7 END, ? = 'x''); DROP TABLE t; --'");
    ok(s != nullptr, "prepare typed parameter expressions");
    if (s) {
        MYSQL_RES *meta = mysql_stmt_result_metadata(s);
        MYSQL_FIELD *fields = meta ? mysql_fetch_fields(meta) : nullptr;
        ok(meta && mysql_num_fields(meta) == 2 && fields[0].type == MYSQL_TYPE_LONGLONG &&
               fields[1].type == MYSQL_TYPE_TINY,
           "resolved integer and boolean expression metadata");
        if (meta)
            mysql_free_result(meta);
        long long number = 42, out1 = 0, out2 = 0;
        char text[] = "x'); DROP TABLE t; --";
        unsigned long len = strlen(text);
        my_bool nulls[2] = {0, 0};
        MYSQL_BIND in[2] = {}, out[2] = {};
        in[0].buffer_type = MYSQL_TYPE_LONGLONG;
        in[0].buffer = &number;
        in[1].buffer_type = MYSQL_TYPE_STRING;
        in[1].buffer = text;
        in[1].buffer_length = sizeof(text);
        in[1].length = &len;
        in[1].is_null = &nulls[1];
        out[0].buffer_type = MYSQL_TYPE_LONGLONG;
        out[0].buffer = &out1;
        out[0].is_null = &nulls[0];
        out[1].buffer_type = MYSQL_TYPE_LONGLONG;
        out[1].buffer = &out2;
        my_bool outnull = 0;
        out[1].is_null = &outnull;
        bool bound = !mysql_stmt_bind_param(s, in) && !mysql_stmt_bind_result(s, out);
        bool executed = bound && !mysql_stmt_execute(s) && !mysql_stmt_fetch(s);
        ok(executed && out1 == 42 && out2 == 1 && !outnull,
           "bind integer and SQL-shaped literal text");
        mysql_stmt_free_result(s);
        number = -7;
        len = 0;
        outnull = 0;
        executed = bound && !mysql_stmt_execute(s) && !mysql_stmt_fetch(s);
        ok(executed && out1 == -7 && out2 == 0 && !outnull,
           "repeat with negative integer and empty text");
        mysql_stmt_free_result(s);
        nulls[1] = 1;
        outnull = 0;
        executed = bound && !mysql_stmt_execute(s) && !mysql_stmt_fetch(s);
        ok(executed && outnull, "NULL text remains NULL");
        mysql_stmt_free_result(s);
        mysql_stmt_close(s);
    }
    s = prepare(c, "SELECT ? + 0");
    ok(!s && last_errno == 1235 && last_error.find("unresolved result type") != std::string::npos,
       "unresolved native output metadata is refused before execution");
    if (s)
        mysql_stmt_close(s);
    s = prepare(c, "SELECT 1");
    ok(s != nullptr, "prepare before changing client encoding");
    ok(!mysql_set_character_set(c, "latin1", 8), "switch tracked client charset to latin1");
    if (s) {
        ok(mysql_stmt_execute(s) && mysql_stmt_errno(s) == 1105,
           "existing prepared execution refuses non-UTF8 client encoding");
    }
    ok(!mysql_set_character_set(c, "utf8mb4", 45), "restore tracked UTF8 client charset");
    if (s) {
        ok(!mysql_stmt_execute(s) && !mysql_stmt_store_result(s),
           "existing prepared execution recovers after UTF8 restoration");
        mysql_stmt_free_result(s);
        mysql_stmt_close(s);
    }
    std::string table = "duckdb_prep_my_" + std::to_string((long)getpid());
    bool created = !mysql_query(
        c, ("CREATE TABLE " + table + " (v INTEGER, b BOOLEAN, f BOOLEAN, d DECIMAL(8,2), x BLOB)")
               .c_str());
    if (!created)
        BAIL_OUT("create owned table: %s", mysql_error(c));
    if (mysql_query(
            c, ("INSERT INTO " + table + " VALUES (1, TRUE, FALSE, 12.34, '\\x00\\xFF')").c_str()))
        BAIL_OUT("insert fixture: %s", mysql_error(c));
    s = prepare(c, ("SELECT b, f, d, x FROM " + table).c_str());
    ok(s != nullptr, "prepare native constants");
    if (s) {
        MYSQL_RES *m = mysql_stmt_result_metadata(s);
        MYSQL_FIELD *f = m ? mysql_fetch_fields(m) : nullptr;
        ok(m && mysql_num_fields(m) == 4 && f[0].type == MYSQL_TYPE_TINY &&
               f[1].type == MYSQL_TYPE_TINY && f[2].type == MYSQL_TYPE_NEWDECIMAL &&
               f[3].type == MYSQL_TYPE_BLOB,
           "boolean decimal blob metadata types");
        char data[4][128] = {};
        unsigned long lengths[4] = {};
        my_bool isnull[4] = {};
        MYSQL_BIND b[4] = {};
        for (int i = 0; i < 4; i++) {
            b[i].buffer_type = MYSQL_TYPE_STRING;
            b[i].buffer = data[i];
            b[i].buffer_length = sizeof(data[i]);
            b[i].length = &lengths[i];
            b[i].is_null = &isnull[i];
        }
        bool done = !mysql_stmt_bind_result(s, b) && !mysql_stmt_execute(s) && !mysql_stmt_fetch(s);
        const unsigned char blob[] = {0, 255};
        ok(done && !strcmp(data[0], "1") && !strcmp(data[1], "0") && !strcmp(data[2], "12.34") &&
               lengths[3] == 2 && !memcmp(data[3], blob, 2),
           "boolean decimal and binary blob values");
        if (m)
            mysql_free_result(m);
        mysql_stmt_close(s);
    }
    auto count = [&]() -> long {
        if (mysql_query(c, ("SELECT COUNT(*) FROM " + table).c_str()))
            return -1;
        MYSQL_RES *r = mysql_store_result(c);
        if (!r)
            return -1;
        MYSQL_ROW row = mysql_fetch_row(r);
        long n = row && row[0] ? strtol(row[0], nullptr, 10) : -1;
        mysql_free_result(r);
        return n;
    };
    s = prepare(c, ("INSERT INTO " + table + " (v) VALUES (2)").c_str());
    ok(!s && last_errno == 1235 &&
           last_error.find("prepared SQL is not an allowed read-only SELECT") != std::string::npos,
       "prepared DML refused by read-only policy: %s", last_error.c_str());
    if (s)
        mysql_stmt_close(s);
    ok(count() == 1, "refused DML leaves fixture unchanged");
    s = prepare(c, "SELECT * FROM read_parquet('/tmp/duckdb_prepared_forbidden.parquet')");
    ok(!s && (last_error.find("prepared SQL is not an allowed read-only SELECT") !=
                  std::string::npos ||
              last_error.find("external access") != std::string::npos),
       "external file access refused: %s", last_error.c_str());
    if (s)
        mysql_stmt_close(s);
    ok(!mysql_query(c, "BEGIN"), "begin explicit transaction");
    ok(!mysql_query(c, ("INSERT INTO " + table + " (v) VALUES (3)").c_str()),
       "insert inside transaction");
    s = prepare(c, "SELECT 1");
    ok(!s && last_errno == 1105 &&
           last_error.find("prepared execution requires an idle autocommit session") !=
               std::string::npos,
       "prepare refused in explicit transaction: %s", last_error.c_str());
    if (s)
        mysql_stmt_close(s);
    ok(!mysql_query(c, "ROLLBACK"), "rollback transaction");
    ok(count() == 1, "rollback preserves initial row and removes transaction insert");
    ok(mysql_autocommit(c, 0) && mysql_errno(c) == 1235 &&
           !strcmp(mysql_sqlstate(c), "0A000"),
       "unsupported implicit transaction mode is refused without state change");
    s = prepare(c, "SELECT 1");
    ok(s != nullptr, "prepared execution remains usable after rejected autocommit change");
    if (s) mysql_stmt_close(s);
    ok(!mysql_autocommit(c, 1), "autocommit already enabled remains accepted");
    const std::string temporary = table + "_temporary";
    ok(!mysql_query(c, ("CREATE TEMP TABLE " + temporary + " (v INTEGER)").c_str()),
       "create connection-local temporary table before reset");
    ok(!mysql_query(c, "BEGIN") &&
           !mysql_query(c, ("INSERT INTO " + table + " (v) VALUES (4)").c_str()),
       "create pending client work before connection reset");
    ok(!mysql_reset_connection(c), "reset connection with pending native transaction");
    ok(count() == 1, "connection reset rolls back pending native writes");
    const int temporary_status = mysql_query(c, ("SELECT * FROM " + temporary).c_str());
    ok(temporary_status != 0, "connection reset discards temporary tables");
    if (!temporary_status) {
        MYSQL_RES *unexpected = mysql_store_result(c);
        if (unexpected) mysql_free_result(unexpected);
    }
    ok(!mysql_set_character_set(c, "utf8mb4", 45), "select UTF8 after connection reset");
    s = prepare(c, "SELECT 1");
    ok(s != nullptr, "public provider registration survives connection reset");
    if (s) {
        ok(!mysql_stmt_execute(s) && !mysql_stmt_store_result(s),
           "prepared execution uses the replacement native connection");
        mysql_stmt_free_result(s);
        mysql_stmt_close(s);
    }
    bool healthy = !mysql_query(c, "SELECT 1");
    MYSQL_RES *result = healthy ? mysql_store_result(c) : nullptr;
    MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
    ok(row && row[0] && !strcmp(row[0], "1"), "session healthy after refusals");
    if (result)
        mysql_free_result(result);
    if (created)
        ok(!mysql_query(c, ("DROP TABLE " + table).c_str()), "drop owned table");
    mysql_close(c);
    return exit_status();
}
