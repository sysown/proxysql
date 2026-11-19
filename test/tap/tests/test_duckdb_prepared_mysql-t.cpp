#include "prepared_owned_fixture.h"
#include "mysql.h"
#include "tap.h"
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <unistd.h>

static std::string last_error;
static unsigned int last_errno;
static MYSQL_STMT *prepare(MYSQL *c, std::string_view sql) {
    MYSQL_STMT *s = mysql_stmt_init(c);
    if (!s)
        BAIL_OUT("stmt init failed");
    if (mysql_stmt_prepare(s, sql.data(), static_cast<unsigned long>(sql.size()))) {
        last_error = mysql_stmt_error(s);
        last_errno = mysql_stmt_errno(s);
        diag("prepare failed (%u/%s): %s; SQL: %s", mysql_stmt_errno(s), mysql_stmt_sqlstate(s),
             mysql_stmt_error(s), sql.data());
        mysql_stmt_close(s);
        return nullptr;
    }
    return s;
}
int main() {
    prepared_owned_fixture::Fixture fixture;
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
        unsigned long len = sizeof(text) - 1;
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
    auto write = [&](const std::string &sql, int value, my_ulonglong affected) {
        MYSQL_STMT *stmt = prepare(c, sql);
        if (!stmt) return false;
        MYSQL_BIND param[1] = {};
        param[0].buffer_type = MYSQL_TYPE_LONG;
        param[0].buffer = &value;
        bool success = !mysql_stmt_bind_param(stmt, param) && !mysql_stmt_execute(stmt) &&
                       mysql_stmt_affected_rows(stmt) == affected;
        if (!success) diag("prepared write failed: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return success;
    };
    ok(write("INSERT INTO " + table + " (v) VALUES (?)", 2, 1),
       "bound INSERT reports one affected row");
    ok(count() == 2, "ordinary SELECT sees prepared INSERT");
    ok(write("UPDATE " + table + " SET v = 5 WHERE v = ?", 2, 1),
       "bound UPDATE reports one affected row");
    ok(write("DELETE FROM " + table + " WHERE v = ?", 5, 1),
       "bound DELETE reports one affected row");
    ok(write("DELETE FROM " + table + " WHERE v = ?", 5, 0),
       "bound DELETE reports zero affected rows when no rows match");
    ok(count() == 1, "ordinary SELECT sees prepared UPDATE and DELETE");
    s = prepare(c, ("INSERT INTO " + table + " (v) VALUES (?) RETURNING v").c_str());
    ok(s != nullptr, "prepare bound INSERT RETURNING");
    if (s) {
        int input = 9, output = 0;
        MYSQL_BIND in[1] = {}, out[1] = {};
        in[0].buffer_type = out[0].buffer_type = MYSQL_TYPE_LONG;
        in[0].buffer = &input;
        out[0].buffer = &output;
        bool returned = !mysql_stmt_bind_param(s, in) && !mysql_stmt_bind_result(s, out) &&
                        !mysql_stmt_execute(s) && !mysql_stmt_fetch(s);
        ok(returned && output == 9, "bound INSERT RETURNING yields inserted value");
        mysql_stmt_close(s);
    }
    ok(count() == 2, "ordinary SELECT sees successful RETURNING write");
    ok(!mysql_query(c, ("DELETE FROM " + table + " WHERE v = 9").c_str()),
       "remove successful RETURNING row");
    s = prepare(c, ("INSERT INTO " + table + " (v) VALUES (10) RETURNING repeat('x', 67108865)").c_str());
    ok(s != nullptr, "prepare write with oversized RETURNING result");
    if (s) {
        int oversized_rc = mysql_stmt_execute(s);
        diag("oversized RETURNING error %u: %s", mysql_stmt_errno(s), mysql_stmt_error(s));
        ok(oversized_rc != 0 && strstr(mysql_stmt_error(s), "budget"),
           "oversized RETURNING result is refused by the result budget");
        mysql_stmt_close(s);
    }
    MYSQL *verify = mysql_init(nullptr);
    bool connected = verify && mysql_real_connect(verify, host && *host ? host : "127.0.0.1",
                                                   user, pass, nullptr,
                                                   port && *port ? atoi(port) : 6031, nullptr, 0);
    long verify_count = -1;
    if (connected && !mysql_query(verify, ("SELECT COUNT(*) FROM " + table).c_str())) {
        MYSQL_RES *check = mysql_store_result(verify);
        MYSQL_ROW value = check ? mysql_fetch_row(check) : nullptr;
        if (value && value[0]) verify_count = strtol(value[0], nullptr, 10);
        if (check) mysql_free_result(check);
    }
    diag("fresh connection count %ld, error %u: %s", verify_count, verify ? mysql_errno(verify) : 0, verify ? mysql_error(verify) : "init failed");
    ok(verify_count == 1, "fresh connection sees oversized RETURNING write rolled back");
    if (verify_count != 1 && !fixture.dir.empty()) {
        std::ifstream log(fixture.dir + "/proxysql.log");
        std::string line;
        while (std::getline(log, line)) diag("fixture log: %s", line.c_str());
    }
    if (verify) mysql_close(verify);
    s = prepare(c, "SELECT * FROM read_parquet('/tmp/duckdb_prepared_forbidden.parquet')");
    ok(!s && (last_error.find("external access") != std::string::npos ||
        last_error.find("file system operations are disabled") != std::string::npos),
       "prepared external file access respects database policy: %s", last_error.c_str());
    if (s)
        mysql_stmt_close(s);
    ok(!mysql_query(c, "BEGIN"), "begin explicit transaction");
    ok(write("INSERT INTO " + table + " (v) VALUES (?)", 3, 1),
       "bound INSERT executes in explicit transaction");
    ok(count() == 2, "ordinary SELECT sees prepared transaction write");
    ok(!mysql_query(c, "ROLLBACK"), "rollback transaction");
    ok(count() == 1, "rollback removes prepared transaction write");
    ok(mysql_autocommit(c, 0) && mysql_errno(c) == 1235 && !strcmp(mysql_sqlstate(c), "0A000"),
       "unsupported implicit transaction mode is refused without state change");
    s = prepare(c, "SELECT 1");
    ok(s != nullptr, "prepared execution remains usable after rejected autocommit change");
    if (s)
        mysql_stmt_close(s);
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
        if (unexpected)
            mysql_free_result(unexpected);
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
    const std::string wide = "duckdb_wide_my_" + std::to_string((long)getpid());
    const char min128[] = "-170141183460469231731687303715884105728";
    const char maxu128[] = "340282366920938463463374607431768211455";
    const char over128[] = "170141183460469231731687303715884105728";
    bool wide_created =
        !mysql_query(c, ("CREATE TABLE " + wide + " (w HUGEINT, u UHUGEINT)").c_str());
    ok(wide_created, "create owned wide numeric table: %s", mysql_error(c));
    if (wide_created) {
        std::string insert =
            "INSERT INTO " + wide + " VALUES ('" + min128 + "', '" + maxu128 + "')";
        ok(!mysql_query(c, insert.c_str()), "insert wide numeric boundaries: %s", mysql_error(c));
        s = prepare(c, ("SELECT w, u FROM " + wide + " WHERE w = ?").c_str());
        ok(s != nullptr, "prepare wide numeric predicate");
        if (s) {
            MYSQL_RES *meta = mysql_stmt_result_metadata(s);
            MYSQL_FIELD *f = meta ? mysql_fetch_fields(meta) : nullptr;
            ok(meta && mysql_num_fields(meta) == 2 && f[0].type == MYSQL_TYPE_NEWDECIMAL &&
                   f[1].type == MYSQL_TYPE_NEWDECIMAL && f[0].length == 40 && f[1].length == 40 &&
                   f[0].decimals == 0 && f[1].decimals == 0,
               "wide columns advertise DECIMAL(39,0)");
            if (meta)
                mysql_free_result(meta);
            char input[64];
            std::memcpy(input, min128, sizeof(min128));
            unsigned long input_len = sizeof(min128) - 1;
            MYSQL_BIND param[1] = {};
            param[0].buffer_type = MYSQL_TYPE_NEWDECIMAL;
            param[0].buffer = input;
            param[0].buffer_length = sizeof(input);
            param[0].length = &input_len;
            char result_values[2][64] = {};
            unsigned long result_len[2] = {};
            MYSQL_BIND output[2] = {};
            for (int j = 0; j < 2; ++j) {
                output[j].buffer_type = MYSQL_TYPE_NEWDECIMAL;
                output[j].buffer = result_values[j];
                output[j].buffer_length = sizeof(result_values[j]);
                output[j].length = &result_len[j];
            }
            bool bound = !mysql_stmt_bind_param(s, param) && !mysql_stmt_bind_result(s, output);
            bool fetched = bound && !mysql_stmt_execute(s) && !mysql_stmt_fetch(s);
            ok(fetched && result_len[0] == sizeof(min128) - 1 &&
                   result_len[1] == sizeof(maxu128) - 1 &&
                   !memcmp(result_values[0], min128, result_len[0]) &&
                   !memcmp(result_values[1], maxu128, result_len[1]),
               "bind signed minimum and return exact signed and unsigned boundaries");
            mysql_stmt_free_result(s);
            std::memcpy(input, over128, sizeof(over128));
            input_len = sizeof(over128) - 1;
            ok(mysql_stmt_execute(s) != 0, "out-of-range signed HUGEINT bind is refused");
            mysql_stmt_free_result(s);
            std::memcpy(input, min128, sizeof(min128));
            input_len = sizeof(min128) - 1;
            fetched = !mysql_stmt_execute(s) && !mysql_stmt_fetch(s);
            ok(fetched && result_len[0] == sizeof(min128) - 1 &&
                   !memcmp(result_values[0], min128, result_len[0]),
               "valid wide bind recovers after overflow");
            mysql_stmt_free_result(s);
            mysql_stmt_close(s);
        }
        ok(!mysql_query(c, ("DROP TABLE " + wide).c_str()), "drop owned wide table");
    }
    s = prepare(c, ("SELECT SUM(v) FROM " + table + " WHERE v = ?").c_str());
    ok(s != nullptr, "prepare integer SUM with typed predicate");
    if (s) {
        MYSQL_RES *meta = mysql_stmt_result_metadata(s);
        MYSQL_FIELD *f = meta ? mysql_fetch_fields(meta) : nullptr;
        ok(meta && f[0].type == MYSQL_TYPE_NEWDECIMAL && f[0].length == 40 && f[0].decimals == 0,
           "integer SUM advertises DECIMAL(39,0)");
        if (meta)
            mysql_free_result(meta);
        int v = 1;
        MYSQL_BIND param[1] = {};
        param[0].buffer_type = MYSQL_TYPE_LONG;
        param[0].buffer = &v;
        char value[64] = {};
        unsigned long length = 0;
        MYSQL_BIND output[1] = {};
        output[0].buffer_type = MYSQL_TYPE_NEWDECIMAL;
        output[0].buffer = value;
        output[0].buffer_length = sizeof(value);
        output[0].length = &length;
        bool fetched = !mysql_stmt_bind_param(s, param) && !mysql_stmt_bind_result(s, output) &&
                       !mysql_stmt_execute(s) && !mysql_stmt_fetch(s);
        ok(fetched && length == 1 && value[0] == '1', "integer SUM returns exact decimal value");
        mysql_stmt_free_result(s);
        mysql_stmt_close(s);
    }
    if (created)
        ok(!mysql_query(c, ("DROP TABLE " + table).c_str()), "drop owned table");
    const std::string readonly_table = table + "_ro";
    if (!fixture.dir.empty()) {
        bool seeded = !mysql_query(c, ("CREATE TABLE " + readonly_table + " (v INTEGER)").c_str()) &&
                      !mysql_query(c, ("INSERT INTO " + readonly_table + " VALUES (1)").c_str());
        ok(seeded, "seed read-only database fixture");
        mysql_close(c);
        c = nullptr;
        bool reopened = seeded && fixture.reopen_read_only();
        ok(reopened, "reopen DuckDB read-only");
        if (reopened) {
            c = mysql_init(nullptr);
            bool connected_ro = c && mysql_real_connect(c, host, user, pass, nullptr, atoi(port), nullptr, 0);
            ok(connected_ro, "connect to read-only DuckDB");
            if (connected_ro) {
                ok(!mysql_query(c, ("SELECT * FROM " + readonly_table).c_str()), "ordinary read works in read-only database");
                MYSQL_RES *rows = mysql_store_result(c);
                if (rows) mysql_free_result(rows);
                ok(mysql_query(c, ("INSERT INTO " + readonly_table + " VALUES (2)").c_str()) != 0,
                   "ordinary write is refused by read-only database");
                mysql_set_character_set(c, "utf8mb4", 45);
                MYSQL_STMT *ro = prepare(c, ("INSERT INTO " + readonly_table + " VALUES (?)").c_str());
                bool denied = !ro;
                if (ro) {
                    int value = 2; MYSQL_BIND bind[1] = {};
                    bind[0].buffer_type = MYSQL_TYPE_LONG; bind[0].buffer = &value;
                    denied = !mysql_stmt_bind_param(ro, bind) && mysql_stmt_execute(ro) != 0;
                    mysql_stmt_close(ro);
                }
                ok(denied, "prepared write is refused by read-only database");
            }
        }
    }
    if (c) mysql_close(c);
    return exit_status();
}
