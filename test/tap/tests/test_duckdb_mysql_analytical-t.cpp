#include "libpq-fe.h"
#include "prepared_owned_fixture.h"
#include "tap.h"
#include <climits>
#include <cstring>
#include <string>
#include <vector>

static bool pg_exec(PGconn *c, const char *sql) {
    PGresult *r = PQexec(c, sql);
    bool success =
        r && (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
    if (!success)
        diag("PostgreSQL %s: %s", sql, r ? PQresultErrorMessage(r) : PQerrorMessage(c));
    if (r)
        PQclear(r);
    return success;
}
static MYSQL_STMT *prepare(MYSQL *c, const char *sql) {
    MYSQL_STMT *stmt = mysql_stmt_init(c);
    if (!stmt)
        return nullptr;
    if (mysql_stmt_prepare(stmt, sql, std::strlen(sql))) {
        diag("prepare %s: %s", sql, mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return nullptr;
    }
    return stmt;
}
static bool prepared_rows(MYSQL_STMT *stmt) {
    long long id = 0;
    MYSQL_BIND bind[1]{};
    bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
    bind[0].buffer = &id;
    if (mysql_stmt_bind_result(stmt, bind) || mysql_stmt_execute(stmt))
        return false;
    bool good = !mysql_stmt_fetch(stmt) && id == 2 && !mysql_stmt_fetch(stmt) && id == 3 &&
                mysql_stmt_fetch(stmt) == MYSQL_NO_DATA;
    mysql_stmt_free_result(stmt);
    return good;
}
static bool query_rows(MYSQL *c, const char *sql) {
    if (mysql_query(c, sql)) {
        diag("query %s: %s", sql, mysql_error(c));
        return false;
    }
    MYSQL_RES *r = mysql_store_result(c);
    if (!r)
        return false;
    MYSQL_ROW first = mysql_fetch_row(r);
    bool good = first && first[0] && !std::strcmp(first[0], "2");
    MYSQL_ROW second = mysql_fetch_row(r);
    good = good && second && second[0] && !std::strcmp(second[0], "3") && !mysql_fetch_row(r);
    mysql_free_result(r);
    return good;
}
static bool fetch_ids(MYSQL_STMT *stmt, const std::vector<long long> &expected) {
    long long id = 0;
    my_bool is_null = 0;
    MYSQL_BIND result[1]{};
    result[0].buffer_type = MYSQL_TYPE_LONGLONG;
    result[0].buffer = &id;
    result[0].is_null = &is_null;
    MYSQL_RES *meta = mysql_stmt_result_metadata(stmt);
    bool good =
        meta && mysql_num_fields(meta) == 1 && !std::strcmp(mysql_fetch_fields(meta)[0].name, "id");
    if (meta)
        mysql_free_result(meta);
    good = good && !mysql_stmt_bind_result(stmt, result) && !mysql_stmt_execute(stmt);
    for (long long value : expected) {
        if (!good || mysql_stmt_fetch(stmt) != 0 || is_null || id != value) {
            good = false;
            break;
        }
    }
    if (good)
        good = mysql_stmt_fetch(stmt) == MYSQL_NO_DATA;
    mysql_stmt_free_result(stmt);
    return good;
}
static void test_parameters(MYSQL *c, const char *label) {
    const char *sql = "SELECT id FROM tiny_fixture WHERE n = ? ORDER BY id";
    MYSQL_STMT *stmt = prepare(c, sql);
    ok(stmt != nullptr, "%s prepares signed parameter predicate", label);
    if (!stmt)
        return;
    long long value = 5;
    my_bool is_null = 0;
    MYSQL_BIND param[1]{};
    param[0].buffer_type = MYSQL_TYPE_LONGLONG;
    param[0].buffer = &value;
    param[0].is_null = &is_null;
    const bool bound = !mysql_stmt_bind_param(stmt, param);
    ok(bound && fetch_ids(stmt, {1}), "%s binds signed 5 and fetches row 1", label);
    value = 6;
    ok(bound && fetch_ids(stmt, {2}), "%s reuses cached type and fetches row 2 for 6", label);
    value = 200;
    ok(bound && fetch_ids(stmt, {}), "%s compares 200 without narrowing to TINYINT", label);
    is_null = 1;
    ok(bound && fetch_ids(stmt, {}), "%s NULL parameter yields no rows", label);
    is_null = 0;
    value = LLONG_MIN;
    ok(bound && fetch_ids(stmt, {}), "%s accepts INT64_MIN", label);
    value = LLONG_MAX;
    ok(bound && fetch_ids(stmt, {}), "%s accepts INT64_MAX", label);
    char text[] = "5";
    double floating = 5.0;
    unsigned long long unsigned_value = 5;
    for (int kind = 0; kind < 3; ++kind) {
        MYSQL_BIND bad[1]{};
        bad[0].buffer_type =
            kind == 0 ? MYSQL_TYPE_STRING : (kind == 1 ? MYSQL_TYPE_DOUBLE : MYSQL_TYPE_LONGLONG);
        bad[0].buffer = kind == 0 ? static_cast<void *>(text)
                                  : (kind == 1 ? static_cast<void *>(&floating)
                                               : static_cast<void *>(&unsigned_value));
        bad[0].buffer_length = kind == 0 ? 1 : sizeof(unsigned_value);
        bad[0].is_unsigned = kind == 2;
        bool rejected = !mysql_stmt_bind_param(stmt, bad) && mysql_stmt_execute(stmt) != 0 &&
                        mysql_stmt_errno(stmt) == 1235 &&
                        !std::strcmp(mysql_stmt_sqlstate(stmt), "0A000");
        ok(rejected, "%s refuses %s parameter with 1235/0A000 (got %u/%s %s)", label,
           kind == 0 ? "text" : (kind == 1 ? "double" : "unsigned"), mysql_stmt_errno(stmt),
           mysql_stmt_sqlstate(stmt), mysql_stmt_error(stmt));
    }
    value = 5;
    ok(!mysql_stmt_bind_param(stmt, param) && fetch_ids(stmt, {1}),
       "%s recovers after unsupported parameter kinds", label);
    mysql_stmt_close(stmt);
    stmt = prepare(c, "SELECT id FROM tiny_fixture WHERE ? < id AND id <= ? ORDER BY id");
    ok(stmt != nullptr, "%s prepares two separately positioned parameters", label);
    if (!stmt)
        return;
    long long bounds[2] = {1, 2};
    MYSQL_BIND args[2]{};
    for (int i = 0; i < 2; ++i) {
        args[i].buffer_type = MYSQL_TYPE_LONGLONG;
        args[i].buffer = &bounds[i];
    }
    ok(!mysql_stmt_bind_param(stmt, args) && fetch_ids(stmt, {2}),
       "%s preserves parameter order with distinct bounds", label);
    mysql_stmt_close(stmt);
}
static bool text_rows(MYSQL *c, const char *sql, const std::vector<const char *> &names,
                      const std::vector<std::vector<const char *>> &expected) {
    if (mysql_query(c, sql)) {
        diag("query %s: %s", sql, mysql_error(c));
        return false;
    }
    MYSQL_RES *r = mysql_store_result(c);
    if (!r)
        return false;
    bool good = mysql_num_fields(r) == names.size();
    MYSQL_FIELD *fields = mysql_fetch_fields(r);
    for (size_t i = 0; good && i < names.size(); ++i)
        good = !std::strcmp(fields[i].name, names[i]);
    for (const auto &values : expected) {
        MYSQL_ROW row = good ? mysql_fetch_row(r) : nullptr;
        good = row != nullptr;
        for (size_t i = 0; good && i < values.size(); ++i)
            good = values[i] ? row[i] && !std::strcmp(row[i], values[i]) : !row[i];
    }
    good = good && !mysql_fetch_row(r);
    mysql_free_result(r);
    return good;
}
static bool prepared_count(MYSQL_STMT *stmt, long long expected) {
    long long count = -1;
    MYSQL_BIND binding[1]{};
    binding[0].buffer_type = MYSQL_TYPE_LONGLONG;
    binding[0].buffer = &count;
    bool good = !mysql_stmt_bind_result(stmt, binding) && !mysql_stmt_execute(stmt) &&
                !mysql_stmt_fetch(stmt) && count == expected &&
                mysql_stmt_fetch(stmt) == MYSQL_NO_DATA;
    if (!good)
        diag("prepared COUNT: %u %s (count %lld)", mysql_stmt_errno(stmt), mysql_stmt_error(stmt),
             count);
    mysql_stmt_free_result(stmt);
    return good;
}
static void test_decimals(MYSQL *c, const char *label) {
    const char *fraction = "SELECT f FROM decimal_fixture ORDER BY id";
    ok(text_rows(c, fraction, {"f"}, {{"0.50"}, {"-0.25"}, {nullptr}}),
       "%s renders fraction-only DECIMAL text with a leading zero", label);
    bool meta = !mysql_query(c, fraction);
    MYSQL_RES *r = meta ? mysql_store_result(c) : nullptr;
    MYSQL_FIELD *field = r ? mysql_fetch_field(r) : nullptr;
    ok(field && field->type == MYSQL_TYPE_NEWDECIMAL && field->decimals == 2,
       "%s keeps fraction-only DECIMAL type and scale metadata", label);
    if (r)
        mysql_free_result(r);
    ok(text_rows(c, "SELECT f AS v, f AS v FROM decimal_fixture ORDER BY id", {"v", "v"},
                 {{"0.50", "0.50"}, {"-0.25", "-0.25"}, {nullptr, nullptr}}),
       "%s preserves explicit aliases on fraction-only DECIMAL", label);
    ok(text_rows(c, "SELECT * FROM decimal_fixture ORDER BY id", {"id", "f", "d"},
                 {{"1", "0.50", "1.0000"}, {"2", "-0.25", "2.5000"}, {"3", nullptr, nullptr}}),
       "%s expands STAR around fraction-only DECIMAL", label);
    ok(text_rows(c, "SELECT id FROM decimal_fixture WHERE d > 1.5 ORDER BY id", {"id"}, {{"2"}}),
       "%s compares DECIMAL column with exact decimal literal", label);
    ok(text_rows(c, "SELECT id FROM decimal_fixture WHERE f < 0.00 OR d = 1 ORDER BY id", {"id"},
                 {{"1"}, {"2"}}),
       "%s compares fraction-only and integer literals exactly", label);
    MYSQL_STMT *stmt = prepare(c, fraction);
    ok(stmt != nullptr, "%s prepares fraction-only DECIMAL projection", label);
    if (!stmt)
        return;
    char text[16];
    unsigned long length = 0;
    my_bool is_null = 0;
    MYSQL_BIND result[1]{};
    result[0].buffer_type = MYSQL_TYPE_STRING;
    result[0].buffer = text;
    result[0].buffer_length = sizeof(text);
    result[0].length = &length;
    result[0].is_null = &is_null;
    bool good = !mysql_stmt_bind_result(stmt, result) && !mysql_stmt_execute(stmt);
    for (const char *expected : {"0.50", "-0.25", static_cast<const char *>(nullptr)}) {
        good = good && !mysql_stmt_fetch(stmt) &&
               (expected ? !is_null && length == std::strlen(expected) &&
                               !std::memcmp(text, expected, length)
                         : is_null);
    }
    good = good && mysql_stmt_fetch(stmt) == MYSQL_NO_DATA;
    mysql_stmt_free_result(stmt);
    ok(good, "%s fetches prepared fraction-only DECIMAL values", label);
    mysql_stmt_close(stmt);
}
static void test_date_format(MYSQL *c, const char *label) {
    const char *name = "DATE_FORMAT(d,'%Y-%m')";
    ok(text_rows(c, "SELECT DATE_FORMAT(d,'%Y-%m') FROM date_fixture ORDER BY id", {name},
                 {{"2024-02"}, {nullptr}, {"1000-01"}}),
       "%s formats DATE with the MySQL source-text label and NULL", label);
    ok(text_rows(c, "SELECT id, DATE_FORMAT(d,'%Y-%m') AS ym FROM date_fixture ORDER BY id",
                 {"id", "ym"}, {{"1", "2024-02"}, {"2", nullptr}, {"3", "1000-01"}}),
       "%s formats DATE with an alias beside a plain column", label);
    MYSQL_STMT *stmt = prepare(c, "SELECT DATE_FORMAT(d,'%Y-%m') AS ym FROM date_fixture "
                                  "ORDER BY id");
    ok(stmt != nullptr, "%s prepares DATE_FORMAT", label);
    if (stmt) {
        char text[16];
        unsigned long length = 0;
        my_bool is_null = 0;
        MYSQL_BIND result[1]{};
        result[0].buffer_type = MYSQL_TYPE_STRING;
        result[0].buffer = text;
        result[0].buffer_length = sizeof(text);
        result[0].length = &length;
        result[0].is_null = &is_null;
        bool good = !mysql_stmt_bind_result(stmt, result) && !mysql_stmt_execute(stmt);
        for (const char *expected : {"2024-02", static_cast<const char *>(nullptr), "1000-01"}) {
            good = good && !mysql_stmt_fetch(stmt) &&
                   (expected ? !is_null && length == std::strlen(expected) &&
                                   !std::memcmp(text, expected, length)
                             : is_null);
        }
        good = good && mysql_stmt_fetch(stmt) == MYSQL_NO_DATA;
        mysql_stmt_free_result(stmt);
        ok(good, "%s fetches prepared DATE_FORMAT values", label);
        mysql_stmt_close(stmt);
    }
    ok(text_rows(c, "SELECT DATE_FORMAT(dt,'%Y-%m') AS ym FROM date_fixture ORDER BY id", {"ym"},
                 {{"2024-02"}, {nullptr}, {"1000-01"}}),
       "%s formats a column proven to be a MySQL DATETIME", label);
    for (const char *bad : {"SELECT DATE_FORMAT(ts,'%Y-%m') FROM date_fixture",
                            "SELECT DATE_FORMAT(d,'%Y-%m-%d') FROM date_fixture",
                            "SELECT DATE_FORMAT (d,'%Y-%m') FROM date_fixture"}) {
        const int status = mysql_query(c, bad);
        ok(status != 0 && mysql_errno(c) == 1235 && !std::strcmp(mysql_sqlstate(c), "0A000"),
           "%s refuses %s with 1235/0A000 (got %u/%s)", label, bad, mysql_errno(c),
           mysql_sqlstate(c));
    }
    stmt = prepare(c, "SELECT DATE_FORMAT(ts,'%Y-%m') FROM date_fixture");
    ok(!stmt, "%s refuses prepared TIMESTAMP DATE_FORMAT", label);
    if (stmt)
        mysql_stmt_close(stmt);
}
static void test_text(MYSQL *c, const char *label) {
    auto ids = [&](const char *sql, const std::vector<std::vector<const char *>> &expected) {
        return text_rows(c, sql, {"id"}, expected);
    };
    ok(ids("SELECT id FROM text_fixture WHERE t = 'a' ORDER BY id", {{"1"}}),
       "%s compares a utf8mb4_0900_bin column with a literal byte for byte", label);
    ok(ids("SELECT id FROM text_fixture WHERE t > 'a' ORDER BY id", {{"3"}, {"4"}, {"6"}}),
       "%s orders code points and treats a trailing space as significant", label);
    ok(ids("SELECT id FROM text_fixture WHERE t <> 'a' ORDER BY id",
           {{"2"}, {"3"}, {"4"}, {"6"}, {"7"}}),
       "%s excludes NULL from <> like MySQL", label);
    ok(ids("SELECT id FROM text_fixture WHERE 'é' = t ORDER BY id", {{"6"}}),
       "%s accepts the literal on the left with a multibyte character", label);
    ok(ids("SELECT id FROM text_fixture ORDER BY t, id",
           {{"5"}, {"7"}, {"2"}, {"1"}, {"3"}, {"4"}, {"6"}}),
       "%s sorts a proven binary text column with NULLs first", label);
    ok(ids("SELECT id FROM text_fixture ORDER BY t DESC, id",
           {{"6"}, {"4"}, {"3"}, {"1"}, {"2"}, {"7"}, {"5"}}),
       "%s sorts descending with NULLs last", label);
    for (const char *bad :
         {"SELECT id FROM text_fixture WHERE ai = 'a'", "SELECT id FROM text_fixture ORDER BY ai",
          "SELECT id FROM text_fixture WHERE t LIKE 'a%'",
          "SELECT id FROM text_fixture WHERE t = 'a\\b'"}) {
        const int status = mysql_query(c, bad);
        ok(status != 0 && mysql_errno(c) == 1235 && !std::strcmp(mysql_sqlstate(c), "0A000"),
           "%s refuses %s with 1235/0A000 (got %u/%s)", label, bad, mysql_errno(c),
           mysql_sqlstate(c));
    }
}
static void test_sum_avg(MYSQL *c, const char *label) {
    ok(text_rows(c,
                 "SELECT g, SUM(n), SUM(d), AVG(n), AVG(d) FROM agg_fixture GROUP BY g ORDER BY g",
                 {"g", "SUM(n)", "SUM(d)", "AVG(n)", "AVG(d)"},
                 {{"1", "30", "3.75", "15.0000", "1.875000"},
                  {"2", "5", "0.01", "5.0000", "0.010000"},
                  {"3", "-15", "-0.07", "-7.5000", "-0.035000"}}),
       "%s matches MySQL SUM/AVG values, scales and labels per group", label);
    ok(text_rows(c, "SELECT SUM(n) AS s, AVG(d) AS a FROM agg_fixture", {"s", "a"},
                 {{"20", "0.738000"}}),
       "%s rounds an ungrouped AVG exactly like MySQL", label);
    ok(text_rows(c, "SELECT SUM(n), AVG(d) FROM agg_fixture WHERE id > 99", {"SUM(n)", "AVG(d)"},
                 {{nullptr, nullptr}}),
       "%s returns NULL for SUM/AVG over an empty set", label);
    bool meta = !mysql_query(c, "SELECT AVG(d) FROM agg_fixture");
    MYSQL_RES *r = meta ? mysql_store_result(c) : nullptr;
    MYSQL_FIELD *field = r ? mysql_fetch_field(r) : nullptr;
    ok(field && field->type == MYSQL_TYPE_NEWDECIMAL && field->decimals == 6,
       "%s reports AVG(DECIMAL(10,2)) as NEWDECIMAL with scale 6", label);
    if (r)
        mysql_free_result(r);
    MYSQL_STMT *stmt = prepare(c, "SELECT AVG(d) FROM agg_fixture");
    ok(stmt != nullptr, "%s prepares AVG", label);
    if (stmt) {
        char text[32];
        unsigned long length = 0;
        MYSQL_BIND result[1]{};
        result[0].buffer_type = MYSQL_TYPE_STRING;
        result[0].buffer = text;
        result[0].buffer_length = sizeof(text);
        result[0].length = &length;
        bool good = !mysql_stmt_bind_result(stmt, result) && !mysql_stmt_execute(stmt) &&
                    !mysql_stmt_fetch(stmt) && length == 8 && !std::memcmp(text, "0.738000", 8) &&
                    mysql_stmt_fetch(stmt) == MYSQL_NO_DATA;
        mysql_stmt_free_result(stmt);
        ok(good, "%s fetches a prepared AVG", label);
        mysql_stmt_close(stmt);
    }
    for (const char *bad :
         {"SELECT SUM(DISTINCT n) FROM agg_fixture", "SELECT SUM(n + 1) FROM agg_fixture",
          "SELECT AVG(n) FROM agg_fixture HAVING AVG(n) > 1", "SELECT SUM (n) FROM agg_fixture"}) {
        const int status = mysql_query(c, bad);
        ok(status != 0 && mysql_errno(c) == 1235 && !std::strcmp(mysql_sqlstate(c), "0A000"),
           "%s refuses %s with 1235/0A000 (got %u/%s)", label, bad, mysql_errno(c),
           mysql_sqlstate(c));
    }
}
static void test_decimal_refresh(MYSQL *c, PGconn *pg) {
    bool created = pg_exec(pg, "CREATE TABLE widen_fixture (d DECIMAL(18,4))") &&
                   pg_exec(pg, "INSERT INTO widen_fixture VALUES (2.0000)");
    MYSQL_STMT *stmt =
        created ? prepare(c, "SELECT COUNT(*) FROM widen_fixture WHERE d > 1.5") : nullptr;
    ok(stmt && prepared_count(stmt, 1), "prepared DECIMAL COUNT executes before widening");
    bool widened = pg_exec(pg, "ALTER TABLE widen_fixture ALTER COLUMN d TYPE DECIMAL(22,4)") &&
                   pg_exec(pg, "INSERT INTO widen_fixture VALUES (999999999999999999.9999)");
    ok(stmt && widened && prepared_count(stmt, 2),
       "widened DECIMAL column refreshes native cast without overflow");
    if (stmt)
        mysql_stmt_close(stmt);
    created = pg_exec(pg, "CREATE TABLE rounding_fixture (d DECIMAL(2,2))");
    stmt = created ? prepare(c, "SELECT COUNT(*) FROM rounding_fixture WHERE d > .3") : nullptr;
    ok(stmt && prepared_count(stmt, 0), "prepared DECIMAL COUNT executes before scale increase");
    bool scaled = pg_exec(pg, "ALTER TABLE rounding_fixture ALTER COLUMN d TYPE DECIMAL(3,3)") &&
                  pg_exec(pg, "INSERT INTO rounding_fixture VALUES (.301)");
    ok(stmt && scaled && prepared_count(stmt, 1),
       "scale increase does not silently round through a stale cast");
    if (stmt)
        mysql_stmt_close(stmt);
    const char *projection = "SELECT f FROM projection_fixture";
    created = pg_exec(pg, "CREATE TABLE projection_fixture (f DECIMAL(4,4))") &&
              pg_exec(pg, "INSERT INTO projection_fixture VALUES (.5000)");
    stmt = created ? prepare(c, projection) : nullptr;
    ok(stmt && !mysql_stmt_execute(stmt), "prepared fraction-only projection executes");
    if (stmt)
        mysql_stmt_free_result(stmt);
    bool changed = pg_exec(pg, "ALTER TABLE projection_fixture ALTER COLUMN f TYPE DECIMAL(5,5)");
    if (stmt) {
        const int status = mysql_stmt_execute(stmt);
        ok(changed && status != 0 && mysql_stmt_errno(stmt) == 1615,
           "scale-changing projection requires reprepare: %u %s", mysql_stmt_errno(stmt),
           mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
    }
    stmt = changed ? prepare(c, projection) : nullptr;
    ok(stmt && !mysql_stmt_execute(stmt), "reprepared projection executes with new scale");
    if (stmt)
        mysql_stmt_close(stmt);
}
int main() {
    plan(NO_PLAN);
    prepared_owned_fixture::Fixture fixture("mysql_analytical");
    const std::string pgport = std::to_string(fixture.dp);
    const char *keys[] = {"host", "port", "user", "password", "dbname", "sslmode", nullptr};
    const char *values[] = {"127.0.0.1", pgport.c_str(), "fixture_client", "fixture_client",
                            "main",      "disable",      nullptr};
    PGconn *pg = PQconnectdbParams(keys, values, 0);
    if (!pg || PQstatus(pg) != CONNECTION_OK)
        BAIL_OUT("PostgreSQL fixture connect failed: %s",
                 pg ? PQerrorMessage(pg) : "allocation failed");
    if (!pg_exec(pg, "CREATE TABLE analytical_fixture (id INTEGER PRIMARY KEY, n INTEGER)") ||
        !pg_exec(pg, "INSERT INTO analytical_fixture VALUES (1,NULL),(2,10),(3,20)") ||
        !pg_exec(pg, "CREATE TABLE tiny_fixture (id INTEGER PRIMARY KEY, n TINYINT)") ||
        !pg_exec(pg, "INSERT INTO tiny_fixture VALUES (1,5),(2,6),(3,NULL)") ||
        !pg_exec(pg, "CREATE TABLE decimal_fixture (id INTEGER PRIMARY KEY, f DECIMAL(2,2), "
                     "d DECIMAL(18,4))") ||
        !pg_exec(pg, "INSERT INTO decimal_fixture VALUES (1,.50,1),(2,-.25,2.5),(3,NULL,NULL)") ||
        !pg_exec(pg, "CREATE TABLE date_fixture (id INTEGER PRIMARY KEY, d DATE, dt TIMESTAMP, ts "
                     "TIMESTAMP)") ||
        !pg_exec(pg, "INSERT INTO date_fixture VALUES (1,'2024-02-29','2024-02-29 10:00:00',"
                     "'2024-02-29 23:00:00'),(2,NULL,NULL,NULL),"
                     "(3,'1000-01-01','1000-01-01 00:00:00','2024-03-01 00:00:00')") ||
        !pg_exec(pg, "CREATE SCHEMA proxysql_replica") ||
        !pg_exec(pg,
                 "CREATE TABLE proxysql_replica.tables (source_id VARCHAR, schema_name VARCHAR, "
                 "table_name VARCHAR, primary_key VARCHAR, "
                 "PRIMARY KEY (source_id, schema_name, table_name))") ||
        !pg_exec(pg, "CREATE TABLE proxysql_replica.columns (source_id VARCHAR, schema_name "
                     "VARCHAR, table_name VARCHAR, column_name VARCHAR, ordinal INTEGER, "
                     "mysql_data_type VARCHAR, mysql_column_type VARCHAR, character_set_name "
                     "VARCHAR, collation_name VARCHAR, duckdb_type VARCHAR, "
                     "PRIMARY KEY (source_id, schema_name, table_name, column_name))") ||
        !pg_exec(pg, "INSERT INTO proxysql_replica.tables VALUES "
                     "('fixture','main','date_fixture','id')") ||
        !pg_exec(pg, "INSERT INTO proxysql_replica.columns VALUES "
                     "('fixture','main','date_fixture','id',1,'int','int','','','INTEGER'),"
                     "('fixture','main','date_fixture','d',2,'date','date','','','DATE'),"
                     "('fixture','main','date_fixture','dt',3,'datetime','datetime(6)','','',"
                     "'TIMESTAMP'),"
                     "('fixture','main','date_fixture','ts',4,'timestamp','timestamp','','',"
                     "'TIMESTAMP')") ||
        !pg_exec(pg, "CREATE TABLE agg_fixture (id INTEGER PRIMARY KEY, g INTEGER, n BIGINT, "
                     "d DECIMAL(10,2))") ||
        !pg_exec(pg, "INSERT INTO agg_fixture VALUES (1,1,10,1.25),(2,1,20,2.50),(3,2,NULL,NULL),"
                     "(4,2,5,0.01),(5,3,-7,-0.03),(6,3,-8,-0.04)") ||
        !pg_exec(pg, "CREATE TABLE text_fixture (id INTEGER PRIMARY KEY, t VARCHAR, ai VARCHAR)") ||
        !pg_exec(pg, "INSERT INTO text_fixture VALUES (1,'a','a'),(2,'A','A'),(3,'a ','a '),"
                     "(4,'b','b'),(5,NULL,NULL),(6,'é','é'),(7,'','')") ||
        !pg_exec(pg, "INSERT INTO proxysql_replica.tables VALUES "
                     "('fixture','main','text_fixture','id')") ||
        !pg_exec(pg, "INSERT INTO proxysql_replica.columns VALUES "
                     "('fixture','main','text_fixture','id',1,'int','int','','','INTEGER'),"
                     "('fixture','main','text_fixture','t',2,'varchar','varchar(10)','utf8mb4',"
                     "'utf8mb4_0900_bin','VARCHAR'),"
                     "('fixture','main','text_fixture','ai',3,'varchar','varchar(10)','utf8mb4',"
                     "'utf8mb4_0900_ai_ci','VARCHAR')") ||
        !pg_exec(pg, "CREATE SEQUENCE analytical_sequence START 1") ||
        !pg_exec(
            pg,
            "CREATE VIEW analytical_side_effect AS SELECT nextval('analytical_sequence') AS id"))
        BAIL_OUT("PostgreSQL fixture setup failed");
    ok(true, "native PostgreSQL listener creates tables, data, sequence and view");
    MYSQL *mysql =
        duckdb_replica_test::connect("127.0.0.1", fixture.d, "fixture_client", "fixture_client");
    if (!mysql)
        BAIL_OUT("MySQL DuckDB fixture connect failed");
    ok(!mysql_set_character_set(mysql, "utf8mb4", 45), "select UTF-8 MySQL connection");
    const char *sql = "SELECT `id` FROM `analytical_fixture` ORDER BY `n`, `id` LIMIT 1,2";
    ok(query_rows(mysql, sql), "COM_QUERY translates backticks, NULL ordering and comma LIMIT");
    const char *grouped =
        "SELECT MIN(id) AS id FROM analytical_fixture GROUP BY n ORDER BY n LIMIT 1,2";
    ok(query_rows(mysql, grouped),
       "COM_QUERY groups integer keys and returns MIN with deterministic LIMIT");
    MYSQL_STMT *group_stmt = prepare(mysql, grouped);
    ok(group_stmt && prepared_rows(group_stmt),
       "prepared grouping executes through shared framework");
    if (group_stmt)
        mysql_stmt_close(group_stmt);
    MYSQL_RES *r = nullptr;
    bool aliases = !mysql_query(
        mysql,
        "SELECT f.`id` AS x, f.`id` AS x FROM `analytical_fixture` AS f ORDER BY f.`id` LIMIT 1");
    if (aliases)
        r = mysql_store_result(mysql);
    MYSQL_FIELD *fields = r ? mysql_fetch_fields(r) : nullptr;
    MYSQL_ROW row = r ? mysql_fetch_row(r) : nullptr;
    ok(r && fields && mysql_num_fields(r) == 2 && !std::strcmp(fields[0].name, "x") &&
           !std::strcmp(fields[1].name, "x") && row && !std::strcmp(row[0], "1") &&
           !std::strcmp(row[1], "1"),
       "table and duplicate projection aliases survive translation");
    if (r)
        mysql_free_result(r);
    bool counted = !mysql_query(mysql, "SELECT COUNT(*) FROM `analytical_fixture`");
    r = counted ? mysql_store_result(mysql) : nullptr;
    row = r ? mysql_fetch_row(r) : nullptr;
    ok(row && row[0] && !std::strcmp(row[0], "3"), "COUNT(*) returns seeded row count");
    if (r)
        mysql_free_result(r);
    for (const char *bad :
         {"INSERT INTO analytical_fixture VALUES (4,40)",
          "SELECT STDDEV(n) FROM analytical_fixture", "SELECT ABS(id) FROM analytical_fixture",
          "SELECT id FROM analytical_fixture /* comment */", "SELECT ? FROM analytical_fixture"}) {
        const int query_status = mysql_query(mysql, bad);
        ok(query_status != 0 && mysql_errno(mysql) == 1235 &&
               !std::strcmp(mysql_sqlstate(mysql), "0A000"),
           "unsupported COM_QUERY returns 1235/0A000: %s (got %u/%s %s)", bad, mysql_errno(mysql),
           mysql_sqlstate(mysql), mysql_error(mysql));
    }
    const int invalid_status = mysql_query(mysql, "SELECT");
    ok(invalid_status != 0 && mysql_errno(mysql) == 1064 &&
           !std::strcmp(mysql_sqlstate(mysql), "42000"),
       "invalid SELECT returns syntax error 1064/42000 (got %u/%s %s)", mysql_errno(mysql),
       mysql_sqlstate(mysql), mysql_error(mysql));
    PGresult *pgrows = PQexec(pg, "SELECT COUNT(*) FROM analytical_fixture");
    ok(pgrows && PQresultStatus(pgrows) == PGRES_TUPLES_OK &&
           !std::strcmp(PQgetvalue(pgrows, 0, 0), "3"),
       "rejected DML leaves native data unchanged");
    if (pgrows)
        PQclear(pgrows);
    MYSQL_STMT *stmt = prepare(mysql, sql);
    ok(stmt != nullptr, "prepare translated zero-parameter SELECT");
    if (stmt) {
        ok(prepared_rows(stmt), "execute and fetch translated SELECT");
        ok(prepared_rows(stmt), "repeat translated prepared execution");
        ok(!mysql_stmt_reset(stmt), "reset translated prepared statement");
        ok(prepared_rows(stmt), "execute translated SELECT after reset");
        ok(!mysql_stmt_close(stmt), "close translated prepared statement");
    }
    stmt = prepare(mysql, "SELECT ? FROM analytical_fixture");
    ok(!stmt, "parameter in SELECT projection is refused");
    if (stmt)
        mysql_stmt_close(stmt);
    test_parameters(mysql, "direct listener");
    test_decimals(mysql, "direct listener");
    test_date_format(mysql, "direct listener");
    test_sum_avg(mysql, "direct listener");
    test_text(mysql, "direct listener");
    test_decimal_refresh(mysql, pg);
    stmt = prepare(mysql, "SELECT COUNT(*) FROM analytical_fixture WHERE n > 1");
    ok(stmt != nullptr, "prepare COUNT with referenced integer column");
    bool changed = pg_exec(pg, "ALTER TABLE analytical_fixture ALTER COLUMN n TYPE VARCHAR");
    ok(changed, "native PostgreSQL changes referenced column type");
    if (stmt) {
        const int status = mysql_stmt_execute(stmt);
        ok(changed && status != 0 && mysql_stmt_errno(stmt) == 1615,
           "unchanged COUNT output still requires reprepare after referenced type change: %u %s",
           mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
    }
    bool restored = pg_exec(pg, "ALTER TABLE analytical_fixture ALTER COLUMN n TYPE INTEGER");
    ok(restored, "native PostgreSQL restores integer column type");
    stmt =
        restored ? prepare(mysql, "SELECT COUNT(*) FROM analytical_fixture WHERE n > 1") : nullptr;
    ok(stmt != nullptr, "prepare COUNT again after restoring column type");
    if (stmt) {
        long long count = 0;
        MYSQL_BIND binding[1]{};
        binding[0].buffer_type = MYSQL_TYPE_LONGLONG;
        binding[0].buffer = &count;
        bool executed = !mysql_stmt_bind_result(stmt, binding) && !mysql_stmt_execute(stmt) &&
                        !mysql_stmt_fetch(stmt) && count == 2;
        ok(executed, "new COUNT statement executes after restoring column type");
        mysql_stmt_close(stmt);
    }
    ok(mysql_query(mysql, "SELECT id FROM analytical_side_effect") != 0,
       "COM_QUERY refuses hidden side-effect view");
    stmt = prepare(mysql, "SELECT id FROM analytical_side_effect");
    bool view_refused = !stmt || mysql_stmt_execute(stmt) != 0;
    ok(view_refused, "prepared SELECT refuses hidden side-effect view");
    if (stmt)
        mysql_stmt_close(stmt);
    pgrows = PQexec(pg, "SELECT nextval('analytical_sequence')");
    ok(pgrows && PQresultStatus(pgrows) == PGRES_TUPLES_OK &&
           !std::strcmp(PQgetvalue(pgrows, 0, 0), "1"),
       "refused view paths do not advance sequence");
    if (pgrows)
        PQclear(pgrows);
    ok(query_rows(mysql, sql), "connection recovers after rejected view");
    ok(!mysql_set_character_set(mysql, "latin1", 8), "switch client to latin1");
    ok(mysql_query(mysql, sql) != 0, "analytical query rejects latin1");
    stmt = prepare(mysql, "SELECT 1");
    ok(!stmt, "zero-parameter SELECT prepare rejects latin1");
    if (stmt)
        mysql_stmt_close(stmt);
    ok(!mysql_set_character_set(mysql, "utf8mb4", 45), "restore UTF-8 client charset");
    stmt = prepare(mysql, sql);
    ok(stmt != nullptr, "SELECT prepare recovers after restoring UTF-8");
    if (stmt) {
        ok(prepared_rows(stmt), "prepared SELECT executes after UTF-8 recovery");
        mysql_stmt_close(stmt);
    }
    ok(query_rows(mysql, sql), "analytical query recovers after restoring UTF-8");
    const std::string server =
        "INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES (91,'127.0.0.1'," +
        std::to_string(fixture.d) + ")";
    bool routed =
        duckdb_replica_test::query(fixture.admin, server) &&
        duckdb_replica_test::query(
            fixture.admin,
            "INSERT INTO mysql_query_rules(rule_id,active,username,destination_hostgroup,apply) "
            "VALUES (91,1,'fixture_client',91,1)") &&
        duckdb_replica_test::query(fixture.admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
        duckdb_replica_test::query(fixture.admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
    ok(routed, "configure query rule to the owned DuckDB listener");
    MYSQL *proxied = routed ? duckdb_replica_test::connect("127.0.0.1", fixture.m, "fixture_client",
                                                           "fixture_client")
                            : nullptr;
    ok(proxied != nullptr, "connect through ordinary MySQL listener");
    if (proxied) {
        ok(!mysql_set_character_set(proxied, "utf8mb4", 45),
           "select UTF-8 through ordinary listener");
        ok(query_rows(proxied, sql), "ordinary listener routes analytical COM_QUERY to DuckDB");
        ok(query_rows(proxied, grouped), "ordinary routing preserves grouped analytical results");
        stmt = prepare(proxied, sql);
        ok(stmt != nullptr, "ordinary listener routes analytical prepare to DuckDB");
        if (stmt) {
            ok(prepared_rows(stmt), "ordinary listener fetches translated prepared result");
            mysql_stmt_close(stmt);
        }
        test_parameters(proxied, "ordinary routed listener");
        test_decimals(proxied, "ordinary routed listener");
        test_date_format(proxied, "ordinary routed listener");
        test_sum_avg(proxied, "ordinary routed listener");
        test_text(proxied, "ordinary routed listener");
        mysql_close(proxied);
    }
    mysql_close(mysql);
    PQfinish(pg);
    return exit_status();
}
