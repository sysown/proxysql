// Differential experiment only: every SQL string is handwritten, not translator output.
#include <cstdlib>
#include <duckdb.h>
#include <iostream>
#include <memory>
#include <mysql.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>
using namespace std;
struct Cell {
    bool null;
    string text;
    bool operator==(const Cell &o) const { return null == o.null && (null || text == o.text); }
};
static string exact_decimal(string s) {
    auto dot = s.find('.');
    if (dot != string::npos) {
        while (!s.empty() && s.back() == '0')
            s.pop_back();
        if (!s.empty() && s.back() == '.')
            s.pop_back();
    }
    if (s == "-0")
        s = "0";
    return s;
}
struct Result {
    vector<string> names;
    vector<int> types;
    vector<vector<Cell>> rows;
};
static int mysql_kind(enum enum_field_types t) {
    switch (t) {
    case MYSQL_TYPE_TINY:
    case MYSQL_TYPE_SHORT:
    case MYSQL_TYPE_LONG:
    case MYSQL_TYPE_LONGLONG:
    case MYSQL_TYPE_INT24:
        return 1;
    case MYSQL_TYPE_DECIMAL:
    case MYSQL_TYPE_NEWDECIMAL:
        return 2;
    case MYSQL_TYPE_DATE:
        return 3;
    case MYSQL_TYPE_DATETIME:
    case MYSQL_TYPE_TIMESTAMP:
        return 4;
    case MYSQL_TYPE_STRING:
    case MYSQL_TYPE_VAR_STRING:
    case MYSQL_TYPE_VARCHAR:
    case MYSQL_TYPE_BLOB:
        return 5;
    default:
        return 0;
    }
}
static int duck_kind(duckdb_type t) {
    switch (t) {
    case DUCKDB_TYPE_TINYINT:
    case DUCKDB_TYPE_SMALLINT:
    case DUCKDB_TYPE_INTEGER:
    case DUCKDB_TYPE_BIGINT:
    case DUCKDB_TYPE_HUGEINT:
    case DUCKDB_TYPE_UTINYINT:
    case DUCKDB_TYPE_USMALLINT:
    case DUCKDB_TYPE_UINTEGER:
    case DUCKDB_TYPE_UBIGINT:
    case DUCKDB_TYPE_UHUGEINT:
        return 1;
    case DUCKDB_TYPE_DECIMAL:
        return 2;
    case DUCKDB_TYPE_DATE:
        return 3;
    case DUCKDB_TYPE_TIMESTAMP:
        return 4;
    case DUCKDB_TYPE_VARCHAR:
        return 5;
    case DUCKDB_TYPE_BLOB:
        return 6;
    default:
        return 0;
    }
}
static void mysql_exec(MYSQL *m, const string &sql) {
    if (mysql_query(m, sql.c_str()))
        throw runtime_error(string("MySQL: ") + mysql_error(m) + " SQL: " + sql);
}
struct DuckResult {
    duckdb_result value{};
    ~DuckResult() { duckdb_destroy_result(&value); }
};
static Result mysql_result(MYSQL *m, const string &sql) {
    mysql_exec(m, sql);
    unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> holder(mysql_store_result(m),
                                                               mysql_free_result);
    MYSQL_RES *r = holder.get();
    if (!r)
        throw runtime_error(mysql_error(m));
    Result out;
    unsigned n = mysql_num_fields(r);
    MYSQL_FIELD *fields = mysql_fetch_fields(r);
    for (unsigned i = 0; i < n; i++) {
        out.names.emplace_back(fields[i].name);
        int kind = mysql_kind(fields[i].type);
        if (kind == 5 && fields[i].charsetnr == 63)
            kind = 6;
        out.types.push_back(kind);
    }
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(r))) {
        auto lengths = mysql_fetch_lengths(r);
        vector<Cell> cells;
        for (unsigned i = 0; i < n; i++)
            cells.push_back({row[i] == nullptr,
                             row[i] ? (out.types[i] == 2 ? exact_decimal(string(row[i], lengths[i]))
                                                         : string(row[i], lengths[i]))
                                    : ""});
        out.rows.push_back(cells);
    }
    if (mysql_errno(m))
        throw runtime_error(mysql_error(m));
    return out;
}
static void duck_exec(duckdb_connection c, const string &sql) {
    DuckResult result;
    auto &r = result.value;
    auto status = duckdb_query(c, sql.c_str(), &r);
    if (status != DuckDBSuccess)
        throw runtime_error(string("DuckDB: ") +
                            (duckdb_result_error(&r) ? duckdb_result_error(&r) : "") +
                            " SQL: " + sql);
}
static Result duck_result(duckdb_connection c, const string &sql) {
    DuckResult result;
    auto &r = result.value;
    if (duckdb_query(c, sql.c_str(), &r) != DuckDBSuccess)
        throw runtime_error(string("DuckDB: ") +
                            (duckdb_result_error(&r) ? duckdb_result_error(&r) : "") +
                            " SQL: " + sql);
    Result out;
    auto n = duckdb_column_count(&r);
    for (idx_t i = 0; i < n; i++) {
        out.names.emplace_back(duckdb_column_name(&r, i));
        out.types.push_back(duck_kind(duckdb_column_type(&r, i)));
    }
    for (idx_t j = 0; j < duckdb_row_count(&r); j++) {
        vector<Cell> cells;
        for (idx_t i = 0; i < n; i++) {
            if (duckdb_value_is_null(&r, i, j))
                cells.push_back({true, ""});
            else if (out.types[i] == 6) {
                duckdb_blob blob = duckdb_value_blob(&r, i, j);
                unique_ptr<void, decltype(&duckdb_free)> data(blob.data, duckdb_free);
                if (!blob.data && blob.size)
                    throw runtime_error("DuckDB blob conversion failed");
                cells.push_back({false, blob.size
                                            ? string(static_cast<char *>(blob.data), blob.size)
                                            : string()});
            } else {
                unique_ptr<char, decltype(&duckdb_free)> value(duckdb_value_varchar(&r, i, j),
                                                               duckdb_free);
                if (!value)
                    throw runtime_error("DuckDB value conversion failed");
                cells.push_back(
                    {false, out.types[i] == 2 ? exact_decimal(value.get()) : string(value.get())});
            }
        }
        out.rows.push_back(cells);
    }
    return out;
}
struct Case {
    const char *name, *mysql, *duck;
    bool equal;
};
int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        cerr << "usage: " << argv[0] << " /absolute/path/to/owned-test-mysql.sock\n";
        return 2;
    }
    const char *socket = argv[1];
    MYSQL *m = mysql_init(nullptr);
    if (!m) {
        cerr << "mysql_init failed\n";
        return 1;
    }
    duckdb_database db = nullptr;
    duckdb_connection c = nullptr;
    string schema = "semantic_oracle_" + to_string(getpid());
    bool created = false;
    int failures = 0;
    try {
        if (!mysql_real_connect(m, "localhost", "root", "", nullptr, 0, socket, 0))
            throw runtime_error(mysql_error(m));
        mysql_exec(m, "SET SESSION "
                      "sql_mode='STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_"
                      "BY_ZERO,ONLY_FULL_GROUP_BY'");
        mysql_exec(m, "SET NAMES utf8mb4 COLLATE utf8mb4_bin");
        mysql_exec(m, "SET SESSION time_zone='+00:00'");
        cout << "DuckDB " << duckdb_library_version() << "\n";
        auto settings = mysql_result(
            m, "SELECT VERSION(), @@session.sql_mode, @@session.character_set_connection, "
               "@@session.collation_connection, @@session.time_zone, "
               "@@session.div_precision_increment, @@lower_case_table_names");
        for (auto &x : settings.rows[0])
            cout << x.text << " | ";
        cout << "\n";
        mysql_exec(m, "CREATE DATABASE `" + schema + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin");
        created = true;
        mysql_exec(m, "USE `" + schema + "`");
        if (duckdb_open(nullptr, &db) != DuckDBSuccess || duckdb_connect(db, &c) != DuckDBSuccess)
            throw runtime_error("DuckDB open/connect failed");
        mysql_exec(m, "CREATE TABLE facts (id INT PRIMARY KEY, `odd``name` BIGINT, u BIGINT "
                      "UNSIGNED, amount DECIMAL(18,4), grp INT, d DATE, dt DATETIME, txt "
                      "VARCHAR(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin, bin VARBINARY(10))");
        duck_exec(
            c, "CREATE TABLE facts (id INTEGER PRIMARY KEY, \"odd`name\" BIGINT, u UBIGINT, amount "
               "DECIMAL(18,4), grp INTEGER, d DATE, dt TIMESTAMP, txt VARCHAR, bin BLOB)");
        string insert = "INSERT INTO facts VALUES "
                        "(1,-9223372036854775808,0,-10.2500,1,'2020-02-29','2020-02-29 "
                        "12:34:56','é',NULL),(2,9223372036854775807,18446744073709551615,10.2500,1,"
                        "'2000-01-01','2000-01-01 "
                        "00:00:00','a',NULL),(3,0,1,NULL,2,NULL,NULL,'a',NULL),(4,0,1,1.5000,NULL,'"
                        "2038-01-19','2038-01-19 03:14:07',NULL,NULL)";
        mysql_exec(m, insert);
        duck_exec(c, insert);
        mysql_exec(m, "UPDATE facts SET bin=X'00FF' WHERE id=1");
        duck_exec(c, "UPDATE facts SET bin=from_hex('00FF') WHERE id=1");
        mysql_exec(m, "CREATE TABLE avg_t (n INT, v DECIMAL(18,4))");
        duck_exec(c, "CREATE TABLE avg_t (n INTEGER, v DECIMAL(18,4))");
        mysql_exec(m, "INSERT INTO avg_t VALUES "
                      "(0,99999999999999.9999),(0,99999999999999.9999),(1,99999999999999.9999)");
        duck_exec(c, "INSERT INTO avg_t VALUES "
                     "(0,99999999999999.9999),(0,99999999999999.9999),(1,99999999999999.9999)");
        mysql_exec(m, "CREATE TABLE groups_t (grp INT, label VARCHAR(10))");
        duck_exec(c, "CREATE TABLE groups_t (grp INTEGER, label VARCHAR)");
        mysql_exec(m, "INSERT INTO groups_t VALUES (1,'one'),(2,'two'),(3,'empty')");
        duck_exec(c, "INSERT INTO groups_t VALUES (1,'one'),(2,'two'),(3,'empty')");
        const Case cases[] = {
            {"identifier and duplicate labels",
             "SELECT `odd``name` AS `same`, id AS `same` FROM facts ORDER BY id",
             "SELECT \"odd`name\" AS \"same\", id AS \"same\" FROM facts ORDER BY id", true},
            {"numeric boundaries", "SELECT id,u,amount FROM facts ORDER BY id",
             "SELECT id,u,amount FROM facts ORDER BY id", true},
            {"nullable temporal and UTF-8", "SELECT id,d,dt,txt,bin FROM facts ORDER BY id",
             "SELECT id,d,dt,txt,bin FROM facts ORDER BY id", true},
            {"limit offset", "SELECT id FROM facts ORDER BY id LIMIT 1, 2",
             "SELECT id FROM facts ORDER BY id LIMIT 2 OFFSET 1", true},
            {"limit zero", "SELECT id FROM facts ORDER BY id LIMIT 0",
             "SELECT id FROM facts ORDER BY id LIMIT 0", true},
            {"offset beyond end", "SELECT id FROM facts ORDER BY id LIMIT 2 OFFSET 99",
             "SELECT id FROM facts ORDER BY id LIMIT 2 OFFSET 99", true},
            {"null ascending", "SELECT id,grp FROM facts ORDER BY grp ASC,id ASC",
             "SELECT id,grp FROM facts ORDER BY grp ASC NULLS FIRST,id ASC", true},
            {"null descending", "SELECT id,grp FROM facts ORDER BY grp DESC,id ASC",
             "SELECT id,grp FROM facts ORDER BY grp DESC NULLS LAST,id ASC", true},
            {"join group aggregates",
             "SELECT g.grp,COUNT(f.id) AS n,SUM(f.amount) AS total FROM groups_t g LEFT JOIN facts "
             "f ON g.grp=f.grp GROUP BY g.grp ORDER BY g.grp",
             "SELECT g.grp,COUNT(f.id) AS n,SUM(f.amount) AS total FROM groups_t g LEFT JOIN facts "
             "f ON g.grp=f.grp GROUP BY g.grp ORDER BY g.grp",
             true},
            {"empty aggregate", "SELECT COUNT(*) AS n,SUM(amount) AS total FROM facts WHERE id<0",
             "SELECT COUNT(*) AS n,SUM(amount) AS total FROM facts WHERE id<0", true},
            {"date format", "SELECT id,DATE_FORMAT(d,'%Y-%m') AS ym FROM facts ORDER BY id",
             "SELECT id,strftime(d,'%Y-%m') AS ym FROM facts ORDER BY id", true},
            {"datetime format", "SELECT id,DATE_FORMAT(dt,'%Y-%m') AS ym FROM facts ORDER BY id",
             "SELECT id,strftime(dt,'%Y-%m') AS ym FROM facts ORDER BY id", true},
            {"AVG integer precision differs", "SELECT CAST(AVG(n) AS CHAR) AS v FROM avg_t",
             "SELECT CAST(AVG(n) AS VARCHAR) AS v FROM avg_t", false},
            {"AVG decimal precision differs", "SELECT CAST(AVG(v) AS CHAR) AS v FROM avg_t",
             "SELECT CAST(AVG(v) AS VARCHAR) AS v FROM avg_t", false},
            {"collation differs",
             "SELECT CAST('A' = _utf8mb4'a' COLLATE utf8mb4_general_ci AS CHAR) AS v",
             "SELECT CASE WHEN 'A' = 'a' THEN '1' ELSE '0' END AS v", false},
            {"numeric coercion differs", "SELECT CAST('2x' = 2 AS CHAR) AS v",
             "SELECT CASE WHEN TRY_CAST('2x' AS INTEGER) = 2 THEN '1' WHEN TRY_CAST('2x' AS "
             "INTEGER) <> 2 THEN '0' ELSE NULL END AS v",
             false},
            {"division differs", "SELECT CAST(3/2 AS CHAR) AS v",
             "SELECT CAST(3//2 AS VARCHAR) AS v", false}};
        for (const auto &q : cases) {
            auto a = mysql_result(m, q.mysql), b = duck_result(c, q.duck);
            bool same = a.names == b.names && a.types == b.types && a.rows == b.rows;
            bool known = true;
            for (int t : a.types)
                known &= t != 0;
            for (int t : b.types)
                known &= t != 0;
            bool ok = known &&
                      (q.equal ? same
                               : (a.names == b.names && a.types == b.types && !(a.rows == b.rows)));
            cout << (ok ? "PASS " : "FAIL ") << q.name
                 << (q.equal ? " [match]" : " [expected difference]");
            if (!q.equal && !a.rows.empty() && !b.rows.empty())
                cout << " mysql=" << (a.rows[0][0].null ? "NULL" : a.rows[0][0].text)
                     << " duckdb=" << (b.rows[0][0].null ? "NULL" : b.rows[0][0].text);
            cout << "\n";
            if (!ok) {
                failures++;
                cout << "  metadata labels=" << (a.names == b.names)
                     << " categories=" << (a.types == b.types) << " rows=" << (a.rows == b.rows)
                     << " known=" << known << "\n";
            }
        }
    } catch (const exception &e) {
        cerr << e.what() << "\n";
        failures++;
    }
    if (created && mysql_query(m, ("DROP DATABASE `" + schema + "`").c_str())) {
        cerr << "cleanup failed: " << mysql_error(m) << " database=" << schema << "\n";
        failures++;
    }
    if (c)
        duckdb_disconnect(&c);
    if (db)
        duckdb_close(&db);
    if (m)
        mysql_close(m);
    cout << "failures=" << failures << "\n";
    return failures ? 1 : 0;
}
