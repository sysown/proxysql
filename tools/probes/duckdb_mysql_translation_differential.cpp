// Differential experiment: DuckDB statements are translator output.
#include "duckdb_mysql_select_compat.h"
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
    bool operator==(const Cell &o) const {
        return null == o.null && (null || text == o.text);
    }
};
struct Result {
    vector<string> names;
    vector<int> types;
    vector<vector<Cell>> rows;
};
static int mysql_kind(enum enum_field_types t) {
    switch (t) {
    case MYSQL_TYPE_NULL:
        return 7;
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
    case DUCKDB_TYPE_SQLNULL:
        return 7;
    case DUCKDB_TYPE_TINYINT:
    case DUCKDB_TYPE_SMALLINT:
    case DUCKDB_TYPE_INTEGER:
    case DUCKDB_TYPE_BIGINT:
    case DUCKDB_TYPE_UTINYINT:
    case DUCKDB_TYPE_USMALLINT:
    case DUCKDB_TYPE_UINTEGER:
    case DUCKDB_TYPE_UBIGINT:
        return 1;
    // The plugin maps both 128-bit native integers to DECIMAL(39,0).
    case DUCKDB_TYPE_HUGEINT:
    case DUCKDB_TYPE_UHUGEINT:
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
    ~DuckResult() {
        duckdb_destroy_result(&value);
    }
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
            cells.push_back({row[i] == nullptr, row[i] ? string(row[i], lengths[i]) : ""});
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
            if (out.types[i] == 7 || duckdb_value_is_null(&r, i, j))
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
                cells.push_back({false, string(value.get())});
            }
        }
        out.rows.push_back(cells);
    }
    return out;
}
struct Fixture {
    MYSQL *mysql = nullptr;
    duckdb_database database = nullptr;
    duckdb_connection duck = nullptr;
    string schema = "translation_oracle_" + to_string(getpid());
    string other_schema = "translation_other_" + to_string(getpid());
    bool schema_owned = false;
    bool other_owned = false;
    ~Fixture() {
        if (duck)
            duckdb_disconnect(&duck);
        if (database)
            duckdb_close(&database);
        if (mysql) {
            if (schema_owned && mysql_query(mysql, ("DROP DATABASE `" + schema + "`").c_str()))
                cerr << "cleanup failed for " << schema << ": " << mysql_error(mysql) << "\n";
            if (other_owned && mysql_query(mysql, ("DROP DATABASE `" + other_schema + "`").c_str()))
                cerr << "cleanup failed for " << other_schema << ": " << mysql_error(mysql) << "\n";
            mysql_close(mysql);
        }
    }
};
struct Case {
    const char *name;
    const char *sql;
};
int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        cerr << "usage: " << argv[0] << " /absolute/path/to/owned-test-mysql.sock\n";
        return 2;
    }
    Fixture f;
    try {
        f.mysql = mysql_init(nullptr);
        if (!f.mysql ||
            !mysql_real_connect(f.mysql, "localhost", "root", "", nullptr, 0, argv[1], 0))
            throw runtime_error(f.mysql ? mysql_error(f.mysql) : "mysql_init failed");
        mysql_exec(f.mysql, "SET SESSION sql_mode='STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY'");
        mysql_exec(f.mysql, "SET NAMES utf8mb4 COLLATE utf8mb4_bin");
        mysql_exec(f.mysql, "SET SESSION time_zone='+00:00'");
        cout << "MySQL " << mysql_get_server_info(f.mysql) << ", DuckDB "
             << duckdb_library_version() << "\n";
        mysql_exec(f.mysql,
                   "CREATE DATABASE `" + f.schema + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin");
        f.schema_owned = true;
        cout << "owned schema " << f.schema << "\n";
        mysql_exec(f.mysql, "USE `" + f.schema + "`");
        if (duckdb_open(nullptr, &f.database) != DuckDBSuccess ||
            duckdb_connect(f.database, &f.duck) != DuckDBSuccess)
            throw runtime_error("DuckDB open/connect failed");
        mysql_exec(f.mysql, "CREATE TABLE `odd``table` (id BIGINT PRIMARY KEY, `a``b` BIGINT, u "
                            "BIGINT UNSIGNED, grp BIGINT, txt VARCHAR(30) CHARACTER SET utf8mb4 "
                            "COLLATE utf8mb4_bin, bin VARBINARY(8))");
        duck_exec(f.duck, "CREATE TABLE \"odd`table\" (id BIGINT PRIMARY KEY, \"a`b\" BIGINT, u "
                          "UBIGINT, grp BIGINT, txt VARCHAR, bin BLOB)");
        string values =
            "(1,-9223372036854775808,0,NULL,'é',NULL),(2,9223372036854775807,18446744073709551615,"
            "2,'abc',NULL),(3,0,1,1,NULL,NULL),(4,0,1,NULL,'z',NULL)";
        mysql_exec(f.mysql, "INSERT INTO `odd``table` VALUES " + values);
        duck_exec(f.duck, "INSERT INTO \"odd`table\" VALUES " + values);
        // A second database proves that a qualified `database.table` name is
        // resolved by its own database, from any selected database.
        mysql_exec(f.mysql, "CREATE DATABASE `" + f.other_schema + "`");
        f.other_owned = true;
        mysql_exec(f.mysql, "CREATE TABLE `" + f.other_schema +
                                "`.`other_probe` (id BIGINT PRIMARY KEY, v VARCHAR(10))");
        duck_exec(f.duck, "CREATE SCHEMA \"" + f.other_schema + "\"");
        duck_exec(f.duck, "CREATE TABLE \"" + f.other_schema +
                              "\".other_probe (id BIGINT PRIMARY KEY, v VARCHAR)");
        const string other_rows = "(1,'left'),(2,'right'),(3,NULL)";
        mysql_exec(f.mysql,
                   "INSERT INTO `" + f.other_schema + "`.other_probe VALUES " + other_rows);
        duck_exec(f.duck,
                  "INSERT INTO \"" + f.other_schema + "\".other_probe VALUES " + other_rows);
        mysql_exec(f.mysql, "UPDATE `odd``table` SET bin=X'00FF' WHERE id=1");
        duck_exec(f.duck, "UPDATE \"odd`table\" SET bin=from_hex('00FF') WHERE id=1");
        mysql_exec(
            f.mysql,
            "CREATE TABLE decimal_probe (id BIGINT PRIMARY KEY, a DECIMAL(18,4), b DECIMAL(38,30), "
            "c DECIMAL(38,0), s BIGINT, u BIGINT UNSIGNED, small DECIMAL(10,2))");
        duck_exec(f.duck,
                  "CREATE TABLE decimal_probe (id BIGINT PRIMARY KEY, a DECIMAL(18,4), b "
                  "DECIMAL(38,30), c DECIMAL(38,0), s BIGINT, u UBIGINT, small DECIMAL(10,2))");
        const string decimal_values =
            "INSERT INTO decimal_probe VALUES "
            "(1,-99999999999999.9999,-99999999.999999999999999999999999999999,-"
            "99999999999999999999999999999999999999,-9223372036854775808,0,-99.99),"
            "(2,-10.2500,0.000000000000000000000000000001,1,9223372036854775807,"
            "18446744073709551615,-10.25),"
            "(3,99999999999999.9999,1.000000000000000000000000000000,"
            "99999999999999999999999999999999999999,0,1,1.50),"
            "(4,NULL,NULL,NULL,NULL,NULL,NULL)";
        mysql_exec(f.mysql, decimal_values);
        duck_exec(f.duck, decimal_values);
        mysql_exec(
            f.mysql,
            "CREATE TABLE fraction_probe (id BIGINT PRIMARY KEY, f DECIMAL(2,2), `é` BIGINT)");
        duck_exec(
            f.duck,
            "CREATE TABLE fraction_probe (id BIGINT PRIMARY KEY, f DECIMAL(2,2), \"é\" BIGINT)");
        mysql_exec(f.mysql, "INSERT INTO fraction_probe VALUES (1,.50,10),(2,-.25,20),(3,NULL,30)");
        duck_exec(f.duck, "INSERT INTO fraction_probe VALUES (1,.50,10),(2,-.25,20),(3,NULL,30)");
        mysql_exec(
            f.mysql,
            "CREATE TABLE wide_probe (id BIGINT PRIMARY KEY, h DECIMAL(39,0), u DECIMAL(39,0))");
        duck_exec(f.duck, "CREATE TABLE wide_probe (id BIGINT PRIMARY KEY, h HUGEINT, u UHUGEINT)");
        const string wide_rows = "(1,'-170141183460469231731687303715884105728','"
                                 "340282366920938463463374607431768211455'),(2,'"
                                 "170141183460469231731687303715884105727','0'),(3,NULL,NULL)";
        mysql_exec(f.mysql, "INSERT INTO wide_probe VALUES " + wide_rows);
        duck_exec(f.duck, "INSERT INTO wide_probe VALUES " + wide_rows);
        mysql_exec(f.mysql,
                   "CREATE TABLE date_probe (id BIGINT PRIMARY KEY, d DATE, dt DATETIME(6), "
                   "ts TIMESTAMP NULL, txt VARCHAR(10))");
        duck_exec(f.duck,
                  "CREATE TABLE date_probe (id BIGINT PRIMARY KEY, d DATE, dt TIMESTAMP, ts "
                  "TIMESTAMP, txt VARCHAR)");
        const string date_rows =
            "(1,'1000-01-01','1000-01-01 00:00:00.000000','2024-02-29 23:00:00','x'),"
            "(2,'2024-02-29','2024-02-29 00:00:00.000000','2024-02-29 23:00:00','x'),"
            "(3,'2024-03-01','2024-03-01 23:59:59.999999','2024-03-01 00:00:00','x'),"
            "(4,'9999-12-31','9999-12-31 23:59:59.999999','2024-12-31 23:00:00','x'),"
            "(5,NULL,NULL,NULL,NULL)";
        mysql_exec(f.mysql, "INSERT INTO date_probe VALUES " + date_rows);
        duck_exec(f.duck, "INSERT INTO date_probe VALUES " + date_rows);
        mysql_exec(f.mysql,
                   "CREATE TABLE sumavg_probe (id BIGINT PRIMARY KEY, i BIGINT, u BIGINT "
                   "UNSIGNED, d19 DECIMAL(19,2), d18 DECIMAL(18,4), d20 DECIMAL(20,2), d19i "
                   "DECIMAL(19,0), frac DECIMAL(2,2), grp BIGINT, txt VARCHAR(10))");
        duck_exec(f.duck,
                  "CREATE TABLE sumavg_probe (id BIGINT PRIMARY KEY, i BIGINT, u UBIGINT, d19 "
                  "DECIMAL(19,2), d18 DECIMAL(18,4), d20 DECIMAL(20,2), d19i DECIMAL(19,0), frac "
                  "DECIMAL(2,2), grp BIGINT, txt VARCHAR)");
        // One extreme row, one negative row, an all-NULL row, an all-NULL group, and
        // two 32-row groups whose only nonzero value makes AVG land exactly on a
        // rounding tie at every admitted result scale (4, 6 and 8 decimals).
        string sum_rows =
            "(1,-9223372036854775808,0,-99999999999999999.99,-99999999999999.9999,-"
            "999999999999999999.99,-9999999999999999999,-0.99,1,'a'),"
            "(2,9223372036854775807,18446744073709551615,99999999999999999.97,"
            "99999999999999.9999,999999999999999999.99,9999999999999999997,0.99,1,'b'),"
            "(3,0,1,0.01,0.0001,0.01,1,0.50,2,'c'),"
            "(4,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),"
            "(5,-1,2,-0.03,-0.0003,-0.03,-3,-0.50,3,'d'),"
            "(6,NULL,NULL,NULL,NULL,NULL,NULL,NULL,3,'e'),"
            "(7,NULL,NULL,NULL,NULL,NULL,NULL,NULL,4,NULL)";
        for (int n = 0; n < 32; ++n) {
            sum_rows += ",(" + to_string(100 + n) + "," + (n == 0 ? "1" : "0") + ",0," +
                        (n == 0 ? "0.01" : "0.00") + "," + (n == 0 ? "0.0001" : "0.0000") +
                        ",0.00,0," + (n == 0 ? "0.01" : "0.00") + ",5,'t')";
            sum_rows += ",(" + to_string(200 + n) + "," + (n == 0 ? "-1" : "0") + ",0," +
                        (n == 0 ? "-0.01" : "0.00") + "," + (n == 0 ? "-0.0001" : "0.0000") +
                        ",0.00,0," + (n == 0 ? "-0.01" : "0.00") + ",6,'u')";
        }
        mysql_exec(f.mysql, "INSERT INTO sumavg_probe VALUES " + sum_rows);
        duck_exec(f.duck, "INSERT INTO sumavg_probe VALUES " + sum_rows);
        mysql_exec(f.mysql, "CREATE TABLE scale_probe (id BIGINT PRIMARY KEY, d DECIMAL(19,19))");
        duck_exec(f.duck, "CREATE TABLE scale_probe (id BIGINT PRIMARY KEY, d DECIMAL(19,19))");
        const string scale_rows = "(1,-0.9999999999999999999),(2,0.9999999999999999999),"
                                  "(3,0.0000000000000000001),(4,NULL),(5,0)";
        mysql_exec(f.mysql, "INSERT INTO scale_probe VALUES " + scale_rows);
        duck_exec(f.duck, "INSERT INTO scale_probe VALUES " + scale_rows);
        mysql_exec(f.mysql, "CREATE TABLE text_probe (id BIGINT PRIMARY KEY, "
                            "t VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin, "
                            "u VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin, "
                            "ai VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci, "
                            "pad VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin)");
        duck_exec(f.duck, "CREATE TABLE text_probe (id BIGINT PRIMARY KEY, t VARCHAR, u VARCHAR, "
                          "ai VARCHAR, pad VARCHAR)");
        struct TextRow {
            const char *id;
            const char *t;
            const char *u;
            const char *ai;
            const char *pad;
        };
        // Bytes are written as UTF-8 hex so the fixture is independent of the
        // client encoding. Row 16 stores an embedded NUL in both engines.
        const TextRow text_rows[] = {{"1", "", "61", "61", nullptr},
                                     {"2", "20", "6120", "41", nullptr},
                                     {"3", "61", "6120", "65", "61"},
                                     {"4", "6120", "61", nullptr, "6120"},
                                     {"5", "2061", "2061", nullptr, nullptr},
                                     {"6", "610961", "610962", nullptr, nullptr},
                                     {"7", "610962", "610961", nullptr, nullptr},
                                     {"8", "C3A9", "C3A9", "C3A9", nullptr},
                                     {"9", "65", "65", "7373", nullptr},
                                     {"10", "65CC81", "65CC81", "C39F", nullptr},
                                     {"11", "F09F9880", "F09F9880", nullptr, nullptr},
                                     {"12", "F0908080", "F0908080", nullptr, nullptr},
                                     {"13", "6162", "616263", nullptr, nullptr},
                                     {"14", "616263", "6162", nullptr, nullptr},
                                     {"15", "616220", "6162", nullptr, nullptr},
                                     {"16", "610062", "610062", nullptr, nullptr},
                                     {"17", "41", "61", nullptr, nullptr},
                                     {"18", nullptr, nullptr, nullptr, nullptr},
                                     {"19", "5A", "61", nullptr, nullptr},
                                     {"20", "5F", "5F", "5F", nullptr},
                                     {"21", "31", "31", "31", nullptr},
                                     {"22", "69742773", "69742773", nullptr, nullptr},
                                     {"23", "612262", "612262", nullptr, nullptr},
                                     {"24", "C39F", "7373", nullptr, nullptr},
                                     {"25", "7373", "C39F", nullptr, nullptr}};
        auto mysql_text = [](const char *hex) -> std::string {
            return hex && *hex ? "CONVERT(0x" + std::string(hex) + " USING utf8mb4)" : "''";
        };
        auto duck_text = [](const char *hex) -> std::string {
            return hex && *hex ? "decode(from_hex('" + std::string(hex) + "'))" : "''";
        };
        std::string mysql_text_insert = "INSERT INTO text_probe VALUES ";
        std::string duck_text_insert = "INSERT INTO text_probe VALUES ";
        for (size_t i = 0; i < sizeof(text_rows) / sizeof(text_rows[0]); ++i) {
            const auto &row = text_rows[i];
            if (i)
                mysql_text_insert += ",";
            mysql_text_insert += "(" + std::string(row.id) + ",";
            mysql_text_insert += row.t ? mysql_text(row.t) : "NULL";
            mysql_text_insert += ",";
            mysql_text_insert += row.u ? mysql_text(row.u) : "NULL";
            mysql_text_insert += ",";
            mysql_text_insert += row.ai ? mysql_text(row.ai) : "NULL";
            mysql_text_insert += ",";
            mysql_text_insert += row.pad ? mysql_text(row.pad) : "NULL";
            mysql_text_insert += ")";
            if (i)
                duck_text_insert += ",";
            duck_text_insert += "(" + std::string(row.id) + ",";
            duck_text_insert += row.t ? duck_text(row.t) : "NULL";
            duck_text_insert += ",";
            duck_text_insert += row.u ? duck_text(row.u) : "NULL";
            duck_text_insert += ",";
            duck_text_insert += row.ai ? duck_text(row.ai) : "NULL";
            duck_text_insert += ",";
            duck_text_insert += row.pad ? duck_text(row.pad) : "NULL";
            duck_text_insert += ")";
        }
        mysql_exec(f.mysql, mysql_text_insert);
        duck_exec(f.duck, duck_text_insert);
        DuckDBMySQLSelectContext context;
        size_t calls = 0;
        context.resolve_relation = [&](const vector<string> &names, DuckDBMySQLRelation &r) {
            ++calls;
            if (names == vector<string>{"wide_probe"}) {
                r.canonical_name = {"wide_probe"};
                r.exact_name_resolution = true;
                r.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"h", {DuckDBMySQLTypeKind::exact_decimal, 39, 0}},
                             {"u", {DuckDBMySQLTypeKind::exact_decimal, 39, 0}}};
                r.unique_keys = {{"id"}};
                return true;
            }
            if (names == vector<string>{"text_probe"}) {
                r.canonical_name = {"text_probe"};
                r.exact_name_resolution = true;
                r.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"t",
                              {DuckDBMySQLTypeKind::text, 0, 0},
                              {DuckDBMySQLSourceType::other, "utf8mb4", "utf8mb4_0900_bin"}},
                             {"u",
                              {DuckDBMySQLTypeKind::text, 0, 0},
                              {DuckDBMySQLSourceType::other, "utf8mb4", "utf8mb4_0900_bin"}},
                             {"ai",
                              {DuckDBMySQLTypeKind::text, 0, 0},
                              {DuckDBMySQLSourceType::other, "utf8mb4", "utf8mb4_0900_ai_ci"}},
                             {"pad",
                              {DuckDBMySQLTypeKind::text, 0, 0},
                              {DuckDBMySQLSourceType::other, "utf8mb4", "utf8mb4_bin"}}};
                r.unique_keys = {{"id"}};
                return true;
            }
            if (names == vector<string>{"date_probe"}) {
                r.canonical_name = {"date_probe"};
                r.exact_name_resolution = true;
                r.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"d", {DuckDBMySQLTypeKind::date, 0, 0}},
                             {"dt",
                              {DuckDBMySQLTypeKind::datetime, 0, 0},
                              {DuckDBMySQLSourceType::datetime}},
                             {"ts",
                              {DuckDBMySQLTypeKind::datetime, 0, 0},
                              {DuckDBMySQLSourceType::timestamp}},
                             {"txt", {DuckDBMySQLTypeKind::text, 0, 0}}};
                r.unique_keys = {{"id"}};
                return true;
            }
            if (names == vector<string>{"scale_probe"}) {
                r.canonical_name = {"scale_probe"};
                r.exact_name_resolution = true;
                r.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"d", {DuckDBMySQLTypeKind::exact_decimal, 19, 19}}};
                r.unique_keys = {{"id"}};
                return true;
            }
            if (names == vector<string>{"sumavg_probe"}) {
                r.canonical_name = {"sumavg_probe"};
                r.exact_name_resolution = true;
                r.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"i", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"u", {DuckDBMySQLTypeKind::unsigned_integer, 0, 0}},
                             {"d19", {DuckDBMySQLTypeKind::exact_decimal, 19, 2}},
                             {"d18", {DuckDBMySQLTypeKind::exact_decimal, 18, 4}},
                             {"d20", {DuckDBMySQLTypeKind::exact_decimal, 20, 2}},
                             {"d19i", {DuckDBMySQLTypeKind::exact_decimal, 19, 0}},
                             {"frac", {DuckDBMySQLTypeKind::exact_decimal, 2, 2}},
                             {"grp", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"txt", {DuckDBMySQLTypeKind::text, 0, 0}}};
                r.unique_keys = {{"id"}};
                return true;
            }
            if (names == vector<string>{"fraction_probe"}) {
                r.canonical_name = {"fraction_probe"};
                r.exact_name_resolution = true;
                r.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"f", {DuckDBMySQLTypeKind::exact_decimal, 2, 2}},
                             {"é", {DuckDBMySQLTypeKind::signed_integer, 0, 0}}};
                r.unique_keys = {{"id"}};
                return true;
            }
            if (names == vector<string>{"decimal_probe"}) {
                r.canonical_name = {"decimal_probe"};
                r.exact_name_resolution = true;
                r.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"a", {DuckDBMySQLTypeKind::exact_decimal, 18, 4}},
                             {"b", {DuckDBMySQLTypeKind::exact_decimal, 38, 30}},
                             {"c", {DuckDBMySQLTypeKind::exact_decimal, 38, 0}},
                             {"s", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"u", {DuckDBMySQLTypeKind::unsigned_integer, 0, 0}},
                             {"small", {DuckDBMySQLTypeKind::exact_decimal, 10, 2}}};
                r.unique_keys = {{"id"}};
                return true;
            }
            if (names == vector<string>{f.other_schema, "other_probe"}) {
                r.canonical_name = {f.other_schema, "other_probe"};
                r.exact_name_resolution = true;
                r.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                             {"v", {DuckDBMySQLTypeKind::text, 0, 0}}};
                r.unique_keys = {{"id"}};
                return true;
            }
            if (names != vector<string>{"odd`table"})
                return false;
            r.canonical_name = {"odd`table"};
            r.exact_name_resolution = true;
            r.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                         {"a`b", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                         {"u", {DuckDBMySQLTypeKind::unsigned_integer, 0, 0}},
                         {"grp", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                         {"txt", {DuckDBMySQLTypeKind::text, 0, 0}},
                         {"bin", {DuckDBMySQLTypeKind::binary, 0, 0}}};
            r.unique_keys = {{"id"}};
            return true;
        };
        const std::string long_integer = "SELECT " + std::string(300, '0') + "1";
        const std::string alias256 = "SELECT 1 AS `" + std::string(256, 'a') + "`";
        std::string bmp;
        for (size_t i = 0; i < 128; ++i)
            bmp += "é";
        const std::string bmp256 = "SELECT 1 AS `" + bmp + "`";
        const std::string aggregate255 = "SELECT COUNT(" + std::string(247, ' ') + "*)";
        const std::string date_format255 = "SELECT DATE_FORMAT(" + std::string(233, ' ') +
                                           "d,'%Y-%m') FROM date_probe ORDER BY id";
        const std::string qualified_other =
            "SELECT * FROM `" + f.other_schema + "`.other_probe ORDER BY id";
        const std::string qualified_other_predicate =
            "SELECT id FROM `" + f.other_schema + "`.other_probe WHERE id > 1 ORDER BY id";
        const std::string qualified_other_count =
            "SELECT COUNT(*) AS n FROM `" + f.other_schema + "`.other_probe";
        const Case cases[] = {
            {"huge extrema projection", "SELECT h,u FROM wide_probe ORDER BY id"},
            {"huge star", "SELECT * FROM wide_probe ORDER BY id"},
            {"huge duplicate labels", "SELECT h AS x,u AS x FROM wide_probe ORDER BY id"},
            {"fraction column", "SELECT f FROM fraction_probe ORDER BY id"},
            {"fraction alias", "SELECT f AS val FROM fraction_probe ORDER BY id"},
            {"fraction duplicate", "SELECT f,f FROM fraction_probe ORDER BY id"},
            {"fraction star", "SELECT * FROM fraction_probe ORDER BY id"},
            {"fraction comparison", "SELECT f FROM fraction_probe WHERE f > .40 ORDER BY id"},
            {"decimal literal labels", "SELECT 001.2300,.50,1.,00.0"},
            {"decimal projections and nulls", "SELECT id,a,b,c FROM decimal_probe ORDER BY id"},
            {"mixed decimal scales", "SELECT id FROM decimal_probe WHERE a = small ORDER BY id"},
            {"signed decimal", "SELECT id FROM decimal_probe WHERE a < s ORDER BY id"},
            {"unsigned decimal", "SELECT id FROM decimal_probe WHERE a < u ORDER BY id"},
            {"decimal boundary",
             "SELECT id FROM decimal_probe WHERE a = 99999999999999.9999 ORDER BY id"},
            {"signed max decimal",
             "SELECT id FROM decimal_probe WHERE s = 9223372036854775807.0000 ORDER BY id"},
            {"unsigned max decimal",
             "SELECT id FROM decimal_probe WHERE u = 18446744073709551615.0 ORDER BY id"},
            {"scale30 small integer", "SELECT id FROM decimal_probe WHERE b = 1 ORDER BY id"},
            {"scale30 fraction",
             "SELECT id FROM decimal_probe WHERE b = 0.000000000000000000000000000001 ORDER BY id"},
            {"38 digit integer", "SELECT id FROM decimal_probe WHERE c = "
                                 "99999999999999999999999999999999999999 ORDER BY id"},
            {"decimal null filtering", "SELECT id FROM decimal_probe WHERE a = 1.0 ORDER BY id"},
            {"escaped and duplicate labels",
             "SELECT `a``b` AS same, id AS same FROM `odd``table` ORDER BY id"},
            {"qualified alias", "SELECT q.id, q.`a``b` FROM `odd``table` AS q ORDER BY q.id"},
            {"all projected types", "SELECT * FROM `odd``table` ORDER BY id"},
            {"count", "SELECT COUNT(*) AS n FROM `odd``table`"},
            {"count nullable", "SELECT COUNT(grp) AS n FROM `odd``table`"},
            {"integer literal", "SELECT 001"},
            {"canonical NULL labels", "SELECT null, NuLl"},
            {"long integral literal label", long_integer.c_str()},
            {"256-byte alias", alias256.c_str()},
            {"256-byte BMP alias", bmp256.c_str()},
            {"trailing alias whitespace", "SELECT 1 AS `x `"},
            {"255-byte aggregate label", aggregate255.c_str()},
            {"null literal", "SELECT NULL"},
            {"null ascending", "SELECT id, grp FROM `odd``table` ORDER BY grp ASC, id ASC"},
            {"null descending", "SELECT id, grp FROM `odd``table` ORDER BY grp DESC, id ASC"},
            {"comma limit", "SELECT id FROM `odd``table` ORDER BY id LIMIT 1, 2"},
            {"integer predicate", "SELECT id FROM `odd``table` WHERE id > 1 ORDER BY id"},
            {"nullable groups ascending", "SELECT grp,COUNT(*) AS n,MIN(id) AS lo,MAX(id) AS hi "
                                          "FROM `odd``table` GROUP BY grp ORDER BY grp"},
            {"nullable groups descending",
             "SELECT grp,COUNT(*) AS n FROM `odd``table` GROUP BY grp ORDER BY grp DESC"},
            {"grouped having", "SELECT grp,COUNT(*) AS n FROM `odd``table` GROUP BY grp HAVING "
                               "COUNT(*) > 1 ORDER BY grp"},
            {"grouped null predicate", "SELECT grp,MIN(id) AS lo FROM `odd``table` GROUP BY grp "
                                       "HAVING MIN(id) IS NOT NULL ORDER BY grp"},
            {"group limit",
             "SELECT grp,COUNT(*) AS n FROM `odd``table` GROUP BY grp ORDER BY grp LIMIT 1, 2"},
            {"multi key",
             "SELECT grp,u,COUNT(*) AS n FROM `odd``table` GROUP BY grp,u ORDER BY grp,u"},
            {"unsigned grouping",
             "SELECT u,MIN(u) AS lo,MAX(u) AS hi FROM `odd``table` GROUP BY u ORDER BY u"},
            {"duplicate aggregate names",
             "SELECT grp,COUNT(*) AS x,MIN(id) AS x FROM `odd``table` GROUP BY grp ORDER BY grp"},
            {"empty count and min", "SELECT COUNT(*) AS n, MIN(id) AS lo FROM `odd``table` WHERE "
                                    "id > 9 HAVING COUNT(*) = 0"},
            {"empty grouped rows",
             "SELECT grp,COUNT(*) AS n FROM `odd``table` WHERE id > 9 GROUP BY grp ORDER BY grp"},
            {"date format date", "SELECT DATE_FORMAT(d,'%Y-%m') FROM date_probe ORDER BY id"},
            {"date format datetime", "SELECT DATE_FORMAT(dt,'%Y-%m') FROM date_probe ORDER BY id"},
            {"date format datetime alias",
             "SELECT DATE_FORMAT(dt,'%Y-%m') AS ym, id FROM date_probe ORDER BY id"},
            {"date format alias",
             "SELECT DATE_FORMAT(d,'%Y-%m') AS ym, id FROM date_probe ORDER BY id"},
            {"date format mixed case", "SELECT date_format(d,'%Y-%m') FROM date_probe ORDER BY id"},
            {"date format backtick label",
             "SELECT DATE_FORMAT(`d`,'%Y-%m') FROM date_probe ORDER BY id"},
            {"date format spaces", "SELECT DATE_FORMAT( d , '%Y-%m' ) FROM date_probe ORDER BY id"},
            {"date format qualified",
             "SELECT p.`d`, DATE_FORMAT(p.`d`,'%Y-%m') AS ym FROM date_probe AS p ORDER BY p.id"},
            {"date format mixed projection",
             "SELECT id, DATE_FORMAT(d,'%Y-%m'), d FROM date_probe ORDER BY id"},
            {"date format duplicate aliases",
             "SELECT DATE_FORMAT(d,'%Y-%m') AS x, DATE_FORMAT(d,'%Y-%m') AS x FROM date_probe "
             "ORDER BY id"},
            {"date format comma limit",
             "SELECT DATE_FORMAT(d,'%Y-%m') FROM date_probe ORDER BY id LIMIT 1, 2"},
            {"date format null positions",
             "SELECT DATE_FORMAT(dt,'%Y-%m') FROM date_probe WHERE id >= 4 ORDER BY id"},
            {"date format empty",
             "SELECT DATE_FORMAT(d,'%Y-%m') FROM date_probe WHERE id > 99 ORDER BY id"},
            {"date format 255-byte label", date_format255.c_str()},
            {"sum and avg integers",
             "SELECT SUM(i) AS si, AVG(i) AS ai, SUM(u) AS su, AVG(u) AS au FROM sumavg_probe"},
            {"sum and avg decimals",
             "SELECT SUM(d19) AS s19, AVG(d19) AS a19, SUM(d18) AS s18, AVG(d18) AS a18, "
             "SUM(d19i) AS s0, AVG(d19i) AS a0, SUM(frac) AS sf, AVG(frac) AS af FROM "
             "sumavg_probe"},
            {"sum and avg labels",
             "SELECT SUM(i), AVG(d18), SUM(frac), AVG(frac) FROM sumavg_probe"},
            {"sum and avg escaped identifier",
             "SELECT SUM(`a``b`) AS s, AVG(`a``b`) AS a FROM `odd``table`"},
            {"sum and avg mixed case", "SELECT sum(i), avg(d19) FROM sumavg_probe"},
            {"sum spaced argument list",
             "SELECT SUM( i ) AS si, AVG( d19 ) AS a19 FROM sumavg_probe"},
            {"sum spaced labels", "SELECT SUM( i ), AVG( d19 ) FROM sumavg_probe"},
            {"grouped sums",
             "SELECT grp, SUM(i) AS si, SUM(u) AS su, SUM(d19) AS s19, SUM(d18) AS s18, "
             "SUM(d19i) AS s0, SUM(frac) AS sf FROM sumavg_probe GROUP BY grp ORDER BY grp"},
            {"grouped averages",
             "SELECT grp, AVG(i) AS ai, AVG(u) AS au, AVG(d19) AS a19, AVG(d18) AS a18, "
             "AVG(d19i) AS a0, AVG(frac) AS af FROM sumavg_probe GROUP BY grp ORDER BY grp"},
            {"grouped sums descending",
             "SELECT grp, SUM(i) AS si FROM sumavg_probe GROUP BY grp ORDER BY grp DESC"},
            {"empty sum and avg",
             "SELECT SUM(i) AS si, AVG(i) AS ai FROM sumavg_probe WHERE id > 9999"},
            {"empty grouped averages",
             "SELECT grp, SUM(i) AS si, AVG(i) AS ai FROM sumavg_probe WHERE id > 9999 "
             "GROUP BY grp ORDER BY grp"},
            {"signed max sum and avg",
             "SELECT SUM(i) AS si, AVG(i) AS ai FROM sumavg_probe WHERE id = 2"},
            {"unsigned max sum and avg",
             "SELECT SUM(u) AS su, AVG(u) AS au FROM sumavg_probe WHERE id = 2"},
            {"decimal max sum and avg",
             "SELECT SUM(d19) AS s19, AVG(d19) AS a19 FROM sumavg_probe WHERE id = 2"},
            {"decimal trailing zero sum and avg",
             "SELECT SUM(a) AS sa, AVG(a) AS aa FROM decimal_probe"},
            {"decimal min sum and avg",
             "SELECT SUM(d18) AS s18, AVG(d18) AS a18 FROM sumavg_probe WHERE id = 1"},
            {"integer magnitude sum",
             "SELECT SUM(d19i) AS s0, AVG(d19i) AS a0 FROM sumavg_probe WHERE id = 2"},
            {"scale 19 sum and avg", "SELECT SUM(d) AS s19, AVG(d) AS a19 FROM scale_probe"},
            {"scale 19 grouped avg",
             "SELECT id, AVG(d) AS a19 FROM scale_probe GROUP BY id ORDER BY id"},
            {"filtered group sum and avg",
             "SELECT SUM(d19) AS s19, AVG(d19) AS a19 FROM sumavg_probe WHERE grp = 3"},
            {"qualified sum and avg",
             "SELECT SUM(s.`i`) AS si, AVG(s.`d19`) AS a19 FROM sumavg_probe AS s WHERE s.id = 2"},
            {"multi key sum and avg",
             "SELECT grp,u,SUM(i) AS si, AVG(d19) AS a19 FROM sumavg_probe GROUP BY grp,u "
             "ORDER BY grp,u"},
            {"grouped sum limit",
             "SELECT grp,SUM(i) AS si,AVG(d18) AS a18 FROM sumavg_probe GROUP BY grp ORDER BY "
             "grp LIMIT 1, 2"},
            {"duplicate sum and avg labels",
             "SELECT grp,SUM(i) AS x,AVG(i) AS x FROM sumavg_probe GROUP BY grp ORDER BY grp"},
            {"text empty literal", "SELECT id FROM text_probe WHERE t = '' ORDER BY id"},
            {"text space literal", "SELECT id FROM text_probe WHERE t = ' ' ORDER BY id"},
            {"text trailing space literal", "SELECT id FROM text_probe WHERE t = 'a ' ORDER BY id"},
            {"text leading space literal", "SELECT id FROM text_probe WHERE t = ' a' ORDER BY id"},
            {"text equality", "SELECT id FROM text_probe WHERE t = 'a' ORDER BY id"},
            {"text inequality", "SELECT id FROM text_probe WHERE t <> 'a' ORDER BY id"},
            {"text bang inequality", "SELECT id FROM text_probe WHERE t != 'a' ORDER BY id"},
            {"text less", "SELECT id FROM text_probe WHERE t < 'a' ORDER BY id"},
            {"text less equal", "SELECT id FROM text_probe WHERE t <= 'a' ORDER BY id"},
            {"text greater", "SELECT id FROM text_probe WHERE t > 'a' ORDER BY id"},
            {"text greater equal", "SELECT id FROM text_probe WHERE t >= 'a' ORDER BY id"},
            {"text literal on left", "SELECT id FROM text_probe WHERE 'a' = t ORDER BY id"},
            {"text literal on left less", "SELECT id FROM text_probe WHERE 'a' < t ORDER BY id"},
            {"text bmp literal", "SELECT id FROM text_probe WHERE t = 'é' ORDER BY id"},
            {"text emoji literal", "SELECT id FROM text_probe WHERE t = '😀' ORDER BY id"},
            {"text supplementary literal",
             "SELECT id FROM text_probe WHERE t = '\xF0\x90\x80\x80' ORDER BY id"},
            {"text combining mark literal",
             "SELECT id FROM text_probe WHERE t = 'e\xCC\x81' ORDER BY id"},
            {"text doubled quote literal",
             "SELECT id FROM text_probe WHERE t = 'it''s' ORDER BY id"},
            {"text embedded tab literal", "SELECT id FROM text_probe WHERE t = 'a\ta' ORDER BY id"},
            {"text embedded control literal",
             "SELECT id FROM text_probe WHERE t = 'a\001b' ORDER BY id"},
            {"text embedded double quote literal",
             "SELECT id FROM text_probe WHERE t = 'a\"b' ORDER BY id"},
            {"text prefix literal", "SELECT id FROM text_probe WHERE t = 'ab' ORDER BY id"},
            {"text case sensitive literal", "SELECT id FROM text_probe WHERE t = 'A' ORDER BY id"},
            {"text column equality", "SELECT id FROM text_probe WHERE t = u ORDER BY id"},
            {"text column inequality", "SELECT id FROM text_probe WHERE t <> u ORDER BY id"},
            {"text column less", "SELECT id FROM text_probe WHERE t < u ORDER BY id"},
            {"text column less equal", "SELECT id FROM text_probe WHERE t <= u ORDER BY id"},
            {"text column greater", "SELECT id FROM text_probe WHERE t > u ORDER BY id"},
            {"text column greater equal", "SELECT id FROM text_probe WHERE t >= u ORDER BY id"},
            {"text and or null logic",
             "SELECT id FROM text_probe WHERE (t = 'a' OR t IS NULL) AND u <> 'b' ORDER BY id"},
            {"text not null logic",
             "SELECT id FROM text_probe WHERE t IS NOT NULL AND t >= 'a' ORDER BY id"},
            {"text parenthesized logic",
             "SELECT id FROM text_probe WHERE ((t = 'a') OR (t = ' ')) AND u IS NOT NULL "
             "ORDER BY id"},
            {"text projected predicate", "SELECT t FROM text_probe WHERE t = 'a' ORDER BY id"},
            {"text ordered projection", "SELECT id,t FROM text_probe WHERE id <> 16 ORDER BY id"},
            {"text order ascending", "SELECT id FROM text_probe ORDER BY t ASC, id ASC"},
            {"text order descending", "SELECT id FROM text_probe ORDER BY t DESC, id ASC"},
            {"text order ascending limit",
             "SELECT id FROM text_probe ORDER BY t ASC, id ASC LIMIT 6"},
            {"text order descending limit",
             "SELECT id FROM text_probe ORDER BY t DESC, id ASC LIMIT 6"},
            {"text order comma limit",
             "SELECT id FROM text_probe ORDER BY t ASC, id ASC LIMIT 2, 3"},
            {"text order nonnull", "SELECT id FROM text_probe WHERE t IS NOT NULL ORDER BY t ASC, "
                                   "id ASC"},
            // Cross-database qualified names: MySQL resolves them in their own
            // database regardless of the selected one.
            {"qualified other database", qualified_other.c_str()},
            {"qualified other database predicate", qualified_other_predicate.c_str()},
            {"qualified other database count", qualified_other_count.c_str()},
        };
        int failures = 0, comparisons = 0;
        for (auto &entry : cases) {
            auto translated = duckdb_translate_mysql_select(entry.sql, context);
            if (translated.decision != DuckDBMySQLSelectDecision::supported) {
                cerr << "REFUSED " << entry.name << ": " << translated.reason << "\n";
                ++failures;
                continue;
            }
            auto left = mysql_result(f.mysql, entry.sql),
                 right = duck_result(f.duck, translated.sql);
            ++comparisons;
            bool values_match = left.names == right.names && left.rows == right.rows;
            if (!values_match && left.rows.size() == 1 && right.rows.size() == 1) {
                for (size_t i = 0; i < left.names.size() && i < right.names.size(); ++i)
                    cerr << " column " << i << " name [" << left.names[i] << "]/[" << right.names[i]
                         << "] value [" << left.rows[0][i].text << "]/[" << right.rows[0][i].text
                         << "]\n";
            }
            bool types_match = left.types == right.types;
            bool known = true;
            for (auto kind : left.types)
                known &= kind != 0;
            for (auto kind : right.types)
                known &= kind != 0;
            cout << (values_match && types_match && known ? "MATCH " : "MISMATCH ") << entry.name
                 << " types=" << (types_match ? "match" : "DIFFER") << " SQL=" << translated.sql
                 << "\n";
            if (!values_match || !types_match || !known)
                ++failures;
        }
        // Rejecting input must not reach either engine.
        const std::vector<std::string> rejected = {
            "SELECT nextval('x')",
            "SELECT @x",
            "SELECT 1; SELECT 2",
            "SELECT id FROM wide_probe WHERE h = 1.0",
            "SELECT 1 AS `" + std::string(257, 'a') + "`",
            "SELECT 1 AS `x😀y`",
            "SELECT 1 AS ` x`",
            "SELECT COUNT(" + std::string(248, ' ') + "*)",
            "SELECT DATE_FORMAT(ts,'%Y-%m') FROM date_probe ORDER BY id",
            "SELECT DATE_FORMAT(d,'%Y-%m'), DATE_FORMAT(ts,'%Y-%m') FROM date_probe",
            "SELECT DATE_FORMAT(d,'%Y-%m-%d') FROM date_probe",
            "SELECT DATE_FORMAT(d,'%Y-%m') FROM date_probe "
            "WHERE DATE_FORMAT(d,'%Y-%m') IS NULL",
            "SELECT DATE_FORMAT(d) FROM date_probe",
            "SELECT DATE_FORMAT(d,'%Y-%m','x') FROM date_probe",
            "SELECT DATE_FORMAT(txt,'%Y-%m') FROM date_probe",
            "SELECT DATE_FORMAT (dt,'%Y-%m') FROM date_probe",
            "SELECT DATE_FORMAT(d, \"%Y-%m\") FROM date_probe",
            "SELECT DATE_FORMAT(d,'%Y-%m'),COUNT(*) FROM "
            "date_probe",
            "SELECT SUM(DISTINCT i) FROM sumavg_probe",
            "SELECT AVG(DISTINCT i) FROM sumavg_probe",
            "SELECT SUM(txt) FROM sumavg_probe",
            "SELECT AVG(txt) FROM sumavg_probe",
            "SELECT SUM(d) FROM date_probe",
            "SELECT SUM(1)",
            "SELECT AVG(1)",
            "SELECT SUM(i+1) FROM sumavg_probe",
            "SELECT AVG(i*2) FROM sumavg_probe",
            "SELECT SUM (i) FROM sumavg_probe",
            "SELECT AVG (i) FROM sumavg_probe",
            "SELECT `SUM`(i) FROM sumavg_probe",
            "SELECT `AVG`(i) FROM sumavg_probe",
            "SELECT SUM(?) FROM sumavg_probe",
            "SELECT AVG(?) FROM sumavg_probe",
            "SELECT SUM(b) FROM decimal_probe",
            "SELECT SUM(d20) FROM sumavg_probe",
            "SELECT AVG(d20) FROM sumavg_probe",
            "SELECT SUM(h) FROM wide_probe",
            "SELECT AVG(h) FROM wide_probe",
            "SELECT grp,SUM(i) FROM sumavg_probe GROUP BY grp HAVING SUM(i) IS NOT NULL",
            "SELECT grp,AVG(i) FROM sumavg_probe GROUP BY grp HAVING AVG(i) > 0",
            "SELECT MIN(SUM(i)) FROM sumavg_probe",
            "SELECT SUM(i),i FROM sumavg_probe",
            "SELECT SUM(i) FROM sumavg_probe WHERE SUM(i) > 0",
            "SELECT SUM(i) FROM sumavg_probe ORDER BY SUM(i)",
            "SELECT id FROM text_probe WHERE ai = 'A' ORDER BY id",
            "SELECT id FROM text_probe WHERE pad = 'a ' ORDER BY id",
            "SELECT id FROM text_probe ORDER BY ai",
            "SELECT id FROM `odd``table` WHERE txt = 'x'",
            "SELECT id FROM text_probe WHERE t = 1",
            "SELECT id FROM text_probe WHERE t LIKE 'a%'",
            "SELECT id FROM text_probe WHERE t COLLATE utf8mb4_0900_bin = 'a'",
            "SELECT id FROM text_probe WHERE t = _utf8mb4'a'",
            "SELECT id FROM text_probe WHERE t = N'a'",
            "SELECT id FROM text_probe WHERE t = 'a\\b'",
            "SELECT id FROM text_probe WHERE t = \"a\"",
            "SELECT id FROM text_probe WHERE t = 'a' 'b'",
            "SELECT id FROM text_probe WHERE t = ?",
            "SELECT id FROM text_probe WHERE 'a' = 'b'"};
        for (const auto &sql : rejected) {
            auto x = duckdb_translate_mysql_select(sql, context);
            if (x.decision == DuckDBMySQLSelectDecision::supported || !x.sql.empty()) {
                cerr << "unexpected admission: " << sql << "\n";
                ++failures;
            } else
                cout << "REFUSAL " << sql << " " << x.reason << " (no engine call)\n";
        }
        // Database namespace policy. MySQL returns ER_NO_DB_ERROR (1046) for an
        // unqualified relation with no database selected, but still resolves a
        // qualified `database.table` name; system schemas are never replica
        // databases. These are translator decisions, checked without an engine.
        {
            auto no_database = context;
            no_database.default_schema.clear();
            no_database.require_selected_database = true;
            auto unqualified =
                duckdb_translate_mysql_select("SELECT * FROM `odd``table`", no_database);
            auto qualified = duckdb_translate_mysql_select(qualified_other, no_database);
            auto reserved = duckdb_translate_mysql_select("SELECT * FROM information_schema.tables",
                                                          no_database);
            auto three_part = duckdb_translate_mysql_select(
                "SELECT * FROM `" + f.other_schema + "`.other_probe.id", no_database);
            const bool namespace_ok =
                unqualified.decision != DuckDBMySQLSelectDecision::supported &&
                unqualified.reason == "no_database_selected" && unqualified.sql.empty() &&
                qualified.decision == DuckDBMySQLSelectDecision::supported &&
                reserved.decision != DuckDBMySQLSelectDecision::supported &&
                reserved.reason == "reserved_database" && reserved.sql.empty() &&
                three_part.decision != DuckDBMySQLSelectDecision::supported &&
                three_part.sql.empty();
            cout << (namespace_ok ? "PASS" : "FAIL")
                 << " database namespace refusals (no-db=" << unqualified.reason
                 << ", qualified=" << qualified.reason << ", reserved=" << reserved.reason
                 << ", three-part=" << three_part.reason << ")\n";
            if (!namespace_ok)
                ++failures;
        }
        // The negative control changes only the copied translator candidate offset.
        auto control = duckdb_translate_mysql_select(
            "SELECT id FROM `odd``table` ORDER BY id LIMIT 1, 2", context);
        if (control.decision != DuckDBMySQLSelectDecision::supported)
            throw runtime_error("control refused");
        auto left = mysql_result(f.mysql, "SELECT id FROM `odd``table` ORDER BY id LIMIT 1, 2");
        auto altered = control.sql;
        auto pos = altered.find(" OFFSET 1");
        if (pos == string::npos)
            throw runtime_error("control expected offset missing");
        altered.replace(pos, 9, " OFFSET 2");
        auto right = duck_result(f.duck, altered);
        bool caught =
            left.names != right.names || left.types != right.types || left.rows != right.rows;
        cout << (caught ? "PASS" : "FAIL") << " comparator negative control (wrong LIMIT offset)\n";
        if (!caught)
            ++failures;
        // MySQL's DATE/DATETIME range starts at 1000, but formatting must also
        // agree for real calendar dates below 1000 before the emitted strftime
        // expression can be admitted for the mapped column domain.
        auto early_left = mysql_result(f.mysql, "SELECT DATE_FORMAT('0001-01-01','%Y-%m') AS a, "
                                                "DATE_FORMAT('0099-12-31 23:59:59','%Y-%m') AS b");
        auto early_right = duck_result(f.duck, "SELECT strftime(DATE '0001-01-01','%Y-%m') AS a, "
                                               "strftime(DATE '0099-12-31','%Y-%m') AS b");
        bool early_match = early_left.names == early_right.names &&
                           early_left.types == early_right.types &&
                           early_left.rows == early_right.rows;
        cout << (early_match ? "PASS" : "FAIL")
             << " early-year DATE_FORMAT domain probe (years below 1000)\n";
        if (!early_match)
            ++failures;
        // A recorded TIMESTAMP is refused because MySQL renders it in the session time zone while
        // DuckDB's naive value has none. The rows below sit on a month boundary, so under
        // UTC+05:00 MySQL and the emitted strftime must disagree, proving the refusal is needed.
        mysql_exec(f.mysql, "SET SESSION time_zone = '+05:00'");
        auto zone_left =
            mysql_result(f.mysql, "SELECT DATE_FORMAT(ts,'%Y-%m') FROM date_probe WHERE id = 2");
        mysql_exec(f.mysql, "SET SESSION time_zone = '+00:00'");
        auto zone_right =
            duck_result(f.duck, "SELECT strftime(ts,'%Y-%m') FROM date_probe WHERE id = 2");
        bool zone_differs = zone_left.rows != zone_right.rows;
        cout << (zone_differs ? "PASS" : "FAIL")
             << " TIMESTAMP DATE_FORMAT depends on the session time zone (refusal required)\n";
        if (!zone_differs)
            ++failures;
        // utf8mb4_0900_ai_ci is case- and accent-insensitive and has its own
        // ordering; DuckDB VARCHAR is bytewise. Both checks must differ on the
        // stated inputs, proving that admitting ai_ci would be wrong.
        auto ai_equal_left =
            mysql_result(f.mysql, "SELECT id FROM text_probe WHERE ai = 'A' ORDER BY id");
        auto ai_equal_right =
            duck_result(f.duck, "SELECT id FROM text_probe WHERE ai = 'A' ORDER BY id");
        bool ai_equal_differs = ai_equal_left.rows != ai_equal_right.rows;
        cout << (ai_equal_differs ? "PASS" : "FAIL")
             << " ai_ci equality differs from DuckDB on ai='A' (refusal required, MySQL rows="
             << ai_equal_left.rows.size() << ", DuckDB rows=" << ai_equal_right.rows.size()
             << ")\n";
        if (!ai_equal_differs)
            ++failures;
        auto ai_order_left =
            mysql_result(f.mysql, "SELECT id FROM text_probe WHERE ai IS NOT NULL ORDER BY ai, id");
        auto ai_order_right =
            duck_result(f.duck, "SELECT id FROM text_probe WHERE ai IS NOT NULL ORDER BY ai, id");
        bool ai_order_differs = ai_order_left.rows != ai_order_right.rows;
        cout << (ai_order_differs ? "PASS" : "FAIL")
             << " ai_ci ordering differs from DuckDB on the ai probe rows (refusal required)\n";
        if (!ai_order_differs)
            ++failures;
        // utf8mb4_bin is PAD SPACE: MySQL treats 'a' and 'a ' as equal, while
        // DuckDB compares the stored bytes and keeps them distinct.
        auto pad_left =
            mysql_result(f.mysql, "SELECT id FROM text_probe WHERE pad = 'a ' ORDER BY id");
        auto pad_right =
            duck_result(f.duck, "SELECT id FROM text_probe WHERE pad = 'a ' ORDER BY id");
        bool pad_differs = pad_left.rows != pad_right.rows;
        cout
            << (pad_differs ? "PASS" : "FAIL")
            << " utf8mb4_bin PAD SPACE equality differs from DuckDB on pad='a ' (refusal required, "
               "MySQL rows="
            << pad_left.rows.size() << ", DuckDB rows=" << pad_right.rows.size() << ")\n";
        if (!pad_differs)
            ++failures;
        cout << "compared=" << comparisons << " resolver_calls=" << calls
             << " failures=" << failures << "\n";
        return failures ? 1 : 0;
    } catch (const exception &e) {
        cerr << "probe error: " << e.what() << "\n";
        return 1;
    }
}
