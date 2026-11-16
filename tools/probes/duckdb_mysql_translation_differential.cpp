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
                cells.push_back(
                    {false, out.types[i] == 2 ? exact_decimal(value.get()) : string(value.get())});
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
    bool schema_owned = false;
    ~Fixture() {
        if (duck)
            duckdb_disconnect(&duck);
        if (database)
            duckdb_close(&database);
        if (mysql) {
            if (schema_owned && mysql_query(mysql, ("DROP DATABASE `" + schema + "`").c_str()))
                cerr << "cleanup failed for " << schema << ": " << mysql_error(mysql) << "\n";
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
        mysql_exec(f.mysql, "UPDATE `odd``table` SET bin=X'00FF' WHERE id=1");
        duck_exec(f.duck, "UPDATE \"odd`table\" SET bin=from_hex('00FF') WHERE id=1");
        DuckDBMySQLSelectContext context;
        size_t calls = 0;
        context.resolve_relation = [&](const vector<string> &names, DuckDBMySQLRelation &r) {
            ++calls;
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
        const Case cases[] = {
            {"escaped and duplicate labels",
             "SELECT `a``b` AS same, id AS same FROM `odd``table` ORDER BY id"},
            {"qualified alias", "SELECT q.id, q.`a``b` FROM `odd``table` AS q ORDER BY q.id"},
            {"all projected types", "SELECT * FROM `odd``table` ORDER BY id"},
            {"count", "SELECT COUNT(*) AS n FROM `odd``table`"},
            {"count nullable", "SELECT COUNT(grp) AS n FROM `odd``table`"},
            {"integer literal", "SELECT 001"},
            {"null literal", "SELECT NULL"},
            {"null ascending", "SELECT id, grp FROM `odd``table` ORDER BY grp ASC, id ASC"},
            {"null descending", "SELECT id, grp FROM `odd``table` ORDER BY grp DESC, id ASC"},
            {"comma limit", "SELECT id FROM `odd``table` ORDER BY id LIMIT 1, 2"},
            {"integer predicate", "SELECT id FROM `odd``table` WHERE id > 1 ORDER BY id"},
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
        for (const char *sql : {"SELECT nextval('x')", "SELECT @x", "SELECT 1; SELECT 2"}) {
            auto x = duckdb_translate_mysql_select(sql, context);
            if (x.decision == DuckDBMySQLSelectDecision::supported || !x.sql.empty()) {
                cerr << "unexpected admission: " << sql << "\n";
                ++failures;
            } else
                cout << "REFUSAL " << sql << " " << x.reason << " (no engine call)\n";
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
        cout << "compared=" << comparisons << " resolver_calls=" << calls
             << " failures=" << failures << "\n";
        return failures ? 1 : 0;
    } catch (const exception &e) {
        cerr << "probe error: " << e.what() << "\n";
        return 1;
    }
}
