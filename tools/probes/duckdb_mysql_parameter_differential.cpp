// Local differential experiment: translator emits DuckDB SQL; both engines bind values.
#include "duckdb_mysql_select_compat.h"
#include <climits>
#include <cstring>
#include <duckdb.h>
#include <iostream>
#include <mysql.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

struct Value {
    long long v;
    bool null;
};
static void mysql_exec(MYSQL *m, const std::string &sql) {
    if (mysql_query(m, sql.c_str()))
        throw std::runtime_error(mysql_error(m));
}
static void duck_exec(duckdb_connection c, const char *sql) {
    duckdb_result r{};
    if (duckdb_query(c, sql, &r) != DuckDBSuccess) {
        std::string error = duckdb_result_error(&r);
        duckdb_destroy_result(&r);
        throw std::runtime_error(error);
    }
    duckdb_destroy_result(&r);
}
static std::vector<long long> mysql_rows(MYSQL *m, std::string_view sql,
                                         const std::vector<Value> &v) {
    MYSQL_STMT *s = mysql_stmt_init(m);
    if (!s)
        throw std::runtime_error("mysql_stmt_init");
    if (mysql_stmt_prepare(s, sql.data(), static_cast<unsigned long>(sql.size()))) {
        std::string e = mysql_stmt_error(s);
        mysql_stmt_close(s);
        throw std::runtime_error(e);
    }
    std::vector<long long> nums(v.size());
    std::vector<my_bool> nulls(v.size());
    std::vector<MYSQL_BIND> binds(v.size());
    for (size_t i = 0; i < v.size(); ++i) {
        nums[i] = v[i].v;
        nulls[i] = v[i].null;
        binds[i].buffer_type = MYSQL_TYPE_LONGLONG;
        binds[i].buffer = &nums[i];
        binds[i].is_null = &nulls[i];
    }
    if (mysql_stmt_bind_param(s, binds.data()) || mysql_stmt_execute(s)) {
        std::string e = mysql_stmt_error(s);
        mysql_stmt_close(s);
        throw std::runtime_error(e);
    }
    MYSQL_RES *meta = mysql_stmt_result_metadata(s);
    if (!meta || mysql_num_fields(meta) != 1 ||
        std::strcmp(mysql_fetch_fields(meta)[0].name, "id") ||
        mysql_fetch_fields(meta)[0].type != MYSQL_TYPE_LONG) {
        if (meta)
            mysql_free_result(meta);
        mysql_stmt_close(s);
        throw std::runtime_error("unexpected MySQL result metadata");
    }
    mysql_free_result(meta);
    long long id = 0;
    my_bool is_null = 0;
    MYSQL_BIND out{};
    out.buffer_type = MYSQL_TYPE_LONGLONG;
    out.buffer = &id;
    out.is_null = &is_null;
    if (mysql_stmt_bind_result(s, &out)) {
        mysql_stmt_close(s);
        throw std::runtime_error("bind mysql output");
    }
    std::vector<long long> rows;
    int rc;
    while ((rc = mysql_stmt_fetch(s)) == 0) {
        if (is_null) {
            mysql_stmt_close(s);
            throw std::runtime_error("unexpected MySQL NULL id");
        }
        rows.push_back(id);
    }
    if (rc != MYSQL_NO_DATA) {
        mysql_stmt_close(s);
        throw std::runtime_error("fetch mysql output");
    }
    mysql_stmt_close(s);
    return rows;
}
static std::vector<long long> duck_rows(duckdb_connection c, const std::string &sql,
                                        const std::vector<Value> &v) {
    duckdb_prepared_statement stmt = nullptr;
    if (duckdb_prepare(c, sql.c_str(), &stmt) != DuckDBSuccess) {
        std::string e = duckdb_prepare_error(stmt);
        duckdb_destroy_prepare(&stmt);
        throw std::runtime_error(e);
    }
    for (size_t i = 0; i < v.size(); ++i)
        if ((v[i].null ? duckdb_bind_null(stmt, i + 1) : duckdb_bind_int64(stmt, i + 1, v[i].v)) !=
            DuckDBSuccess) {
            duckdb_destroy_prepare(&stmt);
            throw std::runtime_error("bind duckdb input");
        }
    duckdb_result r{};
    if (duckdb_execute_prepared(stmt, &r) != DuckDBSuccess) {
        std::string e = duckdb_result_error(&r);
        duckdb_destroy_result(&r);
        duckdb_destroy_prepare(&stmt);
        throw std::runtime_error(e);
    }
    if (duckdb_column_count(&r) != 1 || std::strcmp(duckdb_column_name(&r, 0), "id") ||
        duckdb_column_type(&r, 0) != DUCKDB_TYPE_INTEGER) {
        duckdb_destroy_result(&r);
        duckdb_destroy_prepare(&stmt);
        throw std::runtime_error("unexpected DuckDB result metadata");
    }
    std::vector<long long> rows;
    for (idx_t i = 0; i < duckdb_row_count(&r); ++i) {
        if (duckdb_value_is_null(&r, 0, i)) {
            duckdb_destroy_result(&r);
            duckdb_destroy_prepare(&stmt);
            throw std::runtime_error("unexpected DuckDB NULL id");
        }
        rows.push_back(duckdb_value_int64(&r, 0, i));
    }
    duckdb_destroy_result(&r);
    duckdb_destroy_prepare(&stmt);
    return rows;
}
int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        std::cerr << "usage: " << argv[0] << " /absolute/owned-mysql-socket\n";
        return 2;
    }
    MYSQL *m = mysql_init(nullptr);
    duckdb_database db = nullptr;
    duckdb_connection c = nullptr;
    std::string schema = "parameter_oracle_" + std::to_string(getpid());
    bool created = false;
    int failures = 0;
    try {
        if (!m || !mysql_real_connect(m, "localhost", "root", "", nullptr, 0, argv[1], 0))
            throw std::runtime_error(m ? mysql_error(m) : "mysql_init");
        mysql_exec(m, "CREATE DATABASE `" + schema + "`");
        created = true;
        mysql_exec(m, "USE `" + schema + "`");
        mysql_exec(m, "CREATE TABLE tiny_fixture (id INT PRIMARY KEY,n TINYINT)");
        mysql_exec(m, "INSERT INTO tiny_fixture VALUES (1,5),(2,6),(3,NULL)");
        if (duckdb_open(nullptr, &db) != DuckDBSuccess || duckdb_connect(db, &c) != DuckDBSuccess)
            throw std::runtime_error("duckdb open/connect");
        duck_exec(c, "CREATE TABLE tiny_fixture (id INTEGER PRIMARY KEY,n TINYINT)");
        duck_exec(c, "INSERT INTO tiny_fixture VALUES (1,5),(2,6),(3,NULL)");
        DuckDBMySQLSelectContext context;
        context.parameter_mode = DuckDBMySQLParameterMode::prepare;
        context.resolve_relation = [](const std::vector<std::string> &parts,
                                      DuckDBMySQLRelation &out) {
            if (parts != std::vector<std::string>{"tiny_fixture"})
                return false;
            out.canonical_name = {"tiny_fixture"};
            out.exact_name_resolution = true;
            DuckDBMySQLType t;
            t.kind = DuckDBMySQLTypeKind::signed_integer;
            out.columns = {{"id", t}, {"n", t}};
            out.unique_keys = {{"id"}};
            return true;
        };
        struct Case {
            const char *name, *sql;
            std::vector<Value> params;
        };
        const std::vector<Case> cases = {
            {"five", "SELECT id FROM tiny_fixture WHERE n = ? ORDER BY id", {{5, false}}},
            {"six", "SELECT id FROM tiny_fixture WHERE n = ? ORDER BY id", {{6, false}}},
            {"no narrowing", "SELECT id FROM tiny_fixture WHERE n = ? ORDER BY id", {{200, false}}},
            {"NULL", "SELECT id FROM tiny_fixture WHERE n = ? ORDER BY id", {{0, true}}},
            {"int64 minimum",
             "SELECT id FROM tiny_fixture WHERE n = ? ORDER BY id",
             {{LLONG_MIN, false}}},
            {"int64 maximum",
             "SELECT id FROM tiny_fixture WHERE n = ? ORDER BY id",
             {{LLONG_MAX, false}}},
            {"distinct positions",
             "SELECT id FROM tiny_fixture WHERE ? < id AND id <= ? ORDER BY id",
             {{1, false}, {2, false}}}};
        std::cout << "MySQL " << mysql_get_server_info(m) << " DuckDB " << duckdb_library_version()
                  << "\n";
        for (const auto &test : cases) {
            context.parameter_mode = DuckDBMySQLParameterMode::execute;
            context.parameter_kinds.clear();
            for (const auto &param : test.params)
                context.parameter_kinds.push_back(param.null
                                                      ? DuckDBMySQLParameterKind::null_value
                                                      : DuckDBMySQLParameterKind::signed_integer);
            auto translated = duckdb_translate_mysql_select(test.sql, context);
            if (translated.decision != DuckDBMySQLSelectDecision::supported ||
                translated.parameter_count != test.params.size())
                throw std::runtime_error("translator refused " + std::string(test.name) + ": " +
                                         translated.reason);
            auto a = mysql_rows(m, test.sql, test.params),
                 b = duck_rows(c, translated.sql, test.params);
            const bool same = a == b;
            if (!same)
                ++failures;
            std::cout << (same ? "PASS " : "FAIL ") << test.name << " mysql=";
            for (auto v : a)
                std::cout << v << ",";
            std::cout << " duckdb=";
            for (auto v : b)
                std::cout << v << ",";
            std::cout << "\n";
        }
    } catch (const std::exception &e) {
        ++failures;
        std::cerr << e.what() << "\n";
    }
    if (created && mysql_query(m, ("DROP DATABASE `" + schema + "`").c_str())) {
        ++failures;
        std::cerr << "cleanup failed: " << mysql_error(m) << " database=" << schema << "\n";
    }
    if (c)
        duckdb_disconnect(&c);
    if (db)
        duckdb_close(&db);
    if (m)
        mysql_close(m);
    std::cout << "failures=" << failures << "\n";
    return failures ? 1 : 0;
}
