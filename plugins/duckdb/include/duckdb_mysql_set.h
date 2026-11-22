#pragma once
#include <string>
enum class DuckDBMySQLSetKind { other, names, charset, autocommit_off, autocommit_on };
struct DuckDBMySQLSet {
    DuckDBMySQLSetKind kind = DuckDBMySQLSetKind::other;
    std::string charset;
    std::string collation;
};
DuckDBMySQLSet duckdb_parse_mysql_set(const std::string &sql);
