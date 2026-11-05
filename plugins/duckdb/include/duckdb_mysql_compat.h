#ifndef DUCKDB_MYSQL_COMPAT_H
#define DUCKDB_MYSQL_COMPAT_H
#include <string>
// Rewrites the documented SELECT subset; non-SELECT statements pass through.
// On failure, translated is empty and error explains the unsupported form.
bool duckdb_translate_mysql_select(const std::string &sql, std::string &translated,
								   std::string &error);
#endif
