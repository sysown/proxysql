#include "duckdb_session.h"
#include "sqlite3db.h"
#include "tap.h"

#include <cstring>
#include <memory>
#include <string>

namespace {
DuckDBIntercept classify(const char* s) {
	return duckdb_classify_query(s, std::strlen(s));
}
} // namespace

int main() {
	plan(12);

	ok(classify("SELECT @@version") == DuckDBIntercept::version,
	   "SELECT @@version is intercepted");
	ok(classify("select @@VERSION") == DuckDBIntercept::version,
	   "intercept matching is case-insensitive");
	ok(classify("  SELECT   @@version  ") == DuckDBIntercept::version,
	   "leading, trailing and inner whitespace are tolerated");
	ok(classify("SELECT version()") == DuckDBIntercept::version,
	   "SELECT version() is intercepted");
	ok(classify("SELECT DATABASE()") == DuckDBIntercept::database,
	   "SELECT DATABASE() is intercepted");
	ok(classify("SHOW TABLES") == DuckDBIntercept::show_tables,
	   "SHOW TABLES is intercepted");
	ok(classify("SHOW DATABASES") == DuckDBIntercept::show_databases,
	   "SHOW DATABASES is intercepted");
	ok(classify("SET autocommit=1") == DuckDBIntercept::ok_noop,
	   "SET is accepted as a no-op");
	ok(classify("SELECT * FROM t") == DuckDBIntercept::none,
	   "an ordinary query is not intercepted");
	ok(classify("") == DuckDBIntercept::none,
	   "an empty query is not intercepted");

	// A prefix must not match: "SELECT @@version_comment" is a real query.
	ok(classify("SELECT @@version_comment") == DuckDBIntercept::none,
	   "a longer variable name is not mistaken for @@version");

	{
		std::unique_ptr<SQLite3_result> r(
			duckdb_build_intercept_result(DuckDBIntercept::version));
		ok(r && r->columns == 1 && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr,
		   "the version intercept builds a one-cell resultset");
	}

	return exit_status();
}
