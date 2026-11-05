#include "duckdb_mysql_compat.h"
#include "duckdb.h"
#include "tap.h"
#include <string>
#include <vector>

struct Case {
	const char *name;
	const char *sql;
	const char *want;
};
std::string execute(duckdb_connection conn, const std::string &sql) {
	duckdb_result r;
	if (duckdb_query(conn, sql.c_str(), &r) != DuckDBSuccess) {
		std::string error = duckdb_result_error(&r);
		duckdb_destroy_result(&r);
		return "ERROR: " + error;
	}
	std::string out;
	for (idx_t row = 0; row < duckdb_row_count(&r); ++row) {
		if (row)
			out += ";";
		for (idx_t col = 0; col < duckdb_column_count(&r); ++col) {
			if (col)
				out += "|";
			if (duckdb_value_is_null(&r, col, row))
				out += "NULL";
			else {
				char *text = duckdb_value_varchar(&r, col, row);
				out += text ? text : "";
				duckdb_free(text);
			}
		}
	}
	duckdb_destroy_result(&r);
	return out;
}
int main() {
	plan(NO_PLAN);
	duckdb_database db = nullptr;
	duckdb_connection conn = nullptr;
	if (duckdb_open(nullptr, &db) != DuckDBSuccess || duckdb_connect(db, &conn) != DuckDBSuccess)
		BAIL_OUT("DuckDB connection required");
	execute(
		conn,
		"CREATE TABLE sales(id INT,customer INT,amount DECIMAL(10,2),ts TIMESTAMP,note VARCHAR)");
	execute(conn, "INSERT INTO sales VALUES (1,1,10.00,'2026-11-05 12:34:56.123456','Ada'),"
				  "(2,1,5.00,'2026-11-06 "
				  "00:00:01','Bob'),(3,2,NULL,NULL,NULL),(4,2,20.00,'2026-11-07','Cid')");
	execute(conn, "CREATE SEQUENCE compat_seq START 1");
	execute(conn, "CREATE TABLE customers(id INT,name VARCHAR)");
	execute(conn, "INSERT INTO customers VALUES(1,'one'),(2,'two'),(3,'three')");
	const Case cases[] = {
		{"backtick identifiers", "SELECT `id`,`note` FROM `sales` WHERE `id`=1", "1|Ada"},
		{"escaped backtick", "SELECT 7 AS `a``b`", "7"},
		{"quoted keyword", "SELECT `limit` FROM (SELECT 4 AS `limit`) q", "4"},
		{"null-safe equality", "SELECT NULL <=> NULL, NULL <=> 1, 2 <=> 2", "true|false|true"},
		{"nested predicates",
		 "SELECT id FROM sales WHERE (amount <=> NULL) OR (id <=> 2) ORDER BY id", "2;3"},
		{"pagination", "SELECT id FROM sales ORDER BY id LIMIT 1,2", "2;3"},
		{"nested pagination",
		 "SELECT id FROM (SELECT id FROM sales ORDER BY id LIMIT 1,2) x ORDER BY id DESC LIMIT 0,1",
		 "3"},
		{"signed cast", "SELECT CAST('-12' AS SIGNED INTEGER),CAST('42' AS UNSIGNED)", "-12|42"},
		{"nested cast", "SELECT CAST(COALESCE(NULL,'17') AS SIGNED)", "17"},
		{"aggregates",
		 "SELECT customer,SUM(amount),CAST(AVG(amount) AS DECIMAL(10,2)),COUNT(*) FROM sales GROUP "
		 "BY customer HAVING COUNT(*)>1 ORDER BY customer",
		 "1|15.00|7.50|2;2|20.00|20.00|2"},
		{"join",
		 "SELECT c.name,IFNULL(SUM(s.amount),0) FROM customers c LEFT JOIN sales s ON "
		 "s.customer=c.id GROUP BY c.name ORDER BY c.name",
		 "one|15.00;three|0.00;two|20.00"},
		{"case and if",
		 "SELECT IF(id=1,'yes','no'),CASE WHEN amount IS NULL THEN 'empty' ELSE 'value' END FROM "
		 "sales WHERE id IN(1,3) ORDER BY id",
		 "yes|value;no|empty"},
		{"date difference",
		 "SELECT DATEDIFF('2026-11-06 00:01:00','2026-11-05 "
		 "23:59:00'),DATEDIFF('2026-11-04','2026-11-05')",
		 "1|-1"},
		{"date null", "SELECT DATEDIFF(NULL,'2026-11-05')", "NULL"},
		{"date format", "SELECT DATE_FORMAT(ts,'%Y-%m-%d %H:%i:%s.%f') FROM sales WHERE id=1",
		 "2026-11-05 12:34:56.123456"},
		{"date format nested",
		 "SELECT IFNULL(DATE_FORMAT(NULL,'%Y'),'none'),DATE_FORMAT(CAST('2026-11-05' AS DATE),'%a "
		 "%b %e %%')",
		 "none|Thu Nov 5 %"},
		{"CTE", "WITH x AS (SELECT `id` FROM sales ORDER BY id LIMIT 1,2) SELECT SUM(id) FROM x",
		 "5"},
		{"NULL ordering ASC", "SELECT id FROM sales ORDER BY amount,id", "3;2;1;4"},
		{"NULL ordering DESC", "SELECT id FROM sales ORDER BY amount DESC,id DESC", "4;1;2;3"},
		{"NULL ordering nested",
		 "SELECT id FROM (SELECT id,amount FROM sales ORDER BY amount LIMIT 0,2) q ORDER BY amount "
		 "DESC",
		 "2;3"},
		{"comments",
		 "/* SELECT `fake` */ sElEcT `id` # ignored `fake`\n FROM sales -- ignored\n ORDER BY id "
		 "LIMIT 1,1;",
		 "2"},
		{"literal contents", "SELECT '`id` <=> LIMIT 1,2 DATE_FORMAT(x)', 'O''Reilly'",
		 "`id` <=> LIMIT 1,2 DATE_FORMAT(x)|O'Reilly"},
		{"MySQL strings", "SELECT \"hello\",'O\\'Reilly','a\\\\b','line\\nfeed'",
		 "hello|O'Reilly|a\\b|line\nfeed"},
		{"boolean operators", "SELECT (1=1) && (2=2), (1=0) || (2=2)", "true|true"},
		{"unsigned wrapping",
		 "SELECT CAST(-1 AS UNSIGNED),CAST('-1' AS UNSIGNED),CAST(18446744073709551615 AS "
		 "UNSIGNED)",
		 "18446744073709551615|18446744073709551615|18446744073709551615"},
		{"signed wrapping", "SELECT CAST(18446744073709551615 AS SIGNED)", "-1"},
		{"unsigned aggregate", "SELECT CAST(-SUM(id) AS UNSIGNED) FROM sales",
		 "18446744073709551606"},
		{"cast evaluates once",
		 "SELECT CAST(-nextval('compat_seq') AS UNSIGNED),currval('compat_seq')",
		 "18446744073709551615|1"},
		{"LIKE escaping", "SELECT 'a_b' LIKE 'a\\_b','a_b' NOT LIKE 'a\\_b'", "true|false"},
		{"LIKE dynamic pattern", "SELECT 'a_b' LIKE CONCAT('a', '\\_', 'b')", "true"},
		{"adjacent string literals", "SELECT 'hello' 'world'", "helloworld"},
		{"parenthesized null-safe comparison", "SELECT (2 <=> 2) = 1", "true"},
		{"CASE with null-safe condition",
		 "SELECT CASE WHEN NULL <=> NULL THEN 7 ELSE 9 END,CASE WHEN (2 <=> 2)=1 THEN 5 ELSE 6 END",
		 "7|5"},
		{"date parts", "SELECT YEAR(ts),MONTH(ts),DAY(ts) FROM sales WHERE id=1", "2026|11|5"},
	};
	for (const auto &c : cases) {
		std::string translated, error;
		const bool translated_ok = duckdb_translate_mysql_select(c.sql, translated, error);
		const std::string actual =
			translated_ok ? execute(conn, translated) : "TRANSLATION: " + error;
		ok(translated_ok && actual == c.want, "%s: expected [%s], got [%s]", c.name, c.want,
		   actual.c_str());
	}
	for (const char *sql :
		 {"SELECT 1; SELECT 2", "SELECT 2 <=> 2 = 1",
		  "SELECT 2 <=> CASE WHEN TRUE THEN 2 ELSE 3 END = 1",
		  "SELECT CASE WHEN 2 <=> 2 = 1 THEN 1 ELSE 0 END", "SELECT 1 <=> 1 <=> 1",
		  "SELECT /*!80000 1 */ 2", "SELECT 'unterminated", "SELECT `unterminated", "SELECT '\\0'",
		  "SELECT DATE_FORMAT(ts,'%V') FROM sales", "SELECT DATE_FORMAT(ts,note) FROM sales",
		  "SELECT @secret", "SELECT * FROM sales FOR UPDATE",
		  "SELECT GROUP_CONCAT(note SEPARATOR ',') FROM sales", "SELECT !1=2",
		  "SELECT 1 LIMIT ?,?"}) {
		std::string translated = "stale", error;
		ok(!duckdb_translate_mysql_select(sql, translated, error) && translated.empty() &&
			   !error.empty(),
		   "unsupported/malformed query fails explicitly: %s", sql);
	}
	std::string translated, error;
	const std::string ddl = "CREATE TABLE native_ddl(x INTEGER)";
	ok(duckdb_translate_mysql_select(ddl, translated, error) && translated == ddl &&
		   execute(conn, translated) == "",
	   "non-SELECT statements retain their native execution path");
	std::string nested = "SELECT ";
	nested.append(200, '(');
	nested += "1";
	nested.append(200, ')');
	ok(!duckdb_translate_mysql_select(nested, translated, error),
	   "excessive nesting is rejected safely");
	nested = "SELECT ";
	for (int i = 0; i < 200; ++i)
		nested += "CASE WHEN TRUE THEN ";
	nested += "1";
	for (int i = 0; i < 200; ++i)
		nested += " ELSE 0 END";
	ok(!duckdb_translate_mysql_select(nested, translated, error),
	   "excessive CASE nesting is rejected safely");
	duckdb_disconnect(&conn);
	duckdb_close(&db);
	return exit_status();
}
