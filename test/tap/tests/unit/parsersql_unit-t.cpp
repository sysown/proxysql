#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "Query_Processor_ParserSQL.h"

#include <cstring>
#include <string>
#include <string_view>
#include <map>
#include <vector>

static inline size_t str_view_len(const char *s) {
	return s ? std::string_view{s}.size() : 0;
}

static void test_mysql_digest_select() {
	SQP_par_t qp;
	memset(&qp, 0, sizeof(qp));
	const char* q = "SELECT * FROM t1 WHERE id = 1";
	parsersql_digest_init_mysql(&qp, q, str_view_len(q));
	ok(qp.digest_text != NULL, "MySQL digest: SELECT produces digest_text");
	ok(qp.digest != 0, "MySQL digest: SELECT produces non-zero hash");
	if (qp.digest_text) {
		ok(strstr(qp.digest_text, "?") != NULL, "MySQL digest: literals replaced with ?");
		free(qp.digest_text);
	}
}

static void test_mysql_digest_insert() {
	SQP_par_t qp;
	memset(&qp, 0, sizeof(qp));
	const char* q = "INSERT INTO t1 (a, b) VALUES (1, 'hello')";
	parsersql_digest_init_mysql(&qp, q, str_view_len(q));
	ok(qp.digest_text != NULL, "MySQL digest: INSERT produces digest_text");
	ok(qp.digest != 0, "MySQL digest: INSERT produces non-zero hash");
	if (qp.digest_text) free(qp.digest_text);
}

static void test_mysql_digest_same_for_different_literals() {
	SQP_par_t qp1, qp2;
	memset(&qp1, 0, sizeof(qp1));
	memset(&qp2, 0, sizeof(qp2));
	const char* q1 = "SELECT * FROM t1 WHERE id = 1";
	const char* q2 = "SELECT * FROM t1 WHERE id = 999";
	parsersql_digest_init_mysql(&qp1, q1, str_view_len(q1));
	parsersql_digest_init_mysql(&qp2, q2, str_view_len(q2));
	ok(qp1.digest == qp2.digest, "MySQL digest: same query with different literals produces same hash");
	if (qp1.digest_text) free(qp1.digest_text);
	if (qp2.digest_text) free(qp2.digest_text);
}

static void test_mysql_digest_different_queries() {
	SQP_par_t qp1, qp2;
	memset(&qp1, 0, sizeof(qp1));
	memset(&qp2, 0, sizeof(qp2));
	const char* q1 = "SELECT * FROM t1 WHERE id = 1";
	const char* q2 = "SELECT * FROM t2 WHERE id = 1";
	parsersql_digest_init_mysql(&qp1, q1, str_view_len(q1));
	parsersql_digest_init_mysql(&qp2, q2, str_view_len(q2));
	ok(qp1.digest != qp2.digest, "MySQL digest: different tables produce different hashes");
	if (qp1.digest_text) free(qp1.digest_text);
	if (qp2.digest_text) free(qp2.digest_text);
}

static void test_pgsql_digest_select() {
	SQP_par_t qp;
	memset(&qp, 0, sizeof(qp));
	const char* q = "SELECT * FROM t1 WHERE id = 1";
	parsersql_digest_init_pgsql(&qp, q, str_view_len(q));
	ok(qp.digest_text != NULL, "PgSQL digest: SELECT produces digest_text");
	ok(qp.digest != 0, "PgSQL digest: SELECT produces non-zero hash");
	if (qp.digest_text) free(qp.digest_text);
}

static void test_pgsql_digest_same_for_different_literals() {
	SQP_par_t qp1, qp2;
	memset(&qp1, 0, sizeof(qp1));
	memset(&qp2, 0, sizeof(qp2));
	const char* q1 = "SELECT * FROM t1 WHERE id = 1";
	const char* q2 = "SELECT * FROM t1 WHERE id = 999";
	parsersql_digest_init_pgsql(&qp1, q1, str_view_len(q1));
	parsersql_digest_init_pgsql(&qp2, q2, str_view_len(q2));
	ok(qp1.digest == qp2.digest, "PgSQL digest: same query with different literals produces same hash");
	if (qp1.digest_text) free(qp1.digest_text);
	if (qp2.digest_text) free(qp2.digest_text);
}

static void test_mysql_command_type_select() {
	const char* q = "SELECT 1";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_SELECT,
		"MySQL cmd: SELECT → SELECT");
}

static void test_mysql_command_type_insert() {
	const char* q = "INSERT INTO t1 VALUES (1)";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_INSERT,
		"MySQL cmd: INSERT → INSERT");
}

static void test_mysql_command_type_update() {
	const char* q = "UPDATE t1 SET a = 1";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_UPDATE,
		"MySQL cmd: UPDATE → UPDATE");
}

static void test_mysql_command_type_delete() {
	const char* q = "DELETE FROM t1 WHERE id = 1";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_DELETE,
		"MySQL cmd: DELETE → DELETE");
}

static void test_mysql_command_type_set() {
	const char* q = "SET @a = 1";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_SET,
		"MySQL cmd: SET → SET");
}

static void test_mysql_command_type_begin() {
	const char* q = "BEGIN";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_BEGIN,
		"MySQL cmd: BEGIN → BEGIN");
}

static void test_mysql_command_type_commit() {
	const char* q = "COMMIT";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_COMMIT,
		"MySQL cmd: COMMIT → COMMIT");
}

static void test_mysql_command_type_rollback() {
	const char* q = "ROLLBACK";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_ROLLBACK,
		"MySQL cmd: ROLLBACK → ROLLBACK");
}

static void test_mysql_command_type_create_table() {
	const char* q = "CREATE TABLE t1 (id INT)";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_CREATE_TABLE,
		"MySQL cmd: CREATE TABLE → CREATE_TABLE");
}

static void test_mysql_command_type_drop_table() {
	const char* q = "DROP TABLE t1";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_DROP_TABLE,
		"MySQL cmd: DROP TABLE → DROP_TABLE");
}

static void test_mysql_command_type_show() {
	const char* q = "SHOW TABLES";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_SHOW,
		"MySQL cmd: SHOW → SHOW");
}

static void test_mysql_command_type_use() {
	const char* q = "USE mydb";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_USE,
		"MySQL cmd: USE → USE");
}

static void test_mysql_command_type_prepare() {
	const char* q = "PREPARE stmt FROM 'SELECT 1'";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_PREPARE,
		"MySQL cmd: PREPARE → PREPARE");
}

static void test_mysql_command_type_explain() {
	const char* q = "EXPLAIN SELECT 1";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_EXPLAIN,
		"MySQL cmd: EXPLAIN → EXPLAIN");
}

static void test_pgsql_command_type_select() {
	const char* q = "SELECT 1";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_SELECT,
		"PgSQL cmd: SELECT → SELECT");
}

static void test_pgsql_command_type_insert() {
	const char* q = "INSERT INTO t1 VALUES (1)";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_INSERT,
		"PgSQL cmd: INSERT → INSERT");
}

static void test_pgsql_command_type_update() {
	const char* q = "UPDATE t1 SET a = 1";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_UPDATE,
		"PgSQL cmd: UPDATE → UPDATE");
}

static void test_pgsql_command_type_delete() {
	const char* q = "DELETE FROM t1 WHERE id = 1";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_DELETE,
		"PgSQL cmd: DELETE → DELETE");
}

static void test_pgsql_command_type_set() {
	const char* q = "SET search_path TO public";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_SET,
		"PgSQL cmd: SET → SET");
}

static void test_pgsql_command_type_begin() {
	const char* q = "BEGIN";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_BEGIN,
		"PgSQL cmd: BEGIN → BEGIN");
}

static void test_pgsql_command_type_commit() {
	const char* q = "COMMIT";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_COMMIT,
		"PgSQL cmd: COMMIT → COMMIT");
}

static void test_pgsql_command_type_show() {
	const char* q = "SHOW search_path";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_SHOW,
		"PgSQL cmd: SHOW → SHOW");
}

static void test_pgsql_command_type_truncate() {
	const char* q = "TRUNCATE TABLE t1";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_TRUNCATE,
		"PgSQL cmd: TRUNCATE → TRUNCATE");
}

static void test_pgsql_command_type_reset() {
	const char* q = "RESET ALL";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_RESET,
		"PgSQL cmd: RESET → RESET");
}

static void test_mysql_set_simple() {
	auto m = parsersql_parse_set_mysql("SET wait_timeout = 100");
	ok(m.size() > 0, "MySQL SET: simple assignment produces output");
	ok(m.count("wait_timeout") > 0, "MySQL SET: variable 'wait_timeout' found");
	ok(m.count("wait_timeout") > 0 && m["wait_timeout"].size() >= 1,
		"MySQL SET: variable 'wait_timeout' has value");
}

static void test_mysql_set_multiple() {
	auto m = parsersql_parse_set_mysql("SET wait_timeout = 100, max_connections = 200");
	ok(m.count("wait_timeout") > 0, "MySQL SET multi: variable 'wait_timeout' found");
	ok(m.count("max_connections") > 0, "MySQL SET multi: variable 'max_connections' found");
}

static void test_mysql_set_names() {
	auto m = parsersql_parse_set_mysql("SET NAMES utf8mb4");
	ok(m.count("names") > 0, "MySQL SET NAMES: 'names' key found");
}

static void test_mysql_set_session_scope() {
	auto m = parsersql_parse_set_mysql("SET SESSION wait_timeout = 100");
	ok(m.count("wait_timeout") > 0, "MySQL SET SESSION: scope prefix stripped");
}

static void test_mysql_set_global_scope() {
	auto m = parsersql_parse_set_mysql("SET GLOBAL max_connections = 200");
	ok(m.count("max_connections") > 0, "MySQL SET GLOBAL: scope prefix stripped");
}

static void test_pgsql_set_simple() {
	auto m = parsersql_parse_set_pgsql("SET search_path TO public");
	ok(m.size() > 0, "PgSQL SET: simple assignment produces output");
	ok(m.count("search_path") > 0, "PgSQL SET: variable 'search_path' found");
}

static void test_pgsql_set_multiple_values() {
	auto m = parsersql_parse_set_pgsql("SET search_path TO public, pg_catalog");
	ok(m.count("search_path") > 0, "PgSQL SET multi-value: 'search_path' found");
	if (m.count("search_path") > 0) {
		ok(m["search_path"].size() >= 2, "PgSQL SET multi-value: has multiple values");
	}
}

static void test_pgsql_set_invalid() {
	auto m = parsersql_parse_set_pgsql("NOT A SET STATEMENT");
	ok(m.empty(), "PgSQL SET: invalid input produces empty map");
}

static void test_mysql_set_invalid() {
	auto m = parsersql_parse_set_mysql("NOT A SET STATEMENT");
	ok(m.empty(), "MySQL SET: invalid input produces empty map");
}

static void test_mysql_digest_empty_query() {
	SQP_par_t qp;
	memset(&qp, 0, sizeof(qp));
	const char* q = "";
	parsersql_digest_init_mysql(&qp, q, 0);
	ok(qp.digest_text == NULL, "MySQL digest: empty query produces NULL digest_text");
	ok(qp.digest == 0, "MySQL digest: empty query produces zero hash");
}

static void test_mysql_command_type_unknown() {
	const char* q = "THISISNOTASQLCOMMAND";
	ok(parsersql_command_type_mysql(q, str_view_len(q)) == MYSQL_COM_QUERY_UNKNOWN,
		"MySQL cmd: garbage → UNKNOWN");
}

static void test_pgsql_command_type_unknown() {
	const char* q = "THISISNOTASQLCOMMAND";
	ok(parsersql_command_type_pgsql(q, str_view_len(q)) == PGSQL_QUERY_UNKNOWN,
		"PgSQL cmd: garbage → UNKNOWN");
}

int main() {
	plan(53);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_mysql_digest_select();
	test_mysql_digest_insert();
	test_mysql_digest_same_for_different_literals();
	test_mysql_digest_different_queries();
	test_pgsql_digest_select();
	test_pgsql_digest_same_for_different_literals();
	test_mysql_digest_empty_query();

	test_mysql_command_type_select();
	test_mysql_command_type_insert();
	test_mysql_command_type_update();
	test_mysql_command_type_delete();
	test_mysql_command_type_set();
	test_mysql_command_type_begin();
	test_mysql_command_type_commit();
	test_mysql_command_type_rollback();
	test_mysql_command_type_create_table();
	test_mysql_command_type_drop_table();
	test_mysql_command_type_show();
	test_mysql_command_type_use();
	test_mysql_command_type_prepare();
	test_mysql_command_type_explain();
	test_mysql_command_type_unknown();

	test_pgsql_command_type_select();
	test_pgsql_command_type_insert();
	test_pgsql_command_type_update();
	test_pgsql_command_type_delete();
	test_pgsql_command_type_set();
	test_pgsql_command_type_begin();
	test_pgsql_command_type_commit();
	test_pgsql_command_type_show();
	test_pgsql_command_type_truncate();
	test_pgsql_command_type_reset();
	test_pgsql_command_type_unknown();

	test_mysql_set_simple();
	test_mysql_set_multiple();
	test_mysql_set_names();
	test_mysql_set_session_scope();
	test_mysql_set_global_scope();
	test_mysql_set_invalid();

	test_pgsql_set_simple();
	test_pgsql_set_multiple_values();
	test_pgsql_set_invalid();

	test_cleanup_minimal();
	return exit_status();
}
