#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "Query_Processor_ParserSQL.h"
#include "MySQL_User_Variables.h"

#include <cstring>
#include <string>
#include <string_view>
#include <map>
#include <vector>

bool mysql_user_variable_tracking_can_stage(
	int mode, int set_parser_algorithm, int query_processor_parser,
	bool plain_text_com_query, bool connection_bound_fallback);
bool mysql_user_variable_set_uses_qpo_epilogue(
	UserVariableSetStatus analysis_status,
	MySQL_User_Variable_Apply_Result preflight_result);
bool mysql_user_variable_commit_post_ok(
	MySQL_User_Variable_State& frontend,
	MySQL_User_Variable_State& backend,
	const std::vector<UserVariableAssignment>& assignments);
bool mysql_user_variable_accepts_new_assignments_policy(
	int mode, int set_parser_algorithm, int query_processor_parser,
	bool plain_text_com_query, bool connection_bound_fallback);
bool mysql_user_variable_must_classify_and_sync_policy(
	int mode, int set_parser_algorithm, int query_processor_parser,
	bool plain_text_com_query, bool connection_bound_fallback,
	bool tracking_latched);

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

static UserVariableSetAnalysis analyze_user_set(const char* query) {
	return parsersql_analyze_user_variable_set_mysql(query, str_view_len(query));
}

static void test_user_variable_browser_metadata() {
	const char* q =
		"SET @browser_lang = 'en-US', @browser_time = '2026-08-11 18:11:12', "
		"@browser_timezone = 'GMT+2', @ip_address = '167.235.198.244'";
	auto r = analyze_user_set(q);
	bool exact = r.status == UserVariableSetStatus::SUPPORTED && r.assignments.size() == 4;
	if (exact) {
		exact = r.assignments[0].canonical_name == "browser_lang" &&
			r.assignments[0].replay_target == "@browser_lang" &&
			r.assignments[0].raw_literal == "'en-US'" &&
			r.assignments[0].kind == UserVariableLiteralKind::STRING &&
			r.assignments[1].canonical_name == "browser_time" &&
			r.assignments[1].raw_literal == "'2026-08-11 18:11:12'" &&
			r.assignments[2].canonical_name == "browser_timezone" &&
			r.assignments[2].raw_literal == "'GMT+2'" &&
			r.assignments[3].canonical_name == "ip_address" &&
			r.assignments[3].raw_literal == "'167.235.198.244'";
	}
	ok(exact, "typed user SET: browser metadata is lossless and ordered");
}

static void test_user_variable_supported_literals() {
	struct Case { const char* query; const char* raw; UserVariableLiteralKind kind; };
	const Case cases[] = {
		{"SET @x='a\\\\b'", "'a\\\\b'", UserVariableLiteralKind::STRING},
		{"SET @x=42", "42", UserVariableLiteralKind::INTEGER},
		{"SET @x=-42", "-42", UserVariableLiteralKind::INTEGER},
		{"SET @x=1.25", "1.25", UserVariableLiteralKind::DECIMAL},
		{"SET @x=+1.2E-3", "+1.2E-3", UserVariableLiteralKind::DECIMAL},
		{"SET @x=0xCAFE", "0xCAFE", UserVariableLiteralKind::HEXADECIMAL},
		{"SET @x=X'CAFE'", "X'CAFE'", UserVariableLiteralKind::HEXADECIMAL},
		{"SET @x=0b101", "0b101", UserVariableLiteralKind::BIT},
		{"SET @x=B'101'", "B'101'", UserVariableLiteralKind::BIT},
		{"SET @x=NULL", "NULL", UserVariableLiteralKind::NULL_VALUE},
	};
	for (const auto& c : cases) {
		auto r = analyze_user_set(c.query);
		bool exact = r.status == UserVariableSetStatus::SUPPORTED &&
			r.assignments.size() == 1 && r.assignments[0].raw_literal == c.raw &&
			r.assignments[0].kind == c.kind && r.assignments[0].hash != 0;
		ok(exact, "typed user SET supported literal: %s", c.query);
	}
}

static void test_user_variable_identity_and_order() {
	auto r = analyze_user_set("SET @B=1,@a='x',@b=2,@'safe''name'=NULL");
	bool exact = r.status == UserVariableSetStatus::SUPPORTED && r.assignments.size() == 4;
	if (exact) {
		exact = r.assignments[0].canonical_name == "b" &&
			r.assignments[1].canonical_name == "a" &&
			r.assignments[2].canonical_name == "b" &&
			r.assignments[3].canonical_name == "safe'name" &&
			r.assignments[3].replay_target == "@'safe''name'";
	}
	ok(exact, "typed user SET preserves source order, repeats, and canonical identity");
}

static void test_user_variable_backslashes() {
	auto target = analyze_user_set("SET @'mode\\\\dependent'=1");
	ok(target.status == UserVariableSetStatus::UNSUPPORTED && target.assignments.empty(),
		"typed user SET rejects backslash-containing quoted target atomically");
	auto rhs = analyze_user_set("SET @safe='mode\\\\independent'");
	ok(rhs.status == UserVariableSetStatus::SUPPORTED && rhs.assignments.size() == 1 &&
		rhs.assignments[0].raw_literal == "'mode\\\\independent'",
		"typed user SET preserves backslashes in raw RHS strings");
}

static void test_user_variable_non_user_statuses() {
	auto select = analyze_user_set("SELECT 1");
	ok(select.status == UserVariableSetStatus::NOT_USER_VARIABLE_SET && select.assignments.empty(),
		"typed user SET reports non-SET input");
	auto system = analyze_user_set("SET sql_mode='TRADITIONAL'");
	ok(system.status == UserVariableSetStatus::NOT_USER_VARIABLE_SET && system.assignments.empty(),
		"typed user SET reports system-only SET input");
	auto mariadb_statement = analyze_user_set(
		"SET STATEMENT max_statement_time=300 FOR SELECT 1");
	ok(mariadb_statement.status == UserVariableSetStatus::NOT_USER_VARIABLE_SET &&
		mariadb_statement.assignments.empty(),
		"typed user SET leaves unsupported non-UDV MariaDB SET syntax to the legacy parser");
	auto malformed_user = analyze_user_set("SET @x='unterminated");
	ok(malformed_user.status == UserVariableSetStatus::PARSE_ERROR &&
		malformed_user.assignments.empty(),
		"typed user SET retains parse errors when the tokenizer detected a UDV");
}

static void test_user_variable_rejections() {
	struct Case { const char* query; UserVariableSetStatus status; };
	const Case cases[] = {
		{"SET @x=1, sql_mode='x'", UserVariableSetStatus::UNSUPPORTED},
		{"SET @x=1+2", UserVariableSetStatus::UNSUPPORTED},
		{"SET @x=CAST(1 AS SIGNED)", UserVariableSetStatus::UNSUPPORTED},
		{"SET @x=(1)", UserVariableSetStatus::UNSUPPORTED},
		{"SET @x=NOT 1", UserVariableSetStatus::UNSUPPORTED},
		{"SET @x=(SELECT 1)", UserVariableSetStatus::UNSUPPORTED},
		{"SET @x=?", UserVariableSetStatus::UNSUPPORTED},
		{"SET @x=NOW()", UserVariableSetStatus::UNSUPPORTED},
		{"SET @x=1,@y=NOW()", UserVariableSetStatus::UNSUPPORTED},
		{"SET @x=_utf8mb4'hello'", UserVariableSetStatus::PARSE_ERROR},
		{"SET @x='hello' COLLATE utf8mb4_bin", UserVariableSetStatus::PARSE_ERROR},
		{"SET @x=1,", UserVariableSetStatus::PARSE_ERROR},
		{"SET @x=1; SELECT 1", UserVariableSetStatus::PARSE_ERROR},
		{"SET @x='unterminated", UserVariableSetStatus::PARSE_ERROR},
		{"SET @x=1e+", UserVariableSetStatus::PARSE_ERROR},
		{"SET @bad-name=1", UserVariableSetStatus::PARSE_ERROR},
		{"SET @x=(1", UserVariableSetStatus::PARSE_ERROR},
		{"SET @x=1 /* unterminated", UserVariableSetStatus::PARSE_ERROR},
	};
	for (const auto& c : cases) {
		auto r = analyze_user_set(c.query);
		ok(r.status == c.status && r.assignments.empty(),
			"typed user SET rejects atomically: %s", c.query);
	}
	std::string long_name = "SET @" + std::string(65, 'a') + "=1";
	auto r = parsersql_analyze_user_variable_set_mysql(long_name.data(), long_name.size());
	ok(r.status == UserVariableSetStatus::PARSE_ERROR && r.assignments.empty(),
		"typed user SET rejects names over 64 bytes atomically");
}

static void test_user_variable_hash_contract() {
	auto base = analyze_user_set("SET @x=1");
	auto same = analyze_user_set("SET @x=1");
	auto target = analyze_user_set("SET @y=1");
	auto literal = analyze_user_set("SET @x=2");
	auto kind = analyze_user_set("SET @x='1'");
	auto boundary_left = analyze_user_set("SET @a=12");
	auto boundary_right = analyze_user_set("SET @a1=2");
	bool supported = base.status == UserVariableSetStatus::SUPPORTED &&
		same.status == UserVariableSetStatus::SUPPORTED &&
		target.status == UserVariableSetStatus::SUPPORTED &&
		literal.status == UserVariableSetStatus::SUPPORTED &&
		kind.status == UserVariableSetStatus::SUPPORTED &&
		boundary_left.status == UserVariableSetStatus::SUPPORTED &&
		boundary_right.status == UserVariableSetStatus::SUPPORTED;
	ok(supported && base.assignments[0].hash == 5603253534018379060ULL,
		"typed user SET hash matches the fixed SET @x=1 golden value");
	ok(supported && base.assignments[0].hash == same.assignments[0].hash,
		"typed user SET hash is deterministic for an identical tuple");
	ok(supported && base.assignments[0].hash != target.assignments[0].hash,
		"typed user SET hash includes the replay target");
	ok(supported && base.assignments[0].hash != literal.assignments[0].hash,
		"typed user SET hash includes the raw literal");
	ok(supported && base.assignments[0].hash != kind.assignments[0].hash,
		"typed user SET hash distinguishes literal kind");
	ok(supported && boundary_left.assignments[0].hash != boundary_right.assignments[0].hash,
		"typed user SET hash length-delimits tuple boundaries");
}

static void test_user_variable_usage() {
	struct Case { const char* query; UserVariableUsage usage; };
	const Case cases[] = {
		{"SELECT 1", UserVariableUsage::NO_USER_VARIABLE},
		{"SELECT '@x'", UserVariableUsage::NO_USER_VARIABLE},
		{"SELECT 1 /* @x */", UserVariableUsage::NO_USER_VARIABLE},
		{"SELECT @x", UserVariableUsage::READ_ONLY},
		{"SELECT -@x WHERE @y=1", UserVariableUsage::READ_ONLY},
		{"SELECT 1--@x", UserVariableUsage::READ_ONLY},
		{"SET @x=1", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"SELECT @x:=1", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"SELECT id INTO @x FROM test.uv_source", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"SELECT COALESCE(@x,1)", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"CALL p(@x)", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"SELECT ? + @x", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"SELECT @'unterminated", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"/*!40101 SET @x=1 */", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"/*M!100100 SET @x=1 */", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"/*M! SET @x=1 */", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"SELECT @x /* unterminated", UserVariableUsage::UNSAFE_OR_UNKNOWN},
		{"SET @x=1 /* unterminated", UserVariableUsage::UNSAFE_OR_UNKNOWN},
	};
	for (const auto& c : cases) {
		auto got = parsersql_classify_user_variable_usage_mysql(c.query, str_view_len(c.query));
		ok(got == c.usage, "typed user usage classification: %s", c.query);
	}
}

static void test_user_variable_tracking_policy() {
	ok(mysql_user_variable_tracking_can_stage(1, 3, 0, true, false),
		"user-variable tracking policy accepts ParserSQL SET mode");
	ok(mysql_user_variable_tracking_can_stage(1, 2, 1, true, false),
		"user-variable tracking policy accepts full-query ParserSQL mode");
	ok(!mysql_user_variable_tracking_can_stage(0, 3, 0, true, false),
		"user-variable tracking policy requires mode 1");
	ok(!mysql_user_variable_tracking_can_stage(2, 3, 0, true, false),
		"user-variable tracking policy reserves other integer modes");
	ok(!mysql_user_variable_tracking_can_stage(1, 2, 0, true, false),
		"user-variable tracking policy requires a ParserSQL prerequisite");
	ok(!mysql_user_variable_tracking_can_stage(1, 3, 0, false, false),
		"user-variable tracking policy rejects prepared protocol paths");
	ok(!mysql_user_variable_tracking_can_stage(1, 3, 0, true, true),
		"user-variable tracking policy rejects a connection-bound fallback");
}

static void test_user_variable_staging_preflight() {
	MySQL_User_Variable_State committed;
	auto initial = analyze_user_set("SET @kept=1");
	committed.apply(initial.assignments);
	const size_t committed_size = committed.size();
	const size_t committed_bytes = committed.stored_bytes();

	auto update = analyze_user_set("SET @new='value'");
	MySQL_User_Variable_State staged;
	auto rc = committed.stage(update.assignments, staged);
	ok(rc == MySQL_User_Variable_Apply_Result::OK && staged.size() == 2,
		"user-variable preflight builds the staged post-SET map");
	ok(committed.size() == committed_size && committed.stored_bytes() == committed_bytes,
		"user-variable preflight never mutates committed state");

	std::vector<UserVariableAssignment> fill;
	for (size_t i = 0; i < MySQL_User_Variable_State::kMaxVariables; ++i) {
		const std::string name = "v" + std::to_string(i);
		fill.push_back({name, "@" + name, "1", UserVariableLiteralKind::INTEGER, i + 1});
	}
	MySQL_User_Variable_State full;
	full.apply(fill);
	const size_t full_bytes = full.stored_bytes();
	MySQL_User_Variable_State rejected;
	std::vector<UserVariableAssignment> overflow {
		{"overflow", "@overflow", "2", UserVariableLiteralKind::INTEGER, 999}
	};
	rc = full.stage(overflow, rejected);
	ok(rc == MySQL_User_Variable_Apply_Result::VARIABLE_LIMIT,
		"user-variable preflight rejects a staged post-SET map over the resource limit");
	ok(full.size() == MySQL_User_Variable_State::kMaxVariables && full.stored_bytes() == full_bytes,
		"failed user-variable preflight leaves committed state untouched");
}

static void test_user_variable_routing_disposition() {
	ok(mysql_user_variable_set_uses_qpo_epilogue(
		UserVariableSetStatus::SUPPORTED, MySQL_User_Variable_Apply_Result::OK),
		"supported preflighted UDV SET forwards through the qpo routing epilogue");
	ok(!mysql_user_variable_set_uses_qpo_epilogue(
		UserVariableSetStatus::SUPPORTED, MySQL_User_Variable_Apply_Result::VARIABLE_LIMIT),
		"variable-limit UDV SET does not take the safe qpo routing disposition");
	ok(!mysql_user_variable_set_uses_qpo_epilogue(
		UserVariableSetStatus::SUPPORTED, MySQL_User_Variable_Apply_Result::BYTE_LIMIT),
		"byte-limit UDV SET does not take the safe qpo routing disposition");
	ok(!mysql_user_variable_set_uses_qpo_epilogue(
		UserVariableSetStatus::NOT_USER_VARIABLE_SET, MySQL_User_Variable_Apply_Result::OK),
		"non-UDV SET continues through the legacy SET walker");
	ok(!mysql_user_variable_set_uses_qpo_epilogue(
		UserVariableSetStatus::UNSUPPORTED, MySQL_User_Variable_Apply_Result::OK),
		"unsupported UDV SET takes connection-bound fallback instead of safe routing");
}

static void test_user_variable_post_ok_atomic_commit() {
	auto initial = analyze_user_set("SET @kept=1");
	auto update = analyze_user_set("SET @new='value'");
	MySQL_User_Variable_State frontend;
	MySQL_User_Variable_State backend;
	frontend.apply(initial.assignments);
	backend.apply(initial.assignments);
	const bool committed = mysql_user_variable_commit_post_ok(
		frontend, backend, update.assignments);
	unsigned int frontend_not_matching = 0;
	unsigned int backend_not_matching = 0;
	ok(committed && frontend.size() == 2 && backend.size() == 2 &&
		frontend.count_matches(backend, frontend_not_matching) == 2 &&
		frontend_not_matching == 0 &&
		backend.count_matches(frontend, backend_not_matching) == 2 &&
		backend_not_matching == 0,
		"post-OK helper commits the same supported assignments to both maps");

	std::vector<UserVariableAssignment> fill;
	for (size_t i = 0; i < MySQL_User_Variable_State::kMaxVariables; ++i) {
		const std::string name = "v" + std::to_string(i);
		fill.push_back({name, "@" + name, "1", UserVariableLiteralKind::INTEGER, i + 1});
	}
	std::vector<UserVariableAssignment> overflow {
		{"overflow", "@overflow", "2", UserVariableLiteralKind::INTEGER, 999}
	};

	MySQL_User_Variable_State full_frontend;
	MySQL_User_Variable_State empty_backend;
	full_frontend.apply(fill);
	ok(!mysql_user_variable_commit_post_ok(full_frontend, empty_backend, overflow) &&
		full_frontend.size() == MySQL_User_Variable_State::kMaxVariables &&
		empty_backend.size() == 0,
		"frontend post-OK staging failure commits neither map and requests fallback");

	MySQL_User_Variable_State empty_frontend;
	MySQL_User_Variable_State full_backend;
	full_backend.apply(fill);
	ok(!mysql_user_variable_commit_post_ok(empty_frontend, full_backend, overflow) &&
		empty_frontend.size() == 0 &&
		full_backend.size() == MySQL_User_Variable_State::kMaxVariables,
		"backend post-OK staging failure commits neither map and requests fallback");
}

static void test_user_variable_query_disposition() {
	auto decide = [](const char* query, bool active = true, bool plain = true,
		bool supported_set = false) {
		return mysql_user_variable_query_disposition(
			query, str_view_len(query), active, plain, supported_set);
	};
	auto d = decide("SELECT 1");
	ok(d.disposition == UserVariableQueryDisposition::SAFE && !d.parsersql_called &&
		d.legacy_udv_status_safe,
		"UDV disposition uses the no-at fast gate without ParserSQL");
	d = decide("SELECT '@x'");
	ok(d.disposition == UserVariableQueryDisposition::SAFE && d.parsersql_called &&
		d.legacy_udv_status_safe,
		"UDV disposition parses and proves a string-contained at-sign safe");
	d = decide("SELECT 1 /* @x */");
	ok(d.disposition == UserVariableQueryDisposition::SAFE && d.parsersql_called &&
		d.legacy_udv_status_safe,
		"UDV disposition parses and proves a comment-contained at-sign safe");
	d = decide("SELECT @x");
	ok(d.disposition == UserVariableQueryDisposition::SAFE && d.parsersql_called &&
		d.legacy_udv_status_safe,
		"UDV disposition keeps a read-only occurrence multiplexable");
	d = decide("SET @x=1", true, true, true);
	ok(d.disposition == UserVariableQueryDisposition::SUPPORTED_SET &&
		!d.parsersql_called && d.legacy_udv_status_safe,
		"UDV disposition leaves a supported SET to the staging path");
	d = decide("SELECT @x:=1");
	ok(d.disposition == UserVariableQueryDisposition::UNSAFE_FALLBACK &&
		d.parsersql_called && !d.legacy_udv_status_safe,
		"UDV disposition binds assignment expressions");
	d = decide("SELECT id INTO @x FROM test.uv_source");
	ok(d.disposition == UserVariableQueryDisposition::UNSAFE_FALLBACK,
		"UDV disposition binds SELECT INTO user variables");
	d = decide("SELECT COALESCE(@x,1)");
	ok(d.disposition == UserVariableQueryDisposition::UNSAFE_FALLBACK,
		"UDV disposition binds function AST shapes containing user variables");
	d = decide("CALL p(@x)");
	ok(d.disposition == UserVariableQueryDisposition::UNSAFE_FALLBACK,
		"UDV disposition binds CALL AST shapes containing user variables");
	d = decide("SELECT @x; SELECT 1");
	ok(d.disposition == UserVariableQueryDisposition::UNSAFE_FALLBACK,
		"UDV disposition binds partial or multi-statement input");
	d = decide("SET @x=1", true, false, false);
	ok(d.disposition == UserVariableQueryDisposition::LEGACY &&
		!d.parsersql_called && !d.legacy_udv_status_safe,
		"UDV disposition keeps prepared SETs on the unsafe legacy path");
	d = decide("SELECT @x", false);
	ok(d.disposition == UserVariableQueryDisposition::LEGACY &&
		!d.parsersql_called && !d.legacy_udv_status_safe,
		"UDV disposition preserves current behavior before tracking is active");
}

static void test_user_variable_runtime_drain_policy() {
	ok(mysql_user_variable_accepts_new_assignments_policy(1, 3, 0, true, false),
		"runtime UDV policy accepts new assignments while mode and ParserSQL are active");
	ok(!mysql_user_variable_accepts_new_assignments_policy(0, 3, 0, true, false),
		"runtime UDV policy stops new assignments when mode is disabled");
	ok(!mysql_user_variable_accepts_new_assignments_policy(1, 2, 0, true, false),
		"runtime UDV policy stops new assignments when ParserSQL prerequisite is disabled");
	ok(!mysql_user_variable_accepts_new_assignments_policy(1, 3, 0, true, true),
		"runtime UDV policy stops map updates after authoritative-backend binding");
	ok(mysql_user_variable_must_classify_and_sync_policy(0, 3, 0, true, false, true),
		"runtime mode disable after first commit preserves classification and synchronization");
	ok(mysql_user_variable_must_classify_and_sync_policy(1, 2, 0, true, false, true),
		"runtime ParserSQL prerequisite disable after first commit preserves drain behavior");
	ok(mysql_user_variable_must_classify_and_sync_policy(1, 3, 0, true, true, true),
		"tracking latch preserves synchronization after authoritative-backend binding");
	ok(!mysql_user_variable_must_classify_and_sync_policy(0, 2, 0, true, false, false),
		"unlatched disabled tracking preserves legacy behavior");
	ok(mysql_user_variable_unsafe_query_locks_hostgroup(-1, false),
		"unsafe UDV fallback locks a previously-unbound session without a query-rule override");
	ok(!mysql_user_variable_unsafe_query_locks_hostgroup(0, false),
		"unsafe UDV fallback preserves query-rule multiplex=0 semantics");
	ok(!mysql_user_variable_unsafe_query_locks_hostgroup(1, false),
		"unsafe UDV fallback preserves query-rule multiplex=1 semantics");
}

static void test_user_variable_digest_independent_runtime_policy() {
	auto d = mysql_user_variable_raw_query_disposition(
		"SELECT @x", str_view_len("SELECT @x"), true, true, false, false);
	ok(d.disposition == UserVariableQueryDisposition::SAFE && d.parsersql_called,
		"raw UDV reads are classified when digest text is unavailable");
	d = mysql_user_variable_raw_query_disposition(
		"SELECT @x:=1", str_view_len("SELECT @x:=1"), true, true, false, false);
	ok(d.disposition == UserVariableQueryDisposition::UNSAFE_FALLBACK &&
		d.parsersql_called,
		"raw unsafe UDV use falls back when digest text is unavailable");
	d = mysql_user_variable_raw_query_disposition(
		"SET @x=1", str_view_len("SET @x=1"), true, true, true, false);
	ok(d.disposition == UserVariableQueryDisposition::SUPPORTED_SET &&
		!d.parsersql_called,
		"raw supported SET retains the Task 8 path without digest text");

	for (int multiplex : {-1, 0, 1}) {
		ok(mysql_user_variable_backend_result_requires_binding(
			true, true, false, multiplex),
			"successful unsafe fallback binds independently of qpo multiplex=%d",
			multiplex);
		ok(mysql_user_variable_backend_result_requires_binding(
			true, false, true, multiplex),
			"successful replay-context change binds independently of qpo multiplex=%d",
			multiplex);
	}
	ok(!mysql_user_variable_backend_result_requires_binding(
		true, false, false, -1),
		"successful query without unsafe/context intent does not bind");
	ok(!mysql_user_variable_backend_result_requires_binding(
		false, true, true, 1),
		"backend error clears unsafe/context intent without binding");

	ok(!parsersql_is_set_statement_candidate_mysql(
		"SELECT @x; SELECT 1", str_view_len("SELECT @x; SELECT 1")),
		"partial non-SET UDV input does not enter SET fallback accounting");
	ok(parsersql_is_set_statement_candidate_mysql(
		"SET @x=", str_view_len("SET @x=")),
		"partial SET UDV input retains SET fallback accounting and logging");
	ok(parsersql_is_set_statement_candidate_mysql(
		"SET @x=1", str_view_len("SET @x=1")),
		"full-input SET is a ParserSQL SET candidate");
	ok(mysql_user_variable_fallback_uses_qpo_epilogue(true, false),
		"forwarded unsafe fallback uses the normal qpo epilogue");
	ok(mysql_user_variable_fallback_uses_qpo_epilogue(false, true),
		"forwarded replay-context change uses the normal qpo epilogue");
}

static void test_user_variable_replay_context() {
	const char* context_queries[] = {
		"SET sql_mode='NO_BACKSLASH_ESCAPES'",
		"SET `SQL_MODE`='TRADITIONAL'",
		"SET SESSION sql_mode='TRADITIONAL'",
		"SET LOCAL character_set_client=utf8mb4",
		"SET @@SESSION.sql_mode='TRADITIONAL'",
		"SET @@local.character_set_client=utf8mb4",
		"SET @@character_set_connection=utf8mb4",
		"SET character_set_client=utf8mb4",
		"SET character_set_connection=utf8mb4",
		"SET SESSION `collation_connection`=utf8mb4_bin",
		"SET NAMES utf8mb4 COLLATE utf8mb4_bin",
		"SET CHARACTER SET utf8mb4",
	};
	for (const char* query : context_queries) {
		ok(parsersql_set_changes_user_variable_replay_context_mysql(
			query, str_view_len(query)),
			"strict AST detects replay-context SET: %s", query);
	}
	const char* non_context_queries[] = {
		"SET wait_timeout=10",
		"SET sql_mode='x'; SELECT 1",
		"SET sql_mode=",
		"SELECT 'SET NAMES utf8mb4'",
		"SET GLOBAL sql_mode='TRADITIONAL'",
		"SET PERSIST character_set_client=utf8mb4",
		"SET PERSIST_ONLY character_set_connection=utf8mb4",
		"SET @@GLOBAL.collation_connection=utf8mb4_bin",
	};
	for (const char* query : non_context_queries) {
		ok(!parsersql_set_changes_user_variable_replay_context_mysql(
			query, str_view_len(query)),
			"strict AST rejects non/full-input replay-context lookalike: %s", query);
	}

	const char* context_names[] = {
		"sql_mode", "character_set_client", "character_set_connection",
		"collation_connection"
	};
	for (const char* name : context_names) {
		ok(mysql_user_variable_is_replay_context_name(name, str_view_len(name)),
			"session tracking recognizes replay-context variable: %s", name);
	}
	ok(!mysql_user_variable_is_replay_context_name(
		"character_set_results", str_view_len("character_set_results")),
		"session tracking does not bind for unrelated character_set_results");
	ok(!mysql_user_variable_is_replay_context_name(
		"user_variable", str_view_len("user_variable")),
		"session tracking does not infer hidden UDV writes");
	ok(mysql_user_variable_is_replay_context_name(
		"SQL_MODE", str_view_len("SQL_MODE")),
		"session tracking matches canonical context keys case-insensitively");
}

int main() {
	plan(199);
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

	test_user_variable_browser_metadata();
	test_user_variable_supported_literals();
	test_user_variable_identity_and_order();
	test_user_variable_backslashes();
	test_user_variable_non_user_statuses();
	test_user_variable_rejections();
	test_user_variable_hash_contract();
	test_user_variable_usage();
	test_user_variable_tracking_policy();
	test_user_variable_staging_preflight();
	test_user_variable_routing_disposition();
	test_user_variable_post_ok_atomic_commit();
	test_user_variable_query_disposition();
	test_user_variable_runtime_drain_policy();
	test_user_variable_digest_independent_runtime_policy();
	test_user_variable_replay_context();

	test_cleanup_minimal();
	return exit_status();
}
