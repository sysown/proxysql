/**
 * @file pgsql_parser_command_type_unit-t.cpp
 * @brief PgSQL command classification with pgsql-query_processor_parser=1 (#6422).
 *
 * ParserSQL reports StmtType::SELECT for "SELECT pg_cancel_backend(N)",
 * "SELECT pg_terminate_backend(N)" and data-modifying CTEs. The session only
 * intercepts the two backend functions when they are classified as
 * PGSQL_QUERY_CANCEL_BACKEND / PGSQL_QUERY_TERMINATE_BACKEND; otherwise the
 * ProxySQL session id that pg_backend_pid() returned is sent to a real
 * PostgreSQL server. A CTE classified as SELECT passes the read-only gates.
 *
 * The queries go through PgSQL_Query_Processor::query_parser_init(), so the
 * digest and the cached ParserSQL statement type are the ones a session sees.
 * Every case is also run with the parser off, and both modes must agree.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Query_Processor.h"
#include "sql_parser/common.h"

#include <cstring>
#include <string>

extern PgSQL_Query_Processor* GloPgQPro;

struct ClassifyCase {
	const char* sql;
	enum PGSQL_QUERY_command expected;
};

static const char* cmd_name(enum PGSQL_QUERY_command c) {
	switch (c) {
	case PGSQL_QUERY_SELECT: return "SELECT";
	case PGSQL_QUERY_INSERT: return "INSERT";
	case PGSQL_QUERY_CANCEL_BACKEND: return "CANCEL_BACKEND";
	case PGSQL_QUERY_TERMINATE_BACKEND: return "TERMINATE_BACKEND";
	case PGSQL_QUERY_UNKNOWN: return "UNKNOWN";
	default: return "other";
	}
}

/**
 * @brief Runs one statement through query_parser_init() + query_parser_command_type().
 *
 * @param stmt_type Receives the ParserSQL statement type cached in the digest parse (-1 if none).
 * @param prefix_freed Receives whether query_parser_command_type() released query_prefix.
 */
static enum PGSQL_QUERY_command classify(const char* sql, int* stmt_type = nullptr,
	bool* prefix_freed = nullptr) {
	SQP_par_t qp {};
	GloPgQPro->query_parser_init(&qp, sql, std::strlen(sql), 0);
	if (stmt_type) *stmt_type = qp.parsersql_stmt_type;
	const enum PGSQL_QUERY_command ret = PgSQL_Query_Processor::query_parser_command_type(&qp);
	if (prefix_freed) *prefix_freed = (qp.query_prefix == nullptr);
	GloPgQPro->query_parser_free(&qp);
	free(qp.query_prefix); // NOSONAR: only reached if the classifier failed to release it
	return ret;
}

static const ClassifyCase cases[] = {
	{"SELECT pg_cancel_backend(1234)", PGSQL_QUERY_CANCEL_BACKEND},
	{"SELECT pg_terminate_backend(1234)", PGSQL_QUERY_TERMINATE_BACKEND},
	{"SELECT pg_terminate_backend($1)", PGSQL_QUERY_TERMINATE_BACKEND},
	{"select PG_CANCEL_BACKEND(42)", PGSQL_QUERY_CANCEL_BACKEND},
	{"/* hint */ SELECT pg_cancel_backend(7)", PGSQL_QUERY_CANCEL_BACKEND},
	{"SELECT pg_terminate_backend(7);", PGSQL_QUERY_TERMINATE_BACKEND},
	{"WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", PGSQL_QUERY_UNKNOWN},
	{"WITH d AS (SELECT 1) SELECT pg_cancel_backend(1) FROM d", PGSQL_QUERY_UNKNOWN},
	// Guards: ordinary SELECTs are unchanged, including pg_backend_pid().
	{"SELECT 1", PGSQL_QUERY_SELECT},
	{"SELECT pg_backend_pid()", PGSQL_QUERY_SELECT},
	{"SELECT * FROM t WHERE a = 1", PGSQL_QUERY_SELECT},
	{"SELECT a, pg_cancel_backend(1) FROM t", PGSQL_QUERY_SELECT},
	{"INSERT INTO t VALUES (1)", PGSQL_QUERY_INSERT},
	// Only the complete function name is intercepted, in both modes.
	{"SELECT pg_cancel_backend_extra(1)", PGSQL_QUERY_SELECT},
	{"SELECT pg_terminate_backend2(1)", PGSQL_QUERY_SELECT},
	{"SELECT pg_cancel_backend (1)", PGSQL_QUERY_CANCEL_BACKEND},
	// A comment is whitespace to PostgreSQL, also between the name and '('.
	{"SELECT pg_cancel_backend/*x*/(123)", PGSQL_QUERY_CANCEL_BACKEND},
	{"SELECT pg_terminate_backend /* x */ -- y\n (123)", PGSQL_QUERY_TERMINATE_BACKEND},
};

// Parser mode only. The legacy classifier reads the first token of the text as is, so it
// reports UNKNOWN for a SELECT behind a kept comment, and it sees only the token after
// SELECT, so it cannot tell a column named like the function from a call to it.
static const ClassifyCase parser_only_cases[] = {
	{"SELECT pg_cancel_backend FROM t", PGSQL_QUERY_SELECT},
	{"SELECT pg_terminate_backend AS x FROM t", PGSQL_QUERY_SELECT},
};

// pgsql-query_digests_keep_comment=1: the digest starts with the comment.
static const ClassifyCase keep_comment_cases[] = {
	{"/* hint */ SELECT 1", PGSQL_QUERY_SELECT},
	{"/* hint */ SELECT * FROM t WHERE a = 1", PGSQL_QUERY_SELECT},
	{"/* hint */ SELECT pg_cancel_backend(7)", PGSQL_QUERY_CANCEL_BACKEND},
	{"/* a */ /* b */ SELECT pg_terminate_backend(7)", PGSQL_QUERY_TERMINATE_BACKEND},
	{"/* hint */ SELECT pg_cancel_backend_extra(7)", PGSQL_QUERY_SELECT},
	{"/* hint */ WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", PGSQL_QUERY_UNKNOWN},
	{"/* hint */ INSERT INTO t VALUES (1)", PGSQL_QUERY_INSERT},
	// The kept comment sits between the function name and '('.
	{"SELECT pg_cancel_backend/*x*/(123)", PGSQL_QUERY_CANCEL_BACKEND},
	{"SELECT pg_terminate_backend /* x */ (123)", PGSQL_QUERY_TERMINATE_BACKEND},
};

// With digests enabled the parser path classifies from the cached ParserSQL statement
// type and refines SELECT from the digest text.
static void test_parser_with_digests() {
	pgsql_thread___query_processor_parser = 1;
	pgsql_thread___query_digests = true;
	for (const auto& c : cases) {
		int stmt_type = -1;
		const enum PGSQL_QUERY_command got = classify(c.sql, &stmt_type);
		ok(got == c.expected, "parser=1 digests=1: '%s' -> %s (got %s, stmt_type %d)",
			c.sql, cmd_name(c.expected), cmd_name(got), stmt_type);
	}
	// The fix must be exercised through the ParserSQL AST path, not the fallback:
	// the adapter itself still reports SELECT for these statements.
	for (const char* sql : {"SELECT pg_cancel_backend(1234)", "SELECT pg_terminate_backend($1)",
		"WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"}) {
		int stmt_type = -1;
		classify(sql, &stmt_type);
		ok(stmt_type == static_cast<int>(sql_parser::StmtType::SELECT),
			"ParserSQL reports StmtType::SELECT for '%s' (got %d)", sql, stmt_type);
	}
}

static void test_parser_only_cases() {
	pgsql_thread___query_processor_parser = 1;
	pgsql_thread___query_digests = true;
	for (const auto& c : parser_only_cases) {
		const enum PGSQL_QUERY_command got = classify(c.sql);
		ok(got == c.expected, "parser=1 digests=1: '%s' -> %s (got %s)",
			c.sql, cmd_name(c.expected), cmd_name(got));
	}
	pgsql_thread___query_digests_keep_comment = true;
	for (const auto& c : keep_comment_cases) {
		const enum PGSQL_QUERY_command got = classify(c.sql);
		ok(got == c.expected, "parser=1 digests=1 keep_comment=1: '%s' -> %s (got %s)",
			c.sql, cmd_name(c.expected), cmd_name(got));
	}
	pgsql_thread___query_digests_keep_comment = false;
}

// With digests disabled the parser path classifies the 32-byte query prefix, and the
// classifier owns that prefix in both modes.
static void test_parser_without_digests() {
	pgsql_thread___query_processor_parser = 1;
	pgsql_thread___query_digests = false;
	pgsql_thread___commands_stats = true;
	static const ClassifyCase prefix_cases[] = {
		{"SELECT pg_cancel_backend(1234)", PGSQL_QUERY_CANCEL_BACKEND},
		{"SELECT pg_terminate_backend(12)", PGSQL_QUERY_TERMINATE_BACKEND},
		// Longer than the 32-byte prefix: ParserSQL sees "SELECT pg_terminate_backend(1234".
		{"SELECT pg_terminate_backend(123456)", PGSQL_QUERY_TERMINATE_BACKEND},
		{"WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", PGSQL_QUERY_UNKNOWN},
		{"SELECT 1", PGSQL_QUERY_SELECT},
		{"INSERT INTO t VALUES (1)", PGSQL_QUERY_INSERT},
		// The raw prefix keeps the client's whitespace and comments.
		{"SELECT\n1", PGSQL_QUERY_SELECT},
		{"SELECT\t*\nFROM t", PGSQL_QUERY_SELECT},
		{"SELECT\n\tpg_cancel_backend(1)", PGSQL_QUERY_CANCEL_BACKEND},
		// The prefix stops right after the function name: "/* c */ SELECT pg_cancel_backend".
		{"/* c */ SELECT pg_cancel_backend(1)", PGSQL_QUERY_CANCEL_BACKEND},
		{"-- c\nSELECT 1", PGSQL_QUERY_SELECT},
		{"SELECT pg_cancel_backend_x(1)", PGSQL_QUERY_SELECT},
		// The raw prefix keeps a comment between the function name and '('.
		{"SELECT pg_cancel_backend/**/(1)", PGSQL_QUERY_CANCEL_BACKEND},
		{"SELECT pg_terminate_backend/*x*/(1)", PGSQL_QUERY_TERMINATE_BACKEND},
	};
	for (const auto& c : prefix_cases) {
		bool prefix_freed = false;
		const enum PGSQL_QUERY_command got = classify(c.sql, nullptr, &prefix_freed);
		ok(got == c.expected, "parser=1 digests=0: '%s' -> %s (got %s)",
			c.sql, cmd_name(c.expected), cmd_name(got));
		ok(prefix_freed, "parser=1 digests=0: query_prefix released for '%s'", c.sql);
	}
	pgsql_thread___query_digests = true;
}

// The legacy classifier is the reference: both modes must agree on every case.
static void test_legacy_parity() {
	pgsql_thread___query_processor_parser = 0;
	pgsql_thread___query_digests = true;
	for (const auto& c : cases) {
		const enum PGSQL_QUERY_command got = classify(c.sql);
		ok(got == c.expected, "parser=0 digests=1: '%s' -> %s (got %s)",
			c.sql, cmd_name(c.expected), cmd_name(got));
	}
}

int main() {
	const size_t n_cases = sizeof(cases) / sizeof(cases[0]);
	const size_t n_parser_only = sizeof(parser_only_cases) / sizeof(parser_only_cases[0]) +
		sizeof(keep_comment_cases) / sizeof(keep_comment_cases[0]);
	plan(1 + n_cases + 3 + n_parser_only + 14 * 2 + n_cases);
	ok(test_init_minimal() == 0 && test_init_query_processor() == 0, "test init succeeds");
	// Worker defaults; the legacy digest yields an empty text with a zero length limit.
	pgsql_thread___query_digests_max_query_length = 65000;
	pgsql_thread___query_digests_max_digest_length = 2048;
	pgsql_thread___query_digests_grouping_limit = 3;
	pgsql_thread___query_digests_groups_grouping_limit = 10;

	test_parser_with_digests();
	test_parser_only_cases();
	test_parser_without_digests();
	test_legacy_parity();

	pgsql_thread___query_processor_parser = 0;
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
