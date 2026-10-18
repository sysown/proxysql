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
 * digest is the one a session sees.
 * Every case is also run with the parser off, and both modes must agree.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Query_Processor.h"
#include "Query_Processor_ParserSQL.h"
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
 * @param prefix_freed Receives whether query_parser_command_type() released query_prefix.
 */
static enum PGSQL_QUERY_command classify(const char* sql, bool* prefix_freed = nullptr) {
	SQP_par_t qp {};
	GloPgQPro->query_parser_init(&qp, sql, std::strlen(sql), 0);
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

// Parser mode answers for statements other than SELECT. Most of them come from the legacy
// classifier without asking ParserSQL; CREATE/ALTER/DROP/ROLLBACK and what the legacy classifier
// cannot name still go through ParserSQL. These pin the answers parser mode gave when every
// statement was parsed, so skipping the parse changes none of them.
static const ClassifyCase type_cases[] = {
	{"UPDATE t SET a = 1 WHERE b = 2", PGSQL_QUERY_UPDATE},
	{"DELETE FROM t WHERE a = 1", PGSQL_QUERY_DELETE},
	{"BEGIN", PGSQL_QUERY_BEGIN},
	{"START TRANSACTION", PGSQL_QUERY_BEGIN},
	{"COMMIT", PGSQL_QUERY_COMMIT},
	{"ABORT", PGSQL_QUERY_ROLLBACK},
	{"SAVEPOINT s1", PGSQL_QUERY_SAVEPOINT},
	{"SET search_path TO public", PGSQL_QUERY_SET},
	{"SHOW search_path", PGSQL_QUERY_SHOW},
	{"RESET search_path", PGSQL_QUERY_RESET},
	{"PREPARE p AS SELECT 1", PGSQL_QUERY_PREPARE},
	{"EXECUTE p", PGSQL_QUERY_EXECUTE},
	{"DEALLOCATE p", PGSQL_QUERY_DEALLOCATE},
	{"GRANT SELECT ON t TO u", PGSQL_QUERY_GRANT},
	{"TRUNCATE t", PGSQL_QUERY_TRUNCATE},
	{"LOCK TABLE t", PGSQL_QUERY_LOCK},
	{"EXPLAIN SELECT 1", PGSQL_QUERY_EXPLAIN},
	{"CALL p(1)", PGSQL_QUERY_CALL},
	{"COPY t FROM STDIN", PGSQL_QUERY_COPY},
	{"LISTEN ch", PGSQL_QUERY_LISTEN},
	{"NOTIFY ch", PGSQL_QUERY_NOTIFY},
	{"VACUUM t", PGSQL_QUERY_VACUUM},
	{"DISCARD ALL", PGSQL_QUERY_DISCARD},
	{"DECLARE c CURSOR FOR SELECT 1", PGSQL_QUERY_UNKNOWN},
	{"RELEASE SAVEPOINT s1", PGSQL_QUERY_RELEASE_SAVEPOINT},
	// These still go through ParserSQL, whose answer can differ from the legacy classifier's.
	{"CREATE TABLE t (a int)", PGSQL_QUERY_CREATE_TABLE},
	{"CREATE INDEX i ON t (a)", PGSQL_QUERY_CREATE_TABLE},
	{"DROP INDEX i", PGSQL_QUERY_DROP_TABLE},
	{"ALTER TABLE t ADD COLUMN b int", PGSQL_QUERY_ALTER_TABLE},
	{"ROLLBACK", PGSQL_QUERY_ROLLBACK},
	{"ROLLBACK TO SAVEPOINT s1", PGSQL_QUERY_ROLLBACK},
	// The legacy classifier cannot name these.
	{"END", PGSQL_QUERY_COMMIT},
	{"WITH x AS (SELECT a FROM s) INSERT INTO t SELECT * FROM x", PGSQL_QUERY_INSERT},
	// The digest turns 1 into '?', which ParserSQL cannot parse: it names nothing.
	{"WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x", PGSQL_QUERY_UNKNOWN},
	{"VALUES (1)", PGSQL_QUERY_UNKNOWN},
};

// The same with pgsql-query_digests_keep_comment=1, where the digest starts with the comment.
static const ClassifyCase type_keep_comment_cases[] = {
	{"/* c */ UPDATE t SET a = b", PGSQL_QUERY_UPDATE},
	// '?' again: ParserSQL fails, and the legacy classifier stops at the comment.
	{"/* c */ UPDATE t SET a = 1", PGSQL_QUERY_UNKNOWN},
	{"/* c */ BEGIN", PGSQL_QUERY_BEGIN},
	{"/* c */ COPY t FROM STDIN", PGSQL_QUERY_UNKNOWN},
	{"/* c */ CREATE INDEX i ON t (a)", PGSQL_QUERY_CREATE_TABLE},
};

// The same with digests off, on the 32-byte query prefix.
static const ClassifyCase type_prefix_cases[] = {
	{"UPDATE t SET a = 1 WHERE b = 2", PGSQL_QUERY_UPDATE},
	{"\nINSERT INTO t VALUES (1)", PGSQL_QUERY_INSERT},
	{"CREATE INDEX i ON t (a)", PGSQL_QUERY_CREATE_TABLE},
};

static void test_parser_statement_types() {
	pgsql_thread___query_processor_parser = 1;
	pgsql_thread___query_digests = true;
	for (const auto& c : type_cases) {
		const enum PGSQL_QUERY_command got = classify(c.sql);
		ok(got == c.expected, "parser=1 digests=1: '%s' -> %d (got %d)", c.sql, c.expected, got);
	}
	pgsql_thread___query_digests_keep_comment = true;
	for (const auto& c : type_keep_comment_cases) {
		const enum PGSQL_QUERY_command got = classify(c.sql);
		ok(got == c.expected, "parser=1 digests=1 keep_comment=1: '%s' -> %d (got %d)", c.sql, c.expected, got);
	}
	pgsql_thread___query_digests_keep_comment = false;
	pgsql_thread___query_digests = false;
	for (const auto& c : type_prefix_cases) {
		const enum PGSQL_QUERY_command got = classify(c.sql);
		ok(got == c.expected, "parser=1 digests=0: '%s' -> %d (got %d)", c.sql, c.expected, got);
	}
	pgsql_thread___query_digests = true;
}

// Parser mode skips ParserSQL for every statement the legacy classifier names, except
// CREATE/ALTER/DROP/ROLLBACK, because ParserSQL gives those the same answer or none (UNKNOWN).
// They never reach ParserSQL now, so nothing else would notice a ParserSQL change that breaks
// this. Each is parsed here directly; the expected value is ParserSQL's own answer.
static const ClassifyCase parsersql_skip_cases[] = {
	{"INSERT INTO t SELECT a FROM s", PGSQL_QUERY_INSERT},
	{"UPDATE t SET a = b", PGSQL_QUERY_UPDATE},
	{"DELETE FROM t WHERE a = b", PGSQL_QUERY_DELETE},
	{"BEGIN", PGSQL_QUERY_BEGIN},
	{"START TRANSACTION", PGSQL_QUERY_BEGIN},
	{"COMMIT", PGSQL_QUERY_COMMIT},
	{"COMMIT PREPARED 'x'", PGSQL_QUERY_COMMIT},
	{"ABORT", PGSQL_QUERY_ROLLBACK},
	{"SAVEPOINT s1", PGSQL_QUERY_SAVEPOINT},
	{"SET search_path TO public", PGSQL_QUERY_SET},
	{"SHOW search_path", PGSQL_QUERY_SHOW},
	{"RESET search_path", PGSQL_QUERY_RESET},
	{"PREPARE p AS SELECT a FROM t", PGSQL_QUERY_PREPARE},
	{"PREPARE TRANSACTION 'x'", PGSQL_QUERY_PREPARE},
	{"EXECUTE p", PGSQL_QUERY_EXECUTE},
	{"DEALLOCATE p", PGSQL_QUERY_DEALLOCATE},
	{"GRANT SELECT ON t TO u", PGSQL_QUERY_GRANT},
	{"REVOKE SELECT ON t FROM u", PGSQL_QUERY_REVOKE},
	{"TRUNCATE t", PGSQL_QUERY_TRUNCATE},
	{"LOCK TABLE t", PGSQL_QUERY_LOCK},
	{"EXPLAIN SELECT a FROM t", PGSQL_QUERY_EXPLAIN},
	{"CALL p()", PGSQL_QUERY_CALL},
	// ParserSQL knows these, but its type has no counter name: UNKNOWN.
	{"COPY t FROM STDIN", PGSQL_QUERY_UNKNOWN},
	{"LISTEN ch", PGSQL_QUERY_UNKNOWN},
	{"NOTIFY ch", PGSQL_QUERY_UNKNOWN},
	{"UNLISTEN *", PGSQL_QUERY_UNKNOWN},
	{"DISCARD ALL", PGSQL_QUERY_UNKNOWN},
	{"DECLARE c CURSOR FOR SELECT a FROM t", PGSQL_QUERY_UNKNOWN},
	{"FETCH c", PGSQL_QUERY_UNKNOWN},
	{"MOVE c", PGSQL_QUERY_UNKNOWN},
	{"CLOSE c", PGSQL_QUERY_UNKNOWN},
	{"MERGE INTO t USING s ON t.a = s.a WHEN MATCHED THEN DELETE", PGSQL_QUERY_UNKNOWN},
	{"VACUUM t", PGSQL_QUERY_UNKNOWN},
	{"ANALYZE t", PGSQL_QUERY_UNKNOWN},
	{"CLUSTER t", PGSQL_QUERY_UNKNOWN},
	{"REINDEX TABLE t", PGSQL_QUERY_UNKNOWN},
	{"REFRESH MATERIALIZED VIEW v", PGSQL_QUERY_UNKNOWN},
	{"CHECKPOINT", PGSQL_QUERY_UNKNOWN},
	{"COMMENT ON TABLE t IS 'x'", PGSQL_QUERY_UNKNOWN},
	{"IMPORT FOREIGN SCHEMA s FROM SERVER f INTO t", PGSQL_QUERY_UNKNOWN},
	{"RELEASE SAVEPOINT s1", PGSQL_QUERY_UNKNOWN},
};

// A changed ParserSQL answer fails the first check. The second fails only if the change makes
// skipping wrong: ParserSQL would now name the statement differently from the classifier.
static void test_parsersql_skip_guard() {
	pgsql_thread___query_processor_parser = 1;
	pgsql_thread___query_digests = true;
	for (const auto& c : parsersql_skip_cases) {
		const enum PGSQL_QUERY_command parsed = parsersql_command_type_pgsql(c.sql, std::strlen(c.sql));
		const enum PGSQL_QUERY_command got = classify(c.sql);
		ok(parsed == c.expected, "ParserSQL answers %d for '%s' (got %d)", c.expected, c.sql, parsed);
		ok(parsed == PGSQL_QUERY_UNKNOWN || parsed == got,
			"skipping ParserSQL is safe for '%s': ParserSQL %d, classifier %d", c.sql, parsed, got);
	}
}

// With digests enabled the parser path classifies the digest text with ParserSQL
// and refines SELECT from it.
static void test_parser_with_digests() {
	pgsql_thread___query_processor_parser = 1;
	pgsql_thread___query_digests = true;
	for (const auto& c : cases) {
		const enum PGSQL_QUERY_command got = classify(c.sql);
		ok(got == c.expected, "parser=1 digests=1: '%s' -> %s (got %s)",
			c.sql, cmd_name(c.expected), cmd_name(got));
	}
	// The classification is exercised through the digest text: the tokenizer turns
	// PostgreSQL arguments into '?' placeholders that ParserSQL cannot parse, so the
	// refinement must promote a plain SELECT rather than trust its UNKNOWN. The
	// adapter still reports SELECT for these statements on the raw query.
	for (const char* sql : {"SELECT pg_cancel_backend(1234)", "SELECT pg_terminate_backend($1)",
		"WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"}) {
		const enum PGSQL_QUERY_command direct = parsersql_command_type_pgsql(sql, std::strlen(sql));
		ok(direct == PGSQL_QUERY_SELECT,
			"ParserSQL reports SELECT for '%s' (got %s)", sql, cmd_name(direct));
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
		const enum PGSQL_QUERY_command got = classify(c.sql, &prefix_freed);
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
	const size_t n_types = sizeof(type_cases) / sizeof(type_cases[0]) +
		sizeof(type_keep_comment_cases) / sizeof(type_keep_comment_cases[0]) +
		sizeof(type_prefix_cases) / sizeof(type_prefix_cases[0]);
	const size_t n_skip = sizeof(parsersql_skip_cases) / sizeof(parsersql_skip_cases[0]);
	plan(1 + n_cases + 3 + n_parser_only + 14 * 2 + n_cases + n_types + 2 * n_skip);
	ok(test_init_minimal() == 0 && test_init_query_processor() == 0, "test init succeeds");
	// Worker defaults; the legacy digest yields an empty text with a zero length limit.
	pgsql_thread___query_digests_max_query_length = 65000;
	pgsql_thread___query_digests_max_digest_length = 2048;
	pgsql_thread___query_digests_grouping_limit = 3;
	pgsql_thread___query_digests_groups_grouping_limit = 10;

	test_parser_with_digests();
	test_parser_only_cases();
	test_parser_without_digests();
	test_parser_statement_types();
	test_parsersql_skip_guard();
	test_legacy_parity();

	pgsql_thread___query_processor_parser = 0;
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
