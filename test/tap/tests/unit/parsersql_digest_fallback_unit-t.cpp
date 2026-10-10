/**
 * @file parsersql_digest_fallback_unit-t.cpp
 * @brief Parser failures retain token digests and cannot bypass digest rules.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "query_processor.h"
#include "Query_Processor_ParserSQL.h"
#include "sql_parser/parse_result.h"

#include <cstring>
#include <string>

using DigestInit = void (*)(SQP_par_t*, const char*, int);

static void release_digest(SQP_par_t& qp) {
	// The emitter and tokenizer both use C allocation when not using the inline buffer.
	if (qp.digest_text != qp.buf) free(qp.digest_text); // NOSONAR: matches the adapter's C allocation
	free(qp.first_comment); // NOSONAR: tokenizer comment ownership
	free(qp.query_prefix); // NOSONAR: query_parser_free ownership
}

static bool matches(const QP_rule_t& rule, const SQP_par_t& qp, const char* sql, int engine) {
	return rule_matches_query(&rule, 0, "user", "db", "127.0.0.1", nullptr,
		"127.0.0.1", nullptr, 6033, qp.digest, qp.digest_text, sql, nullptr, engine);
}

static void test_routing(const char* dialect, DigestInit initialize, const char* sql,
	const char* expected) {
	SQP_par_t qp {};
	initialize(&qp, sql, std::strlen(sql));
	for (int engine : {1, 2}) {
		QP_rule_t rule {};
		rule.proxy_port = -1;
		rule.match_digest = const_cast<char*>("^SELECT");
		ok(!matches(rule, qp, sql, engine), "%s unsupported ALTER cannot match a SELECT digest regex (%d)", dialect, engine);
		rule.match_digest = const_cast<char*>("^ALTER");
		ok(matches(rule, qp, sql, engine), "%s unsupported ALTER matches its own digest regex (%d)", dialect, engine);
		rule.match_digest = nullptr;
		rule.digest = SpookyHash::Hash64("SELECT ?", 8, 0);
		ok(!matches(rule, qp, sql, engine), "%s unsupported ALTER cannot match a SELECT digest hash (%d)", dialect, engine);
		rule.digest = SpookyHash::Hash64(expected, std::strlen(expected), 0);
		ok(matches(rule, qp, sql, engine), "%s unsupported ALTER matches its own digest hash (%d)", dialect, engine);
	}
	release_digest(qp);
}

// Missing metadata must not turn a digest-constrained rule into a catch-all.
static void test_missing_digest_rules() {
	for (int engine : {1, 2}) {
		SQP_par_t qp {};
		QP_rule_t rule {};
		rule.proxy_port = -1;
		rule.digest = 123;
		ok(!matches(rule, qp, "/* no SQL */", engine), "Missing hash cannot satisfy a digest rule (%d)", engine);
		rule.digest = 0;
		rule.match_digest = const_cast<char*>("^SELECT");
		ok(!matches(rule, qp, "/* no SQL */", engine), "Missing text cannot satisfy a digest regex (%d)", engine);
		qp.digest_text = qp.buf;
		ok(!matches(rule, qp, "/* no SQL */", engine), "Empty text cannot satisfy a digest regex (%d)", engine);
		rule.negate_match_pattern = true;
		qp.digest_text = nullptr;
		ok(!matches(rule, qp, "/* no SQL */", engine), "Missing text cannot satisfy a negated digest regex (%d)", engine);
		qp.digest_text = qp.buf;
		ok(!matches(rule, qp, "/* no SQL */", engine), "Empty text cannot satisfy a negated digest regex (%d)", engine);
		rule.match_digest = nullptr;
		ok(matches(rule, qp, "/* no SQL */", engine), "Unconstrained rules still match without digest metadata (%d)", engine);
	}
}

struct DigestCase {
	const char* sql;
	const char* expected;
	sql_parser::StmtType type;
};

static void test_digests(const char* dialect, DigestInit initialize) {
	using sql_parser::StmtType;
	const DigestCase cases[] = {
		{"ALTER TABLE t DISCARD TABLESPACE", "ALTER TABLE t DISCARD TABLESPACE", StmtType::ALTER},
		{"ALTER TABLE t IMPORT TABLESPACE", "ALTER TABLE t IMPORT TABLESPACE", StmtType::ALTER},
		{"ALTER SYSTEM SET work_mem='64MB'", "ALTER SYSTEM SET work_mem=?", StmtType::ALTER},
		{"/* leading */ ALTER TABLE t DISCARD TABLESPACE; /* trailing */", "ALTER TABLE t DISCARD TABLESPACE", StmtType::ALTER},
		{"SET = 42", "SET = ?", StmtType::SET},
		{"SELECT (", "SELECT (", StmtType::SELECT},
		{"SELECT * FROM t WHERE a=1 unsupported suffix", "SELECT * FROM t WHERE a=? unsupported suffix", StmtType::SELECT},
		{"SELECT 1 IN (2,3) unsupported suffix", "SELECT ? IN (?,?) unsupported suffix", StmtType::SELECT},
		{"SELECT 42", "SELECT ?", StmtType::SELECT},
	};
	for (const auto& c : cases) {
		SQP_par_t qp {};
		initialize(&qp, c.sql, std::strlen(c.sql));
		ok(qp.digest_text && std::strcmp(qp.digest_text, c.expected) == 0,
			"%s normalizes complete input even without a complete AST: %s (got: %s)",
			dialect, c.sql, qp.digest_text ? qp.digest_text : "NULL");
		ok(qp.digest == SpookyHash::Hash64(c.expected, std::strlen(c.expected), 0),
			"%s hashes the expected token digest: %s", dialect, c.sql);
		ok(qp.parsersql_stmt_type == static_cast<int>(c.type),
			"%s preserves command classification: %s", dialect, c.sql);
		release_digest(qp);
	}

	const std::string long_sql = "ALTER TABLE " + std::string(QUERY_DIGEST_BUF + 32, 't') + " DISCARD TABLESPACE";
	SQP_par_t qp {};
	initialize(&qp, long_sql.data(), long_sql.size());
	ok(qp.digest_text && qp.digest_text != qp.buf && long_sql == qp.digest_text,
		"%s fallback preserves long digests in heap storage", dialect);
	release_digest(qp);
	initialize(&qp, "SELECT 42", 9);
	ok(qp.digest_text == qp.buf && std::strcmp(qp.digest_text, "SELECT ?") == 0,
		"%s successful parsing still works after fallback and arena reset", dialect);
	release_digest(qp);

	for (const char* empty : {"", " \t\n", "/* comment only */"}) {
		initialize(&qp, empty, std::strlen(empty));
		ok(!qp.digest_text && qp.digest == 0, "%s input without SQL tokens has no digest", dialect);
		release_digest(qp);
	}
}

static void test_pgsql_protocol_terminator() {
	for (const auto& c : {
		DigestCase{"SELECT 42", "SELECT ?", sql_parser::StmtType::SELECT},
		DigestCase{"ALTER SYSTEM SET work_mem='64MB'", "ALTER SYSTEM SET work_mem=?", sql_parser::StmtType::ALTER}
	}) {
		SQP_par_t qp {};
		// PgSQL_Query_Info passes a length including the wire terminator.
		parsersql_digest_init_pgsql(&qp, c.sql, std::strlen(c.sql) + 1);
		ok(qp.digest_text && std::strcmp(qp.digest_text, c.expected) == 0,
			"PostgreSQL wire terminator does not change normalized SQL: %s", c.sql);
		ok(qp.digest == SpookyHash::Hash64(c.expected, std::strlen(c.expected), 0),
			"PostgreSQL wire terminator does not change the digest hash: %s", c.sql);
		release_digest(qp);
	}
}

static void test_large_input(const char* dialect, DigestInit initialize) {
	std::string sql = "SELECT a";
	for (int i = 0; i < 200000; ++i) sql += ",a";
	SQP_par_t qp {};
	initialize(&qp, sql.data(), sql.size());
	ok(qp.digest_text && sql == qp.digest_text,
		"%s tokenizes large input after the AST exceeds its arena limit", dialect);
	ok(qp.digest == SpookyHash::Hash64(sql.data(), sql.size(), 0),
		"%s large fallback digest retains the complete token text", dialect);
	release_digest(qp);
}

static void test_fallback_options(const char* dialect, DigestInit initialize,
	int& query_limit, int& hash_limit, bool& lowercase) {
	const int saved_query_limit = query_limit;
	const int saved_hash_limit = hash_limit;
	query_limit = 64;
	hash_limit = 16;
	const std::string sql = "ALTER TABLE " + std::string(200, 't') + " DISCARD TABLESPACE";
	SQP_par_t qp {};
	initialize(&qp, sql.data(), sql.size());
	ok(qp.digest_text && std::strlen(qp.digest_text) == 64,
		"%s fallback honors the configured tokenizer length limit", dialect);
	ok(qp.digest_text && std::strncmp(qp.digest_text, sql.data(), 64) == 0,
		"%s limited fallback preserves the expected token prefix", dialect);
	ok(qp.digest == SpookyHash::Hash64(sql.data(), 16, 0),
		"%s fallback honors the configured digest hash length", dialect);
	release_digest(qp);
	query_limit = saved_query_limit;
	hash_limit = saved_hash_limit;

	const bool saved_lowercase = lowercase;
	lowercase = true;
	const std::string commented = "/* routehint */ ALTER TABLE t DISCARD TABLESPACE";
	initialize(&qp, commented.data(), commented.size());
	ok(qp.digest_text && std::strcmp(qp.digest_text, "alter table t discard tablespace") == 0,
		"%s fallback honors lowercase normalization", dialect);
	ok(qp.first_comment && std::strstr(qp.first_comment, "routehint"),
		"%s fallback preserves first-comment metadata", dialect);
	release_digest(qp);
	lowercase = saved_lowercase;
}

int main() {
	plan(110);
	test_init_minimal();
	mysql_thread___query_digests_max_query_length = pgsql_thread___query_digests_max_query_length = 1048576;
	mysql_thread___query_digests_max_digest_length = pgsql_thread___query_digests_max_digest_length = 1048576;
	mysql_thread___query_digests_grouping_limit = pgsql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit = 1;
	test_missing_digest_rules();
	test_pgsql_protocol_terminator();
	test_digests("MySQL", parsersql_digest_init_mysql);
	test_digests("PostgreSQL", parsersql_digest_init_pgsql);
	test_routing("MySQL", parsersql_digest_init_mysql,
		"ALTER TABLE t DISCARD TABLESPACE", "ALTER TABLE t DISCARD TABLESPACE");
	test_routing("PostgreSQL", parsersql_digest_init_pgsql,
		"ALTER SYSTEM SET work_mem='64MB'", "ALTER SYSTEM SET work_mem=?");
	test_large_input("MySQL", parsersql_digest_init_mysql);
	test_large_input("PostgreSQL", parsersql_digest_init_pgsql);
	test_fallback_options("MySQL", parsersql_digest_init_mysql,
		mysql_thread___query_digests_max_query_length, mysql_thread___query_digests_max_digest_length,
		mysql_thread___query_digests_lowercase);
	test_fallback_options("PostgreSQL", parsersql_digest_init_pgsql,
		pgsql_thread___query_digests_max_query_length, pgsql_thread___query_digests_max_digest_length,
		pgsql_thread___query_digests_lowercase);
	test_cleanup_minimal();
	return exit_status();
}
