/**
 * @file parsersql_first_comment_unit-t.cpp
 * @brief ParserSQL digests extract the same first comment as the legacy tokenizer.
 *
 * Regression test for #6419: with query_processor_parser=1, queries that
 * ParserSQL parsed into a complete AST lost their first comment, so query
 * annotations such as hostgroup=N, query_timeout=N or min_gtid=... were
 * silently ignored. Every case compares the ParserSQL adapter against the
 * legacy tokenizer used with query_processor_parser=0.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "query_processor.h"
#include "Query_Processor_ParserSQL.h"
#include "c_tokenizer.h"

#include <cstring>
#include <string>

using DigestInit = void (*)(SQP_par_t*, const char*, int);
using LegacyDigest = char* (*)(const char*, int, char**, char*, const options*);

struct Dialect {
	const char* name;
	DigestInit parser_init;
	LegacyDigest legacy_digest;
	bool pgsql;
};

static void release_digest(SQP_par_t& qp) {
	if (qp.digest_text != qp.buf) free(qp.digest_text); // NOSONAR: adapter C allocation
	free(qp.first_comment); // NOSONAR: tokenizer comment ownership
	free(qp.query_prefix); // NOSONAR: query_parser_free ownership
	qp = SQP_par_t {};
}

/** First comment as computed by the legacy (query_processor_parser=0) path. */
static std::string legacy_first_comment(const Dialect& d, const std::string& sql, bool& found) {
	options opts {};
	if (d.pgsql) {
		opts.lowercase = pgsql_thread___query_digests_lowercase;
		opts.replace_null = pgsql_thread___query_digests_replace_null;
		opts.replace_number = pgsql_thread___query_digests_no_digits;
		opts.keep_comment = pgsql_thread___query_digests_keep_comment;
		opts.grouping_limit = pgsql_thread___query_digests_grouping_limit;
		opts.groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit;
		opts.max_query_length = pgsql_thread___query_digests_max_query_length;
	} else {
		opts.lowercase = mysql_thread___query_digests_lowercase;
		opts.replace_null = mysql_thread___query_digests_replace_null;
		opts.replace_number = mysql_thread___query_digests_no_digits;
		opts.keep_comment = mysql_thread___query_digests_keep_comment;
		opts.grouping_limit = mysql_thread___query_digests_grouping_limit;
		opts.groups_grouping_limit = mysql_thread___query_digests_groups_grouping_limit;
		opts.max_query_length = mysql_thread___query_digests_max_query_length;
	}
	char* comment = nullptr;
	char* digest = d.legacy_digest(sql.data(), sql.size(), &comment, nullptr, &opts);
	free(digest); // NOSONAR: tokenizer C allocation
	found = comment != nullptr;
	std::string result = comment ? comment : "";
	free(comment); // NOSONAR: tokenizer comment ownership
	return result;
}

/** ParserSQL first comment must equal the legacy one, including NULL vs non-NULL. */
static void check_matches_legacy(const Dialect& d, const std::string& sql, const char* annotation) {
	bool legacy_found = false;
	const std::string legacy = legacy_first_comment(d, sql, legacy_found);
	SQP_par_t qp {};
	d.parser_init(&qp, sql.data(), sql.size());
	const bool parser_found = qp.first_comment != nullptr;
	const std::string parser = parser_found ? qp.first_comment : "";
	std::string shown = sql;
	for (char& c : shown) if (c == '\n') c = ' ';
	ok(parser_found == legacy_found && parser == legacy,
		"%s first comment matches legacy for [%.80s] (parser: %s'%.60s', legacy: %s'%.60s')",
		d.name, shown.c_str(), parser_found ? "" : "NULL ", parser.c_str(),
		legacy_found ? "" : "NULL ", legacy.c_str());
	if (annotation) {
		ok(parser_found && parser.find(annotation) != std::string::npos,
			"%s first comment carries annotation '%s' for [%.80s]", d.name, annotation, shown.c_str());
	}
	ok(qp.digest_text != nullptr, "%s still produces a digest for [%.80s]", d.name, shown.c_str());
	release_digest(qp);
}

static void test_common(const Dialect& d) {
	// Fully parsed statements: these took the full-AST path and lost the comment (#6419).
	check_matches_legacy(d, "/* hostgroup=20 */ SELECT * FROM t WHERE id=1", "hostgroup=20");
	check_matches_legacy(d, "/*hostgroup=20*/SELECT 1", "hostgroup=20");
	check_matches_legacy(d, "/* query_timeout=100 */ SELECT 1", "query_timeout=100");
	check_matches_legacy(d, "/* hostgroup=20;max_lag_ms=100 */ INSERT INTO t VALUES (1)", "max_lag_ms=100");
	check_matches_legacy(d, "/* hostgroup=20 */ UPDATE t SET a=1 WHERE id=2", "hostgroup=20");
	check_matches_legacy(d, "/* hostgroup=20 */ DELETE FROM t WHERE id=2", "hostgroup=20");
	check_matches_legacy(d, "SELECT * FROM t WHERE id=1 /* hostgroup=20 */", "hostgroup=20");
	check_matches_legacy(d, "/* first=1 */ SELECT /* second=2 */ 1", "first=1");
	check_matches_legacy(d, "SELECT /*+ hint */ a FROM t", nullptr);
	// No block comment: the legacy tokenizer reports none, and neither must ParserSQL.
	check_matches_legacy(d, "SELECT 1", nullptr);
	check_matches_legacy(d, "SELECT a/2 FROM t WHERE b=3", nullptr);
	check_matches_legacy(d, "SELECT a FROM t /", nullptr);
	check_matches_legacy(d, "SELECT 'x /* not a comment */' FROM t", nullptr);
	check_matches_legacy(d, "-- hostgroup=20\nSELECT 1", nullptr);
	// Comment longer than the first-comment buffer is truncated identically.
	check_matches_legacy(d, "/* hostgroup=20 " + std::string(FIRST_COMMENT_MAX_LENGTH + 64, 'x') + " */ SELECT 1",
		"hostgroup=20");
	// Query longer than the inline digest buffer: the discarded token digest uses heap scratch.
	check_matches_legacy(d, "/* hostgroup=20 */ SELECT " + std::string(QUERY_DIGEST_BUF * 2, 'c') + " FROM t",
		"hostgroup=20");

	// The comment must not change the ParserSQL digest text or hash.
	SQP_par_t plain {};
	SQP_par_t annotated {};
	const char* plain_sql = "SELECT * FROM t WHERE id=1";
	const char* annotated_sql = "/* hostgroup=20 */ SELECT * FROM t WHERE id=1";
	d.parser_init(&plain, plain_sql, std::strlen(plain_sql));
	d.parser_init(&annotated, annotated_sql, std::strlen(annotated_sql));
	ok(plain.digest_text && annotated.digest_text && std::strcmp(plain.digest_text, annotated.digest_text) == 0,
		"%s annotation does not change the digest text (plain: %s, annotated: %s)", d.name,
		plain.digest_text ? plain.digest_text : "NULL", annotated.digest_text ? annotated.digest_text : "NULL");
	ok(plain.digest == annotated.digest && plain.digest != 0,
		"%s annotation does not change the digest hash", d.name);
	ok(plain.first_comment == nullptr, "%s query without a comment has a NULL first comment", d.name);
	release_digest(plain);
	release_digest(annotated);
}

static void test_mysql(const Dialect& d) {
	check_matches_legacy(d, "/* min_gtid=3E11FA47-71CA-11E1-9E33-C80AA9429562:23 */ SELECT a FROM t",
		"min_gtid=3E11FA47-71CA-11E1-9E33-C80AA9429562:23");
	// Statement outside the ParserSQL grammar still uses the tokenizer fallback.
	check_matches_legacy(d, "/* hostgroup=20 */ SHOW TABLES", "hostgroup=20");
	check_matches_legacy(d, "/*! hostgroup=20 */ SELECT 1", nullptr);
}

static void test_pgsql(const Dialect& d) {
	check_matches_legacy(d, "/* outer /* nested */ hostgroup=20 */ SELECT 1", nullptr);
	// PgSQL_Query_Info passes a length including the wire terminator.
	const char* sql = "/* hostgroup=20 */ SELECT * FROM t WHERE id=1";
	SQP_par_t qp {};
	d.parser_init(&qp, sql, std::strlen(sql) + 1);
	ok(qp.first_comment && std::strstr(qp.first_comment, "hostgroup=20"),
		"%s first comment survives the wire terminator (got: %s)", d.name,
		qp.first_comment ? qp.first_comment : "NULL");
	release_digest(qp);
}

int main() {
	plan(2 * 45 + 8 + 3);
	test_init_minimal();
	mysql_thread___query_digests_max_query_length = pgsql_thread___query_digests_max_query_length = 65000;
	mysql_thread___query_digests_max_digest_length = pgsql_thread___query_digests_max_digest_length = 2048;
	mysql_thread___query_digests_grouping_limit = pgsql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit = 1;
	const Dialect mysql {"MySQL", parsersql_digest_init_mysql, mysql_query_digest_and_first_comment, false};
	const Dialect pgsql {"PostgreSQL", parsersql_digest_init_pgsql, pgsql_query_digest_and_first_comment, true};
	test_common(mysql);
	test_common(pgsql);
	test_mysql(mysql);
	test_pgsql(pgsql);
	test_cleanup_minimal();
	return exit_status();
}
