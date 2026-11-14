/**
 * @file rule_matching_missing_digest_unit-t.cpp
 * @brief How rule_matches_query() treats the 'digest' and 'match_digest'
 *        criteria when the query has no digest, an empty digest, or a digest.
 *
 * The query digest is the input of two rule criteria: 'digest' (the hash) and
 * 'match_digest' (a regex on the digest text). The query has no digest when
 * *-query_digests=0: the hash is 0 and the text is NULL. In that case both
 * criteria are not applicable and the rule's other criteria decide, as in
 * v3.0.11. A query without SQL tokens (empty, whitespace or comments only) has
 * a real digest, the empty text "" and its hash, and match_digest is evaluated
 * on it, negate_match_pattern included.
 *
 * The parser-mode cases check what the rule matcher relies on to keep this safe
 * with *-query_processor_parser=1: a statement ParserSQL cannot parse still gets
 * its token digest, so a SELECT-only digest rule cannot match an unsupported
 * ALTER, and a negated one does.
 *
 * Every regex case runs on engine 1 (PCRE) and engine 2 (RE2).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "query_processor.h"
#include "Query_Processor_ParserSQL.h"

#include <cstring>

using DigestInit = void (*)(SQP_par_t*, const char*, int);

static QP_rule_t make_rule() {
	QP_rule_t rule {};
	rule.flagIN = 0;
	rule.proxy_port = -1;
	qp_addr_predicate_init(&rule.client_addr_pred, NULL, QP_ADDR_FIELD_CLIENT);
	qp_addr_predicate_init(&rule.proxy_addr_pred, NULL, QP_ADDR_FIELD_PROXY);
	return rule;
}

static bool matches(const QP_rule_t& rule, uint64_t digest, const char* digest_text,
	const char* query, int engine) {
	return rule_matches_query(&rule, 0, "user", "db", "127.0.0.1", nullptr,
		"127.0.0.1", nullptr, 6033, digest, digest_text, query, nullptr, engine);
}

static void release_digest(SQP_par_t& qp) {
	if (qp.digest_text != qp.buf) free(qp.digest_text); // NOSONAR: tokenizer C allocation
	free(qp.first_comment); // NOSONAR: tokenizer comment ownership
	free(qp.query_prefix); // NOSONAR: query_parser_free ownership
	qp.digest_text = nullptr;
	qp.first_comment = nullptr;
	qp.query_prefix = nullptr;
}

// *-query_digests=0: digest 0 and digest_text NULL. 6 assertions per engine.
static void test_no_digest(int engine) {
	const char* q = "SELECT 1";
	QP_rule_t r = make_rule();
	r.match_digest = const_cast<char*>("^SELECT");
	ok(matches(r, 0, nullptr, q, engine), "no digest: match_digest '^SELECT' is skipped (%d)", engine);
	r.match_digest = const_cast<char*>("^INSERT");
	ok(matches(r, 0, nullptr, q, engine), "no digest: match_digest '^INSERT' is skipped (%d)", engine);
	r.match_digest = const_cast<char*>("^SELECT");
	r.negate_match_pattern = true;
	ok(matches(r, 0, nullptr, q, engine),
		"no digest: negated match_digest catch-all still matches (%d)", engine);
	r = make_rule();
	r.digest = 123;
	ok(matches(r, 0, nullptr, q, engine), "no digest: the digest hash criterion is skipped (%d)", engine);
	// The other criteria still decide.
	r = make_rule();
	r.match_digest = const_cast<char*>("^SELECT");
	r.username = const_cast<char*>("other");
	ok(!matches(r, 0, nullptr, q, engine), "no digest: a username mismatch still rejects (%d)", engine);
	r = make_rule();
	r.match_digest = const_cast<char*>("^SELECT");
	r.match_pattern = const_cast<char*>("^INSERT");
	ok(!matches(r, 0, nullptr, q, engine), "no digest: match_pattern is still evaluated (%d)", engine);
}

// A query without SQL tokens: digest text "" and the hash of "". 4 per engine.
static void test_empty_digest(int engine) {
	const char* q = "/* ping */";
	const uint64_t h = SpookyHash::Hash64("", 0, 0);
	QP_rule_t r = make_rule();
	r.match_digest = const_cast<char*>("^SELECT");
	ok(!matches(r, h, "", q, engine), "empty digest: '^SELECT' does not match (%d)", engine);
	r.negate_match_pattern = true;
	ok(matches(r, h, "", q, engine), "empty digest: negated '^SELECT' matches (%d)", engine);
	r = make_rule();
	r.match_digest = const_cast<char*>("^$");
	ok(matches(r, h, "", q, engine), "empty digest: '^$' matches (%d)", engine);
	r = make_rule();
	r.digest = h;
	ok(matches(r, h, "", q, engine), "empty digest: the hash of \"\" matches (%d)", engine);
}

// A normal digest: unchanged behaviour. 6 per engine.
static void test_present_digest(int engine) {
	const char* q = "SELECT 1";
	const char* text = "SELECT ?";
	const uint64_t h = SpookyHash::Hash64(text, strlen(text), 0);
	QP_rule_t r = make_rule();
	r.match_digest = const_cast<char*>("^SELECT");
	ok(matches(r, h, text, q, engine), "digest: '^SELECT' matches (%d)", engine);
	r.match_digest = const_cast<char*>("^INSERT");
	ok(!matches(r, h, text, q, engine), "digest: '^INSERT' does not match (%d)", engine);
	r.negate_match_pattern = true;
	ok(matches(r, h, text, q, engine), "digest: negated '^INSERT' matches (%d)", engine);
	r.match_digest = const_cast<char*>("^SELECT");
	ok(!matches(r, h, text, q, engine), "digest: negated '^SELECT' does not match (%d)", engine);
	r = make_rule();
	r.digest = h;
	ok(matches(r, h, text, q, engine), "digest: equal hash matches (%d)", engine);
	r.digest = h + 1;
	ok(!matches(r, h, text, q, engine), "digest: different hash rejects (%d)", engine);
}

// Parser mode: the adapters always produce a digest, so the digest criteria
// are always evaluated. 2 + 5 per engine = 12 per dialect.
static void test_parser_mode(const char* dialect, DigestInit init, const char* unsupported) {
	SQP_par_t alter {};
	init(&alter, unsupported, strlen(unsupported));
	ok(alter.digest_text && *alter.digest_text && alter.digest != 0,
		"%s parser mode: a statement ParserSQL cannot parse has a digest (%s)", dialect,
		alter.digest_text ? alter.digest_text : "NULL");
	SQP_par_t ping {};
	const char* comment_only = "/* ping */";
	init(&ping, comment_only, strlen(comment_only));
	ok(ping.digest_text && *ping.digest_text == '\0' && ping.digest == SpookyHash::Hash64("", 0, 0),
		"%s parser mode: a comment-only query has the empty digest", dialect);

	for (int engine : {1, 2}) {
		QP_rule_t r = make_rule();
		r.match_digest = const_cast<char*>("^SELECT");
		ok(!matches(r, alter.digest, alter.digest_text, unsupported, engine),
			"%s parser mode: unsupported ALTER does not match '^SELECT' (%d)", dialect, engine);
		r.negate_match_pattern = true;
		ok(matches(r, alter.digest, alter.digest_text, unsupported, engine),
			"%s parser mode: unsupported ALTER matches negated '^SELECT' (%d)", dialect, engine);
		ok(matches(r, ping.digest, ping.digest_text, comment_only, engine),
			"%s parser mode: comment-only query matches negated '^SELECT' (%d)", dialect, engine);
		r.negate_match_pattern = false;
		ok(!matches(r, ping.digest, ping.digest_text, comment_only, engine),
			"%s parser mode: comment-only query does not match '^SELECT' (%d)", dialect, engine);
		r = make_rule();
		r.digest = SpookyHash::Hash64("SELECT ?", 8, 0);
		ok(!matches(r, alter.digest, alter.digest_text, unsupported, engine),
			"%s parser mode: unsupported ALTER does not match a SELECT digest hash (%d)", dialect, engine);
	}
	release_digest(alter);
	release_digest(ping);
}

int main() {
	plan(2 * (6 + 4 + 6) + 2 * 12);
	test_init_minimal();
	mysql_thread___query_digests_max_query_length = pgsql_thread___query_digests_max_query_length = 65000;
	mysql_thread___query_digests_max_digest_length = pgsql_thread___query_digests_max_digest_length = 2048;
	mysql_thread___query_digests_grouping_limit = pgsql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit = 1;

	for (int engine : {1, 2}) {
		test_no_digest(engine);
		test_empty_digest(engine);
		test_present_digest(engine);
	}
	test_parser_mode("MySQL", parsersql_digest_init_mysql, "ALTER TABLE t DISCARD TABLESPACE");
	test_parser_mode("PostgreSQL", parsersql_digest_init_pgsql, "ALTER SYSTEM SET work_mem='64MB'");

	test_cleanup_minimal();
	return exit_status();
}
