/**
 * @file query_digest_parser_parity_unit-t.cpp
 * @brief *-query_processor_parser must not change a digest (#6454).
 *
 * The legacy tokenizer is the only digest source; ParserSQL only classifies the
 * command. Both values of *-query_processor_parser must therefore give the same
 * digest, digest text and first comment for every query. This test drives the
 * real entry point, Query_Processor::query_parser_init(), with the parser on and
 * off and compares the results, for MySQL and for PostgreSQL.
 *
 * It also checks two cases where the two paths used to differ:
 *   - PgSQL_Query_Info passes a query length that includes the protocol's NUL
 *     terminator. The legacy path digested the terminator as a character, so a
 *     trailing ';' or whitespace was not trimmed ('SELECT 1;' -> 'select ?;'),
 *     while the parser path stripped it ('select ?').
 *   - A query without SQL tokens (comments or whitespace only) got digest text ""
 *     in legacy mode, and no digest at all (NULL, 0) in parser mode, which also
 *     kept it out of the digest stats.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"

#include <cstring>
#include <string>
#include <vector>

extern MySQL_Query_Processor* GloMyQPro;
extern PgSQL_Query_Processor* GloPgQPro;

struct DigestResult {
	bool has_text = false;
	std::string text;
	uint64_t digest = 0;
	bool has_comment = false;
	std::string comment;
};

static bool operator==(const DigestResult& a, const DigestResult& b) {
	return a.has_text == b.has_text && a.text == b.text && a.digest == b.digest &&
		a.has_comment == b.has_comment && a.comment == b.comment;
}

static const char* show(const DigestResult& r) {
	return r.has_text ? r.text.c_str() : "(null)";
}

/**
 * @brief Digest 'query' (of 'length' bytes) through query_parser_init() of 'qpro'.
 */
template <typename QP>
static DigestResult digest_with(QP* qpro, const char* query, int length) {
	SQP_par_t qp;
	memset(&qp, 0, sizeof(qp));
	qpro->query_parser_init(&qp, query, length, 0);
	DigestResult r;
	r.has_text = qp.digest_text != nullptr;
	if (qp.digest_text) r.text = qp.digest_text;
	r.digest = qp.digest;
	r.has_comment = qp.first_comment != nullptr;
	if (qp.first_comment) r.comment = qp.first_comment;
	qpro->query_parser_free(&qp);
	return r;
}

/** @brief Digest as MySQL_Session does: the length is the query text alone. */
static DigestResult mysql_digest(const char* query, int parser) {
	mysql_thread___query_processor_parser = parser;
	return digest_with(GloMyQPro, query, (int)strlen(query));
}

/** @brief Digest as PgSQL_Session does: the length includes the NUL terminator. */
static DigestResult pgsql_digest(const char* query, int parser) {
	pgsql_thread___query_processor_parser = parser;
	return digest_with(GloPgQPro, query, (int)strlen(query) + 1);
}

/** @brief Digest a PgSQL query given without its NUL terminator. */
static DigestResult pgsql_digest_no_nul(const char* query, int parser) {
	pgsql_thread___query_processor_parser = parser;
	return digest_with(GloPgQPro, query, (int)strlen(query));
}

static void set_options(bool lowercase, bool keep_comment) {
	mysql_thread___query_digests_lowercase = pgsql_thread___query_digests_lowercase = lowercase;
	mysql_thread___query_digests_keep_comment = pgsql_thread___query_digests_keep_comment = keep_comment;
}

// Queries digested with every combination of lowercase and keep_comment.
static const std::vector<const char*> common_queries = {
	"SELECT 1",
	"SELECT 1;",
	"SELECT 1 ;  ",
	"SELECT 1 /* x */",
	"/*a*/ SELECT 1",
	"/*a*/SELECT 1;",
	"select A from T where B = 'x' and C = 10",
	"SELECT * FROM t WHERE id IN (1,2,3,4,5,6,7)",
	"SELECT * FROM t WHERE id IN (1, 2, 3) AND b IN ('a','b','c','d','e')",
	"SELECT 1; SELECT 2",
	"SELECT 1; SELECT 2;",
	"BEGIN; UPDATE t SET a = 1 WHERE id = 2; COMMIT;",
	"INSERT INTO t VALUES (1,'a'),(2,'b'),(3,'c'),(4,'d')",
	"SELECT a -- trailing line comment\n",
	"/* c */",
	"/* c */ ;",
	"-- only a line comment\n",
	"   ",
	"",
};

static const std::vector<const char*> mysql_queries = {
	"SELECT `a` FROM `t` WHERE x = 0x1F",
	"SELECT /*+ MAX_EXECUTION_TIME(10) */ a FROM t",
	"SELECT a FROM t # hash comment\n",
};

static const std::vector<const char*> pgsql_queries = {
	"SELECT $$x$$::text, 'a'::varchar(10)",
	"SELECT \"Col\" FROM \"T\" WHERE b = E'\\n' AND c = ARRAY[1,2,3]",
	"/* outer /* nested */ */ SELECT 1;",
};

static void test_parity(const char* dialect, DigestResult (*digest)(const char*, int),
	const std::vector<const char*>& queries) {
	for (bool lowercase : {false, true}) {
		for (bool keep_comment : {false, true}) {
			set_options(lowercase, keep_comment);
			for (const char* q : queries) {
				const DigestResult legacy = digest(q, 0);
				const DigestResult parser = digest(q, 1);
				ok(legacy == parser,
					"%s lowercase=%d keep_comment=%d: parser on/off give the same digest for '%s'"
					" (legacy '%s' 0x%016llX, parser '%s' 0x%016llX)",
					dialect, lowercase, keep_comment, q, show(legacy), (unsigned long long)legacy.digest,
					show(parser), (unsigned long long)parser.digest);
			}
		}
	}
}

/**
 * @brief The digest of a PgSQL query does not depend on its NUL terminator, so a
 *   trailing ';' and trailing whitespace are trimmed as for MySQL.
 */
static void test_pgsql_terminator(int parser) {
	set_options(true, false);
	const DigestResult plain = pgsql_digest("SELECT 1", parser);
	const DigestResult semi = pgsql_digest("SELECT 1;", parser);
	ok(plain.text == "select ?" && semi.text == "select ?" && plain.digest == semi.digest,
		"PgSQL parser=%d: 'SELECT 1' and 'SELECT 1;' share digest 'select ?' (got '%s' / '%s')",
		parser, show(plain), show(semi));
	const DigestResult cmnt = pgsql_digest("SELECT 1 /* x */", parser);
	ok(cmnt.text == "select ?",
		"PgSQL parser=%d: a trailing comment leaves no trailing space (got '%s')", parser, show(cmnt));
	for (const char* q : {"SELECT 1;", "SELECT 1 /* x */", "SELECT a FROM t WHERE b IN (1,2) ;  "}) {
		const DigestResult with_nul = pgsql_digest(q, parser);
		const DigestResult without_nul = pgsql_digest_no_nul(q, parser);
		ok(with_nul == without_nul,
			"PgSQL parser=%d: the NUL terminator does not change the digest of '%s' ('%s' vs '%s')",
			parser, q, show(with_nul), show(without_nul));
	}
	const DigestResult mysql_semi = mysql_digest("SELECT 1;", parser);
	ok(semi.text == mysql_semi.text && semi.digest == mysql_semi.digest,
		"PgSQL parser=%d: 'SELECT 1;' digests as in MySQL (got '%s', MySQL '%s')",
		parser, show(semi), show(mysql_semi));

	set_options(true, true);
	const DigestResult kept = pgsql_digest("/*a*/", parser);
	ok(kept.text == "/*a*/", "PgSQL parser=%d keep_comment: a lone kept comment has no trailing space (got '%s')",
		parser, show(kept));
	set_options(true, false);
}

/**
 * @brief A query without SQL tokens has the empty digest text and the hash of ""
 *   in both modes, so it is counted in the digest stats in both modes.
 */
static void test_no_sql_tokens(const char* dialect, DigestResult (*digest)(const char*, int)) {
	set_options(true, false);
	const uint64_t empty_hash = SpookyHash::Hash64("", 0, 0);
	for (int parser : {0, 1}) {
		for (const char* q : {"/* comment only */", " \t\n", ""}) {
			const DigestResult r = digest(q, parser);
			ok(r.has_text && r.text.empty() && r.digest == empty_hash,
				"%s parser=%d: '%s' has digest text \"\" and the hash of \"\" (got '%s' 0x%016llX)",
				dialect, parser, q, show(r), (unsigned long long)r.digest);
		}
	}
}

int main() {
#ifndef PROXYSQL31
	plan(1);
	skip(1, "v3.0 experimental ParserSQL digests do not promise legacy parity (#6507)");
	return exit_status();
#else

	const size_t parity_tests = 4 * (2 * common_queries.size() + mysql_queries.size() + pgsql_queries.size());
	plan(parity_tests + 2 * 7 + 2 * 6);

	if (test_init_minimal() != 0 || test_init_query_processor() != 0) {
		BAIL_OUT("test initialization failed");
	}
	mysql_thread___query_digests = pgsql_thread___query_digests = true;
	mysql_thread___query_digests_max_query_length = pgsql_thread___query_digests_max_query_length = 65000;
	mysql_thread___query_digests_max_digest_length = pgsql_thread___query_digests_max_digest_length = 2048;
	mysql_thread___query_digests_grouping_limit = pgsql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit = 1;
	mysql_thread___query_digests_replace_null = pgsql_thread___query_digests_replace_null = true;
	mysql_thread___query_digests_no_digits = pgsql_thread___query_digests_no_digits = false;

	std::vector<const char*> mysql_all = common_queries;
	mysql_all.insert(mysql_all.end(), mysql_queries.begin(), mysql_queries.end());
	std::vector<const char*> pgsql_all = common_queries;
	pgsql_all.insert(pgsql_all.end(), pgsql_queries.begin(), pgsql_queries.end());

	test_parity("MySQL", mysql_digest, mysql_all);
	test_parity("PgSQL", pgsql_digest, pgsql_all);
	test_pgsql_terminator(0);
	test_pgsql_terminator(1);
	test_no_sql_tokens("MySQL", mysql_digest);
	test_no_sql_tokens("PgSQL", pgsql_digest);

	mysql_thread___query_processor_parser = pgsql_thread___query_processor_parser = 0;
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
#endif
}
