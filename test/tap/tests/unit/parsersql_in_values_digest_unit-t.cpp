/**
 * @file parsersql_in_values_digest_unit-t.cpp
 * @brief ParserSQL digests keep non-literal IN-list elements and VALUES rows.
 *
 * Regression test for #6428: with query_processor_parser=1 the ParserSQL
 * DIGEST emitter rendered every IN / NOT IN list that is not a single
 * subquery as "IN (?)" and kept only the first VALUES row, whatever the
 * omitted elements were. ProxySQL string-matches the digest text to route
 * LAST_INSERT_ID() / @@IDENTITY queries to the last written hostgroup and to
 * disable multiplexing on GET_LOCK(, so these decisions were lost for e.g.
 * "id IN (LAST_INSERT_ID())" or "VALUES (1),(GET_LOCK('x',1))".
 *
 * A statement whose collapsed list holds a non-literal expression must now
 * get exactly the digest text and hash of the legacy tokenizer used with
 * query_processor_parser=0. Lists made only of literals and placeholders keep
 * the ParserSQL digest.
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

struct Digest {
	bool found = false;
	std::string text;
	uint64_t hash = 0;
	int stmt_type = -1;
};

static void release_digest(SQP_par_t& qp) {
	if (qp.digest_text != qp.buf) free(qp.digest_text); // NOSONAR: adapter C allocation
	free(qp.first_comment); // NOSONAR: tokenizer comment ownership
	free(qp.query_prefix); // NOSONAR: query_parser_free ownership
	qp = SQP_par_t {};
}

/** Digest text and hash as computed by the legacy (query_processor_parser=0) path. */
static Digest legacy_digest(const Dialect& d, const std::string& sql) {
	options opts {};
	int max_digest_length;
	if (d.pgsql) {
		opts.lowercase = pgsql_thread___query_digests_lowercase;
		opts.replace_null = pgsql_thread___query_digests_replace_null;
		opts.replace_number = pgsql_thread___query_digests_no_digits;
		opts.keep_comment = pgsql_thread___query_digests_keep_comment;
		opts.grouping_limit = pgsql_thread___query_digests_grouping_limit;
		opts.groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit;
		opts.max_query_length = pgsql_thread___query_digests_max_query_length;
		max_digest_length = pgsql_thread___query_digests_max_digest_length;
	} else {
		opts.lowercase = mysql_thread___query_digests_lowercase;
		opts.replace_null = mysql_thread___query_digests_replace_null;
		opts.replace_number = mysql_thread___query_digests_no_digits;
		opts.keep_comment = mysql_thread___query_digests_keep_comment;
		opts.grouping_limit = mysql_thread___query_digests_grouping_limit;
		opts.groups_grouping_limit = mysql_thread___query_digests_groups_grouping_limit;
		opts.max_query_length = mysql_thread___query_digests_max_query_length;
		max_digest_length = mysql_thread___query_digests_max_digest_length;
	}
	char* comment = nullptr;
	char* text = d.legacy_digest(sql.data(), sql.size(), &comment, nullptr, &opts);
	Digest result;
	if (text) {
		result.found = true;
		result.text = text;
		result.hash = SpookyHash::Hash64(text, strnlen(text, max_digest_length), 0);
	}
	free(text); // NOSONAR: tokenizer C allocation
	free(comment); // NOSONAR: tokenizer comment ownership
	return result;
}

/** Digest text and hash as computed by the ParserSQL (query_processor_parser=1) path. */
static Digest parser_digest(const Dialect& d, const std::string& sql) {
	SQP_par_t qp {};
	d.parser_init(&qp, sql.data(), sql.size());
	Digest result;
	if (qp.digest_text) {
		result.found = true;
		result.text = qp.digest_text;
		result.hash = qp.digest;
		result.stmt_type = qp.parsersql_stmt_type;
	}
	release_digest(qp);
	return result;
}

/** ParserSQL digest text and hash must equal the legacy ones. Returns the digest. */
static Digest check_matches_legacy(const Dialect& d, const char* sql) {
	const Digest legacy = legacy_digest(d, sql);
	const Digest parser = parser_digest(d, sql);
	ok(parser.found && legacy.found && parser.text == legacy.text && parser.hash == legacy.hash,
		"%s digest matches legacy for [%s] (parser: '%s', legacy: '%s')", d.name, sql,
		parser.text.c_str(), legacy.text.c_str());
	return parser;
}

/** A query whose collapsed list or VALUES row hides a non-literal expression. */
struct HiddenCase {
	const char* sql;
	const char* needle; ///< substring a digest consumer looks for (strcasestr)
	MYSQL_COM_QUERY_command command;
};

/**
 * MySQL_Session routes on strcasestr(digest, "LAST_INSERT_ID") ||
 * strcasestr(digest, "@@IDENTITY"); MySQL_Connection disables multiplexing on
 * strcasestr(digest, "GET_LOCK(") and on '@' (user variables).
 */
static const HiddenCase mysql_hidden_cases[] = {
	{ "SELECT * FROM t WHERE id IN (LAST_INSERT_ID())", "LAST_INSERT_ID", MYSQL_COM_QUERY_SELECT },
	{ "select id from t where id in (last_insert_id())", "LAST_INSERT_ID", MYSQL_COM_QUERY_SELECT },
	{ "SELECT * FROM t WHERE id IN (@@identity)", "@@IDENTITY", MYSQL_COM_QUERY_SELECT },
	{ "SELECT * FROM t WHERE id IN (LAST_INSERT_ID()+0)", "LAST_INSERT_ID", MYSQL_COM_QUERY_SELECT },
	{ "SELECT * FROM t WHERE id IN (1, 2, LAST_INSERT_ID())", "LAST_INSERT_ID", MYSQL_COM_QUERY_SELECT },
	{ "SELECT * FROM t WHERE id NOT IN (LAST_INSERT_ID())", "LAST_INSERT_ID", MYSQL_COM_QUERY_SELECT },
	{ "SELECT * FROM t WHERE id NOT IN (@@IDENTITY, 5)", "@@IDENTITY", MYSQL_COM_QUERY_SELECT },
	{ "SELECT * FROM t WHERE id IN ((SELECT 1), LAST_INSERT_ID())", "LAST_INSERT_ID", MYSQL_COM_QUERY_SELECT },
	{ "SELECT * FROM t WHERE (a, b) IN ((1, LAST_INSERT_ID()))", "LAST_INSERT_ID", MYSQL_COM_QUERY_SELECT },
	{ "SELECT * FROM t WHERE x IN (SELECT a FROM u WHERE b IN (LAST_INSERT_ID()))", "LAST_INSERT_ID",
		MYSQL_COM_QUERY_SELECT },
	{ "SELECT 1 FROM DUAL WHERE 1 IN (GET_LOCK('x',10))", "GET_LOCK(", MYSQL_COM_QUERY_SELECT },
	{ "SELECT * FROM t WHERE id IN (@a, @b)", "@", MYSQL_COM_QUERY_SELECT },
	{ "UPDATE t SET a = 1 WHERE id IN (LAST_INSERT_ID())", "LAST_INSERT_ID", MYSQL_COM_QUERY_UPDATE },
	{ "DELETE FROM t WHERE id IN (LAST_INSERT_ID())", "LAST_INSERT_ID", MYSQL_COM_QUERY_DELETE },
	{ "INSERT INTO t (a) VALUES (1),(LAST_INSERT_ID())", "LAST_INSERT_ID", MYSQL_COM_QUERY_INSERT },
	{ "INSERT INTO t (a) VALUES (1),(GET_LOCK('x',1))", "GET_LOCK(", MYSQL_COM_QUERY_INSERT },
	{ "INSERT INTO t (a, b) VALUES (1, 2), (3, @@identity)", "@@IDENTITY", MYSQL_COM_QUERY_INSERT },
	{ "INSERT INTO t VALUES ROW(1), ROW(GET_LOCK('x',1))", "GET_LOCK(", MYSQL_COM_QUERY_INSERT },
	{ "REPLACE INTO t (a) VALUES (1),(LAST_INSERT_ID())", "LAST_INSERT_ID", MYSQL_COM_QUERY_REPLACE },
};

/** Lists that hold only literals and placeholders keep the ParserSQL digest. */
struct KeptCase {
	const char* sql;
	const char* expected;
};

static const KeptCase mysql_kept_cases[] = {
	{ "SELECT * FROM t WHERE id IN (1,2,3)", "SELECT * FROM t WHERE id IN (?)" },
	{ "SELECT * FROM t WHERE id NOT IN (1,-2,'a',NULL,0x1F,1.5,b'01',(3),?)",
		"SELECT * FROM t WHERE id NOT IN (?)" },
	{ "SELECT * FROM t WHERE (a,b) IN ((1,2),(3,4))", "SELECT * FROM t WHERE (a, b) IN (?)" },
	{ "INSERT INTO t (a) VALUES (1),(2),(3)", "INSERT INTO t (a) VALUES (?)" },
	{ "INSERT INTO t (a, b) VALUES (1, -2), (+3, 'x'), (NULL, ?)", "INSERT INTO t (a, b) VALUES (?, -?)" },
	// Only additional rows are collapsed: the first row is emitted in full.
	{ "INSERT INTO t (a) VALUES (NOW()),(1)", "INSERT INTO t (a) VALUES (NOW())" },
	// A single subquery is emitted in full.
	{ "SELECT * FROM t WHERE id IN (SELECT LAST_INSERT_ID())",
		"SELECT * FROM t WHERE id IN (SELECT LAST_INSERT_ID())" },
	{ "SELECT * FROM t WHERE id = LAST_INSERT_ID()", "SELECT * FROM t WHERE id = LAST_INSERT_ID()" },
};

static const char* const pgsql_hidden_cases[] = {
	"SELECT * FROM t WHERE true IN (pg_try_advisory_lock(1))",
	"SELECT * FROM t WHERE id IN (1, lastval())",
	"SELECT * FROM t WHERE id NOT IN (currval('s'))",
	"INSERT INTO t (a) VALUES (1),(lastval())",
};

static const KeptCase pgsql_kept_cases[] = {
	{ "SELECT * FROM t WHERE id IN ($1, $2)", "SELECT * FROM t WHERE id IN (?)" },
	{ "SELECT * FROM t WHERE id IN (1,-2,'x',NULL)", "SELECT * FROM t WHERE id IN (?)" },
	{ "INSERT INTO t (a) VALUES ($1),($2)", "INSERT INTO t (a) VALUES ($1)" },
};

static void test_hidden_mysql(const Dialect& d, const HiddenCase& c) {
	const Digest parser = check_matches_legacy(d, c.sql);
	ok(strcasestr(parser.text.c_str(), c.needle) != nullptr,
		"%s digest keeps '%s' for [%s] (got: '%s')", d.name, c.needle, c.sql, parser.text.c_str());
	ok(parsersql_command_type_mysql(c.sql, std::strlen(c.sql)) == c.command,
		"%s statement type comes from ParserSQL lazily for [%s]", d.name, c.sql);
}

// The parser digest is now the legacy tokenizer digest; a literal-only list keeps
// exactly what the tokenizer produces.
static void test_kept(const Dialect& d, const KeptCase& c) {
	const Digest parser = parser_digest(d, c.sql);
	const Digest legacy = legacy_digest(d, c.sql);
	ok(parser.found && legacy.found && parser.text == legacy.text && parser.hash == legacy.hash,
		"%s parser digest and hash equal legacy for [%s] (got: '%s', legacy: '%s')",
		d.name, c.sql, parser.text.c_str(), legacy.text.c_str());
}

int main() {
	const size_t n_mysql_hidden = sizeof(mysql_hidden_cases) / sizeof(mysql_hidden_cases[0]);
	const size_t n_mysql_kept = sizeof(mysql_kept_cases) / sizeof(mysql_kept_cases[0]);
	const size_t n_pgsql_hidden = sizeof(pgsql_hidden_cases) / sizeof(pgsql_hidden_cases[0]);
	const size_t n_pgsql_kept = sizeof(pgsql_kept_cases) / sizeof(pgsql_kept_cases[0]);
	plan(3 * n_mysql_hidden + n_mysql_kept + n_pgsql_hidden + n_pgsql_kept + 2);
	test_init_minimal();
	mysql_thread___query_digests_max_query_length = pgsql_thread___query_digests_max_query_length = 65000;
	mysql_thread___query_digests_max_digest_length = pgsql_thread___query_digests_max_digest_length = 2048;
	mysql_thread___query_digests_grouping_limit = pgsql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit = 1;
	const Dialect mysql {"MySQL", parsersql_digest_init_mysql, mysql_query_digest_and_first_comment, false};
	const Dialect pgsql {"PostgreSQL", parsersql_digest_init_pgsql, pgsql_query_digest_and_first_comment, true};

	for (const HiddenCase& c : mysql_hidden_cases) test_hidden_mysql(mysql, c);
	for (const KeptCase& c : mysql_kept_cases) test_kept(mysql, c);
	for (const char* sql : pgsql_hidden_cases) check_matches_legacy(pgsql, sql);
	for (const KeptCase& c : pgsql_kept_cases) test_kept(pgsql, c);

	// The annotation is still extracted when the token path builds the digest.
	const char* annotated = "/* hostgroup=1 */ SELECT * FROM t WHERE id IN (LAST_INSERT_ID())";
	SQP_par_t qp {};
	mysql.parser_init(&qp, annotated, std::strlen(annotated));
	ok(qp.first_comment && std::strstr(qp.first_comment, "hostgroup=1"),
		"MySQL first comment kept for a collapsed IN list (got: %s)",
		qp.first_comment ? qp.first_comment : "NULL");
	release_digest(qp);

	// A large literal-only multi-row INSERT also gets the legacy tokenizer digest.
	std::string big = "INSERT INTO t (a, b) VALUES (1, 'x')";
	for (int i = 0; i < 5000; i++) big += ", (" + std::to_string(i) + ", 'y')";
	const Digest parser = parser_digest(mysql, big);
	const Digest legacy = legacy_digest(mysql, big);
	ok(parser.found && legacy.found && parser.text == legacy.text,
		"MySQL parser digest equals legacy for a 5001-row literal INSERT (got: '%s', legacy: '%s')",
		parser.text.c_str(), legacy.text.c_str());

	test_cleanup_minimal();
	return exit_status();
}
