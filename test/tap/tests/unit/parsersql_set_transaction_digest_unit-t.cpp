/**
 * @file parsersql_set_transaction_digest_unit-t.cpp
 * @brief SET ... TRANSACTION digests keep the scope with query_processor_parser=1.
 *
 * Regression test for #6420: with query_processor_parser=1 the ParserSQL 1.1.0
 * DIGEST emitter dropped the scope of SET GLOBAL|LOCAL|PERSIST TRANSACTION.
 * The scope-less digest matched MySQL_Session's session-level SET TRANSACTION
 * handler (match_regexes[2]), which replied OK without applying or forwarding
 * the statement. ProxySQL then used the legacy digest for these statements.
 *
 * ParserSQL 1.1.1 keeps the scope and normalizes whitespace, comments and
 * keyword case, so the ParserSQL digest is used. This test checks that:
 *  - every scope form has the expected ParserSQL digest, which equals the
 *    legacy (query_processor_parser=0) digest except for keyword case and
 *    the space after a list comma;
 *  - MYSQL_SET_TRANSACTION_DIGEST_REGEX (match_regexes[2]) matches the same
 *    statements on both digests: unscoped, SESSION and LOCAL forms, never
 *    GLOBAL, PERSIST, PERSIST_ONLY or PgSQL SESSION CHARACTERISTICS;
 *  - MySQL_Set_Stmt_Parser::parse2() reports LOCAL as SESSION, accepts any
 *    whitespace, and returns nothing for a statement it cannot parse fully;
 *  - other SET statements keep the ParserSQL digest.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "query_processor.h"
#include "Query_Processor_ParserSQL.h"
#include "c_tokenizer.h"
#include "Base_Thread.h"
#include "MySQL_Set_Stmt_Parser.h"

#include <map>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

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
};

static void release_digest(SQP_par_t& qp) {
	if (qp.digest_text != qp.buf) free(qp.digest_text); // NOSONAR: adapter C allocation
	free(qp.first_comment); // NOSONAR: tokenizer comment ownership
	free(qp.query_prefix); // NOSONAR: query_parser_free ownership
	qp = SQP_par_t {};
}

static std::string printable(const std::string& sql) {
	std::string shown = sql;
	for (char& c : shown) if (c == '\n' || c == '\t') c = ' ';
	return shown;
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
	}
	release_digest(qp);
	return result;
}

/** Matched against the digest by MySQL_Session, as MySQL_Thread::match_regexes[2]. */
static Session_Regex* set_transaction_regex = nullptr;

enum Tracked { FORWARDED, TRACKED };

struct Case {
	const char* sql;
	const char* digest; // expected ParserSQL digest text
	Tracked mysql;      // outcome of match_regexes[2] in MySQL
};

/** Lowercase, without the space ParserSQL emits after a list comma. */
static std::string loose(const std::string& digest) {
	std::string out;
	for (char c : digest) {
		if (c == ' ' && !out.empty() && out.back() == ',') continue;
		out.push_back(static_cast<char>(tolower(static_cast<unsigned char>(c))));
	}
	return out;
}

/**
 * The parser digest must equal the legacy digest. match_regexes[2] must decide the
 * same on both digests.
 */
static void check_case(const Dialect& d, const Case& c) {
	const Digest legacy = legacy_digest(d, c.sql);
	const Digest parser = parser_digest(d, c.sql);
	ok(parser.found && legacy.found && parser.text == legacy.text,
		"%s digest of [%s] equals the legacy digest (got: '%s', legacy: '%s')", d.name,
		printable(c.sql).c_str(), printable(parser.text).c_str(), printable(legacy.text).c_str());
	ok(legacy.found && loose(parser.text) == loose(legacy.text),
		"%s digest of [%s] equals the legacy digest ignoring case and list spacing (legacy: '%s')", d.name,
		printable(c.sql).c_str(), printable(legacy.text).c_str());
	if (d.pgsql) return; // match_regexes[2] is consumed only by MySQL_Session
	const bool parser_match = set_transaction_regex->match(parser.text.c_str());
	const bool legacy_match = set_transaction_regex->match(legacy.text.c_str());
	ok(parser_match == (c.mysql == TRACKED) && legacy_match == parser_match,
		"%s SET TRANSACTION regex %s [%s] with both digests (parser: %d, legacy: %d)", d.name,
		c.mysql == TRACKED ? "matches" : "does not match", printable(c.sql).c_str(),
		parser_match, legacy_match);
}

static const Case common_cases[] = {
	{"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", TRACKED},
	{"SET TRANSACTION ISOLATION LEVEL READ COMMITTED", "SET TRANSACTION ISOLATION LEVEL READ COMMITTED", TRACKED},
	{"SET TRANSACTION READ ONLY", "SET TRANSACTION READ ONLY", TRACKED},
	{"SET TRANSACTION READ WRITE", "SET TRANSACTION READ WRITE", TRACKED},
	{"set transaction isolation level read uncommitted", "SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED", TRACKED},
	{"SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ", "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ", TRACKED},
	{"SET SESSION TRANSACTION READ ONLY", "SET SESSION TRANSACTION READ ONLY", TRACKED},
	{"SET LOCAL TRANSACTION ISOLATION LEVEL SERIALIZABLE", "SET LOCAL TRANSACTION ISOLATION LEVEL SERIALIZABLE", TRACKED},
	{"SET LOCAL TRANSACTION READ ONLY", "SET LOCAL TRANSACTION READ ONLY", TRACKED},
	{"set local transaction read write", "SET LOCAL TRANSACTION READ WRITE", TRACKED},
	// Raw whitespace inside multi-word levels and access modes.
	{"SET TRANSACTION READ  ONLY", "SET TRANSACTION READ ONLY", TRACKED},
	{"SET TRANSACTION ISOLATION LEVEL READ\nCOMMITTED", "SET TRANSACTION ISOLATION LEVEL READ COMMITTED", TRACKED},
	{"SET\tSESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE;", "SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE", TRACKED},
	{"SET LOCAL\nTRANSACTION ISOLATION LEVEL REPEATABLE  READ", "SET LOCAL TRANSACTION ISOLATION LEVEL REPEATABLE READ", TRACKED},
};

static const Case mysql_cases[] = {
	{"SET GLOBAL TRANSACTION ISOLATION LEVEL SERIALIZABLE", "SET GLOBAL TRANSACTION ISOLATION LEVEL SERIALIZABLE", FORWARDED},
	{"SET GLOBAL TRANSACTION READ ONLY", "SET GLOBAL TRANSACTION READ ONLY", FORWARDED},
	{"SET GLOBAL TRANSACTION READ WRITE", "SET GLOBAL TRANSACTION READ WRITE", FORWARDED},
	{"set global transaction isolation level read committed", "SET GLOBAL TRANSACTION ISOLATION LEVEL READ COMMITTED", FORWARDED},
	{"SET PERSIST TRANSACTION ISOLATION LEVEL READ COMMITTED", "SET PERSIST TRANSACTION ISOLATION LEVEL READ COMMITTED", FORWARDED},
	{"SET PERSIST TRANSACTION READ ONLY", "SET PERSIST TRANSACTION READ ONLY", FORWARDED},
	{"SET PERSIST_ONLY TRANSACTION ISOLATION LEVEL SERIALIZABLE", "SET PERSIST_ONLY TRANSACTION ISOLATION LEVEL SERIALIZABLE", FORWARDED},
	{"SET PERSIST_ONLY TRANSACTION READ WRITE", "SET PERSIST_ONLY TRANSACTION READ WRITE", FORWARDED},
	{"/* hostgroup=1 */ SET GLOBAL TRANSACTION ISOLATION LEVEL SERIALIZABLE", "SET GLOBAL TRANSACTION ISOLATION LEVEL SERIALIZABLE", FORWARDED},
	// The regex matches a prefix; parse2() rejects the unparsed second characteristic.
	{"SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY", "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY", TRACKED},
};

static const Case pgsql_cases[] = {
	{"SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE",
		"SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE", FORWARDED},
	{"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY", "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY", FORWARDED},
};

static bool ends_with(const std::string& s, const char* suffix) {
	const size_t n = std::strlen(suffix);
	return s.size() >= n && s.compare(s.size() - n, n, suffix) == 0;
}

static void test_mysql_scope(const Dialect& d) {
	const Digest unscoped = parser_digest(d, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
	const Digest session = parser_digest(d, "SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE");
	for (const char* scope : {"GLOBAL", "LOCAL", "PERSIST", "PERSIST_ONLY"}) {
		const std::string sql = std::string("SET ") + scope + " TRANSACTION ISOLATION LEVEL SERIALIZABLE";
		const Digest scoped = parser_digest(d, sql);
		const std::string prefix = std::string("SET ") + scope + " TRANSACTION";
		ok(scoped.text.compare(0, prefix.size(), prefix) == 0,
			"%s digest keeps the %s scope (got: '%s')", d.name, scope, scoped.text.c_str());
		ok(scoped.hash != unscoped.hash && scoped.hash != session.hash,
			"%s %s TRANSACTION hash differs from unscoped and SESSION", d.name, scope);
	}
	for (const char* sql : {"SET PERSIST TRANSACTION ISOLATION LEVEL READ COMMITTED",
		"SET PERSIST TRANSACTION READ ONLY", "SET PERSIST_ONLY TRANSACTION READ ONLY"}) {
		const Digest persist = parser_digest(d, sql);
		ok(!ends_with(persist.text, "PERSIST") && !ends_with(persist.text, "PERSIST_ONLY"),
			"%s digest does not render the scope as the isolation level for [%s] (got: '%s')",
			d.name, sql, persist.text.c_str());
	}
	ok(session.text.compare(0, 24, "SET SESSION TRANSACTION ") == 0,
		"%s SESSION TRANSACTION digest keeps the scope (got: '%s')", d.name, session.text.c_str());
	ok(session.hash != unscoped.hash, "%s SESSION TRANSACTION hash differs from unscoped", d.name);

	// The annotation is still extracted, and the command type is classified lazily.
	const char* annotated = "/* hostgroup=1 */ SET GLOBAL TRANSACTION READ ONLY";
	SQP_par_t qp {};
	d.parser_init(&qp, annotated, std::strlen(annotated));
	ok(qp.first_comment && std::strstr(qp.first_comment, "hostgroup=1"),
		"%s first comment kept for SET GLOBAL TRANSACTION (got: %s)", d.name,
		qp.first_comment ? qp.first_comment : "NULL");
	ok(parsersql_command_type_mysql(annotated, std::strlen(annotated)) == MYSQL_COM_QUERY_SET,
		"%s SET GLOBAL TRANSACTION is still classified as SET", d.name);
	release_digest(qp);
}

/** PgSQL SESSION CHARACTERISTICS (session default) and SET SESSION TRANSACTION (current transaction) differ. */
static void test_pgsql_scope(const Dialect& d) {
	const Digest characteristics = parser_digest(d, "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY");
	const Digest session = parser_digest(d, "SET SESSION TRANSACTION READ ONLY");
	const Digest local = parser_digest(d, "SET LOCAL TRANSACTION READ ONLY");
	const Digest unscoped = parser_digest(d, "SET TRANSACTION READ ONLY");
	ok(characteristics.hash != session.hash && characteristics.hash != unscoped.hash &&
		session.hash != unscoped.hash && local.hash != unscoped.hash && local.hash != session.hash,
		"%s SESSION CHARACTERISTICS, SESSION, LOCAL and unscoped TRANSACTION digests differ", d.name);
}

using SetMap = std::map<std::string, std::vector<std::string>>;

/** MySQL_Session's match_regexes[2] branch tracks what parse2() returns; empty means forward. */
static void check_parse2(const char* sql, const SetMap& expected) {
	MySQL_Set_Stmt_Parser parser(sql);
	const SetMap got = parser.parse2();
	std::string shown;
	for (const auto& entry : got) {
		shown += "[" + entry.first + "=";
		for (const auto& value : entry.second) shown += value;
		shown += "]";
	}
	ok(got == expected, "parse2() of [%s] returns %s", printable(sql).c_str(), shown.empty() ? "nothing" : shown.c_str());
}

static void test_parse2() {
	check_parse2("SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE", {{"session:isolation level", {"SERIALIZABLE"}}});
	check_parse2("SET LOCAL TRANSACTION ISOLATION LEVEL SERIALIZABLE", {{"session:isolation level", {"SERIALIZABLE"}}});
	check_parse2("set local transaction isolation level read committed", {{"session:isolation level", {"READ COMMITTED"}}});
	check_parse2("SET LOCAL TRANSACTION READ ONLY", {{"session:read", {"ONLY"}}});
	check_parse2("SET TRANSACTION READ WRITE", {{":read", {"WRITE"}}});
	check_parse2("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", {{":isolation level", {"REPEATABLE READ"}}});
	// Whitespace is collapsed in the digest but not in the query.
	check_parse2("SET LOCAL\nTRANSACTION ISOLATION  LEVEL REPEATABLE\n READ", {{"session:isolation level", {"REPEATABLE READ"}}});
	check_parse2("SET\tSESSION\tTRANSACTION\tREAD\tONLY", {{"session:read", {"ONLY"}}});
	// Not parsed in full: forwarded instead of acknowledged with a partial (or empty) change.
	check_parse2("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY", {});
	check_parse2("SET LOCAL TRANSACTION READ ONLY junk", {});
	check_parse2("SET GLOBAL TRANSACTION ISOLATION LEVEL SERIALIZABLE", {});
	check_parse2("SET PERSIST TRANSACTION READ ONLY", {});
}

/** SET statements without a TRANSACTION clause must also get the legacy digest. */
static void test_other_set_unchanged(const Dialect& d, const char* sql, const char* expected) {
	const Digest parser = parser_digest(d, sql);
	const Digest legacy = legacy_digest(d, sql);
	ok(parser.found && legacy.found && parser.text == legacy.text,
		"%s parser digest equals legacy for [%s] (got: '%s', legacy: '%s', documented: '%s')",
		d.name, sql, parser.text.c_str(), legacy.text.c_str(), expected);
}

int main() {
	const size_t n_common = sizeof(common_cases) / sizeof(common_cases[0]);
	const size_t n_mysql = sizeof(mysql_cases) / sizeof(mysql_cases[0]);
	const size_t n_pgsql = sizeof(pgsql_cases) / sizeof(pgsql_cases[0]);
	plan(5 * n_common + 3 * n_mysql + 2 * n_pgsql + (4 * 2 + 3 + 2 + 2) + 1 + 12 + 8);
	test_init_minimal();
	mysql_thread___query_digests_max_query_length = pgsql_thread___query_digests_max_query_length = 65000;
	mysql_thread___query_digests_max_digest_length = pgsql_thread___query_digests_max_digest_length = 2048;
	mysql_thread___query_digests_grouping_limit = pgsql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit = 1;
	const Dialect mysql {"MySQL", parsersql_digest_init_mysql, mysql_query_digest_and_first_comment, false};
	const Dialect pgsql {"PostgreSQL", parsersql_digest_init_pgsql, pgsql_query_digest_and_first_comment, true};
	set_transaction_regex = new Session_Regex(MYSQL_SET_TRANSACTION_DIGEST_REGEX);

	for (const Case& c : common_cases) {
		check_case(mysql, c);
		check_case(pgsql, c);
	}
	for (const Case& c : mysql_cases) check_case(mysql, c);
	for (const Case& c : pgsql_cases) check_case(pgsql, c);
	test_mysql_scope(mysql);
	test_pgsql_scope(pgsql);
	test_parse2();

	test_other_set_unchanged(mysql, "SET GLOBAL max_connections=10", "SET GLOBAL max_connections = ?");
	test_other_set_unchanged(mysql, "SET @@GLOBAL.transaction_isolation='SERIALIZABLE'",
		"SET @@GLOBAL.transaction_isolation = ?");
	test_other_set_unchanged(mysql, "SET autocommit=0", "SET autocommit = ?");
	test_other_set_unchanged(pgsql, "SET search_path TO public", "SET search_path = public");
	// ParserSQL 1.1.0 digested these as "SET " and "SET search_path = a".
	test_other_set_unchanged(pgsql, "SET ROLE app_reader", "SET ROLE app_reader");
	test_other_set_unchanged(pgsql, "SET SESSION AUTHORIZATION app_user", "SET SESSION AUTHORIZATION app_user");
	test_other_set_unchanged(pgsql, "SET CONSTRAINTS ALL DEFERRED", "SET CONSTRAINTS ALL DEFERRED");
	test_other_set_unchanged(pgsql, "SET search_path TO a, b", "SET search_path = a, b");

	delete set_transaction_regex;
	test_cleanup_minimal();
	return exit_status();
}
