/**
 * @file parsersql_set_transaction_digest_unit-t.cpp
 * @brief ParserSQL digests of SET ... TRANSACTION equal the legacy digests.
 *
 * Regression test for #6420: with query_processor_parser=1 the ParserSQL
 * DIGEST emitter dropped the scope of SET GLOBAL|LOCAL|PERSIST TRANSACTION.
 * The scope-less digest matched MySQL_Session's session-level SET TRANSACTION
 * handler, which replied OK without applying or forwarding the statement.
 * Every SET ... TRANSACTION must now get exactly the digest text and hash of
 * the legacy tokenizer used with query_processor_parser=0, so the session
 * classifies it as in legacy mode. Other SET statements keep the ParserSQL
 * digest.
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

/** ParserSQL digest text and hash must equal the legacy ones. Returns the digest. */
static Digest check_matches_legacy(const Dialect& d, const std::string& sql) {
	const Digest legacy = legacy_digest(d, sql);
	const Digest parser = parser_digest(d, sql);
	ok(parser.found && legacy.found && parser.text == legacy.text && parser.hash == legacy.hash,
		"%s digest matches legacy for [%s] (parser: '%s', legacy: '%s')", d.name,
		printable(sql).c_str(), printable(parser.text).c_str(), printable(legacy.text).c_str());
	return parser;
}

static const char* const common_cases[] = {
	"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
	"SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
	"SET TRANSACTION READ ONLY",
	"SET TRANSACTION READ WRITE",
	"set transaction isolation level read uncommitted",
	"SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
	"SET SESSION TRANSACTION READ ONLY",
	// Raw whitespace inside multi-word levels and access modes.
	"SET TRANSACTION READ  ONLY",
	"SET TRANSACTION ISOLATION LEVEL READ\nCOMMITTED",
	"SET\tSESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE;",
};

static const char* const mysql_cases[] = {
	"SET GLOBAL TRANSACTION ISOLATION LEVEL SERIALIZABLE",
	"SET GLOBAL TRANSACTION READ ONLY",
	"SET GLOBAL TRANSACTION READ WRITE",
	"set global transaction isolation level read committed",
	"SET LOCAL TRANSACTION ISOLATION LEVEL SERIALIZABLE",
	"SET LOCAL TRANSACTION READ ONLY",
	"SET PERSIST TRANSACTION ISOLATION LEVEL READ COMMITTED",
	"SET PERSIST TRANSACTION READ ONLY",
	"SET PERSIST_ONLY TRANSACTION ISOLATION LEVEL SERIALIZABLE",
	"SET PERSIST_ONLY TRANSACTION READ WRITE",
	"/* hostgroup=1 */ SET GLOBAL TRANSACTION ISOLATION LEVEL SERIALIZABLE",
};

static const char* const pgsql_cases[] = {
	"SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE",
	"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
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

	// The annotation is still extracted when the token path builds the digest.
	const char* annotated = "/* hostgroup=1 */ SET GLOBAL TRANSACTION READ ONLY";
	SQP_par_t qp {};
	d.parser_init(&qp, annotated, std::strlen(annotated));
	ok(qp.first_comment && std::strstr(qp.first_comment, "hostgroup=1"),
		"%s first comment kept for SET GLOBAL TRANSACTION (got: %s)", d.name,
		qp.first_comment ? qp.first_comment : "NULL");
	ok(qp.parsersql_stmt_type >= 0 &&
		parsersql_stmt_type_to_mysql_command(qp.parsersql_stmt_type) == MYSQL_COM_QUERY_SET,
		"%s SET GLOBAL TRANSACTION is still classified as SET", d.name);
	release_digest(qp);
}

/** SET statements without a TRANSACTION clause must keep the ParserSQL digest. */
static void test_other_set_unchanged(const Dialect& d, const char* sql, const char* expected) {
	const Digest parser = parser_digest(d, sql);
	ok(parser.text == expected, "%s non-transaction SET keeps the ParserSQL digest for [%s] (got: '%s', expected: '%s')",
		d.name, sql, parser.text.c_str(), expected);
}

int main() {
	const size_t n_common = sizeof(common_cases) / sizeof(common_cases[0]);
	const size_t n_mysql = sizeof(mysql_cases) / sizeof(mysql_cases[0]);
	const size_t n_pgsql = sizeof(pgsql_cases) / sizeof(pgsql_cases[0]);
	plan(2 * n_common + n_mysql + n_pgsql + (4 * 2 + 3 + 2 + 2) + 3 + 1);
	test_init_minimal();
	mysql_thread___query_digests_max_query_length = pgsql_thread___query_digests_max_query_length = 65000;
	mysql_thread___query_digests_max_digest_length = pgsql_thread___query_digests_max_digest_length = 2048;
	mysql_thread___query_digests_grouping_limit = pgsql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit = 1;
	const Dialect mysql {"MySQL", parsersql_digest_init_mysql, mysql_query_digest_and_first_comment, false};
	const Dialect pgsql {"PostgreSQL", parsersql_digest_init_pgsql, pgsql_query_digest_and_first_comment, true};

	for (const char* sql : common_cases) {
		check_matches_legacy(mysql, sql);
		check_matches_legacy(pgsql, sql);
	}
	for (const char* sql : mysql_cases) check_matches_legacy(mysql, sql);
	for (const char* sql : pgsql_cases) check_matches_legacy(pgsql, sql);
	test_mysql_scope(mysql);

	test_other_set_unchanged(mysql, "SET GLOBAL max_connections=10", "SET GLOBAL max_connections = ?");
	test_other_set_unchanged(mysql, "SET @@GLOBAL.transaction_isolation='SERIALIZABLE'",
		"SET @@GLOBAL.transaction_isolation = ?");
	test_other_set_unchanged(mysql, "SET autocommit=0", "SET autocommit = ?");
	test_other_set_unchanged(pgsql, "SET search_path TO public", "SET search_path = public");

	test_cleanup_minimal();
	return exit_status();
}
