/**
 * @file pgsql_set_transaction_regexp_unit-t.cpp
 * @brief 'SET [LOCAL|SESSION] TRANSACTION ...' is recognised on every digest shape.
 *
 * PgSQL_Session forwards a SET for which PgSQL_Variables::is_set_transaction() holds
 * without locking the hostgroup: it only changes the transaction already open, which
 * holds its backend since BEGIN. Any other SET it cannot parse still locks. This test
 * checks the pattern against literal digests, then the helper against the digests the two
 * digest engines actually produce, paired with the query text as the session passes it:
 *   - the legacy tokenizer, with upper/lower case and with comments kept or stripped;
 *   - ParserSQL (pgsql-query_processor_parser=1). Version 1.1.0 drops the SESSION/LOCAL
 *     scope and digests 'SET SESSION CHARACTERISTICS AS TRANSACTION ...' as
 *     'SET TRANSACTION ...', and falls back to the tokenizer on 'SET LOCAL TRANSACTION'.
 *
 * The session-wide 'SET SESSION CHARACTERISTICS AS TRANSACTION' and the
 * default_transaction_* / transaction_* variables must not be forwarded.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "Base_Thread.h"
#include "PgSQL_Variables.h"
#include "c_tokenizer.h"
#include "query_processor.h"
#include "Query_Processor_ParserSQL.h"

#include "re2/re2.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static Session_Regex* re = nullptr;

static bool matches(const std::string& digest) {
	return re->match(digest.c_str());
}

// Digest text as handed to handle_SET_command.
static const std::vector<std::string> digest_positive = {
	"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
	"SET TRANSACTION READ ONLY",
	"SET TRANSACTION READ WRITE",
	"SET TRANSACTION DEFERRABLE",
	"SET TRANSACTION NOT DEFERRABLE",
	"SET TRANSACTION ISOLATION LEVEL READ COMMITTED,READ ONLY,NOT DEFERRABLE",
	"SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ WRITE DEFERRABLE",
	"SET TRANSACTION SNAPSHOT ?",
	"SET LOCAL TRANSACTION READ ONLY",
	"SET LOCAL TRANSACTION SNAPSHOT ?",
	"SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE",
	"SET SESSION TRANSACTION SNAPSHOT ?",
	"set transaction isolation level serializable",
	"set local transaction read only",
	"Set Session Transaction Read Only",
	"SET  TRANSACTION   READ ONLY",
	"SET\tTRANSACTION\tREAD ONLY",
	"SET\nLOCAL\nTRANSACTION\nREAD ONLY",
	"SET TRANSACTION",
	"SET TRANSACTION;",
	"SET /* c */ TRANSACTION READ ONLY",
	"SET /* c */ SESSION /* d */ TRANSACTION READ ONLY",
	"SET SESSION TRANSACTION/* c */READ ONLY",
};

static const std::vector<std::string> digest_negative = {
	"SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE",
	"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
	"SET LOCAL SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
	"set session characteristics as transaction read only",
	"SET default_transaction_isolation = ?",
	"SET default_transaction_isolation TO ?",
	"SET default_transaction_read_only = ?",
	"SET default_transaction_deferrable = ?",
	"SET SESSION default_transaction_isolation = ?",
	"SET transaction_isolation = ?",
	"SET transaction_read_only TO ?",
	"SET transaction_deferrable = ?",
	"SET transaction.foo = ?",
	"SET TRANSACTIONS READ ONLY",
	"SET TRANSACTION_ISOLATION = ?",
	"SET GLOBAL TRANSACTION READ ONLY",
	"SET LOCAL SESSION TRANSACTION READ ONLY",
	"SET SESSION AUTHORIZATION DEFAULT",
	"SET SESSION search_path TO ?",
	"SET LOCAL datestyle TO ?",
	"SETTRANSACTION READ ONLY",
	"SELECT ? FROM t WHERE x = ?",
	"/* c */ SET TRANSACTION READ ONLY",
	" SET TRANSACTION READ ONLY",
	"SET \"transaction\" = ?",
};

// Raw SQL, digested by both engines.
struct SqlCase {
	const char* sql;
	bool forward;
};

static const std::vector<SqlCase> sql_cases = {
	{ "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", true },
	{ "SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY, NOT DEFERRABLE", true },
	{ "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ WRITE DEFERRABLE", true },
	{ "SET TRANSACTION READ ONLY;", true },
	{ "SET TRANSACTION SNAPSHOT '00000003-0000001B-1'", true },
	{ "SET LOCAL TRANSACTION READ ONLY", true },
	{ "SET LOCAL TRANSACTION ISOLATION LEVEL SERIALIZABLE", true },
	{ "SET LOCAL TRANSACTION SNAPSHOT '00000003-0000001B-1'", true },
	{ "SET SESSION TRANSACTION READ ONLY", true },
	{ "SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE", true },
	{ "SET SESSION TRANSACTION SNAPSHOT '00000003-0000001B-1'", true },
	{ "set session transaction isolation level read uncommitted", true },
	{ "SeT   LoCaL\t\tTrAnSaCtIoN\n  read  write", true },
	{ "SET /* hint */ TRANSACTION READ ONLY", true },
	{ "SET SESSION /* hint */ TRANSACTION READ ONLY -- trailing", true },
	{ "/* leading */ SET TRANSACTION READ ONLY", true },
	{ "SET -- line\nTRANSACTION READ ONLY", true },
	{ "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE", false },
	{ "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY", false },
	{ "set session characteristics as transaction read write", false },
	{ "SET default_transaction_isolation = 'serializable'", false },
	{ "SET default_transaction_isolation TO 'read committed'", false },
	{ "SET default_transaction_read_only = on", false },
	{ "SET default_transaction_deferrable TO off", false },
	{ "SET transaction_isolation = 'serializable'", false },
	{ "SET transaction_read_only = on", false },
	{ "SET SESSION AUTHORIZATION DEFAULT", false },
	{ "SET /* x */ SESSION CHARACTERISTICS AS TRANSACTION READ ONLY", false },
};

static std::string legacy_digest(const char* sql, bool lowercase, bool keep_comment) {
	char buf[QUERY_DIGEST_BUF];
	memset(buf, 0, sizeof(buf));
	char* first_comment = nullptr;
	options opts;
	opts.lowercase = lowercase;
	opts.replace_null = true;
	opts.replace_number = false;
	opts.grouping_limit = 3;
	opts.groups_grouping_limit = 1;
	opts.keep_comment = keep_comment;
	opts.max_query_length = 65000;
	const int len = (int)strlen(sql);
	char* d = pgsql_query_digest_and_first_comment(sql, len, &first_comment,
		(len < QUERY_DIGEST_BUF) ? buf : NULL, &opts);
	std::string ret = d ? d : "";
	if (d && d != buf) free(d);
	free(first_comment);
	return ret;
}

static std::string parsersql_digest(const char* sql) {
	SQP_par_t qp {};
	// PgSQL_Query_Info passes a length that includes the wire terminator.
	parsersql_digest_init_pgsql(&qp, sql, (int)strlen(sql) + 1);
	std::string ret = qp.digest_text ? qp.digest_text : "";
	if (qp.digest_text != qp.buf) free(qp.digest_text); // NOSONAR: C allocation by the adapter
	free(qp.first_comment); // NOSONAR: tokenizer comment ownership
	free(qp.query_prefix); // NOSONAR: query_parser_free ownership
	return ret;
}

// The query text as handle_SET_command builds it: block comments removed, trailing
// spaces and semicolons dropped. Same patterns as in PgSQL_Session.cpp.
static std::string session_query_text(const char* sql) {
	static const RE2 re_versioned_set_comment("^/\\*!\\d\\d\\d\\d\\d SET(.*)\\*/");
	static const RE2 re_inline_comment("(?U)/\\*.*\\*/");
	std::string nq = sql;
	RE2::GlobalReplace(&nq, re_versioned_set_comment, "SET\\1");
	RE2::GlobalReplace(&nq, re_inline_comment, "");
	nq.erase(nq.find_last_not_of(" ;") + 1);
	return nq;
}

// The session only calls handle_SET_command when the digest starts with "SET " (a digest
// that kept a leading comment never gets there, and is forwarded without a lock anyway).
// There, a SET it neither tracks nor recognises as SET TRANSACTION locks the hostgroup.
static void check_engine(const char* engine, const SqlCase& c, const std::string& digest) {
	const bool reaches_handler = strncasecmp(digest.c_str(), "SET ", 4) == 0;
	const std::string nq = session_query_text(c.sql);
	const bool locks = reaches_handler &&
		!PgSQL_Variables::is_set_transaction(re, digest.c_str(), nq.c_str());
	ok(locks == !c.forward, "%s: '%s' -> digest '%s' %s",
		engine, c.sql, digest.c_str(), c.forward ? "is forwarded without lock" : "still locks");
}

int main(int, char**) {
	test_init_minimal();
	pgsql_thread___query_digests_max_query_length = 65000;
	pgsql_thread___query_digests_max_digest_length = 65000;
	pgsql_thread___query_digests_grouping_limit = 3;
	pgsql_thread___query_digests_groups_grouping_limit = 1;
	pgsql_thread___query_digests_keep_comment = false;
	pgsql_thread___query_digests_lowercase = false;

	re = new Session_Regex(PgSQL_Variables::set_transaction_regexp());

	// 3 legacy shapes + 2 ParserSQL shapes per raw SQL case, + the helper's own checks.
	plan(digest_positive.size() + digest_negative.size() + sql_cases.size() * 5 + 4);
	diag("pattern: %s", PgSQL_Variables::set_transaction_regexp());

	for (const auto& d : digest_positive) {
		ok(matches(d), "digest '%s' matches", d.c_str());
	}
	for (const auto& d : digest_negative) {
		ok(!matches(d), "digest '%s' does not match", d.c_str());
	}

	// The ParserSQL 1.1.0 shape of SESSION CHARACTERISTICS: the digest alone matches.
	ok(!PgSQL_Variables::is_set_transaction(re, "SET TRANSACTION READ ONLY",
		"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"),
		"helper: a matching digest is not enough when the query text is session-wide");
	ok(!PgSQL_Variables::is_set_transaction(re, "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
		"SET TRANSACTION READ ONLY"), "helper: a matching query text is not enough either");
	ok(PgSQL_Variables::is_set_transaction(re, "SET TRANSACTION READ ONLY", " \t\n SET TRANSACTION READ ONLY"),
		"helper: leading whitespace in the query text is skipped");
	ok(!PgSQL_Variables::is_set_transaction(nullptr, "SET TRANSACTION READ ONLY", "SET TRANSACTION READ ONLY"),
		"helper: no regex, no match");

	for (const auto& c : sql_cases) {
		check_engine("legacy", c, legacy_digest(c.sql, false, false));
		check_engine("legacy lowercase", c, legacy_digest(c.sql, true, false));
		check_engine("legacy keep_comment", c, legacy_digest(c.sql, false, true));

		pgsql_thread___query_digests_lowercase = false;
		check_engine("parsersql", c, parsersql_digest(c.sql));
		pgsql_thread___query_digests_lowercase = true;
		check_engine("parsersql lowercase", c, parsersql_digest(c.sql));
		pgsql_thread___query_digests_lowercase = false;
	}

	delete re;
	test_cleanup_minimal();
	return exit_status();
}
