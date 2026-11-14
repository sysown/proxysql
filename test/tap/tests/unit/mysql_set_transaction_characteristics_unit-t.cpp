/**
 * @file mysql_set_transaction_characteristics_unit-t.cpp
 * @brief SET TRANSACTION with a list of characteristics is tracked (#6469).
 *
 * MySQL accepts `SET [SESSION|LOCAL] TRANSACTION characteristic [, characteristic]`,
 * where a characteristic is `ISOLATION LEVEL <level>` or `READ ONLY|WRITE`, each
 * at most once. MySQL_Session tracks a SET TRANSACTION whose digest matches
 * MYSQL_SET_TRANSACTION_DIGEST_REGEX (match_regexes[2]) with what
 * MySQL_Set_Stmt_Parser::parse2() returns; an empty result forwards the
 * statement and locks the hostgroup. In v3.0.11 parse2() parsed only the first
 * characteristic and returned nothing for a list, so the session lost
 * multiplexing and logged "Unable to parse unknown SET query".
 *
 * This test checks that:
 *  - parse2() returns every characteristic of the list, with the scope of the
 *    statement, for every isolation level, both access modes, both orders and
 *    the unscoped, SESSION and LOCAL forms;
 *  - parse2() returns nothing for lists that MySQL rejects (repeated
 *    characteristic, READ ONLY + READ WRITE, dangling or missing comma, other
 *    items), so these are still forwarded;
 *  - the ParserSQL 1.1.1 AST of the statement has the same characteristics, and
 *    rejects the same lists, as parse2();
 *  - match_regexes[2] matches the list on both the legacy and the ParserSQL
 *    (query_processor_parser=1) digest, and never matches GLOBAL, PERSIST or
 *    PERSIST_ONLY, which keep being forwarded.
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
#include "sql_parser/parser.h"
#include "sql_parser/ast.h"
#include "sql_parser/common.h"

#include <cstring>
#include <map>
#include <string>
#include <vector>

using SetMap = std::map<std::string, std::vector<std::string>>;

static std::string printable(const std::string& sql) {
	std::string shown = sql;
	for (char& c : shown) if (c == '\n' || c == '\t') c = ' ';
	return shown;
}

static std::string show(const SetMap& m) {
	if (m.empty()) return "nothing";
	std::string shown;
	for (const auto& entry : m) {
		shown += "[" + entry.first + "=";
		for (const auto& value : entry.second) shown += value;
		shown += "]";
	}
	return shown;
}

static SetMap parse2(const std::string& sql) {
	MySQL_Set_Stmt_Parser parser(sql);
	return parser.parse2();
}

/**
 * The characteristics of a SET [SESSION|LOCAL] TRANSACTION in the ParserSQL AST,
 * in the parse2() format. Empty if ParserSQL rejects the statement.
 */
static SetMap parsersql_characteristics(const std::string& sql) {
	using namespace sql_parser;
	static Parser<Dialect::MySQL> parser;
	SetMap result;
	const ParseResult r = parser.parse(sql.data(), sql.size());
	const AstNode* txn = (r.status == ParseResult::OK && r.full_input && r.ast &&
		r.ast->type == NodeType::NODE_SET_STMT) ? r.ast->first_child : nullptr;
	if (txn && txn->type == NodeType::NODE_SET_TRANSACTION && !txn->next_sibling) {
		std::string scope;
		bool ok_list = true;
		for (const AstNode* c = txn->first_child; c; c = c->next_sibling) {
			const std::string value(c->value_ptr, c->value_len);
			if (c->type == NodeType::NODE_IDENTIFIER) {
				scope = (value == "SESSION" || value == "LOCAL") ? "session" : "unexpected:" + value;
			} else if (c->type == NodeType::NODE_TRANSACTION_OPTION && value.compare(0, 16, "ISOLATION LEVEL ") == 0) {
				ok_list = result.emplace(scope + ":isolation level", std::vector<std::string>{value.substr(16)}).second && ok_list;
			} else if (c->type == NodeType::NODE_TRANSACTION_OPTION && value.compare(0, 5, "READ ") == 0) {
				ok_list = result.emplace(scope + ":read", std::vector<std::string>{value.substr(5)}).second && ok_list;
			} else {
				ok_list = false;
			}
		}
		if (!ok_list) result.clear();
	}
	parser.reset();
	return result;
}

/** Matched against the digest by MySQL_Session, as MySQL_Thread::match_regexes[2]. */
static Session_Regex* set_transaction_regex = nullptr;

static std::string legacy_digest(const std::string& sql) {
	options opts {};
	opts.lowercase = mysql_thread___query_digests_lowercase;
	opts.replace_null = mysql_thread___query_digests_replace_null;
	opts.replace_number = mysql_thread___query_digests_no_digits;
	opts.keep_comment = mysql_thread___query_digests_keep_comment;
	opts.grouping_limit = mysql_thread___query_digests_grouping_limit;
	opts.groups_grouping_limit = mysql_thread___query_digests_groups_grouping_limit;
	opts.max_query_length = mysql_thread___query_digests_max_query_length;
	char* comment = nullptr;
	char* text = mysql_query_digest_and_first_comment(sql.data(), sql.size(), &comment, nullptr, &opts);
	std::string digest = text ? text : "";
	free(text); // NOSONAR: tokenizer C allocation
	free(comment); // NOSONAR: tokenizer comment ownership
	return digest;
}

static std::string parser_digest(const std::string& sql) {
	SQP_par_t qp {};
	parsersql_digest_init_mysql(&qp, sql.data(), sql.size());
	std::string digest = qp.digest_text ? qp.digest_text : "";
	if (qp.digest_text != qp.buf) free(qp.digest_text); // NOSONAR: adapter C allocation
	free(qp.first_comment); // NOSONAR: tokenizer comment ownership
	free(qp.query_prefix); // NOSONAR: query_parser_free ownership
	return digest;
}

/** match_regexes[2] decides @p tracked on both the legacy and the ParserSQL digest. */
static void check_digests(const std::string& sql, bool tracked) {
	const std::string legacy = legacy_digest(sql);
	const std::string parser = parser_digest(sql);
	const bool legacy_match = !legacy.empty() && set_transaction_regex->match(legacy.c_str());
	const bool parser_match = !parser.empty() && set_transaction_regex->match(parser.c_str());
	ok(legacy_match == tracked && parser_match == tracked,
		"SET TRANSACTION regex %s [%s] (legacy '%s': %d, parser '%s': %d)",
		tracked ? "matches" : "does not match", printable(sql).c_str(),
		legacy.c_str(), legacy_match, parser.c_str(), parser_match);
}

/** parse2() returns @p expected, and ParserSQL finds the same characteristics. */
static void check_parse(const std::string& sql, const SetMap& expected) {
	const SetMap got = parse2(sql);
	ok(got == expected, "parse2() of [%s] returns %s (expected %s)", printable(sql).c_str(),
		show(got).c_str(), show(expected).c_str());
	const SetMap ast = parsersql_characteristics(sql);
	ok(ast == got, "ParserSQL agrees with parse2() on [%s] (ParserSQL: %s)", printable(sql).c_str(),
		show(ast).c_str());
}

static const char* const levels[] = {"READ UNCOMMITTED", "READ COMMITTED", "REPEATABLE READ", "SERIALIZABLE"};
static const char* const access_modes[] = {"ONLY", "WRITE"};

struct Scope { const char* sql; const char* key; };
static const Scope tracked_scopes[] = {{"", ""}, {"SESSION ", "session"}, {"LOCAL ", "session"}};

/** Every isolation level with every access mode, in both orders, for each tracked scope. */
static int test_valid_lists() {
	int n = 0;
	for (const Scope& scope : tracked_scopes) {
		for (const char* level : levels) {
			for (const char* mode : access_modes) {
				const SetMap expected {
					{std::string(scope.key) + ":isolation level", {level}},
					{std::string(scope.key) + ":read", {mode}},
				};
				const std::string head = std::string("SET ") + scope.sql + "TRANSACTION ";
				const std::string isolation = std::string("ISOLATION LEVEL ") + level;
				const std::string access = std::string("READ ") + mode;
				for (const std::string& sql : {head + isolation + ", " + access, head + access + ", " + isolation}) {
					check_parse(sql, expected);
					check_digests(sql, true);
					n += 3;
				}
			}
		}
	}
	return n;
}

/** Whitespace and case as sent by clients: the query is not normalized like the digest. */
static int test_spelling() {
	check_parse("SET TRANSACTION ISOLATION LEVEL READ COMMITTED,READ ONLY",
		{{":isolation level", {"READ COMMITTED"}}, {":read", {"ONLY"}}});
	check_parse("SET SESSION TRANSACTION READ WRITE ,\n ISOLATION  LEVEL REPEATABLE\tREAD",
		{{"session:isolation level", {"REPEATABLE READ"}}, {"session:read", {"WRITE"}}});
	check_parse("set local transaction read only, isolation level serializable",
		{{"session:isolation level", {"SERIALIZABLE"}}, {"session:read", {"ONLY"}}});
	check_parse("SET\tLOCAL\tTRANSACTION\tISOLATION\tLEVEL\tREAD\tUNCOMMITTED\t,\tREAD\tWRITE",
		{{"session:isolation level", {"READ UNCOMMITTED"}}, {"session:read", {"WRITE"}}});
	check_digests("SET SESSION TRANSACTION READ WRITE ,\n ISOLATION  LEVEL REPEATABLE\tREAD", true);
	check_digests("set local transaction read only, isolation level serializable", true);
	// Single characteristics are unchanged.
	check_parse("SET TRANSACTION READ ONLY", {{":read", {"ONLY"}}});
	check_parse("SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE", {{"session:isolation level", {"SERIALIZABLE"}}});
	check_parse("SET LOCAL TRANSACTION READ WRITE", {{"session:read", {"WRITE"}}});
	return 7 * 2 + 2;
}

/** MySQL rejects these: parse2() returns nothing and MySQL_Session forwards them as in v3.0.11. */
static int test_invalid_lists() {
	static const char* const invalid[] = {
		"SET TRANSACTION ISOLATION LEVEL READ COMMITTED, ISOLATION LEVEL SERIALIZABLE",
		"SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE, ISOLATION LEVEL SERIALIZABLE",
		"SET TRANSACTION READ ONLY, READ WRITE",
		"SET SESSION TRANSACTION READ WRITE, READ ONLY",
		"SET LOCAL TRANSACTION READ WRITE, READ WRITE",
		"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ ONLY, READ WRITE",
		"SET SESSION TRANSACTION READ ONLY, ISOLATION LEVEL SERIALIZABLE, ISOLATION LEVEL READ COMMITTED",
		"SET TRANSACTION READ ONLY,",
		"SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE ,",
		"SET TRANSACTION READ ONLY ISOLATION LEVEL SERIALIZABLE",
		"SET TRANSACTION READ ONLY, , ISOLATION LEVEL SERIALIZABLE",
		"SET TRANSACTION READ ONLY, WITH CONSISTENT SNAPSHOT",
		"SET SESSION TRANSACTION READ ONLY, SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE",
		"SET TRANSACTION READ ONLY TRANSACTION READ WRITE",
		"SET LOCAL TRANSACTION ISOLATION LEVEL SERIALIZABLE, autocommit=0",
		"SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ",
	};
	for (const char* sql : invalid) check_parse(sql, {});
	return 2 * (sizeof(invalid) / sizeof(invalid[0]));
}

/** GLOBAL, PERSIST and PERSIST_ONLY lists are never tracked: the digest does not match. */
static int test_untracked_scopes() {
	int n = 0;
	for (const char* scope : {"GLOBAL", "PERSIST", "PERSIST_ONLY"}) {
		const std::string head = std::string("SET ") + scope + " TRANSACTION ";
		for (const std::string& sql : {head + "ISOLATION LEVEL READ COMMITTED, READ ONLY",
			head + "READ WRITE, ISOLATION LEVEL SERIALIZABLE"}) {
			check_digests(sql, false);
			const SetMap got = parse2(sql);
			ok(got.empty(), "parse2() of [%s] returns nothing (got %s)", sql.c_str(), show(got).c_str());
			n += 2;
		}
	}
	return n;
}

int main() {
	// 4 levels x 2 modes x 2 orders x 3 scopes x 3 checks, spelling, invalid, untracked scopes.
	plan(4 * 2 * 2 * 3 * 3 + (7 * 2 + 2) + 2 * 16 + 3 * 2 * 2);
	test_init_minimal();
	mysql_thread___query_digests_max_query_length = 65000;
	mysql_thread___query_digests_max_digest_length = 2048;
	mysql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = 1;
	set_transaction_regex = new Session_Regex((char*)MYSQL_SET_TRANSACTION_DIGEST_REGEX);

	int n = 0;
	n += test_valid_lists();
	n += test_spelling();
	n += test_invalid_lists();
	n += test_untracked_scopes();
	diag("%d checks", n);

	delete set_transaction_regex;
	test_cleanup_minimal();
	return exit_status();
}
