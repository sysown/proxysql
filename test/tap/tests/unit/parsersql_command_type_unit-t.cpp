/**
 * @file parsersql_command_type_unit-t.cpp
 * @brief MySQL command classification with query_processor_parser=1 matches legacy for KILL & co.
 *
 * Regression test for #6421: ParserSQL has no statement type for KILL, so with
 * mysql-query_processor_parser=1 MySQL_Query_Processor::query_parser_command_type()
 * returned MYSQL_COM_QUERY_UNKNOWN for KILL [CONNECTION|QUERY] N. MySQL_Session
 * intercepts KILL only when the command is MYSQL_COM_QUERY_KILL, so the
 * statement was forwarded to an arbitrary backend, where the ProxySQL session id
 * is meaningless (or names an unrelated backend thread).
 *
 * When ParserSQL classifies a statement as UNKNOWN, the classification must now
 * fall back to the legacy tokenizer classifier, i.e. be identical to
 * query_processor_parser=0. Statements ParserSQL does classify keep the
 * ParserSQL mapping.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Query_Processor.h"
#include "Query_Processor_ParserSQL.h"
#include "c_tokenizer.h"

#include <cstring>
#include <string>

static void release(SQP_par_t& qp) {
	if (qp.digest_text != qp.buf) free(qp.digest_text); // NOSONAR: adapter C allocation
	free(qp.first_comment); // NOSONAR: tokenizer comment ownership
	free(qp.query_prefix); // NOSONAR: query_parser_free ownership
	qp = SQP_par_t {};
}

static options legacy_options() {
	options opts {};
	opts.lowercase = mysql_thread___query_digests_lowercase;
	opts.replace_null = mysql_thread___query_digests_replace_null;
	opts.replace_number = mysql_thread___query_digests_no_digits;
	opts.keep_comment = mysql_thread___query_digests_keep_comment;
	opts.grouping_limit = mysql_thread___query_digests_grouping_limit;
	opts.groups_grouping_limit = mysql_thread___query_digests_groups_grouping_limit;
	opts.max_query_length = mysql_thread___query_digests_max_query_length;
	return opts;
}

/** Command type as computed with query_processor_parser=0 (legacy digest + legacy classifier). */
static MYSQL_COM_QUERY_command legacy_command(const std::string& sql) {
	const options opts = legacy_options();
	SQP_par_t qp {};
	qp.parsersql_stmt_type = -1;
	qp.digest_text = mysql_query_digest_and_first_comment(sql.data(), sql.size(), &qp.first_comment, qp.buf, &opts);
	mysql_thread___query_processor_parser = 0;
	const MYSQL_COM_QUERY_command cmd = MySQL_Query_Processor::query_parser_command_type(&qp);
	release(qp);
	return cmd;
}

/** Command type as computed with query_processor_parser=1 (ParserSQL digest + classifier). */
static MYSQL_COM_QUERY_command parser_command(const std::string& sql, int* stmt_type = nullptr) {
	SQP_par_t qp {};
	parsersql_digest_init_mysql(&qp, sql.data(), sql.size());
	if (stmt_type) *stmt_type = qp.parsersql_stmt_type;
	mysql_thread___query_processor_parser = 1;
	const MYSQL_COM_QUERY_command cmd = MySQL_Query_Processor::query_parser_command_type(&qp);
	mysql_thread___query_processor_parser = 0;
	release(qp);
	return cmd;
}

/**
 * Command type with query_digests=0 and commands_stats=1: no digest, only a
 * 32-byte query prefix, which query_parser_command_type() must free.
 */
static MYSQL_COM_QUERY_command prefix_command(const std::string& sql, int parser, bool* prefix_freed) {
	SQP_par_t qp {};
	qp.parsersql_stmt_type = -1;
	qp.query_prefix = strndup(sql.data(), sql.size() < 32 ? sql.size() : 32);
	mysql_thread___query_processor_parser = parser;
	const MYSQL_COM_QUERY_command cmd = MySQL_Query_Processor::query_parser_command_type(&qp);
	mysql_thread___query_processor_parser = 0;
	*prefix_freed = (qp.query_prefix == nullptr);
	release(qp);
	return cmd;
}

static const char* const kill_cases[] = {
	"KILL 42",
	"KILL QUERY 42",
	"KILL CONNECTION 42",
	"kill 42",
	"kill query 42",
	"Kill Connection 42",
	"KILL  QUERY\t42",
	"/* comment */ KILL 42",
	"KILL 42;",
};

// Statements ParserSQL reports as UNKNOWN that the legacy classifier recognizes.
static const struct { const char* sql; MYSQL_COM_QUERY_command expected; } legacy_only_cases[] = {
	{ "FLUSH LOGS", MYSQL_COM_QUERY_FLUSH },
	{ "RELEASE SAVEPOINT sp1", MYSQL_COM_QUERY_RELEASE_SAVEPOINT },
	{ "OPTIMIZE TABLE t1", MYSQL_COM_QUERY_OPTIMIZE },
	{ "PURGE BINARY LOGS TO 'mysql-bin.000010'", MYSQL_COM_QUERY_PURGE },
	{ "CHANGE MASTER TO MASTER_HOST='h1'", MYSQL_COM_QUERY_CHANGE_MASTER },
	{ "RESET MASTER", MYSQL_COM_QUERY_RESET_MASTER },
	{ "RESET REPLICA", MYSQL_COM_QUERY_RESET_REPLICA },
};

// Statements ParserSQL classifies: the ParserSQL mapping must be kept.
static const struct { const char* sql; MYSQL_COM_QUERY_command expected; } parser_cases[] = {
	{ "SELECT 1", MYSQL_COM_QUERY_SELECT },
	{ "SELECT * FROM t1 WHERE id = 42", MYSQL_COM_QUERY_SELECT },
	{ "INSERT INTO t1 VALUES (1)", MYSQL_COM_QUERY_INSERT },
	{ "UPDATE t1 SET a = 1", MYSQL_COM_QUERY_UPDATE },
	{ "DELETE FROM t1", MYSQL_COM_QUERY_DELETE },
	{ "SET autocommit = 0", MYSQL_COM_QUERY_SET },
	{ "BEGIN", MYSQL_COM_QUERY_BEGIN },
	{ "COMMIT", MYSQL_COM_QUERY_COMMIT },
	{ "USE test", MYSQL_COM_QUERY_USE },
};

int main() {
	const size_t n_kill = sizeof(kill_cases) / sizeof(kill_cases[0]);
	const size_t n_legacy = sizeof(legacy_only_cases) / sizeof(legacy_only_cases[0]);
	const size_t n_parser = sizeof(parser_cases) / sizeof(parser_cases[0]);
	plan(3 * n_kill + 3 * n_legacy + 2 * n_parser + 2 * 4 + 2);
	test_init_minimal();
	mysql_thread___query_digests_max_query_length = 65000;
	mysql_thread___query_digests_max_digest_length = 2048;
	mysql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = 1;
	mysql_thread___query_digests_lowercase = 0;
	mysql_thread___query_digests_no_digits = 0;

	for (const char* sql : kill_cases) {
		int stmt_type = -1;
		const MYSQL_COM_QUERY_command parser = parser_command(sql, &stmt_type);
		ok(stmt_type >= 0 && parsersql_stmt_type_to_mysql_command(stmt_type) == MYSQL_COM_QUERY_UNKNOWN,
			"ParserSQL has no statement type for [%s] (stmt_type: %d)", sql, stmt_type);
		ok(parser == MYSQL_COM_QUERY_KILL, "parser=1 classifies [%s] as KILL (got: %d)", sql, parser);
		ok(parser == legacy_command(sql), "parser=1 and parser=0 classify [%s] identically", sql);
	}

	for (const auto& c : legacy_only_cases) {
		const MYSQL_COM_QUERY_command parser = parser_command(c.sql);
		const MYSQL_COM_QUERY_command legacy = legacy_command(c.sql);
		ok(legacy == c.expected, "parser=0 classifies [%s] as %d (got: %d)", c.sql, c.expected, legacy);
		ok(parser == c.expected, "parser=1 classifies [%s] as %d (got: %d)", c.sql, c.expected, parser);
		ok(parser == legacy, "parser=1 and parser=0 classify [%s] identically", c.sql);
	}

	for (const auto& c : parser_cases) {
		int stmt_type = -1;
		const MYSQL_COM_QUERY_command parser = parser_command(c.sql, &stmt_type);
		ok(parser == c.expected, "parser=1 classifies [%s] as %d (got: %d)", c.sql, c.expected, parser);
		ok(stmt_type >= 0 && parser == parsersql_stmt_type_to_mysql_command(stmt_type),
			"parser=1 keeps the ParserSQL mapping for [%s]", c.sql);
	}

	// query_digests=0: classification from the query prefix, prefix released in both modes.
	for (const char* sql : { "KILL 42", "KILL QUERY 42" }) {
		bool freed = false;
		MYSQL_COM_QUERY_command cmd = prefix_command(sql, 1, &freed);
		ok(cmd == MYSQL_COM_QUERY_KILL, "parser=1 classifies prefix [%s] as KILL (got: %d)", sql, cmd);
		ok(freed, "parser=1 frees the query prefix for [%s]", sql);
		cmd = prefix_command(sql, 0, &freed);
		ok(cmd == MYSQL_COM_QUERY_KILL, "parser=0 classifies prefix [%s] as KILL (got: %d)", sql, cmd);
		ok(freed, "parser=0 frees the query prefix for [%s]", sql);
	}
	{
		bool freed = false;
		const MYSQL_COM_QUERY_command cmd = prefix_command("SELECT 1", 1, &freed);
		ok(cmd == MYSQL_COM_QUERY_SELECT, "parser=1 classifies prefix [SELECT 1] as SELECT (got: %d)", cmd);
		ok(freed, "parser=1 frees the query prefix for a ParserSQL-classified statement");
	}

	test_cleanup_minimal();
	return exit_status();
}
