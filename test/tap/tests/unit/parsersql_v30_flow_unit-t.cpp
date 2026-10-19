/** v3.0 retains its experimental ParserSQL digest path (#6507). */
#include "tap.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"
#include "Query_Processor_ParserSQL.h"
#include "sql_parser/parser.h"
#include "sql_parser/emitter.h"
#include "sql_parser/digest.h"
#include "c_tokenizer.h"
#include "mysql_connection.h"
#include <cstring>
#include <string>

#if defined(__linux__) && !defined(PROXYSQL31)
static unsigned legacy_calls;
static unsigned command_parse_calls;
extern "C" char* __real_mysql_query_digest_and_first_comment(const char*, int, char**, char*, const options*);
extern "C" char* __real_pgsql_query_digest_and_first_comment(const char*, int, char**, char*, const options*);
extern "C" char* __wrap_mysql_query_digest_and_first_comment(const char* s, int n, char** c, char* b, const options* o) {
	++legacy_calls;
	return __real_mysql_query_digest_and_first_comment(s,n,c,b,o);
}
extern "C" char* __wrap_pgsql_query_digest_and_first_comment(const char* s, int n, char** c, char* b, const options* o) {
	++legacy_calls;
	return __real_pgsql_query_digest_and_first_comment(s,n,c,b,o);
}
extern "C" MYSQL_COM_QUERY_command __real__Z28parsersql_command_type_mysqlPKci(const char*, int);
extern "C" PGSQL_QUERY_command __real__Z28parsersql_command_type_pgsqlPKci(const char*, int);
extern "C" MYSQL_COM_QUERY_command __wrap__Z28parsersql_command_type_mysqlPKci(const char* s, int n) {
	++command_parse_calls;
	return __real__Z28parsersql_command_type_mysqlPKci(s,n);
}
extern "C" PGSQL_QUERY_command __wrap__Z28parsersql_command_type_pgsqlPKci(const char* s, int n) {
	++command_parse_calls;
	return __real__Z28parsersql_command_type_pgsqlPKci(s,n);
}

template<sql_parser::Dialect D> static void check(const char* sql) {
	using namespace sql_parser;
	Parser<D> native;
	const size_t length = strlen(sql);
	const auto parsed = native.parse(sql, length);
	StringRef expected;
	Emitter<D> emitter(native.arena(), EmitMode::DIGEST);
	Digest<D> token_digest(native.arena());
	if (parsed.status == ParseResult::OK && parsed.full_input && parsed.ast) {
		emitter.emit(parsed.ast);
		expected = emitter.result();
	} else {
		expected = token_digest.compute(sql, length).normalized;
	}
	const std::string expected_text(expected.ptr ? expected.ptr : "", expected.len);
	SQP_par_t qp {};
	legacy_calls = command_parse_calls = 0;
	if constexpr(D == Dialect::MySQL) parsersql_digest_init_mysql(&qp, sql, length);
	else parsersql_digest_init_pgsql(&qp, sql, length);
	ok(legacy_calls == 0, "dialect=%d [%s]: parser digest does not invoke legacy digest (%u calls)", int(D), sql, legacy_calls);
	ok(qp.first_comment == nullptr, "dialect=%d [%s]: v3.0 parser first-comment limitation", int(D), sql);
	ok(qp.digest_text && expected_text == qp.digest_text, "dialect=%d [%s]: native ParserSQL digest expected [%s], got [%s]", int(D), sql, expected_text.c_str(), qp.digest_text ? qp.digest_text : "NULL");
	ok(qp.digest == SpookyHash::Hash64(expected_text.data(), expected_text.size(), 0), "dialect=%d [%s]: ProxySQL keeps SpookyHash", int(D), sql);
	if constexpr(D == Dialect::MySQL) MySQL_Query_Processor::query_parser_command_type(&qp);
	else PgSQL_Query_Processor::query_parser_command_type(&qp);
	ok(command_parse_calls == 0, "dialect=%d [%s]: classification reuses digest parse (%u additional parses)", int(D), sql, command_parse_calls);
	if(qp.digest_text != qp.buf) free(qp.digest_text);
	free(qp.first_comment);
	free(qp.query_prefix);
}
#endif

int main() {
#if !defined(__linux__) || defined(PROXYSQL31)
	plan(1);
	skip(1, "v3.0 flow regression uses GNU linker wrappers");
#else
	plan(NO_PLAN);
	test_init_minimal();
	mysql_thread___query_processor_parser = pgsql_thread___query_processor_parser = 1;
	mysql_thread___query_digests_max_query_length = pgsql_thread___query_digests_max_query_length = 65000;
	mysql_thread___query_digests_max_digest_length = pgsql_thread___query_digests_max_digest_length = 2048;
	mysql_thread___query_digests_grouping_limit = pgsql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit = 1;
	for (const char* sql : {"SELECT 1", "/* hostgroup=20 */ SELECT 1", "SELECT * FROM t WHERE id IN (1,2,3,4)", "INSERT INTO t VALUES (1,2)", "SELECT GET_LOCK('x', 1)"}) {
		check<sql_parser::Dialect::MySQL>(sql);
		check<sql_parser::Dialect::PostgreSQL>(sql);
	}
	const std::string long_query = "SELECT " + std::string(512, 'a');
	check<sql_parser::Dialect::MySQL>(long_query.c_str());
	check<sql_parser::Dialect::PostgreSQL>(long_query.c_str());
	// The AST can fit while digest emission exhausts its arena.
	const std::string large_identifier = "SELECT " + std::string(600000, 'a');
	for (const auto initialize : {parsersql_digest_init_mysql, parsersql_digest_init_pgsql}) {
		SQP_par_t qp {};
		legacy_calls = 0;
		initialize(&qp, large_identifier.data(), large_identifier.size());
		ok(qp.digest_text && strlen(qp.digest_text) == 65000 && legacy_calls == 1,
			"digest-emitter arena exhaustion uses the bounded legacy fallback");
		if (qp.digest_text != qp.buf) free(qp.digest_text);
		free(qp.first_comment);
	}
	std::string nul_identifier = "SELECT `x";
	nul_identifier.push_back('\0');
	nul_identifier += std::string(1000, 'a') + "`";
	for (const auto initialize : {parsersql_digest_init_mysql, parsersql_digest_init_pgsql}) {
		SQP_par_t qp {};
		initialize(&qp, nul_identifier.data(), nul_identifier.size());
		ok(qp.digest_text && qp.digest == SpookyHash::Hash64(qp.digest_text, strlen(qp.digest_text), 0),
			"embedded NUL cannot mismatch digest text length and hash allocation");
		if (qp.digest_text != qp.buf) free(qp.digest_text);
		free(qp.first_comment);
	}
	for (const char* sql : {"SET @a=1, wait_timeout=10", "SET sql_mode='', @a=1"}) {
		const auto result = parsersql_analyze_user_variable_set_mysql(sql, strlen(sql));
		ok(result.status == UserVariableSetStatus::UNSUPPORTED,
			"v3.0 mixed SET uses backend-bound fallback: %s", sql);
	}
	const char* pure = "SET @a=1, @b='hello'";
	const auto supported = parsersql_analyze_user_variable_set_mysql(pure, strlen(pure));
	ok(supported.status == UserVariableSetStatus::SUPPORTED && supported.assignments.size() == 2,
		"v3.0 preserves pure literal user-variable tracking");
	MySQL_User_Variable_State frontend, backend, staged;
	ok(frontend.stage(supported.assignments, staged) == MySQL_User_Variable_Apply_Result::OK &&
		frontend.size() == 0 && backend.size() == 0,
		"v3.0 preflight leaves frontend/backend assignments uncommitted");
	ok(mysql_user_variable_commit_post_ok(frontend, backend, supported.assignments) &&
		frontend.size() == 2 && backend.size() == 2,
		"v3.0 post-OK commit updates both variable maps");
	const auto before = frontend.diagnostic_fingerprint();
	auto oversized = supported.assignments;
	oversized[0].raw_literal = std::string(MySQL_User_Variable_State::MAX_STORED_BYTES + 1, 'x');
	ok(!mysql_user_variable_commit_post_ok(frontend, backend, oversized) &&
		frontend.diagnostic_fingerprint() == before && backend.diagnostic_fingerprint() == before,
		"v3.0 failed commit preserves both previously committed maps");
	const auto replay = frontend.build_replay_plan(MySQL_User_Variable_State{}, 4096);
	ok(replay.batches.size() == 1 && replay.batches[0].sql == "SET @a=1,@b='hello'",
		"v3.0 replay preserves the original raw literals");
	test_cleanup_minimal();
#endif
	return exit_status();
}
