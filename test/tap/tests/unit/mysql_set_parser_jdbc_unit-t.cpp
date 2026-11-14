/**
 * @file mysql_set_parser_jdbc_unit-t.cpp
 * @brief Unit coverage for the MariaDB Connector/J 3.5.11+ initialization SET
 *   statement (issue #6562) across every supported SET-parser backend.
 *
 * The connector sends:
 *
 *   set sql_mode=CONCAT(@@sql_mode,',STRICT_TRANS_TABLES'),
 *       session_track_system_variables=CONCAT('...',
 *           IF(LOCATE('*',@@session_track_system_variables)>0 OR
 *              FIND_IN_SET('last_gtid',
 *                  LOWER(REPLACE(@@session_track_system_variables,' ','')))>0,
 *              ',last_gtid','')),
 *       session_track_schema=1,NAMES utf8mb4
 *
 * ProxySQL must recognise every assignment so the statement can be acknowledged
 * locally. The session_track_system_variables value is backend-dependent and is
 * deliberately not evaluated here: the parser preserves it verbatim and the
 * session layer keeps treating it as an ignored variable.
 *
 * The test deliberately checks both positive coverage and the conservative
 * behaviour that must be preserved: malformed nesting and non-connector RHS
 * shapes still produce no parse result from the regex parsers. An unrecognised
 * *variable name* may still be parsed, as before; rejecting it is the session
 * layer's job and is covered end-to-end by the TAP routing test. The narrow
 * helper is also disabled for the rest of a statement once an ordinary parse
 * step has consumed adjacent input without a comma, so missing-delimiter
 * statements keep their pre-feature forward/lock fallback.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "MySQL_Set_Stmt_Parser.h"
#include "Query_Processor_ParserSQL.h"

#include <map>
#include <string>
#include <vector>

namespace {

constexpr const char* JDBC_SET =
	"set sql_mode=CONCAT(@@sql_mode,',STRICT_TRANS_TABLES'),"
	"session_track_system_variables=CONCAT('autocommit,character_set_client,"
	"character_set_connection,character_set_results,time_zone,tx_isolation',"
	"IF(LOCATE('*',@@session_track_system_variables)>0 OR "
	"FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')))>0,"
	"',last_gtid','')),session_track_schema=1,NAMES utf8mb4";

constexpr const char* JDBC_SET_SCOPED =
	"SET @@session.sql_mode=CONCAT(@@sql_mode,',STRICT_TRANS_TABLES'), "
	"@@session.session_track_system_variables=CONCAT('autocommit,character_set_client,"
	"character_set_connection,character_set_results,time_zone,tx_isolation',"
	"IF(LOCATE('*',@@session_track_system_variables)>0 OR "
	"FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')))>0,"
	"',last_gtid','')), SESSION session_track_schema=1, NAMES utf8mb4";

constexpr const char* JDBC_SET_REORDERED =
	"SET session_track_system_variables=CONCAT('autocommit,character_set_client,"
	"character_set_connection,character_set_results,time_zone,tx_isolation',"
	"IF(LOCATE('*',@@session_track_system_variables)>0 OR "
	"FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')))>0,"
	"',last_gtid','')), sql_mode=CONCAT(@@sql_mode,',STRICT_TRANS_TABLES'), "
	"session_track_schema=1, NAMES utf8mb4";

constexpr const char* JDBC_SET_BACKTICKED =
	"SET sql_mode=CONCAT(@@sql_mode,',STRICT_TRANS_TABLES'),"
	"`session_track_system_variables`=CONCAT('autocommit,character_set_client,"
	"character_set_connection,character_set_results,time_zone,tx_isolation',"
	"IF(LOCATE('*',@@session_track_system_variables)>0 OR "
	"FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')))>0,"
	"',last_gtid','')), `session_track_schema`=1,NAMES utf8mb4";

// Harmless outer case/whitespace changes only: the connector expression bytes
// are exactly the same as JDBC_SET.
constexpr const char* JDBC_SET_FORMATTED =
	"  set  sql_mode = CONCAT(@@sql_mode,',STRICT_TRANS_TABLES') , "
	"  SeSsIoN_Track_System_Variables = CONCAT('autocommit,character_set_client,"
	"character_set_connection,character_set_results,time_zone,tx_isolation',"
	"IF(LOCATE('*',@@session_track_system_variables)>0 OR "
	"FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')))>0,"
	"',last_gtid','')) ,  SESSION_TRACK_SCHEMA = 1 ,  names utf8mb4  ";

constexpr const char* SESSION_TRACK_VALUE =
	"CONCAT('autocommit,character_set_client,character_set_connection,"
	"character_set_results,time_zone,tx_isolation',"
	"IF(LOCATE('*',@@session_track_system_variables)>0 OR "
	"FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')))>0,"
	"',last_gtid',''))";

using SetMap = std::map<std::string, std::vector<std::string>>;

/**
 * @brief Builds the expected parse result for the connector initialization SET.
 * @return Map containing NAMES, the two session-tracking variables, and sql_mode.
 */
SetMap expected_jdbc_set() {
	return {
		{"names", {"utf8mb4"}},
		{"session_track_schema", {"1"}},
		{"session_track_system_variables", {SESSION_TRACK_VALUE}},
		{"sql_mode", {"CONCAT(@@sql_mode,',STRICT_TRANS_TABLES')"}},
	};
}

/**
 * @brief Emits TAP diagnostics for a parser result that did not match expectations.
 * @param parser Parser path that produced @p actual.
 * @param actual Parsed assignment map.
 */
void diag_map(const char* parser, const SetMap& actual) {
	diag("%s returned %zu assignment(s)", parser, actual.size());
	for (const auto& entry : actual) {
		for (const auto& value : entry.second) {
			diag("  %s = <%s>", entry.first.c_str(), value.c_str());
		}
	}
}

/**
 * @brief Checks that both regex SET parsers accept a supported connector variant.
 * @param query SET statement to parse.
 * @param label Human-readable variant name used in TAP output.
 */
void check_regex_parser(const char* query, const char* label) {
	MySQL_Set_Stmt_Parser legacy(query);
	MySQL_Set_Stmt_Parser current(query);
	const SetMap expected = expected_jdbc_set();
	const SetMap legacy_result = legacy.parse1();
	if (legacy_result != expected) diag_map("parse1", legacy_result);
	ok(legacy_result == expected, "parse1 recognises %s", label);
	const SetMap current_result = current.parse1v2();
	if (current_result != expected) diag_map("parse1v2", current_result);
	ok(current_result == expected, "parse1v2 recognises %s", label);
}

/**
 * @brief Checks that ParserSQL accepts a supported connector variant in both modes.
 * @param query SET statement to parse.
 * @param label Human-readable variant name used in TAP output.
 */
void check_parsersql(const char* query, const char* label) {
	const SetMap expected = expected_jdbc_set();
	ok(parsersql_parse_set_mysql(query, true) == expected,
		"ParserSQL recognises %s", label);
	ok(parsersql_parse_set_mysql(query, false) == expected,
		"ParserSQL (full statement) recognises %s", label);
}

/**
 * @brief Checks that both regex SET parsers reject a statement without a result.
 * @param query SET statement that must not be acknowledged by the regex parsers.
 * @param label Human-readable rejection case used in TAP output.
 */
void check_rejected(const std::string& query, const char* label) {
	const SetMap empty;
	MySQL_Set_Stmt_Parser legacy(query);
	MySQL_Set_Stmt_Parser current(query);
	ok(legacy.parse1() == empty, "parse1 rejects %s", label);
	ok(current.parse1v2() == empty, "parse1v2 rejects %s", label);
}

} // namespace

int main() {
	plan(NO_PLAN);
	test_init_minimal();

	const struct {
		const char* query;
		const char* label;
	} positives[] = {
		{JDBC_SET, "the connector SET"},
		{JDBC_SET_SCOPED, "the scoped connector SET"},
		{JDBC_SET_REORDERED, "the connector SET with reordered assignments"},
		{JDBC_SET_BACKTICKED, "the connector SET with paired backticks"},
		{JDBC_SET_FORMATTED, "the connector SET with harmless case/whitespace changes"},
	};
	for (const auto& c : positives) {
		check_regex_parser(c.query, c.label);
		check_parsersql(c.query, c.label);
	}

	// The narrow matcher must not accept any RHS outside the connector shape.
	// These forms keep the regex parsers' legacy "no result" outcome, leaving
	// the existing lock-vs-forward fallback behaviour untouched.
	const char* unsafe[] = {
		"SET session_track_system_variables=(SELECT GET_LOCK('x',1))",
		"SET session_track_system_variables=GET_LOCK('x',1)",
		"SET session_track_system_variables=BOGUS('a','b')",
		"SET session_track_system_variables=CONCAT('autocommit',IF(LOCATE('*',@@session_track_system_variables)>0,',last_gtid',''))",
		"SET session_track_system_variables=CONCAT('x',IF(@@sql_mode>0)",
		"SET @session_track_system_variables=CONCAT('autocommit',IF(LOCATE('*',@@session_track_system_variables)>0,',last_gtid',''))",
		// The connector shape with user-variable references inside the RHS.
		"SET session_track_system_variables=CONCAT('autocommit,character_set_client,character_set_connection,character_set_results,time_zone,tx_isolation',IF(LOCATE('*',@x)>0 OR FIND_IN_SET('last_gtid',LOWER(REPLACE(@x,' ','')))>0,',last_gtid',''))",
		// Likewise with user-variable assignment expressions in the RHS.
		"SET session_track_system_variables=CONCAT('autocommit,character_set_client,character_set_connection,character_set_results,time_zone,tx_isolation',IF(LOCATE('*',@x:=@@session_track_system_variables)>0 OR FIND_IN_SET('last_gtid',LOWER(REPLACE(@x:=@@session_track_system_variables,' ','')))>0,',last_gtid',''))",
	};
	for (const char* query : unsafe) {
		check_rejected(query, "a non-connector shape");
	}
	// Unmatched backticks are rejected even though the expression itself is the
	// connector shape.
	check_rejected(std::string("SET `session_track_system_variables=") + SESSION_TRACK_VALUE,
		"an unmatched opening backtick on the target");
	check_rejected(std::string("SET session_track_system_variables`=") + SESSION_TRACK_VALUE,
		"an unmatched closing backtick on the target");
	check_rejected(std::string("SET `session_track_system_variables`=") + SESSION_TRACK_VALUE +
		",`session_track_schema=1,NAMES utf8mb4",
		"an unmatched opening backtick on the adjacent schema");
	check_rejected(std::string("SET `session_track_system_variables`=") + SESSION_TRACK_VALUE +
		",session_track_schema`=1,NAMES utf8mb4",
		"an unmatched closing backtick on the adjacent schema");
	check_rejected(std::string(JDBC_SET) + "; SELECT 1",
		"a connector SET followed by a trailing statement");
	check_rejected(std::string("SET session_track_system_variables=") + SESSION_TRACK_VALUE + ",",
		"a connector expression followed by a dangling comma");
	for (const char* joined_or : {"OR", " OR", "OR "}) {
		std::string query = std::string("SET session_track_system_variables=") + SESSION_TRACK_VALUE;
		query.replace(query.find(" OR "), 4, joined_or);
		check_rejected(query, "a connector expression with joined OR tokens");
	}

	// A connector-shaped value must start at a real assignment boundary. The
	// legacy grammar can leave the next token after a simple RHS; accepting it
	// there would acknowledge malformed SQL and apply the preceding assignment.
	const std::string connector_assignment =
		std::string("session_track_system_variables=") + SESSION_TRACK_VALUE;
	const std::string missing_comma_sets[] = {
		std::string("SET autocommit=0 ") + connector_assignment,
		std::string("SET NAMES utf8mb4 ") + connector_assignment,
		std::string("SET sql_mode=CONCAT(@@sql_mode,',STRICT_TRANS_TABLES') ") +
			connector_assignment,
		// A missing delimiter earlier in the statement must not be repaired by
		// a later comma: once the ordinary grammar has accepted adjacent
		// assignments, the connector helper stays disabled for the statement.
		std::string("SET autocommit=0 sql_mode='',") + connector_assignment,
		std::string("SET NAMES utf8mb4 sql_mode='ANSI',") + connector_assignment,
		// Once the connector expression succeeds, a following ordinary
		// assignment that leaves input without consuming a delimiter must
		// reject the whole parse.
		std::string("SET session_track_system_variables=") + SESSION_TRACK_VALUE +
			",autocommit=0 sql_mode='ANSI'",
		std::string("SET session_track_system_variables=") + SESSION_TRACK_VALUE +
			",autocommit=0 sql_mode='ANSI',sql_mode='ANSI'",
	};
	for (const std::string& query : missing_comma_sets) {
		check_rejected(query, "a connector expression without an assignment delimiter");
	}

	// A user-variable RHS on the ignored variable is outside the connector
	// shape, but the legacy parser already accepts it as a plain value. Keep
	// that pre-existing behaviour rather than widening this fix; the session
	// still ignores the variable.
	const char* user_rhs = "SET session_track_system_variables=@jdbc_tracking";
	const SetMap legacy_user = {{"session_track_system_variables", {"@jdbc_tracking"}}};
	MySQL_Set_Stmt_Parser legacy_user_parser(user_rhs);
	MySQL_Set_Stmt_Parser current_user_parser(user_rhs);
	ok(legacy_user_parser.parse1() == legacy_user,
		"parse1 keeps the pre-existing plain-value handling for a user-variable RHS");
	ok(current_user_parser.parse1v2() == legacy_user,
		"parse1v2 keeps the pre-existing plain-value handling for a user-variable RHS");

	// Keep commas within quoted values and nested function arguments while
	// bounding the legacy parser's otherwise greedy ordinary value match.
	for (const std::string& sql_mode : {std::string("'ANSI'"),
		std::string("'ANSI,STRICT_TRANS_TABLES'"),
		std::string("CONCAT(@@sql_mode,',ANSI')")}) {
		const std::string query =
			std::string("SET session_track_system_variables=") + SESSION_TRACK_VALUE +
			",autocommit=0,sql_mode=" + sql_mode;
		MySQL_Set_Stmt_Parser legacy(query);
		MySQL_Set_Stmt_Parser current(query);
		const auto legacy_result = legacy.parse1();
		const auto current_result = current.parse1v2();
		for (const auto& parsed : {legacy_result, current_result}) {
			ok(parsed.size() == 3 && parsed.count("session_track_system_variables") &&
				parsed.count("autocommit") && parsed.at("autocommit") == std::vector<std::string>{"0"} &&
				parsed.count("sql_mode"),
				"both parsers preserve comma-separated neighbours after the connector (%s)", sql_mode.c_str());
		}
	}

	test_cleanup_minimal();
	return exit_status();
}
