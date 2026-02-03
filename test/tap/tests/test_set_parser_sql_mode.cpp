/**
 * @file test_set_parser_parity.cpp
 * @brief Checks that the SQL based SET statement parser is on pair with the previous REGEX based one.
 */

// NOTE: Avoids the definition of 'global_variables glovars' in 'proxysql_structs.h'
#include "proxysql_structs.h"

#include "MySQL_SET_Parser_Utils.h" // For SQL parser utilities; p_match_1, etc...

// NOTE: Avoids definition of 'proxy_sqlite3_*' functions as 'extern'
#define MAIN_PROXY_SQLITE3
#include "sqlite3db.h" // IWYU pragma: keep
#include "MySQL_LDAP_Authentication.hpp"

#include "MySQL_Parser.h"
#include "proxysql_utils.h"

#include "ezOptionParser.hpp"

#include "tap.h"
#include "utils.h"

#include <unistd.h>
#include <sys/ioctl.h>

#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <memory>
#include <vector>

#include "json.hpp"

using std::fstream;
using std::pair;
using std::string;
using std::string_view;
using std::unique_ptr;
using std::vector;

MySQL_LDAP_Authentication *GloMyLdapAuth = nullptr;

/**
 * @brief Basic queries.
 */
const vector<string> set_queries {
	"SET sql_mode = 'STRICT_TRANS_TABLES', character_set_client = 'utf8mb4';",
};

// Cases from 'setparser_test.cpp': extracted via 'ack -o "\"SET.*?\"," $path'; filtered for sql_mode
const vector<string> setparser_queries {
	"SET @@sql_mode = 'TRADITIONAL'",
	"SET SESSION sql_mode = 'TRADITIONAL'",
	"SET @@session.sql_mode = 'TRADITIONAL'",
	"SET @@local.sql_mode = 'TRADITIONAL'",
	"SET sql_mode = 'TRADITIONAL'",
	"SET SQL_MODE   ='TRADITIONAL'",
	"SET SQL_MODE  = \"TRADITIONAL\"",
	"SET SQL_MODE  = TRADITIONAL",
	"SET @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')",
	"SET @@LOCAL.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')",
	"SET sql_mode = 'NO_ZERO_DATE,STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY'",
	"SET @@sql_mode = CONCAT(@@sql_mode, ',', 'ONLY_FULL_GROUP_BY')",
	"SET @@sql_mode = REPLACE(REPLACE(REPLACE(@@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')",
	"SET @@sql_mode = REPLACE( REPLACE( REPLACE( @@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')",
	"SET SQL_MODE=IFNULL(@@sql_mode,'')",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION')), time_zone = '+00:00', NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
	"SET sql_mode=''",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))",
	"SET sql_mode = 'TRADITIONAL', NAMES 'utf8' COLLATE 'unicode_ci'",
	"SET  @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO')",
	"SET  @@LOCAL.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO')",
	"SET NAMES utf8, @@SESSION.sql_mode = CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO'), @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 3600",
	"SET NAMES utf8, @@LOCAL.sql_mode = CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO'), @@LOCAL.sql_auto_is_null = 0, @@LOCAL.wait_timeout = 3600",
};

/**
 * @brief Expressions targetting 'sql_mode' special handling ('verf_sql_mode_val').
 * @details The spec for valid `sql_mode` expressions can be seeing in `verf_sql_mode_val` doc.
 */
const vector<string> valid_sql_mode_subexprs {
	// String literal
	"SET sql_mode=\"NO_AUTO_VALUE_ON_ZERO\"",
	"SET sql_mode = \"NO_AUTO_VALUE_ON_ZERO\"",
	// Valid 'system_var'
	"SET sql_mode=@@sql_mode",
	"SET sql_mode=  @@sql_mode",
	// Expressions - Function calls
	"SET sql_mode=\"CONCAT(@@sql_mode, 'STRICT_ALL_TABLES')\"",
	"SET sql_mode=\"REPLACE(@@sql_mode, 'STRICT_ALL_TABLES', 'STRICT_TRANS_TABLES')\"",
	// Expressions - Simple SELECT STRING_LITERAL
	"SET sql_mode=\"(SELECT 'STRICT_ALL_TABLES')\"",
	// Expressions - Function calls + SELECT STRING_LITERAL
	"SET sql_mode=\"CONCAT(@@sql_mode, (SELECT ',STRICT_ALL_TABLES'))\"",
	// SUB-SELECT Literals
	"SET sql_mode=(SELECT 'foo')",
	"SET sql_mode=(SELECT \"foo\")",
	// Valid cases WORKING under REGEX impl
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, NULL))",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, 'foo'))",
	// Valid cases FAILING under REGEX impl
	"SET sql_mode=(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', (SELECT 'foo')))",
	"SET sql_mode=(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', '5'))"
};

/**
 * @brief For testing 'sql_mode' special error handling. Correctly parsed but denied due to AST properties.
 * @details TODO: This requires a special test, current covering is insufficient.
 */
const vector<pair<string,perr_t>> invalid_sql_mode_subexprs {
	{ "SET sql_mode=(SELECT @user_var)",
		{
			-1,
			"Failed to verify 'sql_mode' with value=`(SELECT @user_var)`",
			{
				"Found invalid SUBSELECT expr=`(SELECT @user_var)`",
				"Invalid node=`USER_VAR` found in path=`[(SELECT_STMT,0),(SELECT_ITEM_LIST,1),(SELECT_ITEM,0),(UNKNOWN,0)]`"
			}
		}
	},
	{ "SET sql_mode=(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', (SELECT @sys_var)))",
		{
			-1,
			"Failed to verify 'sql_mode' with value=`(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', (SELECT @sys_var)))`",
			{
				"Found invalid SUBSELECT expr=`(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', (SELECT @sys_var)))`",
				"Failed to verify SUBSELECT with expected AST=`[(SELECT_STMT,0),(SELECT_ITEM_LIST,1),(SELECT_ITEM,0),(STRING_LITERAL,0)]`",
			}
		}
	},
	{ "SET sql_mode=(SELECT 5)",
		{
			-1,
			"Failed to verify 'sql_mode' with value=`(SELECT 5)`",
			{
				"Found invalid SUBSELECT expr=`(SELECT 5)`",
				"Invalid node=`NUMBER_LITERAL` found in path=`[(SELECT_STMT,0),(SELECT_ITEM_LIST,1),(SELECT_ITEM,0),(UNKNOWN,0)]`"
			}
		}
	},
	{ "SET sql_mode=(SELECT NULL)",
		{
			-1,
			"Failed to verify 'sql_mode' with value=`(SELECT NULL)`",
			{
				"Found invalid SUBSELECT expr=`(SELECT NULL)`",
				"Invalid node=`NULL_LITERAL` found in path=`[(SELECT_STMT,0),(SELECT_ITEM_LIST,1),(SELECT_ITEM,0),(UNKNOWN,0)]`"
			}
		}
	},
	{ "SET SQL_MODE=IFNULL(@old_sql_mode,'')",
		{
			-1,
			"Failed to verify 'sql_mode' with value=`IFNULL(@old_sql_mode,'')`",
			{
				"Invalid sysvar or literal=(value=`old_sql_mode`, type=`USER_VAR`)"
			}
		}
	},
	{ "SET SQL_MODE=IFNULL(@OLD_SQL_MODE,'')",
		{
			-1,
			"Failed to verify 'sql_mode' with value=`IFNULL(@OLD_SQL_MODE,'')`",
			{
				"Invalid sysvar or literal=(value=`OLD_SQL_MODE`, type=`USER_VAR`)"
			}
		}
	},
	{ "SET sql_mode=(SELCT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))",
		{
			-1, "ParsingFailure: Only context errors required",
			{
				"syntax error, unexpected TOKEN_IDENTIFIER, expecting TOKEN_RPAREN or TOKEN_AND or TOKEN_XOR or TOKEN_OR"
			}
		}
	},
	{ "SET sql_mode = 'TRADITIONAL', NAMES 'utf8 COLLATE 'unicode_ci'",
		{
			-1, "ParsingFailure: Only context errors required",
			{
				"syntax error, unexpected TOKEN_IDENTIFIER, expecting end of file or TOKEN_SEMICOLON"
			}
		}
	},
	{ "SET sql_mode=(SELECT CONCAT(@@sys_var, 'foo')",
		{
			-1, "ParsingFailure: Only context errors required",
			{
				"syntax error, unexpected end of file"
			}
		}
	},
	{ "SET sql_mode=(SELECT CONCA(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
		{
			-1,
			"Failed to verify 'sql_mode' with value=`(SELECT CONCA(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))`",
			{
				"Found invalid SUBSELECT expr=`(SELECT CONCA(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))`",
				"Found invalid function=`CONCA`"
			}
		}
	},
	{ "SET sql_mode=(SELECT CONCAT(@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
		{
			-1,
			"Failed to verify 'sql_mode' with value=`(SELECT CONCAT(@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))`",
			{
				"Found invalid SUBSELECT expr=`(SELECT CONCAT(@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))`",
				"Invalid sysvar or literal=(value=`sql_mode`, type=`USER_VAR`)"
			}
		}
	},
};

struct cmd_opts_t {
	bool verbose;
	string query;
};

rc_t<cmd_opts_t> get_cmd_options(int argc, const char* argv[]) {
	// command line options to extract
	cmd_opts_t opts { false, {} };

	// define the command line options
	ez::ezOptionParser opt_p {};
	opt_p.overview = "TAP test checking SQL parser capabilities for handling 'sql_mode'";
	opt_p.syntax = "test_set_parser_sql_mode [OPTIONS]";
	opt_p.footer = "\n\nHave fun :)";

	// clang-format off
	opt_p.add(
		(const char *)"", 0, 0, 0, (const char *)"Display usage instructions.",
		(const char *)"-h", (const char *)"-help", (const char *)"--help", (const char *)"--usage"
	);
	opt_p.add(
		(const char *)"", 0, 0, 0, (const char *)"Enable verbose output",
		(const char *)"-v", (const char *)"--verbose"
	);
	opt_p.add(
		(const char *)"", 0, 1, 0, (const char *)"Process single input query",
		(const char *)"-q", (const char *)"--query"
	);
	// clang-format on

	// parse the arguments
	opt_p.parse(argc, argv);

	// extract command line options
	if (opt_p.isSet("-h")) {
		std::string usage {};
		opt_p.getUsage(usage);
		std::cout << usage << std::endl;

		exit(EXIT_SUCCESS);
	}
	if (opt_p.isSet("-v")) {
		opts.verbose = true;
	}
	if (opt_p.isSet("-q")) {
		opt_p.get("-q")->getString(opts.query);
	}

	int n { 0 };
	if (ioctl(STDIN_FILENO, FIONREAD, &n)) {
		std::cerr << "ioctl: Failed to read number of bytes in stdin   errno=" << errno << "\n";
		return { EXIT_FAILURE, {} };
	}

	if (n > 0) {
		string line {};
		string cin_query {};

		while (std::getline(std::cin, line)) {
			opts.query += line + "\n";
		}
	}

	return { 0, opts };
}

rc_t<bool> check_sess_scope(const MySQLParser::AstNode* node) {
	using MySQLParser::NodeType;

	if (node->type != NodeType::NODE_VARIABLE_ASSIGNMENT) {
		return { -1, false };
	}

	const auto scope { get_node(node,
		{{ NodeType::NODE_UNKNOWN, 0 }, { NodeType::NODE_VARIABLE_SCOPE, 0 }})
	};

	if (scope.first == -1) {
		return { 0, true };
	} else {
		return { 0, scope.second->value == "SESSION" };
	}
}

const string SET_TESTING_CSV_PATH { get_env("TAP_WORKDIR") + "./set_testing-240.csv" };

struct test_stmts_t {
	vector<string> valid_stmts;
	vector<pair<string,perr_t>> invalid_stmts;
};

rc_t<test_stmts_t> get_valid_queries() {
	vector<string> valid_stmts {};
	vector<pair<string,perr_t>> invalid_stmts {};

	int n { 0 };
	if (ioctl(STDIN_FILENO, FIONREAD, &n)) {
		std::cerr << "ioctl: Failed to read number of bytes in stdin   errno=" << errno << "\n";
		return { EXIT_FAILURE, {} };
	}

	if (n > 0) {
		string line {};
		string cin_query {};

		while (std::getline(std::cin, line)) {
			cin_query += line + "\n";
		}

		valid_stmts.push_back(cin_query);
	} else {
		std::copy(set_queries.begin(), set_queries.end(), std::back_inserter(valid_stmts));
		std::copy(setparser_queries.begin(), setparser_queries.end(), std::back_inserter(valid_stmts));
		std::copy(valid_sql_mode_subexprs.begin(), valid_sql_mode_subexprs.end(), std::back_inserter(valid_stmts));
		std::copy(valid_sql_mode_subexprs.begin(), valid_sql_mode_subexprs.end(), std::back_inserter(valid_stmts));
		std::copy(invalid_sql_mode_subexprs.begin(), invalid_sql_mode_subexprs.end(), std::back_inserter(invalid_stmts));
	}

	return { 0, { valid_stmts, invalid_stmts } };
}

char safe_tolower(char ch) {
	return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
}

nlohmann::json to_json(const var_map_t& var_map) {
	nlohmann::json json_map;

	for (const auto& [key, assigns] : var_map) {
		nlohmann::json json_vector;

		for (const auto& [_, node, val] : assigns) {
			nlohmann::json json_pair;
			json_pair["node_addr"] = reinterpret_cast<std::uintptr_t>(node);
			json_pair["val"] = val;
			json_vector.push_back(json_pair);
		}

		json_map[key] = json_vector;
	}

	return json_map;
}

string to_string(const perr_t& e) {
	const auto c_join = [](const string& s1, const string& s2) -> string {
		return s2.empty() ? "\"" + s1 + "\"" : s2 + ",\"" + s1 + "\"";
	};
	const string s_err_ctx { "[" + fold(c_join, e.ctx) + "]" };

	return "(" + _TO_S(e.rc) + ", '" + e.msg + "', '" + s_err_ctx + "')";
}

rc_t<string> check_valid_sql_mode_stmt(const unique_ptr<MySQLParser::AstNode>& p, const string& q) {
	if (p == nullptr) { return { -1, "Invalid (nullptr) AST root node" }; }

	const auto var_map { ext_set_details(p.get(), q) };

	for (auto v : var_map.vars_assigns) {
		using MySQLParser::NodeType;

		if (v.second.size() <= 0) {
			assert(0 && "Invalid parse result for a SET statement, at least one value is expected.");
		}

		const string& var_name { v.first };
		const MySQLParser::AstNode* v_node { v.second.front().node };
		const string_view& v_val { v.second.front().val };

		if (strcasecmp(var_name.c_str(), "sql_mode") == 0) {
			const auto verf_err { verf_sql_mode_val(v_node, v_val, q) };

			ok(
				verf_err.rc == 0,
				"Value for SQL mode should be correctly verified   query=`%s` p_err=%s",
				q.c_str(), to_string(verf_err).c_str()
			);
		} else {
			diag(
				"Only handling 'sql_mode' values; skipping...   var_name=`%s` query=%s",
				var_name.c_str(), q.c_str()
			);
		}
	}

	return { 0, "" };
}

bool equals(const perr_t& e1, const perr_t& e2) {
	const bool b_ctx { e1.ctx == e2.ctx };

	return e1.rc == e2.rc && e1.msg == e2.msg && b_ctx;
}

rc_t<string> check_invalid_sql_mode_stmt(
	const unique_ptr<MySQLParser::AstNode>& p, const string& q, const perr_t& exp_err
) {
	if (p == nullptr) { return { -1, "Invalid (nullptr) AST root node" }; }

	const auto var_map { ext_set_details(p.get(), q) };

	for (auto v : var_map.vars_assigns) {
		using MySQLParser::NodeType;

		if (v.second.size() <= 0) {
			assert(0 && "Invalid parse result for a SET statement, at least one value is expected.");
		}

		const string& var_name { v.first };
		const MySQLParser::AstNode* v_node { v.second.front().node };
		const string_view& v_val { v.second.front().val };

		if (strcasecmp(var_name.c_str(), "sql_mode") == 0) {
			const auto verf_err { verf_sql_mode_val(v_node, v_val, q) };

			ok(
				equals(verf_err, exp_err),
				"Query should fail to parse with the expected error"
					"   query=`%s`\n - act_err=%s\n - exp_err=%s",
				q.c_str(), to_string(verf_err).c_str(), to_string(exp_err).c_str()
			);
		} else {
			diag(
				"Only handling 'sql_mode' values; skipping...   var_name=`%s` query=%s",
				var_name.c_str(), q.c_str()
			);
		}
	}

	return { 0, "" };
}

void check_valid_stmts(
	const cmd_opts_t& opts, MySQLParser::Parser& parser, const vector<string>& test_qs
) {
	for (const auto& q : test_qs) {
		diag("Parsing next query   q=`%s`", q.c_str());

		const auto ast { parser.parse(q) };

		if (opts.verbose) {
			MySQLParser::print_ast(ast.get());
		}

		if (ast) {
			rc_t<string> chk_res { check_valid_sql_mode_stmt(ast, q) };

			if (chk_res.first) {
				diag(
					"Check encountered an error; aborting further testing   query=\"%s\" error=\"%s\"",
					q.c_str(), chk_res.second.c_str()
				);
				return;
			}
		} else {
			const auto c_join = [](const string& s1, const string& s2) -> string {
				return s2.empty() ? "\"" + s1 + "\"" : "\"" + s1 + "\"," + s2 ;
			};
			const vector<string> empty_err { "No specific error, check parser logic or 'mysql_yyerror'" };
			const auto& errs { parser.get_errors().empty() ? empty_err : parser.get_errors() };
			const string str_errs { "[" + fold(c_join, errs) + "]" };

			diag("Parsing failed   error='%s'", str_errs.c_str());
		}
	}
}

void check_invalid_stmts(
	const cmd_opts_t& opts, MySQLParser::Parser& parser, const vector<pair<string,perr_t>>& test_qs
) {
	for (const auto& q : test_qs) {
		diag("Parsing next query   q=`%s`", q.first.c_str());

		const auto ast { parser.parse(q.first) };

		if (ast) {
			rc_t<string> chk_res { check_invalid_sql_mode_stmt(ast, q.first, q.second) };

			if (chk_res.first) {
				diag(
					"Check encountered an error; aborting further testing   query=\"%s\" error=\"%s\"",
					q.first.c_str(), chk_res.second.c_str()
				);
				return;
			}
		} else {
			const auto c_join = [](const string& s1, const string& s2) -> string {
				return s2.empty() ? "\"" + s1 + "\"" : "\"" + s1 + "\"," + s2 ;
			};

			const vector<string> empty_err { "No specific error, check parser logic or 'mysql_yyerror'" };
			const auto& errs { parser.get_errors().empty() ? empty_err : parser.get_errors() };

			const string s_act_errs { "[" + fold(c_join, errs) + "]" };
			const string s_exp_errs { "[" + fold(c_join, q.second.ctx) + "]" };

			ok(
				errs == q.second.ctx,
				"Parsing failure should match the expected errors   act_errs=`%s` exp_errs=`%s`",
				s_act_errs.c_str(), s_exp_errs.c_str()
			);
		}
	}
}

int main(int argc, const char** argv) {
	const auto rc_opts { get_cmd_options(argc, argv) };

	rc_t<test_stmts_t> test_qs { rc_opts.second.query.empty() ?
		get_valid_queries() : rc_t<test_stmts_t> { 0, { { rc_opts.second.query }, {} } }
	};

	if (test_qs.first) {
		diag("Creating test queries failed   rc=%d", test_qs.first);
		return test_qs.first;
	} else {
		plan(test_qs.second.valid_stmts.size() + test_qs.second.invalid_stmts.size());
	}

	MySQLParser::Parser parser;

	check_valid_stmts(rc_opts.second, parser, test_qs.second.valid_stmts);
	check_invalid_stmts(rc_opts.second, parser, test_qs.second.invalid_stmts);

	return exit_status();
}
