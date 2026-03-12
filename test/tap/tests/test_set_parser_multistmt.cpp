/**
 * @file test_set_parser_multistmt.cpp
 * @brief TAP test for multi-statement validation in the SET parser helpers.
 */

// NOTE: Avoids the definition of 'global_variables glovars' in 'proxysql_structs.h'
#include "proxysql_structs.h"

#include "MySQL_SET_Parser_Utils.h"

// NOTE: Avoids definition of 'proxy_sqlite3_*' functions as 'extern'
#define MAIN_PROXY_SQLITE3
#include "sqlite3db.h" // IWYU pragma: keep
#include "MySQL_LDAP_Authentication.hpp"

#include "MySQL_Parser.h"

#include "tap.h"

#include <memory>
#include <string>
#include <vector>

using std::string;
using std::unique_ptr;
using std::vector;

using MySQLParser::AstNode;
using MySQLParser::NodeType;

MySQL_LDAP_Authentication* GloMyLdapAuth = nullptr;

struct multistmt_case_t {
	string query;
	bool exp_verf_ok;
	string exp_msg_substr;
};

static const AstNode* first_stmt(const unique_ptr<AstNode>& ast) {
	return ast && !ast->children.empty() ? ast->children.front() : nullptr;
}

int main() {
	vector<multistmt_case_t> cases {
		{
			"SET sql_mode = 'ANSI'; SET time_zone = '+00:00';",
			true,
			""
		},
		{
			"SET sql_mode = 'ANSI'; ; SET autocommit = 0;",
			true,
			""
		},
		{
			"SET sql_mode = 'ANSI'; SET CHARACTER SET utf8mb4;",
			true,
			""
		},
		{
			"SET sql_mode = 'ANSI'; SELECT 1;",
			false,
			"Only SET statements are allowed"
		},
		{
			"SELECT 1; SET autocommit = 0;",
			false,
			"Only SET statements are allowed"
		}
	};

	const int per_case_checks { 4 };
	const int extra_checks { 6 };
	plan(static_cast<int>(cases.size()) * per_case_checks + extra_checks);

	MySQLParser::Parser parser;

	for (const auto& c : cases) {
		unique_ptr<AstNode> ast { parser.parse(c.query) };
		ok(ast != nullptr, "Query should parse   query=`%s`", c.query.c_str());
		ok(
			ast != nullptr && ast->type == NodeType::NODE_INPUT_STATEMENT_LIST,
			"Root should be INPUT_STATEMENT_LIST   query=`%s`",
			c.query.c_str()
		);

		perr_t verf_res { ast ? verf_set_multi_stmts(ast.get(), c.query) : perr_t { -1, "parse failure" } };
		ok(
			(verf_res.rc == 0) == c.exp_verf_ok,
			"Multi-statement verification should match expectation   query=`%s` rc=%d msg=`%s`",
			c.query.c_str(), verf_res.rc, verf_res.msg.c_str()
		);

		const bool msg_ok {
			c.exp_msg_substr.empty() || verf_res.msg.find(c.exp_msg_substr) != string::npos
		};
		ok(
			msg_ok,
			"Verification message should match expectation   query=`%s` msg=`%s`",
			c.query.c_str(), verf_res.msg.c_str()
		);
	}

	{
		const string query { "SET autocommit = 0;" };
		perr_t verf_res { verf_set_multi_stmts(nullptr, query) };
		ok(verf_res.rc != 0, "Null AST should be rejected");
		ok(
			verf_res.msg.find("uninitialized AST") != string::npos,
			"Null AST rejection should explain the failure   msg=`%s`",
			verf_res.msg.c_str()
		);
	}

	{
		const string query { "SET autocommit = 0;" };
		unique_ptr<AstNode> ast { parser.parse(query) };
		ok(ast != nullptr, "Single SET query should parse for wrong-root validation");

		const AstNode* stmt { first_stmt(ast) };
		ok(stmt != nullptr, "Single SET query should expose its first statement");

		perr_t verf_res { verf_set_multi_stmts(stmt, query) };
		ok(verf_res.rc != 0, "Statement node should be rejected as multi-statement root");
		ok(
			verf_res.msg.find("INPUT_STATEMENT_LIST") != string::npos,
			"Wrong-root rejection should mention INPUT_STATEMENT_LIST   msg=`%s`",
			verf_res.msg.c_str()
		);
	}

	return exit_status();
}
