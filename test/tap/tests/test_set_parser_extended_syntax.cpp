/**
 * @file test_set_parser_extended_syntax.cpp
 * @brief TAP test for new SET parser syntax extensions.
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

#include <string>
#include <vector>

using std::string;
using std::vector;

MySQL_LDAP_Authentication* GloMyLdapAuth = nullptr;

struct ext_case_t {
	string query;
	vector<string> exp_vars;
	string scope_var;
};

static bool has_session_scope(const assign_info_t& inf) {
	using MySQLParser::NodeType;

	if (inf.node == nullptr) {
		return false;
	}

	if (inf.node->type == NodeType::NODE_SET_TRANSACTION) {
		const auto scope = get_node(inf.node, {{ NodeType::NODE_VARIABLE_SCOPE, 0 }});
		return scope.first == 0 && scope.second->value == "SESSION";
	}

	const auto scope = get_node(inf.node,
		{{ NodeType::NODE_UNKNOWN, 0 }, { NodeType::NODE_VARIABLE_SCOPE, 0 }}
	);
	return scope.first == 0 && scope.second->value == "SESSION";
}

int main() {
	vector<ext_case_t> cases {
		{
			"SET @my_user := 1;",
			{"@my_user"},
			""
		},
		{
			"SET @user.var := 7;",
			{"@user.var"},
			""
		},
		{
			"SET @@SESSION.wait_timeout := 42;",
			{"wait_timeout"},
			""
		},
		{
			"SET LOCAL wait_timeout = 10;",
			{"wait_timeout"},
			"wait_timeout"
		},
		{
			"SET LOCAL sql_mode := CONCAT(@@sql_mode, ',STRICT_TRANS_TABLES');",
			{"sql_mode"},
			"sql_mode"
		},
		{
			"SET @'quoted-user' := 1;",
			{"@quoted-user"},
			""
		},
		{
			"SET @\"quoted.user\" := 2;",
			{"@quoted.user"},
			""
		},
		{
			"SET @`quoted var` := 3;",
			{"@quoted var"},
			""
		},
		{
			"SET LOCAL TRANSACTION READ ONLY;",
			{"transaction"},
			"transaction"
		},
		{
			"SET @'mix' := 1, LOCAL wait_timeout := 20;",
			{"@mix", "wait_timeout"},
			"wait_timeout"
		}
	};

	int checks { 0 };
	for (const auto& c : cases) {
		checks += 2 + static_cast<int>(c.exp_vars.size()) + (c.scope_var.empty() ? 0 : 1);
	}
	plan(checks);

	MySQLParser::Parser parser;

	for (const auto& c : cases) {
		std::unique_ptr<MySQLParser::AstNode> ast { parser.parse(c.query) };
		ok(ast != nullptr, "Query should parse   query=`%s`", c.query.c_str());

		const MySQLParser::AstNode* stmt { ast && ast->children.size() ? ast->children.front() : nullptr };
		ok(stmt != nullptr, "AST should contain first statement   query=`%s`", c.query.c_str());

		set_details_t details {};
		if (stmt) {
			details = ext_set_details(stmt, c.query);
		}

		for (const auto& exp_var : c.exp_vars) {
			ok(
				details.vars_assigns.find(exp_var) != details.vars_assigns.end(),
				"Expected variable should be extracted   query=`%s` var=`%s`",
				c.query.c_str(), exp_var.c_str()
			);
		}

		if (!c.scope_var.empty()) {
			bool sess_scope_ok { false };
			const auto it = details.vars_assigns.find(c.scope_var);

			if (it != details.vars_assigns.end() && !it->second.empty()) {
				sess_scope_ok = has_session_scope(it->second.front());
			}

			ok(
				sess_scope_ok,
				"LOCAL scope should normalize to SESSION   query=`%s` var=`%s`",
				c.query.c_str(), c.scope_var.c_str()
			);
		}
	}

	return exit_status();
}
