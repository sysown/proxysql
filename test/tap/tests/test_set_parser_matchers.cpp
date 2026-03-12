/**
 * @file test_set_parser_matchers.cpp
 * @brief TAP test for parser matcher helpers and SET detail extraction semantics.
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
#include <utility>
#include <vector>

using std::string;
using std::pair;
using std::unique_ptr;
using std::vector;

using MySQLParser::AstNode;

MySQL_LDAP_Authentication* GloMyLdapAuth = nullptr;

struct exp_var_t {
	string name;
	vector<string> values;
	size_t exp_count;
};

struct matcher_case_t {
	string query;
	bool exp_match1;
	bool exp_match2;
	bool exp_match3;
	bool exp_has_user_var;
	vector<exp_var_t> exp_vars;
};

static const AstNode* first_stmt(const unique_ptr<AstNode>& ast) {
	return ast && !ast->children.empty() ? ast->children.front() : nullptr;
}

static vector<string> extract_values(const set_details_t& details, const string& var_name) {
	vector<string> values {};
	const auto it = details.vars_assigns.find(var_name);

	if (it == details.vars_assigns.end()) {
		return values;
	}

	for (const auto& assign : it->second) {
		values.emplace_back(assign.val);
	}

	return values;
}

static bool same_values(const vector<string>& actual, const vector<string>& expected) {
	if (actual.size() != expected.size()) {
		return false;
	}

	for (size_t i = 0; i < actual.size(); ++i) {
		if (actual[i] != expected[i]) {
			return false;
		}
	}

	return true;
}

int main() {
	vector<matcher_case_t> cases {
		{
			"SET autocommit = 0;",
			true,
			false,
			false,
			false,
			{
				{ "autocommit", { "0" }, 1 }
			}
		},
		{
			"SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;",
			true,
			false,
			false,
			false,
			{
				{ "names", { "utf8mb4", "utf8mb4_0900_ai_ci" }, 2 }
			}
		},
		{
			"SET CHARACTER SET utf8mb4;",
			false,
			false,
			true,
			false,
			{
				{ "character_set", { "utf8mb4" }, 1 }
			}
		},
		{
			"SET SESSION TRANSACTION READ ONLY;",
			false,
			true,
			false,
			false,
			{
				{ "transaction", {}, 0 }
			}
		},
		{
			"SET @quoted_user := 7;",
			false,
			false,
			false,
			true,
			{
				{ "@quoted_user", { "7" }, 1 }
			}
		},
		{
			"SET sql_mode = '   ';",
			true,
			false,
			false,
			false,
			{
				{ "sql_mode", { "" }, 1 }
			}
		},
		{
			"SET sql_mode = 'TRADITIONAL', sql_mode = @@sql_mode;",
			true,
			false,
			false,
			false,
			{
				{ "sql_mode", { "TRADITIONAL", "@@sql_mode" }, 2 }
			}
		},
		{
			"SET @mix := 1, @@SESSION.wait_timeout := 42;",
			false,
			false,
			false,
			true,
			{
				{ "@mix", { "1" }, 1 },
				{ "wait_timeout", { "42" }, 1 }
			}
		}
	};

	int checks { 0 };
	for (const auto& c : cases) {
		checks += 6 + static_cast<int>(c.exp_vars.size()) * 2;
	}
	plan(checks);

	MySQLParser::Parser parser;

	for (const auto& c : cases) {
		unique_ptr<AstNode> ast { parser.parse(c.query) };
		ok(ast != nullptr, "Query should parse   query=`%s`", c.query.c_str());

		const AstNode* stmt { first_stmt(ast) };
		ok(stmt != nullptr, "AST should expose first statement   query=`%s`", c.query.c_str());

		set_details_t details {};
		if (stmt != nullptr) {
			details = ext_set_details(stmt, c.query);
		}

		ok(
			p_match_regex_1(stmt) == c.exp_match1,
			"Matcher 1 should match expectation   query=`%s`",
			c.query.c_str()
		);
		ok(
			p_match_regex_2(stmt) == c.exp_match2,
			"Matcher 2 should match expectation   query=`%s`",
			c.query.c_str()
		);
		ok(
			p_match_regex_3(stmt) == c.exp_match3,
			"Matcher 3 should match expectation   query=`%s`",
			c.query.c_str()
		);
		ok(
			details.has_user_var == c.exp_has_user_var,
			"User variable detection should match expectation   query=`%s`",
			c.query.c_str()
		);

		for (const auto& exp_var : c.exp_vars) {
			const auto it = details.vars_assigns.find(exp_var.name);
			ok(
				it != details.vars_assigns.end(),
				"Expected variable should be extracted   query=`%s` var=`%s`",
				c.query.c_str(), exp_var.name.c_str()
			);

			const vector<string> values { extract_values(details, exp_var.name) };
			const bool count_ok { exp_var.exp_count == 0 || values.size() == exp_var.exp_count };
			const bool exact_values_ok { exp_var.values.empty() || same_values(values, exp_var.values) };
			const bool values_ok {
				count_ok && exact_values_ok
			};
			ok(
				values_ok,
				"Extracted values should match expectation   query=`%s` var=`%s`",
				c.query.c_str(), exp_var.name.c_str()
			);
		}
	}

	return exit_status();
}
