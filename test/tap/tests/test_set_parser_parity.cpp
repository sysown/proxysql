/**
 * @file test_set_parser_parity.cpp
 * @brief Checks that the SQL based SET statement parser is on pair with the previous REGEX based one.
 */

// NOTE: Avoids the definition of 'global_variables glovars' in 'proxysql_structs.h'
#include "proxysql_structs.h"

#include "MySQL_Set_Stmt_Parser.h" // For regex parser 'MySQL_Set_Stmt_Parser'
#include "MySQL_SET_Parser_Utils.h" // For SQL parser utilities; p_match_1, etc...
#include "MySQL_Session_Utils.h" // For 'match_regexes'

// NOTE: Avoids definition of 'proxy_sqlite3_*' functions as 'extern'
#define MAIN_PROXY_SQLITE3
#include "sqlite3db.h" // IWYU pragma: keep
#include "MySQL_LDAP_Authentication.hpp"

#include "c_tokenizer.h"
#include "MySQL_Parser.h"
#include "proxysql_utils.h"

#include "ezOptionParser.hpp"

#include "utils.h"
#include "tap.h"

#include "json.hpp"

#include <unistd.h>
#include <sys/ioctl.h>

#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <string.h>
#include <vector>

using std::fstream;
using std::pair;
using std::map;
using std::string;
using std::string_view;
using std::unique_ptr;
using std::vector;

using nlohmann::json;

MySQL_LDAP_Authentication *GloMyLdapAuth = nullptr;

/**
 * @brief Queries for exhaustive syntax expression covering.
 */
const vector<string> exhaustive_queries {
	"SET @my_user_variable = 123;", // 1
	"SET @my_user_variable = + 123;", // 1
	"SET @my_user_variable = - 123;", // 1
	"SET @my_user_variable = 123, @@GLOBAL.max_connections = 200;", // 2
	"SET @my_custom_var = 'Test Value';", // 3
	"SET P_param_name = 100;", // 4
	"SET my_local_variable = NOW();", // 5
	"SET GLOBAL sort_buffer_size = 512000;", // 6
	"SET @@GLOBAL.sort_buffer_size = 512000;", // 7
	"SET PERSIST max_allowed_packet = 1073741824;", // 8
	"SET @@PERSIST.max_allowed_packet = 1073741824;", // 9
	"SET PERSIST_ONLY sql_mode = 'STRICT_TRANS_TABLES';", // 10
	"SET @@PERSIST_ONLY.sql_mode = 'STRICT_TRANS_TABLES';", // 11
	"SET SESSION sql_select_limit = 100;", // 12
	"SET @@SESSION.sql_select_limit = 100;", // 13
	"SET @@sql_select_limit = 100;", // 14
	"SET sql_select_limit = 100;", // 15
	"SET @generic_var = TRUE OR FALSE;", // 16
	"SET @generic_var = TRUE XOR FALSE;", // 17
	"SET @generic_var = 1 AND 0;", // 18
	"SET @generic_var = NOT TRUE;", // 19
	"SET @generic_var = (5 > 1) IS TRUE;", // 20
	"SET @generic_var = (1 = 0) IS NOT TRUE;", // 21
	"SET @generic_var = (1 = 0) IS FALSE;", // 22
	"SET @generic_var = (5 > 1) IS NOT FALSE;", // 23
	"SET @generic_var = (NULL + 1) IS UNKNOWN;", // 24
	"SET @generic_var = (1 IS NOT NULL) IS NOT UNKNOWN;", // 25
	"SET @generic_var = (col_a < col_b);", // 26
	"SET @generic_var = (0/0) IS NULL;", // 29
	"SET @generic_var = 'hello' IS NOT NULL;", // 30
	"SET @generic_var = (1=1) = ('a' LIKE 'a%');", // 31
	"SET @generic_var = my_value > ALL (SELECT limit_value FROM active_limits WHERE group_id = 'A');", // 32
	"SET @generic_var = (5 BETWEEN 1 AND 10);", // 33
	"SET @generic_var = current_user_id IN (SELECT user_id FROM course_enrollments WHERE course_id = 789);", // 41
	"SET @generic_var = 'PROD123' NOT IN (SELECT product_sku FROM discontinued_products WHERE reason_code = 'OBSOLETE');", // 42
	"SET @generic_var = 5 IN (5);", // 43
	"SET @generic_var = 'apple' IN ('orange', 'apple', 'banana');", // 44
	"SET @generic_var = 10 NOT IN (5);", // 45
	"SET @generic_var = 'grape' NOT IN ('orange', 'apple', 'banana');", // 46
	"SET @generic_var = 'b' MEMBER OF ('[\"a\", \"b\", \"c\"]');", // 47
	"SET @generic_var = 'b' MEMBER ('[\"a\", \"b\", \"c\"]');", // 48
	"SET @generic_var = 7 BETWEEN 5 AND (5 + 5);", // 49
	"SET @generic_var = 3 NOT BETWEEN 5 AND (10 - 2);", // 50
	"SET @generic_var = 'knight' SOUNDS LIKE 'night';", // 51
	"SET @generic_var = 'banana' LIKE 'ba%';", // 52
	"SET @generic_var = 'data_value_100%' LIKE 'data\\_value\\_100\\%' ESCAPE '\\\\';", // 53
	"SET @generic_var = 'apple' NOT LIKE 'ora%';", // 54
	"SET @generic_var = 'test_string%' NOT LIKE 'prod\\_string\\%' ESCAPE '\\\\';", // 55
	"SET @generic_var = 'abcde' REGEXP '^a.c';", // 56
	"SET @generic_var = 'xyz123' NOT REGEXP '[0-9]$';", // 57
	"SET @generic_var = (100 + 200);", // 58
	"SET @generic_var = 5 | 2;", // 61
	"SET @generic_var = 5 & 2;", // 62
	"SET @generic_var = 5 << 1;", // 63
	"SET @generic_var = 10 >> 1;", // 64
	"SET @generic_var = 10.5 + 2;", // 65
	"SET @generic_var = 100 - 33;", // 66
	"SET @generic_var = NOW() + INTERVAL 1 DAY;", // 67
	"SET @generic_var = '2025-12-25' - INTERVAL 2 MONTH;", // 68
	"SET @generic_var = 7 * 6;", // 69
	"SET @generic_var = 100 / 4;", // 70
	"SET @generic_var = 10 % 3;", // 71
	"SET @generic_var = 10 DIV 3;", // 72
	"SET @generic_var = 10 MOD 3;", // 73
	"SET @generic_var = 5 ^ 2;", // 74
	"SET @generic_var = (SELECT SUM(amount) FROM sales WHERE sale_date = CURDATE());" // 75
};

/**
 * @brief Basic queries.
 */
const vector<string> set_queries {
	// Basic User Variable Assignments
	"SET @my_user_var = 'hello world';",
	"SET @anotherVar = 12345;",
	"SET @thirdVar = `ident_value`;", // Using identifier as value
	"SET @complex_var = @@global.max_connections;", // Setting user var to sys var value (expr placeholder)

	// System Variable Assignments
	"SET global max_connections = 1000;",
	"SET session sort_buffer_size = 200000;",
	"SET GLOBAL sort_buffer_size = 400000;", // Case-insensitivity for scope
	"SET SESSION wait_timeout = 180;",
	"SET @@global.tmp_table_size = 32000000;",
	"SET @@session.net_write_timeout = 120;",
	"SET @@net_read_timeout = 60;", // Implicit SESSION scope for @@
	"SET max_allowed_packet = 64000000;", // Implicit SESSION scope for simple sysvar

	// PERSIST / PERSIST_ONLY (if supported by your current grammar for scope)
	"SET persist character_set_server = 'utf8mb4';",
	"SET persist_only innodb_buffer_pool_size = '1G';", // String literal for value

	// SET NAMES and CHARACTER SET
	"SET NAMES 'utf8mb4';",
	"SET NAMES `latin1`;",
	"SET NAMES DEFAULT;",
	"SET NAMES 'gbk' COLLATE 'gbk_chinese_ci';",
	"SET CHARACTER SET 'utf8';",
	"SET CHARACTER SET DEFAULT;",

	// Comma-separated list (testing set_option_list)
	"SET @a = 1, @b = 'two', global max_heap_table_size = 128000000;",
	"SET sql_mode = 'STRICT_TRANS_TABLES', character_set_client = 'utf8mb4';",

	// Statements without trailing semicolon (should work with optional_semicolon)
	"SET @no_semicolon = 'works'",
};

// Cases from 'setparser_test.cpp': extracted via 'ack -o "\"SET.*?\"," $path'
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
	"SET @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')",
	"SET SQL_MODE=IFNULL(@@sql_mode,'')",
	"SET SQL_MODE=IFNULL(@old_sql_mode,'')",
	"SET SQL_MODE=IFNULL(@OLD_SQL_MODE,'')",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION')), time_zone = '+00:00', NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
	"SET sql_mode=''",
	"SET sql_mode=(SELECT CONCA(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
	"SET sql_mode=(SELECT CONCAT(@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))",
	"SET sql_mode=(SELCT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))",
	"SET @@time_zone = 'Europe/Paris'",
	"SET @@time_zone = '+00:00'",
	"SET @@time_zone = \"Europe/Paris\"",
	"SET @@time_zone = \"+00:00\"",
	"SET @@time_zone = @OLD_TIME_ZONE",
	"SET @@TIME_ZONE = @OLD_TIME_ZONE",
	"SET @@session_track_gtids = OFF",
	"SET @@session_track_gtids = OWN_GTID",
	"SET @@SESSION.session_track_gtids = OWN_GTID",
	"SET @@LOCAL.session_track_gtids = OWN_GTID",
	"SET SESSION session_track_gtids = OWN_GTID",
	"SET @@session_track_gtids = ALL_GTIDS",
	"SET @@SESSION.session_track_gtids = ALL_GTIDS",
	"SET @@LOCAL.session_track_gtids = ALL_GTIDS",
	"SET SESSION session_track_gtids = ALL_GTIDS",
	"SET @@character_set_results = utf8",
	"SET @@character_set_results = NULL",
	"SET character_set_results = NULL",
	"SET @@session.character_set_results = NULL",
	"SET @@local.character_set_results = NULL",
	"SET session character_set_results = NULL",
	"SET NAMES utf8",
	"SET NAMES 'utf8'",
	"SET NAMES \"utf8\"",
	"SET NAMES utf8 COLLATE unicode_ci",
	"SET @@SESSION.SQL_SELECT_LIMIT= DEFAULT",
	"SET @@LOCAL.SQL_SELECT_LIMIT= DEFAULT",
	"SET @@SQL_SELECT_LIMIT= DEFAULT",
	"SET SESSION SQL_SELECT_LIMIT   = DEFAULT",
	"SET @@SESSION.SQL_SELECT_LIMIT= 1234",
	"SET @@LOCAL.SQL_SELECT_LIMIT= 1234",
	"SET @@SQL_SELECT_LIMIT= 1234",
	"SET SESSION SQL_SELECT_LIMIT   = 1234",
	"SET @@SESSION.SQL_SELECT_LIMIT= 1234",
	"SET @@LOCAL.SQL_SELECT_LIMIT= 1234",
	"SET @@SESSION.SQL_SELECT_LIMIT= @old_sql_select_limit",
	"SET @@LOCAL.SQL_SELECT_LIMIT= @old_sql_select_limit",
	"SET SQL_SELECT_LIMIT= @old_sql_select_limit",
	"SET @@SESSION.sql_auto_is_null = 0",
	"SET @@LOCAL.sql_auto_is_null = 0",
	"SET SESSION sql_auto_is_null = 1",
	"SET sql_auto_is_null = OFF",
	"SET @@sql_auto_is_null = ON",
	"SET @@SESSION.sql_safe_updates = 0",
	"SET @@LOCAL.sql_safe_updates = 0",
	"SET SESSION sql_safe_updates = 1",
	"SET SQL_SAFE_UPDATES = OFF",
	"SET @@sql_safe_updates = ON",
	"SET time_zone = 'Europe/Paris', sql_mode = 'TRADITIONAL'",
	"SET time_zone = 'Europe/Paris', sql_mode = IFNULL(NULL,\"STRICT_TRANS_TABLES\")",
	"SET sql_mode = 'TRADITIONAL', NAMES 'utf8 COLLATE 'unicode_ci'",
	"SET  @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
	"SET  @@LOCAL.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
	"SET NAMES utf8, @@SESSION.sql_mode = CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO'), @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 3600",
	"SET NAMES utf8, @@LOCAL.sql_mode = CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO'), @@LOCAL.sql_auto_is_null = 0, @@LOCAL.wait_timeout = 3600",
	"SET character_set_results=NULL, NAMES latin7, character_set_client='utf8mb4'",
	"SET character_set_results=NULL,NAMES latin7,character_set_client='utf8mb4'"
};

/**
 * @brief Expected failures, for testing error handling in the SQL parser.
 * @details TODO: Right now this is just used for exercising error handling.
 */
const vector<string> exp_failures {
	// Wrong identifier; should be a valid interval keyword
	"SET @generic_var = (SELECT '2025-12-10') - INTERVAL 2 foo;",
	// Test cases for potential errors or unsupported expressions
	"SET @myvar = some_function(1, 'a');", // 'some_function(...)' is an identifier for 'expr_holder' for now
	"SET global invalid-variable = 100;", // Invalid identifier char (if not quoted)
	"SET @unterminated_string = 'oops",
	"SET =", // Syntax error
	"SET names utf8 collate ;" // Missing collation name
};

/**
 * @brief For testing 'sql_mode' special handling.
 * @details TODO: This requires a special test, current covering is insufficient.
 */
const vector<string> valid_sql_mode_subexpr {
	// Valid cases FAILING under REGEX impl
	"SET sql_mode=(SELECT 'foo')",
	"SET sql_mode=(SELECT \"foo\")",
	"SET sql_mode=(SELECT 5)",
	"SET sql_mode=(SELECT NULL)",
	// Valid cases WORKING under REGEX impl
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, NULL))",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, 'foo'))",
	// Valid cases FAILING under REGEX impl
	"SET sql_mode=(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', (SELECT 'foo')))",
	"SET sql_mode=(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', 5))"
};

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

rc_t<vector<string>> get_valid_queries() {
	vector<string> test_qs {};

	std::copy(exhaustive_queries.begin(), exhaustive_queries.end(), std::back_inserter(test_qs));
	std::copy(set_queries.begin(), set_queries.end(), std::back_inserter(test_qs));
	std::copy(setparser_queries.begin(), setparser_queries.end(), std::back_inserter(test_qs));
	std::copy(valid_sql_mode_subexpr.begin(), valid_sql_mode_subexpr.end(), std::back_inserter(test_qs));

	char* DISABLE_SET_TESTING_CSV { getenv("DISABLE_SET_TESTING_CSV_PATH") };

	if (!DISABLE_SET_TESTING_CSV) {
		std::fstream logfile_fs {};

		printf("Openning log file   path:'%s'\n", SET_TESTING_CSV_PATH.c_str());
		// no scope found, defaults to session
		logfile_fs.open(SET_TESTING_CSV_PATH.c_str(), std::fstream::in | std::fstream::out);

		if (!logfile_fs.is_open() || !logfile_fs.good()) {
			fprintf(stderr, "Failed to open '%s' file   path=\"%s\" error=%d\n",
				basename(SET_TESTING_CSV_PATH.c_str()), SET_TESTING_CSV_PATH.c_str(), errno
			);
			return { EXIT_FAILURE, {} };
		}

		string next_line {};

		while (std::getline(logfile_fs, next_line)) {
			nlohmann::json j_next_line = nlohmann::json::parse(next_line);
			test_qs.push_back(j_next_line["query"]);
		}
	}

	return { 0, test_qs };
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

const auto str_acc = [] (const string& s1, const string& s2) -> string {
	return s2 + " " + s1;
};

string to_string(const perr_t& e) {
	const auto c_join = [](const string& s1, const string& s2) -> string {
		return s2.empty() ? s1 : s1 + "," + s2;
	};
	const string s_err_ctx { "[" + fold(c_join, e.ctx) + "]" };

	return "(" + _TO_S(e.rc) + ", '" + e.msg + "', '" + s_err_ctx + "')";
}

rc_t<string> verf_parser_match(
	const var_map_t& var_map,
	map<string, vector<string>>& regex_vals,
	const string& q
) {
	for (auto e : var_map) {
		using MySQLParser::NodeType;

		if (e.second.size() <= 0) {
			assert(0 && "Invalid parse result for a SET statement, at least one value is expected.");
		}

		const string& v_name { e.first };
		const MySQLParser::AstNode* v_node { e.second.front().node };
		const string_view& v_val { e.second.front().val };

		const bool is_sess_scope { check_sess_scope(v_node).second };
		const bool is_user_def {
			get_node(v_node, {{ MySQLParser::NodeType::NODE_USER_VARIABLE, 0 }}).first == 0
		};

		const string v_pos { "(" + _TO_S(v_node->val_init_pos) + "," + _TO_S(v_node->val_end_pos) + ")" };

		std::cout << "Variable assignment - Node details:\n";
		std::cout << "  - Name:           " << v_name << "\n";
		std::cout << "  - Sess Scope:     " << is_sess_scope << "\n";
		std::cout << "  - User Defined:   " << is_user_def << "\n";
		std::cout << "  - Type:           " << to_string(v_node->type) << "\n";
		std::cout << "  - Value           " << v_pos << ": " << v_val << "\n";

		if (v_name == "sql_mode") {
			const auto v_res { verf_sql_mode_val(v_node, v_val, q) };
			const string s_err { to_string(v_res) };

			std::cout << "  - SQL_MODE_VERF:  " << s_err << "\n";
		}

		std::cout << "  - AST Parser Val: _" << v_val << "_\n";

		const string lc_name {
			std::accumulate(v_name.begin(), v_name.end(), string {},
				[] (const string& s, const char c) -> string {
					return s + safe_tolower(c);
				}
			)
		};

		const vector<string> re_vals { regex_vals[lc_name] };
		const string re_val { trim(fold(str_acc, re_vals)) };

		auto acc_child_vals = [] (MySQLParser::AstNode* const n, const string& s) -> string {
			return s + " " + n->value;
		};

		const vector<string> known_re2_fails {
			"DEFAULT;"
		};

		std::cout << "  - RE2 Parser map: _" << nlohmann::json(regex_vals).dump() << "_\n";
		std::cout << "  - AST Parser map: _" << to_json(var_map).dump() << "_\n";
		std::cout << "  - RE2 Parser Val: _" << re_val << "_\n";
		std::cout << "  - AST Parser Val: _" << v_val << "_\n";

		if (!is_user_def && is_sess_scope && re_val != v_val) {
			std::cout << "WARNING: Mismatch between REGEX Parser and AST parser\n";

			if (std::find(std::begin(known_re2_fails), std::end(known_re2_fails), re_val) != std::end(known_re2_fails)) {
				std::cout << "  + Known legacy failure of the REGEX parser\n";
			} else if (!v_val.empty() && re_val.empty()) {
				std::cout << "  + Query matched with empty value in the REGEX parser, this is likely an"
					" unsupported query for this parser.\n";
			} else {
				return { -1, q };
			}
		}
	}

	return { 0, "" };
}

struct cmd_opts_t {
	bool verbose;
	string query;
};

rc_t<cmd_opts_t> get_cmd_options(int argc, const char* argv[]) {
	// command line options to extract
	cmd_opts_t opts { false, {} };

	// define the command line options
	ez::ezOptionParser opt_p {};
	opt_p.overview = "TAP test for parity between REGEX and Bison SQL parsers for SET statements";
	opt_p.syntax = "test_set_parser_parity [OPTIONS]";
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

int main(int argc, const char* argv[]) {
	// Required for giving some defaults
	mysql_thread___query_digests_max_query_length = 65000;
	mysql_thread___query_digests_lowercase = false;
	mysql_thread___query_digests_replace_null = true;
	mysql_thread___query_digests_no_digits = false;
	mysql_thread___query_digests_keep_comment = false;
	mysql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = 1;

	const auto opts { get_cmd_options(argc, argv) };

	vector<string> failed_matches {};
	rc_t<vector<string>> test_qs {
		opts.second.query.empty() ? get_valid_queries() : rc_t<vector<string>> { 0, { opts.second.query } }
	};

	if (test_qs.first) {
		diag("Creating test queries failed   rc=%d", test_qs.first);
		return test_qs.first;
	} else {
		plan(1);
	}

	// Current ProxySQL parser
	MySQL_Set_Stmt_Parser regex_parser("");
	// Bison SQL parser
	MySQLParser::Parser parser;

	for (const auto& q : test_qs.second) {
		std::cout << "------------------------------------------\n";
		std::cout << "Parsing MySQL SET query: " << q << std::endl;

		std::unique_ptr<MySQLParser::AstNode> ast { parser.parse(q) };
		regex_parser.set_query(q);

		map<string,vector<string>> regex_vals {};

		if (ast) {
			if (opts.second.verbose) {
				std::cout << "[Verbose] AST after query parse:\n";
				MySQLParser::print_ast(ast.get());
			}

			// NOTE: First node from INPUT_STATEMENT_LIST; single statement queries are assumed
			const MySQLParser::AstNode* stmt { ast->children.size() ? ast->children.front() : nullptr };

			std::cout << "'MySQL_Session' regexes equivalences:\n";

			char* q_digest { nullptr };
			{
				char* _cmt { nullptr };
				q_digest = mysql_query_digest_and_first_comment_2(q.c_str(), q.size(), &_cmt, nullptr);

				if (_cmt) {
					free(_cmt);
				}
			}

			// ProxySQL (MySQL_Session) statement regexes
			{
				bool p_match_1 = p_match_regex_1(stmt);
				bool r_match_1 = strncasecmp(q_digest, "SET ", 4) == 0 &&
					(
						mysql_match_regexes[1].match(const_cast<char*>(q_digest))
						|| strncasecmp(q_digest, "SET NAMES", strlen("SET NAMES")) == 0
						|| strcasestr(q_digest,"autocommit")
					);

				printf("  + Match 1   parser=%d regex=%d\n", p_match_1, r_match_1);

				if (r_match_1) {
					regex_vals = regex_parser.parse1v2();
				}
				if (p_match_1 != r_match_1) {
					failed_matches.push_back(q.c_str());
				}
			}

			{
				bool p_match_2 = p_match_regex_2(stmt);
				bool r_match_2 = strncasecmp(q.c_str(), "SET ", 4) == 0 &&
					mysql_match_regexes[2].match(const_cast<char*>(q_digest));

				printf("  + Match 2   parser=%d regex=%d\n", p_match_2, r_match_2);

				if (r_match_2) {
					regex_vals = regex_parser.parse2();
				}
				if (p_match_2 != r_match_2) {
					failed_matches.push_back(q.c_str());
				}
			}

			{
				bool p_match_3 = p_match_regex_3(stmt);
				bool r_match_3 = strncasecmp(q.c_str(), "SET ", 4) == 0 &&
					mysql_match_regexes[3].match(const_cast<char*>(q_digest));

				printf("  + Match 3   parser=%d regex=%d\n", p_match_3, r_match_3);

				if (r_match_3) {
					const string val { regex_parser.parse_character_set() };
					regex_vals["character_set"] = { val };
				}
				if (p_match_3 != r_match_3) {
					failed_matches.push_back(q.c_str());
				}
			}

			const auto var_map { ext_set_details(stmt, q) };

			// Verify REGEX and SQL parser value extraction matches
			{
				const auto p_res { verf_parser_match(var_map.vars_assigns, regex_vals, q) };

				if (p_res.first) {
					failed_matches.push_back(p_res.second);
				}
			}

			free(q_digest);
		} else {
			std::cout << "Parsing failed:\n";
			const auto& errors = parser.get_errors();

			if (errors.empty()) {
				std::cout << " - No specific error, check parser logic or 'mysql_yyerror'.\n";
			} else {
				for (const auto& error : errors) {
					std::cout << " - Error: " << error << "\n";
				}
			}

			if (!regex_vals.empty()) {
				std::cout << " - REGEX based parser returned non-empty output. Flagging as failure!\n";
				std::cout << "   + REGEX Vals: " << nlohmann::json(regex_vals).dump();
				failed_matches.push_back(q);
			}
		}
	}

	std::cout << "\n";

	ok(failed_matches.size() == 0, "No matching differences should be observed between parsers");

	for (const auto& f : failed_matches) {
		std::cout << "Match failure   q=\"" << f << "\"\n";
	}

	return exit_status();
}
