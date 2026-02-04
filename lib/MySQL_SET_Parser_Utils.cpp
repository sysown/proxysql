#include "MySQL_Parser.h"
#include "MySQL_SET_Parser_Utils.h"

#include "proxysql_structs.h"

#include <strings.h>

#include <deque>
#include <utility>
#include <vector>

using std::pair;
using std::map;
using std::deque;
using std::string;
using std::string_view;
using std::unique_ptr;
using std::vector;

using MySQLParser::NodeType;

vector<const MySQLParser::AstNode*> ext_vars_assigns(const MySQLParser::AstNode* root) {
	if (root == nullptr) { return {}; }

	vector<const MySQLParser::AstNode*> result {};
	deque<pair<const MySQLParser::AstNode*, size_t>> queue {{ root, 0 }};
	size_t target_depth { size_t(-1) };

	for (; !queue.empty(); queue.pop_front()) {
		const auto& current { queue.front() };
		const MySQLParser::AstNode* node = current.first;
		size_t depth = current.second;

		if (
			node->type == NodeType::NODE_VARIABLE_ASSIGNMENT
			|| node->type == NodeType::NODE_SET_NAMES
			|| node->type == NodeType::NODE_SET_CHARSET
			|| node->type == NodeType::NODE_SET_TRANSACTION
		) {
			if (target_depth == size_t(-1)) {
				target_depth = depth;
				result.push_back(node);
			} else if (depth == target_depth) {
				result.push_back(node);
			} else if (depth < target_depth) {
				continue;
			} else {
				break;
			}
		}

		for (const auto& child : node->children) {
			queue.push_back({child, depth + 1});
		}
	}

	return result;
}

template <class S>
S unquote_string(const S& s) {
	if (
		s.size() >= 2
		&& (
			(s.front() == '"' && s.back() == '"')
			|| (s.front() == '\'' && s.back() == '\'')
			|| (s.front() == '`' && s.back() == '`')
		)
	) {
		return s.substr(1, s.size() - 2);
	} else {
		return s;
	}
}

char is_space_char(char c) {
	if(c == ' ' || c == '\t' || c == '\n' || c == '\r') {
		return 1;
	} else {
		return 0;
	}
}

string fold_spaces(char c, const string& s) {
	if (s.empty()) {
		return string { c };
	} else {
		if (is_space_char(s.back()) && is_space_char(c)) {
			return s;
		} else {
			return s + c;
		}
	}
}

string get_var_name(const MySQLParser::AstNode* va) {
	if (va->type == NodeType::NODE_VARIABLE_ASSIGNMENT) {
		return get_node(va, {{ NodeType::NODE_UNKNOWN, 0 }}).second->value;
	} else if (va->type == NodeType::NODE_SET_NAMES) {
		return "names";
	} else if (va->type == NodeType::NODE_SET_CHARSET) {
		if (va->value == "CHARACTER_SET") {
			return "character_set";
		} else {
			return "charset";
		}
	} else if (va->type == NodeType::NODE_SET_TRANSACTION) {
		return "transaction";
	} else {
		assert(0 && "Invalid AST node type found in assignment!");
	}
}

vector<string_view> get_var_values(const MySQLParser::AstNode* va, const string_view& q) {
	if (va->type == NodeType::NODE_VARIABLE_ASSIGNMENT) {
		const string_view raw_val { q.data() + va->val_init_pos - 1, va->val_end_pos - va->val_init_pos };

		const bool is_str { get_node(va, {{ NodeType::NODE_STRING_LITERAL, 1 }}).first == 0 };
		const bool is_id { get_node(va, {{ NodeType::NODE_IDENTIFIER, 1 }}).first == 0 };

		// NOTE-TODO: Required for compatibility with REGEX based SET parser and existing logic; quotes are
		// removed from literal values and identifiers.
		const string_view u_val { is_str || is_id ? unquote_string<string_view>(raw_val) : raw_val };
		// NOTE-TODO: Required for compatibility with REGEX based SET parser and existing logic; literal
		// values and identifiers consisting only of spaces are converted into an empty string.
		const string_view f_val { std::all_of(u_val.begin(), u_val.end(), is_space_char) ? "" : u_val };

		return { f_val };
	} else if (va->type == NodeType::NODE_SET_NAMES) {
		return fmap([] (const MySQLParser::AstNode* c) -> string_view { return c->value; }, va->children);
	} else if (va->type == NodeType::NODE_SET_CHARSET) {
		return fmap([] (const MySQLParser::AstNode* c) -> string_view { return c->value; }, va->children);
	} else if (va->type == NodeType::NODE_SET_TRANSACTION) {
		vector<string_view> vals {};
		deque<const MySQLParser::AstNode*> n_queue { va };

		for (; !n_queue.empty(); n_queue.pop_front()) {
			const MySQLParser::AstNode* cur { n_queue.front() };

			for (const MySQLParser::AstNode* c : cur->children) {
				if (c->value != "TXN_CHAR_LIST") {
					vals.push_back(c->value);
				}

				n_queue.push_back(c);
			}
		}

		return vals;
	} else {
		assert(0 && "Invalid AST node type found in assignment!");
	}
}

var_type_t get_var_type(const MySQLParser::AstNode* va) {
	if (va->type == NodeType::NODE_VARIABLE_ASSIGNMENT) {
		const auto rc_node { get_node(va, {{ NodeType::NODE_USER_VARIABLE, 0 }}) };

		if (!rc_node.first) {
			return var_type_t::user;
		} else {
			return var_type_t::system;
		}
	} else {
		return var_type_t::system;
	}
}

set_details_t ext_set_details(const MySQLParser::AstNode* root, const string_view& q) {
	var_map_t var_map {};
	bool has_user_var { false };

	const auto assigns { ext_vars_assigns(root) };

	for (const auto& va : assigns) {
		const var_type_t type { get_var_type(va) };
		const string name { get_var_name(va) };
		const string mkey { type == var_type_t::system ? name : "@" + name };
		const vector<string_view> f_vals { get_var_values(va, q) };

		for (auto&& f_val : f_vals) {
			var_map[mkey].push_back({type, va, std::move(f_val)});
		}

		if (type == var_type_t::user) {
			has_user_var = true;
		}
	}

	return { has_user_var, var_map };
}

rc_t<const MySQLParser::AstNode*> get_node(
	const MySQLParser::AstNode* root, const vector<child_idx_t>& c_path
) {
	const MySQLParser::AstNode* cur_node { root };

	for (const auto& c_idx : c_path) {
		if (cur_node->children.size() && c_idx.second < cur_node->children.size()) {
			cur_node = cur_node->children[c_idx.second];

			if (c_idx.first == MySQLParser::NodeType::NODE_UNKNOWN) {
				continue;
			} else if (cur_node->type != c_idx.first) {
				return { -1, cur_node };
			}
		} else {
			return { -1, cur_node };
		}
	}

	return { 0, cur_node };
}

/**
 * @brief Checks if a var assign within a  'set statement' has 'session' scope.
 * @param node The NODE_VARIABLE_ASSIGNMENT from which to start the check.
 * @return A pair with shape { err_code, bool_res }.
 */
rc_t<bool> check_sys_var(const MySQLParser::AstNode* node) {
	using MySQLParser::NodeType;

	if (node->type != NodeType::NODE_VARIABLE_ASSIGNMENT) {
		return { -1, false };
	}

	const auto scope { get_node(node,
		{{ NodeType::NODE_SYSTEM_VARIABLE, 0 }, { NodeType::NODE_VARIABLE_SCOPE, 0 }})
	};

	if (scope.first == -1) {
		return { 0,
			// no scope found; just check kind since scope defaults to SESSION
			scope.second->type == NodeType::NODE_SYSTEM_VARIABLE
		};
	} else {
		return { 0,
			// found scope, match is required
			scope.second->value == "SESSION"
		};
	}
}

bool p_match_regex_1(const MySQLParser::AstNode* node) {
	if (node == nullptr || node->type != NodeType::NODE_SET_STATEMENT) { return false; }

	const auto vars_assings { ext_vars_assigns(node) };
	// Not a SET with assignments
	if (vars_assings.empty()) { return false; }

	for (const auto& v : vars_assings) {
		// Not a tracked SYSVAR/SET_NAMES; user defined, etc...
		if (v->type == NodeType::NODE_SET_NAMES) {
			continue;
		} else if (!check_sys_var(v).second) {
			return false;
		} else {
			const auto sys_var { get_node(v, {{ NodeType::NODE_SYSTEM_VARIABLE, 0 }}) };
			const auto is_tracked { ci_binary_search(mysql_tracked_vars, sys_var.second->value) };

			if (!is_tracked && sys_var.second->value != "autocommit") {
				return false;
			}
		}
	}

	return true;
}

bool p_match_regex_2(const MySQLParser::AstNode* node) {
	return node != nullptr && node->type == NodeType::NODE_SET_TRANSACTION;
}

bool p_match_regex_3(const MySQLParser::AstNode* node) {
	const auto set_charset { get_node(node,
		{{ NodeType::NODE_SET_OPTION_VALUE_LIST, 0 }, { NodeType::NODE_SET_CHARSET , 0 }}
	)};

	return node != nullptr && set_charset.first == 0;
}

//                         Special Variable Handling
///////////////////////////////////////////////////////////////////////////////

string acc_node_path(const child_idx_t& c, const string& s) {
	const string res { "(" + to_string(c.first) + "," + std::to_string(c.second) + ")" };

	if (s.empty()) {
		return res;
	} else {
		return s + "," + res;
	}
}

template <class S>
S rm_outer_parens(const S& s) {
	if (s.size() < 2) {
		return s;
	} else {
		if (s.front() == '(' && s.back() == ')') {
			return s.substr(1, s.size() - 2);
		} else {
			return s;
		}
	}
}

string comma_join(const string& s1, const string& s2) {
	if (s2.empty()) {
		return s1;
	} else {
		return s1 + "," + s2;
	}
}

string to_string(MySQLParser::AstNode* n) {
	return string { "(" } + "value: " + n->value + ", type: " + to_string(n->type) + ")";
}

perr_t verf_set_multi_stmts(const MySQLParser::AstNode* n, const string_view& q) {
	if (n == nullptr) {
		return { -1, "Invalid param; uninitialized AST supplied for query `" + string {q} + "`" };
	}

	if (n->type != MySQLParser::NodeType::NODE_INPUT_STATEMENT_LIST) {
		return { -1, "Invalid AST found; base node isn't a 'INPUT_STATEMENT_LIST'" };
	} else {
		for (auto c : n->children) {
			if (c->type != NodeType::NODE_SET_STATEMENT && c->type != NodeType::NODE_EMPTY_STATEMENT) {
				return { -1,
					"Only SET statements are allowed (for now) in SET multi-statements"
						"   node=`" + to_string(c) + "`"
				};
			}
		}
	}

	return { 0 };
}

perr_t verf_sql_mode_val(const MySQLParser::AstNode* n, const string_view& v, const string_view& q) {
	if (n == nullptr) {
		return { -1, "Invalid param; uninitialized AST supplied for query `" + string { q } + "`" };
	}

	const string perr_msg {
		"Failed to verify 'sql_mode' with value=`" + string { v.data(), v.size() } + "`"
	};

	const auto verf_fn_expr = [] (const MySQLParser::AstNode* n) -> pair<int,string> {
		const auto valid_fn_name = [] (const string& n) -> bool {
			return
				strcasecmp(n.c_str(), "REPLACE") == 0 ||
				strcasecmp(n.c_str(), "CONCAT") ==  0 ||
				strcasecmp(n.c_str(), "IFNULL") ==  0;
		};

		// EXPR: (IDENTIFIER, EXPR ('expr_list_wrapper'))
		if (n->children.size() != 2) {
			return { -1, "Invalid expr type=`" + to_string(n->type) + "`, function call expected" };
		}

		const bool is_func_expr { n->value.substr(0, n->value.find(':')) == "FUNC_CALL" };
		const string fn_name { n->value.substr(n->value.find(':') + 1) };
		const bool allowed { valid_fn_name(fn_name) };

		if (!is_func_expr || !allowed) {
			return { -1, "Found invalid function=`" + fn_name + "`" };
		} else {
			const auto id { get_node(n, {{ NodeType::NODE_IDENTIFIER, 0 }}) };
			const auto subexpr { get_node(n, {{ NodeType::NODE_EXPR, 1 }}) };
			const bool valid_ast { !id.first && !subexpr.first };
			const string err_msg { valid_ast ? "" : "Found invalid AST for function=`" + fn_name + "`" };

			return { valid_ast ? 0 : -1, err_msg };
		}
	};

	const auto is_valid_sysvar = [] (const MySQLParser::AstNode* n) -> bool {
		const auto scope { get_node(n, {{ NodeType::NODE_VARIABLE_SCOPE, 0 }}) };

		return
			n->type == NodeType::NODE_SYSTEM_VARIABLE
			&& n->value == "sql_mode"
			&& (scope.first == -1 || scope.second->value == "SESSION");
	};

	const auto is_valid_lit = [] (const MySQLParser::AstNode* c) -> bool {
		return
			c->type == NodeType::NODE_STRING_LITERAL
			|| c->type == NodeType::NODE_NULL_LITERAL
			|| c->type == NodeType::NODE_VALUE_LITERAL
			|| c->type == NodeType::NODE_IDENTIFIER;
	};

	// Verifies simple subexpr selects - (SELECT 'str_literal')
	const auto verf_select_lit = [] (const MySQLParser::AstNode* c, const string_view& q, size_t offset)
		-> pair<int,string>
	{
		if (c->type != NodeType::NODE_SELECT_RAW_SUBQUERY) {
			return { -1, "Invalid node type=`" + to_string(c->type) + "` found" };
		} else {
			const string subsel {
				q.substr(c->val_init_pos - 1 + offset, c->val_end_pos - c->val_init_pos)
			};
			MySQLParser::Parser parser;
			std::unique_ptr<MySQLParser::AstNode> ast { parser.parse(rm_outer_parens(subsel)) };

			if (ast) {
				const vector<child_idx_t> str_lit_path {
					{ NodeType::NODE_SELECT_STATEMENT, 0 },
					{ NodeType::NODE_SELECT_ITEM_LIST, 1 },
					{ NodeType::NODE_SELECT_ITEM, 0 },
					{ NodeType::NODE_STRING_LITERAL, 0 }
				};
				const auto rc_node { get_node(ast.get(), str_lit_path) };

				if (!rc_node.first) {
					return { 0, "" };
				} else {
					const string s_path { "[" + fold(acc_node_path, str_lit_path) + "]" };
					return { -1, "Failed to verify SUBSELECT with expected AST=`" + s_path + "`" };
				}
			} else {
				const auto acc_err = [] (const string& s1, const string& s2) { return s2 + "," + s1; };
				const string p_err { fold(acc_err, parser.get_errors()) };

				return { -1, "Failed to verify SUBSELECT due to parse error=`" + p_err + "`" };
			}
		}
	};

	/**
	 * @brief Verifies recurring simple expressions.
	 * @details The allowed expressions kinds are:
	 *   Type: EXPR
	 *   |-- FUNCTION CALL EXPRS, eg: 'REPLACE(@@sql_mode, 'STRICT_ALL_TABLES', 'STRICT_TRANS_TABLES')'
	 *   |-- STRING_LITERAL
	 *   |-- SYSTEM_VAR (SQL_MODE), eg: 'CONCAT(@@sql_mode, LITERAL)'
	 *   `-- SELECT_SUBQUERY, of kind '(SELECT STRING_LITERAL)'
	 * @param n The node from which to start the expression verification.
	 * @param offset Offset of the original query at which AST represented by 'n' is found.
	 * @return A pair of kind { success, error_message }.
	 */
	const auto verf_expr = [&] (const MySQLParser::AstNode* n, size_t offset) -> pair<int,string> {
		// Either SYS_VAR or FUNC_EXPR
		deque<const MySQLParser::AstNode*> n_queue { n };

		for (; !n_queue.empty(); n_queue.pop_front()) {
			const MySQLParser::AstNode* cur { n_queue.front() };
			const bool is_func { cur->value.substr(0, cur->value.find(':')) == "FUNC_CALL" };

			if (cur->type == NodeType::NODE_SELECT_RAW_SUBQUERY) {
				const auto verf_res { verf_select_lit(cur, q, offset) };

				if (verf_res.first) {
					return verf_res;
				}
			} else if (is_func) {
				const auto verf_res { verf_fn_expr(cur) };

				if (verf_res.first) {
					return verf_res;
				}
			} else {
				const auto is_valid { is_valid_lit(cur) || is_valid_sysvar(cur) };

				if (!is_valid) {
					const string lit_kind {
						"(value=`" + cur->value + "`, type=`" + to_string(cur->type) + "`)"
					};
					return { -1, "Invalid sysvar or literal=" + lit_kind + "" };
				}
			}

			// Jumping point to next verf state: S -> S1
			if (cur->type == NodeType::NODE_EXPR) {
				const auto rc_subexpr { get_node(cur, {{ NodeType::NODE_EXPR, 1 }}) };

				for (const MySQLParser::AstNode* c : rc_subexpr.second->children) {
					n_queue.push_back(c);
				}
			}
		}

		return { 0, "" };
	};

	// TODO: We assume a correct literal on user side. This will always be a best effort since supported SQL
	// modes depend on the server itself, and goes in line with a more deep evaluation of the values in SET
	// statements. A deeper analysis could also be used as connection selection criteria.
	const auto verf_str_lit = [] (const MySQLParser::AstNode* n) -> pair<int,string> {
		return { 0, "" };
	};

	const auto c { get_node(n, {{ NodeType::NODE_UNKNOWN, 1 }}) };

	if (c.first) {
		return { -1, perr_msg, { "Unable to extract value node from VAR_ASSIGN" } };
	} else {
		// Simplest form. Eg: SET sql_mode='foo'
		if (c.second->type == NodeType::NODE_STRING_LITERAL) {
			const auto verf_res { verf_str_lit(c.second) };

			if (verf_res.first) {
				return { -1, perr_msg, { verf_res.second } };
			}
		}
		// To check allowed expressions. Eg: SET sql_mode=CONCAT('foo', 'bar')
		else if (c.second->type == NodeType::NODE_EXPR) {
			size_t subexpr_offset { c.second->val_init_pos };
			const auto verf_res { verf_expr(c.second, subexpr_offset) };

			if (verf_res.first) {
				return { -1, perr_msg, { verf_res.second } };
			}
		}
		// To parse specially handled SELECT subqueries, composed of a limited subset of FUNC calls and string
		// literals: SET sql_mode=(SELECT CONCAT(@@sqlmode, 'foo')).
		else if (c.second->type == NodeType::NODE_SELECT_RAW_SUBQUERY) {
			size_t subsel_offset { c.second->val_init_pos };
			const string subsel_err {
				"Found invalid SUBSELECT expr=`" + string { v.data(), v.size() } + "`"
			};

			MySQLParser::Parser parser;
			std::unique_ptr<MySQLParser::AstNode> ast { parser.parse(rm_outer_parens(v)) };

			if (ast) {
				const vector<child_idx_t> c_pth {
					{ NodeType::NODE_SELECT_STATEMENT, 0 },
					{ NodeType::NODE_SELECT_ITEM_LIST, 1 },
					{ NodeType::NODE_SELECT_ITEM, 0 },
					{ NodeType::NODE_UNKNOWN, 0 }
				};
				const string s_c_pth { "[" + fold(acc_node_path, c_pth) + "]" };
				const auto s_c_node { get_node(ast.get(), c_pth) };

				if (s_c_node.first) {
					const string c_type { to_string(s_c_node.second->type) };
					const string last_node_err {
						"Last valid node=`" + c_type + "` found from expected AST=`" + s_c_pth + "`"
					};

					return { -1, perr_msg, { subsel_err, last_node_err } };
				} else {
					const auto& type = s_c_node.second->type;

					if (type == NodeType::NODE_SYSTEM_VARIABLE) {
						const bool is_valid { is_valid_sysvar(s_c_node.second) };

						if (is_valid) {
							return { 0 };
						} else {
							const string inv_var_err { "Failed to verify system variable" };
							return { -1, perr_msg, { subsel_err, inv_var_err } };
						}
					} else if (type == NodeType::NODE_STRING_LITERAL) {
						const auto verf_res { verf_str_lit(s_c_node.second) };

						if (verf_res.first) {
							return { -1, perr_msg, { verf_res.second } };
						}
					} else if (type == NodeType::NODE_EXPR) {
						const auto verf_res { verf_expr(s_c_node.second, subsel_offset) };

						if (verf_res.first) {
							return { -1, perr_msg, { subsel_err, verf_res.second } };
						} else {
							return { 0 };
						}
					} else {
						const string s_path { "[" + fold(acc_node_path, c_pth) + "]" };
						const string inv_node_err {
							"Invalid node=`"+ to_string(type) + "` found in path=`" + s_path + "`"
						};

						return { -1, perr_msg, { subsel_err, inv_node_err } };
					}
				}
			} else {
				const auto& errors = parser.get_errors();

				if (errors.empty()) {
					return { -1, perr_msg, { "No specific error, check parser logic or 'mysql_yyerror'" } };
				} else {
					const auto c_join = [](const string& s1, const string& s2) -> string {
						return s2.empty() ? s1 : s1 + "," + s2;
					};
					const string p_errs { "[" + fold(c_join, parser.get_errors()) + "]" };
					return { -1, perr_msg, { p_errs }};
				}
			}
		} else {
			const auto is_valid { is_valid_lit(c.second) || is_valid_sysvar(c.second) };

			if (is_valid) {
				return { 0 };
			} else {
				const string lit_kind {
					"(value=`" + c.second->value + "`, type=`" + to_string(c.second->type) + "`)"
				};
				return { -1, perr_msg, { "Invalid sysvar or literal=" + lit_kind + "" } };
			}
		}
	}

	return { 0 };
}
