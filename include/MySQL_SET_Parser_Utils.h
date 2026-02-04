#ifndef MYSQL_SET_PARSER_UTILS_H
#define MYSQL_SET_PARSER_UTILS_H

#include "MySQL_AST.h"

#include <map>

/**
 * @brief Map where the key is the variable name and the value is a vector of strings representing the
 *  assigned values for that variable.
 */
using var_map_t = std::map<std::string, std::vector<std::pair<const MySQLParser::AstNode*, std::string>>>;

/**
 * @brief Extracts the AST nodes corresponding to variable assignments from a SQL SET statement's AST.
 * @details This function performs a breadth-first traversal of the Abstract Syntax Tree (AST) rooted at
 *  `root` to identify and extract all nodes representing variable assignments (NODE_VARIABLE_ASSIGNMENT). It
 *  prunes the search space by considering the depth of the nodes. Once the first variable assignment node is
 *  found, subsequent nodes at the same depth are also added to the result. Deeper nodes are ignored, and
 *  shallower nodes terminate the search.
 *
 * @param root A pointer to the root node of the AST. If `root` is `nullptr`, an empty vector is returned.
 * @return A vector containing pointers to the AST nodes of type `NODE_VARIABLE_ASSIGNMENT` that represent
 *         variable assignments within the SQL SET statement.  Returns an empty vector if no such nodes are found,
 *         or if the input `root` is `nullptr`.
 */
std::vector<const MySQLParser::AstNode*> ext_vars_assigns(const MySQLParser::AstNode* root);
/**
 * @brief Extracts variable assignments and maps them to their corresponding values from a SQL SET
 *  statement's AST.
 * @details This function leverages the `ext_vars_assigns` function to identify variable assignment nodes
 *  within the AST and then extracts the variable name and assigned value for each assignment.
 *
 * @param root A pointer to the root node of the AST. If `root` is `nullptr`, an empty map is returned.
 * @param q The original SQL query string from which the AST was generated. Used to extract the values.
 * @return A map where the key is the variable name (string) and the value is a vector of strings
 *  representing the assigned values for that variable. Returns an empty map if no variable assignments are
 *  found or if the input `root` is `nullptr`.
 */
var_map_t ext_vars_assigns_map(const MySQLParser::AstNode* root, const std::string& q);

/**
 * @brief Helper type that holds an RC and an extra value.
 * @details The kind of the contained object is { error_code, value }:
 *  - { rc, {} }: When holding an error, and empty (default constructed) value.
 *  - { 0, val }: On succeed operation.
 */
template <typename T>
using rc_t = std::pair<int,T>;
/**
 * @brief Helper type used to specify a child type and expected index in the AST tree.
 * @details The first element of the pair is the expected `NodeType` of the child, and the second element is
 *  the index of the child within the parent's `children` vector.
 */
using child_idx_t = std::pair<MySQLParser::NodeType, size_t>;
/**
 * @brief Retrieves a node from the AST based on a provided path.
 * @details Traverses the Abstract Syntax Tree (AST) from a given root node, following a specified path of
 *  child indices. It checks the node type at each step against the expected type in the path.
 *
 * @param root A pointer to the root node of the AST to traverse.
 * @param c_path A vector of child_idx_t, where each pair represents a child index to follow.
 *
 * @return A `rc_t<const MySQLParser::AstNode*>`:
 *   - The first element of the pair is an integer return code, `0` on success, `-1` otherwise.
 *   - The second element of the pair is a pointer to the `AstNode` where the traversal ended, either the
 *     target node or the node where an error occurred.
 *
 * @details The function iterates through the `c_path` vector. For each `c_idx` in the path:
 *   1. It checks if the current node has children and if the child index `c_idx.second` is within the bounds
 *      of the `children` vector.
 *   2. If the index is valid, it updates `cur_node` to point to the child node.
 *   3. It then checks the `NodeType` of the child.
 *      - If the expected `NodeType` is `NODE_UNKNOWN`, the check is skipped, and traversal continues.
 *      - Otherwise, it compares the `type` of the current node with the expected `NodeType` `c_idx.first`.
 *        If they don't match, it returns an error code of `-1` along with the current node.
 *   4. If the index is invalid (either no children or index out of bounds), it returns an error code of `-1`
 *      along with the current node.
 *   If the entire path is traversed successfully, the function returns a success code of `0` along with the
 *   final `cur_node`.
 */
rc_t<const MySQLParser::AstNode*> get_node(
    const MySQLParser::AstNode* root, const std::vector<child_idx_t>& c_path
);
/**
 * @brief Checks if a given AST node matches a specific pattern related to SET statements.
 * @details Hanldes both `NODE_SET_STATEMENT` and `NODE_SET_NAMES` node types. This implementation
 *  serves as an equivalent to a previous regex-based approach (`match_regexes[1]`):
 *    - `NODE_SET_STATEMENT`: Verifies that the statement contains variable assignments, that each assigned
 *      variable is a tracked system variable (or "autocommit"), and that the system variable is present in
 *      the `tracked_vars` list.
 *    - `NODE_SET_NAMES`: Returns `true`, expected to be verified later.
 *    - Other node type: Returns `false`.
 * @param node A pointer to the AST node to check.
 * @return `true` if the node matches the expected pattern, `false` otherwise.
 */
bool p_match_regex_1(const MySQLParser::AstNode* node);
/**
 * @brief Checks if a given AST node matches a specific pattern related to transaction SET statements.
 * @details Handles `NODE_SET_STATEMENT` node types. This implementation
 *  serves as an equivalent to a previous regex-based approach (`match_regexes[2]`):
 *    - `NODE_SET_STATEMENT`: Verifies that the node's value is either "SET_SESSION_TRANSACTION" or
 *      "SET_TRANSACTION".
 *    - Other node type: Returns `false`.
 * @param node A pointer to the AST node to check.
 * @return `true` if the node matches the expected pattern, `false` otherwise.
 */
bool p_match_regex_2(const MySQLParser::AstNode* node);
/**
 * @brief Checks if a given AST node matches a specific pattern related to SET CHARSET statements.
 * @details Handles `NODE_SET_CHARSET` node types. This implementation
 *  serves as an equivalent to a previous regex-based approach (`match_regexes[3]`):
 *    - `NODE_SET_CHARSET`: Returns `true`.
 *    - Other node type: Returns `false`.
 * @param node A pointer to the AST node to check.
 * @return `true` if the node matches the expected pattern, `false` otherwise.
 */
bool p_match_regex_3(const MySQLParser::AstNode* node);
/**
 * @brief Type used for improved error reporting for AST based validation.
 * @details When returning an AST error message, it's expected to.
 */
struct perr_t {
	/// Return code used for error identification.
	int rc { 0 };
	/// Error message to report to the caller.
	std::string msg {};
	/// Chain of conditions, or sub-errors, that add context to the error.
	std::vector<std::string> ctx {};
};

/**
 * @brief Verifies recurring simple expressions.
 * @details The allowed expressions kinds are:
 *
 *   - STRING_LITERAL
 *   - SYSTEM_VAR
 *   - EXPR
 *     |-- FUNCTION CALL EXPRS, eg: 'REPLACE(@@sql_mode, 'STRICT_ALL_TABLES', 'STRICT_TRANS_TABLES')'
 *     |-- STRING_LITERAL
 *     |-- SYSTEM_VAR (SQL_MODE), eg: 'CONCAT(@@sql_mode, LITERAL)'
 *     `-- SELECT_SUBQUERY, of kind '(SELECT STRING_LITERAL)'
 *   - (SELECT EXPR) - Previously defined 'EXPR'
 *
 *   These definitions allows recursion, but only through the EXPR. Allowing generic recursion for
 *   '(SELECT EXPR)' was out of the scope. This can be enabled in the future.
 * @param n The node from which to start the expression verification.
 * @param offset Offset of the original query at which AST represented by 'n' is found.
 * @return A pair of kind { success, error_message }.
 */
perr_t verf_sql_mode_val(const MySQLParser::AstNode* n, const std::string& v, const std::string& q);

#endif // MYSQL_SET_PARSER_UTILS_H
