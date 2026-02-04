#ifndef MYSQL_PARSER_AST_H
#define MYSQL_PARSER_AST_H

#include <string>
#include <vector>
#include <iostream>

namespace MySQLParser {

// Enum for Abstract Syntax Tree Node Types
enum class NodeType {
	NODE_UNKNOWN,
	NODE_COMMAND,               // General command like QUIT
	NODE_SELECT_STATEMENT,
	NODE_INSERT_STATEMENT,
	NODE_DELETE_STATEMENT,
	NODE_IDENTIFIER,
	NODE_STRING_LITERAL,
	NODE_NUMBER_LITERAL,         // For numeric values
	NODE_BOOLEAN_LITERAL,        // For boolean values
	NODE_NULL_LITERAL,           // For NULL literal
	NODE_VALUE_LITERAL,          // For values with no type; options like 'ON'
	NODE_TIMESTAMP,              // For dates
	NODE_INTERVAL,               // For dates
	NODE_ASTERISK,               // For '*' in SELECT
	NODE_SET_STATEMENT,
	NODE_SET_OPTION_VALUE_LIST,
	NODE_VARIABLE_ASSIGNMENT,
	NODE_USER_VARIABLE,           // e.g., @my_var
	NODE_SYSTEM_VARIABLE,         // e.g., @@global.var
	NODE_VARIABLE_SCOPE,          // GLOBAL, SESSION, PERSIST, etc.
	NODE_EXPR,                    // Placeholder for more complex expressions (and functions)
	NODE_SIMPLE_EXPRESSION,       // More specific expression type
	NODE_INTERVAL_EXPRESSION,     // More specific expression type
	NODE_AGGREGATE_FUNCTION_CALL, // For COUNT, SUM, AVG etc.
	NODE_SET_NAMES,
	NODE_SET_CHARSET,
	NODE_DELETE_OPTIONS,        // LOW_PRIORITY, QUICK, IGNORE for DELETE
	NODE_TABLE_NAME_LIST,       // For multi-table DELETE or other lists of tables
	NODE_FROM_CLAUSE,
	NODE_USING_CLAUSE,          // For JOIN ... USING (...)
	NODE_WHERE_CLAUSE,
	NODE_HAVING_CLAUSE,         // Added for HAVING
	NODE_ORDER_BY_CLAUSE,
	NODE_ORDER_BY_ITEM,
	NODE_LIMIT_CLAUSE,
	NODE_ESCAPE_CLAUSE,
	NODE_COMPARISON_EXPRESSION, // e.g., col = 5
	NODE_LOGICAL_AND_EXPRESSION, // For AND operator
	NODE_OPERATOR,               // e.g., =, <, +, -, JOIN type strings
	NODE_LEFT_SHIFT_OPERATOR,    // e.g., <<
	NODE_RIGHT_SHIFT_OPERATOR,   // e.g., >>
	NODE_QUALIFIED_IDENTIFIER,   // e.g., table.column

	// For SELECT specific parts
	NODE_SELECT_OPTIONS,        // DISTINCT, SQL_CALC_FOUND_ROWS etc.
	NODE_SELECT_ITEM_LIST,      // List of expressions/columns in SELECT
	NODE_SELECT_ITEM,           // A single item in the SELECT list
	NODE_SELECT_RAW_SUBQUERY,   // Subquery parsing placeholder
	NODE_ALIAS,                 // For 'AS alias_name'
	NODE_TABLE_REFERENCE,       // Reference to a table (name, derived, join result)
	NODE_GROUP_BY_CLAUSE,
	NODE_GROUPING_ELEMENT,      // Item in GROUP BY

	// For JOIN clauses
	NODE_JOIN_CLAUSE,           // Represents a join operation (e.g., t1 JOIN t2)
	NODE_JOIN_TYPE_NATURAL_SPEC,// For 'NATURAL [LEFT|RIGHT|INNER] JOIN' specifier
	NODE_JOIN_CONDITION_ON,     // ON <expr>
	NODE_JOIN_CONDITION_USING,  // USING (col1, col2)
	NODE_COLUMN_LIST,           // For USING (col_list) or INTO (var_list)

	// Nodes for INTO, LOCKING, DERIVED TABLES
	NODE_INTO_CLAUSE,           // Wrapper for INTO ... variants
	NODE_INTO_VAR_LIST,         // INTO @var1, @var2
	NODE_INTO_OUTFILE,          // INTO OUTFILE 'filename' [options]
	NODE_INTO_DUMPFILE,         // INTO DUMPFILE 'filename'
	NODE_LOCKING_CLAUSE_LIST,   // Wrapper for one or more locking clauses
	NODE_LOCKING_CLAUSE,        // FOR UPDATE | FOR SHARE
	NODE_LOCK_STRENGTH,         // Stores "UPDATE" or "SHARE"
	NODE_LOCK_TABLE_LIST,       // Optional 'OF table_list' for locking
	NODE_LOCK_OPTION,           // Optional 'NOWAIT' or 'SKIP LOCKED'
	NODE_DERIVED_TABLE,         // Represents (SELECT ...) AS alias
	NODE_SUBQUERY,              // The (SELECT ...) part of a derived table or sub-expression

	// For INTO OUTFILE options
	NODE_FILE_OPTIONS,          // Wrapper for all file format options
	NODE_FIELDS_OPTIONS_CLAUSE, // Wrapper for FIELDS related options
	NODE_LINES_OPTIONS_CLAUSE,  // Wrapper for LINES related options
	NODE_FIELDS_TERMINATED_BY,
	NODE_FIELDS_ENCLOSED_BY,
	NODE_FIELDS_OPTIONALLY_ENCLOSED_BY,
	NODE_FIELDS_ESCAPED_BY,
	NODE_LINES_STARTING_BY,
	NODE_LINES_TERMINATED_BY,
	NODE_CHARSET_OPTION,        // For CHARACTER SET 'name' in OUTFILE

	NODE_KEYWORD,               // For storing keywords like ALL, DISTINCT (as value) in some contexts

	// Added for SHOW, BEGIN, COMMIT
	NODE_SHOW_STATEMENT,
	NODE_BEGIN_STATEMENT,
	NODE_COMMIT_STATEMENT,
	NODE_SHOW_OPTION_FULL,      // For SHOW FULL ...
	NODE_SHOW_OPTION_FIELDS,    // For SHOW ... FIELDS
	NODE_SHOW_TARGET_DATABASES, // For SHOW DATABASES
	NODE_TABLE_SPECIFICATION,   // For FROM table_name in SHOW FIELDS

	// Added for IS NULL / IS NOT NULL
	NODE_IS_NULL_EXPRESSION,
	NODE_IS_NOT_NULL_EXPRESSION
};

struct AstNode;

inline void print_ast(const AstNode* node, int indent = 0);

/**
 * @brief Structure for an Abstract Syntax Tree (AST) Node.
 * @details Represents a node in the AST, storing its type, value, children, and position information.
 */
struct AstNode {
	/**
	 * @brief The type of the AST node.
	 */
	NodeType type;
	/**
	 * @brief The value of the AST node.
	 * @details Identifier name, literal value, operator type, etc.
	 */
	std::string value;
	/**
	 * @brief The child nodes of this AST node.
	 */
	std::vector<AstNode*> children;
	/**
	 * @brief The starting position of the value in the source code.
	 */
	size_t val_init_pos { 0 };
	/**
	 * @brief The ending position of the value in the source code.
	 */
	size_t val_end_pos { 0 };
	/**
	 * @brief Constructor for AstNode.
	 * @param t The type of the node.
	 * @param val The value of the node (default: "").
	 */
	AstNode(NodeType t, const std::string& val = "") : type(t), value(val) {}
	/**
	 * @brief Move constructor for value.
	 * @param t The type of the node.
	 * @param val The value of the node (rvalue reference).
	 */
	AstNode(NodeType t, std::string&& val) : type(t), value(std::move(val)) {}
	/**
	 * @brief Destructor.
	 * @details Iterates through the childs, freeing resources.
	 */
	~AstNode() {
		for (AstNode* child : children) {
			delete child;
		}
	}
	/**
	 * @brief Deleted copy constructor to prevent implicit copying.
	 */
	AstNode(const AstNode&) = delete;
	/**
	 * @brief Deleted copy assignment operator to prevent implicit copying.
	 */
	AstNode& operator=(const AstNode&) = delete;
	/**
	 * @brief Deleted move constructor.
	 */
	AstNode(AstNode&&) = delete;
	/**
	 * @brief Deleted move assignment operator.
	 */
	AstNode& operator=(AstNode&&) = delete;
	/**
	 * @brief Adds a child node to the current node.
	 * @param child Pointer to the child node to be added. If the pointer is null, the child is not added.
	 */
	void add_child(AstNode* child) {
		if (child) {
			children.push_back(child);
		}
	}
};

inline std::string to_string(NodeType t) {
	if (t == NodeType::NODE_UNKNOWN) { return "UNKNOWN"; }
	else if (t == NodeType::NODE_COMMAND) { return "COMMAND"; }
	else if (t == NodeType::NODE_SELECT_STATEMENT) { return "SELECT_STMT"; }
	else if (t == NodeType::NODE_INSERT_STATEMENT) { return "INSERT_STMT"; }
	else if (t == NodeType::NODE_DELETE_STATEMENT) { return "DELETE_STMT"; }
	else if (t == NodeType::NODE_IDENTIFIER) { return "IDENTIFIER"; }
	else if (t == NodeType::NODE_STRING_LITERAL) { return "STRING_LITERAL"; }
	else if (t == NodeType::NODE_NUMBER_LITERAL) { return "NUMBER_LITERAL"; }
	else if (t == NodeType::NODE_BOOLEAN_LITERAL) { return "BOOLEAN_LITERAL"; }
	else if (t == NodeType::NODE_NULL_LITERAL) { return "NULL_LITERAL"; }
	else if (t == NodeType::NODE_VALUE_LITERAL) { return "VALUE_LITERAL"; }
	else if (t == NodeType::NODE_TIMESTAMP) { return "TIMESTAMP"; }
	else if (t == NodeType::NODE_INTERVAL) { return "INTERVAL"; }
	else if (t == NodeType::NODE_ASTERISK) { return "ASTERISK"; }
	else if (t == NodeType::NODE_SET_STATEMENT) { return "SET_STATEMENT"; }
	else if (t == NodeType::NODE_VARIABLE_ASSIGNMENT) { return "VAR_ASSIGN"; }
	else if (t == NodeType::NODE_SET_OPTION_VALUE_LIST) { return "SET_OPTION_VALUE_LIST"; }
	else if (t == NodeType::NODE_USER_VARIABLE) { return "USER_VAR"; }
	else if (t == NodeType::NODE_SYSTEM_VARIABLE) { return "SYSTEM_VAR"; }
	else if (t == NodeType::NODE_VARIABLE_SCOPE) { return "VAR_SCOPE"; }
	else if (t == NodeType::NODE_EXPR) { return "EXPR"; }
	else if (t == NodeType::NODE_SIMPLE_EXPRESSION) { return "SIMPLE_EXPRESSION"; }
	else if (t == NodeType::NODE_INTERVAL_EXPRESSION) { return "INTERVAL_EXPRESSION"; }
	else if (t == NodeType::NODE_AGGREGATE_FUNCTION_CALL) { return "AGGREGATE_FUNC_CALL"; }
	else if (t == NodeType::NODE_SET_NAMES) { return "SET_NAMES"; }
	else if (t == NodeType::NODE_SET_CHARSET) { return "SET_CHARSET"; }
	else if (t == NodeType::NODE_DELETE_OPTIONS) { return "DELETE_OPTIONS"; }
	else if (t == NodeType::NODE_TABLE_NAME_LIST) { return "TABLE_NAME_LIST"; }
	else if (t == NodeType::NODE_FROM_CLAUSE) { return "FROM_CLAUSE"; }
	else if (t == NodeType::NODE_USING_CLAUSE) { return "USING_CLAUSE"; }
	else if (t == NodeType::NODE_WHERE_CLAUSE) { return "WHERE_CLAUSE"; }
	else if (t == NodeType::NODE_HAVING_CLAUSE) { return "HAVING_CLAUSE"; }
	else if (t == NodeType::NODE_ORDER_BY_CLAUSE) { return "ORDER_BY_CLAUSE"; }
	else if (t == NodeType::NODE_ORDER_BY_ITEM) { return "ORDER_BY_ITEM"; }
	else if (t == NodeType::NODE_LIMIT_CLAUSE) { return "LIMIT_CLAUSE"; }
	else if (t == NodeType::NODE_ESCAPE_CLAUSE) { return "ESCAPE_CLAUSE"; }
	else if (t == NodeType::NODE_COMPARISON_EXPRESSION) { return "COMPARISON_EXPR"; }
	else if (t == NodeType::NODE_LOGICAL_AND_EXPRESSION) { return "LOGICAL_AND_EXPR"; }
	else if (t == NodeType::NODE_OPERATOR) { return "OPERATOR"; }
	else if (t == NodeType::NODE_QUALIFIED_IDENTIFIER) { return "QUALIFIED_IDENTIFIER"; }
	else if (t == NodeType::NODE_SELECT_OPTIONS) { return "SELECT_OPTIONS"; }
	else if (t == NodeType::NODE_SELECT_ITEM_LIST) { return "SELECT_ITEM_LIST"; }
	else if (t == NodeType::NODE_SELECT_ITEM) { return "SELECT_ITEM"; }
	else if (t == NodeType::NODE_SELECT_RAW_SUBQUERY) { return "NODE_SELECT_RAW_SUBQUERY"; }
	else if (t == NodeType::NODE_ALIAS) { return "ALIAS"; }
	else if (t == NodeType::NODE_TABLE_REFERENCE) { return "TABLE_REFERENCE"; }
	else if (t == NodeType::NODE_GROUP_BY_CLAUSE) { return "GROUP_BY_CLAUSE"; }
	else if (t == NodeType::NODE_GROUPING_ELEMENT) { return "GROUPING_ELEMENT"; }
	else if (t == NodeType::NODE_JOIN_CLAUSE) { return "JOIN_CLAUSE"; }
	else if (t == NodeType::NODE_JOIN_TYPE_NATURAL_SPEC) { return "JOIN_TYPE_NATURAL_SPEC"; }
	else if (t == NodeType::NODE_JOIN_CONDITION_ON) { return "JOIN_CONDITION_ON"; }
	else if (t == NodeType::NODE_JOIN_CONDITION_USING) { return "JOIN_CONDITION_USING"; }
	else if (t == NodeType::NODE_COLUMN_LIST) { return "COLUMN_LIST"; }
	else if (t == NodeType::NODE_INTO_CLAUSE) { return "INTO_CLAUSE"; }
	else if (t == NodeType::NODE_INTO_VAR_LIST) { return "INTO_VAR_LIST"; }
	else if (t == NodeType::NODE_INTO_OUTFILE) { return "INTO_OUTFILE"; }
	else if (t == NodeType::NODE_INTO_DUMPFILE) { return "INTO_DUMPFILE"; }
	else if (t == NodeType::NODE_LOCKING_CLAUSE_LIST) { return "LOCKING_CLAUSE_LIST"; }
	else if (t == NodeType::NODE_LOCKING_CLAUSE) { return "LOCKING_CLAUSE"; }
	else if (t == NodeType::NODE_LOCK_STRENGTH) { return "LOCK_STRENGTH"; }
	else if (t == NodeType::NODE_LOCK_TABLE_LIST) { return "LOCK_TABLE_LIST"; }
	else if (t == NodeType::NODE_LOCK_OPTION) { return "LOCK_OPTION"; }
	else if (t == NodeType::NODE_DERIVED_TABLE) { return "DERIVED_TABLE"; }
	else if (t == NodeType::NODE_SUBQUERY) { return "SUBQUERY"; }
	else if (t == NodeType::NODE_FILE_OPTIONS) { return "FILE_OPTIONS"; }
	else if (t == NodeType::NODE_FIELDS_OPTIONS_CLAUSE) { return "FIELDS_OPTIONS_CLAUSE"; }
	else if (t == NodeType::NODE_LINES_OPTIONS_CLAUSE) { return "LINES_OPTIONS_CLAUSE"; }
	else if (t == NodeType::NODE_FIELDS_TERMINATED_BY) { return "FIELDS_TERMINATED_BY"; }
	else if (t == NodeType::NODE_FIELDS_ENCLOSED_BY) { return "FIELDS_ENCLOSED_BY"; }
	else if (t == NodeType::NODE_FIELDS_OPTIONALLY_ENCLOSED_BY) { return "FIELDS_OPTIONALLY_ENCLOSED_BY"; }
	else if (t == NodeType::NODE_FIELDS_ESCAPED_BY) { return "FIELDS_ESCAPED_BY"; }
	else if (t == NodeType::NODE_LINES_STARTING_BY) { return "LINES_STARTING_BY"; }
	else if (t == NodeType::NODE_LINES_TERMINATED_BY) { return "LINES_TERMINATED_BY"; }
	else if (t == NodeType::NODE_CHARSET_OPTION) { return "CHARSET_OPTION"; }
	else if (t == NodeType::NODE_KEYWORD) { return "KEYWORD"; }
	else if (t == NodeType::NODE_SHOW_STATEMENT) { return "SHOW_STMT"; }
	else if (t == NodeType::NODE_BEGIN_STATEMENT) { return "BEGIN_STMT"; }
	else if (t == NodeType::NODE_COMMIT_STATEMENT) { return "COMMIT_STMT"; }
	else if (t == NodeType::NODE_SHOW_OPTION_FULL) { return "SHOW_OPT_FULL"; }
	else if (t == NodeType::NODE_SHOW_OPTION_FIELDS) { return "SHOW_OPT_FIELDS"; }
	else if (t == NodeType::NODE_SHOW_TARGET_DATABASES) { return "SHOW_TARGET_DB"; }
	else if (t == NodeType::NODE_TABLE_SPECIFICATION) { return "TABLE_SPEC"; }
	else if (t == NodeType::NODE_IS_NULL_EXPRESSION) { return "IS_NULL_EXPR"; }
	else if (t == NodeType::NODE_IS_NOT_NULL_EXPRESSION) { return "IS_NOT_NULL_EXPR"; }
	else {
		return "UNHANDLED_TYPE(" + std::to_string(static_cast<int>(t)) + ")";
	}
}

// Helper function to print the AST (for debugging)
inline void print_ast(const AstNode* node, int indent) {
	if (!node) return;

	for (int i = 0; i < indent; ++i) std::cout << "  ";

	std::cout << "Type: " << to_string(node->type);
	if (!node->value.empty()) {
		std::cout << ", Value: '" << node->value << "'";
	}
	std::cout << std::endl;

	for (const AstNode* child : node->children) {
		print_ast(child, indent + 1);
	}
}

} // namespace MySQLParser

#endif // MYSQL_PARSER_AST_H

