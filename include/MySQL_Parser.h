#ifndef MYSQL_PARSER_PARSER_H
#define MYSQL_PARSER_PARSER_H

#include "MySQL_AST.h" // Uses MySQLParser::AstNode
#include <string>
#include <vector>
#include <memory>

/**
 * @brief Opaque type for Flex holding the scanner state
 */
typedef void* yyscan_t;

namespace MySQLParser {

/**
 * @class Parser
 * @brief Parses SQL queries and generates an Abstract Syntax Tree (AST).
 * @details Uses Flex and Bison to tokenize and parse SQL queries. The class itself acts as a
 *   closure, holding the internal parser state and error reporting. This state is shared with the
 *   Bison parser through `this` pointer.
 */
class Parser {
public:
	/**
	 * @brief Constructor for the Parser class.
	 * @details Initializes the Flex scanner.
	 * @throws std::runtime_error On scanner initialization fails.
	 */
	Parser();
	/**
	 * @brief Destructor for the Parser class.
	 * @details Cleanups Flex scanner internal state.
	 */
	~Parser();
	/**
	 * @brief Parses an SQL query string.
	 * @param sql_query The SQL query string to parse.
	 * @return Root node of the generated AST, or nullptr on failure.
	 */
	std::unique_ptr<AstNode> parse(const std::string& sql_query);
	/**
	 * @brief Retrieves the list of errors encountered during parsing.
	 * @return A constant reference to the vector of error messages.
	 */
	const std::vector<std::string>& get_errors() const;
	/**
	 * @brief Clears the list of errors.
	 */
	void clear_errors();

	/**
	 * @brief Internal method used by Bison to set the root of the AST.
	 * @details Called by the Bison-generated parsing code to set the root
	 *   of the Abstract Syntax Tree (AST) after a successful parse.
	 * @param root The root AstNode of the AST. Parser takes ownership.
	 */
	void internal_set_ast(AstNode* root);
	/**
	 * @brief Internal method used by Flex/Bison to add a generic error message.
	 * @param msg The error message to add.
	 */
	void internal_add_error(const std::string& msg);
	/**
	 * @brief Internal method used by Flex/Bison to add an error message with line and column information.
	 * @param msg The error message to add.
	 * @param line The line number where the error occurred.
	 * @param column The column number where the error occurred.
	 */
	void internal_add_error_at(const std::string& msg, int line, int column);

private:
	/**
	 * @brief The root node of the Abstract Syntax Tree (AST).
	 */
	std::unique_ptr<AstNode> ast_root_;
	/**
	 * @brief Vector with the error messages encountered during parsing.
	 */
	std::vector<std::string> errors_;
	/**
	 * @brief The Flex scanner state.
	 */
	yyscan_t scanner_state_;
};

} // namespace MySQLParser

struct MYSQL_YYLTYPE;

/**
 * @brief Declaration for mysql_yyerror, called by Bison's mysql_yyparse.
 * @param yyscanner The scanner state.
 * @param parser_context The parser context.
 * @param msg The error message.
 */
void mysql_yyerror(yyscan_t yyscanner, MySQLParser::Parser* parser_context, const char* msg);
/**
 * @brief Overload for mysql_yyerror, including an extra parameter for location tracking.
 * @param yyloc The location of the token where the error occurred, provided by the lexer.
 * @param yyscanner The scanner state.
 * @param parser_context The parser context.
 * @param msg The error message.
 */
void mysql_yyerror(
	MYSQL_YYLTYPE* yyloc, yyscan_t yyscanner, MySQLParser::Parser* parser_context, const char* msg
);

#endif // MYSQL_PARSER_PARSER_H
