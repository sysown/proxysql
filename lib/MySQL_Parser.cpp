#include "MySQL_Parser.h"

#include <cassert>
#include <stdexcept>

//                 Flex Utility Functions (MySQL_Lexer.yy.c)
////////////////////////////////////////////////////////////////////////////////

// Forward declaration for the opaque Flex buffer type
struct yy_buffer_state;
typedef struct yy_buffer_state *YY_BUFFER_STATE;

// No extern "C" required, as their definitions will also have C++ linkage.
extern int mysql_yylex_init_extra(MySQLParser::Parser* user_defined, yyscan_t* yyscanner_r);
extern int mysql_yylex_destroy(yyscan_t yyscanner);
extern YY_BUFFER_STATE mysql_yy_scan_string(const char *yy_str, yyscan_t yyscanner);
extern void mysql_yy_delete_buffer(YY_BUFFER_STATE b, yyscan_t yyscanner);

////////////////////////////////////////////////////////////////////////////////

//                Bison Parsing Functions (MySQL_Parser.tab.c)
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Bison-generated parser function. Compiled as C++, so C++ linkage.
 * @details Function signature is defined by Bison config options:
 *    - Selected `api.prefix {mysql_yy}` makes it `mysql_yyparse`.
 *    - Option `%parse-param` defines its arguments.
 *   No `extern "C"` required, as definitions will also be C++.
 * @param yyscanner The scanner state.
 * @param parser_context The parser context.
 * @return 0 on success, 1 for invalid input.
 */
extern int mysql_yyparse(yyscan_t yyscanner, MySQLParser::Parser* parser_context);

void mysql_yyerror(yyscan_t, MySQLParser::Parser* parser_context, const char* msg) {
    if (!parser_context) {
        assert(0 && "Invalid param: Context must be 'this' from 'mysqlparser::parser'.");
    } else {
        parser_context->internal_add_error(msg);
    }
}

void mysql_yyerror(MYSQL_YYLTYPE*, yyscan_t, MySQLParser::Parser* parser_context, const char* msg) {
    if (!parser_context) {
        assert(0 && "Invalid param: Context must be 'this' from 'mysqlparser::parser'.");
    } else {
        parser_context->internal_add_error(msg);
    }
}

////////////////////////////////////////////////////////////////////////////////

namespace MySQLParser {

Parser::Parser() : ast_root_(nullptr), scanner_state_(nullptr) {
    if (mysql_yylex_init_extra(this, &scanner_state_)) {
        throw std::runtime_error("MySQLParser: Failed to initialize Flex scanner.");
    }
}

Parser::~Parser() {
    if (scanner_state_) {
        mysql_yylex_destroy(scanner_state_);
    }
}

void Parser::clear_errors() {
    errors_.clear();
}

const std::vector<std::string>& Parser::get_errors() const {
    return errors_;
}

std::unique_ptr<AstNode> Parser::parse(const std::string& sql_query) {
    clear_errors();
    ast_root_.reset();

    if (!scanner_state_) {
        errors_.push_back("MySQLParser: Scanner not initialized.");
        return nullptr;
    }

    YY_BUFFER_STATE buffer_state = mysql_yy_scan_string(sql_query.c_str(), scanner_state_);
    if (!buffer_state) {
        errors_.push_back("MySQLParser: Error setting up scanner buffer for query.");
        return nullptr;
    }

    // Call mysql_yyparse (function from the C++ compiled .tab.c)
    int parse_result = mysql_yyparse(scanner_state_, this);

    mysql_yy_delete_buffer(buffer_state, scanner_state_);

    if (parse_result == 0) {
        return std::move(ast_root_);
    }
    return nullptr;
}

void Parser::internal_set_ast(AstNode* root) {
    ast_root_.reset(root);
}

void Parser::internal_add_error(const std::string& msg) {
    errors_.push_back(msg);
}

void Parser::internal_add_error_at(const std::string& msg, int line, int column) {
    errors_.push_back("Line " + std::to_string(line) + ", Col " + std::to_string(column) + ": " + msg);
}

} // namespace MySQLParser

