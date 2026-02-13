#include <string>
#include <utility>
#include <vector>

#include "MySQL_SET_Parser_Utils.h"

/**
 * @brief Queries for basic SET stmt syntax coverage.
 */
extern const std::vector<std::string> set_queries;
/**
 * @brief Cases from original 'setparser_test.cpp'.
 * @details extracted via 'ack -o "\"SET.*?\"," $path'
 */
extern const std::vector<std::string> setparser_queries;
/**
 * @brief Queries for exhaustive SET stmts syntax coverage.
 */
extern const std::vector<std::string> exhaustive_queries;
/**
 * @brief Queries for testing special validation for 'sql_mode'.
 */
extern const std::vector<std::string> valid_sql_mode_subexpr;
