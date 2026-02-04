#ifndef MYSQL_PARSER_UTILS_H
#define MYSQL_PARSER_UTILS_H

#include "MySQL_AST.h"

#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

/**
 * @brief Represents the type of variable.
 */
enum class var_type_t {
	/**
	 * @brief User-defined variable.
	 */
	user = 0,
	/**
	 * @brief System variable.
	 */
	system
};

/**
 * @brief Stores information about a variable assignment.
 */
struct assign_info_t {
	/**
	 * @brief The type of the variable. Defaults to `var_type_t::user`.
	 */
	var_type_t var_type { var_type_t::user };
	/**
	 * @brief Pointer to the AST node representing the variable assignment.
	 * @details Should **never** be 'nullptr' since an assignment must have a core node.
	 */
	const MySQLParser::AstNode* node { nullptr };
	/**
	 * @brief The assigned value as a string view.
	 */
	std::string_view val {};
};

/**
 * @brief Represents a variable name.
 */
using var_name_t = std::string;

/**
 * @brief Map with keys as variable name and the value is a vector of strings representing the assigned values
 *  for that variable.
 */
using var_map_t = std::map<var_name_t, std::vector<assign_info_t>>;

/**
 * @brief Stores details about a `SET` query.
 */
struct set_details_t {
	/**
	 * @brief Indicates whether the `SET` query contains a user-defined variable.
	 */
	bool has_user_var { false };
	/**
	 * @brief Map containing the variable names and their assigned values.
	 */
	var_map_t vars_assigns {};
};

/**
 * @brief Represents an unknown/unsupported query type.
 */
struct unknown_details_t {};

/**
 * @brief Helper struct for implementing a variant visitor. Allows visiting a variant with multiple
 *        possible types using a single function call.
 * @tparam Ts Types to overload.
 */
template<class... Ts>
struct overloaded : Ts... { using Ts::operator()...; };

/**
 * @brief Deduction guide for the `overloaded` struct.
 * @tparam Ts Types to overload.
 * @param Ts... Function objects to overload.
 */
template<class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

/**
 * @brief Represents the details of a query, which can be one of several types.
 */
using query_details_t = std::variant<
	unknown_details_t, // MYSQL_COM_QUERY_UNKNOWN
	set_details_t      // MYSQL_COM_QUERY_SET
>;

#endif // MYSQL_PARSER_UTILS_H
