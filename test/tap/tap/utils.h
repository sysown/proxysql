#ifndef UTILS_H
#define UTILS_H

#include <mysql.h>
#include <algorithm>
#include <string>
#include <vector>
#include <string>
#include <type_traits>
#include <functional>
#include <memory>

#define MYSQL_QUERY(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			return exit_status(); \
		} \
	} while(0)

template<class...> struct conjunction : std::true_type { };
template<class B1> struct conjunction<B1> : B1 { };
template<class B1, class... Bn>
struct conjunction<B1, Bn...> 
    : std::conditional<bool(B1::value), conjunction<Bn...>, B1>::type {};

/**
 * @brief Stores the result of formatting the first parameter with the provided
 *  arguments, into the std::string reference provided in the second parameter.
 *
 * @param str The string to be formatted.
 * @param result A std::string reference in which store the formatted result.
 * @param args The additional arguments to be formatted into the string.
 * @return int In case of success 0 is returned, otherwise, the formatting error provided
 *  by 'snprintf' is provided.
 */
template<
	typename... Args,
	typename std::enable_if<conjunction<std::is_trivial<Args>...>::value,int>::type = 0
>
int string_format(const std::string& str, std::string& result, Args... args) {
	int err = 0;
	size_t size = snprintf(nullptr, 0, str.c_str(), args... ) + 1;

	if(size <= 0) {
		err = size;
	} else {
		std::unique_ptr<char[]> buf(new char[size]);
		snprintf(buf.get(), size, str.c_str(), args...);
		result = std::string(buf.get(), buf.get() + size - 1);
	}

	return err;
}

/**
 * @brief Helper function to create a error message with the specific
 * file and line embedded into it.
 *
 * @param msg The error message to be appended after the 'file and line'
 *  part of the message.
 * @param file String containing the source file of the error, i.e: '__FILE__'.
 * @param line Number containing the source line of the error, i.e: '__LINE__'.
 * @return std::string A string containing - "File %s, line %d, Error: " + 'msg' paremeter.
 */
std::string err_msg(const std::string& msg, const char* file, int line);

using key_map = std::vector<std::pair<std::string, std::vector<std::string>>>;

/**
 * @brief Returns a key_map containing the column names as keys of the map,
 *  and a vector of values as the values for the columns.
 *
 * @param mysql_res The mysql result to be converted into a key_map.
 * @return key_map The resulting keymap.
 */
key_map fetch_assoc(MYSQL_RES* mysql_res);

using m_row = std::vector<std::string>;

/**
 * @brief Get the rows from the key_map as a vector of vectors.
 *
 * @param map The key_map from which rows are going to be extracted.
 * @return std::vector<m_row> The rows of the keymap.
 */
std::vector<m_row> get_rows(key_map map);

using map_pair = std::pair<std::string,std::vector<std::string>>;

/**
 * @brief Join a vector of string into a single string using the provided separator.
 *
 * @param row The vector of strings to be combined.
 * @param sep The separator to be used.
 * @return std::string The resulting string.
 */
std::string join(const std::vector<std::string>& vec, const std::string& sep);

/**
 * @brief Gets the first row from the provided keymap, for which the column matching
 *  the parameter 'colum_name' contains a value specified in the 'value' parameter.
 *
 * @param map The map to be scrapped.
 * @param colum_name The column name to be matched while searching.
 * @param value The value to be matched withing the matched column.
 * @return m_row The first row that contains a matching value in the column specified.
 */
m_row get_matching_row(key_map map, const std::string& colum_name, const std::string& value);

std::vector<std::string> compare_row(const m_row& exp_row, const m_row& act_row);

/**
 * @brief Get the count from a "SELECT COUNT(*)" like query.
 *
 * @param mysql_res The result of the query, it should contain just a row and a column
 *  with the count result of the query. Otherwise the parameter is invalid and '-1' is returned.
 * @return If success, the count result of the query, or:
 *  - '-1' in case of the parameter being invalid.
 *  - '-2' in case of the query result failed to be parsed as a number.
 */
int fetch_count(MYSQL_RES* mysql_res);

#ifdef __cplusplus
extern "C" {
#endif

int show_variable(MYSQL *mysql, const std::string& var_name, std::string& var_value);
int show_admin_global_variable(MYSQL *mysql, const std::string& var_name, std::string& var_value);
int set_admin_global_variable(MYSQL *mysql, const std::string& var_name, const std::string& var_value);
int get_server_version(MYSQL *mysql, std::string& version);
int select_config_file(MYSQL* mysql, std::string& resultset);
int exec(const std::string& cmd, std::string& result);

#ifdef __cplusplus
}
#endif

/**
 * @brief Execute the given comand, and stores it's output.
 *
 * @param file File to be executed.
 * @param argv Arguments to be given to the executable.
 * @param result The output of the file execution. If the execution succeed it contains `stdout` output,
 *  in case of failure `stderr` contents are returned.
 * @return int Zero in case of success, or the errno returned by `execvp` in case of failure.
 */
int execvp(const std::string& file, const std::vector<const char*>& argv, std::string& result);

#endif // #define UTILS_H
