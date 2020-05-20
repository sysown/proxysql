#ifndef UTILS_H
#define UTILS_H

#include <mysql.h>
#include <string>
#include <vector>

#define MYSQL_QUERY(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			return exit_status(); \
		} \
	} while(0)

#ifdef __cplusplus
extern "C" {
#endif

int show_variable(MYSQL *mysql, const std::string& var_name, std::string& var_value);
int show_admin_global_variable(MYSQL *mysql, const std::string& var_name, std::string& var_value);
int set_admin_global_variable(MYSQL *mysql, const std::string& var_name, const std::string& var_value);
int get_server_version(MYSQL *mysql, std::string& version);
int select_config_file(MYSQL* mysql, std::string& resultset);

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
