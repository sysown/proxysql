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
 * @brief Simple struct that holds the 'timeout options' for 'wexecvp'.
 */
struct to_opts {
	uint timeout_us;
	uint it_delay_us;
	uint select_to_us;
};

/**
 * @brief Execute the given comand, and stores it's output.
 *
 * @param file File to be executed.
 * @param argv Arguments to be given to the executable.
 * @param result The output of the file execution. If the execution succeed it contains `stdout` output,
 *  in case of failure `stderr` contents are returned.
 * @param opts In case of pipe readin error, this timeout options are used for trying to terminate
 *  the child process nicely, before seding a SIGKILL to it:
 *    - timeout_us: Member specifies the total timeout to wait for the child to exit.
 *    - it_delay_us: Member specifies the waiting delay between checks.
 * @return int Zero in case of success, or the errno returned by `execvp` in case of failure.
 */
int wexecvp(const std::string& file, const std::vector<const char*>& argv, const to_opts* opts, std::string& s_stdout, std::string& s_stderr);

/*
 * @return int Zero in case of success, or the errno returned by `execvp` in case of failure.
 */
int execvp(const std::string& file, const std::vector<const char*>& argv, std::string& result);

/**
 * @brief Executes a command using popen and returns the output in the string supplied as second parameter.
 *
 * @param cmd The command to be executed.
 * @param result String with the output of the executed command.
 * @return int The error code returned by popen.
 */
int exec(const std::string& cmd, std::string& result);

#endif // #define UTILS_H
