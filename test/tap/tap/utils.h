#ifndef UTILS_H
#define UTILS_H

#include <mysql.h>
#include <string>
#include <random>
#include <sstream>
#include <vector>
#include <random>
#include <fstream>
#include <sstream>

#include <curl/curl.h>

#define MYSQL_QUERY(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			return EXIT_FAILURE; \
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

// create table test.sbtest1 with num_rows rows
int create_table_test_sbtest1(int num_rows, MYSQL *mysql);
int add_more_rows_test_sbtest1(int num_rows, MYSQL *mysql);

using mysql_res_row = std::vector<std::string>;

/**
 * @brief Function that extracts the provided 'MYSQL_RES' into a vector of vector of
 *   strings.
 * @param my_res The 'MYSQL_RES' for which to extract the values. In case of
 *   being NULL an empty vector is returned.
 * @return The extracted values of all the rows present in the resultset.
 */
std::vector<mysql_res_row> extract_mysql_rows(MYSQL_RES* my_res);

/**
 * @brief Dummy write function to avoid CURL to write received output to stdout.
 * @return Returns the size presented.
 */
size_t my_dummy_write(char*, size_t size, size_t nmemb, void*);

/**
 * @brief Waits until the provided endpoint is ready to be used or the
 *   timeout period expired. For this checks the return code of
 *   'perform_simple_post' which only fails in case the 'CURL' request couldn't
 *   be performed, which is interpreted as endpoint not being yet ready.
 *
 * @param endpoint The endpoint to be queried.
 * @param post_params The required params to be supplied for the 'POST' endpoint
 *   call.
 * @param timeout The max time to wait before declaring a timeout, and
 *   returning '-1'.
 * @param delay The delay specified in 'ms' to be waited between retries.
 *
 * @return '0' in case the endpoint became available before the timeout, or
 *   '-1' in case the timeout expired.
 */
int wait_until_enpoint_ready(
	std::string endpoint, std::string post_params, uint32_t timeout, uint32_t delay=100
);

/**
 * @brief Perform a simple POST query to the specified endpoint using the supplied
 *  'post_params'.
 *
 * @param endpoint The endpoint to be exercised by the POST.
 * @param post_params The post parameters to be supplied to the script.
 * @param curl_out_err A uint64_t reference returning the result code of the
 *   query in case it has been performed. In case the query couldn't be
 *   performed, this value is never initialized.
 * @param curl_out_err A string reference to collect the error as a string reported
 *   by 'libcurl' in case of failure.
 *
 * @return The response code of the query in case of the query.
 */
CURLcode perform_simple_post(
	const std::string& endpoint, const std::string& post_params,
	uint64_t& curl_res_code, std::string& curl_out_err
);

#endif // #define UTILS_H
