#ifndef UTILS_H
#define UTILS_H

#include <mysql.h>
#include <string>
#include <vector>
#include <random>
#include <fstream>
#include <sstream>

#include <curl/curl.h>

#include "command_line.h"

#define MYSQL_QUERY(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			return EXIT_FAILURE; \
		} \
	} while(0)

#define MYSQL_QUERY_err(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
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

/**
 * @brief Generates a random string of the length of the provider 'strSize'
 *  parameter.
 *
 * @param strSize The size of the string to be generated.
 * @return A random string.
 */
std::string random_string(std::size_t strSize);

/**
 * @brief Helper function to wait for replication to complete,
 *   performs a simple supplied queried until it succeed or the
 *   timeout expires.
 *
 * @param proxy A already opened MYSQL connection to ProxySQL.
 * @param proxy_admin A already opened MYSQL connection to ProxySQL Admin interface.
 * @param check Query to perform until timeout expires. The query is expected to produce
 *   a result with only one ROW and one FIELD containing non-case sensitive strings "TRUE"
 *   or "FALSE". "TRUE" meaning that the replication check succeed.
 * @param timeout The timeout in seconds to retry the query.
 * @param reader_hg The current 'reader hostgroup' for which
 *   servers replication needs to be waited.
 *
 * @return EXIT_SUCCESS in case of success, EXIT_FAILURE
 *   otherwise.
 */
int wait_for_replication(
	MYSQL* proxy, MYSQL* proxy_admin, const std::string& check, uint32_t timeout, uint32_t reader_hg
);

/**
 * NOTE: This is a duplicate of 'proxysql_find_charset_collate' in 'MySQL_Variables.h'. Including
 * 'MySQL_Variables' is not a easy task due to its interdependeces with other ProxySQL modules.
 */
#ifdef LIBMYSQL_HELPER
MY_CHARSET_INFO * proxysql_find_charset_collate(const char *collatename);
#else
MARIADB_CHARSET_INFO * proxysql_find_charset_collate(const char *collatename);
#endif
/**
 * @brief Creates the new supplied user in ProxySQL with the provided
 *   attributes.
 *
 * @param proxysql_admin An already opened connection to ProxySQL Admin.
 * @param user The username of the user to be created.
 * @param pass The password of the user to be created.
 * @param attributes The 'attributes' value for the 'attributes' column
 *   for the user to be created.
 *
 * @return EXIT_SUCCESS in case of success, EXIT_FAILURE otherwise.
 */
int create_proxysql_user(
	MYSQL* proxysql_admin, const std::string& user, const std::string& pass, const std::string& attributes
);

/**
 * @brief Create a MySQL user for testing purposes in the server determined
 *  by supplied *already established* MySQL connection.
 *
 * @param mysql_server An already opened connection to a MySQL server.
 * @param user The name of the user to be created.
 * @param pass The password for the user to be created.
 *
 * @return EXIT_SUCCESS in case of success, EXIT_FAILURE otherwise.
 */
int create_mysql_user(MYSQL* mysql_server, const std::string& user, const std::string& pass);

using user_config = std::tuple<std::string, std::string, std::string>;

/**
 * @brief Create the extra required users for the test in
 *   both MYSQL and ProxySQL.
 *
 * @param proxysql_admin An already opened connection to ProxySQL admin
 *   interface.
 * @param mysql_server An already opened connection to a backend MySQL
 *   server.
 * @param user_attributes The user attributes whose should  be part of user
 *   configuration in ProxySQL side.
 *
 * @return EXIT_SUCCESS in case of success, EXIT_FAILURE otherwise.
 */
int create_extra_users(
	MYSQL* proxysql_admin, MYSQL* mysql_server, const std::vector<user_config>& users_config
);

std::string tap_curtime();
/**
 * @brief Returns ProxySQL cpu usage in ms.
 * @param intv The interval in which the CPU usage of ProxySQL is going
 *  to be measured.
 * @param cpu_usage Output parameter with the cpu usage by ProxySQL in
 *  'ms' in the specified interval.
 * @return 0 if success, -1 in case of error.
 */
int get_proxysql_cpu_usage(const CommandLine& cl, uint32_t intv, uint32_t& cpu_usage);

/**
 * @brief Helper struct holding connection options for helper functions creating MySQL connections.
 */
struct conn_opts_t {
	std::string host;
	std::string user;
	std::string pass;
	int port;
	uint64_t client_flags;
};

/**
 * @brief Helper function for waiting until ProxySQL is replying to client connections.
 *
 * @param opts The options to be used for performing the MySQL connection.
 * @param timeout Timeout for the wait.
 *
 * @return An opened MySQL* connection in case a connection could be created before timeout expired,
 *  'nullptr' otherwise.
 */
MYSQL* wait_for_proxysql(const conn_opts_t& opts, int timeout);

#endif // #define UTILS_H
