#ifndef UTILS_H
#define UTILS_H

#include <algorithm>
#include <string>
#include <vector>
#include <random>
#include <fstream>
#include <sstream>

#include <curl/curl.h>
#include <mysql.h>

#include "command_line.h"

inline std::string get_formatted_time() {
	time_t __timer;
	char __buffer[30];

	struct tm __tm_info {};
	time(&__timer);
	localtime_r(&__timer, &__tm_info);
	strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", &__tm_info);

	return std::string(__buffer);
}

int mysql_query_t(MYSQL* mysql, const char* query);

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

#define MYSQL_QUERY_T(mysql, query) \
	do { \
		const std::string time { get_formatted_time() }; \
		fprintf(stderr, "# %s: Issuing query '%s' to ('%s':%d)\n", time.c_str(), query, mysql->host, mysql->port); \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql)); \
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
int create_table_test_sqlite_sbtest1(int num_rows, MYSQL *mysql); // as above, but for SQLite3 server
int add_more_rows_test_sbtest1(int num_rows, MYSQL *mysql, bool sqlite=false);

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
int wait_post_enpoint_ready(
	std::string endpoint, std::string post_params, uint32_t timeout, uint32_t delay=100
);

int wait_get_enpoint_ready(std::string endpoint, uint32_t timeout, uint32_t delay=100);

/**
 * @brief Perform a simple POST query to the specified endpoint using the supplied
 *  'post_params'.
 *
 * @param endpoint The endpoint to be exercised by the POST.
 * @param post_params The post parameters to be supplied to the script.
 * @param curl_out_err A uint64_t reference returning the result code of the
 *   query in case it has been performed. In case the query couldn't be
 *   performed, this value is never initialized.
 * @param curl_res_err A string reference to collect the error as a string reported
 *   by 'libcurl' in case of failure.
 *
 * @return The response code of the query in case of the query.
 */
CURLcode perform_simple_post(
	const std::string& endpoint, const std::string& params, uint64_t& curl_res_code, std::string& curl_res_data
);

CURLcode perform_simple_get(const std::string& endpoint, uint64_t& curl_res_code, std::string& curl_res_data);

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

/**
 * @brief Extract the current value for a given 'variable_name' from
 *   ProxySQL current configuration, either MEMORY or RUNTIME.
 * @param proxysql_admin An already opened connection to ProxySQL Admin.
 * @param variable_name The name of the variable to be retrieved from ProxySQL
 *   config.
 * @param variable_value Reference to string acting as output parameter which
 *   will content the value of the specified variable.
 * @return EXIT_SUCCESS, or one of the following error codes:
 *   - EINVAL if supplied 'proxysql_admin' is NULL.
 *   - '-1' in case of ProxySQL returns an 'NULL' row for the query selecting
 *     the variable 'sqliteserver-read_only'.
 *   - EXIT_FAILURE in case other operation failed.
 */
int get_variable_value(
	MYSQL* proxysql_admin, const std::string& variable_name, std::string& variable_value, bool runtime=false
);

/**
 * @brief Returns all the possible permutations of the supplied generic 'std::vector<T>'.
 *   This methods holds as long as the generic <T> holds the type requirements for
 *   'std::next_permutation'.
 * @param elem_set An 'std::vector<T>' from which to generate all the possible permutations.
 * @return All the possible permutations of the supplied vector.
 */
template <typename T>
std::vector<std::vector<T>> get_permutations(const std::vector<T>& elem_set) {
	std::vector<std::vector<T>> result {};

	std::vector<T> c_elem_set(elem_set.begin(), elem_set.end());
	std::sort(c_elem_set.begin(), c_elem_set.end());

	do {
		result.push_back(c_elem_set);
	} while (std::next_permutation(c_elem_set.begin(), c_elem_set.end()));

	return result;
}

/**
 * @brief Struct holding options on how to performs connections for 'EOF' tests.
 */
struct conn_cnf_t {
	bool f_conn_eof;
	bool b_conn_eof;
	bool f_conn_compr;
	bool b_conn_compr;
	bool fast_forward;
	std::string fast_forward_user;
};

/**
 * @brief Helper function to serialize 'conn_cnf_t' structs.
 * @return The string representation of the provided 'conn_cnf_t'.
 */
std::string to_string(const conn_cnf_t& cnf);

/**
 * @brief Execute the the test 'deprecate_eof_cache-t' with the 'mysql-variables'
 *  'mysql-enable_client_deprecate_eof' and 'mysql-enable_server_deprecate_eof'
 *  with the values suppplied in the parameters.
 *
 * @param cl CommandLine arguments supplied to the test.
 * @param mysql A MYSQL* initialized againt ProxySQL admin interface.
 * @param test File test name to be executed.
 * @param cl_depr_eof Bool to set to 'mysql-enable_client_deprecate_eof'
 * @param srv_depr_eof Bool to set to 'mysql-enable_server_deprecate_eof'
 *
 * @return The error code from executing 'deprecate_eof_cache-t' via system, or
 *  '0' in case of success.
 */
int execute_eof_test(
	const CommandLine& cl, MYSQL* mysql, const std::string& test, bool cl_depr_eof, bool srv_depr_eof
);
int execute_eof_test(const CommandLine& cl, MYSQL* mysql, const std::string& test, const conn_cnf_t&);

/**
 * @brief Waits until either the number of backend connections of the expected type is reached, or the
 *   timeout expires.
 *
 * @param proxy_admin An already oppened connection to ProxySQL Admin.
 * @param conn_type The type of backend connections to filter from 'stats_mysql_connection' pool. Possible
 *   values are: 'ConnUsed', 'ConnFree', 'ConnOK', 'ConnERR'.
 * @param exp_conn_num The target number of connections to reach to end the wait.
 * @param timeout Maximum waiting time for the connections to reach the expected value.
 *
 * @return EXIT_SUCCESS if the target number of connections was reached before timeout, EXIT_FAILURE otherwise.
 */
int wait_for_backend_conns(
	MYSQL* proxy_admin, const std::string& conn_type, uint32_t exp_conn_num, uint32_t timeout
);

/**
 * @brief Queries 'stats_mysql_connection_pool' and retrieves the number of connections of the specified type.
 *
 * @param proxy_admin An already oppened connection to ProxySQL Admin.
 * @param conn_type The type of backend connections to filter from 'stats_mysql_connection' pool. Possible
 *   values are: 'ConnUsed', 'ConnFree', 'ConnOK', 'ConnERR'.
 * @param found_conn_num The current number of connections of the specified type.
 *
 * @return EXIT_SUCCESS in case the conns number was properly retrieved, EXIT_FAILURE and error logged
 *   otherwise.
 */
int get_cur_backend_conns(MYSQL* proxy_admin, const std::string& conn_type, uint32_t& found_conn_num);

/**
 * @brief Join two string paths. Appends '/' to the first supplied string if doesn't already finish with one.
 * @param p1 First part of the path to be joined.
 * @param p2 Second string to append to the first path.
 * @return A string holding at least one '/' between the two previously supplied strings.
 */
std::string join_path(const std::string& p1, const std::string& p2);

/**
 * @brief Holds the required info for the definition of a RESTAPI endpoint.
 */
struct ept_info_t {
	std::string name;
	std::string file;
	std::string method;
	uint64_t timeout;
};

/**
 * @brief Represents a RESTAPI endpoint request expected to succeed.
 */
struct honest_req_t {
	ept_info_t ept_info;
	std::vector<std::string> params;
};

/**
 * @brief Holds the test payload information for faulty requests.
 */
struct ept_pl_t {
	/* @brief Params to be issued in the request against the endpoint */
	std::string params;
	/* @brief Expected code to be returned by CURL */
	uint64_t curl_rc;
	/* @brief Expected response output returned by CURL */
	uint64_t script_err;
};

/**
 * @brief Represents a RESTAPI endpoint request expected to fail.
 */
struct faulty_req_t {
	ept_info_t ept_info;
	std::vector<ept_pl_t> ept_pls;
};

/**
 * @brief Configure the supplied endpoints using the provided information
 *
 * @param admin Opened connection to ProxySQL admin interface.
 * @param script_base_path Common base path for the scripts location.
 * @param epts_info Information of the endpoints to be configured.
 * @param dummy_ept Dummy endpoint used to check when interface is ready.
 * @param prevent_dups Prevent duplicates when inserting the provided info.
 *
 * @return EXIT_SUCCESS in case of success, EXIT_FAILURE otherwise. Errors are logged.
 */
int configure_endpoints(
	MYSQL* admin,
	const std::string& script_base_path,
	const std::vector<ept_info_t>& epts_info,
	const ept_info_t& dummy_ept,
	bool prevent_dups = true
);

/**
 * @brief Returns the matches found of the 'substr' provided in the provided string.
 *
 * @param str String from which to count the matches.
 * @param substr The substring which matches needs to be counted.
 *
 * @return Number of matches of the 'substr' in the provided string.
 */
std::size_t count_matches(const std::string& str, const std::string& substr);

#endif // #define UTILS_H
