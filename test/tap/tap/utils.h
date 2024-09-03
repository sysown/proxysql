#ifndef UTILS_H
#define UTILS_H

#include <algorithm>
#include <string>
#include <vector>
#include <fstream>

#include "curl/curl.h"

#include "sqlite3db.h"
#include "json_fwd.hpp"

#include "command_line.h"
#include "mysql.h"

// Improve dependency failure compilation error
#ifndef DISABLE_WARNING_COUNT_LOGGING

extern "C" {

/* We are overriding some of the mariadb APIs to extract the warning count and print it in the log. 
   This override will apply to all TAP tests, except when the TAP test is linked with the MySQL client library (LIBMYSQL_HELPER defined).
*/
static MYSQL* (*real_mysql_init)(MYSQL* mysql) = &mysql_init;
static int (*real_mysql_query)(MYSQL* mysql, const char* query) = &mysql_query;
static MYSQL_RES* (*real_mysql_store_result)(MYSQL* mysql) = &mysql_store_result;
static void (*real_mysql_close)(MYSQL* mysql) = &mysql_close;
static MYSQL_STMT* (*real_mysql_stmt_init)(MYSQL* mysql) = &mysql_stmt_init;
static int (*real_mysql_stmt_prepare)(MYSQL_STMT* stmt, const char* stmt_str, unsigned long length) = &mysql_stmt_prepare;
static int (*real_mysql_stmt_execute)(MYSQL_STMT* stmt) = &mysql_stmt_execute;
static int (*real_mysql_stmt_store_result)(MYSQL_STMT* stmt) = &mysql_stmt_store_result;
static my_bool (*real_mysql_stmt_close)(MYSQL_STMT* stmt) = &mysql_stmt_close;

MYSQL* mysql_init_override(MYSQL* mysql, const char* file, int line);
int mysql_query_override(MYSQL* mysql, const char* query, const char* file, int line);
MYSQL_RES* mysql_store_result_override(MYSQL* mysql, const char* file, int line);
void mysql_close_override(MYSQL* mysql, const char* file, int line);
MYSQL_STMT* mysql_stmt_init_override(MYSQL* mysql, const char* file, int line);
int mysql_stmt_prepare_override(MYSQL_STMT* stmt, const char* stmt_str, unsigned long length, const char* file, int line);
int mysql_stmt_execute_override(MYSQL_STMT* stmt, const char* file, int line);
int mysql_stmt_store_result_override(MYSQL_STMT* stmt, const char* file, int line);
my_bool mysql_stmt_close_override(MYSQL_STMT* stmt, const char* file, int line);

#define mysql_init(mysql) mysql_init_override(mysql,__FILE__,__LINE__)
#define mysql_query(mysql,query) mysql_query_override(mysql,query,__FILE__,__LINE__)
#define mysql_store_result(mysql) mysql_store_result_override(mysql,__FILE__,__LINE__)
#define mysql_close(mysql) mysql_close_override(mysql,__FILE__,__LINE__)
#define mysql_stmt_init(mysql) mysql_stmt_init_override(mysql,__FILE__,__LINE__)
#define mysql_stmt_prepare(stmt,stmt_str,length) mysql_stmt_prepare_override(stmt,stmt_str,length,__FILE__,__LINE__)
#define mysql_stmt_execute(stmt) mysql_stmt_execute_override(stmt,__FILE__,__LINE__)
#define mysql_stmt_store_result(stmt) mysql_stmt_store_result_override(stmt,__FILE__,__LINE__)
#define mysql_stmt_close(stmt) mysql_stmt_close_override(stmt,__FILE__,__LINE__)

}

#endif 

/**
 * @brief Helper function to disable Core nodes scheduler from ProxySQL Cluster nodes.
 * @details In the CI environment, 'Scheduler' is used to induce extra load via Admin interface on
 *  all the cluster nodes. Disabling this allows for more accurate measurements on the primary.
 * @param cl CommandLine arguments supplied to the test.
 * @param admin Already opened Admin conn to the primary instance.
 * @return On success, the opened Admin connections to the Core nodes used to change their config,
 *  these conns should later be used to restore their original config. On failure, a pair of shape
 *  '{ EXIT_FAILURE, {} }'.
 */
std::pair<int,std::vector<MYSQL*>> disable_core_nodes_scheduler(CommandLine& cl, MYSQL* admin);

inline std::string get_formatted_time() {
	time_t __timer;
	char __buffer[30];

	struct tm __tm_info {};
	time(&__timer);
	localtime_r(&__timer, &__tm_info);
	strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", &__tm_info);

	return std::string(__buffer);
}

/**
 * @brief Wrapper for 'mysql_query' with logging for convenience.
 * @details Should be used through 'mysql_query_t' macro.
 * @return Result of calling 'mysql_query'.
 */
int mysql_query_t__(MYSQL* mysql, const char* query, const char* f, int ln, const char* fn);

/**
 * @brief Convenience macro with query logging.
 */
#define mysql_query_t(mysql, query)\
	mysql_query_t__(mysql, query, __FILE__, __LINE__, __func__)

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
		diag("Issuing query '%s' to ('%s':%d)", query, mysql->host, mysql->port); \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql)); \
			return EXIT_FAILURE; \
		} \
	} while(0)

int show_variable(MYSQL *mysql, const std::string& var_name, std::string& var_value);
int show_admin_global_variable(MYSQL *mysql, const std::string& var_name, std::string& var_value);
int set_admin_global_variable(MYSQL *mysql, const std::string& var_name, const std::string& var_value);
int get_server_version(MYSQL *mysql, std::string& version);
int select_config_file(MYSQL* mysql, std::string& resultset);

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
 * @brief Executes the given query and returns the received resultset, if any.
 * @param mysql Already oppened MYSQL connection.
 * @param query The query to be executed.
 * @return A pair of kind {err_code, results}; 'results' is left empty if either:
 *   * Query produces no resulset.
 *   * An error takes place during query execution or resultset retrieval.
 */
std::pair<uint32_t,std::vector<mysql_res_row>> mysql_query_ext_rows(MYSQL* mysql, const std::string& query);

/**
 * @brief Holds the result of an `mysql_query_ext_val` operation.
 */
template <typename T>
struct ext_val_t {
	// @brief Error that took place during query exuction or value extraction.
	int err;
	// @brief Final value extracted from resultset and parsed.
	// @details In case of error filled with 'def_val' param for 'mysql_query_ext_val'.
	T val;
	// @brief String representation of the received value.
	// @details Useful in case of parsing error.
	std::string str;
};

/**
 * @brief Specifications of function 'ext_single_row_val' for different types.
 * @details These functions serve as the extension point for `mysql_query_ext_val`. A new specialization of
 *  the function is required for each type that `mysql_query_ext_val` should support for the default value.
 * @param row The row from which the first value is going to be extracted and parsed.
 * @param def_val The default value to use in case of failure to extract.
 * @return An `ext_val_t<T>` where T is the type of the provided default value.
 */
ext_val_t<std::string> ext_single_row_val(const mysql_res_row& row, const std::string& def_val);
ext_val_t<int32_t> ext_single_row_val(const mysql_res_row& row, const int32_t& def_val);
ext_val_t<uint32_t> ext_single_row_val(const mysql_res_row& row, const uint32_t& def_val);
ext_val_t<int64_t> ext_single_row_val(const mysql_res_row& row, const int64_t& def_val);
ext_val_t<uint64_t> ext_single_row_val(const mysql_res_row& row, const uint64_t& def_val);

/**
 * @brief Helper function that executed a query and extracts a single value from the resultset.
 * @details Example use case:
 *  ```
 *  ext_val_t<uint64_t> cur_conns {
 *      mysql_query_ext_val(admin,
 *          "SELECT SUM(ConnUsed + ConnFree) FROM stats.stats_mysql_connection_pool", uint64_t(0)
 *      )
 *  };
 *
 *  if (cur_conns.err) {
 *      const string err { get_ext_val_err(admin, cur_conns) };
 *      diag("Fetching conn count from pool failed   err:'%s'", err.c_str());
 *  }
 *  ```
 *  Provides a single line way of handling a value extraction + boilerplate error handling. The casting of the
 *  second supplied integer isn't optional, this way there can be disambiguation based on parameter type.
 *
 * @param mysql Already oppened MYSQL connection.
 * @param query The query to be executed.
 * @param def_val Default value to be used in case of extraction failure.
 * @return An `ext_val_t<T>` where T is the type of the provided default value.
 */
template <typename T>
ext_val_t<T> mysql_query_ext_val(MYSQL* mysql, const std::string& query, const T& def_val) {
	 const auto rows { mysql_query_ext_rows(mysql, query) };

	 if (rows.first) {
		return { static_cast<int>(rows.first), def_val };
	 } else if (rows.second.empty()) {
		return { -1, def_val };
	 } else {
		 return ext_single_row_val(rows.second.front(), def_val);
	 }
}

/**
 * @brief Extract the error from a `ext_val_t<T>`.
 * @param mysql Already oppened MYSQL connection.
 * @param res A value extraction result that failed.
 * @return The string message for the error hold in the supplied `ext_val_t`.
 */
template <typename T>
std::string get_ext_val_err(MYSQL* mysql, const ext_val_t<T>& ext_val) {
	if (ext_val.err == -1) {
		return "Received invalid empty resultset/row";
	} else if (ext_val.err == -2) {
		return "Failed to parse response value '" + ext_val.str + "'";
	} else {
		return std::string { mysql_error(mysql) };
	}
}

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
/*
#ifdef LIBMYSQL_HELPER
MY_CHARSET_INFO * proxysqlTap_find_charset_collate(const char *collatename);
#else
MARIADB_CHARSET_INFO * proxysqlTap_find_charset_collate(const char *collatename);
#endif
*/
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
int get_proxysql_cpu_usage(const CommandLine& cl, uint32_t intv, double& cpu_usage);

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
 * @brief Generates permutations of binary vectors of the specified size.
 * @param tg_size The target size of the binary vectors.
 * @return The generated permutations.
 */
std::vector<std::vector<bool>> get_all_bin_vec(size_t tg_size);

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
 * @brief Execute the test 'deprecate_eof_cache-t' with the 'mysql-variables'
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

/**
 * @brief Extracts the current 'sqliteserver-mysql_ifaces' from ProxySQL config.
 * @param proxysql_admin An already opened connection to ProxySQL Admin.
 * @param host_port Output param to hold the host and port of the current 'sqliteserver-mysql_ifaces'.
 * @return EXIT_SUCCESS for success, EXIT_FAILURE otherwise. Error cause is logged.
 */
int extract_sqlite3_host_port(MYSQL* admin, std::pair<std::string, int>& host_port);

/**
 * @brief Split the supplied string with the supplied delimiter.
 * @param s The string to be split.
 * @param delimiter The delimiter to use for splitting the string.
 * @return String splits.
 */
std::vector<std::string> split(const std::string& s, char delim);

/**
 * @brief Joins the supplied list of words using the supplied delim.
 */
std::string join(std::string delim, const std::vector<std::string>& words);

/**
 * @brief Gets the supplied environmental variable as a std::string.
 * @param var The variable to value to extract.
 * @return The variable value if present, an empty string if not found.
 */
std::string get_env(const std::string& var);

/**
 * @brief Opens the file in the supplied path in the provided stream, and seeks the end of it.
 * @param f_path Path to the file to open.
 * @param f_logfile Output parameter with the stream to be updated with the opened file.
 * @return EXIT_SUCCESS in case of success, EXIT_FAILURE otherwise. Error cause is logged.
 */
int open_file_and_seek_end(const std::string& f_path, std::fstream& f_stream);

using line_match_t = std::tuple<std::fstream::pos_type, std::string, std::string>;
enum LINE_MATCH_T { POS, LINE, MATCH };

/**
 * @brief Extracts the lines matching the regex from the supplied stream till reaching EOF.
 * @param f_stream The stream to be matched with the regex.
 * @param regex The regex used to match the stream line-by-line.
 * @param get_matches If matched patterns should be returned (LINE_MATCH_T::MATCH). If supplied, the regex
 *  should contain at least one sub-pattern, or be a complete sub-pattern, otherwise it will fail to match.
 *  For example, regex '\d+' should become '(\d+)'.
 * @return All the lines found matching the regex.
 */
std::vector<line_match_t> get_matching_lines(
	std::fstream& f_stream, const std::string& regex, bool get_matches=false
);

/**
 * @brief Opens a sqlite3 db file located in the supplied path with the provided flags.
 * @param f_path Path to the 'db' file.
 * @param db Output parameter to the sqlite3 object to be opened.
 * @param flags The flags used to open the file.
 * @return EXIT_SUCCESS in case of success, EXIT_FAILURE otherwise. Error cause is logged.
 */
int open_sqlite3_db(const std::string& f_path, sqlite3** db, int flags);

using sq3_col_def_t = std::string;
using sq3_row_t = std::vector<std::string>;
using sq3_err_t = std::string;
using sq3_res_t = std::tuple<std::vector<sq3_col_def_t>,std::vector<sq3_row_t>,int64_t,sq3_err_t>;

enum SQ3_RES_T {
	SQ3_COLUMNS_DEF,
	SQ3_ROWS,
	SQ3_AFFECTED_ROWS,
	SQ3_ERR
};

/**
 * @brief Executes the provided query in the supplied sqlite3 db object.
 * @param db Already initialized 'sqlite3' handler.
 * @param query The query to be executed.
 * @return An 'sq3_result_t' object holding the result, depending on the type of query and result, different
 *  fields will be populated, in case of success:
 *   - For DQL stmts COLUMN_DEF and ROWS will hold the columns definitions and the rows from the resultset.
 *   - For DML stmts the AFFECTED_ROWS will show the number of modified rows.
 *  In case of failure, ERR field will be populated and others will remain empty.
 */
sq3_res_t sqlite3_execute_stmt(sqlite3* db, const std::string& query);

/**
 * @brief If found returns the element index, -1 otherwise.
 */
template <typename T>
int64_t get_elem_idx(const T& e, const std::vector<T>& v) {
	const auto& it = std::find(v.begin(), v.end(), e);

	if (it == v.end()) {
		return -1;
	} else {
		return it - v.begin();
	}
}

/**
 * @brief Returns a 'JSON' object holding 'PROXYSQL INTERNAL SESSION' contents.
 * @param proxy And already openned connection to ProxySQL.
 * @param verbose Wether to log or not the issued queries.
 */
nlohmann::json fetch_internal_session(MYSQL* proxy, bool verbose=true);

/**
 * @brief Extract the metrics values from the output of:
 *   - The admin command 'SHOW PROMETHEUS METRICS'.
 *   - Querying the RESTAPI metrics endpoint.
 * @param s ProxySQL prometheus exporter output.
 * @return A map of metrics identifiers and values.
 */
std::map<std::string, double> parse_prometheus_metrics(const std::string& s);

/**
 * @brief Returns a string table representation of the supplied resultset.
 */
std::string dump_as_table(MYSQL_RES* result);

using mysql_row_t = std::vector<std::string>;

/**
 * @brief Executes a DQL query and returns the contents of its resultset.
 * @param conn An already opened MYSQL connection.
 * @param query The DQL query to be executed.
 * @param dump_res Wether or not to dump the resultset contents as a table to 'stderr'.
 * @return A pair with the shape {err_code, contents}.
 */
std::pair<int,std::vector<mysql_row_t>> exec_dql_query(MYSQL* conn, const std::string& query, bool dump_res=false);

struct POOL_STATS_IDX {
	enum {
		HOSTGROUP,
		CONN_USED,
		CONN_FREE,
		CONN_OK,
		CONN_ERR,
		MAX_CONN_USED,
		QUERIES,
	};
};

/**
 * @brief Dumps a resultset with fields from the supplied hgs from 'stats_mysql_connection_pool'.
 * @details The fetched fields are 'hostgroup,ConnUsed,ConnFree,ConnOk,ConnERR,MaxConnUsed,Queries'.
 */
int dump_conn_stats(MYSQL* admin, const std::vector<uint32_t> hgs);

using pool_state_t = std::map<uint32_t,mysql_row_t>;

/**
 * @brief Fetches several fields from table 'stats_mysql_connection_pool' for supplied hostgroups.
 * @details The fetched fields are 'hostgroup,ConnUsed,ConnFree,ConnOk,ConnERR,MaxConnUsed,Queries'.
 * @param admin An already opened connection to Admin.
 * @param hgs The hostgroups from which to fetch several fields.
 * @return A pair of the shape {err_code, pool_state_t}.
 */
std::pair<int,pool_state_t> fetch_conn_stats(MYSQL* admin, const std::vector<uint32_t> hgs);
/**
 * @brief Waits until the condition specified by the 'query' holds, or 'timeout' is reached.
 * @details Several details about the function impl:
 *   - Sleeps of 500ms are performed between each check.
 *   - The time and check being performed is always logged ahead.
 *   - If query execution fails, reason is logged, wait aborted and EXIT_FAILURE returned.
 * @param mysql And already opened conn to ProxySQL in which the query is to be executed.
 * @param query Query with the condition check, it's expected to return 'TRUE' when the check succeeds.
 * @param timeout A timeout specified in seconds.
 * @return EXIT_SUCCESS if the checks holds before the timeout, EXIT_FAILURE otherwise.
 */
int wait_for_cond(MYSQL* mysql, const std::string& query, uint32_t timeout);

using check_res_t = std::pair<int,std::string>;

/**
 * @brief Waits for multiple conditions to take place before returning.
 * @param mysql Already oppened connection in which to execute the queries.
 * @param qs Conditions represented as queries; must pass 'check_cond' requirements.
 * @param to Timeout in which all the conditions should be accomplished.
 * @return Vector of pairs of shape '{err, check}'.
 */
std::vector<check_res_t> wait_for_conds(MYSQL* mysql, const std::vector<std::string>& qs, uint32_t to);

/**
 * @brief Reduces a vector of 'check_res_t' to either success or failure.
 * @param chks Vector to be fold into single value.
 * @return -1 in case a check failed to execute, 1 if any check timedout, 0 for success.
 */
int proc_wait_checks(const std::vector<check_res_t>& chks);

/**
 * @brief Encapsulates a server address.
 */
struct srv_addr_t {
	const std::string host;
	const int port;
};

// Helpers using 'wait_for_cond' on 'stats_mysql_connection'
void check_conn_count(MYSQL* admin, const std::string& conn_type, uint32_t conn_num, int32_t hg=-1);
void check_query_count(MYSQL* admin, uint32_t queries, uint32_t hg);
void check_query_count(MYSQL* admin, std::vector<uint32_t> queries, uint32_t hg);

/**
 * @brief Fetches the ProxySQL nodes configured in the supplied instance.
 * @param cl Parameters for performing the connection to the instance.
 * @return Pair of shape '{err, {srv_addr}}'.
 */
std::pair<int,std::vector<srv_addr_t>> fetch_cluster_nodes(MYSQL* admin, bool dump_fetch=false);

/**
 * @brief Helper function that waits for a check in all the supplied nodes.
 * @param cl Used for credentials to open conns to the nodes.
 * @param nodes The nodes addresses in which to perform the checks.
 * @param check The check itself to be performed in all the nodes. Must pass 'check_cond' requirements.
 * @param to Timeout for synchronization to take place.
 * @return 0 in case of success, 1 in case of timeout, and -1 in case of check failure.
 */
int check_nodes_sync(
	const CommandLine& cl, const std::vector<srv_addr_t>& nodes, const std::string& check, uint32_t to
);

/**
 * @brief fetches and converts env var value to str/int/bool if possible otherwise uses default
 * @details helper function for fetching str/int/bool from env
 * @param envname - name for the env variable
 * @param envdefault - default value to use
 * @return str/int/bool value or default
 */
const char* get_env_str(const char* envname, const char* envdefault);
int get_env_int(const char* envname, int envdefault);
bool get_env_bool(const char* envname, bool envdefault);

#endif // #define UTILS_H
