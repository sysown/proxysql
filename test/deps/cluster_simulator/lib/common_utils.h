#ifndef CLUSTER_SIM_COMMON_UTILS
#define CLUSTER_SIM_COMMON_UTILS

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <mysql.h>

#include "json.hpp"

using nlohmann::json;
using nlohmann::ordered_json;

using hg_id    = unsigned int;
using hostname = std::string;
using port     = unsigned int;
using status   = std::string;
using comment  = std::string;

using mysql_server_def = std::tuple<int, hostname, port, status, int, comment>;
using server_status =
	std::tuple<hg_id, hostname, port, status, int64_t, int64_t, int32_t, comment, bool>;
struct MYSQL_SERVER_STATUS_T {
	enum {
		HG_ID,
		HOSTNAME,
		PORT,
		STATUS,
		WEIGHT,
		MAX_CONNS,
		USE_SSL,
		COMMENT,
		COMMENT_IS_SET
	};
};

using cluster_status   = std::vector<server_status>;
using hostgroup_attributes_def = std::tuple<uint64_t,int64_t,int64_t,int32_t,int32_t>;
struct HOSTGROUP_ATTRIBUTES_T {
	enum {
		HG_ID,
		WEIGHT,
		MAX_CONNS,
		USE_SSL,
		MONITOR_SLAVE_LAG_WHEN_NULL
	};
};

using server_id        = std::string;
using column_id        = std::string;
using cluster_state_changes =
	std::map<server_id, std::vector<std::pair<column_id, std::string>>>;

////////////////////////////////////////////////////////////////////////////////
//                         GENERIC HELPER FUNCTIONS                           //
////////////////////////////////////////////////////////////////////////////////
//
/**
 * @brief Split 's' into tokens using 'delimiter'.
 *
 * @param s The string to split.
 * @param delimiter Character used as a separator.
 *
 * @return Vector of tokens, in source order.
 */
std::vector<std::string> str_split(const std::string& s, char delimiter);
/**
 * @brief Return a copy of 's' with every non-overlapping occurrence of 'from' replaced by 'to'.
 *
 * @param s The source string.
 * @param from The substring to search for. Empty 'from' returns 's' unchanged.
 * @param to The replacement substring.
 *
 * @return The transformed string.
 */
std::string replace(const std::string& s, const std::string& from, const std::string& to);
/**
 * @brief Parse a generic 'MYSQL_RES*' into a 'json' array. Each
 *  of the rows present in the resulset is parsed into a 'json' element
 *  hold in the return array in which the keys are the columns from
 *  the resulset.
 *
 * @param result The 'MYSQL_RES*' to be converted in to a JSON array.
 * @param j Output parameter 'json' to be filled with the contents
 *  of the MYSQL_RES.
 */
void parse_result_to_json(MYSQL_RES *result, nlohmann::ordered_json& j);


std::string cluster_status_checksum(const std::vector<server_status>& cluster_status);

////////////////////////////////////////////////////////////////////////////////
//                          HELPER ERROR FUNCTIONS                            //
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Returns a error in the form of a 'std::pair' holding the created message
 *  using the 'query' itself, the 'mysql_error' and the file an dthe line in which
 *  the failure took place.
 *
 * @param conn The connection in which the failure has taken place.
 * @param query The query that provoked the failure.
 * @param file The file in which the error took place. (__LINE__)
 * @param line The line number in which the error took place.(__FILE__)
 *
 * @return The constructed error.
 */
std::pair<int, std::string> create_query_error(
	MYSQL* conn,
	const std::string& query,
	const char* file,
	const int line
);
/**
 * @brief Build an EXIT_FAILURE pair carrying an 'invalid_input' error JSON with location prefix.
 *
 * @param err_msg The human-readable error description.
 * @param file Source file in which the failure was detected (typically '__FILE__').
 * @param line Source line in which the failure was detected (typically '__LINE__').
 *
 * @return A pair of '{ EXIT_FAILURE, { err_type: "invalid_input", err_msg: "..." } }'.
 */
std::pair<int, nlohmann::ordered_json> invalid_input_error(
	const std::string& err_msg,
	const char* file,
	const int line
);
/**
 * @brief Build an EXIT_FAILURE pair carrying an 'internal_error' error JSON with location prefix.
 *
 * @param err_msg The human-readable error description.
 * @param file Source file in which the failure was detected (typically '__FILE__').
 * @param line Source line in which the failure was detected (typically '__LINE__').
 *
 * @return A pair of '{ EXIT_FAILURE, { err_type: "internal_error", err_msg: "..." } }'.
 */
std::pair<int, nlohmann::ordered_json> internal_error(
	const std::string& err_msg,
	const char* file,
	const int line
);
/**
 * @brief Build an EXIT_FAILURE pair carrying an 'invalid_config' error JSON with location prefix.
 *
 * @param err_msg The human-readable error description.
 * @param file Source file in which the failure was detected (typically '__FILE__').
 * @param line Source line in which the failure was detected (typically '__LINE__').
 *
 * @return A pair of '{ EXIT_FAILURE, { err_type: "invalid_config", err_msg: "..." } }'.
 */
std::pair<int, nlohmann::ordered_json> invalid_config_error(
	const std::string& err_msg,
	const char* file,
	const int line
);
/**
 * @brief Build an EXIT_FAILURE pair carrying an 'invalid_payload' error JSON with location prefix.
 *
 * @param err_msg The human-readable error description.
 * @param file Source file in which the failure was detected (typically '__FILE__').
 * @param line Source line in which the failure was detected (typically '__LINE__').
 *
 * @return A pair of '{ EXIT_FAILURE, { err_type: "invalid_payload", err_msg: "..." } }'.
 */
std::pair<int, nlohmann::ordered_json> invalid_json_error(
	const std::string& err_msg,
	const char* file,
	const int line
);
/**
 * @brief Build a 'verification_error' JSON describing a mismatch between the
 *  expected and actual cluster states.
 *
 * @param err_msg Human-readable summary of the mismatch.
 * @param exp_cluster_state The cluster state that was expected.
 * @param act_cluster_state The cluster state that was actually observed.
 * @param cluster_st_diff Per-server column diff between the two states.
 * @param exp_state_timestamp Optional capture timestamp for 'exp_cluster_state'.
 * @param act_state_timestamp Optional capture timestamp for 'act_cluster_state'.
 *
 * @return A pair of '{ EXIT_FAILURE, json }' with both states, their checksums,
 *  the diff, and the timestamps.
 */
std::pair<int, nlohmann::ordered_json> verification_error(
	const std::string& err_msg,
	const std::vector<server_status>& exp_cluster_state,
	const std::vector<server_status>& act_cluster_state,
	const cluster_state_changes& cluster_st_diff,
	const std::string& exp_state_timestamp = {},
	const std::string& act_state_timestamp = {}
);
/**
 * @brief Pretty-print a 'verification_error' JSON for human-readable display,
 *  sorting the expected/actual server arrays by (hostgroup_id, hostname, port)
 *  so that diffs line up.
 *
 * @param j_verification_err A JSON produced by 'verification_error()'.
 * @param out_error_str Output parameter receiving the formatted string.
 *
 * @return A pair of '{ err_code, "err_msg" }'. EXIT_SUCCESS on success;
 *  EXIT_FAILURE with a parser error message if the input is malformed.
 */
std::pair<int, std::string> serialize_verification_error(
	const nlohmann::ordered_json& j_verification_err,
	std::string& out_error_str
);

////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Given a 'json' element, check if all the keys present in it
 *  are contained in the given array 'valid_keys'. If all the keys
 *  are contained it returns an empty vector, otherwise it returns a vector
 *  holding all the invalid keys found.
 *
 * @param valid_keys A vector holding the valid key identifiers.
 * @param elem A arbitrary 'json' element.
 *
 * @return Vector holding all the present invalid keys, empty vector otherwise.
 */
std::vector<std::string> get_invalid_keys(std::vector<std::string> valid_keys, json elem);
/**
 * @brief Build an error pair listing the unrecognized keys found in a JSON object.
 *
 * @param invalid_keys The keys to report. Empty list yields a no-error result.
 * @param name The JSON object name to include in the message (e.g. "mysql_servers").
 *
 * @return EXIT_FAILURE with a formatted message when 'invalid_keys' is
 *  non-empty; EXIT_SUCCESS with an empty message otherwise.
 */
std::pair<int,std::string> gen_invalid_keys_err(
	const std::vector<std::string>& invalid_keys,
	const std::string name
);
/**
 * @brief Walk 'path' through nested JSON objects in 'j' and check whether the
 *  leaf exists and matches the supplied 'type'.
 *
 * @param j The root JSON to traverse.
 * @param path Sequence of object keys to follow; the last element is the leaf
 *  to type-check.
 * @param type The expected type of the leaf value.
 *
 * @return 'true' if every step in 'path' resolves AND the leaf has type 'type';
 *  'false' otherwise.
 */
bool check_present_and_type(const json& j, const std::vector<std::string>& path, const json::value_t& type);
/**
 * @brief Check whether an actual server status satisfies an expected status.
 *
 * Optional fields omitted from the expected status are wildcards. Fields that
 * are present, including an explicitly empty comment, are compared exactly.
 *
 * @param exp_srv_st The expected server status.
 * @param act_srv_st The actual server status.
 *
 * @return 'true' if the actual status satisfies every expectation.
 */
bool matching_server_status(const server_status& exp_srv_st, const server_status& act_srv_st);
/**
 * @brief Check that the both supplied cluster states are equal, or equivalent.
 *
 * @param exp_status The expected cluster status.
 * @param act_status The actual cluster status.
 *
 * @return True if both are equal, false otherwise.
 */
bool check_cluster_status(const cluster_status& exp_status, const cluster_status& act_status);
/**
 * @brief
 *
 * @param servers_1
 * @param servers_2
 *
 * @return
 */
bool compare_mysql_servers(
	const std::vector<mysql_server_def>& servers_1,
	const std::vector<mysql_server_def>& servers_2
);
/**
 * @brief Receive a vector of servers definitions and cleans current servers in ProxySQL setting the new
 *  supplied ones.
 *
 * @param proxysql_admin An already oppened 'MYSQL*' connection handle to proxysql admin.
 * @param servers A list of servers to configure in ProxySQL.
 *
 * @return EXIT_FAILURE if any of the queries failed, EXIT_SUCCESS otherwise.
 */
std::pair<int, std::string> prepare_mysql_servers_config(MYSQL* proxysql_admin, const std::vector<mysql_server_def>& servers);

std::pair<int,std::string> prepare_mysql_hostgroup_attributes_config(
	MYSQL* proxysql_admin, const std::vector<hostgroup_attributes_def>& hostgroup_attributes
);
/**
 * @brief Type representing a monitor variable. Holding it's name and value.
 */
using monitor_variable = std::pair<std::string, uint32_t>;
/**
 * @brief Extracts the monitor variables supplied in the test definition.
 *
 * @param test_def The test definition to be inspected searching for the monitor variables.
 * @param monitor_variables Reference to an array to be filled with the found monitor variables.
 * @return The monitor variables found in the test definition.
 */
std::pair<int, std::string> extract_monitor_config(
	const json& test_def, std::vector<monitor_variable>& monitor_variables
);
/**
 * @brief Set the provided monitor variables if they are present in the given
 *  'allowed_variables' list.
 *
 * @param proxysql_admin And already open connection to ProxySQL Admin.
 * @param allowed_variables The list of allowed variables to verify.
 * @param monitor_variables The monitor variables to be set.
 *
 * @return EXIT_FAILURE if any of the queries failed, EXIT_SUCCESS otherwise.
 */
std::pair<int, std::string> set_monitor_variables(
	MYSQL* proxysql_admin,
	const std::vector<std::string>& allowed_variables,
	const std::vector<monitor_variable>& monitor_variables
);
/**
 * @brief Set the default values for the supplied monitor variables which are not
 *   provided by the test configuration.
 *
 * @param monitor_variables The monitor variables which are supplied by the test
 *   configuration.
 * @param def_vars_values The default values that should be included in the
 *   configuration in case of not being supplied by the test config itself.
 *
 * @return The updated 'monitor_variables' including the added default values.
 */
std::vector<monitor_variable> set_monitor_variables_defaults(
	const std::vector<monitor_variable>& monitor_variables,
	const std::vector<monitor_variable>& def_vars_values
);
/**
 * @brief Parse the 'mysql_servers' array from a test definition into typed tuples.
 *
 * @param galera_test_def The test definition object.
 * @param out_mysql_servers Output parameter filled with one tuple per parsed server.
 *
 * @return EXIT_SUCCESS on success; EXIT_FAILURE with a descriptive message
 *  if the field is missing, has the wrong shape, or contains invalid keys.
 */
std::pair<int,std::string> extract_mysql_servers(
	const json& galera_test_def,
	std::vector<mysql_server_def>& out_mysql_servers
);
/**
 * @brief Parse the optional 'mysql_hostgroup_attributes' array from a test
 *  definition into typed tuples. A missing field is not an error.
 *
 * @param galera_test_def The test definition object.
 * @param out_hostgroup_attributes Output parameter filled with one tuple per
 *  parsed hostgroup. Left empty when the field is absent.
 *
 * @return EXIT_SUCCESS on success or when the field is absent; EXIT_FAILURE
 *  with a descriptive message on shape errors or invalid keys.
 */
std::pair<int,std::string> extract_mysql_hostgroup_attributes(
	const json& galera_test_def,
	std::vector<hostgroup_attributes_def>& out_hostgroup_attributes
);
/**
 * @brief Query 'mysql_servers' from ProxySQL admin and parse the result into
 *  typed tuples.
 *
 * @param proxysql_admin An already opened connection to ProxySQL admin.
 * @param out_cur_mysql_servers Output parameter filled with the current servers.
 *
 * @return EXIT_SUCCESS on success; EXIT_FAILURE with a descriptive message
 *  on query or parse failure.
 */
std::pair<int, std::string> get_current_mysql_servers(
	MYSQL* proxysql_admin,
	std::vector<mysql_server_def>& out_cur_mysql_servers
);
/**
 * @brief Selector for which cluster-state snapshot to read from a test definition.
 */
enum class cluster_state {
	init_state,
	final_state
};
/**
 * @brief Parse a cluster-state snapshot ('proxysql_init_state' or
 *  'proxysql_final_state') from a test definition into typed tuples.
 *
 * @param state Selects which snapshot to read.
 * @param galera_test_def The test definition object.
 * @param out_cluster_status Output parameter filled with one tuple per server.
 *
 * @return EXIT_SUCCESS on success; EXIT_FAILURE with a descriptive message
 *  if the snapshot is missing, has the wrong shape, or contains invalid keys.
 */
std::pair<int, std::string> extract_cluster_status(
	cluster_state state,
	const json& galera_test_def,
	std::vector<server_status>& out_cluster_status
);
/**
 * @brief Query 'runtime_mysql_servers' from ProxySQL admin and return it as
 *  the current cluster status.
 *
 * @param proxysql_admin An already opened connection to ProxySQL admin.
 * @param out_cluster_status Output parameter filled with one tuple per server.
 *
 * @return EXIT_SUCCESS on success; EXIT_FAILURE with a descriptive message
 *  on query or parse failure.
 */
std::pair<int, std::string> get_current_cluster_status(
	MYSQL* proxysql_admin,
	std::vector<server_status>& out_cluster_status
);
/**
 * @brief Converts the current cluster status into a JSON following the
 *  convention followed for input parameters.
 * @param cluster_status The cluster status to be converted into a JSON.
 * @return A JSON representing the supplied 'cluster_status'.
 */
nlohmann::ordered_json cluster_status_to_json(const std::vector<server_status>& cluster_status);
/**
 * @brief POC of a pretty serializer.
 *
 * @param j_res
 * @param out_str_res
 *
 * @return
 */
std::pair<int, std::string> serialize_result(const nlohmann::ordered_json& j_res, std::string& out_str_res);
/**
 * @brief Pretty-print a top-level simulation/verification result, recursively
 *  serializing each per-test entry under 'results' (success or 'verification_error').
 *
 * @param j_result The aggregate result JSON.
 *
 * @return The formatted string.
 */
std::string serialize_result(const nlohmann::ordered_json& j_result);
/**
 * @brief Escapes each key with double quotes and accumulates them in a comma separated string.
 * @param keys Keys to generate the string with.
 * @return Comma separated string with the keys, empty string if no keys are supplied.
 */
std::string acc_keys(const std::vector<std::string>& keys);
/**
 * @brief Gets the current date and time formatted as YYYY-MM-DD HH:MM:SS.
 * @return A string representing the current date and time in YYYY-MM-DD HH:MM:SS format.
 */
std::string get_fmt_time();
#endif
