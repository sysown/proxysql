#include "common_utils.h"

#include <algorithm>
#include <ios>
#include <stdio.h>
#include <sstream>
#include <tuple>

// NOTE: Only needed during testing
#include <functional>

#include <mysql.h>
#include <mysqld_error.h>
#include <string.h>
#include <string>
#include <unistd.h>

#include "proxysql_utils.h"
#include "SpookyV2.h"
#include "tap.h"
#include "utils.h"
#include "command_line.h"
#include "json.hpp"

using nlohmann::ordered_json;
using std::string;
using std::vector;

////////////////////////////////////////////////////////////////////////////////
//                         GENERIC HELPER FUNCTIONS                           //
////////////////////////////////////////////////////////////////////////////////

std::vector<std::string> str_split(const std::string& s, char delimiter) {
	std::vector<std::string> tokens {};
	std::string token {};
	std::istringstream tokenStream(s);

	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(token);
	}

	return tokens;
}

std::string replace(const std::string& s, const std::string& from, const std::string& to) {
	std::string res { s };

	if(!from.empty()) {
		for(size_t pos = 0; (pos = res.find(from, pos)) != std::string::npos; pos += to.size()) {
			res.replace(pos, from.size(), to);
		}
	}

	return res;
}

void parse_result_to_json(MYSQL_RES *result, ordered_json& j) {
	if(!result) { return; }

	// Get the fields
	std::vector<std::string> field_names {};

	mysql_fetch_fields(result);
	int num_fields = mysql_num_fields(result);
	MYSQL_FIELD* fields = mysql_fetch_fields(result);

	for(int i = 0; i < num_fields; i++) {
		field_names.push_back(fields[i].name);
	}

	// Get each of the row values
	MYSQL_ROW row = nullptr;

	while ((row = mysql_fetch_row(result))) {
		ordered_json j_row {};
		unsigned long *lengths;
		lengths = mysql_fetch_lengths(result);

		for(int i = 0; i < num_fields; i++) {
			if (row[i]) {
				j_row[field_names[i]] = row[i];
			} else {
				j_row[field_names[i]] = "NULL";
			}
		}

		j.push_back(j_row);
	}
}

bool json_server_comparator(const ordered_json& j_srv_1, const ordered_json& j_srv_2) {
	std::string id_1 {
		std::to_string(static_cast<int>(j_srv_1.at("hostgroup_id"))) +
		std::string { j_srv_1.at("hostname") } +
		std::to_string(static_cast<int>(j_srv_1.at("port")))
	};
	std::string id_2 {
		std::to_string(static_cast<int>(j_srv_2.at("hostgroup_id"))) +
		std::string { j_srv_2.at("hostname") } +
		std::to_string(static_cast<int>(j_srv_2.at("port")))
	};
	
	return id_1 < id_2;
}

////////////////////////////////////////////////////////////////////////////////
//                          HELPER ERROR FUNCTIONS                            //
////////////////////////////////////////////////////////////////////////////////

std::pair<int, std::string> create_query_error(
	MYSQL* conn, const std::string& query, const char* file, const int line
) {
	std::string t_err_msg { "File '%s', line '%d', Error: Query '%s' failed with error '%s'" };
	std::string err_msg {};
	string_format(t_err_msg, err_msg, file, line, query.c_str(), mysql_error(conn));

	return { EXIT_FAILURE, err_msg };
}

std::pair<int, nlohmann::ordered_json> internal_error(const std::string& err_msg, const char* file, const int line) {
	std::string t_err_msg { "File '%s', line '%d', Error: '%s'" };
	std::string f_err_msg {};

	string_format(t_err_msg, f_err_msg, file, line, err_msg.c_str());
	return { EXIT_FAILURE, { { "err_type", "internal_error" }, { "err_msg", f_err_msg } } };
}

std::pair<int, nlohmann::ordered_json> invalid_input_error(const std::string& err_msg, const char* file, const int line) {
	std::string t_err_msg { "File '%s', line '%d', Error: '%s'" };
	std::string f_err_msg {};

	string_format(t_err_msg, f_err_msg, file, line, err_msg.c_str());
	return { EXIT_FAILURE, { { "err_type", "invalid_input" }, { "err_msg", f_err_msg } } };
}

std::pair<int, nlohmann::ordered_json> invalid_config_error(const std::string& err_msg, const char* file, const int line) {
	std::string t_err_msg { "File '%s', line '%d', Error: '%s'" };
	std::string f_err_msg {};

	string_format(t_err_msg, f_err_msg, file, line, err_msg.c_str());
	return { EXIT_FAILURE, { { "err_type", "invalid_config" }, { "err_msg", f_err_msg } } };
}

std::pair<int, nlohmann::ordered_json> invalid_json_error(
	const std::string& err_msg,
	const char* file,
	const int line
) {
	std::string t_err_msg { "File '%s', line '%d', Error: '%s'" };
	std::string f_err_msg {};

	string_format(t_err_msg, f_err_msg, file, line, err_msg.c_str());
	return { EXIT_FAILURE, { { "err_type", "invalid_payload" }, { "err_msg", f_err_msg } } };
}

std::pair<int, std::string> serialize_verification_error(
	const nlohmann::ordered_json& j_verification_err,
	std::string& out_error_str
) {
	std::pair<int, std::string> result { EXIT_SUCCESS, "" };

	try {
		nlohmann::ordered_json c_verification_error = j_verification_err;

		nlohmann::ordered_json j_exp_proxysql_state =
			j_verification_err.at("exp_proxysql_state");
		nlohmann::ordered_json j_act_proxysql_state =
			j_verification_err.at("act_proxysql_state");

		std::sort(
			j_exp_proxysql_state.begin(),
			j_exp_proxysql_state.end(),
			json_server_comparator
		);

		std::sort(
			j_act_proxysql_state.begin(),
			j_act_proxysql_state.end(),
			json_server_comparator
		);

		c_verification_error["exp_proxysql_state"] = nlohmann::ordered_json::array();
		c_verification_error["act_proxysql_state"] = nlohmann::ordered_json::array();

		unsigned int elem_num = 0;

		for (std::size_t i = 0; i < j_exp_proxysql_state.size(); i++) {
			c_verification_error["exp_proxysql_state"].push_back(
				"%" + std::to_string(elem_num) + "s"
			);
			elem_num += 1;
		}

		for (std::size_t i = 0; i < j_act_proxysql_state.size(); i++) {
			c_verification_error["act_proxysql_state"].push_back(
				"%" + std::to_string(elem_num) + "s"
			);
			elem_num += 1;
		}

		elem_num = 0;

		std::string str_result { c_verification_error.dump(4) };

		for (const nlohmann::ordered_json& j_state_elem : j_exp_proxysql_state) {
			std::string elem_str { j_state_elem.dump() };

			elem_str = replace(elem_str, "{", "{ ");
			elem_str = replace(elem_str, "}", " }");

			str_result = replace(
				str_result,
				"\"%" + std::to_string(elem_num) + "s\"",
				elem_str
			);
			elem_num += 1;
		}

		for (const nlohmann::ordered_json& j_state_elem : j_act_proxysql_state) {
			std::string elem_str { j_state_elem.dump() };

			elem_str = replace(elem_str, "{", "{ ");
			elem_str = replace(elem_str, "}", " }");

			str_result = replace(
				str_result,
				"\"%" + std::to_string(elem_num) + "s\"",
				elem_str
			);
			elem_num += 1;
		}

		// add proper indentation
		str_result = replace(str_result, "\n", "\n        ");

		// fill the output parameter
		out_error_str = str_result;
	} catch (const std::exception& e) {
		result = {
			EXIT_FAILURE,
			"Malformed JSON 'verification_error': '" + std::string { e.what() } + "'"
		};
	}

	return result;
}

////////////////////////////////////////////////////////////////////////////////

std::pair<int, nlohmann::ordered_json> verification_error(
	const string& err_msg,
	const vector<server_status>& exp_cluster_state,
	const vector<server_status>& act_cluster_state,
	const cluster_state_changes& cluster_st_diff,
	const string& exp_state_timestamp,
	const string& act_state_timestamp
) {
	nlohmann::ordered_json j_exp_cluster_state =
		cluster_status_to_json(exp_cluster_state);
	nlohmann::ordered_json j_act_cluster_state =
		cluster_status_to_json(act_cluster_state);

	std::sort(
		j_exp_cluster_state.begin(),
		j_exp_cluster_state.end(),
		json_server_comparator
	);

	std::sort(
		j_act_cluster_state.begin(),
		j_act_cluster_state.end(),
		json_server_comparator
	);

	std::string exp_cluster_state_checksum =
		cluster_status_checksum(exp_cluster_state);
	std::string act_cluster_state_checksum =
		cluster_status_checksum(act_cluster_state);

	return {
		EXIT_FAILURE, 
		{
			{ "err_type", "verification_error" },
			{ "err_msg", err_msg },
			{ "cluster_state_diff", cluster_st_diff },
			{ "exp_proxysql_state_checksum", exp_cluster_state_checksum },
			{ "exp_proxysql_state", j_exp_cluster_state },
			{ "exp_state_timestamp", exp_state_timestamp },
			{ "act_proxysql_state_checksum", act_cluster_state_checksum },
			{ "act_proxysql_state", j_act_cluster_state },
			{ "act_state_timestamp", act_state_timestamp }
		}
	};
}

std::vector<std::string> get_invalid_keys(std::vector<std::string> valid_keys, json elem) {
	std::vector<std::string> invalid_keys {};

	std::vector<std::string> found_keys {};
	for (const auto& item : elem.items()) {
		found_keys.push_back(item.key());
	}

	for (const auto& key : found_keys) {
		bool invalid_key_found =
			std::find(
				valid_keys.begin(),
				valid_keys.end(),
				key
			) == std::end(valid_keys);

		if (invalid_key_found) {
			invalid_keys.push_back(key);
		}
	}

	return invalid_keys;
}

std::pair<int,std::string> gen_invalid_keys_err(
	const std::vector<std::string>& invalid_keys,
	const std::string name
) {
	if (!invalid_keys.empty()) {
		std::string t_err_msg { "'%s' contains invalid keys: [%s]" };
		std::string err_msg {};
		std::string invalid_keys_str { acc_keys(invalid_keys) };

		string_format(t_err_msg, err_msg, name.c_str(), invalid_keys_str.c_str());
		return { EXIT_FAILURE, err_msg };
	} else {
		return { EXIT_SUCCESS, "" };
	}
}

bool check_present_and_type(const json& j, const std::vector<std::string>& path, const json::value_t& type) {
	bool res = false;

	json cur_j {};

	for (const auto& step : path) {
		if (j.contains(step)) {
			cur_j = j.at(step);

			if (&step == &path.back()) {
				return type == cur_j.type();
			}
		} else {
			break;
		}
	}

	return res;
}

bool matching_server_status(const server_status& exp_srv_st, const server_status& act_srv_st) {
	bool res = false;
	bool same_hid_host =
		std::get<0>(exp_srv_st) == std::get<0>(act_srv_st) &&
		std::get<1>(exp_srv_st) == std::get<1>(act_srv_st) &&
		std::get<2>(exp_srv_st) == std::get<2>(act_srv_st);

	if (same_hid_host) {
		std::vector<std::string> allowed_sts {
			str_split(std::get<3>(exp_srv_st), '|')
		};

		if (std::find(allowed_sts.begin(), allowed_sts.end(), std::get<3>(act_srv_st)) != allowed_sts.end()) {
			const int64_t exp_weight = std::get<MYSQL_SERVER_STATUS_T::WEIGHT>(exp_srv_st);
			const int64_t exp_max_conns = std::get<MYSQL_SERVER_STATUS_T::MAX_CONNS>(exp_srv_st);
			const int32_t exp_use_ssl = std::get<MYSQL_SERVER_STATUS_T::USE_SSL>(exp_srv_st);
			const std::string& exp_comment = std::get<MYSQL_SERVER_STATUS_T::COMMENT>(exp_srv_st);
			const bool exp_comment_is_set =
				std::get<MYSQL_SERVER_STATUS_T::COMMENT_IS_SET>(exp_srv_st);

			bool match = true;

			if (exp_weight != -1) {
				match = match && exp_weight == std::get<MYSQL_SERVER_STATUS_T::WEIGHT>(act_srv_st);
			}
			if (exp_max_conns != -1) {
				match = match && exp_max_conns == std::get<MYSQL_SERVER_STATUS_T::MAX_CONNS>(act_srv_st);
			}
			if (exp_use_ssl != -1) {
				match = match && exp_use_ssl == std::get<MYSQL_SERVER_STATUS_T::USE_SSL>(act_srv_st);
			}
			if (exp_comment_is_set) {
				match = match && exp_comment == std::get<MYSQL_SERVER_STATUS_T::COMMENT>(act_srv_st);
			}

			res = match;
		}
	}

	return res;
}

bool check_cluster_status(const cluster_status& exp_status, const cluster_status& act_status) {
	// filter 'OFFLINE_HARD' servers due to the transitive nature of the state
	cluster_status f_act_status {};
	std::copy_if(
		act_status.begin(),
		act_status.end(),
		std::back_inserter(f_act_status),
		[] (const server_status& srv_st) -> bool {
			return std::get<3>(srv_st) != "OFFLINE_HARD";
		}
	);

	// check for different size
	if (exp_status.size() != f_act_status.size()) { return false; }

	// we first sort for hostgroup and for hostname, as toguether should form an id for sorting
	cluster_status c_exp_status { exp_status };
	cluster_status c_act_status { f_act_status };

	std::sort(
		c_exp_status.begin(),
		c_exp_status.end(),
		[] (const server_status& srv_st1, const server_status& srv_st2) -> bool {
			const std::string srv_st1_id { std::to_string(std::get<0>(srv_st1)) + std::get<1>(srv_st1) };
			const std::string srv_st2_id { std::to_string(std::get<0>(srv_st2)) + std::get<1>(srv_st2) };

			return srv_st1_id > srv_st2_id;
		}
	);

	std::sort(
		c_act_status.begin(),
		c_act_status.end(),
		[] (const server_status& srv_st1, const server_status& srv_st2) -> bool {
			const std::string srv_st1_id { std::to_string(std::get<0>(srv_st1)) + std::get<1>(srv_st1) };
			const std::string srv_st2_id { std::to_string(std::get<0>(srv_st2)) + std::get<1>(srv_st2) };

			return srv_st1_id > srv_st2_id;
		}
	);

	return std::equal(
		c_exp_status.begin(),
		c_exp_status.end(),
		c_act_status.begin(),
		[] (const server_status& srv_st1, const server_status& srv_st2) {
			return matching_server_status(srv_st1, srv_st2);
		}
	);
}

bool compare_mysql_servers(
	const std::vector<mysql_server_def>& servers_1,
	const std::vector<mysql_server_def>& servers_2
) {
	std::vector<mysql_server_def> c_servers_1 { servers_1 };
	std::vector<mysql_server_def> c_servers_2 { servers_2 };

	std::sort(
		c_servers_1.begin(),
		c_servers_1.end(),
		[] (const mysql_server_def& srv_st1, const mysql_server_def& srv_st2) -> bool {
			const std::string srv_st1_id { std::to_string(std::get<0>(srv_st1)) + std::get<1>(srv_st1) };
			const std::string srv_st2_id { std::to_string(std::get<0>(srv_st2)) + std::get<1>(srv_st2) };

			return srv_st1_id > srv_st2_id;
		}
	);

	std::sort(
		c_servers_2.begin(),
		c_servers_2.end(),
		[] (const mysql_server_def& srv_st1, const mysql_server_def& srv_st2) -> bool {
			const std::string srv_st1_id { std::to_string(std::get<0>(srv_st1)) + std::get<1>(srv_st1) };
			const std::string srv_st2_id { std::to_string(std::get<0>(srv_st2)) + std::get<1>(srv_st2) };

			return srv_st1_id > srv_st2_id;
		}
	);

	return c_servers_1 == c_servers_2;
}

std::pair<int, std::string> prepare_mysql_servers_config(
	MYSQL* proxysql_admin,
	const std::vector<mysql_server_def>& servers
) {
	int query_error = 0;

	// Remove the current configured servers
	query_error = mysql_query(proxysql_admin, "DELETE FROM mysql_servers");
	if (query_error) {
		return create_query_error(proxysql_admin, "DELETE FROM mysql_servers", __FILE__, __LINE__);
	}

	// Prevent any reconfiguration until all the cluster is setup
	const std::string load_to_runtime_query { "LOAD MYSQL SERVERS TO RUNTIME" };
	query_error = mysql_query(proxysql_admin, load_to_runtime_query.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, load_to_runtime_query, __FILE__, __LINE__);
	}

	// Leave sometime after "LOAD MYSQL SERVERS TO RUNTIME" for leaving time
	// to ProxySQL to reconfigure servers, otherwise query might fail.
	usleep(500 * 1000);

	std::string query { "INSERT INTO mysql_servers(hostgroup_id,hostname,port, status, max_replication_lag,comment) VALUES" };

	for (const auto& server : servers) {
		std::string t_server_values {};
		std::string server_values {};

		if (&server != &servers.back()) {
			t_server_values = " (%d,'%s',%d,'%s',%d,'%s'), ";
		} else {
			t_server_values = " (%d,'%s',%d,'%s',%d,'%s')";
		}

		string_format(
			t_server_values,
			server_values,
			std::get<0>(server),
			std::get<1>(server).c_str(),
			std::get<2>(server),
			std::get<3>(server).c_str(),
			std::get<4>(server),
			std::get<5>(server).c_str()
		);

		query += server_values;
	}

	query_error = mysql_query(proxysql_admin, query.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, query, __FILE__, __LINE__);
	}

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> prepare_mysql_hostgroup_attributes_config(
	MYSQL* proxysql_admin, const std::vector<hostgroup_attributes_def>& hostgroup_attributes
) {
	int query_error = 0;

	query_error = mysql_query(proxysql_admin, "DELETE FROM mysql_hostgroup_attributes");
	if (query_error) {
		return create_query_error(proxysql_admin, "DELETE FROM mysql_hostgroup_attributes", __FILE__, __LINE__);
	}

	std::string query { "INSERT INTO mysql_hostgroup_attributes(hostgroup_id,servers_defaults,hostgroup_settings) VALUES" };

	for (const auto& hg_attrib : hostgroup_attributes) {
		std::string t_values {};
		std::string values {};

		if (&hg_attrib != &hostgroup_attributes.back()) {
			t_values = " (%d,'%s','%s'), ";
		} else {
			t_values = " (%d,'%s','%s')";
		}

		ordered_json j_servers_defaults {};

		int64_t def_weight = std::get<HOSTGROUP_ATTRIBUTES_T::WEIGHT>(hg_attrib);
		int64_t def_max_conns = std::get<HOSTGROUP_ATTRIBUTES_T::MAX_CONNS>(hg_attrib);
		int64_t def_use_ssl = std::get<HOSTGROUP_ATTRIBUTES_T::USE_SSL>(hg_attrib);

		if (def_weight != -1) {
			j_servers_defaults["weight"] = def_weight;
		}
		if (def_max_conns != -1) {
			j_servers_defaults["max_connections"] = def_max_conns;
		}
		if (def_use_ssl != -1) {
			j_servers_defaults["use_ssl"] = def_use_ssl;
		}

		const string s_servers_defaults { j_servers_defaults.dump() };

		ordered_json j_hostgroup_settings {};
		int32_t monitor_slave_lag_when_null = std::get<HOSTGROUP_ATTRIBUTES_T::MONITOR_SLAVE_LAG_WHEN_NULL>(hg_attrib);
		if (monitor_slave_lag_when_null != -1) {
			j_hostgroup_settings["monitor_slave_lag_when_null"] = monitor_slave_lag_when_null;
		}

		const string s_hostgroup_settings { j_hostgroup_settings.dump() };

		string_format(
			t_values,
			values,
			std::get<HOSTGROUP_ATTRIBUTES_T::HG_ID>(hg_attrib),
			s_servers_defaults.c_str(),
			s_hostgroup_settings.c_str()
		);

		query += values;
	}

	query_error = mysql_query(proxysql_admin, query.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, query, __FILE__, __LINE__);
	}

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> extract_monitor_config(
	const json& test_def, std::vector<monitor_variable>& out_monitor_variables
) {
	std::vector<monitor_variable> result {};

	// perform basic payload checks
	if (!test_def.is_object()) {
		return { EXIT_FAILURE, "Invalid input. Expected 'test_definition' should be a JSON object." };
	}

	bool has_monitor_config =
		check_present_and_type(test_def, {"mysql_monitor_config"}, json::value_t::array);
	if (has_monitor_config == false) {
		return { EXIT_SUCCESS, "No 'mysql_monitor_config' provided, using default values." };
	}

	json m_monitor_variables = test_def["mysql_monitor_config"];

	for (const auto& m_monitor_variable : m_monitor_variables.items()) {
		if (
			m_monitor_variable.value().type() != json::value_t::object ||
			m_monitor_variable.value().size() != 1
		) {
			return {
				EXIT_FAILURE,
				"Object of kind '{ var_name: var_value }' expected for"
				" 'mysql_monitor_config' variable but got: '" +
				m_monitor_variable.value().dump() + "'"
			};
		}

		for (const auto& var_value : m_monitor_variable.value().items()) {
			if (
				var_value.value().type() != json::value_t::number_unsigned &&
				var_value.value().type() != json::value_t::number_integer
			) {
				return {
					EXIT_FAILURE,
					"Type expected for 'mysql_monitor_config' variable '" + var_value.value().dump() +
					"' was either: 'number_unsigned' or 'number_integer'"
				};
			}
			result.push_back({ var_value.key(), var_value.value() });
		}
	}

	// return the extracted values
	out_monitor_variables =  result;

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> set_monitor_variables(
	MYSQL* proxysql_admin,
	const std::vector<std::string>& allowed_variables,
	const std::vector<monitor_variable>& monitor_variables
) {
	std::string t_set_var_query {
		"SET mysql-%s=%d"
	};
	for (const auto& monitor_variable : monitor_variables) {
		const auto allowed =
			std::find(
				allowed_variables.begin(),
				allowed_variables.end(),
				monitor_variable.first
			);

		if (allowed != std::end(allowed_variables)) {
			std::string set_var_query {};
			string_format(
				t_set_var_query, set_var_query, monitor_variable.first.c_str(),
				monitor_variable.second
			);

			int query_err = mysql_query(proxysql_admin, set_var_query.c_str());
			if (query_err) {
				return {
					EXIT_FAILURE,
					"Setting monitor variable query '" + set_var_query + "'" +
					" failed with error: '" + std::string { mysql_error(proxysql_admin) }
				};
			}
		}
	}

	return { EXIT_SUCCESS, "" };
}

std::vector<monitor_variable> set_monitor_variables_defaults(
	const std::vector<monitor_variable>& monitor_variables,
	const std::vector<monitor_variable>& def_vars_values
) {
	std::vector<monitor_variable> result { monitor_variables };

	for (auto& def_var : def_vars_values) {
		auto found_var = std::find_if(
			result.begin(),
			result.end(),
			[&def_var] (const monitor_variable& var) {
				return def_var.first == var.first;
			}
		);

		if (found_var == std::end(result)) {
			result.push_back(def_var);
		}
	}

	return result;
}

const std::vector<std::string> valid_mysql_entries {
	"hostgroup_id",
	"hostname",
	"port",
	"status",
	"max_replication_lag",
	"comment"
};

std::pair<int,std::string> extract_mysql_servers(
	const json& galera_test_def,
	std::vector<mysql_server_def>& out_mysql_servers
) {
	// result
	std::vector<mysql_server_def> result {};

	// perform basic payload checks
	if (!galera_test_def.is_object()) {
		return { EXIT_FAILURE, "Invalid input. Expected 'test_definition' should be a JSON object." };
	}

	bool has_mysql_servers =
		check_present_and_type(galera_test_def, {"mysql_servers"}, json::value_t::array);
	if (has_mysql_servers == false) {
		return { EXIT_FAILURE, "Invalid input. Unable to find required field 'mysql_servers'" };
	}

	json m_mysql_servers = galera_test_def["mysql_servers"];
	if (!m_mysql_servers.is_array()) {
		return { EXIT_FAILURE, "Invalid input. 'mysql_servers' isn't of expected type 'array'" };
	}

	for (const auto& m_mysql_server : m_mysql_servers) {
		// *********************** CHECK FOR INVALID KEYS ******************* //

		std::vector<std::string> invalid_keys {
			get_invalid_keys(valid_mysql_entries, m_mysql_server)
		};

		if (!invalid_keys.empty()) {
			return gen_invalid_keys_err(invalid_keys, "mysql_servers");
		}

		// ****************************************************************** //

		int hostgroup_id;
		std::string hostname {};
		int port;
		std::string status { "ONLINE" };
		int max_replication_lag = 0;
		std::string comment {};

		try {
			hostgroup_id = m_mysql_server.at("hostgroup_id");
			hostname = m_mysql_server.at("hostname");
			port = m_mysql_server.at("port");

			if (m_mysql_server.contains("max_replication_lag")) {
				max_replication_lag = m_mysql_server.at("max_replication_lag");
			}

			bool has_status = m_mysql_server.contains("status");
			if (has_status) {
				status = m_mysql_server.at("status");
			}

			if (m_mysql_server.contains("comment")) {
				comment = m_mysql_server.at("comment");
			}
		} catch(const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}

		result.push_back(std::make_tuple(hostgroup_id, hostname, port, status, max_replication_lag, comment));
	}

	// return the extracted values
	out_mysql_servers =  std::move(result);

	return { EXIT_SUCCESS, "" };
}

const vector<string> valid_hostgroup_attributes_entries {
	"hostgroup_id", "weight", "max_connections", "use_ssl", "monitor_slave_lag_when_null"
};

std::pair<int,std::string> extract_mysql_hostgroup_attributes(
	const json& test_def, std::vector<hostgroup_attributes_def>& out_hostgroup_attributes
) {
	std::pair<int, std::string> err_res {};
	std::vector<hostgroup_attributes_def> result {};

	if (!test_def.is_object()) {
		return { EXIT_FAILURE, "Invalid input. Expected 'test_definition' should be a JSON object." };
	}

	// 'mysql_hostgroup_attributes' is an optional field, exit if not found
	bool has_server_attrs = check_present_and_type(test_def, {"mysql_hostgroup_attributes"}, json::value_t::array);
	if (!has_server_attrs) {
		return { EXIT_SUCCESS, "" };
	}

	json j_hostgroups_attrs = test_def["mysql_hostgroup_attributes"];
	if (!j_hostgroups_attrs.is_array()) {
		return { EXIT_FAILURE, "Invalid input. 'mysql_hostgroup_attributes' isn't of expected type 'array'" };
	}

	for (const auto& j_hg_attrs : j_hostgroups_attrs) {
		// *********************** CHECK FOR INVALID KEYS ******************* //

		std::vector<std::string> invalid_keys { get_invalid_keys(valid_hostgroup_attributes_entries, j_hg_attrs) };

		if (!invalid_keys.empty()) {
			return gen_invalid_keys_err(invalid_keys, "mysql_hostgroup_attributes");
		}

		// ****************************************************************** //

		uint64_t hostgroup_id = 0;
		int64_t weight = -1;
		int64_t max_conns = -1;
		int32_t use_ssl = -1;
		int32_t monitor_slave_lag_when_null = -1;

		try {
			hostgroup_id = j_hg_attrs.at("hostgroup_id");

			const bool found_weight = j_hg_attrs.find("weight") != j_hg_attrs.end();
			const bool found_max_conns = j_hg_attrs.find("max_connections") != j_hg_attrs.end();
			const bool found_use_ssl = j_hg_attrs.find("use_ssl") != j_hg_attrs.end();
			const bool found_monitor_slave_lag_when_null = j_hg_attrs.find("monitor_slave_lag_when_null") != j_hg_attrs.end();

			weight = found_weight ? static_cast<int64_t>(j_hg_attrs.at("weight")) : -1;
			max_conns = found_max_conns ? static_cast<int64_t>(j_hg_attrs.at("max_connections")) : -1;
			use_ssl = found_use_ssl ? static_cast<int32_t>(j_hg_attrs.at("use_ssl")) : -1;
			monitor_slave_lag_when_null = found_monitor_slave_lag_when_null ? 
										  static_cast<int32_t>(j_hg_attrs.at("monitor_slave_lag_when_null")) : -1;
		} catch(const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}

		result.push_back(std::make_tuple(hostgroup_id, weight, max_conns, use_ssl, monitor_slave_lag_when_null));
	}

	out_hostgroup_attributes = std::move(result);

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> get_current_mysql_servers(
	MYSQL* proxysql_admin,
	std::vector<mysql_server_def>& out_cur_mysql_servers
) {
	std::pair<int, std::string> err_res {};
	std::string t_err_msg { "'get_current_mysql_servers' failed with error: '%s'" };
	std::string err_msg {};

	const std::string mysql_servers_query { "SELECT hostgroup_id, hostname, port, max_replication_lag FROM mysql_servers" };
	int q_res = mysql_query(proxysql_admin, mysql_servers_query.c_str());

	if (q_res == 0) {
		ordered_json j_servers {};
		j_servers["mysql_servers"] = {};

		MYSQL_RES* my_servers_res = mysql_store_result(proxysql_admin);
		parse_result_to_json(my_servers_res, j_servers["mysql_servers"]);

		// convert the fields into the proper types
		for (ordered_json& j_server : j_servers["mysql_servers"]) {
			j_server["hostgroup_id"] = atoi(std::string {j_server["hostgroup_id"]}.c_str());
			j_server["port"] = atoi(std::string {j_server["port"]}.c_str());
			j_server["max_replication_lag"] = atoi(std::string {j_server["max_replication_lag"]}.c_str());
		}

		std::vector<mysql_server_def> res_cur_mysql_servers {};
		std::pair<int, std::string> ext_res =
			extract_mysql_servers(j_servers, res_cur_mysql_servers);

		if (ext_res.first == EXIT_SUCCESS) {
			out_cur_mysql_servers = res_cur_mysql_servers;
		} else {
			string_format(t_err_msg, err_msg, ext_res.second.c_str());
			err_res = { EXIT_FAILURE, err_msg };
		}
	} else {
		string_format(t_err_msg, err_msg, mysql_error(proxysql_admin));
		err_res = { EXIT_FAILURE, err_msg };
	}

	return err_res;
}

const std::vector<std::string> valid_server_status_entries {
	"hostgroup_id",
	"hostname",
	"port",
	"status",
	"weight",
	"max_connections",
	"use_ssl",
	"comment"
};

std::pair<int, std::string> extract_cluster_status(
	cluster_state state,
	const json& galera_test_def,
	std::vector<server_status>& out_cluster_status
) {
	// result
	std::vector<server_status> cluster_status {};

	// perform basic payload checks
	if (!galera_test_def.is_object()) {
		return {
			EXIT_FAILURE,
			"Invalid input. Expected 'test_definition' should be a JSON object."
		};
	}

	std::string json_key {};

	if (state == cluster_state::init_state) {
		json_key = "proxysql_init_state";
	} else {
		json_key = "proxysql_final_state";
	}

	bool has_proxysql_init_state =
		check_present_and_type(
			galera_test_def, { json_key }, json::value_t::object
		);

	if (has_proxysql_init_state) {
		std::string t_err_msg {
			"Invalid input. Unable to find required field '%s'"
		};
		std::string err_msg {};
		string_format(t_err_msg, err_msg, json_key.c_str());

		return {
			EXIT_FAILURE,
			err_msg
		};
	}

	ordered_json m_proxysql_init_state = galera_test_def[json_key];
	if (!m_proxysql_init_state.is_array()) {
		std::string t_err_msg {
			"Invalid input. '%s' isn't of expected type 'array'"
		};
		std::string err_msg {};
		string_format(t_err_msg, err_msg, json_key.c_str());

		return {
			EXIT_FAILURE,
			err_msg
		};
	}

	for (const auto& m_mysql_server : m_proxysql_init_state) {
		// *********************** CHECK FOR INVALID KEYS ******************* //

		std::vector<std::string> invalid_keys {
			get_invalid_keys(valid_server_status_entries, m_mysql_server)
		};

		if (!invalid_keys.empty()) {
			return gen_invalid_keys_err(invalid_keys, json_key);
		}

		// ****************************************************************** //

		int hostgroup_id;
		std::string hostname {};
		int port;
		std::string status {};
		int64_t weight = -1;
		int64_t max_conns = -1;
		int32_t use_ssl = -1;
		std::string comment {};
		bool comment_is_set = false;

		try {
			hostgroup_id = m_mysql_server.at("hostgroup_id");
			hostname = m_mysql_server.at("hostname");
			port = m_mysql_server.at("port");
			status = m_mysql_server.at("status");

			if (m_mysql_server.contains("weight")) {
				weight = m_mysql_server.at("weight");
			}
			if (m_mysql_server.contains("max_connections")) {
				max_conns = m_mysql_server.at("max_connections");
			}
			if (m_mysql_server.contains("use_ssl")) {
				use_ssl = m_mysql_server.at("use_ssl");
			}
			if (m_mysql_server.contains("comment")) {
				comment = m_mysql_server.at("comment");
				comment_is_set = true;
			}
		} catch(const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}

		cluster_status.push_back(
			std::make_tuple(
				hostgroup_id,
				hostname,
				port,
				status,
				weight,
				max_conns,
				use_ssl,
				comment,
				comment_is_set
			)
		);
	}

	// fill output parameter
	out_cluster_status = std::move(cluster_status);

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> get_current_cluster_status(
	MYSQL* proxysql_admin,
	std::vector<server_status>& out_cluster_status
) {
	std::pair<int, std::string> err_res {};
	std::string t_err_msg { "'get_current_cluster_status' failed with error: '%s'" };
	std::string err_msg {};

	const std::string cluster_status_query {
		"SELECT hostgroup_id,hostname,port,status,weight,max_connections,use_ssl,comment FROM runtime_mysql_servers"
	};
	int q_res = mysql_query(proxysql_admin, cluster_status_query.c_str());

	if (q_res == 0) {
		ordered_json j_servers {};
		j_servers["proxysql_init_state"] = {};

		MYSQL_RES* my_servers_res = mysql_store_result(proxysql_admin);
		parse_result_to_json(my_servers_res, j_servers["proxysql_init_state"]);
		mysql_free_result(my_servers_res);

		// convert the fields into the proper types
		for (ordered_json& j_server : j_servers["proxysql_init_state"]) {
			j_server["hostgroup_id"] = atoi(std::string { j_server["hostgroup_id"] }.c_str());
			j_server["hostname"] = std::string { j_server["hostname"] };
			j_server["port"] = atoi(std::string { j_server["port"] }.c_str());
			j_server["status"] = std::string { j_server["status"] };
			j_server["weight"] = std::stoi(std::string { j_server["weight"] });
			j_server["max_connections"] = std::stoi(std::string { j_server["max_connections"] });
			j_server["use_ssl"] = std::stoi(std::string { j_server["use_ssl"] });
			j_server["comment"] = std::string { j_server["comment"] };
		}

		std::vector<server_status> res_cluster_status {};

		auto ext_st_err = extract_cluster_status(
			cluster_state::init_state, j_servers, res_cluster_status
		);

		if (ext_st_err.first == EXIT_SUCCESS) {
			out_cluster_status = std::move(res_cluster_status);
		} else {
			string_format(t_err_msg, err_msg, ext_st_err.second.c_str());
			err_res = { EXIT_FAILURE, err_msg };
		}
	} else {
		string_format(t_err_msg, err_msg, mysql_error(proxysql_admin));
		err_res = { EXIT_FAILURE, err_msg };
	}

	return err_res;
}

ordered_json cluster_status_to_json(const std::vector<server_status>& cluster_status) {
	ordered_json result = ordered_json::array({});

	for (const auto& server_status : cluster_status) {
		ordered_json srv_result {
			{ "hostgroup_id", std::get<0>(server_status) },
			{ "hostname", std::get<1>(server_status) },
			{ "port", std::get<2>(server_status) },
			{ "status", std::get<3>(server_status) },
		};

		const int64_t weight = std::get<MYSQL_SERVER_STATUS_T::WEIGHT>(server_status);
		const int64_t max_conns = std::get<MYSQL_SERVER_STATUS_T::MAX_CONNS>(server_status);
		const int64_t use_ssl = std::get<MYSQL_SERVER_STATUS_T::USE_SSL>(server_status);
		const string& comment = std::get<MYSQL_SERVER_STATUS_T::COMMENT>(server_status);
		const bool comment_is_set = std::get<MYSQL_SERVER_STATUS_T::COMMENT_IS_SET>(server_status);

		if (weight != -1) {
			srv_result["weight"] = weight;
		}
		if (max_conns != -1) {
			srv_result["max_connections"] = max_conns;
		}
		if (use_ssl != -1) {
			srv_result["use_ssl"] = use_ssl;
		}
		if (comment_is_set) {
			srv_result["comment"] = comment;
		}

		result.push_back(srv_result);
	}

	return result;
}

std::string cluster_status_checksum(const std::vector<server_status>& cluster_status) {
	SpookyHash spooky {};
	spooky.Init(13, 4);

	for (const auto& srv_st : cluster_status) {
		std::string hostgroup_id { std::to_string(std::get<0>(srv_st)) };
		std::string hostname { std::get<1>(srv_st)  };
		std::string port { std::to_string(std::get<2>(srv_st)) };
		std::string status { std::get<3>(srv_st) };
		std::string weight { std::to_string(std::get<4>(srv_st)) };
		std::string max_conns { std::to_string(std::get<5>(srv_st)) };
		std::string use_ssl { std::to_string(std::get<6>(srv_st)) };
		std::string comment { std::get<7>(srv_st) };

		spooky.Update(hostgroup_id.c_str(), hostgroup_id.size());
		spooky.Update(hostname.c_str(), hostname.size());
		spooky.Update(port.c_str(), port.size());
		spooky.Update(status.c_str(), status.size());
		spooky.Update(weight.c_str(), weight.size());
		spooky.Update(max_conns.c_str(), max_conns.size());
		spooky.Update(use_ssl.c_str(), use_ssl.size());
		spooky.Update(comment.c_str(), comment.size());
	}

	uint64_t hash1, hash2;
	spooky.Final(&hash1, &hash2);

	std::stringstream sstream;
	sstream << std::hex << hash1;
	std::string res_hash { sstream.str() };

	return res_hash;
}

std::pair<int, std::string> serialize_result(const nlohmann::ordered_json& j_res, std::string& out_str_res) {
	nlohmann::ordered_json c_j_res = j_res;
	nlohmann::ordered_json j_proxysql_init_state {};
	nlohmann::ordered_json j_proxysql_final_state {};
	nlohmann::ordered_json j_mysql_servers {};
	nlohmann::ordered_json j_mysql_monitor_variables {};

	const auto j_comparator =
		[] (const nlohmann::ordered_json& j_srv_st_1, const nlohmann::ordered_json& j_srv_st_2) {
			std::string id_1 {
				std::to_string(static_cast<int>(j_srv_st_1.at("hostgroup_id"))) +
				std::string { j_srv_st_1.at("hostname") } +
				std::to_string(static_cast<int>(j_srv_st_1.at("port")))
			};
			std::string id_2 {
				std::to_string(static_cast<int>(j_srv_st_2.at("hostgroup_id"))) +
				std::string { j_srv_st_2.at("hostname") } +
				std::to_string(static_cast<int>(j_srv_st_2.at("port")))
			};

			return id_1 < id_2;
		};

	try {
		j_proxysql_init_state = j_res.at("proxysql_init_state");
		j_proxysql_final_state = j_res.at("proxysql_final_state");
		j_mysql_servers = j_res.at("mysql_servers");

		if (j_res.find("mysql_monitor_config") != j_res.end()) {
			j_mysql_monitor_variables = j_res.at("mysql_monitor_config");
		} else {
			j_mysql_monitor_variables = {};
		}

		std::sort(j_proxysql_init_state.begin(), j_proxysql_init_state.end(), j_comparator);
		std::sort(j_proxysql_final_state.begin(), j_proxysql_final_state.end(), j_comparator);
		std::sort(j_mysql_servers.begin(), j_mysql_servers.end(), j_comparator);

		c_j_res["proxysql_init_state"] = nlohmann::ordered_json::array();
		c_j_res["proxysql_final_state"] = nlohmann::ordered_json::array();
		c_j_res["mysql_servers"] = nlohmann::ordered_json::array();
		c_j_res["mysql_monitor_config"] = nlohmann::ordered_json::array();

		unsigned int elem_num = 0;

		for (std::size_t i = 0; i < j_mysql_servers.size(); i++) {
			c_j_res["mysql_servers"].push_back("%" + std::to_string(elem_num) + "s");
			elem_num += 1;
		}

		for (std::size_t i = 0; i < j_proxysql_init_state.size(); i++) {
			c_j_res["proxysql_init_state"].push_back(
				"%" + std::to_string(elem_num) + "s"
			);
			elem_num += 1;
		}

		for (std::size_t i = 0; i < j_proxysql_final_state.size(); i++) {
			c_j_res["proxysql_final_state"].push_back(
				"%" + std::to_string(elem_num) + "s"
			);
			elem_num += 1;
		}

		for (std::size_t i = 0; i < j_mysql_monitor_variables.size(); i++) {
			c_j_res["mysql_monitor_config"].push_back("%" + std::to_string(elem_num) + "s");
			elem_num += 1;
		}

		elem_num = 0;

		std::string str_result { c_j_res.dump(4) };

		for (const nlohmann::ordered_json& j_mysql_srv_elem : j_mysql_servers) {
			std::string elem_str { j_mysql_srv_elem.dump() };

			elem_str = replace(elem_str, "{", "{ ");
			elem_str = replace(elem_str, "}", " }");

			str_result = replace(
				str_result,
				"\"%" + std::to_string(elem_num) + "s\"",
				elem_str
			);
			elem_num += 1;
		}

		for (const nlohmann::ordered_json& j_state_elem : j_proxysql_init_state) {
			std::string elem_str { j_state_elem.dump() };

			elem_str = replace(elem_str, "{", "{ ");
			elem_str = replace(elem_str, "}", " }");

			str_result = replace(
				str_result,
				"\"%" + std::to_string(elem_num) + "s\"",
				elem_str
			);
			elem_num += 1;
		}

		for (const nlohmann::ordered_json& j_state_elem : j_proxysql_final_state) {
			std::string elem_str { j_state_elem.dump() };

			elem_str = replace(elem_str, "{", "{ ");
			elem_str = replace(elem_str, "}", " }");

			str_result = replace(
				str_result,
				"\"%" + std::to_string(elem_num) + "s\"",
				elem_str
			);
			elem_num += 1;
		}

		for (const nlohmann::ordered_json& j_state_elem : j_mysql_monitor_variables) {
			std::string elem_str { j_state_elem.dump() };

			elem_str = replace(elem_str, "{", "{ ");
			elem_str = replace(elem_str, "}", " }");

			str_result = replace(
				str_result,
				"\"%" + std::to_string(elem_num) + "s\"",
				elem_str
			);
			elem_num += 1;
		}

		// add proper indentation
		str_result = replace(str_result, "\n", "\n        ");

		// fill the output parameter
		out_str_res = str_result;
	} catch (const std::exception& e) {
		return { EXIT_FAILURE, e.what() };
	}

	return { EXIT_SUCCESS, "" };
}

std::string serialize_result(const nlohmann::ordered_json& j_result) {
	nlohmann::ordered_json c_j_result = j_result;

	// report all the simuation outputs
	unsigned int res_num = 0;

	std::vector<std::string> sim_results_str {};
	if (c_j_result.contains("results")) {
		for (auto& j_sim_result : c_j_result["results"]) {
			if (j_sim_result.contains("result")) {
				std::string sim_result_str {};
				const auto ser_res_err =
					serialize_result(j_sim_result["result"], sim_result_str);

				if (ser_res_err.first) {
					c_j_result = internal_error(ser_res_err.second, __FILE__, __LINE__);
					break;
				} else {
					sim_results_str.push_back(sim_result_str);
					j_sim_result = "%" + std::to_string(res_num) + "s";
				}
			} else if (
				j_sim_result.contains("err_type") &&
				(j_sim_result.at("err_type") == "verification_error" )
			) {
				std::string sim_err_str {};
				const auto ser_res_err =
					serialize_verification_error(j_sim_result, sim_err_str);

				if (ser_res_err.first) {
					c_j_result = internal_error(ser_res_err.second, __FILE__, __LINE__);
					break;
				} else {
					sim_results_str.push_back(sim_err_str);
					j_sim_result = "%" + std::to_string(res_num) + "s";
				}
			} else {
				std::string sim_result_str { j_sim_result.dump(4) };

				// add proper indentation
				sim_result_str = replace(sim_result_str, "\n", "\n        ");

				sim_results_str.push_back(sim_result_str);
				j_sim_result = "%" + std::to_string(res_num) + "s";
			}

			// update the placeholder
			res_num += 1;
		}
	}

	res_num = 0;

	std::string t_str_res { c_j_result.dump(4) };

	// replace the placeholders
	for (const auto& sim_str : sim_results_str) {
		t_str_res = replace(
			t_str_res,
			"\"%" + std::to_string(res_num) + "s\"",
			sim_str
		);
		res_num += 1;
	}

	return t_str_res;
}

string acc_keys(const vector<string>& keys) {
	const auto append = [](const string& a, const string& b) -> string {
		string f { a.size() > 0 ? string { a + "," } : a };
		return f + string { "\"" + b + "\"" };
	};
	return std::accumulate(keys.begin(), keys.end(), string {}, append);
}

std::string get_fmt_time() {
	time_t __timer;
	char __buffer[30];

	struct tm __tm_info {};
	time(&__timer);
	localtime_r(&__timer, &__tm_info);
	strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", &__tm_info);

	return std::string(__buffer);
}
