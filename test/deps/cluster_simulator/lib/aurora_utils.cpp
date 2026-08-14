#include "aurora_utils.h"

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <stdio.h>
#include <sstream>
#include <tuple>
#include <unordered_map>

// NOTE: Only needed during testing
#include <functional>

#include <mysql.h>
#include <mysqld_error.h>
#include <string.h>
#include <string>
#include <unistd.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"
#include "command_line.h"
#include "json.hpp"

using std::string;
using std::vector;

const vector<string> valid_aurora_hostgroup_entries {
	"writer_hostgroup",
	"reader_hostgroup",
	"active",
	"domain_name",
	"max_lag_ms",
	"check_interval_ms",
	"writer_is_also_reader",
	"new_reader_weight",
	"add_lag_ms",
	"min_lag_ms",
	"autopurge_missing_checks",
	"comment"
};

const char t_aurora_hostgroup_insert[] {
	"INSERT INTO mysql_aws_aurora_hostgroups ("
		" writer_hostgroup,"
		" reader_hostgroup,"
		" active,"
		" domain_name,"
		" max_lag_ms,"
		" check_interval_ms,"
		" writer_is_also_reader,"
		" new_reader_weight,"
		" add_lag_ms,"
		" min_lag_ms,"
		" autopurge_missing_checks,"
		" comment"
	") VALUES ("
		" %d, %d, %d, '%s', %d, %d, %d, %d, %d, %d, %d, '%s'"
	")"
};

std::pair<int,string> extract_aurora_hostgroup_config(
	const json& aurora_test_def,
	vector<aurora_hostgroup_config_t>& out_hostgroups_configs
) {
	// result
	vector<aurora_hostgroup_config_t> res_hostgroup_configs {};

	if (!aurora_test_def.is_object()) {
		return {
			EXIT_FAILURE,
			"Invalid input. Expected 'test_definition' should be a JSON object.",
		};
	}

	const auto& j_aurora_hostgroups { aurora_test_def.find("mysql_aws_aurora_hostgroups") };
	if (j_aurora_hostgroups == aurora_test_def.end()) {
		return {
			EXIT_FAILURE,
			"Invalid input. Unable to find required field 'mysql_aws_aurora_hostgroups'",
		};
	}
	if (!j_aurora_hostgroups.value().is_array()) {
		return {
			EXIT_FAILURE,
			"Invalid input. 'mysql_aws_aurora_hostgroups' isn't of expected type 'array'"
		};
	}

	for (const auto& j_aurora_hg : j_aurora_hostgroups.value()) {
		// *********************** CHECK FOR INVALID KEYS ******************* //

		vector<string> invalid_keys { get_invalid_keys(valid_aurora_hostgroup_entries, j_aurora_hg) };

		if (!invalid_keys.empty()) {
			return gen_invalid_keys_err(invalid_keys, "mysql_aws_aurora_hostgroups");
		}

		// ****************************************************************** //

		int writer_hostgroup = 0;
		int reader_hostgroup = 0;
		int active = 0;
		string domain_name {};
		int max_lag_ms = 0;
		int writer_is_also_reader = 0;
		int new_reader_weight = 0;
		string comment {};
		json j_comment {};

		// Default values for optional fields
		int32_t min_lag_ms = 30;
		int32_t add_lag_ms = 30;
		int32_t check_interval_ms = 1000;
		int32_t autopurge_missing_checks = 0;

		try {
			writer_hostgroup = j_aurora_hg.at("writer_hostgroup");
			reader_hostgroup = j_aurora_hg.at("reader_hostgroup");
			active = j_aurora_hg.at("active");
			domain_name = j_aurora_hg.at("domain_name");
			max_lag_ms = j_aurora_hg.at("max_lag_ms");
			writer_is_also_reader = j_aurora_hg.at("writer_is_also_reader");
			new_reader_weight = j_aurora_hg.at("new_reader_weight");

			// Optional fields
			if (j_aurora_hg.find("add_lag_ms") != j_aurora_hg.end()) {
				add_lag_ms = j_aurora_hg.at("add_lag_ms");
			}
			if (j_aurora_hg.find("min_lag_ms") != j_aurora_hg.end()) {
				min_lag_ms = j_aurora_hg.at("min_lag_ms");
			}
			if (j_aurora_hg.find("check_interval_ms") != j_aurora_hg.end()) {
				check_interval_ms = j_aurora_hg.at("check_interval_ms");
			}
			if (j_aurora_hg.find("autopurge_missing_checks") != j_aurora_hg.end()) {
				autopurge_missing_checks = j_aurora_hg.at("autopurge_missing_checks");
			}
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}

		if (j_comment == nullptr) {
			comment = "NULL";
		} else {
			try {
				comment = j_aurora_hg.at("comment");
			} catch (const std::exception& e) {
				return { EXIT_FAILURE, e.what() };
			}
		}

		res_hostgroup_configs.push_back(
			{
				writer_hostgroup,
				reader_hostgroup,
				active,
				domain_name,
				max_lag_ms,
				check_interval_ms,
				writer_is_also_reader,
				new_reader_weight,
				add_lag_ms,
				min_lag_ms,
				autopurge_missing_checks,
				comment
			}
		);
	}

	// fill the output parameter with the result
	out_hostgroups_configs = res_hostgroup_configs;

	return { EXIT_SUCCESS, "" };
}

const vector<string> valid_aurora_entries {
	"SERVER_ID",
	"DOMAIN_NAME",
	"SESSION_ID",
	"REPLICA_LAG_IN_MILLISECONDS",
};

std::pair<int,string> extract_aurora_servers_state(
	const aurora_state_id& state_id,
	const json& aurora_test_def,
	vector<aurora_server_state_t>& out_server_states
) {
	// result
	vector<aurora_server_state_t> res_states {};

	// perform basic payload checks
	bool has_cluster_type {
		check_present_and_type(aurora_test_def, {"cluster_type"}, json::value_t::string)
	};
	if (!has_cluster_type || string { aurora_test_def["cluster_type"] } != "AURORA") {
		return { EXIT_FAILURE, "Unable to find required field \"cluster_type\"'" };
	}

	json j_clusters_statuses {};

	if (state_id == aurora_state_id::init_state) {
		try {
			j_clusters_statuses = aurora_test_def.at("aurora_servers_init_state");
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}
	} else {
		try {
			j_clusters_statuses = aurora_test_def.at("aurora_servers_new_state");
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}
	}

	if (!j_clusters_statuses.is_object()) {
		return { EXIT_FAILURE, "'aurora_j_servers_state' isn't of expected type 'Object'" };
	}

	for (const auto& j_cluster_state : j_clusters_statuses.items()) {
		const string domain_name { j_cluster_state.key() };

		for (const auto& server_state : j_cluster_state.value()) {
			// *********************** CHECK FOR INVALID KEYS ******************* //

			// check that the keys only match the expected ones, non-expected keys
			// are not allowed this is to avoid typos in cluster config.
			vector<string> invalid_keys { get_invalid_keys(valid_aurora_entries, server_state) };

			if (!invalid_keys.empty()) {
				string t_err_msg { "'%s' contains invalid keys: [%s]" };
				string err_msg {};
				string invalid_keys_str { acc_keys(invalid_keys) };

				if (state_id == aurora_state_id::init_state) {
					string_format(t_err_msg, err_msg, "aurora_servers_init_state", invalid_keys_str.c_str());
					return { EXIT_FAILURE, err_msg };
				} else {
					string_format(t_err_msg, err_msg, "aurora_servers_new_state", invalid_keys_str.c_str());
					return { EXIT_FAILURE, err_msg };
				}
			}

			// ****************************************************************** //

			string server_id {};
			string session_id {};
			int32_t replica_lag_in_ms = 0;

			if (state_id == aurora_state_id::init_state) {
				// try to extract all the expected fields
				try {
					server_id = server_state.at("SERVER_ID");
					session_id = server_state.at("SESSION_ID");
					replica_lag_in_ms = server_state.at("REPLICA_LAG_IN_MILLISECONDS");
				} catch (const std::exception& e) {
					return { EXIT_FAILURE, e.what() };
				}
			} else {
				try {
					const auto& m_server_id = server_state.at("SERVER_ID");
					const auto& m_session_id = server_state.at("SESSION_ID");
					const auto& m_replica_lag_in_ms = server_state.at("REPLICA_LAG_IN_MILLISECONDS");

					if (m_server_id == nullptr) {
						server_id = "nullptr";
					} else {
						try {
							server_id = server_state["SERVER_ID"];
						} catch (const std::exception& e) {
							return { EXIT_FAILURE, e.what() };
						}
					}
					if (m_session_id == nullptr) {
						session_id = true;
					} else {
						try {
							session_id = server_state["SESSION_ID"];
						} catch (const std::exception& e) {
							return { EXIT_FAILURE, e.what() };
						}
					}
					if (m_replica_lag_in_ms == nullptr) {
						replica_lag_in_ms = -1;
					} else {
						try {
							replica_lag_in_ms = server_state["REPLICA_LAG_IN_MILLISECONDS"];
						} catch (const std::exception& e) {
							return { EXIT_FAILURE, e.what() };
						}
					}
				} catch (const std::exception& e) {
					return { EXIT_FAILURE, e.what() };
				}
			}
			// if no error ocurred push the state to the result
			res_states.push_back(
				std::make_tuple(
					server_id,
					domain_name,
					session_id,
					replica_lag_in_ms
				)
			);
		}
	}

	// fill the output parameter
	out_server_states = res_states;

	return { EXIT_SUCCESS, "" };
}

std::pair<int, string> prepare_mysql_aurora_hostgroups(
	MYSQL* proxysql_admin,
	const vector<aurora_hostgroup_config_t>& hostgroups_configs
) {
	int query_error = 0;

	const string hostgroups_cleanup { "DELETE FROM mysql_aws_aurora_hostgroups" };
	query_error = mysql_query(proxysql_admin, hostgroups_cleanup.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, hostgroups_cleanup, __FILE__, __LINE__);
	}

	for (const auto& hostgroup_config : hostgroups_configs) {
		string aurora_hostgroup_insert {};

		// NOTE: Comment can't be null, no need of special handling
		string_format(
			t_aurora_hostgroup_insert,
			aurora_hostgroup_insert,
			hostgroup_config.writer_hostgroup,
			hostgroup_config.reader_hostgroup,
			hostgroup_config.active,
			hostgroup_config.domain_name.c_str(),
			hostgroup_config.max_lag_ms,
			hostgroup_config.check_interval_ms,
			hostgroup_config.writer_is_also_reader,
			hostgroup_config.new_reader_weight,
			hostgroup_config.add_lag_ms,
			hostgroup_config.min_lag_ms,
			hostgroup_config.autopurge_missing_checks,
			hostgroup_config.comment.c_str()
		);

		query_error = mysql_query(proxysql_admin, aurora_hostgroup_insert.c_str());
		if (query_error) {
			return create_query_error(
				proxysql_admin, aurora_hostgroup_insert, __FILE__, __LINE__
			);
		}
	}

	return { EXIT_SUCCESS, "" };
}

namespace {

string aurora_sql_quote(const string& value) {
	string quoted { "'" };
	for (char c : value) {
		quoted += c;
		if (c == '\'') {
			quoted += '\'';
		}
	}
	quoted += '\'';
	return quoted;
}

string aurora_utc_timestamp() {
	time_t now = time(nullptr);
	struct tm utc_time {};
	gmtime_r(&now, &utc_time);
	char timestamp[20] {};
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &utc_time);
	return timestamp;
}

std::pair<int, uint64_t> aurora_scalar_uint64(MYSQL* connection, const string& query) {
	if (mysql_query(connection, query.c_str()) != 0) {
		return { EXIT_FAILURE, 0 };
	}
	MYSQL_RES* result = mysql_store_result(connection);
	if (result == nullptr) {
		return { EXIT_FAILURE, 0 };
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	const bool valid = row != nullptr && row[0] != nullptr;
	const uint64_t value = valid ? strtoull(row[0], nullptr, 10) : 0;
	mysql_free_result(result);
	return { valid ? EXIT_SUCCESS : EXIT_FAILURE, value };
}

std::pair<int, string> load_aurora_backend_addresses(
	std::unordered_map<string, string>& addresses)
{
	const char* host_file_path = getenv("CLUSTER_SIM_HOST_FILE");
	if (host_file_path == nullptr || *host_file_path == '\0') {
		return { EXIT_FAILURE, "CLUSTER_SIM_HOST_FILE is not configured" };
	}

	std::ifstream host_file { host_file_path };
	if (!host_file.is_open()) {
		return {
			EXIT_FAILURE,
			"Unable to open CLUSTER_SIM_HOST_FILE '" + string { host_file_path } + "'"
		};
	}

	string line {};
	uint64_t line_number = 0;
	while (std::getline(host_file, line)) {
		++line_number;
		std::istringstream fields { line };
		string hostname {};
		string ip {};
		if (!(fields >> hostname) || hostname.front() == '#') {
			continue;
		}
		if (!(fields >> ip)) {
			return {
				EXIT_FAILURE,
				"Missing IP in CLUSTER_SIM_HOST_FILE at line " + std::to_string(line_number)
			};
		}

		auto existing = addresses.find(hostname);
		if (existing != addresses.end() && existing->second != ip) {
			return {
				EXIT_FAILURE,
				"Conflicting CLUSTER_SIM_HOST_FILE mappings for '" + hostname + "'"
			};
		}
		addresses[hostname] = ip;
	}

	return { EXIT_SUCCESS, "" };
}

}  // namespace

std::pair<int, string> prepare_aurora_cluster_state(
	MYSQL* proxysql_sqlite,
	const vector<aurora_server_state_t>& servers,
	aurora_publication_mode mode
) {
	std::unordered_map<string, string> backend_addresses {};
	auto [host_file_rc, host_file_error] =
		load_aurora_backend_addresses(backend_addresses);
	if (host_file_rc != EXIT_SUCCESS) {
		return { EXIT_FAILURE, host_file_error };
	}

	std::map<string, vector<aurora_server_state_t>> replica_sets {};
	for (const aurora_server_state_t& server : servers) {
		replica_sets[std::get<AURORA_SERVER_STATE::DOMAIN_NAME>(server)].push_back(server);
	}

	int query_error = mysql_query(proxysql_sqlite, "BEGIN IMMEDIATE");
	if (query_error) {
		return create_query_error(proxysql_sqlite, "BEGIN IMMEDIATE", __FILE__, __LINE__);
	}

	const auto execute_or_rollback = [proxysql_sqlite](const string& query) {
		if (mysql_query(proxysql_sqlite, query.c_str()) == 0) {
			return std::pair<int, string> { EXIT_SUCCESS, "" };
		}
		auto error = create_query_error(proxysql_sqlite, query, __FILE__, __LINE__);
		(void)mysql_query(proxysql_sqlite, "ROLLBACK");
		return error;
	};

	string replica_set_list {};
	for (const auto& replica_set : replica_sets) {
		if (!replica_set_list.empty()) replica_set_list += ",";
		replica_set_list += aurora_sql_quote(replica_set.first);
	}

	uint64_t probe_checkpoint = 0;
	if (mode == aurora_publication_mode::replace_snapshot_retaining_backends) {
		auto [checkpoint_rc, checkpoint] = aurora_scalar_uint64(
			proxysql_sqlite,
			"SELECT COALESCE(MAX(sequence_id),0) FROM AWS_AURORA_REPLICA_PROBE_LOG");
		if (checkpoint_rc != EXIT_SUCCESS) {
			(void)mysql_query(proxysql_sqlite, "ROLLBACK");
			return { EXIT_FAILURE, "Unable to read the Aurora replica probe checkpoint" };
		}
		probe_checkpoint = checkpoint;
	}

	if (mode == aurora_publication_mode::reset_scenario) {
		auto [control_rc, control_error] =
			execute_or_rollback("DELETE FROM AWS_AURORA_REPLICA_CONTROL");
		if (control_rc != EXIT_SUCCESS) return { control_rc, control_error };
		auto [rows_rc, rows_error] = execute_or_rollback("DELETE FROM REPLICA_HOST_STATUS");
		if (rows_rc != EXIT_SUCCESS) return { rows_rc, rows_error };
	} else if (mode == aurora_publication_mode::replace_snapshot_retaining_backends) {
		const string delete_controls {
			replica_set_list.empty()
				? "DELETE FROM AWS_AURORA_REPLICA_CONTROL"
				: "DELETE FROM AWS_AURORA_REPLICA_CONTROL WHERE replica_set_id NOT IN (" +
					replica_set_list + ")"
		};
		auto [control_rc, control_error] = execute_or_rollback(delete_controls);
		if (control_rc != EXIT_SUCCESS) return { control_rc, control_error };
		if (!replica_set_list.empty()) {
			auto [reset_rc, reset_error] = execute_or_rollback(
				"UPDATE AWS_AURORA_REPLICA_CONTROL SET replica_table_present=1,"
				"error_code=0,error_msg='' WHERE replica_set_id IN (" +
				replica_set_list + ")");
			if (reset_rc != EXIT_SUCCESS) return { reset_rc, reset_error };
		}
		auto [rows_rc, rows_error] = execute_or_rollback("DELETE FROM REPLICA_HOST_STATUS");
		if (rows_rc != EXIT_SUCCESS) return { rows_rc, rows_error };
	} else {
		for (const auto& replica_set : replica_sets) {
			const string set_literal { aurora_sql_quote(replica_set.first) };
			auto [control_rc, control_error] = execute_or_rollback(
				"DELETE FROM AWS_AURORA_REPLICA_CONTROL WHERE replica_set_id=" + set_literal);
			if (control_rc != EXIT_SUCCESS) return { control_rc, control_error };
			auto [rows_rc, rows_error] = execute_or_rollback(
				"DELETE FROM REPLICA_HOST_STATUS WHERE REPLICA_SET_ID=" + set_literal);
			if (rows_rc != EXIT_SUCCESS) return { rows_rc, rows_error };
		}
	}

	const string timestamp { aurora_utc_timestamp() };
	for (const auto& replica_set : replica_sets) {
		const string& replica_set_id = replica_set.first;
		std::map<std::pair<string, int>, bool> mapped_backends {};
		for (const aurora_server_state_t& server : replica_set.second) {
			const string& server_id = std::get<AURORA_SERVER_STATE::SERVER_ID>(server);
			string session_id = std::get<AURORA_SERVER_STATE::SESSION_ID>(server);
			if (session_id.empty()) {
				session_id = "TESTID-" + server_id + replica_set_id + "-R";
			}
			const string hostname { server_id + replica_set_id };
			auto address = backend_addresses.find(hostname);
			if (address == backend_addresses.end()) {
				(void)mysql_query(proxysql_sqlite, "ROLLBACK");
				return {
					EXIT_FAILURE,
					"Missing CLUSTER_SIM_HOST_FILE mapping for Aurora member '" +
						hostname + "'"
				};
			}

			const string row_query {
				"INSERT INTO REPLICA_HOST_STATUS"
				"(REPLICA_SET_ID,SERVER_ID,SESSION_ID,CPU,LAST_UPDATE_TIMESTAMP,"
					"REPLICA_LAG_IN_MILLISECONDS,IS_CURRENT) VALUES (" +
				aurora_sql_quote(replica_set_id) + "," + aurora_sql_quote(server_id) +
				"," + aurora_sql_quote(session_id) + ",0," +
				aurora_sql_quote(timestamp) + "," +
				std::to_string(std::get<AURORA_SERVER_STATE::REPLICA_LAG_IN_MILLISECONDS>(server)) +
				",1)"
			};
			auto [row_rc, row_error] = execute_or_rollback(row_query);
			if (row_rc != EXIT_SUCCESS) return { row_rc, row_error };

			mapped_backends[{ address->second, 3306 }] = true;
		}

		for (const auto& backend : mapped_backends) {
			const string control_query {
				"INSERT OR REPLACE INTO AWS_AURORA_REPLICA_CONTROL"
				"(backend_ip,backend_port,replica_set_id,replica_table_present,error_code,error_msg) "
				"VALUES (" + aurora_sql_quote(backend.first.first) + "," +
				std::to_string(backend.first.second) + "," + aurora_sql_quote(replica_set_id) +
				",1,0,'')"
			};
			auto [control_rc, control_error] = execute_or_rollback(control_query);
			if (control_rc != EXIT_SUCCESS) return { control_rc, control_error };
		}
	}

	query_error = mysql_query(proxysql_sqlite, "COMMIT");
	if (query_error) {
		(void)mysql_query(proxysql_sqlite, "ROLLBACK");
		return create_query_error(proxysql_sqlite, "COMMIT", __FILE__, __LINE__);
	}

	if (mode == aurora_publication_mode::replace_snapshot_retaining_backends &&
		!replica_sets.empty()) {
		const uint64_t deadline = monotonic_time() + 10000000;
		const string observed_sets_query {
			"SELECT COUNT(DISTINCT replica_set_id) FROM AWS_AURORA_REPLICA_PROBE_LOG "
			"WHERE sequence_id>" + std::to_string(probe_checkpoint) +
			" AND probe_kind='ordinary' AND replica_set_id IN (" +
			replica_set_list + ")"
		};
		do {
			auto [observed_rc, observed_sets] =
				aurora_scalar_uint64(proxysql_sqlite, observed_sets_query);
			if (observed_rc != EXIT_SUCCESS) {
				return { EXIT_FAILURE, "Unable to read the Aurora replica probe log" };
			}
			if (observed_sets == replica_sets.size()) {
				return { EXIT_SUCCESS, "" };
			}
			usleep(50000);
		} while (monotonic_time() < deadline);

		return {
			EXIT_FAILURE,
			"Timed out waiting for every Aurora replica set to be probed"
		};
	}

	return { EXIT_SUCCESS, "" };
}

std::pair<int,std::string> set_aurora_monitor_check_times(MYSQL* admin) {
	// NOTE: Not required for now
	return { 0, {} };
}

std::pair<int, std::string> get_aurora_monitor_check_times(
	MYSQL* admin, int& out_healthcheck_interval, int& out_healthcheck_timeout
) {
	// NOTE: Hardcoded for now
	out_healthcheck_interval = 200;
	out_healthcheck_timeout = 100;

	return { 0, {} };
}

vector<aurora_server_state_t> sort_aurora_server_state(
	const vector<aurora_server_state_t>& aurora_servers_state
) {
	vector<aurora_server_state_t> c_aurora_servers_state { aurora_servers_state };

	const auto aurora_server_state_comparator = [] (
		const aurora_server_state_t& srv_st1,
		const aurora_server_state_t& srv_st2
	) -> bool {
		const string srv_st1_id {
			std::get<AURORA_SERVER_STATE::DOMAIN_NAME>(srv_st1) +
			std::get<AURORA_SERVER_STATE::SERVER_ID>(srv_st1)
		};
		const string srv_st2_id {
			std::get<AURORA_SERVER_STATE::DOMAIN_NAME>(srv_st2) +
			std::get<AURORA_SERVER_STATE::SERVER_ID>(srv_st2)
		};

		return srv_st1_id > srv_st2_id;
	};

	std::sort(
		c_aurora_servers_state.begin(),
		c_aurora_servers_state.end(),
		aurora_server_state_comparator
	);

	return c_aurora_servers_state;
}

vector<std::pair<column_id, string>> aurora_state_members_diff(
	const aurora_server_state_t& st1,
	const aurora_server_state_t& st2
) {
	vector<std::pair<column_id, string>> result {};

	// SERVER_ID and DOMAIN_NAME **can't** be changed, because the are part of the server 'id'. Only the other
	// fields are allowed to change, otherwise, the verification step should have failed.

	string st1_session_id = std::get<AURORA_SERVER_STATE::SESSION_ID>(st1);
	string st2_session_id = std::get<AURORA_SERVER_STATE::SESSION_ID>(st2);

	int st1_replica_lag = std::get<AURORA_SERVER_STATE::REPLICA_LAG_IN_MILLISECONDS>(st1);
	int st2_replica_lag = std::get<AURORA_SERVER_STATE::REPLICA_LAG_IN_MILLISECONDS>(st2);

	// NOTE: This decission breaks the 'cluster_state_diff' report. Probably automatically filling the values
	// would be the best decission.
	if (st1_session_id != "" && st1_session_id != st2_session_id) {
		result.push_back({ "SESSION_ID", st2_session_id });
	}

	if (st2_replica_lag != -1 && st1_replica_lag != st2_replica_lag) {
		result.push_back({ "REPLICA_LAG_IN_MILLISECONDS", std::to_string(st2_replica_lag) });
	}

	return result;
}

cluster_state_changes aurora_servers_state_diff(
	const vector<aurora_server_state_t>& servers_state_p,
	const vector<aurora_server_state_t>& servers_state_n
) {
	cluster_state_changes result {};

	vector<aurora_server_state_t> s_servers_state_p { sort_aurora_server_state(servers_state_p) };
	vector<aurora_server_state_t> s_servers_state_n { sort_aurora_server_state(servers_state_n) };

	// find the differences
	for (const auto& server_state_n : s_servers_state_n) {
		for (const auto& server_state_p : s_servers_state_p) {
			const string n_server_state_id {
				std::get<AURORA_SERVER_STATE::SERVER_ID>(server_state_n) + ":" +
				std::get<AURORA_SERVER_STATE::DOMAIN_NAME>(server_state_n)
			};
			const string p_server_state_id {
				std::get<AURORA_SERVER_STATE::SERVER_ID>(server_state_p) + ":" +
				std::get<AURORA_SERVER_STATE::DOMAIN_NAME>(server_state_p)
			};

			bool diff_server_status =
				( n_server_state_id == p_server_state_id ) &&
				( server_state_n != server_state_p );

			if (diff_server_status) {
				const auto server_state_diff =
					aurora_state_members_diff(server_state_p, server_state_n);
				result.insert({ n_server_state_id, server_state_diff });
			}
		}
	}

	return result;
}
