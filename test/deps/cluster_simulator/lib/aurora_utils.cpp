#include "aurora_utils.h"

#include <algorithm>
#include <iostream>
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

const char t_aurora_server_state_insert[] {
	"INSERT OR REPLACE INTO REPLICA_HOST_STATUS("
		" SERVER_ID,"
		" DOMAIN_NAME,"
		" SESSION_ID,"
		" CPU,"
		" LAST_UPDATE_TIMESTAMP,"
		" REPLICA_LAG_IN_MILLISECONDS"
	") VALUES ("
		"'%s', '%s', '%s', %d, '%s', %d"
	")"
};

std::pair<int, string> prepare_aurora_cluster_state(
	MYSQL* proxysql_sqlite,
	const vector<aurora_server_state_t>& servers,
	uint32_t cleanup
) {
	int query_error = 0;

	if (cleanup) {
		string srv_ids {};
		string domain_names {};

		for (const auto& server : servers) {
			srv_ids += "'" + std::get<AURORA_SERVER_STATE::SERVER_ID>(server) + "'";
			domain_names += "'" + std::get<AURORA_SERVER_STATE::DOMAIN_NAME>(server) + "'";

			if (&server != &servers.back()) {
				srv_ids += ",";
				domain_names += ",";
			}
		}

		string cleanup_query {};

		if (cleanup == 1) {
			cleanup_query = "DELETE FROM REPLICA_HOST_STATUS WHERE SERVER_ID NOT IN (" +
				srv_ids + ") OR DOMAIN_NAME NOT IN (" + domain_names + ")";
		} else {
			cleanup_query = "DELETE FROM REPLICA_HOST_STATUS";
		}

		query_error = mysql_query(proxysql_sqlite, cleanup_query.c_str());
		if (query_error) {
			return create_query_error(proxysql_sqlite, cleanup_query, __FILE__, __LINE__);
		}
	}

	usleep(1000 * 1000);

	// NOTE: We adquire a 'write lock' so there are no dirty reads on ProxySQL side
	// while we write the new values.
	query_error = mysql_query(proxysql_sqlite, "BEGIN IMMEDIATE");
	if (query_error) {
		return create_query_error(proxysql_sqlite, "BEGIN IMMEDIATE", __FILE__, __LINE__);
	}

	for (const auto& server : servers) {
		string server_insert_query {};

		string_format(
			t_aurora_server_state_insert,
			server_insert_query,
			std::get<AURORA_SERVER_STATE::SERVER_ID>(server).c_str(),
			std::get<AURORA_SERVER_STATE::DOMAIN_NAME>(server).c_str(),
			std::get<AURORA_SERVER_STATE::SESSION_ID>(server).c_str(),
			0,
			"",
			std::get<AURORA_SERVER_STATE::REPLICA_LAG_IN_MILLISECONDS>(server)
		);

		query_error = mysql_query(proxysql_sqlite, server_insert_query.c_str());
		if (query_error) {
			return create_query_error(proxysql_sqlite, server_insert_query, __FILE__, __LINE__);
		}
	}

	query_error = mysql_query(proxysql_sqlite, "COMMIT");
	if (query_error) {
		return create_query_error(proxysql_sqlite, "COMMIT", __FILE__, __LINE__);
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

aurora_server_state_t aurora_update_state(
	const aurora_server_state_t& st1,
	const aurora_server_state_t& st2
) {
	aurora_server_state_t result {};

	// SERVER_ID and DOMAIN_NAME **can't** be changed, because the are part of the server 'id'. Only the other
	// fields are allowed to change, otherwise, the verification step should have failed.

	const string st1_session_id { std::get<AURORA_SERVER_STATE::SESSION_ID>(st1) };
	const string st2_session_id { std::get<AURORA_SERVER_STATE::SESSION_ID>(st2) };

	int32_t st1_read_only { std::get<AURORA_SERVER_STATE::REPLICA_LAG_IN_MILLISECONDS>(st1) };
	int32_t st2_read_only { std::get<AURORA_SERVER_STATE::REPLICA_LAG_IN_MILLISECONDS>(st2) };

	// Since empty 'SESSION_IDs' have no meaning, we ignore them for updated states
	if (st2_session_id != "" && st1_session_id != st2_session_id) {
		std::get<2>(result) = st2_session_id;
	}

	if (st2_read_only != -1 && st1_read_only != st2_read_only) {
		std::get<3>(result) = st2_read_only;
	}

	return result;
}

vector<aurora_server_state_t> aurora_update_cluster_state(
	const vector<aurora_server_state_t>& servers_state_p,
	const vector<aurora_server_state_t>& servers_state_n
) {
	vector<aurora_server_state_t> result {};

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
				const aurora_server_state_t server_state_update {
					aurora_update_state(server_state_p, server_state_n)
				};
				result.push_back(server_state_update);
			}
		}
	}

	return result;
}
