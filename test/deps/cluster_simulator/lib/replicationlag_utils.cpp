#include "replicationlag_utils.h"

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


const std::vector<std::string> valid_replicationlag_entries {
	"hostname",
	"port",
	"seconds_behind_master",
};

std::pair<int,std::string> extract_replicationlag_servers_state(
	const replicationlag_state_id& state_id,
	const json& replicationlag_test_def,
	std::vector<replicationlag_server_state>& out_server_states
) {
	// result
	std::vector<replicationlag_server_state> res_states {};

	// perform basic payload checks
	bool has_cluster_type =
		check_present_and_type(replicationlag_test_def, {"cluster_type"}, json::value_t::string);
	if (!has_cluster_type || std::string { replicationlag_test_def["cluster_type"] } != "REPLICATION_LAG") {
		return { EXIT_FAILURE, "Unable to find required field \"cluster_type\"'" };
	}

	json j_servers_state {};

	if (state_id == replicationlag_state_id::init_state) {
		try {
			j_servers_state = replicationlag_test_def.at("replicationlag_servers_init_state");
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}
	} else {
		try {
			j_servers_state = replicationlag_test_def.at("replicationlag_servers_new_state");
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}
	}

	if (!j_servers_state.is_array()) {
		return { EXIT_FAILURE, "'replicationlag_j_servers_state' isn't of expected type 'array'" };
	}

	for (const auto& server_state : j_servers_state) {
		// *********************** CHECK FOR INVALID KEYS ******************* //

		// check that the keys only match the expected ones, non-expected keys
		// are not allowed this is to avoid typos in cluster config.

		std::vector<std::string> invalid_keys {
			get_invalid_keys(valid_replicationlag_entries, server_state)
		};

		if (!invalid_keys.empty()) {
			std::string t_err_msg { "'%s' contains invalid keys: ['%s']" };
			std::string err_msg {};

			std::string invalid_keys_str =
				std::accumulate(
					invalid_keys.begin(),
					invalid_keys.end(),
					std::string {},
					[](const std::string& a, const std::string& b) -> std::string {
						return "\"" + a + "\"" + (a.length() > 0 ? "," : "") + "\"" + b + "\"";
					}
				);

			if (state_id == replicationlag_state_id::init_state) {
				string_format(t_err_msg, err_msg, "replicationlag_servers_init_state", invalid_keys_str.c_str());
				return { EXIT_FAILURE, err_msg };
			} else {
				string_format(t_err_msg, err_msg, "replicationlag_servers_new_state", invalid_keys_str.c_str());
				return { EXIT_FAILURE, err_msg };
			}
		}

		// ****************************************************************** //

		std::string hostname {};
		int port;
		std::unique_ptr<int> seconds_behind_master;

		if (state_id == replicationlag_state_id::init_state) {
			// try to extract all the expected fields
			try {
				hostname = server_state.at("hostname");
				port = server_state.at("port");
				const auto& m_seconds_behind_master = server_state.at("seconds_behind_master");
				if (m_seconds_behind_master == nullptr || m_seconds_behind_master.is_null()) {
					seconds_behind_master = nullptr;
				} else {
					int* repl_lag = new int(server_state["seconds_behind_master"]);
					seconds_behind_master = std::unique_ptr<int>(repl_lag);
				}
			} catch (const std::exception& e) {
				return { EXIT_FAILURE, e.what() };
			}
		} else {
			try {
				const auto& m_hostname = server_state.at("hostname");
				const auto& m_port = server_state.at("port");
				const auto& m_seconds_behind_master = server_state.at("seconds_behind_master");

				if (m_hostname == nullptr) {
					hostname = "nullptr";
				} else {
					try {
						hostname = server_state["hostname"];
					} catch (const std::exception& e) {
						return { EXIT_FAILURE, e.what() };
					}
				}
				if (m_port == nullptr) {
					port = -1;
				} else {
					try {
						port = server_state["port"];
					} catch (const std::exception& e) {
						return { EXIT_FAILURE, e.what() };
					}
				}
				if (m_seconds_behind_master == nullptr || m_seconds_behind_master.is_null()) {
					seconds_behind_master = nullptr;
				} else {
					try {
						int* repl_lag = new int(server_state["seconds_behind_master"]);
						seconds_behind_master = std::unique_ptr<int>(repl_lag);
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
				hostname,
				port,
				std::move(seconds_behind_master)
			)
		);
	}

	// fill the output parameter
	out_server_states = std::move(res_states);

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> get_current_replicationlag_servers_state(
	MYSQL* proxysql_admin,
	std::vector<replicationlag_server_state>& out_cur_replicationlag_servers_state
) {
	std::pair<int, std::string> err_res {};
	std::string t_err_msg { "'get_current_replicationlag_servers_state' failed with error: '%s'" };
	std::string err_msg {};

	int q_res = mysql_query(
		proxysql_admin,
		"SELECT hostname, port, seconds_behind_master FROM REPLICATIONLAG_HOST_STATUS"
	);

	if (q_res == 0) {
		ordered_json j_servers {};
		j_servers["cluster_type"] = "replicationlag";
		j_servers["replicationlag_servers_init_state"] = {};

		MYSQL_RES* my_servers_res = mysql_store_result(proxysql_admin);
		parse_result_to_json(my_servers_res, j_servers["replicationlag_servers_init_state"]);

		// convert the fields into the proper types
		for (ordered_json& j_server : j_servers["replicationlag_servers_init_state"]) {
			j_server["hostname"] = atoi(std::string {j_server["hostname"]}.c_str());
			j_server["port"] = atoi(std::string {j_server["port"]}.c_str());

			const auto& seconds_behind_master = j_server.at("seconds_behind_master");
			if (seconds_behind_master == nullptr || seconds_behind_master.is_null()) {
				j_server["seconds_behind_master"] = nullptr;	
			} else {
				j_server["seconds_behind_master"] = atoi(std::string {j_server["seconds_behind_master"]}.c_str());
			}
			j_server["comment"] = atoi(std::string {j_server["comment"]}.c_str());
		}

		std::vector<replicationlag_server_state> cur_replicationlag_servers_state {};
		std::pair<int, std::string> ext_res =
			extract_replicationlag_servers_state(
				replicationlag_state_id::init_state, j_servers, cur_replicationlag_servers_state
			);

		if (ext_res.first == EXIT_SUCCESS) {
			out_cur_replicationlag_servers_state = std::move(cur_replicationlag_servers_state);
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

const std::string t_replicationlag_server_state_insert {
	"INSERT OR REPLACE INTO REPLICATIONLAG_HOST_STATUS("
		" hostname,"
		" port,"
		" seconds_behind_master"
		") VALUES ("
			"'%s', %d, %s"
		")"
};

std::pair<int, std::string> prepare_replicationlag_cluster_state(
	MYSQL* proxysql_sqlite,
	const std::vector<replicationlag_server_state>& servers,
	bool cleanup
) {
	int query_error = 0;

	if (cleanup) {
		// Cleanup the current servers from 'REPLICATIONLAG_HOST_STATUS'
		// and insert the ones for testing the cluster
		const std::string cleanup_query { "DELETE FROM REPLICATIONLAG_HOST_STATUS" };
		query_error = mysql_query(proxysql_sqlite, cleanup_query.c_str());
		if (query_error) {
			return create_query_error(proxysql_sqlite, cleanup_query, __FILE__, __LINE__);
		}
	}

	usleep(1000 * 1000);

	for (const auto& server : servers) {
		std::string server_insert_query {};

		string_format(
			t_replicationlag_server_state_insert,
			server_insert_query,
			std::get<0>(server).c_str(),
			std::get<1>(server),
			std::get<2>(server) == nullptr ? "null" : std::to_string(*std::get<2>(server)).c_str() 
		);

		query_error = mysql_query(proxysql_sqlite, server_insert_query.c_str());
		if (query_error) {
			return create_query_error(proxysql_sqlite, server_insert_query, __FILE__, __LINE__);
		}
	}

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> set_replicationlag_monitor_check_times(MYSQL* proxysql_admin) {
	if (proxysql_admin == nullptr ) { return  { EXIT_FAILURE, "Supplied MYSQL handle is 'NULL'" }; }

	int query_error = 0;

	const std::string set_hcheck_query { "SET mysql-monitor_replication_lag_interval=200" };
	query_error = mysql_query(proxysql_admin, set_hcheck_query.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, set_hcheck_query, __FILE__, __LINE__);
	}

	const std::string set_hcheck_to_query { "SET mysql-monitor_replication_lag_timeout=100" };
	query_error = mysql_query(proxysql_admin, set_hcheck_to_query.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, set_hcheck_to_query, __FILE__, __LINE__);
	}

	const std::string load_to_runtime_query { "LOAD MYSQL VARIABLES TO RUNTIME" };
	query_error = mysql_query(proxysql_admin, load_to_runtime_query.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, load_to_runtime_query, __FILE__, __LINE__);
	}

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> get_replicationlag_monitor_check_times(
	MYSQL* proxysql_admin,
	int& out_healthcheck_interval,
	int& out_healthcheck_timeout
) {
	if (proxysql_admin == nullptr ) { return  { EXIT_FAILURE, "Supplied MYSQL handle is 'NULL'" }; }
	int query_error = 0;

	const std::string select_ro_interval_query {
		"SELECT variable_value FROM global_variables WHERE"
		" variable_name='mysql-monitor_replication_lag_interval'"
	};
	query_error = mysql_query(proxysql_admin, select_ro_interval_query.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, select_ro_interval_query, __FILE__, __LINE__);
	}

	MYSQL_RES* my_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW my_row = mysql_fetch_row(my_res);
	int healthcheck_interval = atoi(my_row[0]);
	mysql_free_result(my_res);

	const std::string select_ro_timeout_query {
		"SELECT variable_value FROM global_variables WHERE"
		" variable_name='mysql-monitor_replication_lag_timeout'"
	};
	query_error = mysql_query(proxysql_admin, select_ro_timeout_query.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, select_ro_timeout_query, __FILE__, __LINE__);
	}

	my_res = mysql_store_result(proxysql_admin);
	my_row = mysql_fetch_row(my_res);
	int healthcheck_timeout = atoi(my_row[0]);
	mysql_free_result(my_res);

	// fill the output parameters
	out_healthcheck_interval = healthcheck_interval;
	out_healthcheck_timeout = healthcheck_timeout;

	return { EXIT_SUCCESS, "" };
}

std::vector<replicationlag_server_state> sort_replicationlag_server_state(
	const std::vector<replicationlag_server_state>& replicationlag_servers_state
) {
	std::vector<replicationlag_server_state> c_replicationlag_servers_state { replicationlag_servers_state };

	const auto replicationlag_server_state_comparator = [] (
		const replicationlag_server_state& srv_st1,
		const replicationlag_server_state& srv_st2
	) -> bool {
		const std::string srv_st1_id {
			std::get<0>(srv_st1) +
			std::to_string(std::get<1>(srv_st1))
		};
		const std::string srv_st2_id {
			std::get<0>(srv_st2) +
			std::to_string(std::get<1>(srv_st2))
		};

		return srv_st1_id > srv_st2_id;
	};

	std::sort(
		c_replicationlag_servers_state.begin(),
		c_replicationlag_servers_state.end(),
		replicationlag_server_state_comparator
	);

	return c_replicationlag_servers_state;
}

std::vector<std::pair<column_id, std::string>> replicationlag_state_members_diff(
	const replicationlag_server_state& st1,
	const replicationlag_server_state& st2
) {
	std::vector<std::pair<column_id, std::string>> result {};

	// hostname and port **can't** be changed, because the are part of
	// the server 'id'. Only the other fields are allowed to change,
	// otherwise, the verification step should have failed.

	const std::shared_ptr<int>& st1_replicationlag = std::get<2>(st1);
	const std::shared_ptr<int>& st2_replicationlag = std::get<2>(st2);

	if (st1_replicationlag != nullptr && st2_replicationlag != nullptr) {
		if ( *st1_replicationlag != *st2_replicationlag) {
			result.push_back({ "seconds_behind_master", std::to_string(*st2_replicationlag) });
		}
	} else {
		if (st1_replicationlag == nullptr && st2_replicationlag != nullptr) {
			result.push_back({ "seconds_behind_master", "null" });
		} 
	}
	return result;
}

cluster_state_changes replicationlag_servers_state_diff(
	const std::vector<replicationlag_server_state>& servers_state_p,
	const std::vector<replicationlag_server_state>& servers_state_n
) {
	cluster_state_changes result {};

	std::vector<replicationlag_server_state> s_servers_state_p
		= sort_replicationlag_server_state(servers_state_p);
	std::vector<replicationlag_server_state> s_servers_state_n
		= sort_replicationlag_server_state(servers_state_n);

	// find the differences
	for (const auto& server_state_n : s_servers_state_n) {
		for (const auto& server_state_p : s_servers_state_p) {
			const std::string n_server_state_id {
				std::get<0>(server_state_n) + ":" +
				std::to_string(std::get<1>(server_state_n))
			};
			const std::string p_server_state_id {
				std::get<0>(server_state_p) + ":" +
				std::to_string(std::get<1>(server_state_p))
			};

			bool diff_server_status =
				( n_server_state_id == p_server_state_id ) &&
				( server_state_n != server_state_p );

			if (diff_server_status) {
				const auto server_state_diff =
					replicationlag_state_members_diff(server_state_p, server_state_n);
				result.insert({ n_server_state_id, server_state_diff });
			}
		}
	}

	return result;
}

replicationlag_server_state replicationlag_update_state(
	const replicationlag_server_state& st1,
	const replicationlag_server_state& st2
) {
	replicationlag_server_state result {};

	// hostname and port **can't** be changed,
	// because the are part of the server 'id'. Only the
	// other fields are allowed to change, otherwise, the
	// verification step should have failed.

	const std::shared_ptr<int>& st1_replicationlag = std::get<2>(st1);
	const std::shared_ptr<int>& st2_replicationlag = std::get<2>(st2);

	if (st1_replicationlag != nullptr && st2_replicationlag != nullptr) {
		if (st1_replicationlag != st2_replicationlag) {
			std::get<2>(result) = st2_replicationlag;
		}
	} else {
		std::get<2>(result) = st2_replicationlag;
	}

	return result;
}

std::vector<replicationlag_server_state> replicationlag_update_cluster_state(
	const std::vector<replicationlag_server_state>& servers_state_p,
	const std::vector<replicationlag_server_state>& servers_state_n
) {
	std::vector<replicationlag_server_state> result {};

	std::vector<replicationlag_server_state> s_servers_state_p
		= sort_replicationlag_server_state(servers_state_p);
	std::vector<replicationlag_server_state> s_servers_state_n
		= sort_replicationlag_server_state(servers_state_n);

	// find the differences
	for (const auto& server_state_n : s_servers_state_n) {
		for (const auto& server_state_p : s_servers_state_p) {
			const std::string n_server_state_id {
				std::get<0>(server_state_n) + ":" +
				std::to_string(std::get<1>(server_state_n))
			};
			const std::string p_server_state_id {
				std::get<0>(server_state_p) + ":" +
				std::to_string(std::get<1>(server_state_p))
			};

			bool diff_server_status =
				( n_server_state_id == p_server_state_id ) &&
				( server_state_n != server_state_p );

			if (diff_server_status) {
				const replicationlag_server_state server_state_update =
					replicationlag_update_state(server_state_p, server_state_n);
				result.push_back(server_state_update);
			}
		}
	}

	return result;
}
