#include "readonly_utils.h"

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

const std::vector<std::string> valid_replication_hostgroup_entries {
	"writer_hostgroup",
	"reader_hostgroup",
	"check_type",
	"comment",
};

const std::string t_replication_hosgroup_insert {
	"INSERT INTO mysql_replication_hostgroups ("
		" writer_hostgroup,"
		" reader_hostgroup,"
		" check_type,"
		" comment"
	") VALUES ("
		" %d, %d, '%s', '%s'"
	")"
};

std::pair<int,std::string> extract_replication_hostgroup_config(
	const json& replication_test_def,
	std::vector<replication_hostgroup_config>& out_hostgroups_configs
) {
	// result
	std::vector<replication_hostgroup_config> res_hostgroup_configs {};

	if (!replication_test_def.is_object()) {
		return {
			EXIT_FAILURE,
			"Invalid input. Expected 'test_definition' should be a JSON object.",
		};
	}

	const auto& j_replication_hostgroups =
		replication_test_def["mysql_replication_hostgroups"];
	if (j_replication_hostgroups == nullptr) {
		return {
			EXIT_FAILURE,
			"Invalid input. Unable to find required field 'mysql_replication_hostgroups'",
		};
	}
	if (!j_replication_hostgroups.is_array()) {
		return {
			EXIT_FAILURE,
			"Invalid input. 'mysql_replication_hostgroups' isn't of expected type 'array'"
		};
	}

	for (const auto& j_replication_hostgroup : j_replication_hostgroups) {
		// *********************** CHECK FOR INVALID KEYS ******************* //

		std::vector<std::string> invalid_keys {
			get_invalid_keys(valid_replication_hostgroup_entries, j_replication_hostgroup)
		};

		if (!invalid_keys.empty()) {
			return gen_invalid_keys_err(invalid_keys, "mysql_replication_hostgroups");
		}

		// ****************************************************************** //

		int writer_hostgroup = 0;
		int reader_hostgroup = 0;
		std::string check_type {};
		std::string comment {};
		json j_comment {};

		try {
			writer_hostgroup =
				j_replication_hostgroup.at("writer_hostgroup");
			reader_hostgroup =
				j_replication_hostgroup.at("reader_hostgroup");
			check_type =
				j_replication_hostgroup.at("check_type");
			j_comment =
				j_replication_hostgroup.at("comment");
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}

		if (j_comment == nullptr) {
			comment = "NULL";
		} else {
			try {
				comment = j_replication_hostgroup.at("comment");
			} catch (const std::exception& e) {
				return { EXIT_FAILURE, e.what() };
			}
		}

		res_hostgroup_configs.push_back(
			std::make_tuple(
				writer_hostgroup,
				reader_hostgroup,
				check_type,
				comment
			)
		);
	}

	// fill the output parameter with the result
	out_hostgroups_configs = res_hostgroup_configs;

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> get_current_mysql_replication_hostgroups(
	MYSQL* proxysql_admin,
	std::vector<replication_hostgroup_config>& out_cur_replication_hostgroups
) {
	std::pair<int, std::string> err_res {};
	std::string t_err_msg { "'get_current_mysql_replication_hostgroups' failed with error: '%s'" };
	std::string err_msg {};

	int q_res = mysql_query(
		proxysql_admin,
		"SELECT writer_hostgroup, reader_hostgroup, check_type, comment"
		" FROM mysql_replication_hostgroups"
	);

	if (q_res == 0) {
		ordered_json j_servers {};
		j_servers["mysql_replication_hostgroups"] = {};

		MYSQL_RES* my_servers_res = mysql_store_result(proxysql_admin);
		parse_result_to_json(my_servers_res, j_servers["mysql_replication_hostgroups"]);

		// convert the fields into the proper types
		for (ordered_json& j_server : j_servers["mysql_replication_hostgroups"]) {
			j_server["writer_hostgroup"] =
				 atoi(std::string {j_server["writer_hostgroup"]}.c_str());
			j_server["reader_hostgroup"] =
				 atoi(std::string {j_server["reader_hostgroup"]}.c_str());
			j_server["check_type"] =
				 atoi(std::string {j_server["check_type"]}.c_str());
			j_server["comment"] = std::string {j_server["comment"]};
		}

		std::vector<replication_hostgroup_config> cur_replication_hostgroups {};
		std::pair<int, std::string> ext_res =
			extract_replication_hostgroup_config(j_servers, cur_replication_hostgroups);

		if (ext_res.first == EXIT_SUCCESS) {
			out_cur_replication_hostgroups = cur_replication_hostgroups;
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

const std::vector<std::string> valid_readonly_entries {
	"hostname",
	"port",
	"read_only",
};

std::pair<int,std::string> extract_readonly_servers_state(
	const readonly_state_id& state_id,
	const json& readonly_test_def,
	std::vector<readonly_server_state>& out_server_states
) {
	// result
	std::vector<readonly_server_state> res_states {};

	// perform basic payload checks
	bool has_cluster_type =
		check_present_and_type(readonly_test_def, {"cluster_type"}, json::value_t::string);
	if (!has_cluster_type || std::string { readonly_test_def["cluster_type"] } != "READ_ONLY") {
		return { EXIT_FAILURE, "Unable to find required field \"cluster_type\"'" };
	}

	json j_servers_state {};

	if (state_id == readonly_state_id::init_state) {
		try {
			j_servers_state = readonly_test_def.at("readonly_servers_init_state");
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}
	} else {
		try {
			j_servers_state = readonly_test_def.at("readonly_servers_new_state");
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}
	}

	if (!j_servers_state.is_array()) {
		return { EXIT_FAILURE, "'readonly_j_servers_state' isn't of expected type 'array'" };
	}

	for (const auto& server_state : j_servers_state) {
		// *********************** CHECK FOR INVALID KEYS ******************* //

		// check that the keys only match the expected ones, non-expected keys
		// are not allowed this is to avoid typos in cluster config.

		std::vector<std::string> invalid_keys {
			get_invalid_keys(valid_readonly_entries, server_state)
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

			if (state_id == readonly_state_id::init_state) {
				string_format(t_err_msg, err_msg, "readonly_servers_init_state", invalid_keys_str.c_str());
				return { EXIT_FAILURE, err_msg };
			} else {
				string_format(t_err_msg, err_msg, "readonly_servers_new_state", invalid_keys_str.c_str());
				return { EXIT_FAILURE, err_msg };
			}
		}

		// ****************************************************************** //

		std::string hostname {};
		int port;
		int read_only;

		if (state_id == readonly_state_id::init_state) {
			// try to extract all the expected fields
			try {
				hostname = server_state.at("hostname");
				port = server_state.at("port");
				read_only = server_state.at("read_only");
			} catch (const std::exception& e) {
				return { EXIT_FAILURE, e.what() };
			}
		} else {
			try {
				const auto& m_hostname = server_state.at("hostname");
				const auto& m_port = server_state.at("port");
				const auto& m_read_only = server_state.at("read_only");

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
				if (m_read_only == nullptr) {
					read_only = -1;
				} else {
					try {
						read_only = server_state["read_only"];
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
				read_only
			)
		);
	}

	// fill the output parameter
	out_server_states = res_states;

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> get_current_readonly_servers_state(
	MYSQL* proxysql_admin,
	std::vector<readonly_server_state>& out_cur_readonly_servers_state
) {
	std::pair<int, std::string> err_res {};
	std::string t_err_msg { "'get_current_readonly_servers_state' failed with error: '%s'" };
	std::string err_msg {};

	int q_res = mysql_query(
		proxysql_admin,
		"SELECT hostname, port, read_only FROM READONLY_STATUS"
	);

	if (q_res == 0) {
		ordered_json j_servers {};
		j_servers["cluster_type"] = "readonly";
		j_servers["readonly_servers_init_state"] = {};

		MYSQL_RES* my_servers_res = mysql_store_result(proxysql_admin);
		parse_result_to_json(my_servers_res, j_servers["readonly_servers_init_state"]);

		// convert the fields into the proper types
		for (ordered_json& j_server : j_servers["readonly_servers_init_state"]) {
			j_server["hostname"] = atoi(std::string {j_server["hostname"]}.c_str());
			j_server["port"] = atoi(std::string {j_server["port"]}.c_str());
			j_server["read_only"] = atoi(std::string {j_server["read_only"]}.c_str());
			j_server["comment"] = atoi(std::string {j_server["commetn"]}.c_str());
		}

		std::vector<readonly_server_state> cur_readonly_servers_state {};
		std::pair<int, std::string> ext_res =
			extract_readonly_servers_state(readonly_state_id::init_state, j_servers, cur_readonly_servers_state);

		if (ext_res.first == EXIT_SUCCESS) {
			out_cur_readonly_servers_state = cur_readonly_servers_state;
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

std::pair<int, std::string> prepare_mysql_replication_hostgroups(
	MYSQL* proxysql_admin,
	const std::vector<replication_hostgroup_config>& hostgroups_configs
) {
	int query_error = 0;

	const std::string hostgroups_cleanup { "DELETE FROM mysql_replication_hostgroups" };
	query_error = mysql_query(proxysql_admin, hostgroups_cleanup.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, hostgroups_cleanup, __FILE__, __LINE__);
	}

	for (const auto& hostgroup_config : hostgroups_configs) {
		std::string replication_hostgroup_insert {};

		// NOTE: Comment can't be null, no need of special handling
		string_format(
			t_replication_hosgroup_insert,
			replication_hostgroup_insert,
			std::get<0>(hostgroup_config),
			std::get<1>(hostgroup_config),
			std::get<2>(hostgroup_config).c_str(),
			std::get<3>(hostgroup_config).c_str()
		);

		query_error = mysql_query(proxysql_admin, replication_hostgroup_insert.c_str());
		if (query_error) {
			return create_query_error(proxysql_admin, replication_hostgroup_insert, __FILE__, __LINE__);
		}
	}

	return { EXIT_SUCCESS, "" };
}

const std::string t_readonly_server_state_insert {
	"INSERT OR REPLACE INTO READONLY_STATUS("
		" hostname,"
		" port,"
		" read_only"
		") VALUES ("
			"'%s', %d, %d"
		")"
};

std::pair<int, std::string> prepare_readonly_cluster_state(
	MYSQL* proxysql_sqlite,
	const std::vector<readonly_server_state>& servers,
	bool cleanup
) {
	int query_error = 0;

	if (cleanup) {
		// Cleanup the current servers from 'READONLY_STATUS'
		// and insert the ones for testing the cluster
		const std::string cleanup_query { "DELETE FROM READONLY_STATUS" };
		query_error = mysql_query(proxysql_sqlite, cleanup_query.c_str());
		if (query_error) {
			return create_query_error(proxysql_sqlite, cleanup_query, __FILE__, __LINE__);
		}
	}

	usleep(1000 * 1000);

	for (const auto& server : servers) {
		std::string server_insert_query {};

		string_format(
			t_readonly_server_state_insert,
			server_insert_query,
			std::get<0>(server).c_str(),
			std::get<1>(server),
			std::get<2>(server)
		);

		query_error = mysql_query(proxysql_sqlite, server_insert_query.c_str());
		if (query_error) {
			return create_query_error(proxysql_sqlite, server_insert_query, __FILE__, __LINE__);
		}
	}

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> set_readonly_monitor_check_times(MYSQL* proxysql_admin) {
	if (proxysql_admin == nullptr ) { return  { EXIT_FAILURE, "Supplied MYSQL handle is 'NULL'" }; }

	int query_error = 0;

	const std::string set_hcheck_query { "SET mysql-monitor_read_only_interval=200" };
	query_error = mysql_query(proxysql_admin, set_hcheck_query.c_str());
	if (query_error) {
		return create_query_error(proxysql_admin, set_hcheck_query, __FILE__, __LINE__);
	}

	const std::string set_hcheck_to_query { "SET mysql-monitor_read_only_timeout=100" };
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

std::pair<int, std::string> get_readonly_monitor_check_times(
	MYSQL* proxysql_admin,
	int& out_healthcheck_interval,
	int& out_healthcheck_timeout
) {
	if (proxysql_admin == nullptr ) { return  { EXIT_FAILURE, "Supplied MYSQL handle is 'NULL'" }; }
	int query_error = 0;

	const std::string select_ro_interval_query {
		"SELECT variable_value FROM global_variables WHERE"
		" variable_name='mysql-monitor_read_only_interval'"
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
		" variable_name='mysql-monitor_read_only_timeout'"
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

std::vector<readonly_server_state> sort_readonly_server_state(
	const std::vector<readonly_server_state>& readonly_servers_state
) {
	std::vector<readonly_server_state> c_readonly_servers_state { readonly_servers_state };

	const auto readonly_server_state_comparator = [] (
		const readonly_server_state& srv_st1,
		const readonly_server_state& srv_st2
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
		c_readonly_servers_state.begin(),
		c_readonly_servers_state.end(),
		readonly_server_state_comparator
	);

	return c_readonly_servers_state;
}

std::vector<std::pair<column_id, std::string>> readonly_state_members_diff(
	const readonly_server_state& st1,
	const readonly_server_state& st2
) {
	std::vector<std::pair<column_id, std::string>> result {};

	// hostname and port **can't** be changed, because the are part of
	// the server 'id'. Only the other fields are allowed to change,
	// otherwise, the verification step should have failed.

	int st1_read_only = std::get<2>(st1);
	int st2_read_only = std::get<2>(st2);

	if (st2_read_only != -1 && st1_read_only != st2_read_only) {
		result.push_back({ "read_only", std::to_string(st2_read_only) });
	}

	return result;
}

cluster_state_changes readonly_servers_state_diff(
	const std::vector<readonly_server_state>& servers_state_p,
	const std::vector<readonly_server_state>& servers_state_n
) {
	cluster_state_changes result {};

	std::vector<readonly_server_state> s_servers_state_p
		= sort_readonly_server_state(servers_state_p);
	std::vector<readonly_server_state> s_servers_state_n
		= sort_readonly_server_state(servers_state_n);

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
					readonly_state_members_diff(server_state_p, server_state_n);
				result.insert({ n_server_state_id, server_state_diff });
			}
		}
	}

	return result;
}

readonly_server_state readonly_update_state(
	const readonly_server_state& st1,
	const readonly_server_state& st2
) {
	readonly_server_state result {};

	// hostname and port **can't** be changed,
	// because the are part of the server 'id'. Only the
	// other fields are allowed to change, otherwise, the
	// verification step should have failed.

	int st1_read_only = std::get<2>(st1);
	int st2_read_only = std::get<2>(st2);

	if (st2_read_only != -1 && st1_read_only != st2_read_only) {
		std::get<2>(result) = st2_read_only;
	}

	return result;
}

std::vector<readonly_server_state> readonly_update_cluster_state(
	const std::vector<readonly_server_state>& servers_state_p,
	const std::vector<readonly_server_state>& servers_state_n
) {
	std::vector<readonly_server_state> result {};

	std::vector<readonly_server_state> s_servers_state_p
		= sort_readonly_server_state(servers_state_p);
	std::vector<readonly_server_state> s_servers_state_n
		= sort_readonly_server_state(servers_state_n);

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
				const readonly_server_state server_state_update =
					readonly_update_state(server_state_p, server_state_n);
				result.push_back(server_state_update);
			}
		}
	}

	return result;
}
