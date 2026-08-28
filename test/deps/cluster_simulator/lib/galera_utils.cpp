#include "galera_utils.h"

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

////////////////////////////////////////////////////////////////////////////////
//                              GALERA UTILS                                  //
////////////////////////////////////////////////////////////////////////////////

const std::vector<std::string> valid_galera_hostgroup_entries {
	"writer_hostgroup",
	"backup_writer_hostgroup",
	"reader_hostgroup",
	"offline_hostgroup",
	"active",
	"max_writers",
	"writer_is_also_reader",
	"max_transactions_behind",
	"comment",
};

std::pair<int,std::string> extract_galera_hostgroup_config(
	const json& galera_test_def,
	std::vector<galera_hostgroup_config>& out_hostgroups_configs
) {
	// result
	std::vector<galera_hostgroup_config> res_hostgroup_configs {};

	// perform basic payload checks
	if (!galera_test_def.is_object()) {
		return { EXIT_FAILURE, "Invalid input. Expected 'test_definition' should be a JSON object." };
	}
	const auto& j_galera_hostgroups = galera_test_def["mysql_galera_hostgroups"];
	if (j_galera_hostgroups == nullptr) {
		return { EXIT_FAILURE, "Invalid input. Unable to find required field 'mysql_galera_hostgroups'" };
	}
	if (!j_galera_hostgroups.is_array()) {
		return { EXIT_FAILURE, "Invalid input. 'mysql_galera_hostgroups' isn't of expected type 'array'" };
	}

	for (const auto& j_galera_hostgroup : j_galera_hostgroups) {
		// *********************** CHECK FOR INVALID KEYS ******************* //

		std::vector<std::string> invalid_keys {
			get_invalid_keys(valid_galera_hostgroup_entries, j_galera_hostgroup)
		};

		if (!invalid_keys.empty()) {
			return gen_invalid_keys_err(invalid_keys, "mysql_galera_hostgroups");
		}

		// ****************************************************************** //

		int writer_hostgroup;
		int backup_writer_hostgroup;
		int reader_hostgroup;
		int offline_hostgroup;
		int active;
		int max_writers;
		int writer_is_also_reader;
		int max_transactions_behind;
		std::string comment {};
		json j_comment {};

		try {
			writer_hostgroup = j_galera_hostgroup.at("writer_hostgroup");
			backup_writer_hostgroup = j_galera_hostgroup.at("backup_writer_hostgroup");
			reader_hostgroup = j_galera_hostgroup.at("reader_hostgroup");
			offline_hostgroup = j_galera_hostgroup.at("offline_hostgroup");
			active = j_galera_hostgroup.at("active");
			max_writers = j_galera_hostgroup.at("max_writers");
			writer_is_also_reader = j_galera_hostgroup.at("writer_is_also_reader");
			max_transactions_behind = j_galera_hostgroup.at("max_transactions_behind");
			j_comment = j_galera_hostgroup.at("comment");
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}

		if (j_comment == nullptr) {
			comment = "NULL";
		} else {
			try {
				comment = j_galera_hostgroup.at("comment");
			} catch (const std::exception& e) {
				return { EXIT_FAILURE, e.what() };
			}
		}

		res_hostgroup_configs.push_back(
			std::make_tuple(
				writer_hostgroup,
				backup_writer_hostgroup,
				reader_hostgroup,
				offline_hostgroup,
				active,
				max_writers,
				writer_is_also_reader,
				max_transactions_behind,
				comment
			)
		);
	}

	// fill the output parameter with the result
	out_hostgroups_configs = res_hostgroup_configs;

	return { EXIT_SUCCESS, "" };
}

const std::string t_galera_hosgroup_insert {
	"INSERT INTO mysql_galera_hostgroups ("
		" writer_hostgroup,"
		" backup_writer_hostgroup,"
		" reader_hostgroup,"
		" offline_hostgroup,"
		" active,"
		" max_writers,"
		" writer_is_also_reader,"
		" max_transactions_behind,"
		" comment"
	") VALUES ("
		" %d, %d, %d, %d, %d, %d, %d, %d, %s"
	")"
};

std::pair<int, std::string> prepare_mysql_galera_hostgroups(
	MYSQL* proxysql_admin,
	const std::vector<galera_hostgroup_config>& hostgroups_configs
) {
	int query_error = 0;

	const std::string hostgroups_cleanup { "DELETE FROM mysql_galera_hostgroups" };
	query_error = mysql_query(proxysql_admin, hostgroups_cleanup.c_str());
	if (query_error) { return create_query_error(proxysql_admin, hostgroups_cleanup, __FILE__, __LINE__); }

	for (const auto& hostgroup_config : hostgroups_configs) {
		std::string galera_hostgroup_insert {};

		// NOTE: Comment can't be null, no need of special handling
		string_format(
			t_galera_hosgroup_insert,
			galera_hostgroup_insert,
			std::get<0>(hostgroup_config),
			std::get<1>(hostgroup_config),
			std::get<2>(hostgroup_config),
			std::get<3>(hostgroup_config),
			std::get<4>(hostgroup_config),
			std::get<5>(hostgroup_config),
			std::get<6>(hostgroup_config),
			std::get<7>(hostgroup_config),
			std::get<8>(hostgroup_config).c_str()
		);

		query_error = mysql_query(proxysql_admin, galera_hostgroup_insert.c_str());
		if (query_error) { return create_query_error(proxysql_admin, galera_hostgroup_insert, __FILE__, __LINE__); }
	}

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> get_current_mysql_galera_hostgroups(
	MYSQL* proxysql_admin,
	std::vector<galera_hostgroup_config>& out_cur_galera_hostgroups
) {
	std::pair<int, std::string> err_res {};
	std::string t_err_msg { "'get_current_mysql_galera_hostgroups' failed with error: '%s'" };
	std::string err_msg {};

	int q_res = mysql_query(
		proxysql_admin,
		"SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, "
		"max_writers, writer_is_also_reader, max_transactions_behind, comment FROM mysql_galera_hostgroups"
	);

	if (q_res == 0) {
		ordered_json j_servers {};
		j_servers["mysql_galera_hostgroups"] = {};

		MYSQL_RES* my_servers_res = mysql_store_result(proxysql_admin);
		parse_result_to_json(my_servers_res, j_servers["mysql_galera_hostgroups"]);

		// convert the fields into the proper types
		for (ordered_json& j_server : j_servers["mysql_galera_hostgroups"]) {
			j_server["writer_hostgroup"] =
				 atoi(std::string {j_server["writer_hostgroup"]}.c_str());
			j_server["backup_writer_hostgroup"] =
				 atoi(std::string {j_server["backup_writer_hostgroup"]}.c_str());
			j_server["reader_hostgroup"] =
				 atoi(std::string {j_server["reader_hostgroup"]}.c_str());
			j_server["offline_hostgroup"] =
				 atoi(std::string {j_server["offline_hostgroup"]}.c_str());
			j_server["active"] =
				 atoi(std::string {j_server["active"]}.c_str());
			j_server["max_writers"] =
				 atoi(std::string {j_server["max_writers"]}.c_str());
			j_server["writer_is_also_reader"] =
				 atoi(std::string {j_server["writer_is_also_reader"]}.c_str());
			j_server["max_transactions_behind"] =
				 atoi(std::string {j_server["max_transactions_behind"]}.c_str());
		}

		std::vector<galera_hostgroup_config> cur_galera_hostgroups {};
		std::pair<int, std::string> ext_res =
			extract_galera_hostgroup_config(j_servers, cur_galera_hostgroups);

		if (ext_res.first == EXIT_SUCCESS) {
			out_cur_galera_hostgroups = cur_galera_hostgroups;
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

bool compare_mysql_galera_hostgroups(
	const std::vector<galera_hostgroup_config>& galera_hostgroups_1,
	const std::vector<galera_hostgroup_config>& galera_hostgroups_2
) {
	std::vector<galera_hostgroup_config> c_galera_hostgroups_1 { galera_hostgroups_1 };
	std::vector<galera_hostgroup_config> c_galera_hostgroups_2 { galera_hostgroups_2 };

	const auto hostgroup_comparator = [] (
		const galera_hostgroup_config& srv_st1,
		const galera_hostgroup_config& srv_st2
	) -> bool {
		const std::string srv_st1_id {
			std::to_string(std::get<0>(srv_st1)) +
			std::to_string(std::get<1>(srv_st1)) +
			std::to_string(std::get<2>(srv_st1)) + 
			std::to_string(std::get<3>(srv_st1))
		};
		const std::string srv_st2_id {
			std::to_string(std::get<0>(srv_st2)) +
			std::to_string(std::get<1>(srv_st2)) +
			std::to_string(std::get<2>(srv_st2)) + 
			std::to_string(std::get<3>(srv_st2))
		};

		return srv_st1_id > srv_st2_id;
	};

	std::sort(
		c_galera_hostgroups_1.begin(),
		c_galera_hostgroups_1.end(),
		hostgroup_comparator
	);

	std::sort(
		c_galera_hostgroups_2.begin(),
		c_galera_hostgroups_2.end(),
		hostgroup_comparator
	);

	return c_galera_hostgroups_1 == c_galera_hostgroups_2;
}

const std::string t_galera_server_state_insert {
	"INSERT OR REPLACE INTO HOST_STATUS_GALERA("
		" hostgroup_id,"
		" hostname,"
		" port,"
		" wsrep_local_state,"
		" read_only,"
		" wsrep_local_recv_queue,"
		" wsrep_desync,"
		" wsrep_reject_queries,"
		" wsrep_sst_donor_rejects_queries,"
		" wsrep_cluster_status,"
		" pxc_maint_mode"
		") VALUES ("
			"%d, '%s', %d, %d, %d, %d, %d, '%s', %d, '%s', '%s'"
		")"
};

std::pair<int, std::string> prepare_galera_cluster_state(
	MYSQL* proxysql_sqlite,
	const std::vector<galera_server_state>& servers,
	bool cleanup
) {
	int query_error = 0;

	if (cleanup) {
		std::string srv_hostnames {};
		std::string srv_ports {};

		for (const auto& server : servers) {
			srv_hostnames += "'" + std::get<1>(server) + "'";
			srv_ports += std::to_string(std::get<2>(server));

			if (&server != &servers.back()) {
				srv_hostnames += ",";
				srv_ports += ",";
			}
		}

		std::string cleanup_query {
			"DELETE FROM HOST_STATUS_GALERA WHERE hostname NOT IN (" +
				srv_hostnames + ") AND port NOT IN (" + srv_ports + ")"
		};

		// Cleanup the current servers from 'HOST_STATUS_GALERA' and insert the ones for testing the cluster
		query_error = mysql_query(proxysql_sqlite, cleanup_query.c_str());
		if (query_error) { return create_query_error(proxysql_sqlite, cleanup_query, __FILE__, __LINE__); }
	}

	usleep(1000 * 1000);

	// NOTE: We adquire a 'write lock' so there are no dirty reads on ProxySQL side
	// while we write the new values.
	query_error = mysql_query(proxysql_sqlite, "BEGIN IMMEDIATE");
	if (query_error) {
		return create_query_error(proxysql_sqlite, "BEGIN IMMEDIATE", __FILE__, __LINE__);
	}

	for (const auto& server : servers) {
		std::string server_insert_query {};

		string_format(
			t_galera_server_state_insert,
			server_insert_query,
			std::get<0>(server),
			std::get<1>(server).c_str(),
			std::get<2>(server),
			std::get<3>(server),
			std::get<4>(server),
			std::get<5>(server),
			std::get<6>(server),
			std::get<7>(server).c_str(),
			std::get<8>(server),
			std::get<9>(server).c_str(),
			std::get<10>(server).c_str()
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

const std::vector<std::string> valid_galera_entries {
	"hostgroup_id",
	"hostname",
	"port",
	"wsrep_local_state",
	"read_only",
	"wsrep_local_recv_queue",
	"wsrep_desync",
	"wsrep_reject_queries",
	"wsrep_sst_donor_rejects_queries",
	"wsrep_cluster_status",
	"pxc_maint_mode",
};

std::pair<int,std::string> extract_galera_servers_state(
	const galera_state_id& state_id,
	const json& galera_test_def,
	std::vector<galera_server_state>& out_server_states
) {
	// result
	std::vector<galera_server_state> res_states {};

	// perform basic payload checks
	bool has_cluster_type =
		check_present_and_type(galera_test_def, {"cluster_type"}, json::value_t::string);
	if (!has_cluster_type || std::string { galera_test_def["cluster_type"] } != "GALERA") {
		return { EXIT_FAILURE, "Unable to find required field 'cluster_type'" };
	}

	json j_servers_state {};

	if (state_id == galera_state_id::init_state) {
		try {
			j_servers_state = galera_test_def.at("galera_servers_init_state");
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}
	} else {
		try {
			j_servers_state = galera_test_def.at("galera_servers_new_state");
		} catch (const std::exception& e) {
			return { EXIT_FAILURE, e.what() };
		}
	}

	if (!j_servers_state.is_array()) {
		return { EXIT_FAILURE, "'galera_j_servers_state' isn't of expected type 'array'" };
	}

	for (const auto& server_state : j_servers_state) {
		// *********************** CHECK FOR INVALID KEYS ******************* //

		// check that the keys only match the expected ones, non-expected keys
		// are not allowed this is to avoid typos in cluster config.

		std::vector<std::string> invalid_keys {
			get_invalid_keys(valid_galera_entries, server_state)
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

			if (state_id == galera_state_id::init_state) {
				string_format(t_err_msg, err_msg, "galera_servers_init_state", invalid_keys_str.c_str());
				return { EXIT_FAILURE, err_msg };
			} else {
				string_format(t_err_msg, err_msg, "galera_servers_new_state", invalid_keys_str.c_str());
				return { EXIT_FAILURE, err_msg };
			}
		}

		// ****************************************************************** //

		int hostgroup_id;
		std::string hostname {};
		int port;
		int wsrep_local_state;
		int read_only;
		int wsrep_local_recv_queue;
		int wsrep_desync;
		std::string wsrep_reject_queries {};
		int wsrep_sst_donor_rejects_queries;
		std::string wsrep_cluster_status {};
		std::string pxc_maint_mode {};

		if (state_id == galera_state_id::init_state) {
			// try to extract all the expected fields
			try {
				hostgroup_id = server_state.at("hostgroup_id");
				hostname = server_state.at("hostname");
				port = server_state.at("port");
				wsrep_local_state = server_state.at("wsrep_local_state");
				read_only = server_state.at("read_only");
				wsrep_local_recv_queue = server_state.at("wsrep_local_recv_queue");
				wsrep_desync = server_state.at("wsrep_desync");
				wsrep_reject_queries = server_state.at("wsrep_reject_queries");
				wsrep_sst_donor_rejects_queries = server_state.at("wsrep_sst_donor_rejects_queries");
				wsrep_cluster_status = server_state.at("wsrep_cluster_status");
				pxc_maint_mode = server_state.at("pxc_maint_mode");
			} catch (const std::exception& e) {
				return { EXIT_FAILURE, e.what() };
			}
		} else {
			try {
				const auto& m_hostgroup_id = server_state.at("hostgroup_id");
				const auto& m_hostname = server_state.at("hostname");
				const auto& m_port = server_state.at("port");
				const auto& m_wsrep_local_state = server_state.at("wsrep_local_state");
				const auto& m_read_only = server_state.at("read_only");
				const auto& m_wsrep_local_recv_queue = server_state.at("wsrep_local_recv_queue");
				const auto& m_wsrep_desync = server_state.at("wsrep_desync");
				const auto& m_wsrep_reject_queries = server_state.at("wsrep_reject_queries");
				const auto& m_wsrep_sst_donor_rejects_queries = server_state.at("wsrep_sst_donor_rejects_queries");
				const auto& m_wsrep_cluster_status = server_state.at("wsrep_cluster_status");
				const auto& m_pxc_maint_mode = server_state.at("pxc_maint_mode");

				if (m_hostgroup_id == nullptr) {
					hostgroup_id = -1;
				} else {
					try {
						hostgroup_id = server_state["hostgroup_id"];
					} catch (const std::exception& e) {
						return { EXIT_FAILURE, e.what() };
					}
				}
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
				if (m_wsrep_local_state == nullptr) {
					wsrep_local_state = -1;
				} else {
					try {
						wsrep_local_state = server_state["wsrep_local_state"];
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
				if (m_wsrep_local_recv_queue == nullptr) {
					wsrep_local_recv_queue = -1;
				} else {
					try {
						wsrep_local_recv_queue = server_state["wsrep_local_recv_queue"];
					} catch (const std::exception& e) {
						return { EXIT_FAILURE, e.what() };
					}
				}
				if (m_wsrep_desync == nullptr) {
					wsrep_desync = -1;
				} else {
					try {
						wsrep_desync = server_state["wsrep_desync"];
					} catch (const std::exception& e) {
						return { EXIT_FAILURE, e.what() };
					}
				}
				if (m_wsrep_reject_queries == nullptr) {
					wsrep_reject_queries = "nullptr";
				} else {
					try {
						wsrep_reject_queries = server_state["wsrep_reject_queries"];
					} catch (const std::exception& e) {
						return { EXIT_FAILURE, e.what() };
					}
				}
				if (m_wsrep_sst_donor_rejects_queries == nullptr) {
					wsrep_sst_donor_rejects_queries = -1;
				} else {
					try {
						wsrep_sst_donor_rejects_queries = server_state["wsrep_sst_donor_rejects_queries"];
					} catch (const std::exception& e) {
						return { EXIT_FAILURE, e.what() };
					}
				}
				if (m_wsrep_cluster_status == nullptr) {
					wsrep_cluster_status = "nullptr";
				} else {
					try {
						wsrep_cluster_status = server_state["wsrep_cluster_status"];
					} catch (const std::exception& e) {
						return { EXIT_FAILURE, e.what() };
					}
				}
				if (m_pxc_maint_mode == nullptr) {
					pxc_maint_mode = "nullptr";
				} else {
					try {
						pxc_maint_mode = server_state["pxc_maint_mode"];
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
				hostgroup_id,
				hostname,
				port,
				wsrep_local_state,
				read_only,
				wsrep_local_recv_queue,
				wsrep_desync,
				wsrep_reject_queries,
				wsrep_sst_donor_rejects_queries,
				wsrep_cluster_status,
				pxc_maint_mode
			)
		);
	}

	// fill the output parameter
	out_server_states = res_states;

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> get_current_galera_servers_state(
	MYSQL* proxysql_admin,
	std::vector<galera_server_state>& out_cur_galera_servers_state
) {
	std::pair<int, std::string> err_res {};
	std::string t_err_msg { "'get_current_galera_servers_state' failed with error: '%s'" };
	std::string err_msg {};

	int q_res = mysql_query(
		proxysql_admin,
		"SELECT hostgroup_id, hostname, port, wsrep_local_state, read_only, wsrep_local_recv_queue,"
		" wsrep_desync, wsrep_reject_queries, wsrep_sst_donor_rejects_queries, wsrep_cluster_status,"
		" pxc_maint_mode FROM HOST_STATUS_GALERA"
	);

	if (q_res == 0) {
		ordered_json j_servers {};
		j_servers["cluster_type"] = "GALERA";
		j_servers["galera_servers_init_state"] = {};

		MYSQL_RES* my_servers_res = mysql_store_result(proxysql_admin);
		parse_result_to_json(my_servers_res, j_servers["galera_servers_init_state"]);

		// convert the fields into the proper types
		for (ordered_json& j_server : j_servers["galera_servers_init_state"]) {
			j_server["hostgroup_id"] = atoi(std::string {j_server["hostgroup_id"]}.c_str());
			j_server["port"] = atoi(std::string {j_server["port"]}.c_str());
			j_server["wsrep_local_state"] = atoi(std::string {j_server["wsrep_local_state"]}.c_str());
			j_server["read_only"] = atoi(std::string {j_server["read_only"]}.c_str());
			j_server["wsrep_local_recv_queue"] = atoi(std::string {j_server["wsrep_local_recv_queue"]}.c_str());
			j_server["wsrep_desync"] = atoi(std::string {j_server["wsrep_desync"]}.c_str());
			j_server["wsrep_sst_donor_rejects_queries"] = atoi(std::string {j_server["wsrep_sst_donor_rejects_queries"]}.c_str());
		}

		std::vector<galera_server_state> cur_galera_servers_state {};
		std::pair<int, std::string> ext_res =
			extract_galera_servers_state(galera_state_id::init_state, j_servers, cur_galera_servers_state);

		if (ext_res.first == EXIT_SUCCESS) {
			out_cur_galera_servers_state = cur_galera_servers_state;
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

std::vector<galera_server_state> sort_galera_server_state(
	const std::vector<galera_server_state>& galera_servers_state
) {
	std::vector<galera_server_state> c_galera_servers_state { galera_servers_state };

	const auto galera_server_state_comparator = [] (
		const galera_server_state& srv_st1,
		const galera_server_state& srv_st2
	) -> bool {
		const std::string srv_st1_id {
			std::to_string(std::get<0>(srv_st1)) +
			std::get<1>(srv_st1) + 
			std::to_string(std::get<2>(srv_st1))
		};
		const std::string srv_st2_id {
			std::to_string(std::get<0>(srv_st2)) +
			std::get<1>(srv_st2) + 
			std::to_string(std::get<2>(srv_st2))
		};

		return srv_st1_id > srv_st2_id;
	};

	std::sort(
		c_galera_servers_state.begin(),
		c_galera_servers_state.end(),
		galera_server_state_comparator
	);

	return c_galera_servers_state;
}

bool compare_galera_servers_state(
	const std::vector<galera_server_state>& galera_servers_state_1,
	const std::vector<galera_server_state>& galera_servers_state_2
) {
	std::vector<galera_server_state> s_galera_servers_state_1
		= sort_galera_server_state(galera_servers_state_1);
	std::vector<galera_server_state> s_galera_servers_state_2
		= sort_galera_server_state(galera_servers_state_2);

	return s_galera_servers_state_1 == s_galera_servers_state_2;
}

// *********************************************************************

// NOTE: Some template magic for access the indexes with a common
// check based, and perform a random supplied operation.

std::vector<std::pair<column_id, std::string>> galera_state_members_diff(
	const galera_server_state& st1,
	const galera_server_state& st2
) {
	std::vector<std::pair<column_id, std::string>> result {};

	// hostgroup_id, hostname and port **can't** be changed,
	// because the are part of the server 'id'. Only the
	// other fields are allowed to change, otherwise, the
	// verification step should have failed.

	int st1_wsrep_local_state = std::get<3>(st1);
	int st2_wsrep_local_state = std::get<3>(st2);

	if (st2_wsrep_local_state != -1 && st1_wsrep_local_state != st2_wsrep_local_state) {
		result.push_back({ "wsrep_local_state", std::to_string(st2_wsrep_local_state) });
	}

	int st1_read_only = std::get<4>(st1);
	int st2_read_only = std::get<4>(st2);

	if (st2_read_only != -1 && st1_read_only != st2_read_only) {
		result.push_back({ "read_only", std::to_string(st2_read_only) });
	}

	int st1_wsrep_local_recv_queue = std::get<5>(st1);
	int st2_wsrep_local_recv_queue = std::get<5>(st2);

	if (
		st2_wsrep_local_recv_queue != -1 &&
		st1_wsrep_local_recv_queue != st2_wsrep_local_recv_queue
	) {
		result.push_back({ "wsrep_local_recv_queue", std::to_string(st2_wsrep_local_recv_queue) });
	}

	int st1_wsrep_desync = std::get<6>(st1);
	int st2_wsrep_desync = std::get<6>(st2);

	if (st2_wsrep_desync != -1 && st1_wsrep_desync != st2_wsrep_desync) {
		result.push_back({ "wsrep_desync", std::to_string(st2_wsrep_desync) });
	}

	std::string st1_wsrep_reject_queries = std::get<7>(st1);
	std::string st2_wsrep_reject_queries = std::get<7>(st2);

	if (
		st2_wsrep_reject_queries != "NULL" &&
		st1_wsrep_reject_queries != st2_wsrep_reject_queries
	) {
		result.push_back({ "wsrep_reject_queries", st2_wsrep_reject_queries });
	}

	int st1_wsrep_sst_donor_rejects_queries = std::get<8>(st1);
	int st2_wsrep_sst_donor_rejects_queries = std::get<8>(st2);

	if (
		st2_wsrep_sst_donor_rejects_queries != -1 &&
		st1_wsrep_sst_donor_rejects_queries != st2_wsrep_sst_donor_rejects_queries
	) {
		result.push_back({
			"wsrep_sst_donor_rejects_queries",
			std::to_string(st1_wsrep_sst_donor_rejects_queries)
		});
	}

	std::string st1_cluster_status = std::get<9>(st1);
	std::string st2_cluster_status = std::get<9>(st2);

	if (st2_cluster_status != "NULL" && st1_cluster_status != st2_cluster_status) {
		result.push_back({ "cluster_status", st2_cluster_status });
	}

	std::string st1_pxc_maint_mode = std::get<10>(st1);
	std::string st2_pxc_maint_mode = std::get<10>(st2);

	if (st2_pxc_maint_mode != "NULL" && st1_pxc_maint_mode != st2_pxc_maint_mode) {
		result.push_back({ "pxc_maint_mode", st2_pxc_maint_mode });
	}

	return result;
}

galera_server_state galera_update_state(
	const galera_server_state& st1,
	const galera_server_state& st2
) {
	galera_server_state result {};

	// hostgroup_id, hostname and port **can't** be changed,
	// because the are part of the server 'id'. Only the
	// other fields are allowed to change, otherwise, the
	// verification step should have failed.

	int st1_wsrep_local_state = std::get<3>(st1);
	int st2_wsrep_local_state = std::get<3>(st2);

	if (st2_wsrep_local_state != -1 && st1_wsrep_local_state != st2_wsrep_local_state) {
		std::get<3>(result) = st2_wsrep_local_state;
	}

	int st1_read_only = std::get<4>(st1);
	int st2_read_only = std::get<4>(st2);

	if (st2_read_only != -1 && st1_read_only != st2_read_only) {
		std::get<4>(result) = st2_wsrep_local_state;
	}

	int st1_wsrep_local_recv_queue = std::get<5>(st1);
	int st2_wsrep_local_recv_queue = std::get<5>(st2);

	if (
		st2_wsrep_local_recv_queue != -1 &&
		st1_wsrep_local_recv_queue != st2_wsrep_local_recv_queue
	) {
		std::get<5>(result) = st2_wsrep_local_recv_queue;
	}

	int st1_wsrep_desync = std::get<6>(st1);
	int st2_wsrep_desync = std::get<6>(st2);

	if (st2_wsrep_desync != -1 && st1_wsrep_desync != st2_wsrep_desync) {
		std::get<6>(result) = st2_wsrep_local_recv_queue;
	}

	std::string st1_wsrep_reject_queries = std::get<7>(st1);
	std::string st2_wsrep_reject_queries = std::get<7>(st2);

	if (
		st2_wsrep_reject_queries != "NULL" &&
		st1_wsrep_reject_queries != st2_wsrep_reject_queries
	) {
		std::get<7>(result) = st2_wsrep_reject_queries;
	}

	int st1_wsrep_sst_donor_rejects_queries = std::get<8>(st1);
	int st2_wsrep_sst_donor_rejects_queries = std::get<8>(st2);

	if (
		st2_wsrep_sst_donor_rejects_queries != -1 &&
		st1_wsrep_sst_donor_rejects_queries != st2_wsrep_sst_donor_rejects_queries
	) {
		std::get<8>(result) = st2_wsrep_sst_donor_rejects_queries;
	}

	std::string st1_cluster_status = std::get<9>(st1);
	std::string st2_cluster_status = std::get<9>(st2);

	if (st2_cluster_status != "NULL" && st1_cluster_status != st2_cluster_status) {
		std::get<9>(result) = st2_wsrep_sst_donor_rejects_queries;
	}

	std::string st1_pxc_maint_mode = std::get<10>(st1);
	std::string st2_pxc_maint_mode = std::get<10>(st2);

	if (st2_pxc_maint_mode != "NULL" && st1_pxc_maint_mode != st2_pxc_maint_mode) {
		std::get<10>(result) = st2_wsrep_sst_donor_rejects_queries;
	}

	return result;
}

std::vector<galera_server_state> galera_update_cluster_state(
	const std::vector<galera_server_state>& servers_state_p,
	const std::vector<galera_server_state>& servers_state_n
) {
	std::vector<galera_server_state> result {};

	std::vector<galera_server_state> s_servers_state_p
		= sort_galera_server_state(servers_state_p);
	std::vector<galera_server_state> s_servers_state_n
		= sort_galera_server_state(servers_state_n);

	// find the differences
	for (const auto& server_state_n : s_servers_state_n) {
		for (const auto& server_state_p : s_servers_state_p) {
			const std::string n_server_state_id {
				std::to_string(std::get<0>(server_state_n)) + ":" +
				std::get<1>(server_state_n) + ":" +
				std::to_string(std::get<2>(server_state_n))
			};
			const std::string p_server_state_id {
				std::to_string(std::get<0>(server_state_p)) + ":" +
				std::get<1>(server_state_p) + ":" +
				std::to_string(std::get<2>(server_state_p))
			};

			bool diff_server_status =
				( n_server_state_id == p_server_state_id ) &&
				( server_state_n != server_state_p );

			if (diff_server_status) {
				const galera_server_state server_state_update =
					galera_update_state(server_state_p, server_state_n);
				result.push_back(server_state_update);
			}
		}
	}

	return result;
}

// *********************************************************************

cluster_state_changes galera_servers_state_diff(
	const std::vector<galera_server_state>& servers_state_p,
	const std::vector<galera_server_state>& servers_state_n
) {
	cluster_state_changes result {};

	std::vector<galera_server_state> s_servers_state_p
		= sort_galera_server_state(servers_state_p);
	std::vector<galera_server_state> s_servers_state_n
		= sort_galera_server_state(servers_state_n);

	// find the differences
	for (const auto& server_state_n : s_servers_state_n) {
		for (const auto& server_state_p : s_servers_state_p) {
			const std::string n_server_state_id {
				std::to_string(std::get<0>(server_state_n)) + ":" +
				std::get<1>(server_state_n) + ":" +
				std::to_string(std::get<2>(server_state_n))
			};
			const std::string p_server_state_id {
				std::to_string(std::get<0>(server_state_p)) + ":" +
				std::get<1>(server_state_p) + ":" +
				std::to_string(std::get<2>(server_state_p))
			};

			bool diff_server_status =
				( n_server_state_id == p_server_state_id ) &&
				( server_state_n != server_state_p );

			if (diff_server_status) {
				const auto server_state_diff =
					galera_state_members_diff(server_state_p, server_state_n);
				result.insert({ n_server_state_id, server_state_diff });
			}
		}
	}

	return result;
}

std::pair<int, std::string> set_galera_monitor_check_times(MYSQL* proxysql_admin) {
	if (proxysql_admin == nullptr ) { return  { EXIT_FAILURE, "Supplied MYSQL handle is 'NULL'" }; }

	int query_error = 0;

	const std::string set_hcheck_query { "SET mysql-monitor_galera_healthcheck_interval=200" };
	query_error = mysql_query(proxysql_admin, set_hcheck_query.c_str());
	if (query_error) { return create_query_error(proxysql_admin, set_hcheck_query, __FILE__, __LINE__); }

	const std::string set_hcheck_to_query { "SET mysql-monitor_galera_healthcheck_timeout=100" };
	query_error = mysql_query(proxysql_admin, set_hcheck_to_query.c_str());
	if (query_error) { return create_query_error(proxysql_admin, set_hcheck_to_query, __FILE__, __LINE__); }

	const std::string load_to_runtime_query { "LOAD MYSQL VARIABLES TO RUNTIME" };
	query_error = mysql_query(proxysql_admin, load_to_runtime_query.c_str());
	if (query_error) { return create_query_error(proxysql_admin, load_to_runtime_query, __FILE__, __LINE__); }

	return { EXIT_SUCCESS, "" };
}

std::pair<int, std::string> get_galera_monitor_check_times(
	MYSQL* proxysql_admin,
	int& out_healthcheck_interval,
	int& out_healthcheck_timeout
) {
	if (proxysql_admin == nullptr ) { return  { EXIT_FAILURE, "Supplied MYSQL handle is 'NULL'" }; }
	int query_error = 0;

	const std::string select_hcheck_query {
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-monitor_galera_healthcheck_interval'"
	};
	query_error = mysql_query(proxysql_admin, select_hcheck_query.c_str());
	if (query_error) { return create_query_error(proxysql_admin, select_hcheck_query, __FILE__, __LINE__); }

	MYSQL_RES* my_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW my_row = mysql_fetch_row(my_res);
	int healthcheck_interval = atoi(my_row[0]);
	mysql_free_result(my_res);

	const std::string select_hcheck_to_query {
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-monitor_galera_healthcheck_timeout'"
	};
	query_error = mysql_query(proxysql_admin, select_hcheck_to_query.c_str());
	if (query_error) { return create_query_error(proxysql_admin, select_hcheck_to_query, __FILE__, __LINE__); }

	my_res = mysql_store_result(proxysql_admin);
	my_row = mysql_fetch_row(my_res);
	int healthcheck_timeout = atoi(my_row[0]);
	mysql_free_result(my_res);

	// fill the output parameters
	out_healthcheck_interval = healthcheck_interval;
	out_healthcheck_timeout = healthcheck_timeout;

	return { EXIT_SUCCESS, "" };
}

////////////////////////////////////////////////////////////////////////////////

