/**
 * @file galera_simulator-t.cpp
 * @brief Test file for testing Galera behavior using a simulation through SQLiteServer exposed via
 *   'TEST_GALERA'.
 */

#include <iostream>
#include <fstream>
#include <tuple>

// NOTE: Only needed during testing
#include <functional>

#include <mysql.h>
#include <mysqld_error.h>
#include <string>
#include <unistd.h>

#include "ezOptionParser.hpp"
#include "proxysql_utils.h"
#include "utils.h"
#include "command_line.h"
#include "json.hpp"

#include "common_utils.h"
#include "galera_utils.h"
#include "readonly_utils.h"
#include "replicationlag_utils.h"
#include "grouprep_utils.h"
#include "aurora_utils.h"

using std::string;

/**
 * @brief Top-level mode of the simulator: drive the cluster state ('simulate')
 *  or verify the current state against the expected one ('verify').
 */
enum class operation_mode {
	simulate,
	verify
};
/**
 * @brief Command-line options parsed in 'main()' and passed to the simulator drivers.
 */
struct simulator_options {
	// command line options variables
	bool verbose_output = false;
	bool stop_on_failure = false;
	operation_mode op_mode = operation_mode::simulate;
	std::string payload_path {};
};

std::pair<int, nlohmann::ordered_json> simulate_galera_cluster_state(
	MYSQL* proxysql_admin,
	MYSQL* proxysql_sqlite,
	const json& j_test_definition,
	const operation_mode& op_mode,
	const bool verbose = false
) {
	std::pair<int, nlohmann::ordered_json> result {};

	std::vector<mysql_server_def> mysql_servers {};
	std::vector<galera_hostgroup_config> galera_hostgroups {};

	std::vector<galera_server_state> galera_init_servers_state {};
	std::vector<galera_server_state> galera_new_servers_state {};

	// the expected initial cluster servers status
	std::vector<server_status> exp_init_cluster_status {};
	// the expected final cluster servers status
	std::vector<server_status> exp_final_cluster_status {};

	// validations errors from extracting the required values from the JSON payload
	std::pair<int, std::string> ext_mysql_srvs_err {};
	std::pair<int, std::string> ext_galera_conf_err {};
	std::pair<int, std::string> ext_galera_init_srvs_state_err {};
	std::pair<int, std::string> ext_galera_next_srvs_state_err {};
	std::pair<int, std::string> ext_init_cluster_status_err {};
	std::pair<int, std::string> ext_final_cluster_status_err {};

	// errors from applying the required configuration to ProxySQL
	std::pair<int, std::string> prep_galera_hostgroups_err {};
	std::pair<int, std::string> prep_galera_init_state_err {};
	std::pair<int, std::string> prep_galera_final_state_err {};
	std::pair<int, std::string> prep_mysql_servers_conf_err {};
	std::pair<int, std::string> set_monitor_tos_err {};
	int load_to_run_err = 0;

	// **************************  VALIDATION  ********************************

	ext_mysql_srvs_err = extract_mysql_servers(j_test_definition, mysql_servers);

	if (ext_mysql_srvs_err.first) {
		result = invalid_json_error(
			ext_mysql_srvs_err.second, __FILE__, __LINE__
		);

		goto exit;
	}

	ext_galera_conf_err =
		extract_galera_hostgroup_config(j_test_definition, galera_hostgroups);

	if (ext_galera_conf_err.first) {
		result = invalid_json_error(
			ext_galera_conf_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_galera_init_srvs_state_err =
		extract_galera_servers_state(
			galera_state_id::init_state,
			j_test_definition,
			galera_init_servers_state
		);

	if (ext_galera_init_srvs_state_err.first) {
		result = invalid_json_error(
			ext_galera_init_srvs_state_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_init_cluster_status_err =
		extract_cluster_status(
			cluster_state::init_state,
			j_test_definition,
			exp_init_cluster_status
		);

	if (ext_init_cluster_status_err.first) {
		result = invalid_json_error(
			ext_init_cluster_status_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_final_cluster_status_err =
		extract_cluster_status(
			cluster_state::final_state,
			j_test_definition,
			exp_final_cluster_status
		);

	if (ext_final_cluster_status_err.first) {
		result = invalid_json_error(
			ext_final_cluster_status_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_galera_next_srvs_state_err =
		extract_galera_servers_state(
			galera_state_id::new_state,
			j_test_definition,
			galera_new_servers_state
		);

	if (ext_galera_next_srvs_state_err.first) {
		result = invalid_json_error(
			ext_galera_next_srvs_state_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	// ************************ CONFIGURATION  ********************************

	prep_mysql_servers_conf_err =
		prepare_mysql_servers_config(proxysql_admin, mysql_servers);
	if (prep_mysql_servers_conf_err.first) {
		result = invalid_config_error(prep_mysql_servers_conf_err.second, __FILE__, __LINE__);
		goto exit;
	}

	prep_galera_hostgroups_err =
		prepare_mysql_galera_hostgroups(proxysql_admin, galera_hostgroups);

	if (prep_galera_hostgroups_err.first) {
		result = invalid_config_error(prep_galera_hostgroups_err.second, __FILE__, __LINE__);
		goto exit;
	}

	prep_galera_init_state_err =
		prepare_galera_cluster_state(proxysql_sqlite, galera_init_servers_state, true);

	if (prep_galera_init_state_err.first) {
		result = invalid_config_error(prep_galera_init_state_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// final LOAD after all the configuration has been setup
	load_to_run_err = mysql_query(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	if (load_to_run_err) {
		const auto& query_err =
			create_query_error(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME", __FILE__, __LINE__);
		result = internal_error(query_err.second, __FILE__, __LINE__);
		goto exit;
	}

	set_monitor_tos_err = set_galera_monitor_check_times(proxysql_admin);
	if (set_monitor_tos_err.first) {
		result = internal_error(set_monitor_tos_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// ************************** VERIFICATION *********************************
	{
		int healthcheck_interval = 0;
		int healthcheck_timeout = 0;

		std::pair<int, std::string> get_monitor_times_err =
			get_galera_monitor_check_times(proxysql_admin, healthcheck_interval, healthcheck_timeout);
		if (get_monitor_times_err.first) {
			result = internal_error(get_monitor_times_err.second, __FILE__, __LINE__);
			goto exit;
		}

		// map the values to secs
		double healthcheck_interval_s = static_cast<double>(healthcheck_interval) / 1000;
		double healthcheck_timeout_s = static_cast<double>(healthcheck_timeout) / 1000;

		// proper waiting for monitor timing
		sleep(healthcheck_interval_s + mysql_servers.size()*healthcheck_timeout_s*3 + 1);

		// check that the current cluster state matches the expected one
		std::vector<server_status> init_cluster_status {};
		const auto& init_cluster_st_err =
			get_current_cluster_status(proxysql_admin, init_cluster_status);

		if (init_cluster_st_err.first) {
			result = internal_error(
				"'get_current_cluster_status' failed for 'init_state': '" +
				init_cluster_st_err.second + "'",
				__FILE__, __LINE__
			);
			goto exit;
		}

		// check the initial cluster status is the expected one
		if (!check_cluster_status(exp_init_cluster_status, init_cluster_status)) {
			result = verification_error(
				"Expected 'proxysql_init_state' doesn't match actual cluster state",
				exp_init_cluster_status,
				init_cluster_status,
				{}
			);
			goto exit;
		}

		// detect the changes that are going to be imposed
		const auto& state_diff =
			galera_servers_state_diff(galera_init_servers_state, galera_new_servers_state);

		// set the new servers state
		const auto& galera_new_state_to_set =
			galera_update_cluster_state(galera_init_servers_state, galera_new_servers_state);
		prep_galera_final_state_err =
			prepare_galera_cluster_state(proxysql_sqlite, galera_new_servers_state);

		if (prep_galera_final_state_err.first) {
			result = internal_error(prep_galera_final_state_err.second, __FILE__, __LINE__);
			goto exit;
		}

		// sleep for monitor ot reconfigure the servers
		sleep(healthcheck_interval_s + mysql_servers.size()*healthcheck_timeout_s*3 + 1);

		// check that the final cluster state matches the expected one
		std::vector<server_status> final_cluster_status {};
		const auto& final_cluster_st_err =
			get_current_cluster_status(proxysql_admin, final_cluster_status);

		if (final_cluster_st_err.first) {
			result = internal_error(
				"'get_current_cluster_status' failed for 'final_state': '" +
				final_cluster_st_err.second + "'",
				__FILE__, __LINE__
			);
			goto exit;
		}

		// if we are just simulating no further operations are needed
		if (op_mode == operation_mode::simulate) {
			ordered_json j_final_cluster_status = cluster_status_to_json(final_cluster_status);
			std::string init_state_checksum = cluster_status_checksum(init_cluster_status);
			std::string final_state_checksum = cluster_status_checksum(final_cluster_status);

			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json {
					{ "err_type", "none" },
					{ "result",
						nlohmann::ordered_json {
							{ "cluster_type", "GALERA" },
							{ "mysql_servers", j_test_definition.at("mysql_servers") },
							{ "mysql_galera_hostgroups", j_test_definition.at("mysql_galera_hostgroups") },
							{ "galera_servers_init_state", j_test_definition.at("galera_servers_init_state") },
							{ "galera_servers_new_state", j_test_definition.at("galera_servers_new_state") },
							{ "proxysql_init_state_checksum", init_state_checksum },
							{ "proxysql_init_state", j_test_definition.at("proxysql_init_state") },
							{ "proxysql_final_state_checksum", final_state_checksum },
							{ "proxysql_final_state", j_final_cluster_status },
						}
					}
				}
			};
			goto exit;
		}

		if (!check_cluster_status(exp_final_cluster_status, final_cluster_status)) {
			result = verification_error(
				"Expected 'proxysql_final_state' doesn't match actual cluster state",
				exp_final_cluster_status,
				final_cluster_status,
				state_diff
			);
			goto exit;
		}

		if (verbose) {
			ordered_json j_init_cluster_status = cluster_status_to_json(init_cluster_status);
			ordered_json j_final_cluster_status = cluster_status_to_json(final_cluster_status);
			std::string init_state_checksum = cluster_status_checksum(init_cluster_status);
			std::string final_state_checksum = cluster_status_checksum(final_cluster_status);

			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json {
					{ "err_type", "none" },
					{ "result",
						nlohmann::ordered_json {
							{ "err_type", "none" },
							{ "err_msg", "" },
							{ "cluster_type", "GALERA" },
							{ "mysql_servers", j_test_definition.at("mysql_servers") },
							{ "mysql_galera_hostgroups", j_test_definition.at("mysql_galera_hostgroups") },
							{ "galera_servers_init_state", j_test_definition.at("galera_servers_init_state") },
							{ "galera_servers_new_state", j_test_definition.at("galera_servers_new_state") },
							{ "proxysql_init_state_checksum", init_state_checksum },
							{ "proxysql_init_state", j_init_cluster_status },
							{ "proxysql_final_state_checksum", final_state_checksum },
							{ "proxysql_final_state", j_final_cluster_status },
						}
					}
				}
			};
		} else {
			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json { { "err_type", "none" }, { "err_msg", "" } },
			};
		}
	}

exit:

	return result;
}

std::pair<int, nlohmann::ordered_json> simulate_mysql_readonly_cluster_state(
	MYSQL* proxysql_admin,
	MYSQL* proxysql_sqlite,
	const json& j_test_definition,
	const operation_mode& op_mode,
	const bool verbose = false
) {
	std::pair<int, nlohmann::ordered_json> result {};

	std::vector<mysql_server_def> mysql_servers {};
	std::vector<replication_hostgroup_config> replication_hostgroups {};
	std::vector<monitor_variable> monitor_variables {};
	std::vector<readonly_server_state> readonly_init_servers_state {};
	std::vector<readonly_server_state> readonly_new_servers_state {};

	// the expected initial cluster servers status
	std::vector<server_status> exp_init_cluster_status {};
	// the expected final cluster servers status
	std::vector<server_status> exp_final_cluster_status {};

	// validations errors from extracting the required values from the JSON payload
	std::pair<int, std::string> ext_mysql_srvs_err {};
	std::pair<int, std::string> ext_replication_conf_err {};
	std::pair<int, std::string> ext_monitor_conf_err{};
	std::pair<int, std::string> ext_readonly_init_srvs_state_err {};
	std::pair<int, std::string> ext_readonly_next_srvs_state_err {};
	std::pair<int, std::string> ext_init_cluster_status_err {};
	std::pair<int, std::string> ext_final_cluster_status_err {};

	// errors from applying the required configuration to ProxySQL
	std::pair<int, std::string> prep_replication_hostgroups_err {};
	std::pair<int, std::string> prep_replication_init_state_err {};
	std::pair<int, std::string> prep_replication_final_state_err {};
	std::pair<int, std::string> prep_mysql_servers_conf_err {};
	std::pair<int, std::string> set_monitor_variables_err{};
	std::pair<int, std::string> set_monitor_tos_err {};
	int load_to_run_err = 0;

	const std::vector<std::string> rephostgrp_monitor_variables{
		"monitor_writer_is_also_reader"
	};

	const std::vector<monitor_variable> monitor_defaults_variables{
		{ "monitor_writer_is_also_reader", 1 }
	};

	// **************************  VALIDATION  ********************************

	ext_mysql_srvs_err = extract_mysql_servers(j_test_definition, mysql_servers);

	if (ext_mysql_srvs_err.first) {
		result = invalid_json_error(
			ext_mysql_srvs_err.second, __FILE__, __LINE__
		);

		goto exit;
	}

	ext_replication_conf_err =
		extract_replication_hostgroup_config(j_test_definition, replication_hostgroups);

	if (ext_replication_conf_err.first) {
		result = invalid_json_error(
			ext_replication_conf_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_monitor_conf_err =
		extract_monitor_config(j_test_definition, monitor_variables);

	if (ext_monitor_conf_err.first) {
		result = invalid_json_error(
			ext_monitor_conf_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_readonly_init_srvs_state_err =
		extract_readonly_servers_state(
			readonly_state_id::init_state,
			j_test_definition,
			readonly_init_servers_state
		);

	if (ext_readonly_init_srvs_state_err.first) {
		result = invalid_json_error(
			ext_readonly_init_srvs_state_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_init_cluster_status_err =
		extract_cluster_status(
			cluster_state::init_state,
			j_test_definition,
			exp_init_cluster_status
		);

	if (ext_init_cluster_status_err.first) {
		result = invalid_json_error(
			ext_init_cluster_status_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_final_cluster_status_err =
		extract_cluster_status(
			cluster_state::final_state,
			j_test_definition,
			exp_final_cluster_status
		);

	if (ext_final_cluster_status_err.first) {
		result = invalid_json_error(
			ext_final_cluster_status_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_readonly_next_srvs_state_err =
		extract_readonly_servers_state(
			readonly_state_id::new_state,
			j_test_definition,
			readonly_new_servers_state
		);

	if (ext_readonly_next_srvs_state_err.first) {
		result = invalid_json_error(
			ext_readonly_next_srvs_state_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	// ************************ CONFIGURATION  ********************************

	prep_mysql_servers_conf_err =
		prepare_mysql_servers_config(proxysql_admin, mysql_servers);
	if (prep_mysql_servers_conf_err.first) {
		result = invalid_config_error(prep_mysql_servers_conf_err.second, __FILE__, __LINE__);
		goto exit;
	}

	prep_replication_hostgroups_err =
		prepare_mysql_replication_hostgroups(proxysql_admin, replication_hostgroups);

	if (prep_replication_hostgroups_err.first) {
		result = invalid_config_error(prep_replication_hostgroups_err.second, __FILE__, __LINE__);
		goto exit;
	}

	/**
	 * @brief Change the monitored server state values first for READ_ONLY.
	 * @details Due to these two facts, reported servers could not match the right 'exp_init_cluster_status':
	 *   - The non-convergent nature of READ_ONLY actions due to 'writer_is_also_reader'. When enabled servers
	 *     are only placed in the 'reader_hostgroup' if they were previously detected there.
	 *   - Simulator assumes a value 'read_only: 1' for servers that didn't previously receive a value.
	 *
	 *  Due to this conditions, a server could be found in the 'reader_hostgroup', due to
	 *  'writer_is_also_reader' even if it wasn't ever placed there by user configuration.
	 */
	{
		prep_replication_init_state_err =
			prepare_readonly_cluster_state(proxysql_sqlite, readonly_init_servers_state, true);

		if (prep_replication_init_state_err.first) {
			result = invalid_config_error(prep_replication_init_state_err.second, __FILE__, __LINE__);
			goto exit;
		}
	}

	/**
	 * @brief Change the monitor variable values before server loading for READ_ONLY.
	 * @details Due to the non-convergent nature of READ_ONLY actions due to 'writer_is_also_reader', servers could
	 *  not match the right 'exp_init_cluster_status' if the configuration value for 'writer_is_also_reader' changes
	 *  after previous monitoring actions has been already taken.
	 */
	{
		// prepare monitor variables
		set_monitor_variables_err =
			set_monitor_variables(proxysql_admin, rephostgrp_monitor_variables, monitor_variables);

		// final LOAD for 'mysql' variables after configuration has been setup
		load_to_run_err = mysql_query(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		if (load_to_run_err) {
			const auto& query_err =
				create_query_error(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME", __FILE__, __LINE__);
			result = internal_error(query_err.second, __FILE__, __LINE__);
			goto exit;
		}
	}

	// final LOAD after all the configuration has been setup
	load_to_run_err = mysql_query(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	if (load_to_run_err) {
		const auto& query_err =
			create_query_error(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME", __FILE__, __LINE__);
		result = internal_error(query_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// give the variables some defaults if they are not present
	monitor_variables = set_monitor_variables_defaults(
		monitor_variables, monitor_defaults_variables
	);

	set_monitor_tos_err = set_readonly_monitor_check_times(proxysql_admin);
	if (set_monitor_tos_err.first) {
		result = internal_error(set_monitor_tos_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// ************************** VERIFICATION *********************************
	{
		int readonly_interval = 0;
		int readonly_timeout = 0;

		std::pair<int, std::string> get_monitor_times_err =
			get_readonly_monitor_check_times(proxysql_admin, readonly_interval, readonly_timeout);
		if (get_monitor_times_err.first) {
			result = internal_error(get_monitor_times_err.second, __FILE__, __LINE__);
			goto exit;
		}

		// map the values to secs
		double readonly_interval_s = static_cast<double>(readonly_interval) / 1000;
		double readonly_timeout_s = static_cast<double>(readonly_timeout) / 1000;

		// proper waiting for monitor timing
		double sleep_delay =
			readonly_interval_s + mysql_servers.size()*readonly_timeout_s*0.1 + 1;

		usleep(sleep_delay * pow(10, 6));

		// check that the current cluster state matches the expected one
		std::vector<server_status> init_cluster_status {};
		const auto& init_cluster_st_err =
			get_current_cluster_status(proxysql_admin, init_cluster_status);

		if (init_cluster_st_err.first) {
			result = internal_error(
				"'get_current_cluster_status' failed for 'init_state': '" +
				init_cluster_st_err.second + "'",
				__FILE__, __LINE__
			);
			goto exit;
		}

		// check the initial cluster status is the expected one
		if (!check_cluster_status(exp_init_cluster_status, init_cluster_status)) {
			result = verification_error(
				"Expected 'proxysql_init_state' doesn't match actual cluster state",
				exp_init_cluster_status,
				init_cluster_status,
				{}
			);
			goto exit;
		}

		// detect the changes that are going to be imposed
		const auto& state_diff =
			readonly_servers_state_diff(readonly_init_servers_state, readonly_new_servers_state);

		// set the new servers state
		const auto& replication_new_state_to_set =
			readonly_update_cluster_state(readonly_init_servers_state, readonly_new_servers_state);
		prep_replication_final_state_err =
			prepare_readonly_cluster_state(proxysql_sqlite, readonly_new_servers_state);

		if (prep_replication_final_state_err.first) {
			result = internal_error(prep_replication_final_state_err.second, __FILE__, __LINE__);
			goto exit;
		}

		// sleep for monitor ot reconfigure the servers
		usleep(sleep_delay * pow(10, 6));

		// check that the final cluster state matches the expected one
		std::vector<server_status> final_cluster_status {};
		const auto& final_cluster_st_err =
			get_current_cluster_status(proxysql_admin, final_cluster_status);

		if (final_cluster_st_err.first) {
			result = internal_error(
				"'get_current_cluster_status' failed for 'final_state': '" +
				final_cluster_st_err.second + "'",
				__FILE__, __LINE__
			);
			goto exit;
		}

		// if we are just simulating no further operations are needed
		if (op_mode == operation_mode::simulate) {
			ordered_json j_final_cluster_status = cluster_status_to_json(final_cluster_status);
			std::string init_state_checksum = cluster_status_checksum(init_cluster_status);
			std::string final_state_checksum = cluster_status_checksum(final_cluster_status);

			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json {
					{ "err_type", "none" },
					{ "result",
						nlohmann::ordered_json {
							{ "cluster_type", "replication" },
							{ "mysql_servers", j_test_definition.at("mysql_servers") },
							{ "mysql_replication_hostgroups", j_test_definition.at("mysql_replication_hostgroups") },
							{ "readonly_servers_init_state", j_test_definition.at("readonly_servers_init_state") },
							{ "readonly_servers_new_state", j_test_definition.at("readonly_servers_new_state") },
							{ "proxysql_init_state_checksum", init_state_checksum },
							{ "proxysql_init_state", j_test_definition.at("proxysql_init_state") },
							{ "proxysql_final_state_checksum", final_state_checksum },
							{ "proxysql_final_state", j_final_cluster_status },
						}
					}
				}
			};

			bool has_monitor_config =
				check_present_and_type(j_test_definition, { "mysql_monitor_config" }, json::value_t::array);

			if (has_monitor_config) {
				result.second["result"]["mysql_monitor_config"] = j_test_definition.at("mysql_monitor_config");
			}

			goto exit;
		}

		if (!check_cluster_status(exp_final_cluster_status, final_cluster_status)) {
			result = verification_error(
				"Expected 'proxysql_final_state' doesn't match actual cluster state",
				exp_final_cluster_status,
				final_cluster_status,
				state_diff
			);
			goto exit;
		}

		if (verbose) {
			ordered_json j_init_cluster_status = cluster_status_to_json(init_cluster_status);
			ordered_json j_final_cluster_status = cluster_status_to_json(final_cluster_status);
			std::string init_state_checksum = cluster_status_checksum(init_cluster_status);
			std::string final_state_checksum = cluster_status_checksum(final_cluster_status);

			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json {
					{ "err_type", "none" },
					{ "result",
						nlohmann::ordered_json {
							{ "err_type", "none" },
							{ "err_msg", "" },
							{ "cluster_type", "READ_ONLY" },
							{ "mysql_servers", j_test_definition.at("mysql_servers") },
							{ "mysql_replication_hostgroups", j_test_definition.at("mysql_replication_hostgroups") },
							{ "readonly_servers_init_state", j_test_definition.at("readonly_servers_init_state") },
							{ "readonly_servers_new_state", j_test_definition.at("readonly_servers_new_state") },
							{ "proxysql_init_state_checksum", init_state_checksum },
							{ "proxysql_init_state", j_init_cluster_status },
							{ "proxysql_final_state_checksum", final_state_checksum },
							{ "proxysql_final_state", j_final_cluster_status },
						}
					}
				}
			};

			bool has_monitor_config =
				check_present_and_type(j_test_definition, { "mysql_monitor_config" }, json::value_t::array);

			if (has_monitor_config) {
				result.second["result"]["mysql_monitor_config"] = j_test_definition.at("mysql_monitor_config");
			}

		} else {
			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json { { "err_type", "none" }, { "err_msg", "" } },
			};
		}
	}

exit:

	return result;
}

std::pair<int, nlohmann::ordered_json> simulate_mysql_group_replication_cluster_state(
	MYSQL* proxysql_admin,
	MYSQL* proxysql_sqlite,
	const json& j_test_definition,
	const operation_mode& op_mode,
	const bool verbose = false
) {
	std::pair<int, nlohmann::ordered_json> result {};

	std::vector<mysql_server_def> mysql_servers {};
	std::vector<hostgroup_attributes_def> hostgroup_attributes {};
	std::vector<monitor_variable> monitor_variables {};
	std::vector<group_replication_hostgroup_config> group_replication_hostgroups {};

	std::vector<grouprep_server_state> grouprep_init_servers_state {};
	std::vector<grouprep_server_state> grouprep_new_servers_state {};

	// the expected initial cluster servers status
	std::vector<server_status> exp_init_cluster_status {};
	// the expected final cluster servers status
	std::vector<server_status> exp_final_cluster_status {};

	// validations errors from extracting the required values from the JSON payload
	std::pair<int, std::string> ext_mysql_srvs_err {};
	std::pair<int, std::string> ext_hostgroup_attributes_err {};
	std::pair<int, std::string> ext_group_replication_conf_err {};
	std::pair<int, std::string> ext_monitor_conf_err {};
	std::pair<int, std::string> ext_grouprep_init_srvs_state_err {};
	std::pair<int, std::string> ext_grouprep_next_srvs_state_err {};
	std::pair<int, std::string> ext_init_cluster_status_err {};
	std::pair<int, std::string> ext_final_cluster_status_err {};

	// errors from applying the required configuration to ProxySQL
	std::pair<int, std::string> prep_group_replication_hostgroups_err {};
	std::pair<int, std::string> prep_group_replication_init_state_err {};
	std::pair<int, std::string> prep_group_replication_final_state_err {};
	std::pair<int, std::string> prep_mysql_servers_conf_err {};
	std::pair<int, std::string> prep_mysql_hostgroup_attributes_conf_err {};
	std::pair<int, std::string> set_monitor_tos_err {};
	std::pair<int, std::string> set_monitor_variables_err {};
	int load_to_run_err = 0;

	string setup_state_timestamp {};

	const std::vector<std::string> grouprep_monitor_variables {
		"monitor_groupreplication_max_transactions_behind_for_read_only",
		"monitor_groupreplication_healthcheck_interval",
		"monitor_groupreplication_healthcheck_timeout",
		"monitor_groupreplication_max_transactions_behind_count"
	};

	const std::vector<monitor_variable> monitor_defaults_variables {
		{ "monitor_groupreplication_max_transactions_behind_for_read_only", 1 },
		{ "monitor_groupreplication_healthcheck_interval", 200 },
		{ "monitor_groupreplication_healthcheck_timeout", 100 },
		{ "monitor_groupreplication_max_transactions_behind_count", 3 }
	};
	// **************************  VALIDATION  ********************************

	ext_mysql_srvs_err = extract_mysql_servers(j_test_definition, mysql_servers);

	if (ext_mysql_srvs_err.first) {
		result = invalid_json_error(
			ext_mysql_srvs_err.second, __FILE__, __LINE__
		);

		goto exit;
	}

	ext_hostgroup_attributes_err = extract_mysql_hostgroup_attributes(j_test_definition, hostgroup_attributes);
	if (ext_hostgroup_attributes_err.first) {
		result = invalid_json_error(ext_hostgroup_attributes_err.second, __FILE__, __LINE__);

		goto exit;
	}

	ext_group_replication_conf_err =
		extract_group_replication_hostgroup_config(
			j_test_definition, group_replication_hostgroups
		);

	if (ext_group_replication_conf_err.first) {
		result = invalid_json_error(
			ext_group_replication_conf_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_monitor_conf_err =
		extract_monitor_config(j_test_definition, monitor_variables);

	if (ext_monitor_conf_err.first) {
		result = invalid_json_error(
			ext_monitor_conf_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_grouprep_init_srvs_state_err =
		extract_grouprep_servers_state(
			grouprep_state_id::init_state,
			j_test_definition,
			grouprep_init_servers_state
		);

	if (ext_grouprep_init_srvs_state_err.first) {
		result = invalid_json_error(
			ext_grouprep_init_srvs_state_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_init_cluster_status_err =
		extract_cluster_status(
			cluster_state::init_state,
			j_test_definition,
			exp_init_cluster_status
		);

	if (ext_init_cluster_status_err.first) {
		result = invalid_json_error(
			ext_init_cluster_status_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_final_cluster_status_err =
		extract_cluster_status(
			cluster_state::final_state,
			j_test_definition,
			exp_final_cluster_status
		);

	if (ext_final_cluster_status_err.first) {
		result = invalid_json_error(
			ext_final_cluster_status_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_grouprep_next_srvs_state_err =
		extract_grouprep_servers_state(
			grouprep_state_id::new_state,
			j_test_definition,
			grouprep_new_servers_state
		);

	if (ext_grouprep_next_srvs_state_err.first) {
		result = invalid_json_error(
			ext_grouprep_next_srvs_state_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	// ************************ CONFIGURATION  ********************************

	prep_mysql_servers_conf_err =
		prepare_mysql_servers_config(proxysql_admin, mysql_servers);
	if (prep_mysql_servers_conf_err.first) {
		result = invalid_config_error(
			prep_mysql_servers_conf_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	if (!hostgroup_attributes.empty()) {
		prep_mysql_hostgroup_attributes_conf_err =
			prepare_mysql_hostgroup_attributes_config(proxysql_admin, hostgroup_attributes);
		if (prep_mysql_hostgroup_attributes_conf_err.first) {
			result = invalid_config_error(prep_mysql_hostgroup_attributes_conf_err.second, __FILE__, __LINE__);
			goto exit;
		}
	}

	prep_group_replication_hostgroups_err =
		prepare_mysql_group_replication_hostgroups(
			proxysql_admin, group_replication_hostgroups
		);

	if (prep_group_replication_hostgroups_err.first) {
		result = invalid_config_error(
			prep_group_replication_hostgroups_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	// give the variables some defaults if they are not present
	monitor_variables = set_monitor_variables_defaults(
		monitor_variables, monitor_defaults_variables
	);

	// prepare monitor variables
	set_monitor_variables_err =
		set_monitor_variables(
			proxysql_admin, grouprep_monitor_variables, monitor_variables
		);

	// final LOAD for 'mysql' variables after configuration has been setup
	load_to_run_err = mysql_query(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	if (load_to_run_err) {
		const auto& query_err =
			create_query_error(
				proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME", __FILE__, __LINE__
			);
		result = internal_error(query_err.second, __FILE__, __LINE__);
		goto exit;
	}

	setup_state_timestamp = get_fmt_time();

	// change the values for the cluster state as a last step
	prep_group_replication_init_state_err =
		prepare_grouprep_cluster_state(
			proxysql_sqlite, grouprep_init_servers_state, hostgroup_attributes.empty() ? 1 : 2
		);

	if (prep_group_replication_init_state_err.first) {
		result = invalid_config_error(prep_group_replication_init_state_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// final LOAD after all the configuration has been setup
	load_to_run_err = mysql_query(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	if (load_to_run_err) {
		const auto& query_err =
			create_query_error(
				proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME", __FILE__, __LINE__
			);
		result = internal_error(query_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// ************************** VERIFICATION *********************************
	{
		int grouprep_interval = 0;
		int grouprep_timeout = 0;

		std::pair<int, std::string> get_monitor_times_err =
			get_grouprep_monitor_check_times(proxysql_admin, grouprep_interval, grouprep_timeout);
		if (get_monitor_times_err.first) {
			result = internal_error(get_monitor_times_err.second, __FILE__, __LINE__);
			goto exit;
		}

		// map the values to secs
		double grouprep_interval_s = static_cast<double>(grouprep_interval) / 1000;
		double grouprep_timeout_s = static_cast<double>(grouprep_timeout) / 1000;

		// proper waiting for monitor timing
		double sleep_delay =
			grouprep_interval_s + mysql_servers.size()*grouprep_timeout_s*0.1 + 1;

		usleep(sleep_delay * pow(10, 6));

		string init_state_timestamp { get_fmt_time() };

		// check that the current cluster state matches the expected one
		std::vector<server_status> init_cluster_status {};
		const auto& init_cluster_st_err =
			get_current_cluster_status(proxysql_admin, init_cluster_status);

		if (init_cluster_st_err.first) {
			result = internal_error(
				"'get_current_cluster_status' failed for 'init_state': '" +
				init_cluster_st_err.second + "'",
				__FILE__, __LINE__
			);
			goto exit;
		}

		// check the initial cluster status is the expected one
		if (!check_cluster_status(exp_init_cluster_status, init_cluster_status)) {
			result = verification_error(
				"Expected 'proxysql_init_state' doesn't match actual cluster state",
				exp_init_cluster_status,
				init_cluster_status,
				{},
				setup_state_timestamp,
				init_state_timestamp
			);
			goto exit;
		}

		// detect the changes that are going to be imposed
		const auto& state_diff =
			grouprep_servers_state_diff(grouprep_init_servers_state, grouprep_new_servers_state);

		// set the new servers state
		const auto& group_replication_new_state_to_set =
			grouprep_update_cluster_state(grouprep_init_servers_state, grouprep_new_servers_state);
		prep_group_replication_final_state_err =
			prepare_grouprep_cluster_state(proxysql_sqlite, grouprep_new_servers_state);

		if (prep_group_replication_final_state_err.first) {
			result = internal_error(prep_group_replication_final_state_err.second, __FILE__, __LINE__);
			goto exit;
		}

		// sleep for monitor ot reconfigure the servers
		usleep(sleep_delay * pow(10, 6));

		string final_state_timestamp { get_fmt_time() };

		// check that the final cluster state matches the expected one
		std::vector<server_status> final_cluster_status {};
		const auto& final_cluster_st_err =
			get_current_cluster_status(proxysql_admin, final_cluster_status);

		if (final_cluster_st_err.first) {
			result = internal_error(
				"'get_current_cluster_status' failed for 'final_state': '" +
				final_cluster_st_err.second + "'",
				__FILE__, __LINE__
			);
			goto exit;
		}

		// if we are just simulating no further operations are needed
		if (op_mode == operation_mode::simulate) {
			ordered_json j_final_cluster_status = cluster_status_to_json(final_cluster_status);
			std::string init_state_checksum = cluster_status_checksum(init_cluster_status);
			std::string final_state_checksum = cluster_status_checksum(final_cluster_status);

			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json {
					{ "err_type", "none" },
					{ "result", nlohmann::ordered_json {} }
				}
			};

			bool has_monitor_config =
				check_present_and_type(j_test_definition, {"mysql_monitor_config"}, json::value_t::array);

			result.second["result"]["cluster_type"] = "GROUP_REPLICATION";
			result.second["result"]["mysql_servers"] = j_test_definition.at("mysql_servers");
			result.second["result"]["mysql_group_replication_hostgroups"] = j_test_definition.at("mysql_group_replication_hostgroups");
			if (has_monitor_config) {
				result.second["result"]["mysql_monitor_config"] = j_test_definition.at("mysql_monitor_config");
			}
			result.second["result"]["grouprep_servers_init_state"] = j_test_definition.at("grouprep_servers_init_state");
			result.second["result"]["grouprep_servers_new_state"] = j_test_definition.at("grouprep_servers_new_state");
			result.second["result"]["proxysql_init_state_checksum"] = init_state_checksum;
			result.second["result"]["proxysql_init_state"] = j_test_definition.at("proxysql_init_state");
			result.second["result"]["proxysql_init_state_timestamp"] = init_state_timestamp;
			result.second["result"]["proxysql_final_state_checksum"] = final_state_checksum;
			result.second["result"]["proxysql_final_state"] = j_final_cluster_status;
			result.second["result"]["proxysql_final_state_timestamp"] = final_state_timestamp;

			goto exit;
		}

		if (!check_cluster_status(exp_final_cluster_status, final_cluster_status)) {
			result = verification_error(
				"Expected 'proxysql_final_state' doesn't match actual cluster state",
				exp_final_cluster_status,
				final_cluster_status,
				state_diff,
				init_state_timestamp,
				final_state_timestamp
			);
			goto exit;
		}

		if (verbose) {
			ordered_json j_init_cluster_status = cluster_status_to_json(init_cluster_status);
			ordered_json j_final_cluster_status = cluster_status_to_json(final_cluster_status);
			std::string init_state_checksum = cluster_status_checksum(init_cluster_status);
			std::string final_state_checksum = cluster_status_checksum(final_cluster_status);

			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json {
					{ "err_type", "none" },
					{ "result", nlohmann::ordered_json {} }
				}
			};

			bool has_monitor_config =
				check_present_and_type(j_test_definition, {"mysql_monitor_config"}, json::value_t::array);

			result.second["result"]["err_type"] = "none";
			result.second["result"]["err_msg"] = "";
			result.second["result"]["cluster_type"] = "GROUP_REPLICATION";
			result.second["result"]["mysql_servers"] = j_test_definition.at("mysql_servers");
			result.second["result"]["mysql_group_replication_hostgroups"] = j_test_definition.at("mysql_group_replication_hostgroups");
			if (has_monitor_config) {
				result.second["result"]["mysql_monitor_config"] = j_test_definition.at("mysql_monitor_config");
			}
			result.second["result"]["grouprep_servers_init_state"] = j_test_definition.at("grouprep_servers_init_state");
			result.second["result"]["grouprep_servers_new_state"] = j_test_definition.at("grouprep_servers_new_state");
			result.second["result"]["proxysql_init_state_timestamp"] = init_state_timestamp;
			result.second["result"]["proxysql_init_state_checksum"] = init_state_checksum;
			result.second["result"]["proxysql_init_state"] = j_init_cluster_status;
			result.second["result"]["proxysql_final_state_checksum"] = final_state_checksum;
			result.second["result"]["proxysql_final_state_timestamp"] = final_state_timestamp;
			result.second["result"]["proxysql_final_state"] = j_final_cluster_status;
		} else {
			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json { { "err_type", "none" }, { "err_msg", "" } },
			};
		}
	}

exit:

	return result;
}

std::pair<int, nlohmann::ordered_json> simulate_mysql_replicationlag_cluster_state(
	MYSQL* proxysql_admin,
	MYSQL* proxysql_sqlite,
	const json& j_test_definition,
	const operation_mode& op_mode,
	const bool verbose = false
) {
	std::pair<int, nlohmann::ordered_json> result{};

	std::vector<mysql_server_def> mysql_servers{};
	std::vector<monitor_variable> monitor_variables{};
	std::vector<replicationlag_server_state> replicationlag_init_servers_state{};
	std::vector<replicationlag_server_state> replicationlag_new_servers_state{};
	std::vector<hostgroup_attributes_def> hostgroup_attributes {};

	// the expected initial cluster servers status
	std::vector<server_status> exp_init_cluster_status{};
	// the expected final cluster servers status
	std::vector<server_status> exp_final_cluster_status{};

	// validations errors from extracting the required values from the JSON payload
	std::pair<int, std::string> ext_mysql_srvs_err{};
	std::pair<int, std::string> ext_hostgroup_attributes_err{};
	std::pair<int, std::string> ext_replication_conf_err{};
	std::pair<int, std::string> ext_monitor_conf_err{};
	std::pair<int, std::string> ext_replicationlag_init_srvs_state_err{};
	std::pair<int, std::string> ext_replicationlag_next_srvs_state_err{};
	std::pair<int, std::string> ext_init_cluster_status_err{};
	std::pair<int, std::string> ext_final_cluster_status_err{};

	// errors from applying the required configuration to ProxySQL
	std::pair<int, std::string> prep_replication_init_state_err{};
	std::pair<int, std::string> prep_replication_final_state_err{};
	std::pair<int, std::string> prep_mysql_servers_conf_err{};
	std::pair<int, std::string> prep_mysql_hostgroup_attributes_conf_err {};
	std::pair<int, std::string> set_monitor_variables_err{};
	std::pair<int, std::string> set_monitor_tos_err{};
	int load_to_run_err = 0;

	const std::vector<std::string> rephostgrp_monitor_variables{
		"monitor_replication_lag_count",
		"monitor_slave_lag_when_null"
	};

	const std::vector<monitor_variable> monitor_defaults_variables{
		{ "monitor_replication_lag_count", 1 },
		{ "monitor_slave_lag_when_null", 60 }
	};

	// **************************  VALIDATION  ********************************

	ext_mysql_srvs_err = extract_mysql_servers(j_test_definition, mysql_servers);

	if (ext_mysql_srvs_err.first) {
		result = invalid_json_error(
			ext_mysql_srvs_err.second, __FILE__, __LINE__
		);

		goto exit;
	}

	ext_hostgroup_attributes_err = extract_mysql_hostgroup_attributes(j_test_definition, hostgroup_attributes);
	if (ext_hostgroup_attributes_err.first) {
		result = invalid_json_error(ext_hostgroup_attributes_err.second, __FILE__, __LINE__);

		goto exit;
	}

	ext_monitor_conf_err =
		extract_monitor_config(j_test_definition, monitor_variables);

	if (ext_monitor_conf_err.first) {
		result = invalid_json_error(
			ext_monitor_conf_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_replicationlag_init_srvs_state_err =
		extract_replicationlag_servers_state(
			replicationlag_state_id::init_state,
			j_test_definition,
			replicationlag_init_servers_state
		);

	if (ext_replicationlag_init_srvs_state_err.first) {
		result = invalid_json_error(
			ext_replicationlag_init_srvs_state_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_init_cluster_status_err =
		extract_cluster_status(
			cluster_state::init_state,
			j_test_definition,
			exp_init_cluster_status
		);

	if (ext_init_cluster_status_err.first) {
		result = invalid_json_error(
			ext_init_cluster_status_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_final_cluster_status_err =
		extract_cluster_status(
			cluster_state::final_state,
			j_test_definition,
			exp_final_cluster_status
		);

	if (ext_final_cluster_status_err.first) {
		result = invalid_json_error(
			ext_final_cluster_status_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_replicationlag_next_srvs_state_err =
		extract_replicationlag_servers_state(
			replicationlag_state_id::new_state,
			j_test_definition,
			replicationlag_new_servers_state
		);

	if (ext_replicationlag_next_srvs_state_err.first) {
		result = invalid_json_error(
			ext_replicationlag_next_srvs_state_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	// ************************ CONFIGURATION  ********************************

	prep_mysql_servers_conf_err =
		prepare_mysql_servers_config(proxysql_admin, mysql_servers);
	if (prep_mysql_servers_conf_err.first) {
		result = invalid_config_error(prep_mysql_servers_conf_err.second, __FILE__, __LINE__);
		goto exit;
	}

	if (!hostgroup_attributes.empty()) {
		prep_mysql_hostgroup_attributes_conf_err =
			prepare_mysql_hostgroup_attributes_config(proxysql_admin, hostgroup_attributes);
		if (prep_mysql_hostgroup_attributes_conf_err.first) {
			result = invalid_config_error(prep_mysql_hostgroup_attributes_conf_err.second, __FILE__, __LINE__);
			goto exit;
		}
	}

	// final LOAD after all the configuration has been setup
	load_to_run_err = mysql_query(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	if (load_to_run_err) {
		const auto& query_err =
			create_query_error(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME", __FILE__, __LINE__);
		result = internal_error(query_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// give the variables some defaults if they are not present
	monitor_variables = set_monitor_variables_defaults(
		monitor_variables, monitor_defaults_variables
	);

	// prepare monitor variables
	set_monitor_variables_err =
		set_monitor_variables(
			proxysql_admin, rephostgrp_monitor_variables, monitor_variables
		);

	// final LOAD for 'mysql' variables after configuration has been setup
	load_to_run_err = mysql_query(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	if (load_to_run_err) {
		const auto& query_err =
			create_query_error(
				proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME", __FILE__, __LINE__
			);
		result = internal_error(query_err.second, __FILE__, __LINE__);
		goto exit;
	}

	set_monitor_tos_err = set_replicationlag_monitor_check_times(proxysql_admin);
	if (set_monitor_tos_err.first) {
		result = internal_error(set_monitor_tos_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// change the values for the cluster state as a last step
	prep_replication_init_state_err =
		prepare_replicationlag_cluster_state(proxysql_sqlite, replicationlag_init_servers_state, true);

	if (prep_replication_init_state_err.first) {
		result = invalid_config_error(prep_replication_init_state_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// ************************** VERIFICATION *********************************
	{
		int replicationlag_interval = 0;
		int replicationlag_timeout = 0;

		std::pair<int, std::string> get_monitor_times_err =
			get_replicationlag_monitor_check_times(proxysql_admin, replicationlag_interval, replicationlag_timeout);
		if (get_monitor_times_err.first) {
			result = internal_error(get_monitor_times_err.second, __FILE__, __LINE__);
			goto exit;
		}

		// map the values to secs
		double replicationlag_interval_s = static_cast<double>(replicationlag_interval) / 1000;
		double replicationlag_timeout_s = static_cast<double>(replicationlag_timeout) / 1000;

		// proper waiting for monitor timing
		double sleep_delay =
			replicationlag_interval_s + mysql_servers.size() * replicationlag_timeout_s * 0.1 + 1;

		usleep(sleep_delay * pow(10, 6));

		// check that the current cluster state matches the expected one
		std::vector<server_status> init_cluster_status{};
		const auto& init_cluster_st_err =
			get_current_cluster_status(proxysql_admin, init_cluster_status);

		if (init_cluster_st_err.first) {
			result = internal_error(
				"'get_current_cluster_status' failed for 'init_state': '" +
				init_cluster_st_err.second + "'",
				__FILE__, __LINE__
			);
			goto exit;
		}

		// check the initial cluster status is the expected one
		if (!check_cluster_status(exp_init_cluster_status, init_cluster_status)) {
			result = verification_error(
				"Expected 'proxysql_init_state' doesn't match actual cluster state",
				exp_init_cluster_status,
				init_cluster_status,
				{}
			);
			goto exit;
		}

		// detect the changes that are going to be imposed
		const auto& state_diff =
			replicationlag_servers_state_diff(replicationlag_init_servers_state, replicationlag_new_servers_state);

		// set the new servers state
		const auto& replication_new_state_to_set =
			replicationlag_update_cluster_state(replicationlag_init_servers_state, replicationlag_new_servers_state);
		prep_replication_final_state_err =
			prepare_replicationlag_cluster_state(proxysql_sqlite, replicationlag_new_servers_state);

		if (prep_replication_final_state_err.first) {
			result = internal_error(prep_replication_final_state_err.second, __FILE__, __LINE__);
			goto exit;
		}

		// sleep for monitor ot reconfigure the servers
		usleep(sleep_delay * pow(10, 6));

		// check that the final cluster state matches the expected one
		std::vector<server_status> final_cluster_status{};
		const auto& final_cluster_st_err =
			get_current_cluster_status(proxysql_admin, final_cluster_status);

		if (final_cluster_st_err.first) {
			result = internal_error(
				"'get_current_cluster_status' failed for 'final_state': '" +
				final_cluster_st_err.second + "'",
				__FILE__, __LINE__
			);
			goto exit;
		}

		// if we are just simulating no further operations are needed
		if (op_mode == operation_mode::simulate) {
			json j_final_cluster_status = cluster_status_to_json(final_cluster_status);
			std::string init_state_checksum = cluster_status_checksum(init_cluster_status);
			std::string final_state_checksum = cluster_status_checksum(final_cluster_status);

			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json {
					{ "err_type", "none" },
					{ "result",
						nlohmann::ordered_json {
							{ "cluster_type", "replicationlag" },
							{ "mysql_servers", j_test_definition.at("mysql_servers") },
							{ "replicationlag_servers_init_state", j_test_definition.at("replicationlag_servers_init_state") },
							{ "replicationlag_servers_new_state", j_test_definition.at("replicationlag_servers_new_state") },
							{ "proxysql_init_state_checksum", init_state_checksum },
							{ "proxysql_init_state", j_test_definition.at("proxysql_init_state") },
							{ "proxysql_final_state_checksum", final_state_checksum },
							{ "proxysql_final_state", j_final_cluster_status },
						}
					}
				}
			};

			bool has_monitor_config =
				check_present_and_type(j_test_definition, { "mysql_monitor_config" }, json::value_t::array);

			if (has_monitor_config) {
				result.second["result"]["mysql_monitor_config"] = j_test_definition.at("mysql_monitor_config");
			}

			bool has_hostgroup_attributes =
				check_present_and_type(j_test_definition, { "mysql_hostgroup_attributes" }, json::value_t::array);

			if (has_hostgroup_attributes) {
				result.second["result"]["mysql_hostgroup_attributes"] = j_test_definition.at("mysql_hostgroup_attributes");
			}

			goto exit;
		}

		if (!check_cluster_status(exp_final_cluster_status, final_cluster_status)) {
			result = verification_error(
				"Expected 'proxysql_final_state' doesn't match actual cluster state",
				exp_final_cluster_status,
				final_cluster_status,
				state_diff
			);
			goto exit;
		}

		if (verbose) {
			json j_init_cluster_status = cluster_status_to_json(init_cluster_status);
			json j_final_cluster_status = cluster_status_to_json(final_cluster_status);
			std::string init_state_checksum = cluster_status_checksum(init_cluster_status);
			std::string final_state_checksum = cluster_status_checksum(final_cluster_status);

			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json {
					{ "err_type", "none" },
					{ "result",
						nlohmann::ordered_json {
							{ "err_type", "none" },
							{ "err_msg", "" },
							{ "cluster_type", "REPLICATION_LAG" },
							{ "mysql_servers", j_test_definition.at("mysql_servers") },
							{ "replicationlag_servers_init_state", j_test_definition.at("replicationlag_servers_init_state") },
							{ "replicationlag_servers_new_state", j_test_definition.at("replicationlag_servers_new_state") },
							{ "proxysql_init_state_checksum", init_state_checksum },
							{ "proxysql_init_state", j_init_cluster_status },
							{ "proxysql_final_state_checksum", final_state_checksum },
							{ "proxysql_final_state", j_final_cluster_status },
						}
					}
				}
			};

			bool has_monitor_config =
				check_present_and_type(j_test_definition, { "mysql_monitor_config" }, json::value_t::array);

			if (has_monitor_config) {
				result.second["result"]["mysql_monitor_config"] = j_test_definition.at("mysql_monitor_config");
			}

			bool has_hostgroup_attributes =
				check_present_and_type(j_test_definition, { "mysql_hostgroup_attributes" }, json::value_t::array);

			if (has_hostgroup_attributes) {
				result.second["result"]["mysql_hostgroup_attributes"] = j_test_definition.at("mysql_hostgroup_attributes");
			}

		}
		else {
			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json { { "err_type", "none" }, { "err_msg", "" } },
			};
		}
	}

exit:

	return result;
}

std::pair<int, nlohmann::ordered_json> simulate_aws_aurora_cluster_state(
	MYSQL* proxysql_admin,
	MYSQL* proxysql_sqlite,
	const json& j_test_definition,
	const operation_mode& op_mode,
	const bool verbose = false
) {
	std::pair<int, nlohmann::ordered_json> result {};

	std::vector<mysql_server_def> mysql_servers {};
	std::vector<hostgroup_attributes_def> hostgroup_attributes {};
	std::vector<monitor_variable> monitor_variables {};
	std::vector<aurora_hostgroup_config_t> aurora_hostgroups {};

	std::vector<aurora_server_state_t> aurora_init_servers_state {};
	std::vector<aurora_server_state_t> aurora_new_servers_state {};

	// the expected initial cluster servers status
	std::vector<server_status> exp_init_cluster_status {};
	// the expected final cluster servers status
	std::vector<server_status> exp_final_cluster_status {};

	// validations errors from extracting the required values from the JSON payload
	std::pair<int, std::string> ext_mysql_srvs_err {};
	std::pair<int, std::string> ext_hostgroup_attributes_err {};
	std::pair<int, std::string> ext_aurora_conf_err {};
	std::pair<int, std::string> ext_monitor_conf_err {};
	std::pair<int, std::string> ext_aurora_init_srvs_state_err {};
	std::pair<int, std::string> ext_aurora_next_srvs_state_err {};
	std::pair<int, std::string> ext_init_cluster_status_err {};
	std::pair<int, std::string> ext_final_cluster_status_err {};

	// errors from applying the required configuration to ProxySQL
	std::pair<int, std::string> prep_aurora_hostgroups_err {};
	std::pair<int, std::string> prep_aurora_init_state_err {};
	std::pair<int, std::string> prep_aurora_final_state_err {};
	std::pair<int, std::string> prep_mysql_servers_conf_err {};
	std::pair<int, std::string> prep_mysql_hostgroup_attributes_conf_err {};
	std::pair<int, std::string> set_monitor_tos_err {};
	std::pair<int, std::string> set_monitor_variables_err {};
	int load_to_run_err = 0;

	string setup_state_timestamp {};

	const std::vector<std::string> aurora_monitor_variables {
		"mysql-aurora_max_lag_ms_only_read_from_replicas"
	};

	const std::vector<monitor_variable> monitor_defaults_variables {
		{ "mysql-aurora_max_lag_ms_only_read_from_replicas", 2 }
	};
	// **************************  VALIDATION  ********************************

	ext_mysql_srvs_err = extract_mysql_servers(j_test_definition, mysql_servers);

	if (ext_mysql_srvs_err.first) {
		result = invalid_json_error(ext_mysql_srvs_err.second, __FILE__, __LINE__);
		goto exit;
	}

	ext_hostgroup_attributes_err = extract_mysql_hostgroup_attributes(j_test_definition, hostgroup_attributes);
	if (ext_hostgroup_attributes_err.first) {
		result = invalid_json_error(ext_hostgroup_attributes_err.second, __FILE__, __LINE__);

		goto exit;
	}

	ext_aurora_conf_err =
		extract_aurora_hostgroup_config(j_test_definition, aurora_hostgroups);

	if (ext_aurora_conf_err.first) {
		result = invalid_json_error(ext_aurora_conf_err.second, __FILE__, __LINE__);
		goto exit;
	}

	ext_monitor_conf_err =
		extract_monitor_config(j_test_definition, monitor_variables);

	if (ext_monitor_conf_err.first) {
		result = invalid_json_error(ext_monitor_conf_err.second, __FILE__, __LINE__);
		goto exit;
	}

	ext_aurora_init_srvs_state_err =
		extract_aurora_servers_state(
			aurora_state_id::init_state, j_test_definition, aurora_init_servers_state
		);

	if (ext_aurora_init_srvs_state_err.first) {
		result = invalid_json_error(
			ext_aurora_init_srvs_state_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_init_cluster_status_err =
		extract_cluster_status(
			cluster_state::init_state, j_test_definition, exp_init_cluster_status
		);

	if (ext_init_cluster_status_err.first) {
		result = invalid_json_error(
			ext_init_cluster_status_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_final_cluster_status_err =
		extract_cluster_status(
			cluster_state::final_state,
			j_test_definition,
			exp_final_cluster_status
		);

	if (ext_final_cluster_status_err.first) {
		result = invalid_json_error(
			ext_final_cluster_status_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	ext_aurora_next_srvs_state_err =
		extract_aurora_servers_state(
			aurora_state_id::new_state, j_test_definition, aurora_new_servers_state
		);

	if (ext_aurora_next_srvs_state_err.first) {
		result = invalid_json_error(
			ext_aurora_next_srvs_state_err.second, __FILE__, __LINE__
		);
		goto exit;
	}

	// ************************ CONFIGURATION  ********************************

	prep_mysql_servers_conf_err = prepare_mysql_servers_config(proxysql_admin, mysql_servers);
	if (prep_mysql_servers_conf_err.first) {
		result = invalid_config_error(prep_mysql_servers_conf_err.second, __FILE__, __LINE__);
		goto exit;
	}

	if (!hostgroup_attributes.empty()) {
		prep_mysql_hostgroup_attributes_conf_err =
			prepare_mysql_hostgroup_attributes_config(proxysql_admin, hostgroup_attributes);
		if (prep_mysql_hostgroup_attributes_conf_err.first) {
			result = invalid_config_error(prep_mysql_hostgroup_attributes_conf_err.second, __FILE__, __LINE__);
			goto exit;
		}
	}

	prep_aurora_hostgroups_err = prepare_mysql_aurora_hostgroups(proxysql_admin, aurora_hostgroups);
	if (prep_aurora_hostgroups_err.first) {
		result = invalid_config_error(prep_aurora_hostgroups_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// give the variables some defaults if they are not present
	monitor_variables = set_monitor_variables_defaults(
		monitor_variables, monitor_defaults_variables
	);

	// prepare monitor variables
	set_monitor_variables_err =
		set_monitor_variables(
			proxysql_admin, aurora_monitor_variables, monitor_variables
		);

	// final LOAD for 'mysql' variables after configuration has been setup
	load_to_run_err = mysql_query(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	if (load_to_run_err) {
		const auto& query_err {
			create_query_error(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME", __FILE__, __LINE__)
		};
		result = internal_error(query_err.second, __FILE__, __LINE__);
		goto exit;
	}

	setup_state_timestamp = get_fmt_time();

	// change the values for the cluster state as a last step
	prep_aurora_init_state_err =
		prepare_aurora_cluster_state(
			proxysql_sqlite,
			aurora_init_servers_state,
			aurora_publication_mode::reset_scenario
		);

	if (prep_aurora_init_state_err.first) {
		result = invalid_config_error(prep_aurora_init_state_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// final LOAD after all the configuration has been setup
	load_to_run_err = mysql_query(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	if (load_to_run_err) {
		const auto& query_err =
			create_query_error(
				proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME", __FILE__, __LINE__
			);
		result = internal_error(query_err.second, __FILE__, __LINE__);
		goto exit;
	}

	// ************************** VERIFICATION *********************************
	{
		int aurora_interval = 0;
		int aurora_timeout = 0;

		std::pair<int, std::string> get_monitor_times_err =
			get_aurora_monitor_check_times(proxysql_admin, aurora_interval, aurora_timeout);
		if (get_monitor_times_err.first) {
			result = internal_error(get_monitor_times_err.second, __FILE__, __LINE__);
			goto exit;
		}

		// map the values to secs
		double aurora_interval_s = static_cast<double>(aurora_interval) / 1000;
		double aurora_timeout_s = static_cast<double>(aurora_timeout) / 1000;

		// proper waiting for monitor timing
		double sleep_delay =
			aurora_interval_s + mysql_servers.size()*aurora_timeout_s*0.1 + 1;

		usleep(sleep_delay * pow(10, 6));

		string init_state_timestamp { get_fmt_time() };

		// check that the current cluster state matches the expected one
		std::vector<server_status> init_cluster_status {};
		const auto& init_cluster_st_err =
			get_current_cluster_status(proxysql_admin, init_cluster_status);

		if (init_cluster_st_err.first) {
			result = internal_error(
				"'get_current_cluster_status' failed for 'init_state': '" +
				init_cluster_st_err.second + "'",
				__FILE__, __LINE__
			);
			goto exit;
		}

		// check the initial cluster status is the expected one
		if (!check_cluster_status(exp_init_cluster_status, init_cluster_status)) {
			result = verification_error(
				"Expected 'proxysql_init_state' doesn't match actual cluster state",
				exp_init_cluster_status,
				init_cluster_status,
				{},
				setup_state_timestamp,
				init_state_timestamp
			);
			goto exit;
		}

		// detect the changes that are going to be imposed
		const auto& state_diff {
			aurora_servers_state_diff(aurora_init_servers_state, aurora_new_servers_state)
		};

		// Replace the published replica sets and their complete backend mappings so
		// payloads can simulate members being removed (for example, autopurge coverage).
		prep_aurora_final_state_err = prepare_aurora_cluster_state(
			proxysql_sqlite,
			aurora_new_servers_state,
			aurora_publication_mode::replace_snapshot_retaining_backends
		);

		if (prep_aurora_final_state_err.first) {
			result = internal_error(prep_aurora_final_state_err.second, __FILE__, __LINE__);
			goto exit;
		}

		// sleep for monitor ot reconfigure the servers
		usleep(sleep_delay * pow(10, 6));
		string final_state_timestamp { get_fmt_time() };

		// check that the final cluster state matches the expected one
		std::vector<server_status> final_cluster_status {};
		const auto& final_cluster_st_err { get_current_cluster_status(proxysql_admin, final_cluster_status) };

		if (final_cluster_st_err.first) {
			result = internal_error(
				"'get_current_cluster_status' failed for 'final_state': '" +
				final_cluster_st_err.second + "'",
				__FILE__, __LINE__
			);
			goto exit;
		}

		// if we are just simulating no further operations are needed
		if (op_mode == operation_mode::simulate) {
			ordered_json j_final_cluster_status = cluster_status_to_json(final_cluster_status);
			std::string init_state_checksum = cluster_status_checksum(init_cluster_status);
			std::string final_state_checksum = cluster_status_checksum(final_cluster_status);

			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json {
					{ "err_type", "none" },
					{ "result", nlohmann::ordered_json {} }
				}
			};

			bool has_monitor_config {
				check_present_and_type(j_test_definition, {"mysql_monitor_config"}, json::value_t::array)
			};

			result.second["result"]["cluster_type"] = "AURORA";
			result.second["result"]["mysql_servers"] = j_test_definition.at("mysql_servers");
            result.second["result"]["mysql_aws_aurora_hostgroups"] = j_test_definition.at("mysql_aws_aurora_hostgroups");
			if (has_monitor_config) {
				result.second["result"]["mysql_monitor_config"] = j_test_definition.at("mysql_monitor_config");
			}
			result.second["result"]["aurora_servers_init_state"] = j_test_definition.at("aurora_servers_init_state");
			result.second["result"]["aurora_servers_new_state"] = j_test_definition.at("aurora_servers_new_state");
			result.second["result"]["proxysql_init_state_checksum"] = init_state_checksum;
			result.second["result"]["proxysql_init_state"] = j_test_definition.at("proxysql_init_state");
			result.second["result"]["proxysql_init_state_timestamp"] = init_state_timestamp;
			result.second["result"]["proxysql_final_state_checksum"] = final_state_checksum;
			result.second["result"]["proxysql_final_state"] = j_final_cluster_status;
			result.second["result"]["proxysql_final_state_timestamp"] = final_state_timestamp;

			goto exit;
		}

		if (!check_cluster_status(exp_final_cluster_status, final_cluster_status)) {
			result = verification_error(
				"Expected 'proxysql_final_state' doesn't match actual cluster state",
				exp_final_cluster_status,
				final_cluster_status,
				state_diff,
				init_state_timestamp,
				final_state_timestamp
			);
			goto exit;
		}

		if (verbose) {
			ordered_json j_init_cluster_status = cluster_status_to_json(init_cluster_status);
			ordered_json j_final_cluster_status = cluster_status_to_json(final_cluster_status);
			std::string init_state_checksum = cluster_status_checksum(init_cluster_status);
			std::string final_state_checksum = cluster_status_checksum(final_cluster_status);

			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json {
					{ "err_type", "none" },
					{ "result", nlohmann::ordered_json {} }
				}
			};

			bool has_monitor_config =
				check_present_and_type(j_test_definition, {"mysql_monitor_config"}, json::value_t::array);

			result.second["result"]["err_type"] = "none";
			result.second["result"]["err_msg"] = "";
			result.second["result"]["cluster_type"] = "AURORA";
			result.second["result"]["mysql_servers"] = j_test_definition.at("mysql_servers");
            result.second["result"]["mysql_aws_aurora_hostgroups"] = j_test_definition.at("mysql_aws_aurora_hostgroups");
			if (has_monitor_config) {
				result.second["result"]["mysql_monitor_config"] = j_test_definition.at("mysql_monitor_config");
			}
			result.second["result"]["aurora_servers_init_state"] = j_test_definition.at("aurora_servers_init_state");
			result.second["result"]["aurora_servers_new_state"] = j_test_definition.at("aurora_servers_new_state");
			result.second["result"]["proxysql_init_state_timestamp"] = init_state_timestamp;
			result.second["result"]["proxysql_init_state_checksum"] = init_state_checksum;
			result.second["result"]["proxysql_init_state"] = j_init_cluster_status;
			result.second["result"]["proxysql_final_state_checksum"] = final_state_checksum;
			result.second["result"]["proxysql_final_state_timestamp"] = final_state_timestamp;
			result.second["result"]["proxysql_final_state"] = j_final_cluster_status;
		} else {
			result = {
				EXIT_SUCCESS,
				nlohmann::ordered_json { { "err_type", "none" }, { "err_msg", "" } },
			};
		}
	}

exit:

	return result;
}

/**
 * @brief Enum holding the types of payloads supported by the
 *   simulator.
 */
enum class test_def_type {
	UNSUPPORTED = -1,
	GALERA_CLUSTER = 0,
	READONLY_TEST,
	GROUP_REPLICATION,
	REPLICATION_LAG,
	AWS_AURORA
};

/**
 * @brief Retrieve the type of the supplied test file.
 *
 * @param j_test_definition The JSON holding the test definition.
 * @param test_type A reference to the 'test type' to be retrieved.
 *
 * @return A `std::pair` of kind `{ err_code, "err_msg" }`.
 */
std::pair<int, std::string> get_test_type(
	const nlohmann::ordered_json& j_test_definition,
	enum test_def_type& test_type
) {
	std::pair<int, std::string> result { EXIT_SUCCESS, "" };

	try {
		const std::string cluster_type = j_test_definition.at("cluster_type");

		if (cluster_type == "GALERA") {
			test_type = test_def_type::GALERA_CLUSTER;
		} else if (cluster_type == "READ_ONLY") {
			test_type = test_def_type::READONLY_TEST;
		} else if (cluster_type == "GROUP_REPLICATION") {
			test_type = test_def_type::GROUP_REPLICATION;
		} else if (cluster_type == "REPLICATION_LAG") {
			test_type = test_def_type::REPLICATION_LAG;
		} else if (cluster_type == "AURORA") {
			test_type = test_def_type::AWS_AURORA;
		} else {
			test_type = test_def_type::UNSUPPORTED;
			// Specify the error
			result = { EXIT_FAILURE, "Unsupported 'cluster_type'" };
		}
	} catch (const std::exception& e) {
		result = {
			EXIT_FAILURE,
			std::string { "Exception trying to access supplied JSON: '" } + e.what() + "'",
		};
		test_type = test_def_type::UNSUPPORTED;
	}

	return result;
}

std::pair<int, std::string> get_cmd_options(
	int argc, const char* argv[], simulator_options& out_sim_options
) {
	std::pair<int, std::string> err_res { EXIT_SUCCESS, "" };

	// command line options to extract
	bool enable_verbose_output = false;
	bool stop_on_failure = false;
	operation_mode op_mode = operation_mode::simulate;
	std::string payload_path {};

	// define the command line options
	ez::ezOptionParser opt {};
	opt.overview = "Generic Cluster Simulator for ProxySQL";
	opt.syntax = "cluster_simulator [OPTIONS]";
	opt.footer = "\n\nHave fun :)";

	// clang-format off
	opt.add(
		(const char *)"", 0, 0, 0, (const char *)"Display usage instructions.",
		(const char *)"-h", (const char *)"-help", (const char *)"--help", (const char *)"--usage"
	);
	opt.add(
		(const char *)"", 0, 0, 0, (const char *)"Enable verbose output",
		(const char *)"-v", (const char *)"--verbose"
	);
	opt.add(
		(const char *)"simulate", 0, 1, 0, (const char *)"Operation mode",
		(const char *)"-m", (const char *)"--mode"
	);
	opt.add(
		(const char *)"", 0, 0, 0, (const char *)"Stop on failure",
		(const char *)"--stop-on-failure"
	);
	opt.add(
		(const char *)"", 1, 1, 0, (const char *)"Specify input payload file",
		(const char *)"-f", (const char *)"--file"
	);
	// clang-format on

	// parse the arguments
	opt.parse(argc, argv);

	// extract command line options
	if (opt.isSet("-h")) {
		std::string usage {};
		opt.getUsage(usage);
		std::cout << usage << std::endl;

		exit(EXIT_SUCCESS);
	}
	if (opt.isSet("-v")) {
		enable_verbose_output = true;
	}
	if (opt.isSet("--stop-on-failure")) {
		stop_on_failure = true;
	}
	if (opt.isSet("-m")) {
		std::string s_op_mode {};
		opt.get("-m")->getString(s_op_mode);

		if (s_op_mode == "simulate") {
			op_mode = operation_mode::simulate;
		} else if (s_op_mode == "verify") {
			op_mode = operation_mode::verify;
		} else {
			std::string t_err_msg { "File %s, line %d, Error: %s" };
			std::string err_msg {};
			string_format(
				t_err_msg, err_msg, __FILE__, __LINE__,
				"Invalid '--mode' supplied"
			);
			err_res = { EXIT_FAILURE, err_msg };
		}
	}
	if (opt.isSet("-f")) {
		opt.get("-f")->getString(payload_path);

		if (payload_path.empty()) {
			std::string t_err_msg { "File %s, line %d, Error: %s" };
			std::string err_msg {};
			string_format(
				t_err_msg, err_msg, __FILE__, __LINE__,
				"Empty string supplied to parameter '--file'"
			);
			err_res = { EXIT_FAILURE, err_msg };
		}
	} else {
		std::string t_err_msg { "File %s, line %d, Error: %s" };
		std::string err_msg {};
		string_format(
			t_err_msg, err_msg, __FILE__, __LINE__,
			"Missing required parameter '--file'"
		);
		err_res = { EXIT_FAILURE, err_msg };
	}

	// check if arguments has been properly extracted
	if (err_res.first == EXIT_SUCCESS) {
		// option struct to be filled and returned
		simulator_options sim_options {};

		sim_options.verbose_output = enable_verbose_output;
		sim_options.op_mode = op_mode;
		sim_options.payload_path = payload_path;
		sim_options.stop_on_failure = stop_on_failure;

		// fill the output parameter
		out_sim_options = sim_options;
	}

	return err_res;
}

// Per-family SQLiteServer endpoints — env var overrides with legacy defaults.
static std::string env_or(const char* name, const std::string& def) {
	const char* v = std::getenv(name);
	return (v != nullptr && *v != '\0') ? std::string { v } : def;
}
static int env_or(const char* name, int def) {
	const char* v = std::getenv(name);
	if (v == nullptr || *v == '\0') { return def; }
	try { return std::stoi(v); } catch (const std::exception&) { return def; }
}

const std::string galera_hostname { env_or("GALERA_HOSTNAME", "127.1.1.11") };
const std::string galera_username { env_or("GALERA_USERNAME", "galera1") };
const std::string galera_pass { env_or("GALERA_PASSWORD", "pass1") };
const int galera_port = env_or("GALERA_PORT", 3306);

const std::string readonly_hostname { env_or("READONLY_HOSTNAME", "127.0.0.1") };
const std::string readonly_username { env_or("READONLY_USERNAME", "root") };
const std::string readonly_pass { env_or("READONLY_PASSWORD", "root") };
const int readonly_port = env_or("READONLY_PORT", 3306);

const std::string grouprep_hostname { env_or("GROUPREP_HOSTNAME", "127.2.1.1") };
const std::string grouprep_username { env_or("GROUPREP_USERNAME", "grouprep1") };
const std::string grouprep_pass { env_or("GROUPREP_PASSWORD", "pass1") };
const int grouprep_port = env_or("GROUPREP_PORT", 3306);

const std::string replicationlag_hostname { env_or("REPL_LAG_HOSTNAME", "127.0.0.1") };
const std::string replicationlag_username { env_or("REPL_LAG_USERNAME", "root") };
const std::string replicationlag_pass { env_or("REPL_LAG_PASSWORD", "root") };
const int replicationlag_port = env_or("REPL_LAG_PORT", 3306);

const std::string aws_aurora_hostname { env_or("AURORA_HOSTNAME", "127.0.1.11") };
const std::string aws_aurora_username { env_or("AURORA_USERNAME", "aurora1") };
const std::string aws_aurora_pass { env_or("AURORA_PASSWORD", "pass1") };
const int aws_aurora_port = env_or("AURORA_PORT", 3306);

// //////////////////////////////////////////////

int main(int argc, const char *argv[]) {
	int err_code = 0;
	CommandLine cl {};
	std::pair<int, nlohmann::ordered_json> result {
		EXIT_SUCCESS,
		{
			{ "err_type", "none" },
			{ "err_msg", "" }
		}
	};

	MYSQL* proxysql_admin = mysql_init(NULL);
	MYSQL* proxysql_sqlite = nullptr;

	std::pair<int, std::string> cmd_options_err {};
	simulator_options options {};

	if(cl.getEnv()) {
		result = invalid_input_error(
			"Unable to get the required 'ENV' variables", __FILE__, __LINE__
		);

		goto cleanup;
	}

	if (
		!mysql_real_connect(
			proxysql_admin, cl.host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0
		)
	) {
		result = invalid_input_error(
			std::string { mysql_error(proxysql_admin) }, __FILE__, __LINE__
		);

		goto cleanup;
	}

	cmd_options_err = get_cmd_options(argc, argv, options);
	if (cmd_options_err.first) {
		result = invalid_input_error(cmd_options_err.second, __FILE__, __LINE__);

		goto cleanup;
	}

	{
		nlohmann::ordered_json j_tests_defs {};
		std::vector<nlohmann::ordered_json> simulation_results {};

		try {
			std::ifstream payload_stream { options.payload_path };
			j_tests_defs = nlohmann::ordered_json::parse(payload_stream);
		} catch (std::exception& e) {
			std::string t_err_msg {
				"Input JSON payload failed to be parsed with error: '%s'"
			};
			std::string err_msg {};
			string_format(t_err_msg, err_msg, e.what());
			result = invalid_input_error(err_msg, __FILE__, __LINE__);

			goto cleanup;
		}

		// check that the payload has the basic shape to access the test
		// definitions
		if (!j_tests_defs.is_array()) {
			result = invalid_input_error(
				"Test payload must be a JSON array", __FILE__, __LINE__
			);

			goto cleanup;
		}

		// *********************  CLUSTER SIMULATION  **************************
		// *********************************************************************

		for (const auto& j_test_def : j_tests_defs) {
			// Extract the type of cluster to simulate from the payload
			enum test_def_type test_type { test_def_type::UNSUPPORTED };
			const auto& test_type_res =
				get_test_type(j_test_def, test_type);

			if (test_type_res.first) {
				result = invalid_input_error(
					"Test payload holds an non-existent, invalid or unsupported"
					" \"cluster_type\"",
					__FILE__, __LINE__
				);
				break;
			}

			if (test_type == test_def_type::GALERA_CLUSTER) {
				// Connect to the 'SQLite' to change the contents of 'HOST_STATUS_GALERA'
				proxysql_sqlite = mysql_init(NULL);

				if (
					!mysql_real_connect(
						proxysql_sqlite, galera_hostname.c_str(), galera_username.c_str(),
						galera_pass.c_str(), NULL, galera_port, NULL, 0
					)
				) {
					result = invalid_input_error(
						std::string { mysql_error(proxysql_sqlite) }, __FILE__, __LINE__
					);

					goto cleanup;
				}

				const std::pair<int, nlohmann::ordered_json> sim_res =
					simulate_galera_cluster_state(
						proxysql_admin,
						proxysql_sqlite,
						j_test_def,
						options.op_mode,
						options.verbose_output
					);

				simulation_results.push_back(sim_res.second);

				if (sim_res.first) {
					result.second = {
						{ "err_type", "simulation_error" },
						{ "err_msg", "One or more of the requested simulations have failed" }
					};

					result.first = EXIT_FAILURE;
					if (options.stop_on_failure) {
						break;
					}
				}
			} else if (test_type == test_def_type::READONLY_TEST) {
				// Connect to the 'SQLite' to change the contents of 'READONLY_STATUS'
				proxysql_sqlite = mysql_init(NULL);

				if (
					!mysql_real_connect(
						proxysql_sqlite, readonly_hostname.c_str(), readonly_username.c_str(),
						readonly_pass.c_str(), NULL, readonly_port, NULL, 0
					)
				) {
					result = invalid_input_error(
						std::string { mysql_error(proxysql_sqlite) }, __FILE__, __LINE__
					);

					goto cleanup;
				}

				const std::pair<int, nlohmann::ordered_json> sim_res =
					simulate_mysql_readonly_cluster_state(
						proxysql_admin,
						proxysql_sqlite,
						j_test_def,
						options.op_mode,
						options.verbose_output
					);

				simulation_results.push_back(sim_res.second);

				if (sim_res.first) {
					result.second = {
						{ "err_type", "simulation_error" },
						{ "err_msg", "One or more of the requested simulations have failed" }
					};

					result.first = EXIT_FAILURE;
					if (options.stop_on_failure) {
						break;
					}
				}
			} else if (test_type == test_def_type::GROUP_REPLICATION) {
				// Connect to the 'SQLite' to change the contents of
				// 'GR_MEMBER_ROUTING_CANDIDATE_STATUS'.
				proxysql_sqlite = mysql_init(NULL);

				if (
					!mysql_real_connect(
						proxysql_sqlite, grouprep_hostname.c_str(), grouprep_username.c_str(),
						grouprep_pass.c_str(), NULL, grouprep_port, NULL, 0
					)
				) {
					result = invalid_input_error(
						std::string { mysql_error(proxysql_sqlite) }, __FILE__, __LINE__
					);

					goto cleanup;
				}

				const std::pair<int, nlohmann::ordered_json> sim_res =
					simulate_mysql_group_replication_cluster_state(
						proxysql_admin,
						proxysql_sqlite,
						j_test_def,
						options.op_mode,
						options.verbose_output
					);

				simulation_results.push_back(sim_res.second);

				if (sim_res.first) {
					result.second = {
						{ "err_type", "simulation_error" },
						{ "err_msg", "One or more of the requested simulations have failed" }
					};

					result.first = EXIT_FAILURE;
					if (options.stop_on_failure) {
						break;
					}
				}
			} else if (test_type == test_def_type::REPLICATION_LAG) {
				// Connect to the 'SQLite' to change the contents of 'REPLICATIONLAG_HOST_STATUS'
				proxysql_sqlite = mysql_init(NULL);

				if (
					!mysql_real_connect(
						proxysql_sqlite, replicationlag_hostname.c_str(), replicationlag_username.c_str(),
						replicationlag_pass.c_str(), NULL, replicationlag_port, NULL, 0
					)
					) {
					result = invalid_input_error(
						std::string{ mysql_error(proxysql_sqlite) }, __FILE__, __LINE__
					);

					goto cleanup;
				}

				const std::pair<int, nlohmann::ordered_json> sim_res =
					simulate_mysql_replicationlag_cluster_state(
						proxysql_admin,
						proxysql_sqlite,
						j_test_def,
						options.op_mode,
						options.verbose_output
					);

				simulation_results.push_back(sim_res.second);

				if (sim_res.first) {
					result.second = {
						{ "err_type", "simulation_error" },
						{ "err_msg", "One or more of the requested simulations have failed" }
					};

					result.first = EXIT_FAILURE;
					if (options.stop_on_failure) {
						break;
					}
				}
			} else if (test_type == test_def_type::AWS_AURORA) {
				// Connect to the 'SQLite' to change the contents of 'HOST_STATUS_aws_aurora'
				proxysql_sqlite = mysql_init(NULL);

				if (
					!mysql_real_connect(
						proxysql_sqlite, aws_aurora_hostname.c_str(), aws_aurora_username.c_str(),
						aws_aurora_pass.c_str(), NULL, aws_aurora_port, NULL, 0
					)
				) {
					result = invalid_input_error(mysql_error(proxysql_sqlite), __FILE__, __LINE__);

					goto cleanup;
				}

				const std::pair<int, nlohmann::ordered_json> sim_res =
					simulate_aws_aurora_cluster_state(
						proxysql_admin,
						proxysql_sqlite,
						j_test_def,
						options.op_mode,
						options.verbose_output
					);

				simulation_results.push_back(sim_res.second);

				if (sim_res.first) {
					result.second = {
						{ "err_type", "simulation_error" },
						{ "err_msg", "One or more of the requested simulations have failed" }
					};

					result.first = EXIT_FAILURE;
					if (options.stop_on_failure) {
						break;
					}
				}
			}

			mysql_close(proxysql_sqlite);
		}

		// ************************************************************************

		// set the simulations results in the output
		result.second["results"] = simulation_results;
	}

cleanup:
	std::string t_str_res { serialize_result(result.second) };
	std::cout << t_str_res << std::endl;

	mysql_close(proxysql_admin);

	return result.first;
}
