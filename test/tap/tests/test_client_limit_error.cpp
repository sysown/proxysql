/**
 * @file test_client_limit_error.cpp
 * @brief This test aims to verify the logic for the 'client_limit_error' feature.
 *   NOTE: This test isn't executed automatically because it requires elevated privileges
 *   for being able to run the scripts 'create_netns_n' and 'delete_netns_n' that creates
 *   and delete the networks namespaces required for it.
 *
 * @details Right now the test verifies the following cases:
 *  1. Enable the feature and checks that the error count is incremented when a single
 *     client tries to connect and that the cache entry values match expected ones.
 *  2. Flush the entries, and check that counting is performed properly for a
 *     single cache entry.
 *  3. Flush the entries, and check that counting is performed properly for
 *     multiple cache entries.
 *  4. Flush the entries, and check:
 *       1. That counting is performed properly for multiple cache entries.
 *       2. Connections fail after the limit for one client.
 *       3. Clients are deleted after a succesfull connection is performed.
 *  5. Flush the entries, fill the cache and check that when the
 *  'mysql-client_host_error_counts' is changed at runtime, connections are denied
 *  to a client exceeding the new limit.
 *  6. Flush the entries, fill the cache and check that the when the
 *  'mysql-client_host_cache_size' is changed at runtime:
 *    1. The exceeding elements are cleaned with each new connection.
 *    2. Check that is not relevant if the element was or not present 
 *       in the cache.
 *    3. Checks that a proper connection is performed succesfully and the element is
 *    removed from the cache
 *
 * @date 2021-09-10
 */

#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>

#include <atomic>
#include <algorithm>
#include <tuple>
#include <vector>
#include <string>
#include <thread>
#include <iostream>
#include <fstream>

#include <libconfig.h>
#include <proxysql_utils.h>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

const uint32_t NUM_NETWORK_NAMESPACES = 5;

using host_cache_entry = std::tuple<std::string, uint32_t, uint64_t>;

inline unsigned long long monotonic_time() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

std::vector<host_cache_entry> get_client_host_cache_entries(MYSQL* proxysql_admin) {
	int rc = mysql_query(
		proxysql_admin,
		"SELECT * FROM stats.stats_mysql_client_host_cache ORDER BY client_address"
	);

	MYSQL_ROW row = NULL;
	MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
	std::vector<host_cache_entry> host_cache_entries {};

	while ((row = mysql_fetch_row(proxy_res))) {
		std::string client_address = row[0];
		uint32_t error_count = atoi(row[1]);
		uint64_t last_update = atoll(row[2]);

		host_cache_entries.push_back({client_address, error_count, last_update});
	}

	mysql_free_result(proxy_res);

	return host_cache_entries;
}

int main(int, char**) {
	int res = 0;
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(27);

	MYSQL* proxysql_admin = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_admin) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(proxysql_admin)
		);
		return -1;
	}

	// Connect to ProxySQL Admin
	if (
		!mysql_real_connect(
			proxysql_admin, cl.host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0
		)
	) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(proxysql_admin)
		);
		return -1;
	}

	// Setup the virtual namespaces to be used by the test
	diag("                Setting up testing network namespaces                ");
	diag("*********************************************************************");
	printf("\n");

	int setup_ns_i = 0;
	const std::string t_create_ns_command =
		std::string { cl.workdir } + "/client_host_err/create_netns_n.sh %d";
	for (setup_ns_i = 1; setup_ns_i < NUM_NETWORK_NAMESPACES; setup_ns_i++) {
		std::string create_ns_command {};
		string_format(t_create_ns_command, create_ns_command, setup_ns_i);

		int c_err = system(create_ns_command.c_str());
		if (c_err) {
			diag(
				"Failed to create netns number '%d' with err: '%d'",
				setup_ns_i, c_err
			);
			goto cleanup;
		}
	}

	printf("\n");
	diag("*********************************************************************");
	printf("\n");

	diag("                 Performing queries and checks                       ");
	diag("*********************************************************************");
	printf("\n");

	{
		const std::string t_inv_user_command =
			"ip netns exec ns%d mysql -h10.200.%d.1 -uinv_user -pinv_pass -P6033";
		const std::string t_valid_connection_command {
			"ip netns exec ns%d mysql -h10.200.%d.1 -uroot -proot -P6033 -e'DO 1' 2>&1"
		};

		// 1. Enable the feature check that error count is incremented when a
		// new client fails to connect, and that the cache entry values are the
		// expected ones.
		{
			printf("\n");
			diag("                 START TEST NUMBER 1                         ");
			diag("-------------------------------------------------------------");

			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_cache_size=1");
			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_error_counts=5");
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

			// There shouldn't be any other entries in the cache for this test.
			MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH MYSQL CLIENT HOSTS");

			std::string inv_user_command {};
			string_format(t_inv_user_command, inv_user_command, 1, 1);
			uint64_t pre_command_time = monotonic_time();

			diag("Performing connections to fill 'client_host_cache'");

			printf("\n");
			int inv_user_errno = system(inv_user_command.c_str());
			diag("Client connection failed with error: %d", inv_user_errno);
			printf("\n");

			diag("Performing checks over 'client_host_cache'");

			std::vector<host_cache_entry> entries =
				get_client_host_cache_entries(proxysql_admin);

			ok(
				entries.size() == 1,
				"'client_host_cache' entries should be '1' after issuing 'PROXYSQL FLUSH"
				" MYSQL CLIENT HOSTS' and one failed connection."
			);

			if (entries.size() == 1) {
				host_cache_entry unique_entry { entries.back() };
				const std::string client_addr { std::get<0>(unique_entry) };
				const uint32_t error_count { std::get<1>(unique_entry) };
				const uint64_t last_updated { std::get<2>(unique_entry) };
				uint64_t post_command_time = monotonic_time();

				ok(
					client_addr == "10.200.1.2" && error_count == 1 &&
					(pre_command_time < last_updated < post_command_time),
					"Entry should match expected values - exp(addr: %s, err_count: %d, last_updated: %ld < %ld < %ld),"
					" act(addr: %s, err_count: %d, last_updated: %ld < %ld < %ld)",
					"10.200.1.2", 1, pre_command_time, last_updated, post_command_time,
					client_addr.c_str(), error_count, pre_command_time, last_updated, post_command_time
				);
			}
		}

		// 2. Flush the entries, and check that counting is performed properly for a
		// single cache entry.
		{
			printf("\n");
			diag("                 START TEST NUMBER 2                         ");
			diag("-------------------------------------------------------------");


			// There shouldn't be any other entries in the cache for this test.
			MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH MYSQL CLIENT HOSTS");
			int errors = 0;

			std::string inv_user_command {};
			string_format(t_inv_user_command, inv_user_command, 1, 1);
			uint64_t pre_command_time = monotonic_time();

			printf("\n");
			diag("Performing connections to fill 'client_host_cache'");
			for (errors = 0; errors < 5; errors++) {
				printf("\n");
				int inv_user_errno = system(inv_user_command.c_str());
				diag("Client connection failed with error: %d", inv_user_errno);
			}
			printf("\n");

			diag("Performing checks over 'client_host_cache'");

			std::vector<host_cache_entry> entries =
				get_client_host_cache_entries(proxysql_admin);

			ok(
				entries.size() == 1,
				"'client_host_cache' entries should be '1' after issuing 'PROXYSQL FLUSH"
				" MYSQL CLIENT HOSTS' and one failed connection."
			);

			if (entries.size() == 1) {
				host_cache_entry unique_entry { entries.back() };
				const std::string client_addr { std::get<0>(unique_entry) };
				const uint32_t error_count { std::get<1>(unique_entry) };
				const uint64_t last_updated { std::get<2>(unique_entry) };
				uint64_t post_command_time = monotonic_time();

				ok(
					client_addr == "10.200.1.2" && error_count == errors &&
					(pre_command_time < last_updated < post_command_time),
					"Entry should match expected values - exp(addr: %s, err_count: %d, last_updated: %ld < %ld < %ld),"
					" act(addr: %s, err_count: %d, last_updated: %ld < %ld < %ld)",
					"10.200.1.2", 1, pre_command_time, last_updated, post_command_time,
					client_addr.c_str(), error_count, pre_command_time, last_updated, post_command_time
				);
			}
		}

		// 3. Flush the entries, and check that counting is performed properly for
		// multiple cache entries.
		{
			printf("\n");
			diag("                 START TEST NUMBER 3                         ");
			diag("-------------------------------------------------------------");

			// Increase cache size
			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_cache_size=5");
			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_error_counts=5");
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

			// There shouldn't be any other entries in the cache for this test.
			MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH MYSQL CLIENT HOSTS");
			int errors = 0;

			// Prepare several commands from different network namespaces
			std::vector<std::string> inv_connection_commands {};
			for (int i = 1; i < NUM_NETWORK_NAMESPACES; i++) {
				std::string inv_user_command {};
				string_format(t_inv_user_command, inv_user_command, i, i);
				inv_connection_commands.push_back(inv_user_command);
			}

			uint64_t pre_command_time = monotonic_time();

			printf("\n");
			diag("Performing connections to fill 'client_host_cache'");
			for (const auto inv_conn_command : inv_connection_commands) {
				for (errors = 0; errors < 2; errors++) {
					printf("\n");
					int inv_user_errno = system(inv_conn_command.c_str());
					diag("Client connection failed with error: %d", inv_user_errno);
				}
				printf("\n");
			}

			diag("Performing checks over 'client_host_cache'");

			std::vector<host_cache_entry> entries =
				get_client_host_cache_entries(proxysql_admin);

			ok(
				entries.size() == NUM_NETWORK_NAMESPACES - 1,
				"'client_host_cache' entries should be 'NUM_NETWORK_NAMESPACES' after issuing 'PROXYSQL FLUSH"
				" MYSQL CLIENT HOSTS' and 'NUM_NETWORK_NAMESPACES' failed connections. Entries: '%ld'",
				entries.size()
			);

			if (entries.size() == NUM_NETWORK_NAMESPACES - 1) {
				uint32_t entry_num = 1;

				for (const auto& entry : entries) {
					const std::string client_addr { std::get<0>(entry) };
					const uint32_t error_count { std::get<1>(entry) };
					const uint64_t last_updated { std::get<2>(entry) };
					uint64_t post_command_time = monotonic_time();

					std::string t_exp_client_addr { "10.200.%d.2" };
					std::string exp_client_addr {};
					string_format(t_exp_client_addr, exp_client_addr, entry_num);

					ok(
						client_addr == exp_client_addr && error_count == errors &&
						(pre_command_time < last_updated < post_command_time),
						"Entry should match expected values - exp(addr: %s, err_count: %d, last_updated: %ld < %ld < %ld),"
						" act(addr: %s, err_count: %d, last_updated: %ld < %ld < %ld)",
						exp_client_addr.c_str(), errors, pre_command_time, last_updated, post_command_time,
						client_addr.c_str(), error_count, pre_command_time, last_updated, post_command_time
					);

					entry_num += 1;
				}
			}
		}

		// 4. Flush the entries, and check:
		//   1. That counting is performed properly for multiple cache entries.
		//   2. Connections fail after the limit for one client.
		//   3. Clients are deleted after a succesfull connection is performed.
		{
			printf("\n");
			diag("                 START TEST NUMBER 4                         ");
			diag("-------------------------------------------------------------");

			// Increase cache size
			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_cache_size=5");
			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_error_counts=5");
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

			// There shouldn't be any other entries in the cache for this test.
			MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH MYSQL CLIENT HOSTS");
			int errors = 0;

			// Prepare several commands from different network namespaces
			std::vector<std::string> inv_connection_commands {};
			for (int i = 1; i < NUM_NETWORK_NAMESPACES; i++) {
				std::string inv_user_command {};
				string_format(t_inv_user_command, inv_user_command, i, i);
				inv_connection_commands.push_back(inv_user_command);
			}

			uint64_t pre_command_time = monotonic_time();

			printf("\n");
			diag("Performing connections to fill 'client_host_cache'");
			for (const auto inv_conn_command : inv_connection_commands) {
				for (errors = 0; errors < 3; errors++) {
					printf("\n");
					int inv_user_errno = system(inv_conn_command.c_str());
					diag("Client connection failed with error: %d", inv_user_errno);
				}
				printf("\n");
			}

			printf("\n");
			diag("1. Check that counting is perfomred properly over multiple 'client_host_cache'");

			std::vector<host_cache_entry> entries =
				get_client_host_cache_entries(proxysql_admin);

			ok(
				entries.size() == NUM_NETWORK_NAMESPACES - 1,
				"'client_host_cache' entries should be 'NUM_NETWORK_NAMESPACES' after issuing 'PROXYSQL FLUSH"
				" MYSQL CLIENT HOSTS' and 'NUM_NETWORK_NAMESPACES' failed connections. Entries: '%ld'",
				entries.size()
			);

			if (entries.size() == NUM_NETWORK_NAMESPACES - 1) {
				uint32_t entry_num = 1;

				for (const auto& entry : entries) {
					const std::string client_addr { std::get<0>(entry) };
					const uint32_t error_count { std::get<1>(entry) };
					const uint64_t last_updated { std::get<2>(entry) };
					uint64_t post_command_time = monotonic_time();

					std::string t_exp_client_addr { "10.200.%d.2" };
					std::string exp_client_addr {};
					string_format(t_exp_client_addr, exp_client_addr, entry_num);

					ok(
						client_addr == exp_client_addr && error_count == errors &&
						(pre_command_time < last_updated < post_command_time),
						"Entry should match expected values - exp(addr: %s, err_count: %d, last_updated: %ld < %ld < %ld),"
						" act(addr: %s, err_count: %d, last_updated: %ld < %ld < %ld)",
						exp_client_addr.c_str(), errors, pre_command_time, last_updated, post_command_time,
						client_addr.c_str(), error_count, pre_command_time, last_updated, post_command_time
					);

					entry_num += 1;
				}
			}

			printf("\n");
			diag("Performing connections to fill 'client_host_cache'");

			uint32_t expected_ns = 4;
			const std::string expected_address { "10.200.4.2" };
			uint32_t expected_errors = 5;

			int limits = errors;
			std::string inv_user_command_limit {};
			const std::string t_stderr_inv_user_command {
				"ip netns exec ns%d mysql -h10.200.%d.1 -uinv_user -pinv_pass -P6033 2>&1"
			};
			string_format(t_stderr_inv_user_command, inv_user_command_limit, 4, 4);

			std::string command_res {};
			for (int limits = errors; limits < 5 + 1; limits++) {
				printf("\n");
				int inv_user_limit_err = exec(inv_user_command_limit.c_str(), command_res);
				diag("Client connection failed with error: (%d, %s)", inv_user_limit_err, command_res.c_str());
			}
			printf("\n");

			diag("2. Checking the connection is denied when the limit is reached.");

			auto limit_error = command_res.find("ERROR 2013 (HY000)");
			ok(
				limit_error != std::string::npos,
				"Last connection should fail with 'ERROR 2013', it exceeded the error limit. ErrMsg: '%s'",
				command_res.c_str()
			);

			std::vector<host_cache_entry> new_entries {
				get_client_host_cache_entries(proxysql_admin)
			};

			auto cache_entry =
				std::find_if(
					std::begin(new_entries),
					std::end(new_entries),
					[&] (const host_cache_entry& elem) -> bool {
						return std::get<0>(elem) == expected_address;
					}
				);

			bool found_exp_values = false;
			std::string client_address {};
			uint32_t found_errors = 0;

			if (cache_entry != std::end(new_entries)) {
				client_address = std::get<0>(*cache_entry);
				found_errors = std::get<1>(*cache_entry);

				found_exp_values =
					std::get<0>(*cache_entry) == expected_address &&
					std::get<1>(*cache_entry) == expected_errors;
			}

			ok(
				found_exp_values,
				"Entry should match expected values - exp(addr: %s, err_count: %d), act(addr: %s, err_count: %d)",
				expected_address.c_str(), expected_errors, client_address.c_str(), found_errors
			);

			diag("3. Check that clients are deleted from the cache when the connections are succesfully performed");

			for (int i = 1; i < NUM_NETWORK_NAMESPACES; i++) {
				// This client as exceeded the max failures

				std::string valid_connection_command {};
				string_format(t_valid_connection_command, valid_connection_command, i, i);

				// Client has exceeded maximum connections failure is expected
				if (i == 4) {
					std::string command_res {};
					exec(valid_connection_command, command_res);
					auto limit_error = command_res.find("ERROR 2013 (HY000)");

					ok(
						limit_error != std::string::npos,
						"Connection should fail due to limit exceeded. ErrMsg: '%s'", command_res.c_str()
					);
				} else {
					int command_err = system(valid_connection_command.c_str());
					ok(
						command_err == 0,
						"Connection should succeed for clients which limit haven't been exceeded."
					);
				}
			}

			new_entries = get_client_host_cache_entries(proxysql_admin);
			ok(
				new_entries.size() == 1 &&
				std::get<0>(new_entries.back()) == "10.200.4.2",
				"Only client address exceeding the limit should remain in the cache -"
				" exp('10.200.4.2'), act('%s')", std::get<0>(new_entries.back()).c_str()
			);
		}

		// 5. Flush the entries, fill the cache and check that the when the
		// 'mysql-client_host_error_counts' is changed at runtime, connections are denied
		// to a client exceeding the new limit.
		{
			printf("\n");
			diag("                 START TEST NUMBER 5                         ");
			diag("-------------------------------------------------------------");

			// Increase cache size
			printf("\n");
			diag("Setting the value of 'mysql-client_host_cache_size' to '5'");

			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_cache_size=5");
			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_error_counts=5");
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

			// There shouldn't be any other entries in the cache for this test.
			MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH MYSQL CLIENT HOSTS");
			int errors = 0;

			std::string inv_user_command {};
			string_format(t_inv_user_command, inv_user_command, 1, 1);
			uint64_t pre_command_time = monotonic_time();

			diag("Performing connections to fill 'client_host_cache'");

			for (int i = 0; i < 4; i++) {
				printf("\n");
				int inv_user_errno = system(inv_user_command.c_str());
				diag("Client connection failed with error: %d", inv_user_errno);
				printf("\n");
			}

			diag("Decreasing the value of 'mysql-client_host_error_counts' to '3'");
			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_error_counts=3");
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

			{
				printf("\n");
				std::string valid_user_command {};
				string_format(t_valid_connection_command, valid_user_command, 1, 1);

				std::string command_res {};
				int valid_user_err = exec(valid_user_command.c_str(), command_res);
				diag("Client connection failed with error: (%d, %s)", valid_user_err, command_res.c_str());

				auto limit_error = command_res.find("ERROR 2013 (HY000)");
				ok(
					limit_error != std::string::npos,
					"Last connection should fail with 'ERROR 2013', it exceeded the error limit. ErrMsg: '%s'",
					command_res.c_str()
				);
			}
		}

		// 6. Flush the entries, fill the cache and check that the when the
		// 'mysql-client_host_cache_size' is changed at runtime, the exceeding
		// elements are cleaned with each new connection. Without being relevant if was
		// present or not in the cache.
		{
			printf("\n");
			diag("                 START TEST NUMBER 6                         ");
			diag("-------------------------------------------------------------");

			// Increase cache size
			printf("\n");
			diag("Setting the value of 'mysql-client_host_cache_size' to '5'");

			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_cache_size=5");
			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_error_counts=5");
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

			// There shouldn't be any other entries in the cache for this test.
			MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH MYSQL CLIENT HOSTS");
			int errors = 0;

			// Fill the cache with the entries from all the created namespaces
			{
				std::vector<std::string> inv_connection_commands {};
				for (int i = 1; i < NUM_NETWORK_NAMESPACES; i++) {
					std::string inv_user_command {};
					string_format(t_inv_user_command, inv_user_command, i, i);
					inv_connection_commands.push_back(inv_user_command);
				}

				printf("\n");
				diag("Performing connections to fill 'client_host_cache'");
				for (const auto inv_conn_command : inv_connection_commands) {
					for (errors = 0; errors < 3; errors++) {
						printf("\n");
						int inv_user_errno = system(inv_conn_command.c_str());
						diag("Client connection failed with error: %d", inv_user_errno);
					}
					printf("\n");
				}
				printf("\n");
			}

			diag("Decreasing the value of 'mysql-client_host_cache_size' to '3'");
			MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_cache_size=1");
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

			// Update the latest entry in the cache, oldest member "10.200.1.2" should go away.
			{
				uint64_t pre_command_time = monotonic_time();

				diag("1. Checking that the connection updates the entry and the oldest entry is removed");

				std::string inv_user_command {};
				string_format(t_inv_user_command, inv_user_command, 4, 4);

				printf("\n");
				int inv_user_err = system(inv_user_command.c_str());
				diag("Client connection failed with error: %d", inv_user_err);
				printf("\n");

				std::vector<host_cache_entry> updated_entries {
					get_client_host_cache_entries(proxysql_admin)
				};

				std::string exp_client_addr { "10.200.4.2" };

				auto entry = std::find_if(
					std::begin(updated_entries),
					std::end(updated_entries),
					[&] (const host_cache_entry& entry) -> bool {
						return std::get<0>(entry) == exp_client_addr;
					}
				);

				std::string act_client_addr {};
				uint64_t last_updated = 0;

				if (entry != std::end(updated_entries)) {
					act_client_addr = std::get<0>(*entry);
					last_updated = std::get<2>(*entry);
				}

				ok(
					exp_client_addr == act_client_addr && last_updated > pre_command_time,
					"Entry should be present and updated with the following values -"
					" exp('%s', %ld > %ld), act('%s', %ld > %ld)", exp_client_addr.c_str(),
					last_updated, pre_command_time, act_client_addr.c_str(), last_updated,
					pre_command_time
				);

				// Oldest member shouldn't be present
				std::string oldest_member { "10.200.1.2" };

				auto oldest_entry = std::find_if(
					std::begin(updated_entries),
					std::end(updated_entries),
					[&] (const host_cache_entry& entry) -> bool {
						return std::get<0>(entry) == oldest_member;
					}
				);

				ok(
					oldest_entry == std::end(updated_entries),
					"Oldest entry '%s' shouldn't be present in the cache.", oldest_member.c_str()
				);

				printf("\n");
				diag("2. Checking that the same behavior is observed if connection comes from a non-cached address");

				string_format(t_inv_user_command, inv_user_command, 1, 1);

				printf("\n");
				inv_user_err = system(inv_user_command.c_str());
				diag("Client connection failed with error: %d", inv_user_err);
				printf("\n");

				diag("2.1 Checking that the address hasn't been added");

				const std::string new_member { "10.200.1.2" };

				updated_entries = get_client_host_cache_entries(proxysql_admin);
				auto new_entry = std::find_if(
					std::begin(updated_entries),
					std::end(updated_entries),
					[&] (const host_cache_entry& entry) -> bool {
						return std::get<0>(entry) == new_member;
					}
				);

				ok(
					new_entry == std::end(updated_entries),
					"New entry from address '10.200.1.2' shouldn't be present in the cache"
				);

				printf("\n");
				diag("2.1 Checking that the oldest address has been removed");
				oldest_member = "10.200.2.2";

				oldest_entry = std::find_if(
					std::begin(updated_entries),
					std::end(updated_entries),
					[&] (const host_cache_entry& entry) -> bool {
						return std::get<0>(entry) == oldest_member;
					}
				);

				ok(
					oldest_entry == std::end(updated_entries),
					"Oldest entry '%s' shouldn't be present in the cache.", oldest_member.c_str()
				);

				printf("\n");
				diag("2.2 Checking that a successful connection gets a client removed");
				printf("\n");

				std::string valid_connection_command {};
				string_format(t_valid_connection_command, valid_connection_command, 3, 3);
				system(valid_connection_command.c_str());

				const std::string forgotten_address { "10.200.3.2" };

				updated_entries = get_client_host_cache_entries(proxysql_admin);
				auto forgot_entry = std::find_if(
					std::begin(updated_entries),
					std::end(updated_entries),
					[&] (const host_cache_entry& entry) -> bool {
						return std::get<0>(entry) == forgotten_address;
					}
				);

				ok(
					forgot_entry == std::end(updated_entries),
					"Entry '%s' should have been forgotten due to successful connection.",
					forgotten_address.c_str()
				);
			}
		}
	}

cleanup:
	// Cleanup the virtual namespaces to be used by the test
	printf("\n");
	diag("            Cleanup of testing network namespaces                    ");
	diag("*********************************************************************");
	printf("\n");

	const std::string t_delete_ns_command =
		std::string { cl.workdir } + "/client_host_err/delete_netns_n.sh %d";
	for (int i = 1; i < setup_ns_i; i++) {
		std::string delete_ns_command {};
		string_format(t_delete_ns_command, delete_ns_command, i);
		system(delete_ns_command.c_str());
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
