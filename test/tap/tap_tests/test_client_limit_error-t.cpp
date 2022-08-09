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
 *  7. Flush the entries and checks that client connections timeouts interact with the
 *    cache in the same way as regular client connection errors.
 *
 * @date 2021-09-10
 */

#include <arpa/inet.h>
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

#include "json.hpp"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

const uint32_t NUM_LOOPBACK_ADDRS = 5;

using host_cache_entry = std::tuple<std::string, uint32_t, uint64_t>;

inline unsigned long long realtime_time_s() {
	time_t __now = time(NULL);
	return __now;
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

int invalid_proxysql_conn(const std::string& addr, const CommandLine& cl) {
	MYSQL* proxysql = mysql_init(NULL);
	int my_err = EXIT_SUCCESS;

	if (!mysql_real_connect(proxysql, addr.c_str(), "limit_inv_user", "limit_inv_pass", NULL, 6033, NULL, 0)) {
		my_err = mysql_errno(proxysql);
	}

	mysql_close(proxysql);

	return my_err;
}

int invalid_proxysql_conn(const std::string& addr, const CommandLine& cl, std::string& err_msg) {
	MYSQL* proxysql = mysql_init(NULL);
	int my_err = EXIT_SUCCESS;

	if (!mysql_real_connect(proxysql, addr.c_str(), "limit_inv_user", "limit_inv_pass", NULL, 6033, NULL, 0)) {
		my_err = mysql_errno(proxysql);
		err_msg = mysql_error(proxysql);
	}

	mysql_close(proxysql);

	return my_err;
}

int valid_proxysql_conn(const std::string& addr, const CommandLine& cl, std::string& err_msg) {
	MYSQL* proxysql = mysql_init(NULL);
	int my_err = EXIT_SUCCESS;

	if (!mysql_real_connect(proxysql, addr.c_str(), cl.username, cl.password, NULL, 6033, NULL, 0)) {
		my_err = mysql_errno(proxysql);
		err_msg = mysql_error(proxysql);
	}

	mysql_close(proxysql);

	return my_err;
}

/**
 * @brief Enable the feature check that error count is incremented when a
 * new client fails to connect, and that the cache entry values are the
 * expected ones.
 *
 * @param cl CommandLine info for connection creation.
 * @param proxysql_admin An already oppened connection to ProxySQL Admin.
 *
 * @return 'EXIT_SUCCESS' in case of success, 'EXIT_FAILURE' otherwise.
 */
int test_cache_filled_by_invalid_conn(const CommandLine& cl, MYSQL* proxysql_admin) {
	diag("                 START TEST NUMBER 1                         ");
	diag("-------------------------------------------------------------");

	MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_cache_size=1");
	MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_error_counts=5");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// There shouldn't be any other entries in the cache for this test.
	MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH MYSQL CLIENT HOSTS");

	uint64_t pre_command_time = realtime_time_s();
	const std::string exp_client_addr { "127.0.0.2" };

	diag("Performing connection to fill 'client_host_cache'");
	int inv_user_errno = invalid_proxysql_conn(exp_client_addr, cl);
	if (inv_user_errno == EXIT_SUCCESS) {
		diag("Expected failure but client connection succeed");
		return EXIT_FAILURE;
	}

	diag("Performing checks over 'client_host_cache'");
	std::vector<host_cache_entry> entries = get_client_host_cache_entries(proxysql_admin);

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
		uint64_t post_command_time = realtime_time_s();

		ok(
			client_addr == exp_client_addr && error_count == 1 &&
			(pre_command_time <= (last_updated + 1) && (last_updated - 1) <= post_command_time),
			"Entry should match expected values - exp(addr: %s, err_count: %d, last_updated: %ld <= %ld +/- 1 <= %ld),"
			" act(addr: %s, err_count: %d, last_updated: %ld <= %ld +/- 1 <= %ld)",
			exp_client_addr.c_str(), 1, pre_command_time, last_updated, post_command_time, client_addr.c_str(), error_count,
			pre_command_time, last_updated, post_command_time
		);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Flush the entries, and check that counting is performed properly for a single cache entry.
 *
 * @param cl CommandLine info for connection creation.
 * @param proxysql_admin An already oppened connection to ProxySQL Admin.
 *
 * @return 'EXIT_SUCCESS' in case of success, 'EXIT_FAILURE' otherwise.
 */
int test_cache_entry_count_by_invalid_conn(const CommandLine& cl, MYSQL* proxysql_admin) {
	printf("\n");
	diag("                 START TEST NUMBER 2                         ");
	diag("-------------------------------------------------------------");

	// There shouldn't be any other entries in the cache for this test.
	MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH MYSQL CLIENT HOSTS");
	int errors = 0;
	const std::string exp_client_addr { "127.0.0.2" };
	uint64_t pre_command_time = realtime_time_s();

	diag("Performing connection to fill 'client_host_cache'");
	for (errors = 0; errors < 5; errors++) {
		int inv_user_errno = invalid_proxysql_conn(exp_client_addr, cl);
		if (inv_user_errno == EXIT_SUCCESS) {
			diag("Expected failure but client connection succeed");
			return EXIT_FAILURE;
		}
	}

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
		uint64_t post_command_time = realtime_time_s();

		ok(
			client_addr == exp_client_addr && error_count == errors &&
			(pre_command_time <= (last_updated + 1) && (last_updated - 1) <= post_command_time),
			"Entry should match expected values - exp(addr: %s, err_count: %d, last_updated: %ld <= %ld +/- 1 <= %ld),"
			" act(addr: %s, err_count: %d, last_updated: %ld <= %ld +/- 1 <= %ld)",
			exp_client_addr.c_str(), 1, pre_command_time, last_updated, post_command_time,
			client_addr.c_str(), error_count, pre_command_time, last_updated, post_command_time
		);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Flush the entries, and check that counting is performed properly for multiple cache entries.
 * @param cl CommandLine info for connection creation.
 * @param proxysql_admin An already oppened connection to ProxySQL Admin.
 *
 * @return 'EXIT_SUCCESS' in case of success, 'EXIT_FAILURE' otherwise.
 */
int test_cache_entry_count_by_mult_invalid_conns(const CommandLine& cl, MYSQL* proxysql_admin) {
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

	uint64_t pre_command_time = realtime_time_s();

	printf("\n");
	diag("Performing connections to fill 'client_host_cache'");
	for (int i = 2; i < NUM_LOOPBACK_ADDRS; i++) {
		std::string loopback_addr { "127.0.0." + std::to_string(i) };
		for (errors = 0; errors < 2; errors++) {
			int inv_user_errno = invalid_proxysql_conn(loopback_addr, cl);
			diag("Client connection failed with error: %d", inv_user_errno);
		}
	}

	diag("Performing checks over 'client_host_cache'");

	std::vector<host_cache_entry> entries =
		get_client_host_cache_entries(proxysql_admin);

	ok(
		entries.size() == NUM_LOOPBACK_ADDRS - 2,
		"'client_host_cache' entries should be 'NUM_LOOPBACK_ADDRS' after issuing 'PROXYSQL FLUSH"
		" MYSQL CLIENT HOSTS' and 'NUM_LOOPBACK_ADDRS' failed connections. Entries: '%ld'",
		entries.size()
	);

	if (entries.size() == NUM_LOOPBACK_ADDRS - 2) {
		uint32_t entry_num = 2;

		for (const auto& entry : entries) {
			const std::string client_addr { std::get<0>(entry) };
			const uint32_t error_count { std::get<1>(entry) };
			const uint64_t last_updated { std::get<2>(entry) };
			uint64_t post_command_time = realtime_time_s();

			std::string exp_client_addr { "127.0.0." + std::to_string(entry_num) };

			ok(
				client_addr == exp_client_addr && error_count == errors &&
				(pre_command_time <= (last_updated + 1) && (last_updated - 1) <= post_command_time),
				"Entry should match expected values - exp(addr: %s, err_count: %d, last_updated: %ld <= %ld +/- 1 <= %ld),"
				" act(addr: %s, err_count: %d, last_updated: %ld <= %ld +/- 1 <= %ld)",
				exp_client_addr.c_str(), errors, pre_command_time, last_updated, post_command_time,
				client_addr.c_str(), error_count, pre_command_time, last_updated, post_command_time
			);

			entry_num += 1;
		}
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Flush the entries, and check:
 *    1. That counting is performed properly for multiple cache entries.
 *    2. Connections fail after the limit for one client.
 *    3. Clients are deleted after a succesfull connection is performed.
 * @param cl CommandLine info for connection creation.
 * @param proxysql_admin An already oppened connection to ProxySQL Admin.
 *
 * @return 'EXIT_SUCCESS' in case of success, 'EXIT_FAILURE' otherwise.
 */
int test_client_exceeding_cache_error_limit(const CommandLine& cl, MYSQL* proxysql_admin) {
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

	std::vector<std::string> loopback_addrs {};
	for (int i = 2; i < NUM_LOOPBACK_ADDRS; i++) {
		loopback_addrs.push_back("127.0.0." + std::to_string(i));
	}

	uint64_t pre_command_time = realtime_time_s();

	printf("\n");
	diag("Performing connections to fill 'client_host_cache'");
	for (const auto loopback_addr : loopback_addrs) {
		for (errors = 0; errors < 3; errors++) {
			int inv_user_errno = invalid_proxysql_conn(loopback_addr, cl);
			diag("Client connection failed with error: %d", inv_user_errno);
		}
	}

	printf("\n");
	diag("1. Check that counting is perfomred properly over multiple 'client_host_cache'");

	std::vector<host_cache_entry> entries =
		get_client_host_cache_entries(proxysql_admin);

	ok(
		entries.size() == NUM_LOOPBACK_ADDRS - 2,
		"'client_host_cache' entries should be 'NUM_LOOPBACK_ADDRS' after issuing 'PROXYSQL FLUSH"
		" MYSQL CLIENT HOSTS' and 'NUM_LOOPBACK_ADDRS' failed connections. Entries: '%ld'",
		entries.size()
	);

	if (entries.size() == NUM_LOOPBACK_ADDRS - 2) {
		uint32_t entry_num = 2;

		for (const auto& entry : entries) {
			const std::string client_addr { std::get<0>(entry) };
			const uint32_t error_count { std::get<1>(entry) };
			const uint64_t last_updated { std::get<2>(entry) };
			uint64_t post_command_time = realtime_time_s();

			std::string exp_client_addr { "127.0.0." + std::to_string(entry_num) };

			ok(
				client_addr == exp_client_addr && error_count == errors &&
				(pre_command_time <= (last_updated + 1) && (last_updated - 1) <= post_command_time),
				"Entry should match expected values - exp(addr: %s, err_count: %d, last_updated: %ld <= %ld +/- 1 <= %ld),"
				" act(addr: %s, err_count: %d, last_updated: %ld <= %ld +/- 1 <= %ld)",
				exp_client_addr.c_str(), errors, pre_command_time, last_updated, post_command_time,
				client_addr.c_str(), error_count, pre_command_time, last_updated, post_command_time
			);

			entry_num += 1;
		}
	}

	printf("\n");
	diag("Performing connections to fill 'client_host_cache'");

	const std::string loopback_addr { "127.0.0.4" };
	uint32_t expected_errors = 5;

	int limits = errors;

	std::string command_res {};
	int limit_conn_err = EXIT_SUCCESS;

	for (int limits = errors; limits < 5 + 1; limits++) {
		limit_conn_err = invalid_proxysql_conn(loopback_addr, cl, command_res);
		diag("Client connection failed with error: (%d, %s)", limit_conn_err, command_res.c_str());
	}
	printf("\n");

	diag("2. Checking the connection is denied when the limit is reached.");

	ok(
		limit_conn_err == 2013,
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
				return std::get<0>(elem) == loopback_addr;
			}
		);

	bool found_exp_values = false;
	std::string client_address {};
	uint32_t found_errors = 0;

	if (cache_entry != std::end(new_entries)) {
		client_address = std::get<0>(*cache_entry);
		found_errors = std::get<1>(*cache_entry);

		found_exp_values =
			std::get<0>(*cache_entry) == loopback_addr &&
			std::get<1>(*cache_entry) == expected_errors;
	}

	ok(
		found_exp_values,
		"Entry should match expected values - exp(addr: %s, err_count: %d), act(addr: %s, err_count: %d)",
		loopback_addr.c_str(), expected_errors, client_address.c_str(), found_errors
	);

	diag("3. Check that clients are deleted from the cache when the connections are succesfully performed");

	for (int i = 1; i < NUM_LOOPBACK_ADDRS; i++) {
		// This client as exceeded the max failures

		std::string loopback_addr { "127.0.0." + std::to_string(i) };

		// Client has exceeded maximum connections failure is expected
		if (i == 4) {
			std::string conn_err_msg {};
			int limit_conn_err = valid_proxysql_conn(loopback_addr, cl, conn_err_msg);

			ok(
				limit_conn_err == 2013,
				"Connection should fail due to limit exceeded. ErrMsg: '%s'", conn_err_msg.c_str()
			);
		} else {
			std::string command_res {};
			int command_err = valid_proxysql_conn(loopback_addr, cl, command_res);
			ok(
				command_err == 0,
				"Connection should succeed for clients which limit haven't been exceeded."
			);
		}
	}

	new_entries = get_client_host_cache_entries(proxysql_admin);
	std::string last_client_addr { "" };
	if (new_entries.size()) {
		last_client_addr = std::get<0>(new_entries.back());
	}

	ok(
		new_entries.size() == 1 && last_client_addr == "127.0.0.4",
		"Only client address exceeding the limit should remain in the cache - exp('127.0.0.4'), act('%s')",
		last_client_addr.c_str()
	);
	return EXIT_SUCCESS;
}

/**
 * @brief Flush the entries, fill the cache and check that the when the 'mysql-client_host_error_counts'
 *   is changed at runtime, connections are denied to a client exceeding the new limit.
 * @param cl CommandLine info for connection creation.
 * @param proxysql_admin An already oppened connection to ProxySQL Admin.
 *
 * @return 'EXIT_SUCCESS' in case of success, 'EXIT_FAILURE' otherwise.
 */
int test_client_exceeding_changed_error_limit(const CommandLine& cl, MYSQL* proxysql_admin) {
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


	uint64_t pre_command_time = realtime_time_s();

	std::string loopback_addr { "127.0.0.2" };
	diag("Performing connections to fill 'client_host_cache'");

	for (int i = 0; i < 4; i++) {
		int inv_user_errno = invalid_proxysql_conn(loopback_addr, cl);
		diag("Client connection failed with error: %d", inv_user_errno);
	}

	diag("Decreasing the value of 'mysql-client_host_error_counts' to '3'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_error_counts=3");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	{
		printf("\n");

		std::string conn_err_msg {};
		int valid_user_err = valid_proxysql_conn(loopback_addr, cl, conn_err_msg);
		diag("Client connection failed with error: (%d, %s)", valid_user_err, conn_err_msg.c_str());

		ok(
			valid_user_err == 2013,
			"Last connection should fail with 'ERROR 2013', it exceeded the error limit. ErrMsg: '%s'",
			conn_err_msg.c_str()
		);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Flush the entries, set 'mysql-client_host_cache_size' to '0', and check
 *   that cache isn't filled by connections timing out. Increase 'mysql-client_host_cache_size'
 *   and check that cache is filled by timeout connections.
 * @param cl CommandLine info for connection creation.
 * @param proxysql_admin An already oppened connection to ProxySQL Admin.
 *
 * @return 'EXIT_SUCCESS' in case of success, 'EXIT_FAILURE' otherwise.
 */
int test_cache_size_decrease_by_new_connections(const CommandLine& cl, MYSQL* proxysql_admin) {
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

	std::vector<std::string> loopback_addrs {};
	for (int i = 2; i < NUM_LOOPBACK_ADDRS; i++) {
		loopback_addrs.push_back("127.0.0." + std::to_string(i));
	}

	uint64_t pre_command_time = realtime_time_s();

	printf("\n");
	diag("Performing connections to fill 'client_host_cache'");
	for (const auto loopback_addr : loopback_addrs) {
		for (errors = 0; errors < 3; errors++) {
			int inv_user_errno = invalid_proxysql_conn(loopback_addr, cl);
			diag("Client connection failed with error: %d", inv_user_errno);
		}
	}

	diag("Decreasing the value of 'mysql-client_host_cache_size' to '3'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_cache_size=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Update the latest entry in the cache, oldest member "10.200.1.2" should go away.
	{
		uint64_t pre_command_time = realtime_time_s();

		diag("1. Checking that the connection updates the entry and the oldest entry is removed");

		std::string loopback_addr { "127.0.0.4" };

		printf("\n");
		int inv_user_err = invalid_proxysql_conn(loopback_addr, cl);
		diag("Client connection failed with error: %d", inv_user_err);

		std::vector<host_cache_entry> updated_entries {
			get_client_host_cache_entries(proxysql_admin)
		};

		std::string exp_client_addr { "127.0.0.4" };

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
			exp_client_addr == act_client_addr && (last_updated + 1) >= pre_command_time,
			"Entry should be present and updated with the following values -"
			" exp('%s', %ld >= %ld), act('%s', %ld >= %ld)", exp_client_addr.c_str(),
			last_updated, pre_command_time, act_client_addr.c_str(), last_updated,
			pre_command_time
		);

		// Oldest member shouldn't be present
		std::string oldest_member { "127.0.0.2" };

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

		const std::string new_member { "127.0.0.5" };

		inv_user_err = invalid_proxysql_conn(new_member, cl);
		diag("Client connection failed with error: %d", inv_user_err);

		diag("2.1 Checking that the address hasn't been added");

		updated_entries = get_client_host_cache_entries(proxysql_admin);
		auto new_entry = std::find_if(
			std::begin(updated_entries), std::end(updated_entries),
			[&] (const host_cache_entry& entry) -> bool {
				return std::get<0>(entry) == new_member;
			}
		);

		ok(
			new_entry == std::end(updated_entries),
			"New entry from address '127.0.0.5' shouldn't be present in the cache"
		);

		diag("2.1 Checking that the oldest address has been removed");
		oldest_member = "127.0.0.3";

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

		diag("2.2 Checking that a successful connection gets a client removed");

		const std::string forgotten_address { "127.0.0.4" };
		std::string err_msg {};
		int valid_conn_err = valid_proxysql_conn(forgotten_address, cl, err_msg);
		if (valid_conn_err) {
			diag("Failed to execute 'valid_proxysql_conn' at ('%s':'%d')", __FILE__, __LINE__);
		}

		updated_entries = get_client_host_cache_entries(proxysql_admin);
		auto forgot_entry = std::find_if(
			std::begin(updated_entries), std::end(updated_entries),
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

	return EXIT_SUCCESS;
}

int create_tcp_conn(const CommandLine& cl, const std::string& addr) {
	int sock = 0;
	struct sockaddr_in serv_addr;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		diag("_socket creation error");
		return EXIT_FAILURE;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(cl.port);

	if(inet_pton(AF_INET, addr.c_str(), &serv_addr.sin_addr)<=0)  {
		diag("Invalid address/ Address not supported");
		return EXIT_FAILURE;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		diag("Connection Failed");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Checks that client connections timeouts interact with the cache in the same way
 *   as regular client connection errors.
 * @param cl CommandLine info for connection creation.
 * @param proxysql_admin An already oppened connection to ProxySQL Admin.
 *
 * @return 'EXIT_SUCCESS' in case of success, 'EXIT_FAILURE' otherwise.
 */
int test_cache_populated_timeout_conns(const CommandLine& cl, MYSQL* proxysql_admin) {
	printf("\n");
	diag("                 START TEST NUMBER 7                         ");
	diag("-------------------------------------------------------------");

	// Increase cache size
	printf("\n");
	diag("Setting the value of 'mysql-client_host_cache_size' to '0'");

	// Disable the cache
	MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_cache_size=0");
	MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_error_counts=0");

	// Decrease client connection timeout
	const int client_timeout = 1000;
	std::string set_connect_timeout_client { "SET mysql-connect_timeout_client=" + std::to_string(client_timeout) };

	MYSQL_QUERY(proxysql_admin, set_connect_timeout_client.c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// There shouldn't be any other entries in the cache for the start of this test.
	MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH MYSQL CLIENT HOSTS");

	int errors = 0;

	// Create some connections timeout
	printf("\n");
	diag("Performing timeout connections to fill 'client_host_cache'");
	std::vector<int> sockets {};
	for (int i = 2; i < NUM_LOOPBACK_ADDRS; i++) {
		std::string loopback_addr { "127.0.0." + std::to_string(i) };
		int inv_user_errno = create_tcp_conn(cl, loopback_addr);
		diag("Client connection failed with error: %d", inv_user_errno);
	}
	sleep((client_timeout / 1000) * 2 + 1);

	std::vector<host_cache_entry> updated_entries = get_client_host_cache_entries(proxysql_admin);
	ok(updated_entries.size() == 0, "Entries should be empty because cache was disabled.");

	diag("Setting the value of 'mysql-client_host_cache_size' to '10'");
	// Disable the cache
	MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_cache_size=10");
	MYSQL_QUERY(proxysql_admin, "SET mysql-client_host_error_counts=10");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH MYSQL CLIENT HOSTS");

	uint64_t pre_command_time = realtime_time_s();

	for (int i = 2; i < NUM_LOOPBACK_ADDRS; i++) {
		std::string loopback_addr { "127.0.0." + std::to_string(i) };
		for (errors = 0; errors < 2; errors++) {
			int inv_user_errno = create_tcp_conn(cl, loopback_addr);
			diag("Client connection timeout out with error: %d", inv_user_errno);
		}
	}
	sleep((client_timeout / 1000) * 2 + 1);

	updated_entries = get_client_host_cache_entries(proxysql_admin);
	ok(updated_entries.size() == 3, "Cache should hold three entries for the timed out connections.");

	int entry_num = 0;
	for (const auto& entry : updated_entries) {
		const std::string client_addr { std::get<0>(entry) };
		const uint32_t error_count { std::get<1>(entry) };
		const uint64_t last_updated { std::get<2>(entry) };
		uint64_t post_command_time = realtime_time_s();

		std::string exp_client_addr { "127.0.0." + std::to_string(entry_num + 2) };

		ok(
			client_addr == exp_client_addr && error_count == errors &&
			(pre_command_time <= (last_updated + 1) && (last_updated - 1) <= post_command_time),
			"Entry should match expected values - exp(addr: %s, err_count: %d, last_updated: %ld <= %ld +/- 1 <= %ld),"
			" act(addr: %s, err_count: %d, last_updated: %ld <= %ld +/- 1 <= %ld)",
			exp_client_addr.c_str(), errors, pre_command_time, last_updated, post_command_time,
			client_addr.c_str(), error_count, pre_command_time, last_updated, post_command_time
		);

		entry_num += 1;
	}


	return EXIT_SUCCESS;
}

int main(int, char**) {
	int res = 0;
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(30);

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
	diag("                Setting up extra loopback addresses                  ");
	diag("*********************************************************************");
	printf("\n");

	int setup_ns_i = 0;
	const std::string t_create_loopback_addr { "sudo ip addr add 127.0.0.%d dev lo" };
	const std::string t_delete_loopback_addr { "sudo ip addr delete 127.0.0.%d/32 dev lo" };

	for (setup_ns_i = 2; setup_ns_i < NUM_LOOPBACK_ADDRS; setup_ns_i++) {
		std::string create_loopback_addr {};
		string_format(t_create_loopback_addr, create_loopback_addr, setup_ns_i);

		int c_err = system(create_loopback_addr.c_str());
		if (c_err) {
			diag(
				"Failed to create netns number '%d' with err: '%d'",
				setup_ns_i, c_err
			);
			goto cleanup;
		}
	}

	// Create two extra loopback addresses for testing 'connection_timeout'
	for (; setup_ns_i < NUM_LOOPBACK_ADDRS + 2; setup_ns_i++) {
		std::string create_ns_command {};
		string_format(t_create_loopback_addr, create_ns_command, setup_ns_i);

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


	test_cache_filled_by_invalid_conn(cl, proxysql_admin);
	test_cache_entry_count_by_invalid_conn(cl, proxysql_admin);
	test_cache_entry_count_by_mult_invalid_conns(cl, proxysql_admin);
	test_client_exceeding_cache_error_limit(cl, proxysql_admin);
	test_client_exceeding_changed_error_limit(cl, proxysql_admin);
	test_cache_size_decrease_by_new_connections(cl, proxysql_admin);
	test_cache_populated_timeout_conns(cl, proxysql_admin);

cleanup:
	// Cleanup the virtual namespaces to be used by the test
	printf("\n");
	diag("            Cleanup of testing network namespaces                    ");
	diag("*********************************************************************");
	printf("\n");

	for (int i = 2; i < setup_ns_i; i++) {
		std::string delete_loopback_addr {};
		string_format(t_delete_loopback_addr, delete_loopback_addr, i);
		system(delete_loopback_addr.c_str());
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
