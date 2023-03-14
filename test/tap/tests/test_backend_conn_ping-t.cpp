/**
 * @file test_backend_conn_ping-t.cpp
 * @brief Checks that backend connections are getting properly kept alive via ping by ProxySQL.
 * @details For achieving this, the test performs the following actions:
 *   1. Create an specific number of backend connections in batches in the target hostgroups via
 *      'create_new_connection' and 'hostgroup' query annotations.
 *      NOTE: The number of created connections per batch and in total shouldn't exceed ProxySQL
 *      maximum processing rate. Determined by 'mysql-ping_interval_server_msec'.
 *   2. Check periodically that the number of current connections reflected in both the target MySQL server
 *      ('information_schema.processlist') and in ProxySQL ('stats_mysql_free_connections') doesn't change
 *      over time. I.e. connections are not getting destroyed due to not being kept alive.
 *   3. Perform a query per each created connection exahusting the backend connections while checking for
 *      any error reported by the client due to broken connections.
 */

/*
NOTE: the parameters in this test are tuned in a way that if proxysql starts
with only 1 worker thread, it is unlikely to ping all connections on time.
See note on wait_timeout
*/

#include <string>
#include <vector>
#include <map>
#include <utility>
#include <iostream>

#include <unistd.h>
#include <string.h>
#include <sys/resource.h>

#include "tap.h"
#include "utils.h"
#include "json.hpp"

using std::vector;
using std::string;
using std::pair;

using srv_cfg = vector<pair<string,int>>;

int wait_timeout = 10;

// if only 1 worker thread is running, wait_timeout should be bigger
// 1 worker thread : wait_timeout = 45
// 4 worker threads : wait_timeout = 10
int compute_wait_timeout(MYSQL *my_conn) {
	int res = EXIT_SUCCESS;
	res = mysql_query(my_conn, "SELECT @@mysql-threads");
	if (res != EXIT_SUCCESS) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(my_conn));
		res = EXIT_FAILURE;
		return res;
	}
	MYSQL_RES* my_res = mysql_store_result(my_conn);
	if (my_res == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(my_conn));
		res = EXIT_FAILURE;
		return res;
	}

	MYSQL_ROW row = mysql_fetch_row(my_res);
	if (row == nullptr || row[0] == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(my_conn));
		res = EXIT_FAILURE;
		return res;
	} else {
		const char *val = row[0];
		diag("mysql-threads = %s", val);
		if (strcmp(val,"1")==0) {
			diag("Setting wait_timeout to 45 instead of 10");
			wait_timeout = 45;
		}
	}
	mysql_free_result(my_res);

	return res;
}


int change_mysql_cfg(
	const CommandLine& cl, const string& host, const string& port, const srv_cfg& new_srv_cfg, srv_cfg& out_old_srv_cfg
) {
	int res = EXIT_SUCCESS;

	MYSQL* my_conn = mysql_init(NULL);
	if (!my_conn) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(my_conn));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(my_conn, host.c_str(), cl.username, cl.password, NULL, std::stol(port.c_str()), NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(my_conn));
		res = EXIT_FAILURE;
	}

	if (res == EXIT_SUCCESS) {
		srv_cfg old_server_config {};

		for (const pair<string,int>& config_var : new_srv_cfg) {
			res = mysql_query(my_conn, string {"SELECT @@" + config_var.first}.c_str());
			if (res != EXIT_SUCCESS) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(my_conn));
				res = EXIT_FAILURE;
				break;
			}

			MYSQL_RES* my_res = mysql_store_result(my_conn);
			if (my_res == nullptr) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(my_conn));
				res = EXIT_FAILURE;
				break;
			}

			MYSQL_ROW row = mysql_fetch_row(my_res);
			if (row == nullptr || row[0] == nullptr) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(my_conn));
				res = EXIT_FAILURE;
				break;
			} else {
				old_server_config.push_back({ config_var.first, std::stol(row[0]) });
			}

			mysql_free_result(my_res);

			string query = string { "SET GLOBAL " + config_var.first + "=" + std::to_string(config_var.second) };
			diag("Setting on %s:%s : %s", host.c_str(), port.c_str(), query.c_str());
			mysql_query(my_conn, query.c_str());
			if (res != EXIT_SUCCESS) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(my_conn));
				res = EXIT_FAILURE;
				break;
			}
		}

		if (res == EXIT_SUCCESS) {
			out_old_srv_cfg = old_server_config;
		}
	}

	mysql_close(my_conn);

	return res;
}

int create_new_backend_conn(const CommandLine& cl, int tg_hg, vector<MYSQL*>& mysql_conns) {
	MYSQL* conn = mysql_init(NULL);

	if (!conn) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(conn, cl.host, cl.username, cl.password, "backend_conn_ping_test", cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
		return EXIT_FAILURE;
	}

	const string query { "DO /* ;hostgroup=" + std::to_string(tg_hg) + ";create_new_connection=1 */ 1" };
	MYSQL_QUERY(conn, query.c_str());
	mysql_conns.push_back(conn);

	return EXIT_SUCCESS;
}

int get_query_result(MYSQL* mysql, const string& query, uint64_t& out_val) {
	int rc = mysql_query(mysql, query.c_str());
	if (rc != EXIT_SUCCESS) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return EXIT_FAILURE;
	}

	MYSQL_RES* myres = mysql_store_result(mysql);
	if (myres == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return EXIT_FAILURE;
	}

	MYSQL_ROW row = mysql_fetch_row(myres);
	if (row == nullptr || row[0] == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "mysql_fetch_row() failed");
		return EXIT_FAILURE;
	}

	out_val = std::stol(row[0]);

	mysql_free_result(myres);

	return EXIT_SUCCESS;
}

struct test_params_t {
	double init_batch_size;
	double batch_size;
	double its;
	double delay_s;
};

using svr_addr = pair<string,uint32_t>;

int check_backend_conns(
	const CommandLine& cl, const test_params_t& test_params, uint32_t hg, const vector<svr_addr>& svrs_addrs
) {
	vector<MYSQL*> mysql_conns {};
	int res = EXIT_SUCCESS;

	for (uint32_t i = 0; i < test_params.init_batch_size; i++) {
		int c_res = create_new_backend_conn(cl, hg, mysql_conns);
		if (c_res != EXIT_SUCCESS) { return EXIT_FAILURE; }
	}

	usleep(test_params.delay_s * (test_params.init_batch_size / test_params.batch_size) * 1000 * 1000);

	// 1. Create server connections to monitor
	for (uint32_t i = 0; i < test_params.its; i++) {
		for (uint32_t j = 0; j < test_params.batch_size; j++) {
			int c_res = create_new_backend_conn(cl, hg, mysql_conns);
			if (c_res != EXIT_SUCCESS) { return EXIT_FAILURE; }
		}

		usleep(test_params.delay_s * 1000 * 1000);
	}

	// 2. Check that the connections remain steady for a period of time
	MYSQL* admin = mysql_init(NULL);
	vector<MYSQL*> svrs_conns {};

	{
		if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
			return EXIT_FAILURE;
		}

		for (const auto& svr_addr : svrs_addrs) {
			MYSQL* mysql = mysql_init(NULL);

			if (!mysql_real_connect(mysql, svr_addr.first.c_str(), cl.username, cl.password, NULL, svr_addr.second, NULL, 0)) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
				res = EXIT_FAILURE;
				goto cleanup;
			}

			svrs_conns.push_back(mysql);
		}

		sleep(5);

		uint64_t exp_conn_count = test_params.init_batch_size + test_params.batch_size * test_params.its;

		int q_res = EXIT_SUCCESS;
		uint64_t act_mysql_conn_count = 0;
		uint64_t act_proxy_free_conn_count = 0;
		uint64_t act_proxy_used_conn_count = 0;

		uint32_t total_wait_time = 40;
		uint32_t intv = 5;
		uint32_t total_checks = total_wait_time / intv;

		for (uint32_t check_num = 0; check_num < total_checks; check_num++) {
			// Reset the previous value
			act_mysql_conn_count = 0;

			const string mysql_query {
				"SELECT count(*) FROM information_schema.processlist WHERE"
					" COMMAND=\"Sleep\" and USER=\"" + string { cl.username } + "\" and DB=\"backend_conn_ping_test\""
			};

			for (MYSQL* mysql : svrs_conns) {
				uint64_t tmp_mysql_conn_count = 0;

				int q_res = get_query_result(mysql, mysql_query, tmp_mysql_conn_count);
				if (q_res != EXIT_SUCCESS) {
					fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "get_query_result() failed");
					break;
				}

				act_mysql_conn_count += tmp_mysql_conn_count;
			}

			const string srv_ports {
				std::accumulate(std::begin(svrs_addrs), std::end(svrs_addrs), string {},
					[](const string& s1, const svr_addr& addr) -> string {
						if (s1.empty()) {
							return "'" + std::to_string(addr.second) + "'";
						} else {
							return s1 + ", '" + std::to_string(addr.second) + "'";
						}
					}
				)
			};

			const string proxy_query {
				"SELECT COUNT(*) FROM stats_mysql_free_connections WHERE"
					" user='" + string { cl.username } + "'"
					" AND hostgroup='" + std::to_string(hg) + "'"
					" AND schema='backend_conn_ping_test'"
					" AND srv_port IN (" + srv_ports + ")"
			};

			q_res = get_query_result(admin, proxy_query, act_proxy_free_conn_count);
			if (q_res != EXIT_SUCCESS) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "get_query_result() failed");
				break;
			}

			const string proxy_used_query {
				"SELECT ConnUsed from stats_mysql_connection_pool WHERE hostgroup=" + std::to_string(hg)
			};
			q_res = get_query_result(admin, proxy_query, act_proxy_used_conn_count);

			diag(
				"Waiting and checking backend connections...:"
				" { CheckNum: %d, ExpConns: %ld, ActMySQLConns: %ld, ActProxyFreeConns: %ld, ActProxyUsedConns: %ld }",
				check_num, exp_conn_count, act_mysql_conn_count, act_proxy_free_conn_count, act_proxy_used_conn_count
			);

			if (
				act_mysql_conn_count >= exp_conn_count ||
				(act_proxy_free_conn_count + act_proxy_used_conn_count) >= exp_conn_count
			) {
				break;
			}

			sleep(intv);
		}

		ok(
			q_res == EXIT_SUCCESS && act_mysql_conn_count >= exp_conn_count &&
			((act_proxy_free_conn_count + act_proxy_used_conn_count) >= exp_conn_count) &&
			act_mysql_conn_count == act_proxy_free_conn_count,
			"Created server connections should be properly maintained (pinged) by ProxySQL:"
			" { ExpConns: %ld, ActMySQLConns: %ld, ActProxyConns: %ld }",
			exp_conn_count, act_mysql_conn_count, act_proxy_free_conn_count
		);
	}

	// 3. Check that no client side errors take place when exhausting backend connections
	{
		uint32_t broken_conns = 0;
		for (MYSQL* conn : mysql_conns) {
			int rc = mysql_query(conn, string {"/* ;hostgroup=" + std::to_string(hg) +  "*/ BEGIN"}.c_str());
			if (rc != EXIT_SUCCESS) {
				diag("'mysql_query' failed with error: '%s'", mysql_error(conn));
				broken_conns += 1;
			}

			rc = mysql_query(conn, "DO 1");
			if (rc != EXIT_SUCCESS) {
				diag("'mysql_query' failed with error: '%s'", mysql_error(conn));
				broken_conns += 1;
			}
		}

		ok(broken_conns == 0, "Found '%d' client side errors due to broken connections.", broken_conns);
	}

cleanup:

	mysql_close(admin);
	for (MYSQL* mysql : svrs_conns) {
		mysql_close(mysql);
	}

	for (MYSQL* mysql : mysql_conns) {
		mysql_close(mysql);
	}

	return res;
}

int wait_target_backend_conns(MYSQL* admin, uint32_t tg_backend_conns, uint32_t timeout) {
	uint32_t waited = 0;

	while (waited < timeout) {
		uint64_t cur_conn_num = 0;
		int q_res = get_query_result(admin, "SELECT SUM(ConnFree + ConnUsed) FROM stats_mysql_connection_pool", cur_conn_num);
		if (q_res != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "'get_query_result() failed.");
			return -1;
		}

		if (cur_conn_num == tg_backend_conns) {
			diag("tg_backend_conns: %d, cur_conn_num: %ld", tg_backend_conns, cur_conn_num);
			break;
		} else {
			waited += 1;
			diag("tg_backend_conns: %d, cur_conn_num: %ld , not matching after %lu checks", tg_backend_conns, cur_conn_num, waited);
			sleep(1);
		}
	}

	return waited < timeout ? 0 : -2;
}

int main(int, char**) {
	CommandLine cl;

	plan(4);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	struct rlimit limits { 0, 0 };
	getrlimit(RLIMIT_NOFILE, &limits);
	limits.rlim_cur = 10000;
	setrlimit(RLIMIT_NOFILE, &limits);

	MYSQL* proxy_mysql = mysql_init(NULL);

	// Initialize connections
	if (!proxy_mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		return EXIT_FAILURE;
	}

	// Create a new 'db' for connection filtering
	MYSQL_QUERY(proxy_mysql, "CREATE DATABASE IF NOT EXISTS backend_conn_ping_test");
	// Close no longer required connection
	mysql_close(proxy_mysql);

	MYSQL* proxy_admin = mysql_init(NULL);
	if (!proxy_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	if (compute_wait_timeout(proxy_admin) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	double intv = 5;
	double b = 128;
	double b_0 = 256;
	double freq = 1000;
	double rate = 64 / ( freq / 1000 );
	double conn_creation_intv = 30;

	double its = (conn_creation_intv - b_0/rate) / ( b / rate );
	double delay_s = conn_creation_intv / its;

	// Cleanup previous backend connections
	diag("Cleaning up previous backend connections...");
	MYSQL_QUERY(proxy_admin, "UPDATE mysql_servers SET max_connections=0");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Wait for backend connection cleanup
	int w_res = wait_target_backend_conns(proxy_admin, 0, 10);
	if (w_res != EXIT_SUCCESS) {
		if (w_res == -2) {
			const char* err_msg = "'wait_target_backend_conns()' timed out";
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, err_msg);
		}

		return EXIT_FAILURE;
	}
	MYSQL_QUERY(proxy_admin, "UPDATE mysql_servers SET max_connections=2500");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	diag("Setting ProxySQL config...");
	{
		// Set the backend connections ping frequency
		string query = string { "SET mysql-ping_interval_server_msec=" + std::to_string(freq) };
		diag("%s", query.c_str());
		MYSQL_QUERY(proxy_admin, query.c_str());
		// Make sure no connection cleanup takes place
		query = "SET mysql-free_connections_pct=100";
		diag("%s", query.c_str());
		MYSQL_QUERY(proxy_admin, query.c_str());
		// Don't retry on failure
		query = "SET mysql-query_retries_on_failure=0";
		diag("%s", query.c_str());
		MYSQL_QUERY(proxy_admin, query.c_str());
		// Set a higher max_connection number for the servers
		MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}
	// Configure MySQL infra servers with: 'wait_timeout' and 'max_connections'
	vector<pair<mysql_res_row, srv_cfg>> servers_old_configs {};

	diag("Configure 'MYSQL' infra servers...");
	{
		MYSQL_QUERY(proxy_admin, "SELECT DISTINCT hostname, port FROM mysql_servers WHERE hostgroup_id IN (0,1)");
		MYSQL_RES* my_servers_res = mysql_store_result(proxy_admin);
		vector<mysql_res_row> servers_rows = extract_mysql_rows(my_servers_res);
		mysql_free_result(my_servers_res);

		if (servers_rows.empty()) {
			fprintf(stderr, "File %s, line %d, Error: Invalid result returned from 'mysql_servers'\n", __FILE__, __LINE__);
			return EXIT_FAILURE;
		}

		srv_cfg new_srv_cfg { { "wait_timeout", wait_timeout }, { "max_connections", 2500 } };

		for (const mysql_res_row& srv_row : servers_rows) {
			srv_cfg old_srv_cfg {};
			int cfg_res = change_mysql_cfg(cl, srv_row[0], srv_row[1], new_srv_cfg, old_srv_cfg);

			if (cfg_res != EXIT_SUCCESS) {
				return EXIT_FAILURE;
			} else {
				servers_old_configs.push_back({ srv_row, old_srv_cfg });
			}
		}

		usleep(500 * 1000);
	}

	test_params_t test_params { b_0, b, its, delay_s };

	vector<svr_addr> s_server_test { { "127.0.0.1", 13306 } };
	vector<svr_addr> m_server_test { { "127.0.0.1", 13306 }, { "127.0.0.1", 13307 }, { "127.0.0.1", 13308 } };

	diag("Performing 'check_backend_conns()' for servers: '%s'", nlohmann::json(s_server_test).dump().c_str());
	int s_server_rc = check_backend_conns(cl, test_params, 0, s_server_test);
	if (s_server_rc == EXIT_SUCCESS) {
		diag("Cleaning up previous backend connections...");
		MYSQL_QUERY(proxy_admin, "UPDATE mysql_servers SET max_connections=0");
		MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		int w_res = wait_target_backend_conns(proxy_admin, 0, 10);
		if (w_res != EXIT_SUCCESS) {
			string err_msg {};
			if (w_res == -2) {
				err_msg = "'wait_target_backend_conns()' timed out";
			} else {
				err_msg = "'wait_target_backend_conns()' failed";
			}
			fprintf(stderr, "File %s, line %d, Error: \"%s\"\n", __FILE__, __LINE__, err_msg.c_str());
		}

		MYSQL_QUERY(proxy_admin, "UPDATE mysql_servers SET max_connections=2500");
		MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		if (w_res == EXIT_SUCCESS) {
			diag("Performing 'check_backend_conns()' for servers: '%s'", nlohmann::json(m_server_test).dump().c_str());

			int m_server_rc = check_backend_conns(cl, test_params, 1, m_server_test);
			if (m_server_rc == EXIT_FAILURE) {
				diag("'check_backend_conns()' failed for servers: '%s'", nlohmann::json(s_server_test).dump().c_str());
			}
		}
	} else {
		diag("'check_backend_conns()' failed for servers: '%s'", nlohmann::json(m_server_test).dump().c_str());
	}

	diag("Restoring previous 'MySQL' servers infra config...");

	{
		// do some cleanup
		string query = "SET mysql-free_connections_pct=5";
		diag("%s", query.c_str());
		MYSQL_QUERY(proxy_admin, query.c_str());
		MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}
	{
		for (const auto& server_old_config : servers_old_configs) {
			const mysql_res_row& res_row = server_old_config.first;
			const srv_cfg& old_srv_config = server_old_config.second;

			srv_cfg _tmp_conf {};
			int cfg_res = change_mysql_cfg(cl, res_row[0], res_row[1], old_srv_config, _tmp_conf);
			if (cfg_res != EXIT_SUCCESS) {
				return EXIT_FAILURE;
			}
		}
	}

	sleep(2); // wait for the cleanup to happen
	mysql_close(proxy_admin);

	return exit_status();
}
