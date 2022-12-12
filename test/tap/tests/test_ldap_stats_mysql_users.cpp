/**
 * @file test_ldap_stats_mysql_users.cpp
 * @brief Test that ensures that 'stats_mysql_users' feature works as expected (including LDAP plugin).
 * @details TODO: Disabled for now because it requires CI changes.
 */

#include <algorithm>
#include <map>
#include <cstring>
#include <string>
#include <stdio.h>
#include <vector>

#include <sys/resource.h>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

using std::string;
using std::vector;
using std::map;

using user_stats_t = std::tuple<string,uint32_t>;

const string LDAP_USER_T { "clientuser" };
const string LDAP_PASS_T { "pfkdIfdHY&2" };

int get_ldap_users_stats(MYSQL* admin, vector<user_stats_t>& out_users_stats) {
	int rc = mysql_query(admin, "SELECT username, frontend_connections FROM stats_mysql_users");
	if (rc) {
		diag("'mysql_query' failed - errno:'%d', error:'%s'", mysql_errno(admin), mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL_RES* myres = mysql_store_result(admin);
	vector<mysql_res_row> res_rows { extract_mysql_rows(myres) };
	mysql_free_result(myres);

	auto matches_ldap_user = [] (const vector<string>& user_row) -> bool {
		if (user_row.empty()) {
			return false;
		}
		const string username { user_row[0] };
		return username.rfind(LDAP_USER_T, 0) == 0;
	};

	auto vec_to_user_stats = [] (const mysql_res_row& row) -> user_stats_t {
		if (row.empty()) {
			return {};
		} else if (row.size() < 2) {
			return { row[0], 0 };
		} else {
			return { row[0], std::stoi(row[1]) };
		}
	};

	vector<mysql_res_row> ldap_user_rows {};
	std::copy_if(res_rows.begin(), res_rows.end(), std::back_inserter(ldap_user_rows), matches_ldap_user);

	vector<user_stats_t> res_stats {};
	std::transform(
		ldap_user_rows.begin(), ldap_user_rows.end(), std::back_inserter(res_stats), vec_to_user_stats
	);

	out_users_stats = res_stats;

	return EXIT_SUCCESS;
}

void close_mysql_conns(vector<vector<MYSQL*>>& conns) {
	for (const vector<MYSQL*>& u_conns : conns) {
		for (MYSQL* u_conn : u_conns) {
			mysql_close(u_conn);
		}
	}
	conns.clear();
}

const uint32_t SRV_MAX_CONNS = 1000;
const uint32_t LDAP_MAX_CONNS = 20;
const uint32_t USER_NUM = 30;

int main(int argc, char** argv) {
	plan(
		1 + // Check that 'ldap-max_db_connections' is properly updated
		1 + // Check that row count from 'stats_mysql_users' match expected
		USER_NUM + // Check that actual user conns match expected
		USER_NUM + // Check that user conn cleanup worked as expected - zero conns
		LDAP_MAX_CONNS * 5 + // Check that conns are properly created below 'LDAP_MAX_CONNS'
		5 // Check that conns fails to be created over 'LDAP_MAX_CONNS'
	);

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	struct rlimit limits { 0, 0 };
	getrlimit(RLIMIT_NOFILE, &limits);
	diag("Old process limits: { %ld, %ld }", limits.rlim_cur, limits.rlim_max);
	limits.rlim_cur = USER_NUM * 1000;
	setrlimit(RLIMIT_NOFILE, &limits);
	diag("New process limits: { %ld, %ld }", limits.rlim_cur, limits.rlim_max);

	MYSQL* proxy = mysql_init(NULL);
	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, 13306, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Get the maximum number of connections per LDAP user right now, ''
	uint32_t ldap_max_conns = 0;
	vector<vector<MYSQL*>> users_mysql_conns {};
	uint32_t DEF_HG = 0;

	// Get the testing user default hostgroup - we assume PRIMARY
	{
		const string SELECT_DEF_HG_QUERY {
			"SELECT default_hostgroup FROM mysql_users WHERE username='" + string { cl.username } + "'"
		};
		MYSQL_QUERY(admin, SELECT_DEF_HG_QUERY.c_str());

		MYSQL_RES* res = mysql_store_result(admin);
		MYSQL_ROW row = mysql_fetch_row(res);

		DEF_HG = atoi(row[0]);
		mysql_free_result(res);
	}

	// Enforce a maximum number of connections for target backend server
	{
		const char UPD_SRVS_QUERY_T[] {
			"UPDATE mysql_servers SET max_connections=%d WHERE hostgroup_id=%d"
		};
		const string UPD_SRVS_QUERY { cstr_format(UPD_SRVS_QUERY_T, SRV_MAX_CONNS, DEF_HG).str };

		MYSQL_QUERY(admin, UPD_SRVS_QUERY.c_str());
		MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	// Enforce a maximum number of connections that for LDAP users
	{
		const string UPD_LDAP_MAX_CONNS_QUERY {
			"SET ldap-max_db_connections=" + std::to_string(LDAP_MAX_CONNS)
		};

		MYSQL_QUERY(admin, UPD_LDAP_MAX_CONNS_QUERY.c_str());
		MYSQL_QUERY(admin, "LOAD LDAP VARIABLES TO RUNTIME");
	}

	{
		MYSQL_QUERY(admin, "SHOW VARIABLES LIKE 'ldap-max_db_connections'");
		MYSQL_RES* res = mysql_store_result(admin);
		MYSQL_ROW row = mysql_fetch_row(res);

		ldap_max_conns = atoi(row[1]);
		mysql_free_result(res);

		ok(
			ldap_max_conns == LDAP_MAX_CONNS,
			"LDAP max conns for users should be correctly updated - Exp: %d, Act: %d",
			LDAP_MAX_CONNS, ldap_max_conns
		);
	}

	if (ldap_max_conns == 0) {
		diag("Invalid 'ldap_max_conns':'%d' found! Exiting...", ldap_max_conns);
		goto cleanup;
	}

	srand(time(NULL));

	// Create N random connections, that are less or equal to 'max_connections' for LDAP users and check that
	// matches stats from 'stats_mysql_users'
	{
		map<string, uint32_t> tg_users_conns {};

		for (uint32_t i = 0; i < USER_NUM; i++) {
			const string LDAP_USER { LDAP_USER_T + std::to_string(i) };
			const string LDAP_PASS { LDAP_PASS_T + std::to_string(i) };

			const uint32_t rand_conns = rand() % ldap_max_conns;
			const uint32_t tg_conns = rand_conns == 0 ? 1 : rand_conns;

			vector<MYSQL*> user_conns {};

			for (uint32_t j = 0; j < tg_conns; j++) {
				diag("Creating connection for user '%s'", LDAP_USER.c_str());

				MYSQL* conn = mysql_init(NULL);
				if (!mysql_real_connect(conn, cl.host, LDAP_USER.c_str(), LDAP_PASS.c_str(), NULL, cl.port, NULL, 0)) {
					fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
					goto cleanup;
				}

				user_conns.push_back(conn);
			}

			tg_users_conns.insert({LDAP_USER, tg_conns});
			users_mysql_conns.push_back(user_conns);
		}

		// Check conns from 'stats_mysql_users'
		vector<user_stats_t> ldap_user_stats {};
		int stats_res = get_ldap_users_stats(admin, ldap_user_stats);
		if (stats_res) {
			diag("Failure: 'get_ldap_users_stats' failed to obtain user stats");
			goto cleanup;
		}

		const bool stats_users_match_exp = ldap_user_stats.size() == USER_NUM;
		ok(
			stats_users_match_exp,
			"Rows from 'stats_mysql_users' should match expected users NUM - exp: %d, act: %lu",
			USER_NUM, ldap_user_stats.size()
		);

		if (stats_users_match_exp == false) {
			goto cleanup;
		} else {
			for (const user_stats_t& user_stats : ldap_user_stats) {
				const string& user { std::get<0>(user_stats) };
				const uint32_t exp_user_conns = tg_users_conns.at(user);
				const uint32_t act_user_conns = std::get<1>(user_stats);

				ok(
					exp_user_conns == act_user_conns,
					"Actual user connections should match expected - user: %s, exp:'%d', act:'%d'",
					user.c_str(),  exp_user_conns, act_user_conns
				);
			}
		}

		// Check that all the conns go back to '0' after closing all the connections
		diag("Closing all the connection and checking '0' is reported in stats");
		close_mysql_conns(users_mysql_conns);

		// Impose a timeout for connections to be actually closed on ProxySQL side before the final query
		const string conn_sum_check {
			"SELECT SUM(frontend_connections) FROM stats_mysql_users WHERE username LIKE 'clientuser%'"
		};

		int timeout = 3;
		int wait = 0;

		diag("Waiting timeout '%d's until conns closed on ProxySQL side...", timeout);

		while (wait < timeout) {
			mysql_query(admin, conn_sum_check.c_str());
			MYSQL_RES* sum_res = mysql_store_result(admin);
			MYSQL_ROW row = mysql_fetch_row(sum_res);

			bool not_empty_row = row != nullptr && row[0] != nullptr;
			int found_conns = -1;

			if (not_empty_row) {
				found_conns = atoi(row[0]);
			}

			mysql_free_result(sum_res);

			if (not_empty_row && found_conns == 0) {
				diag("-> Zero conns found open, stopping wait");
				break;
			} else {
				diag("-> Found '%d' conns still open, continue waiting...", found_conns);
				wait += 1;
				sleep(1);
			}
		}

		stats_res = get_ldap_users_stats(admin, ldap_user_stats);
		if (stats_res) {
			diag("Failure: 'get_ldap_users_stats' failed to obtain user stats");
			goto cleanup;
		}

		for (uint32_t i = 0; i < USER_NUM; i++) {
			const string& user { std::get<0>(ldap_user_stats[i]) };
			const uint32_t act_user_conns = std::get<1>(ldap_user_stats[i]);

			ok(
				0 == act_user_conns, "Zero should be reported for user connections - user: %s, act:'%d'",
				user.c_str(), act_user_conns
			);
		}
	}

	// Change the number of max_frontend connections and check the behavior for N users
	{
		uint32_t MAX_CONNS = 20;
		uint32_t USER_NUM = 5;

		string SET_LDAP_MAX_CONNS {};
		string_format("SET ldap-max_db_connections=%d", SET_LDAP_MAX_CONNS, MAX_CONNS);

		MYSQL_QUERY(admin, SET_LDAP_MAX_CONNS.c_str());
		MYSQL_QUERY(admin, "LOAD LDAP VARIABLES TO RUNTIME");

		vector<vector<MYSQL*>> users_conns {};

		for (uint32_t i = 0; i < USER_NUM; i++) {
			const string LDAP_USER { LDAP_USER_T + std::to_string(i) };
			const string LDAP_PASS { LDAP_PASS_T + std::to_string(i) };
			vector<MYSQL*> user_conns {};

			diag(
				"Creating initial '%d' conn under MAX_CONN limit '%d' for user '%s'",
				MAX_CONNS, MAX_CONNS, LDAP_USER.c_str()
			);

			for (uint32_t j = 0; j < MAX_CONNS; j++) {
				diag("Creating connection number '%d' for user '%s'", j, LDAP_USER.c_str());

				MYSQL* conn = mysql_init(NULL);
				MYSQL* myerr = mysql_real_connect(conn, cl.host, LDAP_USER.c_str(), LDAP_PASS.c_str(), NULL, cl.port, NULL, 0);

				ok(
					myerr != nullptr, "Conn number '%d' should SUCCEED for user '%s' - errno: '%d', error: '%s'",
					j, LDAP_USER.c_str(), mysql_errno(conn), mysql_error(conn)
				);

				if (myerr != nullptr) {
					user_conns.push_back(conn);
				}
			}

			// Create a final failing connection
			diag(
				"Creating final failing connection '%d' conn over MAX_CONN limit '%d' for user '%s'",
				MAX_CONNS, MAX_CONNS, LDAP_USER.c_str()
			);

			MYSQL* conn = mysql_init(NULL);
			MYSQL* myerr = mysql_real_connect(conn, cl.host, LDAP_USER.c_str(), LDAP_PASS.c_str(), NULL, cl.port, NULL, 0);

			ok(
				myerr == nullptr, "Conn number '%d' should FAIL for user '%s' - errno: '%d', error: '%s'",
				MAX_CONNS + 1, LDAP_USER.c_str(), mysql_errno(conn), mysql_error(conn)
			);

			if (conn != nullptr) {
				user_conns.push_back(conn);
			}

			users_conns.push_back(user_conns);
		}

		close_mysql_conns(users_conns);
	}

cleanup:
	close_mysql_conns(users_mysql_conns);

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
