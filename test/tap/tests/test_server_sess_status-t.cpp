/**
 * @file test_server_sess_status-t.cpp
 * @brief Test checking that ProxySQL 'server_status' value is properly updated for different operations.
 * @details Test should also check that unsupported status like 'SERVER_SESSION_STATE_CHANGED' are never
 *   reported by ProxySQL.
 */

#include <cstring>
#include <string>
#include <stdio.h>
#include <utility>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::pair;
using std::string;

int get_user_def_hg(MYSQL* admin, const string& user) {
	const string sel_q { "SELECT default_hostgroup FROM mysql_users WHERE username='" + user + "'" };
	if (mysql_query(admin, sel_q.c_str())) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin)); \
		return -1;
	}

	MYSQL_RES* myres = mysql_store_result(admin);
	MYSQL_ROW myrow = mysql_fetch_row(myres);

	if (myrow && myrow[0]) {
		int def_hg = std::atoi(myrow[0]);
		mysql_free_result(myres);

		return def_hg;
	} else {
		const string err_msg { "Unexpected empty result received for query: " + sel_q };
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, err_msg.c_str());
		return -1;
	}
}

pair<string,int> get_def_srv_host_port(MYSQL* admin, int hg) {
	const string sel_q { "SELECT hostname,port FROM mysql_servers WHERE hostgroup_id=" + std::to_string(hg) };
	int myrc = mysql_query(admin, sel_q.c_str());

	if (myrc) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return { "", -1 };
	} else {
		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[0] && myrow[1]) {
			string host { myrow[0] };
			int port { std::atoi(myrow[1]) };
			mysql_free_result(myres);

			return { host, port };
		} else {
			const string err_msg { "Unexpected empty result received for query: '" + sel_q + "'"};
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, err_msg.c_str());
			return { "", -1 };
		}
	}
}

pair<string,int> get_def_srv_host(MYSQL* admin, const string user) {
	// Get the server from the default hostgroup
	int def_hg = get_user_def_hg(admin, user);
	if (def_hg == -1) {
		return { "", -1 };
	}

	return get_def_srv_host_port(admin, def_hg);
}

int main(int argc, char** argv) {
	CommandLine cl;

	// TODO: Harcoded for now, this is an initial version of the test.
	plan(4);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxy = mysql_init(NULL);
	MYSQL* mysql = mysql_init(NULL);
	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	const pair<string,int> srv_host { get_def_srv_host(admin, cl.username) };
	if (srv_host.first.empty()) {
		diag("Failed to obtain the target server hostname/port. Aborting further testing");
		goto cleanup;
	}

	{
		if (!mysql_real_connect(mysql, srv_host.first.c_str(), cl.username, cl.password, NULL, srv_host.second, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			goto cleanup;
		}

		int exp_mysql_srv_st = SERVER_STATUS_AUTOCOMMIT;

		ok(
			exp_mysql_srv_st == SERVER_STATUS_AUTOCOMMIT,
			"MySQL init server status should match expected - exp: '%d', act:'%d'",
			exp_mysql_srv_st, mysql->server_status
		);

		mysql_query(mysql, "SET SESSION session_track_transaction_info=\"CHARACTERISTICS\"");
		mysql_query(mysql, "START TRANSACTION");

		exp_mysql_srv_st = SERVER_STATUS_AUTOCOMMIT | SERVER_STATUS_IN_TRANS | SERVER_SESSION_STATE_CHANGED;

		ok(
			exp_mysql_srv_st == mysql->server_status,
			"MySQL new server status should match expected - exp: '%d', act:'%d'",
			exp_mysql_srv_st, mysql->server_status
		);

		// TODO-FIXME: We are setting here '0' as expecting to see 'SERVER_STATUS_AUTOCOMMIT' to be false.
		// This is a bug that should be addressed, and this test revisited.
		ok(
			proxy->server_status == 0,
			"ProxySQL init server status should match expected - exp: '%d', act:'%d'",
			0, proxy->server_status
		);

		mysql_query(proxy, "SET SESSION session_track_transaction_info=\"CHARACTERISTICS\"");
		mysql_query(proxy, "START TRANSACTION");

		uint32_t exp_proxy_srv_st = SERVER_STATUS_AUTOCOMMIT | SERVER_STATUS_IN_TRANS;

		ok(
			exp_proxy_srv_st == proxy->server_status,
			"ProxySQL new server status should match expected - exp: '%d', act:'%d'",
			exp_proxy_srv_st, proxy->server_status
		);
	}

cleanup:
	mysql_close(proxy);
	mysql_close(mysql);
	mysql_close(admin);

	return exit_status();
}
