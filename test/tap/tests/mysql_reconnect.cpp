/**
 * @file mysql_reconnect.cpp
 * @brief Check that reconnect works against ProxySQL with/without SSL enabled.
 * @details The test requires to be compiled against libmariadb and libmysql. This allows to perform a
 *   regression test against libmysql regarding reconnect and SSL session tickets.
 */

#include <cstring>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <thread>

#ifdef LIBMYSQL_HELPER8
#include "mysql/mysql.h"
#else
#include "mysql.h"
#endif

#include "utils.h"
#include "tap.h"
#include "command_line.h"

using std::string;
using std::vector;

struct _conn_cnf_t {
	bool ssl;
	bool eof;
};

int test_reconnect(const CommandLine& cl, const _conn_cnf_t& cnf) {
	MYSQL* proxy = mysql_init(NULL);

	bool reconnect = 1;
	int cflags = 0;

	if (cnf.ssl) {
#ifdef LIBMYSQL_HELPER8
		enum mysql_ssl_mode ssl_mode = SSL_MODE_REQUIRED;
		mysql_options(proxy, MYSQL_OPT_SSL_MODE, &ssl_mode);
#else
		mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);
		cflags |= CLIENT_SSL;
#endif
	}

	if (cnf.eof) {
		proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;
	}

	mysql_options(proxy, MYSQL_OPT_RECONNECT, &reconnect);
	cflags |= CLIENT_REMEMBER_OPTIONS;

	const string TG_BACKEND { get_env_str("TG_BACKEND", "PROXYSQL") };

	const char* user = cl.username;
	const char* pass = cl.password;
	const char* host = cl.host;
	int port = cl.port;

	if (TG_BACKEND == "MYSQL") {
		port = cl.mysql_port;
	}

	diag(
		"Creating initial conn against ProxySQL   host:'%s', port:'%d', user:'%s', pass:'%s'",
		cl.host, cl.port, cl.username, cl.password
	);

	if (!mysql_real_connect(proxy, host, user, pass, NULL, port, NULL, cflags)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

#ifdef LIBMYSQL_HELPER8
	void* ssl_session_data = nullptr;

	if (cnf.ssl) {
		ssl_session_data = mysql_get_ssl_session_data(proxy, 0, nullptr);
		if (ssl_session_data) {
			mysql_options(proxy, MYSQL_OPT_SSL_SESSION_DATA, ssl_session_data);
		}
	}
#endif

	const char* admin_user = cl.admin_username;
	const char* admin_pass = cl.admin_password;
	const char* admin_host = cl.admin_host;
	int admin_port = cl.admin_port;

	if (TG_BACKEND == "MYSQL") {
		admin_user = cl.mysql_username;
		admin_pass = cl.mysql_password;
		admin_port = cl.mysql_port;
	}

	MYSQL* admin = mysql_init(NULL);

	diag(
		"Creating Admin conn against ProxySQL   host:'%s', port:'%d', user:'%s', pass:'%s'",
		admin_host, admin_port, admin_user, admin_pass
	);
	if (!mysql_real_connect(admin, admin_host, admin_user, admin_pass, NULL, admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	pid_t pid = getpid();
	const string s_pid { std::to_string(pid) };

	std::thread query_thread([proxy, s_pid] () {
		const string query { "/* client_pid=" + s_pid + " */ SELECT SLEEP(20)" };
		int rc = mysql_query(proxy, query.c_str());

		ok(rc != 0, "Query should exit with error   rc:%d, err:'%s'", rc, mysql_error(proxy));

		rc = mysql_query(proxy, "DO 1");
		if (rc) {
			diag("Simple query failed after reconnect   query:'%s', err:'%s'", "DO 1", mysql_error(proxy));
		}

		ok(rc == 0, "Second query should succeed (reconnect)   rc:%d, err:'%s'", rc, mysql_error(proxy));
	});

	const string cond_query {
		TG_BACKEND == "PROXYSQL" ?
			"SELECT IIF("
				"(SELECT COUNT(*) FROM stats_mysql_processlist WHERE"
					" info LIKE '%client_pid=" + s_pid + "%')=1, 'TRUE', 'FALSE')" :
			"SELECT IF("
				"(SELECT COUNT(*) FROM information_schema.processlist WHERE"
					" info LIKE '%client_pid=" + s_pid + "%' AND state='User sleep')=1, 'TRUE', 'FALSE')"
	};

	int wres = wait_for_cond(admin, cond_query.c_str(), 60);

	const string ext_query {
		TG_BACKEND == "PROXYSQL" ?
			"SELECT SessionID FROM stats_mysql_processlist WHERE info LIKE '%client_pid=" + s_pid + "%'" :
			"SELECT ID FROM information_schema.processlist WHERE info LIKE '%client_pid=" + s_pid + "%'"
				" AND state='User sleep'"
	};

	ext_val_t<int64_t> ext_sess_id = mysql_query_ext_val(admin, ext_query, int64_t(0));

	if (ext_sess_id.err != EXIT_SUCCESS) {
		const string err { get_ext_val_err(admin, ext_sess_id) };
		diag("Failed getting 'SessionID'   query:`%s`, err:`%s`", ext_query.c_str(), err.c_str());
		goto cleanup;
	}

	{
		const string kill_sess_query { "KILL CONNECTION " + std::to_string(ext_sess_id.val) };
		mysql_query(admin, kill_sess_query.c_str());
	}

cleanup:

	{
		query_thread.join();

		mysql_close(admin);
#ifdef LIBMYSQL_HELPER8
		if (ssl_session_data) {
			mysql_free_ssl_session_data(proxy, ssl_session_data);
		}
#endif
		mysql_close(proxy);
	}

	return EXIT_SUCCESS;
}


int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const auto& bin_vecs { get_all_bin_vec(2) };
	plan(bin_vecs.size() * 2);

	for (const vector<bool> vec : bin_vecs) {
		_conn_cnf_t conf { vec[0], vec[1] };
		diag("Testing reconnect with config   ssl:%d, eof:%d", conf.ssl, conf.eof);

		int rc = test_reconnect(cl, conf);
		if (rc) {
			diag("Reconnect failed, aborting further testing...   rc:%d, ssl:%d, eof:%d", rc, conf.ssl, conf.eof);
			break;
		}
	}

	return exit_status();
}
