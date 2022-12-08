/**
 * @file reg_test_3847_admin_lock-t.cpp
 * @brief This is a regression test for the deadlock described in issue #3847.
 */

#include <cstring>
#include <vector>
#include <string>
#include <thread>
#include <stdio.h>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

int main(int argc, char** argv) {
	CommandLine cl;

	const char* WORKSPACE = getenv("WORKSPACE");

	if (cl.getEnv() || WORKSPACE == nullptr) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	bool stop = false;
	int q_load_res = -1;
	int q_globals_res = -1;

	MYSQL* p_proxy_admin = mysql_init(NULL);

	if (!mysql_real_connect(p_proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(p_proxy_admin));
		return EXIT_FAILURE;
	}

	const string sec_cfg_file = string { cl.workdir } + "reg_test_3847_node_datadir/proxysql_sec.cfg";
	const string sec_log_file = string { cl.workdir } + "reg_test_3847_node_datadir/proxysql_sec.log";

	const string sec_proxy_cmd {
		string { "ASAN_OPTIONS=abort_on_error=0:halt_on_error=0:fast_unwind_on_fatal=1:detect_leaks=0 " } +
			string { WORKSPACE } + "/src/proxysql -M -c \"" + sec_cfg_file + "\" > " + sec_log_file + " 2>&1"
	};

	int launch_res = -1;

	std::thread launch_sec_proxy = std::thread([&WORKSPACE,&cl] (int& err_code) -> void {
		to_opts_t wexecvp_opts {};
		wexecvp_opts.poll_to_us = 100*1000;
		wexecvp_opts.waitpid_delay_us = 500*1000;
		// Stop launched process after 20s
		wexecvp_opts.timeout_us = 20000 * 1000;
		// Send sigkill 3s after timeout
		wexecvp_opts.sigkill_to_us = 3000 * 1000;

		const string sec_cfg_file = string { cl.workdir } + "reg_test_3847_node_datadir/proxysql_sec.cfg";
		const string sec_log_file = string { cl.workdir } + "reg_test_3847_node_datadir/proxysql_sec.log";
		const string proxysql_path { string { WORKSPACE } + "/src/proxysql" };

		const vector<const char*> proxy_args { "-f", "-M", "-c", sec_cfg_file.c_str() };

		string s_stdout {};
		string s_stderr {};

		int w_res = wexecvp(proxysql_path, proxy_args, wexecvp_opts, s_stdout, s_stderr);
		if (w_res != EXIT_SUCCESS) {
			diag("'wexecvp' failed with error: %d", w_res);
		}

		err_code = w_res;

		// Write process output to log file
		try {
			std::ofstream os_logfile { sec_log_file, std::ios::out };
			os_logfile << s_stderr;
		} catch (const std::exception& ex) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, ex.what());
		}
	}, std::ref(launch_res));

	// Check that the second ProxySQL is up and responsive
	conn_opts_t conn_opts { "127.0.0.1", "radmin", "radmin", 26081 };
	// Wait at max the child process timeout plus 5 seconds
	MYSQL* s_proxy_admin = wait_for_proxysql(conn_opts, 25);

	if (s_proxy_admin == nullptr) {
		fprintf(stderr, "Error: %s\n", "Waiting for ProxySQL replica timedout");
		launch_sec_proxy.detach();
		return EXIT_FAILURE;
	}

	// Configure Cluster access for primary ProxySQL
	MYSQL_QUERY(p_proxy_admin, "SET admin-admin_credentials='admin:admin;radmin:radmin;cluster1:secret1pass'");
	MYSQL_QUERY(p_proxy_admin, "SET admin-cluster_username='cluster1'");
	MYSQL_QUERY(p_proxy_admin, "SET admin-cluster_password='secret1pass'");
	MYSQL_QUERY(p_proxy_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// Configure secondary node
	MYSQL_QUERY(s_proxy_admin, "SET admin-cluster_check_interval_ms=10");
	MYSQL_QUERY(s_proxy_admin, "SET admin-cluster_mysql_variables_diffs_before_sync=1");
	MYSQL_QUERY(s_proxy_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	std::thread th_load_mysql_vars([&cl] (bool& stop, int& load_res) -> void {
		MYSQL* admin = mysql_init(NULL);

		if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
			load_res = mysql_errno(admin);
		}

		int default_query_timeout = 36000000;

		while (stop == false) {
			string set_query { "SET mysql-default_query_timeout=" + std::to_string(default_query_timeout) };
			mysql_query(admin, set_query.c_str());
			int my_res = mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

			if (my_res) {
				load_res = mysql_errno(admin);
				break;
			} else {
				usleep(1000 * 10 * 2);
			}

			if (default_query_timeout > 36000000) {
				default_query_timeout = 36000000;
			} else {
				default_query_timeout += 1;
			}
		}

		load_res = 0;

		mysql_close(admin);
	}, std::ref(stop), std::ref(q_load_res));

	std::thread th_query_globals([&cl] (bool& stop, int& save_res) -> void {
		MYSQL* admin = mysql_init(NULL);

		if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, 26081, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
			save_res = mysql_errno(admin);
		}

		while (stop == false) {
			int my_res = mysql_query(admin, "SELECT COUNT(*) FROM runtime_global_variables");
			if (my_res) {
				save_res = mysql_errno(admin);
				break;
			} else {
				mysql_free_result(mysql_store_result(admin));
			}
		}

		save_res = 0;

		mysql_close(admin);
	}, std::ref(stop), std::ref(q_globals_res));

	uint32_t timeout = 10;
	uint32_t wait = 0;

	while (wait < timeout) {
		if (q_globals_res != -1) {
			fprintf(stderr, "'th_admin_save' failed with error: %d\n", q_globals_res);
			break;
		}
		if (q_load_res != -1) {
			fprintf(stderr, "'th_admin_load' failed with error: %d\n", q_load_res);
			break;
		}

		sleep(1);
		wait += 1;
	}

	{
		diag("Shutting down worker threads");
		int timeout = 2;
		int waited = 0;

		stop = true;

		if ((q_globals_res == -1 || q_load_res == -1) && waited < timeout) {
			sleep(1);
			waited += 1;
		}
	}

	ok(q_load_res == 0, "'th_load_mysql_vars' thread didn't deadlock: %d", q_load_res);
	ok(q_globals_res == 0, "'th_query_globals' thread didn't deadlock: %d", q_globals_res);

	th_load_mysql_vars.detach();
	th_query_globals.detach();

	{
		// NOTE: Can lock for a max of 20s (child process timeout)
		diag("Shutting down ProxySQL replica");
		mysql_query(s_proxy_admin, "PROXYSQL SHUTDOWN SLOW");

		int timeout = 3;
		int waited = 0;

		// Wait for shutdown
		if (launch_res == -1 && waited < timeout) {
			sleep(1);
			waited += 1;
		}

		ok(launch_res == 0, "Replica was properly shutdown and no deadlock took place");
	}

	launch_sec_proxy.join();

	mysql_close(p_proxy_admin);
	mysql_close(s_proxy_admin);

	return exit_status();
}
