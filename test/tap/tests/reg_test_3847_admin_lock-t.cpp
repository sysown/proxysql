/**
 * @file reg_test_3847_admin_lock-t.cpp
 * @brief This is a regression test for the deadlock described in issue #3847.
 */

#include <cstring>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <fstream>
#include <filesystem>
#include <stdio.h>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;
namespace fs = std::filesystem;

static constexpr const char* SEC_PROXY_HOST = "127.0.0.1";
static constexpr int SEC_PROXY_ADMIN_PORT = 26081;
static constexpr int SEC_PROXY_MYSQL_PORT = 36081;
static constexpr int SEC_PROXY_WAIT_TIMEOUT_S = 25;
static constexpr const char* CLUSTER_USER = "cluster1";
static constexpr const char* CLUSTER_PASS = "secret1pass";

static bool connect_or_diag(
	MYSQL* conn, const char* label, const char* host, const char* user, const char* password, unsigned int port
) {
	diag("Connecting %s   host='%s' port=%u user='%s'", label, host, port, user);
	if (mysql_real_connect(conn, host, user, password, NULL, port, NULL, 0)) {
		return true;
	}

	diag(
		"Connect failed for %s   host='%s' port=%u user='%s' errno=%u error=\"%s\"",
		label, host, port, user, mysql_errno(conn), mysql_error(conn)
	);
	return false;
}

static int prepare_secondary_proxy_runtime(
	const CommandLine& cl, const fs::path& runtime_dir, const fs::path& cfg_file
) {
	try {
		diag(
			"Preparing secondary ProxySQL runtime directory   runtime_dir='%s' cfg_file='%s'",
			runtime_dir.c_str(), cfg_file.c_str()
		);
		fs::remove_all(runtime_dir);
		fs::create_directories(runtime_dir);

		std::ofstream cfg_stream { cfg_file };
		if (!cfg_stream.is_open()) {
			diag("Failed to open secondary ProxySQL config for writing   cfg_file='%s'", cfg_file.c_str());
			return EXIT_FAILURE;
		}

		cfg_stream
			<< "datadir=\"" << runtime_dir.string() << "\"\n"
			<< "cluster_sync_interfaces=false\n"
			<< "restart_on_missing_heartbeats=3\n\n"
			<< "admin_variables=\n"
			<< "{\n"
			<< "\tadmin_credentials=\"admin:admin;" << cl.admin_username << ":" << cl.admin_password
			<< ";" << CLUSTER_USER << ":" << CLUSTER_PASS << "\"\n"
			<< "\tmysql_ifaces=\"0.0.0.0:" << SEC_PROXY_ADMIN_PORT << "\"\n"
			<< "\tcluster_username=\"" << CLUSTER_USER << "\"\n"
			<< "\tcluster_password=\"" << CLUSTER_PASS << "\"\n"
			<< "}\n\n"
			<< "mysql_variables=\n"
			<< "{\n"
			<< "\tinterfaces=\"0.0.0.0:" << SEC_PROXY_MYSQL_PORT << "\"\n"
			<< "}\n\n"
			<< "proxysql_servers =\n"
			<< "(\n"
			<< "\t{\n"
			<< "\t\thostname=\"" << SEC_PROXY_HOST << "\"\n"
			<< "\t\tport=" << SEC_PROXY_ADMIN_PORT << "\n"
			<< "\t\tweight=0\n"
			<< "\t\tcomment=\"replica\"\n"
			<< "\t},\n"
			<< "\t{\n"
			<< "\t\thostname=\"" << cl.admin_host << "\"\n"
			<< "\t\tport=" << cl.admin_port << "\n"
			<< "\t\tweight=0\n"
			<< "\t\tcomment=\"primary\"\n"
			<< "\t}\n"
			<< ")\n";
		cfg_stream.close();

		diag(
			"Prepared secondary ProxySQL config   replica_admin='%s:%d' replica_mysql='%s:%d' primary_admin='%s:%d'",
			SEC_PROXY_HOST, SEC_PROXY_ADMIN_PORT, SEC_PROXY_HOST, SEC_PROXY_MYSQL_PORT, cl.admin_host, cl.admin_port
		);

		return EXIT_SUCCESS;
	} catch (const std::exception& ex) {
		diag("Failed to prepare secondary ProxySQL runtime   error=\"%s\"", ex.what());
		return EXIT_FAILURE;
	}
}

int main(int argc, char** argv) {
	CommandLine cl;

	const char* WORKSPACE = getenv("WORKSPACE");

	if (cl.getEnv() || WORKSPACE == nullptr) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(3);
	std::atomic<bool> stop { false };
	std::atomic<int> q_load_res { -1 };
	std::atomic<int> q_globals_res { -1 };

	MYSQL* p_proxy_admin = mysql_init(NULL);

	if (!connect_or_diag(
		p_proxy_admin, "primary ProxySQL admin", cl.admin_host, cl.admin_username, cl.admin_password, cl.admin_port
	)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(p_proxy_admin));
		return EXIT_FAILURE;
	}

	const fs::path sec_runtime_dir { fs::path { cl.workdir } / "reg_test_3847_node_datadir" / "runtime" };
	const fs::path sec_cfg_file { sec_runtime_dir / "proxysql_sec.cfg" };
	const fs::path sec_launch_log_file { sec_runtime_dir / "launcher_capture.log" };
	const fs::path sec_internal_log_file { sec_runtime_dir / "proxysql.log" };

	if (prepare_secondary_proxy_runtime(cl, sec_runtime_dir, sec_cfg_file) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	std::atomic<int> launch_res { -1 };

	std::thread launch_sec_proxy = std::thread([&WORKSPACE, &sec_runtime_dir, &sec_cfg_file, &sec_launch_log_file] (std::atomic<int>& err_code) -> void {
		to_opts_t wexecvp_opts {};
		wexecvp_opts.poll_to_us = 100*1000;
		wexecvp_opts.waitpid_delay_us = 500*1000;
		// Stop launched process after 20s
		wexecvp_opts.timeout_us = 20000 * 1000;
		// Send sigkill 3s after timeout
		wexecvp_opts.sigkill_to_us = 3000 * 1000;

		const string proxysql_path { string { WORKSPACE } + "/src/proxysql" };

		const string sec_cfg_file_str { sec_cfg_file.string() };
		const string sec_runtime_dir_str { sec_runtime_dir.string() };
		const vector<const char*> proxy_args {
			"-f", "-M", "-c", sec_cfg_file_str.c_str(), "-D", sec_runtime_dir_str.c_str()
		};

		string s_stdout {};
		string s_stderr {};

		diag(
			"Launching secondary ProxySQL   binary='%s' cfg_file='%s' datadir='%s'",
			proxysql_path.c_str(), sec_cfg_file_str.c_str(), sec_runtime_dir_str.c_str()
		);
		int w_res = wexecvp(proxysql_path, proxy_args, wexecvp_opts, s_stdout, s_stderr);
		if (w_res != EXIT_SUCCESS) {
			diag("'wexecvp' failed with error: %d (ETIME=62 is expected if timeout reached while ProxySQL is still running in foreground)", w_res);
		}

		err_code.store(w_res);

		// Write process output to log file
		try {
			std::ofstream os_logfile { sec_launch_log_file, std::ios::out };
			os_logfile << "STDOUT:\n" << s_stdout << "\nSTDERR:\n" << s_stderr << "\n";
		} catch (const std::exception& ex) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, ex.what());
		}
	}, std::ref(launch_res));

	// Check that the second ProxySQL is up and responsive
	diag(
		"Waiting for ProxySQL replica to be ready   admin='%s:%d' user='%s' runtime_dir='%s' cfg_file='%s' internal_log='%s' launcher_log='%s'",
		SEC_PROXY_HOST, SEC_PROXY_ADMIN_PORT, cl.admin_username, sec_runtime_dir.c_str(), sec_cfg_file.c_str(),
		sec_internal_log_file.c_str(), sec_launch_log_file.c_str()
	);
	conn_opts_t conn_opts { SEC_PROXY_HOST, cl.admin_username, cl.admin_password, SEC_PROXY_ADMIN_PORT };
	// Wait at max the child process timeout plus 5 seconds
	MYSQL* s_proxy_admin = wait_for_proxysql(conn_opts, SEC_PROXY_WAIT_TIMEOUT_S);

	if (s_proxy_admin == nullptr) {
		fprintf(
			stderr,
			"Error: %s (attempted with user %s:%s, admin=%s:%d, cfg=%s, datadir=%s, internal_log=%s, launcher_log=%s, launch_res=%d)\n",
			"Waiting for ProxySQL replica timedout", cl.admin_username, cl.admin_password, SEC_PROXY_HOST,
			SEC_PROXY_ADMIN_PORT, sec_cfg_file.c_str(), sec_runtime_dir.c_str(), sec_internal_log_file.c_str(),
			sec_launch_log_file.c_str(), launch_res.load()
		);
		if (launch_sec_proxy.joinable()) {
			launch_sec_proxy.join();
		}
		return EXIT_FAILURE;
	}

	// Configure Cluster access for primary ProxySQL
	diag("Configuring primary ProxySQL cluster credentials");
	MYSQL_QUERY(p_proxy_admin, "SET admin-admin_credentials='admin:admin;radmin:radmin;cluster1:secret1pass'");
	MYSQL_QUERY(p_proxy_admin, "SET admin-cluster_username='cluster1'");
	MYSQL_QUERY(p_proxy_admin, "SET admin-cluster_password='secret1pass'");
	MYSQL_QUERY(p_proxy_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// Configure secondary node
	diag("Configuring secondary ProxySQL cluster polling");
	MYSQL_QUERY(s_proxy_admin, "SET admin-cluster_check_interval_ms=10");
	MYSQL_QUERY(s_proxy_admin, "SET admin-cluster_mysql_variables_diffs_before_sync=1");
	MYSQL_QUERY(s_proxy_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	std::thread th_load_mysql_vars([&cl] (std::atomic<bool>& stop, std::atomic<int>& load_res) -> void {
		MYSQL* admin = mysql_init(NULL);

		if (!connect_or_diag(
			admin, "primary admin worker", cl.admin_host, cl.admin_username, cl.admin_password, cl.admin_port
		)) {
			load_res.store(mysql_errno(admin));
			mysql_close(admin);
			return;
		}

		int default_query_timeout = 36000000;
		uint64_t iteration = 0;
		diag("Started worker 'th_load_mysql_vars'   initial_default_query_timeout=%d", default_query_timeout);

		while (stop.load() == false) {
			string set_query { "SET mysql-default_query_timeout=" + std::to_string(default_query_timeout) };
			int set_res = mysql_query(admin, set_query.c_str());
			if (set_res) {
				load_res.store(mysql_errno(admin));
				diag(
					"'th_load_mysql_vars' failed during SET   iteration=%lu errno=%u error=\"%s\"",
					iteration, mysql_errno(admin), mysql_error(admin)
				);
				mysql_close(admin);
				return;
			}
			int my_res = mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

			if (my_res) {
				load_res.store(mysql_errno(admin));
				diag(
					"'th_load_mysql_vars' failed   iteration=%lu errno=%u error=\"%s\"",
					iteration, mysql_errno(admin), mysql_error(admin)
				);
				mysql_close(admin);
				return;
			}
			if (iteration % 100 == 0) {
				diag(
					"'th_load_mysql_vars' progress   iteration=%lu current_default_query_timeout=%d",
					iteration, default_query_timeout
				);
			}
			usleep(1000 * 10 * 2);

			if (default_query_timeout > 36000000) {
				default_query_timeout = 36000000;
			} else {
				default_query_timeout += 1;
			}
			iteration += 1;
		}

		load_res.store(0);
		diag("'th_load_mysql_vars' stopping cleanly");
		mysql_close(admin);
	}, std::ref(stop), std::ref(q_load_res));

	std::thread th_query_globals([&cl] (std::atomic<bool>& stop, std::atomic<int>& save_res) -> void {
		MYSQL* admin = mysql_init(NULL);

		if (!connect_or_diag(
			admin, "secondary admin worker", SEC_PROXY_HOST, cl.admin_username, cl.admin_password, SEC_PROXY_ADMIN_PORT
		)) {
			save_res.store(mysql_errno(admin));
			mysql_close(admin);
			return;
		}

		uint64_t iteration = 0;
		diag("Started worker 'th_query_globals'");
		while (stop.load() == false) {
			int my_res = mysql_query(admin, "SELECT COUNT(*) FROM runtime_global_variables");
			if (my_res) {
				save_res.store(mysql_errno(admin));
				diag(
					"'th_query_globals' failed   iteration=%lu errno=%u error=\"%s\"",
					iteration, mysql_errno(admin), mysql_error(admin)
				);
				mysql_close(admin);
				return;
			} else {
				mysql_free_result(mysql_store_result(admin));
			}
			if (iteration % 100 == 0) {
				diag("'th_query_globals' progress   iteration=%lu", iteration);
			}
			iteration += 1;
		}

		save_res.store(0);
		diag("'th_query_globals' stopping cleanly");
		mysql_close(admin);
	}, std::ref(stop), std::ref(q_globals_res));

	uint32_t timeout = 10;
	uint32_t wait = 0;

	while (wait < timeout) {
		if (q_globals_res.load() > 0) {
			fprintf(stderr, "'th_admin_save' failed with error: %d\n", q_globals_res.load());
			break;
		}
		if (q_load_res.load() > 0) {
			fprintf(stderr, "'th_admin_load' failed with error: %d\n", q_load_res.load());
			break;
		}

		diag(
			"Main wait loop   second=%u/%u launch_res=%d q_load_res=%d q_globals_res=%d",
			wait + 1, timeout, launch_res.load(), q_load_res.load(), q_globals_res.load()
		);
		sleep(1);
		wait += 1;
	}

	{
		diag("Shutting down worker threads");
		int timeout = 2;
		int waited = 0;

		stop.store(true);

		while ((q_globals_res.load() == -1 || q_load_res.load() == -1) && waited < timeout) {
			diag(
				"Waiting for worker threads to acknowledge stop   waited=%d q_load_res=%d q_globals_res=%d",
				waited, q_load_res.load(), q_globals_res.load()
			);
			sleep(1);
			waited += 1;
		}
	}

	ok(q_load_res.load() == 0, "'th_load_mysql_vars' thread didn't deadlock: %d", q_load_res.load());
	ok(q_globals_res.load() == 0, "'th_query_globals' thread didn't deadlock: %d", q_globals_res.load());

	th_load_mysql_vars.detach();
	th_query_globals.detach();

	{
		// NOTE: Can lock for a max of 20s (child process timeout)
		diag("Shutting down ProxySQL replica");
		mysql_query(s_proxy_admin, "PROXYSQL SHUTDOWN SLOW");

		int timeout = 3;
		int waited = 0;

		// Wait for shutdown
		while (launch_res.load() == -1 && waited < timeout) {
			diag("Waiting for replica launcher thread to finish   waited=%d launch_res=%d", waited, launch_res.load());
			sleep(1);
			waited += 1;
		}

		ok(launch_res.load() == 0, "Replica was properly shutdown and no deadlock took place");
	}

	launch_sec_proxy.join();

	mysql_close(p_proxy_admin);
	mysql_close(s_proxy_admin);

	return exit_status();
}
