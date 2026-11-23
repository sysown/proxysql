/**
 * @file reg_test_3847_admin_lock-t.cpp
 * @brief This is a regression test for the deadlock described in issue #3847.
 */

#include <chrono>
#include <cstring>
#include <map>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <stdio.h>
#include <stdlib.h>
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
// Safety net only: the test stops the replica itself with PROXYSQL SHUTDOWN SLOW.
// The limit counts from launch, and startup alone has taken 5-20s on slow CI
// runners, so 20s used to expire before the test reached the shutdown (#6696).
static constexpr int SEC_PROXY_LIFETIME_S = 90;
// How long to wait for the replica to exit after PROXYSQL SHUTDOWN SLOW.
static constexpr int SEC_PROXY_SHUTDOWN_WAIT_S = 20;
// A replica query that makes no progress for this long is treated as stuck, and
// the replica's thread state is captured before the test fails (#6696).
static constexpr int64_t STALL_CAPTURE_MS = 3000;
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

static int64_t now_ms() {
	using namespace std::chrono;
	return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

static string read_first_line(const fs::path& path) {
	std::ifstream is { path };
	string line {};
	std::getline(is, line);
	return line;
}

/** Finds the replica ProxySQL by its config file path in /proc/<pid>/cmdline; 0 if not found. */
static pid_t find_replica_pid(const fs::path& cfg_file) {
	const string needle { cfg_file.string() };
	std::error_code ec {};
	for (const auto& entry : fs::directory_iterator("/proc", ec)) {
		const string name { entry.path().filename().string() };
		if (name.empty() || name.find_first_not_of("0123456789") != string::npos) {
			continue;
		}
		std::ifstream is { entry.path() / "cmdline", std::ios::binary };
		const string cmdline { std::istreambuf_iterator<char>(is), std::istreambuf_iterator<char>() };
		if (cmdline.find(needle) != string::npos && cmdline.find("proxysql") != string::npos) {
			return static_cast<pid_t>(std::stol(name));
		}
	}
	return 0;
}

/**
 * Records why the replica stopped answering: every thread's name, scheduler state and
 * kernel wait channel from /proc and, with 'with_gdb', a gdb backtrace of all threads
 * when gdb is installed and allowed to attach. Appends to 'out_file' and logs a summary.
 *
 * The /proc part takes milliseconds. gdb pauses the replica for seconds, so callers use
 * it only after the test's verdict is recorded.
 */
static void capture_replica_state(pid_t pid, const fs::path& out_file, const string& reason, bool with_gdb) {
	std::ofstream os { out_file, std::ios::out | std::ios::app };
	diag("Capturing replica thread state   pid=%d reason='%s' file='%s'", pid, reason.c_str(), out_file.c_str());
	os << "=== " << reason << " (pid " << pid << ")\n";

	if (pid <= 0) {
		os << "replica process not found\n";
		diag("Replica process not found; no thread state captured");
		return;
	}

	std::map<string, int> by_wchan {};
	std::error_code ec {};
	const fs::path task_dir { fs::path { "/proc" } / std::to_string(pid) / "task" };
	for (const auto& task : fs::directory_iterator(task_dir, ec)) {
		const string comm { read_first_line(task.path() / "comm") };
		const string wchan { read_first_line(task.path() / "wchan") };
		const string stat { read_first_line(task.path() / "stat") };
		// The state is the first field after the ')' that closes the thread name.
		const size_t paren = stat.rfind(')');
		const string state { paren != string::npos && paren + 2 < stat.size() ? stat.substr(paren + 2, 1) : "?" };
		os << "tid=" << task.path().filename().string() << " comm=" << comm << " state=" << state
			<< " wchan=" << (wchan.empty() ? "-" : wchan) << "\n";
		by_wchan[state + "/" + (wchan.empty() ? "-" : wchan)] += 1;
	}
	string summary {};
	for (const auto& [key, count] : by_wchan) {
		summary += key + "=" + std::to_string(count) + " ";
	}
	diag("Replica threads by state/wchan: %s", summary.c_str());

	if (!with_gdb) {
		return;
	}
	if (system("command -v gdb >/dev/null 2>&1") != 0) {
		os << "gdb not installed; no backtraces\n";
		diag("gdb not installed; only /proc thread state was captured");
		return;
	}

	const string cmd {
		"timeout 120 gdb -p " + std::to_string(pid) + " -batch -nx -q"
		" -ex 'set pagination off' -ex 'thread apply all bt' 2>&1"
	};
	os.flush();
	FILE* gdb = popen(cmd.c_str(), "r");
	if (gdb == nullptr) {
		os << "popen(gdb) failed: " << strerror(errno) << "\n";
		return;
	}
	char buf[4096];
	size_t frames = 0;
	while (fgets(buf, sizeof(buf), gdb) != nullptr) {
		os << buf;
		if (buf[0] == '#') {
			frames += 1;
		}
	}
	const int rc = pclose(gdb);
	diag("gdb backtrace captured   frames=%zu rc=%d file='%s'", frames, rc, out_file.c_str());
}

/**
 * Copies a replica-side file next to this test's TAP log, so CI uploads it. The tester
 * writes TAP logs to ${TESTS_LOGS_PATH}/proxysql-tester.py/tests/. Outside that harness
 * the file stays in the replica's runtime directory.
 */
static void publish_replica_file(const fs::path& src, const string& suffix) {
	const char* logs_path = getenv("TESTS_LOGS_PATH");
	std::error_code ec {};
	if (logs_path == nullptr || !fs::exists(src, ec)) {
		return;
	}
	const fs::path dst_dir { fs::path { logs_path } / "proxysql-tester.py" / "tests" };
	if (!fs::is_directory(dst_dir, ec)) {
		return;
	}
	const fs::path dst { dst_dir / ("reg_test_3847_admin_lock-t." + suffix) };
	fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
	diag("Saved replica file   src='%s' dst='%s' error='%s'", src.c_str(), dst.c_str(), ec ? ec.message().c_str() : "");
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
		// Stop the launched process if the test never shuts it down
		wexecvp_opts.timeout_us = SEC_PROXY_LIFETIME_S * 1000 * 1000;
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
		publish_replica_file(sec_launch_log_file, "replica.log");
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

	// Time of the replica query loop's last completed query, read by the stall check.
	// Static: the worker is detached below and may still update it after main returns.
	static std::atomic<int64_t> globals_last_progress_ms { 0 };
	globals_last_progress_ms.store(now_ms());

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
			globals_last_progress_ms.store(now_ms());
			iteration += 1;
		}

		save_res.store(0);
		diag("'th_query_globals' stopping cleanly");
		mysql_close(admin);
	}, std::ref(stop), std::ref(q_globals_res));

	const fs::path stall_file { sec_runtime_dir / "replica_stall_state.txt" };
	bool stall_captured = false;
	// Records the replica's thread state from /proc once, the first time its query loop
	// has made no progress for STALL_CAPTURE_MS. Only the /proc snapshot runs here: it
	// takes milliseconds, so it cannot move the worker-stop deadline (#6700 review).
	auto check_replica_stall = [&] (const char* where) -> void {
		const int64_t idle_ms = now_ms() - globals_last_progress_ms.load();
		if (stall_captured || q_globals_res.load() != -1 || idle_ms < STALL_CAPTURE_MS) {
			return;
		}
		stall_captured = true;
		const string reason {
			string { "'th_query_globals' made no progress for " } + std::to_string(idle_ms) + "ms (" + where + ")"
		};
		diag("Replica looks stuck: %s", reason.c_str());
		capture_replica_state(find_replica_pid(sec_cfg_file), stall_file, reason, false);
	};

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
		check_replica_stall("main wait loop");
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
			check_replica_stall("waiting for workers to stop");
		}
	}

	// Record the verdict at the deadline, before any slow diagnostics: a worker that
	// recovers while gdb runs must still fail.
	const int load_verdict = q_load_res.load();
	const int globals_verdict = q_globals_res.load();

	if (globals_verdict == -1) {
		capture_replica_state(
			find_replica_pid(sec_cfg_file), stall_file,
			"'th_query_globals' still blocked at the worker-stop deadline", true
		);
	}

	ok(load_verdict == 0, "'th_load_mysql_vars' thread didn't deadlock: %d", load_verdict);
	ok(globals_verdict == 0, "'th_query_globals' thread didn't deadlock: %d", globals_verdict);

	th_load_mysql_vars.detach();
	th_query_globals.detach();

	{
		// NOTE: Can lock for a max of SEC_PROXY_LIFETIME_S (child process timeout)
		diag("Shutting down ProxySQL replica");
		const int64_t shutdown_start_ms = now_ms();
		mysql_query(s_proxy_admin, "PROXYSQL SHUTDOWN SLOW");
		diag("PROXYSQL SHUTDOWN SLOW returned   elapsed_ms=%ld", static_cast<long>(now_ms() - shutdown_start_ms));

		int timeout = SEC_PROXY_SHUTDOWN_WAIT_S;
		int waited = 0;

		// Wait for shutdown
		while (launch_res.load() == -1 && waited < timeout) {
			diag("Waiting for replica launcher thread to finish   waited=%d launch_res=%d", waited, launch_res.load());
			sleep(1);
			waited += 1;
		}

		ok(launch_res.load() == 0, "Replica was properly shutdown and no deadlock took place");
	}

	if (launch_res.load() == -1) {
		// Still running after the shutdown wait: record what it is doing.
		capture_replica_state(find_replica_pid(sec_cfg_file), stall_file, "replica still running after PROXYSQL SHUTDOWN SLOW", true);
	}

	launch_sec_proxy.join();

	// The replica runs in the foreground, so its log is the captured stdout/stderr.
	// Publish it, and any captured thread state, when something went wrong.
	if (exit_status() != 0 || stall_captured || globals_verdict == -1) {
		publish_replica_file(sec_launch_log_file, "replica.log");
		publish_replica_file(stall_file, "replica_stall_state.txt");
	}

	mysql_close(p_proxy_admin);
	mysql_close(s_proxy_admin);

	return exit_status();
}
