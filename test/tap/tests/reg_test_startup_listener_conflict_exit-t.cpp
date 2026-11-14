/**
 * @file reg_test_startup_listener_conflict_exit-t.cpp
 * @brief Two ProxySQL modules on overlapping listeners: log and exit with code 0 (issue #6414).
 *
 * ProxySQL used to log "ProxySQL startup aborted due to configuration error" and then hang
 * forever in the shutdown path, joining worker threads that wait for listeners that are never
 * started. The listener validation now runs before the plugin lifecycle and exits with code 0, as
 * v3.0.11 did, so the angel process does not restart it.
 *
 * Each case launches a secondary 'proxysql -f -M' with a temporary config and datadir, under a
 * timeout with a SIGKILL fallback, and asserts that it exits on its own with code 0 and logs the
 * error. The same validation runs on PROXYSQL START after '--no-start', with the Admin session that
 * issued it still open. A port held by another process is not a module conflict: ProxySQL keeps
 * running.
 */

#include <arpa/inet.h>
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "mysql.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
namespace fs = std::filesystem;

namespace {

constexpr const char* HOST = "127.0.0.1";
constexpr const char* ABORT_MSG = "ProxySQL startup aborted due to configuration error";
constexpr int ADMIN_PORT = 26414;
constexpr int SHARED_PORT = 26415;
constexpr int PGSQL_PORT = 26416;
constexpr int WAIT_TIMEOUT_S = 25;

struct listener_config {
	string admin_ifaces;
	string mysql_ifaces;
	string pgsql_ifaces;
};

struct launch_result {
	int rc { -1 };
	string out;
	string err;
};

string addr(const char* host, int port) { return string(host) + ":" + std::to_string(port); }

bool write_config(const CommandLine& cl, const fs::path& dir, const listener_config& cfg) {
	fs::remove_all(dir);
	fs::create_directories(dir);
	std::ofstream out { dir / "proxysql.cfg" };
	if (!out.is_open()) return false;
	out << "datadir=\"" << dir.string() << "\"\n\n"
		<< "admin_variables=\n{\n"
		<< "\tadmin_credentials=\"admin:admin;" << cl.admin_username << ":" << cl.admin_password << "\"\n"
		<< "\tmysql_ifaces=\"" << cfg.admin_ifaces << "\"\n"
		<< "\tpgsql_ifaces=\"\"\n"
		<< "}\n\n"
		<< "mysql_variables=\n{\n\tthreads=2\n\tinterfaces=\"" << cfg.mysql_ifaces << "\"\n}\n\n"
		<< "pgsql_variables=\n{\n\tthreads=2\n\tinterfaces=\"" << cfg.pgsql_ifaces << "\"\n}\n";
	return out.good();
}

/** @brief Runs proxysql until it exits, killing it after 'timeout_s' (wexecvp then returns ETIME). */
launch_result run_proxysql(const char* workspace, const fs::path& dir, std::vector<string> extra_args,
	int timeout_s) {
	to_opts_t opts {};
	opts.poll_to_us = 100 * 1000;
	opts.waitpid_delay_us = 500 * 1000;
	opts.timeout_us = static_cast<unsigned int>(timeout_s) * 1000 * 1000;
	opts.sigkill_to_us = 3000 * 1000;

	const string proxysql { string { workspace } + "/src/proxysql" };
	const string cfg { (dir / "proxysql.cfg").string() };
	const string datadir { dir.string() };
	std::vector<const char*> args { "-f", "-M", "--initial", "-c", cfg.c_str(), "-D", datadir.c_str() };
	for (const string& arg : extra_args) args.push_back(arg.c_str());

	launch_result res {};
	res.rc = wexecvp(proxysql, args, opts, res.out, res.err);
	return res;
}

bool logged_abort(const launch_result& res) {
	return res.err.find(ABORT_MSG) != string::npos || res.out.find(ABORT_MSG) != string::npos;
}

void test_startup_conflict(const CommandLine& cl, const char* workspace, const fs::path& base,
	const char* name, const listener_config& cfg, bool idle_threads) {
	const string label = string(name) + (idle_threads ? " (--idle-threads)" : "");
	const fs::path dir = base / (string(name) + (idle_threads ? "_idle" : ""));
	if (!write_config(cl, dir, cfg)) BAIL_OUT("cannot write the config for %s", label.c_str());
	std::vector<string> extra;
	if (idle_threads) extra.push_back("--idle-threads");
	const launch_result res = run_proxysql(workspace, dir, extra, 30);
	ok(res.rc == 0, "%s: ProxySQL exits on its own with code 0 (rc=%d)", label.c_str(), res.rc);
	ok(logged_abort(res), "%s: the configuration error is logged", label.c_str());
	if (res.rc != 0 || !logged_abort(res)) diag("stderr:\n%s", res.err.c_str());
	fs::remove_all(dir);
}

/** @brief The same validation runs on PROXYSQL START after '--no-start'. */
void test_runtime_conflict(const CommandLine& cl, const char* workspace, const fs::path& base) {
	const fs::path dir = base / "runtime";
	const listener_config cfg { addr(HOST, ADMIN_PORT), addr(HOST, SHARED_PORT), addr(HOST, PGSQL_PORT) };
	if (!write_config(cl, dir, cfg)) BAIL_OUT("cannot write the runtime config");

	launch_result res {};
	std::thread launcher([&] { res = run_proxysql(workspace, dir, { "--no-start" }, 40); });
	conn_opts_t opts { HOST, cl.admin_username, cl.admin_password, ADMIN_PORT, 0 };
	MYSQL* admin = wait_for_proxysql(opts, WAIT_TIMEOUT_S);
	ok(admin != nullptr, "runtime: Admin is reachable with --no-start");
	if (admin != nullptr) {
		// MySQL/PgSQL 'interfaces' cannot change at runtime, Admin's can: make
		// Admin also listen on the MySQL listener before the modules start.
		const string set_admin = "SET admin-mysql_ifaces='" + addr(HOST, ADMIN_PORT) + ";" +
			addr(HOST, SHARED_PORT) + "'";
		const std::vector<string> queries {
			set_admin, "LOAD ADMIN VARIABLES TO RUNTIME", "PROXYSQL START"
		};
		for (const string& query : queries) {
			// PROXYSQL START can drop the session when the process exits.
			if (mysql_query(admin, query.c_str()) != 0) {
				diag("'%s' returned: %s", query.c_str(), mysql_error(admin));
			}
		}
		// The session stays open while ProxySQL validates the listeners.
	}
	launcher.join();
	if (admin != nullptr) mysql_close(admin);
	ok(res.rc == 0, "runtime: PROXYSQL START with conflicting listeners exits with code 0 (rc=%d)", res.rc);
	ok(logged_abort(res), "runtime: the configuration error is logged");
	if (res.rc != 0 || !logged_abort(res)) diag("stderr:\n%s", res.err.c_str());
	fs::remove_all(dir);
}

/** @brief A port held by another process is not a module conflict: ProxySQL keeps running. */
void test_external_listener(const CommandLine& cl, const char* workspace, const fs::path& base) {
	const int holder = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in sa {};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(SHARED_PORT);
	inet_pton(AF_INET, HOST, &sa.sin_addr);
	const int one = 1;
	setsockopt(holder, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (holder < 0 || bind(holder, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0 ||
		listen(holder, 1) != 0) {
		BAIL_OUT("cannot hold %s for the external-listener case", addr(HOST, SHARED_PORT).c_str());
	}

	const fs::path dir = base / "external";
	const listener_config cfg { addr(HOST, ADMIN_PORT), addr(HOST, SHARED_PORT), addr(HOST, PGSQL_PORT) };
	if (!write_config(cl, dir, cfg)) BAIL_OUT("cannot write the external-listener config");
	launch_result res {};
	std::thread launcher([&] { res = run_proxysql(workspace, dir, {}, 40); });
	conn_opts_t opts { HOST, cl.admin_username, cl.admin_password, ADMIN_PORT, 0 };
	MYSQL* admin = wait_for_proxysql(opts, WAIT_TIMEOUT_S);
	ok(admin != nullptr, "external listener: ProxySQL keeps running and Admin is reachable");
	if (admin != nullptr) {
		mysql_query(admin, "PROXYSQL SHUTDOWN SLOW");
		mysql_close(admin);
	}
	launcher.join();
	close(holder);
	ok(res.rc == 0 && !logged_abort(res),
		"external listener: no configuration error, clean exit after shutdown (rc=%d)", res.rc);
	fs::remove_all(dir);
}

} // namespace

int main() {
	CommandLine cl;
	const char* workspace = getenv("WORKSPACE");
	if (cl.getEnv() || workspace == nullptr) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(3 * 2 * 2 + 3 + 2);

	const fs::path base { fs::path { cl.workdir } / "reg_test_startup_listener_conflict_exit" };
	const std::vector<std::pair<const char*, listener_config>> conflicts {
		{ "mysql_vs_pgsql", { addr(HOST, ADMIN_PORT), addr(HOST, SHARED_PORT), addr(HOST, SHARED_PORT) } },
		{ "admin_vs_mysql", { addr(HOST, SHARED_PORT), addr(HOST, SHARED_PORT), addr(HOST, PGSQL_PORT) } },
		{ "wildcard_vs_ip", { addr(HOST, ADMIN_PORT), addr("0.0.0.0", SHARED_PORT), addr(HOST, SHARED_PORT) } },
	};
	for (bool idle_threads : { false, true }) {
		for (const auto& conflict : conflicts) {
			test_startup_conflict(cl, workspace, base, conflict.first, conflict.second, idle_threads);
		}
	}
	test_runtime_conflict(cl, workspace, base);
	test_external_listener(cl, workspace, base);

	fs::remove_all(base);
	return exit_status();
}
