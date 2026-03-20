/**
 * @file test_load_restapi_from_config_startup-t.cpp
 * @brief Verifies restapi routes from config are loaded into runtime on startup.
 */

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

#include "mysql.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
namespace fs = std::filesystem;

static constexpr const char* SEC_PROXY_HOST = "127.0.0.1";
static constexpr int SEC_PROXY_ADMIN_PORT = 26082;
static constexpr int SEC_PROXY_MYSQL_PORT = 36082;
static constexpr int SEC_PROXY_RESTAPI_PORT = 26083;
static constexpr int SEC_PROXY_WAIT_TIMEOUT_S = 25;

static int prepare_secondary_proxy_runtime(
	const CommandLine& cl, const fs::path& runtime_dir, const fs::path& cfg_file, const fs::path& script_file
) {
	try {
		fs::remove_all(runtime_dir);
		fs::create_directories(runtime_dir);

		std::ofstream script_stream { script_file };
		if (!script_stream.is_open()) {
			diag("Failed to open RESTAPI script for writing   path='%s'", script_file.c_str());
			return EXIT_FAILURE;
		}
		script_stream << "#!/bin/sh\n";
		script_stream << "printf '{\"ok\":true}'\n";
		script_stream.close();
		fs::permissions(
			script_file,
			fs::perms::owner_read | fs::perms::owner_write | fs::perms::owner_exec |
				fs::perms::group_read | fs::perms::group_exec |
				fs::perms::others_read | fs::perms::others_exec
		);

		std::ofstream cfg_stream { cfg_file };
		if (!cfg_stream.is_open()) {
			diag("Failed to open ProxySQL config for writing   path='%s'", cfg_file.c_str());
			return EXIT_FAILURE;
		}

		cfg_stream
			<< "datadir=\"" << runtime_dir.string() << "\"\n"
			<< "errorlog=\"" << (runtime_dir / "proxysql.log").string() << "\"\n\n"
			<< "admin_variables=\n"
			<< "{\n"
			<< "\tadmin_credentials=\"admin:admin;" << cl.admin_username << ":" << cl.admin_password << "\"\n"
			<< "\tmysql_ifaces=\"0.0.0.0:" << SEC_PROXY_ADMIN_PORT << "\"\n"
			<< "\trestapi_enabled=true\n"
			<< "\trestapi_port=" << SEC_PROXY_RESTAPI_PORT << "\n"
			<< "}\n\n"
			<< "mysql_variables=\n"
			<< "{\n"
			<< "\tinterfaces=\"0.0.0.0:" << SEC_PROXY_MYSQL_PORT << "\"\n"
			<< "}\n\n"
			<< "restapi_routes=\n"
			<< "(\n"
			<< "\t{\n"
			<< "\t\tactive=1\n"
			<< "\t\ttimeout_ms=5000\n"
			<< "\t\tmethod=\"GET\"\n"
			<< "\t\turi=\"healthz\"\n"
			<< "\t\tscript=\"" << script_file.string() << "\"\n"
			<< "\t\tcomment=\"health check\"\n"
			<< "\t}\n"
			<< ")\n";
		cfg_stream.close();

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

	plan(5);

	const fs::path runtime_dir { fs::path { cl.workdir } / "test_load_restapi_from_config_startup" };
	const fs::path cfg_file { runtime_dir / "proxysql.cfg" };
	const fs::path script_file { runtime_dir / "healthcheck.sh" };

	if (prepare_secondary_proxy_runtime(cl, runtime_dir, cfg_file, script_file) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	std::atomic<int> launch_res { -1 };
	string launch_stdout {};
	string launch_stderr {};

	std::thread launch_proxy = std::thread(
		[&WORKSPACE, &runtime_dir, &cfg_file, &launch_res, &launch_stdout, &launch_stderr]() -> void {
			to_opts_t wexecvp_opts {};
			wexecvp_opts.poll_to_us = 100 * 1000;
			wexecvp_opts.waitpid_delay_us = 500 * 1000;
			wexecvp_opts.timeout_us = 30000 * 1000;
			wexecvp_opts.sigkill_to_us = 3000 * 1000;

			const string proxysql_path { string { WORKSPACE } + "/src/proxysql" };
			const string cfg_file_str { cfg_file.string() };
			const string runtime_dir_str { runtime_dir.string() };
			const std::vector<const char*> proxy_args {
				"-f", "-M", "--reload", "-c", cfg_file_str.c_str(), "-D", runtime_dir_str.c_str()
			};

			launch_res.store(wexecvp(proxysql_path, proxy_args, wexecvp_opts, launch_stdout, launch_stderr));
		}
	);

	conn_opts_t conn_opts { SEC_PROXY_HOST, cl.admin_username, cl.admin_password, SEC_PROXY_ADMIN_PORT, 0 };
	MYSQL* proxy_admin = wait_for_proxysql(conn_opts, SEC_PROXY_WAIT_TIMEOUT_S);

	ok(proxy_admin != nullptr, "Secondary ProxySQL started with config-file RESTAPI routes");

	if (proxy_admin) {
		auto [main_err, main_rows] = mysql_query_ext_rows(
			proxy_admin, "SELECT active, timeout_ms, method, uri, script, comment FROM restapi_routes"
		);
		ok(main_err == EXIT_SUCCESS && main_rows.size() == 1, "Startup config loaded one row into restapi_routes");

		auto [runtime_err, runtime_rows] = mysql_query_ext_rows(
			proxy_admin, "SELECT active, timeout_ms, method, uri, script, comment FROM runtime_restapi_routes"
		);
		ok(
			runtime_err == EXIT_SUCCESS && runtime_rows.size() == 1,
			"Startup config loaded one row into runtime_restapi_routes"
		);

		bool runtime_row_matches = false;
		if (runtime_err == EXIT_SUCCESS && runtime_rows.size() == 1) {
			const auto& row = runtime_rows.front();
			runtime_row_matches =
				row[0] == "1" &&
				row[1] == "5000" &&
				row[2] == "GET" &&
				row[3] == "healthz" &&
				row[4] == script_file.string() &&
				row[5] == "health check";
		}
		ok(runtime_row_matches, "Runtime RESTAPI row matches the config-file route definition");

		const int shutdown_rc = mysql_query(proxy_admin, "PROXYSQL SHUTDOWN SLOW");
		const string shutdown_err = shutdown_rc == 0 ? "" : mysql_error(proxy_admin);
		mysql_close(proxy_admin);
		proxy_admin = nullptr;

		if (shutdown_rc != 0) {
			diag("Shutdown query failed: %s", shutdown_err.c_str());
		}
	} else {
		ok(false, "Startup config loaded one row into restapi_routes");
		ok(false, "Startup config loaded one row into runtime_restapi_routes");
		ok(false, "Runtime RESTAPI row matches the config-file route definition");
	}

	if (launch_proxy.joinable()) {
		launch_proxy.join();
	}

	ok(launch_res.load() == EXIT_SUCCESS, "Secondary ProxySQL exited cleanly after verification");

	if (tests_failed()) {
		diag("Secondary ProxySQL stdout:\n%s", launch_stdout.c_str());
		diag("Secondary ProxySQL stderr:\n%s", launch_stderr.c_str());
	}

	fs::remove_all(runtime_dir);

	return exit_status();
}
