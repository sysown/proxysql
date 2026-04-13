/**
 * @file test_com_binlog_dump_enables_fast_forward-t.cpp
 * @brief Test COM_BINLOG_DUMP enables fast forward.
 * @details Test checks if mysqlbinlog is executed successfully using a user
 * with fast forward flag set to false. mysqlbinlog sends command
 * COM_BINLOG_DUMP, then ProxySQL enables fast forward.
 */

#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	plan(1);
	diag("Testing COM_BINLOG_DUMP enables fast forward");
	diag("This test verifies that mysqlbinlog can successfully connect through ProxySQL even if fast_forward is initially disabled for the user, as ProxySQL should enable it upon receiving COM_BINLOG_DUMP.");

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	diag("Connection details: host=%s, port=%d, user=%s", cl.host, 6033, cl.root_username);

	const char * tdp = getenv("TEST_DEPS");
	std::string mysqlbinlog_path = "mysqlbinlog";
	if (tdp && *tdp) {
		diag("TEST_DEPS is set to: %s", tdp);
		mysqlbinlog_path = std::string(tdp) + "/mysqlbinlog";
	} else {
		diag("TEST_DEPS is not set or empty, using 'mysqlbinlog' from PATH");
	}

	diag("Final mysqlbinlog path: %s", mysqlbinlog_path.c_str());

	// Verify if file exists if it's an absolute path
	if (mysqlbinlog_path[0] == '/') {
		struct stat buffer;
		if (stat(mysqlbinlog_path.c_str(), &buffer) == 0) {
			diag("Confirmed: %s exists", mysqlbinlog_path.c_str());
			if (buffer.st_mode & S_IXUSR) {
				diag("Confirmed: %s is executable", mysqlbinlog_path.c_str());
			} else {
				diag("WARNING: %s exists but is NOT executable", mysqlbinlog_path.c_str());
			}
		} else {
			diag("ERROR: %s DOES NOT EXIST", mysqlbinlog_path.c_str());
			// List directory content to help debug
			size_t last_slash = mysqlbinlog_path.find_last_of('/');
			std::string dir = mysqlbinlog_path.substr(0, last_slash);
			diag("Listing contents of %s:", dir.c_str());
			std::string list_cmd = "ls -la " + dir;
			system(list_cmd.c_str());
		}
	} else {
		// If not absolute path, check which
		diag("Checking 'which %s':", mysqlbinlog_path.c_str());
		std::string which_cmd = "which " + mysqlbinlog_path;
		system(which_cmd.c_str());
	}

	// Query ProxySQL for the actual binlog filename instead of hardcoding it.
	// The binlog name depends on the backend (e.g. "mysql1-bin" vs "mysql-bin" with dbdeployer).
	std::string binlog_file = "mysql1-bin.000001"; // fallback
	{
		MYSQL* admin = mysql_init(NULL);
		if (admin && mysql_real_connect(admin, cl.host, cl.root_username, cl.root_password, NULL, cl.root_port, NULL, 0)) {
			// Try MySQL 8.4+ syntax first, fall back to legacy for 5.7
			if (mysql_query(admin, "SHOW BINARY LOG STATUS") != 0) {
				mysql_query(admin, "SHOW MASTER STATUS");
			}
			{
				MYSQL_RES* res = mysql_store_result(admin);
				if (res) {
					MYSQL_ROW row = mysql_fetch_row(res);
					if (row && row[0]) {
						binlog_file = row[0];
						diag("Detected binlog file from backend: %s", binlog_file.c_str());
					}
					mysql_free_result(res);
				}
			}
			mysql_close(admin);
		}
	}

	// Redirect stdout to /dev/null — we only care about the exit code (proving
	// COM_BINLOG_DUMP triggered fast_forward), not the binlog content itself.
	// Without this, the test harness captures every line, turning a fast read
	// into minutes of Python line-by-line logging.
	std::string cmd = mysqlbinlog_path + " " + binlog_file + " "
						"--read-from-remote-server --user " + std::string(cl.root_username) +
						" --password=" + std::string(cl.root_password) +
						" --host " + std::string(cl.host) + " --port 6033"
						" > /dev/null";
	
	diag("Executing: %s", cmd.c_str());
	const int mysqlbinlog_res = system(cmd.c_str());
	
	if (mysqlbinlog_res != 0) {
		diag("mysqlbinlog failed with exit code: %d", mysqlbinlog_res);
		diag("Current PATH: %s", getenv("PATH") ? getenv("PATH") : "unset");
		
		char cwd[1024];
		if (getcwd(cwd, sizeof(cwd)) != NULL) {
			diag("Current working directory: %s", cwd);
		}
	}

	ok(mysqlbinlog_res == 0, "'mysqlbinlog' should be correctly executed. Err code was: %d", mysqlbinlog_res);

	diag("Test completed");
	return exit_status();
}
