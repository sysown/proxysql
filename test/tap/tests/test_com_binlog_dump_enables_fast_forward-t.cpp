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

	std::string cmd = mysqlbinlog_path + " mysql1-bin.000001 "
						"--read-from-remote-server --user " + std::string(cl.root_username) + 
						" --password=" + std::string(cl.root_password) +
						" --host " + std::string(cl.host) + " --port 6033";
	
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
