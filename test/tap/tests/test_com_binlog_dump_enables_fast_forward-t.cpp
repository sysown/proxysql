/**
 * @file test_com_binlog_dump_enables_fast_forward-t.cpp
 * @brief Test COM_BINLOG_DUMP enables fast forward.
 * @details Test checks if mysqlbinlog is executed successfully using a user
 * with fast forward flag set to false. mysqlginlog sends command
 * COM_BINLOG_DUMP, then ProxySQL enables fast forward.
 */

#include <string>
#include <cstdlib>
#include "tap.h"
#include "command_line.h"

int main(int argc, char** argv) {
	CommandLine cl;

	plan(1);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	const char * tdp = getenv("TEST_DEPS");
	const std::string test_deps_path = ( tdp == nullptr ? "" : std::string(tdp) );

	std::string cmd = test_deps_path + "/mysqlbinlog mysql1-bin.000001 "
						"--read-from-remote-server --user " + std::string(cl.root_username) + 
						" --password=" + std::string(cl.root_password) +
						" --host " + std::string(cl.host) + " --port 6033";
	
	diag("Executing: %s", cmd.c_str());
	const int mysqlbinlog_res = system(cmd.c_str());
	ok(mysqlbinlog_res == 0, "'mysqlbinlog' should be correctly executed. Err code was: %d", mysqlbinlog_res);

	return exit_status();
}
