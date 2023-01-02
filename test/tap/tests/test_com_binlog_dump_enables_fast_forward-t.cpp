/**
 * @file test_com_binlog_dump_enables_fast_forward-t.cpp
 * @brief Test COM_BINLOG_DUMP enables fast forward.
 * @details Test checks if mysqlbinlog is executed successfully using a user
 * with fast forward flag set to false. mysqlginlog sends command
 * COM_BINLOG_DUMP, then ProxySQL enables fast forward.
 */

#include "tap.h"
#include "command_line.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	const std::string user = "sbtest1";

	const int mysqlbinlog_res = system(("mysqlbinlog single_mysql8_backend-bin.000001 "
										"--read-from-remote-server --user " + user + " --password=" + user +
										" --host 127.0.0.1 --port 6033").c_str());
	ok(mysqlbinlog_res == 0, "'mysqlbinlog' should be correctly executed. Err code was: %d", mysqlbinlog_res);

	return exit_status();
}
