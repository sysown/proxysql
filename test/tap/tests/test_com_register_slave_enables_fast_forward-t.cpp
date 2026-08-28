/**
 * @file test_com_register_slave_enables_fast_forward-t.cpp
 * @brief Test COM_REGISTER_SLAVE enables fast forward.
 * @details Verifies that ProxySQL correctly enables fast forward for a user
 *   when it receives COM_REGISTER_SLAVE, even if fast_forward was initially
 *   disabled. Uses MARIADB_RPL to send COM_REGISTER_SLAVE commands.
 */

#include <cstdlib>
#include "tap.h"
#include "command_line.h"
#include "binlog_rpl.h"

int main(int argc, char** argv) {
	CommandLine cl;

	plan(1);
	diag("Testing COM_REGISTER_SLAVE enables fast forward");
	diag("This test verifies that ProxySQL correctly enables fast forward for a"
		" user when it receives COM_REGISTER_SLAVE, even if it was initially disabled.");

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const int res = run_binlog_rpl(cl);

	if (res != 0) {
		diag("Binlog RPL test failed with exit code: %d", res);
	}

	ok(
		res == 0,
		"Binlog RPL test should complete successfully. Err code was: %d",
		res
	);

	diag("Test completed");
	return exit_status();
}
