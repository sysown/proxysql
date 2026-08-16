/**
 * @brief Exercises query-cache EOF/OK conversion using two real client libraries.
 *
 * The child workload fills the cache with a client for which ProxySQL has removed
 * CLIENT_DEPRECATE_EOF, then reads it with a newly connected client for which the
 * capability is enabled; it repeats the inverse direction.  It checks both the
 * cache counters and the negotiated frontend capability on the real connections.
 */

#include <stdlib.h>
#include <string>

#include "tap.h"
#include "command_line.h"

int main(int argc, char** argv) {
	CommandLine cl;
	plan(1);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	const std::string command = std::string(cl.workdir) + "deprecate_eof_cache-t --mixed-capabilities";
	const int status = system(command.c_str());
	ok(status == 0, "mixed-capability real-client query-cache conversion workload succeeds");

	return exit_status();
}
