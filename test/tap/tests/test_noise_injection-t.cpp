/**
 * @file test_noise_injection-t.cpp
 * @brief This tests the noise injection framework by spawning all available routines.
 */

#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <string>

#include "tap.h"
#include "command_line.h"
#include "noise_utils.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

    // Force noise to be enabled for this test
    cl.use_noise = true;

    // We have 7 internal noise tools
    const int noise_tools_count = 7;
    plan(noise_tools_count);

    diag("Spawning all available noise tools...");

	spawn_internal_noise(cl, internal_noise_admin_pinger);
	spawn_internal_noise(cl, internal_noise_stats_poller);
	spawn_internal_noise(cl, internal_noise_prometheus_poller);
	spawn_internal_noise(cl, internal_noise_random_stats_poller);
	spawn_internal_noise(cl, internal_noise_mysql_traffic);
	spawn_internal_noise(cl, internal_noise_pgsql_traffic);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller);

    diag("Sleeping for 10 seconds to let noises work...");
    sleep(10);

    diag("Exiting test, noise reports should follow...");

	return exit_status();
}
