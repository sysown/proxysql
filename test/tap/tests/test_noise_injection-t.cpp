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

	// Set protocol-specific noise flags based on available infrastructure
	const char* mysql_infra = getenv("DEFAULT_MYSQL_INFRA");
	const char* pgsql_infra = getenv("DEFAULT_PGSQL_INFRA");
	cl.use_noise_mysql = (mysql_infra && mysql_infra[0] != '\0');
	cl.use_noise_pgsql = (pgsql_infra && pgsql_infra[0] != '\0');

	spawn_internal_noise(cl, internal_noise_admin_pinger);
	spawn_internal_noise(cl, internal_noise_stats_poller);
	spawn_internal_noise(cl, internal_noise_prometheus_poller);
	spawn_internal_noise(cl, internal_noise_random_stats_poller);
	spawn_internal_noise(cl, internal_noise_mysql_traffic);
	spawn_internal_noise(cl, internal_noise_mysql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}, {"num_tables", "5"}, {"protocol", "mix"}});
	spawn_internal_noise(cl, internal_noise_pgsql_traffic);
	spawn_internal_noise(cl, internal_noise_pgsql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}, {"num_tables", "2"}, {"protocol", "binary"}});
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}, {"port", "6070"}});

	int noise_tools_count = get_noise_tools_count();
	plan(noise_tools_count);

	diag("Sleeping for some time to let noises work...");
	int sleep_duration = get_env_int("NOISE_INJECTION_SLEEP", 60);
	sleep(sleep_duration);

    diag("Exiting test, noise reports should follow...");

	return exit_status();
}
