/**
 * @file test_cluster_sim_galera-t.cpp
 * @brief TAP wrapper running cluster_simulator against galera_tests_payloads/.
 */
#include "cluster_sim_runner.h"

int main(int, const char*[]) {
	return run_cluster_sim("galera_tests_payloads");
}
