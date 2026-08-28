/**
 * @file test_cluster_sim_group_repl-t.cpp
 * @brief TAP wrapper running cluster_simulator against grouprep_tests_payloads/.
 */
#include "cluster_sim_runner.h"

int main(int, const char*[]) {
	return run_cluster_sim("grouprep_tests_payloads");
}
