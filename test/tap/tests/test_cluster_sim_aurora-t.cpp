/**
 * @file test_cluster_sim_aurora-t.cpp
 * @brief TAP wrapper running cluster_simulator against aurora_tests_payloads/.
 */
#include "cluster_sim_runner.h"

int main(int, const char*[]) {
	return run_cluster_sim("aurora_tests_payloads");
}
