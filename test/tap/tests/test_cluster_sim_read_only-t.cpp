/**
 * @file test_cluster_sim_read_only-t.cpp
 * @brief TAP wrapper running cluster_simulator against readonly_tests_payloads/.
 */
#include "cluster_sim_runner.h"

int main(int, const char*[]) {
	return run_cluster_sim("readonly_tests_payloads");
}
