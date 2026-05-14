/**
 * @file test_cluster_sim_repl_lag-t.cpp
 * @brief TAP wrapper running cluster_simulator against repl_tests_payloads/.
 */
#include "cluster_sim_runner.h"

int main(int, const char*[]) {
	return run_cluster_sim("repl_tests_payloads");
}
