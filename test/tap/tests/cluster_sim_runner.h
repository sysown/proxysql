/**
 * @file cluster_sim_runner.h
 * @brief Shared body for the test_cluster_sim_<family>-t TAP wrappers.
 *   Each family wrapper is a one-liner that calls run_cluster_sim("<subdir>").
 */
#ifndef TEST_CLUSTER_SIM_RUNNER_H
#define TEST_CLUSTER_SIM_RUNNER_H

#include <algorithm>
#include <cstdlib>
#include <dirent.h>
#include <exception>
#include <string>
#include <utility>
#include <vector>

#include "tap.h"
#include "utils.h"
#include "command_line.h"
#include "proxysql_utils.h"
#include "re2/re2.h"
#include "json.hpp"

namespace cluster_sim_runner_detail {

inline std::vector<std::string> get_test_files(const std::string& path) {
	const re2::RE2 json_regex { R"(.*\.json$)" };

	DIR* dirp = opendir(path.c_str());
	if (dirp == nullptr) { return {}; }

	std::vector<std::string> entries {};
	for (struct dirent* dp = readdir(dirp); dp != nullptr; dp = readdir(dirp)) {
		std::string entry { dp->d_name };
		if (RE2::FullMatch(entry, json_regex)) {
			std::string full_path { path };
			full_path.append("/").append(entry);
			entries.push_back(std::move(full_path));
		}
	}
	(void)closedir(dirp);

	std::sort(entries.begin(), entries.end());
	return entries;
}

inline std::pair<int, std::string> make_internal_error(
	const std::string& err_msg, const char* file, int line
) {
	std::string formatted {};
	string_format(
		std::string { "File '%s', line '%d', Error: '%s'" },
		formatted, file, line, err_msg.c_str()
	);
	return { EXIT_FAILURE, formatted };
}

// Sorts per-server JSON objects by (hostgroup_id, hostname, port) so expected
// and actual cluster states are diffed in a stable order.
inline bool server_state_less(
	const nlohmann::ordered_json& a, const nlohmann::ordered_json& b
) {
	auto key = [](const nlohmann::ordered_json& j) {
		return std::to_string(static_cast<int>(j.at("hostgroup_id"))) +
		       std::string { j.at("hostname") } +
		       std::to_string(static_cast<int>(j.at("port")));
	};
	return key(a) < key(b);
}

// Formats a single verification_error entry with expected/actual state arrays
// sorted and indented for TAP diagnostic output.
inline std::pair<int, std::string> serialize_verification_error(
	const nlohmann::ordered_json& j_err, std::string& out_error_str
) {
	using nlohmann::ordered_json;
	try {
		ordered_json c_err = j_err;
		ordered_json exp_state = j_err.at("exp_proxysql_state");
		ordered_json act_state = j_err.at("act_proxysql_state");

		std::sort(exp_state.begin(), exp_state.end(), server_state_less);
		std::sort(act_state.begin(), act_state.end(), server_state_less);

		c_err["exp_proxysql_state"] = ordered_json::array();
		c_err["act_proxysql_state"] = ordered_json::array();

		unsigned int placeholder_num = 0;
		for (std::size_t i = 0; i < exp_state.size(); i++) {
			c_err["exp_proxysql_state"].push_back("%" + std::to_string(placeholder_num) + "s");
			placeholder_num += 1;
		}
		for (std::size_t i = 0; i < act_state.size(); i++) {
			c_err["act_proxysql_state"].push_back("%" + std::to_string(placeholder_num) + "s");
			placeholder_num += 1;
		}

		std::string str_result { c_err.dump(4) };
		placeholder_num = 0;
		for (const ordered_json& elem : exp_state) {
			std::string elem_str { elem.dump() };
			elem_str = replace_str(elem_str, "{", "{ ");
			elem_str = replace_str(elem_str, "}", " }");
			str_result = replace_str(
				str_result,
				"\"%" + std::to_string(placeholder_num) + "s\"",
				elem_str
			);
			placeholder_num += 1;
		}
		for (const ordered_json& elem : act_state) {
			std::string elem_str { elem.dump() };
			elem_str = replace_str(elem_str, "{", "{ ");
			elem_str = replace_str(elem_str, "}", " }");
			str_result = replace_str(
				str_result,
				"\"%" + std::to_string(placeholder_num) + "s\"",
				elem_str
			);
			placeholder_num += 1;
		}

		str_result = replace_str(str_result, "\n", "\n        ");
		out_error_str = str_result;
	} catch (const std::exception& e) {
		return { EXIT_FAILURE, std::string { "Malformed JSON 'verification_error': '" } + e.what() + "'" };
	}

	return { EXIT_SUCCESS, "" };
}

// Flattens the simulator's `results` array into a human-readable TAP diagnostic.
inline std::pair<int, std::string> serialize_errors(
	const nlohmann::ordered_json& j_results, std::string& out_str_errs
) {
	using nlohmann::ordered_json;
	std::pair<int, std::string> err_res { EXIT_SUCCESS, "" };
	std::vector<std::string> verf_errors {};

	ordered_json c_results = j_results;
	unsigned int res_num = 0;

	for (auto& j_sim_result : c_results) {
		if (
			j_sim_result.contains("err_type") &&
			(j_sim_result.at("err_type") == "verification_error")
		) {
			std::string sim_err_str {};
			const auto ser_res = serialize_verification_error(j_sim_result, sim_err_str);
			if (ser_res.first) {
				err_res = make_internal_error(ser_res.second, __FILE__, __LINE__);
				break;
			}
			verf_errors.push_back(sim_err_str);
			j_sim_result = "%" + std::to_string(res_num) + "s";
			res_num += 1;
		}
	}

	if (err_res.first == EXIT_SUCCESS) {
		std::string t_str_res { c_results.dump(4) };
		res_num = 0;
		for (const auto& sim_str : verf_errors) {
			t_str_res = replace_str(
				t_str_res,
				"\"%" + std::to_string(res_num) + "s\"",
				sim_str
			);
			res_num += 1;
		}
		out_str_errs = t_str_res;
	}

	return err_res;
}

}  // namespace cluster_sim_runner_detail

// Entry point for a family-specific TAP wrapper. Pass the payload subdirectory
// (e.g. "aurora_tests_payloads") resolved relative to CLUSTER_SIM_TESTS_ROOT.
// Emits one TAP point per .json payload, invoking
// `cluster_simulator --mode verify -f <payload>` from CLUSTER_SIM_BINARY_PATH.
inline int run_cluster_sim(const char* payload_subdir) {
	using nlohmann::ordered_json;
	using namespace cluster_sim_runner_detail;

	CommandLine cl {};
	if (cl.getEnv()) {
		diag("Unable to properly get 'ENV' variables");
		return EXIT_FAILURE;
	}

	const char* c_sim_path = std::getenv("CLUSTER_SIM_BINARY_PATH");
	if (c_sim_path == nullptr || *c_sim_path == '\0') {
		diag("CLUSTER_SIM_BINARY_PATH env var is required");
		return EXIT_FAILURE;
	}
	const std::string sim_path { c_sim_path };

	const char* c_tests_root = std::getenv("CLUSTER_SIM_TESTS_ROOT");
	if (c_tests_root == nullptr || *c_tests_root == '\0') {
		diag("CLUSTER_SIM_TESTS_ROOT env var is required");
		return EXIT_FAILURE;
	}
	const std::string tests_path = std::string { c_tests_root } + "/" + payload_subdir;

	const std::vector<std::string> payload_files = get_test_files(tests_path);
	if (payload_files.empty()) {
		diag("No payload '.json' files found under '%s'", tests_path.c_str());
		return EXIT_FAILURE;
	}

	plan(static_cast<int>(payload_files.size()));

	for (const std::string& payload : payload_files) {
		std::string sim_stdout {};
		std::string sim_stderr {};
		std::vector<const char*> sim_args { "--mode", "verify", "-f", payload.c_str() };

		int err = wexecvp(sim_path, sim_args, {}, sim_stdout, sim_stderr);

		if (err == EXIT_SUCCESS || ((err / 256) == EXIT_FAILURE)) {
			try {
				ordered_json j_test_result = ordered_json::parse(sim_stdout);
				const bool no_errors = j_test_result.at("err_type") == "none";
				ordered_json j_errors {};
				if (!no_errors) {
					j_errors = j_test_result.at("results");
				}

				std::string str_errs {};
				serialize_errors(j_errors, str_errs);
				ok(no_errors, "Tested '%s'. Errs: '%s'", payload.c_str(), str_errs.c_str());
			} catch (const std::exception& e) {
				std::string err_msg {};
				string_format(
					std::string {
						"INTERNAL_SIM_ERROR - Invalid simulator output '%s' result, with value '%s',"
						" failed to be parsed as a JSON: '%s'"
					},
					err_msg, payload.c_str(), sim_stdout.c_str(), e.what()
				);
				diag("%s", err_msg.c_str());
				return EXIT_FAILURE;
			}
		} else {
			std::string err_msg {};
			string_format(
				std::string {
					"Call to 'cluster_simulator' failed with 'err_code': '%d', 'stdout': '%s'"
					" and 'stderr': '%s'"
				},
				err_msg, err, sim_stdout.c_str(), sim_stderr.c_str()
			);
			diag("%s", err_msg.c_str());
			return EXIT_FAILURE;
		}
	}

	return exit_status();
}

#endif  // TEST_CLUSTER_SIM_RUNNER_H
