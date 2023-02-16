/**
 * @file test_format_utils-t.cpp
 * @brief Test for checking the string formatting utility functions 'cstr_format'.
 * @details The test exercises both variants of the function. It also ensures that the vicinities of the
 *   supplied buffer size are properly tested.
 */

#include <algorithm>
#include <iostream>
#include <tuple>
#include <vector>
#include <string>

#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

using std::vector;
using std::tuple;
using std::string;

using test_pl_t = tuple<string, const void*, uint32_t, uint32_t, uint64_t, double>;

test_pl_t gen_rand_test_vals(uint32_t buf_size) {
	// Use the buf size to ensure testing below, above and around buf size limits
	uint32_t rnd_str_max_val = buf_size - (6 + 14 + (log(pow(2, 32))+1) * 2 + (log(pow(2, 64))+1) + 17);
	string rnd_str(random_string(rand() % (rnd_str_max_val * 3)));
	const void* rnd_ptr = static_cast<const void*>(rnd_str.data());
	uint32_t rnd_d = rand();
	uint32_t rnd_i = rand();
	uint64_t rnd_ld = rand() * 1000;
	double rnd_lf = rand();

	return test_pl_t { rnd_str, rnd_ptr, rnd_d, rnd_i, rnd_ld, rnd_lf };
}

uint32_t TEST_CASES = 10000;

vector<string> test_pl_to_str_vec(const test_pl_t& test_pl) {
	vector<string> res {};

	res.push_back(std::get<0>(test_pl));

	std::stringstream ss;
	ss << std::hex << std::get<1>(test_pl);
	res.push_back(ss.str());

	res.push_back(std::to_string(std::get<2>(test_pl)));
	res.push_back(std::to_string(std::get<3>(test_pl)));
	res.push_back(std::to_string(std::get<4>(test_pl)));
	res.push_back(std::to_string(std::get<5>(test_pl)));

	return res;
}

const char GEN_TEST_FMT_STR[] {
	"fmt - %s %p %d %i %lu %lf"
};

template <int N>
cfmt_t fmt_test_pl(char (&buf)[N], const test_pl_t& test_pl) {
	const string& str(std::get<0>(test_pl));
	const void* p = std::get<1>(test_pl);
	uint32_t d = std::get<2>(test_pl);
	uint32_t i = std::get<3>(test_pl);
	uint64_t ld = std::get<4>(test_pl);
	double lf = std::get<5>(test_pl);

	return cstr_format(buf, GEN_TEST_FMT_STR, str.c_str(), p, d, i, ld, lf);
}

cfmt_t fmt_test_pl(const test_pl_t& test_pl) {
	const string& str(std::get<0>(test_pl));
	const void* p = std::get<1>(test_pl);
	uint32_t d = std::get<2>(test_pl);
	uint32_t i = std::get<3>(test_pl);
	uint64_t ld = std::get<4>(test_pl);
	double lf = std::get<5>(test_pl);

	return cstr_format(GEN_TEST_FMT_STR, str.c_str(), p, d, i, ld, lf);
}

template <int N>
void fmt_test_payloads(const vector<test_pl_t>& test_cases, char (&buf)[N], bool use_buf, bool verbose = false) {
	vector<string> failed_checks {};

	for (const test_pl_t& t : test_cases) {
		string exp_str { "fmt -" };
		vector<string> test_str_vals { test_pl_to_str_vec(t) };

		for (const string& str_val : test_str_vals) {
			exp_str += " " + str_val;
		}

		cfmt_t f_out {};

		if (use_buf) {
			f_out = fmt_test_pl(buf, t);
		} else {
			f_out = fmt_test_pl(t);
		}

		if (f_out.str.size()) {
			if (exp_str != f_out.str) {
				string fail_msg { "Out str format should match - Size: " };
				fail_msg += std::to_string(f_out.str.size());
				fail_msg += ", Exp: " + exp_str + ", Act: " + f_out.str;

				failed_checks.push_back(fail_msg);
			}

			if (verbose) {
				diag(
					"Out str format should match - Size: %ld, Exp: %s, Act: %s",
					f_out.str.size(), exp_str.c_str(), f_out.str.c_str()
				);
			}
		} else {
			string act_str { buf };

			if (exp_str != act_str) {
				string fail_msg { "Out buf format should match - Size: "  };
				fail_msg += std::to_string(f_out.size);
				fail_msg += ", Exp: " + exp_str + ", Act: " + act_str;

				failed_checks.push_back(fail_msg);
			}

			if (verbose) {
				diag(
					"Out buf format should match - Size: %d, Exp: %s, Act: %s",
					f_out.size, exp_str.c_str(), act_str.c_str()
				);
			}
		}
	}

	string fail_msg {
		std::accumulate(failed_checks.begin(), failed_checks.end(), string { "" },
				[] (const string& s1, const string& s2) -> string {
					return s1 + "\n" + s2;
				}
			)
	};
	ok(failed_checks.empty(), "No checks should have failed: %s", fail_msg.c_str());
}

int main(int argc, char** argv) {
	plan(2);

	bool verbose = false;
	if (argc == 2 && string {argv[1]} == "verbose") {
		verbose = true;
	}

	srand(time(NULL));
	char buf[256] = { 0 };

	vector<test_pl_t> test_cases {};
	for (uint32_t i = 0; i < TEST_CASES; i++) {
		test_cases.push_back(gen_rand_test_vals(sizeof(buf) / sizeof(char)));
	}

	fmt_test_payloads(test_cases, buf, true, verbose);
	fmt_test_payloads(test_cases, buf, false, verbose);

	return exit_status();
}
