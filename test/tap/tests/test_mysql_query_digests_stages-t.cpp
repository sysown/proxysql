#include <utility>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <chrono>
#include <ctype.h>

#include "json.hpp"
#include "proxysql.h"
#include "utils.h"
#include "command_line.h"
#include "tap.h"

__thread int mysql_thread___query_digests_max_query_length = 65000;
__thread bool mysql_thread___query_digests_lowercase = false;
__thread bool mysql_thread___query_digests_replace_null = false;
__thread bool mysql_thread___query_digests_no_digits = false;
__thread int mysql_thread___query_digests_grouping_limit = 3;

using std::vector;
using std::string;
using std::tuple;

std::string replace_str(const std::string& str, const std::string& match, const std::string& repl) {
	if(match.empty()) {
		return str;
	}

	std::string result = str;
	size_t start_pos = 0;

	while((start_pos = result.find(match, start_pos)) != std::string::npos) {
		result.replace(start_pos, match.length(), repl);
		start_pos += repl.length();
	}

	return result;
}

std::string increase_mark_num(const std::string query, uint32_t num) {
	std::string result = query;
	std::string marks = "";

	for (uint32_t i = 0; i < num - 1; i++) {
		marks += "?,";
	}
	marks += "?,...";

	result = replace_str(result, "?,...", marks);

	return result;
}

char is_digit_char(char c) {
	if(c >= '0' && c <= '9') {
		return 1;
	}
	return 0;
}

vector<string> extract_numbers(const string query) {
	vector<string> numbers {};
	string number {};

	for (const char c : query) {
		if (is_digit_char(c)) {
			number += c;
		} else {
			if (!number.empty()) {
				numbers.push_back(number);
				number.clear();
			}
		}
	}

	return numbers;
}

string replace_numbers(const string query, const char mark) {
	vector<string> numbers { extract_numbers(query) };
	std::sort(
		numbers.begin(), numbers.end(),
		[](const string& s1, const string& s2) -> bool { return s1.size() > s2.size(); }
	);

	string query_res { query };

	for (const string& num : numbers) {
		query_res = replace_str(query_res, num, string { mark });
	}

	return query_res;
}

typedef std::chrono::high_resolution_clock hrc;

uint64_t benchmark_parsing(const vector<string>& queries, int mode, uint32_t iterations, int& len) {
	std::chrono::nanoseconds duration;
	hrc::time_point start;
	hrc::time_point end;

	vector<char*> results {};
	char buf[QUERY_DIGEST_BUF];

	start = hrc::now();

	for (size_t j = 0; j < iterations; j++) {
		for (const string& query : queries) {
			char* first_comment = NULL;

			char* c_res = NULL;
			if (mode == 0) {
				c_res =
					mysql_query_digest_and_first_comment(
						const_cast<char*>(query.c_str()), query.length(), &first_comment, buf
					);
			} else if (mode == 1){
				c_res =
					mysql_query_digest_and_first_comment_one_it(
						const_cast<char*>(query.c_str()), query.length(), &first_comment, buf
					);
			} else {
				c_res =
					mysql_query_digest_and_first_comment_2(
						const_cast<char*>(query.c_str()), query.length(), &first_comment, buf
					);
			}

			results.push_back(c_res);
		}
	}

	end = hrc::now();
	duration = end - start;

	return duration.count();
}


const string DIGESTS_TEST_FILENAME { "tokenizer_payloads/regular_tokenizer_digests.hjson" };

/**
 * @brief The digest test is defined to be four strings:
 *   0. The query itself.
 *   1. The result of first stage parsing.
 *   2. The result of second stage parsing. Can be empty.
 *   3. The result of third stage parsing. Can be empty.
 *
 *   The parsing performed to the query is incremental. If the results for stages 2 and 3 are present then
 *   parsing of stages 2 and 3 are performed, and results are checked.
 */
using query_digest_test = tuple<string, string, string, string>;

int get_tests_defs(const string& filepath, vector<query_digest_test>& tests_def, uint32_t& test_num) {
	std::ifstream file_stream(filepath);
	std::string test_file_contents((std::istreambuf_iterator<char>(file_stream)), (std::istreambuf_iterator<char>()));

	vector<query_digest_test> res_tests_def {};
	uint32_t res_test_num = 0;

	try {
		nlohmann::json j_test_defs = nlohmann::json::parse(test_file_contents, nullptr, true, true);

		for (const auto& j_test_def : j_test_defs) {
			const string& query = j_test_def.at("q");
			const string& s1 = j_test_def.at("s1");
			string s2 {};
			string s3 {};

			if (j_test_def.contains("s2")) {
				s2 = j_test_def["s2"];
				res_test_num++;
			}

			// TODO: Stage 3 is WIP
			/*
			if (j_test_def.contains("s3")) {
				s3 = j_test_def["s3"];
				res_test_num++;
			}
			*/

			res_tests_def.push_back({ query, s1, s2, s3 });
			res_test_num++;
		}
	} catch (const std::exception& ex){
		diag("Failed to parse the test payload file '%s' with ex: '%s'", filepath.c_str(), ex.what());
		return EXIT_FAILURE;
	}

	// return results
	tests_def = res_tests_def;
	test_num = res_test_num;

	return EXIT_SUCCESS;
}

void process_digest_tests(const vector<query_digest_test>& tests_def) {
	char buf[QUERY_DIGEST_BUF];

	for (size_t i = 0; i < tests_def.size(); i++) {
		const auto& query = std::get<0>(tests_def[i]);
		const auto& digest_stage_1 = std::get<1>(tests_def[i]);
		const auto& digest_stage_2 = std::get<2>(tests_def[i]);
		const auto& digest_stage_3 = std::get<3>(tests_def[i]);
		const auto& query_str_rep = replace_str(std::get<0>(tests_def[i]), "\n", "\\n");

		char* first_comment = NULL;
		string exp_res {};
		char* c_res = NULL;

		c_res = mysql_query_digest_first_stage(query.c_str(), query.size(), &first_comment, buf);
		std::string stage_1_res(c_res);

		ok(
			stage_1_res == digest_stage_1,
			"Digest should be equal to exp result for 'STAGE 1' parsing:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
			query.c_str(), stage_1_res.c_str(), digest_stage_1.c_str()
		);

		if (digest_stage_2.empty() == false) {
			c_res = mysql_query_digest_and_first_comment_2(query.c_str(), query.size(), &first_comment, buf);
			std::string stage_2_res(c_res);

			ok(
				stage_2_res == digest_stage_2,
				"Digest should be equal to exp result for 'STAGE 2' parsing:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
				query.c_str(), stage_2_res.c_str(), digest_stage_2.c_str()
			);
		}
	}
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const string digests_filepath { string(cl.workdir) + DIGESTS_TEST_FILENAME };
	vector<query_digest_test> tests_defs {};
	uint32_t tests_num = 0;

	int err = get_tests_defs(digests_filepath, tests_defs, tests_num);
	if (err == EXIT_FAILURE) {
		diag("Failed to execute 'get_tests_defs' at ('%s':'%d')", __FILE__, __LINE__);
	}

	plan(tests_num);

	process_digest_tests(tests_defs);

	// Simple benchmarking for tracking impls overhead.
	/*
	{
		err = get_tests_defs(digests_filepath, tests_defs, tests_num);
		if (err == EXIT_FAILURE) {
			diag("Failed to execute 'get_tests_defs' at ('%s':'%d')", __FILE__, __LINE__);
		}
		vector<string> queries {};
		std::transform(
			tests_defs.begin(), tests_defs.end(), std::back_inserter(queries),
			[](const query_digest_test& test_def){ return std::get<0>(test_def); }
		);

		int len = 0;
		uint64_t duration = 0;

		// duration = benchmark_parsing(queries, 0, 1000000, len);
		// std::cout << "Current: " << duration << "\n";
		// duration = benchmark_parsing(queries, 1, 1000000, len);
		// std::cout << "One iteration: " << duration << "\n";
		duration = benchmark_parsing(queries, 2, 1000000, len);
		std::cout << "Stages: " << duration << "\n";
		std::cout << "Size: " << queries.size() << "\n";

		// duration = benchmark_parsing(queries, 1, 1000000, len);
		// std::cout << "One iteration: " << duration << "\n";
		// duration = benchmark_parsing(queries, 2, 1000000, len);
		// std::cout << "Stages: " << duration << "\n";
		// duration = benchmark_parsing(queries, 0, 1000000, len);
		// std::cout << "Current: " << duration << "\n";
	}
	*/

	return exit_status();
}
