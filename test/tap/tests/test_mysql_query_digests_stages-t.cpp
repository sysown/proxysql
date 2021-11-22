#include <utility>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <chrono>
#include <ctype.h>
#include <regex>

#include "json.hpp"
#include "proxysql.h"
#include "utils.h"
#include "command_line.h"
#include "tap.h"

__thread int mysql_thread___query_digests_max_query_length = 65000;
__thread bool mysql_thread___query_digests_lowercase = false;
__thread bool mysql_thread___query_digests_replace_null = true;
__thread bool mysql_thread___query_digests_no_digits = false;
__thread int mysql_thread___query_digests_grouping_limit = 3;
__thread int mysql_thread___query_digests_groups_grouping_limit = 1;

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
						const_cast<char*>(query.c_str()), query.length(), &first_comment,
						((query.size() < QUERY_DIGEST_BUF) ? buf : NULL)
					);
			} else if (mode == 1) {
				c_res =
					mysql_query_digest_and_first_comment_one_it(
						const_cast<char*>(query.c_str()), query.length(), &first_comment,
						((query.size() < QUERY_DIGEST_BUF) ? buf : NULL)
					);
			} else if (mode == 2) {
				c_res =
					mysql_query_digest_and_first_comment_2(
						const_cast<char*>(query.c_str()), query.length(), &first_comment,
						((query.size() < QUERY_DIGEST_BUF) ? buf : NULL)
					);
			} else if (mode == 3) {
				c_res =
					mysql_query_digest_first_stage(
						const_cast<char*>(query.c_str()), query.length(), &first_comment,
						((query.size() < QUERY_DIGEST_BUF) ? buf : NULL)
					);
			} else if (mode == 4) {
				c_res =
					mysql_query_digest_second_stage(
						const_cast<char*>(query.c_str()), query.length(), &first_comment,
						((query.size() < QUERY_DIGEST_BUF) ? buf : NULL)
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
 *   4. Digit replacement result. Can be empty.
 *
 *   The parsing performed to the query is incremental. If the results for stages 2 and 3 are present then
 *   parsing of stages 2 and 3 are performed, and results are checked.
 */
using query_digest_test = tuple<string, string, string, string, string, string>;

struct dt_idx {
	enum : int {
		query = 0,
		first_stage = 1,
		second_stage = 2,
		third_stage = 3,
		fourth_stage = 5,
		digit_replacement = 4
	};
};

nlohmann::json get_tests_defs(const string& filepath) {
	std::ifstream file_stream(filepath);
	std::string test_file_contents((std::istreambuf_iterator<char>(file_stream)), (std::istreambuf_iterator<char>()));

	std::regex comment_pattern { ".*\\/\\/.*[\\r\\n]" };
	string test_file_no_comments { std::regex_replace(test_file_contents, comment_pattern, "") };
	nlohmann::json j_test_defs = nlohmann::json::parse(test_file_no_comments, nullptr, true);

	return j_test_defs;
}

int count_test_defs(const nlohmann::json& j_test_defs, uint32_t& test_num) {
	uint32_t res_test_num = 0;

	try {
		for (const auto& j_test_def : j_test_defs) {
			const auto& j_queries = j_test_def.at("q");

			for (const string& s_query : j_queries) {
				bool contains_supp_check =
					j_test_def.contains("s1") ||
					j_test_def.contains("s2") ||
					j_test_def.contains("s3") ||
					j_test_def.contains("s4") ||
					j_test_def.contains("dr");

				if (contains_supp_check) {
					res_test_num++;
				}
			}
		}
	} catch (const std::exception& ex){
		diag("Invalid test definition doesn't specify a query: '%s'", ex.what());
		return EXIT_FAILURE;
	}

	// return results
	test_num = res_test_num;

	return EXIT_SUCCESS;
}

int process_digest_test(const nlohmann::json& test_def) {
	char buf[QUERY_DIGEST_BUF];
	char* first_comment = NULL;
	std::string query { test_def.at("q") };
	char* c_query = (char*)malloc(query.size());
	memcpy(c_query, query.c_str(), query.size());

	if (test_def.contains("s1")) {
		std::string digest_stage_1 { test_def.at("s1") };
		char* c_res = mysql_query_digest_first_stage(c_query, query.size(), &first_comment,
				((query.size() < QUERY_DIGEST_BUF) ? buf : NULL));
		std::string stage_1_res(c_res);

		ok(
			stage_1_res == digest_stage_1,
			"Digest should be equal to exp result for 'STAGE 1' parsing:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
			query.c_str(), stage_1_res.c_str(), digest_stage_1.c_str()
		);
	}
	if (test_def.contains("s2")) {
		std::string digest_stage_2 { test_def.at("s2") };
		if (digest_stage_2.empty() == false) {
			char* c_res = mysql_query_digest_second_stage(c_query, query.size(), &first_comment,
					((query.size() < QUERY_DIGEST_BUF) ? buf : NULL));
			std::string stage_2_res(c_res);

			ok(
				stage_2_res == digest_stage_2,
				"Digest should be equal to exp result for 'STAGE 2' parsing:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
				query.c_str(), stage_2_res.c_str(), digest_stage_2.c_str()
			);
		}
	}
	if (test_def.contains("s3")) {
		std::string digest_stage_3 { test_def.at("s3") };
		if (digest_stage_3.empty() == false) {
			int backup_groups_grouping_limit = mysql_thread___query_digests_groups_grouping_limit;
			mysql_thread___query_digests_groups_grouping_limit = 0;
			char* c_res = mysql_query_digest_and_first_comment_2(c_query, query.size(), &first_comment,
					((query.size() < QUERY_DIGEST_BUF) ? buf : NULL));
			std::string stage_3_res(c_res);

			ok(
				stage_3_res == digest_stage_3,
				"Digest should be equal to exp result for 'STAGE 3' parsing:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
				query.c_str(), stage_3_res.c_str(), digest_stage_3.c_str()
			);

			mysql_thread___query_digests_groups_grouping_limit = backup_groups_grouping_limit;
		}
	}
	if (test_def.contains("s4")) {
		std::string digest_stage_4 { test_def.at("s4") };
		if (digest_stage_4.empty() == false) {
			char* c_res = mysql_query_digest_and_first_comment_2(c_query, query.size(), &first_comment,
					((query.size() < QUERY_DIGEST_BUF) ? buf : NULL));
			std::string stage_4_res(c_res);

			ok(
				stage_4_res == digest_stage_4,
				"Digest should be equal to exp result for 'STAGE 4' parsing:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
				query.c_str(), stage_4_res.c_str(), digest_stage_4.c_str()
			);
		}
	}
	if (test_def.contains("dr")) {
		std::string digest_no_digits { test_def.at("dr") };
		if (digest_no_digits.empty() == false) {
			int no_digits_backup = mysql_thread___query_digests_no_digits;
			mysql_thread___query_digests_no_digits = 1;

			char* c_res = mysql_query_digest_and_first_comment_2(c_query, query.size(), &first_comment,
					((query.size() < QUERY_DIGEST_BUF) ? buf : NULL));
			std::string no_digits_res(c_res);
			ok(
				no_digits_res == digest_no_digits,
				"Digest should be equal to exp result for 'NoDigits' parsing:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
				query.c_str(), no_digits_res.c_str(), digest_no_digits.c_str()
			);

			mysql_thread___query_digests_no_digits = no_digits_backup;
		}
	}
	if (test_def.contains("mz")) {
		vector<nlohmann::json> mz_tests_defs {};

		if (test_def.at("mz").is_array()) {
			for (const nlohmann::json& mz_test_def : test_def.at("mz")) {
				mz_tests_defs.push_back(mz_test_def);
			}
		} else {
			mz_tests_defs.push_back(test_def.at("mz"));
		}

		for (const nlohmann::json& mz_test_def : mz_tests_defs) {
			int digest_max_size = mz_test_def.at("digest_max_size");
			int grouping_limit = mz_test_def.at("grouping_limit");
			int groups_grouping_limit = mz_test_def.at("groups_grouping_limit");
			string exp_digest = mz_test_def.at("digest");
			int replace_digits = 0;

			if (mz_test_def.contains("replace_digits")) {
				replace_digits = mz_test_def.at("replace_digits");
			}

			int backup_digest_max_length = mysql_thread___query_digests_max_query_length;
			mysql_thread___query_digests_max_query_length = digest_max_size;
			int backup_grouping_limit = mysql_thread___query_digests_grouping_limit;
			mysql_thread___query_digests_grouping_limit = grouping_limit;
			int backup_groups_grouping_limit = mysql_thread___query_digests_groups_grouping_limit;
			mysql_thread___query_digests_groups_grouping_limit = groups_grouping_limit;
			int no_digits_backup = mysql_thread___query_digests_no_digits;
			mysql_thread___query_digests_no_digits = replace_digits;

			char* c_res = mysql_query_digest_and_first_comment_2(c_query, query.size(), &first_comment,
					((query.size() < QUERY_DIGEST_BUF) ? buf : NULL));
			std::string digest_res(c_res);
			ok(
				exp_digest == digest_res,
				"Digest should be equal to exp result for 'MultipleSettings' parsing:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
				query.c_str(), digest_res.c_str(), exp_digest.c_str()
			);

			mysql_thread___query_digests_max_query_length = backup_digest_max_length;
			mysql_thread___query_digests_grouping_limit = backup_grouping_limit;
			mysql_thread___query_digests_groups_grouping_limit = backup_groups_grouping_limit;
			mysql_thread___query_digests_no_digits = no_digits_backup;
		}
	}

	free(c_query);

	return EXIT_SUCCESS;
}

int process_digest_tests(const nlohmann::json& tests_defs) {
	int res = EXIT_SUCCESS;

	for (const auto& test_def : tests_defs) {
		if (test_def.at("q").is_array()) {
			vector<nlohmann::json> same_digest_tests {};

			for (const string& query : test_def.at("q")) {
				nlohmann::json new_test_def = test_def;
				new_test_def["q"] = query;

				same_digest_tests.push_back(new_test_def);
			}

			for (const auto& s_digest_test : same_digest_tests) {
				process_digest_test(s_digest_test);
			}
		} else {
			process_digest_test(test_def);
		}
	}

	return res;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const string digests_filepath { string(cl.workdir) + DIGESTS_TEST_FILENAME };

	uint32_t tests_num = 0;

	nlohmann::json tests_defs {};

	try {
		tests_defs = get_tests_defs(digests_filepath);
	} catch (const std::exception& ex) {
		diag("'get_tests_defs' failed at ('%s':'%d') with exception: '%s'", __FILE__, __LINE__, ex.what());
	}

	plan(tests_num);

	process_digest_tests(tests_defs);

	/*
	// Simple benchmarking for tracking impls overhead.
	{
		vector<string> queries {};
		for (const auto& test_def : tests_defs) {
			if (test_def.at("q").is_array()) {
				for (const string& query : test_def.at("q")) {
					queries.push_back(query);
				}
			} else {
				queries.push_back(static_cast<std::string>(test_def.at("q")));
			}
		}

		int len = 0;
		uint64_t duration = 0;

		std::cout << "Size: " << queries.size() << "\n\n";

		uint64_t iterations = 100000;
		duration = benchmark_parsing(queries, 0, iterations, len);
		std::cout << "Current:       " << duration << "\n";
		duration = benchmark_parsing(queries, 1, iterations, len);
		std::cout << "One iteration: " << duration << "\n";
		duration = benchmark_parsing(queries, 2, iterations, len);
		std::cout << "Stages:        " << duration << "\n";
		duration = benchmark_parsing(queries, 3, iterations, len);
		std::cout << "First stage:   " << duration << "\n";
		duration = benchmark_parsing(queries, 4, iterations, len);
		std::cout << "Second stage:  " << duration << "\n";

		std::cout << "\n";

		duration = benchmark_parsing(queries, 1, iterations, len);
		std::cout << "One iteration: " << duration << "\n";
		duration = benchmark_parsing(queries, 3, iterations, len);
		std::cout << "First stage:   " << duration << "\n";
		duration = benchmark_parsing(queries, 2, iterations, len);
		std::cout << "Stages:        " << duration << "\n";
		duration = benchmark_parsing(queries, 4, iterations, len);
		std::cout << "Second stage:  " << duration << "\n";
		duration = benchmark_parsing(queries, 0, iterations, len);
		std::cout << "Current:       " << duration << "\n";
	}
	*/

	return exit_status();
}
