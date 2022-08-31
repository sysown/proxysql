/**
 * @file test_mysql_query_digests_stages-t.cpp
 * @brief This test file is responsible for checking the correctness of
 *   'mysql_query_digest_and_first_comment_2' implementation.
 * @details The test allows to individually execute three types of testing payloads:
 *   * Regular tokenizer digests: These payloads types can be found in the 'regular_tokenizer_digests.hjson'
 *     file. This file can be used for testing the correctness of the tokenizer behavior for any given payload
 *     and configuration settings, using a simple JSON format. The `hjson` file allows comments starting with '//'.
 *   * Crashing tokenizer tests: These payloads where discovered during testing to cause memory issues, the
 *     system created for specifying the configuration used for consuming the payload and the payloads themselves
 *     are left as documentation and regression testing, the main file for specifying new payloads of these
 *     kind is: `crashing_payloads.hjson`.
 *   * Grouping tests: These payloads are randomly generated with each test execution, testing the tokenizer
 *     grouping features for a number of different configurations.
 *
 *   For making testing easier, it's possible to select which tests to execute, simply by supplying to the
 *   test file a string holding any of the following options (or a combination of them) as first parameter:
 *     * 'grouping': Only executes the grouping tests.
 *     * 'regular': Only executes the regular tests.
 *     * 'crashing': Only executes the crashing tests.
 *
 *   So:
 *     * `test_mysql_query_digests_stages-t regular` will just execute the regular tests.
 *     * `test_mysql_query_digests_stages-t regular,crashing` will execute both regular and crashing tests.
 *
 *   By default all types of tests are executed.
 */
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
#include "proxysql_utils.h"
#include "utils.h"
#include "command_line.h"
#include "tap.h"

__thread int mysql_thread___query_digests_max_query_length = 65000;
__thread bool mysql_thread___query_digests_lowercase = false;
__thread bool mysql_thread___query_digests_replace_null = true;
__thread bool mysql_thread___query_digests_no_digits = false;
__thread bool mysql_thread___query_digests_keep_comment = false;
__thread int mysql_thread___query_digests_grouping_limit = 3;
__thread int mysql_thread___query_digests_groups_grouping_limit = 1;

using std::vector;
using std::string;

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

typedef std::chrono::high_resolution_clock hrc;

uint64_t benchmark_parsing(const vector<string>& queries, int mode, uint32_t iterations, int& len) {
	std::chrono::nanoseconds duration;
	hrc::time_point start;
	hrc::time_point end;

	vector<char*> results {};
	vector<char*> comments {};

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

			if (query.size() > QUERY_DIGEST_BUF) {
				results.push_back(c_res);
			}
			if (first_comment != NULL) {
				comments.push_back(first_comment);
			}
		}
	}

	end = hrc::now();
	duration = end - start;

	for (char* result : results) {
		free(result);
	}

	for (char* comment : comments) {
		free(comment);
	}

	return duration.count();
}

const string DIGESTS_TEST_FILENAME { "tokenizer_payloads/regular_tokenizer_digests.hjson" };

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
				if (j_test_def.contains("s1")) {
					res_test_num++;
				}
				if (j_test_def.contains("s2")) {
					res_test_num++;
				}
				if (j_test_def.contains("s3")) {
					res_test_num++;
				}
				if (j_test_def.contains("s4")) {
					res_test_num++;
				}
				if (j_test_def.contains("dr")) {
					res_test_num++;
				}

				bool contains_settings = j_test_def.contains("mz");
				if (contains_settings) {
					if (j_test_def.at("mz").is_array()) {
						for (const auto& j_mz_test : j_test_def.at("mz")) {
							res_test_num++;
						}
					} else {
						res_test_num++;
					}
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

void process_mz_test_def(const nlohmann::json& test_def, const char* c_query, const string query) {
	char* first_comment = NULL;
	char buf[QUERY_DIGEST_BUF];

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
			string exp_digest {};

			int digest_max_size = 2048;
			int grouping_limit = 3;
			int groups_grouping_limit = 0;
			int replace_digits = 0;
			bool no_digest = true;
			int lowercase = 0;
			bool keep_comment = false;

			if (mz_test_def.contains("digest_max_size")) {
				digest_max_size = mz_test_def.at("digest_max_size");
			}
			if (mz_test_def.contains("grouping_limit")) {
				grouping_limit = mz_test_def.at("grouping_limit");
			}
			if (mz_test_def.contains("groups_grouping_limit")) {
				groups_grouping_limit = mz_test_def.at("groups_grouping_limit");
			}
			if (mz_test_def.contains("replace_digits")) {
				replace_digits = mz_test_def.at("replace_digits");
			}
			if (mz_test_def.contains("digest")) {
				exp_digest = mz_test_def.at("digest");
				no_digest = false;
			}
			if (mz_test_def.contains("lowercase")) {
				lowercase = mz_test_def.at("lowercase");
			}
			if (mz_test_def.contains("keep_comment")) {
				keep_comment = mz_test_def.at("keep_comment");
			}

			int backup_digest_max_length = mysql_thread___query_digests_max_query_length;
			mysql_thread___query_digests_max_query_length = digest_max_size;
			int backup_grouping_limit = mysql_thread___query_digests_grouping_limit;
			mysql_thread___query_digests_grouping_limit = grouping_limit;
			int backup_groups_grouping_limit = mysql_thread___query_digests_groups_grouping_limit;
			mysql_thread___query_digests_groups_grouping_limit = groups_grouping_limit;
			int no_digits_backup = mysql_thread___query_digests_no_digits;
			mysql_thread___query_digests_no_digits = replace_digits;
			int lowercase_backup = mysql_thread___query_digests_lowercase;
			mysql_thread___query_digests_lowercase = lowercase_backup;
			int keep_comment_backup = mysql_thread___query_digests_keep_comment;
			mysql_thread___query_digests_keep_comment = keep_comment;

			char* c_res = mysql_query_digest_and_first_comment_2(c_query, query.size(), &first_comment,
					((query.size() < QUERY_DIGEST_BUF) ? buf : NULL));
			std::string digest_res(c_res);

			if (no_digest == false) {
				ok(
					exp_digest == digest_res,
					"Digest should be equal to exp result for 'MultipleSettings' parsing:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
					query.c_str(), digest_res.c_str(), exp_digest.c_str()
				);
			}

			mysql_thread___query_digests_max_query_length = backup_digest_max_length;
			mysql_thread___query_digests_grouping_limit = backup_grouping_limit;
			mysql_thread___query_digests_groups_grouping_limit = backup_groups_grouping_limit;
			mysql_thread___query_digests_no_digits = no_digits_backup;
			mysql_thread___query_digests_lowercase = lowercase_backup;
			mysql_thread___query_digests_keep_comment = keep_comment_backup;

			if (query.size() >= QUERY_DIGEST_BUF) {
				free(c_res);
			}

			if (first_comment != NULL) {
				free(first_comment);
				first_comment = NULL;
			}
		}
	}
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

		if (first_comment != NULL) {
			free(first_comment);
			first_comment = NULL;
		}
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

			if (first_comment != NULL) {
				free(first_comment);
				first_comment = NULL;
			}
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

			if (first_comment != NULL) {
				free(first_comment);
				first_comment = NULL;
			}
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

			if (first_comment != NULL) {
				free(first_comment);
				first_comment = NULL;
			}
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

			if (first_comment != NULL) {
				free(first_comment);
				first_comment = NULL;
			}
		}
	}
	if (test_def.contains("mz")) {
		process_mz_test_def(test_def, c_query, query);
	}

	free(c_query);

	return EXIT_SUCCESS;
}

int count_crashing_test_defs(const nlohmann::json& j_test_defs, uint32_t& test_num) {
	test_num = j_test_defs.size();
	return EXIT_SUCCESS;
}

void process_crashing_tests(CommandLine& cl, const nlohmann::json& test_defs) {
	int res = EXIT_SUCCESS;

	for (const auto& test_def : test_defs) {
		const string q_path = string { cl.workdir } + string { test_def.at("q_path") };
		std::ifstream file_stream(q_path);
		std::string query((std::istreambuf_iterator<char>(file_stream)), (std::istreambuf_iterator<char>()));

		char* c_query = (char*)malloc(query.size());
		memcpy(c_query, query.c_str(), query.size());

		process_mz_test_def(test_def, c_query, query);
		ok(true, "Crashing test execution finished without a crash");

		free(c_query);
	}
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

std::random_device rd;
std::default_random_engine generator(rd());

std::string gen_rand_string(std::size_t len) {
	const char alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	std::uniform_int_distribution<> distribution(0, sizeof(alphanum) - 2);
	std::uniform_int_distribution<> binary_dist(0, 1);
	std::string rand_str(static_cast<std::size_t>(len), '\0');
	std::string result {};

	for (std::size_t i = 0; i < len; i++) {
		rand_str[i] = alphanum[distribution(generator)];
	}

	result = binary_dist(generator) == 0 ? "'" + rand_str + "'" : "\"" + rand_str + "\"";

	return result;
}

double gen_rand_float(std::size_t max_range) {
	std::normal_distribution<> distribution(0, max_range);

	return distribution(generator);
}

std::string gen_rand_float_str(std::size_t max_range) {
	std::normal_distribution<> distribution(0, 6);
	uint32_t precision = distribution(generator);

    std::ostringstream float_fixed_precision {};
    float_fixed_precision.precision(precision);
    float_fixed_precision << std::fixed << gen_rand_float(max_range);

	return float_fixed_precision.str();
}

std::string gen_rand_int_str(std::size_t max_range) {
	int64_t rand_num = std::floor(gen_rand_float(max_range));
	return std::to_string(rand_num);
}

std::string gen_rand_spaces(std::size_t len) {
	std::uniform_int_distribution<> distribution(0, len);
	return std::string(static_cast<std::size_t>(distribution(generator)), ' ');
}

std::string gen_rand_null() {
	std::uniform_int_distribution<> distribution(0, 1);
	string null_res {};

	null_res += distribution(generator) == 0 ? 'N' : 'n';
	null_res += distribution(generator) == 0 ? 'U' : 'u';
	null_res += distribution(generator) == 0 ? 'L' : 'l';
	null_res += distribution(generator) == 0 ? 'L' : 'l';

	return null_res;
}

std::string gen_rand_hex_str(std::size_t max_range) {
	int64_t rand_num = std::floor(gen_rand_float(max_range));
	std::stringstream sstream {};
	sstream << std::hex << rand_num;

	return "0x" + sstream.str();
}

const uint32_t RAND_INT_RANGE = 100000;
const uint32_t RAND_FLOAT_RANGE = 100000;
const uint32_t RAND_STR_RANGE = 30;

std::string gen_random_value() {
	std::uniform_int_distribution<> distribution(0, 5);
	int value_type = distribution(generator);
	std::string result {};

	switch (value_type) {
		case 0: result = gen_rand_int_str(RAND_INT_RANGE); break;
		case 1: result = gen_rand_float_str(RAND_INT_RANGE); break;
		case 2: result = gen_rand_float_str(RAND_INT_RANGE); break;
		case 3: result = gen_rand_string(RAND_STR_RANGE); break;
		case 4: result = gen_rand_null(); break;
		case 5: result = gen_rand_hex_str(RAND_INT_RANGE); break;
		default: result = gen_rand_hex_str(RAND_INT_RANGE); break;
	}

	return result;
}

std::string gen_random_value_group(uint32_t num_group_values) {
	std::string group_values_str { "(" + gen_rand_spaces(3) } ;

	for (uint32_t i = 0; i < num_group_values - 1; i++) {
		group_values_str += gen_random_value() + gen_rand_spaces(3) + "," + gen_rand_spaces(3);
	}

	group_values_str += gen_rand_spaces(3) + gen_random_value() + gen_rand_spaces(3) + ")";

	return group_values_str;
}

std::string gen_rnd_grouping_query(uint32_t num_group_values, uint32_t num_groups, const string& query_start, const string query_end) {
	std::string result { query_start + gen_rand_spaces(3) + ' '};

	for (uint32_t i = 0; i < num_groups - 1; i++) {
		result += gen_random_value_group(num_group_values) + gen_rand_spaces(3) + "," + gen_rand_spaces(3);
	}

	result += gen_rand_spaces(3) + gen_random_value_group(num_group_values) + gen_rand_spaces(3);
	result += ' ' + query_end;

	return result;
}

std::string gen_digest_value_group(uint32_t num_group_values, uint32_t grouping_limit, bool& group_compress) {
	std::string result { "(" };
	bool compressed = false;

	for (uint32_t i = 0; i < num_group_values - 1; i++) {
		if (grouping_limit != 0 && i >= grouping_limit && num_group_values - grouping_limit >= 2) {
			result += "...";
			compressed = true;
			break;
		} else {
			result += "?,";
		}
	}

	if (compressed == false) {
		result += "?)";
	} else {
		result += ")";
	}

	group_compress = compressed;

	return result;
}

/**
 * @brief Generates a random grouping query using the values supplied in the parameters.
 *
 * @param num_group_values The number of grouped values to be generated for the query digest.
 * @param grouping_limit Value grouping limit set for the query digest.
 * @param num_groups Number of groups of values to be generated for the query digest.
 * @param groups_grouping_limit Value of groups grouping limit set for the query digest.
 * @param query_start An arbitrary query start for insert at the beggining of the generated digest.
 * @param query_end An arbitrary query end to append to the end of the generated digest.
 *
 * @return The generated query digest.
 */
std::string gen_digest_grouping_query(
	uint32_t num_group_values, uint32_t grouping_limit, uint32_t num_groups,
	uint32_t groups_grouping_limit, const string& query_start, const string query_end
) {
	std::string result { query_start + ' '};
	bool compressed = false;
	bool groups_compressed = true;
	uint32_t i = 0;

	for (i = 0; i < num_groups - 1; i++) {
		if (grouping_limit != 0 && groups_grouping_limit != 0 && groups_compressed == true && i >= groups_grouping_limit) {
			result += "...";
			compressed = true;
			break;
		} else {
			result += gen_digest_value_group(num_group_values, grouping_limit, groups_compressed) + ",";
		}
	}

	if (compressed == false) {
		if (grouping_limit != 0 && groups_grouping_limit != 0 && groups_compressed == true && i >= groups_grouping_limit) {
			result += "...";
			compressed = true;
		} else {
			result += gen_digest_value_group(num_group_values, grouping_limit, groups_compressed);
		}
	}

	if (query_end.empty() == false) {
		result += ' ' + query_end;
	}

	return result;
}

using std::vector;
using std::tuple;
using std::string;

using failed_test_case = tuple<string,string,string,int,int>;

/**
 * @brief Generates random grouping queries and matches the result of the digests with the expected
 *   self-generated digests for the chosen values of:
 *     * 'mysql_thread___query_digests_grouping_limit'.
 *     * 'mysql_thread___query_digests_groups_grouping_limit'.
 *
 * @details It performs 'pow((pow(max_groups-1, 2) + max_groups-1)/2, 2)' comparsions between digests
 *   generated by 'mysql_query_digest_and_first_comment_2' and the self generated expected digests, modifying
 *   the values of:
 *     * 'mysql_thread___query_digests_grouping_limit'.
 *     * 'mysql_thread___query_digests_groups_grouping_limit'.
 *
 *   From '0' to 'max_groups' param value one each time.
 *
 * @param max_groups The maximum grouping number to be used for:
 *   * 'mysql_thread___query_digests_grouping_limit'.
 *   * 'mysql_thread___query_digests_groups_grouping_limit'.
 */
void process_grouping_tests(uint32_t max_groups) {
	char buf[QUERY_DIGEST_BUF];
	char* first_comment = NULL;

	int backup_grouping_limit = mysql_thread___query_digests_grouping_limit;
	int backup_groups_grouping_limit = mysql_thread___query_digests_groups_grouping_limit;
	vector<failed_test_case> failed_cases {};
	uint32_t max_query_size = 0;
	uint32_t max_digest_size = 0;

	for (int i = 1; i < max_groups; i++) {
		for (int j = 1; j < max_groups; j++) {
			for (int m = 1; m <= i; m++) {
				for (int n = 1; n <= j; n++) {
					mysql_thread___query_digests_grouping_limit = m;
					mysql_thread___query_digests_groups_grouping_limit = n;

					std::string query = gen_rnd_grouping_query(
						i, j, "INSERT INTO db.table (col1,col2,col3) VALUES", "ON DUPLICATE KEY UPDATE col1 = VALUES(col2)"
					);

					if (max_query_size < query.size()) {
						max_query_size = query.size();
					}

					std::string exp_result = gen_digest_grouping_query(
						i, m, j, n, "INSERT INTO db.table (col1,col2,col3) VALUES", "ON DUPLICATE KEY UPDATE col1 = VALUES(col2)"
					);

					char* c_query = (char*)malloc(query.size());
					memcpy(c_query, query.c_str(), query.size());

					char* c_res = mysql_query_digest_and_first_comment_2(c_query, query.size(), &first_comment,
							((query.size() < QUERY_DIGEST_BUF) ? buf : NULL));
					std::string parsing_res(c_res);

					if (max_digest_size < parsing_res.size()) {
						max_digest_size = parsing_res.size();
					}

					// ok(
					// 	parsing_res == exp_result,
					// 	"Grouping digest should be equal to exp result for parsing:\n"
					// 	" * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`,\n * Config: grouping_limit='%d', groups_grouping='%d'",
					// 	query.c_str(), parsing_res.c_str(), exp_result.c_str(), m, n
					// );

					if (parsing_res != exp_result) {
						failed_cases.push_back({query, parsing_res, exp_result, m, n});
					}

					if (query.size() >= QUERY_DIGEST_BUF) {
						free(c_res);
					}

					free(c_query);
				}
			}
		}
	}

	string ok_msg_t {
		"Grouping digest should be equal to exp result for parsing - Stats: max_gen_query_size='%d', max_digest_size='%d'"
	};
	string ok_msg {};
	string_format(ok_msg_t, ok_msg, max_query_size, max_digest_size);

	for (const auto& test_case : failed_cases) {
		string test_case_msg_t {
			"\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`,\n * Config: grouping_limit='%d', groups_grouping='%d',\n * \n"
		};
		string test_case_msg {};
		string_format(test_case_msg_t, test_case_msg, std::get<0>(test_case).c_str(), std::get<1>(test_case).c_str(),
			std::get<2>(test_case).c_str(), std::get<3>(test_case), std::get<4>(test_case));

		ok_msg += test_case_msg;
	}

	ok(failed_cases.empty() == true, "%s", ok_msg.c_str());

	mysql_thread___query_digests_grouping_limit = backup_grouping_limit;
	mysql_thread___query_digests_groups_grouping_limit = backup_groups_grouping_limit;
}

int MAX_GEN_QUERY_LENGTH = 1800;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	bool exec_crashing_tests = true;
	bool exec_grouping_tests = true;
	bool exec_regular_tests = true;
	std::string tests_filter_str {};

	// check parameters for test filtering
	if (argc == 2) {
		tests_filter_str = argv[1];

		if (tests_filter_str.find("crashing") == std::string::npos) {
			exec_crashing_tests = false;
		}
		if (tests_filter_str.find("grouping") == std::string::npos) {
			exec_grouping_tests = false;
		}
		if (tests_filter_str.find("regular") == std::string::npos) {
			exec_regular_tests = false;
		}
	}

	const string digests_filepath { string(cl.workdir) + DIGESTS_TEST_FILENAME };
	const string crashing_payloads { string(cl.workdir) + "tokenizer_payloads/crashing_payloads.hjson" };

	uint32_t max_groups = 10;

	uint32_t regular_tests_num = 0;
	uint32_t grouping_tests_num = (1800 - 300) / 50;
	uint32_t crashing_tests_num = 0;
	uint32_t tests_planned = 0;

	nlohmann::json regular_tests_defs {};
	nlohmann::json crashing_tests_defs {};

	try {
		regular_tests_defs = get_tests_defs(digests_filepath);
	} catch (const std::exception& ex) {
		diag("'get_tests_defs' failed at ('%s':'%d') with exception: '%s'", __FILE__, __LINE__, ex.what());
		return EXIT_FAILURE;
	}

	int count_defs_err = count_test_defs(regular_tests_defs, regular_tests_num);
	if (count_defs_err) {
		diag("'count_test_defs' failed at ('%s':'%d')", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	try {
		crashing_tests_defs = get_tests_defs(crashing_payloads);
	} catch (const std::exception& ex) {
		diag("'get_tests_defs' failed at ('%s':'%d') with exception: '%s'", __FILE__, __LINE__, ex.what());
		return EXIT_FAILURE;
	}

	crashing_tests_num = crashing_tests_defs.size();

	if (exec_regular_tests) { tests_planned += regular_tests_num; };
	if (exec_grouping_tests) { tests_planned += grouping_tests_num; };
	if (exec_crashing_tests) { tests_planned += crashing_tests_num; };

	plan(tests_planned);

	if (exec_regular_tests) {
		process_digest_tests(regular_tests_defs);
	}
	if (exec_crashing_tests) {
		process_crashing_tests(cl, crashing_tests_defs);
	}
	if (exec_grouping_tests) {
		for (uint32_t i = 300; i < MAX_GEN_QUERY_LENGTH; i += 50) {
			mysql_thread___query_digests_max_query_length=i;
			process_grouping_tests(max_groups);
		}
	}

	// Simple benchmarking for tracking impls overhead. TODO: Refactor and improve, or delete.
	/*
	{
		nlohmann::json tests_defs {};

		try {
			tests_defs = get_tests_defs(digests_filepath);
		} catch (const std::exception& ex) {
			diag("'get_tests_defs' failed at ('%s':'%d') with exception: '%s'", __FILE__, __LINE__, ex.what());
		}

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
