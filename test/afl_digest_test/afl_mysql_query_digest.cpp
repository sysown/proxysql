#pragma GCC            optimize("O0")
#define QUERY_DIGEST_BUF 128

#include "c_tokenizer.h"
#include "proxysql_utils.h"
#include "ezOptionParser.hpp"

#include <cstddef>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>

#include <string>
#include <iostream>

__thread int mysql_thread___query_digests_max_query_length = 65000;
__thread bool mysql_thread___query_digests_lowercase = false;
__thread bool mysql_thread___query_digests_replace_null = true;
__thread bool mysql_thread___query_digests_no_digits = false;
__thread int mysql_thread___query_digests_grouping_limit = 3;
__thread int mysql_thread___query_digests_groups_grouping_limit = 1;
__thread int mysql_thread___query_digests_keep_comment = 0;

using std::string;
using option_err = std::pair<int, string>;

option_err check_and_set_option(ez::ezOptionParser& opts, string opt_id, int* config_option_val) {
	option_err err_res { EXIT_SUCCESS, "" };

	if (opts.isSet(opt_id)) {
		string s_option_val {};
		char* str_end = NULL;

		opts.get(opt_id.c_str())->getString(s_option_val);
		int option_val = std::strtoll(s_option_val.c_str(), &str_end, 10);

		if (errno != ERANGE) {
			*config_option_val = option_val;
		} else {
			string t_invalid_value_msg { "Invalid '%s' supplied" };
			string invalid_value_msg {};
			string_format(t_invalid_value_msg, invalid_value_msg, opt_id.c_str());

			string t_err_msg { "File %s, line %d, Error: %s" };
			string err_msg {};
			string_format(t_err_msg, err_msg, __FILE__, __LINE__, invalid_value_msg.c_str());

			err_res = { EXIT_FAILURE, err_msg };
		}
	}

	return err_res;
}

void print_invalid_input_error(const option_err& err) {
	std::cout << "InvalidInputError: " << err.second << "\n";
}

option_err parse_parameter_options(int argc, const char** argv) {
	option_err err_res { EXIT_SUCCESS, "" };

	ez::ezOptionParser opts {};
	opts.overview = "AFL fuzz testing for digest parsing";
	opts.syntax = "afl_test [OPTIONS]";
	opts.footer = "\n\nHappy bug hunting :)";

	opts.add(
		(const char *)"", 0, 0, 0, (const char *)"Display usage instructions.",
		(const char *)"-h", (const char *)"-help", (const char *)"--help", (const char *)"--usage"
	);
	opts.add(
		(const char *)"", 1, 1, 0, (const char *)"Query digest 'MaxLength'",
		(const char *)"-s", (const char *)"--digest-size"
	);
	opts.add(
		(const char *)"", 1, 1, 0, (const char *)"Query digest 'LowerCase'",
		(const char *)"-l", (const char *)"--lowercase"
	);
	opts.add(
		(const char *)"", 1, 1, 0, (const char *)"Query digest 'ReplaceNULL'",
		(const char *)"-n", (const char *)"--replace-null"
	);
	opts.add(
		(const char *)"", 1, 1, 0, (const char *)"Query digest 'NoDigits'",
		(const char *)"-d", (const char *)"--replace-digits"
	);
	opts.add(
		(const char *)"", 1, 1, 0, (const char *)"Query digest 'GroupingLimit'",
		(const char *)"-g", (const char *)"--grouping-limit"
	);
	opts.add(
		(const char *)"", 1, 1, 0, (const char *)"Query digest 'GroupsGroupingLimit'",
		(const char *)"-G", (const char *)"--groups-grouping-limit"
	);
	opts.add(
		(const char *)"", 1, 1, 0, (const char *)"Query digest 'KeepComment'",
		(const char *)"-c", (const char *)"--keep-comment"
	);

	// parse the arguments
	opts.parse(argc, argv);

	// extract command line options
	if (opts.isSet("-h")) {
		std::string usage {};
		opts.getUsage(usage);
		std::cout << usage << std::endl;

		exit(EXIT_SUCCESS);
	}

	int option_value = 0;

	err_res = check_and_set_option(opts, "-s", &option_value);
	if (err_res.first != EXIT_SUCCESS) {
		return err_res;
	} else {
		mysql_thread___query_digests_max_query_length = option_value;
	}
	err_res = check_and_set_option(opts, "-l", &option_value);
	if (err_res.first != EXIT_SUCCESS) {
		return err_res;
	} else {
		mysql_thread___query_digests_lowercase = option_value;
	}
	err_res = check_and_set_option(opts, "-n", &option_value);
	if (err_res.first != EXIT_SUCCESS) {
		return err_res;
	} else {
		mysql_thread___query_digests_replace_null = option_value;
	}
	err_res = check_and_set_option(opts, "-d", &option_value);
	if (err_res.first != EXIT_SUCCESS) {
		return err_res;
	} else {
		mysql_thread___query_digests_no_digits = option_value;
	}
	err_res = check_and_set_option(opts, "-g", &option_value);
	if (err_res.first != EXIT_SUCCESS) {
		return err_res;
	} else {
		mysql_thread___query_digests_grouping_limit = option_value;
	}
	err_res = check_and_set_option(opts, "-G", &option_value);
	if (err_res.first != EXIT_SUCCESS) {
		return err_res;
	} else {
		mysql_thread___query_digests_groups_grouping_limit = option_value;
	}
	err_res = check_and_set_option(opts, "-c", &option_value);
	if (err_res.first != EXIT_SUCCESS) {
		return err_res;
	} else {
		mysql_thread___query_digests_keep_comment = option_value;
	}

	return err_res;
}

void process_digest_test(unsigned char* query, int len) {
	char buf[QUERY_DIGEST_BUF];
	char* first_comment = NULL;
	mysql_query_digest_and_first_comment_2(query, len, &first_comment, ((len < QUERY_DIGEST_BUF) ? buf : NULL));
}

__AFL_FUZZ_INIT();

int main(int argc, const char** argv) {
	option_err opt_err = parse_parameter_options(argc, argv);
	if (opt_err.first != EXIT_SUCCESS) {
		std::cout << "InvalidSuppliedOption: " << opt_err.second << "\n";
		return EXIT_FAILURE;
	}

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif

	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF; 
	fflush(stdin);

	while (__AFL_LOOP(10000)) {
		int len = __AFL_FUZZ_TESTCASE_LEN;

		unsigned char* alloc_buff = static_cast<unsigned char*>(malloc(len));
		memcpy(alloc_buff, buf, len);

		process_digest_test(alloc_buff, len);
	}

	return 0;
}
