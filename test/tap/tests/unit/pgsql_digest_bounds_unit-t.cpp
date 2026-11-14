/**
 * @file pgsql_digest_bounds_unit-t.cpp
 * @brief Regression tests for empty compression ranges and bounded digest restarts (#6595).
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

#include <cstring>
#include <string>

// Exercise the production stage helpers without adding a test API to the tokenizer.
#include "../../../../lib/pgsql_tokenizer.cpp"

/** @brief Detect invalid pointer comparisons as well as memory accesses in this ASan fixture. */
extern "C" const char* __asan_default_options() {
	return "detect_invalid_pointer_pairs=2";
}

/** @brief Empty and unfinished-number ranges must not manufacture a preceding character. */
static void test_digest_end() {
	char buffer[64] = {};
	pgsql_shared_st shared = {};
	pgsql_stage_1_st first = {};
	shared.res_init_pos = buffer;
	shared.res_cur_pos = buffer;
	ok(get_stage_digest_end(&shared, &first) == nullptr, "empty result has no last complete character");
	shared.st = st_literal_number;
	shared.res_cur_pos = buffer + 4;
	first.literal_dig_st.start_pos = buffer;
	first.new_end_pos = buffer + 4;
	ok(get_stage_digest_end(&shared, &first) == nullptr, "unfinished leading number has no compression prefix");
	first.literal_dig_st.start_pos = buffer + 2;
	ok(get_stage_digest_end(&shared, &first) == buffer + 1, "complete prefix ends immediately before the unfinished number");
	shared.st = st_no_mark_found;
	ok(get_stage_digest_end(&shared, &first) == buffer + 3, "complete result ends before its write position");
	shared.res_cur_pos = buffer + 1;
	ok(get_stage_digest_end(&shared, &first) == buffer, "one complete character is a valid compression range");
}

/** @brief Restarts outside the completed range must fall back before any pointer is formed. */
static void test_restart_positions() {
	char buffer[64] = {};
	pgsql_shared_st shared = {};
	shared.res_init_pos = buffer;
	shared.res_it_init_pos = buffer + 1;
	struct RestartCase { int previous; int lookback; int expected; };
	const RestartCase cases[] = {
		{-1, 6, 0}, {20, 6, 14}, {3, 6, 0}, {16, 16, 0},
		{31, 0, 0}, {32, 0, 0}, {3, -2, 5}, {0, 0, 0}
	};
	for (const auto& c : cases) {
		char* previous = c.previous < 0 ? nullptr : buffer + c.previous;
		set_stage_next_start_pos(&shared, buffer + 31, previous, c.lookback);
		ok(shared.res_cur_pos == buffer + c.expected && shared.res_pre_pos == buffer + c.expected,
			"restart previous=%d lookback=%d selects offset %d", c.previous, c.lookback, c.expected);
	}
	shared.res_it_init_pos = buffer;
	set_stage_next_start_pos(&shared, buffer + 31, buffer + 20, 6);
	ok(shared.res_cur_pos == buffer && shared.res_pre_pos == buffer, "first iteration starts at the result beginning");
	shared.res_it_init_pos = buffer + 1;
	set_stage_next_start_pos(&shared, nullptr, buffer + 20, 6);
	ok(shared.res_cur_pos == buffer && shared.res_pre_pos == buffer, "empty compression range restarts at the beginning");
}

/** @brief All compression stages must preserve an unfinished leading number and accept empty results. */
static void test_empty_compression_ranges() {
	for (bool number : {false, true}) {
		char buffer[16] = {};
		if (number) strcpy(buffer, "1234");
		pgsql_shared_st shared = {};
		shared.res_init_pos = shared.res_it_init_pos = buffer;
		shared.res_cur_pos = shared.res_pre_pos = buffer + (number ? 4 : 0);
		shared.st = number ? st_literal_number : st_no_mark_found;
		pgsql_stage_1_st first = {};
		if (number) {
			first.literal_dig_st.start_pos = buffer;
			first.new_end_pos = buffer + 4;
		}
		options opts = {true, true, true, false, 1, 2, 4};
		auto check = [&](auto stage, auto parse, int n) {
			stage.c_offset = 99;
			parse(&shared, &first, &stage, &opts);
			ok(shared.res_cur_pos == buffer + (number ? 4 : 0) &&
				strcmp(buffer, number ? "1234" : "") == 0 &&
				stage.c_offset == 0 && stage.pre_it_pos == buffer,
				"stage %d preserves %s without compression", n, number ? "unfinished leading digits" : "an empty result");
		};
		check(pgsql_stage_2_st{}, stage_2_parsing, 2);
		check(pgsql_stage_3_st{}, stage_3_parsing, 3);
		check(pgsql_stage_4_st{}, stage_4_parsing, 4);
	}
}

/** @brief Every compression stage must clamp a restart whose lookback exceeds its saved prefix. */
static void test_compression_restarts() {
	options opts = {true, true, true, false, 1, 2, 64};
	auto check = [&](auto stage, auto parse, int n, const char* expected) {
		char buffer[64] = "(?,?,?)";
		pgsql_shared_st shared = {};
		shared.res_init_pos = buffer;
		shared.res_it_init_pos = buffer + 1;
		shared.res_cur_pos = shared.res_pre_pos = buffer + 7;
		pgsql_stage_1_st first = {};
		stage.pre_it_pos = buffer + 1;
		parse(&shared, &first, &stage, &opts);
		ok(strcmp(buffer, expected) == 0 && shared.res_cur_pos == buffer + strlen(expected),
			"stage %d clamps an oversized restart lookback and preserves its digest (got '%s')", n, buffer);
	};
	check(pgsql_stage_2_st{}, stage_2_parsing, 2, "(?,?,?)");
	check(pgsql_stage_3_st{}, stage_3_parsing, 3, "(?,...)");
	check(pgsql_stage_4_st{}, stage_4_parsing, 4, "(?,?,?)");
}

/** @brief Verify small-buffer results and group compression through the public digest entry point. */
static void test_small_buffer_digests() {
	struct DigestCase { const char* query; const char* expected; };
	const DigestCase cases[] = {
		{"", ""}, {"/* comment */", ""}, {"12345678901234567890", "?"},
		{" 12345678901234567890", "?"}, {"1e+12345678901234567890", "?"},
		{"SELECT 12345678901234567890", "select ?"}
	};
	options opts = {true, true, true, false, 1, 2, 8};
	for (const auto& c : cases) {
		char* comment = nullptr;
		char* digest = pgsql_query_digest_and_first_comment(c.query, strlen(c.query), &comment, nullptr, &opts);
		ok(strcmp(digest, c.expected) == 0, "small-buffer digest of '%s' is '%s' (got '%s')", c.query, c.expected, digest);
		free(comment);
		free(digest);
	}
	const std::string query = "SELECT (1,2,3),(4,5,6),(7,8,9)";
	for (int limit : {32, 64}) {
		opts.max_query_length = limit;
		char* comment = nullptr;
		char* digest = pgsql_query_digest_and_first_comment(query.c_str(), query.size(), &comment, nullptr, &opts);
		ok(strcmp(digest, "select (?,...),(?,...),...") == 0,
			"complete groups collapse with digest limit %d (got '%s')", limit, digest);
		free(comment);
		free(digest);
	}
}

/** @brief Run the digest boundary regressions with the standard unit-test harness. */
int main() {
	plan(32);
	if (test_init_minimal() != 0) return EXIT_FAILURE;
	test_digest_end();
	test_restart_positions();
	test_empty_compression_ranges();
	test_compression_restarts();
	test_small_buffer_digests();
	test_cleanup_minimal();
	return exit_status();
}
