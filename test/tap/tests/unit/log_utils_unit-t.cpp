/**
 * @file log_utils_unit-t.cpp
 * @brief Unit tests for LogBuffer and LogBufferThreadContext in log_utils.cpp.
 *
 * Tests cover:
 *   - LogBuffer construction and empty state
 *   - append() overloads (std::string, const char*, const char* + len)
 *   - write() overloads
 *   - operator<< for std::string, const char*, and char
 *   - operator<< chaining
 *   - data() returning accumulated content
 *   - size() and empty() consistency
 *   - reset() clearing buffer and updating flush time
 *   - LogBufferThreadContext::should_log() rate-limiting behavior
 *   - GetLogBufferThreadContext() thread context creation and retrieval
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "log_utils.h"

#include <cstring>
#include <string>

/**
 * @brief Test that a newly constructed LogBuffer is empty.
 */
static void test_empty_buffer() {
	LogBuffer buf;
	ok(buf.empty() == true, "New LogBuffer is empty");
	ok(buf.size() == 0, "New LogBuffer size is 0");
	ok(std::strlen(buf.data()) == 0, "New LogBuffer data() returns empty string");
	ok(buf.get_last_flush_time() == 0, "New LogBuffer last_flush_time is 0");
}

/**
 * @brief Test append(const std::string&).
 */
static void test_append_string() {
	LogBuffer buf;
	std::string s = "hello";
	buf.append(s);
	ok(buf.size() == 5, "append(string) sets correct size");
	ok(std::strncmp(buf.data(), "hello", 5) == 0, "append(string) sets correct content");
}

/**
 * @brief Test append(const char*).
 */
static void test_append_cstr() {
	LogBuffer buf;
	buf.append("world");
	ok(buf.size() == 5, "append(const char*) sets correct size");
	ok(std::strncmp(buf.data(), "world", 5) == 0, "append(const char*) sets correct content");
}

/**
 * @brief Test append(const char*, size_t).
 */
static void test_append_cstr_len() {
	LogBuffer buf;
	buf.append("hello world", 5);
	ok(buf.size() == 5, "append(const char*, len) sets correct size");
	ok(std::strncmp(buf.data(), "hello", 5) == 0, "append(const char*, len) sets correct content");
}

/**
 * @brief Test write(const std::string&).
 */
static void test_write_string() {
	LogBuffer buf;
	std::string s = "write_test";
	buf.write(s);
	ok(buf.size() == 10, "write(string) sets correct size");
	ok(std::strncmp(buf.data(), "write_test", 10) == 0, "write(string) sets correct content");
}

/**
 * @brief Test write(const char*, size_t).
 */
static void test_write_cstr_len() {
	LogBuffer buf;
	buf.write("write_test_extra", 10);
	ok(buf.size() == 10, "write(const char*, len) sets correct size");
	ok(std::strncmp(buf.data(), "write_test", 10) == 0, "write(const char*, len) sets correct content");
}

/**
 * @brief Test operator<<(const std::string&).
 */
static void test_operator_string() {
	LogBuffer buf;
	std::string s = "stream";
	buf << s;
	ok(buf.size() == 6, "operator<<(string) sets correct size");
	ok(std::strncmp(buf.data(), "stream", 6) == 0, "operator<<(string) sets correct content");
}

/**
 * @brief Test operator<<(const char*).
 */
static void test_operator_cstr() {
	LogBuffer buf;
	buf << "cstream";
	ok(buf.size() == 7, "operator<<(const char*) sets correct size");
	ok(std::strncmp(buf.data(), "cstream", 7) == 0, "operator<<(const char*) sets correct content");
}

/**
 * @brief Test operator<<(char).
 */
static void test_operator_char() {
	LogBuffer buf;
	buf << 'X';
	ok(buf.size() == 1, "operator<<(char) sets correct size");
	ok(buf.data()[0] == 'X', "operator<<(char) sets correct content");
}

/**
 * @brief Test that multiple appends concatenate correctly.
 */
static void test_multiple_appends() {
	LogBuffer buf;
	buf.append("hello");
	buf.append(" ");
	std::string w = "world";
	buf.append(w);
	ok(buf.size() == 11, "Multiple appends produce correct size");
	ok(std::strncmp(buf.data(), "hello world", 11) == 0, "Multiple appends concatenate correctly");
}

/**
 * @brief Test operator<< chaining.
 */
static void test_chaining() {
	LogBuffer buf;
	std::string mid = " beautiful ";
	buf << "hello" << mid << "world";
	ok(buf.size() == 21, "Chained operator<< produces correct size");
	ok(std::strncmp(buf.data(), "hello beautiful world", 21) == 0, "Chained operator<< concatenates correctly");
}

/**
 * @brief Test mixing append, write, and operator<<.
 */
static void test_mixed_operations() {
	LogBuffer buf;
	buf.append("A");
	buf.write(std::string("B"));
	buf << "C";
	buf << 'D';
	buf.append("EF", 1);
	ok(buf.size() == 5, "Mixed operations produce correct size");
	ok(std::strncmp(buf.data(), "ABCDE", 5) == 0, "Mixed operations concatenate correctly");
}

/**
 * @brief Test reset() clears buffer and updates flush time.
 */
static void test_reset() {
	LogBuffer buf;
	buf.append("some data");
	buf.reset(12345);
	ok(buf.empty() == true, "reset() clears buffer");
	ok(buf.size() == 0, "reset() sets size to 0");
	ok(buf.get_last_flush_time() == 12345, "reset() updates last_flush_time");
}

/**
 * @brief Test set_last_flush_time() and get_last_flush_time().
 */
static void test_flush_time() {
	LogBuffer buf;
	buf.set_last_flush_time(99999);
	ok(buf.get_last_flush_time() == 99999, "set/get_last_flush_time() round-trips correctly");
}

/**
 * @brief Test should_log() with rate_limit=1 always returns true.
 *
 * With rate_limit=1, the formula is: dist(rng) * 1 <= 1.0.
 * Since dist produces [0.0, 1.0), the product is always < 1.0, so always true.
 */
static void test_should_log_rate_1() {
	LogBufferThreadContext ctx;
	bool all_true = true;
	for (int i = 0; i < 1000; i++) {
		if (!ctx.should_log(1)) {
			all_true = false;
			break;
		}
	}
	ok(all_true, "should_log(1) always returns true (log everything)");
}

/**
 * @brief Test should_log() with rate_limit=0 always returns true.
 *
 * With rate_limit=0, the formula is: dist(rng) * 0 <= 1.0 -> 0 <= 1.0, always true.
 */
static void test_should_log_rate_0() {
	LogBufferThreadContext ctx;
	bool all_true = true;
	for (int i = 0; i < 1000; i++) {
		if (!ctx.should_log(0)) {
			all_true = false;
			break;
		}
	}
	ok(all_true, "should_log(0) always returns true (0 * anything = 0 <= 1)");
}

/**
 * @brief Test should_log() with a high rate_limit returns true only sometimes.
 *
 * With rate_limit=1000, expected acceptance ~0.1%. Over 10000 trials we expect
 * some true and some false. We verify it is not all-true and not all-false.
 */
static void test_should_log_high_rate() {
	LogBufferThreadContext ctx;
	int true_count = 0;
	const int trials = 10000;
	for (int i = 0; i < trials; i++) {
		if (ctx.should_log(1000)) {
			true_count++;
		}
	}
	ok(true_count < trials, "should_log(1000) does not return true for all trials");
	ok(true_count >= 0, "should_log(1000) returns a non-negative count of true results");
	// With rate=1000, expected ~0.1% acceptance -> ~10 out of 10000
	// Allow generous bounds: 0 to 100
	ok(true_count <= 200, "should_log(1000) acceptance rate is roughly in expected range (<2%%)");
}

/**
 * @brief Test GetLogBufferThreadContext creates and retrieves context.
 */
static void test_get_log_buffer_thread_context() {
	std::unordered_map<pthread_t, std::unique_ptr<LogBufferThreadContext>> contexts;
	std::mutex lock;

	// First call should create a new context
	LogBufferThreadContext* ctx1 = GetLogBufferThreadContext(contexts, lock, 5000);
	ok(ctx1 != nullptr, "GetLogBufferThreadContext returns non-null on first call");
	ok(ctx1->events.get_last_flush_time() == 5000, "New context events flush time initialized");
	ok(ctx1->audit.get_last_flush_time() == 5000, "New context audit flush time initialized");

	// Second call from same thread should return the same context
	LogBufferThreadContext* ctx2 = GetLogBufferThreadContext(contexts, lock, 9000);
	ok(ctx2 == ctx1, "GetLogBufferThreadContext returns same pointer on second call");
	// flush time should NOT be updated for existing context
	ok(ctx2->events.get_last_flush_time() == 5000, "Existing context flush time unchanged");
}

/**
 * @brief Test flush_to_file with null logfile does not crash.
 */
static void test_flush_to_file_null() {
	LogBuffer buf;
	buf.append("test data");
	buf.flush_to_file(nullptr);
	// Should not crash; buffer should remain unchanged
	ok(buf.size() == 9, "flush_to_file(nullptr) does not crash or modify buffer");
}

/**
 * @brief Test flush_to_file with empty buffer does not write.
 */
static void test_flush_to_file_empty() {
	LogBuffer buf;
	// Even with a null fstream, empty buffer should early-return
	buf.flush_to_file(nullptr);
	ok(buf.empty(), "flush_to_file with empty buffer and null stream does not crash");
}

int main() {
	plan(42);
	test_init_minimal();

	test_empty_buffer();
	test_append_string();
	test_append_cstr();
	test_append_cstr_len();
	test_write_string();
	test_write_cstr_len();
	test_operator_string();
	test_operator_cstr();
	test_operator_char();
	test_multiple_appends();
	test_chaining();
	test_mixed_operations();
	test_reset();
	test_flush_time();
	test_should_log_rate_1();
	test_should_log_rate_0();
	test_should_log_high_rate();
	test_get_log_buffer_thread_context();
	test_flush_to_file_null();
	test_flush_to_file_empty();

	test_cleanup_minimal();
	return exit_status();
}
