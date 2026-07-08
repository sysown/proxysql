/**
 * @file genai_stats_parsing_unit-t.cpp
 * @brief Unit tests for Stats_Tool_Handler parsing/helper functions.
 *
 * Tests pure parsing functions from lib/Stats_Tool_Handler.cpp:
 *   - parse_server_filter()  -- "host:port" parsing
 *   - parse_digest_filter()  -- hex/decimal digest parsing
 *   - parse_ll_or_zero()     -- null-safe string->int64
 *   - parse_int_or_zero()    -- null-safe string->int32
 *   - get_interval_config()  -- interval string->seconds mapping
 *   - calculate_percentile() -- histogram percentile estimation
 *
 * Built with all v4.0 plugins under PROXYSQL40=1 (auto-detected from libproxysql.a).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

#ifdef PROXYSQL40

#include "Stats_Tool_Handler.h"

using namespace stats_utils;

#include <climits>
#include <cstring>
#include <string>
#include <vector>

// ============================================================
// parse_server_filter() -- "host:port" parsing
// ============================================================

static void test_parse_server_filter_valid_ip() {
	std::string host, error;
	int port = 0;
	bool result = parse_server_filter("127.0.0.1:3306", host, port, error);
	ok(result == true, "parse_server_filter: valid IP:port accepted");
	ok(host == "127.0.0.1", "parse_server_filter: host extracted as '127.0.0.1'");
	ok(port == 3306, "parse_server_filter: port extracted as 3306");
}

static void test_parse_server_filter_hostname() {
	std::string host, error;
	int port = 0;
	bool result = parse_server_filter("db-primary.internal:5432", host, port, error);
	ok(result == true, "parse_server_filter: hostname:port accepted");
	ok(host == "db-primary.internal", "parse_server_filter: hostname extracted");
	ok(port == 5432, "parse_server_filter: port 5432 extracted");
}

static void test_parse_server_filter_ipv6() {
	// IPv6 addresses contain colons; rfind(':') should find the last one
	std::string host, error;
	int port = 0;
	bool result = parse_server_filter("::1:3306", host, port, error);
	ok(result == true, "parse_server_filter: IPv6-like address accepted");
	ok(host == "::1", "parse_server_filter: IPv6 host extracted");
	ok(port == 3306, "parse_server_filter: port from IPv6 address correct");
}

static void test_parse_server_filter_edge_ports() {
	std::string host, error;
	int port = 0;

	// Port 1 (minimum)
	bool result = parse_server_filter("host:1", host, port, error);
	ok(result == true, "parse_server_filter: port 1 accepted");
	ok(port == 1, "parse_server_filter: port 1 value correct");

	// Port 65535 (maximum)
	result = parse_server_filter("host:65535", host, port, error);
	ok(result == true, "parse_server_filter: port 65535 accepted");
	ok(port == 65535, "parse_server_filter: port 65535 value correct");
}

static void test_parse_server_filter_invalid() {
	std::string host, error;
	int port = 0;

	// Missing port
	bool result = parse_server_filter("no-port-here", host, port, error);
	ok(result == false, "parse_server_filter: missing port rejected");
	ok(!error.empty(), "parse_server_filter: error message set for missing port");

	// Empty host (colon at start)
	result = parse_server_filter(":3306", host, port, error);
	ok(result == false, "parse_server_filter: empty host rejected");

	// Empty port (colon at end)
	result = parse_server_filter("host:", host, port, error);
	ok(result == false, "parse_server_filter: empty port rejected");

	// Port > 65535
	result = parse_server_filter("host:99999", host, port, error);
	ok(result == false, "parse_server_filter: port > 65535 rejected");

	// Port 0
	result = parse_server_filter("host:0", host, port, error);
	ok(result == false, "parse_server_filter: port 0 rejected");

	// Non-numeric port
	result = parse_server_filter("host:abc", host, port, error);
	ok(result == false, "parse_server_filter: non-numeric port rejected");

	// Negative port
	result = parse_server_filter("host:-1", host, port, error);
	ok(result == false, "parse_server_filter: negative port rejected");
}

// ============================================================
// parse_digest_filter() -- hex/decimal digest parsing
// ============================================================

static void test_parse_digest_hex_with_prefix() {
	uint64_t digest = 0;
	std::string error;
	bool result = parse_digest_filter("0x1A2B3C", digest, error);
	ok(result == true, "parse_digest_filter: hex with 0x prefix accepted");
	ok(digest == 0x1A2B3C, "parse_digest_filter: hex value correct");
}

static void test_parse_digest_hex_without_prefix() {
	uint64_t digest = 0;
	std::string error;
	// "ABCDEF" is not valid decimal, so it should be retried as hex
	bool result = parse_digest_filter("ABCDEF", digest, error);
	ok(result == true, "parse_digest_filter: hex without 0x prefix accepted");
	ok(digest == 0xABCDEF, "parse_digest_filter: hex-without-prefix value correct");
}

static void test_parse_digest_decimal() {
	uint64_t digest = 0;
	std::string error;
	bool result = parse_digest_filter("12345", digest, error);
	ok(result == true, "parse_digest_filter: decimal accepted");
	ok(digest == 12345, "parse_digest_filter: decimal value correct");
}

static void test_parse_digest_zero() {
	uint64_t digest = 999;
	std::string error;
	bool result = parse_digest_filter("0", digest, error);
	ok(result == true, "parse_digest_filter: zero accepted");
	ok(digest == 0, "parse_digest_filter: zero value correct");
}

static void test_parse_digest_large() {
	uint64_t digest = 0;
	std::string error;
	// Max uint64: 18446744073709551615
	bool result = parse_digest_filter("0xFFFFFFFFFFFFFFFF", digest, error);
	ok(result == true, "parse_digest_filter: max uint64 hex accepted");
	ok(digest == 0xFFFFFFFFFFFFFFFFULL, "parse_digest_filter: max uint64 value correct");
}

static void test_parse_digest_invalid() {
	uint64_t digest = 0;
	std::string error;

	// Empty string
	bool result = parse_digest_filter("", digest, error);
	ok(result == false, "parse_digest_filter: empty string rejected");

	// Non-numeric, non-hex
	result = parse_digest_filter("not_a_number", digest, error);
	ok(result == false, "parse_digest_filter: non-numeric rejected");
}

// ============================================================
// parse_ll_or_zero() -- null-safe string->int64
// ============================================================

static void test_parse_ll_or_zero_basic() {
	ok(parse_ll_or_zero("42") == 42, "parse_ll_or_zero: '42' = 42");
	ok(parse_ll_or_zero("-1") == -1, "parse_ll_or_zero: '-1' = -1");
	ok(parse_ll_or_zero("0") == 0, "parse_ll_or_zero: '0' = 0");
	ok(parse_ll_or_zero("9999999999") == 9999999999LL, "parse_ll_or_zero: large value correct");
}

static void test_parse_ll_or_zero_null_empty() {
	ok(parse_ll_or_zero(nullptr) == 0, "parse_ll_or_zero: nullptr = 0");
	ok(parse_ll_or_zero("") == 0, "parse_ll_or_zero: empty string = 0");
}

static void test_parse_ll_or_zero_invalid() {
	// Non-numeric strings should return 0
	ok(parse_ll_or_zero("abc") == 0, "parse_ll_or_zero: 'abc' = 0");
	ok(parse_ll_or_zero("12abc") == 0, "parse_ll_or_zero: '12abc' = 0 (trailing garbage)");
}

// ============================================================
// parse_int_or_zero() -- null-safe string->int32
// ============================================================

static void test_parse_int_or_zero_basic() {
	ok(parse_int_or_zero("42") == 42, "parse_int_or_zero: '42' = 42");
	ok(parse_int_or_zero(nullptr) == 0, "parse_int_or_zero: nullptr = 0");
	ok(parse_int_or_zero("") == 0, "parse_int_or_zero: empty = 0");
	ok(parse_int_or_zero("-100") == -100, "parse_int_or_zero: '-100' = -100");
}

static void test_parse_int_or_zero_overflow() {
	// Value exceeding INT_MAX should clamp to INT_MAX
	char buf[32];
	snprintf(buf, sizeof(buf), "%lld", (long long)INT_MAX + 1);
	ok(parse_int_or_zero(buf) == INT_MAX, "parse_int_or_zero: overflow clamps to INT_MAX");

	// Value below INT_MIN should clamp to INT_MIN
	snprintf(buf, sizeof(buf), "%lld", (long long)INT_MIN - 1);
	ok(parse_int_or_zero(buf) == INT_MIN, "parse_int_or_zero: underflow clamps to INT_MIN");
}

// ============================================================
// Stats_Tool_Handler::get_interval_config()
// ============================================================

static void test_interval_config_valid() {
	Stats_Tool_Handler handler(nullptr);
	int seconds = 0;
	bool use_hourly = false;

	// Short intervals use raw tables (use_hourly = false)
	bool result = handler.get_interval_config("30m", seconds, use_hourly);
	ok(result == true, "get_interval_config: '30m' accepted");
	ok(seconds == 1800, "get_interval_config: 30m = 1800 seconds");
	ok(use_hourly == false, "get_interval_config: 30m uses raw tables");

	result = handler.get_interval_config("1h", seconds, use_hourly);
	ok(result == true, "get_interval_config: '1h' accepted");
	ok(seconds == 3600, "get_interval_config: 1h = 3600 seconds");
	ok(use_hourly == false, "get_interval_config: 1h uses raw tables");

	result = handler.get_interval_config("6h", seconds, use_hourly);
	ok(result == true, "get_interval_config: '6h' accepted");
	ok(seconds == 21600, "get_interval_config: 6h = 21600 seconds");
	ok(use_hourly == false, "get_interval_config: 6h uses raw tables");

	// Longer intervals use hourly aggregated tables (use_hourly = true)
	result = handler.get_interval_config("8h", seconds, use_hourly);
	ok(result == true, "get_interval_config: '8h' accepted");
	ok(seconds == 28800, "get_interval_config: 8h = 28800 seconds");
	ok(use_hourly == true, "get_interval_config: 8h uses hourly tables");

	result = handler.get_interval_config("1d", seconds, use_hourly);
	ok(result == true, "get_interval_config: '1d' accepted");
	ok(seconds == 86400, "get_interval_config: 1d = 86400 seconds");
	ok(use_hourly == true, "get_interval_config: 1d uses hourly tables");

	result = handler.get_interval_config("90d", seconds, use_hourly);
	ok(result == true, "get_interval_config: '90d' accepted");
	ok(seconds == 7776000, "get_interval_config: 90d = 7776000 seconds");
	ok(use_hourly == true, "get_interval_config: 90d uses hourly tables");
}

static void test_interval_config_invalid() {
	Stats_Tool_Handler handler(nullptr);
	int seconds = 0;
	bool use_hourly = false;

	bool result = handler.get_interval_config("invalid", seconds, use_hourly);
	ok(result == false, "get_interval_config: 'invalid' rejected");

	result = handler.get_interval_config("", seconds, use_hourly);
	ok(result == false, "get_interval_config: empty string rejected");

	result = handler.get_interval_config("5h", seconds, use_hourly);
	ok(result == false, "get_interval_config: '5h' (not in map) rejected");
}

// ============================================================
// Stats_Tool_Handler::calculate_percentile()
// ============================================================

static void test_percentile_empty() {
	Stats_Tool_Handler handler(nullptr);
	std::vector<int> empty_buckets;
	std::vector<int> empty_thresholds;
	std::vector<int> thresholds = {100, 500, 1000};

	ok(handler.calculate_percentile(empty_buckets, thresholds, 0.5) == 0,
		"calculate_percentile: empty buckets returns 0");
	ok(handler.calculate_percentile({1, 2, 3}, empty_thresholds, 0.5) == 0,
		"calculate_percentile: empty thresholds returns 0");
}

static void test_percentile_single_bucket() {
	Stats_Tool_Handler handler(nullptr);
	std::vector<int> buckets = {100};
	std::vector<int> thresholds = {500};

	int p50 = handler.calculate_percentile(buckets, thresholds, 0.5);
	ok(p50 == 500, "calculate_percentile: single bucket p50 = threshold");

	int p99 = handler.calculate_percentile(buckets, thresholds, 0.99);
	ok(p99 == 500, "calculate_percentile: single bucket p99 = threshold");
}

static void test_percentile_typical_histogram() {
	Stats_Tool_Handler handler(nullptr);
	// Simulated latency histogram: most queries fast, few slow
	std::vector<int> buckets    = {1000, 500, 200, 50, 10, 5,  2,  1};
	std::vector<int> thresholds = {100,  500, 1000, 5000, 10000, 50000, 100000, 500000};

	// p0 should return first non-empty bucket threshold
	int p0 = handler.calculate_percentile(buckets, thresholds, 0.0);
	ok(p0 == 100, "calculate_percentile: p0 returns first non-empty bucket (100us)");

	// p50 should be in the first bucket (1000 out of 1768 total)
	int p50 = handler.calculate_percentile(buckets, thresholds, 0.5);
	ok(p50 == 100, "calculate_percentile: p50 in first bucket (most queries fast)");

	// p99 should be in a later bucket
	int p99 = handler.calculate_percentile(buckets, thresholds, 0.99);
	ok(p99 > 100, "calculate_percentile: p99 in a later bucket than p50");
}

static void test_percentile_all_zeros() {
	Stats_Tool_Handler handler(nullptr);
	std::vector<int> buckets    = {0, 0, 0, 0};
	std::vector<int> thresholds = {100, 500, 1000, 5000};

	int result = handler.calculate_percentile(buckets, thresholds, 0.5);
	ok(result == 0, "calculate_percentile: all-zero buckets returns 0");
}

static void test_percentile_clamping() {
	Stats_Tool_Handler handler(nullptr);
	std::vector<int> buckets    = {10, 10};
	std::vector<int> thresholds = {100, 500};

	// Percentile < 0 should clamp to 0
	int p_neg = handler.calculate_percentile(buckets, thresholds, -1.0);
	ok(p_neg == 100, "calculate_percentile: negative percentile clamped to p0");

	// Percentile > 1 should clamp to 1
	int p_over = handler.calculate_percentile(buckets, thresholds, 2.0);
	ok(p_over == 500, "calculate_percentile: percentile > 1 clamped to p100");
}

static void test_percentile_p100() {
	Stats_Tool_Handler handler(nullptr);
	std::vector<int> buckets    = {5, 5, 5};
	std::vector<int> thresholds = {100, 500, 1000};

	int p100 = handler.calculate_percentile(buckets, thresholds, 1.0);
	ok(p100 == 1000, "calculate_percentile: p100 returns last bucket threshold");
}

#endif /* PROXYSQL40 */

int main() {
#ifdef PROXYSQL40
	plan(79);
	test_init_minimal();

	// parse_server_filter tests (17)
	test_parse_server_filter_valid_ip();       // 3
	test_parse_server_filter_hostname();       // 3
	test_parse_server_filter_ipv6();           // 3
	test_parse_server_filter_edge_ports();     // 4
	test_parse_server_filter_invalid();        // 8

	// parse_digest_filter tests (12)
	test_parse_digest_hex_with_prefix();       // 2
	test_parse_digest_hex_without_prefix();    // 2
	test_parse_digest_decimal();               // 2
	test_parse_digest_zero();                  // 2
	test_parse_digest_large();                 // 2
	test_parse_digest_invalid();               // 2

	// parse_ll_or_zero tests (8)
	test_parse_ll_or_zero_basic();             // 4
	test_parse_ll_or_zero_null_empty();        // 2
	test_parse_ll_or_zero_invalid();           // 2

	// parse_int_or_zero tests (6)
	test_parse_int_or_zero_basic();            // 4
	test_parse_int_or_zero_overflow();         // 2

	// get_interval_config tests (21)
	test_interval_config_valid();              // 18
	test_interval_config_invalid();            // 3

	// calculate_percentile tests (9)
	test_percentile_empty();                   // 2
	test_percentile_single_bucket();           // 2
	test_percentile_typical_histogram();       // 3
	test_percentile_all_zeros();               // 1
	test_percentile_clamping();                // 2
	test_percentile_p100();                    // 1

	// Note: not calling test_cleanup_minimal() before exit_status()
	// because Stats_Tool_Handler destructor needs proxy_debug which
	// requires GloVars to still be alive.
	test_cleanup_minimal();
	return exit_status();
#else
	plan(1);
	ok(1, "SKIP: GenAI not enabled in libproxysql.a");
	return exit_status();
#endif
}
