/**
 * @file trxid_interval_unit-t.cpp
 * @brief Unit tests for TrxId_Interval.
 *
 * Tests the pure data-structure operations in lib/proxysql_gtid.cpp:
 *   - TrxId_Interval constructors   — from range, single, C string, C++ string
 *   - contains()                    — membership checks for trxid and interval
 *   - to_string()                   — serialization to "start-end" or "n" format
 *   - append()                      — extend interval at end
 *   - merge()                       — merge two overlapping/adjacent intervals
 *   - cmp() and comparison operators
 *
 */

#include "tap.h"

#include "proxysql_gtid.h"

/**
 * @brief Construct from (start, end) in normal and reversed order.
 *
 * Verifies that reversed arguments are swapped so start <= end.
 */
static void test_construct_from_range() {
	TrxId_Interval iv(123, 456);
	ok(iv.start == 123 && iv.end == 456, "construct from (start, end): normal order");

	TrxId_Interval iv_rev(456, 123);
	ok(iv_rev.start == 123 && iv_rev.end == 456, "construct from (start, end): reversed order swaps");
}

/**
 * @brief Construct from a single trxid_t value.
 *
 * Produces a degenerate interval [n,n].
 */
static void test_construct_from_single() {
	TrxId_Interval iv(42);
	ok(iv.start == 42 && iv.end == 42, "construct from single trxid: [42,42]");
}

/**
 * @brief Construct from string literal in "start-end" and "n" formats.
 */
static void test_construct_from_string_literal() {
	TrxId_Interval iv_range("123-456");
	ok(iv_range.start == 123 && iv_range.end == 456, "construct from string literal range: 123-456");

	TrxId_Interval iv_single("111");
	ok(iv_single.start == 111 && iv_single.end == 111, "construct from string literal single: 111");
}

/**
 * @brief Construct from std::string in "start-end" and "n" formats.
 */
static void test_construct_from_string() {
	TrxId_Interval iv_range(std::string("789-1234"));
	ok(iv_range.start == 789 && iv_range.end == 1234, "construct from C++ string range: 789-1234");

	TrxId_Interval iv_single(std::string("222"));
	ok(iv_single.start == 222 && iv_single.end == 222, "construct from C++ string single: 222");
}

/**
 * @brief Construct from negative values.
 */
static void test_construct_negative() {
	TrxId_Interval iv(-10, -5);
	ok(iv.start == -10 && iv.end == -5, "construct from negative range: [-10,-5]");
}

/**
 * @brief contains(trxid) at boundaries, middle, and outside the interval.
 */
static void test_contains_trxid() {
	TrxId_Interval iv(123, 456);

	ok(iv.contains(123), "contains trxid: start boundary");
	ok(iv.contains(456), "contains trxid: end boundary");
	ok(iv.contains(300), "contains trxid: middle");
	ok(!iv.contains(100), "contains trxid: before start");
	ok(!iv.contains(500), "contains trxid: past end");
}

/**
 * @brief contains(TrxId_Interval) for partial, full, and exact containment.
 */
static void test_contains_interval() {
	TrxId_Interval iv(123, 456);

	ok(!iv.contains(TrxId_Interval(100, 300)), "contains interval: range before start");
	ok(!iv.contains(TrxId_Interval(300, 500)), "contains interval: range past end");
	ok(iv.contains(TrxId_Interval(150, 310)), "contains interval: fully contained");
	ok(iv.contains(TrxId_Interval(123, 456)), "contains interval: exact match");
}

/**
 * @brief to_string() produces "start-end" for ranges and "n" for single values.
 */
static void test_to_string() {
	ok(TrxId_Interval(123, 456).to_string() == "123-456", "to_string: range format");
	ok(TrxId_Interval(111).to_string() == "111", "to_string: single format");
	ok(TrxId_Interval(0, 0).to_string() == "0", "to_string: zero interval");
}

/**
 * @brief append() extends the interval at end, rejects before start and past end.
 */
static void test_append() {
	TrxId_Interval iv(123, 456);

	ok(!iv.append(TrxId_Interval(90, 100)), "append: before start, rejected");
	ok(!iv.append(TrxId_Interval(100, 200)), "append: overlapping at start, rejected");
	ok(!iv.append(TrxId_Interval(500, 600)), "append: past end with gap, rejected");

	ok(iv.append(TrxId_Interval(457, 490)), "append: adjacent at end");
	ok(iv.to_string() == "123-490", "append: adjacent result");

	TrxId_Interval iv2(123, 456);
	ok(iv2.append(TrxId_Interval(200, 600)), "append: overlapping at end");
	ok(iv2.to_string() == "123-600", "append: overlapping result");
}

/**
 * @brief merge() handles all overlap/adjacency cases and rejects non-overlapping intervals.
 */
static void test_merge() {
	{
		TrxId_Interval iv(123, 456);
		ok(!iv.merge(TrxId_Interval(90, 100)), "merge: no overlap before, rejected");
	}
	{
		TrxId_Interval iv(123, 456);
		ok(!iv.merge(TrxId_Interval(500, 600)), "merge: no overlap after, rejected");
	}
	{
		TrxId_Interval iv(123, 456);
		ok(iv.merge(TrxId_Interval(200, 300)), "merge: contained in middle");
		ok(iv.start == 123 && iv.end == 456, "merge: contained result unchanged");
	}
	{
		TrxId_Interval iv(123, 456);
		ok(iv.merge(TrxId_Interval(90, 200)), "merge: overlap at start");
		ok(iv.start == 90 && iv.end == 456, "merge: overlap at start result");
	}
	{
		TrxId_Interval iv(123, 456);
		ok(iv.merge(TrxId_Interval(300, 500)), "merge: overlap at end");
		ok(iv.start == 123 && iv.end == 500, "merge: overlap at end result");
	}
	{
		TrxId_Interval iv(123, 456);
		ok(iv.merge(TrxId_Interval(100, 500)), "merge: full overlap");
		ok(iv.start == 100 && iv.end == 500, "merge: full overlap result");
	}
	{
		TrxId_Interval iv(123, 456);
		ok(iv.merge(TrxId_Interval(100, 122)), "merge: append at start (adjacent)");
		ok(iv.start == 100 && iv.end == 456, "merge: append at start result");
	}
	{
		TrxId_Interval iv(123, 456);
		ok(iv.merge(TrxId_Interval(457, 600)), "merge: append at end (adjacent)");
		ok(iv.start == 123 && iv.end == 600, "merge: append at end result");
	}
}

/**
 * @brief cmp() and operator<, operator==, operator!= for strict weak ordering.
 */
static void test_cmp_operators() {
	TrxId_Interval a(10, 20);
	TrxId_Interval b(10, 30);
	TrxId_Interval c(20, 30);
	TrxId_Interval d(10, 20);

	ok(a < b, "operator<: same start, smaller end");
	ok(a < c, "operator<: smaller start");
	ok(!(b < a), "operator<: not reversed");
	ok(a == d, "operator==: identical");
	ok(!(a == b), "operator==: different");
	ok(a != b, "operator!=: different");
	ok(!(a != d), "operator!=: identical");
}

int main() {
	plan(48);

	test_construct_from_range();            // 2 assertions
	test_construct_from_single();           // 1 assertion
	test_construct_from_string_literal();   // 2 assertions
	test_construct_from_string();           // 2 assertions
	test_construct_negative();              // 1 assertion
	test_contains_trxid();                  // 5 assertions
	test_contains_interval();               // 4 assertions
	test_to_string();                       // 3 assertions
	test_append();                          // 7 assertions
	test_merge();                           // 14 assertions
	test_cmp_operators();                   // 7 assertions

	return exit_status();
}
