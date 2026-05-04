/**
 * @file gtid_set_unit-t.cpp
 * @brief Unit tests for GTID_Set.
 *
 * Tests the pure data-structure operations in lib/proxysql_gtid.cpp:
 *   - GTID_Set::add() overloads   — add intervals, single trxids, string ranges
 *   - GTID_Set::has_gtid()        — membership checks across UUID-keyed intervals
 *   - GTID_Set::to_string()       — serialization to MySQL GTID format
 *   - GTID_Set::clear()           — reset to empty state
 *   - GTID_Set::copy()            — deep copy with independence
 *
 */

#include "tap.h"

#include "proxysql_gtid.h"

#include <set>
#include <sstream>

static const std::string UUID_A = "aaaaaaaa000011112222aaaaaaaaaaaa";
static const std::string UUID_B = "bbbbbbbb333344445555bbbbbbbbbbbb";

/**
 * @brief add() with TrxId_Interval: new range, append fast-path, partial overlap, gap.
 */
static void test_add_interval() {
	GTID_Set gs;

	ok(gs.add(UUID_A, TrxId_Interval(10, 20)), "add interval: new range for UUID A");
	ok(gs.add(UUID_A, TrxId_Interval(15, 22)), "add interval: contained range handled via append fast-path");
	ok(gs.add(UUID_A, TrxId_Interval(9, 22)), "add interval: partial overlap extends");
	ok(gs.add(UUID_A, TrxId_Interval(40, 50)), "add interval: gap creates new interval");
	ok(gs.map.size() == 1, "add interval: one UUID");
	ok(gs.map[UUID_A].size() == 2, "add interval: two intervals");
	auto it = gs.map[UUID_A].begin();
	ok(it->start == 9 && it->end == 22, "add interval: first interval is [9,22]");
	++it;
	ok(it->start == 40 && it->end == 50, "add interval: second interval is [40,50]");
}

/**
 * @brief add() with a single trxid_t: new entry and duplicate does not create an extra interval.
 */
static void test_add_trxid() {
	GTID_Set gs;

	ok(gs.add(UUID_A, trxid_t(14)), "add single: new trxid");
	gs.add(UUID_A, trxid_t(14));
	ok(gs.map[UUID_A].size() == 1, "add single: duplicate does not create new interval");
}

/**
 * @brief add() with C string range for single and multiple UUIDs.
 */
static void test_add_cstring_range() {
	GTID_Set gs;

	ok(gs.add(UUID_A, "9-22"), "add C string range: new range");
	ok(gs.add(UUID_B, "31-50"), "add C string range: new range for UUID B");
	ok(gs.map.size() == 2, "add C string range: two UUIDs");
	auto it_a = gs.map[UUID_A].begin();
	ok(it_a->start == 9 && it_a->end == 22, "add C string range: UUID A interval is [9,22]");
	auto it_b = gs.map[UUID_B].begin();
	ok(it_b->start == 31 && it_b->end == 50, "add C string range: UUID B interval is [31,50]");
}

/**
 * @brief add() with std::string range.
 */
static void test_add_string_range() {
	GTID_Set gs;

	ok(gs.add(UUID_A, std::string("18-30")), "add string range: new range");
	ok(gs.map.size() == 1, "add string range: one UUID");
	auto it = gs.map[UUID_A].begin();
	ok(it->start == 18 && it->end == 30, "add string range: interval is [18,30]");
}

/**
 * @brief add() with malformed string ranges must not create a trxid 0 interval.
 */
static void test_add_invalid_string_range() {
	GTID_Set gs;

	ok(!gs.add(UUID_A, "abc"), "add invalid C string range: rejects non-numeric input");
	ok(!gs.add(UUID_A, "10-abc"), "add invalid C string range: rejects malformed end");
	ok(!gs.add(UUID_A, "10-20x"), "add invalid C string range: rejects trailing characters");
	ok(gs.map.empty(), "add invalid C string range: no UUID entry created");
	ok(!gs.has_gtid(UUID_A, 0), "add invalid C string range: trxid 0 was not added");
}

/**
 * @brief add() with explicit start, end parameters.
 */
static void test_add_start_end() {
	GTID_Set gs;

	ok(gs.add(UUID_A, trxid_t(40), trxid_t(50)), "add start,end: new range");
	ok(gs.map.size() == 1, "add start,end: one UUID");
	auto it = gs.map[UUID_A].begin();
	ok(it->start == 40 && it->end == 50, "add start,end: interval is [40,50]");
}

/**
 * @brief Multiple UUIDs are tracked independently in the same GTID_Set.
 */
static void test_add_multi_uuid() {
	GTID_Set gs;

	gs.add(UUID_A, TrxId_Interval(10, 20));
	gs.add(UUID_B, TrxId_Interval(30, 40));

	ok(gs.map.count(UUID_A) == 1, "multi-uuid: UUID A exists");
	ok(gs.map.count(UUID_B) == 1, "multi-uuid: UUID B exists");
	ok(gs.map.size() == 2, "multi-uuid: exactly two UUIDs");
}

/**
 * @brief add() with consecutive trxid values (1,2,3) merges into a single interval [1,3].
 */
static void test_add_consecutive_trxid() {
	GTID_Set gs;

	gs.add(UUID_A, trxid_t(1));
	gs.add(UUID_A, trxid_t(2));
	gs.add(UUID_A, trxid_t(3));

	ok(gs.map[UUID_A].size() == 1, "consecutive adds: merged into one interval");
	auto& iv = gs.map[UUID_A].front();
	ok(iv.start == 1 && iv.end == 3, "consecutive adds: interval is [1,3]");
}

/**
 * @brief add() with non-consecutive trxid values (1,5) produces two separate intervals.
 */
static void test_add_non_consecutive_trxid() {
	GTID_Set gs;

	gs.add(UUID_A, trxid_t(1));
	gs.add(UUID_A, trxid_t(5));

	ok(gs.map[UUID_A].size() == 2, "non-consecutive adds: two separate intervals");
}

/**
 * @brief add() with reverse-order trxid values (5,4,3,2,1) still produces [1,5].
 */
static void test_add_reverse_order_trxid() {
	GTID_Set gs;

	for (trxid_t i = 5; i >= 1; i--) {
		gs.add(UUID_A, i);
	}

	ok(gs.map[UUID_A].size() == 1, "reverse order: merged into one interval");
	auto& iv = gs.map[UUID_A].front();
	ok(iv.start == 1 && iv.end == 5, "reverse order: interval is [1,5]");
}

/**
 * @brief add() with a duplicate trxid does not create a new interval.
 */
static void test_add_duplicate_trxid() {
	GTID_Set gs;

	gs.add(UUID_A, trxid_t(3));
	gs.add(UUID_A, trxid_t(3));

	ok(gs.map[UUID_A].size() == 1, "duplicate single: still one interval");
	auto& iv = gs.map[UUID_A].front();
	ok(iv.start == 3 && iv.end == 3, "duplicate single: interval unchanged [3,3]");
}

/**
 * @brief add() merges two intervals when a trxid fills the gap between them.
 */
static void test_add_merge_trxid() {
	GTID_Set gs;

	gs.add(UUID_A, trxid_t(1));
	gs.add(UUID_A, trxid_t(3));
	ok(gs.map[UUID_A].size() == 2, "bridge merge: two intervals before bridge");

	gs.add(UUID_A, trxid_t(2));
	ok(gs.map[UUID_A].size() == 1, "bridge merge: merged into one interval");
	auto& iv = gs.map[UUID_A].front();
	ok(iv.start == 1 && iv.end == 3, "bridge merge: interval is [1,3]");
}

/**
 * @brief add() merges two intervals when an interval fills the gap between them.
 */
static void test_add_merge_interval() {
	GTID_Set gs;

	gs.add(UUID_A, TrxId_Interval(1, 10));
	gs.add(UUID_A, TrxId_Interval(20, 30));
	ok(gs.map[UUID_A].size() == 2, "gap fill: two intervals before fill");

	gs.add(UUID_A, TrxId_Interval(11, 19));
	ok(gs.map[UUID_A].size() == 1, "gap fill: merged into one interval");
	auto& iv = gs.map[UUID_A].front();
	ok(iv.start == 1 && iv.end == 30, "gap fill: interval is [1,30]");
}

/**
 * @brief has_gtid() at boundaries, in gap, past ranges, and for unknown UUIDs.
 */
static void test_has_gtid() {
	GTID_Set gs;
	gs.add(UUID_A, "10-20");
	gs.add(UUID_A, "30-40");
	gs.add(UUID_B, TrxId_Interval(100, 200));

	ok(!gs.has_gtid("cccccccc666677778888cccccccccccc", 10), "has_gtid: unknown UUID returns false");

	ok(!gs.has_gtid(UUID_A, 7), "has_gtid: before range");
	ok(gs.has_gtid(UUID_A, 10), "has_gtid: at start");
	ok(gs.has_gtid(UUID_A, 16), "has_gtid: in range");
	ok(gs.has_gtid(UUID_A, 20), "has_gtid: at end");
	ok(!gs.has_gtid(UUID_A, 25), "has_gtid: in gap");
	ok(!gs.has_gtid(UUID_A, 55), "has_gtid: past all ranges");

	ok(!gs.has_gtid(UUID_B, 74), "has_gtid: before range (UUID B)");
	ok(gs.has_gtid(UUID_B, 100), "has_gtid: at start (UUID B)");
	ok(gs.has_gtid(UUID_B, 168), "has_gtid: in range (UUID B)");
	ok(gs.has_gtid(UUID_B, 200), "has_gtid: at end (UUID B)");
	ok(!gs.has_gtid(UUID_B, 201), "has_gtid: past range (UUID B)");
}

/**
 * @brief clear() removes all entries; has_gtid() returns false afterwards.
 */
static void test_clear() {
	GTID_Set gs;

	gs.add(UUID_A, "10-20");
	gs.add(UUID_B, "100-200");

	gs.clear();

	ok(!gs.has_gtid(UUID_A, 16), "clear: UUID A gone");
	ok(!gs.has_gtid(UUID_B, 168), "clear: UUID B gone");
	ok(gs.map.empty(), "clear: map is empty");
}

/**
 * @brief to_string() serialization: empty set, single interval, and multiple intervals/UUIDs.
 */
static void test_to_string() {
	// empty set
	{
		GTID_Set gs;
		ok(gs.to_string().empty(), "to_string: empty set returns empty string");
	}

	// single UUID with single interval
	{
		GTID_Set gs;
		gs.add("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TrxId_Interval(1, 10));
		std::string result = gs.to_string();
		std::string expected = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:1-10";
		ok(result == expected, "to_string: single UUID single interval matches");
	}

	// multiple intervals and UUIDs
	{
		GTID_Set gs;
		gs.add(UUID_A, TrxId_Interval(10, 20));
		gs.add(UUID_A, "9-22");
		gs.add(UUID_A, std::string("18-30"));
		gs.add(UUID_A, TrxId_Interval(40, 50));
		gs.add(UUID_B, TrxId_Interval(10, 30));
		gs.add(UUID_B, "31-50");
		std::string result = gs.to_string();

		std::set<std::string> parts;
		std::istringstream iss(result);
		std::string part;
		while (std::getline(iss, part, ',')) {
			parts.insert(part);
		}

		ok(parts.size() == 2, "to_string: two UUID sets separated by comma");
		ok(parts.count("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:9-30:40-50") == 1,
			"to_string: UUID A format is uuid:9-30:40-50");
		ok(parts.count("bbbbbbbb-3333-4444-5555-bbbbbbbbbbbb:10-50") == 1,
			"to_string: UUID B format is uuid:10-50");
	}
}

/**
 * @brief copy() produces a deep copy with the same data, and modifying the copy does not affect the original.
 */
static void test_copy() {
	GTID_Set gs;

	gs.add(UUID_A, TrxId_Interval(10, 20));
	gs.add(UUID_B, TrxId_Interval(30, 40));

	GTID_Set cp = gs.copy();

	ok(cp.map.size() == 2, "copy: same number of UUIDs");
	ok(cp.has_gtid(UUID_A, 15), "copy: has UUID A trxid");
	ok(cp.has_gtid(UUID_B, 35), "copy: has UUID B trxid");

	cp.add(UUID_A, TrxId_Interval(30, 40));

	ok(!gs.has_gtid(UUID_A, 35), "copy: original not affected by copy mutation");
	ok(cp.has_gtid(UUID_A, 35), "copy: copy has new data");
}

int main() {
	plan(67);

	test_add_interval();				          // 8 assertions
	test_add_trxid();                             // 2 assertions
	test_add_cstring_range();                     // 5 assertions
	test_add_string_range();                      // 3 assertions
	test_add_invalid_string_range();              // 5 assertions
	test_add_start_end();                         // 3 assertions
	test_add_multi_uuid();                        // 3 assertions
	test_add_consecutive_trxid();                 // 2 assertions
	test_add_non_consecutive_trxid();             // 1 assertion
	test_add_reverse_order_trxid();               // 2 assertions
	test_add_duplicate_trxid();                   // 2 assertions
	test_add_merge_trxid();                       // 3 assertions
	test_add_merge_interval();                    // 3 assertions	
	test_has_gtid();                              // 12 assertions
	test_clear();                                 // 3 assertions
	test_to_string();                             // 5 assertions
	test_copy();                                  // 5 assertions

	return exit_status();
}
