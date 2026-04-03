/**
 * @file gtid_utils_unit-t.cpp
 * @brief Unit tests for GTID helper functions.
 *
 * Tests the pure data-structure operations in lib/GTID_Server_Data.cpp:
 *   - addGtid()                 — add a single GTID, merge intervals
 *   - addGtidInterval()         — add a [from,to] interval
 *   - gtid_executed_to_string() — serialize a gtid_set_t to MySQL format
 *
 * These are free functions that operate on gtid_set_t (an unordered_map
 * of UUID -> list of intervals) and require no I/O or event-loop setup.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "proxysql_gtid.h"

// Free function declarations (defined in lib/GTID_Server_Data.cpp,
// declared in include/Base_HostGroups_Manager.h)
extern void addGtid(const gtid_t& gtid, gtid_set_t& gtid_executed);
extern bool addGtidInterval(gtid_set_t& gtid_executed, std::string server_uuid,
                            int64_t txid_start, int64_t txid_end);
extern std::string gtid_executed_to_string(gtid_set_t& gtid_executed);


// =========================================================================
// addGtid tests
// =========================================================================

/**
 * @brief Adding a single GTID to an empty set creates one interval [n,n].
 */
static void test_addGtid_single_to_empty() {
	gtid_set_t gs;
	gtid_t g = std::make_pair(std::string("uuid1"), (int64_t)5);
	addGtid(g, gs);

	ok(gs.count("uuid1") == 1,
	   "addGtid: uuid1 key exists after first insert");
	ok(gs["uuid1"].size() == 1,
	   "addGtid: exactly one interval after first insert");
	auto &iv = gs["uuid1"].front();
	ok(iv.first == 5 && iv.second == 5,
	   "addGtid: interval is [5,5]");
}

/**
 * @brief Consecutive GTIDs merge into a single interval.
 */
static void test_addGtid_consecutive_merge() {
	gtid_set_t gs;
	std::string uuid = "uuid1";
	// Insert 1, 2, 3 in order
	for (int64_t i = 1; i <= 3; i++) {
		addGtid(std::make_pair(uuid, i), gs);
	}

	ok(gs[uuid].size() == 1,
	   "addGtid consecutive: merged into one interval");
	auto &iv = gs[uuid].front();
	ok(iv.first == 1 && iv.second == 3,
	   "addGtid consecutive: interval is [1,3]");
}

/**
 * @brief Non-consecutive GTIDs produce separate intervals.
 */
static void test_addGtid_non_consecutive() {
	gtid_set_t gs;
	std::string uuid = "uuid1";
	addGtid(std::make_pair(uuid, (int64_t)1), gs);
	addGtid(std::make_pair(uuid, (int64_t)5), gs);

	ok(gs[uuid].size() == 2,
	   "addGtid non-consecutive: two separate intervals");
}

/**
 * @brief Duplicate GTID is a no-op.
 */
static void test_addGtid_duplicate() {
	gtid_set_t gs;
	std::string uuid = "uuid1";
	addGtid(std::make_pair(uuid, (int64_t)3), gs);
	addGtid(std::make_pair(uuid, (int64_t)3), gs);

	ok(gs[uuid].size() == 1,
	   "addGtid duplicate: still one interval");
	auto &iv = gs[uuid].front();
	ok(iv.first == 3 && iv.second == 3,
	   "addGtid duplicate: interval unchanged [3,3]");
}

/**
 * @brief Multiple UUIDs are tracked independently.
 */
static void test_addGtid_multiple_uuids() {
	gtid_set_t gs;
	addGtid(std::make_pair(std::string("aaa"), (int64_t)1), gs);
	addGtid(std::make_pair(std::string("bbb"), (int64_t)2), gs);

	ok(gs.size() == 2,
	   "addGtid multiple UUIDs: two entries in map");
	ok(gs["aaa"].front().first == 1,
	   "addGtid multiple UUIDs: aaa has trxid 1");
	ok(gs["bbb"].front().first == 2,
	   "addGtid multiple UUIDs: bbb has trxid 2");
}

/**
 * @brief Adding a GTID that bridges two intervals merges them.
 */
static void test_addGtid_bridge_merge() {
	gtid_set_t gs;
	std::string uuid = "uuid1";
	// Create two separate intervals: [1,1] and [3,3]
	addGtid(std::make_pair(uuid, (int64_t)1), gs);
	addGtid(std::make_pair(uuid, (int64_t)3), gs);
	ok(gs[uuid].size() == 2,
	   "addGtid bridge: two intervals before bridge");

	// Insert 2 — should merge [1,1] and [3,3] into [1,3]
	addGtid(std::make_pair(uuid, (int64_t)2), gs);
	ok(gs[uuid].size() == 1,
	   "addGtid bridge: merged into one interval after bridge");
	auto &iv = gs[uuid].front();
	ok(iv.first == 1 && iv.second == 3,
	   "addGtid bridge: interval is [1,3]");
}

/**
 * @brief Adding GTIDs in reverse order still merges correctly.
 */
static void test_addGtid_reverse_order() {
	gtid_set_t gs;
	std::string uuid = "uuid1";
	for (int64_t i = 5; i >= 1; i--) {
		addGtid(std::make_pair(uuid, i), gs);
	}

	ok(gs[uuid].size() == 1,
	   "addGtid reverse: merged into one interval");
	auto &iv = gs[uuid].front();
	ok(iv.first == 1 && iv.second == 5,
	   "addGtid reverse: interval is [1,5]");
}

/**
 * @brief GTID inside an existing interval is a no-op.
 */
static void test_addGtid_within_interval() {
	gtid_set_t gs;
	std::string uuid = "uuid1";
	addGtid(std::make_pair(uuid, (int64_t)1), gs);
	addGtid(std::make_pair(uuid, (int64_t)2), gs);
	addGtid(std::make_pair(uuid, (int64_t)3), gs);
	// Now [1,3] exists. Adding 2 again should be a no-op.
	addGtid(std::make_pair(uuid, (int64_t)2), gs);

	ok(gs[uuid].size() == 1,
	   "addGtid within: still one interval");
	auto &iv = gs[uuid].front();
	ok(iv.first == 1 && iv.second == 3,
	   "addGtid within: interval unchanged [1,3]");
}


// =========================================================================
// addGtidInterval tests
// =========================================================================

/**
 * @brief Adding an interval to an empty set.
 */
static void test_addGtidInterval_empty() {
	gtid_set_t gs;
	bool updated = addGtidInterval(gs, "uuid1", 1, 10);

	ok(updated == true,
	   "addGtidInterval empty: returns true (updated)");
	ok(gs["uuid1"].size() == 1,
	   "addGtidInterval empty: one interval");
	auto &iv = gs["uuid1"].front();
	ok(iv.first == 1 && iv.second == 10,
	   "addGtidInterval empty: interval is [1,10]");
}

/**
 * @brief Updating an existing interval with the same start but larger end.
 */
static void test_addGtidInterval_update_same_start() {
	gtid_set_t gs;
	addGtidInterval(gs, "uuid1", 1, 10);
	bool updated = addGtidInterval(gs, "uuid1", 1, 19);

	ok(updated == true,
	   "addGtidInterval update: returns true when end changed");
	ok(gs["uuid1"].size() == 1,
	   "addGtidInterval update: still one interval");
	auto &iv = gs["uuid1"].front();
	ok(iv.first == 1 && iv.second == 19,
	   "addGtidInterval update: interval is [1,19]");
}

/**
 * @brief Re-adding an identical interval returns false (no update).
 */
static void test_addGtidInterval_duplicate() {
	gtid_set_t gs;
	addGtidInterval(gs, "uuid1", 1, 10);
	bool updated = addGtidInterval(gs, "uuid1", 1, 10);

	ok(updated == false,
	   "addGtidInterval duplicate: returns false (no change)");
	ok(gs["uuid1"].size() == 1,
	   "addGtidInterval duplicate: still one interval");
}

/**
 * @brief Adding a non-overlapping interval creates a second entry.
 */
static void test_addGtidInterval_separate() {
	gtid_set_t gs;
	addGtidInterval(gs, "uuid1", 1, 10);
	bool updated = addGtidInterval(gs, "uuid1", 20, 30);

	ok(updated == true,
	   "addGtidInterval separate: returns true");
	ok(gs["uuid1"].size() == 2,
	   "addGtidInterval separate: two intervals");
}

/**
 * @brief Multiple UUIDs are tracked independently.
 */
static void test_addGtidInterval_multi_uuid() {
	gtid_set_t gs;
	addGtidInterval(gs, "aaa", 1, 5);
	addGtidInterval(gs, "bbb", 10, 20);

	ok(gs.size() == 2,
	   "addGtidInterval multi-uuid: two UUIDs");
	ok(gs["aaa"].front().second == 5,
	   "addGtidInterval multi-uuid: aaa interval correct");
	ok(gs["bbb"].front().first == 10,
	   "addGtidInterval multi-uuid: bbb interval correct");
}


// =========================================================================
// gtid_executed_to_string tests
// =========================================================================

/**
 * @brief Empty set produces empty string.
 */
static void test_toString_empty() {
	gtid_set_t gs;
	std::string result = gtid_executed_to_string(gs);
	ok(result.empty(),
	   "toString empty: returns empty string");
}

/**
 * @brief Single UUID with a single interval.
 *
 * gtid_executed_to_string inserts dashes into the UUID at positions
 * 8, 13, 18, 23 to produce standard MySQL GTID format:
 *   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx:from-to
 *
 * The stored UUID must be 32 hex chars (no dashes).
 */
static void test_toString_single_uuid_single_interval() {
	gtid_set_t gs;
	// 32-char hex UUID (no dashes) — the format stored internally
	std::string uuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	gs[uuid].emplace_back(1, 10);

	std::string result = gtid_executed_to_string(gs);
	std::string expected = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:1-10";
	ok(result == expected,
	   "toString single interval: '%s' == '%s'",
	   result.c_str(), expected.c_str());
}

/**
 * @brief Single UUID with multiple intervals.
 */
static void test_toString_single_uuid_multi_interval() {
	gtid_set_t gs;
	std::string uuid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	gs[uuid].emplace_back(1, 5);
	gs[uuid].emplace_back(10, 20);

	std::string result = gtid_executed_to_string(gs);
	// Each interval gets its own "uuid:from-to" segment, comma-separated
	std::string expected =
		"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb:1-5,"
		"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb:10-20";
	ok(result == expected,
	   "toString multi-interval: '%s' == '%s'",
	   result.c_str(), expected.c_str());
}

/**
 * @brief Multiple UUIDs.
 *
 * Since gtid_set_t is an unordered_map, iteration order is not
 * guaranteed. We check that both UUIDs appear and the total length
 * is correct.
 */
static void test_toString_multi_uuid() {
	gtid_set_t gs;
	std::string uuid_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	std::string uuid_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	gs[uuid_a].emplace_back(1, 5);
	gs[uuid_b].emplace_back(10, 20);

	std::string result = gtid_executed_to_string(gs);

	// Both UUIDs should appear (with dashes)
	std::string dashed_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
	std::string dashed_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
	ok(result.find(dashed_a) != std::string::npos,
	   "toString multi-uuid: contains uuid_a");
	ok(result.find(dashed_b) != std::string::npos,
	   "toString multi-uuid: contains uuid_b");
	// Should have exactly one comma separating the two entries
	size_t comma_count = 0;
	for (char c : result) { if (c == ',') comma_count++; }
	ok(comma_count == 1,
	   "toString multi-uuid: exactly one comma separator");
}


// =========================================================================
// main
// =========================================================================

int main() {
	plan(37);
	test_init_minimal();

	// addGtid tests
	test_addGtid_single_to_empty();       // 3 checks
	test_addGtid_consecutive_merge();      // 2 checks
	test_addGtid_non_consecutive();        // 1 check
	test_addGtid_duplicate();              // 2 checks
	test_addGtid_multiple_uuids();         // 3 checks
	test_addGtid_bridge_merge();           // 3 checks
	test_addGtid_reverse_order();          // 2 checks
	test_addGtid_within_interval();        // 2 checks

	// addGtidInterval tests
	test_addGtidInterval_empty();          // 3 checks
	test_addGtidInterval_update_same_start(); // 3 checks
	test_addGtidInterval_duplicate();      // 2 checks
	test_addGtidInterval_separate();       // 2 checks
	test_addGtidInterval_multi_uuid();     // 3 checks

	// gtid_executed_to_string tests
	test_toString_empty();                 // 1 check
	test_toString_single_uuid_single_interval(); // 1 check
	test_toString_single_uuid_multi_interval();  // 1 check
	test_toString_multi_uuid();            // 3 checks

	test_cleanup_minimal();
	return exit_status();
}
