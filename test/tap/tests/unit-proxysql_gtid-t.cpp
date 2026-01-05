#include <stdlib.h>

#include "tap.h"
#include "unit_test.h"
#include "proxysql_gtid.h"

using std::string;

int testGtidIntervalFromString_Count() {
    return 2;
}
void testGtidIntervalFromString() {
	ok(gtid_interval_t("123-456") == gtid_interval_t(123, 456), "GTID interval from range string");
	ok(gtid_interval_t("111") == gtid_interval_t(111, 111), "GTID interval from single GTID string");
}

int testGtidIntervalContains_Count() {
	return 8;
}
void testGtidIntervalContains() {
	auto iv = gtid_interval_t(123, 456);

	ok(iv.contains(123), "GTID interval contains start");
	ok(iv.contains(456), "GTID interval contains end");
	ok(iv.contains(300), "GTID interval contains middle");
	ok(!iv.contains(100), "GTID interval doesn't contain before start");
	ok(!iv.contains(500), "GTID interval doesn't contain past end");
	ok(!iv.contains(gtid_interval_t(100, 300)), "GTID interval doesn't contain range before start");
	ok(!iv.contains(gtid_interval_t(300, 500)), "GTID interval doesn't contain range past end");
	ok(iv.contains(gtid_interval_t(150, 310)), "GTID interval contains range");
}

int testGtidIntervalAppend_Count() {
	return 7;
}
void testGtidIntervalAppend() {
	auto iv = gtid_interval_t(123, 456);

	ok(!iv.append(gtid_interval_t(90, 100)), "cannot append before range start");
	ok(!iv.append(gtid_interval_t(100, 200)), "cannot append at start");
	ok(!iv.append(gtid_interval_t(500, 600)), "cannot append past end");
	ok(iv.append(gtid_interval_t(457, 490)), "append");
	ok(iv.to_string() == "123-490", "append result");

	iv = gtid_interval_t(123, 456);
	ok(iv.append(gtid_interval_t(200, 600)), "append with overlap");
	ok(iv.to_string() == "123-600", "append with overlap result");
}

int testAddGtidInterval_Count() {
	return 8;
}
void testAddGtidInterval() {
	gtid_set_t gtid_set;

	ok(addGtidInterval("aaaaaaaa000011112222aaaaaaaaaaaa", gtid_interval_t(10, 20), gtid_set), "new GTID range for server A");
	ok(addGtidInterval("aaaaaaaa000011112222aaaaaaaaaaaa", gtid_interval_t(9, 22), gtid_set), "new GTID range with partial overlap for server A");
	ok(addGtidInterval("aaaaaaaa000011112222aaaaaaaaaaaa", gtid_interval_t(18, 30), gtid_set), "new GTID range with partial overlap for server A");
	ok(!addGtidInterval("aaaaaaaa000011112222aaaaaaaaaaaa", gtid_interval_t(15, 22), gtid_set), "GTID range is already fully contained for server A");
	ok(addGtidInterval("aaaaaaaa000011112222aaaaaaaaaaaa", gtid_interval_t(40, 50), gtid_set), "new GTID range with gap for server A");
	ok(addGtidInterval("bbbbbbbb333344445555bbbbbbbbbbbb", gtid_interval_t(10, 30), gtid_set), "new GTID range for server B");
	ok(addGtidInterval("bbbbbbbb333344445555bbbbbbbbbbbb", gtid_interval_t(31, 50), gtid_set), "new GTID range for server B");
	ok(gtid_set_to_string(gtid_set) == "aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:10-30,aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:40-50,bbbbbbbb-3333-4444-5555-bbbbbbbbbbbb:10-50", "add interval result");
}

int testGtidIntervalMerge_Count() {
	return 14;
}
void testGtidIntervalMerge() {
	auto iv = gtid_interval_t(123, 456);
	ok(!iv.merge(gtid_interval_t(90, 100)), "cannot merge before range start");
	ok(!iv.merge(gtid_interval_t(500, 600)), "cannot merge past range end");
	ok(iv.merge(gtid_interval_t(90, 200)), "merge at start");
	auto want = gtid_interval_t(90, 456);
	ok(iv == want, "merge at start result");

	iv = gtid_interval_t(123, 456);
	ok(iv.merge(gtid_interval_t(300, 500)), "merge at end");
	want = gtid_interval_t(123, 500);
	ok(iv == want, "merge at end result");

	iv = gtid_interval_t(123, 456);
	ok(iv.merge(gtid_interval_t(200, 300)), "merge at middle");
	want = gtid_interval_t(123, 456);
	ok(iv == want, "merge at middle result");

	iv = gtid_interval_t(123, 456);
	ok(iv.merge(gtid_interval_t(100, 500)), "merge overlap");
	want = gtid_interval_t(100, 500);
	ok(iv == want, "merge overlap result");

	iv = gtid_interval_t(123, 456);
	ok(iv.merge(gtid_interval_t(100, 122)), "merge append at start");
	want = gtid_interval_t(100, 456);
	ok(iv == want, "merge append at start result");

	iv = gtid_interval_t(123, 456);
	want = gtid_interval_t(123, 600);
	ok(iv.merge(gtid_interval_t(457, 600)), "merge append at end");
	ok(iv == want, "merge append at end result");
}

std::function<int(void)> testFunctionCounts[] = {
	testGtidIntervalFromString_Count,
	testGtidIntervalContains_Count,
	testGtidIntervalAppend_Count,
	testGtidIntervalMerge_Count,
	testAddGtidInterval_Count,
};
std::function<void(void)> testFunctions[] = {
	testGtidIntervalFromString,
	testGtidIntervalContains,
	testGtidIntervalAppend,
	testGtidIntervalMerge,
	testAddGtidInterval,
};

int main(int argc, char** argv) {
	// Set up unit tests...
	int n = 0;
	for (auto f : testFunctionCounts) {
		n += f();
	}
	plan(n);
	
	// ...and run them.
	for (auto f : testFunctions) {
		f();
	}

	return exit_status();
}