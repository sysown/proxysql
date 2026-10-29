/**
 * @file gtid_set_separator_unit-t.cpp
 * @brief Multi-UUID GTID sets with the server's ",\n" block separator are
 *   accepted, both as tracked OWN_GTID values and as min_gtid annotations
 *   (#6415 follow-up).
 *
 * MySQL's Gtid_set::to_string separates UUID blocks with ",\n". The set parser
 * split on ',' and '\n' separately, so that separator produced an empty block
 * and the whole set was rejected. A min_gtid annotation echoing the value
 * arrives as ", " (the comment parser folds the newline into a space), was
 * rejected by validation with "Invalid min_gtid", and the query ran with no
 * GTID constraint at all.
 */

#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#define private public
#define protected public
#include "cpp.h"
#include "MySQL_Query_Processor.h"
#undef protected
#undef private
#include "proxysql_gtid.h"

extern MySQL_Query_Processor* GloMyQPro;

namespace {

const char kA[] = "aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa";
const char kB[] = "bbbbbbbb-0000-1111-2222-bbbbbbbbbbbb";

std::string set_of(const char* sep) {
	return std::string(kA) + ":1-5" + sep + kB + ":1-3";
}

bool parses_two_blocks(const std::string& v) {
	std::map<std::string, std::vector<TrxId_Interval>> out;
	if (!parse_gtid_set(v.c_str(), v.size(), &out) || out.size() != 2) {
		return false;
	}
	const auto a = out.find("aaaaaaaa000011112222aaaaaaaaaaaa");
	const auto b = out.find("bbbbbbbb000011112222bbbbbbbbbbbb");
	return a != out.end() && b != out.end() && a->second.size() == 1 &&
		a->second[0].start == 1 && a->second[0].end == 5 &&
		b->second.size() == 1 && b->second[0].start == 1 && b->second[0].end == 3;
}

bool rejected(const std::string& v) {
	std::map<std::string, std::vector<TrxId_Interval>> out;
	out["sentinel"] = {};
	return !parse_gtid_set(v.c_str(), v.size(), &out) && out.size() == 1 &&
		out.count("sentinel") == 1;
}

void test_tracked_forms() {
	ok(parses_two_blocks(set_of(",\n")), "tracked: the server's ',\\n' separator is accepted");
	ok(parses_two_blocks(set_of(", ")), "tracked: ', ' is accepted");
	ok(parses_two_blocks(set_of(",")), "tracked: ',' is still accepted");
	ok(parses_two_blocks(set_of("\n")), "tracked: a bare newline is still accepted");
	ok(parses_two_blocks(set_of(" ,\r\n\t")), "tracked: whitespace on both sides of ',' is accepted");
	ok(parses_two_blocks(" \n" + set_of(",\n") + "\n "),
		"tracked: whitespace around the whole value is ignored");

	ok(rejected(set_of(",,")), "tracked: ',,' (an empty block) is rejected");
	ok(rejected(set_of(",\n,")), "tracked: an empty block between whitespace is rejected");
	ok(rejected("," + set_of(",")), "tracked: a leading ',' is rejected");
	ok(rejected(set_of(",") + ",\n"), "tracked: a trailing ',' is rejected");
	ok(rejected(set_of(" ")), "tracked: blocks separated only by a blank are rejected");
	ok(rejected(std::string(kA) + ": 1-5"), "tracked: a blank inside a block is rejected");
	ok(rejected(" \n\t"), "tracked: a whitespace-only value is rejected");
	ok(rejected(std::string(kA) + ":1-5,\n" + kA + ":7"),
		"tracked: a repeated UUID is still rejected");

	// Routing keeps failing closed on a multi-UUID set: it must reach that
	// decision (writer fallback), not a parse failure on the separator.
	char id[64];
	uint64_t trx = 0;
	const std::string single = std::string("\n") + kA + ":1-5:7-9,\n";
	ok(!parse_gtid_set_for_routing(single.c_str(), id, sizeof(id), &trx),
		"routing: a trailing ',\\n' is still an empty block");
	const std::string single_ws = std::string(" ") + kA + ":1-5:7-9\n";
	ok(parse_gtid_set_for_routing(single_ws.c_str(), id, sizeof(id), &trx) && trx == 9,
		"routing: a single-UUID set with surrounding whitespace routes on its highest trxid");
}

/** @brief Feeds a query comment through the real first-comment parser. */
bool annotation_kept(const std::string& comment, std::string* stored) {
	MySQL_Query_Processor_Output qpo;
	qpo.init();
	std::vector<char> fc(comment.begin(), comment.end());
	fc.push_back('\0');
	GloMyQPro->query_parser_first_comment(&qpo, fc.data());
	const bool kept = qpo.min_gtid != nullptr;
	if (kept && stored != nullptr) {
		*stored = qpo.min_gtid;
	}
	qpo.destroy();
	return kept;
}

void test_min_gtid_forms() {
	std::string stored;
	ok(annotation_kept(" min_gtid=" + set_of(",\n") + " ", &stored) && stored == set_of(", "),
		"min_gtid: the ',\\n' form survives the comment parser (as ', ') and is kept");
	ok(annotation_kept("min_gtid=" + set_of(", "), nullptr), "min_gtid: ', ' is kept");
	ok(annotation_kept("min_gtid=" + set_of(","), nullptr), "min_gtid: ',' is kept");

	ok(MySQL_Query_Processor::_is_valid_gtid(set_of(", ").c_str(), set_of(", ").size()),
		"min_gtid validation accepts ', '");
	ok(!annotation_kept("min_gtid=" + set_of(",,"), nullptr), "min_gtid: ',,' is still rejected");
	ok(!annotation_kept("min_gtid=" + set_of(", ,"), nullptr),
		"min_gtid: an empty block between blanks is still rejected");
	ok(!annotation_kept("min_gtid=" + set_of(" "), nullptr),
		"min_gtid: blocks separated only by a blank are still rejected");

	// The kept annotation is enforced, not dropped: routing reaches its
	// fail-closed multi-UUID decision.
	char id[64];
	uint64_t trx = 0;
	ok(!parse_gtid_set_for_routing(set_of(", ").c_str(), id, sizeof(id), &trx),
		"min_gtid: a kept multi-UUID annotation is not routable (fail-closed, not dropped)");
}

} // namespace

int main() {
	plan(24);
	if (test_init_minimal() != 0 || test_init_query_processor() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	test_tracked_forms();
	test_min_gtid_forms();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
