/**
 * @file gtid_wire_contract_unit-t.cpp
 * @brief Replays the reader's real wire output through ProxySQL's parser.
 *
 * The MariaDB GTID reader (sysown/proxysql_mysqlbinlog) and ProxySQL's
 * consumer of its output (GTID_Server_Data) live in two repositories, and CI
 * never runs them against each other. ProxySQL pins the reader to the
 * published 2.4.0 image -- which predates MariaDB GTID support -- and has no
 * MariaDB binlog-reader infrastructure, so every other MariaDB assertion in
 * gtid_server_data_unit-t.cpp feeds hand-written strings into the buffer and
 * only proves the parser agrees with the author's own idea of the format.
 *
 * This test closes that gap from the consumer side: it reads the same fixture
 * the reader's live test verifies against, so a change to the reader's output
 * has to be mirrored here and shows up as a failing check on both sides.
 *
 * The fixture is duplicated byte-identically in the reader repository at
 * test/tap/wire_contract/mariadb_gtid_wire.txt, as is the reader's
 * test/tap/wire_contract.h (copied here as wire_contract.h). Keep all three in
 * sync; a divergence is itself a contract break.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "GTID_Server_Data.h"
#include "MySQL_HostGroups_Manager.h"
#include "proxysql_gtid.h"
#include "proxysql_utils.h"
#include "wire_contract.h"

#include <cstring>
#include <string>
#include <vector>

static char LOOPBACK[] = "127.0.0.1";

/**
 * @brief Replaces the entire buffer content, as the reader's socket handler
 *        would after a read() delivered `msg`.
 */
static void stuff_buffer(GTID_Server_Data &sd, const std::string &msg) {
	if (msg.size() > sd.size) {
		sd.resize(msg.size());
	}
	memcpy(sd.data, msg.c_str(), msg.size());
	sd.len = msg.size();
	sd.pos = 0;
}

/**
 * @brief Finds the fixture whether the binary runs from test/tap/tests/unit,
 *        test/tap, or the repository root.
 */
static std::string resolve_fixture() {
	const char *candidates[] = {
		"fixtures/mariadb_gtid_wire.txt",
		"test/tap/tests/unit/fixtures/mariadb_gtid_wire.txt",
		"../fixtures/mariadb_gtid_wire.txt",
		"tests/unit/fixtures/mariadb_gtid_wire.txt",
	};
	for (const char *candidate : candidates) {
		std::ifstream probe(candidate);
		if (probe) {
			return candidate;
		}
	}
	return candidates[0];
}

/**
 * @brief The concrete numbers the fixture's placeholders expand to.
 *
 * Any positive values work; they only have to be distinguishable, so that an
 * off-by-one in the watermark is visible.
 */
static const std::map<std::string, std::string> &expansion() {
	static const std::map<std::string, std::string> values = {
		{ "start", "1" },
		{ "end", "77" },
		{ "seq", "78" },
		{ "seq2", "79" },
	};
	return values;
}

/**
 * @brief Feeds every fixture record to the parser, in fixture order, through a
 *        single reader session.
 *
 * Using one session is the point: ST= must establish the domain, I1 must
 * extend it, and I2 must reuse the reader's last domain. A parser that
 * mishandles the carry-over shows up as a wrong watermark rather than as three
 * unrelated parses that each happen to look fine.
 */
static void test_fixture_replays_as_documented() {
	std::vector<WireContractRecord> records;
	if (!load_wire_contract(resolve_fixture(), &records)) {
		ok(false, "wire contract fixture is readable");
		return;
	}
	if (records.size() != 3) {
		ok(false, "wire contract fixture has exactly the ST, I1 and I2 records");
		return;
	}

	GTID_Server_Data sd(nullptr, LOOPBACK, 0, 3306);
	char *domain = (char *)"0";

	for (size_t i = 0; i < records.size(); i++) {
		const std::string line = wire_contract::expand(records[i].templ, expansion());
		stuff_buffer(sd, line + "\n");
		const bool parsed = sd.read_next_gtid();
		ok(parsed, "wire contract: fixture %s record parses (raw='%s')",
		   records[i].kind.c_str(), line.c_str());
		if (!parsed) {
			ok(false, "wire contract: aborting, the session state is not meaningful");
			return;
		}
	}

	// The snapshot closed [1, 77] and the two streamed transactions extended it
	// to 79, all on domain 0.
	ok(sd.gtid_exists(domain, 77) == true,
	   "wire contract: the snapshot watermark <end> is a causal-read match");
	ok(sd.gtid_exists(domain, 79) == true,
	   "wire contract: the streamed <seq2> is a causal-read match");
	ok(sd.gtid_exists(domain, 80) == false,
	   "wire contract: nothing beyond <seq2> is claimed");
	ok(sd.gtid_exists(domain, 0) == false,
	   "wire contract: sequence 0 is never claimed");
	ok(sd.gtid_flavor == GTID_ID_FLAVOR_DOMAIN,
	   "wire contract: a bare decimal id is a domain, not a UUID");

	// A bare I2= carries no domain, so it must land on the reader's last domain
	// and nowhere else. If the carry-over were dropped, the set would grow a
	// second, empty domain instead of collapsing to one.
	//
	// The reader puts no server id on the wire, so the display lists the domain
	// interval rather than the native `domain-server-seq` form (issue #6336).
	const std::string display = sd.gtid_executed.to_display_string();
	ok(display == "0:1-79",
	   "wire contract: the whole fixture collapses to one domain watermark (got '%s')",
	   display.c_str());
}

/**
 * @brief The fixture's id must be a canonical decimal, and the two spellings of
 *        the zero domain must not be treated as one.
 */
static void test_fixture_id_is_canonical() {
	ok(is_canonical_mariadb_domain_id("0", 1) == true, "wire contract: domain 0 is canonical");
	ok(is_canonical_mariadb_domain_id("00", 2) == false, "wire contract: domain 00 is not canonical");
	ok(is_canonical_mariadb_domain_id("0-1-270", 7) == false,
	   "wire contract: the native MariaDB spelling is not a domain id");
}

int main() {
	plan(13);
	ok(test_init_minimal() == 0, "test_init_minimal() succeeds");

	test_fixture_replays_as_documented();
	test_fixture_id_is_canonical();

	return exit_status();
}
