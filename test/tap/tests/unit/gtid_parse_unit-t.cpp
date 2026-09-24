#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql_gtid.h"
#include "cpp.h"
#include "mysql_connection.h"
#include <cstring>

static void test_session_tracking_reset() {
	{
		MySQL_Connection connection;
		connection.options.session_track_gtids = strdup("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:42");
		connection.options.session_track_gtids_int = 42;
		connection.options.session_track_gtids_sent = true;
		connection.options.session_track_variables_sent = true;
		connection.options.session_track_state_sent = true;
		connection.reset();
		ok(connection.options.session_track_gtids == nullptr
		       && connection.options.session_track_gtids_int == 0
		       && !connection.options.session_track_gtids_sent
		       && !connection.options.session_track_variables_sent
		       && !connection.options.session_track_state_sent,
		   "reset clears tracking state and frees the GTID payload");
	}
	{
		MySQL_Connection connection;
		connection.options.session_track_gtids_int = 42;
		connection.options.session_track_gtids_sent = true;
		connection.options.session_track_variables_sent = true;
		connection.options.session_track_state_sent = true;
		connection.reset();
		ok(connection.options.session_track_gtids_int == 0
		       && !connection.options.session_track_gtids_sent
		       && !connection.options.session_track_variables_sent
		       && !connection.options.session_track_state_sent,
		   "reset clears tracking sent flags without a GTID payload");
	}
}

int main() {
	plan(32);
	ok(test_init_minimal() == 0, "test_init_minimal() succeeds");
	ParsedGTID p;

	ok(parse_gtid("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:42", &p)
	       && p.id == "aaaaaaaa000011112222aaaaaaaaaaaa" && p.trxid == 42
	       && p.server_id == 0 && !p.mariadb,
	   "MySQL dashed UUID");
	ok(parse_gtid("aaaaaaaa000011112222aaaaaaaaaaaa:42", &p) && !p.mariadb
	       && p.trxid == 42,
	   "MySQL dash-free UUID");
	ok(parse_gtid("0-1-100", &p) && p.mariadb && p.id == "0"
	       && p.trxid == 100 && p.server_id == 1,
	   "MariaDB domain-server-seq");
	ok(!parse_gtid("0-1", &p), "reject two-field");
	ok(!parse_gtid("0-1-0", &p), "reject seq 0");
	ok(!parse_gtid("00-1-1", &p), "reject leading zeros");
	ok(!parse_gtid("not-a-gtid", &p), "reject junk");
	ok(!parse_gtid(nullptr, &p), "reject null");

	GTID_Set set;
	ok(parse_gtid_set("0-1-270,1-2-50", &set)
	       && set.has_gtid("0", 100) && set.has_gtid("0", 270)
	       && !set.has_gtid("0", 271) && set.has_gtid("1", 50),
	   "MariaDB set is per-domain watermark [1, seq]");
	GTID_Set mysql_set;
	ok(parse_gtid_set("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:1-3:5", &mysql_set)
	       && mysql_set.has_gtid("aaaaaaaa000011112222aaaaaaaaaaaa", 3)
	       && !mysql_set.has_gtid("aaaaaaaa000011112222aaaaaaaaaaaa", 4)
	       && mysql_set.has_gtid("aaaaaaaa000011112222aaaaaaaaaaaa", 5),
	   "MySQL set keeps sparse intervals");
	ok(!parse_gtid_set("0-1-270,aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:1", &set),
	   "reject mixed flavors in one set");
	ok(!parse_gtid_set("", &set), "reject empty");
	ok(!parse_gtid(" 0-1-100 ", &p), "reject surrounding whitespace");
	ok(!parse_gtid("0-1-100", nullptr), "reject null out");
	ok(!parse_gtid_set("0-1-270,", &set), "reject trailing comma");
	ok(!parse_gtid("aaaaaaaa000011112222aaaaaaaaaaaa: 42", &p), "reject whitespace after colon");

	char id[64];
	uint64_t trx = 0;
	ok(parse_gtid_for_routing("0-1-100", id, sizeof(id), &trx)
	       && std::string(id) == "0" && trx == 100,
	   "routing parse MariaDB");
	ok(parse_gtid_for_routing("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:9",
	                          id, sizeof(id), &trx)
	       && std::string(id) == "aaaaaaaa000011112222aaaaaaaaaaaa" && trx == 9,
	   "routing parse MySQL");
	ok(!parse_gtid_for_routing("nope", id, sizeof(id), &trx), "routing reject");

	char id_sentinel[sizeof(id)];
	memset(id_sentinel, 0x5a, sizeof(id_sentinel));
	memset(id, 0x5a, sizeof(id));
	trx = 0xfeedfacecafebeefULL;
	ok(!parse_gtid_for_routing(nullptr, id, sizeof(id), &trx)
	       && trx == 0xfeedfacecafebeefULL && memcmp(id, id_sentinel, sizeof(id)) == 0,
	   "routing rejects null gtid without changing outputs");
	memset(id, 0x5a, sizeof(id));
	trx = 0xfeedfacecafebeefULL;
	ok(!parse_gtid_for_routing("0-1-100", nullptr, sizeof(id), &trx)
	       && trx == 0xfeedfacecafebeefULL && memcmp(id, id_sentinel, sizeof(id)) == 0,
	   "routing rejects null id buffer without changing outputs");
	memset(id, 0x5a, sizeof(id));
	trx = 0xfeedfacecafebeefULL;
	ok(!parse_gtid_for_routing("0-1-100", id, 0, &trx)
	       && trx == 0xfeedfacecafebeefULL && memcmp(id, id_sentinel, sizeof(id)) == 0,
	   "routing rejects zero id buffer length without changing outputs");
	memset(id, 0x5a, sizeof(id));
	trx = 0xfeedfacecafebeefULL;
	struct {
		char id[1];
		char guard;
	} small = { { 0x5a }, 0x5a };
	ok(!parse_gtid_for_routing("0-1-100", small.id, sizeof(small.id), &trx)
	       && trx == 0xfeedfacecafebeefULL && small.id[0] == 0x5a && small.guard == 0x5a,
	   "routing rejects a too-small id buffer without overflow");

	const char bounded_gtid[] = "0-1-100junk";
	ok(parse_gtid(bounded_gtid, 7, &p) && p.id == "0" && p.trxid == 100,
	   "bounded parser accepts exactly supplied length");

	std::unordered_map<std::string, std::string> sysvars;
	char session_gtid[128] = {0};
	const char mysql_gtid[] = "aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:42";
	ok(select_session_gtid(mysql_gtid, strlen(mysql_gtid), sysvars,
	                       session_gtid, sizeof(session_gtid))
	       && strcmp(session_gtid, mysql_gtid) == 0,
	   "select session GTID copies MySQL payload");

	memset(session_gtid, 0, sizeof(session_gtid));
	sysvars["gtid_binlog_pos"] = "0-1-100";
	ok(select_session_gtid(nullptr, 0, sysvars,
	                       session_gtid, sizeof(session_gtid))
	       && strcmp(session_gtid, "0-1-100") == 0,
	   "select session GTID copies MariaDB binlog position");

	memset(session_gtid, 0, sizeof(session_gtid));
	sysvars["gtid_current_pos"] = "0-1-99";
	ok(select_session_gtid(nullptr, 0, sysvars,
	                       session_gtid, sizeof(session_gtid))
	       && strcmp(session_gtid, "0-1-100") == 0,
	   "select session GTID prefers binlog position");

	strcpy(session_gtid, "0-1-100");
	ok(!select_session_gtid(nullptr, 0, sysvars,
	                        session_gtid, sizeof(session_gtid)),
	   "select session GTID rejects unchanged value");

	char unchanged[sizeof(session_gtid)];
	memset(unchanged, 0x5a, sizeof(unchanged));
	char unchanged_before[sizeof(unchanged)];
	memcpy(unchanged_before, unchanged, sizeof(unchanged));
	sysvars.clear();
	ok(!select_session_gtid(nullptr, 0, sysvars,
	                        unchanged, sizeof(unchanged))
	       && memcmp(unchanged, unchanged_before, sizeof(unchanged)) == 0,
	   "select session GTID leaves buffer unchanged without a value");

	test_session_tracking_reset();
	test_cleanup_minimal();
	return exit_status();
}
