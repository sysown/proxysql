#include "tap.h"
#include "proxysql_gtid.h"

int main() {
	plan(16);
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
	return exit_status();
}
