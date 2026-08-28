/**
 * mysqlx_route_store_unit-t.cpp
 *
 * Unit tests for route selection strategies (first_available, round_robin,
 * round_robin_with_fallback) in MysqlxConfigStore.
 */

#include "mysqlx_config_store.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "sqlite3db.h"
#include "tap.h"

#include <memory>
#include <set>
#include <string>

namespace {

void create_runtime_tables(SQLite3DB& db) {
	// Use the canonical Admin definitions for runtime_mysql_users and
	// runtime_mysql_servers. install_all_from_admin SELECTs columns
	// (e.g. password, weight, status) that an ad-hoc minimal schema
	// would omit, breaking every assertion in this file.
	db.execute(ADMIN_SQLITE_RUNTIME_MYSQL_USERS);
	db.execute(ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS);
	db.execute(
		"CREATE TABLE mysqlx_users ("
		" username VARCHAR PRIMARY KEY, active INT DEFAULT 1,"
		" require_tls INT DEFAULT 0, allowed_auth_methods VARCHAR DEFAULT '',"
		" default_route VARCHAR, policy_profile VARCHAR,"
		" backend_auth_mode VARCHAR DEFAULT 'mapped',"
		" backend_username VARCHAR, backend_password VARCHAR,"
		" attributes VARCHAR DEFAULT '', comment VARCHAR DEFAULT '')"
	);
	db.execute(
		"CREATE TABLE mysqlx_routes ("
		" name VARCHAR PRIMARY KEY, bind VARCHAR,"
		" destination_hostgroup INT, fallback_hostgroup INT,"
		" strategy VARCHAR DEFAULT 'first_available',"
		" active INT DEFAULT 1, attributes VARCHAR DEFAULT '',"
		" comment VARCHAR DEFAULT '')"
	);
	db.execute(
		"CREATE TABLE mysqlx_backend_endpoints ("
		" hostname VARCHAR, mysql_port INT, mysqlx_port INT DEFAULT 33060,"
		" use_ssl INT DEFAULT 0, attributes VARCHAR DEFAULT '',"
		" comment VARCHAR DEFAULT '',"
		" PRIMARY KEY (hostname, mysql_port))"
	);
	db.execute(
		"CREATE TABLE mysqlx_variables ("
		" variable_name VARCHAR PRIMARY KEY, variable_value VARCHAR DEFAULT '')"
	);
}

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(26);
	diag("=== mysqlx_route_store_unit-t starting ===");

	// ====== Original tests (1-8) ======

	SQLite3DB db;
	db.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
	create_runtime_tables(db);

	db.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) "
	           "VALUES (10, 'db-a', 3306, 0, 'ONLINE')");
	db.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) "
	           "VALUES (10, 'db-b', 3306, 0, 'ONLINE')");
	db.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) "
	           "VALUES (20, 'db-c', 3306, 0, 'ONLINE')");

	db.execute("INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port) "
	           "VALUES ('db-a', 3306, 33060)");
	db.execute("INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port) "
	           "VALUES ('db-b', 3306, 33061)");
	db.execute("INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port) "
	           "VALUES ('db-c', 3306, 33062)");

	db.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) "
	           "VALUES ('fa_route', '127.0.0.1:6603', 10, 'first_available', 1)");
	db.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) "
	           "VALUES ('rr_route', '127.0.0.1:6604', 10, 'round_robin', 1)");
	db.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active) "
	           "VALUES ('rr_fb_route', '127.0.0.1:6605', 99, 20, 'round_robin_with_fallback', 1)");

	MysqlxConfigStore store;
	std::string err {};
	ok(store.install_all_from_admin(db, err), "install_all_from_admin succeeds");

	{
		auto ep1 = store.pick_endpoint("fa_route");
		auto ep2 = store.pick_endpoint("fa_route");
		ok(ep1.hostname == "db-a" && ep2.hostname == "db-a",
		   "first_available always picks first endpoint");
	}

	{
		auto ep1 = store.pick_endpoint("rr_route");
		auto ep2 = store.pick_endpoint("rr_route");
		ok(ep1.hostname != ep2.hostname,
		   "round_robin alternates between endpoints");
		ok(ep1.hostname == "db-a" || ep1.hostname == "db-b",
		   "round_robin returns valid endpoint from hostgroup");
	}

	{
		auto ep = store.pick_endpoint("rr_fb_route");
		ok(ep.hostname == "db-c",
		   "round_robin_with_fallback uses fallback hostgroup");
		ok(ep.mysqlx_port == 33062,
		   "fallback endpoint has correct mysqlx_port override");
	}

	{
		auto ep = store.pick_endpoint("nonexistent_route");
		ok(ep.hostname.empty(), "unknown route returns empty endpoint");
	}

	{
		auto ep = store.pick_endpoint("fa_route");
		ok(ep.mysqlx_port == 33060, "X port override applied from endpoint table");
	}

	// ====== Round-robin thorough (tests 9-14) ======

	{
		SQLite3DB db3;
		db3.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(db3);
		db3.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (30, 'rr-a', 3306, 0, 'ONLINE')");
		db3.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (30, 'rr-b', 3306, 0, 'ONLINE')");
		db3.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (30, 'rr-c', 3306, 0, 'ONLINE')");
		db3.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('rr3', '127.0.0.1:6606', 30, 'round_robin', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(db3, err);

		std::set<std::string> seen;
		for (int i = 0; i < 6; i++) {
			seen.insert(s.pick_endpoint("rr3").hostname);
		}
		ok(seen.size() == 3,
		   "round_robin with 3 endpoints cycles through all 3");
	}

	{
		SQLite3DB dbw;
		dbw.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbw);
		dbw.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (31, 'w-a', 3306, 0, 'ONLINE')");
		dbw.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (31, 'w-b', 3306, 0, 'ONLINE')");
		dbw.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('rr_wrap', '127.0.0.1:6607', 31, 'round_robin', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbw, err);

		auto first = s.pick_endpoint("rr_wrap");
		s.pick_endpoint("rr_wrap");
		auto third = s.pick_endpoint("rr_wrap");
		ok(first.hostname == third.hostname,
		   "round_robin wraps back to first after visiting all");
	}

	{
		SQLite3DB dbphg;
		dbphg.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbphg);
		dbphg.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (10, 'hg10-a', 3306, 0, 'ONLINE')");
		dbphg.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (10, 'hg10-b', 3306, 0, 'ONLINE')");
		dbphg.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (20, 'hg20-a', 3306, 0, 'ONLINE')");
		dbphg.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (20, 'hg20-b', 3306, 0, 'ONLINE')");
		dbphg.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('rr_hg10', '127.0.0.1:6610', 10, 'round_robin', 1)");
		dbphg.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('rr_hg20', '127.0.0.1:6620', 20, 'round_robin', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbphg, err);

		auto hg10_first = s.pick_endpoint("rr_hg10");
		s.pick_endpoint("rr_hg10");
		auto hg20_first = s.pick_endpoint("rr_hg20");
		auto hg10_third = s.pick_endpoint("rr_hg10");
		ok(hg10_third.hostname == hg10_first.hostname && hg20_first.hostname != hg10_first.hostname,
		   "round_robin counter is per-hostgroup: each HG rotates independently");
	}

	{
		SQLite3DB dbs;
		dbs.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbs);
		dbs.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (32, 'single', 3306, 0, 'ONLINE')");
		dbs.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('rr_single', '127.0.0.1:6608', 32, 'round_robin', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbs, err);

		auto ep1 = s.pick_endpoint("rr_single");
		auto ep2 = s.pick_endpoint("rr_single");
		auto ep3 = s.pick_endpoint("rr_single");
		ok(ep1.hostname == "single" && ep2.hostname == "single" && ep3.hostname == "single",
		   "round_robin with 1 endpoint always returns same");
	}

	{
		SQLite3DB dbfa3;
		dbfa3.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbfa3);
		dbfa3.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (33, 'fa-a', 3306, 0, 'ONLINE')");
		dbfa3.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (33, 'fa-b', 3306, 0, 'ONLINE')");
		dbfa3.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (33, 'fa-c', 3306, 0, 'ONLINE')");
		dbfa3.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('fa3', '127.0.0.1:6609', 33, 'first_available', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbfa3, err);

		bool all_same = true;
		for (int i = 0; i < 5; i++) {
			if (s.pick_endpoint("fa3").hostname != "fa-a") all_same = false;
		}
		ok(all_same, "first_available with 3 endpoints always returns first");
	}

	{
		SQLite3DB dbmix;
		dbmix.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbmix);
		dbmix.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (34, 'mix-a', 3306, 0, 'ONLINE')");
		dbmix.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (34, 'mix-b', 3306, 0, 'ONLINE')");
		dbmix.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('mix_rr', '127.0.0.1:6611', 34, 'round_robin', 1)");
		dbmix.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('mix_fa', '127.0.0.1:6612', 34, 'first_available', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbmix, err);

		s.pick_endpoint("mix_rr");
		s.pick_endpoint("mix_rr");
		bool fa_always_first = true;
		for (int i = 0; i < 3; i++) {
			if (s.pick_endpoint("mix_fa").hostname != "mix-a") fa_always_first = false;
		}
		ok(fa_always_first,
		   "first_available always returns first regardless of round_robin state");
	}

	// ====== Fallback (tests 15-18) ======

	{
		SQLite3DB dbfb;
		dbfb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbfb);
		dbfb.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (40, 'primary-srv', 3306, 0, 'ONLINE')");
		dbfb.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (41, 'fallback-srv', 3306, 0, 'ONLINE')");
		dbfb.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active) VALUES ('fb_primary', '127.0.0.1:6613', 40, 41, 'first_available', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbfb, err);

		ok(s.pick_endpoint("fb_primary").hostname == "primary-srv",
		   "primary has servers, fallback exists - returns from primary");
	}

	{
		SQLite3DB dbfb2;
		dbfb2.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbfb2);
		dbfb2.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (50, 'fb-only', 3306, 0, 'ONLINE')");
		dbfb2.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active) VALUES ('fb_fallback', '127.0.0.1:6614', 42, 50, 'first_available', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbfb2, err);

		ok(s.pick_endpoint("fb_fallback").hostname == "fb-only",
		   "primary empty, fallback has servers - returns from fallback");
	}

	{
		SQLite3DB dbfb3;
		dbfb3.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbfb3);
		dbfb3.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active) VALUES ('fb_none', '127.0.0.1:6615', 43, 44, 'first_available', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbfb3, err);

		ok(s.pick_endpoint("fb_none").hostname.empty(),
		   "primary empty, fallback empty - returns empty");
	}

	{
		SQLite3DB dbrrfb;
		dbrrfb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbrrfb);
		dbrrfb.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (45, 'rr-pri', 3306, 0, 'ONLINE')");
		dbrrfb.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (46, 'rr-fb', 3306, 0, 'ONLINE')");
		dbrrfb.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active) VALUES ('rrfb_pri', '127.0.0.1:6616', 45, 46, 'round_robin_with_fallback', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbrrfb, err);

		ok(s.pick_endpoint("rrfb_pri").hostname == "rr-pri",
		   "round_robin_with_fallback when primary has servers does NOT use fallback");
	}

	// ====== Inactive routes (tests 19-21) ======

	{
		SQLite3DB dbia;
		dbia.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbia);
		dbia.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (50, 'ia-srv', 3306, 0, 'ONLINE')");
		dbia.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('inactive_route', '127.0.0.1:6617', 50, 'first_available', 0)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbia, err);

		ok(s.pick_endpoint("inactive_route").hostname.empty(),
		   "route with active=0 is not loaded - pick_endpoint returns empty");
	}

	{
		SQLite3DB dbia2;
		dbia2.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbia2);
		dbia2.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (51, 'ia-srv1', 3306, 0, 'ONLINE')");
		dbia2.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (52, 'ia-srv2', 3306, 0, 'ONLINE')");
		dbia2.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('active_route', '127.0.0.1:6618', 51, 'first_available', 1)");
		dbia2.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('inactive_route2', '127.0.0.1:6619', 52, 'first_available', 0)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbia2, err);

		ok(s.pick_endpoint("active_route").hostname == "ia-srv1" &&
		   s.pick_endpoint("inactive_route2").hostname.empty(),
		   "only active route is resolvable when mixed with inactive");
	}

	{
		SQLite3DB dbia3;
		dbia3.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbia3);
		dbia3.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (53, 'ia-srv3', 3306, 0, 'ONLINE')");
		dbia3.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('all_off1', '127.0.0.1:6620', 53, 'first_available', 0)");
		dbia3.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('all_off2', '127.0.0.1:6621', 53, 'round_robin', 0)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbia3, err);

		ok(s.pick_endpoint("all_off1").hostname.empty() &&
		   s.pick_endpoint("all_off2").hostname.empty(),
		   "all routes inactive - pick_endpoint returns empty for all");
	}

	// ====== Endpoint overrides (tests 22-24) ======

	{
		SQLite3DB dbeo;
		dbeo.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbeo);
		dbeo.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (60, 'eo-srv', 3306, 0, 'ONLINE')");
		dbeo.execute("INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port, use_ssl) VALUES ('eo-srv', 3306, 33070, 0)");
		dbeo.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('eo_port', '127.0.0.1:6622', 60, 'first_available', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbeo, err);

		ok(s.pick_endpoint("eo_port").mysqlx_port == 33070,
		   "endpoint with custom mysqlx_port override has mysqlx_port=33070");
	}

	{
		SQLite3DB dbss;
		dbss.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbss);
		dbss.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (61, 'ssl-srv', 3306, 0, 'ONLINE')");
		dbss.execute("INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port, use_ssl) VALUES ('ssl-srv', 3306, 33060, 1)");
		dbss.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('eo_ssl', '127.0.0.1:6623', 61, 'first_available', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbss, err);

		ok(s.pick_endpoint("eo_ssl").use_ssl == true,
		   "endpoint with use_ssl=1 override has use_ssl=true");
	}

	{
		SQLite3DB dbdef;
		dbdef.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbdef);
		dbdef.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (62, 'def-srv', 3306, 0, 'ONLINE')");
		dbdef.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('eo_def', '127.0.0.1:6624', 62, 'first_available', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbdef, err);

		auto ep = s.pick_endpoint("eo_def");
		ok(ep.mysqlx_port == 33060 && ep.use_ssl == false,
		   "endpoint with no override defaults to mysqlx_port=33060, use_ssl=false");
	}

	// ====== Multiple routes (tests 25-26) ======

	{
		SQLite3DB dbmr;
		dbmr.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbmr);
		dbmr.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (70, 'mr-a', 3306, 0, 'ONLINE')");
		dbmr.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (71, 'mr-b', 3306, 0, 'ONLINE')");
		dbmr.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('mr_r1', '127.0.0.1:6625', 70, 'first_available', 1)");
		dbmr.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('mr_r2', '127.0.0.1:6626', 71, 'first_available', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbmr, err);

		ok(s.pick_endpoint("mr_r1").hostname == "mr-a" &&
		   s.pick_endpoint("mr_r2").hostname == "mr-b",
		   "two routes pointing to different hostgroups each picks from correct hostgroup");
	}

	{
		SQLite3DB dbss2;
		dbss2.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);  // NOSONAR: SQLite3DB::open requires non-const char*
		create_runtime_tables(dbss2);
		dbss2.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (80, 'ss-a', 3306, 0, 'ONLINE')");
		dbss2.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) VALUES (80, 'ss-b', 3306, 0, 'ONLINE')");
		dbss2.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('ss_rr', '127.0.0.1:6627', 80, 'round_robin', 1)");
		dbss2.execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy, active) VALUES ('ss_fa', '127.0.0.1:6628', 80, 'first_available', 1)");

		MysqlxConfigStore s;
		s.install_all_from_admin(dbss2, err);

		auto rr1 = s.pick_endpoint("ss_rr");
		auto rr2 = s.pick_endpoint("ss_rr");
		bool fa_always = true;
		for (int i = 0; i < 3; i++) {
			if (s.pick_endpoint("ss_fa").hostname != "ss-a") fa_always = false;
		}
		ok(rr1.hostname != rr2.hostname && fa_always,
		   "two routes same hostgroup different strategies work independently");
	}

	return exit_status();
}
