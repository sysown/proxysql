/**
 * mysqlx_route_store_unit-t.cpp
 *
 * Unit tests for route selection strategies (first_available, round_robin,
 * round_robin_with_fallback) in MysqlxConfigStore.
 */

#include "mysqlx_config_store.h"
#include "sqlite3db.h"
#include "tap.h"

#include <memory>
#include <string>

namespace {

void create_runtime_tables(SQLite3DB& db) {
	db.execute(
		"CREATE TABLE runtime_mysql_users ("
		" username VARCHAR, default_hostgroup INT, max_connections INT,"
		" active INT DEFAULT 1, frontend INT DEFAULT 1)"
	);
	db.execute(
		"CREATE TABLE runtime_mysql_servers ("
		" hostgroup_id INT, hostname VARCHAR, port INT, use_ssl INT,"
		" status VARCHAR DEFAULT 'ONLINE', weight INT DEFAULT 1)"
	);
	db.execute(
		"CREATE TABLE runtime_mysqlx_users ("
		" username VARCHAR PRIMARY KEY, active INT DEFAULT 1,"
		" require_tls INT DEFAULT 0, allowed_auth_methods VARCHAR DEFAULT '',"
		" default_route VARCHAR, policy_profile VARCHAR,"
		" backend_auth_mode VARCHAR DEFAULT 'mapped',"
		" backend_username VARCHAR, backend_password VARCHAR,"
		" attributes VARCHAR DEFAULT '')"
	);
	db.execute(
		"CREATE TABLE runtime_mysqlx_routes ("
		" name VARCHAR PRIMARY KEY, bind VARCHAR,"
		" destination_hostgroup INT, fallback_hostgroup INT,"
		" strategy VARCHAR DEFAULT 'first_available',"
		" active INT DEFAULT 1, attributes VARCHAR DEFAULT '')"
	);
	db.execute(
		"CREATE TABLE runtime_mysqlx_backend_endpoints ("
		" hostname VARCHAR, mysql_port INT, mysqlx_port INT DEFAULT 33060,"
		" use_ssl INT DEFAULT 0, attributes VARCHAR DEFAULT '',"
		" PRIMARY KEY (hostname, mysql_port))"
	);
}

} // namespace

int main() {
	plan(8);

	SQLite3DB db;
	db.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	create_runtime_tables(db);

	// Seed two backend servers in hostgroup 10.
	db.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) "
	           "VALUES (10, 'db-a', 3306, 0, 'ONLINE')");
	db.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) "
	           "VALUES (10, 'db-b', 3306, 0, 'ONLINE')");
	// One server in fallback hostgroup 20.
	db.execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, use_ssl, status) "
	           "VALUES (20, 'db-c', 3306, 0, 'ONLINE')");

	// X port overrides.
	db.execute("INSERT INTO runtime_mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port) "
	           "VALUES ('db-a', 3306, 33060)");
	db.execute("INSERT INTO runtime_mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port) "
	           "VALUES ('db-b', 3306, 33061)");
	db.execute("INSERT INTO runtime_mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port) "
	           "VALUES ('db-c', 3306, 33062)");

	// Route: first_available
	db.execute("INSERT INTO runtime_mysqlx_routes (name, bind, destination_hostgroup, strategy, active) "
	           "VALUES ('fa_route', '127.0.0.1:6603', 10, 'first_available', 1)");

	// Route: round_robin
	db.execute("INSERT INTO runtime_mysqlx_routes (name, bind, destination_hostgroup, strategy, active) "
	           "VALUES ('rr_route', '127.0.0.1:6604', 10, 'round_robin', 1)");

	// Route: round_robin_with_fallback (destination=99 which is empty, fallback=20)
	db.execute("INSERT INTO runtime_mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active) "
	           "VALUES ('rr_fb_route', '127.0.0.1:6605', 99, 20, 'round_robin_with_fallback', 1)");

	MysqlxConfigStore store;
	std::string err {};
	ok(store.load_from_runtime(db, err), "load_from_runtime succeeds");

	// Test 2: first_available always returns first server.
	{
		auto ep1 = store.pick_endpoint("fa_route");
		auto ep2 = store.pick_endpoint("fa_route");
		ok(ep1.hostname == "db-a" && ep2.hostname == "db-a",
		   "first_available always picks first endpoint");
	}

	// Test 3-4: round_robin rotates.
	{
		auto ep1 = store.pick_endpoint("rr_route");
		auto ep2 = store.pick_endpoint("rr_route");
		ok(ep1.hostname != ep2.hostname,
		   "round_robin alternates between endpoints");
		ok(ep1.hostname == "db-a" || ep1.hostname == "db-b",
		   "round_robin returns valid endpoint from hostgroup");
	}

	// Test 5: round_robin_with_fallback uses fallback when primary empty.
	{
		auto ep = store.pick_endpoint("rr_fb_route");
		ok(ep.hostname == "db-c",
		   "round_robin_with_fallback uses fallback hostgroup");
		ok(ep.mysqlx_port == 33062,
		   "fallback endpoint has correct mysqlx_port override");
	}

	// Test 7: unknown route returns empty.
	{
		auto ep = store.pick_endpoint("nonexistent_route");
		ok(ep.hostname.empty(), "unknown route returns empty endpoint");
	}

	// Test 8: X port overrides applied correctly.
	{
		auto ep = store.pick_endpoint("fa_route");
		ok(ep.mysqlx_port == 33060, "X port override applied from endpoint table");
	}

	return exit_status();
}
