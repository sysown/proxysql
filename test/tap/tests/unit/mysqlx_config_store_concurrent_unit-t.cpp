#include "mysqlx_config_store.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "sqlite3db.h"
#include "tap.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

const char kMysqlxUsersDdl[] =
	"CREATE TABLE mysqlx_users ("
	" username VARCHAR NOT NULL PRIMARY KEY,"
	" active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,"
	" require_tls INT CHECK (require_tls IN (0,1)) NOT NULL DEFAULT 0,"
	" allowed_auth_methods VARCHAR NOT NULL DEFAULT '',"
	" default_route VARCHAR,"
	" policy_profile VARCHAR,"
	" backend_auth_mode VARCHAR NOT NULL DEFAULT 'mapped',"
	" backend_username VARCHAR,"
	" backend_password VARCHAR,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT ''"
	" )";

const char kMysqlxRoutesDdl[] =
	"CREATE TABLE mysqlx_routes ("
	" name VARCHAR NOT NULL PRIMARY KEY,"
	" bind VARCHAR NOT NULL,"
	" destination_hostgroup INT NOT NULL,"
	" fallback_hostgroup INT,"
	" strategy VARCHAR NOT NULL DEFAULT 'first_available',"
	" active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT ''"
	" )";

const char kMysqlxEndpointsDdl[] =
	"CREATE TABLE mysqlx_backend_endpoints ("
	" hostname VARCHAR NOT NULL,"
	" mysql_port INT NOT NULL,"
	" mysqlx_port INT NOT NULL DEFAULT 33060,"
	" use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT '',"
	" PRIMARY KEY (hostname, mysql_port)"
	" )";

// install_variables_from_admin queries mysqlx_variables. Without the
// table, fetch_result returns false and install short-circuits before
// swapping in the newly-loaded identities/routes — every assertion that
// depends on data actually being loaded silently fails. This DDL matches
// the one in mysqlx_admin_schema.cpp.
const char kMysqlxVariablesDdl[] =
	"CREATE TABLE mysqlx_variables ("
	" variable_name VARCHAR NOT NULL PRIMARY KEY,"
	" variable_value VARCHAR NOT NULL DEFAULT ''"
	" )";

std::unique_ptr<SQLite3DB> create_runtime_db() {
	auto db = std::make_unique<SQLite3DB>();
	db->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	db->execute(ADMIN_SQLITE_RUNTIME_MYSQL_USERS);
	db->execute(ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS);
	db->execute(kMysqlxUsersDdl);
	db->execute(kMysqlxRoutesDdl);
	db->execute(kMysqlxEndpointsDdl);
	db->execute(kMysqlxVariablesDdl);
	return db;
}

void insert_user(SQLite3DB& db, const std::string& username, int hostgroup, int max_conn = 10000) {
	char sql[512];
	snprintf(sql, sizeof(sql),
		"INSERT INTO runtime_mysql_users "
		"(username, password, active, use_ssl, default_hostgroup, "
		"default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, "
		"max_connections, attributes, comment) VALUES "
		"('%s', 'pw', 1, 0, %d, NULL, 0, 1, 0, 0, 1, %d, '', '')",
		username.c_str(), hostgroup, max_conn);
	db.execute(sql);
}

void insert_mysqlx_user(SQLite3DB& db, const std::string& username, const std::string& default_route = "") {
	char sql[512];
	snprintf(sql, sizeof(sql),
		"INSERT INTO mysqlx_users "
		"(username, active, require_tls, allowed_auth_methods, "
		"default_route, policy_profile, backend_auth_mode, backend_username, backend_password, attributes, comment) VALUES "
		"('%s', 1, 0, 'PLAIN', '%s', '', 'mapped', NULL, NULL, '', '')",
		username.c_str(), default_route.c_str());
	db.execute(sql);
}

void insert_route(SQLite3DB& db, const std::string& name, int hg, const std::string& strategy = "first_available") {
	char sql[512];
	snprintf(sql, sizeof(sql),
		"INSERT INTO mysqlx_routes "
		"(name, bind, destination_hostgroup, fallback_hostgroup, strategy, active, attributes, comment) VALUES "
		"('%s', '127.0.0.1:6603', %d, -1, '%s', 1, '', '')",
		name.c_str(), hg, strategy.c_str());
	db.execute(sql);
}

void insert_server(SQLite3DB& db, int hg, const std::string& hostname, int port) {
	char sql[512];
	snprintf(sql, sizeof(sql),
		"INSERT INTO runtime_mysql_servers "
		"(hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, "
		"max_replication_lag, use_ssl, max_latency_ms, comment) VALUES "
		"(%d, '%s', %d, 0, 'ONLINE', 100, 0, 1000, 0, 0, 0, '')",
		hg, hostname.c_str(), port);
	db.execute(sql);
}

void insert_endpoint(SQLite3DB& db, const std::string& hostname, int port, int mysqlx_port = 33060) {
	char sql[512];
	snprintf(sql, sizeof(sql),
		"INSERT INTO mysqlx_backend_endpoints "
		"(hostname, mysql_port, mysqlx_port, use_ssl, attributes, comment) VALUES "
		"('%s', %d, %d, 0, '', '')",
		hostname.c_str(), port, mysqlx_port);
	db.execute(sql);
}

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(15);
	diag("=== mysqlx_config_store_concurrent_unit-t starting ===");

	// === Concurrent reads during load (5) ===

	{
		auto db = create_runtime_db();
		insert_user(*db, "alice", 10);
		insert_mysqlx_user(*db, "alice", "rw");
		insert_route(*db, "rw", 10);
		insert_server(*db, 10, "db1.test", 3306);
		insert_endpoint(*db, "db1.test", 3306);

		MysqlxConfigStore store;
		std::string err;

		std::atomic<bool> load_done { false };
		std::thread loader([&]() {
			store.install_all_from_admin(*db, err);
			load_done.store(true);
		});
		std::thread reader([&]() {
			while (!load_done.load()) {
				auto r = store.resolve_identity("alice");
			}
		});
		loader.join();
		reader.join();
		ok(true, "resolve_identity during install_all_from_admin: no crash");
	}
	{
		auto db = create_runtime_db();
		insert_user(*db, "alice", 10);
		insert_mysqlx_user(*db, "alice", "rw");
		insert_route(*db, "rw", 10);
		insert_server(*db, 10, "db1.test", 3306);
		insert_endpoint(*db, "db1.test", 3306);

		MysqlxConfigStore store;
		std::string err;

		std::atomic<bool> load_done { false };
		std::thread loader([&]() {
			store.install_all_from_admin(*db, err);
			load_done.store(true);
		});
		std::thread picker([&]() {
			while (!load_done.load()) {
				auto ep = store.pick_endpoint("rw");
			}
		});
		loader.join();
		picker.join();
		ok(true, "pick_endpoint during install_all_from_admin: no crash");
	}
	{
		auto db = create_runtime_db();
		insert_user(*db, "alice", 10);
		insert_mysqlx_user(*db, "alice", "rw");

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);

		std::vector<std::thread> threads;
		for (int t = 0; t < 4; ++t) {
			threads.emplace_back([&store]() {
				for (int i = 0; i < 1000; ++i) {
					auto r = store.resolve_identity("alice");
				}
			});
		}
		for (auto& t : threads) t.join();
		ok(true, "4 threads x 1000 resolve_identity: no crash");
	}
	{
		auto db1 = create_runtime_db();
		insert_user(*db1, "alice", 10);
		insert_mysqlx_user(*db1, "alice", "rw");

		auto db2 = create_runtime_db();
		insert_user(*db2, "bob", 20);
		insert_mysqlx_user(*db2, "bob", "ro");

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db1, err);
		bool alice_found = store.resolve_identity("alice").has_value();

		store.install_all_from_admin(*db2, err);
		bool alice_gone = !store.resolve_identity("alice").has_value();
		bool bob_found = store.resolve_identity("bob").has_value();
		ok(alice_found && alice_gone && bob_found,
		   "sequential load: second call completely replaces first");
	}
	{
		auto db = create_runtime_db();
		insert_user(*db, "alice", 10);
		insert_mysqlx_user(*db, "alice", "rw");

		MysqlxConfigStore store;
		std::string err;
		std::mutex load_mutex;

		auto do_load = [&]() {
			std::lock_guard<std::mutex> lk(load_mutex);
			store.install_all_from_admin(*db, err);
		};

		std::vector<std::thread> threads;
		for (int t = 0; t < 2; ++t) {
			threads.emplace_back(do_load);
		}
		for (auto& t : threads) t.join();
		ok(true, "concurrent resolve_identity with serialized loads: no crash");
	}

	// === Concurrent endpoint picking (5) ===

	{
		auto db = create_runtime_db();
		insert_user(*db, "alice", 10);
		insert_route(*db, "rw", 10);
		insert_server(*db, 10, "db1.test", 3306);
		insert_endpoint(*db, "db1.test", 3306);

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);

		std::vector<std::thread> threads;
		for (int t = 0; t < 4; ++t) {
			threads.emplace_back([&store]() {
				for (int i = 0; i < 1000; ++i) {
					auto ep = store.pick_endpoint("rw");
				}
			});
		}
		for (auto& t : threads) t.join();
		ok(true, "4 threads x 1000 pick_endpoint: no crash");
	}
	{
		auto db = create_runtime_db();
		insert_route(*db, "rr", 10, "round_robin");
		insert_server(*db, 10, "db1.test", 3306);
		insert_server(*db, 10, "db2.test", 3306);
		insert_endpoint(*db, "db1.test", 3306);
		insert_endpoint(*db, "db2.test", 3306);

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);

		std::vector<std::thread> threads;
		for (int t = 0; t < 4; ++t) {
			threads.emplace_back([&store]() {
				for (int i = 0; i < 1000; ++i) {
					auto ep = store.pick_endpoint("rr");
				}
			});
		}
		for (auto& t : threads) t.join();
		ok(true, "4 threads round_robin pick_endpoint: no crash");
	}
	{
		auto db_a = create_runtime_db();
		insert_route(*db_a, "rw", 10);
		insert_server(*db_a, 10, "db1.test", 3306);
		insert_endpoint(*db_a, "db1.test", 3306);

		auto db_b = create_runtime_db();
		insert_route(*db_b, "rw", 20);
		insert_server(*db_b, 20, "db2.test", 3306);
		insert_endpoint(*db_b, "db2.test", 3306);

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db_a, err);

		std::atomic<bool> done { false };
		std::thread loader([&]() {
			store.install_all_from_admin(*db_b, err);
			done.store(true);
		});
		std::thread picker([&]() {
			while (!done.load()) {
				auto ep = store.pick_endpoint("rw");
			}
		});
		loader.join();
		picker.join();
		ok(true, "pick_endpoint while load replaces routes: no crash");
	}
	{
		MysqlxConfigStore store;
		std::atomic<bool> done { false };
		std::thread bumper([&store, &done]() {
			for (int i = 0; i < 100; ++i)
				store.bump_topology_generation();
			done.store(true);
		});
		std::thread reader([&store, &done]() {
			while (!done.load()) {
				volatile uint64_t g = store.topology_generation();
				(void)g;
			}
		});
		bumper.join();
		reader.join();
		ok(store.topology_generation() >= 100,
		   "topology_generation >= 100 after 100 bumps");
	}
	{
		auto db = create_runtime_db();
		insert_route(*db, "rw", 10);
		insert_server(*db, 10, "db1.test", 3306);
		insert_endpoint(*db, "db1.test", 3306);

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);

		std::vector<std::thread> threads;
		for (int t = 0; t < 10; ++t) {
			threads.emplace_back([&store]() {
				for (int i = 0; i < 1000; ++i) {
					auto ep = store.pick_endpoint("rw");
				}
			});
		}
		for (auto& t : threads) t.join();
		ok(true, "10 threads x 1000 pick_endpoint stress: no crash, no hang");
	}

	// === Data consistency after reload (5) ===

	{
		auto db_a = create_runtime_db();
		insert_user(*db_a, "alice", 10);
		insert_mysqlx_user(*db_a, "alice", "rw");

		auto db_b = create_runtime_db();

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db_a, err);
		auto r1 = store.resolve_identity("alice");
		store.install_all_from_admin(*db_b, err);
		auto r2 = store.resolve_identity("alice");
		ok(r1.has_value() && !r2.has_value(),
		   "load A has alice, load B empty: data replaced atomically");
	}
	{
		auto db_a = create_runtime_db();
		insert_route(*db_a, "rw", 10);
		insert_server(*db_a, 10, "db1.test", 3306);
		insert_endpoint(*db_a, "db1.test", 3306);

		auto db_b = create_runtime_db();
		insert_route(*db_b, "rw", 20);

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db_a, err);
		auto ep1 = store.pick_endpoint("rw");
		store.install_all_from_admin(*db_b, err);
		auto ep2 = store.pick_endpoint("rw");
		ok(!ep1.hostname.empty() && ep2.hostname.empty(),
		   "load A has servers, load B empty HG: complete swap");
	}
	{
		auto db_a = create_runtime_db();
		insert_route(*db_a, "R1", 1);
		insert_route(*db_a, "R2", 2);
		insert_server(*db_a, 1, "db1.test", 3306);
		insert_endpoint(*db_a, "db1.test", 3306);

		auto db_b = create_runtime_db();
		insert_route(*db_b, "R2", 2);
		insert_route(*db_b, "R3", 3);
		insert_server(*db_b, 3, "db3.test", 3306);
		insert_endpoint(*db_b, "db3.test", 3306);

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db_a, err);
		store.install_all_from_admin(*db_b, err);
		auto ep_r1 = store.pick_endpoint("R1");
		auto ep_r3 = store.pick_endpoint("R3");
		ok(ep_r1.hostname.empty() && !ep_r3.hostname.empty(),
		   "R1 gone, R3 present after load swap");
	}
	{
		auto db_a = create_runtime_db();
		insert_route(*db_a, "rw", 10);
		insert_server(*db_a, 10, "db1.test", 3306);
		insert_endpoint(*db_a, "db1.test", 3306);

		auto db_b = create_runtime_db();
		insert_route(*db_b, "rw", 10);

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db_a, err);
		auto ep1 = store.pick_endpoint("rw");
		store.install_all_from_admin(*db_b, err);
		auto ep2 = store.pick_endpoint("rw");
		ok(!ep1.hostname.empty() && ep2.hostname.empty(),
		   "HG with servers then same HG empty: endpoint goes empty");
	}
	{
		auto db = create_runtime_db();
		insert_route(*db, "rr", 10, "round_robin");
		insert_server(*db, 10, "db1.test", 3306);
		insert_server(*db, 10, "db2.test", 3307);
		insert_endpoint(*db, "db1.test", 3306);
		insert_endpoint(*db, "db2.test", 3307);

		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);

		auto ep1 = store.pick_endpoint("rr");
		auto ep2 = store.pick_endpoint("rr");

		store.install_all_from_admin(*db, err);

		auto ep3 = store.pick_endpoint("rr");
		auto ep4 = store.pick_endpoint("rr");
		ok(!ep1.hostname.empty() && !ep2.hostname.empty() &&
		   !ep3.hostname.empty() && !ep4.hostname.empty(),
		   "pick_endpoint after reload: no crash, valid endpoints");
	}

	return exit_status();
}
