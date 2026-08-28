#include "mysqlx_config_store.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "sqlite3db.h"
#include "tap.h"

#include <memory>
#include <string>

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

// install_variables_from_admin queries mysqlx_variables. Without the table
// fetch_result returns false and install short-circuits before swapping in
// the newly-loaded routes/identities, silently breaking every scenario in
// this file that depended on data actually being loaded.
const char kMysqlxVariablesDdl[] =
	"CREATE TABLE mysqlx_variables ("
	" variable_name VARCHAR NOT NULL PRIMARY KEY,"
	" variable_value VARCHAR NOT NULL DEFAULT ''"
	" )";

std::unique_ptr<SQLite3DB> create_test_db() {
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

void insert_mysql_user(SQLite3DB& db, const char* username, int hostgroup, int max_conn,
                        int active, int frontend) {
	char sql[1024];
	snprintf(sql, sizeof(sql),
		"INSERT INTO runtime_mysql_users (username, password, active, use_ssl, default_hostgroup, "
		"default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, "
		"max_connections, attributes, comment) VALUES "
		"('%s', 'pw', %d, 0, %d, NULL, 0, 1, 0, 0, %d, %d, '', '')",
		username, active, hostgroup, frontend, max_conn);
	db.execute(sql);
}

void insert_mysqlx_user(SQLite3DB& db, const char* username, const char* auth_mode,
                         const char* route, const char* profile) {
	char sql[1024];
	snprintf(sql, sizeof(sql),
		"INSERT INTO mysqlx_users (username, active, require_tls, allowed_auth_methods, "
		"default_route, policy_profile, backend_auth_mode, backend_username, backend_password, "
		"attributes, comment) VALUES ('%s', 1, 0, '', '%s', '%s', '%s', '', '', '', '')",
		username, route, profile, auth_mode);
	db.execute(sql);
}

void insert_server(SQLite3DB& db, int hostgroup, const char* hostname, int port,
                    const char* status) {
	char sql[1024];
	snprintf(sql, sizeof(sql),
		"INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, gtid_port, status, "
		"weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, "
		"comment) VALUES (%d, '%s', %d, 0, '%s', 100, 0, 1000, 0, 0, 0, '')",
		hostgroup, hostname, port, status);
	db.execute(sql);
}

void insert_endpoint(SQLite3DB& db, const char* hostname, int mysql_port, int mysqlx_port,
                      int use_ssl) {
	char sql[1024];
	snprintf(sql, sizeof(sql),
		"INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port, "
		"use_ssl, attributes, comment) VALUES ('%s', %d, %d, %d, '', '')",
		hostname, mysql_port, mysqlx_port, use_ssl);
	db.execute(sql);
}

void insert_route(SQLite3DB& db, const char* name, int dest_hg, int fallback_hg,
                   const char* strategy, int active) {
	char sql[1024];
	snprintf(sql, sizeof(sql),
		"INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, "
		"fallback_hostgroup, strategy, active, attributes, comment) VALUES "
		"('%s', '127.0.0.1:6603', %d, %d, '%s', %d, '', '')",
		name, dest_hg, fallback_hg, strategy, active);
	db.execute(sql);
}

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(25);
	diag("=== mysqlx_config_store_pure_unit-t starting ===");

	// ====== Backend auth mode parsing (6 assertions) ======

	ok(mysqlx_backend_auth_mode_from_string("mapped") == MysqlxBackendAuthMode::mapped,
	   "auth mode 'mapped' returns mapped");
	ok(mysqlx_backend_auth_mode_from_string("MAPPED") == MysqlxBackendAuthMode::mapped,
	   "auth mode 'MAPPED' returns mapped (case insensitive)");
	ok(mysqlx_backend_auth_mode_from_string("service_account") ==
	   MysqlxBackendAuthMode::service_account,
	   "auth mode 'service_account' returns service_account");
	ok(mysqlx_backend_auth_mode_from_string("pass_through") ==
	   MysqlxBackendAuthMode::pass_through,
	   "auth mode 'pass_through' returns pass_through");
	ok(mysqlx_backend_auth_mode_from_string("unknown_value") ==
	   MysqlxBackendAuthMode::mapped,
	   "auth mode 'unknown_value' defaults to mapped");
	ok(mysqlx_backend_auth_mode_from_string("") == MysqlxBackendAuthMode::mapped,
	   "auth mode empty string defaults to mapped");

	// ====== Identity resolution edge cases (8 assertions) ======

	{
		auto db = create_test_db();
		insert_mysql_user(*db, "alice", 10, 25, 1, 1);
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		ok(!store.resolve_identity("nonexistent_user").has_value(),
		   "resolve_identity returns nullopt for nonexistent user");
	}

	{
		auto db = create_test_db();
		insert_mysql_user(*db, "bob", 5, 100, 1, 1);
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		// install_users_from_admin drops canonical-only users (no mysqlx_users
		// override row) so they have no x_enabled flag and would never
		// authenticate via X anyway. resolve_identity returns nullopt.
		ok(!store.resolve_identity("bob").has_value(),
		   "user in mysql_users but not mysqlx_users is dropped (no x_enabled)");
	}

	{
		auto db = create_test_db();
		insert_mysqlx_user(*db, "orphan", "mapped", "", "");
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		ok(!store.resolve_identity("orphan").has_value(),
		   "user in mysqlx_users but not mysql_users returns nullopt (canonical wins)");
	}

	{
		auto db = create_test_db();
		MysqlxConfigStore store;
		std::string err;
		bool loaded = store.install_all_from_admin(*db, err);
		ok(loaded && err.empty() && !store.resolve_identity("anyone").has_value(),
		   "install_all_from_admin with empty mysql_users returns true, resolve returns nullopt");
	}

	{
		auto db = create_test_db();
		insert_mysql_user(*db, "charlie", 7, 200, 1, 1);
		MysqlxConfigStore store;
		std::string err;
		bool loaded = store.install_all_from_admin(*db, err);
		// install_users_from_admin drops canonical-only users; charlie has
		// no mysqlx_users row so he never gets x_enabled and is filtered out.
		ok(loaded && err.empty() && !store.resolve_identity("charlie").has_value(),
		   "install_all_from_admin with empty mysqlx_users drops canonical-only users");
	}

	{
		auto db = create_test_db();
		insert_mysql_user(*db, "alice", 10, 25, 1, 1);
		insert_mysql_user(*db, "bob", 20, 50, 1, 1);
		insert_mysqlx_user(*db, "alice", "service_account", "rw", "policy-a");
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		auto a = store.resolve_identity("alice");
		auto b = store.resolve_identity("bob");
		// alice has both canonical + mysqlx override; bob is canonical only
		// and gets dropped by install_users_from_admin.
		ok(a.has_value() && a->default_hostgroup == 10 && a->x_enabled &&
		   a->backend_auth_mode == MysqlxBackendAuthMode::service_account &&
		   a->default_route == "rw" && a->policy_profile == "policy-a" &&
		   !b.has_value(),
		   "users with mysqlx override are kept; canonical-only users are dropped");
	}

	{
		auto db = create_test_db();
		insert_mysql_user(*db, "inactive_user", 5, 100, 0, 1);
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		ok(!store.resolve_identity("inactive_user").has_value(),
		   "inactive user (active=0) in mysql_users is excluded");
	}

	{
		auto db = create_test_db();
		insert_mysql_user(*db, "svc_account", 5, 100, 1, 0);
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		ok(!store.resolve_identity("svc_account").has_value(),
		   "backend user (frontend=0) is excluded");
	}

	// ====== Endpoint picking edge cases (7 assertions) ======

	{
		auto db = create_test_db();
		insert_server(*db, 50, "srv1", 3306, "ONLINE");
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		ok(store.pick_endpoint("nonexistent_route").hostname.empty(),
		   "pick_endpoint for nonexistent route returns empty endpoint");
	}

	{
		auto db = create_test_db();
		insert_route(*db, "empty_hg", 999, -1, "first_available", 1);
		insert_server(*db, 999, "shunned_srv", 3306, "SHUNNED");
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		ok(store.pick_endpoint("empty_hg").hostname.empty(),
		   "route whose hostgroup has no online servers returns empty");
	}

	{
		auto db = create_test_db();
		insert_route(*db, "fb_route", 998, 50, "first_available", 1);
		insert_server(*db, 50, "fb_srv", 3306, "ONLINE");
		insert_endpoint(*db, "fb_srv", 3306, 33060, 0);
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		ok(store.pick_endpoint("fb_route").hostname == "fb_srv",
		   "route with fallback uses fallback when primary empty");
	}

	{
		auto db = create_test_db();
		insert_route(*db, "no_fb", 997, -1, "first_available", 1);
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		ok(store.pick_endpoint("no_fb").hostname.empty(),
		   "route with fallback=-1 and empty primary returns empty");
	}

	{
		auto db = create_test_db();
		insert_route(*db, "override_route", 60, -1, "first_available", 1);
		insert_server(*db, 60, "xport_srv", 3306, "ONLINE");
		insert_endpoint(*db, "xport_srv", 3306, 33070, 0);
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		auto ep = store.pick_endpoint("override_route");
		ok(ep.hostname == "xport_srv" && ep.mysqlx_port == 33070,
		   "endpoint with mysqlx_port override uses override");
	}

	{
		auto db = create_test_db();
		insert_route(*db, "default_port", 61, -1, "first_available", 1);
		insert_server(*db, 61, "def_srv", 3306, "ONLINE");
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db, err);
		auto ep = store.pick_endpoint("default_port");
		ok(ep.hostname == "def_srv" && ep.mysqlx_port == 33060,
		   "endpoint with no override defaults to mysqlx_port=33060");
	}

	{
		auto db1 = create_test_db();
		insert_route(*db1, "first_route", 70, -1, "first_available", 1);
		insert_server(*db1, 70, "srv_v1", 3306, "ONLINE");
		MysqlxConfigStore store;
		std::string err;
		store.install_all_from_admin(*db1, err);
		store.install_all_from_admin(*db1, err);
		auto db2 = create_test_db();
		insert_route(*db2, "second_route", 80, -1, "first_available", 1);
		insert_server(*db2, 80, "srv_v2", 3306, "ONLINE");
		store.install_all_from_admin(*db2, err);
		ok(store.pick_endpoint("first_route").hostname.empty() &&
		   store.pick_endpoint("second_route").hostname == "srv_v2",
		   "second install_all_from_admin replaces all data");
	}

	// ====== Topology generation (4 assertions) ======

	{
		MysqlxConfigStore store;
		ok(store.topology_generation() == 0,
		   "topology generation starts at 0");
	}

	{
		MysqlxConfigStore store;
		store.bump_topology_generation();
		ok(store.topology_generation() == 1,
		   "bump_topology_generation increments by 1");
	}

	{
		MysqlxConfigStore store;
		store.bump_topology_generation();
		store.bump_topology_generation();
		store.bump_topology_generation();
		ok(store.topology_generation() == 3,
		   "multiple bumps reach correct value");
	}

	{
		MysqlxConfigStore store;
		store.bump_topology_generation();
		store.bump_topology_generation();
		auto db = create_test_db();
		std::string err;
		store.install_all_from_admin(*db, err);
		ok(store.topology_generation() == 2,
		   "topology generation survives install_all_from_admin");
	}

	return exit_status();
}
