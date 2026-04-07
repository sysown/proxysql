#include "mysqlx_config_store.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "sqlite3db.h"
#include "tap.h"

#include <memory>
#include <string>

namespace {

const char kRuntimeMysqlxUsersDdl[] =
	"CREATE TABLE runtime_mysqlx_users ("
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

const char kRuntimeMysqlxRoutesDdl[] =
	"CREATE TABLE runtime_mysqlx_routes ("
	" name VARCHAR NOT NULL PRIMARY KEY,"
	" bind VARCHAR NOT NULL,"
	" destination_hostgroup INT NOT NULL,"
	" fallback_hostgroup INT,"
	" strategy VARCHAR NOT NULL DEFAULT 'first_available',"
	" active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT ''"
	" )";

const char kRuntimeMysqlxEndpointsDdl[] =
	"CREATE TABLE runtime_mysqlx_backend_endpoints ("
	" hostname VARCHAR NOT NULL,"
	" mysql_port INT NOT NULL,"
	" mysqlx_port INT NOT NULL DEFAULT 33060,"
	" use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT '',"
	" PRIMARY KEY (hostname, mysql_port)"
	" )";

std::unique_ptr<SQLite3DB> create_test_db() {
	auto db = std::make_unique<SQLite3DB>();
	db->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	return db;
}

} // namespace

int main() {
	plan(16);

	MysqlxResolvedIdentity identity {};
	identity.username = "canonical_user";
	identity.default_hostgroup = 42;
	identity.x_enabled = true;

	ok(identity.username == "canonical_user",
	   "MysqlxResolvedIdentity keeps canonical username");
	ok(identity.default_hostgroup == 42,
	   "MysqlxResolvedIdentity keeps canonical default_hostgroup");
	ok(identity.x_enabled,
	   "MysqlxResolvedIdentity can enable mysqlx access");
	ok(identity.backend_auth_mode == MysqlxBackendAuthMode::mapped,
	   "MysqlxResolvedIdentity defaults backend_auth_mode to mapped");
	ok(mysqlx_backend_auth_mode_from_string("pass_through") ==
	   MysqlxBackendAuthMode::pass_through,
	   "backend auth mode parser accepts pass_through");

	auto db = create_test_db();
	ok(db->execute(ADMIN_SQLITE_RUNTIME_MYSQL_USERS),
	   "runtime mysql users table is created");
	ok(db->execute(ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS),
	   "runtime mysql servers table is created");
	ok(db->execute(kRuntimeMysqlxUsersDdl) &&
	   db->execute(kRuntimeMysqlxRoutesDdl) &&
	   db->execute(kRuntimeMysqlxEndpointsDdl),
	   "runtime mysqlx tables are created");

	ok(db->execute("INSERT INTO runtime_mysql_users (username, password, active, use_ssl, default_hostgroup, "
	               "default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, "
	               "max_connections, attributes, comment) VALUES "
	               "('alice', 'pw', 1, 0, 10, NULL, 0, 1, 0, 0, 1, 25, '', 'canonical')"),
	   "canonical frontend mysql user is inserted");
	ok(db->execute("INSERT INTO runtime_mysqlx_users (username, active, require_tls, allowed_auth_methods, "
	               "default_route, policy_profile, backend_auth_mode, backend_username, backend_password, attributes, comment) VALUES "
	               "('alice', 1, 1, 'PLAIN', 'rw', 'policy-a', 'service_account', 'svc_user', 'svc_pass', '', 'override')"),
	   "mysqlx override row is inserted");
	ok(db->execute("INSERT INTO runtime_mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active, attributes, comment) VALUES "
	               "('rw', '127.0.0.1:6603', 42, 43, 'first_available', 1, '', 'route')") &&
	   db->execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES "
	               "(42, 'db1.internal', 3306, 0, 'ONLINE', 100, 0, 1000, 0, 0, 0, 'server')") &&
	   db->execute("INSERT INTO runtime_mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port, use_ssl, attributes, comment) VALUES "
	               "('db1.internal', 3306, 33100, 1, '', 'endpoint')"),
	   "route, backend server, and mysqlx endpoint are inserted");

	MysqlxConfigStore store {};
	std::string err {};
	ok(store.load_from_runtime(*db, err) && err.empty(),
	   "config store loads runtime mysql and mysqlx state");

	const auto resolved = store.resolve_identity("alice");
	ok(resolved.has_value() &&
	   resolved->default_hostgroup == 10 &&
	   resolved->max_connections == 25 &&
	   resolved->x_enabled &&
	   resolved->require_tls &&
	   resolved->default_route == "rw" &&
	   resolved->policy_profile == "policy-a" &&
	   resolved->backend_auth_mode == MysqlxBackendAuthMode::service_account &&
	   resolved->backend_username == "svc_user" &&
	   resolved->backend_password == "svc_pass",
	   "config store merges canonical mysql user and mysqlx override state");

	const MysqlxBackendEndpoint endpoint = store.pick_endpoint("rw");
	ok(endpoint.hostname == "db1.internal" &&
	   endpoint.mysql_port == 3306 &&
	   endpoint.mysqlx_port == 33100 &&
	   endpoint.use_ssl,
	   "config store picks backend endpoint from route hostgroup and mysqlx overrides");

	ok(store.topology_generation() == 0,
	   "topology generation starts at zero");
	store.bump_topology_generation();
	ok(store.topology_generation() == 1,
	   "topology generation increments on demand");

	return exit_status();
}
