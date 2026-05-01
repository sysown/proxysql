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

const char kMysqlxVariablesDdl[] =
	"CREATE TABLE mysqlx_variables ("
	" variable_name VARCHAR NOT NULL PRIMARY KEY,"
	" variable_value VARCHAR NOT NULL DEFAULT ''"
	" )";

std::unique_ptr<SQLite3DB> create_test_db() {
	auto db = std::make_unique<SQLite3DB>();
	db->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	return db;
}

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(33);
	diag("=== mysqlx_config_store_unit-t starting ===");

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
	ok(db->execute(kMysqlxUsersDdl) &&
	   db->execute(kMysqlxRoutesDdl) &&
	   db->execute(kMysqlxEndpointsDdl) &&
	   db->execute(kMysqlxVariablesDdl),
	   "editable mysqlx tables are created");

	ok(db->execute("INSERT INTO runtime_mysql_users (username, password, active, use_ssl, default_hostgroup, "
	               "default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, "
	               "max_connections, attributes, comment) VALUES "
	               "('alice', 'pw', 1, 0, 10, NULL, 0, 1, 0, 0, 1, 25, '', 'canonical')"),
	   "canonical frontend mysql user is inserted");
	ok(db->execute("INSERT INTO mysqlx_users (username, active, require_tls, allowed_auth_methods, "
	               "default_route, policy_profile, backend_auth_mode, backend_username, backend_password, attributes, comment) VALUES "
	               "('alice', 1, 1, 'PLAIN', 'rw', 'policy-a', 'service_account', 'svc_user', 'svc_pass', '', 'override')"),
	   "mysqlx override row is inserted");
	ok(db->execute("INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active, attributes, comment) VALUES "
	               "('rw', '127.0.0.1:6603', 42, 43, 'first_available', 1, '', 'route')") &&
	   db->execute("INSERT INTO runtime_mysql_servers (hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES "
	               "(42, 'db1.internal', 3306, 0, 'ONLINE', 100, 0, 1000, 0, 0, 0, 'server')") &&
	   db->execute("INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port, use_ssl, attributes, comment) VALUES "
	               "('db1.internal', 3306, 33100, 1, '', 'endpoint')"),
	   "route, backend server, and mysqlx endpoint are inserted");

	MysqlxConfigStore store {};
	std::string err {};
	ok(store.install_all_from_admin(*db, err) && err.empty(),
	   "config store installs from admin tables");

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

	// --- mysqlx_tls_backend_mode (asymmetric TLS / AsClient mode) ---

	// String parser exercise: each documented value parses, unknown
	// values produce nullopt so the install path can surface a useful
	// error to the operator instead of silently coercing to default.
	ok(mysqlx_backend_tls_mode_from_string("disabled") ==
	   std::optional<MysqlxBackendTlsMode>(MysqlxBackendTlsMode::disabled) &&
	   mysqlx_backend_tls_mode_from_string("PREFERRED") ==
	   std::optional<MysqlxBackendTlsMode>(MysqlxBackendTlsMode::preferred) &&
	   mysqlx_backend_tls_mode_from_string("Required") ==
	   std::optional<MysqlxBackendTlsMode>(MysqlxBackendTlsMode::required) &&
	   mysqlx_backend_tls_mode_from_string("as_client") ==
	   std::optional<MysqlxBackendTlsMode>(MysqlxBackendTlsMode::as_client),
	   "backend tls mode parser accepts all four documented values case-insensitively");
	ok(!mysqlx_backend_tls_mode_from_string("nonsense").has_value() &&
	   !mysqlx_backend_tls_mode_from_string("").has_value(),
	   "backend tls mode parser rejects unknown values");
	ok(std::string(mysqlx_backend_tls_mode_to_string(MysqlxBackendTlsMode::as_client)) == "as_client",
	   "backend tls mode renders to canonical lowercase string");

	// Default value: as_client matches the legacy implicit behaviour
	// where backend TLS was tied to client TLS at resolve time.
	ok(store.get_backend_tls_mode() == MysqlxBackendTlsMode::as_client,
	   "store defaults backend tls mode to as_client (matches legacy behaviour)");

	// LOAD round-trip: an explicit row should be parsed and cached.
	ok(db->execute("INSERT INTO mysqlx_variables (variable_name, variable_value) VALUES "
	               "('mysqlx_tls_backend_mode', 'required')") &&
	   store.install_variables_from_admin(*db, err) && err.empty() &&
	   store.get_backend_tls_mode() == MysqlxBackendTlsMode::required,
	   "store parses explicit mysqlx_tls_backend_mode='required' from admin");

	// Invalid value: install must fail with a non-empty err describing the bad value.
	ok(db->execute("UPDATE mysqlx_variables SET variable_value='garbage' "
	               "WHERE variable_name='mysqlx_tls_backend_mode'") &&
	   !store.install_variables_from_admin(*db, err) &&
	   err.find("garbage") != std::string::npos,
	   "store rejects invalid mysqlx_tls_backend_mode with descriptive error");
	ok(store.get_backend_tls_mode() == MysqlxBackendTlsMode::required,
	   "store retains last-good backend tls mode after rejected install");

	// Absent row: removing the variable leaves the cached value alone.
	// Reset `err` first because the previous failing call left a message
	// in it; install_variables_from_admin only writes on failure.
	err.clear();
	ok(db->execute("DELETE FROM mysqlx_variables WHERE variable_name='mysqlx_tls_backend_mode'") &&
	   store.install_variables_from_admin(*db, err) && err.empty() &&
	   store.get_backend_tls_mode() == MysqlxBackendTlsMode::required,
	   "absent mysqlx_tls_backend_mode row leaves cached mode untouched");

	// --- per-route tls_mode (issue #5692, TLS passthrough) ---
	//
	// Parser exercise (mirrors the backend-tls-mode block above).
	ok(mysqlx_route_tls_mode_from_string("inherit") ==
	   std::optional<MysqlxRouteTlsMode>(MysqlxRouteTlsMode::inherit) &&
	   mysqlx_route_tls_mode_from_string("DISABLED") ==
	   std::optional<MysqlxRouteTlsMode>(MysqlxRouteTlsMode::disabled) &&
	   mysqlx_route_tls_mode_from_string("Preferred") ==
	   std::optional<MysqlxRouteTlsMode>(MysqlxRouteTlsMode::preferred) &&
	   mysqlx_route_tls_mode_from_string("required") ==
	   std::optional<MysqlxRouteTlsMode>(MysqlxRouteTlsMode::required) &&
	   mysqlx_route_tls_mode_from_string("PASSTHROUGH") ==
	   std::optional<MysqlxRouteTlsMode>(MysqlxRouteTlsMode::passthrough),
	   "route tls mode parser accepts all five documented values case-insensitively");
	ok(mysqlx_route_tls_mode_from_string("") ==
	   std::optional<MysqlxRouteTlsMode>(MysqlxRouteTlsMode::inherit),
	   "route tls mode parser collapses empty/NULL to inherit");
	ok(!mysqlx_route_tls_mode_from_string("nonsense").has_value(),
	   "route tls mode parser rejects unknown values");
	ok(std::string(mysqlx_route_tls_mode_to_string(MysqlxRouteTlsMode::passthrough)) == "passthrough" &&
	   std::string(mysqlx_route_tls_mode_to_string(MysqlxRouteTlsMode::inherit)) == "inherit",
	   "route tls mode renders to canonical lowercase string");

	// Default value: any route loaded without an explicit tls_mode
	// remains inherit (already the case for the 'rw' route loaded above
	// via install_all_from_admin against the legacy mysqlx_routes DDL,
	// which has no tls_mode column).
	ok(store.route_tls_mode("rw") == MysqlxRouteTlsMode::inherit,
	   "route loaded from legacy schema (no tls_mode column) defaults to inherit");
	ok(store.route_tls_mode("nonexistent") == MysqlxRouteTlsMode::inherit,
	   "unknown route reports inherit (safest default)");

	// Round-trip: SAVE a route with passthrough mode, then re-LOAD it
	// against a schema that DOES have the tls_mode column.
	{
		auto db2 = create_test_db();
		ok(db2->execute(ADMIN_SQLITE_RUNTIME_MYSQL_USERS) &&
		   db2->execute(ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS) &&
		   db2->execute(
			   "CREATE TABLE mysqlx_routes ("
			   " name VARCHAR NOT NULL PRIMARY KEY,"
			   " bind VARCHAR NOT NULL,"
			   " destination_hostgroup INT NOT NULL,"
			   " fallback_hostgroup INT,"
			   " strategy VARCHAR NOT NULL DEFAULT 'first_available',"
			   " active INT NOT NULL DEFAULT 1,"
			   " attributes VARCHAR NOT NULL DEFAULT '',"
			   " comment VARCHAR NOT NULL DEFAULT '',"
			   " tls_mode VARCHAR NOT NULL DEFAULT 'inherit')") &&
		   db2->execute(
			   "INSERT INTO mysqlx_routes "
			   "(name, bind, destination_hostgroup, strategy, tls_mode) VALUES "
			   "('compliance', '127.0.0.1:7777', 99, 'first_available', 'passthrough')") &&
		   db2->execute(
			   "INSERT INTO mysqlx_routes "
			   "(name, bind, destination_hostgroup, strategy, tls_mode) VALUES "
			   "('admin', '127.0.0.1:7778', 99, 'first_available', 'inherit')"),
		   "schema with tls_mode column and two passthrough/inherit rows is created");

		MysqlxConfigStore store2 {};
		std::string err2;
		ok(store2.install_routes_from_admin(*db2, err2) && err2.empty() &&
		   store2.route_tls_mode("compliance") == MysqlxRouteTlsMode::passthrough &&
		   store2.route_tls_mode("admin") == MysqlxRouteTlsMode::inherit,
		   "install_routes_from_admin reads tls_mode column for each row");

		// Reject a malformed value.
		ok(db2->execute("UPDATE mysqlx_routes SET tls_mode='garbage' WHERE name='compliance'") &&
		   !store2.install_routes_from_admin(*db2, err2) &&
		   err2.find("garbage") != std::string::npos,
		   "install_routes_from_admin surfaces malformed tls_mode with descriptive error");
	}

	return exit_status();
}
