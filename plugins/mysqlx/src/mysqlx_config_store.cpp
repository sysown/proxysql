#include "mysqlx_config_store.h"

#include "sqlite3db.h"

#include <cstdlib>
#include <memory>
#include <strings.h>
#include <unordered_map>

namespace {

std::string nullable_string(const char* value) {
	return value != nullptr ? value : "";
}

int nullable_int(const char* value, int default_value = 0) {
	return value != nullptr ? std::atoi(value) : default_value;
}

bool nullable_bool(const char* value, bool default_value = false) {
	return value != nullptr ? std::atoi(value) != 0 : default_value;
}

std::string endpoint_key(const std::string& hostname, int mysql_port) {
	return hostname + ":" + std::to_string(mysql_port);
}

bool fetch_result(SQLite3DB& db, const char* sql, std::unique_ptr<SQLite3_result>& result, std::string& err) {
	char* error = nullptr;
	result.reset(db.execute_statement(sql, &error));
	if (error != nullptr) {
		err = error;
		free(error);
		return false;
	}
	if (!result) {
		err = "sqlite query returned no result";
		return false;
	}
	return true;
}

void load_canonical_users(
	SQLite3_result& rows,
	std::unordered_map<std::string, MysqlxResolvedIdentity>& identities
) {
	for (auto* row : rows.rows) {
		if (row == nullptr) {
			continue;
		}

		MysqlxResolvedIdentity identity {};
		identity.username = nullable_string(row->fields[0]);
		identity.password = nullable_string(row->fields[1]);
		identity.default_hostgroup = nullable_int(row->fields[2]);
		identity.max_connections = nullable_int(row->fields[3]);
		identities[identity.username] = std::move(identity);
	}
}

// merge_mysqlx_users:
// Field layout matches the SELECT in install_users_from_admin:
//   0 username
//   1 active        -> x_enabled
//   2 require_tls
//   3 allowed_auth_methods
//   4 default_route
//   5 policy_profile
//   6 backend_auth_mode
//   7 backend_username
//   8 backend_password
//   9 attributes
//  10 comment
void merge_mysqlx_users(
	SQLite3_result& rows,
	std::unordered_map<std::string, MysqlxResolvedIdentity>& identities
) {
	for (auto* row : rows.rows) {
		if (row == nullptr || row->fields[0] == nullptr) {
			continue;
		}

		const std::string username = row->fields[0];
		auto it = identities.find(username);
		if (it == identities.end()) {
			continue;
		}

		MysqlxResolvedIdentity& identity = it->second;
		identity.x_enabled = nullable_bool(row->fields[1]);
		identity.require_tls = nullable_bool(row->fields[2]);
		identity.allowed_auth_methods = nullable_string(row->fields[3]);
		identity.default_route = nullable_string(row->fields[4]);
		identity.policy_profile = nullable_string(row->fields[5]);
		identity.backend_auth_mode = mysqlx_backend_auth_mode_from_string(nullable_string(row->fields[6]));
		identity.backend_username = nullable_string(row->fields[7]);
		identity.backend_password = nullable_string(row->fields[8]);
		identity.attributes = nullable_string(row->fields[9]);
		identity.comment = nullable_string(row->fields[10]);
	}
}

// Field layout matches the SELECT in install_routes_from_admin:
//   0 name
//   1 bind
//   2 destination_hostgroup
//   3 fallback_hostgroup
//   4 strategy
//   5 active
//   6 attributes
//   7 comment
//   8 tls_mode      (added with mysqlx_routes.tls_mode column)
//
// `parse_err` mirrors load_variables(): a malformed tls_mode token is
// recorded as a string the install path can surface to the operator,
// rather than silently coerced to inherit. The route is then dropped
// (not partially loaded) so the operator's intent isn't half-applied.
void load_routes(
	SQLite3_result& rows,
	std::unordered_map<std::string, MysqlxRoute>& routes,
	std::string& parse_err
) {
	for (auto* row : rows.rows) {
		if (row == nullptr || row->fields[0] == nullptr) {
			continue;
		}

		MysqlxRoute route {};
		route.name = nullable_string(row->fields[0]);
		route.bind = nullable_string(row->fields[1]);
		route.destination_hostgroup = nullable_int(row->fields[2]);
		route.fallback_hostgroup = nullable_int(row->fields[3], -1);
		route.strategy = nullable_string(row->fields[4]);
		route.active = nullable_bool(row->fields[5], true);
		route.attributes = nullable_string(row->fields[6]);
		route.comment = nullable_string(row->fields[7]);
		// tls_mode column was added with issue #5692. A pre-upgrade
		// admin DB without the column shows up as a NULL field here;
		// nullable_string -> "" -> mysqlx_route_tls_mode_from_string
		// resolves to inherit, preserving prior behaviour.
		const std::string tls_mode_raw = nullable_string(row->fields[8]);
		auto parsed = mysqlx_route_tls_mode_from_string(tls_mode_raw);
		if (!parsed) {
			if (parse_err.empty()) {
				parse_err = "invalid tls_mode '";
				parse_err += tls_mode_raw;
				parse_err += "' for route '";
				parse_err += route.name;
				parse_err += "' (expected one of: inherit, disabled, preferred, required, passthrough)";
			}
			continue;
		}
		route.tls_mode = *parsed;
		routes[route.name] = std::move(route);
	}
}

void load_endpoint_overrides(
	SQLite3_result& rows,
	std::unordered_map<std::string, MysqlxBackendEndpointOverride>& overrides
) {
	for (auto* row : rows.rows) {
		if (row == nullptr || row->fields[0] == nullptr) {
			continue;
		}

		MysqlxBackendEndpointOverride endpoint_override {};
		endpoint_override.hostname = nullable_string(row->fields[0]);
		endpoint_override.mysql_port = nullable_int(row->fields[1]);
		endpoint_override.mysqlx_port = nullable_int(row->fields[2], 33060);
		endpoint_override.use_ssl = nullable_bool(row->fields[3]);
		endpoint_override.attributes = nullable_string(row->fields[4]);
		endpoint_override.comment = nullable_string(row->fields[5]);
		overrides[endpoint_key(endpoint_override.hostname, endpoint_override.mysql_port)] = std::move(endpoint_override);
	}
}

void load_backend_servers(
	SQLite3_result& rows,
	const std::unordered_map<std::string, MysqlxBackendEndpointOverride>& overrides,
	std::unordered_map<int, std::vector<MysqlxBackendEndpoint>>& hostgroup_endpoints
) {
	for (auto* row : rows.rows) {
		if (row == nullptr || row->fields[1] == nullptr) {
			continue;
		}

		MysqlxBackendEndpoint endpoint {};
		const int hostgroup_id = nullable_int(row->fields[0]);
		endpoint.hostname = nullable_string(row->fields[1]);
		endpoint.mysql_port = nullable_int(row->fields[2]);
		endpoint.use_ssl = nullable_bool(row->fields[3]);

		const auto it = overrides.find(endpoint_key(endpoint.hostname, endpoint.mysql_port));
		if (it != overrides.end()) {
			endpoint.mysqlx_port = it->second.mysqlx_port;
			endpoint.use_ssl = it->second.use_ssl;
			endpoint.attributes = it->second.attributes;
		}

		hostgroup_endpoints[hostgroup_id].push_back(std::move(endpoint));
	}
}

// load_variables walks `mysqlx_variables` rows and writes the
// recognised tunables back through reference parameters. The
// backend-TLS-mode field is captured as a raw string + a parsed enum +
// a "did the operator set it" flag so that:
//
//   * an unrecognised value can be reported back as a useful error
//     instead of silently coerced to the default,
//   * an absent row leaves the existing `backend_tls_mode_` cached on
//     the store untouched (rather than resetting to as_client on every
//     LOAD), matching how the other variables behave.
//
// `parse_err` is populated with the first malformed row encountered;
// the caller is responsible for surfacing it back to the operator and
// aborting the install if it is non-empty.
void load_variables(
	SQLite3_result& rows,
	int& thread_pool_size,
	int& connect_timeout,
	std::string& tls_mode,
	int& max_cached_connections,
	MysqlxBackendTlsMode& backend_tls_mode,
	bool& backend_tls_mode_set,
	std::string& parse_err
) {
	for (auto* row : rows.rows) {
		if (row == nullptr || row->fields[0] == nullptr) {
			continue;
		}
		const std::string name = row->fields[0];
		const char* value = row->fields[1] ? row->fields[1] : "";
		if (name == "mysqlx_thread_pool_size") {
			thread_pool_size = std::atoi(value);
		} else if (name == "mysqlx_connect_timeout") {
			connect_timeout = std::atoi(value);
		} else if (name == "mysqlx_tls_mode") {
			tls_mode = value;
		} else if (name == "mysqlx_max_cached_connections_per_thread") {
			max_cached_connections = std::atoi(value);
		} else if (name == "mysqlx_tls_backend_mode") {
			auto parsed = mysqlx_backend_tls_mode_from_string(value);
			if (!parsed) {
				if (parse_err.empty()) {
					parse_err = "invalid mysqlx_tls_backend_mode '";
					parse_err += value;
					parse_err += "' (expected one of: disabled, preferred, required, as_client)";
				}
				continue;
			}
			backend_tls_mode = *parsed;
			backend_tls_mode_set = true;
		}
	}
}

// SQLite text quoting for ad-hoc statement composition. The plugin
// already owns its rows (we just round-tripped them through admindb)
// so SQL-injection from operator data isn't a concern, but a single
// quote in a username or attribute would still corrupt the statement.
// Doubled-quote is the SQLite-canonical escape inside string literals.
std::string sqlite_quote(const std::string& s) {
	std::string out;
	out.reserve(s.size() + 2);
	out.push_back('\'');
	for (char c : s) {
		out.push_back(c);
		if (c == '\'') out.push_back('\'');
	}
	out.push_back('\'');
	return out;
}

const char* backend_auth_mode_to_string(MysqlxBackendAuthMode m) {
	switch (m) {
	case MysqlxBackendAuthMode::pass_through:    return "pass_through";
	case MysqlxBackendAuthMode::service_account: return "service_account";
	case MysqlxBackendAuthMode::mapped:
	default:                                     return "mapped";
	}
}

} // namespace

MysqlxBackendAuthMode mysqlx_backend_auth_mode_from_string(const std::string& value) {
	if (strcasecmp(value.c_str(), "pass_through") == 0) {
		return MysqlxBackendAuthMode::pass_through;
	}
	if (strcasecmp(value.c_str(), "service_account") == 0) {
		return MysqlxBackendAuthMode::service_account;
	}
	return MysqlxBackendAuthMode::mapped;
}

std::optional<MysqlxBackendTlsMode> mysqlx_backend_tls_mode_from_string(const std::string& value) {
	if (strcasecmp(value.c_str(), "disabled") == 0) {
		return MysqlxBackendTlsMode::disabled;
	}
	if (strcasecmp(value.c_str(), "preferred") == 0) {
		return MysqlxBackendTlsMode::preferred;
	}
	if (strcasecmp(value.c_str(), "required") == 0) {
		return MysqlxBackendTlsMode::required;
	}
	if (strcasecmp(value.c_str(), "as_client") == 0) {
		return MysqlxBackendTlsMode::as_client;
	}
	return std::nullopt;
}

const char* mysqlx_backend_tls_mode_to_string(MysqlxBackendTlsMode m) {
	switch (m) {
		case MysqlxBackendTlsMode::disabled:  return "disabled";
		case MysqlxBackendTlsMode::preferred: return "preferred";
		case MysqlxBackendTlsMode::required:  return "required";
		case MysqlxBackendTlsMode::as_client: return "as_client";
	}
	return "as_client";
}

std::optional<MysqlxRouteTlsMode> mysqlx_route_tls_mode_from_string(const std::string& value) {
	// An empty/NULL column collapses to `inherit` so the LOAD path
	// can treat a freshly-added column on an upgraded admin DB as
	// "default" without forcing the operator to back-fill every row.
	if (value.empty()) {
		return MysqlxRouteTlsMode::inherit;
	}
	if (strcasecmp(value.c_str(), "inherit") == 0) {
		return MysqlxRouteTlsMode::inherit;
	}
	if (strcasecmp(value.c_str(), "disabled") == 0) {
		return MysqlxRouteTlsMode::disabled;
	}
	if (strcasecmp(value.c_str(), "preferred") == 0) {
		return MysqlxRouteTlsMode::preferred;
	}
	if (strcasecmp(value.c_str(), "required") == 0) {
		return MysqlxRouteTlsMode::required;
	}
	if (strcasecmp(value.c_str(), "passthrough") == 0) {
		return MysqlxRouteTlsMode::passthrough;
	}
	return std::nullopt;
}

const char* mysqlx_route_tls_mode_to_string(MysqlxRouteTlsMode m) {
	switch (m) {
		case MysqlxRouteTlsMode::inherit:     return "inherit";
		case MysqlxRouteTlsMode::disabled:    return "disabled";
		case MysqlxRouteTlsMode::preferred:   return "preferred";
		case MysqlxRouteTlsMode::required:    return "required";
		case MysqlxRouteTlsMode::passthrough: return "passthrough";
	}
	return "inherit";
}

// install_users_from_admin
//
// Reads two admin-side tables and atomically swaps `identities_` under
// the store's own mutex:
//
//   * runtime_mysql_users -- canonical user identity (password,
//     default_hostgroup, max_connections). Cross-module dependency:
//     this is admin's view of MySQL_Authentication state and may be
//     stale unless the operator has run `LOAD MYSQL USERS TO RUNTIME`
//     recently. We deliberately do not reach into GloMyAuth directly
//     to keep the module isolated from admin's runtime state machinery
//     -- the admin module's view-refresh scheme is the contract.
//
//   * mysqlx_users -- the editable mysqlx-side override table the
//     operator writes. We read it directly here (NOT runtime_mysqlx_
//     users): the runtime view is owned and projected by THIS module,
//     reading from the editable table is what makes mysqlx_users
//     authoritative for the operator's intent.
//
// Identity rows for users that exist in mysqlx_users WHERE active=1
// but have no matching active=1, frontend=1 row in runtime_mysql_users
// are silently dropped: a mysqlx user with no canonical mysql identity
// has no password to authenticate against, so listing them in the
// store would only enable a misleading "user exists but auth always
// fails" path.
bool MysqlxConfigStore::install_users_from_admin(SQLite3DB& db, std::string& err) {
	std::unordered_map<std::string, MysqlxResolvedIdentity> new_identities {};
	std::unique_ptr<SQLite3_result> result {};

	if (!fetch_result(
		    db,
		    "SELECT username, password, default_hostgroup, max_connections "
		    "FROM runtime_mysql_users WHERE active=1 AND frontend=1",
		    result,
		    err)) {
		return false;
	}
	load_canonical_users(*result, new_identities);

	if (!fetch_result(
		    db,
		    "SELECT username, active, require_tls, allowed_auth_methods, default_route, policy_profile, "
		    "backend_auth_mode, backend_username, backend_password, attributes, comment "
		    "FROM mysqlx_users WHERE active=1",
		    result,
		    err)) {
		return false;
	}
	merge_mysqlx_users(*result, new_identities);

	// Drop any canonical-only users (no mysqlx override row); they have
	// no x_enabled flag so they wouldn't authenticate via X anyway.
	for (auto it = new_identities.begin(); it != new_identities.end();) {
		if (!it->second.x_enabled) {
			it = new_identities.erase(it);
		} else {
			++it;
		}
	}

	std::unique_lock<std::shared_mutex> lock(mutex_);
	identities_.swap(new_identities);
	return true;
}

bool MysqlxConfigStore::install_routes_from_admin(SQLite3DB& db, std::string& err) {
	std::unordered_map<std::string, MysqlxRoute> new_routes {};
	std::unique_ptr<SQLite3_result> result {};

	// SELECT tolerates pre-upgrade admin DBs missing the tls_mode column:
	// fetch_result will surface the error from sqlite, but we'd rather
	// emit a friendlier "default to inherit" path. Since the column is
	// part of the canonical schema (mysqlx_admin_schema.cpp adds it),
	// every fresh install has it; only an out-of-band ALTER-skipping
	// upgrade would land here. Detect via a separate PRAGMA query and
	// drop tls_mode from the SELECT in that case.
	bool has_tls_mode = false;
	{
		std::unique_ptr<SQLite3_result> cols {};
		std::string pragma_err;
		if (fetch_result(db, "PRAGMA table_info(mysqlx_routes)", cols, pragma_err)) {
			for (auto* row : cols->rows) {
				if (row != nullptr && row->fields[1] != nullptr &&
				    strcasecmp(row->fields[1], "tls_mode") == 0) {
					has_tls_mode = true;
					break;
				}
			}
		}
	}

	const char* sql = has_tls_mode
		? "SELECT name, bind, destination_hostgroup, fallback_hostgroup, strategy, active, attributes, comment, tls_mode "
		  "FROM mysqlx_routes WHERE active=1"
		: "SELECT name, bind, destination_hostgroup, fallback_hostgroup, strategy, active, attributes, comment, NULL AS tls_mode "
		  "FROM mysqlx_routes WHERE active=1";

	if (!fetch_result(db, sql, result, err)) {
		return false;
	}
	std::string parse_err;
	load_routes(*result, new_routes, parse_err);
	if (!parse_err.empty()) {
		err = std::move(parse_err);
		return false;
	}

	std::unique_lock<std::shared_mutex> lock(mutex_);
	routes_.swap(new_routes);
	return true;
}

// install_endpoints_from_admin
//
// The endpoint store is the resolved per-hostgroup view used at route
// dispatch time. It is rebuilt from two inputs:
//
//   * runtime_mysql_servers -- canonical hostgroup -> (hostname, port,
//     use_ssl) topology, cross-module dependency on MySQL_HostGroups_
//     Manager.
//   * mysqlx_backend_endpoints -- per-(hostname,mysql_port) overrides
//     the operator sets to expose mysqlx_port and force use_ssl.
//
// Both raw inputs are kept in `endpoint_overrides_` so a SAVE / view
// projection can faithfully round-trip; the resolved per-hostgroup
// view is what `pick_endpoint` ultimately uses.
bool MysqlxConfigStore::install_endpoints_from_admin(SQLite3DB& db, std::string& err) {
	std::unordered_map<std::string, MysqlxBackendEndpointOverride> new_overrides {};
	std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> new_hostgroup_endpoints {};
	std::unique_ptr<SQLite3_result> result {};

	if (!fetch_result(
		    db,
		    "SELECT hostname, mysql_port, mysqlx_port, use_ssl, attributes, comment "
		    "FROM mysqlx_backend_endpoints",
		    result,
		    err)) {
		return false;
	}
	load_endpoint_overrides(*result, new_overrides);

	if (!fetch_result(
		    db,
		    "SELECT hostgroup_id, hostname, port, use_ssl "
		    "FROM runtime_mysql_servers WHERE UPPER(status)='ONLINE' "
		    "ORDER BY hostgroup_id, weight DESC, hostname, port",
		    result,
		    err)) {
		return false;
	}
	load_backend_servers(*result, new_overrides, new_hostgroup_endpoints);

	std::unique_lock<std::shared_mutex> lock(mutex_);
	endpoint_overrides_.swap(new_overrides);
	hostgroup_endpoints_.swap(new_hostgroup_endpoints);
	return true;
}

bool MysqlxConfigStore::install_all_from_admin(SQLite3DB& db, std::string& err) {
	return install_users_from_admin(db, err)
	    && install_routes_from_admin(db, err)
	    && install_endpoints_from_admin(db, err)
	    && install_variables_from_admin(db, err);
}

bool MysqlxConfigStore::install_variables_from_admin(SQLite3DB& db, std::string& err) {
	int new_pool_size = thread_pool_size_;
	int new_connect_timeout = connect_timeout_;
	std::string new_tls_mode = tls_mode_;
	int new_max_cached = max_cached_connections_;
	// Seed with the currently-installed value so an absent
	// mysqlx_tls_backend_mode row leaves the cached mode untouched.
	MysqlxBackendTlsMode new_backend_tls_mode = backend_tls_mode_;
	bool backend_tls_mode_set = false;
	std::string parse_err;
	std::unique_ptr<SQLite3_result> result {};

	if (!fetch_result(
		    db,
		    "SELECT variable_name, variable_value FROM mysqlx_variables",
		    result,
		    err)) {
		return false;
	}
	load_variables(*result, new_pool_size, new_connect_timeout, new_tls_mode, new_max_cached,
	               new_backend_tls_mode, backend_tls_mode_set, parse_err);
	if (!parse_err.empty()) {
		err = std::move(parse_err);
		return false;
	}

	std::unique_lock<std::shared_mutex> lock(mutex_);
	thread_pool_size_ = new_pool_size;
	connect_timeout_ = new_connect_timeout;
	tls_mode_ = std::move(new_tls_mode);
	max_cached_connections_ = new_max_cached;
	if (backend_tls_mode_set) {
		backend_tls_mode_ = new_backend_tls_mode;
	}
	return true;
}

// ===========================================================================
// SAVE_*_TO_ADMIN_TABLE: mirror the canonical save_mysql_users_runtime_to_
// database(false) shape -- mark all existing rows inactive, then upsert the
// live store contents with active=1. Inactive rows in the editable table
// are preserved so the operator's "deactivate but don't delete" workflow
// still works.
//
// PROJECT_*_TO_RUNTIME_VIEW: mirror save_mysql_users_runtime_to_database
// (true) -- DELETE the projected runtime_<table>, then INSERT the live
// store contents. Used by the chassis register_runtime_view() refresh
// callbacks before any admin SELECT against the projected table.
// ===========================================================================

bool MysqlxConfigStore::save_users_to_admin_table(SQLite3DB& db) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!db.execute("BEGIN")) return false;
	if (!db.execute("UPDATE mysqlx_users SET active=0")) {
		db.execute("ROLLBACK");
		return false;
	}
	for (const auto& [username, identity] : identities_) {
		std::string sql = "REPLACE INTO mysqlx_users "
			"(username, active, require_tls, allowed_auth_methods, default_route, "
			"policy_profile, backend_auth_mode, backend_username, backend_password, "
			"attributes, comment) VALUES (";
		sql += sqlite_quote(identity.username) + ", 1, ";
		sql += (identity.require_tls ? "1, " : "0, ");
		sql += sqlite_quote(identity.allowed_auth_methods) + ", ";
		sql += sqlite_quote(identity.default_route) + ", ";
		sql += sqlite_quote(identity.policy_profile) + ", ";
		sql += sqlite_quote(backend_auth_mode_to_string(identity.backend_auth_mode)) + ", ";
		sql += sqlite_quote(identity.backend_username) + ", ";
		sql += sqlite_quote(identity.backend_password) + ", ";
		sql += sqlite_quote(identity.attributes) + ", ";
		sql += sqlite_quote(identity.comment) + ")";
		if (!db.execute(sql.c_str())) {
			db.execute("ROLLBACK");
			return false;
		}
	}
	return db.execute("COMMIT");
}

bool MysqlxConfigStore::save_routes_to_admin_table(SQLite3DB& db) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!db.execute("BEGIN")) return false;
	if (!db.execute("UPDATE mysqlx_routes SET active=0")) {
		db.execute("ROLLBACK");
		return false;
	}
	for (const auto& [name, route] : routes_) {
		std::string sql = "REPLACE INTO mysqlx_routes "
			"(name, bind, destination_hostgroup, fallback_hostgroup, strategy, "
			"active, attributes, comment, tls_mode) VALUES (";
		sql += sqlite_quote(route.name) + ", ";
		sql += sqlite_quote(route.bind) + ", ";
		sql += std::to_string(route.destination_hostgroup) + ", ";
		if (route.fallback_hostgroup >= 0) {
			sql += std::to_string(route.fallback_hostgroup) + ", ";
		} else {
			sql += "NULL, ";
		}
		sql += sqlite_quote(route.strategy) + ", 1, ";
		sql += sqlite_quote(route.attributes) + ", ";
		sql += sqlite_quote(route.comment) + ", ";
		sql += sqlite_quote(mysqlx_route_tls_mode_to_string(route.tls_mode)) + ")";
		if (!db.execute(sql.c_str())) {
			db.execute("ROLLBACK");
			return false;
		}
	}
	return db.execute("COMMIT");
}

bool MysqlxConfigStore::save_endpoints_to_admin_table(SQLite3DB& db) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!db.execute("BEGIN")) return false;
	if (!db.execute("DELETE FROM mysqlx_backend_endpoints")) {
		db.execute("ROLLBACK");
		return false;
	}
	for (const auto& [key, ov] : endpoint_overrides_) {
		std::string sql = "INSERT INTO mysqlx_backend_endpoints "
			"(hostname, mysql_port, mysqlx_port, use_ssl, attributes, comment) VALUES (";
		sql += sqlite_quote(ov.hostname) + ", ";
		sql += std::to_string(ov.mysql_port) + ", ";
		sql += std::to_string(ov.mysqlx_port) + ", ";
		sql += (ov.use_ssl ? "1, " : "0, ");
		sql += sqlite_quote(ov.attributes) + ", ";
		sql += sqlite_quote(ov.comment) + ")";
		if (!db.execute(sql.c_str())) {
			db.execute("ROLLBACK");
			return false;
		}
	}
	return db.execute("COMMIT");
}

bool MysqlxConfigStore::save_variables_to_admin_table(SQLite3DB& db) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!db.execute("BEGIN")) return false;
	if (!db.execute("DELETE FROM mysqlx_variables")) {
		db.execute("ROLLBACK");
		return false;
	}
	auto put = [&](const char* name, const std::string& value) -> bool {
		std::string sql = "INSERT INTO mysqlx_variables (variable_name, variable_value) VALUES (";
		sql += sqlite_quote(name) + ", " + sqlite_quote(value) + ")";
		return db.execute(sql.c_str());
	};
	if (!put("mysqlx_thread_pool_size", std::to_string(thread_pool_size_))) {
		db.execute("ROLLBACK"); return false;
	}
	if (!put("mysqlx_connect_timeout", std::to_string(connect_timeout_))) {
		db.execute("ROLLBACK"); return false;
	}
	if (!put("mysqlx_tls_mode", tls_mode_)) {
		db.execute("ROLLBACK"); return false;
	}
	if (!put("mysqlx_max_cached_connections_per_thread", std::to_string(max_cached_connections_))) {
		db.execute("ROLLBACK"); return false;
	}
	if (!put("mysqlx_tls_backend_mode", mysqlx_backend_tls_mode_to_string(backend_tls_mode_))) {
		db.execute("ROLLBACK"); return false;
	}
	return db.execute("COMMIT");
}

void MysqlxConfigStore::project_users_to_runtime_view(SQLite3DB& db) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!db.execute("BEGIN")) return;
	if (!db.execute("DELETE FROM runtime_mysqlx_users")) {
		db.execute("ROLLBACK"); return;
	}
	for (const auto& [username, identity] : identities_) {
		std::string sql = "INSERT INTO runtime_mysqlx_users "
			"(username, active, require_tls, allowed_auth_methods, default_route, "
			"policy_profile, backend_auth_mode, backend_username, backend_password, "
			"attributes, comment) VALUES (";
		sql += sqlite_quote(identity.username) + ", 1, ";
		sql += (identity.require_tls ? "1, " : "0, ");
		sql += sqlite_quote(identity.allowed_auth_methods) + ", ";
		sql += sqlite_quote(identity.default_route) + ", ";
		sql += sqlite_quote(identity.policy_profile) + ", ";
		sql += sqlite_quote(backend_auth_mode_to_string(identity.backend_auth_mode)) + ", ";
		sql += sqlite_quote(identity.backend_username) + ", ";
		sql += sqlite_quote(identity.backend_password) + ", ";
		sql += sqlite_quote(identity.attributes) + ", ";
		sql += sqlite_quote(identity.comment) + ")";
		if (!db.execute(sql.c_str())) {
			db.execute("ROLLBACK"); return;
		}
	}
	db.execute("COMMIT");
}

void MysqlxConfigStore::project_routes_to_runtime_view(SQLite3DB& db) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!db.execute("BEGIN")) return;
	if (!db.execute("DELETE FROM runtime_mysqlx_routes")) {
		db.execute("ROLLBACK"); return;
	}
	for (const auto& [name, route] : routes_) {
		std::string sql = "INSERT INTO runtime_mysqlx_routes "
			"(name, bind, destination_hostgroup, fallback_hostgroup, strategy, "
			"active, attributes, comment, tls_mode) VALUES (";
		sql += sqlite_quote(route.name) + ", ";
		sql += sqlite_quote(route.bind) + ", ";
		sql += std::to_string(route.destination_hostgroup) + ", ";
		if (route.fallback_hostgroup >= 0) {
			sql += std::to_string(route.fallback_hostgroup) + ", ";
		} else {
			sql += "NULL, ";
		}
		sql += sqlite_quote(route.strategy) + ", 1, ";
		sql += sqlite_quote(route.attributes) + ", ";
		sql += sqlite_quote(route.comment) + ", ";
		sql += sqlite_quote(mysqlx_route_tls_mode_to_string(route.tls_mode)) + ")";
		if (!db.execute(sql.c_str())) {
			db.execute("ROLLBACK"); return;
		}
	}
	db.execute("COMMIT");
}

void MysqlxConfigStore::project_endpoints_to_runtime_view(SQLite3DB& db) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!db.execute("BEGIN")) return;
	if (!db.execute("DELETE FROM runtime_mysqlx_backend_endpoints")) {
		db.execute("ROLLBACK"); return;
	}
	for (const auto& [key, ov] : endpoint_overrides_) {
		std::string sql = "INSERT INTO runtime_mysqlx_backend_endpoints "
			"(hostname, mysql_port, mysqlx_port, use_ssl, attributes, comment) VALUES (";
		sql += sqlite_quote(ov.hostname) + ", ";
		sql += std::to_string(ov.mysql_port) + ", ";
		sql += std::to_string(ov.mysqlx_port) + ", ";
		sql += (ov.use_ssl ? "1, " : "0, ");
		sql += sqlite_quote(ov.attributes) + ", ";
		sql += sqlite_quote(ov.comment) + ")";
		if (!db.execute(sql.c_str())) {
			db.execute("ROLLBACK"); return;
		}
	}
	db.execute("COMMIT");
}

void MysqlxConfigStore::project_variables_to_runtime_view(SQLite3DB& db) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!db.execute("BEGIN")) return;
	if (!db.execute("DELETE FROM runtime_mysqlx_variables")) {
		db.execute("ROLLBACK"); return;
	}
	auto put = [&](const char* name, const std::string& value) -> bool {
		std::string sql = "INSERT INTO runtime_mysqlx_variables (variable_name, variable_value) VALUES (";
		sql += sqlite_quote(name) + ", " + sqlite_quote(value) + ")";
		return db.execute(sql.c_str());
	};
	if (!put("mysqlx_thread_pool_size", std::to_string(thread_pool_size_)) ||
	    !put("mysqlx_connect_timeout", std::to_string(connect_timeout_)) ||
	    !put("mysqlx_tls_mode", tls_mode_) ||
	    !put("mysqlx_max_cached_connections_per_thread", std::to_string(max_cached_connections_)) ||
	    !put("mysqlx_tls_backend_mode", mysqlx_backend_tls_mode_to_string(backend_tls_mode_))) {
		db.execute("ROLLBACK"); return;
	}
	db.execute("COMMIT");
}

std::optional<MysqlxResolvedIdentity> MysqlxConfigStore::resolve_identity(const std::string& username) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	const auto it = identities_.find(username);
	if (it == identities_.end()) {
		return std::nullopt;
	}
	return it->second;
}

MysqlxBackendEndpoint MysqlxConfigStore::pick_from_hostgroup(int hostgroup_id, const std::string& strategy) const {
	// Caller must hold mutex_ (shared lock).
	const auto it = hostgroup_endpoints_.find(hostgroup_id);
	if (it == hostgroup_endpoints_.end() || it->second.empty()) {
		return {};
	}

	const auto& endpoints = it->second;

	if (strategy == "round_robin" || strategy == "round_robin_with_fallback") {
		std::lock_guard<std::mutex> rr_lock(rr_mutex_);
		uint32_t& counter = rr_counters_[hostgroup_id];
		uint32_t idx = counter++ % static_cast<uint32_t>(endpoints.size());
		return endpoints[idx];
	}

	// first_available (default)
	return endpoints.front();
}

MysqlxBackendEndpoint MysqlxConfigStore::pick_endpoint(const std::string& route_name) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	const auto route_it = routes_.find(route_name);
	if (route_it == routes_.end()) {
		return {};
	}

	const MysqlxRoute& route = route_it->second;
	auto result = pick_from_hostgroup(route.destination_hostgroup, route.strategy);
	if (!result.hostname.empty()) {
		return result;
	}

	if (route.fallback_hostgroup >= 0) {
		return pick_from_hostgroup(route.fallback_hostgroup, route.strategy);
	}

	return {};
}

int MysqlxConfigStore::route_hostgroup(const std::string& route_name) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	auto it = routes_.find(route_name);
	if (it == routes_.end()) return 0;
	return it->second.destination_hostgroup;
}

bool MysqlxConfigStore::route_exists(const std::string& route_name) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return routes_.find(route_name) != routes_.end();
}

MysqlxRouteTlsMode MysqlxConfigStore::route_tls_mode(const std::string& route_name) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	auto it = routes_.find(route_name);
	if (it == routes_.end()) {
		// Unknown route -> safest default. Caller can route_exists()
		// first when it needs to distinguish "missing route" from "route
		// configured to inherit".
		return MysqlxRouteTlsMode::inherit;
	}
	return it->second.tls_mode;
}

std::vector<std::pair<std::string, std::string>> MysqlxConfigStore::snapshot_active_routes() const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	std::vector<std::pair<std::string, std::string>> out;
	out.reserve(routes_.size());
	for (const auto& [name, route] : routes_) {
		if (!route.active) continue;
		out.emplace_back(route.name, route.bind);
	}
	return out;
}

void MysqlxConfigStore::install_for_test(
	std::unordered_map<std::string, MysqlxRoute> routes,
	std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints
) {
	std::unique_lock<std::shared_mutex> lock(mutex_);
	routes_ = std::move(routes);
	hostgroup_endpoints_ = std::move(endpoints);
}

uint64_t MysqlxConfigStore::topology_generation() const {
	return topology_generation_.load();
}

void MysqlxConfigStore::bump_topology_generation() {
	topology_generation_.fetch_add(1);
}

int MysqlxConfigStore::get_thread_pool_size() const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return thread_pool_size_;
}

int MysqlxConfigStore::get_connect_timeout() const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return connect_timeout_;
}

std::string MysqlxConfigStore::get_tls_mode() const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return tls_mode_;
}

int MysqlxConfigStore::get_max_cached_connections() const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return max_cached_connections_;
}

MysqlxBackendTlsMode MysqlxConfigStore::get_backend_tls_mode() const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return backend_tls_mode_;
}
