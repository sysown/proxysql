#ifdef PROXYSQL40

#include "proxysql.h"
#include "cpp.h"

#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "Query_Tool_Handler.h"
#include "MCP_Thread.h"
#include "proxysql_debug.h"
#include "proxysql_admin.h"
#include "Static_Harvester.h"
#include "PgSQL_Static_Harvester.h"

#include <vector>
#include <map>
#include <regex>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <memory>
#include <random>

// MySQL client library
#include <mysql.h>
#include <libpq-fe.h>

extern ProxySQL_Admin *GloAdmin;

bool is_pgsql_protocol(const std::string& protocol) {
	return protocol == "pgsql";
}

static std::unique_ptr<SQLite3_result> dump_runtime_servers_for_protocol(const std::string& protocol) {
	if (is_pgsql_protocol(protocol)) {
		if (PgHGM == NULL) {
			return nullptr;
		}
		return std::unique_ptr<SQLite3_result>(PgHGM->dump_table_pgsql("pgsql_servers"));
	}

	if (MyHGM == NULL) {
		return nullptr;
	}
	return std::unique_ptr<SQLite3_result>(MyHGM->dump_table_mysql("mysql_servers"));
}

static int runtime_status_col_idx(const std::string& protocol) {
	return is_pgsql_protocol(protocol) ? 3 : 4;
}

static int runtime_weight_col_idx(const std::string& protocol) {
	return is_pgsql_protocol(protocol) ? 4 : 5;
}

std::string uppercase_or_unknown(const char* s) {
	if (s == NULL) {
		return "UNKNOWN";
	}
	std::string out(s);
	std::transform(out.begin(), out.end(), out.begin(), ::toupper);
	return out.empty() ? "UNKNOWN" : out;
}

bool is_runtime_online_status(const std::string& status) {
	return status == "ONLINE";
}

static size_t pick_weighted_random_index(const std::vector<int>& weights) {
	long long total_weight = 0;
	for (size_t i = 0; i < weights.size(); i++) {
		if (weights[i] > 0) {
			total_weight += weights[i];
		}
	}
	if (total_weight <= 0) {
		return 0;
	}

	static thread_local std::mt19937_64 rng(std::random_device{}());
	std::uniform_int_distribution<long long> dist(1, total_weight);
	const long long pick = dist(rng);

	long long cumulative = 0;
	for (size_t i = 0; i < weights.size(); i++) {
		if (weights[i] > 0) {
			cumulative += weights[i];
			if (pick <= cumulative) {
				return i;
			}
		}
	}
	return 0;
}

static std::string get_runtime_hostgroup_status_summary(const std::string& protocol, int hostgroup_id) {
	std::unique_ptr<SQLite3_result> resultset = dump_runtime_servers_for_protocol(protocol);
	if (!resultset) {
		return std::string("runtime status unavailable (") + protocol + " hostgroup manager not ready)";
	}

	std::map<std::string, int> status_counts;
	for (const auto* row : resultset->rows) {
		if (row == NULL || row->cnt < 1 || row->fields[0] == NULL) {
			continue;
		}
		const int row_hostgroup_id = atoi(row->fields[0]);
		if (row_hostgroup_id != hostgroup_id) {
			continue;
		}
		const int status_idx = runtime_status_col_idx(protocol);
		const char* status_raw = (status_idx < row->cnt) ? row->fields[status_idx] : NULL;
		status_counts[uppercase_or_unknown(status_raw)]++;
	}

	if (status_counts.empty()) {
		std::ostringstream msg;
		msg << "no rows in HGM runtime snapshot for hostgroup " << hostgroup_id;
		return msg.str();
	}

	std::ostringstream out;
	bool first = true;
	for (const auto& kv : status_counts) {
		if (!first) {
			out << ", ";
		}
		first = false;
		out << kv.first << "=" << kv.second;
	}
	return out.str();
}

// ============================================================
// JSON Helper Functions
//
// These helper functions provide safe extraction of values from
// nlohmann::json objects with type coercion and default values.
// They handle edge cases like null values, type mismatches, and
// missing keys gracefully.
// ============================================================

// Safely extract a string value from JSON.
//
// Returns the value as a string if the key exists and is not null.
// For non-string types, returns the JSON dump representation.
// Returns the default value if the key is missing or null.
//
// Parameters:
//   j           - JSON object to extract from
//   key         - Key to look up
//   default_val - Default value if key is missing or null
//
// Returns:
//   String value, JSON dump, or default value
std::string json_string(const json& j, const std::string& key, const std::string& default_val) {
	if (j.contains(key) && !j[key].is_null()) {
		if (j[key].is_string()) {
			return j[key].get<std::string>();
		}
		return j[key].dump();
	}
	return default_val;
}

// Safely extract an integer value from JSON with type coercion.
//
// Handles multiple input types:
// - Numbers: Returns directly as int
// - Booleans: Converts (true=1, false=0)
// - Strings: Attempts numeric parsing
// - Missing/null: Returns default value
//
// Parameters:
//   j           - JSON object to extract from
//   key         - Key to look up
//   default_val - Default value if key is missing, null, or unparseable
//
// Returns:
//   Integer value, or default value
int json_int(const json& j, const std::string& key, int default_val) {
	if (j.contains(key) && !j[key].is_null()) {
		const json& val = j[key];
		// If it's already a number, return it
		if (val.is_number()) {
			return val.get<int>();
		}
		// If it's a boolean, convert to int (true=1, false=0)
		if (val.is_boolean()) {
			return val.get<bool>() ? 1 : 0;
		}
		// If it's a string, try to parse it as an int
		if (val.is_string()) {
			std::string s = val.get<std::string>();
			try {
				return std::stoi(s);
			} catch (...) {
				// Parse failed, return default
				return default_val;
			}
		}
	}
	return default_val;
}

// Safely extract a double value from JSON with type coercion.
//
// Handles multiple input types:
// - Numbers: Returns directly as double
// - Strings: Attempts numeric parsing
// - Missing/null: Returns default value
//
// Parameters:
//   j           - JSON object to extract from
//   key         - Key to look up
//   default_val - Default value if key is missing, null, or unparseable
//
// Returns:
//   Double value, or default value
double json_double(const json& j, const std::string& key, double default_val) {
	if (j.contains(key) && !j[key].is_null()) {
		const json& val = j[key];
		// If it's already a number, return it
		if (val.is_number()) {
			return val.get<double>();
		}
		// If it's a string, try to parse it as a double
		if (val.is_string()) {
			std::string s = val.get<std::string>();
			try {
				return std::stod(s);
			} catch (...) {
				// Parse failed, return default
				return default_val;
			}
		}
	}
	return default_val;
}

// ============================================================
// SQL Escaping Helper Functions
//
// These functions provide safe SQL escaping to prevent
// SQL injection vulnerabilities when building queries.
// ============================================================

/**
 * @brief Validate and escape a SQL identifier (table name, column name, etc.)
 *
 * For SQLite, we validate that the identifier contains only safe characters.
 * This prevents SQL injection while allowing valid identifiers.
 *
 * @param identifier The identifier to validate/escape
 * @return Empty string if unsafe, otherwise the validated identifier
 */
std::string validate_sql_identifier_sqlite(const std::string& identifier) {
	if (identifier.empty()) {
		return "";
	}

	// Check length (SQLite identifiers max 1000 characters, but we're more conservative)
	if (identifier.length() > 128) {
		return "";
	}

	// First character must be letter or underscore
	if (!isalpha(identifier[0]) && identifier[0] != '_') {
		return "";
	}

	// All characters must be alphanumeric, underscore, or dollar sign
	for (char c : identifier) {
		if (!isalnum(c) && c != '_' && c != '$') {
			return "";
		}
	}

	return identifier;
}

/**
 * @brief Escape a SQL string literal for use in queries
 *
 * Escapes single quotes by doubling them (standard SQL) and also escapes
 * backslashes for defense-in-depth (important for MySQL with certain modes).
 *
 * @param value The string value to escape
 * @return Escaped string safe for use in SQL queries
 */
std::string escape_string_literal(const std::string& value) {
	std::string escaped;
	escaped.reserve(value.length() * 2 + 1);

	for (char c : value) {
		if (c == '\'') {
			escaped += "''";  // Double single quotes to escape (SQL standard)
		} else if (c == '\\') {
			escaped += "\\\\";  // Escape backslash (defense-in-depth)
		} else {
			escaped += c;
		}
	}

	return escaped;
}

Query_Tool_Handler::Query_Tool_Handler(
	const std::string& catalog_path)
	: catalog(NULL),
	  mysql_harvester(NULL),
	  pgsql_harvester(NULL),
	  pool_size(0),
	  pg_pool_size(0),
	  max_rows(200),
	  timeout_ms(2000),
	  allow_select_star(false)
{
	// Initialize pool mutex
	pthread_mutex_init(&pool_lock, NULL);

	// Initialize counters mutex
	pthread_mutex_init(&counters_lock, NULL);

	// Create discovery schema and protocol-specific harvesters.
	catalog = new Discovery_Schema(catalog_path);
	mysql_harvester = new Static_Harvester("127.0.0.1", 3306, "", "", "", catalog_path);
	pgsql_harvester = new PgSQL_Static_Harvester("127.0.0.1", 5432, "", "", "", catalog_path);

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Query_Tool_Handler created with Discovery_Schema and protocol harvesters\n");
}

Query_Tool_Handler::~Query_Tool_Handler() {
	close();

	if (catalog) {
		delete catalog;
		catalog = NULL;
	}

	if (mysql_harvester) {
		delete mysql_harvester;
		mysql_harvester = NULL;
	}

	if (pgsql_harvester) {
		delete pgsql_harvester;
		pgsql_harvester = NULL;
	}

	pthread_mutex_destroy(&pool_lock);
	pthread_mutex_destroy(&counters_lock);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Query_Tool_Handler destroyed\n");
}

int Query_Tool_Handler::init() {
	// Initialize discovery schema
	if (catalog->init()) {
		proxy_error("Query_Tool_Handler: Failed to initialize Discovery_Schema\n");
		return -1;
	}

	// Initialize protocol-specific harvesters (lazy backend connect).
	if (mysql_harvester->init()) {
		proxy_error("Query_Tool_Handler: Failed to initialize MySQL Static_Harvester\n");
		return -1;
	}
	if (pgsql_harvester->init()) {
		proxy_error("Query_Tool_Handler: Failed to initialize PgSQL Static_Harvester\n");
		return -1;
	}

	// Initialize connection pool
	if (init_connection_pool()) {
		proxy_error("Query_Tool_Handler: Failed to initialize connection pool\n");
		return -1;
	}

	proxy_info("Query_Tool_Handler initialized with Discovery_Schema and protocol harvesters\n");
	return 0;
}

void Query_Tool_Handler::close() {
	pthread_mutex_lock(&pool_lock);

	for (auto& conn : connection_pool) {
		if (conn.mysql) {
			mysql_close(static_cast<MYSQL*>(conn.mysql));
			conn.mysql = NULL;
		}
	}
	connection_pool.clear();
	pool_size = 0;

	for (auto& conn : pgsql_connection_pool) {
		if (conn.pgconn) {
			PQfinish(static_cast<PGconn*>(conn.pgconn));
			conn.pgconn = NULL;
		}
	}
	pgsql_connection_pool.clear();
	pg_pool_size = 0;

	pthread_mutex_unlock(&pool_lock);
}

int Query_Tool_Handler::init_connection_pool() {
	// Ensure re-initialization is idempotent when topology/auth changes at runtime.
	close();
	refresh_target_registry();

	pthread_mutex_lock(&pool_lock);
	pool_size = 0;
	pg_pool_size = 0;

	for (const auto& target : target_registry) {
		if (!target.executable || target.protocol != "mysql") {
			continue;
		}
		MySQLConnection conn;
		conn.target_id = target.target_id;
		conn.auth_profile_id = target.auth_profile_id;
		conn.host = target.host;
		conn.port = target.port;
		conn.in_use = false;
		conn.current_schema = target.default_schema;

		MYSQL* mysql = mysql_init(NULL);
		if (!mysql) {
			proxy_error("Query_Tool_Handler: mysql_init failed for %s:%d\n",
				conn.host.c_str(), conn.port);
			continue;
		}

		unsigned int timeout = 5;
		mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
		mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, &timeout);
		mysql_options(mysql, MYSQL_OPT_WRITE_TIMEOUT, &timeout);

		// GHSA-7wh6-2vcc-gcm4: the MCP query path advertises a per-call
		// read-only contract.  Allowing the server to accept multi-statement
		// payloads on this connection makes that contract unenforceable from
		// a substring validator (see validate_readonly_query() below), so we
		// explicitly do not enable CLIENT_MULTI_STATEMENTS here.
		if (!mysql_real_connect(
			mysql,
			conn.host.c_str(),
			target.db_username.c_str(),
			target.db_password.c_str(),
			target.default_schema.empty() ? NULL : target.default_schema.c_str(),
			conn.port,
			NULL,
			0
		)) {
			proxy_error("Query_Tool_Handler: mysql_real_connect failed for %s:%d: %s\n",
				conn.host.c_str(), conn.port, mysql_error(mysql));
			mysql_close(mysql);
			continue;
		}

		conn.mysql = mysql;
		connection_pool.push_back(conn);
		pool_size++;

		proxy_info("Query_Tool_Handler: Connected target '%s' to %s:%d\n",
			conn.target_id.c_str(), conn.host.c_str(), conn.port);

		if (default_target_id.empty()) {
			default_target_id = conn.target_id;
		}
	}

	for (const auto& target : target_registry) {
		if (!target.executable || target.protocol != "pgsql") {
			continue;
		}

		PgSQLConnection conn;
		conn.target_id = target.target_id;
		conn.auth_profile_id = target.auth_profile_id;
		conn.host = target.host;
		conn.port = target.port;
		conn.in_use = false;
		conn.current_schema = target.default_schema;

		std::ostringstream conninfo;
		conninfo << "host=" << conn.host
		         << " port=" << conn.port
		         << " user=" << target.db_username
		         << " password=" << target.db_password
		         << " connect_timeout=5";
		if (!target.default_schema.empty()) {
			conninfo << " dbname=" << target.default_schema;
		}

		PGconn* pgconn = PQconnectdb(conninfo.str().c_str());
		if (pgconn == NULL || PQstatus(pgconn) != CONNECTION_OK) {
			proxy_error(
				"Query_Tool_Handler: PQconnectdb failed for %s:%d: %s\n",
				conn.host.c_str(), conn.port, pgconn ? PQerrorMessage(pgconn) : "null connection"
			);
			if (pgconn) {
				PQfinish(pgconn);
			}
			continue;
		}

		conn.pgconn = pgconn;
		pgsql_connection_pool.push_back(conn);
		pg_pool_size++;

		proxy_info("Query_Tool_Handler: Connected target '%s' to pgsql %s:%d\n",
			conn.target_id.c_str(), conn.host.c_str(), conn.port);

		if (default_target_id.empty()) {
			default_target_id = conn.target_id;
		}
	}

	pthread_mutex_unlock(&pool_lock);
	if ((pool_size + pg_pool_size) == 0) {
		proxy_warning("Query_Tool_Handler: No executable targets available yet (handler remains initialized)\n");
		return 0;
	}

	proxy_info(
		"Query_Tool_Handler: Connection pools initialized mysql=%d pgsql=%d, default target '%s'\n",
		pool_size, pg_pool_size, default_target_id.c_str()
	);
	return 0;
}

void Query_Tool_Handler::refresh_target_registry() {
	target_registry.clear();
	default_target_id.clear();

	if (!GloMCPH) {
		return;
	}

	// Per the ABI-3 separation-of-duties contract, the listener consumes
	// MCP_Threads_Handler's in-memory snapshot, NOT a re-read of the
	// runtime_mcp_<X> view tables (which are now admin-side projections
	// owned by the chassis, refreshed lazily per-SELECT). The plugin's
	// LOAD MCP PROFILES TO RUNTIME path (mcp_load_target_auth_map_from_admindb)
	// is what installs main.mcp_<X> into that snapshot; here we just read
	// what's already there.
	const auto profiles = GloMCPH->get_all_target_auth_contexts();

	const auto resolve_endpoint = [&](
		const std::string& protocol,
		int hostgroup_id,
		std::string& host,
		int& port,
		int& backends
	) -> bool {
		std::unique_ptr<SQLite3_result> resultset = dump_runtime_servers_for_protocol(protocol);
		if (!resultset) {
			return false;
		}

		struct CandidateEndpoint {
			int weight = 0;
			std::string host;
			int port = 0;
		};

		std::vector<CandidateEndpoint> candidates;
		for (const auto* row : resultset->rows) {
			if (row == NULL || row->cnt < 4 || row->fields[0] == NULL) {
				continue;
			}

			const int row_hostgroup_id = atoi(row->fields[0]);
			if (row_hostgroup_id != hostgroup_id) {
				continue;
			}

			const int status_idx = runtime_status_col_idx(protocol);
			const std::string status = uppercase_or_unknown((status_idx < row->cnt) ? row->fields[status_idx] : NULL);
			if (!is_runtime_online_status(status)) {
				continue;
			}

			CandidateEndpoint candidate;
			candidate.host = row->fields[1] ? row->fields[1] : "";
			candidate.port = row->fields[2] ? atoi(row->fields[2]) : (is_pgsql_protocol(protocol) ? 5432 : 3306);
			const int weight_idx = runtime_weight_col_idx(protocol);
			candidate.weight = (weight_idx < row->cnt && row->fields[weight_idx]) ? atoi(row->fields[weight_idx]) : 0;
			if (!candidate.host.empty()) {
				candidates.push_back(candidate);
			}
		}

		if (candidates.empty()) {
			return false;
		}

		backends = candidates.size();
		std::vector<int> weights;
		weights.reserve(candidates.size());
		for (size_t i = 0; i < candidates.size(); i++) {
			weights.push_back(candidates[i].weight);
		}
		const size_t picked_idx = pick_weighted_random_index(weights);
		host = candidates[picked_idx].host;
		port = candidates[picked_idx].port;
		return true;
	};

	for (const auto& ctx : profiles) {
		QueryTarget target;
		target.target_id = ctx.target_id;
		target.protocol = ctx.protocol;
		std::transform(target.protocol.begin(), target.protocol.end(), target.protocol.begin(), ::tolower);
		target.hostgroup_id = ctx.hostgroup_id;
		target.auth_profile_id = ctx.auth_profile_id;
		target.db_username = ctx.db_username;
		target.db_password = ctx.db_password;
		target.default_schema = ctx.default_schema;
		target.description = ctx.description;
		target.executable = false;

		int backend_count = 0;
		if (resolve_endpoint(target.protocol, target.hostgroup_id, target.host, target.port, backend_count)) {
			target.executable = !target.db_username.empty();
			if (target.description.empty()) {
				target.description = "Hostgroup " + std::to_string(target.hostgroup_id) +
					" (" + std::to_string(backend_count) + " backend(s))";
			}
			if (!target.executable) {
				proxy_warning(
					"Query_Tool_Handler: target '%s' resolved backend %s:%d but has empty db_username\n",
					target.target_id.c_str(), target.host.c_str(), target.port
				);
			}
		} else {
			if (target.description.empty()) {
				target.description = "Hostgroup " + std::to_string(target.hostgroup_id) + " (no ONLINE backends)";
			}
			proxy_warning(
				"Query_Tool_Handler: target '%s' has no eligible backend for protocol '%s' in hostgroup %d\n",
				target.target_id.c_str(), target.protocol.c_str(), target.hostgroup_id
			);
		}

		target_registry.push_back(target);
	}

	for (const auto& target : target_registry) {
		if (target.executable) {
			default_target_id = target.target_id;
			break;
		}
	}
}

const Query_Tool_Handler::QueryTarget* Query_Tool_Handler::resolve_target(const std::string& target_id) {
	const std::string& resolved_target_id = target_id.empty() ? default_target_id : target_id;
	if (resolved_target_id.empty()) {
		return NULL;
	}
	for (const auto& target : target_registry) {
		if (target.target_id == resolved_target_id) {
			return &target;
		}
	}
	return NULL;
}

std::string Query_Tool_Handler::format_target_unavailable_error(const std::string& target_id) const {
	const std::string resolved_target_id = target_id.empty() ? default_target_id : target_id;
	if (resolved_target_id.empty()) {
		if (target_registry.empty()) {
			return "No MCP targets loaded in runtime_mcp_target_profiles";
		}

		std::ostringstream oss;
		oss << "No executable default target available. Loaded targets: ";
		for (size_t i = 0; i < target_registry.size(); i++) {
			const QueryTarget& t = target_registry[i];
			if (i) {
				oss << ", ";
			}
			oss << t.target_id << "[protocol=" << t.protocol << ", hostgroup=" << t.hostgroup_id;
		if (!t.executable) {
			if (t.db_username.empty()) {
				oss << ", reason=empty db_username in auth_profile_id=" << t.auth_profile_id;
			} else if (t.host.empty()) {
				oss << ", reason=no ONLINE backend, statuses={"
				    << get_runtime_hostgroup_status_summary(t.protocol, t.hostgroup_id) << "}";
			} else {
				oss << ", reason=not executable";
			}
			} else {
				oss << ", executable=1";
			}
			oss << "]";
		}
		return oss.str();
	}

	for (const auto& t : target_registry) {
		if (t.target_id != resolved_target_id) {
			continue;
		}
		if (t.executable) {
			return "Target is executable";
		}

		std::ostringstream oss;
		oss << "Target '" << t.target_id << "' is not executable"
		    << " [protocol=" << t.protocol
		    << ", hostgroup=" << t.hostgroup_id
		    << ", auth_profile_id=" << t.auth_profile_id << "]";

		if (t.db_username.empty()) {
			oss << ": auth profile has empty db_username";
		} else if (t.host.empty()) {
			oss << ": no ONLINE backend in hostgroup " << t.hostgroup_id
			    << ", statuses={" << get_runtime_hostgroup_status_summary(t.protocol, t.hostgroup_id) << "}";
		} else {
			oss << ": backend " << t.host << ":" << t.port << " resolved but target is still non-executable";
		}

		return oss.str();
	}

	return std::string("Unknown target_id: ") + resolved_target_id;
}

void* Query_Tool_Handler::get_connection(const std::string& target_id) {
	const auto find_available_connection = [&](const std::string& resolved_target, const std::string& expected_auth_profile_id) -> void* {
		pthread_mutex_lock(&pool_lock);
		for (auto& conn : connection_pool) {
			if (!conn.in_use && conn.target_id == resolved_target && conn.auth_profile_id == expected_auth_profile_id) {
				conn.in_use = true;
				void* mysql_ptr = conn.mysql;
				pthread_mutex_unlock(&pool_lock);
				return mysql_ptr;
			}
		}
		pthread_mutex_unlock(&pool_lock);
		return NULL;
	};

	refresh_target_registry();
	const std::string resolved_target = target_id.empty() ? default_target_id : target_id;
	const QueryTarget* target = resolve_target(resolved_target);
	if (target == NULL || !target->executable) {
		std::string reason = format_target_unavailable_error(target_id);
		proxy_error("Query_Tool_Handler: %s\n", reason.c_str());
		return NULL;
	}

	void* mysql_ptr = find_available_connection(resolved_target, target->auth_profile_id);
	if (mysql_ptr) {
		return mysql_ptr;
	}

	// Self-heal path: runtime targets/backends may have changed after handler startup.
	if (init_connection_pool() == 0) {
		refresh_target_registry();
		const QueryTarget* refreshed_target = resolve_target(resolved_target);
		if (refreshed_target && refreshed_target->executable) {
			mysql_ptr = find_available_connection(resolved_target, refreshed_target->auth_profile_id);
			if (mysql_ptr) {
				return mysql_ptr;
			}
		}
	}

	proxy_error("Query_Tool_Handler: No available connection for target '%s'\n", resolved_target.c_str());
	return NULL;
}

void* Query_Tool_Handler::get_pgsql_connection(const std::string& target_id) {
	const auto find_available_pg_connection = [&](const std::string& resolved_target, const std::string& expected_auth_profile_id) -> void* {
		pthread_mutex_lock(&pool_lock);
		for (auto& conn : pgsql_connection_pool) {
			if (!conn.in_use && conn.target_id == resolved_target && conn.auth_profile_id == expected_auth_profile_id) {
				conn.in_use = true;
				void* pgconn_ptr = conn.pgconn;
				pthread_mutex_unlock(&pool_lock);
				return pgconn_ptr;
			}
		}
		pthread_mutex_unlock(&pool_lock);
		return NULL;
	};

	refresh_target_registry();
	const std::string resolved_target = target_id.empty() ? default_target_id : target_id;
	const QueryTarget* target = resolve_target(resolved_target);
	if (target == NULL || !target->executable) {
		std::string reason = format_target_unavailable_error(target_id);
		proxy_error("Query_Tool_Handler: %s\n", reason.c_str());
		return NULL;
	}

	void* pgconn_ptr = find_available_pg_connection(resolved_target, target->auth_profile_id);
	if (pgconn_ptr) {
		return pgconn_ptr;
	}

	// Self-heal path: runtime targets/backends may have changed after handler startup.
	if (init_connection_pool() == 0) {
		refresh_target_registry();
		const QueryTarget* refreshed_target = resolve_target(resolved_target);
		if (refreshed_target && refreshed_target->executable) {
			pgconn_ptr = find_available_pg_connection(resolved_target, refreshed_target->auth_profile_id);
			if (pgconn_ptr) {
				return pgconn_ptr;
			}
		}
	}

	proxy_error("Query_Tool_Handler: No available pgsql connection for target '%s'\n", resolved_target.c_str());
	return NULL;
}

void Query_Tool_Handler::return_connection(void* mysql_ptr) {
	if (!mysql_ptr) return;

	pthread_mutex_lock(&pool_lock);

	for (auto& conn : connection_pool) {
		if (conn.mysql == mysql_ptr) {
			conn.in_use = false;
			pthread_mutex_unlock(&pool_lock);
			return;
		}
	}

	for (auto& conn : pgsql_connection_pool) {
		if (conn.pgconn == mysql_ptr) {
			conn.in_use = false;
			pthread_mutex_unlock(&pool_lock);
			return;
		}
	}

	pthread_mutex_unlock(&pool_lock);
}

// Helper to find connection wrapper by mysql pointer (thread-safe, acquires pool_lock)
Query_Tool_Handler::MySQLConnection* Query_Tool_Handler::find_connection(void* mysql_ptr) {
	pthread_mutex_lock(&pool_lock);
	for (auto& conn : connection_pool) {
		if (conn.mysql == mysql_ptr) {
			pthread_mutex_unlock(&pool_lock);
			return &conn;
		}
	}
	pthread_mutex_unlock(&pool_lock);
	return nullptr;
}

// Helper to find pgsql connection wrapper by PGconn pointer (thread-safe, acquires pool_lock)
Query_Tool_Handler::PgSQLConnection* Query_Tool_Handler::find_pgsql_connection(void* pgconn_ptr) {
	pthread_mutex_lock(&pool_lock);
	for (auto& conn : pgsql_connection_pool) {
		if (conn.pgconn == pgconn_ptr) {
			pthread_mutex_unlock(&pool_lock);
			return &conn;
		}
	}
	pthread_mutex_unlock(&pool_lock);
	return nullptr;
}

std::string Query_Tool_Handler::execute_query(const std::string& query, const std::string& target_id) {
	const QueryTarget* target = resolve_target(target_id);
	if (target == NULL) {
		json j;
		j["success"] = false;
		j["error"] = std::string("Unknown target: ") +
			(target_id.empty() ? default_target_id : target_id);
		return j.dump();
	}

	if (target->protocol == "pgsql") {
		void* pgconn_v = get_pgsql_connection(target_id);
		if (!pgconn_v) {
			json j;
			j["success"] = false;
			j["error"] = std::string("No available pgsql connection for target: ") +
				(target_id.empty() ? default_target_id : target_id);
			return j.dump();
		}
		PGconn* pgconn = static_cast<PGconn*>(pgconn_v);
		PGresult* res = PQexec(pgconn, query.c_str());
		if (res == NULL) {
			proxy_error(
				"Query_Tool_Handler: PQexec returned null result for target='%s' query='%s'\n",
				target->target_id.c_str(), query.c_str()
			);
			return_connection(pgconn_v);
			json j;
			j["success"] = false;
			j["error"] = std::string("PQexec returned null result");
			return j.dump();
		}

		ExecStatusType st = PQresultStatus(res);
		if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
			std::string err = PQresultErrorMessage(res);
			proxy_error(
				"Query_Tool_Handler: pgsql query failed for target='%s': %s | query='%s'\n",
				target->target_id.c_str(), err.c_str(), query.c_str()
			);
			PQclear(res);
			return_connection(pgconn_v);
			json j;
			j["success"] = false;
			j["error"] = err;
			return j.dump();
		}

		if (st == PGRES_COMMAND_OK) {
			const char* tuples = PQcmdTuples(res);
			long affected = 0;
			if (tuples && tuples[0] != '\0') {
				affected = atol(tuples);
			}
			PQclear(res);
			return_connection(pgconn_v);
			json j;
			j["success"] = true;
			j["affected_rows"] = affected;
			return j.dump();
		}

		int num_fields = PQnfields(res);
		int num_rows = PQntuples(res);
		json results = json::array();
		for (int r = 0; r < num_rows; r++) {
			json row_data = json::array();
			for (int c = 0; c < num_fields; c++) {
				row_data.push_back(PQgetisnull(res, r, c) ? "" : PQgetvalue(res, r, c));
			}
			results.push_back(row_data);
		}
		PQclear(res);
		return_connection(pgconn_v);

		json j;
		j["success"] = true;
		j["columns"] = num_fields;
		j["rows"] = results;
		return j.dump();
	}

	void* mysql = get_connection(target_id);
	if (!mysql) {
		json j;
		j["success"] = false;
		j["error"] = std::string("No available mysql connection for target: ") +
			(target_id.empty() ? default_target_id : target_id);
		return j.dump();
	}
	MYSQL* mysql_ptr = static_cast<MYSQL*>(mysql);

	if (mysql_query(mysql_ptr, query.c_str())) {
		proxy_error(
			"Query_Tool_Handler: mysql query failed for target='%s': %s | query='%s'\n",
			target->target_id.c_str(), mysql_error(mysql_ptr), query.c_str()
		);
		return_connection(mysql);
		json j;
		j["success"] = false;
		j["error"] = std::string(mysql_error(mysql_ptr));
		return j.dump();
	}

	MYSQL_RES* res = mysql_store_result(mysql_ptr);

	// Capture affected_rows BEFORE return_connection to avoid race condition
	unsigned long affected_rows_val = mysql_affected_rows(mysql_ptr);
	return_connection(mysql);

	if (!res) {
		// No result set (e.g., INSERT/UPDATE)
		json j;
		j["success"] = true;
		j["affected_rows"] = static_cast<long>(affected_rows_val);
		return j.dump();
	}

	int num_fields = mysql_num_fields(res);
	MYSQL_ROW row;

	json results = json::array();
	while ((row = mysql_fetch_row(res))) {
		json row_data = json::array();
		for (int i = 0; i < num_fields; i++) {
			row_data.push_back(row[i] ? row[i] : "");
		}
		results.push_back(row_data);
	}

	mysql_free_result(res);

	json j;
	j["success"] = true;
	j["columns"] = num_fields;
	j["rows"] = results;
	return j.dump();
}

// Execute query with optional schema switching
std::string Query_Tool_Handler::execute_query_with_schema(
	const std::string& query,
	const std::string& schema,
	const std::string& target_id
) {
	const QueryTarget* target = resolve_target(target_id);
	if (target == NULL) {
		json j;
		j["success"] = false;
		j["error"] = std::string("Unknown target: ") +
			(target_id.empty() ? default_target_id : target_id);
		return j.dump();
	}

	if (target->protocol == "pgsql") {
		void* pgconn_v = get_pgsql_connection(target_id);
		if (!pgconn_v) {
			json j;
			j["success"] = false;
			j["error"] = std::string("No available pgsql connection for target: ") +
				(target_id.empty() ? default_target_id : target_id);
			return j.dump();
		}
		PGconn* pgconn = static_cast<PGconn*>(pgconn_v);
		PgSQLConnection* conn_wrapper = find_pgsql_connection(pgconn_v);

		if (!schema.empty() && conn_wrapper && conn_wrapper->current_schema != schema) {
			std::string validated_schema = validate_sql_identifier_sqlite(schema);
			if (validated_schema.empty()) {
				return_connection(pgconn_v);
				json j;
				j["success"] = false;
				j["error"] = "Invalid schema name: contains unsafe characters";
				return j.dump();
			}
			std::string set_search_path = "SET search_path TO " + validated_schema;
			PGresult* set_res = PQexec(pgconn, set_search_path.c_str());
			if (set_res == NULL || PQresultStatus(set_res) != PGRES_COMMAND_OK) {
				std::string err = set_res ? PQresultErrorMessage(set_res) : "set search_path failed";
				proxy_error(
					"Query_Tool_Handler: failed SET search_path for target='%s' schema='%s': %s\n",
					target->target_id.c_str(), validated_schema.c_str(), err.c_str()
				);
				if (set_res) {
					PQclear(set_res);
				}
				return_connection(pgconn_v);
				json j;
				j["success"] = false;
				j["error"] = err;
				return j.dump();
			}
			PQclear(set_res);
			conn_wrapper->current_schema = validated_schema;
		}

		PGresult* res = PQexec(pgconn, query.c_str());
		if (res == NULL) {
			proxy_error(
				"Query_Tool_Handler: PQexec returned null result for target='%s' query='%s'\n",
				target->target_id.c_str(), query.c_str()
			);
			return_connection(pgconn_v);
			json j;
			j["success"] = false;
			j["error"] = std::string("PQexec returned null result");
			return j.dump();
		}

		ExecStatusType st = PQresultStatus(res);
		if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
			std::string err = PQresultErrorMessage(res);
			proxy_error(
				"Query_Tool_Handler: pgsql query with schema failed for target='%s': %s | schema='%s' query='%s'\n",
				target->target_id.c_str(), err.c_str(), schema.c_str(), query.c_str()
			);
			PQclear(res);
			return_connection(pgconn_v);
			json j;
			j["success"] = false;
			j["error"] = err;
			return j.dump();
		}

		if (st == PGRES_COMMAND_OK) {
			const char* tuples = PQcmdTuples(res);
			long affected = 0;
			if (tuples && tuples[0] != '\0') {
				affected = atol(tuples);
			}
			PQclear(res);
			return_connection(pgconn_v);
			json j;
			j["success"] = true;
			j["affected_rows"] = affected;
			return j.dump();
		}

		int num_fields = PQnfields(res);
		int num_rows = PQntuples(res);
		json results = json::array();
		for (int r = 0; r < num_rows; r++) {
			json row_data = json::array();
			for (int c = 0; c < num_fields; c++) {
				row_data.push_back(PQgetisnull(res, r, c) ? "" : PQgetvalue(res, r, c));
			}
			results.push_back(row_data);
		}

		PQclear(res);
		return_connection(pgconn_v);

		json j;
		j["success"] = true;
		j["columns"] = num_fields;
		j["rows"] = results;
		return j.dump();
	}

	void* mysql = get_connection(target_id);
	if (!mysql) {
		json j;
		j["success"] = false;
		j["error"] = std::string("No available mysql connection for target: ") +
			(target_id.empty() ? default_target_id : target_id);
		return j.dump();
	}
	MYSQL* mysql_ptr = static_cast<MYSQL*>(mysql);
	MySQLConnection* conn_wrapper = find_connection(mysql);

	// If schema is provided and differs from current, switch to it
	if (!schema.empty() && conn_wrapper && conn_wrapper->current_schema != schema) {
		if (mysql_select_db(mysql_ptr, schema.c_str()) != 0) {
			proxy_error("Query_Tool_Handler: Failed to select database '%s': %s\n",
				schema.c_str(), mysql_error(mysql_ptr));
			return_connection(mysql);
			json j;
			j["success"] = false;
			j["error"] = std::string("Failed to select database: ") + schema;
			return j.dump();
		}
		// Update current schema tracking
		conn_wrapper->current_schema = schema;
		proxy_info("Query_Tool_Handler: Switched to schema '%s'\n", schema.c_str());
	}

	// Execute the actual query
	if (mysql_query(mysql_ptr, query.c_str())) {
		proxy_error(
			"Query_Tool_Handler: mysql query with schema failed for target='%s': %s | schema='%s' query='%s'\n",
			target->target_id.c_str(), mysql_error(mysql_ptr), schema.c_str(), query.c_str()
		);
		return_connection(mysql);
		json j;
		j["success"] = false;
		j["error"] = std::string(mysql_error(mysql_ptr));
		return j.dump();
	}

	MYSQL_RES* res = mysql_store_result(mysql_ptr);

	// Capture affected_rows BEFORE return_connection to avoid race condition
	unsigned long affected_rows_val = mysql_affected_rows(mysql_ptr);
	return_connection(mysql);

	if (!res) {
		// No result set (e.g., INSERT/UPDATE)
		json j;
		j["success"] = true;
		j["affected_rows"] = static_cast<long>(affected_rows_val);
		return j.dump();
	}

	int num_fields = mysql_num_fields(res);
	MYSQL_ROW row;

	json results = json::array();
	while ((row = mysql_fetch_row(res))) {
		json row_data = json::array();
		for (int i = 0; i < num_fields; i++) {
			row_data.push_back(row[i] ? row[i] : "");
		}
		results.push_back(row_data);
	}

	mysql_free_result(res);

	json j;
	j["success"] = true;
	j["columns"] = num_fields;
	j["rows"] = results;
	return j.dump();
}

bool Query_Tool_Handler::contains_multi_statement(const std::string& query) {
	// Track a small lexical state so a ';' inside a string literal, an
	// identifier-quoted name, or a comment does not produce false positives.
	enum class S { Code, SingleStr, DoubleStr, BacktickIdent, LineComment, BlockComment };
	S state = S::Code;
	bool seen_separator = false;
	const size_t n = query.size();
	for (size_t i = 0; i < n; ++i) {
		const char c = query[i];
		const char next = (i + 1 < n) ? query[i + 1] : '\0';
		switch (state) {
			case S::Code:
				if (c == '\'') { state = S::SingleStr; seen_separator = false; }
				else if (c == '"') { state = S::DoubleStr; seen_separator = false; }
				else if (c == '`') { state = S::BacktickIdent; seen_separator = false; }
				else if (c == '-' && next == '-') { state = S::LineComment; ++i; }
				else if (c == '/' && next == '*') { state = S::BlockComment; ++i; }
				else if (c == ';') { seen_separator = true; }
				else if (seen_separator && !std::isspace(static_cast<unsigned char>(c))) {
					return true;
				}
				break;
			case S::SingleStr:
				if (c == '\\' && next != '\0') { ++i; }
				else if (c == '\'') { state = S::Code; }
				break;
			case S::DoubleStr:
				if (c == '\\' && next != '\0') { ++i; }
				else if (c == '"') { state = S::Code; }
				break;
			case S::BacktickIdent:
				if (c == '`') { state = S::Code; }
				break;
			case S::LineComment:
				if (c == '\n') { state = S::Code; }
				break;
			case S::BlockComment:
				if (c == '*' && next == '/') { state = S::Code; ++i; }
				break;
		}
	}
	return false;
}

bool Query_Tool_Handler::validate_readonly_query(const std::string& query) {
	// GHSA-7wh6-2vcc-gcm4: reject multi-statement payloads up front.  A
	// payload like "SELECT 1; RENAME TABLE x TO y" must not pass validation
	// just because the first keyword is SELECT.
	if (contains_multi_statement(query)) {
		return false;
	}

	std::string upper = query;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	// Substring blacklist of keywords that always indicate a side-effecting
	// statement (or admin operation) regardless of where they appear.  The
	// pre-fix list missed several MySQL keywords that could slip past the
	// first-token whitelist; the additional entries cover them.
	std::vector<std::string> dangerous = {
		"INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
		"TRUNCATE", "REPLACE", "LOAD", "CALL", "EXECUTE",
		"RENAME", "GRANT", "REVOKE", "FLUSH", "RESET", "LOCK",
		"UNLOCK", "KILL", "OPTIMIZE", "REPAIR", "HANDLER",
		"INSTALL", "UNINSTALL", "CHANGE", "PURGE", "SAVEPOINT",
		"RELEASE", "ROLLBACK", "COMMIT", "BEGIN", "START", "XA",
		"SHUTDOWN", "INTO OUTFILE", "INTO DUMPFILE",
		// GHSA-7wh6-2vcc-gcm4: ANALYZE has two side-effecting forms that
		// the prior literal "EXPLAIN ANALYZE" check below cannot cover:
		//   * standalone "ANALYZE TABLE x" (MySQL) / "ANALYZE foo" (PG)
		//     — collects stats, is a write-side-effect on system tables.
		//   * "EXPLAIN ANALYZE ..." with any obfuscation in between,
		//     including comments, multiple whitespace, newlines, and the
		//     PostgreSQL parenthesized option form "EXPLAIN (ANALYZE)" or
		//     "EXPLAIN (VERBOSE, ANALYZE)" — these execute the wrapped
		//     statement on PG.
		// Putting ANALYZE in the substring blacklist catches all of these
		// regardless of whitespace/comment shape.
		"ANALYZE"
	};

	for (const auto& word : dangerous) {
		if (upper.find(word) != std::string::npos) {
			return false;
		}
	}

	// `SET` is dangerous (SET GLOBAL/SESSION) but appears legitimately as a
	// substring inside SELECT (e.g. INTERSECT, RESULTSET).  Reject only when
	// it appears as a standalone token at the start.
	if (upper.substr(0, 4) == "SET ") {
		return false;
	}

	// `USE` changes the current schema as a side effect and must not be
	// reachable through a read-only tool.
	if (upper.substr(0, 4) == "USE ") {
		return false;
	}

	// Whitelist validation: query must start with an allowed read-only keyword.
	if (upper.find("SELECT") == 0) {
		return true;
	}
	if (upper.find("WITH") == 0) {
		return true;
	}
	if (upper.find("EXPLAIN") == 0) {
		return true;
	}
	if (upper.find("SHOW") == 0) {
		return true;
	}
	if (upper.find("DESCRIBE") == 0 || upper.find("DESC") == 0) {
		return true;
	}

	return false;
}

bool Query_Tool_Handler::is_dangerous_query(const std::string& query) {
	std::string upper = query;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	// Extremely dangerous operations
	std::vector<std::string> critical = {
		"DROP DATABASE", "DROP TABLE", "TRUNCATE", "DELETE FROM", "DELETE FROM",
		"GRANT", "REVOKE", "CREATE USER", "ALTER USER", "SET PASSWORD",
		"INTO OUTFILE", "INTO DUMPFILE"
	};

	for (const auto& phrase : critical) {
		if (upper.find(phrase) != std::string::npos) {
			return true;
		}
	}

	return false;
}

std::string Query_Tool_Handler::strip_leading_comments(const std::string& sql) {
	std::string result = sql;
	size_t pos = 0;
	size_t len = result.length();

	// Skip leading whitespace
	while (pos < len && isspace(result[pos])) {
		pos++;
	}

	// Remove leading '-- ' comment lines
	while (pos < len && result.substr(pos, 2) == "--") {
		// Skip until end of line
		while (pos < len && result[pos] != '\n') {
			pos++;
		}
		// Skip the newline
		if (pos < len && result[pos] == '\n') {
			pos++;
		}
		// Skip leading whitespace after the comment
		while (pos < len && isspace(result[pos])) {
			pos++;
		}
	}

	return result.substr(pos);
}

json Query_Tool_Handler::create_tool_schema(
	const std::string& tool_name,
	const std::string& description,
	const std::vector<std::string>& required_params,
	const std::map<std::string, std::string>& optional_params
) {
	json properties = json::object();

	for (const auto& param : required_params) {
		properties[param] = {
			{"type", "string"},
			{"description", param + " parameter"}
		};
	}

	for (const auto& param : optional_params) {
		properties[param.first] = {
			{"type", param.second},
			{"description", param.first + " parameter"}
		};
	}

	json schema;
	schema["type"] = "object";
	schema["properties"] = properties;
	if (!required_params.empty()) {
		schema["required"] = required_params;
	}

	return create_tool_description(tool_name, description, schema);
}

json Query_Tool_Handler::get_tool_list() {
	json tools = json::array();

	// ============================================================
	// INVENTORY TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"list_targets",
		"List logical query targets. Each target maps internally to a ProxySQL hostgroup and routing policy.",
		{},
		{}
	));

	tools.push_back(create_tool_schema(
		"list_schemas",
		"List all available schemas/databases",
		{},
		{{"page_token", "string"}, {"page_size", "integer"}, {"target_id", "string"}}
	));

	tools.push_back(create_tool_schema(
		"list_tables",
		"List tables in a schema",
		{"schema"},
		{{"page_token", "string"}, {"page_size", "integer"}, {"name_filter", "string"}, {"target_id", "string"}}
	));

	// ============================================================
	// STRUCTURE TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"get_constraints",
		"[DEPRECATED] Use catalog.get_relationships with run_id=schema_name and object_key=schema.table instead. Get constraints (foreign keys, unique constraints, etc.) for a table",
		{"schema"},
		{{"table", "string"}}
	));

	// ============================================================
	// SAMPLING TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"sample_rows",
		"Get sample rows from a table (with hard cap on rows returned)",
		{"schema", "table"},
		{{"columns", "string"}, {"where", "string"}, {"order_by", "string"}, {"limit", "integer"}}
	));

	tools.push_back(create_tool_schema(
		"sample_distinct",
		"Sample distinct values from a column",
		{"schema", "table", "column"},
		{{"where", "string"}, {"limit", "integer"}}
	));

	// ============================================================
	// QUERY TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"run_sql_readonly",
		"Execute a read-only SQL query with safety guardrails enforced. Optional schema parameter switches database context before query execution. target_id routes the query to a logical backend target.",
		{"sql"},
		{{"schema", "string"}, {"target_id", "string"}, {"max_rows", "integer"}, {"timeout_sec", "integer"}}
	));

	tools.push_back(create_tool_schema(
		"explain_sql",
		"Explain a query execution plan using EXPLAIN or EXPLAIN ANALYZE. Optional schema parameter switches database context before query execution. target_id routes to a logical backend target.",
		{"sql"},
		{{"schema", "string"}, {"target_id", "string"}}
	));

	// ============================================================
	// RELATIONSHIP INFERENCE TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"suggest_joins",
		"[DEPRECATED] Use catalog.get_relationships with run_id=schema_name instead. Suggest table joins based on heuristic analysis of column names and types",
		{"schema", "table_a"},
		{{"table_b", "string"}, {"max_candidates", "integer"}}
	));

	tools.push_back(create_tool_schema(
		"find_reference_candidates",
		"[DEPRECATED] Use catalog.get_relationships with run_id=schema_name instead. Find tables that might be referenced by a foreign key column",
		{"schema", "table", "column"},
		{{"max_tables", "integer"}}
	));

	// ============================================================
	// DISCOVERY TOOLS (Phase 1: Static Discovery)
	// ============================================================
	tools.push_back(create_tool_schema(
		"discovery.run_static",
		"Trigger ProxySQL to perform static metadata harvest for a specific logical target. target_id is required and protocol-aware (mysql/pgsql).",
		{"target_id"},
		{{"schema_filter", "string"}, {"notes", "string"}}
	));

	// ============================================================
	// CATALOG TOOLS (using Discovery_Schema)
	// ============================================================
	tools.push_back(create_tool_schema(
		"catalog.init",
		"Initialize (or migrate) the SQLite catalog schema using the embedded Discovery_Schema.",
		{},
		{{"sqlite_path", "string"}}
	));

	tools.push_back(create_tool_schema(
		"catalog.search",
		"Full-text search over discovered objects (tables/views/routines) using FTS5. Returns ranked object_keys and basic metadata.",
		{"target_id", "run_id", "query"},
		{{"limit", "integer"}, {"object_type", "string"}, {"schema_name", "string"}}
	));

	tools.push_back(create_tool_schema(
		"catalog.get_object",
		"Fetch a discovered object and its columns/indexes/foreign keys by object_key (schema.object) or by object_id.",
		{"target_id", "run_id"},
		{{"object_id", "integer"}, {"object_key", "string"}, {"include_definition", "boolean"}, {"include_profiles", "boolean"}}
	));

	tools.push_back(create_tool_schema(
		"catalog.list_objects",
		"List objects (paged) for a run, optionally filtered by schema/type, ordered by name or size/rows estimate.",
		{"target_id", "run_id"},
		{{"schema_name", "string"}, {"object_type", "string"}, {"order_by", "string"}, {"page_size", "integer"}, {"page_token", "string"}}
	));

	tools.push_back(create_tool_schema(
		"catalog.get_relationships",
		"Get relationships for a given object: foreign keys, view deps, inferred relationships (deterministic + LLM).",
		{"target_id", "run_id"},
		{{"object_id", "integer"}, {"object_key", "string"}, {"include_inferred", "boolean"}, {"min_confidence", "number"}}
	));

	// ============================================================
	// AGENT TOOLS (Phase 2: LLM Agent Discovery)
	// ============================================================
	tools.push_back(create_tool_schema(
		"agent.run_start",
		"Create a new LLM agent run bound to a deterministic discovery run_id.",
		{"target_id", "run_id", "model_name"},
		{{"prompt_hash", "string"}, {"budget", "object"}}
	));

	tools.push_back(create_tool_schema(
		"agent.run_finish",
		"Mark an agent run finished (success or failure).",
		{"agent_run_id", "status"},
		{{"error", "string"}}
	));

	tools.push_back(create_tool_schema(
		"agent.event_append",
		"Append an agent event for traceability (tool calls, results, notes, decisions).",
		{"agent_run_id", "event_type", "payload"},
		{}
	));

	// ============================================================
	// LLM MEMORY TOOLS (Phase 2: LLM Agent Discovery)
	// ============================================================
	tools.push_back(create_tool_schema(
		"llm.summary_upsert",
		"Upsert a structured semantic summary for an object (table/view/routine). This is the main LLM 'memory' per object.",
		{"target_id", "agent_run_id", "run_id", "object_id", "summary"},
		{{"confidence", "number"}, {"status", "string"}, {"sources", "object"}}
	));

	tools.push_back(create_tool_schema(
		"llm.summary_get",
		"Get the LLM semantic summary for an object, optionally for a specific agent_run_id.",
		{"target_id", "run_id", "object_id"},
		{{"agent_run_id", "integer"}, {"latest", "boolean"}}
	));

	tools.push_back(create_tool_schema(
		"llm.relationship_upsert",
		"Upsert an LLM-inferred relationship (join edge) between objects/columns with confidence and evidence.",
		{"target_id", "agent_run_id", "run_id", "child_object_id", "child_column", "parent_object_id", "parent_column", "confidence"},
		{{"rel_type", "string"}, {"evidence", "object"}}
	));

	tools.push_back(create_tool_schema(
		"llm.domain_upsert",
		"Create or update a domain (cluster) like 'billing' and its description.",
		{"target_id", "agent_run_id", "run_id", "domain_key"},
		{{"title", "string"}, {"description", "string"}, {"confidence", "number"}}
	));

	tools.push_back(create_tool_schema(
		"llm.domain_set_members",
		"Replace members of a domain with a provided list of object_ids and optional roles/confidences.",
		{"target_id", "agent_run_id", "run_id", "domain_key", "members"},
		{}
	));

	tools.push_back(create_tool_schema(
		"llm.metric_upsert",
		"Upsert a metric/KPI definition with optional SQL template and dependencies.",
		{"target_id", "agent_run_id", "run_id", "metric_key", "title"},
		{{"description", "string"}, {"domain_key", "string"}, {"grain", "string"}, {"unit", "string"}, {"sql_template", "string"}, {"depends", "object"}, {"confidence", "number"}}
	));

	tools.push_back(create_tool_schema(
		"llm.question_template_add",
		"Add a question template (NL) mapped to a structured query plan. Extract table/view names from example_sql and populate related_objects. agent_run_id is optional - if not provided, uses the last agent run for the schema.",
		{"target_id", "run_id", "title", "question_nl", "template"},
		{{"agent_run_id", "integer"}, {"example_sql", "string"}, {"related_objects", "array"}, {"confidence", "number"}}
	));

	tools.push_back(create_tool_schema(
		"llm.note_add",
		"Add a durable free-form note (global/schema/object/domain scoped) for the agent memory.",
		{"target_id", "agent_run_id", "run_id", "scope", "body"},
		{{"object_id", "integer"}, {"domain_key", "string"}, {"title", "string"}, {"tags", "array"}}
	));

	tools.push_back(create_tool_schema(
		"llm.search",
		"Full-text search across LLM artifacts. For question_templates, returns example_sql, related_objects, template_json, and confidence. Use include_objects=true with a non-empty query to get full object schema details (for search mode only). Empty query (list mode) returns only templates without objects to avoid huge responses.",
		{"target_id", "run_id"},
		{{"query", "string"}, {"limit", "integer"}, {"include_objects", "boolean"}}
	));

	// ============================================================
	// STATISTICS TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"stats.get_tool_usage",
		"Get in-memory tool usage statistics grouped by tool name and schema.",
		{},
		{}
	));

	json result;
	result["tools"] = tools;
	return result;
}

json Query_Tool_Handler::get_tool_description(const std::string& tool_name) {
	json tools_list = get_tool_list();
	for (const auto& tool : tools_list["tools"]) {
		if (tool["name"] == tool_name) {
			return tool;
		}
	}
	return create_error_response("Tool not found: " + tool_name);
}

/**
 * @brief Extract schema name from tool arguments
 * Returns "(no schema)" for tools without schema context
 */
static std::string extract_schema_name(const std::string& tool_name, const json& arguments, Discovery_Schema* catalog) {
	(void)tool_name;
	std::string target_id = json_string(arguments, "target_id");

	// Tools that use run_id (can be resolved to schema)
	if (arguments.contains("run_id") && !target_id.empty()) {
		std::string run_id_str = json_string(arguments, "run_id");
		int run_id = catalog->resolve_run_id(target_id, run_id_str);
		if (run_id > 0) {
			// Look up schema name from catalog
			char* error = NULL;
			int cols = 0, affected = 0;
			SQLite3_result* resultset = NULL;

			std::ostringstream sql;
			sql << "SELECT schema_name FROM schemas WHERE run_id = " << run_id << " LIMIT 1;";

			catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
			if (resultset && resultset->rows_count > 0) {
				SQLite3_row* row = resultset->rows[0];
				std::string schema = std::string(row->fields[0] ? row->fields[0] : "");
				delete resultset;
				return schema;
			}
			if (resultset) delete resultset;
		}
		return std::to_string(run_id);
	}

	// Tools that use schema_name directly
	if (arguments.contains("schema_name")) {
		return json_string(arguments, "schema_name");
	}

	// Tools without schema context
	return "(no schema)";
}

/**
 * @brief Track tool invocation (thread-safe)
 */
void track_tool_invocation(
	Query_Tool_Handler* handler,
	const std::string& endpoint,
	const std::string& tool_name,
	const std::string& schema_name,
	unsigned long long duration_us
) {
	pthread_mutex_lock(&handler->counters_lock);
	handler->tool_usage_stats[endpoint][tool_name][schema_name].add_timing(duration_us, monotonic_time());
	pthread_mutex_unlock(&handler->counters_lock);
}

json Query_Tool_Handler::execute_tool(const std::string& tool_name, const json& arguments) {
	// Start timing
	unsigned long long start_time = monotonic_time();

	std::string schema = extract_schema_name(tool_name, arguments, catalog);
	json result;

	// ============================================================
	// INVENTORY TOOLS
	// ============================================================
	if (tool_name == "list_targets") {
		refresh_target_registry();
		json targets = json::array();
		for (const auto& target : target_registry) {
			json t;
			t["target_id"] = target.target_id;
			t["description"] = target.description;
			json capabilities = json::array();
			capabilities.push_back("inventory");
			if (target.executable) {
				capabilities.push_back("readonly_sql");
				capabilities.push_back("explain");
			}
			t["capabilities"] = capabilities;
			targets.push_back(t);
		}
		json payload;
		payload["targets"] = targets;
		payload["default_target_id"] = default_target_id;
		result = create_success_response(payload);
	}

	else if (tool_name == "list_schemas") {
		std::string target_id = json_string(arguments, "target_id");
		std::string page_token = json_string(arguments, "page_token");
		int page_size = json_int(arguments, "page_size", 50);
		refresh_target_registry();
		std::string resolved_target_id = target_id.empty() ? default_target_id : target_id;
		if (resolved_target_id.empty()) {
			return create_error_response("target_id is required because no default target is available");
		}
		const QueryTarget* target = resolve_target(resolved_target_id);
		if (target == NULL) {
			return create_error_response("Unknown target_id: " + resolved_target_id);
		}

		// Query catalog schemas for the resolved target only.
		char* error = NULL;
		int cols = 0, affected = 0;
		SQLite3_result* resultset = NULL;

		std::ostringstream sql;
		sql << "SELECT DISTINCT s.schema_name"
		    << " FROM schemas s JOIN runs r ON r.run_id=s.run_id"
		    << " WHERE r.target_id='" << escape_string_literal(resolved_target_id) << "'"
		    << " ORDER BY s.schema_name";
		if (page_size > 0) {
			sql << " LIMIT " << page_size;
			if (!page_token.empty()) {
				sql << " OFFSET " << page_token;
			}
		}
		sql << ";";

		catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
		if (error) {
			std::string err_msg = std::string("Failed to query catalog: ") + error;
			free(error);
			return create_error_response(err_msg);
		}

		// Build results array (as array of arrays to match original format)
		json results = json::array();
		if (resultset && resultset->rows_count > 0) {
			for (const auto& row : resultset->rows) {
				if (row->cnt > 0 && row->fields[0]) {
					json schema_row = json::array();
					schema_row.push_back(std::string(row->fields[0]));
					results.push_back(schema_row);
				}
			}
		}
		delete resultset;

		// Return in format matching original: {columns: 1, rows: [[schema], ...]}
		json output;
		output["columns"] = 1;
		output["rows"] = results;
		output["success"] = true;

		result = create_success_response(output);
	}

	else if (tool_name == "list_tables") {
		std::string schema = json_string(arguments, "schema");
		std::string target_id = json_string(arguments, "target_id");
		std::string page_token = json_string(arguments, "page_token");
		int page_size = json_int(arguments, "page_size", 50);
		std::string name_filter = json_string(arguments, "name_filter");
		(void)page_token;
		(void)page_size;

		refresh_target_registry();
		const QueryTarget* target = resolve_target(target_id);
		if (target == NULL) {
			result = create_error_response(
				target_id.empty() ? "No executable default target available" : "Unknown target_id: " + target_id
			);
			return result;
		}
		if (!target->executable) {
			result = create_error_response(format_target_unavailable_error(target_id));
			return result;
		}

		// Validate schema identifier if provided
		if (!schema.empty()) {
			std::string validated = validate_sql_identifier_sqlite(schema);
			if (validated.empty()) {
				result = create_error_response("Invalid schema name: contains unsafe characters");
				return result;  // Early return on validation failure
			} else {
				schema = validated;
			}
		}

		std::ostringstream sql;
		if (target->protocol == "pgsql") {
			sql << "SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE'";
			if (!schema.empty()) {
				sql << " AND table_schema='" << escape_string_literal(schema) << "'";
			}
			if (!name_filter.empty()) {
				sql << " AND table_name LIKE '" << escape_string_literal(name_filter) << "'";
			}
			sql << " ORDER BY table_name";
		} else {
			sql << "SHOW TABLES";
			if (!schema.empty()) {
				sql << " FROM " << schema;
			}
			if (!name_filter.empty()) {
				// Escape the name_filter to prevent SQL injection
				sql << " LIKE '" << escape_string_literal(name_filter) << "'";
			}
		}
		std::string query_result = execute_query_with_schema(sql.str(), schema, target->target_id);
		result = create_success_response(json::parse(query_result));
	}

	// ============================================================
	// STRUCTURE TOOLS
	// ============================================================
	else if (tool_name == "get_constraints") {
		// Return deprecation warning with migration path
		result = create_error_response(
			"DEPRECATED: The 'get_constraints' tool is deprecated. "
			"Use 'catalog.get_relationships' with run_id='<schema_name>' (or numeric run_id) "
			"and object_key='schema.table' instead. "
			"Example: catalog.get_relationships(run_id='your_schema', object_key='schema.table')"
		);
	}

	// ============================================================
	// DISCOVERY TOOLS
	// ============================================================
	else if (tool_name == "discovery.run_static") {
		std::string target_id = json_string(arguments, "target_id");
		std::string schema_filter = json_string(arguments, "schema_filter");
		std::string notes = json_string(arguments, "notes", "Static discovery harvest");

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else {
			refresh_target_registry();
			const QueryTarget* target = resolve_target(target_id);
			if (target == NULL) {
				result = create_error_response("Unknown target_id: " + target_id);
			} else if (!target->executable) {
				result = create_error_response(format_target_unavailable_error(target_id));
			} else {
				int run_id = -1;
				if (target->protocol == "pgsql") {
					if (!pgsql_harvester) {
						result = create_error_response("PgSQL static harvester not configured");
					} else {
						PgSQL_Static_Harvester harvester(
							target->host,
							target->port > 0 ? target->port : 5432,
							target->db_username,
							target->db_password,
							target->default_schema,
							catalog->get_db_path()
						);
						if (harvester.init()) {
							result = create_error_response("Failed to initialize PgSQL static harvester");
						} else {
							run_id = harvester.run_full_harvest(target->target_id, schema_filter, notes);
							if (run_id >= 0) {
								std::string stats_str = harvester.get_harvest_stats(run_id);
								try {
									json stats = json::parse(stats_str);
									stats["target_id"] = target->target_id;
									stats["protocol"] = target->protocol;
									result = create_success_response(stats);
								} catch (...) {
									json stats;
									stats["run_id"] = run_id;
									stats["target_id"] = target->target_id;
									stats["protocol"] = target->protocol;
									result = create_success_response(stats);
								}
							}
						}
					}
				} else {
					if (!mysql_harvester) {
						result = create_error_response("MySQL static harvester not configured");
					} else {
						Static_Harvester harvester(
							target->host,
							target->port > 0 ? target->port : 3306,
							target->db_username,
							target->db_password,
							target->default_schema,
							catalog->get_db_path()
						);
						if (harvester.init()) {
							result = create_error_response("Failed to initialize MySQL static harvester");
						} else {
							run_id = harvester.run_full_harvest(target->target_id, schema_filter, notes);
							if (run_id >= 0) {
								std::string stats_str = harvester.get_harvest_stats(run_id);
								try {
									json stats = json::parse(stats_str);
									stats["target_id"] = target->target_id;
									stats["protocol"] = target->protocol;
									result = create_success_response(stats);
								} catch (...) {
									json stats;
									stats["run_id"] = run_id;
									stats["target_id"] = target->target_id;
									stats["protocol"] = target->protocol;
									result = create_success_response(stats);
								}
							}
						}
					}
				}

				if (run_id < 0) {
					result = create_error_response("Static discovery failed");
				}
			}
		}
	}

	// ============================================================
	// CATALOG TOOLS (Discovery_Schema)
	// ============================================================
	else if (tool_name == "catalog.init") {
		std::string sqlite_path = json_string(arguments, "sqlite_path");
		if (sqlite_path.empty()) {
			sqlite_path = catalog->get_db_path();
		}
		// Catalog already initialized, just return success
		json init_result;
		init_result["sqlite_path"] = sqlite_path;
		init_result["status"] = "initialized";
		result = create_success_response(init_result);
	}

	else if (tool_name == "catalog.search") {
		std::string target_id = json_string(arguments, "target_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string query = json_string(arguments, "query");
		int limit = json_int(arguments, "limit", 25);
		std::string object_type = json_string(arguments, "object_type");
		std::string schema_name = json_string(arguments, "schema_name");

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else if (query.empty()) {
			result = create_error_response("query is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				std::string search_results = catalog->fts_search(run_id, query, limit, object_type, schema_name);
				try {
					result = create_success_response(json::parse(search_results));
				} catch (...) {
					result = create_error_response("Failed to parse search results");
				}
			}
		}
	}

	else if (tool_name == "catalog.get_object") {
		std::string target_id = json_string(arguments, "target_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		int object_id = json_int(arguments, "object_id", -1);
		std::string object_key = json_string(arguments, "object_key");
		bool include_definition = json_int(arguments, "include_definition", 0) != 0;
		bool include_profiles = json_int(arguments, "include_profiles", 1) != 0;

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				std::string schema_name, object_name;
				if (!object_key.empty()) {
					size_t dot_pos = object_key.find('.');
					if (dot_pos != std::string::npos) {
						schema_name = object_key.substr(0, dot_pos);
						object_name = object_key.substr(dot_pos + 1);
					}
				}

				std::string obj_result = catalog->get_object(
					run_id, object_id, schema_name, object_name,
					include_definition, include_profiles
				);
				try {
					json parsed = json::parse(obj_result);
					if (parsed.is_null()) {
						result = create_error_response("Object not found");
					} else {
						result = create_success_response(parsed);
					}
				} catch (...) {
					result = create_error_response("Failed to parse object data");
				}
			}
		}
	}

	else if (tool_name == "catalog.list_objects") {
		std::string target_id = json_string(arguments, "target_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string schema_name = json_string(arguments, "schema_name");
		std::string object_type = json_string(arguments, "object_type");
		std::string order_by = json_string(arguments, "order_by", "name");
		int page_size = json_int(arguments, "page_size", 50);
		std::string page_token = json_string(arguments, "page_token");

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				std::string list_result = catalog->list_objects(
					run_id, schema_name, object_type, order_by, page_size, page_token
				);
				try {
					result = create_success_response(json::parse(list_result));
				} catch (...) {
					result = create_error_response("Failed to parse objects list");
				}
			}
		}
	}

	else if (tool_name == "catalog.get_relationships") {
		std::string target_id = json_string(arguments, "target_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		int object_id = json_int(arguments, "object_id", -1);
		std::string object_key = json_string(arguments, "object_key");
		bool include_inferred = json_int(arguments, "include_inferred", 1) != 0;
		double min_confidence = json_double(arguments, "min_confidence", 0.0);

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				// Resolve object_key to object_id if needed
				if (object_id < 0 && !object_key.empty()) {
					size_t dot_pos = object_key.find('.');
					if (dot_pos != std::string::npos) {
						std::string schema = object_key.substr(0, dot_pos);
						std::string table = object_key.substr(dot_pos + 1);

						// Validate identifiers to prevent SQL injection
						std::string validated_schema = validate_sql_identifier_sqlite(schema);
						std::string validated_table = validate_sql_identifier_sqlite(table);

						if (validated_schema.empty() || validated_table.empty()) {
							result = create_error_response("Invalid object_key: contains unsafe characters");
						} else {
							// Quick query to get object_id
							char* error = NULL;
							int cols = 0, affected = 0;
							SQLite3_result* resultset = NULL;
							std::ostringstream sql;
							sql << "SELECT object_id FROM objects WHERE run_id = " << run_id
							    << " AND schema_name = '" << validated_schema << "'"
							    << " AND object_name = '" << validated_table << "' LIMIT 1;";
							catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
							if (resultset && !resultset->rows.empty()) {
								object_id = atoi(resultset->rows[0]->fields[0]);
							}
							delete resultset;
						}
					}
				}

				if (object_id < 0 && result.is_null()) {
					result = create_error_response("Valid object_id or object_key is required");
				} else if (!result.is_null()) {
					// Already have an error result from validation
				} else {
					std::string rel_result = catalog->get_relationships(run_id, object_id, include_inferred, min_confidence);
					try {
						result = create_success_response(json::parse(rel_result));
					} catch (...) {
						result = create_error_response("Failed to parse relationships");
					}
				}
			}
		}
	}

	// ============================================================
	// AGENT TOOLS
	// ============================================================
	else if (tool_name == "agent.run_start") {
		std::string target_id = json_string(arguments, "target_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string model_name = json_string(arguments, "model_name");
		std::string prompt_hash = json_string(arguments, "prompt_hash");

		std::string budget_json;
		if (arguments.contains("budget") && !arguments["budget"].is_null()) {
			budget_json = arguments["budget"].dump();
		}

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else if (model_name.empty()) {
			result = create_error_response("model_name is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				int agent_run_id = catalog->create_agent_run(run_id, model_name, prompt_hash, budget_json);
				if (agent_run_id < 0) {
					result = create_error_response("Failed to create agent run");
				} else {
					json agent_result;
					agent_result["agent_run_id"] = agent_run_id;
					agent_result["run_id"] = run_id;
					agent_result["model_name"] = model_name;
					agent_result["status"] = "running";
					result = create_success_response(agent_result);
				}
			}
		}
	}

	else if (tool_name == "agent.run_finish") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string status = json_string(arguments, "status");
		std::string error = json_string(arguments, "error");

		if (agent_run_id <= 0) {
			result = create_error_response("agent_run_id is required");
		} else if (status != "success" && status != "failed") {
			result = create_error_response("status must be 'success' or 'failed'");
		} else {
			int rc = catalog->finish_agent_run(agent_run_id, status, error);
			if (rc) {
				result = create_error_response("Failed to finish agent run");
			} else {
				json finish_result;
				finish_result["agent_run_id"] = agent_run_id;
				finish_result["status"] = status;
				result = create_success_response(finish_result);
			}
		}
	}

	else if (tool_name == "agent.event_append") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string event_type = json_string(arguments, "event_type");

		std::string payload_json;
		if (arguments.contains("payload")) {
			payload_json = arguments["payload"].dump();
		}

		if (agent_run_id <= 0) {
			result = create_error_response("agent_run_id is required");
		} else if (event_type.empty()) {
			result = create_error_response("event_type is required");
		} else {
			int event_id = catalog->append_agent_event(agent_run_id, event_type, payload_json);
			if (event_id < 0) {
				result = create_error_response("Failed to append event");
			} else {
				json event_result;
				event_result["event_id"] = event_id;
				result = create_success_response(event_result);
			}
		}
	}

	// ============================================================
	// LLM MEMORY TOOLS
	// ============================================================
	else if (tool_name == "llm.summary_upsert") {
		std::string target_id = json_string(arguments, "target_id");
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		int object_id = json_int(arguments, "object_id");

		std::string summary_json;
		if (arguments.contains("summary")) {
			summary_json = arguments["summary"].dump();
		}

		double confidence = json_double(arguments, "confidence", 0.5);
		std::string status = json_string(arguments, "status", "draft");

		std::string sources_json;
		if (arguments.contains("sources") && !arguments["sources"].is_null()) {
			sources_json = arguments["sources"].dump();
		}

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (agent_run_id <= 0 || run_id_or_schema.empty() || object_id <= 0) {
			result = create_error_response("agent_run_id, run_id, and object_id are required");
		} else if (summary_json.empty()) {
			result = create_error_response("summary is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				int rc = catalog->upsert_llm_summary(
					agent_run_id, run_id, object_id, summary_json,
					confidence, status, sources_json
				);
				if (rc) {
					result = create_error_response("Failed to upsert summary");
				} else {
					json sum_result;
					sum_result["object_id"] = object_id;
					sum_result["status"] = "upserted";
					result = create_success_response(sum_result);
				}
			}
		}
	}

	else if (tool_name == "llm.summary_get") {
		std::string target_id = json_string(arguments, "target_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		int object_id = json_int(arguments, "object_id");
		int agent_run_id = json_int(arguments, "agent_run_id", -1);
		bool latest = json_int(arguments, "latest", 1) != 0;

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (run_id_or_schema.empty() || object_id <= 0) {
			result = create_error_response("run_id and object_id are required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				std::string sum_result = catalog->get_llm_summary(run_id, object_id, agent_run_id, latest);
				try {
					json parsed = json::parse(sum_result);
					if (parsed.is_null()) {
						result = create_error_response("Summary not found");
					} else {
						result = create_success_response(parsed);
					}
				} catch (...) {
					result = create_error_response("Failed to parse summary");
				}
			}
		}
	}

	else if (tool_name == "llm.relationship_upsert") {
		std::string target_id = json_string(arguments, "target_id");
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		int child_object_id = json_int(arguments, "child_object_id");
		std::string child_column = json_string(arguments, "child_column");
		int parent_object_id = json_int(arguments, "parent_object_id");
		std::string parent_column = json_string(arguments, "parent_column");
		double confidence = json_double(arguments, "confidence");

		std::string rel_type = json_string(arguments, "rel_type", "fk_like");
		std::string evidence_json;
		if (arguments.contains("evidence")) {
			evidence_json = arguments["evidence"].dump();
		}

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (agent_run_id <= 0 || run_id_or_schema.empty() || child_object_id <= 0 || parent_object_id <= 0) {
			result = create_error_response("agent_run_id, run_id, child_object_id, and parent_object_id are required");
		} else if (child_column.empty() || parent_column.empty()) {
			result = create_error_response("child_column and parent_column are required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				int rc = catalog->upsert_llm_relationship(
					agent_run_id, run_id, child_object_id, child_column,
					parent_object_id, parent_column, rel_type, confidence, evidence_json
				);
				if (rc) {
					result = create_error_response("Failed to upsert relationship");
				} else {
					json rel_result;
					rel_result["status"] = "upserted";
					result = create_success_response(rel_result);
				}
			}
		}
	}

	else if (tool_name == "llm.domain_upsert") {
		std::string target_id = json_string(arguments, "target_id");
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string domain_key = json_string(arguments, "domain_key");
		std::string title = json_string(arguments, "title");
		std::string description = json_string(arguments, "description");
		double confidence = json_double(arguments, "confidence", 0.6);

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (agent_run_id <= 0 || run_id_or_schema.empty() || domain_key.empty()) {
			result = create_error_response("agent_run_id, run_id, and domain_key are required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				int domain_id = catalog->upsert_llm_domain(
					agent_run_id, run_id, domain_key, title, description, confidence
				);
				if (domain_id < 0) {
					result = create_error_response("Failed to upsert domain");
				} else {
					json domain_result;
					domain_result["domain_id"] = domain_id;
					domain_result["domain_key"] = domain_key;
					result = create_success_response(domain_result);
				}
			}
		}
	}

	else if (tool_name == "llm.domain_set_members") {
		std::string target_id = json_string(arguments, "target_id");
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string domain_key = json_string(arguments, "domain_key");

		std::string members_json;
		if (arguments.contains("members")) {
			const json& members = arguments["members"];
			if (members.is_array()) {
				// Array passed directly - serialize it
				members_json = members.dump();
			} else if (members.is_string()) {
				// JSON string passed - use it directly
				members_json = members.get<std::string>();
			}
		}

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (agent_run_id <= 0 || run_id_or_schema.empty() || domain_key.empty()) {
			result = create_error_response("agent_run_id, run_id, and domain_key are required");
		} else if (members_json.empty()) {
			proxy_error("llm.domain_set_members: members not provided or invalid type (got: %s)\n",
				arguments.contains("members") ? arguments["members"].dump().c_str() : "missing");
			result = create_error_response("members array is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				proxy_debug(PROXY_DEBUG_GENERIC, 3, "llm.domain_set_members: setting members='%s'\n", members_json.c_str());
				int rc = catalog->set_domain_members(agent_run_id, run_id, domain_key, members_json);
				if (rc) {
					proxy_error("llm.domain_set_members: failed to set members (rc=%d)\n", rc);
					result = create_error_response("Failed to set domain members");
				} else {
					json members_result;
					members_result["domain_key"] = domain_key;
					members_result["status"] = "members_set";
					result = create_success_response(members_result);
				}
			}
		}
	}

	else if (tool_name == "llm.metric_upsert") {
		std::string target_id = json_string(arguments, "target_id");
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string metric_key = json_string(arguments, "metric_key");
		std::string title = json_string(arguments, "title");
		std::string description = json_string(arguments, "description");
		std::string domain_key = json_string(arguments, "domain_key");
		std::string grain = json_string(arguments, "grain");
		std::string unit = json_string(arguments, "unit");
		std::string sql_template = json_string(arguments, "sql_template");

		std::string depends_json;
		if (arguments.contains("depends")) {
			depends_json = arguments["depends"].dump();
		}

		double confidence = json_double(arguments, "confidence", 0.6);

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (agent_run_id <= 0 || run_id_or_schema.empty() || metric_key.empty() || title.empty()) {
			result = create_error_response("agent_run_id, run_id, metric_key, and title are required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				int metric_id = catalog->upsert_llm_metric(
					agent_run_id, run_id, metric_key, title, description, domain_key,
					grain, unit, sql_template, depends_json, confidence
				);
				if (metric_id < 0) {
					result = create_error_response("Failed to upsert metric");
				} else {
					json metric_result;
					metric_result["metric_id"] = metric_id;
					metric_result["metric_key"] = metric_key;
					result = create_success_response(metric_result);
				}
			}
		}
	}

	else if (tool_name == "llm.question_template_add") {
		std::string target_id = json_string(arguments, "target_id");
		int agent_run_id = json_int(arguments, "agent_run_id", 0);  // Optional, default 0
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string title = json_string(arguments, "title");
		std::string question_nl = json_string(arguments, "question_nl");

		std::string template_json;
		if (arguments.contains("template")) {
			template_json = arguments["template"].dump();
		}

		std::string example_sql = json_string(arguments, "example_sql");
		double confidence = json_double(arguments, "confidence", 0.6);

		// Extract related_objects as JSON array string
		std::string related_objects = "";
		if (arguments.contains("related_objects") && arguments["related_objects"].is_array()) {
			related_objects = arguments["related_objects"].dump();
		}

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (run_id_or_schema.empty() || title.empty() || question_nl.empty()) {
			result = create_error_response("run_id, title, and question_nl are required");
		} else if (template_json.empty()) {
			result = create_error_response("template is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				// If agent_run_id not provided, get the last one for this run_id
				if (agent_run_id <= 0) {
					agent_run_id = catalog->get_last_agent_run_id(run_id);
					if (agent_run_id <= 0) {
						result = create_error_response(
							"No agent run found for schema. Please run discovery first, or provide agent_run_id."
						);
					}
				}

				if (agent_run_id > 0) {
					int template_id = catalog->add_question_template(
						agent_run_id, run_id, title, question_nl, template_json, example_sql, related_objects, confidence
					);
					if (template_id < 0) {
						result = create_error_response("Failed to add question template");
					} else {
						json tmpl_result;
						tmpl_result["template_id"] = template_id;
						tmpl_result["agent_run_id"] = agent_run_id;
						tmpl_result["title"] = title;
						result = create_success_response(tmpl_result);
					}
				}
			}
		}
	}

	else if (tool_name == "llm.note_add") {
		std::string target_id = json_string(arguments, "target_id");
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string scope = json_string(arguments, "scope");
		int object_id = json_int(arguments, "object_id", -1);
		std::string domain_key = json_string(arguments, "domain_key");
		std::string title = json_string(arguments, "title");
		std::string body = json_string(arguments, "body");

		std::string tags_json;
		if (arguments.contains("tags") && arguments["tags"].is_array()) {
			tags_json = arguments["tags"].dump();
		}

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (agent_run_id <= 0 || run_id_or_schema.empty() || scope.empty() || body.empty()) {
			result = create_error_response("agent_run_id, run_id, scope, and body are required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				int note_id = catalog->add_llm_note(
					agent_run_id, run_id, scope, object_id, domain_key, title, body, tags_json
				);
				if (note_id < 0) {
					result = create_error_response("Failed to add note");
				} else {
					json note_result;
					note_result["note_id"] = note_id;
					result = create_success_response(note_result);
				}
			}
		}
	}

	else if (tool_name == "llm.search") {
		std::string target_id = json_string(arguments, "target_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string query = json_string(arguments, "query");
		int limit = json_int(arguments, "limit", 25);
		bool include_objects = json_int(arguments, "include_objects", 0) != 0;

		if (target_id.empty()) {
			result = create_error_response("target_id is required");
		} else if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(target_id, run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found for target_id " + target_id + ": " + run_id_or_schema);
			} else {
				// Log the search query
				catalog->log_llm_search(run_id, query, limit);

				std::string search_results = catalog->fts_search_llm(run_id, query, limit, include_objects);
				try {
					result = create_success_response(json::parse(search_results));
				} catch (...) {
					result = create_error_response("Failed to parse LLM search results");
				}
			}
		}
	}

	// ============================================================
	// QUERY TOOLS
	// ============================================================
	else if (tool_name == "run_sql_readonly") {
		std::string sql = json_string(arguments, "sql");
		std::string schema = json_string(arguments, "schema");
		std::string target_id = json_string(arguments, "target_id");
		int max_rows = json_int(arguments, "max_rows", 200);
		int timeout_sec = json_int(arguments, "timeout_sec", 2);
		(void)max_rows;
		(void)timeout_sec;

		if (sql.empty()) {
			result = create_error_response("sql is required");
		} else {
			refresh_target_registry();
			const QueryTarget* target = resolve_target(target_id);
			if (target == NULL) {
				result = create_error_response(
					target_id.empty() ? "No executable default target available" : "Unknown target_id: " + target_id
				);
				return result;
			}
			if (!target->executable) {
				result = create_error_response(format_target_unavailable_error(target_id));
				return result;
			}

			// ============================================================
			// MCP QUERY RULES EVALUATION
			// ============================================================
			MCP_Query_Processor_Output* qpo = catalog->evaluate_mcp_query_rules(
				tool_name,
				target->db_username,
				target->target_id,
				schema,
				arguments,
				sql
			);

			// Check for OK_msg (return success without executing)
			if (qpo->OK_msg) {
				unsigned long long duration = monotonic_time() - start_time;
				track_tool_invocation(this, "MCP", tool_name, schema, duration);
				catalog->log_query_tool_call(tool_name, schema, 0, start_time, duration, "OK message from query rule");
				result = create_success_response(qpo->OK_msg);
				delete qpo;
				return result;
			}

			// Check for error_msg (block the query)
			if (qpo->error_msg) {
				unsigned long long duration = monotonic_time() - start_time;
				track_tool_invocation(this, "MCP", tool_name, schema, duration);
				catalog->log_query_tool_call(tool_name, schema, 0, start_time, duration, "Blocked by query rule");
				result = create_error_response(qpo->error_msg);
				delete qpo;
				return result;
			}

			// Apply rewritten query if provided
			if (qpo->new_query) {
				sql = *qpo->new_query;
			}

			// Apply timeout if provided
			if (qpo->timeout_ms > 0) {
				// Use ceiling division to ensure sub-second timeouts are at least 1 second
				timeout_sec = (qpo->timeout_ms + 999) / 1000;
			}

			// Apply log flag if set
			if (qpo->log == 1) {
				// TODO: Implement query logging if needed
			}

			delete qpo;

			// Strip leading comments from query
			sql = strip_leading_comments(sql);

			// Continue with validation and execution
			if (!validate_readonly_query(sql)) {
				result = create_error_response("SQL is not read-only");
			} else if (is_dangerous_query(sql)) {
				result = create_error_response("SQL contains dangerous operations");
			} else {
				std::string query_result = execute_query_with_schema(sql, schema, target->target_id);
				try {
					json result_json = json::parse(query_result);
					// Check if query actually failed
					if (result_json.contains("success") && !result_json["success"]) {
						result = create_error_response(result_json["error"]);
					} else {
						// ============================================================
						// MCP QUERY DIGEST TRACKING (on success)
						// ============================================================
						// Track successful MCP tool calls for statistics aggregation.
						// This computes a digest hash (similar to MySQL query digest) that
						// groups similar queries together by replacing literal values with
						// placeholders. Statistics are accumulated per digest and can be
						// queried via the stats_mcp_query_digest table.
						//
						// Process:
						//   1. Compute digest hash using fingerprinted arguments
						//   2. Store/aggregate statistics in the digest map (count, timing)
						//   3. Stats are available via stats_mcp_query_digest table
						//
						// Statistics tracked:
						//   - count_star: Number of times this digest was executed
						//   - sum_time, min_time, max_time: Execution timing metrics
						//   - first_seen, last_seen: Timestamps for occurrence tracking
						uint64_t digest = Discovery_Schema::compute_mcp_digest(tool_name, arguments);
						std::string digest_text = Discovery_Schema::fingerprint_mcp_args(arguments);
						unsigned long long duration = monotonic_time() - start_time;
						int digest_run_id = schema.empty() ? 0 : catalog->resolve_run_id(target->target_id, schema);
						catalog->update_mcp_query_digest(
							tool_name,
							digest_run_id,
							digest,
							digest_text,
							duration,
							time(NULL)
						);
						result = create_success_response(result_json);
					}
				} catch (...) {
					result = create_success_response(query_result);
				}
			}
		}
	}

	else if (tool_name == "explain_sql") {
		std::string sql = json_string(arguments, "sql");
		std::string schema = json_string(arguments, "schema");
		std::string target_id = json_string(arguments, "target_id");
		if (sql.empty()) {
			result = create_error_response("sql is required");
		} else {
			refresh_target_registry();
			const QueryTarget* target = resolve_target(target_id);
			if (target == NULL) {
				result = create_error_response(
					target_id.empty() ? "No executable default target available" : "Unknown target_id: " + target_id
				);
				return result;
			}
			if (!target->executable) {
				result = create_error_response(format_target_unavailable_error(target_id));
				return result;
			}

			// Reuse MCP query-rules pipeline for explain_sql too.
			MCP_Query_Processor_Output* qpo = catalog->evaluate_mcp_query_rules(
				tool_name,
				target->db_username,
				target->target_id,
				schema,
				arguments,
				sql
			);

			if (qpo->OK_msg) {
				result = create_success_response(qpo->OK_msg);
				delete qpo;
				return result;
			}
			if (qpo->error_msg) {
				result = create_error_response(qpo->error_msg);
				delete qpo;
				return result;
			}
			if (qpo->new_query) {
				sql = *qpo->new_query;
			}
			delete qpo;

			// GHSA-7wh6-2vcc-gcm4: explain_sql was previously prepending
			// "EXPLAIN " to attacker-controlled SQL with no validation, so
			// any side-effecting statement could ride through as
			// "EXPLAIN <stmt>" with a trailing ";<stmt2>" appended.  Apply
			// the same read-only validation here.
			sql = strip_leading_comments(sql);
			if (!validate_readonly_query(sql)) {
				result = create_error_response("SQL is not read-only");
				return result;
			}
			if (is_dangerous_query(sql)) {
				result = create_error_response("SQL contains dangerous operations");
				return result;
			}

			std::string explain_query = "EXPLAIN " + sql;
			std::string query_result = schema.empty()
				? execute_query(explain_query, target->target_id)
				: execute_query_with_schema(explain_query, schema, target->target_id);
			try {
				result = create_success_response(json::parse(query_result));
			} catch (...) {
				result = create_success_response(query_result);
			}
		}
	}

	// ============================================================
	// RELATIONSHIP INFERENCE TOOLS (DEPRECATED)
	// ============================================================
	else if (tool_name == "suggest_joins") {
		// Return deprecation warning with migration path
		result = create_error_response(
			"DEPRECATED: The 'suggest_joins' tool is deprecated. "
			"Use 'catalog.get_relationships' with run_id='<schema_name>' instead. "
			"This provides foreign keys, view dependencies, and LLM-inferred relationships."
		);
	}

	else if (tool_name == "find_reference_candidates") {
		// Return deprecation warning with migration path
		result = create_error_response(
			"DEPRECATED: The 'find_reference_candidates' tool is deprecated. "
			"Use 'catalog.get_relationships' with run_id='<schema_name>' instead. "
			"This provides foreign keys, view dependencies, and LLM-inferred relationships."
		);
	}

	// ============================================================
	// STATISTICS TOOLS
	// ============================================================
	else if (tool_name == "stats.get_tool_usage") {
		ToolUsageStatsMap stats = get_tool_usage_stats();
		json stats_result = json::object();
		for (ToolUsageStatsMap::const_iterator eit = stats.begin(); eit != stats.end(); ++eit) {
			const std::string& endpoint = eit->first;
			const ToolStatsMap& tools = eit->second;
			json endpoint_stats = json::object();
			for (ToolStatsMap::const_iterator tit = tools.begin(); tit != tools.end(); ++tit) {
				const std::string& tool_name = tit->first;
				const SchemaStatsMap& schemas = tit->second;
				json schema_stats = json::object();
				for (SchemaStatsMap::const_iterator sit = schemas.begin(); sit != schemas.end(); ++sit) {
					json stats_obj = json::object();
					stats_obj["count"] = sit->second.count;
					stats_obj["first_seen"] = sit->second.first_seen;
					stats_obj["last_seen"] = sit->second.last_seen;
					stats_obj["sum_time"] = sit->second.sum_time;
					stats_obj["min_time"] = sit->second.min_time;
					stats_obj["max_time"] = sit->second.max_time;
					schema_stats[sit->first] = stats_obj;
				}
				endpoint_stats[tool_name] = schema_stats;
			}
			stats_result[endpoint] = endpoint_stats;
		}
		result = create_success_response(stats_result);
	}

	// ============================================================
	// FALLBACK - UNKNOWN TOOL
	// ============================================================
	else {
		result = create_error_response("Unknown tool: " + tool_name);
	}

	// Track invocation with timing
	unsigned long long duration = monotonic_time() - start_time;
	track_tool_invocation(this, "MCP", tool_name, schema, duration);

	// Log tool invocation to catalog
	int run_id = 0;
	std::string run_id_str = json_string(arguments, "run_id");
	std::string run_target_id = json_string(arguments, "target_id");
	if (!run_id_str.empty()) {
		if (!run_target_id.empty()) {
			run_id = catalog->resolve_run_id(run_target_id, run_id_str);
		}
	}

	// Extract error message if present
	std::string error_msg;
	if (result.contains("error")) {
		const json& err = result["error"];
		if (err.is_string()) {
			error_msg = err.get<std::string>();
		}
	}

	catalog->log_query_tool_call(tool_name, schema, run_id, start_time, duration, error_msg);

	return result;
}

Query_Tool_Handler::ToolUsageStatsMap Query_Tool_Handler::get_tool_usage_stats() {
	// Thread-safe copy of counters
	pthread_mutex_lock(&counters_lock);
	ToolUsageStatsMap copy = tool_usage_stats;
	pthread_mutex_unlock(&counters_lock);
	return copy;
}

SQLite3_result* Query_Tool_Handler::get_tool_usage_stats_resultset(bool reset) {
	SQLite3_result* result = new SQLite3_result(9);
	result->add_column_definition(SQLITE_TEXT, "endpoint");
	result->add_column_definition(SQLITE_TEXT, "tool");
	result->add_column_definition(SQLITE_TEXT, "schema");
	result->add_column_definition(SQLITE_TEXT, "count");
	result->add_column_definition(SQLITE_TEXT, "first_seen");
	result->add_column_definition(SQLITE_TEXT, "last_seen");
	result->add_column_definition(SQLITE_TEXT, "sum_time");
	result->add_column_definition(SQLITE_TEXT, "min_time");
	result->add_column_definition(SQLITE_TEXT, "max_time");

	pthread_mutex_lock(&counters_lock);

	for (ToolUsageStatsMap::const_iterator endpoint_it = tool_usage_stats.begin();
	     endpoint_it != tool_usage_stats.end(); ++endpoint_it) {
		const std::string& endpoint = endpoint_it->first;
		const ToolStatsMap& tools = endpoint_it->second;

		for (ToolStatsMap::const_iterator tool_it = tools.begin();
		     tool_it != tools.end(); ++tool_it) {
			const std::string& tool_name = tool_it->first;
			const SchemaStatsMap& schemas = tool_it->second;

			for (SchemaStatsMap::const_iterator schema_it = schemas.begin();
			     schema_it != schemas.end(); ++schema_it) {
				const std::string& schema_name = schema_it->first;
				const ToolUsageStats& stats = schema_it->second;

				char** row = new char*[9];
				row[0] = strdup(endpoint.c_str());
				row[1] = strdup(tool_name.c_str());
				row[2] = strdup(schema_name.c_str());

				char buf[32];
				snprintf(buf, sizeof(buf), "%llu", stats.count);
				row[3] = strdup(buf);
				snprintf(buf, sizeof(buf), "%llu", stats.first_seen);
				row[4] = strdup(buf);
				snprintf(buf, sizeof(buf), "%llu", stats.last_seen);
				row[5] = strdup(buf);
				snprintf(buf, sizeof(buf), "%llu", stats.sum_time);
				row[6] = strdup(buf);
				snprintf(buf, sizeof(buf), "%llu", stats.min_time);
				row[7] = strdup(buf);
				snprintf(buf, sizeof(buf), "%llu", stats.max_time);
				row[8] = strdup(buf);

				result->add_row(row);
			}
		}
	}

	if (reset) {
		tool_usage_stats.clear();
	}

	pthread_mutex_unlock(&counters_lock);
	return result;
}

#endif /* PROXYSQL40 */
