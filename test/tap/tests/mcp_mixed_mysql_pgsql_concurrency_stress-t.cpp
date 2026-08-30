/**
 * @file mcp_mixed_mysql_pgsql_concurrency_stress-t.cpp
 * @brief TAP stress test for concurrent MySQL+PgSQL traffic with parallel MCP polling.
 *
 * This test drives both MySQL and PgSQL frontends through ProxySQL at the same
 * time, while independent MCP pollers query stats for both protocols.
 *
 * Workload characteristics:
 * 1. Concurrent MySQL and PgSQL client worker pools.
 * 2. Mixed per-protocol traffic streams:
 *    - simple reads (`SELECT 1`, `SELECT 1 + 2`)
 *    - mutable workload (`INSERT/UPDATE/DELETE/SELECT`)
 *    - randomized sleeps (`SELECT SLEEP(x)` and `SELECT pg_sleep(x)`)
 * 3. Parallel MCP polling for both protocols:
 *    - `stats.show_processlist` for `db_type=mysql|pgsql`
 *    - `stats.show_queries` for `db_type=mysql|pgsql`
 *
 * Primary objective: validate MCP stats behavior under simultaneous cross-protocol
 * load and verify that filtering/sorting metadata remains consistent.
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "mysql.h"
#include "libpq-fe.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mcp_client.h"

using json = nlohmann::json;

namespace {

/** Default number of MySQL worker threads. */
static constexpr int k_default_mysql_worker_threads = 12;
/** Default number of PgSQL worker threads. */
static constexpr int k_default_pgsql_worker_threads = 12;
/** Default stress runtime in seconds. */
static constexpr int k_default_runtime_seconds = 14;
/** Default MCP cap for `stats.show_processlist`. */
static constexpr int k_default_processlist_cap = 120;
/** Default MCP cap for `stats.show_queries`. */
static constexpr int k_default_show_queries_cap = 180;
/** Requested processlist limit used to verify cap metadata. */
static constexpr int k_processlist_requested_limit = 500;
/** Requested show_queries limit used to verify cap metadata. */
static constexpr int k_show_queries_requested_limit = 500;
/** Minimum successful poll count expected from each MCP poller thread. */
static constexpr uint64_t k_min_successful_polls = 10;
/** Minimum successful MySQL query volume expected. */
static constexpr uint64_t k_min_total_mysql_queries = 300;
/** Minimum successful PgSQL query volume expected. */
static constexpr uint64_t k_min_total_pgsql_queries = 300;
/** Fixed schema used for MySQL workload table. */
static constexpr const char* k_mysql_workload_schema = "test";

/** Lower bound for generated processlist cap profile values. */
static constexpr int k_min_processlist_cap = 10;
/** Lower bound for generated show_queries cap profile values. */
static constexpr int k_min_show_queries_cap = 10;
/** Maximum allowed worker threads per protocol from environment. */
static constexpr int k_max_worker_threads = 256;
/** Maximum allowed runtime in seconds from environment. */
static constexpr int k_max_runtime_seconds = 1800;
/** Maximum allowed cap-churn interval in milliseconds from environment. */
static constexpr int k_max_cap_churn_interval_ms = 10000;
/** Minimum allowed cap-churn interval in milliseconds from environment. */
static constexpr int k_min_cap_churn_interval_ms = 50;
/** Default cap-churn interval in milliseconds. */
static constexpr int k_default_cap_churn_interval_ms = 700;

using MYSQLConnPtr = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

/**
 * @brief Aggregated counters for a protocol workload generator.
 */
struct workload_stats_t {
	std::atomic<uint64_t> connected_workers {0};
	std::atomic<uint64_t> connection_failures {0};
	std::atomic<uint64_t> total_queries {0};
	std::atomic<uint64_t> failed_queries {0};
	std::atomic<uint64_t> simple_queries {0};
	std::atomic<uint64_t> insert_queries {0};
	std::atomic<uint64_t> update_queries {0};
	std::atomic<uint64_t> delete_queries {0};
	std::atomic<uint64_t> table_select_queries {0};
	std::atomic<uint64_t> sleep_queries {0};
};

/**
 * @brief Aggregated counters for an MCP show_processlist poller.
 */
struct processlist_poll_stats_t {
	std::atomic<uint64_t> calls_total {0};
	std::atomic<uint64_t> calls_ok {0};
	std::atomic<uint64_t> calls_failed {0};
	std::atomic<uint64_t> parse_failures {0};
	std::atomic<uint64_t> metadata_failures {0};
	std::atomic<uint64_t> row_shape_failures {0};
	std::atomic<uint64_t> non_empty_snapshots {0};
	std::atomic<uint64_t> filtered_calls_ok {0};
	std::atomic<uint64_t> filtered_non_empty_snapshots {0};
	std::atomic<uint64_t> filtered_invalid_rows {0};
	std::atomic<uint64_t> max_sessions_observed {0};
};

/**
 * @brief Aggregated counters for an MCP show_queries poller.
 */
struct show_queries_poll_stats_t {
	std::atomic<uint64_t> calls_total {0};
	std::atomic<uint64_t> calls_ok {0};
	std::atomic<uint64_t> calls_failed {0};
	std::atomic<uint64_t> parse_failures {0};
	std::atomic<uint64_t> metadata_failures {0};
	std::atomic<uint64_t> sorted_failures {0};
	std::atomic<uint64_t> digests_seen_snapshots {0};
	std::atomic<uint64_t> filtered_calls_ok {0};
	std::atomic<uint64_t> filtered_non_empty_snapshots {0};
	std::atomic<uint64_t> filtered_invalid_rows {0};
};

/**
 * @brief Parse an integer environment variable with range clamping.
 *
 * If the variable is absent or invalid, the default value is returned.
 *
 * @param name Environment variable name.
 * @param default_value Value used when the variable is absent or invalid.
 * @param min_value Lower accepted bound.
 * @param max_value Upper accepted bound.
 * @return Parsed and clamped value.
 */
int env_int_clamped(const char* name, int default_value, int min_value, int max_value) {
	const char* value = std::getenv(name);
	if (!value || std::strlen(value) == 0) {
		return default_value;
	}

	char* end = nullptr;
	long parsed = std::strtol(value, &end, 10);
	if (!end || *end != '\0') {
		return default_value;
	}

	if (parsed < static_cast<long>(min_value)) {
		return min_value;
	}
	if (parsed > static_cast<long>(max_value)) {
		return max_value;
	}
	return static_cast<int>(parsed);
}

/**
 * @brief Parse a boolean environment variable.
 *
 * Accepted true values: `1`, `true`, `yes`, `on` (case-insensitive).
 * Accepted false values: `0`, `false`, `no`, `off` (case-insensitive).
 * Any other value falls back to the provided default.
 *
 * @param name Environment variable name.
 * @param default_value Value used when the variable is absent or invalid.
 * @return Parsed boolean value.
 */
bool env_bool(const char* name, bool default_value) {
	const char* raw = std::getenv(name);
	if (!raw || std::strlen(raw) == 0) {
		return default_value;
	}

	std::string value(raw);
	std::transform(value.begin(), value.end(), value.begin(), [] (unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});

	if (value == "1" || value == "true" || value == "yes" || value == "on") {
		return true;
	}
	if (value == "0" || value == "false" || value == "no" || value == "off") {
		return false;
	}
	return default_value;
}

/**
 * @brief Build a three-level cap profile used for optional live cap churn.
 *
 * The returned profile always includes @p max_cap and one or two lower levels,
 * then removes duplicates while preserving ascending order.
 *
 * @param max_cap Highest cap value in the profile.
 * @param min_cap Minimum cap value to enforce.
 * @return Ordered unique cap profile.
 */
std::vector<int> build_cap_profile(int max_cap, int min_cap) {
	std::vector<int> caps = {
		std::max(min_cap, max_cap / 3),
		std::max(min_cap, max_cap / 2),
		std::max(min_cap, max_cap)
	};
	std::sort(caps.begin(), caps.end());
	caps.erase(std::unique(caps.begin(), caps.end()), caps.end());
	return caps;
}

/**
 * @brief Execute an admin SQL statement and consume any result set.
 *
 * @param admin Open admin connection.
 * @param query SQL statement to execute.
 * @param context Diagnostic label used on failure.
 * @return true on success, false on failure.
 */
bool run_admin_stmt(MYSQL* admin, const std::string& query, const char* context) {
	if (!admin) {
		diag("%s: admin connection is null", context);
		return false;
	}
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("%s failed: %s", context, mysql_error(admin));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (res) {
		mysql_free_result(res);
	}
	return true;
}

std::string escape_sql_literal(MYSQL* admin, const char* input) {
	if (input == nullptr) return {};
	const size_t input_length = std::strlen(input);
	std::string escaped(input_length * 2 + 1, '\0');
	const unsigned long escaped_length = mysql_real_escape_string(
		admin, escaped.data(), input, static_cast<unsigned long>(input_length));
	escaped.resize(escaped_length);
	return escaped;
}

/**
 * @brief Configure MCP runtime for concurrent cross-protocol stats polling.
 *
 * @param admin Open admin connection.
 * @param cl TAP command-line configuration.
 * @return true if all setup statements succeeded.
 */
bool configure_mcp_runtime(
	MYSQL* admin,
	const CommandLine& cl,
	int processlist_cap,
	int show_queries_cap
) {
	if (admin == nullptr) return false;
	const std::string auth_token = escape_sql_literal(admin, cl.mcp_auth_token);
	const std::vector<std::string> statements = {
		"SET mcp-port=" + std::to_string(cl.mcp_port),
		"SET mcp-use_ssl=false",
		"SET mcp-enabled=true",
		"SET mcp-config_endpoint_auth='" + auth_token + "'",
		"SET mcp-stats_endpoint_auth='" + auth_token + "'",
		"SET mcp-stats_show_processlist_max_rows=" + std::to_string(processlist_cap),
		"SET mcp-stats_show_queries_max_rows=" + std::to_string(show_queries_cap),
		"LOAD MCP VARIABLES TO RUNTIME"
	};

	for (const auto& stmt : statements) {
		if (!run_admin_stmt(admin, stmt, "MCP mixed stress setup")) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Restore MCP variables changed by this test.
 *
 * @param admin Open admin connection.
 */
void restore_mcp_runtime(MYSQL* admin) {
	if (!admin) {
		return;
	}
	run_admin_stmt(admin, "LOAD MCP VARIABLES FROM DISK", "MCP mixed stress restore");
}

/**
 * @brief Execute a SQL statement on MySQL and validate success.
 *
 * @param conn Open MySQL connection.
 * @param sql SQL statement to execute.
 * @param error Output error text on failure.
 * @return true on success, false on failure.
 */
bool execute_mysql_sql(MYSQL* conn, const std::string& sql, std::string& error) {
	if (!conn) {
		error = "MySQL connection is null";
		return false;
	}
	if (mysql_query(conn, sql.c_str()) != 0) {
		error = mysql_error(conn);
		return false;
	}
	MYSQL_RES* res = mysql_store_result(conn);
	if (res) {
		mysql_free_result(res);
	} else if (mysql_field_count(conn) != 0) {
		error = mysql_error(conn);
		return false;
	}
	return true;
}

/**
 * @brief Open a MySQL connection through ProxySQL.
 *
 * @param host MySQL frontend host.
 * @param port MySQL frontend port.
 * @param user User for authentication.
 * @param pass Password for authentication.
 * @param error Output error text on failure.
 * @return Managed connection pointer (null on failure).
 */
MYSQLConnPtr create_mysql_connection(const char* host, int port, const char* user, const char* pass, std::string& error) {
	MYSQL* raw = mysql_init(nullptr);
	if (!raw) {
		error = "mysql_init returned null";
		return MYSQLConnPtr(nullptr, &mysql_close);
	}
	unsigned int connect_timeout_s = 5;
	mysql_options(raw, MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout_s);
	if (!mysql_real_connect(raw, host, user, pass, nullptr, port, nullptr, 0)) {
		error = mysql_error(raw);
		mysql_close(raw);
		return MYSQLConnPtr(nullptr, &mysql_close);
	}
	return MYSQLConnPtr(raw, &mysql_close);
}

/**
 * @brief Execute a SQL statement on PgSQL and validate status class.
 *
 * @param conn Open PgSQL connection.
 * @param sql SQL statement to execute.
 * @param error Output error text on failure.
 * @return true on success (command or tuple result), false on failure.
 */
bool execute_pg_sql(PGconn* conn, const std::string& sql, std::string& error) {
	if (!conn) {
		error = "PgSQL connection is null";
		return false;
	}
	PGresult* res = PQexec(conn, sql.c_str());
	if (!res) {
		error = PQerrorMessage(conn);
		return false;
	}
	const ExecStatusType status = PQresultStatus(res);
	const bool ok = (status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK);
	if (!ok) {
		error = PQresultErrorMessage(res) ? PQresultErrorMessage(res) : "unknown PgSQL execution error";
	}
	PQclear(res);
	return ok;
}

/**
 * @brief Open a PgSQL connection through ProxySQL.
 *
 * @param cl TAP command-line configuration.
 * @param use_root_credentials Whether to use privileged pgsql root credentials.
 * @param application_name Optional application_name value.
 * @param error Output error text on failure.
 * @return Managed connection pointer (null on failure).
 */
PGConnPtr create_pg_connection(
	const CommandLine& cl,
	bool use_root_credentials,
	const std::string& application_name,
	std::string& error
) {
	const char* host = use_root_credentials ? cl.pgsql_root_host : cl.pgsql_host;
	const int port = use_root_credentials ? cl.pgsql_root_port : cl.pgsql_port;
	const char* user = use_root_credentials ? cl.pgsql_root_username : cl.pgsql_username;
	const char* pass = use_root_credentials ? cl.pgsql_root_password : cl.pgsql_password;

	std::ostringstream ss;
	ss << "host=" << host
	   << " port=" << port
	   << " dbname=postgres"
	   << " user=" << user
	   << " password=" << pass
	   << " sslmode=disable"
	   << " connect_timeout=5";
	if (!application_name.empty()) {
		ss << " application_name=" << application_name;
	}

	PGconn* raw = PQconnectdb(ss.str().c_str());
	PGConnPtr conn(raw, &PQfinish);
	if (!raw || PQstatus(raw) != CONNECTION_OK) {
		error = raw ? PQerrorMessage(raw) : "PQconnectdb returned null connection";
		return PGConnPtr(nullptr, &PQfinish);
	}
	return conn;
}

/**
 * @brief Case-insensitive substring check.
 *
 * @param haystack Candidate text.
 * @param needle Search token.
 * @return true when @p needle appears in @p haystack ignoring case.
 */
bool contains_icase(const std::string& haystack, const std::string& needle) {
	if (needle.empty()) {
		return true;
	}
	for (size_t p = 0; p < haystack.size(); ++p) {
		size_t i = 0;
		while (i < needle.size() && (p + i) < haystack.size()) {
			const unsigned char lhs = static_cast<unsigned char>(haystack[p + i]);
			const unsigned char rhs = static_cast<unsigned char>(needle[i]);
			if (std::tolower(lhs) != std::tolower(rhs)) {
				break;
			}
			++i;
		}
		if (i == needle.size()) {
			return true;
		}
	}
	return false;
}

/**
 * @brief Parse successful MCP tool payload into a result object.
 *
 * Supported payload shapes:
 * - direct result object: `{ ... }`
 * - legacy wrapped payload: `{ "success": true, "result": { ... } }`
 *
 * @param response MCP response object.
 * @param result_obj Output parsed result object.
 * @param error Output error text on failure.
 * @return true on successful parsing.
 */
bool extract_tool_result(const MCPResponse& response, json& result_obj, std::string& error) {
	if (!response.is_success()) {
		error = response.get_error_message();
		return false;
	}

	const json& payload = response.get_result();
	if (!payload.is_object()) {
		error = "MCP payload is not an object";
		return false;
	}

	if (!payload.contains("success") && !payload.contains("result")) {
		result_obj = payload;
		return true;
	}

	if (!payload.value("success", false)) {
		error = payload.value("error", std::string("tool returned error payload"));
		return false;
	}

	if (!payload.contains("result") || !payload["result"].is_object()) {
		error = "wrapped MCP payload missing object field 'result'";
		return false;
	}

	result_obj = payload["result"];
	return true;
}

/**
 * @brief Atomically update an integer maximum value.
 *
 * @tparam T Unsigned integer type.
 * @param max_value Atomic max target.
 * @param candidate Candidate max value.
 */
template <typename T>
void atomic_update_max(std::atomic<T>& max_value, T candidate) {
	T current = max_value.load(std::memory_order_relaxed);
	while (candidate > current && !max_value.compare_exchange_weak(
		current, candidate, std::memory_order_relaxed, std::memory_order_relaxed
	)) {
	}
}

/**
 * @brief Create workload table used by concurrent MySQL workers.
 *
 * @param conn Open setup connection.
 * @param table_name Test table name.
 * @param error Output error text on failure.
 * @return true when table creation succeeds.
 */
bool create_mysql_workload_table(MYSQL* conn, const std::string& table_name, std::string& error) {
	if (!execute_mysql_sql(conn, std::string("CREATE DATABASE IF NOT EXISTS ") + k_mysql_workload_schema, error)) {
		return false;
	}
	const std::string drop_sql = "DROP TABLE IF EXISTS " + std::string(k_mysql_workload_schema) + "." + table_name;
	if (!execute_mysql_sql(conn, drop_sql, error)) {
		return false;
	}
	const std::string create_sql =
		"CREATE TABLE " + std::string(k_mysql_workload_schema) + "." + table_name + " ("
		"id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, "
		"worker_id INT NOT NULL, "
		"v INT NOT NULL, "
		"payload TEXT NOT NULL, "
		"created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
		")";
	return execute_mysql_sql(conn, create_sql, error);
}

/**
 * @brief Drop MySQL workload table created by this test.
 *
 * @param conn Open setup connection.
 * @param table_name Test table name.
 * @param error Output error text on failure.
 * @return true when table drop succeeds.
 */
bool drop_mysql_workload_table(MYSQL* conn, const std::string& table_name, std::string& error) {
	const std::string drop_sql = "DROP TABLE IF EXISTS " + std::string(k_mysql_workload_schema) + "." + table_name;
	return execute_mysql_sql(conn, drop_sql, error);
}

/**
 * @brief Create workload table used by concurrent PgSQL workers.
 *
 * @param conn Open setup connection.
 * @param table_name Test table name.
 * @param error Output error text on failure.
 * @return true when table creation succeeds.
 */
bool create_pgsql_workload_table(PGconn* conn, const std::string& table_name, std::string& error) {
	const std::string drop_sql = "DROP TABLE IF EXISTS " + table_name;
	if (!execute_pg_sql(conn, drop_sql, error)) {
		return false;
	}

	const std::string create_sql =
		"CREATE TABLE " + table_name + " ("
		"id BIGSERIAL PRIMARY KEY, "
		"worker_id INT NOT NULL, "
		"v INT NOT NULL, "
		"payload TEXT NOT NULL, "
		"created_at TIMESTAMP NOT NULL DEFAULT NOW()"
		")";

	return execute_pg_sql(conn, create_sql, error);
}

/**
 * @brief Drop PgSQL workload table created by this test.
 *
 * @param conn Open setup connection.
 * @param table_name Test table name.
 * @param error Output error text on failure.
 * @return true when table drop succeeds.
 */
bool drop_pgsql_workload_table(PGconn* conn, const std::string& table_name, std::string& error) {
	const std::string drop_sql = "DROP TABLE IF EXISTS " + table_name;
	return execute_pg_sql(conn, drop_sql, error);
}

/**
 * @brief MySQL worker thread body issuing mixed traffic continuously.
 *
 * @param worker_id Worker identifier.
 * @param cl TAP command-line configuration.
 * @param table_name Shared MySQL workload table.
 * @param stop Stop flag set by main thread.
 * @param stats Shared workload counters.
 */
void run_mysql_worker(
	int worker_id,
	const CommandLine& cl,
	const std::string& table_name,
	const std::atomic<bool>& stop,
	workload_stats_t& stats
) {
	std::string err;
	MYSQLConnPtr conn = create_mysql_connection(cl.root_host, cl.root_port, cl.root_username, cl.root_password, err);
	if (!conn) {
		conn = create_mysql_connection(cl.host, cl.port, cl.username, cl.password, err);
	}
	if (!conn) {
		stats.connection_failures.fetch_add(1, std::memory_order_relaxed);
		return;
	}

	stats.connected_workers.fetch_add(1, std::memory_order_relaxed);

	std::mt19937 rng(static_cast<uint32_t>(
		std::chrono::steady_clock::now().time_since_epoch().count() ^ (worker_id * 2654435761U)
	));
	std::uniform_int_distribution<int> op_dist(0, 99);
	std::uniform_int_distribution<int> val_dist(1, 100000);
	std::uniform_int_distribution<int> sleep_ms_dist(50, 350);

	uint64_t local_seq = 0;
	while (!stop.load(std::memory_order_relaxed)) {
		const int roll = op_dist(rng);
		std::string sql;
		enum class op_t { simple, ins, upd, del, sel, sleep } op = op_t::simple;

		if (roll < 20) {
			sql = "SELECT 1";
			op = op_t::simple;
		} else if (roll < 35) {
			sql = "SELECT 1 + 2";
			op = op_t::simple;
		} else if (roll < 55) {
			sql = "INSERT INTO " + std::string(k_mysql_workload_schema) + "." + table_name + " (worker_id, v, payload) VALUES (" +
				std::to_string(worker_id) + ", " + std::to_string(val_dist(rng)) + ", 'mx_" +
				std::to_string(worker_id) + "_" + std::to_string(local_seq) + "')";
			op = op_t::ins;
		} else if (roll < 70) {
			sql = "UPDATE " + std::string(k_mysql_workload_schema) + "." + table_name + " "
			      "SET v = v + 1, payload = CONCAT(payload, '_u') "
			      "WHERE worker_id=" + std::to_string(worker_id) + " "
			      "ORDER BY id DESC LIMIT 1";
			op = op_t::upd;
		} else if (roll < 82) {
			sql = "DELETE FROM " + std::string(k_mysql_workload_schema) + "." + table_name + " "
			      "WHERE worker_id=" + std::to_string(worker_id) + " "
			      "ORDER BY id ASC LIMIT 1";
			op = op_t::del;
		} else if (roll < 90) {
			sql = "SELECT COUNT(*) FROM " + std::string(k_mysql_workload_schema) + "." + table_name +
			      " WHERE worker_id=" + std::to_string(worker_id);
			op = op_t::sel;
		} else {
			const double sleep_s = static_cast<double>(sleep_ms_dist(rng)) / 1000.0;
			std::ostringstream ss;
			ss.setf(std::ios::fixed);
			ss.precision(3);
			ss << "SELECT SLEEP(" << sleep_s << ")";
			sql = ss.str();
			op = op_t::sleep;
		}

		std::string query_error;
		if (!execute_mysql_sql(conn.get(), sql, query_error)) {
			stats.failed_queries.fetch_add(1, std::memory_order_relaxed);
		} else {
			stats.total_queries.fetch_add(1, std::memory_order_relaxed);
			switch (op) {
				case op_t::simple:
					stats.simple_queries.fetch_add(1, std::memory_order_relaxed);
					break;
				case op_t::ins:
					stats.insert_queries.fetch_add(1, std::memory_order_relaxed);
					break;
				case op_t::upd:
					stats.update_queries.fetch_add(1, std::memory_order_relaxed);
					break;
				case op_t::del:
					stats.delete_queries.fetch_add(1, std::memory_order_relaxed);
					break;
				case op_t::sel:
					stats.table_select_queries.fetch_add(1, std::memory_order_relaxed);
					break;
				case op_t::sleep:
					stats.sleep_queries.fetch_add(1, std::memory_order_relaxed);
					break;
			}
		}

		++local_seq;
	}
}

/**
 * @brief PgSQL worker thread body issuing mixed traffic continuously.
 *
 * @param worker_id Worker identifier.
 * @param cl TAP command-line configuration.
 * @param table_name Shared PgSQL workload table.
 * @param stop Stop flag set by main thread.
 * @param stats Shared workload counters.
 */
void run_pgsql_worker(
	int worker_id,
	const CommandLine& cl,
	const std::string& table_name,
	const std::atomic<bool>& stop,
	workload_stats_t& stats
) {
	std::string err;
	PGConnPtr conn = create_pg_connection(cl, true, "mcp_mixed_pg_worker_" + std::to_string(worker_id), err);
	if (!conn) {
		conn = create_pg_connection(cl, false, "mcp_mixed_pg_worker_" + std::to_string(worker_id), err);
	}
	if (!conn) {
		stats.connection_failures.fetch_add(1, std::memory_order_relaxed);
		return;
	}

	stats.connected_workers.fetch_add(1, std::memory_order_relaxed);

	std::mt19937 rng(static_cast<uint32_t>(
		std::chrono::steady_clock::now().time_since_epoch().count() ^ (worker_id * 1140071481U)
	));
	std::uniform_int_distribution<int> op_dist(0, 99);
	std::uniform_int_distribution<int> val_dist(1, 100000);
	std::uniform_int_distribution<int> sleep_ms_dist(50, 350);

	uint64_t local_seq = 0;
	while (!stop.load(std::memory_order_relaxed)) {
		const int roll = op_dist(rng);
		std::string sql;
		enum class op_t { simple, ins, upd, del, sel, sleep } op = op_t::simple;

		if (roll < 20) {
			sql = "SELECT 1";
			op = op_t::simple;
		} else if (roll < 35) {
			sql = "SELECT 1 + 2";
			op = op_t::simple;
		} else if (roll < 55) {
			sql = "INSERT INTO " + table_name + " (worker_id, v, payload) VALUES (" +
				std::to_string(worker_id) + ", " + std::to_string(val_dist(rng)) + ", 'pg_" +
				std::to_string(worker_id) + "_" + std::to_string(local_seq) + "')";
			op = op_t::ins;
		} else if (roll < 70) {
			sql = "UPDATE " + table_name + " SET v = v + 1, payload = payload || '_u' "
			      "WHERE id = (SELECT id FROM " + table_name + " WHERE worker_id=" +
			      std::to_string(worker_id) + " ORDER BY id DESC LIMIT 1)";
			op = op_t::upd;
		} else if (roll < 82) {
			sql = "DELETE FROM " + table_name + " WHERE id IN (SELECT id FROM " + table_name +
			      " WHERE worker_id=" + std::to_string(worker_id) + " ORDER BY id ASC LIMIT 1)";
			op = op_t::del;
		} else if (roll < 90) {
			sql = "SELECT COUNT(*) FROM " + table_name + " WHERE worker_id=" + std::to_string(worker_id);
			op = op_t::sel;
		} else {
			const double sleep_s = static_cast<double>(sleep_ms_dist(rng)) / 1000.0;
			std::ostringstream ss;
			ss.setf(std::ios::fixed);
			ss.precision(3);
			ss << "SELECT pg_sleep(" << sleep_s << ")";
			sql = ss.str();
			op = op_t::sleep;
		}

		std::string query_error;
		if (!execute_pg_sql(conn.get(), sql, query_error)) {
			stats.failed_queries.fetch_add(1, std::memory_order_relaxed);
		} else {
			stats.total_queries.fetch_add(1, std::memory_order_relaxed);
			switch (op) {
				case op_t::simple:
					stats.simple_queries.fetch_add(1, std::memory_order_relaxed);
					break;
				case op_t::ins:
					stats.insert_queries.fetch_add(1, std::memory_order_relaxed);
					break;
				case op_t::upd:
					stats.update_queries.fetch_add(1, std::memory_order_relaxed);
					break;
				case op_t::del:
					stats.delete_queries.fetch_add(1, std::memory_order_relaxed);
					break;
				case op_t::sel:
					stats.table_select_queries.fetch_add(1, std::memory_order_relaxed);
					break;
				case op_t::sleep:
					stats.sleep_queries.fetch_add(1, std::memory_order_relaxed);
					break;
			}
		}

		++local_seq;
	}
}

/**
 * @brief Continuously churn MCP cap variables while traffic and polling run.
 *
 * This thread cycles configured processlist/query caps and reloads MCP runtime
 * variables. It is optional and enabled only when `MCP_MIXED_STRESS_ENABLE_CAP_CHURN`
 * is true.
 *
 * @param cl TAP command-line configuration.
 * @param stop Stop flag set by main thread.
 * @param processlist_caps Ordered processlist cap profile.
 * @param show_queries_caps Ordered show_queries cap profile.
 * @param interval_ms Delay between cap updates.
 */
void run_mcp_cap_churner(
	const CommandLine& cl,
	const std::atomic<bool>& stop,
	const std::vector<int>& processlist_caps,
	const std::vector<int>& show_queries_caps,
	int interval_ms
) {
	if (processlist_caps.empty() || show_queries_caps.empty()) {
		return;
	}

	std::string connect_error;
	MYSQLConnPtr admin_conn = create_mysql_connection(
		cl.admin_host,
		cl.admin_port,
		cl.admin_username,
		cl.admin_password,
		connect_error
	);
	if (!admin_conn) {
		diag("MCP cap churner: cannot open admin connection: %s", connect_error.c_str());
		return;
	}

	size_t idx = 0;
	while (!stop.load(std::memory_order_relaxed)) {
		const int processlist_cap = processlist_caps[idx % processlist_caps.size()];
		const int show_queries_cap = show_queries_caps[idx % show_queries_caps.size()];

		const bool ok =
			run_admin_stmt(
				admin_conn.get(),
				"SET mcp-stats_show_processlist_max_rows=" + std::to_string(processlist_cap),
				"MCP cap churner"
			) &&
			run_admin_stmt(
				admin_conn.get(),
				"SET mcp-stats_show_queries_max_rows=" + std::to_string(show_queries_cap),
				"MCP cap churner"
			) &&
			run_admin_stmt(admin_conn.get(), "LOAD MCP VARIABLES TO RUNTIME", "MCP cap churner");

		if (!ok) {
			diag(
				"MCP cap churner: failed updating caps to processlist=%d show_queries=%d",
				processlist_cap,
				show_queries_cap
			);
		}

		++idx;
		std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
	}
}

/**
 * @brief MCP poller validating `stats.show_processlist` for a specific protocol.
 *
 * @param cl TAP command-line configuration.
 * @param db_type MCP db_type (`mysql` or `pgsql`).
 * @param filter_token Token expected in filtered `info` values.
 * @param accepted_caps Cap values accepted in metadata assertions.
 * @param dynamic_cap_check Whether `limit_cap` can vary across calls.
 * @param stop Stop flag set by main thread.
 * @param stats Shared processlist poll counters.
 */
void run_processlist_poller(
	const CommandLine& cl,
	const std::string& db_type,
	const std::string& filter_token,
	const std::vector<int>& accepted_caps,
	bool dynamic_cap_check,
	const std::atomic<bool>& stop,
	processlist_poll_stats_t& stats
) {
	MCPClient mcp(cl.admin_host, cl.mcp_port);
	if (std::strlen(cl.mcp_auth_token) > 0) {
		mcp.set_auth_token(cl.mcp_auth_token);
	}

	uint64_t iter = 0;
	while (!stop.load(std::memory_order_relaxed)) {
		stats.calls_total.fetch_add(1, std::memory_order_relaxed);
		const MCPResponse resp = mcp.call_tool(
			"stats",
			"show_processlist",
			json{
				{"db_type", db_type},
				{"sort_by", "time_ms"},
				{"sort_order", "desc"},
				{"limit", k_processlist_requested_limit}
			}
		);

		json result_obj = json::object();
		std::string parse_error;
		if (!extract_tool_result(resp, result_obj, parse_error)) {
			stats.calls_failed.fetch_add(1, std::memory_order_relaxed);
			stats.parse_failures.fetch_add(1, std::memory_order_relaxed);
		} else {
			stats.calls_ok.fetch_add(1, std::memory_order_relaxed);

			const int requested_limit = result_obj.value("requested_limit", -1);
			const int effective_limit = result_obj.value("effective_limit", -1);
			const int limit_cap = result_obj.value("limit_cap", -1);

			bool cap_match = false;
			if (dynamic_cap_check) {
				cap_match = std::find(accepted_caps.begin(), accepted_caps.end(), limit_cap) != accepted_caps.end();
			} else {
				cap_match = !accepted_caps.empty() && (limit_cap == accepted_caps.back());
			}

			if (!(requested_limit == k_processlist_requested_limit &&
			      effective_limit >= 0 &&
			      cap_match &&
			      effective_limit <= limit_cap)) {
				stats.metadata_failures.fetch_add(1, std::memory_order_relaxed);
			}

			if (!result_obj.contains("sessions") || !result_obj["sessions"].is_array()) {
				stats.row_shape_failures.fetch_add(1, std::memory_order_relaxed);
			} else {
				const json& sessions = result_obj["sessions"];
				if (!sessions.empty()) {
					stats.non_empty_snapshots.fetch_add(1, std::memory_order_relaxed);
					atomic_update_max(stats.max_sessions_observed, static_cast<uint64_t>(sessions.size()));
					const json& first = sessions[0];
					const bool shape_ok =
						first.contains("session_id") &&
						first.contains("user") &&
						first.contains("database") &&
						first.contains("command") &&
						first.contains("time_ms") &&
						first.contains("info");
					if (!shape_ok) {
						stats.row_shape_failures.fetch_add(1, std::memory_order_relaxed);
					}
				}
			}
		}

		if ((iter % 4U) == 0U) {
			const MCPResponse filter_resp = mcp.call_tool(
				"stats",
				"show_processlist",
				json{
					{"db_type", db_type},
					{"sort_by", "time_ms"},
					{"sort_order", "desc"},
					{"limit", 60},
					{"match_info", filter_token},
					{"info_case_sensitive", false}
				}
			);

			json filter_obj = json::object();
			std::string filter_error;
			if (extract_tool_result(filter_resp, filter_obj, filter_error)) {
				stats.filtered_calls_ok.fetch_add(1, std::memory_order_relaxed);
				if (filter_obj.contains("sessions") && filter_obj["sessions"].is_array()) {
					const json& sessions = filter_obj["sessions"];
					if (!sessions.empty()) {
						stats.filtered_non_empty_snapshots.fetch_add(1, std::memory_order_relaxed);
						for (const auto& row : sessions) {
							const std::string info = row.value("info", std::string(""));
							if (!contains_icase(info, filter_token)) {
								stats.filtered_invalid_rows.fetch_add(1, std::memory_order_relaxed);
								break;
							}
						}
					}
				}
			}
		}

		++iter;
		std::this_thread::sleep_for(std::chrono::milliseconds(45));
	}
}

/**
 * @brief MCP poller validating `stats.show_queries` for a specific protocol.
 *
 * @param cl TAP command-line configuration.
 * @param db_type MCP db_type (`mysql` or `pgsql`).
 * @param filter_token Token expected in filtered `digest_text` values.
 * @param accepted_caps Cap values accepted in metadata assertions.
 * @param dynamic_cap_check Whether `limit_cap` can vary across calls.
 * @param stop Stop flag set by main thread.
 * @param stats Shared show_queries poll counters.
 */
void run_show_queries_poller(
	const CommandLine& cl,
	const std::string& db_type,
	const std::string& filter_token,
	const std::vector<int>& accepted_caps,
	bool dynamic_cap_check,
	const std::atomic<bool>& stop,
	show_queries_poll_stats_t& stats
) {
	MCPClient mcp(cl.admin_host, cl.mcp_port);
	if (std::strlen(cl.mcp_auth_token) > 0) {
		mcp.set_auth_token(cl.mcp_auth_token);
	}

	uint64_t iter = 0;
	while (!stop.load(std::memory_order_relaxed)) {
		stats.calls_total.fetch_add(1, std::memory_order_relaxed);
		const MCPResponse resp = mcp.call_tool(
			"stats",
			"show_queries",
			json{
				{"db_type", db_type},
				{"sort_by", "count"},
				{"limit", k_show_queries_requested_limit}
			}
		);

		json result_obj = json::object();
		std::string parse_error;
		if (!extract_tool_result(resp, result_obj, parse_error)) {
			stats.calls_failed.fetch_add(1, std::memory_order_relaxed);
			stats.parse_failures.fetch_add(1, std::memory_order_relaxed);
		} else {
			stats.calls_ok.fetch_add(1, std::memory_order_relaxed);

			const int requested_limit = result_obj.value("requested_limit", -1);
			const int effective_limit = result_obj.value("effective_limit", -1);
			const int limit_cap = result_obj.value("limit_cap", -1);

			bool cap_match = false;
			if (dynamic_cap_check) {
				cap_match = std::find(accepted_caps.begin(), accepted_caps.end(), limit_cap) != accepted_caps.end();
			} else {
				cap_match = !accepted_caps.empty() && (limit_cap == accepted_caps.back());
			}

			if (!(requested_limit == k_show_queries_requested_limit &&
			      effective_limit >= 0 &&
			      cap_match &&
			      effective_limit <= limit_cap)) {
				stats.metadata_failures.fetch_add(1, std::memory_order_relaxed);
			}

			const uint64_t total_digests = result_obj.value("total_digests", static_cast<uint64_t>(0));
			if (total_digests > 0) {
				stats.digests_seen_snapshots.fetch_add(1, std::memory_order_relaxed);
			}

			if (result_obj.contains("queries") && result_obj["queries"].is_array()) {
				const json& queries = result_obj["queries"];
				uint64_t prev = std::numeric_limits<uint64_t>::max();
				for (const auto& row : queries) {
					const uint64_t count_star = row.value("count_star", static_cast<uint64_t>(0));
					if (count_star > prev) {
						stats.sorted_failures.fetch_add(1, std::memory_order_relaxed);
						break;
					}
					prev = count_star;
				}
			}
		}

		if ((iter % 3U) == 0U) {
			const MCPResponse filter_resp = mcp.call_tool(
				"stats",
				"show_queries",
				json{
					{"db_type", db_type},
					{"sort_by", "count"},
					{"limit", 60},
					{"match_digest_text", filter_token},
					{"digest_text_case_sensitive", false}
				}
			);

			json filter_obj = json::object();
			std::string filter_error;
			if (extract_tool_result(filter_resp, filter_obj, filter_error)) {
				stats.filtered_calls_ok.fetch_add(1, std::memory_order_relaxed);
				if (filter_obj.contains("queries") && filter_obj["queries"].is_array()) {
					const json& queries = filter_obj["queries"];
					if (!queries.empty()) {
						stats.filtered_non_empty_snapshots.fetch_add(1, std::memory_order_relaxed);
						for (const auto& row : queries) {
							const std::string digest_text = row.value("digest_text", std::string(""));
							if (!contains_icase(digest_text, filter_token)) {
								stats.filtered_invalid_rows.fetch_add(1, std::memory_order_relaxed);
								break;
							}
						}
					}
				}
			}
		}

		++iter;
		std::this_thread::sleep_for(std::chrono::milliseconds(65));
	}
}

} // namespace

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;

	plan(47);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to load TAP environment");
		return exit_status();
	}

	diag("=== MCP Mixed MySQL+PgSQL Concurrency Stress Test ===");
	diag("This test drives concurrent traffic through both MySQL and PgSQL frontends");
	diag("while parallel MCP pollers query stats tools for both protocols.");
	diag("Workload includes: simple reads, INSERT/UPDATE/DELETE/SELECT on test tables,");
	diag("and randomized SLEEP/pg_sleep calls. MCP polling covers show_processlist");
	diag("and show_queries with sorting, metadata, and substring filtering validation.");
	diag("The goal is to validate MCP stats correctness under cross-protocol load.");
	diag("=====================================================");

	const int mysql_worker_threads = env_int_clamped(
		"MCP_MIXED_STRESS_MYSQL_WORKERS",
		k_default_mysql_worker_threads,
		1,
		k_max_worker_threads
	);
	const int pgsql_worker_threads = env_int_clamped(
		"MCP_MIXED_STRESS_PGSQL_WORKERS",
		k_default_pgsql_worker_threads,
		1,
		k_max_worker_threads
	);
	const int runtime_seconds = env_int_clamped(
		"MCP_MIXED_STRESS_RUNTIME_SEC",
		k_default_runtime_seconds,
		1,
		k_max_runtime_seconds
	);
	const int processlist_cap_max = env_int_clamped(
		"MCP_MIXED_STRESS_PROCESSLIST_CAP",
		k_default_processlist_cap,
		k_min_processlist_cap,
		1000
	);
	const int show_queries_cap_max = env_int_clamped(
		"MCP_MIXED_STRESS_SHOW_QUERIES_CAP",
		k_default_show_queries_cap,
		k_min_show_queries_cap,
		1000
	);
	const bool cap_churn_enabled = env_bool("MCP_MIXED_STRESS_ENABLE_CAP_CHURN", false);
	const int cap_churn_interval_ms = env_int_clamped(
		"MCP_MIXED_STRESS_CAP_CHURN_INTERVAL_MS",
		k_default_cap_churn_interval_ms,
		k_min_cap_churn_interval_ms,
		k_max_cap_churn_interval_ms
	);

	const std::vector<int> processlist_cap_profile = cap_churn_enabled
		? build_cap_profile(processlist_cap_max, k_min_processlist_cap)
		: std::vector<int>{processlist_cap_max};
	const std::vector<int> show_queries_cap_profile = cap_churn_enabled
		? build_cap_profile(show_queries_cap_max, k_min_show_queries_cap)
		: std::vector<int>{show_queries_cap_max};

	diag(
		"Mixed MCP stress config: runtime=%ds mysql_workers=%d pgsql_workers=%d cap_churn=%d processlist_cap_max=%d show_queries_cap_max=%d",
		runtime_seconds,
		mysql_worker_threads,
		pgsql_worker_threads,
		cap_churn_enabled ? 1 : 0,
		processlist_cap_max,
		show_queries_cap_max
	);

	MYSQL* admin = nullptr;
	bool can_continue = true;

	admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	ok(admin != nullptr, "Admin connection established");
	if (!admin) {
		skip(46, "Cannot continue without admin connection");
		can_continue = false;
	}

	if (can_continue) {
		const bool configured = configure_mcp_runtime(
			admin,
			cl,
			processlist_cap_profile.back(),
			show_queries_cap_profile.back()
		);
		ok(configured, "Configured MCP runtime for mixed MySQL+PgSQL stress");
		if (!configured) {
			skip(45, "Cannot continue without MCP runtime configuration");
			can_continue = false;
		}
	}

	MCPClient* mcp = nullptr;
	if (can_continue) {
		mcp = new MCPClient(cl.admin_host, cl.mcp_port);
		if (std::strlen(cl.mcp_auth_token) > 0) {
			mcp->set_auth_token(cl.mcp_auth_token);
		}
		const bool mcp_ready = mcp->check_server();
		ok(mcp_ready, "MCP server reachable at %s", mcp->get_connection_info().c_str());
		if (!mcp_ready) {
			skip(44, "Cannot continue without MCP connectivity");
			can_continue = false;
		}
	}

	MYSQLConnPtr mysql_setup_conn(nullptr, &mysql_close);
	std::string mysql_setup_error;
	if (can_continue) {
		mysql_setup_conn = create_mysql_connection(cl.root_host, cl.root_port, cl.root_username, cl.root_password, mysql_setup_error);
		if (!mysql_setup_conn) {
			mysql_setup_conn = create_mysql_connection(cl.host, cl.port, cl.username, cl.password, mysql_setup_error);
		}
		if (mysql_setup_conn) {
			ok(true, "MySQL workload connection established via ProxySQL");
		} else {
			ok(false, "MySQL workload connection established via ProxySQL: %s", mysql_setup_error.c_str());
			skip(43, "Cannot continue without MySQL connectivity");
			can_continue = false;
		}
	}

	std::string mysql_table_name = "mcp_mixed_mysql_stress_" + std::to_string(static_cast<unsigned long long>(getpid()));
	if (can_continue) {
		std::string mysql_table_error;
		const bool mysql_table_created = create_mysql_workload_table(mysql_setup_conn.get(), mysql_table_name, mysql_table_error);
		ok(mysql_table_created, "Created MySQL workload table `%s.%s`", k_mysql_workload_schema, mysql_table_name.c_str());
		if (!mysql_table_created) {
			diag("MySQL table setup error: %s", mysql_table_error.c_str());
			skip(42, "Cannot continue without MySQL workload table");
			can_continue = false;
		}
	}

	PGConnPtr pg_setup_conn(nullptr, &PQfinish);
	std::string pg_setup_error;
	if (can_continue) {
		pg_setup_conn = create_pg_connection(cl, true, "mcp_mixed_pg_setup", pg_setup_error);
		if (!pg_setup_conn) {
			pg_setup_conn = create_pg_connection(cl, false, "mcp_mixed_pg_setup", pg_setup_error);
		}
		if (pg_setup_conn) {
			ok(true, "PgSQL workload connection established via ProxySQL");
		} else {
			ok(false, "PgSQL workload connection established via ProxySQL: %s", pg_setup_error.c_str());
			skip(41, "Cannot continue without PgSQL connectivity");
			can_continue = false;
		}
	}

	std::string pg_table_name = "mcp_mixed_pgsql_stress_" + std::to_string(static_cast<unsigned long long>(getpid()));
	if (can_continue) {
		std::string pg_table_error;
		const bool pg_table_created = create_pgsql_workload_table(pg_setup_conn.get(), pg_table_name, pg_table_error);
		ok(pg_table_created, "Created PgSQL workload table `%s`", pg_table_name.c_str());
		if (!pg_table_created) {
			diag("PgSQL table setup error: %s", pg_table_error.c_str());
			skip(40, "Cannot continue without PgSQL workload table");
			can_continue = false;
		}
	}

	workload_stats_t mysql_workload_stats {};
	workload_stats_t pgsql_workload_stats {};
	processlist_poll_stats_t mysql_processlist_stats {};
	processlist_poll_stats_t pgsql_processlist_stats {};
	show_queries_poll_stats_t mysql_show_queries_stats {};
	show_queries_poll_stats_t pgsql_show_queries_stats {};

	if (can_continue) {
		std::atomic<bool> stop {false};
		std::vector<std::thread> workers;
		workers.reserve(static_cast<size_t>(mysql_worker_threads + pgsql_worker_threads));

		for (int i = 0; i < mysql_worker_threads; ++i) {
			workers.emplace_back(
				run_mysql_worker,
				i,
				std::cref(cl),
				std::cref(mysql_table_name),
				std::cref(stop),
				std::ref(mysql_workload_stats)
			);
		}
		for (int i = 0; i < pgsql_worker_threads; ++i) {
			workers.emplace_back(
				run_pgsql_worker,
				i,
				std::cref(cl),
				std::cref(pg_table_name),
				std::cref(stop),
				std::ref(pgsql_workload_stats)
			);
		}

		std::thread mysql_processlist_poller(
			run_processlist_poller,
			std::cref(cl),
			std::string("mysql"),
			std::string("SLEEP("),
			std::cref(processlist_cap_profile),
			cap_churn_enabled,
			std::cref(stop),
			std::ref(mysql_processlist_stats)
		);
		std::thread pgsql_processlist_poller(
			run_processlist_poller,
			std::cref(cl),
			std::string("pgsql"),
			std::string("pg_sleep"),
			std::cref(processlist_cap_profile),
			cap_churn_enabled,
			std::cref(stop),
			std::ref(pgsql_processlist_stats)
		);
		std::thread mysql_show_queries_poller(
			run_show_queries_poller,
			std::cref(cl),
			std::string("mysql"),
			std::string("SLEEP"),
			std::cref(show_queries_cap_profile),
			cap_churn_enabled,
			std::cref(stop),
			std::ref(mysql_show_queries_stats)
		);
		std::thread pgsql_show_queries_poller(
			run_show_queries_poller,
			std::cref(cl),
			std::string("pgsql"),
			std::string("PG_SLEEP"),
			std::cref(show_queries_cap_profile),
			cap_churn_enabled,
			std::cref(stop),
			std::ref(pgsql_show_queries_stats)
		);

		std::thread cap_churner;
		if (cap_churn_enabled) {
			cap_churner = std::thread(
				run_mcp_cap_churner,
				std::cref(cl),
				std::cref(stop),
				std::cref(processlist_cap_profile),
				std::cref(show_queries_cap_profile),
				cap_churn_interval_ms
			);
		}

		std::this_thread::sleep_for(std::chrono::seconds(runtime_seconds));
		stop.store(true, std::memory_order_relaxed);

		for (auto& t : workers) {
			if (t.joinable()) {
				t.join();
			}
		}
		if (mysql_processlist_poller.joinable()) {
			mysql_processlist_poller.join();
		}
		if (pgsql_processlist_poller.joinable()) {
			pgsql_processlist_poller.join();
		}
		if (mysql_show_queries_poller.joinable()) {
			mysql_show_queries_poller.join();
		}
		if (pgsql_show_queries_poller.joinable()) {
			pgsql_show_queries_poller.join();
		}
		if (cap_churner.joinable()) {
			cap_churner.join();
		}
	}

	if (can_continue) {
		const uint64_t mysql_connected_workers = mysql_workload_stats.connected_workers.load(std::memory_order_relaxed);
		const uint64_t mysql_total_queries = mysql_workload_stats.total_queries.load(std::memory_order_relaxed);
		const uint64_t mysql_failed_queries = mysql_workload_stats.failed_queries.load(std::memory_order_relaxed);
		const uint64_t mysql_insert_queries = mysql_workload_stats.insert_queries.load(std::memory_order_relaxed);
		const uint64_t mysql_update_queries = mysql_workload_stats.update_queries.load(std::memory_order_relaxed);
		const uint64_t mysql_delete_queries = mysql_workload_stats.delete_queries.load(std::memory_order_relaxed);
		const uint64_t mysql_select_queries = mysql_workload_stats.table_select_queries.load(std::memory_order_relaxed);
		const uint64_t mysql_sleep_queries = mysql_workload_stats.sleep_queries.load(std::memory_order_relaxed);
		const uint64_t mysql_max_failed_queries = std::max<uint64_t>(5, mysql_total_queries / 200);

		ok(
			mysql_connected_workers >= static_cast<uint64_t>(mysql_worker_threads / 2),
			"MySQL: at least half of worker connections succeeded (%llu/%d)",
			static_cast<unsigned long long>(mysql_connected_workers),
			mysql_worker_threads
		);
		ok(
			mysql_total_queries >= k_min_total_mysql_queries,
			"MySQL: workload generated sufficient traffic (%llu >= %llu)",
			static_cast<unsigned long long>(mysql_total_queries),
			static_cast<unsigned long long>(k_min_total_mysql_queries)
		);
		ok(
			mysql_insert_queries > 0 && mysql_update_queries > 0 && mysql_delete_queries > 0 && mysql_select_queries > 0,
			"MySQL: R/W workload mix executed (ins=%llu upd=%llu del=%llu sel=%llu)",
			static_cast<unsigned long long>(mysql_insert_queries),
			static_cast<unsigned long long>(mysql_update_queries),
			static_cast<unsigned long long>(mysql_delete_queries),
			static_cast<unsigned long long>(mysql_select_queries)
		);
		ok(mysql_sleep_queries > 0, "MySQL: sleep workload executed");
		ok(
			mysql_failed_queries <= mysql_max_failed_queries,
			"MySQL: workload query error budget respected (failed=%llu allowed=%llu total=%llu)",
			static_cast<unsigned long long>(mysql_failed_queries),
			static_cast<unsigned long long>(mysql_max_failed_queries),
			static_cast<unsigned long long>(mysql_total_queries)
		);
	}

	if (can_continue) {
		const uint64_t pg_connected_workers = pgsql_workload_stats.connected_workers.load(std::memory_order_relaxed);
		const uint64_t pg_total_queries = pgsql_workload_stats.total_queries.load(std::memory_order_relaxed);
		const uint64_t pg_failed_queries = pgsql_workload_stats.failed_queries.load(std::memory_order_relaxed);
		const uint64_t pg_insert_queries = pgsql_workload_stats.insert_queries.load(std::memory_order_relaxed);
		const uint64_t pg_update_queries = pgsql_workload_stats.update_queries.load(std::memory_order_relaxed);
		const uint64_t pg_delete_queries = pgsql_workload_stats.delete_queries.load(std::memory_order_relaxed);
		const uint64_t pg_select_queries = pgsql_workload_stats.table_select_queries.load(std::memory_order_relaxed);
		const uint64_t pg_sleep_queries = pgsql_workload_stats.sleep_queries.load(std::memory_order_relaxed);
		const uint64_t pg_max_failed_queries = std::max<uint64_t>(5, pg_total_queries / 200);

		ok(
			pg_connected_workers >= static_cast<uint64_t>(pgsql_worker_threads / 2),
			"PgSQL: at least half of worker connections succeeded (%llu/%d)",
			static_cast<unsigned long long>(pg_connected_workers),
			pgsql_worker_threads
		);
		ok(
			pg_total_queries >= k_min_total_pgsql_queries,
			"PgSQL: workload generated sufficient traffic (%llu >= %llu)",
			static_cast<unsigned long long>(pg_total_queries),
			static_cast<unsigned long long>(k_min_total_pgsql_queries)
		);
		ok(
			pg_insert_queries > 0 && pg_update_queries > 0 && pg_delete_queries > 0 && pg_select_queries > 0,
			"PgSQL: R/W workload mix executed (ins=%llu upd=%llu del=%llu sel=%llu)",
			static_cast<unsigned long long>(pg_insert_queries),
			static_cast<unsigned long long>(pg_update_queries),
			static_cast<unsigned long long>(pg_delete_queries),
			static_cast<unsigned long long>(pg_select_queries)
		);
		ok(pg_sleep_queries > 0, "PgSQL: sleep workload executed");
		ok(
			pg_failed_queries <= pg_max_failed_queries,
			"PgSQL: workload query error budget respected (failed=%llu allowed=%llu total=%llu)",
			static_cast<unsigned long long>(pg_failed_queries),
			static_cast<unsigned long long>(pg_max_failed_queries),
			static_cast<unsigned long long>(pg_total_queries)
		);
	}

	if (can_continue) {
		const uint64_t m_ok = mysql_processlist_stats.calls_ok.load(std::memory_order_relaxed);
		const uint64_t m_fail = mysql_processlist_stats.calls_failed.load(std::memory_order_relaxed);
		const uint64_t m_non_empty = mysql_processlist_stats.non_empty_snapshots.load(std::memory_order_relaxed);
		const uint64_t m_metadata_fail = mysql_processlist_stats.metadata_failures.load(std::memory_order_relaxed);
		const uint64_t m_shape_fail = mysql_processlist_stats.row_shape_failures.load(std::memory_order_relaxed);
		const uint64_t m_filtered_ok = mysql_processlist_stats.filtered_calls_ok.load(std::memory_order_relaxed);
		const uint64_t m_filtered_non_empty = mysql_processlist_stats.filtered_non_empty_snapshots.load(std::memory_order_relaxed);
		const uint64_t m_filtered_invalid = mysql_processlist_stats.filtered_invalid_rows.load(std::memory_order_relaxed);

		ok(m_ok >= k_min_successful_polls, "MySQL show_processlist poller collected enough successful samples (%llu)", static_cast<unsigned long long>(m_ok));
		ok(m_ok > m_fail, "MySQL show_processlist success dominates failures (ok=%llu fail=%llu)", static_cast<unsigned long long>(m_ok), static_cast<unsigned long long>(m_fail));
		ok(m_non_empty > 0, "MySQL show_processlist observed non-empty snapshots during load");
		ok(m_metadata_fail == 0 && m_shape_fail == 0, "MySQL show_processlist metadata and row shape remained consistent");
		ok(m_filtered_ok > 0 && m_filtered_non_empty > 0, "MySQL show_processlist filtered polling executed and returned non-empty snapshots");
		ok(m_filtered_invalid == 0, "MySQL show_processlist filtered rows matched expected token");
	}

	if (can_continue) {
		const uint64_t p_ok = pgsql_processlist_stats.calls_ok.load(std::memory_order_relaxed);
		const uint64_t p_fail = pgsql_processlist_stats.calls_failed.load(std::memory_order_relaxed);
		const uint64_t p_non_empty = pgsql_processlist_stats.non_empty_snapshots.load(std::memory_order_relaxed);
		const uint64_t p_metadata_fail = pgsql_processlist_stats.metadata_failures.load(std::memory_order_relaxed);
		const uint64_t p_shape_fail = pgsql_processlist_stats.row_shape_failures.load(std::memory_order_relaxed);
		const uint64_t p_filtered_ok = pgsql_processlist_stats.filtered_calls_ok.load(std::memory_order_relaxed);
		const uint64_t p_filtered_non_empty = pgsql_processlist_stats.filtered_non_empty_snapshots.load(std::memory_order_relaxed);
		const uint64_t p_filtered_invalid = pgsql_processlist_stats.filtered_invalid_rows.load(std::memory_order_relaxed);

		ok(p_ok >= k_min_successful_polls, "PgSQL show_processlist poller collected enough successful samples (%llu)", static_cast<unsigned long long>(p_ok));
		ok(p_ok > p_fail, "PgSQL show_processlist success dominates failures (ok=%llu fail=%llu)", static_cast<unsigned long long>(p_ok), static_cast<unsigned long long>(p_fail));
		ok(p_non_empty > 0, "PgSQL show_processlist observed non-empty snapshots during load");
		ok(p_metadata_fail == 0 && p_shape_fail == 0, "PgSQL show_processlist metadata and row shape remained consistent");
		ok(p_filtered_ok > 0 && p_filtered_non_empty > 0, "PgSQL show_processlist filtered polling executed and returned non-empty snapshots");
		ok(p_filtered_invalid == 0, "PgSQL show_processlist filtered rows matched expected token");
	}

	if (can_continue) {
		const uint64_t m_ok = mysql_show_queries_stats.calls_ok.load(std::memory_order_relaxed);
		const uint64_t m_fail = mysql_show_queries_stats.calls_failed.load(std::memory_order_relaxed);
		const uint64_t m_digests = mysql_show_queries_stats.digests_seen_snapshots.load(std::memory_order_relaxed);
		const uint64_t m_meta_fail = mysql_show_queries_stats.metadata_failures.load(std::memory_order_relaxed);
		const uint64_t m_sorted_fail = mysql_show_queries_stats.sorted_failures.load(std::memory_order_relaxed);
		const uint64_t m_filtered_ok = mysql_show_queries_stats.filtered_calls_ok.load(std::memory_order_relaxed);
		const uint64_t m_filtered_non_empty = mysql_show_queries_stats.filtered_non_empty_snapshots.load(std::memory_order_relaxed);
		const uint64_t m_filtered_invalid = mysql_show_queries_stats.filtered_invalid_rows.load(std::memory_order_relaxed);

		ok(m_ok >= k_min_successful_polls, "MySQL show_queries poller collected enough successful samples (%llu)", static_cast<unsigned long long>(m_ok));
		ok(m_ok > m_fail, "MySQL show_queries success dominates failures (ok=%llu fail=%llu)", static_cast<unsigned long long>(m_ok), static_cast<unsigned long long>(m_fail));
		ok(m_digests > 0, "MySQL show_queries observed non-zero digest snapshots");
		ok(m_meta_fail == 0 && m_sorted_fail == 0, "MySQL show_queries metadata and sort order remained consistent");
		ok(m_filtered_ok > 0 && m_filtered_non_empty > 0, "MySQL show_queries filtered polling executed and returned non-empty snapshots");
		ok(m_filtered_invalid == 0, "MySQL show_queries filtered rows matched expected token");
	}

	if (can_continue) {
		const uint64_t p_ok = pgsql_show_queries_stats.calls_ok.load(std::memory_order_relaxed);
		const uint64_t p_fail = pgsql_show_queries_stats.calls_failed.load(std::memory_order_relaxed);
		const uint64_t p_digests = pgsql_show_queries_stats.digests_seen_snapshots.load(std::memory_order_relaxed);
		const uint64_t p_meta_fail = pgsql_show_queries_stats.metadata_failures.load(std::memory_order_relaxed);
		const uint64_t p_sorted_fail = pgsql_show_queries_stats.sorted_failures.load(std::memory_order_relaxed);
		const uint64_t p_filtered_ok = pgsql_show_queries_stats.filtered_calls_ok.load(std::memory_order_relaxed);
		const uint64_t p_filtered_non_empty = pgsql_show_queries_stats.filtered_non_empty_snapshots.load(std::memory_order_relaxed);
		const uint64_t p_filtered_invalid = pgsql_show_queries_stats.filtered_invalid_rows.load(std::memory_order_relaxed);

		ok(p_ok >= k_min_successful_polls, "PgSQL show_queries poller collected enough successful samples (%llu)", static_cast<unsigned long long>(p_ok));
		ok(p_ok > p_fail, "PgSQL show_queries success dominates failures (ok=%llu fail=%llu)", static_cast<unsigned long long>(p_ok), static_cast<unsigned long long>(p_fail));
		ok(p_digests > 0, "PgSQL show_queries observed non-zero digest snapshots");
		ok(p_meta_fail == 0 && p_sorted_fail == 0, "PgSQL show_queries metadata and sort order remained consistent");
		ok(p_filtered_ok > 0 && p_filtered_non_empty > 0, "PgSQL show_queries filtered polling executed and returned non-empty snapshots");
		ok(p_filtered_invalid == 0, "PgSQL show_queries filtered rows matched expected token");
	}

	if (can_continue) {
		const MCPResponse final_mysql_processlist = mcp->call_tool(
			"stats",
			"show_processlist",
			json{{"db_type", "mysql"}, {"sort_by", "time_ms"}, {"sort_order", "desc"}, {"limit", 25}}
		);
		json final_mysql_processlist_obj = json::object();
		std::string final_mysql_processlist_err;
		const bool final_mysql_processlist_ok = extract_tool_result(
			final_mysql_processlist,
			final_mysql_processlist_obj,
			final_mysql_processlist_err
		);
		ok(
			final_mysql_processlist_ok && final_mysql_processlist_obj.value("db_type", std::string("")) == "mysql",
			"Final show_processlist call succeeded for mysql%s%s",
			final_mysql_processlist_ok ? "" : ": ",
			final_mysql_processlist_ok ? "" : final_mysql_processlist_err.c_str()
		);

		const MCPResponse final_pgsql_processlist = mcp->call_tool(
			"stats",
			"show_processlist",
			json{{"db_type", "pgsql"}, {"sort_by", "time_ms"}, {"sort_order", "desc"}, {"limit", 25}}
		);
		json final_pgsql_processlist_obj = json::object();
		std::string final_pgsql_processlist_err;
		const bool final_pgsql_processlist_ok = extract_tool_result(
			final_pgsql_processlist,
			final_pgsql_processlist_obj,
			final_pgsql_processlist_err
		);
		ok(
			final_pgsql_processlist_ok && final_pgsql_processlist_obj.value("db_type", std::string("")) == "pgsql",
			"Final show_processlist call succeeded for pgsql%s%s",
			final_pgsql_processlist_ok ? "" : ": ",
			final_pgsql_processlist_ok ? "" : final_pgsql_processlist_err.c_str()
		);

		const MCPResponse final_mysql_queries = mcp->call_tool(
			"stats",
			"show_queries",
			json{{"db_type", "mysql"}, {"sort_by", "count"}, {"limit", 25}}
		);
		json final_mysql_queries_obj = json::object();
		std::string final_mysql_queries_err;
		const bool final_mysql_queries_ok = extract_tool_result(
			final_mysql_queries,
			final_mysql_queries_obj,
			final_mysql_queries_err
		);
		ok(
			final_mysql_queries_ok && final_mysql_queries_obj.value("db_type", std::string("")) == "mysql",
			"Final show_queries call succeeded for mysql%s%s",
			final_mysql_queries_ok ? "" : ": ",
			final_mysql_queries_ok ? "" : final_mysql_queries_err.c_str()
		);

		const MCPResponse final_pgsql_queries = mcp->call_tool(
			"stats",
			"show_queries",
			json{{"db_type", "pgsql"}, {"sort_by", "count"}, {"limit", 25}}
		);
		json final_pgsql_queries_obj = json::object();
		std::string final_pgsql_queries_err;
		const bool final_pgsql_queries_ok = extract_tool_result(
			final_pgsql_queries,
			final_pgsql_queries_obj,
			final_pgsql_queries_err
		);
		ok(
			final_pgsql_queries_ok && final_pgsql_queries_obj.value("db_type", std::string("")) == "pgsql",
			"Final show_queries call succeeded for pgsql%s%s",
			final_pgsql_queries_ok ? "" : ": ",
			final_pgsql_queries_ok ? "" : final_pgsql_queries_err.c_str()
		);
	}

	if (can_continue) {
		std::string mysql_drop_err;
		const bool mysql_dropped = drop_mysql_workload_table(mysql_setup_conn.get(), mysql_table_name, mysql_drop_err);
		ok(mysql_dropped, "Dropped MySQL workload table `%s.%s`", k_mysql_workload_schema, mysql_table_name.c_str());
		if (!mysql_dropped) {
			diag("MySQL cleanup error: %s", mysql_drop_err.c_str());
		}

		std::string pg_drop_err;
		const bool pg_dropped = drop_pgsql_workload_table(pg_setup_conn.get(), pg_table_name, pg_drop_err);
		ok(pg_dropped, "Dropped PgSQL workload table `%s`", pg_table_name.c_str());
		if (!pg_dropped) {
			diag("PgSQL cleanup error: %s", pg_drop_err.c_str());
		}
	}

	if (mysql_setup_conn) {
		mysql_setup_conn.reset();
	}
	if (pg_setup_conn) {
		pg_setup_conn.reset();
	}
	if (mcp) {
		delete mcp;
	}
	if (admin) {
		restore_mcp_runtime(admin);
		mysql_close(admin);
	}

	return exit_status();
}
