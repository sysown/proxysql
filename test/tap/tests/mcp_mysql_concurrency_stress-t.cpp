/**
 * @file mcp_mysql_concurrency_stress-t.cpp
 * @brief TAP stress test for concurrent MySQL traffic with parallel MCP stats polling.
 *
 * This test generates sustained traffic through ProxySQL's MySQL frontend while
 * concurrently querying MCP stats tools from multiple threads.
 *
 * Workload characteristics:
 * 1. Many concurrent MySQL client connections.
 * 2. Mixed query stream:
 *    - simple reads (`SELECT 1`, `SELECT 1 + 2`)
 *    - mutable workload over a test-created table (`INSERT/UPDATE/DELETE/SELECT`)
 *    - randomized sleeps (`SELECT SLEEP(x)`)
 * 3. Parallel MCP polling while workload is active:
 *    - `stats.show_processlist` with sorting, metadata, and `match_info` filtering
 *    - `stats.show_queries` with sorting, metadata, and `match_digest_text` filtering
 *
 * The primary goal is validating that MCP stats remains correct and responsive
 * under concurrent client traffic.
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

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mcp_client.h"

using json = nlohmann::json;

namespace {

/**
 * Number of parallel MySQL workers used to generate traffic.
 */
static constexpr int k_worker_threads = 24;

/**
 * Total stress runtime in seconds.
 */
static constexpr int k_runtime_seconds = 12;

/**
 * Configured MCP cap for `stats.show_processlist`.
 */
static constexpr int k_processlist_cap = 80;

/**
 * Configured MCP cap for `stats.show_queries`.
 */
static constexpr int k_show_queries_cap = 120;

/**
 * Requested processlist limit used to verify cap metadata.
 */
static constexpr int k_processlist_requested_limit = 500;

/**
 * Requested show_queries limit used to verify cap metadata.
 */
static constexpr int k_show_queries_requested_limit = 500;

/**
 * Minimum query volume expected from the mixed workload.
 */
static constexpr uint64_t k_min_total_queries = 500;

/**
 * Minimum successful poll count expected from each MCP poller thread.
 */
static constexpr uint64_t k_min_successful_polls = 10;

/**
 * Fixed schema used by this TAP for workload table creation.
 */
static constexpr const char* k_workload_schema = "test";

using MYSQLConnPtr = std::unique_ptr<MYSQL, decltype(&mysql_close)>;

/**
 * @brief Aggregated counters for the MySQL workload generator.
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
 * @brief Aggregated counters for the processlist MCP poller.
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
 * @brief Aggregated counters for the show_queries MCP poller.
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

std::string escape_sql_literal(const char* input) {
	std::string escaped = input ? input : "";
	size_t pos = 0;
	while ((pos = escaped.find('\'', pos)) != std::string::npos) {
		escaped.insert(pos, 1, '\'');
		pos += 2;
	}
	return escaped;
}

/**
 * @brief Configure MCP runtime for concurrent stats polling.
 *
 * @param admin Open admin connection.
 * @param cl TAP command-line configuration.
 * @return true if all setup statements succeeded.
 */
bool configure_mcp_runtime(MYSQL* admin, const CommandLine& cl) {
	const std::string auth_token = escape_sql_literal(cl.mcp_auth_token);
	const std::vector<std::string> statements = {
		"SET mcp-port=" + std::to_string(cl.mcp_port),
		"SET mcp-use_ssl=false",
		"SET mcp-enabled=true",
		"SET mcp-config_endpoint_auth='" + auth_token + "'",
		"SET mcp-stats_endpoint_auth='" + auth_token + "'",
		"SET mcp-stats_show_processlist_max_rows=" + std::to_string(k_processlist_cap),
		"SET mcp-stats_show_queries_max_rows=" + std::to_string(k_show_queries_cap),
		"LOAD MCP VARIABLES TO RUNTIME"
	};

	for (const auto& stmt : statements) {
		if (!run_admin_stmt(admin, stmt, "MCP stress setup")) {
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
	run_q(admin, "LOAD MCP VARIABLES FROM DISK");
}

/**
 * @brief Execute a SQL statement on MySQL and validate success.
 *
 * @param conn Open MySQL connection.
 * @param sql SQL statement to execute.
 * @param error Output error text on failure.
 * @return true on success (statement accepted and result consumed), false on failure.
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
MYSQLConnPtr create_mysql_connection(
	const char* host,
	int port,
	const char* user,
	const char* pass,
	std::string& error
) {
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
bool create_workload_table(MYSQL* conn, const std::string& table_name, std::string& error) {
	if (!execute_mysql_sql(conn, std::string("CREATE DATABASE IF NOT EXISTS ") + k_workload_schema, error)) {
		return false;
	}

	const std::string drop_sql = "DROP TABLE IF EXISTS " + std::string(k_workload_schema) + "." + table_name;
	if (!execute_mysql_sql(conn, drop_sql, error)) {
		return false;
	}

	const std::string create_sql =
		"CREATE TABLE " + std::string(k_workload_schema) + "." + table_name + " ("
		"id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, "
		"worker_id INT NOT NULL, "
		"v INT NOT NULL, "
		"payload TEXT NOT NULL, "
		"created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
		")";

	return execute_mysql_sql(conn, create_sql, error);
}

/**
 * @brief Drop workload table created by this test.
 *
 * @param conn Open setup connection.
 * @param table_name Test table name.
 * @param error Output error text on failure.
 * @return true when table drop succeeds.
 */
bool drop_workload_table(MYSQL* conn, const std::string& table_name, std::string& error) {
	const std::string drop_sql = "DROP TABLE IF EXISTS " + std::string(k_workload_schema) + "." + table_name;
	return execute_mysql_sql(conn, drop_sql, error);
}

/**
 * @brief Worker thread body that issues mixed MySQL traffic continuously.
 *
 * @param worker_id Worker identifier.
 * @param cl TAP command-line configuration.
 * @param table_name Shared workload table.
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
		std::chrono::steady_clock::now().time_since_epoch().count() ^ (static_cast<uint64_t>(worker_id) * 2654435761U)
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
			sql = "INSERT INTO " + std::string(k_workload_schema) + "." + table_name + " (worker_id, v, payload) VALUES (" +
				std::to_string(worker_id) + ", " + std::to_string(val_dist(rng)) + ", 'p_" +
				std::to_string(worker_id) + "_" + std::to_string(local_seq) + "')";
			op = op_t::ins;
		} else if (roll < 70) {
			sql = "UPDATE " + std::string(k_workload_schema) + "." + table_name + " "
			      "SET v = v + 1, payload = CONCAT(payload, '_u') "
			      "WHERE worker_id=" + std::to_string(worker_id) + " "
			      "ORDER BY id DESC LIMIT 1";
			op = op_t::upd;
		} else if (roll < 82) {
			sql = "DELETE FROM " + std::string(k_workload_schema) + "." + table_name + " "
			      "WHERE worker_id=" + std::to_string(worker_id) + " "
			      "ORDER BY id ASC LIMIT 1";
			op = op_t::del;
		} else if (roll < 90) {
			sql = "SELECT COUNT(*) FROM " + std::string(k_workload_schema) + "." + table_name +
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
 * @brief MCP poller thread that validates `stats.show_processlist` during load.
 *
 * @param cl TAP command-line configuration.
 * @param stop Stop flag set by main thread.
 * @param stats Shared processlist poll counters.
 */
void run_processlist_poller(
	const CommandLine& cl,
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
				{"db_type", "mysql"},
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
			if (!(requested_limit == k_processlist_requested_limit &&
			      effective_limit >= 0 &&
			      limit_cap == k_processlist_cap &&
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
					{"db_type", "mysql"},
					{"sort_by", "time_ms"},
					{"sort_order", "desc"},
					{"limit", 50},
					{"match_info", "SLEEP("},
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
							if (!contains_icase(info, "SLEEP(")) {
								stats.filtered_invalid_rows.fetch_add(1, std::memory_order_relaxed);
								break;
							}
						}
					}
				}
			}
		}

		++iter;
		std::this_thread::sleep_for(std::chrono::milliseconds(40));
	}
}

/**
 * @brief MCP poller thread that validates `stats.show_queries` during load.
 *
 * @param cl TAP command-line configuration.
 * @param stop Stop flag set by main thread.
 * @param stats Shared show_queries poll counters.
 */
void run_show_queries_poller(
	const CommandLine& cl,
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
				{"db_type", "mysql"},
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
			if (!(requested_limit == k_show_queries_requested_limit &&
			      effective_limit >= 0 &&
			      limit_cap == k_show_queries_cap &&
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
					{"db_type", "mysql"},
					{"sort_by", "count"},
					{"limit", 50},
					{"match_digest_text", "SLEEP"},
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
							if (!contains_icase(digest_text, "SLEEP")) {
								stats.filtered_invalid_rows.fetch_add(1, std::memory_order_relaxed);
								break;
							}
						}
					}
				}
			}
		}

		++iter;
		std::this_thread::sleep_for(std::chrono::milliseconds(60));
	}
}

} // namespace

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;

	plan(31);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to load TAP environment");
		return exit_status();
	}

	diag("=== MCP MySQL Concurrency Stress Test ===");
	diag("This test generates sustained MySQL traffic through ProxySQL while");
	diag("concurrently querying MCP stats tools from multiple threads.");
	diag("Workload includes: simple reads, INSERT/UPDATE/DELETE/SELECT on a test table,");
	diag("and randomized SLEEP calls. MCP polling validates show_processlist and show_queries");
	diag("with sorting, cap metadata, and match_info/match_digest_text filtering.");
	diag("The goal is to ensure MCP stats remains correct under concurrent MySQL load.");
	diag("==========================================");

	MYSQL* admin = nullptr;
	bool can_continue = true;

	admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	ok(admin != nullptr, "Admin connection established");
	if (!admin) {
		skip(30, "Cannot continue without admin connection");
		can_continue = false;
	}

	if (can_continue) {
		const bool configured = configure_mcp_runtime(admin, cl);
		ok(configured, "Configured MCP runtime for MySQL concurrency stress");
		if (!configured) {
			skip(29, "Cannot continue without MCP runtime configuration");
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
			skip(28, "Cannot continue without MCP connectivity");
			can_continue = false;
		}
	}

	MYSQLConnPtr setup_conn(nullptr, &mysql_close);
	std::string setup_error;
	if (can_continue) {
		setup_conn = create_mysql_connection(cl.root_host, cl.root_port, cl.root_username, cl.root_password, setup_error);
		if (!setup_conn) {
			setup_conn = create_mysql_connection(cl.host, cl.port, cl.username, cl.password, setup_error);
		}
		if (setup_conn) {
			ok(true, "MySQL workload connection established via ProxySQL");
		} else {
			ok(false, "MySQL workload connection established via ProxySQL: %s", setup_error.c_str());
			skip(27, "Cannot continue without MySQL connectivity");
			can_continue = false;
		}
	}

	std::string table_name = "mcp_mysql_stress_" + std::to_string(static_cast<unsigned long long>(getpid()));
	if (can_continue) {
		std::string table_error;
		const bool table_created = create_workload_table(setup_conn.get(), table_name, table_error);
		ok(table_created, "Created stress workload table `%s.%s`", k_workload_schema, table_name.c_str());
		if (!table_created) {
			diag("Table setup error: %s", table_error.c_str());
			skip(26, "Cannot continue without workload table");
			can_continue = false;
		}
	}

	workload_stats_t workload_stats {};
	processlist_poll_stats_t processlist_stats {};
	show_queries_poll_stats_t show_queries_stats {};

	if (can_continue) {
		std::atomic<bool> stop {false};
		std::vector<std::thread> workers;
		workers.reserve(k_worker_threads);
		for (int i = 0; i < k_worker_threads; ++i) {
			workers.emplace_back(run_mysql_worker, i, std::cref(cl), std::cref(table_name), std::cref(stop), std::ref(workload_stats));
		}

		std::thread processlist_poller(
			run_processlist_poller, std::cref(cl), std::cref(stop), std::ref(processlist_stats)
		);
		std::thread show_queries_poller(
			run_show_queries_poller, std::cref(cl), std::cref(stop), std::ref(show_queries_stats)
		);

		std::this_thread::sleep_for(std::chrono::seconds(k_runtime_seconds));
		stop.store(true, std::memory_order_relaxed);

		for (auto& t : workers) {
			if (t.joinable()) {
				t.join();
			}
		}
		if (processlist_poller.joinable()) {
			processlist_poller.join();
		}
		if (show_queries_poller.joinable()) {
			show_queries_poller.join();
		}
	}

	if (can_continue) {
		const uint64_t connected_workers = workload_stats.connected_workers.load(std::memory_order_relaxed);
		const uint64_t total_queries = workload_stats.total_queries.load(std::memory_order_relaxed);
		const uint64_t failed_queries = workload_stats.failed_queries.load(std::memory_order_relaxed);
		const uint64_t simple_queries = workload_stats.simple_queries.load(std::memory_order_relaxed);
		const uint64_t insert_queries = workload_stats.insert_queries.load(std::memory_order_relaxed);
		const uint64_t update_queries = workload_stats.update_queries.load(std::memory_order_relaxed);
		const uint64_t delete_queries = workload_stats.delete_queries.load(std::memory_order_relaxed);
		const uint64_t table_select_queries = workload_stats.table_select_queries.load(std::memory_order_relaxed);
		const uint64_t sleep_queries = workload_stats.sleep_queries.load(std::memory_order_relaxed);
		const uint64_t max_failed_queries = std::max<uint64_t>(5, total_queries / 200);

		ok(
			connected_workers >= static_cast<uint64_t>(k_worker_threads / 2),
			"At least half of worker connections succeeded (%llu/%d)",
			static_cast<unsigned long long>(connected_workers),
			k_worker_threads
		);
		ok(
			total_queries >= k_min_total_queries,
			"Workload generated sufficient traffic (%llu >= %llu)",
			static_cast<unsigned long long>(total_queries),
			static_cast<unsigned long long>(k_min_total_queries)
		);
		ok(simple_queries > 0, "Simple SELECT workload executed");
		ok(
			insert_queries > 0 && update_queries > 0 && delete_queries > 0 && table_select_queries > 0,
			"R/W workload mix executed (ins=%llu upd=%llu del=%llu sel=%llu)",
			static_cast<unsigned long long>(insert_queries),
			static_cast<unsigned long long>(update_queries),
			static_cast<unsigned long long>(delete_queries),
			static_cast<unsigned long long>(table_select_queries)
		);
		ok(sleep_queries > 0, "SLEEP workload executed");
		ok(
			failed_queries <= max_failed_queries,
			"Workload query error budget respected (failed=%llu allowed=%llu total=%llu)",
			static_cast<unsigned long long>(failed_queries),
			static_cast<unsigned long long>(max_failed_queries),
			static_cast<unsigned long long>(total_queries)
		);
	}

	if (can_continue) {
		const uint64_t pl_calls_ok = processlist_stats.calls_ok.load(std::memory_order_relaxed);
		const uint64_t pl_calls_failed = processlist_stats.calls_failed.load(std::memory_order_relaxed);
		const uint64_t pl_non_empty = processlist_stats.non_empty_snapshots.load(std::memory_order_relaxed);
		const uint64_t pl_max_sessions = processlist_stats.max_sessions_observed.load(std::memory_order_relaxed);
		const uint64_t pl_metadata_failures = processlist_stats.metadata_failures.load(std::memory_order_relaxed);
		const uint64_t pl_row_shape_failures = processlist_stats.row_shape_failures.load(std::memory_order_relaxed);
		const uint64_t pl_filtered_ok = processlist_stats.filtered_calls_ok.load(std::memory_order_relaxed);
		const uint64_t pl_filtered_non_empty = processlist_stats.filtered_non_empty_snapshots.load(std::memory_order_relaxed);
		const uint64_t pl_filtered_invalid = processlist_stats.filtered_invalid_rows.load(std::memory_order_relaxed);

		ok(
			pl_calls_ok >= k_min_successful_polls,
			"show_processlist poller collected enough successful samples (%llu)",
			static_cast<unsigned long long>(pl_calls_ok)
		);
		ok(
			pl_calls_ok > pl_calls_failed,
			"show_processlist poller success dominates failures (ok=%llu fail=%llu)",
			static_cast<unsigned long long>(pl_calls_ok),
			static_cast<unsigned long long>(pl_calls_failed)
		);
		ok(pl_non_empty > 0, "show_processlist observed non-empty snapshots during load");
		ok(
			pl_max_sessions >= 3,
			"show_processlist observed at least 3 concurrent sessions (max=%llu)",
			static_cast<unsigned long long>(pl_max_sessions)
		);
		ok(pl_metadata_failures == 0, "show_processlist limit-cap metadata remained consistent");
		ok(pl_row_shape_failures == 0, "show_processlist row shape remained consistent");
		ok(pl_filtered_ok > 0, "show_processlist filtered polling executed");
		ok(pl_filtered_non_empty > 0, "show_processlist filter returned non-empty snapshots");
		ok(pl_filtered_invalid == 0, "show_processlist filter rows matched expected `SLEEP(` token");
	}

	if (can_continue) {
		const uint64_t q_calls_ok = show_queries_stats.calls_ok.load(std::memory_order_relaxed);
		const uint64_t q_calls_failed = show_queries_stats.calls_failed.load(std::memory_order_relaxed);
		const uint64_t q_metadata_failures = show_queries_stats.metadata_failures.load(std::memory_order_relaxed);
		const uint64_t q_sorted_failures = show_queries_stats.sorted_failures.load(std::memory_order_relaxed);
		const uint64_t q_digests_seen = show_queries_stats.digests_seen_snapshots.load(std::memory_order_relaxed);
		const uint64_t q_filtered_ok = show_queries_stats.filtered_calls_ok.load(std::memory_order_relaxed);
		const uint64_t q_filtered_non_empty = show_queries_stats.filtered_non_empty_snapshots.load(std::memory_order_relaxed);
		const uint64_t q_filtered_invalid = show_queries_stats.filtered_invalid_rows.load(std::memory_order_relaxed);

		ok(
			q_calls_ok >= k_min_successful_polls,
			"show_queries poller collected enough successful samples (%llu)",
			static_cast<unsigned long long>(q_calls_ok)
		);
		ok(
			q_calls_ok > q_calls_failed,
			"show_queries poller success dominates failures (ok=%llu fail=%llu)",
			static_cast<unsigned long long>(q_calls_ok),
			static_cast<unsigned long long>(q_calls_failed)
		);
		ok(q_digests_seen > 0, "show_queries observed non-zero digest snapshots");
		ok(q_metadata_failures == 0, "show_queries limit-cap metadata remained consistent");
		ok(q_sorted_failures == 0, "show_queries snapshots remained sorted by count_star DESC");
		ok(q_filtered_ok > 0, "show_queries filtered polling executed");
		ok(q_filtered_non_empty > 0, "show_queries filter returned non-empty snapshots");
		ok(q_filtered_invalid == 0, "show_queries filtered rows matched expected digest token");
	}

	if (can_continue) {
		const MCPResponse final_queries_resp = mcp->call_tool(
			"stats",
			"show_queries",
			json{
				{"db_type", "mysql"},
				{"sort_by", "count"},
				{"limit", 50},
				{"match_digest_text", "SLEEP"},
				{"digest_text_case_sensitive", false}
			}
		);
		json final_queries_result = json::object();
		std::string final_queries_error;
		const bool final_queries_ok = extract_tool_result(final_queries_resp, final_queries_result, final_queries_error);
		ok(
			final_queries_ok && final_queries_result.value("db_type", std::string("")) == "mysql",
			"Final show_queries call succeeded for mysql%s%s",
			final_queries_ok ? "" : ": ",
			final_queries_ok ? "" : final_queries_error.c_str()
		);

		const MCPResponse final_processlist_resp = mcp->call_tool(
			"stats",
			"show_processlist",
			json{
				{"db_type", "mysql"},
				{"sort_by", "time_ms"},
				{"sort_order", "desc"},
				{"limit", 20}
			}
		);
		json final_processlist_result = json::object();
		std::string final_processlist_error;
		const bool final_processlist_ok = extract_tool_result(
			final_processlist_resp, final_processlist_result, final_processlist_error
		);
		ok(
			final_processlist_ok && final_processlist_result.value("db_type", std::string("")) == "mysql",
			"Final show_processlist call succeeded for mysql%s%s",
			final_processlist_ok ? "" : ": ",
			final_processlist_ok ? "" : final_processlist_error.c_str()
		);
	}

	if (can_continue) {
		std::string drop_error;
		const bool dropped = drop_workload_table(setup_conn.get(), table_name, drop_error);
		ok(dropped, "Dropped stress workload table `%s.%s`", k_workload_schema, table_name.c_str());
		if (!dropped) {
			diag("Table cleanup error: %s", drop_error.c_str());
		}
	}

	if (setup_conn) {
		setup_conn.reset();
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
