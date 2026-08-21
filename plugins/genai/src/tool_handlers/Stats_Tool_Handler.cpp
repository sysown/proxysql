#ifdef PROXYSQL40

#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <limits>
#include <algorithm>

#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "sqlite3db.h"
#include "proxysql_debug.h"
#include "proxysql_utils.h"
#include "MySQL_Logger.hpp"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"
#include "MySQL_HostGroups_Manager.h"
#include "PgSQL_HostGroups_Manager.h"
#include "MySQL_Authentication.hpp"
#include "PgSQL_Authentication.h"
#include "MySQL_LDAP_Authentication.hpp"

#include "MCP_Thread.h"
#include "Stats_Tool_Handler.h"

extern ProxySQL_Admin *GloAdmin;
extern MySQL_Logger *GloMyLogger;
extern MySQL_Threads_Handler *GloMTH;
extern PgSQL_Threads_Handler *GloPTH;

extern MySQL_Query_Processor* GloMyQPro;
extern PgSQL_Query_Processor* GloPgQPro;
extern MySQL_HostGroups_Manager* MyHGM;
extern PgSQL_HostGroups_Manager* PgHGM;
extern MySQL_Authentication* GloMyAuth;
extern PgSQL_Authentication* GloPgAuth;
extern MySQL_LDAP_Authentication* GloMyLdapAuth;

// Latency bucket thresholds in microseconds for commands_counters histogram
static const std::vector<int> LATENCY_BUCKET_THRESHOLDS = {
	100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000, 10000000, 100000000
};

// Interval configuration: maps user-friendly strings to seconds and table selection
// Table selection: false = raw tables (higher resolution), true = hourly aggregated tables
// Rule: intervals <=6h use raw tables, intervals >=8h use hourly tables
static const std::map<std::string, std::pair<int, bool>> INTERVAL_MAP = {
	{"30m",  {1800, false}},
	{"1h",   {3600, false}},
	{"2h",   {7200, false}},
	{"4h",   {14400, false}},
	{"6h",   {21600, false}},
	{"8h",   {28800, true}},
	{"12h",  {43200, true}},
	{"1d",   {86400, true}},
	{"3d",   {259200, true}},
	{"7d",   {604800, true}},
	{"30d",  {2592000, true}},
	{"90d",  {7776000, true}}
};

// Category prefixes for show_status filtering
static const std::map<std::string, std::vector<std::string>> CATEGORY_PREFIXES = {
	{"connections", {"Client_Connections_", "Server_Connections_", "Active_Transactions"}},
	{"queries", {"Questions", "Slow_queries", "GTID_", "Queries_", "Query_Processor_", "Backend_query_time_"}},
	{"commands", {"Com_"}},
	{"pool_ops", {"ConnPool_", "MyHGM_", "PgHGM_"}},
	{"monitor", {"MySQL_Monitor_", "PgSQL_Monitor_"}},
	{"query_cache", {"Query_Cache_"}},
	{"prepared_stmts", {"Stmt_"}},
	{"security", {"automatic_detected_sql_injection", "ai_", "mysql_whitelisted_"}},
	{"memory", {"_buffers_bytes", "_internal_bytes", "SQLite3_memory_bytes", "ConnPool_memory_bytes",
				"jemalloc_", "Auth_memory", "query_digest_memory", "query_rules_memory",
				"prepare_statement_", "firewall_", "stack_memory_"}},
	{"errors", {"generated_error_packets", "Access_Denied_", "client_host_error_", "mysql_unexpected_"}},
	{"logger", {"MySQL_Logger_"}},
	{"system", {"ProxySQL_Uptime", "MySQL_Thread_Workers", "PgSQL_Thread_Workers",
				"Servers_table_version", "mysql_listener_paused", "pgsql_listener_paused", "OpenSSL_"}},
	{"mirror", {"Mirror_"}}
};

/**
 * Hard upper bound for configurable `mcp_stats_show_queries_max_rows`.
 *
 * The runtime MCP variable can reduce this value, but cannot exceed it.
 * It protects the process from unbounded Top-K windows.
 */
static constexpr uint32_t SHOW_QUERIES_MAX_LIMIT_HARDCODED = 1000;

/**
 * Hard upper bound for configurable `mcp_stats_show_processlist_max_rows`.
 *
 * The runtime MCP variable can reduce this value, but cannot exceed it.
 * It protects the process from unbounded processlist page windows.
 */
static constexpr uint32_t SHOW_PROCESSLIST_MAX_LIMIT_HARDCODED = 1000;

namespace stats_utils {

/**
 * @brief Parse and validate a backend filter in `host:port` format.
 *
 * The helper enforces a strict numeric port with range `[1, 65535]`.
 * On error it returns false and provides a short diagnostic message
 * in @p error so the caller can both log and return a user-facing error.
 *
 * @param server_filter Raw filter string provided by tool arguments.
 * @param host Output host part when parsing succeeds.
 * @param port Output TCP port when parsing succeeds.
 * @param error Output validation message when parsing fails.
 * @return true when parsing succeeds and @p host/@p port are valid.
 */
bool parse_server_filter(const std::string& server_filter, std::string& host, int& port, std::string& error) {
	size_t colon = server_filter.rfind(':');
	if (colon == std::string::npos || colon == 0 || colon == server_filter.size() - 1) {
		error = "expected format host:port";
		return false;
	}

	host = server_filter.substr(0, colon);
	std::string port_str = server_filter.substr(colon + 1);

	char* end = nullptr;
	errno = 0;
	long parsed_port = strtol(port_str.c_str(), &end, 10);
	if (end == port_str.c_str() || *end != '\0' || errno != 0 || parsed_port < 1 || parsed_port > 65535) {
		error = "port must be an integer in range [1,65535]";
		return false;
	}

	port = static_cast<int>(parsed_port);
	return true;
}

/**
 * @brief Parse digest filter string into uint64 digest identifier.
 *
 * Accepted input formats:
 * - hexadecimal with prefix (`0x1234ABCD`)
 * - hexadecimal without prefix (`1234ABCD`)
 * - decimal unsigned integer
 *
 * @param digest_filter Input digest text from MCP arguments.
 * @param digest_value Parsed numeric digest output.
 * @param error Parsing error details if conversion fails.
 * @return true on successful conversion.
 */
bool parse_digest_filter(const std::string& digest_filter, uint64_t& digest_value, std::string& error) {
	if (digest_filter.empty()) {
		error = "empty digest filter";
		return false;
	}

	char* end = nullptr;
	errno = 0;

	int base = 10;
	std::string input = digest_filter;
	if (input.size() > 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
		base = 16;
	}

	uint64_t parsed = strtoull(input.c_str(), &end, base);
	if (end == input.c_str() || *end != '\0' || errno != 0) {
		/**
		 * Retry as hexadecimal without `0x` prefix (common digest representation).
		 */
		errno = 0;
		end = nullptr;
		parsed = strtoull(input.c_str(), &end, 16);
		if (end == input.c_str() || *end != '\0' || errno != 0) {
			error = "digest must be a valid unsigned integer (decimal or hex)";
			return false;
		}
	}

	digest_value = parsed;
	return true;
}

/**
 * @brief Parse a nullable numeric SQLite field into signed 64-bit.
 *
 * Resultsets returned by in-memory ProxySQL snapshots expose numbers as
 * null-terminated strings. This helper centralizes conversion semantics for MCP
 * tools, treating null fields as zero and avoiding exceptions.
 *
 * @param value Nullable C string from `SQLite3_row::fields`.
 * @return Parsed value, or zero when @p value is null.
 */
long long parse_ll_or_zero(const char* value) {
	if (!value || !value[0]) {
		return 0LL;
	}

	char* end = nullptr;
	errno = 0;
	const long long parsed = strtoll(value, &end, 10);
	if (end == value || *end != '\0' || errno == ERANGE) {
		return 0LL;
	}

	return parsed;
}

/**
 * @brief Parse a nullable numeric SQLite field into signed int.
 *
 * This helper mirrors `parse_ll_or_zero()` for integer-sized fields and keeps
 * conversion behavior consistent across MCP handlers.
 *
 * @param value Nullable C string from `SQLite3_row::fields`.
 * @return Parsed value, or zero when @p value is null.
 */
int parse_int_or_zero(const char* value) {
	const long long parsed = parse_ll_or_zero(value);
	if (parsed > std::numeric_limits<int>::max()) {
		return std::numeric_limits<int>::max();
	}
	if (parsed < std::numeric_limits<int>::min()) {
		return std::numeric_limits<int>::min();
	}
	return static_cast<int>(parsed);
}

} // namespace stats_utils

// Make helpers available unqualified within this translation unit.
// The namespace prevents symbol collisions in other TUs that include the header.
using namespace stats_utils;

/**
 * @brief Snapshot row used by in-memory implementation of `show_commands`.
 *
 * Values are copied from `MySQL_Query_Processor::get_stats_commands_counters()`
 * or `PgSQL_Query_Processor::get_stats_commands_counters()` once, then sorted,
 * filtered, and paginated in C++ without querying `stats.*` tables.
 */
struct mcp_command_counter_row_t {
	std::string command;             ///< Command name (for example `SELECT`).
	long long total_time_us;         ///< Total observed execution time in microseconds.
	long long total_count;           ///< Total observed executions for the command.
	std::vector<int> latency_buckets;///< Histogram buckets from `cnt_100us` to `cnt_INFs`.
};

/**
 * @brief Snapshot row used by in-memory implementation of `show_connections`.
 *
 * The row models both MySQL and PostgreSQL connection-pool snapshots. The
 * `queries_gtid_sync` field is valid only for MySQL.
 */
struct mcp_connection_pool_row_t {
	int hostgroup;                   ///< Runtime hostgroup id.
	std::string srv_host;            ///< Backend hostname/ip.
	int srv_port;                    ///< Backend TCP port.
	std::string status;              ///< ONLINE/SHUNNED/OFFLINE_* textual status.
	int conn_used;                   ///< Number of connections currently in use.
	int conn_free;                   ///< Number of idle pooled connections.
	long long conn_ok;               ///< Successful backend connects.
	long long conn_err;              ///< Failed backend connects.
	int max_conn_used;               ///< Maximum concurrently used pooled connections.
	long long queries;               ///< Total queries sent through this backend.
	long long queries_gtid_sync;     ///< GTID sync queries (MySQL only).
	long long bytes_data_sent;       ///< Bytes sent to backend.
	long long bytes_data_recv;       ///< Bytes received from backend.
	int latency_us;                  ///< Last measured latency in microseconds.
};

/**
 * @brief Snapshot row used by in-memory implementation of `show_users`.
 *
 * The row models user-level frontend connection usage exported by authentication
 * modules. It intentionally mirrors `stats_[mysql|pgsql]_users` columns while
 * avoiding runtime-populated stats tables.
 */
struct mcp_frontend_user_row_t {
	std::string username;            ///< Frontend username.
	int frontend_connections;        ///< Current active frontend connections.
	int frontend_max_connections;    ///< Configured per-user max connections.
};

// ============================================================================
// Constructor / Destructor / Init / Close
// ============================================================================

Stats_Tool_Handler::Stats_Tool_Handler(MCP_Threads_Handler* handler)
	: mcp_handler(handler)
{
	pthread_mutex_init(&handler_lock, NULL);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Stats_Tool_Handler created\n");
}

Stats_Tool_Handler::~Stats_Tool_Handler() {
	close();
	pthread_mutex_destroy(&handler_lock);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Stats_Tool_Handler destroyed\n");
}

int Stats_Tool_Handler::init() {
	proxy_info("Stats_Tool_Handler initialized\n");
	return 0;
}

void Stats_Tool_Handler::close() {
	proxy_debug(PROXY_DEBUG_GENERIC, 2, "Stats_Tool_Handler closed\n");
}

// ============================================================================
// Helper Methods
// ============================================================================

/**
 * @brief Execute a statement against Admin in-memory DB under Admin global SQL mutex.
 *
 * This method is the temporary correctness bridge for MCP stats tools:
 * the tools build SQL directly over `stats.*` tables, but most of these tables are
 * refreshed on demand by Admin interception logic. To preserve data freshness when MCP
 * bypasses Admin SQL parsing, this helper optionally triggers
 * `ProxySQL_Admin::GenericRefreshStatistics()` before running the statement.
 *
 * The refresh and statement execution are performed while holding
 * `GloAdmin->sql_query_global_mutex`, mirroring Admin session serialization.
 *
 * @param sql SQL statement to execute.
 * @param resultset Output result set pointer. Set to NULL on failure.
 * @param cols Output column count pointer. Set to 0 on failure.
 * @param refresh_before_query If true, run GenericRefreshStatistics for @p sql before execution.
 * @return Empty string on success, or descriptive error text on failure.
 */
std::string Stats_Tool_Handler::execute_admin_query(const char* sql, SQLite3_result** resultset, int* cols, bool refresh_before_query) {
	if (!GloAdmin || !GloAdmin->admindb) {
		return "ProxySQL Admin not available";
	}
	if (!resultset || !cols) {
		return "Invalid output pointers for admin query execution";
	}
	if (!sql || sql[0] == '\0') {
		*resultset = NULL;
		*cols = 0;
		return "Empty SQL query";
	}

	*resultset = NULL;
	*cols = 0;

	int lock_rc = pthread_mutex_lock(&GloAdmin->sql_query_global_mutex);
	if (lock_rc != 0) {
		return std::string("Failed to lock sql_query_global_mutex: ") + std::strerror(lock_rc);
	}

	if (refresh_before_query) {
		GloAdmin->GenericRefreshStatistics(sql, static_cast<unsigned int>(strlen(sql)), false);
	}

	char* error = NULL;
	int affected_rows = 0;
	GloAdmin->admindb->execute_statement(sql, &error, cols, &affected_rows, resultset);

	int unlock_rc = pthread_mutex_unlock(&GloAdmin->sql_query_global_mutex);
	if (unlock_rc != 0) {
		if (error) {
			std::string err_msg(error);
			free(error);
			if (*resultset) {
				delete *resultset;
				*resultset = NULL;
			}
			return "Admin query error: " + err_msg +
				"; also failed to unlock sql_query_global_mutex: " + std::string(std::strerror(unlock_rc));
		}
		if (*resultset) {
			delete *resultset;
			*resultset = NULL;
		}
		*cols = 0;
		return std::string("Failed to unlock sql_query_global_mutex: ") + std::strerror(unlock_rc);
	}

	if (error) {
		std::string err_msg(error);
		free(error);
		if (*resultset) {
			delete *resultset;
			*resultset = NULL;
		}
		return err_msg;
	}

	return "";
}

std::string Stats_Tool_Handler::execute_statsdb_disk_query(const char* sql, SQLite3_result** resultset, int* cols) {
	if (!GloAdmin || !GloAdmin->statsdb_disk) {
		return "ProxySQL statsdb_disk not available";
	}

	char* error = NULL;
	int affected_rows = 0;
	*resultset = NULL;
	*cols = 0;

	GloAdmin->statsdb_disk->execute_statement(sql, &error, cols, &affected_rows, resultset);

	if (error) {
		std::string err_msg(error);
		free(error);
		if (*resultset) {
			delete *resultset;
			*resultset = NULL;
		}
		return err_msg;
	}

	return "";
}

std::map<std::string, std::string> Stats_Tool_Handler::parse_global_stats(SQLite3_result* resultset) {
	std::map<std::string, std::string> stats;

	if (!resultset) return stats;

	for (const auto& row : resultset->rows) {
		if (row->fields[0] && row->fields[1]) {
			stats[row->fields[0]] = row->fields[1];
		}
	}

	return stats;
}

bool Stats_Tool_Handler::get_interval_config(const std::string& interval, int& seconds, bool& use_hourly) {
	auto it = INTERVAL_MAP.find(interval);
	if (it == INTERVAL_MAP.end()) {
		return false;
	}
	seconds = it->second.first;
	use_hourly = it->second.second;
	return true;
}

int Stats_Tool_Handler::calculate_percentile(const std::vector<int>& buckets, const std::vector<int>& thresholds, double percentile) {
	if (buckets.empty() || thresholds.empty()) {
		return 0;
	}

	if (percentile < 0.0) {
		percentile = 0.0;
	} else if (percentile > 1.0) {
		percentile = 1.0;
	}

	if (percentile == 0.0) {
		for (size_t i = 0; i < buckets.size() && i < thresholds.size(); i++) {
			if (buckets[i] > 0) {
				return thresholds[i];
			}
		}
		return 0;
	}

	long long total = 0;
	for (int count : buckets) {
		if (count > 0) {
			total += count;
		}
	}

	if (total == 0) return 0;

	long long target = static_cast<long long>(std::ceil(static_cast<long double>(total) * percentile));
	if (target < 1) {
		target = 1;
	}
	long long cumulative = 0;

	for (size_t i = 0; i < buckets.size() && i < thresholds.size(); i++) {
		if (buckets[i] > 0) {
			cumulative += buckets[i];
		}
		if (cumulative >= target) {
			return thresholds[i];
		}
	}

	return thresholds.empty() ? 0 : thresholds.back();
}

// ============================================================================
// Tool List / Description / Dispatch
// ============================================================================

json Stats_Tool_Handler::get_tool_list() {
	json tools = json::array();

	// =========================================================================
	// Live Data Tools (13)
	// =========================================================================

	tools.push_back(create_tool_description(
		"show_status",
		"Returns global status variables and metrics from ProxySQL. Similar to MySQL's SHOW STATUS command.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"category", {
					{"type", "string"},
					{"enum", {"connections", "queries", "commands", "pool_ops", "monitor", "query_cache",
							  "prepared_stmts", "security", "memory", "errors", "logger", "system", "mirror"}},
					{"description", "Filter by category"}
				}},
				{"variable_name", {
					{"type", "string"},
					{"description", "Filter by variable name pattern (supports SQL LIKE with % wildcards)"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_processlist",
		"Shows all currently active sessions being processed by ProxySQL.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"username", {
					{"type", "string"},
					{"description", "Filter by username"}
				}},
				{"database", {
					{"type", "string"},
					{"description", "Filter by schema/database name"}
				}},
				{"hostgroup", {
					{"type", "integer"},
					{"description", "Filter by hostgroup ID"}
				}},
				{"command", {
					{"type", "string"},
					{"description", "Filter by command/status (for example Query, Sleep, Connect)"}
				}},
				{"session_id", {
					{"type", "integer"},
					{"description", "Filter by ProxySQL SessionID"}
				}},
				{"min_time_ms", {
					{"type", "integer"},
					{"description", "Only show sessions running longer than N milliseconds"}
				}},
				{"match_info", {
					{"type", "string"},
					{"description", "Substring filter on current query text/info"}
				}},
				{"info_case_sensitive", {
					{"type", "boolean"},
					{"description", "Case-sensitive matching for match_info (default: false)"},
					{"default", false}
				}},
				{"sort_by", {
					{"type", "string"},
					{"enum", {"time_ms", "session_id", "username", "hostgroup", "command"}},
					{"description", "Sort key (default: time_ms)"},
					{"default", "time_ms"}
				}},
				{"sort_order", {
					{"type", "string"},
					{"enum", {"asc", "desc"}},
					{"description", "Sort direction (default: desc)"},
					{"default", "desc"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Maximum number of sessions to return (default: 100)"},
					{"default", 100}
				}},
				{"offset", {
					{"type", "integer"},
					{"description", "Skip first N results (default: 0)"},
					{"default", 0}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_queries",
		"Returns aggregated query performance statistics by digest pattern.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"sort_by", {
					{"type", "string"},
					{"enum", {"count", "avg_time", "sum_time", "max_time", "rows_sent"}},
					{"description", "Sort order (default: count)"},
					{"default", "count"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Maximum number of results (default: 100)"},
					{"default", 100}
				}},
				{"offset", {
					{"type", "integer"},
					{"description", "Skip first N results (default: 0)"},
					{"default", 0}
				}},
				{"min_count", {
					{"type", "integer"},
					{"description", "Only show queries executed at least N times"}
				}},
				{"min_time_us", {
					{"type", "integer"},
					{"description", "Only show queries with avg time >= N microseconds"}
				}},
				{"database", {
					{"type", "string"},
					{"description", "Filter by database name"}
				}},
				{"username", {
					{"type", "string"},
					{"description", "Filter by username"}
				}},
				{"hostgroup", {
					{"type", "integer"},
					{"description", "Filter by hostgroup ID"}
				}},
					{"digest", {
						{"type", "string"},
						{"description", "Filter by specific query digest"}
					}},
					{"match_digest_text", {
						{"type", "string"},
						{"description", "Substring filter over digest_text"}
					}},
					{"digest_text_case_sensitive", {
						{"type", "boolean"},
						{"description", "Case-sensitive matching for match_digest_text (default: false)"},
						{"default", false}
					}}
				}}
			}
		));

	tools.push_back(create_tool_description(
		"show_commands",
		"Returns command execution statistics with latency distribution histograms.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"command", {
					{"type", "string"},
					{"description", "Filter by specific command (SELECT, INSERT, etc.)"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Maximum number of commands to return (default: 100)"},
					{"default", 100}
				}},
				{"offset", {
					{"type", "integer"},
					{"description", "Skip first N results (default: 0)"},
					{"default", 0}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_connections",
		"Returns backend connection pool metrics per server.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"hostgroup", {
					{"type", "integer"},
					{"description", "Filter by hostgroup ID"}
				}},
				{"server", {
					{"type", "string"},
					{"description", "Filter by server (format: host:port)"}
				}},
				{"status", {
					{"type", "string"},
					{"enum", {"ONLINE", "SHUNNED", "OFFLINE_SOFT", "OFFLINE_HARD"}},
					{"description", "Filter by server status"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_free_connections",
		"Returns debug free-connection pool snapshots. Requires mcp-stats_enable_debug_tools=true.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"hostgroup", {
					{"type", "integer"},
					{"description", "Filter by hostgroup ID"}
				}},
				{"server", {
					{"type", "string"},
					{"description", "Filter by server (format: host:port)"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_errors",
		"Returns error tracking statistics with frequency analysis.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"errno", {
					{"type", "integer"},
					{"description", "Filter by error number (MySQL)"}
				}},
				{"sqlstate", {
					{"type", "string"},
					{"description", "Filter by SQLSTATE (PostgreSQL)"}
				}},
				{"username", {
					{"type", "string"},
					{"description", "Filter by username"}
				}},
				{"database", {
					{"type", "string"},
					{"description", "Filter by database name"}
				}},
				{"hostgroup", {
					{"type", "integer"},
					{"description", "Filter by hostgroup ID"}
				}},
				{"min_count", {
					{"type", "integer"},
					{"description", "Only show errors with count >= N"}
				}},
				{"sort_by", {
					{"type", "string"},
					{"enum", {"count", "first_seen", "last_seen"}},
					{"description", "Sort order (default: count)"},
					{"default", "count"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Maximum number of results (default: 100)"},
					{"default", 100}
				}},
				{"offset", {
					{"type", "integer"},
					{"description", "Skip first N results (default: 0)"},
					{"default", 0}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_users",
		"Returns connection statistics per user.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"username", {
					{"type", "string"},
					{"description", "Filter by specific username"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Maximum number of users to return (default: 100)"},
					{"default", 100}
				}},
				{"offset", {
					{"type", "integer"},
					{"description", "Skip first N results (default: 0)"},
					{"default", 0}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_client_cache",
		"Returns client host error cache for connection throttling analysis.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"client_address", {
					{"type", "string"},
					{"description", "Filter by specific client IP"}
				}},
				{"min_error_count", {
					{"type", "integer"},
					{"description", "Only show hosts with error count >= N"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Maximum number of hosts to return (default: 100)"},
					{"default", 100}
				}},
				{"offset", {
					{"type", "integer"},
					{"description", "Skip first N results (default: 0)"},
					{"default", 0}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_query_rules",
		"Returns query rule hit statistics.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"rule_id", {
					{"type", "integer"},
					{"description", "Filter by specific rule ID"}
				}},
				{"min_hits", {
					{"type", "integer"},
					{"description", "Only show rules with hits >= N"}
				}},
				{"include_zero_hits", {
					{"type", "boolean"},
					{"description", "Include rules with zero hits (default: false)"},
					{"default", false}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Maximum number of rules to return (default: 100)"},
					{"default", 100}
				}},
				{"offset", {
					{"type", "integer"},
					{"description", "Skip first N results (default: 0)"},
					{"default", 0}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_prepared_statements",
		"Returns prepared statement information.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"username", {
					{"type", "string"},
					{"description", "Filter by username"}
				}},
				{"database", {
					{"type", "string"},
					{"description", "Filter by database name"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_gtid",
		"Returns GTID (Global Transaction ID) replication information. MySQL only.",
		{
			{"type", "object"},
			{"properties", {
				{"hostname", {
					{"type", "string"},
					{"description", "Filter by backend server hostname"}
				}},
				{"port", {
					{"type", "integer"},
					{"description", "Filter by backend server port"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_cluster",
		"Returns ProxySQL cluster node health, synchronization status, and configuration checksums.",
		{
			{"type", "object"},
			{"properties", {
				{"hostname", {
					{"type", "string"},
					{"description", "Filter by specific node hostname"}
				}},
				{"include_checksums", {
					{"type", "boolean"},
					{"description", "Include configuration checksums (default: true)"},
					{"default", true}
				}}
			}}
		}
	));

	// =========================================================================
	// Historical Data Tools (4)
	// =========================================================================

	tools.push_back(create_tool_description(
		"show_system_history",
		"Returns historical CPU and memory usage trends.",
		{
			{"type", "object"},
			{"properties", {
				{"metric", {
					{"type", "string"},
					{"enum", {"cpu", "memory", "all"}},
					{"description", "Which metrics to return (default: all)"},
					{"default", "all"}
				}},
				{"interval", {
					{"type", "string"},
					{"enum", {"30m", "1h", "2h", "4h", "6h", "8h", "12h", "1d", "3d", "7d", "30d", "90d"}},
					{"description", "How far back to look (default: 1h)"},
					{"default", "1h"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_query_cache_history",
		"Returns historical query cache performance metrics. MySQL only.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"interval", {
					{"type", "string"},
					{"enum", {"30m", "1h", "2h", "4h", "6h", "8h", "12h", "1d", "3d", "7d", "30d", "90d"}},
					{"description", "How far back to look (default: 1h)"},
					{"default", "1h"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_connection_history",
		"Returns historical connection metrics at global or per-server level. MySQL only.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"interval", {
					{"type", "string"},
					{"enum", {"30m", "1h", "2h", "4h", "6h", "8h", "12h", "1d", "3d", "7d", "30d", "90d"}},
					{"description", "How far back to look (default: 1h)"},
					{"default", "1h"}
				}},
				{"scope", {
					{"type", "string"},
					{"enum", {"global", "per_server", "all"}},
					{"description", "Level of detail (default: global)"},
					{"default", "global"}
				}},
				{"hostgroup", {
					{"type", "integer"},
					{"description", "Filter per_server by hostgroup"}
				}},
				{"server", {
					{"type", "string"},
					{"description", "Filter per_server by server (format: host:port)"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_query_history",
		"Returns historical query digest snapshots for trend analysis.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}},
				{"dump_time", {
					{"type", "integer"},
					{"description", "Filter by specific snapshot timestamp"}
				}},
				{"start_time", {
					{"type", "integer"},
					{"description", "Start of time range (Unix timestamp)"}
				}},
				{"end_time", {
					{"type", "integer"},
					{"description", "End of time range (Unix timestamp)"}
				}},
				{"digest", {
					{"type", "string"},
					{"description", "Filter by specific query digest"}
				}},
				{"username", {
					{"type", "string"},
					{"description", "Filter by username"}
				}},
				{"database", {
					{"type", "string"},
					{"description", "Filter by database name"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Maximum results per snapshot (default: 100)"},
					{"default", 100}
				}},
				{"offset", {
					{"type", "integer"},
					{"description", "Skip first N results (default: 0)"},
					{"default", 0}
				}}
			}}
		}
	));

	// =========================================================================
	// Utility Tools (3)
	// =========================================================================

	tools.push_back(create_tool_description(
		"flush_query_log",
		"Flushes query events from the circular buffer into queryable tables. MySQL only.",
		{
			{"type", "object"},
			{"properties", {
				{"destination", {
					{"type", "string"},
					{"enum", {"memory", "disk", "both"}},
					{"description", "Where to flush events (default: memory)"},
					{"default", "memory"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_query_log",
		"Returns individual query execution events from the audit log. MySQL only.",
		{
			{"type", "object"},
			{"properties", {
				{"source", {
					{"type", "string"},
					{"enum", {"memory", "disk"}},
					{"description", "Which table to read from (default: memory)"},
					{"default", "memory"}
				}},
				{"username", {
					{"type", "string"},
					{"description", "Filter by username"}
				}},
				{"database", {
					{"type", "string"},
					{"description", "Filter by database name"}
				}},
				{"query_digest", {
					{"type", "string"},
					{"description", "Filter by digest hash"}
				}},
				{"server", {
					{"type", "string"},
					{"description", "Filter by backend server"}
				}},
				{"errno", {
					{"type", "integer"},
					{"description", "Filter by error number"}
				}},
				{"errors_only", {
					{"type", "boolean"},
					{"description", "Only show queries with errors (default: false)"},
					{"default", false}
				}},
				{"start_time", {
					{"type", "integer"},
					{"description", "Start of time range (Unix timestamp)"}
				}},
				{"end_time", {
					{"type", "integer"},
					{"description", "End of time range (Unix timestamp)"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Maximum results (default: 100)"},
					{"default", 100}
				}},
				{"offset", {
					{"type", "integer"},
					{"description", "Skip first N results (default: 0)"},
					{"default", 0}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"flush_queries",
		"Saves current query digest statistics to disk and resets the in-memory counters.",
		{
			{"type", "object"},
			{"properties", {
				{"db_type", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	json result;
	result["tools"] = tools;
	return result;
}

json Stats_Tool_Handler::get_tool_description(const std::string& tool_name) {
	json tools_list = get_tool_list();
	for (const auto& tool : tools_list["tools"]) {
		if (tool["name"] == tool_name) {
			return tool;
		}
	}
	return create_error_response("Tool not found: " + tool_name);
}

json Stats_Tool_Handler::execute_tool(const std::string& tool_name, const json& arguments) {
	pthread_mutex_lock(&handler_lock);

	json result;

	try {
		// Live Data Tools
		if (tool_name == "show_status") {
			result = handle_show_status(arguments);
		} else if (tool_name == "show_processlist") {
			result = handle_show_processlist(arguments);
		} else if (tool_name == "show_queries") {
			result = handle_show_queries(arguments);
		} else if (tool_name == "show_commands") {
			result = handle_show_commands(arguments);
		} else if (tool_name == "show_connections") {
			result = handle_show_connections(arguments);
		} else if (tool_name == "show_free_connections") {
			result = handle_show_free_connections(arguments);
		} else if (tool_name == "show_errors") {
			result = handle_show_errors(arguments);
		} else if (tool_name == "show_users") {
			result = handle_show_users(arguments);
		} else if (tool_name == "show_client_cache") {
			result = handle_show_client_cache(arguments);
		} else if (tool_name == "show_query_rules") {
			result = handle_show_query_rules(arguments);
		} else if (tool_name == "show_prepared_statements") {
			result = handle_show_prepared_statements(arguments);
		} else if (tool_name == "show_gtid") {
			result = handle_show_gtid(arguments);
		} else if (tool_name == "show_cluster") {
			result = handle_show_cluster(arguments);
		}
		// Historical Data Tools
		else if (tool_name == "show_system_history") {
			result = handle_show_system_history(arguments);
		} else if (tool_name == "show_query_cache_history") {
			result = handle_show_query_cache_history(arguments);
		} else if (tool_name == "show_connection_history") {
			result = handle_show_connection_history(arguments);
		} else if (tool_name == "show_query_history") {
			result = handle_show_query_history(arguments);
		}
		// Utility Tools
		else if (tool_name == "flush_query_log") {
			result = handle_flush_query_log(arguments);
		} else if (tool_name == "show_query_log") {
			result = handle_show_query_log(arguments);
		} else if (tool_name == "flush_queries") {
			result = handle_flush_queries(arguments);
		} else {
			result = create_error_response("Unknown tool: " + tool_name);
		}
	} catch (const std::exception& e) {
		result = create_error_response(std::string("Exception: ") + e.what());
	}

	pthread_mutex_unlock(&handler_lock);
	return result;
}

// ============================================================================
// Live Data Tool Implementations
// ============================================================================

/**
 * @brief Returns global status variables and metrics from ProxySQL
 *
 * Queries stats_mysql_global or stats_pgsql_global tables for system metrics.
 * Supports filtering by category (connections, queries, memory, etc.) or by
 * variable name pattern using SQL LIKE wildcards.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - category: Filter by category (connections, queries, commands, etc.)
 *   - variable_name: Filter by variable name pattern (supports % wildcards)
 *
 * @return JSON response with variables array containing variable_name and value
 */
json Stats_Tool_Handler::handle_show_status(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	std::string category = arguments.value("category", "");
	std::string variable_name = arguments.value("variable_name", "");

	std::string table = (db_type == "pgsql") ? "stats_pgsql_global" : "stats_mysql_global";

	std::string sql = "SELECT Variable_Name, Variable_Value FROM stats." + table;

	// Build WHERE clause based on filters
	std::vector<std::string> conditions;

	if (!variable_name.empty()) {
		conditions.push_back("Variable_Name LIKE '" + sql_escape(variable_name) + "'");
	} else if (!category.empty()) {
		auto it = CATEGORY_PREFIXES.find(category);
		if (it != CATEGORY_PREFIXES.end()) {
			std::vector<std::string> or_conditions;
			for (const auto& prefix : it->second) {
				if (prefix.back() == '_') {
					or_conditions.push_back("Variable_Name LIKE '" + sql_escape(prefix) + "%'");
				} else {
					or_conditions.push_back("Variable_Name = '" + sql_escape(prefix) + "'");
				}
			}
			if (!or_conditions.empty()) {
				std::string combined = "(";
				for (size_t i = 0; i < or_conditions.size(); i++) {
					if (i > 0) combined += " OR ";
					combined += or_conditions[i];
				}
				combined += ")";
				conditions.push_back(combined);
			}
		} else {
			proxy_error("show_status: unknown category '%s'\n", category.c_str());
			return create_error_response("Unknown category: " + category);
		}
	}

	if (!conditions.empty()) {
		sql += " WHERE ";
		for (size_t i = 0; i < conditions.size(); i++) {
			if (i > 0) sql += " AND ";
			sql += conditions[i];
		}
	}

	sql += " ORDER BY Variable_Name";

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query status: " + err);
	}

	json variables = json::array();

	if (resultset) {
		for (const auto& row : resultset->rows) {
			json var;
			var["variable_name"] = row->fields[0] ? row->fields[0] : "";
			var["value"] = row->fields[1] ? row->fields[1] : "";
			variables.push_back(var);
		}
		delete resultset;
	}

	json result;
	result["db_type"] = db_type;
	result["variables"] = variables;

	return create_success_response(result);
}

/**
 * @brief Shows all currently active sessions being processed by ProxySQL
 *
 * Reads live in-memory processlist state via `SQL3_Processlist()` and applies
 * typed filters/sort/pagination through `processlist_query_options_t`.
 *
 * This avoids stale reads from runtime-populated `stats_*_processlist` tables.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - username: Filter by username
 *   - database: Filter by schema/database
 *   - hostgroup: Filter by hostgroup ID
 *   - command: Filter by command/status text
 *   - session_id: Filter by SessionID
 *   - min_time_ms: Only show sessions running longer than N milliseconds
 *   - match_info: Optional substring filter on query/info text
 *   - info_case_sensitive: Optional case-sensitive toggle for match_info
 *   - sort_by: "time_ms" (default), "session_id", "username", "hostgroup", "command"
 *   - sort_order: "desc" (default) or "asc"
 *   - limit: Maximum number of sessions to return (default: 100)
 *   - offset: Skip first N results (default: 0)
 *
 * @return JSON response with filtered session rows and summary buckets.
 */
json Stats_Tool_Handler::handle_show_processlist(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	std::string username = arguments.value("username", "");
	std::string database = arguments.value("database", "");
	int hostgroup = arguments.value("hostgroup", -1);
	std::string command = arguments.value("command", "");
	long long session_id = arguments.value("session_id", -1LL);
	int min_time_ms = arguments.value("min_time_ms", -1);
	std::string match_info = arguments.value("match_info", "");
	bool info_case_sensitive = arguments.value("info_case_sensitive", false);
	std::string sort_by = arguments.value("sort_by", "time_ms");
	std::string sort_order = arguments.value("sort_order", "desc");
	int limit = arguments.value("limit", 100);
	int offset = arguments.value("offset", 0);

	if (limit < 0) {
		return create_error_response("limit must be >= 0");
	}
	if (offset < 0) {
		return create_error_response("offset must be >= 0");
	}
	if (hostgroup < -1) {
		return create_error_response("hostgroup must be >= -1");
	}
	if (min_time_ms < -1) {
		return create_error_response("min_time_ms must be >= -1");
	}
	if (session_id < -1) {
		return create_error_response("session_id must be >= -1");
	}
	if (session_id > static_cast<long long>(std::numeric_limits<uint32_t>::max())) {
		return create_error_response("session_id is too large");
	}

	processlist_sort_by_t sort_mode = processlist_sort_by_t::time_ms;
	if (sort_by == "session_id") {
		sort_mode = processlist_sort_by_t::session_id;
	} else if (sort_by == "username") {
		sort_mode = processlist_sort_by_t::username;
	} else if (sort_by == "hostgroup") {
		sort_mode = processlist_sort_by_t::hostgroup;
	} else if (sort_by == "command") {
		sort_mode = processlist_sort_by_t::command;
	} else if (sort_by != "time_ms") {
		return create_error_response("Invalid sort_by: " + sort_by);
	}

	bool sort_desc = true;
	if (sort_order == "asc") {
		sort_desc = false;
	} else if (sort_order != "desc") {
		return create_error_response("Invalid sort_order: " + sort_order);
	}

	if (!GloAdmin) {
		return create_error_response("ProxySQL Admin not available");
	}

	const bool is_pgsql = (db_type == "pgsql");
	if (!is_pgsql && db_type != "mysql") {
		return create_error_response("Invalid db_type: " + db_type);
	}
	if (is_pgsql && !GloPTH) {
		return create_error_response("PgSQL threads handler not available");
	}
	if (!is_pgsql && !GloMTH) {
		return create_error_response("MySQL threads handler not available");
	}

	uint32_t configured_cap = 200;
	if (mcp_handler) {
		const int configured_value = mcp_handler->variables.mcp_stats_show_processlist_max_rows;
		if (configured_value > 0) {
			configured_cap = static_cast<uint32_t>(configured_value);
		}
	}
	if (configured_cap > SHOW_PROCESSLIST_MAX_LIMIT_HARDCODED) {
		configured_cap = SHOW_PROCESSLIST_MAX_LIMIT_HARDCODED;
	}

	const uint32_t requested_limit = static_cast<uint32_t>(limit);
	const uint32_t requested_offset = static_cast<uint32_t>(offset);
	const uint32_t effective_limit = std::min(requested_limit, configured_cap);
	const uint32_t capped_offset = std::min(requested_offset, configured_cap);

	processlist_query_options_t query_opts {};
	query_opts.enabled = true;
	query_opts.username = username;
	query_opts.database = database;
	query_opts.hostgroup = hostgroup;
	query_opts.command = command;
	query_opts.min_time_ms = min_time_ms;
	query_opts.has_session_id = (session_id >= 0);
	query_opts.session_id = (session_id >= 0) ? static_cast<uint32_t>(session_id) : 0;
	query_opts.match_info = match_info;
	query_opts.info_case_sensitive = info_case_sensitive;
	query_opts.sort_by = sort_mode;
	query_opts.sort_desc = sort_desc;
	query_opts.limit = effective_limit;
	query_opts.offset = capped_offset;

	processlist_config_t base_cfg {};
#ifdef IDLE_THREADS
	base_cfg.show_idle_session = is_pgsql
		? GloPTH->get_variable_int("session_idle_show_processlist")
		: GloMTH->get_variable_int("session_idle_show_processlist");
#endif
	base_cfg.show_extended = is_pgsql
		? GloPTH->get_variable_int("show_processlist_extended")
		: GloMTH->get_variable_int("show_processlist_extended");
	base_cfg.max_query_length = is_pgsql
		? GloPTH->get_variable_int("processlist_max_query_length")
		: GloMTH->get_variable_int("processlist_max_query_length");
	base_cfg.query_options = query_opts;

	/**
	 * Compute the full matched cardinality before pagination so the MCP payload
	 * can expose deterministic metadata (`total_sessions`) regardless of page.
	 */
	processlist_config_t count_cfg = base_cfg;
	count_cfg.query_options.sort_by = processlist_sort_by_t::none;
	count_cfg.query_options.disable_pagination = true;

	SQLite3_result* count_rs = is_pgsql ? GloPTH->SQL3_Processlist(count_cfg) : GloMTH->SQL3_Processlist(count_cfg);
	if (!count_rs) {
		return create_error_response("Failed to read in-memory processlist for total count");
	}
	const int total_sessions = count_rs->rows_count;
	delete count_rs;

	SQLite3_result* resultset = is_pgsql ? GloPTH->SQL3_Processlist(base_cfg) : GloMTH->SQL3_Processlist(base_cfg);
	if (!resultset) {
		return create_error_response("Failed to read in-memory processlist rows");
	}

	auto to_int64 = [](const char* value) -> int64_t {
		if (!value || !value[0]) {
			return 0;
		}
		char* end = nullptr;
		errno = 0;
		long long parsed = strtoll(value, &end, 10);
		if (end == value || *end != '\0' || errno != 0) {
			return 0;
		}
		return static_cast<int64_t>(parsed);
	};

	json sessions = json::array();
	std::map<std::string, int> by_user, by_hostgroup, by_command;
	const int command_idx = is_pgsql ? 13 : 11;
	const int time_ms_idx = is_pgsql ? 14 : 12;
	const int info_idx = is_pgsql ? 15 : 13;

	for (const auto& row : resultset->rows) {
		json session;
		session["session_id"] = static_cast<uint64_t>(to_int64(row->fields[1]));
		session["thread_id"] = static_cast<int>(to_int64(row->fields[0]));
		session["user"] = row->fields[2] ? row->fields[2] : "";
		session["database"] = row->fields[3] ? row->fields[3] : "";
		session["client_host"] = row->fields[4] ? row->fields[4] : "";
		session["client_port"] = static_cast<int>(to_int64(row->fields[5]));
		session["hostgroup"] = static_cast<int>(to_int64(row->fields[6]));
		session["local_backend_host"] = row->fields[7] ? row->fields[7] : "";
		session["local_backend_port"] = static_cast<int>(to_int64(row->fields[8]));
		session["backend_host"] = row->fields[9] ? row->fields[9] : "";
		session["backend_port"] = static_cast<int>(to_int64(row->fields[10]));
		if (is_pgsql) {
			session["backend_pid"] = static_cast<int>(to_int64(row->fields[11]));
			session["backend_state"] = row->fields[12] ? row->fields[12] : "";
		}
		session["command"] = row->fields[command_idx] ? row->fields[command_idx] : "";
		session["time_ms"] = static_cast<int>(to_int64(row->fields[time_ms_idx]));
		session["info"] = row->fields[info_idx] ? row->fields[info_idx] : "";
		sessions.push_back(session);

		const std::string summary_user = row->fields[2] ? row->fields[2] : "unknown";
		const std::string summary_hg = row->fields[6] ? row->fields[6] : "unknown";
		const std::string summary_cmd = row->fields[command_idx] ? row->fields[command_idx] : "unknown";
		by_user[summary_user]++;
		by_hostgroup[summary_hg]++;
		by_command[summary_cmd]++;
	}
	delete resultset;

	json result;
	result["db_type"] = db_type;
	result["total_sessions"] = total_sessions;
	result["sessions"] = sessions;
	result["requested_limit"] = requested_limit;
	result["requested_offset"] = requested_offset;
	result["effective_limit"] = effective_limit;
	result["limit_cap"] = configured_cap;
	result["sort_by"] = sort_by;
	result["sort_order"] = sort_desc ? "desc" : "asc";
	result["summary"] = {
		{"by_user", by_user},
		{"by_hostgroup", by_hostgroup},
		{"by_command", by_command}
	};

	return create_success_response(result);
}

/**
 * @brief Returns aggregated query performance statistics by digest pattern
 *
 * Reads in-memory digest structures through Admin/Query Processor Top-K API.
 * This avoids stale reads from runtime-populated `stats_*_query_digest` tables
 * while preserving MCP filter and sorting semantics.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - sort_by: "count" (default), "avg_time", "sum_time", "max_time", "rows_sent"
 *   - limit: Maximum number of results (default: 100)
 *   - offset: Skip first N results (default: 0)
 *   - min_count: Only show queries executed at least N times
 *   - min_time_us: Only show queries with avg time >= N microseconds
 *   - database: Filter by database/schema name
 *   - username: Filter by username
 *   - hostgroup: Filter by hostgroup ID
 *   - digest: Filter by specific digest hash
 *   - match_digest_text: Optional digest text substring filter
 *   - digest_text_case_sensitive: Optional case-sensitive toggle for digest text filter
 *
 * @return JSON response with queries array containing performance metrics
 */
json Stats_Tool_Handler::handle_show_queries(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	std::string sort_by = arguments.value("sort_by", "count");
	int limit = arguments.value("limit", 100);
	int offset = arguments.value("offset", 0);
	int min_count = arguments.value("min_count", 0);
	int min_time_us = arguments.value("min_time_us", 0);
	std::string database = arguments.value("database", "");
	std::string username = arguments.value("username", "");
	int hostgroup = arguments.value("hostgroup", -1);
	std::string digest = arguments.value("digest", "");
	std::string match_digest_text = arguments.value("match_digest_text", "");
	bool digest_text_case_sensitive = arguments.value("digest_text_case_sensitive", false);

	if (limit < 0) {
		return create_error_response("limit must be >= 0");
	}
	if (offset < 0) {
		return create_error_response("offset must be >= 0");
	}
	if (min_count < 0) {
		return create_error_response("min_count must be >= 0");
	}
	if (min_time_us < 0) {
		return create_error_response("min_time_us must be >= 0");
	}

	query_digest_sort_by_t sort_mode = query_digest_sort_by_t::count_star;
	if (sort_by == "avg_time") {
		sort_mode = query_digest_sort_by_t::avg_time;
	} else if (sort_by == "sum_time") {
		sort_mode = query_digest_sort_by_t::sum_time;
	} else if (sort_by == "max_time") {
		sort_mode = query_digest_sort_by_t::max_time;
	} else if (sort_by == "rows_sent") {
		sort_mode = query_digest_sort_by_t::rows_sent;
	} else if (sort_by != "count") {
		return create_error_response("Invalid sort_by: " + sort_by);
	}

	query_digest_filter_opts_t filters {};
	filters.schemaname = database;
	filters.username = username;
	filters.hostgroup = hostgroup;
	filters.match_digest_text = match_digest_text;
	filters.digest_text_case_sensitive = digest_text_case_sensitive;
	filters.min_count = static_cast<uint32_t>(min_count);
	filters.min_avg_time_us = static_cast<uint64_t>(min_time_us);

	if (!digest.empty()) {
		std::string parse_err;
		uint64_t digest_value = 0;
		if (!parse_digest_filter(digest, digest_value, parse_err)) {
			proxy_error("show_queries: invalid digest filter '%s': %s\n", digest.c_str(), parse_err.c_str());
			return create_error_response("Invalid digest filter '" + digest + "': " + parse_err);
		}
		filters.has_digest = true;
		filters.digest = digest_value;
	}

	uint32_t configured_cap = 200;
	if (mcp_handler) {
		int configured_value = mcp_handler->variables.mcp_stats_show_queries_max_rows;
		if (configured_value > 0) {
			configured_cap = static_cast<uint32_t>(configured_value);
		}
	}
	if (configured_cap > SHOW_QUERIES_MAX_LIMIT_HARDCODED) {
		configured_cap = SHOW_QUERIES_MAX_LIMIT_HARDCODED;
	}

	const uint32_t requested_limit = static_cast<uint32_t>(limit);
	const uint32_t requested_offset = static_cast<uint32_t>(offset);
	const uint32_t effective_limit = std::min(requested_limit, configured_cap);
	const uint32_t capped_offset = std::min(requested_offset, configured_cap);

	if (!GloAdmin) {
		return create_error_response("ProxySQL Admin not available");
	}

	query_digest_topk_result_t topk_result {};
	if (db_type == "pgsql") {
		topk_result = GloAdmin->QueryDigestTopK<SERVER_TYPE_PGSQL>(
			filters, sort_mode, effective_limit, capped_offset, configured_cap
		);
	} else if (db_type == "mysql") {
		topk_result = GloAdmin->QueryDigestTopK<SERVER_TYPE_MYSQL>(
			filters, sort_mode, effective_limit, capped_offset, configured_cap
		);
	} else {
		return create_error_response("Invalid db_type: " + db_type);
	}

	json queries = json::array();
	for (const auto& row : topk_result.rows) {
		char digest_hex[24];
		snprintf(digest_hex, sizeof(digest_hex), "0x%016llX", static_cast<unsigned long long>(row.digest));
		const uint64_t avg_time = row.count_star > 0 ? (row.sum_time / row.count_star) : 0;

		json q;
		q["digest"] = digest_hex;
		q["digest_text"] = row.digest_text;
		q["hostgroup"] = row.hid;
		q["database"] = row.schemaname;
		q["username"] = row.username;
		q["client_address"] = row.client_address;
		q["count_star"] = row.count_star;
		q["first_seen"] = row.first_seen;
		q["last_seen"] = row.last_seen;
		q["sum_time_us"] = row.sum_time;
		q["min_time_us"] = row.min_time;
		q["max_time_us"] = row.max_time;
		q["avg_time_us"] = avg_time;
		q["sum_rows_affected"] = row.rows_affected;
		q["sum_rows_sent"] = row.rows_sent;
		queries.push_back(q);
	}

	json result;
	result["db_type"] = db_type;
	result["total_digests"] = topk_result.matched_count;
	result["queries"] = queries;
	result["summary"] = {
		{"total_queries", topk_result.matched_total_queries},
		{"total_time_us", topk_result.matched_total_time_us}
	};
	result["requested_limit"] = requested_limit;
	result["requested_offset"] = requested_offset;
	result["effective_limit"] = effective_limit;
	result["limit_cap"] = configured_cap;

	return create_success_response(result);
}

/**
 * @brief Returns command execution statistics with latency histograms
 *
 * This implementation reads command counters directly from in-memory query
 * processor snapshots (`get_stats_commands_counters()`), avoiding
 * `stats_mysql_commands_counters` / `stats_pgsql_commands_counters` table reads.
 *
 * The handler keeps the external MCP contract unchanged by reproducing the same
 * SQL semantics in C++:
 * - exact `command` filtering
 * - `total_count DESC` ordering
 * - `limit` / `offset` pagination
 * - per-row histogram/percentile projection
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - command: Filter by specific command name
 *   - limit: Maximum number of results (default: 100)
 *   - offset: Skip first N results (default: 0)
 *
 * @return JSON response with commands array containing counts and percentiles
 */
json Stats_Tool_Handler::handle_show_commands(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	std::string command = arguments.value("command", "");
	int limit = arguments.value("limit", 100);
	int offset = arguments.value("offset", 0);

	if (db_type != "mysql" && db_type != "pgsql") {
		return create_error_response("Invalid db_type: " + db_type);
	}
	if (limit < 0) {
		return create_error_response("limit must be >= 0");
	}
	if (offset < 0) {
		return create_error_response("offset must be >= 0");
	}

	SQLite3_result* resultset = NULL;
	if (db_type == "pgsql") {
		if (!GloPgQPro) {
			return create_error_response("PgSQL Query Processor not available");
		}
		resultset = GloPgQPro->get_stats_commands_counters();
	} else {
		if (!GloMyQPro) {
			return create_error_response("MySQL Query Processor not available");
		}
		resultset = GloMyQPro->get_stats_commands_counters();
	}
	if (!resultset) {
		return create_error_response("Failed to read in-memory commands counters");
	}

	std::vector<mcp_command_counter_row_t> snapshots;
	snapshots.reserve(resultset->rows.size());
	if (resultset) {
		for (const auto& row : resultset->rows) {
			if (!row) {
				continue;
			}
			const std::string row_command = row->fields[0] ? row->fields[0] : "";
			if (!command.empty() && row_command != command) {
				continue;
			}

			mcp_command_counter_row_t snapshot;
			snapshot.command = row_command;
			/**
			 * `Command_Counter::get_row()` encodes values in this order:
			 * [0]=Command, [1]=Total_Time_us, [2]=Total_Cnt, [3..14]=histogram.
			 */
			snapshot.total_time_us = parse_ll_or_zero(row->fields[1]);
			snapshot.total_count = parse_ll_or_zero(row->fields[2]);
			snapshot.latency_buckets.reserve(12);
			for (int i = 3; i <= 14; i++) {
				snapshot.latency_buckets.push_back(parse_int_or_zero(row->fields[i]));
			}
			snapshots.push_back(std::move(snapshot));
		}
		delete resultset;
	}

	std::sort(snapshots.begin(), snapshots.end(), [](const mcp_command_counter_row_t& lhs, const mcp_command_counter_row_t& rhs) {
		if (lhs.total_count != rhs.total_count) {
			return lhs.total_count > rhs.total_count;
		}
		if (lhs.total_time_us != rhs.total_time_us) {
			return lhs.total_time_us > rhs.total_time_us;
		}
		return lhs.command < rhs.command;
	});

	const size_t page_begin = std::min(static_cast<size_t>(offset), snapshots.size());
	const size_t page_end = std::min(page_begin + static_cast<size_t>(limit), snapshots.size());

	json commands = json::array();
	long long total_commands = 0;
	long long total_time = 0;

	for (size_t idx = page_begin; idx < page_end; ++idx) {
		const auto& snapshot = snapshots[idx];
		const long long avg_time = (snapshot.total_count > 0) ? (snapshot.total_time_us / snapshot.total_count) : 0;

		total_commands += snapshot.total_count;
		total_time += snapshot.total_time_us;

		const std::vector<int>& buckets = snapshot.latency_buckets;
		json cmd;
		cmd["command"] = snapshot.command;
		cmd["total_count"] = snapshot.total_count;
		cmd["total_time_us"] = snapshot.total_time_us;
		cmd["avg_time_us"] = avg_time;
		cmd["latency_histogram"] = {
			{"cnt_100us", buckets.size() > 0 ? buckets[0] : 0},
			{"cnt_500us", buckets.size() > 1 ? buckets[1] : 0},
			{"cnt_1ms", buckets.size() > 2 ? buckets[2] : 0},
			{"cnt_5ms", buckets.size() > 3 ? buckets[3] : 0},
			{"cnt_10ms", buckets.size() > 4 ? buckets[4] : 0},
			{"cnt_50ms", buckets.size() > 5 ? buckets[5] : 0},
			{"cnt_100ms", buckets.size() > 6 ? buckets[6] : 0},
			{"cnt_500ms", buckets.size() > 7 ? buckets[7] : 0},
			{"cnt_1s", buckets.size() > 8 ? buckets[8] : 0},
			{"cnt_5s", buckets.size() > 9 ? buckets[9] : 0},
			{"cnt_10s", buckets.size() > 10 ? buckets[10] : 0},
			{"cnt_INFs", buckets.size() > 11 ? buckets[11] : 0}
		};
		cmd["percentiles"] = {
			{"p50_us", calculate_percentile(buckets, LATENCY_BUCKET_THRESHOLDS, 0.50)},
			{"p90_us", calculate_percentile(buckets, LATENCY_BUCKET_THRESHOLDS, 0.90)},
			{"p95_us", calculate_percentile(buckets, LATENCY_BUCKET_THRESHOLDS, 0.95)},
			{"p99_us", calculate_percentile(buckets, LATENCY_BUCKET_THRESHOLDS, 0.99)}
		};

		commands.push_back(cmd);
	}

	json result;
	result["db_type"] = db_type;
	result["commands"] = commands;
	result["summary"] = {
		{"total_commands", total_commands},
		{"total_time_us", total_time}
	};

	return create_success_response(result);
}

/**
 * @brief Returns backend connection pool metrics
 *
 * This implementation reads connection-pool snapshots directly from hostgroup
 * managers (`SQL3_Connection_Pool()`), avoiding
 * `stats_mysql_connection_pool` / `stats_pgsql_connection_pool` table reads.
 *
 * The MCP output contract is preserved:
 * - same response fields and summary object
 * - same filter semantics (`hostgroup`, `server`, `status`)
 * - same server ordering (`hostgroup`, `srv_host`, `srv_port`)
 *
 * Free-connection row details were intentionally removed from this tool to keep
 * it focused on operational metrics. Callers needing debug-level free-pool
 * visibility must use `show_free_connections` instead.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - hostgroup: Filter by hostgroup ID
 *   - server: Filter by server address (format: "host:port")
 *   - status: Filter by server status (ONLINE, SHUNNED, etc.)
 *
 * @return JSON response with connection-pool server rows and summary
 */
json Stats_Tool_Handler::handle_show_connections(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	int hostgroup = arguments.value("hostgroup", -1);
	std::string server = arguments.value("server", "");
	std::string status = arguments.value("status", "");
	const bool detail_requested = arguments.value("detail", false);

	if (detail_requested) {
		return create_error_response(
			"Parameter 'detail' was removed from show_connections. "
			"Use show_free_connections and enable mcp-stats_enable_debug_tools=true."
		);
	}

	if (db_type != "mysql" && db_type != "pgsql") {
		return create_error_response("Invalid db_type: " + db_type);
	}
	const bool is_mysql = (db_type == "mysql");

	std::string server_host;
	int server_port = 0;
	bool has_server_filter = false;
	if (!server.empty()) {
		std::string parse_err;
		if (!parse_server_filter(server, server_host, server_port, parse_err)) {
			proxy_error("show_connections: invalid server filter '%s': %s\n", server.c_str(), parse_err.c_str());
			return create_error_response("Invalid server filter '" + server + "': " + parse_err);
		}
		has_server_filter = true;
	}

	SQLite3_result* resultset = NULL;
	if (is_mysql) {
		if (!MyHGM) {
			return create_error_response("MySQL HostGroups Manager not available");
		}
		resultset = MyHGM->SQL3_Connection_Pool(false, NULL);
	} else {
		if (!PgHGM) {
			return create_error_response("PgSQL HostGroups Manager not available");
		}
		resultset = PgHGM->SQL3_Connection_Pool(false, NULL);
	}
	if (!resultset) {
		return create_error_response("Failed to read in-memory connection pool");
	}

	std::vector<mcp_connection_pool_row_t> snapshots;
	snapshots.reserve(resultset->rows.size());

	for (const auto& row : resultset->rows) {
		if (!row) {
			continue;
		}

		mcp_connection_pool_row_t snapshot {};
		snapshot.hostgroup = parse_int_or_zero(row->fields[0]);
		snapshot.srv_host = row->fields[1] ? row->fields[1] : "";
		snapshot.srv_port = parse_int_or_zero(row->fields[2]);
		snapshot.status = row->fields[3] ? row->fields[3] : "";
		snapshot.conn_used = parse_int_or_zero(row->fields[4]);
		snapshot.conn_free = parse_int_or_zero(row->fields[5]);
		snapshot.conn_ok = parse_ll_or_zero(row->fields[6]);
		snapshot.conn_err = parse_ll_or_zero(row->fields[7]);
		snapshot.max_conn_used = parse_int_or_zero(row->fields[8]);
		snapshot.queries = parse_ll_or_zero(row->fields[9]);
		if (is_mysql) {
			snapshot.queries_gtid_sync = parse_ll_or_zero(row->fields[10]);
			snapshot.bytes_data_sent = parse_ll_or_zero(row->fields[11]);
			snapshot.bytes_data_recv = parse_ll_or_zero(row->fields[12]);
			snapshot.latency_us = parse_int_or_zero(row->fields[13]);
		} else {
			snapshot.queries_gtid_sync = 0;
			snapshot.bytes_data_sent = parse_ll_or_zero(row->fields[10]);
			snapshot.bytes_data_recv = parse_ll_or_zero(row->fields[11]);
			snapshot.latency_us = parse_int_or_zero(row->fields[12]);
		}

		if (hostgroup >= 0 && snapshot.hostgroup != hostgroup) {
			continue;
		}
		if (has_server_filter &&
			(snapshot.srv_host != server_host || snapshot.srv_port != server_port)) {
			continue;
		}
		if (!status.empty() && snapshot.status != status) {
			continue;
		}
		snapshots.push_back(std::move(snapshot));
	}
	delete resultset;

	std::sort(snapshots.begin(), snapshots.end(), [](const mcp_connection_pool_row_t& lhs, const mcp_connection_pool_row_t& rhs) {
		if (lhs.hostgroup != rhs.hostgroup) {
			return lhs.hostgroup < rhs.hostgroup;
		}
		if (lhs.srv_host != rhs.srv_host) {
			return lhs.srv_host < rhs.srv_host;
		}
		return lhs.srv_port < rhs.srv_port;
	});

	json servers = json::array();
	int total_servers = 0, online_servers = 0;
	long long total_used = 0, total_free = 0, total_queries = 0;
	std::map<std::string, int> by_status;

	for (const auto& snapshot : snapshots) {
		double utilization = (snapshot.conn_used + snapshot.conn_free > 0) ?
			(double)snapshot.conn_used / (double)(snapshot.conn_used + snapshot.conn_free) * 100.0 : 0.0;
		double error_rate = (snapshot.conn_ok + snapshot.conn_err > 0) ?
			(double)snapshot.conn_err / (double)(snapshot.conn_ok + snapshot.conn_err) : 0.0;

		json srv;
		srv["hostgroup"] = snapshot.hostgroup;
		srv["srv_host"] = snapshot.srv_host;
		srv["srv_port"] = snapshot.srv_port;
		srv["status"] = snapshot.status;
		srv["conn_used"] = snapshot.conn_used;
		srv["conn_free"] = snapshot.conn_free;
		srv["conn_ok"] = snapshot.conn_ok;
		srv["conn_err"] = snapshot.conn_err;
		srv["max_conn_used"] = snapshot.max_conn_used;
		srv["queries"] = snapshot.queries;
		if (is_mysql) {
			srv["queries_gtid_sync"] = snapshot.queries_gtid_sync;
		}
		srv["bytes_data_sent"] = snapshot.bytes_data_sent;
		srv["bytes_data_recv"] = snapshot.bytes_data_recv;
		srv["latency_us"] = snapshot.latency_us;
		srv["utilization_pct"] = utilization;
		srv["error_rate"] = error_rate;
		servers.push_back(srv);

		total_servers++;
		if (snapshot.status == "ONLINE") online_servers++;
		total_used += snapshot.conn_used;
		total_free += snapshot.conn_free;
		total_queries += snapshot.queries;
		by_status[snapshot.status]++;
	}

	json result;
	result["db_type"] = db_type;
	result["servers"] = servers;
	result["summary"] = {
		{"total_servers", total_servers},
		{"online_servers", online_servers},
		{"total_conn_used", total_used},
		{"total_conn_free", total_free},
		{"total_queries", total_queries},
		{"overall_utilization_pct", (total_used + total_free > 0) ?
			(double)total_used / (double)(total_used + total_free) * 100.0 : 0.0},
		{"by_status", by_status}
	};

	return create_success_response(result);
}

/**
 * @brief Returns debug free-connection snapshots for backend connection pools.
 *
 * This tool intentionally exposes low-level free-connection details that are
 * useful primarily during debugging and development. To avoid surfacing this
 * heavier diagnostic payload in normal operational workflows, it is gated by
 * MCP runtime variable `mcp-stats_enable_debug_tools`.
 *
 * The data source is fully in-memory:
 * - MySQL: `MyHGM->SQL3_Free_Connections()`
 * - PgSQL: `PgHGM->SQL3_Free_Connections()`
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - hostgroup: Filter by hostgroup ID
 *   - server: Filter by server address (format: "host:port")
 *
 * @return JSON response with `free_connections` rows and summary counters.
 */
json Stats_Tool_Handler::handle_show_free_connections(const json& arguments) {
	if (!mcp_handler || !mcp_handler->variables.mcp_stats_enable_debug_tools) {
		return create_error_response(
			"show_free_connections is disabled. "
			"Set mcp-stats_enable_debug_tools=true and LOAD MCP VARIABLES TO RUNTIME."
		);
	}

	std::string db_type = arguments.value("db_type", "mysql");
	const int hostgroup = arguments.value("hostgroup", -1);
	const std::string server = arguments.value("server", "");

	if (db_type != "mysql" && db_type != "pgsql") {
		return create_error_response("Invalid db_type: " + db_type);
	}
	const bool is_mysql = (db_type == "mysql");

	std::string server_host;
	int server_port = 0;
	bool has_server_filter = false;
	if (!server.empty()) {
		std::string parse_err;
		if (!parse_server_filter(server, server_host, server_port, parse_err)) {
			proxy_error("show_free_connections: invalid server filter '%s': %s\n", server.c_str(), parse_err.c_str());
			return create_error_response("Invalid server filter '" + server + "': " + parse_err);
		}
		has_server_filter = true;
	}

	SQLite3_result* free_rs = NULL;
	if (is_mysql) {
		if (!MyHGM) {
			return create_error_response("MySQL HostGroups Manager not available");
		}
		free_rs = MyHGM->SQL3_Free_Connections();
	} else {
		if (!PgHGM) {
			return create_error_response("PgSQL HostGroups Manager not available");
		}
		free_rs = PgHGM->SQL3_Free_Connections();
	}
	if (!free_rs) {
		return create_error_response("Failed to read in-memory free connection pool");
	}

	json free_connections = json::array();
	std::map<std::string, int> by_hostgroup;

	for (const auto& row : free_rs->rows) {
		if (!row) {
			continue;
		}

		const int row_hostgroup = parse_int_or_zero(row->fields[1]);
		const std::string row_host = row->fields[2] ? row->fields[2] : "";
		const int row_port = parse_int_or_zero(row->fields[3]);

		if (hostgroup >= 0 && row_hostgroup != hostgroup) {
			continue;
		}
		if (has_server_filter && (row_host != server_host || row_port != server_port)) {
			continue;
		}

		json fc;
		fc["fd"] = parse_int_or_zero(row->fields[0]);
		fc["hostgroup"] = row_hostgroup;
		fc["srv_host"] = row_host;
		fc["srv_port"] = row_port;
		fc["user"] = row->fields[4] ? row->fields[4] : "";
		if (is_mysql) {
			fc["schema"] = row->fields[5] ? row->fields[5] : "";
			fc["init_connect"] = row->fields[6] ? row->fields[6] : "";
			fc["time_zone"] = row->fields[7] ? row->fields[7] : "";
			fc["sql_mode"] = row->fields[8] ? row->fields[8] : "";
			fc["autocommit"] = row->fields[9] ? row->fields[9] : "";
			fc["idle_ms"] = parse_int_or_zero(row->fields[10]);
			fc["statistics"] = row->fields[11] ? row->fields[11] : "";
			fc["mysql_info"] = row->fields[12] ? row->fields[12] : "";
		} else {
			fc["database"] = row->fields[5] ? row->fields[5] : "";
			fc["init_connect"] = row->fields[6] ? row->fields[6] : "";
			fc["time_zone"] = row->fields[7] ? row->fields[7] : "";
			fc["sql_mode"] = row->fields[8] ? row->fields[8] : "";
			fc["idle_ms"] = parse_int_or_zero(row->fields[9]);
			fc["statistics"] = row->fields[10] ? row->fields[10] : "";
			fc["pgsql_info"] = row->fields[11] ? row->fields[11] : "";
		}

		free_connections.push_back(fc);
		by_hostgroup[std::to_string(row_hostgroup)]++;
	}
	delete free_rs;

	json result;
	result["db_type"] = db_type;
	result["free_connections"] = free_connections;
	result["summary"] = {
		{"total_free_connections", static_cast<int>(free_connections.size())},
		{"by_hostgroup", by_hostgroup}
	};
	return create_success_response(result);
}

/**
 * @brief Returns error tracking statistics
 *
 * Queries error statistics from stats_mysql_errors or stats_pgsql_errors.
 * Shows error counts, frequency, and last occurrence per error type/server.
 * MySQL uses errno, PostgreSQL uses sqlstate for error identification.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - errno: Filter by error number (MySQL)
 *   - sqlstate: Filter by SQL state (PostgreSQL)
 *   - username: Filter by username
 *   - database: Filter by database name
 *   - hostgroup: Filter by hostgroup ID
 *   - min_count: Only show errors with count >= N
 *   - sort_by: "count" (default), "last_seen", "frequency"
 *   - limit: Maximum number of results (default: 100)
 *   - offset: Skip first N results (default: 0)
 *
 * @return JSON response with errors array and summary statistics
 */
json Stats_Tool_Handler::handle_show_errors(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	int errno_filter = arguments.value("errno", -1);
	std::string sqlstate_filter = arguments.value("sqlstate", "");
	std::string username = arguments.value("username", "");
	std::string database = arguments.value("database", "");
	int hostgroup = arguments.value("hostgroup", -1);
	int min_count = arguments.value("min_count", 0);
	std::string sort_by = arguments.value("sort_by", "count");
	int limit = arguments.value("limit", 100);
	int offset = arguments.value("offset", 0);

	std::string table = (db_type == "pgsql") ? "stats_pgsql_errors" : "stats_mysql_errors";
	std::string schema_col = (db_type == "pgsql") ? "database" : "schemaname";
	std::string errno_col = (db_type == "pgsql") ? "sqlstate" : "errno";

	std::string sql = "SELECT hostgroup, hostname, port, username, client_address, "
		+ schema_col + ", " + errno_col + ", count_star, first_seen, last_seen, last_error "
		"FROM stats." + table + " WHERE 1=1";

	if (min_count > 0) {
		sql += " AND count_star >= " + std::to_string(min_count);
	}
	if (db_type == "pgsql" && !sqlstate_filter.empty()) {
		sql += " AND sqlstate = '" + sql_escape(sqlstate_filter) + "'";
	} else if (db_type == "mysql" && errno_filter >= 0) {
		sql += " AND errno = " + std::to_string(errno_filter);
	}
	if (!username.empty()) {
		sql += " AND username = '" + sql_escape(username) + "'";
	}
	if (!database.empty()) {
		sql += " AND " + schema_col + " = '" + sql_escape(database) + "'";
	}
	if (hostgroup >= 0) {
		sql += " AND hostgroup = " + std::to_string(hostgroup);
	}

	// Sort
	std::string order_col = "count_star";
	if (sort_by == "first_seen") order_col = "first_seen";
	else if (sort_by == "last_seen") order_col = "last_seen";
	sql += " ORDER BY " + order_col + " DESC LIMIT " + std::to_string(limit) + " OFFSET " + std::to_string(offset);

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query errors: " + err);
	}

	// Get total counts
	std::string count_sql = "SELECT COUNT(*), SUM(count_star) FROM stats." + table;
	SQLite3_result* count_rs = NULL;
	int count_cols = 0;
	int total_error_types = 0;
	long long total_error_count = 0;
	std::string count_err = execute_admin_query(count_sql.c_str(), &count_rs, &count_cols, false);
	if (!count_err.empty()) {
		if (count_rs) {
			delete count_rs;
		}
		proxy_error("show_errors: failed to count rows: %s\n", count_err.c_str());
		return create_error_response("Failed to count error rows: " + count_err);
	}
	if (count_rs && count_rs->rows_count > 0) {
		total_error_types = parse_int_or_zero(count_rs->rows[0]->fields[0]);
		total_error_count = parse_ll_or_zero(count_rs->rows[0]->fields[1]);
	}
	if (count_rs) delete count_rs;

	json errors = json::array();
	std::map<std::string, long long> by_errno, by_hostgroup;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long count = parse_ll_or_zero(row->fields[7]);
			long long first_seen = parse_ll_or_zero(row->fields[8]);
			long long last_seen = parse_ll_or_zero(row->fields[9]);

			// Calculate frequency (errors per hour)
			double hours = (last_seen > first_seen) ? (double)(last_seen - first_seen) / 3600.0 : 1.0;
			double freq_per_hour = count / hours;

			json error;
			error["hostgroup"] = parse_int_or_zero(row->fields[0]);
			error["hostname"] = row->fields[1] ? row->fields[1] : "";
			error["port"] = parse_int_or_zero(row->fields[2]);
			error["username"] = row->fields[3] ? row->fields[3] : "";
			error["client_address"] = row->fields[4] ? row->fields[4] : "";
			error["database"] = row->fields[5] ? row->fields[5] : "";
			if (db_type == "pgsql") {
				error["sqlstate"] = row->fields[6] ? row->fields[6] : "";
			} else {
				error["errno"] = parse_int_or_zero(row->fields[6]);
			}
			error["count_star"] = count;
			error["first_seen"] = first_seen;
			error["last_seen"] = last_seen;
			error["last_error"] = row->fields[10] ? row->fields[10] : "";
			error["frequency_per_hour"] = freq_per_hour;

			errors.push_back(error);

			// Aggregations
			std::string en = row->fields[6] ? row->fields[6] : "unknown";
			std::string hg = row->fields[0] ? row->fields[0] : "unknown";
			by_errno[en] += count;
			by_hostgroup[hg] += count;
		}
		delete resultset;
	}

	json result;
	result["db_type"] = db_type;
	result["total_error_types"] = total_error_types;
	result["total_error_count"] = total_error_count;
	result["errors"] = errors;

	json summary;
	if (db_type == "pgsql") {
		summary["by_sqlstate"] = by_errno;
	} else {
		summary["by_errno"] = by_errno;
	}
	summary["by_hostgroup"] = by_hostgroup;
	result["summary"] = summary;

	return create_success_response(result);
}

/**
 * @brief Returns connection statistics per frontend user.
 *
 * This implementation reads user counters directly from authentication runtime
 * state instead of querying `stats_mysql_users` / `stats_pgsql_users`.
 *
 * Data sources:
 * - MySQL: `GloMyAuth->dump_all_users(..., false)` (+ LDAP users when enabled)
 * - PgSQL: `GloPgAuth->dump_all_users(..., false)`
 *
 * Only non-admin/non-stats accounts are returned (`default_hostgroup >= 0`),
 * matching Admin stats population semantics.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - username: Filter by specific username
 *   - limit: Maximum number of results (default: 100, max: 1000)
 *   - offset: Skip first N results (default: 0)
 *
 * @return JSON response with `users` array and aggregate summary.
 */
json Stats_Tool_Handler::handle_show_users(const json& arguments) {
	const std::string db_type = arguments.value("db_type", "mysql");
	const std::string username_filter = arguments.value("username", "");
	int limit = arguments.value("limit", 100);
	int offset = arguments.value("offset", 0);

	if (db_type != "mysql" && db_type != "pgsql") {
		return create_error_response("Invalid db_type: " + db_type);
	}

	/**
	 * Keep behavior deterministic and bounded when callers pass invalid or
	 * oversized pagination parameters.
	 */
	if (limit <= 0) limit = 100;
	if (limit > 1000) limit = 1000;
	if (offset < 0) offset = 0;

	std::vector<mcp_frontend_user_row_t> snapshots;

	if (db_type == "mysql") {
		if (!GloMyAuth) {
			return create_error_response("MySQL Authentication module not available");
		}

		account_details_t** ads = NULL;
		const int num_users = GloMyAuth->dump_all_users(&ads, false);

		for (int i = 0; i < num_users; ++i) {
			account_details_t* ad = ads[i];
			if (ad) {
				/**
				 * Match `stats___mysql_users()` semantics: expose only frontend-like
				 * users (exclude admin/stats internal accounts).
				 */
				if (ad->default_hostgroup >= 0) {
					const std::string row_username = ad->username ? ad->username : "";
					if (username_filter.empty() || row_username == username_filter) {
						mcp_frontend_user_row_t row {};
						row.username = row_username;
						row.frontend_connections = ad->num_connections_used;
						row.frontend_max_connections = ad->max_connections;
						snapshots.push_back(std::move(row));
					}
				}
				free(ad->username);
				free(ad);
			}
		}
		free(ads);

		/**
		 * Keep parity with `stats___mysql_users()` by including LDAP frontend
		 * users when the LDAP authentication module is loaded.
		 */
		if (GloMyLdapAuth) {
			std::unique_ptr<SQLite3_result> ldap_users { GloMyLdapAuth->dump_all_users() };
			if (ldap_users) {
				for (const SQLite3_row* ldap_row : ldap_users->rows) {
					if (!ldap_row) {
						continue;
					}
					const std::string ldap_username = ldap_row->fields[LDAP_USER_FIELD_IDX::USERNAME]
						? ldap_row->fields[LDAP_USER_FIELD_IDX::USERNAME] : "";
					if (!username_filter.empty() && ldap_username != username_filter) {
						continue;
					}

					mcp_frontend_user_row_t row {};
					row.username = ldap_username;
					row.frontend_connections = parse_int_or_zero(ldap_row->fields[LDAP_USER_FIELD_IDX::FRONTEND_CONNECTIONS]);
					row.frontend_max_connections = parse_int_or_zero(ldap_row->fields[LDAP_USER_FIELD_IDX::FRONTED_MAX_CONNECTIONS]);
					snapshots.push_back(std::move(row));
				}
			}
		}
	} else {
		if (!GloPgAuth) {
			return create_error_response("PgSQL Authentication module not available");
		}

		pgsql_account_details_t** ads = NULL;
		const int num_users = GloPgAuth->dump_all_users(&ads, false);

		for (int i = 0; i < num_users; ++i) {
			pgsql_account_details_t* ad = ads[i];
			if (ad) {
				/**
				 * Match `stats___pgsql_users()` semantics: expose only frontend-like
				 * users (exclude admin/stats internal accounts).
				 */
				if (ad->default_hostgroup >= 0) {
					const std::string row_username = ad->username ? ad->username : "";
					if (username_filter.empty() || row_username == username_filter) {
						mcp_frontend_user_row_t row {};
						row.username = row_username;
						row.frontend_connections = ad->num_connections_used;
						row.frontend_max_connections = ad->max_connections;
						snapshots.push_back(std::move(row));
					}
				}
				free(ad->username);
				free(ad);
			}
		}
		free(ads);
	}

	std::sort(snapshots.begin(), snapshots.end(), [](
		const mcp_frontend_user_row_t& lhs, const mcp_frontend_user_row_t& rhs) {
		if (lhs.frontend_connections != rhs.frontend_connections) {
			return lhs.frontend_connections > rhs.frontend_connections;
		}
		return lhs.username < rhs.username;
	});

	const size_t page_begin = std::min(static_cast<size_t>(offset), snapshots.size());
	const size_t page_end = std::min(page_begin + static_cast<size_t>(limit), snapshots.size());

	json users = json::array();
	int total_users = 0;
	long long total_connections = 0;
	long long total_capacity = 0;

	for (size_t idx = page_begin; idx < page_end; ++idx) {
		const mcp_frontend_user_row_t& snapshot = snapshots[idx];
		const int connections = snapshot.frontend_connections;
		const int max_connections = snapshot.frontend_max_connections;
		const double utilization = (max_connections > 0)
			? static_cast<double>(connections) / static_cast<double>(max_connections) * 100.0
			: 0.0;

		std::string status = "normal";
		if (max_connections > 0 && connections >= max_connections) {
			status = "at_limit";
		} else if (max_connections > 0 && utilization >= 80.0) {
			status = "near_limit";
		}

		json user;
		user["username"] = snapshot.username;
		user["frontend_connections"] = connections;
		user["frontend_max_connections"] = max_connections;
		user["utilization_pct"] = utilization;
		user["status"] = status;
		users.push_back(user);

		total_users++;
		total_connections += connections;
		total_capacity += max_connections;
	}

	json result;
	result["db_type"] = db_type;
	result["users"] = users;
	result["summary"] = {
		{"total_users", total_users},
		{"total_connections", total_connections},
		{"total_capacity", total_capacity},
		{"overall_utilization_pct", (total_capacity > 0)
			? static_cast<double>(total_connections) / static_cast<double>(total_capacity) * 100.0
			: 0.0}
	};

	return create_success_response(result);
}

/**
 * @brief Returns client host error cache
 *
 * Queries stats_mysql_client_host_cache or stats_pgsql_client_host_cache
 * for client host error tracking data used for connection throttling.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - client_address: Filter by client IP address
 *   - min_error_count: Only show hosts with error_count >= N
 *   - limit: Maximum number of results (default: 100)
 *   - offset: Skip first N results (default: 0)
 *
 * @return JSON response with clients array containing error cache data
 */
json Stats_Tool_Handler::handle_show_client_cache(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	std::string client_address = arguments.value("client_address", "");
	int min_error_count = arguments.value("min_error_count", 0);
	int limit = arguments.value("limit", 100);
	int offset = arguments.value("offset", 0);

	std::string table = (db_type == "pgsql") ? "stats_pgsql_client_host_cache" : "stats_mysql_client_host_cache";

	std::string sql = "SELECT client_address, error_count, last_updated "
		"FROM stats." + table + " WHERE 1=1";

	if (!client_address.empty()) {
		sql += " AND client_address = '" + sql_escape(client_address) + "'";
	}
	if (min_error_count > 0) {
		sql += " AND error_count >= " + std::to_string(min_error_count);
	}

	sql += " ORDER BY error_count DESC LIMIT " + std::to_string(limit) + " OFFSET " + std::to_string(offset);

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query client host cache: " + err);
	}

	json hosts = json::array();
	int total_hosts = 0;
	long long total_errors = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			int error_count = parse_int_or_zero(row->fields[1]);

			json host;
			host["client_address"] = row->fields[0] ? row->fields[0] : "";
			host["error_count"] = error_count;
			host["last_updated"] = parse_ll_or_zero(row->fields[2]);

			hosts.push_back(host);
			total_hosts++;
			total_errors += error_count;
		}
		delete resultset;
	}

	json result;
	result["db_type"] = db_type;
	result["hosts"] = hosts;
	result["summary"] = {
		{"total_hosts", total_hosts},
		{"total_errors", total_errors}
	};

	return create_success_response(result);
}

/**
 * @brief Returns query rule hit statistics
 *
 * Queries stats_mysql_query_rules or stats_pgsql_query_rules for
 * hit counts per query rule, useful for analyzing rule effectiveness.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - rule_id: Filter by specific rule ID
 *   - min_hits: Only show rules with hits >= N
 *   - include_zero_hits: Include rules with zero hits (default: false)
 *   - limit: Maximum number of results (default: 100)
 *   - offset: Skip first N results (default: 0)
 *
 * @return JSON response with rules array containing rule_id and hits
 */
json Stats_Tool_Handler::handle_show_query_rules(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	int rule_id = arguments.value("rule_id", -1);
	int min_hits = arguments.value("min_hits", 0);
	bool include_zero_hits = arguments.value("include_zero_hits", false);
	int limit = arguments.value("limit", 100);
	int offset = arguments.value("offset", 0);

	std::string table = (db_type == "pgsql") ? "stats_pgsql_query_rules" : "stats_mysql_query_rules";

	std::string sql = "SELECT rule_id, hits FROM stats." + table + " WHERE 1=1";

	if (rule_id >= 0) {
		sql += " AND rule_id = " + std::to_string(rule_id);
	}
	if (!include_zero_hits) {
		sql += " AND hits > 0";
	}
	if (min_hits > 0) {
		sql += " AND hits >= " + std::to_string(min_hits);
	}

	sql += " ORDER BY hits DESC LIMIT " + std::to_string(limit) + " OFFSET " + std::to_string(offset);

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query query rules: " + err);
	}

	// Get total count
	std::string count_sql = "SELECT COUNT(*) FROM stats." + table;
	SQLite3_result* count_rs = NULL;
	int count_cols = 0;
	int total_rules = 0;
	std::string count_err = execute_admin_query(count_sql.c_str(), &count_rs, &count_cols, false);
	if (!count_err.empty()) {
		if (count_rs) {
			delete count_rs;
		}
		proxy_error("show_query_rules: failed to count rows: %s\n", count_err.c_str());
		return create_error_response("Failed to count query rule rows: " + count_err);
	}
	if (count_rs && count_rs->rows_count > 0 && count_rs->rows[0]->fields[0]) {
		total_rules = parse_int_or_zero(count_rs->rows[0]->fields[0]);
	}
	if (count_rs) delete count_rs;

	json rules = json::array();
	long long total_hits = 0;
	int rules_with_hits = 0;
	int rules_without_hits = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long hits = parse_ll_or_zero(row->fields[1]);
			total_hits += hits;
			if (hits > 0) rules_with_hits++;
			else rules_without_hits++;

			json rule;
			rule["rule_id"] = parse_int_or_zero(row->fields[0]);
			rule["hits"] = hits;

			rules.push_back(rule);
		}
		delete resultset;
	}

	json result;
	result["db_type"] = db_type;
	result["total_rules"] = total_rules;
	result["rules"] = rules;
	result["summary"] = {
		{"total_hits", total_hits},
		{"rules_with_hits", rules_with_hits},
		{"rules_without_hits", rules_without_hits}
	};

	return create_success_response(result);
}

/**
 * @brief Returns prepared statement information
 *
 * Queries stats_mysql_prepared_statements_info or stats_pgsql_prepared_statements_info
 * for active prepared statement details including digest, reference counts, and query text.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" (default) or "pgsql"
 *   - username: Filter by username
 *   - database: Filter by database name
 *
 * @return JSON response with statements array containing prepared statement details
 */
json Stats_Tool_Handler::handle_show_prepared_statements(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	std::string username = arguments.value("username", "");
	std::string database = arguments.value("database", "");

	std::string table = (db_type == "pgsql") ? "stats_pgsql_prepared_statements_info" : "stats_mysql_prepared_statements_info";
	std::string schema_col = (db_type == "pgsql") ? "database" : "schemaname";

	std::string sql;
	if (db_type == "pgsql") {
		sql = "SELECT global_stmt_id, " + schema_col + ", username, digest, "
			"ref_count_client, ref_count_server, num_param_types, query "
			"FROM stats." + table;
	} else {
		sql = "SELECT global_stmt_id, " + schema_col + ", username, digest, "
			"ref_count_client, ref_count_server, num_columns, num_params, query "
			"FROM stats." + table;
	}

	std::vector<std::string> conditions;
	if (!username.empty()) {
		conditions.push_back("username = '" + sql_escape(username) + "'");
	}
	if (!database.empty()) {
		conditions.push_back(schema_col + " = '" + sql_escape(database) + "'");
	}

	if (!conditions.empty()) {
		sql += " WHERE ";
		for (size_t i = 0; i < conditions.size(); i++) {
			if (i > 0) sql += " AND ";
			sql += conditions[i];
		}
	}

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query prepared statements: " + err);
	}

	json statements = json::array();
	int total_statements = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			json stmt;
			stmt["global_stmt_id"] = parse_int_or_zero(row->fields[0]);
			stmt["database"] = row->fields[1] ? row->fields[1] : "";
			stmt["username"] = row->fields[2] ? row->fields[2] : "";
			stmt["digest"] = row->fields[3] ? row->fields[3] : "";
			stmt["ref_count_client"] = parse_int_or_zero(row->fields[4]);
			stmt["ref_count_server"] = parse_int_or_zero(row->fields[5]);
			if (db_type == "pgsql") {
				stmt["num_param_types"] = parse_int_or_zero(row->fields[6]);
				stmt["query"] = row->fields[7] ? row->fields[7] : "";
			} else {
				stmt["num_columns"] = parse_int_or_zero(row->fields[6]);
				stmt["num_params"] = parse_int_or_zero(row->fields[7]);
				stmt["query"] = row->fields[8] ? row->fields[8] : "";
			}

			statements.push_back(stmt);
			total_statements++;
		}
		delete resultset;
	}

	json result;
	result["db_type"] = db_type;
	result["total_statements"] = total_statements;
	result["statements"] = statements;

	return create_success_response(result);
}

/**
 * @brief Returns GTID replication information (MySQL only)
 *
 * Queries stats_mysql_gtid_executed for GTID tracking data per backend server.
 * This tool is MySQL-specific; PostgreSQL does not support GTID.
 *
 * @param arguments JSON object with optional parameters:
 *   - hostname: Filter by backend hostname
 *   - port: Filter by backend port
 *
 * @return JSON response with servers array containing GTID execution data
 */
json Stats_Tool_Handler::handle_show_gtid(const json& arguments) {
	std::string hostname = arguments.value("hostname", "");
	int port = arguments.value("port", -1);

	std::string sql = "SELECT hostname, port, gtid_executed, events "
		"FROM stats.stats_mysql_gtid_executed WHERE 1=1";

	if (!hostname.empty()) {
		sql += " AND hostname = '" + sql_escape(hostname) + "'";
	}
	if (port > 0) {
		sql += " AND port = " + std::to_string(port);
	}

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query GTID: " + err);
	}

	json servers = json::array();
	long long total_events = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long events = parse_ll_or_zero(row->fields[3]);
			total_events += events;

			json srv;
			srv["hostname"] = row->fields[0] ? row->fields[0] : "";
			srv["port"] = parse_int_or_zero(row->fields[1]);
			srv["gtid_executed"] = row->fields[2] ? row->fields[2] : "";
			srv["events"] = events;

			servers.push_back(srv);
		}
		delete resultset;
	}

	json result;
	result["servers"] = servers;
	result["summary"] = {
		{"total_servers", (int)servers.size()},
		{"total_events", total_events}
	};

	return create_success_response(result);
}

/**
 * @brief Returns ProxySQL cluster node health and sync status
 *
 * Queries multiple cluster-related tables for node status, sync metrics,
 * and configuration checksums. Useful for monitoring cluster health.
 *
 * @param arguments JSON object with optional parameters:
 *   - hostname: Filter by specific cluster node hostname
 *   - include_checksums: Include configuration checksums (default: true)
 *
 * @return JSON response with nodes array, metrics, and optional checksums
 */
json Stats_Tool_Handler::handle_show_cluster(const json& arguments) {
	std::string hostname_filter = arguments.value("hostname", "");
	bool include_checksums = arguments.value("include_checksums", true);

	// 1. Get cluster node status
	std::string sql = "SELECT hostname, port, weight, master, global_version, "
		"check_age_us, ping_time_us, checks_OK, checks_ERR "
		"FROM stats.stats_proxysql_servers_status";

	if (!hostname_filter.empty()) {
		sql += " WHERE hostname = '" + sql_escape(hostname_filter) + "'";
	}

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query cluster status: " + err);
	}

	json nodes = json::array();
	int total_nodes = 0, online_nodes = 0;
	std::string master_node = "";
	long long total_ping = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long checks_ok = parse_ll_or_zero(row->fields[7]);
			long long checks_err = parse_ll_or_zero(row->fields[8]);
			double success_rate = (checks_ok + checks_err > 0) ?
				(double)checks_ok / (double)(checks_ok + checks_err) : 0.0;

			bool is_master = row->fields[3] && std::string(row->fields[3]) == "TRUE";
			long long ping = parse_ll_or_zero(row->fields[6]);

			json node;
			node["hostname"] = row->fields[0] ? row->fields[0] : "";
			node["port"] = parse_int_or_zero(row->fields[1]);
			node["weight"] = parse_int_or_zero(row->fields[2]);
			node["master"] = is_master;
			node["global_version"] = parse_int_or_zero(row->fields[4]);
			node["check_age_us"] = parse_ll_or_zero(row->fields[5]);
			node["ping_time_us"] = ping;
			node["checks_ok"] = checks_ok;
			node["checks_err"] = checks_err;
			node["check_success_rate"] = success_rate;

			if (is_master) {
				master_node = std::string(row->fields[0] ? row->fields[0] : "") + ":" +
					std::string(row->fields[1] ? row->fields[1] : "");
			}

			nodes.push_back(node);
			total_nodes++;
			if (success_rate > 0.5) online_nodes++;
			total_ping += ping;
		}
		delete resultset;
	}

	// 2. Get metrics from stats_proxysql_servers_metrics
	std::string metrics_sql = "SELECT hostname, port, Uptime_s, Queries, Client_Connections_connected "
		"FROM stats.stats_proxysql_servers_metrics";
	if (!hostname_filter.empty()) {
		metrics_sql += " WHERE hostname = '" + sql_escape(hostname_filter) + "'";
	}

	SQLite3_result* metrics_rs = NULL;
	int mcols = 0;
	long long total_queries = 0;
	long long total_client_connections = 0;
	std::string metrics_err = execute_admin_query(metrics_sql.c_str(), &metrics_rs, &mcols);
	if (!metrics_err.empty()) {
		if (metrics_rs) {
			delete metrics_rs;
		}
		proxy_error("show_cluster: failed to query metrics: %s\n", metrics_err.c_str());
		return create_error_response("Failed to query cluster metrics: " + metrics_err);
	}

	if (metrics_rs) {
		for (const auto& mrow : metrics_rs->rows) {
			std::string host = mrow->fields[0] ? mrow->fields[0] : "";
			int port = parse_int_or_zero(mrow->fields[1]);

			// Find matching node and add metrics
			for (auto& node : nodes) {
				if (node["hostname"] == host && node["port"] == port) {
					node["uptime_s"] = parse_ll_or_zero(mrow->fields[2]);
					node["queries"] = parse_ll_or_zero(mrow->fields[3]);
					node["client_connections"] = parse_ll_or_zero(mrow->fields[4]);
					total_queries += parse_ll_or_zero(mrow->fields[3]);
					total_client_connections += parse_ll_or_zero(mrow->fields[4]);
					break;
				}
			}
		}
		delete metrics_rs;
	}

	// 3. Get checksums if requested
	json checksums = json::array();
	bool config_in_sync = true;
	int nodes_in_sync = 0;
	int nodes_out_of_sync = 0;

	if (include_checksums) {
		std::string cksum_sql = "SELECT hostname, port, name, version, epoch, checksum, changed_at, updated_at, diff_check "
			"FROM stats.stats_proxysql_servers_checksums";
		if (!hostname_filter.empty()) {
			cksum_sql += " WHERE hostname = '" + sql_escape(hostname_filter) + "'";
		}

		SQLite3_result* cksum_rs = NULL;
		int ccols = 0;
		std::string cksum_err = execute_admin_query(cksum_sql.c_str(), &cksum_rs, &ccols);
		if (!cksum_err.empty()) {
			if (cksum_rs) {
				delete cksum_rs;
			}
			proxy_error("show_cluster: failed to query checksums: %s\n", cksum_err.c_str());
			return create_error_response("Failed to query cluster checksums: " + cksum_err);
		}

		std::set<std::string> sync_nodes, out_of_sync_nodes;

		if (cksum_rs) {
			for (const auto& crow : cksum_rs->rows) {
				int diff_check = parse_int_or_zero(crow->fields[8]);
				std::string node_key = std::string(crow->fields[0] ? crow->fields[0] : "") + ":" +
					std::string(crow->fields[1] ? crow->fields[1] : "");

				if (diff_check > 0) {
					config_in_sync = false;
					out_of_sync_nodes.insert(node_key);
				} else {
					sync_nodes.insert(node_key);
				}

				json cs;
				cs["hostname"] = crow->fields[0] ? crow->fields[0] : "";
				cs["port"] = parse_int_or_zero(crow->fields[1]);
				cs["name"] = crow->fields[2] ? crow->fields[2] : "";
				cs["version"] = parse_int_or_zero(crow->fields[3]);
				cs["epoch"] = parse_ll_or_zero(crow->fields[4]);
				cs["checksum"] = crow->fields[5] ? crow->fields[5] : "";
				cs["changed_at"] = parse_ll_or_zero(crow->fields[6]);
				cs["updated_at"] = parse_ll_or_zero(crow->fields[7]);
				cs["diff_check"] = diff_check;

				checksums.push_back(cs);
			}
			delete cksum_rs;

			// Count nodes that are fully in sync vs out of sync
			for (const auto& n : sync_nodes) {
				if (out_of_sync_nodes.find(n) == out_of_sync_nodes.end()) {
					nodes_in_sync++;
				}
			}
			nodes_out_of_sync = out_of_sync_nodes.size();
		}
	}

	// Determine cluster health
	std::string cluster_health = "healthy";
	if (total_nodes == 0) {
		cluster_health = "not_configured";
	} else if (online_nodes == 0) {
		cluster_health = "unhealthy";
	} else if (online_nodes < total_nodes || !config_in_sync) {
		cluster_health = "degraded";
	}

	json result;
	result["cluster_health"] = cluster_health;
	result["total_nodes"] = total_nodes;
	result["online_nodes"] = online_nodes;
	result["master_node"] = master_node;
	result["nodes"] = nodes;
	if (include_checksums) {
		result["checksums"] = checksums;
	}
	result["summary"] = {
		{"config_in_sync", config_in_sync},
		{"nodes_in_sync", nodes_in_sync},
		{"nodes_out_of_sync", nodes_out_of_sync},
		{"total_queries_all_nodes", total_queries},
		{"total_client_connections", total_client_connections},
		{"avg_ping_time_us", (total_nodes > 0) ? total_ping / total_nodes : 0}
	};

	return create_success_response(result);
}

// ============================================================================
// Historical Data Tool Implementations
// ============================================================================

/**
 * @brief Returns historical CPU and memory usage trends
 *
 * Queries historical system metrics from statsdb_disk. Automatically selects
 * between raw tables and hourly aggregated tables based on the requested interval.
 *
 * @param arguments JSON object with optional parameters:
 *   - metric: "cpu", "memory", or "all" (default)
 *   - interval: Time range - "30m", "1h", "2h", "4h", "6h", "12h", "1d", "2d", "1w"
 *
 * @return JSON response with data_points array containing timestamped metrics
 */
json Stats_Tool_Handler::handle_show_system_history(const json& arguments) {
	std::string metric = arguments.value("metric", "all");
	std::string interval = arguments.value("interval", "1h");

	int seconds = 0;
	bool use_hourly = false;
	if (!get_interval_config(interval, seconds, use_hourly)) {
		return create_error_response("Invalid interval: " + interval);
	}

	time_t now = time(NULL);
	time_t start = now - seconds;
	std::string resolution = use_hourly ? "hourly" : "raw";

	json result;
	result["interval"] = interval;
	result["resolution"] = resolution;

	// Query CPU data
	if (metric == "cpu" || metric == "all") {
		std::string table = use_hourly ? "system_cpu_hour" : "system_cpu";
		std::string sql = "SELECT timestamp, tms_utime, tms_stime FROM " + table +
			" WHERE timestamp BETWEEN " + std::to_string(start) + " AND " + std::to_string(now) +
			" ORDER BY timestamp";

		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string err = execute_statsdb_disk_query(sql.c_str(), &resultset, &cols);

		json cpu = json::array();
		if (err.empty() && resultset) {
			for (const auto& row : resultset->rows) {
				json entry;
				entry["timestamp"] = parse_ll_or_zero(row->fields[0]);
				entry["tms_utime"] = parse_ll_or_zero(row->fields[1]);
				entry["tms_stime"] = parse_ll_or_zero(row->fields[2]);
				cpu.push_back(entry);
			}
			delete resultset;
		}
		result["cpu"] = cpu;
	}

	// Query memory data
	if (metric == "memory" || metric == "all") {
		std::string table = use_hourly ? "system_memory_hour" : "system_memory";
		std::string sql = "SELECT timestamp, allocated, resident, active, mapped, metadata, retained FROM " + table +
			" WHERE timestamp BETWEEN " + std::to_string(start) + " AND " + std::to_string(now) +
			" ORDER BY timestamp";

		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string err = execute_statsdb_disk_query(sql.c_str(), &resultset, &cols);

		json memory = json::array();
		if (err.empty() && resultset) {
			for (const auto& row : resultset->rows) {
				json entry;
				entry["timestamp"] = parse_ll_or_zero(row->fields[0]);
				entry["allocated"] = parse_ll_or_zero(row->fields[1]);
				entry["resident"] = parse_ll_or_zero(row->fields[2]);
				entry["active"] = parse_ll_or_zero(row->fields[3]);
				entry["mapped"] = parse_ll_or_zero(row->fields[4]);
				entry["metadata"] = parse_ll_or_zero(row->fields[5]);
				entry["retained"] = parse_ll_or_zero(row->fields[6]);
				memory.push_back(entry);
			}
			delete resultset;
		}
		result["memory"] = memory;
	}

	return create_success_response(result);
}

/**
 * @brief Retrieves historical query cache performance metrics.
 *
 * Queries the stats database for historical query cache statistics including
 * GET/SET operations, cache hit rates, memory usage, and entry counts. Data
 * is automatically aggregated to hourly resolution for intervals >= 24h.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: Database type, only "mysql" supported (default: "mysql")
 *   - interval: Time range - "1h", "6h", "24h", "7d", "30d" (default: "1h")
 *
 * @return JSON response containing:
 *   - db_type: The database type queried
 *   - interval: The time interval requested
 *   - resolution: "raw" for short intervals, "hourly" for >= 24h
 *   - data: Array of cache metrics with timestamp, counts, bytes, and hit_rate
 */
json Stats_Tool_Handler::handle_show_query_cache_history(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	std::string interval = arguments.value("interval", "1h");

	// PostgreSQL not supported for query cache history
	if (db_type == "pgsql") {
		return create_error_response("PostgreSQL is not supported for this tool. Historical query cache data is only available for MySQL.");
	}

	int seconds = 0;
	bool use_hourly = false;
	if (!get_interval_config(interval, seconds, use_hourly)) {
		return create_error_response("Invalid interval: " + interval);
	}

	time_t now = time(NULL);
	time_t start = now - seconds;
	std::string resolution = use_hourly ? "hourly" : "raw";

	std::string table = use_hourly ? "mysql_query_cache_hour" : "mysql_query_cache";
	std::string sql = "SELECT timestamp, count_GET, count_GET_OK, count_SET, bytes_IN, bytes_OUT, "
		"Entries_Purged, Entries_In_Cache, Memory_Bytes FROM " + table +
		" WHERE timestamp BETWEEN " + std::to_string(start) + " AND " + std::to_string(now) +
		" ORDER BY timestamp";

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_statsdb_disk_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query query cache history: " + err);
	}

	json data = json::array();
	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long count_get = parse_ll_or_zero(row->fields[1]);
			long long count_get_ok = parse_ll_or_zero(row->fields[2]);
			double hit_rate = (count_get > 0) ? (double)count_get_ok / (double)count_get : 0.0;

			json entry;
			entry["timestamp"] = parse_ll_or_zero(row->fields[0]);
			entry["count_GET"] = count_get;
			entry["count_GET_OK"] = count_get_ok;
			entry["count_SET"] = parse_ll_or_zero(row->fields[3]);
			entry["bytes_IN"] = parse_ll_or_zero(row->fields[4]);
			entry["bytes_OUT"] = parse_ll_or_zero(row->fields[5]);
			entry["entries_purged"] = parse_ll_or_zero(row->fields[6]);
			entry["entries_in_cache"] = parse_ll_or_zero(row->fields[7]);
			entry["memory_bytes"] = parse_ll_or_zero(row->fields[8]);
			entry["hit_rate"] = hit_rate;
			data.push_back(entry);
		}
		delete resultset;
	}

	json result;
	result["db_type"] = db_type;
	result["interval"] = interval;
	result["resolution"] = resolution;
	result["data"] = data;

	return create_success_response(result);
}

/**
 * @brief Retrieves historical connection pool and client connection metrics.
 *
 * Queries the stats database for historical connection statistics at both
 * global and per-server levels. Global metrics include client/server connection
 * counts and connection pool operations. Per-server metrics show detailed
 * backend server connection states and query throughput.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: Database type, only "mysql" supported (default: "mysql")
 *   - interval: Time range - "1h", "6h", "24h", "7d", "30d" (default: "1h")
 *   - scope: "global", "per_server", or "all" (default: "global")
 *   - hostgroup: Filter per-server data by hostgroup ID (default: all)
 *   - server: Filter by server "host:port" (default: all)
 *
 * @return JSON response containing:
 *   - db_type: The database type queried
 *   - interval: The time interval requested
 *   - resolution: "raw" for short intervals, "hourly" for >= 24h
 *   - scope: The scope requested
 *   - global: (if scope includes global) Connection and MyHGM metrics arrays
 *   - per_server: (if scope includes per_server) Per-backend connection metrics
 */
json Stats_Tool_Handler::handle_show_connection_history(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	std::string interval = arguments.value("interval", "1h");
	std::string scope = arguments.value("scope", "global");
	int hostgroup = arguments.value("hostgroup", -1);
	std::string server = arguments.value("server", "");

	// PostgreSQL not supported for connection history
	if (db_type == "pgsql") {
		return create_error_response("PostgreSQL is not supported for this tool. Historical connection data is only available for MySQL.");
	}

	int seconds = 0;
	bool use_hourly = false;
	if (!get_interval_config(interval, seconds, use_hourly)) {
		return create_error_response("Invalid interval: " + interval);
	}

	time_t now = time(NULL);
	time_t start = now - seconds;
	std::string resolution = use_hourly ? "hourly" : "raw";

	json result;
	result["db_type"] = db_type;
	result["interval"] = interval;
	result["resolution"] = resolution;
	result["scope"] = scope;

	// Query global connection metrics
	if (scope == "global" || scope == "all") {
		std::string table = use_hourly ? "mysql_connections_hour" : "mysql_connections";
		std::string sql = "SELECT timestamp, Client_Connections_aborted, Client_Connections_connected, "
			"Client_Connections_created, Server_Connections_aborted, Server_Connections_connected, "
			"Server_Connections_created, ConnPool_get_conn_failure, ConnPool_get_conn_immediate, "
			"ConnPool_get_conn_success, Questions, Slow_queries, GTID_consistent_queries FROM " + table +
			" WHERE timestamp BETWEEN " + std::to_string(start) + " AND " + std::to_string(now) +
			" ORDER BY timestamp";

		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string err = execute_statsdb_disk_query(sql.c_str(), &resultset, &cols);

		json connections = json::array();
		if (err.empty() && resultset) {
			connections = resultset_to_json(resultset, cols);
			delete resultset;
		}

		// Query MyHGM metrics
		std::string myhgm_table = use_hourly ? "myhgm_connections_hour" : "myhgm_connections";
		std::string myhgm_sql = "SELECT timestamp, MyHGM_myconnpoll_destroy, MyHGM_myconnpoll_get, "
			"MyHGM_myconnpoll_get_ok, MyHGM_myconnpoll_push, MyHGM_myconnpoll_reset FROM " + myhgm_table +
			" WHERE timestamp BETWEEN " + std::to_string(start) + " AND " + std::to_string(now) +
			" ORDER BY timestamp";

		SQLite3_result* myhgm_rs = NULL;
		int myhgm_cols = 0;
		std::string myhgm_err = execute_statsdb_disk_query(myhgm_sql.c_str(), &myhgm_rs, &myhgm_cols);

		json myhgm = json::array();
		if (myhgm_err.empty() && myhgm_rs) {
			myhgm = resultset_to_json(myhgm_rs, myhgm_cols);
			delete myhgm_rs;
		}

		result["global"] = {
			{"connections", connections},
			{"myhgm", myhgm}
		};
	}

	// Query per-server metrics
	if (scope == "per_server" || scope == "all") {
		std::string sql = "SELECT timestamp, hostgroup, srv_host, srv_port, status, "
			"ConnUsed, ConnFree, ConnOK, ConnERR, MaxConnUsed, "
			"Queries, Queries_GTID_sync, Bytes_data_sent, Bytes_data_recv, Latency_us "
			"FROM history_stats_mysql_connection_pool "
			"WHERE timestamp BETWEEN " + std::to_string(start) + " AND " + std::to_string(now);

		if (hostgroup >= 0) {
			sql += " AND hostgroup = " + std::to_string(hostgroup);
		}
		if (!server.empty()) {
			std::string host;
			int port = 0;
			std::string parse_err;
			if (!parse_server_filter(server, host, port, parse_err)) {
				proxy_error("show_connection_history: invalid server filter '%s': %s\n", server.c_str(), parse_err.c_str());
				return create_error_response("Invalid server filter '" + server + "': " + parse_err);
			}
			sql += " AND srv_host = '" + sql_escape(host) + "' AND srv_port = " + std::to_string(port);
		}

		sql += " ORDER BY timestamp, hostgroup, srv_host";

		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string err = execute_statsdb_disk_query(sql.c_str(), &resultset, &cols);

		json per_server = json::array();
		if (err.empty() && resultset) {
			per_server = resultset_to_json(resultset, cols);
			delete resultset;
		}

		result["per_server"] = per_server;
	}

	return create_success_response(result);
}

/**
 * @brief Retrieves historical query digest snapshots from disk storage.
 *
 * Queries the history_mysql_query_digest or history_pgsql_query_digest tables
 * for previously saved query digest snapshots. These snapshots are created by
 * flush_queries and contain aggregated query statistics at specific points in
 * time, enabling trend analysis and historical query pattern investigation.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" or "pgsql" (default: "mysql")
 *   - dump_time: Specific snapshot timestamp to retrieve (default: all)
 *   - start_time: Filter snapshots after this timestamp (default: no filter)
 *   - end_time: Filter snapshots before this timestamp (default: no filter)
 *   - digest: Filter by specific query digest hash (default: all)
 *   - username: Filter by username (default: all)
 *   - database: Filter by database/schema name (default: all)
 *   - limit: Maximum queries to return (default: 100)
 *   - offset: Pagination offset (default: 0)
 *
 * @return JSON response containing:
 *   - db_type: The database type queried
 *   - snapshots: Array of snapshots, each with dump_time and queries array
 *   - summary: Total snapshots count and time range
 */
json Stats_Tool_Handler::handle_show_query_history(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");
	long long dump_time = arguments.value("dump_time", (long long)-1);
	long long start_time = arguments.value("start_time", (long long)-1);
	long long end_time = arguments.value("end_time", (long long)-1);
	std::string digest = arguments.value("digest", "");
	std::string username = arguments.value("username", "");
	std::string database = arguments.value("database", "");
	int limit = arguments.value("limit", 100);
	int offset = arguments.value("offset", 0);

	std::string table = (db_type == "pgsql") ? "history_pgsql_query_digest" : "history_mysql_query_digest";
	// Note: Both MySQL and PostgreSQL history tables use 'schemaname' column

	std::string sql = "SELECT dump_time, hostgroup, schemaname, username, client_address, "
		"digest, digest_text, count_star, first_seen, last_seen, "
		"sum_time, min_time, max_time, sum_rows_affected, sum_rows_sent "
		"FROM " + table + " WHERE 1=1";

	if (dump_time >= 0) {
		sql += " AND dump_time = " + std::to_string(dump_time);
	}
	if (start_time >= 0) {
		sql += " AND dump_time >= " + std::to_string(start_time);
	}
	if (end_time >= 0) {
		sql += " AND dump_time <= " + std::to_string(end_time);
	}
	if (!digest.empty()) {
		sql += " AND digest = '" + sql_escape(digest) + "'";
	}
	if (!username.empty()) {
		sql += " AND username = '" + sql_escape(username) + "'";
	}
	if (!database.empty()) {
		sql += " AND schemaname = '" + sql_escape(database) + "'";
	}

	sql += " ORDER BY dump_time DESC, count_star DESC LIMIT " + std::to_string(limit) + " OFFSET " + std::to_string(offset);

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_statsdb_disk_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query history query digest: " + err);
	}

	// Group by dump_time into snapshots
	std::map<long long, json> snapshot_map;
	long long earliest = LLONG_MAX;
	long long latest = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long dt = parse_ll_or_zero(row->fields[0]);
			if (dt < earliest) earliest = dt;
			if (dt > latest) latest = dt;

			long long count_star = parse_ll_or_zero(row->fields[7]);
			long long sum_time = parse_ll_or_zero(row->fields[10]);

			json query;
			query["hostgroup"] = parse_int_or_zero(row->fields[1]);
			query["database"] = row->fields[2] ? row->fields[2] : "";
			query["username"] = row->fields[3] ? row->fields[3] : "";
			query["client_address"] = row->fields[4] ? row->fields[4] : "";
			query["digest"] = row->fields[5] ? row->fields[5] : "";
			query["digest_text"] = row->fields[6] ? row->fields[6] : "";
			query["count_star"] = count_star;
			query["first_seen"] = parse_ll_or_zero(row->fields[8]);
			query["last_seen"] = parse_ll_or_zero(row->fields[9]);
			query["sum_time_us"] = sum_time;
			query["min_time_us"] = parse_ll_or_zero(row->fields[11]);
			query["max_time_us"] = parse_ll_or_zero(row->fields[12]);
			query["sum_rows_affected"] = parse_ll_or_zero(row->fields[13]);
			query["sum_rows_sent"] = parse_ll_or_zero(row->fields[14]);

			if (snapshot_map.find(dt) == snapshot_map.end()) {
				snapshot_map[dt] = json::array();
			}
			snapshot_map[dt].push_back(query);
		}
		delete resultset;
	}

	// Convert map to array of snapshots
	json snapshots = json::array();
	for (auto it = snapshot_map.rbegin(); it != snapshot_map.rend(); ++it) {
		json snapshot;
		snapshot["dump_time"] = it->first;
		snapshot["queries"] = it->second;
		snapshots.push_back(snapshot);
	}

	json result;
	result["db_type"] = db_type;
	result["snapshots"] = snapshots;
	result["summary"] = {
		{"total_snapshots", (int)snapshots.size()},
		{"earliest_snapshot", earliest == LLONG_MAX ? 0 : earliest},
		{"latest_snapshot", latest}
	};

	return create_success_response(result);
}

// ============================================================================
// Utility Tool Implementations
// ============================================================================

/**
 * @brief Flushes query events from the MySQL Logger buffer to database storage.
 *
 * Triggers immediate processing of buffered query events from the MySQL Logger,
 * writing them to the specified destination database(s). This is useful for
 * ensuring recent query activity is persisted before querying with show_query_log.
 *
 * @note This function calls GloMyLogger->processEvents() directly rather than
 *       executing an admin command, as admin commands are intercepted only via
 *       the MySQL admin interface, not when sent directly to SQLite.
 *
 * @param arguments JSON object with optional parameters:
 *   - destination: "memory", "disk", or "both" (default: "memory")
 *
 * @return JSON response containing:
 *   - events_flushed: Number of query events written to database
 *   - destination: The destination that was used
 */
json Stats_Tool_Handler::handle_flush_query_log(const json& arguments) {
	std::string destination = arguments.value("destination", "memory");

	// Validate destination
	if (destination != "memory" && destination != "disk" && destination != "both") {
		return create_error_response("Invalid destination: " + destination + ". Must be 'memory', 'disk', or 'both'.");
	}

	// Check if MySQL Logger is available
	if (!GloMyLogger) {
		return create_error_response("MySQL Logger not available");
	}

	// Check if Admin is available for database access
	if (!GloAdmin) {
		return create_error_response("ProxySQL Admin not available");
	}

	// Determine which databases to flush to
	SQLite3DB* statsdb = nullptr;
	SQLite3DB* statsdb_disk = nullptr;

	if (destination == "memory" || destination == "both") {
		statsdb = GloAdmin->statsdb;
		if (!statsdb) {
			return create_error_response("Stats memory database not available");
		}
	}
	if (destination == "disk" || destination == "both") {
		statsdb_disk = GloAdmin->statsdb_disk;
		if (!statsdb_disk) {
			return create_error_response("Stats disk database not available");
		}
	}

	// Call the underlying C++ function to flush events from buffer to database(s)
	int events_flushed = GloMyLogger->processEvents(statsdb, statsdb_disk);

	json result;
	result["events_flushed"] = events_flushed;
	result["destination"] = destination;

	return create_success_response(result);
}

/**
 * @brief Retrieves individual query events from the query log.
 *
 * Queries the MySQL query events table for detailed information about individual
 * query executions. This provides full query text, timing, and error information
 * for debugging and auditing purposes. Events can be retrieved from either the
 * in-memory stats database or the on-disk history database.
 *
 * @param arguments JSON object with optional parameters:
 *   - source: "memory" for recent events, "disk" for history (default: "memory")
 *   - username: Filter by username (default: all)
 *   - database: Filter by database/schema name (default: all)
 *   - query_digest: Filter by query digest hash (default: all)
 *   - server: Filter by backend server address (default: all)
 *   - errno: Filter by specific error number (default: all)
 *   - errors_only: If true, only return events with errors (default: false)
 *   - start_time: Filter events after this timestamp (default: no filter)
 *   - end_time: Filter events before this timestamp (default: no filter)
 *   - limit: Maximum events to return (default: 100)
 *   - offset: Pagination offset (default: 0)
 *
 * @return JSON response containing:
 *   - source: The data source used
 *   - total_events: Count of events returned
 *   - events: Array of query event details
 *   - summary: Error count and time range statistics
 */
json Stats_Tool_Handler::handle_show_query_log(const json& arguments) {
	std::string source = arguments.value("source", "memory");
	std::string username = arguments.value("username", "");
	std::string database = arguments.value("database", "");
	std::string query_digest = arguments.value("query_digest", "");
	std::string server = arguments.value("server", "");
	int errno_filter = arguments.value("errno", -1);
	bool errors_only = arguments.value("errors_only", false);
	long long start_time = arguments.value("start_time", (long long)-1);
	long long end_time = arguments.value("end_time", (long long)-1);
	int limit = arguments.value("limit", 100);
	int offset = arguments.value("offset", 0);

	std::string table = (source == "disk") ? "history_mysql_query_events" : "stats.stats_mysql_query_events";

	std::string sql = "SELECT thread_id, username, schemaname, start_time, end_time, "
		"query_digest, query, server, client, event_type, hid, "
		"affected_rows, rows_sent, errno, error "
		"FROM " + table + " WHERE 1=1";

	if (!username.empty()) {
		sql += " AND username = '" + sql_escape(username) + "'";
	}
	if (!database.empty()) {
		sql += " AND schemaname = '" + sql_escape(database) + "'";
	}
	if (!query_digest.empty()) {
		sql += " AND query_digest = '" + sql_escape(query_digest) + "'";
	}
	if (!server.empty()) {
		sql += " AND server = '" + sql_escape(server) + "'";
	}
	if (errno_filter >= 0) {
		sql += " AND errno = " + std::to_string(errno_filter);
	}
	if (errors_only) {
		sql += " AND errno != 0";
	}
	if (start_time >= 0) {
		sql += " AND start_time >= " + std::to_string(start_time);
	}
	if (end_time >= 0) {
		sql += " AND start_time <= " + std::to_string(end_time);
	}

	sql += " ORDER BY start_time DESC LIMIT " + std::to_string(limit) + " OFFSET " + std::to_string(offset);

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err;

	if (source == "disk") {
		err = execute_statsdb_disk_query(sql.c_str(), &resultset, &cols);
	} else {
		err = execute_admin_query(sql.c_str(), &resultset, &cols);
	}

	if (!err.empty()) {
		return create_error_response("Failed to query query log: " + err);
	}

	json events = json::array();
	int total_errors = 0;
	long long earliest = LLONG_MAX;
	long long latest = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long st = parse_ll_or_zero(row->fields[3]);
			int err_no = parse_int_or_zero(row->fields[13]);

			if (st < earliest) earliest = st;
			if (st > latest) latest = st;
			if (err_no != 0) total_errors++;

			json event;
			event["thread_id"] = parse_int_or_zero(row->fields[0]);
			event["username"] = row->fields[1] ? row->fields[1] : "";
			event["database"] = row->fields[2] ? row->fields[2] : "";
			event["start_time"] = st;
			event["end_time"] = parse_ll_or_zero(row->fields[4]);
			event["query_digest"] = row->fields[5] ? row->fields[5] : "";
			event["query"] = row->fields[6] ? row->fields[6] : "";
			event["server"] = row->fields[7] ? row->fields[7] : "";
			event["client"] = row->fields[8] ? row->fields[8] : "";
			event["event_type"] = parse_int_or_zero(row->fields[9]);
			event["hostgroup"] = parse_int_or_zero(row->fields[10]);
			event["affected_rows"] = parse_ll_or_zero(row->fields[11]);
			event["rows_sent"] = parse_ll_or_zero(row->fields[12]);
			event["errno"] = err_no;
			event["error"] = row->fields[14] ? row->fields[14] : nullptr;

			events.push_back(event);
		}
		delete resultset;
	}

	json result;
	result["source"] = source;
	result["total_events"] = (int)events.size();
	result["events"] = events;
	result["summary"] = {
		{"total_errors", total_errors},
		{"time_range", {
			{"earliest", earliest == LLONG_MAX ? 0 : earliest},
			{"latest", latest}
		}}
	};

	return create_success_response(result);
}

/**
 * @brief Saves current query digest statistics to disk for historical analysis.
 *
 * Flushes the current in-memory query digest statistics to the history tables
 * on disk, creating a point-in-time snapshot. This enables historical trend
 * analysis via show_query_history. Each flush creates a new snapshot with a
 * unique dump_time timestamp.
 *
 * @note This function calls GloAdmin->FlushDigestTableToDisk() directly rather
 *       than executing an admin command, as admin commands are intercepted only
 *       via the MySQL admin interface, not when sent directly to SQLite.
 *
 * @param arguments JSON object with optional parameters:
 *   - db_type: "mysql" or "pgsql" (default: "mysql")
 *
 * @return JSON response containing:
 *   - db_type: The database type flushed
 *   - digests_saved: Number of query digests written to disk
 *   - dump_time: Unix timestamp of this snapshot
 */
json Stats_Tool_Handler::handle_flush_queries(const json& arguments) {
	std::string db_type = arguments.value("db_type", "mysql");

	// Validate db_type
	if (db_type != "mysql" && db_type != "pgsql") {
		return create_error_response("Invalid db_type: " + db_type);
	}

	// Check if Admin is available
	if (!GloAdmin) {
		return create_error_response("ProxySQL Admin not available");
	}

	// Check if statsdb_disk is available
	if (!GloAdmin->statsdb_disk) {
		return create_error_response("Stats disk database not available");
	}

	// Call the underlying C++ function to flush digest stats to disk
	int digests_saved = 0;
	if (db_type == "mysql") {
		digests_saved = GloAdmin->FlushDigestTableToDisk<SERVER_TYPE_MYSQL>(GloAdmin->statsdb_disk);
	} else {
		digests_saved = GloAdmin->FlushDigestTableToDisk<SERVER_TYPE_PGSQL>(GloAdmin->statsdb_disk);
	}

	json result;
	result["db_type"] = db_type;
	result["digests_saved"] = digests_saved;
	result["dump_time"] = (long long)time(NULL);

	return create_success_response(result);
}

#endif /* PROXYSQL40 */
