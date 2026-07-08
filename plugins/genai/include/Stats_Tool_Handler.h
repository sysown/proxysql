#ifndef CLASS_STATS_TOOL_HANDLER_H
#define CLASS_STATS_TOOL_HANDLER_H

#ifdef PROXYSQL40

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "MCP_Tool_Handler.h"
#include "MCP_Thread.h"

// =========================================================================
// Free helper functions (defined in Stats_Tool_Handler.cpp)
// =========================================================================
namespace stats_utils {

/**
 * @brief Parse and validate a backend filter in `host:port` format.
 */
bool parse_server_filter(const std::string& server_filter, std::string& host, int& port, std::string& error);

/**
 * @brief Parse digest filter string into uint64 digest identifier.
 */
bool parse_digest_filter(const std::string& digest_filter, uint64_t& digest_value, std::string& error);

/**
 * @brief Parse a nullable numeric SQLite field into signed 64-bit.
 */
long long parse_ll_or_zero(const char* value);

/**
 * @brief Parse a nullable numeric SQLite field into signed int.
 */
int parse_int_or_zero(const char* value);

} // namespace stats_utils

/**
 * @brief Stats Tool Handler for /mcp/stats endpoint
 *
 * This handler provides MCP tools for monitoring ProxySQL statistics and metrics.
 * Tools are organized into three categories:
 *
 * Live Data Tools (13):
 * - show_status: Global status variables and metrics
 * - show_processlist: Currently active sessions
 * - show_queries: Query digest performance statistics
 * - show_commands: Command execution counters with latency histograms
 * - show_connections: Backend connection pool metrics
 * - show_free_connections: Debug free-connection pool snapshots
 * - show_errors: Error tracking and frequency
 * - show_users: User connection statistics
 * - show_client_cache: Client host error cache
 * - show_query_rules: Query rule hit counts
 * - show_prepared_statements: Prepared statement information
 * - show_gtid: GTID replication status (MySQL only)
 * - show_cluster: ProxySQL cluster node health
 *
 * Historical Data Tools (4):
 * - show_system_history: CPU and memory trends over time
 * - show_query_cache_history: Query cache performance trends
 * - show_connection_history: Connection metrics history
 * - show_query_history: Query digest snapshots over time
 *
 * Utility Tools (3):
 * - flush_query_log: Flush query events from buffer to tables
 * - show_query_log: View query event audit log
 * - flush_queries: Save query digest statistics to disk
 */
class Stats_Tool_Handler : public MCP_Tool_Handler {
private:
	MCP_Threads_Handler* mcp_handler;  ///< Pointer to MCP handler
	pthread_mutex_t handler_lock;      ///< Mutex for thread-safe operations

	// =========================================================================
	// Live Data Tool Handlers
	// =========================================================================

	/**
	 * @brief Returns global status variables and metrics
	 * @param arguments JSON with db_type, category, variable_name
	 */
	json handle_show_status(const json& arguments);

	/**
	 * @brief Shows all currently active sessions
	 * @param arguments JSON with db_type, filters, sort_by, sort_order, limit, offset
	 */
	json handle_show_processlist(const json& arguments);

	/**
	 * @brief Returns aggregated query performance statistics
	 * @param arguments JSON with db_type, sort_by, limit, offset, filters
	 */
	json handle_show_queries(const json& arguments);

	/**
	 * @brief Returns command execution statistics with latency histograms
	 * @param arguments JSON with db_type, command, limit, offset
	 */
	json handle_show_commands(const json& arguments);

	/**
	 * @brief Returns backend connection pool metrics
	 * @param arguments JSON with db_type, hostgroup, server, status
	 */
	json handle_show_connections(const json& arguments);

	/**
	 * @brief Returns debug free-connection snapshots from backend pools
	 * @param arguments JSON with db_type, hostgroup, server
	 */
	json handle_show_free_connections(const json& arguments);

	/**
	 * @brief Returns error tracking statistics
	 * @param arguments JSON with db_type, errno, sqlstate, username, database, hostgroup, filters
	 */
	json handle_show_errors(const json& arguments);

	/**
	 * @brief Returns connection statistics per user
	 * @param arguments JSON with db_type, username, limit, offset
	 */
	json handle_show_users(const json& arguments);

	/**
	 * @brief Returns client host error cache
	 * @param arguments JSON with db_type, client_address, min_error_count, limit, offset
	 */
	json handle_show_client_cache(const json& arguments);

	/**
	 * @brief Returns query rule hit statistics
	 * @param arguments JSON with db_type, rule_id, min_hits, include_zero_hits, limit, offset
	 */
	json handle_show_query_rules(const json& arguments);

	/**
	 * @brief Returns prepared statement information
	 * @param arguments JSON with db_type, username, database
	 */
	json handle_show_prepared_statements(const json& arguments);

	/**
	 * @brief Returns GTID replication information (MySQL only)
	 * @param arguments JSON with hostname, port
	 */
	json handle_show_gtid(const json& arguments);

	/**
	 * @brief Returns ProxySQL cluster node health and sync status
	 * @param arguments JSON with hostname, include_checksums
	 */
	json handle_show_cluster(const json& arguments);

	// =========================================================================
	// Historical Data Tool Handlers
	// =========================================================================

	/**
	 * @brief Returns historical CPU and memory usage trends
	 * @param arguments JSON with metric, interval
	 */
	json handle_show_system_history(const json& arguments);

	/**
	 * @brief Returns historical query cache performance metrics
	 * @param arguments JSON with db_type, interval
	 */
	json handle_show_query_cache_history(const json& arguments);

	/**
	 * @brief Returns historical connection metrics
	 * @param arguments JSON with db_type, interval, scope, hostgroup, server
	 */
	json handle_show_connection_history(const json& arguments);

	/**
	 * @brief Returns historical query digest snapshots
	 * @param arguments JSON with db_type, dump_time, start_time, end_time, filters, limit, offset
	 */
	json handle_show_query_history(const json& arguments);

	// =========================================================================
	// Utility Tool Handlers
	// =========================================================================

	/**
	 * @brief Flushes query events from buffer to tables (MySQL only)
	 * @param arguments JSON with destination (memory, disk, both)
	 */
	json handle_flush_query_log(const json& arguments);

	/**
	 * @brief Returns query event audit log (MySQL only)
	 * @param arguments JSON with source, filters, limit, offset
	 */
	json handle_show_query_log(const json& arguments);

	/**
	 * @brief Saves query digest statistics to disk
	 * @param arguments JSON with db_type
	 */
	json handle_flush_queries(const json& arguments);

	// =========================================================================
	// Helper Methods
	// =========================================================================

	/**
	 * @brief Execute a SQL query against `GloAdmin->admindb` with Admin-session semantics.
	 *
	 * This helper intentionally mirrors the critical part of the Admin SQL execution path
	 * used by `ProxySQL_Admin::admin_session_handler()`:
	 *
	 * 1. Acquire `GloAdmin->sql_query_global_mutex` to serialize access to the internal
	 *    in-memory SQLite databases.
	 * 2. Optionally invoke `ProxySQL_Admin::GenericRefreshStatistics()` on the current SQL
	 *    statement so `stats_*` tables are repopulated before they are read.
	 * 3. Execute the SQL statement via `admindb->execute_statement()`.
	 * 4. Release `sql_query_global_mutex`.
	 *
	 * Using this flow avoids stale reads from runtime-populated `stats.*` tables when tools
	 * access them directly through `admindb`.
	 *
	 * @param sql SQL statement to execute. Must not be `nullptr` or empty.
	 * @param resultset Output pointer receiving the result set on success. Caller owns it.
	 * @param cols Output pointer receiving the number of columns on success.
	 * @param refresh_before_query
	 *   If true (default), call `GenericRefreshStatistics()` before executing @p sql.
	 *   Set to false for secondary queries (for example `COUNT(*)` immediately after a
	 *   primary read) to avoid redundant expensive refresh passes.
	 *
	 * @return Empty string on success, otherwise a human-readable error message.
	 */
	std::string execute_admin_query(const char* sql, SQLite3_result** resultset, int* cols, bool refresh_before_query = true);

	/**
	 * @brief Execute a SQL query against GloAdmin->statsdb_disk (historical data)
	 * @param sql The SQL query to execute
	 * @param resultset Output pointer for the result set (caller must delete)
	 * @param cols Output for number of columns
	 * @return Empty string on success, error message on failure
	 */
	std::string execute_statsdb_disk_query(const char* sql, SQLite3_result** resultset, int* cols);

	/**
	 * @brief Parse key-value pairs from stats_*_global tables
	 * @param resultset The result set from a global stats query
	 * @return Map of variable name to variable value
	 */
	std::map<std::string, std::string> parse_global_stats(SQLite3_result* resultset);

public:
	/**
	 * @brief Get interval configuration for historical queries
	 * @param interval User-friendly interval string (e.g. "1h", "1d")
	 * @param seconds Output: interval in seconds
	 * @param use_hourly Output: whether to use hourly aggregated tables
	 * @return true if interval is valid
	 */
	bool get_interval_config(const std::string& interval, int& seconds, bool& use_hourly);

	/**
	 * @brief Estimate a latency percentile from histogram buckets.
	 *
	 * This helper clamps percentile bounds, handles the p0 edge case by
	 * returning the first non-empty bucket, and uses 64-bit accumulation
	 * to avoid overflow when counters are very large.
	 *
	 * @param buckets Bucket counts (aligned by index with @p thresholds).
	 * @param thresholds Bucket upper bounds in microseconds.
	 * @param percentile Requested percentile in `[0.0, 1.0]`.
	 * @return Estimated percentile latency in microseconds, or 0 when empty/invalid.
	 */
	int calculate_percentile(const std::vector<int>& buckets, const std::vector<int>& thresholds, double percentile);

	/**
	 * @brief Constructor
	 * @param handler Pointer to MCP_Threads_Handler
	 */
	Stats_Tool_Handler(MCP_Threads_Handler* handler);

	/**
	 * @brief Destructor
	 */
	~Stats_Tool_Handler() override;

	// MCP_Tool_Handler interface implementation
	json get_tool_list() override;
	json get_tool_description(const std::string& tool_name) override;
	json execute_tool(const std::string& tool_name, const json& arguments) override;
	int init() override;
	void close() override;
	std::string get_handler_name() const override { return "stats"; }
};

#endif /* PROXYSQL40 */
#endif /* CLASS_STATS_TOOL_HANDLER_H */
