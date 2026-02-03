#ifndef CLASS_STATS_TOOL_HANDLER_H
#define CLASS_STATS_TOOL_HANDLER_H

#include <map>

#include "MCP_Tool_Handler.h"
#include "MCP_Thread.h"

/**
 * @brief Stats Tool Handler for /mcp/stats endpoint
 *
 * This handler provides tools for real-time metrics, statistics, and monitoring
 * of ProxySQL internals including connection pools, query digests, errors,
 * cluster status, and more.
 *
 * Tools provided:
 * - get_health: Comprehensive health status summary
 * - show_processlist: Active sessions (like MySQL SHOW PROCESSLIST)
 * - show_metrics: Prometheus-compatible metrics
 * - show_queries: Query digest performance statistics
 * - show_connections: Backend connection pool metrics
 * - show_errors: Error tracking and analysis
 * - show_cluster: Cluster node health and sync status
 * - list_stats: List available statistics tables
 * - get_stats: Ad-hoc query any stats table
 * - show_commands: Command execution statistics with latency distribution
 * - show_users: User connection statistics
 * - show_client_cache: Client host cache for connection throttling
 * - show_gtid: GTID replication information
 * - show_query_rules: Query rule hit statistics
 * - show_history_connections: Historical connection trends
 * - show_history_query_digest: Historical query digest snapshots
 * - aggregate_metrics: Custom metric aggregations
 */
class Stats_Tool_Handler : public MCP_Tool_Handler {
private:
	MCP_Threads_Handler* mcp_handler;  ///< Pointer to MCP handler
	pthread_mutex_t handler_lock;      ///< Mutex for thread-safe operations

	// Tool handlers
	json handle_get_health(const json& arguments);
	json handle_show_processlist(const json& arguments);
	json handle_show_metrics(const json& arguments);
	json handle_show_queries(const json& arguments);
	json handle_show_connections(const json& arguments);
	json handle_show_errors(const json& arguments);
	json handle_show_cluster(const json& arguments);
	json handle_list_stats(const json& arguments);
	json handle_get_stats(const json& arguments);
	json handle_show_commands(const json& arguments);
	json handle_show_users(const json& arguments);
	json handle_show_client_cache(const json& arguments);
	json handle_show_gtid(const json& arguments);
	json handle_show_query_rules(const json& arguments);
	json handle_show_history_connections(const json& arguments);
	json handle_show_history_query_digest(const json& arguments);
	json handle_aggregate_metrics(const json& arguments);

	// Helper methods

	/**
	 * @brief Execute a SQL query against GloAdmin->admindb
	 * @param sql The SQL query to execute
	 * @param resultset Output pointer for the result set (caller must delete)
	 * @param cols Output for number of columns
	 * @return Empty string on success, error message on failure
	 */
	std::string execute_admin_query(const char* sql, SQLite3_result** resultset, int* cols);

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

	/**
	 * @brief Validate a stats table name against a whitelist
	 * @param table The table name to validate
	 * @return true if the table name is valid
	 */
	static bool is_valid_stats_table(const std::string& table);

public:
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

#endif /* CLASS_STATS_TOOL_HANDLER_H */
