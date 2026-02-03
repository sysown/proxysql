#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <numeric>

#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "sqlite3db.h"
#include "proxysql_debug.h"
#include "proxysql_utils.h"

#include "MCP_Thread.h"
#include "Stats_Tool_Handler.h"

extern ProxySQL_Admin *GloAdmin;

// Latency bucket thresholds in microseconds for commands_counters histogram
static const std::vector<int> LATENCY_BUCKET_THRESHOLDS = {
	100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000, 10000000, 100000000
};

// Whitelist of allowed stats table prefixes for get_stats
static const std::vector<std::string> VALID_STATS_TABLE_PREFIXES = {
	"stats_mysql_", "stats_pgsql_", "stats_proxysql_", "stats_memory_",
	"history_mysql_", "history_pgsql_",
	"mysql_connections", "pgsql_connections",
	"mysql_query_cache", "system_cpu", "system_memory",
	"myhgm_connections"
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

std::string Stats_Tool_Handler::execute_admin_query(const char* sql, SQLite3_result** resultset, int* cols) {
	if (!GloAdmin || !GloAdmin->admindb) {
		return "ProxySQL Admin not available";
	}

	char* error = NULL;
	int affected_rows = 0;
	*resultset = NULL;
	*cols = 0;

	GloAdmin->admindb->execute_statement(sql, &error, cols, &affected_rows, resultset);

	if (error) {
		std::string err_msg(error);
		free(error);
		if (*resultset) {
			delete *resultset;
			*resultset = NULL;
		}
		return err_msg;
	}

	return "";  // empty string = success
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

bool Stats_Tool_Handler::is_valid_stats_table(const std::string& table) {
	for (const auto& prefix : VALID_STATS_TABLE_PREFIXES) {
		if (table.compare(0, prefix.size(), prefix) == 0) {
			return true;
		}
	}
	return false;
}

// ============================================================================
// Tool List / Description / Dispatch
// ============================================================================

json Stats_Tool_Handler::get_tool_list() {
	json tools = json::array();

	// Core operational tools

	tools.push_back(create_tool_description(
		"get_health",
		"Returns a comprehensive health status summary of ProxySQL and its backend servers, "
		"including connection health, query performance, memory usage, and cluster status",
		{
			{"type", "object"},
			{"properties", {
				{"include_backend", {
					{"type", "boolean"},
					{"description", "Include detailed backend server health (default: false)"},
					{"default", false}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql", "all"}},
					{"description", "Filter by database type (default: all)"},
					{"default", "all"}
				}},
				{"severity_threshold", {
					{"type", "string"},
					{"enum", {"warning", "critical"}},
					{"description", "Only return issues at or above this severity level"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_processlist",
		"Shows all active sessions currently being processed, similar to MySQL's SHOW PROCESSLIST. "
		"Includes session details, client/backend info, query text, and timing",
		{
			{"type", "object"},
			{"properties", {
				{"user", {
					{"type", "string"},
					{"description", "Filter by username"}
				}},
				{"hostgroup", {
					{"type", "integer"},
					{"description", "Filter by hostgroup ID"}
				}},
				{"backend", {
					{"type", "string"},
					{"description", "Filter by specific backend server (host:port)"}
				}},
				{"min_time_ms", {
					{"type", "integer"},
					{"description", "Only show sessions running longer than X ms"}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Filter by database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_metrics",
		"Returns categorized metrics in Prometheus-compatible format for monitoring integration",
		{
			{"type", "object"},
			{"properties", {
				{"category", {
					{"type", "string"},
					{"enum", {"query", "connection", "memory", "cluster", "all"}},
					{"description", "Metric category (default: all)"},
					{"default", "all"}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql", "all"}},
					{"description", "Filter by database type (default: all)"},
					{"default", "all"}
				}},
				{"format", {
					{"type", "string"},
					{"enum", {"prometheus", "json"}},
					{"description", "Output format (default: prometheus)"},
					{"default", "prometheus"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_queries",
		"Returns aggregated query performance statistics from query digest, identifying slow "
		"and frequently executed queries with timing, row counts, and performance tiers",
		{
			{"type", "object"},
			{"properties", {
				{"sort_by", {
					{"type", "string"},
					{"enum", {"count", "avg_time", "sum_time", "max_time", "rows_sent"}},
					{"description", "Sort order (default: count)"},
					{"default", "count"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Max number of results (default: 100)"},
					{"default", 100}
				}},
				{"min_count", {
					{"type", "integer"},
					{"description", "Only show queries executed at least N times"}
				}},
				{"min_time_us", {
					{"type", "integer"},
					{"description", "Only show queries with avg time >= N microseconds"}
				}},
				{"schemaname", {
					{"type", "string"},
					{"description", "Filter by schema/database name"}
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
				{"include_top", {
					{"type", "boolean"},
					{"description", "Include top 10 summary (default: true)"},
					{"default", true}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Filter by database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_connections",
		"Detailed view of backend connection pool metrics per server, including utilization, "
		"error rates, queries, latency, and data transfer stats",
		{
			{"type", "object"},
			{"properties", {
				{"hostgroup", {
					{"type", "integer"},
					{"description", "Filter by hostgroup ID"}
				}},
				{"server", {
					{"type", "string"},
					{"description", "Filter by specific backend server (host:port)"}
				}},
				{"status", {
					{"type", "string"},
					{"enum", {"ONLINE", "SHUNNED", "OFFLINE_SOFT", "OFFLINE_HARD"}},
					{"description", "Filter by server status"}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Filter by database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_errors",
		"Tracks MySQL/PostgreSQL errors with frequency, timing, and grouping by type, user, schema, and hostgroup",
		{
			{"type", "object"},
			{"properties", {
				{"errno", {
					{"type", "integer"},
					{"description", "Filter by specific error number (MySQL) or sqlstate (PostgreSQL)"}
				}},
				{"username", {
					{"type", "string"},
					{"description", "Filter by username"}
				}},
				{"schemaname", {
					{"type", "string"},
					{"description", "Filter by schema/database"}
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
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Filter by database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_cluster",
		"Shows ProxySQL cluster node health, synchronization status, and network metrics "
		"including checksums, ping times, and check results",
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
				}},
				{"detailed_metrics", {
					{"type", "boolean"},
					{"description", "Include detailed per-node metrics (default: false)"},
					{"default", false}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"list_stats",
		"List all available statistics tables with descriptions, column info, and row counts",
		{
			{"type", "object"},
			{"properties", {
				{"filter", {
					{"type", "string"},
					{"description", "Pattern filter for table names (e.g. 'mysql', 'pgsql', 'cluster')"}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql", "all"}},
					{"description", "Filter by database type (default: all)"},
					{"default", "all"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"get_stats",
		"Get specific statistics by querying any stats table directly with optional filtering, ordering, and limits",
		{
			{"type", "object"},
			{"properties", {
				{"table", {
					{"type", "string"},
					{"description", "Stats table name (required, e.g. 'stats_mysql_query_digest')"}
				}},
				{"columns", {
					{"type", "array"},
					{"items", {{"type", "string"}}},
					{"description", "Columns to select (default: all)"}
				}},
				{"where", {
					{"type", "string"},
					{"description", "WHERE clause for filtering (e.g. \"count_star > 100\")"}
				}},
				{"order_by", {
					{"type", "string"},
					{"description", "ORDER BY clause (e.g. \"count_star DESC\")"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "LIMIT clause (default: 100)"},
					{"default", 100}
				}}
			}},
			{"required", {"table"}}
		}
	));

	// Performance, historical, and analysis tools

	tools.push_back(create_tool_description(
		"show_commands",
		"Returns command execution statistics with latency distribution (SELECT, INSERT, UPDATE, DELETE, etc.) "
		"including histogram buckets and calculated percentiles (p50, p90, p95, p99)",
		{
			{"type", "object"},
			{"properties", {
				{"command", {
					{"type", "string"},
					{"description", "Filter by specific command (e.g. SELECT, INSERT)"}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Filter by database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_users",
		"Shows connection statistics per user, including current connections, limits, and utilization",
		{
			{"type", "object"},
			{"properties", {
				{"username", {
					{"type", "string"},
					{"description", "Filter by specific username"}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Filter by database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_client_cache",
		"Shows client host cache for connection throttling - identifies blocked or throttled client IPs",
		{
			{"type", "object"},
			{"properties", {
				{"client_address", {
					{"type", "string"},
					{"description", "Filter by specific IP address"}
				}},
				{"min_error_count", {
					{"type", "integer"},
					{"description", "Only show hosts with error count >= N"}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Filter by database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_gtid",
		"Shows GTID (Global Transaction ID) replication information for MySQL backends",
		{
			{"type", "object"},
			{"properties", {
				{"hostname", {
					{"type", "string"},
					{"description", "Filter by specific backend server hostname"}
				}},
				{"port", {
					{"type", "integer"},
					{"description", "Filter by specific port"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_query_rules",
		"Shows hit counts for query routing rules, identifying heavily used and unused rules",
		{
			{"type", "object"},
			{"properties", {
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
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Filter by database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_history_connections",
		"Historical connection trends over time (raw/hourly/daily aggregates) for capacity planning",
		{
			{"type", "object"},
			{"properties", {
				{"resolution", {
					{"type", "string"},
					{"enum", {"raw", "hour", "day"}},
					{"description", "Time resolution (default: hour)"},
					{"default", "hour"}
				}},
				{"start_time", {
					{"type", "integer"},
					{"description", "Unix timestamp start (default: 24 hours ago)"}
				}},
				{"end_time", {
					{"type", "integer"},
					{"description", "Unix timestamp end (default: now)"}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Filter by database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"show_history_query_digest",
		"Historical query digest snapshots for trend analysis - compare query performance over time",
		{
			{"type", "object"},
			{"properties", {
				{"digest", {
					{"type", "string"},
					{"description", "Filter by specific query digest"}
				}},
				{"limit", {
					{"type", "integer"},
					{"description", "Max number of results (default: 100)"},
					{"default", 100}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql"}},
					{"description", "Filter by database type (default: mysql)"},
					{"default", "mysql"}
				}}
			}}
		}
	));

	tools.push_back(create_tool_description(
		"aggregate_metrics",
		"Perform custom aggregations (avg, sum, min, max, count) on metrics from global stats tables",
		{
			{"type", "object"},
			{"properties", {
				{"metric", {
					{"type", "string"},
					{"description", "Metric/variable name pattern to aggregate (e.g. 'Client_Connections', 'Questions')"}
				}},
				{"aggregation", {
					{"type", "string"},
					{"enum", {"avg", "sum", "min", "max", "count"}},
					{"description", "Aggregation function (default: sum)"},
					{"default", "sum"}
				}},
				{"database", {
					{"type", "string"},
					{"enum", {"mysql", "pgsql", "all"}},
					{"description", "Filter by database type (default: all)"},
					{"default", "all"}
				}}
			}},
			{"required", {"metric"}}
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
		// Core operational tools
		if (tool_name == "get_health") {
			result = handle_get_health(arguments);
		} else if (tool_name == "show_processlist") {
			result = handle_show_processlist(arguments);
		} else if (tool_name == "show_metrics") {
			result = handle_show_metrics(arguments);
		} else if (tool_name == "show_queries") {
			result = handle_show_queries(arguments);
		} else if (tool_name == "show_connections") {
			result = handle_show_connections(arguments);
		} else if (tool_name == "show_errors") {
			result = handle_show_errors(arguments);
		} else if (tool_name == "show_cluster") {
			result = handle_show_cluster(arguments);
		} else if (tool_name == "list_stats") {
			result = handle_list_stats(arguments);
		} else if (tool_name == "get_stats") {
			result = handle_get_stats(arguments);
		}
		// Performance, historical, and analysis tools
		else if (tool_name == "show_commands") {
			result = handle_show_commands(arguments);
		} else if (tool_name == "show_users") {
			result = handle_show_users(arguments);
		} else if (tool_name == "show_client_cache") {
			result = handle_show_client_cache(arguments);
		} else if (tool_name == "show_gtid") {
			result = handle_show_gtid(arguments);
		} else if (tool_name == "show_query_rules") {
			result = handle_show_query_rules(arguments);
		} else if (tool_name == "show_history_connections") {
			result = handle_show_history_connections(arguments);
		} else if (tool_name == "show_history_query_digest") {
			result = handle_show_history_query_digest(arguments);
		} else if (tool_name == "aggregate_metrics") {
			result = handle_aggregate_metrics(arguments);
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
// Core Operational Tool Implementations
// ============================================================================

json Stats_Tool_Handler::handle_get_health(const json& arguments) {
	std::string database = arguments.value("database", "all");
	bool include_backend = arguments.value("include_backend", false);

	json health_data;
	health_data["timestamp"] = (long long)time(NULL);

	json alerts = json::array();
	int warning_count = 0;
	int critical_count = 0;

	// 1. Get MySQL global stats
	json connections_data;
	json queries_data;

	if (database == "mysql" || database == "all") {
		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string err = execute_admin_query(
			"SELECT Variable_Name, Variable_Value FROM stats.stats_mysql_global",
			&resultset, &cols
		);

		if (err.empty() && resultset) {
			auto stats = parse_global_stats(resultset);

			long long client_conn = 0, server_conn = 0, questions = 0, slow = 0;
			long long client_created = 0, server_created = 0;

			if (stats.count("Client_Connections_connected"))
				client_conn = std::stoll(stats["Client_Connections_connected"]);
			if (stats.count("Client_Connections_created"))
				client_created = std::stoll(stats["Client_Connections_created"]);
			if (stats.count("Server_Connections_connected"))
				server_conn = std::stoll(stats["Server_Connections_connected"]);
			if (stats.count("Server_Connections_created"))
				server_created = std::stoll(stats["Server_Connections_created"]);
			if (stats.count("Questions"))
				questions = std::stoll(stats["Questions"]);
			if (stats.count("Slow_queries"))
				slow = std::stoll(stats["Slow_queries"]);

			connections_data["client_connections"] = {
				{"connected", client_conn},
				{"created_lifetime", client_created},
				{"status", "normal"}
			};
			connections_data["server_connections"] = {
				{"connected", server_conn},
				{"created_lifetime", server_created},
				{"status", "normal"}
			};

			double slow_rate = (questions > 0) ? (double)slow / (double)questions : 0.0;
			queries_data["total"] = questions;
			queries_data["slow"] = slow;
			queries_data["slow_rate_pct"] = slow_rate * 100.0;

			// Check slow query rate
			if (slow_rate > 0.05) {
				critical_count++;
				alerts.push_back({
					{"severity", "critical"},
					{"metric", "slow_query_rate"},
					{"value", slow_rate * 100.0},
					{"threshold", 5.0},
					{"message", "Slow query rate exceeds critical threshold (5%)"}
				});
			} else if (slow_rate > 0.01) {
				warning_count++;
				alerts.push_back({
					{"severity", "warning"},
					{"metric", "slow_query_rate"},
					{"value", slow_rate * 100.0},
					{"threshold", 1.0},
					{"message", "Slow query rate exceeds warning threshold (1%)"}
				});
			}

			delete resultset;
		}
	}

	// 2. Get memory stats
	json memory_data;
	{
		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string err = execute_admin_query(
			"SELECT Variable_Name, Variable_Value FROM stats.stats_memory_metrics",
			&resultset, &cols
		);

		if (err.empty() && resultset) {
			auto stats = parse_global_stats(resultset);

			long long allocated = 0, resident = 0, active = 0;
			if (stats.count("Auth_memory"))
				allocated += std::stoll(stats["Auth_memory"]);
			if (stats.count("SQLite3_memory_bytes"))
				allocated += std::stoll(stats["SQLite3_memory_bytes"]);
			if (stats.count("query_digest_memory"))
				allocated += std::stoll(stats["query_digest_memory"]);

			// Use jemalloc metrics if available
			for (const auto& kv : stats) {
				if (kv.first.find("jemalloc") != std::string::npos) {
					if (kv.first.find("allocated") != std::string::npos) allocated = std::stoll(kv.second);
					else if (kv.first.find("resident") != std::string::npos) resident = std::stoll(kv.second);
					else if (kv.first.find("active") != std::string::npos) active = std::stoll(kv.second);
				}
			}

			memory_data["allocated_mb"] = allocated / (1024.0 * 1024.0);
			memory_data["resident_mb"] = resident / (1024.0 * 1024.0);
			memory_data["active_mb"] = active / (1024.0 * 1024.0);

			delete resultset;
		}
	}

	// 3. Get cluster stats
	json cluster_data;
	{
		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string err = execute_admin_query(
			"SELECT hostname, port, checks_OK, checks_ERR, ping_time_us FROM stats.stats_proxysql_servers_status",
			&resultset, &cols
		);

		if (err.empty() && resultset) {
			int total_nodes = resultset->rows_count;
			int online_nodes = 0;

			for (const auto& row : resultset->rows) {
				long long checks_ok = row->fields[2] ? std::stoll(row->fields[2]) : 0;
				long long checks_err = row->fields[3] ? std::stoll(row->fields[3]) : 0;
				double success_rate = (checks_ok + checks_err > 0) ?
					(double)checks_ok / (double)(checks_ok + checks_err) : 0.0;
				if (success_rate > 0.5) online_nodes++;
			}

			cluster_data["nodes_online"] = online_nodes;
			cluster_data["total_nodes"] = total_nodes;
			cluster_data["status"] = (total_nodes > 0 && online_nodes == total_nodes) ? "all_healthy" :
				(online_nodes > 0 ? "degraded" : "unhealthy");

			delete resultset;
		} else {
			cluster_data["nodes_online"] = 0;
			cluster_data["total_nodes"] = 0;
			cluster_data["status"] = "not_configured";
		}
	}

	// 4. Include backend connection pool summary if requested
	if (include_backend) {
		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string table = (database == "pgsql") ? "stats_pgsql_connection_pool" : "stats_mysql_connection_pool";
		std::string sql = "SELECT hostgroup, srv_host, srv_port, status, ConnUsed, ConnFree, ConnERR, Latency_us "
			"FROM stats." + table;

		std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);
		if (err.empty() && resultset) {
			json backends = json::array();
			for (const auto& row : resultset->rows) {
				json backend;
				backend["hostgroup"] = row->fields[0] ? std::stoi(row->fields[0]) : 0;
				backend["srv_host"] = row->fields[1] ? row->fields[1] : "";
				backend["srv_port"] = row->fields[2] ? std::stoi(row->fields[2]) : 0;
				backend["status"] = row->fields[3] ? row->fields[3] : "";
				int used = row->fields[4] ? std::stoi(row->fields[4]) : 0;
				int free = row->fields[5] ? std::stoi(row->fields[5]) : 0;
				backend["ConnUsed"] = used;
				backend["ConnFree"] = free;
				backend["utilization_pct"] = (used + free > 0) ? (double)used / (double)(used + free) * 100.0 : 0.0;
				backend["Latency_us"] = row->fields[7] ? std::stoi(row->fields[7]) : 0;
				backends.push_back(backend);
			}
			health_data["backend_servers"] = backends;
			delete resultset;
		}
	}

	// Determine overall health status
	if (critical_count > 0) {
		health_data["overall_status"] = "unhealthy";
		health_data["severity"] = "critical";
	} else if (warning_count > 0) {
		health_data["overall_status"] = "degraded";
		health_data["severity"] = "warning";
	} else {
		health_data["overall_status"] = "healthy";
		health_data["severity"] = "info";
	}

	health_data["summary"] = json::object();
	if (!connections_data.empty()) {
		health_data["summary"]["client_connections"] = connections_data["client_connections"];
		health_data["summary"]["server_connections"] = connections_data["server_connections"];
	}
	if (!queries_data.empty()) {
		health_data["summary"]["queries"] = queries_data;
	}
	if (!memory_data.empty()) {
		health_data["summary"]["memory"] = memory_data;
	}
	health_data["summary"]["cluster"] = cluster_data;
	health_data["alerts"] = alerts;

	return create_success_response(health_data);
}

json Stats_Tool_Handler::handle_show_processlist(const json& arguments) {
	std::string database = arguments.value("database", "mysql");
	std::string user_filter = arguments.value("user", "");
	int hostgroup_filter = arguments.value("hostgroup", -1);
	std::string backend_filter = arguments.value("backend", "");
	int min_time_ms = arguments.value("min_time_ms", -1);

	std::string table = (database == "pgsql") ? "stats_pgsql_processlist" : "stats_mysql_processlist";
	std::string db_col = (database == "pgsql") ? "database" : "db";

	std::string sql = "SELECT ThreadID, SessionID, user, " + db_col + ", cli_host, cli_port, "
		"hostgroup, srv_host, srv_port, command, time_ms, info "
		"FROM stats." + table + " WHERE 1=1";

	if (!user_filter.empty()) {
		sql += " AND user = '" + sql_escape(user_filter) + "'";
	}
	if (hostgroup_filter >= 0) {
		sql += " AND hostgroup = " + std::to_string(hostgroup_filter);
	}
	if (!backend_filter.empty()) {
		size_t colon = backend_filter.find(':');
		if (colon != std::string::npos) {
			std::string host = backend_filter.substr(0, colon);
			std::string port = backend_filter.substr(colon + 1);
			sql += " AND srv_host = '" + sql_escape(host) + "' AND srv_port = " + port;
		}
	}
	if (min_time_ms >= 0) {
		sql += " AND time_ms >= " + std::to_string(min_time_ms);
	}

	sql += " ORDER BY time_ms DESC";

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query processlist: " + err);
	}

	json sessions = json::array();
	std::map<std::string, int> by_user, by_hostgroup, by_command, by_backend;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			json session;
			session["thread_id"] = row->fields[0] ? std::stoi(row->fields[0]) : 0;
			session["session_id"] = row->fields[1] ? std::stoll(row->fields[1]) : 0;
			session["user"] = row->fields[2] ? row->fields[2] : "";
			session["database"] = row->fields[3] ? row->fields[3] : "";
			session["client_host"] = row->fields[4] ? row->fields[4] : "";
			session["client_port"] = row->fields[5] ? std::stoi(row->fields[5]) : 0;
			session["hostgroup"] = row->fields[6] ? std::stoi(row->fields[6]) : 0;
			session["backend_host"] = row->fields[7] ? row->fields[7] : "";
			session["backend_port"] = row->fields[8] ? std::stoi(row->fields[8]) : 0;
			session["command"] = row->fields[9] ? row->fields[9] : "";
			session["time_ms"] = row->fields[10] ? std::stoi(row->fields[10]) : 0;
			session["query"] = row->fields[11] ? row->fields[11] : "";
			sessions.push_back(session);

			// Aggregate summaries
			std::string u = row->fields[2] ? row->fields[2] : "unknown";
			std::string hg = row->fields[6] ? row->fields[6] : "unknown";
			std::string cmd = row->fields[9] ? row->fields[9] : "unknown";
			std::string be = std::string(row->fields[7] ? row->fields[7] : "") + ":" +
				std::string(row->fields[8] ? row->fields[8] : "0");

			by_user[u]++;
			by_hostgroup[hg]++;
			by_command[cmd]++;
			by_backend[be]++;
		}

		delete resultset;
	}

	json result;
	result["total_sessions"] = (int)sessions.size();
	result["database"] = database;
	result["sessions"] = sessions;
	result["summary"] = {
		{"by_user", by_user},
		{"by_hostgroup", by_hostgroup},
		{"by_command", by_command},
		{"by_backend", by_backend}
	};

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_metrics(const json& arguments) {
	std::string category = arguments.value("category", "all");
	std::string database = arguments.value("database", "all");
	std::string format = arguments.value("format", "prometheus");

	json metrics = json::array();
	long long ts = (long long)time(NULL);

	auto add_metric = [&](const std::string& name, const std::string& type,
		const std::string& help, long long value, const json& labels = json::object()) {
		json m;
		m["name"] = name;
		m["type"] = type;
		m["help"] = help;
		m["value"] = value;
		m["timestamp"] = ts;
		m["labels"] = labels;
		metrics.push_back(m);
	};

	// Connection metrics
	if (category == "connection" || category == "all") {
		auto fetch_global = [&](const std::string& db_type) {
			std::string table = "stats_" + db_type + "_global";
			SQLite3_result* resultset = NULL;
			int cols = 0;
			std::string sql = "SELECT Variable_Name, Variable_Value FROM stats." + table;
			std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

			if (err.empty() && resultset) {
				auto stats = parse_global_stats(resultset);

				json lbl = {{"database", db_type}};

				if (stats.count("Client_Connections_connected"))
					add_metric("proxysql_client_connections_connected", "gauge",
						"Number of active client connections", std::stoll(stats["Client_Connections_connected"]), lbl);
				if (stats.count("Client_Connections_created"))
					add_metric("proxysql_client_connections_created_total", "counter",
						"Total client connections created", std::stoll(stats["Client_Connections_created"]), lbl);
				if (stats.count("Server_Connections_connected"))
					add_metric("proxysql_server_connections_connected", "gauge",
						"Number of active server connections", std::stoll(stats["Server_Connections_connected"]), lbl);
				if (stats.count("Server_Connections_created"))
					add_metric("proxysql_server_connections_created_total", "counter",
						"Total server connections created", std::stoll(stats["Server_Connections_created"]), lbl);

				delete resultset;
			}
		};

		if (database == "mysql" || database == "all") fetch_global("mysql");
		if (database == "pgsql" || database == "all") fetch_global("pgsql");
	}

	// Query metrics
	if (category == "query" || category == "all") {
		auto fetch_query_metrics = [&](const std::string& db_type) {
			std::string table = "stats_" + db_type + "_global";
			SQLite3_result* resultset = NULL;
			int cols = 0;
			std::string sql = "SELECT Variable_Name, Variable_Value FROM stats." + table;
			std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

			if (err.empty() && resultset) {
				auto stats = parse_global_stats(resultset);
				json lbl = {{"database", db_type}};

				if (stats.count("Questions"))
					add_metric("proxysql_questions_total", "counter",
						"Total number of questions", std::stoll(stats["Questions"]), lbl);
				if (stats.count("Slow_queries"))
					add_metric("proxysql_slow_queries_total", "counter",
						"Total number of slow queries", std::stoll(stats["Slow_queries"]), lbl);

				delete resultset;
			}
		};

		if (database == "mysql" || database == "all") fetch_query_metrics("mysql");
		if (database == "pgsql" || database == "all") fetch_query_metrics("pgsql");
	}

	// Memory metrics
	if (category == "memory" || category == "all") {
		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string err = execute_admin_query(
			"SELECT Variable_Name, Variable_Value FROM stats.stats_memory_metrics",
			&resultset, &cols
		);

		if (err.empty() && resultset) {
			auto stats = parse_global_stats(resultset);
			for (const auto& kv : stats) {
				add_metric("proxysql_memory_bytes", "gauge",
					"Memory usage in bytes", std::stoll(kv.second),
					{{"type", kv.first}});
			}
			delete resultset;
		}
	}

	// Cluster metrics
	if (category == "cluster" || category == "all") {
		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string err = execute_admin_query(
			"SELECT hostname, port, weight, master, ping_time_us, checks_OK, checks_ERR "
			"FROM stats.stats_proxysql_servers_status",
			&resultset, &cols
		);

		if (err.empty() && resultset) {
			for (const auto& row : resultset->rows) {
				json lbl = {
					{"hostname", row->fields[0] ? row->fields[0] : ""},
					{"port", row->fields[1] ? row->fields[1] : ""}
				};

				if (row->fields[2])
					add_metric("proxysql_cluster_node_weight", "gauge",
						"Cluster node weight", std::stoll(row->fields[2]), lbl);
				if (row->fields[3])
					add_metric("proxysql_cluster_node_master", "gauge",
						"Whether node is master (1) or not (0)",
						std::string(row->fields[3]) == "TRUE" ? 1 : 0, lbl);
				if (row->fields[4])
					add_metric("proxysql_cluster_ping_time_us", "gauge",
						"Cluster node ping time in microseconds", std::stoll(row->fields[4]), lbl);
				if (row->fields[5])
					add_metric("proxysql_cluster_checks_ok_total", "counter",
						"Total successful health checks", std::stoll(row->fields[5]), lbl);
				if (row->fields[6])
					add_metric("proxysql_cluster_checks_error_total", "counter",
						"Total failed health checks", std::stoll(row->fields[6]), lbl);
			}
			delete resultset;
		}
	}

	json result;
	result["metrics"] = metrics;
	result["format"] = format;

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_queries(const json& arguments) {
	std::string database = arguments.value("database", "mysql");
	std::string sort_by = arguments.value("sort_by", "count");
	int limit = arguments.value("limit", 100);
	int min_count = arguments.value("min_count", 0);
	int min_time_us = arguments.value("min_time_us", 0);
	std::string schemaname = arguments.value("schemaname", "");
	std::string username = arguments.value("username", "");
	int hostgroup_filter = arguments.value("hostgroup", -1);
	std::string digest_filter = arguments.value("digest", "");
	bool include_top = arguments.value("include_top", true);

	std::string table = (database == "pgsql") ? "stats_pgsql_query_digest" : "stats_mysql_query_digest";
	std::string schema_col = (database == "pgsql") ? "database" : "schemaname";

	std::string sql = "SELECT hostgroup, " + schema_col + ", username, client_address, digest, "
		"digest_text, count_star, first_seen, last_seen, "
		"sum_time, min_time, max_time, sum_rows_affected, sum_rows_sent "
		"FROM stats." + table + " WHERE 1=1";

	if (min_count > 0) {
		sql += " AND count_star >= " + std::to_string(min_count);
	}
	if (!schemaname.empty()) {
		sql += " AND " + schema_col + " = '" + sql_escape(schemaname) + "'";
	}
	if (!username.empty()) {
		sql += " AND username = '" + sql_escape(username) + "'";
	}
	if (hostgroup_filter >= 0) {
		sql += " AND hostgroup = " + std::to_string(hostgroup_filter);
	}
	if (!digest_filter.empty()) {
		sql += " AND digest = '" + sql_escape(digest_filter) + "'";
	}

	// Sort order
	std::string order_col = "count_star";
	if (sort_by == "avg_time") order_col = "sum_time/count_star";
	else if (sort_by == "sum_time") order_col = "sum_time";
	else if (sort_by == "max_time") order_col = "max_time";
	else if (sort_by == "rows_sent") order_col = "sum_rows_sent";

	sql += " ORDER BY " + order_col + " DESC LIMIT " + std::to_string(limit);

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query digest: " + err);
	}

	json queries = json::array();
	long long total_queries = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long count_star = row->fields[6] ? std::stoll(row->fields[6]) : 0;
			long long sum_time = row->fields[9] ? std::stoll(row->fields[9]) : 0;
			long long min_time = row->fields[10] ? std::stoll(row->fields[10]) : 0;
			long long max_time = row->fields[11] ? std::stoll(row->fields[11]) : 0;
			long long avg_time = (count_star > 0) ? sum_time / count_star : 0;

			total_queries += count_star;

			// Classify performance tier
			std::string tier = "fast";
			if (avg_time > 1000000) tier = "very_slow";      // > 1s
			else if (avg_time > 100000) tier = "slow";        // > 100ms
			else if (avg_time > 10000) tier = "medium";       // > 10ms

			// Filter by min_time_us if specified
			if (min_time_us > 0 && avg_time < min_time_us) continue;

			json q;
			q["hostgroup"] = row->fields[0] ? std::stoi(row->fields[0]) : 0;
			q["schemaname"] = row->fields[1] ? row->fields[1] : "";
			q["username"] = row->fields[2] ? row->fields[2] : "";
			q["client_address"] = row->fields[3] ? row->fields[3] : "";
			q["digest"] = row->fields[4] ? row->fields[4] : "";
			q["digest_text"] = row->fields[5] ? row->fields[5] : "";
			q["count_star"] = count_star;
			q["first_seen"] = row->fields[7] ? std::stoll(row->fields[7]) : 0;
			q["last_seen"] = row->fields[8] ? std::stoll(row->fields[8]) : 0;
			q["sum_time_us"] = sum_time;
			q["min_time_us"] = min_time;
			q["max_time_us"] = max_time;
			q["avg_time_us"] = avg_time;
			q["sum_rows_affected"] = row->fields[12] ? std::stoll(row->fields[12]) : 0;
			q["sum_rows_sent"] = row->fields[13] ? std::stoll(row->fields[13]) : 0;
			q["performance_tier"] = tier;

			queries.push_back(q);
		}

		delete resultset;
	}

	json result;
	result["database"] = database;
	result["total_queries"] = total_queries;
	result["queries"] = queries;

	if (include_top && queries.size() > 0) {
		// Top 10 slowest by avg_time
		json top_slowest = json::array();
		json sorted_by_time = queries;
		std::sort(sorted_by_time.begin(), sorted_by_time.end(),
			[](const json& a, const json& b) {
				return a["avg_time_us"].get<long long>() > b["avg_time_us"].get<long long>();
			});
		for (size_t i = 0; i < std::min((size_t)10, sorted_by_time.size()); i++) {
			top_slowest.push_back({
				{"digest", sorted_by_time[i]["digest"]},
				{"digest_text", sorted_by_time[i]["digest_text"]},
				{"avg_time_us", sorted_by_time[i]["avg_time_us"]},
				{"count_star", sorted_by_time[i]["count_star"]}
			});
		}

		// Top 10 most frequent
		json top_frequent = json::array();
		json sorted_by_count = queries;
		std::sort(sorted_by_count.begin(), sorted_by_count.end(),
			[](const json& a, const json& b) {
				return a["count_star"].get<long long>() > b["count_star"].get<long long>();
			});
		for (size_t i = 0; i < std::min((size_t)10, sorted_by_count.size()); i++) {
			top_frequent.push_back({
				{"digest", sorted_by_count[i]["digest"]},
				{"digest_text", sorted_by_count[i]["digest_text"]},
				{"count_star", sorted_by_count[i]["count_star"]},
				{"avg_time_us", sorted_by_count[i]["avg_time_us"]}
			});
		}

		result["summary"] = {
			{"top_10_slowest", top_slowest},
			{"top_10_most_frequent", top_frequent}
		};
	}

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_connections(const json& arguments) {
	std::string database = arguments.value("database", "mysql");
	int hostgroup_filter = arguments.value("hostgroup", -1);
	std::string server_filter = arguments.value("server", "");
	std::string status_filter = arguments.value("status", "");

	std::string table = (database == "pgsql") ? "stats_pgsql_connection_pool" : "stats_mysql_connection_pool";

	std::string sql = "SELECT hostgroup, srv_host, srv_port, status, "
		"ConnUsed, ConnFree, ConnOK, ConnERR, MaxConnUsed, "
		"Queries, Bytes_data_sent, Bytes_data_recv, Latency_us "
		"FROM stats." + table + " WHERE 1=1";

	if (hostgroup_filter >= 0) {
		sql += " AND hostgroup = " + std::to_string(hostgroup_filter);
	}
	if (!server_filter.empty()) {
		size_t colon = server_filter.find(':');
		if (colon != std::string::npos) {
			std::string host = server_filter.substr(0, colon);
			std::string port = server_filter.substr(colon + 1);
			sql += " AND srv_host = '" + sql_escape(host) + "' AND srv_port = " + port;
		}
	}
	if (!status_filter.empty()) {
		sql += " AND status = '" + sql_escape(status_filter) + "'";
	}

	sql += " ORDER BY hostgroup, srv_host, srv_port";

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query connection pool: " + err);
	}

	json servers = json::array();
	int total_servers = 0, online_servers = 0;
	long long total_used = 0, total_free = 0, total_queries = 0;
	std::map<std::string, int> by_status;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			int conn_used = row->fields[4] ? std::stoi(row->fields[4]) : 0;
			int conn_free = row->fields[5] ? std::stoi(row->fields[5]) : 0;
			long long conn_ok = row->fields[6] ? std::stoll(row->fields[6]) : 0;
			long long conn_err = row->fields[7] ? std::stoll(row->fields[7]) : 0;
			long long queries = row->fields[9] ? std::stoll(row->fields[9]) : 0;
			std::string status = row->fields[3] ? row->fields[3] : "";

			double utilization = (conn_used + conn_free > 0) ?
				(double)conn_used / (double)(conn_used + conn_free) * 100.0 : 0.0;
			double error_rate = (conn_ok + conn_err > 0) ?
				(double)conn_err / (double)(conn_ok + conn_err) : 0.0;

			json server;
			server["hostgroup"] = row->fields[0] ? std::stoi(row->fields[0]) : 0;
			server["srv_host"] = row->fields[1] ? row->fields[1] : "";
			server["srv_port"] = row->fields[2] ? std::stoi(row->fields[2]) : 0;
			server["status"] = status;
			server["ConnUsed"] = conn_used;
			server["ConnFree"] = conn_free;
			server["ConnOK"] = conn_ok;
			server["ConnERR"] = conn_err;
			server["MaxConnUsed"] = row->fields[8] ? std::stoi(row->fields[8]) : 0;
			server["Queries"] = queries;
			server["Bytes_data_sent"] = row->fields[10] ? std::stoll(row->fields[10]) : 0;
			server["Bytes_data_recv"] = row->fields[11] ? std::stoll(row->fields[11]) : 0;
			server["Latency_us"] = row->fields[12] ? std::stoi(row->fields[12]) : 0;
			server["utilization_pct"] = utilization;
			server["error_rate"] = error_rate;

			servers.push_back(server);

			total_servers++;
			if (status == "ONLINE") online_servers++;
			total_used += conn_used;
			total_free += conn_free;
			total_queries += queries;
			by_status[status]++;
		}

		delete resultset;
	}

	json result;
	result["database"] = database;
	result["servers"] = servers;
	result["summary"] = {
		{"total_servers", total_servers},
		{"online_servers", online_servers},
		{"total_used", total_used},
		{"total_free", total_free},
		{"total_queries", total_queries},
		{"overall_utilization_pct", (total_used + total_free > 0) ?
			(double)total_used / (double)(total_used + total_free) * 100.0 : 0.0},
		{"by_status", by_status}
	};

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_errors(const json& arguments) {
	std::string database = arguments.value("database", "mysql");
	int errno_filter = arguments.value("errno", -1);
	std::string username = arguments.value("username", "");
	std::string schemaname = arguments.value("schemaname", "");
	int hostgroup_filter = arguments.value("hostgroup", -1);
	int min_count = arguments.value("min_count", 0);
	std::string sort_by = arguments.value("sort_by", "count");

	std::string table = (database == "pgsql") ? "stats_pgsql_errors" : "stats_mysql_errors";
	std::string schema_col = (database == "pgsql") ? "database" : "schemaname";
	std::string errno_col = (database == "pgsql") ? "sqlstate" : "errno";

	std::string sql = "SELECT hostgroup, hostname, port, username, client_address, "
		+ schema_col + ", " + errno_col + ", count_star, first_seen, last_seen, last_error "
		"FROM stats." + table + " WHERE 1=1";

	if (min_count > 0) {
		sql += " AND count_star >= " + std::to_string(min_count);
	}
	if (errno_filter >= 0) {
		sql += " AND " + errno_col + " = " + std::to_string(errno_filter);
	}
	if (!username.empty()) {
		sql += " AND username = '" + sql_escape(username) + "'";
	}
	if (!schemaname.empty()) {
		sql += " AND " + schema_col + " = '" + sql_escape(schemaname) + "'";
	}
	if (hostgroup_filter >= 0) {
		sql += " AND hostgroup = " + std::to_string(hostgroup_filter);
	}

	// Sort
	std::string order_col = "count_star";
	if (sort_by == "first_seen") order_col = "first_seen";
	else if (sort_by == "last_seen") order_col = "last_seen";
	sql += " ORDER BY " + order_col + " DESC";

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query errors: " + err);
	}

	json errors = json::array();
	long long total_occurrences = 0;
	std::map<std::string, long long> by_errno, by_username, by_schema, by_hostgroup;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long count = row->fields[7] ? std::stoll(row->fields[7]) : 0;
			long long first_seen = row->fields[8] ? std::stoll(row->fields[8]) : 0;
			long long last_seen = row->fields[9] ? std::stoll(row->fields[9]) : 0;

			total_occurrences += count;

			// Calculate frequency (errors per hour)
			double hours_since_first = 0;
			if (first_seen > 0) {
				hours_since_first = (double)(time(NULL) - first_seen) / 3600.0;
			}
			double freq_per_hour = (hours_since_first > 0) ? (double)count / hours_since_first : (double)count;

			json error;
			error["hostgroup"] = row->fields[0] ? std::stoi(row->fields[0]) : 0;
			error["hostname"] = row->fields[1] ? row->fields[1] : "";
			error["port"] = row->fields[2] ? std::stoi(row->fields[2]) : 0;
			error["username"] = row->fields[3] ? row->fields[3] : "";
			error["client_address"] = row->fields[4] ? row->fields[4] : "";
			error["schemaname"] = row->fields[5] ? row->fields[5] : "";
			error[errno_col] = row->fields[6] ? std::stoi(row->fields[6]) : 0;
			error["count_star"] = count;
			error["first_seen"] = first_seen;
			error["last_seen"] = last_seen;
			error["last_error"] = row->fields[10] ? row->fields[10] : "";
			error["frequency_per_hour"] = freq_per_hour;

			errors.push_back(error);

			// Aggregations
			std::string en = row->fields[6] ? row->fields[6] : "unknown";
			std::string un = row->fields[3] ? row->fields[3] : "unknown";
			std::string sn = row->fields[5] ? row->fields[5] : "unknown";
			std::string hg = row->fields[0] ? row->fields[0] : "unknown";
			by_errno[en] += count;
			by_username[un] += count;
			by_schema[sn] += count;
			by_hostgroup[hg] += count;
		}

		delete resultset;
	}

	json result;
	result["database"] = database;
	result["total_error_types"] = (int)errors.size();
	result["total_error_occurrences"] = total_occurrences;
	result["errors"] = errors;
	result["summary"] = {
		{"by_errno", by_errno},
		{"by_username", by_username},
		{"by_schemaname", by_schema},
		{"by_hostgroup", by_hostgroup}
	};

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_cluster(const json& arguments) {
	std::string hostname_filter = arguments.value("hostname", "");
	bool include_checksums = arguments.value("include_checksums", true);
	bool detailed_metrics = arguments.value("detailed_metrics", false);

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
			long long checks_ok = row->fields[7] ? std::stoll(row->fields[7]) : 0;
			long long checks_err = row->fields[8] ? std::stoll(row->fields[8]) : 0;
			double success_rate = (checks_ok + checks_err > 0) ?
				(double)checks_ok / (double)(checks_ok + checks_err) : 0.0;

			bool is_master = row->fields[3] && std::string(row->fields[3]) == "TRUE";
			long long ping = row->fields[6] ? std::stoll(row->fields[6]) : 0;

			json node;
			node["hostname"] = row->fields[0] ? row->fields[0] : "";
			node["port"] = row->fields[1] ? std::stoi(row->fields[1]) : 0;
			node["weight"] = row->fields[2] ? std::stoi(row->fields[2]) : 0;
			node["master"] = is_master;
			node["global_version"] = row->fields[4] ? std::stoi(row->fields[4]) : 0;
			node["check_age_us"] = row->fields[5] ? std::stoll(row->fields[5]) : 0;
			node["ping_time_us"] = ping;
			node["checks_ok"] = checks_ok;
			node["checks_error"] = checks_err;
			node["check_success_rate"] = success_rate;
			node["status"] = (success_rate > 0.5) ? "ONLINE" : "OFFLINE";

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

	// 2. Get detailed metrics if requested
	if (detailed_metrics) {
		std::string metrics_sql = "SELECT hostname, port, Uptime_s, Queries, Client_Connections_connected "
			"FROM stats.stats_proxysql_servers_metrics";
		if (!hostname_filter.empty()) {
			metrics_sql += " WHERE hostname = '" + sql_escape(hostname_filter) + "'";
		}

		SQLite3_result* metrics_rs = NULL;
		int mcols = 0;
		err = execute_admin_query(metrics_sql.c_str(), &metrics_rs, &mcols);

		if (err.empty() && metrics_rs) {
			for (const auto& mrow : metrics_rs->rows) {
				std::string host = mrow->fields[0] ? mrow->fields[0] : "";
				int port = mrow->fields[1] ? std::stoi(mrow->fields[1]) : 0;

				// Find matching node and add metrics
				for (auto& node : nodes) {
					if (node["hostname"] == host && node["port"] == port) {
						node["uptime_s"] = mrow->fields[2] ? std::stoll(mrow->fields[2]) : 0;
						node["queries"] = mrow->fields[3] ? std::stoll(mrow->fields[3]) : 0;
						node["client_connections"] = mrow->fields[4] ? std::stoll(mrow->fields[4]) : 0;
						break;
					}
				}
			}
			delete metrics_rs;
		}
	}

	// 3. Get checksums if requested
	json checksums = json::array();
	bool config_in_sync = true;

	if (include_checksums) {
		std::string cksum_sql = "SELECT hostname, port, name, version, epoch, checksum, changed_at, updated_at, diff_check "
			"FROM stats.stats_proxysql_servers_checksums";
		if (!hostname_filter.empty()) {
			cksum_sql += " WHERE hostname = '" + sql_escape(hostname_filter) + "'";
		}

		SQLite3_result* cksum_rs = NULL;
		int ccols = 0;
		err = execute_admin_query(cksum_sql.c_str(), &cksum_rs, &ccols);

		if (err.empty() && cksum_rs) {
			std::map<std::string, std::string> name_to_checksum;

			for (const auto& crow : cksum_rs->rows) {
				int diff_check = crow->fields[8] ? std::stoi(crow->fields[8]) : 0;
				std::string name = crow->fields[2] ? crow->fields[2] : "";
				std::string checksum = crow->fields[5] ? crow->fields[5] : "";

				if (diff_check > 0) config_in_sync = false;

				json cs;
				cs["hostname"] = crow->fields[0] ? crow->fields[0] : "";
				cs["port"] = crow->fields[1] ? std::stoi(crow->fields[1]) : 0;
				cs["name"] = name;
				cs["version"] = crow->fields[3] ? std::stoi(crow->fields[3]) : 0;
				cs["epoch"] = crow->fields[4] ? std::stoll(crow->fields[4]) : 0;
				cs["checksum"] = checksum;
				cs["changed_at"] = crow->fields[6] ? std::stoll(crow->fields[6]) : 0;
				cs["updated_at"] = crow->fields[7] ? std::stoll(crow->fields[7]) : 0;
				cs["diff_check"] = diff_check;
				cs["in_sync"] = (diff_check == 0);

				checksums.push_back(cs);
			}
			delete cksum_rs;
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
	result["summary"] = {
		{"avg_ping_time_us", (total_nodes > 0) ? total_ping / total_nodes : 0},
		{"config_in_sync", config_in_sync}
	};
	if (include_checksums) {
		result["checksums"] = checksums;
	}

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_list_stats(const json& arguments) {
	std::string filter = arguments.value("filter", "");
	std::string database = arguments.value("database", "all");

	// Query available stats tables from sqlite_master
	std::string sql = "SELECT name FROM stats.sqlite_master "
		"WHERE type='table' AND name LIKE 'stats_%'";

	if (!filter.empty()) {
		sql += " AND name LIKE '%" + sql_escape(filter) + "%'";
	}
	if (database == "mysql") {
		sql += " AND (name LIKE '%mysql%' OR name LIKE 'stats_memory%' OR name LIKE 'stats_proxysql%')";
	} else if (database == "pgsql") {
		sql += " AND (name LIKE '%pgsql%' OR name LIKE 'stats_memory%' OR name LIKE 'stats_proxysql%')";
	}

	sql += " ORDER BY name";

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to list stats tables: " + err);
	}

	json tables = json::array();
	json categories;
	categories["connection"] = json::array();
	categories["query"] = json::array();
	categories["error"] = json::array();
	categories["cluster"] = json::array();
	categories["memory"] = json::array();
	categories["other"] = json::array();

	if (resultset) {
		for (const auto& row : resultset->rows) {
			std::string name = row->fields[0] ? row->fields[0] : "";

			// Get row count for this table
			std::string count_sql = "SELECT COUNT(*) FROM stats." + name;
			SQLite3_result* count_rs = NULL;
			int ccols = 0;
			long long row_count = 0;
			std::string count_err = execute_admin_query(count_sql.c_str(), &count_rs, &ccols);
			if (count_err.empty() && count_rs && count_rs->rows_count > 0) {
				row_count = count_rs->rows[0]->fields[0] ? std::stoll(count_rs->rows[0]->fields[0]) : 0;
			}
			if (count_rs) delete count_rs;

			json table_info;
			table_info["name"] = name;
			table_info["row_count"] = row_count;

			tables.push_back(table_info);

			// Categorize
			if (name.find("connection") != std::string::npos || name.find("processlist") != std::string::npos) {
				categories["connection"].push_back(name);
			} else if (name.find("query") != std::string::npos || name.find("commands") != std::string::npos) {
				categories["query"].push_back(name);
			} else if (name.find("error") != std::string::npos || name.find("client_host") != std::string::npos) {
				categories["error"].push_back(name);
			} else if (name.find("proxysql_servers") != std::string::npos) {
				categories["cluster"].push_back(name);
			} else if (name.find("memory") != std::string::npos) {
				categories["memory"].push_back(name);
			} else {
				categories["other"].push_back(name);
			}
		}

		delete resultset;
	}

	json result;
	result["database"] = database;
	result["tables"] = tables;
	result["categories"] = categories;

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_get_stats(const json& arguments) {
	if (!arguments.contains("table")) {
		return create_error_response("Missing required parameter: table");
	}

	std::string table = arguments["table"].get<std::string>();

	// Validate table name
	if (!is_valid_stats_table(table)) {
		return create_error_response("Invalid or disallowed table name: " + table +
			". Table must start with a valid stats prefix (e.g. stats_mysql_, stats_pgsql_, stats_proxysql_, etc.)");
	}

	// Build SQL
	std::string columns_str = "*";
	if (arguments.contains("columns") && arguments["columns"].is_array() && !arguments["columns"].empty()) {
		columns_str = "";
		for (size_t i = 0; i < arguments["columns"].size(); i++) {
			if (i > 0) columns_str += ", ";
			columns_str += sql_escape(arguments["columns"][i].get<std::string>());
		}
	}

	// Determine which schema prefix to use
	std::string schema_prefix = "stats.";
	if (table.find("history_") == 0 || table.find("mysql_connections") == 0 ||
		table.find("pgsql_connections") == 0 || table.find("mysql_query_cache") == 0 ||
		table.find("system_") == 0 || table.find("myhgm_") == 0) {
		schema_prefix = "stats_history.";
	}

	std::string sql = "SELECT " + columns_str + " FROM " + schema_prefix + table;

	if (arguments.contains("where") && arguments["where"].is_string() && !arguments["where"].get<std::string>().empty()) {
		sql += " WHERE " + arguments["where"].get<std::string>();
	}
	if (arguments.contains("order_by") && arguments["order_by"].is_string() && !arguments["order_by"].get<std::string>().empty()) {
		sql += " ORDER BY " + arguments["order_by"].get<std::string>();
	}

	int limit = arguments.value("limit", 100);
	sql += " LIMIT " + std::to_string(limit);

	SQLite3_result* resultset = NULL;
	int cols = 0;

	std::string err;
	if (schema_prefix == "stats_history.") {
		err = execute_statsdb_disk_query(sql.c_str(), &resultset, &cols);
	} else {
		err = execute_admin_query(sql.c_str(), &resultset, &cols);
	}

	if (!err.empty()) {
		return create_error_response("Query failed: " + err);
	}

	json rows = resultset_to_json(resultset, cols);
	int row_count = resultset ? resultset->rows_count : 0;

	if (resultset) delete resultset;

	json result;
	result["table"] = table;
	result["query"] = sql;
	result["rows"] = rows;
	result["row_count"] = row_count;

	return create_success_response(result);
}

// ============================================================================
// Performance, Historical, and Analysis Tool Implementations
// ============================================================================

json Stats_Tool_Handler::handle_show_commands(const json& arguments) {
	std::string database = arguments.value("database", "mysql");
	std::string command_filter = arguments.value("command", "");

	std::string table = (database == "pgsql") ? "stats_pgsql_commands_counters" : "stats_mysql_commands_counters";

	std::string sql = "SELECT Command, Total_Time_us, Total_cnt, "
		"cnt_100us, cnt_500us, cnt_1ms, cnt_5ms, cnt_10ms, cnt_50ms, "
		"cnt_100ms, cnt_500ms, cnt_1s, cnt_5s, cnt_10s, cnt_INFs "
		"FROM stats." + table;

	if (!command_filter.empty()) {
		sql += " WHERE Command = '" + sql_escape(command_filter) + "'";
	}

	sql += " ORDER BY Total_cnt DESC";

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query commands: " + err);
	}

	json commands = json::array();
	long long total_commands = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long total_time = row->fields[1] ? std::stoll(row->fields[1]) : 0;
			long long total_cnt = row->fields[2] ? std::stoll(row->fields[2]) : 0;
			long long avg_time = (total_cnt > 0) ? total_time / total_cnt : 0;

			total_commands += total_cnt;

			// Parse histogram buckets
			std::vector<int> buckets;
			for (int i = 3; i <= 14 && i < (int)resultset->column_definition.size(); i++) {
				buckets.push_back(row->fields[i] ? std::stoi(row->fields[i]) : 0);
			}

			json cmd;
			cmd["command"] = row->fields[0] ? row->fields[0] : "";
			cmd["total_cnt"] = total_cnt;
			cmd["total_time_us"] = total_time;
			cmd["avg_time_us"] = avg_time;
			cmd["latency_distribution"] = {
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

			// Calculate percentiles from histogram
			cmd["percentiles"] = {
				{"p50", calculate_percentile_from_histogram(buckets, LATENCY_BUCKET_THRESHOLDS, 0.50)},
				{"p90", calculate_percentile_from_histogram(buckets, LATENCY_BUCKET_THRESHOLDS, 0.90)},
				{"p95", calculate_percentile_from_histogram(buckets, LATENCY_BUCKET_THRESHOLDS, 0.95)},
				{"p99", calculate_percentile_from_histogram(buckets, LATENCY_BUCKET_THRESHOLDS, 0.99)}
			};

			commands.push_back(cmd);
		}

		delete resultset;
	}

	json result;
	result["database"] = database;
	result["commands"] = commands;
	result["summary"] = {{"total_commands", total_commands}};

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_users(const json& arguments) {
	std::string database = arguments.value("database", "mysql");
	std::string username_filter = arguments.value("username", "");

	std::string table = (database == "pgsql") ? "stats_pgsql_users" : "stats_mysql_users";

	std::string sql = "SELECT username, frontend_connections, frontend_max_connections "
		"FROM stats." + table;

	if (!username_filter.empty()) {
		sql += " WHERE username = '" + sql_escape(username_filter) + "'";
	}

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query users: " + err);
	}

	json users = json::array();
	int total_users = 0;
	long long total_connections = 0, total_capacity = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			int connections = row->fields[1] ? std::stoi(row->fields[1]) : 0;
			int max_connections = row->fields[2] ? std::stoi(row->fields[2]) : 0;
			double utilization = (max_connections > 0) ? (double)connections / (double)max_connections * 100.0 : 0.0;

			std::string status = "normal";
			if (max_connections > 0 && connections >= max_connections) status = "at_limit";
			else if (max_connections > 0 && utilization >= 80.0) status = "near_limit";

			json user;
			user["username"] = row->fields[0] ? row->fields[0] : "";
			user["frontend_connections"] = connections;
			user["frontend_max_connections"] = max_connections;
			user["utilization_pct"] = utilization;
			user["status"] = status;

			users.push_back(user);

			total_users++;
			total_connections += connections;
			total_capacity += max_connections;
		}

		delete resultset;
	}

	json result;
	result["database"] = database;
	result["users"] = users;
	result["summary"] = {
		{"total_users", total_users},
		{"total_connections", total_connections},
		{"total_capacity", total_capacity},
		{"overall_utilization_pct", (total_capacity > 0) ? (double)total_connections / (double)total_capacity * 100.0 : 0.0}
	};

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_client_cache(const json& arguments) {
	std::string database = arguments.value("database", "mysql");
	std::string client_filter = arguments.value("client_address", "");
	int min_error_count = arguments.value("min_error_count", 0);

	std::string table = (database == "pgsql") ? "stats_pgsql_client_host_cache" : "stats_mysql_client_host_cache";

	std::string sql = "SELECT client_address, error_count, last_updated "
		"FROM stats." + table + " WHERE 1=1";

	if (!client_filter.empty()) {
		sql += " AND client_address = '" + sql_escape(client_filter) + "'";
	}
	if (min_error_count > 0) {
		sql += " AND error_count >= " + std::to_string(min_error_count);
	}

	sql += " ORDER BY error_count DESC";

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query client host cache: " + err);
	}

	json hosts = json::array();
	int total_hosts = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			json host;
			host["client_address"] = row->fields[0] ? row->fields[0] : "";
			host["error_count"] = row->fields[1] ? std::stoi(row->fields[1]) : 0;
			host["last_updated"] = row->fields[2] ? std::stoll(row->fields[2]) : 0;

			hosts.push_back(host);
			total_hosts++;
		}

		delete resultset;
	}

	json result;
	result["database"] = database;
	result["total_hosts"] = total_hosts;
	result["hosts"] = hosts;

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_gtid(const json& arguments) {
	std::string hostname_filter = arguments.value("hostname", "");
	int port_filter = arguments.value("port", -1);

	std::string sql = "SELECT hostname, port, gtid_executed, events "
		"FROM stats.stats_mysql_gtid_executed WHERE 1=1";

	if (!hostname_filter.empty()) {
		sql += " AND hostname = '" + sql_escape(hostname_filter) + "'";
	}
	if (port_filter > 0) {
		sql += " AND port = " + std::to_string(port_filter);
	}

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query GTID: " + err);
	}

	json gtid_info = json::array();
	long long total_events = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long events = row->fields[3] ? std::stoll(row->fields[3]) : 0;
			total_events += events;

			json info;
			info["hostname"] = row->fields[0] ? row->fields[0] : "";
			info["port"] = row->fields[1] ? std::stoi(row->fields[1]) : 0;
			info["gtid_executed"] = row->fields[2] ? row->fields[2] : "";
			info["events"] = events;

			gtid_info.push_back(info);
		}

		delete resultset;
	}

	json result;
	result["gtid_info"] = gtid_info;
	result["summary"] = {
		{"total_events", total_events},
		{"total_servers", (int)gtid_info.size()}
	};

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_query_rules(const json& arguments) {
	std::string database = arguments.value("database", "mysql");
	int rule_id_filter = arguments.value("rule_id", -1);
	int min_hits = arguments.value("min_hits", 0);
	bool include_zero_hits = arguments.value("include_zero_hits", false);

	std::string table = (database == "pgsql") ? "stats_pgsql_query_rules" : "stats_mysql_query_rules";

	std::string sql = "SELECT rule_id, hits FROM stats." + table + " WHERE 1=1";

	if (rule_id_filter >= 0) {
		sql += " AND rule_id = " + std::to_string(rule_id_filter);
	}
	if (!include_zero_hits) {
		sql += " AND hits > 0";
	}
	if (min_hits > 0) {
		sql += " AND hits >= " + std::to_string(min_hits);
	}

	sql += " ORDER BY hits DESC";

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query query rules: " + err);
	}

	json rules = json::array();
	long long total_hits = 0;
	int unused_rules = 0;

	if (resultset) {
		for (const auto& row : resultset->rows) {
			long long hits = row->fields[1] ? std::stoll(row->fields[1]) : 0;
			total_hits += hits;
			if (hits == 0) unused_rules++;

			json rule;
			rule["rule_id"] = row->fields[0] ? std::stoi(row->fields[0]) : 0;
			rule["hits"] = hits;

			rules.push_back(rule);
		}

		delete resultset;
	}

	json result;
	result["database"] = database;
	result["total_rules"] = (int)rules.size();
	result["rules"] = rules;
	result["summary"] = {
		{"total_hits", total_hits},
		{"unused_rules", unused_rules}
	};

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_history_connections(const json& arguments) {
	std::string database = arguments.value("database", "mysql");
	std::string resolution = arguments.value("resolution", "hour");
	long long start_time = arguments.value("start_time", (long long)(time(NULL) - 86400));
	long long end_time = arguments.value("end_time", (long long)time(NULL));

	// Choose table based on resolution
	std::string db_prefix = (database == "pgsql") ? "pgsql" : "mysql";
	std::string table = db_prefix + "_connections";
	if (resolution == "hour") table = db_prefix + "_connections_hour";
	else if (resolution == "day") table = db_prefix + "_connections_day";

	std::string sql = "SELECT * FROM " + table +
		" WHERE timestamp >= " + std::to_string(start_time) +
		" AND timestamp <= " + std::to_string(end_time) +
		" ORDER BY timestamp ASC";

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_statsdb_disk_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query history connections: " + err);
	}

	json metrics_arr = resultset_to_json(resultset, cols);
	int data_points = resultset ? resultset->rows_count : 0;

	if (resultset) delete resultset;

	json result;
	result["database"] = database;
	result["resolution"] = resolution;
	result["time_range"] = {
		{"start", start_time},
		{"end", end_time},
		{"data_points", data_points}
	};
	result["metrics"] = metrics_arr;

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_show_history_query_digest(const json& arguments) {
	std::string database = arguments.value("database", "mysql");
	std::string digest_filter = arguments.value("digest", "");
	int limit = arguments.value("limit", 100);

	std::string table = (database == "pgsql") ? "history_pgsql_query_digest" : "history_mysql_query_digest";

	std::string sql = "SELECT * FROM " + table + " WHERE 1=1";

	if (!digest_filter.empty()) {
		sql += " AND digest = '" + sql_escape(digest_filter) + "'";
	}

	sql += " ORDER BY dump_time DESC, count_star DESC LIMIT " + std::to_string(limit);

	SQLite3_result* resultset = NULL;
	int cols = 0;
	std::string err = execute_statsdb_disk_query(sql.c_str(), &resultset, &cols);

	if (!err.empty()) {
		return create_error_response("Failed to query history query digest: " + err);
	}

	json rows = resultset_to_json(resultset, cols);
	int row_count = resultset ? resultset->rows_count : 0;

	if (resultset) delete resultset;

	json result;
	result["database"] = database;
	result["queries"] = rows;
	result["row_count"] = row_count;

	return create_success_response(result);
}

json Stats_Tool_Handler::handle_aggregate_metrics(const json& arguments) {
	if (!arguments.contains("metric")) {
		return create_error_response("Missing required parameter: metric");
	}

	std::string metric = arguments["metric"].get<std::string>();
	std::string aggregation = arguments.value("aggregation", "sum");
	std::string database = arguments.value("database", "all");

	json results_arr = json::array();

	auto aggregate_from_table = [&](const std::string& db_type) {
		std::string table = "stats_" + db_type + "_global";
		SQLite3_result* resultset = NULL;
		int cols = 0;
		std::string sql = "SELECT Variable_Name, Variable_Value FROM stats." + table +
			" WHERE Variable_Name LIKE '%" + sql_escape(metric) + "%'";

		std::string err = execute_admin_query(sql.c_str(), &resultset, &cols);

		if (err.empty() && resultset) {
			auto stats = parse_global_stats(resultset);

			for (const auto& kv : stats) {
				try {
					long long val = std::stoll(kv.second);
					results_arr.push_back({
						{"database", db_type},
						{"variable", kv.first},
						{"value", val}
					});
				} catch (...) {
					// Skip non-numeric values
				}
			}

			delete resultset;
		}
	};

	if (database == "mysql" || database == "all") aggregate_from_table("mysql");
	if (database == "pgsql" || database == "all") aggregate_from_table("pgsql");

	// Perform aggregation
	long long agg_result = 0;
	if (!results_arr.empty()) {
		std::vector<long long> values;
		for (const auto& r : results_arr) {
			values.push_back(r["value"].get<long long>());
		}

		if (aggregation == "sum") {
			agg_result = std::accumulate(values.begin(), values.end(), 0LL);
		} else if (aggregation == "avg") {
			agg_result = std::accumulate(values.begin(), values.end(), 0LL) / (long long)values.size();
		} else if (aggregation == "min") {
			agg_result = *std::min_element(values.begin(), values.end());
		} else if (aggregation == "max") {
			agg_result = *std::max_element(values.begin(), values.end());
		} else if (aggregation == "count") {
			agg_result = (long long)values.size();
		}
	}

	json result;
	result["metric"] = metric;
	result["aggregation"] = aggregation;
	result["database"] = database;
	result["aggregated_value"] = agg_result;
	result["details"] = results_arr;

	return create_success_response(result);
}
