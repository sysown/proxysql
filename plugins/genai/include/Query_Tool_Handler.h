#ifndef CLASS_QUERY_TOOL_HANDLER_H
#define CLASS_QUERY_TOOL_HANDLER_H

#ifdef PROXYSQL40

#include "MCP_Tool_Handler.h"
#include "Discovery_Schema.h"
#include <pthread.h>

// Forward declaration to avoid circular include
class Static_Harvester;
class PgSQL_Static_Harvester;

/**
 * @brief Query Tool Handler for /mcp/query endpoint
 *
 * This handler provides tools for safe database exploration and query execution.
 * It now uses the comprehensive Discovery_Schema for catalog operations and includes
 * the two-phase discovery tools.
 *
 * Tools provided:
 * - Inventory: list_schemas, list_tables, describe_table, get_constraints
 * - Profiling: table_profile, column_profile
 * - Sampling: sample_rows, sample_distinct
 * - Query: run_sql_readonly, explain_sql
 * - Relationships: suggest_joins, find_reference_candidates
 * - Discovery (NEW): discovery.run_static, agent.*, llm.*
 * - Catalog (NEW): All catalog tools now use Discovery_Schema
 */
class Query_Tool_Handler : public MCP_Tool_Handler {
private:
	// Logical query targets discovered from runtime hostgroups
	struct QueryTarget {
		std::string target_id;     ///< Opaque MCP-visible target identifier
		std::string description;   ///< Human-readable target description
		std::string protocol;      ///< Internal protocol: mysql|pgsql
		int hostgroup_id;          ///< Internal hostgroup identifier
		std::string auth_profile_id; ///< Server-side auth profile identifier
		std::string db_username;   ///< Backend DB username (from auth profile)
		std::string db_password;   ///< Backend DB password (from auth profile)
		std::string default_schema; ///< Backend default schema/database
		std::string host;          ///< Concrete host used by executor
		int port;                  ///< Concrete port used by executor
		bool executable;           ///< True if current handler can execute against this target
	};

	std::string default_target_id;

	// Discovery components (NEW - replaces MySQL_Tool_Handler wrapper)
	Discovery_Schema* catalog;       ///< Discovery catalog (replaces old MySQL_Catalog)
	Static_Harvester* mysql_harvester;       ///< MySQL static harvester for Phase 1
	PgSQL_Static_Harvester* pgsql_harvester; ///< PostgreSQL static harvester for Phase 1

	// Connection pool for MySQL queries
	struct MySQLConnection {
		void* mysql;           ///< MySQL connection handle (MYSQL*)
		std::string target_id;
		std::string auth_profile_id;
		std::string host;
		int port;
		bool in_use;
		std::string current_schema;  ///< Track current schema for this connection
	};
	struct PgSQLConnection {
		void* pgconn;          ///< PostgreSQL connection handle (PGconn*)
		std::string target_id;
		std::string auth_profile_id;
		std::string host;
		int port;
		bool in_use;
		std::string current_schema;  ///< Track current schema for this connection
	};
	std::vector<MySQLConnection> connection_pool;
	std::vector<PgSQLConnection> pgsql_connection_pool;
	std::vector<QueryTarget> target_registry;
	pthread_mutex_t pool_lock;
	int pool_size;      ///< MySQL pool size
	int pg_pool_size;   ///< PostgreSQL pool size

	// Query guardrails
	int max_rows;
	int timeout_ms;
	bool allow_select_star;

	// Statistics for a specific (tool, schema) pair
	struct ToolUsageStats {
		unsigned long long count;
		unsigned long long first_seen;
		unsigned long long last_seen;
		unsigned long long sum_time;
		unsigned long long min_time;
		unsigned long long max_time;

		ToolUsageStats() : count(0), first_seen(0), last_seen(0),
		                   sum_time(0), min_time(0), max_time(0) {}

		void add_timing(unsigned long long duration, unsigned long long timestamp) {
			count++;
			sum_time += duration;
			if (duration < min_time || min_time == 0) {
				if (duration) min_time = duration;
			}
			if (duration > max_time) {
				max_time = duration;
			}
			if (first_seen == 0) {
				first_seen = timestamp;
			}
			last_seen = timestamp;
		}
	};

	// Tool usage counters: endpoint -> tool_name -> schema_name -> ToolUsageStats
	typedef std::map<std::string, ToolUsageStats> SchemaStatsMap;
	typedef std::map<std::string, SchemaStatsMap> ToolStatsMap;
	typedef std::map<std::string, ToolStatsMap> ToolUsageStatsMap;
	ToolUsageStatsMap tool_usage_stats;
	pthread_mutex_t counters_lock;

	/**
	 * @brief Create tool list schema for a tool
	 */
	json create_tool_schema(
		const std::string& tool_name,
		const std::string& description,
		const std::vector<std::string>& required_params,
		const std::map<std::string, std::string>& optional_params
	);

	/**
	 * @brief Initialize MySQL connection pool
	 */
	int init_connection_pool();

	/**
	 * @brief Discover logical targets from runtime hostgroups
	 */
	void refresh_target_registry();

	/**
	 * @brief Resolve target id (or default target if empty)
	 */
	const QueryTarget* resolve_target(const std::string& target_id);
	std::string format_target_unavailable_error(const std::string& target_id) const;

	/**
	 * @brief Get a connection from the pool
	 */
	void* get_connection(const std::string& target_id);
	void* get_pgsql_connection(const std::string& target_id);

	/**
	 * @brief Return a connection to the pool
	 */
	void return_connection(void* mysql);

	/**
	 * @brief Find connection wrapper by mysql pointer (for internal use)
	 * @param mysql_ptr MySQL connection pointer
	 * @return Pointer to connection wrapper, or nullptr if not found
	 * @note Caller should NOT hold pool_lock when calling this
	 */
	MySQLConnection* find_connection(void* mysql_ptr);
	PgSQLConnection* find_pgsql_connection(void* pgconn_ptr);

	/**
	 * @brief Execute a query and return results as JSON
	 */
	std::string execute_query(const std::string& query, const std::string& target_id = "");

	/**
	 * @brief Execute a query with optional schema switching
	 * @param query SQL query to execute
	 * @param schema Schema name to switch to (empty = use default)
	 * @return JSON result with success flag and rows/error
	 */
	std::string execute_query_with_schema(
		const std::string& query,
		const std::string& schema,
		const std::string& target_id
	);

	/**
	 * @brief Validate SQL is read-only
	 */
	bool validate_readonly_query(const std::string& query);

	/**
	 * @brief Detect multi-statement payloads
	 *
	 * GHSA-7wh6-2vcc-gcm4: returns true if @p query contains a ';'
	 * outside of string literals, identifier quoting (backticks), or
	 * comments, followed by any non-whitespace content (i.e. a second
	 * statement).  A bare trailing ';' is permitted.
	 */
	bool contains_multi_statement(const std::string& query);

	/**
	 * @brief Check if SQL contains dangerous keywords
	 */
	bool is_dangerous_query(const std::string& query);

	/**
	 * @brief Strip simple SQL comments from the start of a query
	 *
	 * Removes leading '-- ' style comments from SQL queries.
	 * Handles multiple comment lines and whitespace before/after comments.
	 * This is a simple pre-processing step to allow queries with leading comments.
	 *
	 * @param sql The SQL query that may have leading comments
	 * @return SQL query with leading comments removed
	 *
	 * @note Only removes comments from the START of the query
	 * @note Does not handle inline comments (comments within the query)
	 * @note Does not handle block comments
	 */
	std::string strip_leading_comments(const std::string& sql);

	// Friend function for tracking tool invocations
	friend void track_tool_invocation(Query_Tool_Handler*, const std::string&, const std::string&, const std::string&, unsigned long long);

	// Friend class for unit testing private methods
	friend class QueryToolHandlerUnitTest;

public:
	/**
	 * @brief Constructor (creates catalog and harvester)
	 */
	Query_Tool_Handler(
		const std::string& catalog_path
	);

	/**
	 * @brief Destructor
	 */
	~Query_Tool_Handler() override;

	// MCP_Tool_Handler interface implementation
	json get_tool_list() override;
	json get_tool_description(const std::string& tool_name) override;
	json execute_tool(const std::string& tool_name, const json& arguments) override;
	int init() override;
	void close() override;
	std::string get_handler_name() const override { return "query"; }

	/**
	 * @brief Get the discovery catalog
	 */
	Discovery_Schema* get_catalog() const { return catalog; }

	/**
	 * @brief Get the static harvester
	 */
	Static_Harvester* get_harvester() const { return mysql_harvester; }

	/**
	 * @brief Get tool usage statistics (thread-safe copy)
	 * @return ToolUsageStatsMap copy with endpoint -> tool_name -> schema_name -> ToolUsageStats
	 */
	ToolUsageStatsMap get_tool_usage_stats();

	/**
	 * @brief Get tool usage statistics as SQLite3_result* with optional reset
	 * @param reset If true, resets internal counters after capturing data
	 * @return SQLite3_result* with columns: endpoint, tool, schema, count, first_seen, last_seen, sum_time, min_time, max_time. Caller must delete.
	 */
	SQLite3_result* get_tool_usage_stats_resultset(bool reset = false);
};

// Free helper functions (defined in Query_Tool_Handler.cpp, exposed for unit testing)
std::string validate_sql_identifier_sqlite(const std::string& identifier);
std::string escape_string_literal(const std::string& value);
bool is_pgsql_protocol(const std::string& protocol);
bool is_runtime_online_status(const std::string& status);
std::string uppercase_or_unknown(const char* s);
std::string json_string(const nlohmann::json& j, const std::string& key, const std::string& default_val = "");
int json_int(const nlohmann::json& j, const std::string& key, int default_val = 0);
double json_double(const nlohmann::json& j, const std::string& key, double default_val = 0.0);

#endif /* PROXYSQL40 */

#endif /* CLASS_QUERY_TOOL_HANDLER_H */
