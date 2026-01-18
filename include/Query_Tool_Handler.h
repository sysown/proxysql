#ifndef CLASS_QUERY_TOOL_HANDLER_H
#define CLASS_QUERY_TOOL_HANDLER_H

#include "MCP_Tool_Handler.h"
#include "Discovery_Schema.h"
#include "Static_Harvester.h"
#include <pthread.h>

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
	// MySQL connection configuration
	std::string mysql_hosts;
	std::string mysql_ports;
	std::string mysql_user;
	std::string mysql_password;
	std::string mysql_schema;

	// Discovery components (NEW - replaces MySQL_Tool_Handler wrapper)
	Discovery_Schema* catalog;       ///< Discovery catalog (replaces old MySQL_Catalog)
	Static_Harvester* harvester;       ///< Static harvester for Phase 1

	// Connection pool for MySQL queries
	struct MySQLConnection {
		void* mysql;           ///< MySQL connection handle (MYSQL*)
		std::string host;
		int port;
		bool in_use;
	};
	std::vector<MySQLConnection> connection_pool;
	pthread_mutex_t pool_lock;
	int pool_size;

	// Query guardrails
	int max_rows;
	int timeout_ms;
	bool allow_select_star;

	// Tool usage counters: tool_name -> schema_name -> count
	typedef std::map<std::string, unsigned long long> SchemaCountMap;
	typedef std::map<std::string, SchemaCountMap> ToolUsageMap;
	ToolUsageMap tool_usage_counters;
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
	 * @brief Get a connection from the pool
	 */
	void* get_connection();

	/**
	 * @brief Return a connection to the pool
	 */
	void return_connection(void* mysql);

	/**
	 * @brief Execute a query and return results as JSON
	 */
	std::string execute_query(const std::string& query);

	/**
	 * @brief Validate SQL is read-only
	 */
	bool validate_readonly_query(const std::string& query);

	/**
	 * @brief Check if SQL contains dangerous keywords
	 */
	bool is_dangerous_query(const std::string& query);

	// Friend function for tracking tool invocations
	friend void track_tool_invocation(Query_Tool_Handler*, const std::string&, const std::string&);

public:
	/**
	 * @brief Constructor (creates catalog and harvester)
	 */
	Query_Tool_Handler(
		const std::string& hosts,
		const std::string& ports,
		const std::string& user,
		const std::string& password,
		const std::string& schema,
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
	Static_Harvester* get_harvester() const { return harvester; }

	/**
	 * @brief Get tool usage statistics (thread-safe copy)
	 * @return ToolUsageMap copy with tool_name -> schema_name -> count
	 */
	ToolUsageMap get_tool_usage_stats();

	/**
	 * @brief Get tool usage statistics as SQLite3_result* with optional reset
	 * @param reset If true, resets internal counters after capturing data
	 * @return SQLite3_result* with columns: tool, schema, count. Caller must delete.
	 */
	SQLite3_result* get_tool_usage_stats_resultset(bool reset = false);
};

#endif /* CLASS_QUERY_TOOL_HANDLER_H */
