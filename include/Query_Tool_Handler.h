#ifndef CLASS_QUERY_TOOL_HANDLER_H
#define CLASS_QUERY_TOOL_HANDLER_H

#include "MCP_Tool_Handler.h"
#include "MySQL_Tool_Handler.h"
#include <pthread.h>

/**
 * @brief Query Tool Handler for /mcp/query endpoint
 *
 * This handler provides tools for safe database exploration and query execution.
 * It wraps the existing MySQL_Tool_Handler to provide MCP protocol compliance.
 *
 * Tools provided:
 * - list_schemas: List databases
 * - list_tables: List tables in schema
 * - describe_table: Get table structure
 * - get_constraints: Get foreign keys and constraints
 * - table_profile: Get table statistics
 * - column_profile: Get column statistics
 * - sample_rows: Get sample data
 * - sample_distinct: Sample distinct values
 * - run_sql_readonly: Execute read-only SQL
 * - explain_sql: Explain query execution plan
 * - suggest_joins: Suggest table joins
 * - find_reference_candidates: Find foreign key references
 * - catalog_upsert: Store data in catalog
 * - catalog_get: Retrieve from catalog
 * - catalog_search: Search catalog
 * - catalog_list: List catalog entries
 * - catalog_merge: Merge catalog entries
 * - catalog_delete: Delete from catalog
 */
class Query_Tool_Handler : public MCP_Tool_Handler {
private:
	MySQL_Tool_Handler* mysql_handler;  ///< Underlying MySQL tool handler
	bool owns_handler;                  ///< Whether we created the handler

	/**
	 * @brief Create tool list schema for a tool
	 * @param tool_name Name of the tool
	 * @param description Description of the tool
	 * @param required_params Required parameter names
	 * @param optional_params Optional parameter names with types
	 * @return JSON schema object
	 */
	json create_tool_schema(
		const std::string& tool_name,
		const std::string& description,
		const std::vector<std::string>& required_params,
		const std::map<std::string, std::string>& optional_params
	);

public:
	/**
	 * @brief Constructor with existing MySQL_Tool_Handler
	 * @param handler Existing MySQL_Tool_Handler to wrap
	 */
	Query_Tool_Handler(MySQL_Tool_Handler* handler);

	/**
	 * @brief Constructor creating new MySQL_Tool_Handler
	 * @param hosts Comma-separated list of MySQL hosts
	 * @param ports Comma-separated list of MySQL ports
	 * @param user MySQL username
	 * @param password MySQL password
	 * @param schema Default schema/database
	 * @param catalog_path Path to catalog database
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
	 * @brief Get the underlying MySQL_Tool_Handler
	 * @return Pointer to MySQL_Tool_Handler
	 */
	MySQL_Tool_Handler* get_mysql_handler() const { return mysql_handler; }
};

#endif /* CLASS_QUERY_TOOL_HANDLER_H */
