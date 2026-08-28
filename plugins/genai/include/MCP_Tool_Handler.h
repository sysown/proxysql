#ifndef CLASS_MCP_TOOL_HANDLER_H
#define CLASS_MCP_TOOL_HANDLER_H

#ifdef PROXYSQL40

#include <string>

#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

class SQLite3_result;

/**
 * @brief Base class for all MCP Tool Handlers
 *
 * This class defines the interface that all tool handlers must implement.
 * Each endpoint (config, query, admin, cache, stats) will have its own
 * dedicated tool handler that provides specific tools for that endpoint's purpose.
 *
 * Tool handlers are responsible for:
 * - Providing a list of available tools (get_tool_list)
 * - Providing detailed tool descriptions (get_tool_description)
 * - Executing tool calls with arguments (execute_tool)
 * - Managing their own resources (connections, state, etc.)
 * - Proper initialization and cleanup
 */
class MCP_Tool_Handler {
public:
	/**
	 * @brief Virtual destructor for proper cleanup in derived classes
	 */
	virtual ~MCP_Tool_Handler() = default;

	/**
	 * @brief Get the list of available tools
	 *
	 * This method is called in response to the MCP tools/list method.
	 * Each derived class implements this to return its specific tools.
	 *
	 * @return JSON object with tools array
	 *
	 * Example return format:
	 * {
	 *   "tools": [
	 *     {
	 *       "name": "tool_name",
	 *       "description": "Tool description",
	 *       "inputSchema": {...}
	 *     },
	 *     ...
	 *   ]
	 * }
	 */
	virtual json get_tool_list() = 0;

	/**
	 * @brief Get detailed description of a specific tool
	 *
	 * This method is called in response to the MCP tools/describe method.
	 * Returns detailed information about a single tool including
	 * full schema for inputs and outputs.
	 *
	 * @param tool_name The name of the tool to describe
	 * @return JSON object with tool description
	 *
	 * Example return format:
	 * {
	 *   "name": "tool_name",
	 *   "description": "Detailed description",
	 *   "inputSchema": {
	 *     "type": "object",
	 *     "properties": {...},
	 *     "required": [...]
	 *   }
	 * }
	 */
	virtual json get_tool_description(const std::string& tool_name) = 0;

	/**
	 * @brief Execute a tool with provided arguments
	 *
	 * This method is called in response to the MCP tools/call method.
	 * Executes the requested tool with the provided arguments.
	 *
	 * @param tool_name The name of the tool to execute
	 * @param arguments JSON object containing tool arguments
	 * @return JSON object with execution result or error
	 *
	 * Example return format (success):
	 * {
	 *   "success": true,
	 *   "result": {...}
	 * }
	 *
	 * Example return format (error):
	 * {
	 *   "success": false,
	 *   "error": "Error message"
	 * }
	 */
	virtual json execute_tool(const std::string& tool_name, const json& arguments) = 0;

	/**
	 * @brief Initialize the tool handler
	 *
	 * Called during ProxySQL startup or when MCP module is enabled.
	 * Implementations should initialize connections, load configuration,
	 * and prepare any resources needed for tool execution.
	 *
	 * @return 0 on success, -1 on error
	 */
	virtual int init() = 0;

	/**
	 * @brief Close and cleanup the tool handler
	 *
	 * Called during ProxySQL shutdown or when MCP module is disabled.
	 * Implementations should close connections, free resources,
	 * and perform any necessary cleanup.
	 */
	virtual void close() = 0;

	/**
	 * @brief Get the handler name
	 *
	 * Returns the name of this handler for logging and debugging purposes.
	 *
	 * @return Handler name (e.g., "query", "config", "admin")
	 */
	virtual std::string get_handler_name() const = 0;

protected:
	/**
	 * @brief Helper method to create a tool description JSON
	 *
	 * Standard format for tool descriptions used across all handlers.
	 *
	 * @param name Tool name
	 * @param description Tool description
	 * @param input_schema JSON schema for input validation
	 * @return JSON object with tool description
	 */
	json create_tool_description(
		const std::string& name,
		const std::string& description,
		const json& input_schema
	) {
		json tool;
		tool["name"] = name;
		tool["description"] = description;
		if (!input_schema.is_null()) {
			tool["inputSchema"] = input_schema;
		}
		return tool;
	}

	/**
	 * @brief Helper method to create a success response
	 *
	 * @param result The result data
	 * @return JSON object with success flag and result
	 */
	json create_success_response(const json& result) {
		json response;
		response["success"] = true;
		response["result"] = result;
		return response;
	}

	/**
	 * @brief Helper method to create an error response
	 *
	 * @param message Error message
	 * @param code Optional error code
	 * @return JSON object with error flag and message
	 */
	json create_error_response(const std::string& message, int code = -1) {
		json response;
		response["success"] = false;
		response["error"] = message;
		if (code >= 0) {
			response["code"] = code;
		}
		return response;
	}

		/**
		 * @brief Convert a SQLite3_result into a JSON array of row objects.
		 *
		 * Each row becomes a JSON object keyed by column name. Field values
		 * are parsed using the following precedence:
		 * 1) signed 64-bit integer
		 * 2) unsigned 64-bit integer (for large counters)
		 * 3) finite double
		 * 4) raw string fallback
		 *
		 * Conversion guards against overflow (`ERANGE`) and avoids non-finite
		 * floating-point JSON values (`NaN`, `+/-Inf`). NULL fields become JSON null.
		 *
		 * @param resultset The SQLite3_result to convert (may be NULL).
		 * @param cols      Number of columns in the result set.
		 * @return JSON array of row objects (empty array when resultset is NULL or has no rows).
		 */
	static json resultset_to_json(SQLite3_result* resultset, int cols);
};

#endif /* PROXYSQL40 */
#endif /* CLASS_MCP_TOOL_HANDLER_H */
