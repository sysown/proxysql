#ifndef CLASS_CONFIG_TOOL_HANDLER_H
#define CLASS_CONFIG_TOOL_HANDLER_H

#ifdef PROXYSQL40

#include "MCP_Tool_Handler.h"
#include <pthread.h>

// Forward declaration
class MCP_Threads_Handler;

/**
 * @brief Configuration Tool Handler for /mcp/config endpoint
 *
 * This handler provides tools for runtime configuration and management
 * of ProxySQL. It allows LLMs to view and modify ProxySQL configuration,
 * reload variables, and manage the server state.
 *
 * Tools provided:
 * - get_config: Get current configuration values
 * - set_config: Modify configuration values
 * - reload_config: Reload configuration from disk/memory
 * - list_variables: List all available variables
 * - get_status: Get server status information
 * - query: Execute constrained SQL against the admin/config database
 */
class Config_Tool_Handler : public MCP_Tool_Handler {
private:
	MCP_Threads_Handler* mcp_handler;  ///< Pointer to MCP handler for variable access
	pthread_mutex_t handler_lock;      ///< Mutex for thread-safe operations

	/**
	 * @brief Get a configuration variable value
	 * @param var_name Variable name (without 'mcp-' prefix)
	 * @return JSON with variable value
	 */
	json handle_get_config(const std::string& var_name);

	/**
	 * @brief Set a configuration variable value
	 * @param var_name Variable name (without 'mcp-' prefix)
	 * @param var_value New value
	 * @return JSON with success status
	 */
	json handle_set_config(const std::string& var_name, const std::string& var_value);

	/**
	 * @brief Reload configuration
	 * @param scope "disk", "memory", or "runtime"
	 * @return JSON with success status
	 */
	json handle_reload_config(const std::string& scope);

	/**
	 * @brief Execute constrained SQL against the ProxySQL admin/config DB
	 * @param sql SQL statement
	 * @return JSON with query result or error
	 */
	json handle_query(const std::string& sql);

	/**
	 * @brief List all configuration variables
	 * @param filter Optional filter pattern
	 * @return JSON with variables list
	 */
	json handle_list_variables(const std::string& filter);

	/**
	 * @brief Get server status
	 * @return JSON with status information
	 */
	json handle_get_status();

public:
	/**
	 * @brief Constructor
	 * @param handler Pointer to MCP_Threads_Handler
	 */
	Config_Tool_Handler(MCP_Threads_Handler* handler);

	/**
	 * @brief Destructor
	 */
	~Config_Tool_Handler() override;

	// MCP_Tool_Handler interface implementation
	json get_tool_list() override;
	json get_tool_description(const std::string& tool_name) override;
	json execute_tool(const std::string& tool_name, const json& arguments) override;
	int init() override;
	void close() override;
	std::string get_handler_name() const override { return "config"; }
};

#endif /* PROXYSQL40 */
#endif /* CLASS_CONFIG_TOOL_HANDLER_H */
