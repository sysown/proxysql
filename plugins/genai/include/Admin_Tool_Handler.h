#ifndef CLASS_ADMIN_TOOL_HANDLER_H
#define CLASS_ADMIN_TOOL_HANDLER_H

#ifdef PROXYSQL40

#include "MCP_Tool_Handler.h"
#include <pthread.h>

// Forward declaration
class MCP_Threads_Handler;

/**
 * @brief Administration Tool Handler for /mcp/admin endpoint
 *
 * This handler provides tools for administrative operations on ProxySQL.
 * These tools allow LLMs to perform management tasks like user management,
 * process control, and server administration.
 *
 * Tools provided (stub implementation):
 * - admin_list_users: List MySQL users
 * - admin_show_processes: Show running processes
 * - admin_kill_query: Kill a running query
 * - admin_flush_cache: Flush various caches
 * - admin_reload: Reload users/servers configuration
 */
class Admin_Tool_Handler : public MCP_Tool_Handler {
private:
	MCP_Threads_Handler* mcp_handler;  ///< Pointer to MCP handler
	pthread_mutex_t handler_lock;      ///< Mutex for thread-safe operations

public:
	/**
	 * @brief Constructor
	 * @param handler Pointer to MCP_Threads_Handler
	 */
	Admin_Tool_Handler(MCP_Threads_Handler* handler);

	/**
	 * @brief Destructor
	 */
	~Admin_Tool_Handler() override;

	// MCP_Tool_Handler interface implementation
	json get_tool_list() override;
	json get_tool_description(const std::string& tool_name) override;
	json execute_tool(const std::string& tool_name, const json& arguments) override;
	int init() override;
	void close() override;
	std::string get_handler_name() const override { return "admin"; }
};

#endif /* PROXYSQL40 */
#endif /* CLASS_ADMIN_TOOL_HANDLER_H */
