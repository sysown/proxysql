#ifndef CLASS_OBSERVE_TOOL_HANDLER_H
#define CLASS_OBSERVE_TOOL_HANDLER_H

#ifdef PROXYSQL40

#include "MCP_Tool_Handler.h"
#include <pthread.h>

// Forward declaration
class MCP_Threads_Handler;

/**
 * @brief Observability Tool Handler for /mcp/stats endpoint (legacy observe naming)
 *
 * This handler provides tools for real-time metrics, statistics, and monitoring.
 *
 * Tools provided (stub implementation):
 * - list_stats: List available statistics
 * - get_stats: Get specific statistics
 * - show_connections: Show active connections
 * - show_queries: Show query statistics
 * - get_health: Get health check information
 * - show_metrics: Show performance metrics
 */
class Observe_Tool_Handler : public MCP_Tool_Handler {
private:
	MCP_Threads_Handler* mcp_handler;  ///< Pointer to MCP handler
	pthread_mutex_t handler_lock;      ///< Mutex for thread-safe operations

public:
	/**
	 * @brief Constructor
	 * @param handler Pointer to MCP_Threads_Handler
	 */
	Observe_Tool_Handler(MCP_Threads_Handler* handler);

	/**
	 * @brief Destructor
	 */
	~Observe_Tool_Handler() override;

	// MCP_Tool_Handler interface implementation
	json get_tool_list() override;
	json get_tool_description(const std::string& tool_name) override;
	json execute_tool(const std::string& tool_name, const json& arguments) override;
	int init() override;
	void close() override;
	std::string get_handler_name() const override { return "observe"; }
};

#endif /* PROXYSQL40 */
#endif /* CLASS_OBSERVE_TOOL_HANDLER_H */
