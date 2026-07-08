#ifndef CLASS_CACHE_TOOL_HANDLER_H
#define CLASS_CACHE_TOOL_HANDLER_H

#ifdef PROXYSQL40

#include "MCP_Tool_Handler.h"
#include <pthread.h>

// Forward declaration
class MCP_Threads_Handler;

/**
 * @brief Cache Tool Handler for /mcp/cache endpoint
 *
 * This handler provides tools for managing ProxySQL's query cache.
 *
 * Tools provided (stub implementation):
 * - get_cache_stats: Get cache statistics
 * - invalidate_cache: Invalidate cache entries
 * - set_cache_ttl: Set cache TTL
 * - clear_cache: Clear all cache
 * - warm_cache: Warm up cache with queries
 * - get_cache_entries: List cached queries
 */
class Cache_Tool_Handler : public MCP_Tool_Handler {
private:
	MCP_Threads_Handler* mcp_handler;  ///< Pointer to MCP handler
	pthread_mutex_t handler_lock;      ///< Mutex for thread-safe operations

public:
	/**
	 * @brief Constructor
	 * @param handler Pointer to MCP_Threads_Handler
	 */
	Cache_Tool_Handler(MCP_Threads_Handler* handler);

	/**
	 * @brief Destructor
	 */
	~Cache_Tool_Handler() override;

	// MCP_Tool_Handler interface implementation
	json get_tool_list() override;
	json get_tool_description(const std::string& tool_name) override;
	json execute_tool(const std::string& tool_name, const json& arguments) override;
	int init() override;
	void close() override;
	std::string get_handler_name() const override { return "cache"; }
};

#endif /* PROXYSQL40 */
#endif /* CLASS_CACHE_TOOL_HANDLER_H */
