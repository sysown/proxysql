#ifndef __CLASS_MCP_THREAD_H
#define __CLASS_MCP_THREAD_H

#ifdef PROXYSQLGENAI

#define MCP_THREAD_VERSION "0.1.0"

#include <pthread.h>
#include <cstring>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

// Forward declarations
class ProxySQL_MCP_Server;
class MySQL_Tool_Handler;
class MCP_Tool_Handler;
class Config_Tool_Handler;
class Query_Tool_Handler;
class Admin_Tool_Handler;
class Cache_Tool_Handler;
class Stats_Tool_Handler;
class AI_Tool_Handler;
class RAG_Tool_Handler;
class SQLite3_result;

/**
 * @brief MCP Threads Handler class for managing MCP module configuration
 *
 * This class handles the MCP (Model Context Protocol) module's configuration
 * variables and lifecycle. It provides methods for initializing, shutting down,
 * and managing module variables that are accessible via the admin interface.
 *
 * This is a standalone class independent from MySQL/PostgreSQL thread handlers.
 */
class MCP_Threads_Handler
{
private:
	int shutdown_;
	pthread_rwlock_t rwlock;  ///< Read-write lock for thread-safe access

public:
	struct MCP_Target_Auth_Context {
		std::string target_id;
		std::string protocol;
		int hostgroup_id;
		std::string auth_profile_id;
		std::string db_username;
		std::string db_password;
		std::string default_schema;
		int max_rows;
		int timeout_ms;
		bool allow_explain;
		bool allow_discovery;
		std::string description;
	};

	/**
	 * @brief Structure holding MCP module configuration variables
	 *
	 * These variables are stored in the global_variables table with the
	 * 'mcp-' prefix and can be modified at runtime.
	 */
	struct {
		bool mcp_enabled;                      ///< Enable/disable MCP server
		int mcp_port;                           ///< HTTP/HTTPS port for MCP server (default: 6071)
		bool mcp_use_ssl;                       ///< Enable/disable SSL/TLS (default: true)
		char* mcp_config_endpoint_auth;         ///< Authentication for /mcp/config endpoint
		char* mcp_stats_endpoint_auth;          ///< Authentication for /mcp/stats endpoint
		char* mcp_query_endpoint_auth;          ///< Authentication for /mcp/query endpoint
		char* mcp_admin_endpoint_auth;          ///< Authentication for /mcp/admin endpoint
		char* mcp_cache_endpoint_auth;          ///< Authentication for /mcp/cache endpoint
		char* mcp_ai_endpoint_auth;             ///< Authentication for /mcp/ai endpoint
		char* mcp_rag_endpoint_auth;            ///< Authentication for /mcp/rag endpoint

		int mcp_timeout_ms;                     ///< Request timeout in milliseconds (default: 30000)
			/**
			 * @brief Runtime cap for `stats.show_queries` retained Top-K window.
			 *
			 * The MCP handler enforces this as a configurable upper bound for the
			 * caller-requested page (`limit + offset`). It is further bounded by a
			 * hardcoded safety maximum in `Stats_Tool_Handler`.
			 */
			int mcp_stats_show_queries_max_rows;
			/**
			 * @brief Runtime cap for `stats.show_processlist` returned rows.
			 *
			 * The handler applies this as an upper bound for caller-requested page
			 * size (`limit`). The configurable value is itself clamped by a
			 * hardcoded safety maximum in `Stats_Tool_Handler`.
			 */
			int mcp_stats_show_processlist_max_rows;
			/**
			 * @brief Enables MCP debug-oriented stats tools.
			 *
			 * When set to `false` (default), tools intended primarily for
			 * troubleshooting and development diagnostics are hidden/blocked
			 * from regular MCP usage.
			 */
			bool mcp_stats_enable_debug_tools;
		// Catalog path is hardcoded to mcp_catalog.db in the datadir
	} variables;

	/**
	 * @brief Structure holding MCP module status variables (read-only counters)
	 */
	struct {
		unsigned long long total_requests;      ///< Total number of requests received
		unsigned long long failed_requests;     ///< Total number of failed requests
		unsigned long long active_connections;  ///< Current number of active connections
	} status_variables;

	/**
	 * @brief Pointer to the HTTP/HTTPS server instance
	 *
	 * This is managed by the MCP_Thread module and provides HTTP/HTTPS
	 * endpoints for MCP protocol communication.
	 */
	ProxySQL_MCP_Server* mcp_server;

	/**
	 * @brief Pointer to the MySQL Tool Handler instance
	 *
	 * This provides tools for LLM-based MySQL database exploration,
	 * including inventory, structure, profiling, sampling, query,
	 * relationship inference, and catalog operations.
	 *
	 * @deprecated Use query_tool_handler instead. Kept for backward compatibility.
	 */
	MySQL_Tool_Handler* mysql_tool_handler;

	/**
	 * @brief Pointers to the new dedicated tool handlers for each endpoint
	 *
	 * Each endpoint has its own dedicated tool handler:
	 * - config_tool_handler: /mcp/config endpoint
	 * - query_tool_handler: /mcp/query endpoint (includes two-phase discovery tools)
	 * - admin_tool_handler: /mcp/admin endpoint
	 * - cache_tool_handler: /mcp/cache endpoint
	 * - stats_tool_handler: /mcp/stats endpoint
	 * - ai_tool_handler: /mcp/ai endpoint
	 * - rag_tool_handler: /mcp/rag endpoint
	 */
	Config_Tool_Handler* config_tool_handler;
	Query_Tool_Handler* query_tool_handler;
	Admin_Tool_Handler* admin_tool_handler;
	Cache_Tool_Handler* cache_tool_handler;
	Stats_Tool_Handler* stats_tool_handler;
	AI_Tool_Handler* ai_tool_handler;
	RAG_Tool_Handler* rag_tool_handler;


	/**
	 * @brief Default constructor for MCP_Threads_Handler
	 *
	 * Initializes member variables to default values and sets up
	 * synchronization primitives.
	 */
	MCP_Threads_Handler();

	/**
	 * @brief Destructor for MCP_Threads_Handler
	 *
	 * Cleans up allocated resources including strings and server instance.
	 */
	~MCP_Threads_Handler();

	/**
	 * @brief Acquire write lock on variables
	 *
	 * Locks the module for write access to prevent race conditions
	 * when modifying variables.
	 */
	void wrlock();

	/**
	 * @brief Release write lock on variables
	 *
	 * Unlocks the module after write operations are complete.
	 */
	void wrunlock();

	/**
	 * @brief Initialize the MCP module
	 *
	 * Sets up the module with default configuration values and starts
	 * the HTTP/HTTPS server if enabled. Must be called before using any
	 * other methods.
	 */
	void init();

	/**
	 * @brief Shutdown the MCP module
	 *
	 * Stops the HTTPS server and performs cleanup. Called during
	 * ProxySQL shutdown.
	 */
	void shutdown();

	/**
	 * @brief Get the value of a variable as a string
	 *
	 * @param name The name of the variable (without 'mcp-' prefix)
	 * @param val Output buffer to store the value
	 * @return 0 on success, -1 if variable not found
	 */
	int get_variable(const char* name, char* val);

	/**
	 * @brief Set the value of a variable
	 *
	 * @param name The name of the variable (without 'mcp-' prefix)
	 * @param value The new value to set
	 * @return 0 on success, -1 if variable not found or value invalid
	 */
	int set_variable(const char* name, const char* value);

	/**
	 * @brief Check if a variable exists
	 *
	 * @param name The name of the variable (without 'mcp-' prefix)
	 * @return true if the variable exists, false otherwise
	 */
	bool has_variable(const char* name);

	/**
	 * @brief Get a list of all variable names
	 *
	 * @return Dynamically allocated array of strings, terminated by NULL
	 *
	 * @note The caller is responsible for freeing the array and its elements.
	 */
	char** get_variables_list();

	/**
	 * @brief Print the version information
	 *
	 * Outputs the MCP module version to stderr.
	 */
	void print_version();

	/**
	 * @brief Load MCP target/auth profiles from a joined runtime resultset into memory map
	 * @return 0 on success, -1 on failure
	 */
	int load_target_auth_map(SQLite3_result* resultset);

	/**
	 * @brief Resolve backend auth/policy context for a target_id
	 */
	bool get_target_auth_context(const std::string& target_id, MCP_Target_Auth_Context& out_ctx);

	/**
	 * @brief Return all active target auth contexts (thread-safe copy)
	 */
	std::vector<MCP_Target_Auth_Context> get_all_target_auth_contexts();

private:
	std::map<std::string, MCP_Target_Auth_Context> target_auth_map;
};

// Global instance of the MCP Threads Handler
extern MCP_Threads_Handler *GloMCPH;

#endif /* PROXYSQLGENAI */

#endif // __CLASS_MCP_THREAD_H
