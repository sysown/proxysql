#ifndef PROXYSQL_MCP_THREAD_H
#define PROXYSQL_MCP_THREAD_H

#ifdef PROXYSQL40

#define MCP_THREAD_VERSION "0.1.0"

#include <pthread.h>
#include <cstring>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>
#include <utility>

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
class SQLite3DB;

/**
 * @brief Outcome of a profile install (issue #6168).
 *
 * `LOAD MCP PROFILES TO RUNTIME` and the startup install read every row of
 * main.mcp_target_profiles, but only the rows that survive the join against
 * main.mcp_auth_profiles enter target_auth_map -- the map the MCP query
 * endpoint actually consumes. Rows dropped by that join used to disappear
 * without a trace: the command still replied OK, nothing was logged, and the
 * row stayed visible in runtime_mcp_target_profiles. These counters let the
 * admin verb report the drop, and each dropped row is additionally logged with
 * its target_id and reason.
 */
struct MCP_Profile_Install_Stats {
	int auth_profiles_installed = 0;
	int targets_read = 0;
	int targets_effective = 0;
	int targets_skipped_inactive = 0;
	int targets_skipped_no_auth_profile = 0;

	int targets_skipped() const {
		return targets_skipped_inactive + targets_skipped_no_auth_profile;
	}
};

// Stable skip_reason values, also used verbatim in the runtime_mcp_target_
// profiles.skip_reason column. Keep them short and machine-greppable: TAP
// tests and operators match on them.
#define MCP_SKIP_REASON_INACTIVE          "inactive"
#define MCP_SKIP_REASON_NO_AUTH_PROFILE   "auth_profile_id not found"

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

	// Full-row records for the editable admin tables — module-owned
	// state, the source of truth that runtime_<X> projects from
	// (ABI 3 separation-of-duties contract). target_auth_map above is
	// the joined view consumed by the listener; auth_profiles_ and
	// target_profiles_ retain the raw rows so SAVE TO MEMORY can
	// reconstruct the editable tables and the runtime_<X> projection
	// callbacks have something to project.
	struct MCP_Auth_Profile_Row {
		std::string auth_profile_id;
		std::string db_username;
		std::string db_password;
		std::string default_schema;
		int use_ssl;
		std::string ssl_mode;
		std::string comment;
	};

	struct MCP_Target_Profile_Row {
		std::string target_id;
		std::string protocol;
		int hostgroup_id;
		std::string auth_profile_id;
		std::string description;
		int max_rows;
		int timeout_ms;
		int allow_explain;
		int allow_discovery;
		int active;
		std::string comment;
	};

	// Module-owned snapshot of mcp_query_rules.  See ABI-3 contract:
	// the runtime_mcp_query_rules table is a chassis-projected view of
	// this snapshot, and SAVE MCP QUERY RULES TO MEMORY pulls from
	// here back into main.mcp_query_rules.  When the MCP listener is
	// running, install_query_rules_from_admin also pushes the rows
	// through Query_Tool_Handler::get_catalog()->load_mcp_query_rules
	// so the request hot-path sees them; the snapshot guarantees
	// SAVE / projection still work when the listener is down.
	struct MCP_Query_Rule_Row {
		// nullable_int = -1 means "NULL in main.mcp_query_rules" (for
		// columns where SQLite stores NULL as a sentinel, not 0).
		int rule_id;
		int active;
		std::string username;
		std::string target_id;
		std::string schemaname;
		std::string tool_name;
		std::string match_pattern;
		int negate_match_pattern;
		std::string re_modifiers;
		int flagIN;
		int flagOUT;          // -1 means NULL
		bool flagOUT_is_null;
		std::string replace_pattern;
		int timeout_ms;       // -1 means NULL
		bool timeout_ms_is_null;
		std::string error_msg;
		std::string OK_msg;
		int log;
		bool log_is_null;
		int apply;
		std::string comment;
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
	 * @param val_size Size of the output buffer in bytes
	 * @return 0 on success, -1 if the variable is unknown, the arguments are
	 *   null/invalid, or the value does not fit in `val_size` bytes
	 *
	 * @deprecated The unbounded sprintf into `val` is a stack-buffer
	 *   overflow risk for variables that hold arbitrary-length values
	 *   (the `*_endpoint_auth` strings are bearer tokens supplied by
	 *   operators).  Prefer `get_variable_string()` below.  Retained
	 *   for callers that haven't been updated yet.
	 */
	int get_variable(const char* name, char* val, size_t val_size);

	/**
	 * @brief Get the value of a variable as a std::string.
	 *
	 * Safe replacement for `get_variable(name, char*)`: no caller
	 * buffer to size or overflow.  Returns the empty string when the
	 * variable is unknown — the bool return is the not-found signal.
	 */
	bool get_variable_string(const char* name, std::string& out);

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
	 *
	 * @deprecated Pre-ABI-3 helper: takes ownership of a JOINed resultset
	 *   (runtime_mcp_target_profiles ⨝ runtime_mcp_auth_profiles) and
	 *   replaces target_auth_map. Retained because the bootstrap path
	 *   still calls it; new code should drive install_auth_profiles_from_admin
	 *   + install_target_profiles_from_admin (which rebuild target_auth_map
	 *   from the per-table in-memory snapshots).
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

	// ---- ABI-3 separation-of-duties triplets ----
	//
	// install_<X>_from_admin: read main.mcp_<X> rows under module mutex
	//   and replace the in-memory snapshot. The joined target_auth_map
	//   gets rebuilt whenever EITHER profile table changes so the
	//   listener consumer always sees a coherent view.
	// save_<X>_to_admin_table: REPLACE the editable main.mcp_<X> rows
	//   from the in-memory snapshot. Never reads runtime_<X>.
	// project_<X>_to_runtime_view: DELETE+INSERT runtime_mcp_<X> from
	//   the in-memory snapshot. Invoked by the chassis just before any
	//   admin SELECT against runtime_mcp_<X>.

	bool install_auth_profiles_from_admin(SQLite3DB& admindb, std::string& err);
	bool install_target_profiles_from_admin(SQLite3DB& admindb, std::string& err);
	bool install_query_rules_from_admin(SQLite3DB& admindb, std::string& err);

	// Atomic install of BOTH profile tables: reads main.mcp_auth_profiles
	// and main.mcp_target_profiles, then under a single wrlock swaps
	// both vectors and rebuilds target_auth_map. Use this in preference
	// to calling install_auth_profiles_from_admin +
	// install_target_profiles_from_admin separately — that pair leaves
	// target_auth_map rebuilt from a mismatched (auth_v2, target_v1)
	// snapshot if the second install fails.
	bool install_profiles_from_admin(SQLite3DB& admindb, std::string& err);

	bool save_auth_profiles_to_admin_table(SQLite3DB& admindb);
	bool save_target_profiles_to_admin_table(SQLite3DB& admindb);
	bool save_query_rules_to_admin_table(SQLite3DB& admindb);

	// Atomic save of BOTH profile tables: copies both in-memory
	// snapshots under a single rdlock, then writes both
	// main.mcp_auth_profiles and main.mcp_target_profiles inside one
	// transaction. SQLite enforces FK integrity inside the txn, so
	// dangling target.auth_profile_id rows can never be observed by an
	// admin reader between the two table writes.
	bool save_profiles_to_admin_table(SQLite3DB& admindb);

	void project_auth_profiles_to_runtime_view(SQLite3DB& admindb);
	void project_target_profiles_to_runtime_view(SQLite3DB& admindb);
	void project_query_rules_to_runtime_view(SQLite3DB& admindb);

	std::vector<MCP_Auth_Profile_Row> get_auth_profiles_snapshot();
	std::vector<MCP_Target_Profile_Row> get_target_profiles_snapshot();
	std::vector<MCP_Query_Rule_Row> get_query_rules_snapshot();

	// Result of the most recent rebuild_target_auth_map_locked(). Read it
	// right after an install to report what the install actually did; the
	// admin command path is serialized, so no other install can interleave
	// between the two calls there.
	MCP_Profile_Install_Stats get_last_profile_install_stats();

	std::vector<std::pair<std::string, std::string>> collect_status_variables();

private:
	std::map<std::string, MCP_Target_Auth_Context> target_auth_map;

	// In-memory module-owned snapshots of the editable admin tables.
	// These, target_auth_map above, and the two rebuild by-products below
	// (target_skip_reasons_, last_profile_install_stats_) are all guarded
	// by `rwlock`.
	std::vector<MCP_Auth_Profile_Row> auth_profiles_;
	std::vector<MCP_Target_Profile_Row> target_profiles_;
	std::vector<MCP_Query_Rule_Row> query_rules_;

	// target_id -> why the row was excluded from target_auth_map, for the
	// rows that were. Filled by rebuild_target_auth_map_locked() in the same
	// pass that builds the map, so runtime_mcp_target_profiles.skip_reason
	// reports the very decision the query endpoint made rather than a second,
	// independently-derived opinion that could drift from it.
	std::map<std::string, std::string> target_skip_reasons_;

	// Counters from the most recent rebuild. Guarded by `rwlock` like the
	// collections above.
	MCP_Profile_Install_Stats last_profile_install_stats_ {};

	// Rebuild target_auth_map from auth_profiles_ + target_profiles_, and
	// with it target_skip_reasons_ and last_profile_install_stats_.
	// Caller MUST hold a write lock on `rwlock`.
	void rebuild_target_auth_map_locked();
};

// Global instance of the MCP Threads Handler
extern MCP_Threads_Handler *GloMCPH;

#endif /* PROXYSQL40 */

#endif // __CLASS_MCP_THREAD_H
