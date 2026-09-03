#ifndef CLASS_MYSQL_TOOL_HANDLER_H
#define CLASS_MYSQL_TOOL_HANDLER_H

#ifdef PROXYSQL40

#include "MySQL_Catalog.h"
#include "MySQL_FTS.h"
#include <string>
#include <memory>
#include <vector>
#include <map>
#include <pthread.h>

// Forward declaration for MYSQL (mysql.h is included via proxysql.h/cpp.h)
typedef struct st_mysql MYSQL;

/**
 * @brief MySQL Tool Handler for LLM Database Exploration
 *
 * This class provides tools for an LLM to safely explore a MySQL database:
 * - Discovery tools (list_schemas, list_tables, describe_table)
 * - Profiling tools (table_profile, column_profile)
 * - Sampling tools (sample_rows, sample_distinct)
 * - Query tools (run_sql_readonly, explain_sql)
 * - Relationship tools (suggest_joins, find_reference_candidates)
 * - Catalog tools (external memory for LLM discoveries)
 */
class MySQL_Tool_Handler {
private:
	// Connection configuration
	std::vector<std::string> mysql_hosts;     ///< List of MySQL host addresses
	std::vector<int> mysql_ports;             ///< List of MySQL port numbers
	std::string mysql_user;                   ///< MySQL username for authentication
	std::string mysql_password;               ///< MySQL password for authentication
	std::string mysql_schema;                 ///< Default schema/database name

	// Connection pool
	/**
	 * @brief Represents a single MySQL connection in the pool
	 *
	 * Contains the MYSQL handle, connection details, and availability status.
	 */
	struct MySQLConnection {
		MYSQL* mysql;           ///< MySQL connection handle (NULL if not connected)
		std::string host;       ///< Host address for this connection
		int port;               ///< Port number for this connection
		bool in_use;            ///< True if connection is currently checked out
	};
	std::vector<MySQLConnection> connection_pool; ///< Pool of MySQL connections
	pthread_mutex_t pool_lock;                   ///< Mutex protecting connection pool access
	int pool_size;                               ///< Number of connections in the pool

	// Catalog for LLM memory
	MySQL_Catalog* catalog;                     ///< SQLite catalog for LLM discoveries

	// FTS for fast data discovery
	MySQL_FTS* fts;                             ///< SQLite FTS for full-text search
	pthread_mutex_t fts_lock;                  ///< Mutex protecting FTS lifecycle/usage

	// Query guardrails
	int max_rows;                               ///< Maximum rows to return (default 200)
	int timeout_ms;                             ///< Query timeout in milliseconds (default 2000)
	bool allow_select_star;                     ///< Allow SELECT * without LIMIT (default false)

	/**
	 * @brief Initialize connection pool to backend MySQL servers
	 * @return 0 on success, -1 on error
	 */
	int init_connection_pool();

	/**
	 * @brief Get a connection from the pool
	 * @return Pointer to MYSQL connection, or NULL if none available
	 */
	MYSQL* get_connection();

	/**
	 * @brief Return a connection to the pool
	 * @param mysql The MYSQL connection to return
	 */
	void return_connection(MYSQL* mysql);

	/**
	 * @brief Validate SQL is read-only
	 * @param query SQL to validate
	 * @return true if safe, false otherwise
	 */
	bool validate_readonly_query(const std::string& query);

	/**
	 * @brief Check if SQL contains dangerous keywords
	 * @param query SQL to check
	 * @return true if dangerous, false otherwise
	 */
	bool is_dangerous_query(const std::string& query);

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
	 * @brief Sanitize SQL to prevent injection
	 * @param query SQL to sanitize
	 * @return Sanitized query
	 */
	std::string sanitize_query(const std::string& query);

public:
	/**
	 * @brief Constructor
	 * @param hosts Comma-separated list of MySQL hosts
	 * @param ports Comma-separated list of MySQL ports
	 * @param user MySQL username
	 * @param password MySQL password
	 * @param schema Default schema/database
	 * @param catalog_path Path to catalog database
	 * @param fts_path Path to FTS database
	 */
	MySQL_Tool_Handler(
		const std::string& hosts,
		const std::string& ports,
		const std::string& user,
		const std::string& password,
		const std::string& schema,
		const std::string& catalog_path,
		const std::string& fts_path = ""
	);

	/**
	 * @brief Reset FTS database path at runtime
	 * @param path New SQLite FTS database path
	 * @return true on success, false on error
	 */
	bool reset_fts_path(const std::string& path);

	/**
	 * @brief Destructor
	 */
	~MySQL_Tool_Handler();

	/**
	 * @brief Initialize the tool handler
	 * @return 0 on success, -1 on error
	 */
	int init();

	/**
	 * @brief Close connections and cleanup
	 */
	void close();

	/**
	 * @brief Execute a query and return results as JSON
	 * @param query SQL query to execute
	 * @return JSON with results or error
	 */
	std::string execute_query(const std::string& query);

	// ========== Inventory Tools ==========

	/**
	 * @brief List available schemas/databases
	 * @param page_token Pagination token (optional)
	 * @param page_size Page size (default 50)
	 * @return JSON array of schemas with metadata
	 */
	std::string list_schemas(const std::string& page_token = "", int page_size = 50);

	/**
	 * @brief List tables in a schema
	 * @param schema Schema name (empty for all schemas)
	 * @param page_token Pagination token (optional)
	 * @param page_size Page size (default 50)
	 * @param name_filter Optional name pattern filter
	 * @return JSON array of tables with size estimates
	 */
	std::string list_tables(
		const std::string& schema = "",
		const std::string& page_token = "",
		int page_size = 50,
		const std::string& name_filter = ""
	);

	// ========== Structure Tools ==========

	/**
	 * @brief Get detailed table schema
	 * @param schema Schema name
	 * @param table Table name
	 * @return JSON with columns, types, keys, indexes
	 */
	std::string describe_table(const std::string& schema, const std::string& table);

	/**
	 * @brief Get constraints (FK, unique, etc.)
	 * @param schema Schema name
	 * @param table Table name (empty for all tables in schema)
	 * @return JSON array of constraints
	 */
	std::string get_constraints(const std::string& schema, const std::string& table = "");

	/**
	 * @brief Get view definition
	 * @param schema Schema name
	 * @param view View name
	 * @return JSON with view details
	 */
	std::string describe_view(const std::string& schema, const std::string& view);

	// ========== Profiling Tools ==========

	/**
	 * @brief Get quick table profile
	 * @param schema Schema name
	 * @param table Table name
	 * @param mode Profile mode ("quick" or "full")
	 * @return JSON with table statistics
	 */
	std::string table_profile(
		const std::string& schema,
		const std::string& table,
		const std::string& mode = "quick"
	);

	/**
	 * @brief Get column profile (distinct values, nulls, etc.)
	 * @param schema Schema name
	 * @param table Table name
	 * @param column Column name
	 * @param max_top_values Max distinct values to return (default 20)
	 * @return JSON with column statistics
	 */
	std::string column_profile(
		const std::string& schema,
		const std::string& table,
		const std::string& column,
		int max_top_values = 20
	);

	// ========== Sampling Tools ==========

	/**
	 * @brief Sample rows from a table (with hard cap)
	 * @param schema Schema name
	 * @param table Table name
	 * @param columns Optional comma-separated column list
	 * @param where Optional WHERE clause
	 * @param order_by Optional ORDER BY clause
	 * @param limit Max rows (hard cap default 20)
	 * @return JSON array of rows
	 */
	std::string sample_rows(
		const std::string& schema,
		const std::string& table,
		const std::string& columns = "",
		const std::string& where = "",
		const std::string& order_by = "",
		int limit = 20
	);

	/**
	 * @brief Sample distinct values from a column
	 * @param schema Schema name
	 * @param table Table name
	 * @param column Column name
	 * @param where Optional WHERE clause
	 * @param limit Max distinct values (default 50)
	 * @return JSON array of distinct values
	 */
	std::string sample_distinct(
		const std::string& schema,
		const std::string& table,
		const std::string& column,
		const std::string& where = "",
		int limit = 50
	);

	// ========== Query Tools ==========

	/**
	 * @brief Execute read-only SQL with guardrails
	 * @param sql SQL query
	 * @param max_rows Max rows (enforced, default 200)
	 * @param timeout_sec Timeout in seconds (enforced, default 2)
	 * @return JSON with query results or error
	 */
	std::string run_sql_readonly(
		const std::string& sql,
		int max_rows = 200,
		int timeout_sec = 2
	);

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

	/**
	 * @brief Explain a query (EXPLAIN/EXPLAIN ANALYZE)
	 * @param sql SQL query to explain
	 * @return JSON with execution plan
	 */
	std::string explain_sql(const std::string& sql);

	// ========== Relationship Inference Tools ==========

	/**
	 * @brief Suggest joins between two tables (heuristic-based)
	 * @param schema Schema name
	 * @param table_a First table
	 * @param table_b Second table (empty for auto-detect)
	 * @param max_candidates Max suggestions (default 5)
	 * @return JSON array of join candidates with confidence
	 */
	std::string suggest_joins(
		const std::string& schema,
		const std::string& table_a,
		const std::string& table_b = "",
		int max_candidates = 5
	);

	/**
	 * @brief Find tables referenced by a column (e.g., orders.customer_id)
	 * @param schema Schema name
	 * @param table Table name
	 * @param column Column name
	 * @param max_tables Max results (default 50)
	 * @return JSON array of candidate references
	 */
	std::string find_reference_candidates(
		const std::string& schema,
		const std::string& table,
		const std::string& column,
		int max_tables = 50
	);

	// ========== Catalog Tools (LLM Memory) ==========

	/**
	 * @brief Upsert catalog entry
	 * @param kind Entry kind
	 * @param key Unique key
	 * @param document JSON document
	 * @param schema Schema name (empty for all schemas)
	 * @param tags Comma-separated tags
	 * @param links Comma-separated links
	 * @return JSON result
	 */
	std::string catalog_upsert(
		const std::string& schema,
		const std::string& kind,
		const std::string& key,
		const std::string& document,
		const std::string& tags = "",
		const std::string& links = ""
	);

	/**
	 * @brief Get catalog entry
	 * @param schema Schema name (empty for all schemas)
	 * @param kind Entry kind
	 * @param key Unique key
	 * @return JSON document or error
	 */
	std::string catalog_get(const std::string& schema, const std::string& kind, const std::string& key);

	/**
	 * @brief Search catalog
	 * @param schema Schema name (empty for all schemas)
	 * @param query Search query
	 * @param kind Optional kind filter
	 * @param tags Optional tag filter
	 * @param limit Max results (default 20)
	 * @param offset Pagination offset (default 0)
	 * @return JSON array of matching entries
	 */
	std::string catalog_search(
		const std::string& schema,
		const std::string& query,
		const std::string& kind = "",
		const std::string& tags = "",
		int limit = 20,
		int offset = 0
	);

	/**
	 * @brief List catalog entries
	 * @param schema Schema name (empty for all schemas)
	 * @param kind Optional kind filter
	 * @param limit Max results per page (default 50)
	 * @param offset Pagination offset (default 0)
	 * @return JSON with total count and results array
	 */
	std::string catalog_list(
		const std::string& schema = "",
		const std::string& kind = "",
		int limit = 50,
		int offset = 0
	);

	/**
	 * @brief Merge catalog entries
	 * @param keys JSON array of keys to merge
	 * @param target_key Target key for merged entry
	 * @param kind Kind for merged entry (default "domain")
	 * @param instructions Optional instructions
	 * @return JSON result
	 */
	std::string catalog_merge(
		const std::string& keys,
		const std::string& target_key,
		const std::string& kind = "domain",
		const std::string& instructions = ""
	);

	/**
	 * @brief Delete catalog entry
	 * @param schema Schema name (empty for all schemas)
	 * @param kind Entry kind
	 * @param key Unique key
	 * @return JSON result
	 */
	std::string catalog_delete(const std::string& schema, const std::string& kind, const std::string& key);

	// ========== FTS Tools (Full Text Search) ==========

	/**
	 * @brief Create and populate an FTS index for a MySQL table
	 * @param schema Schema name
	 * @param table Table name
	 * @param columns JSON array of column names to index
	 * @param primary_key Primary key column name
	 * @param where_clause Optional WHERE clause for filtering
	 * @return JSON result with success status and metadata
	 */
	std::string fts_index_table(
		const std::string& schema,
		const std::string& table,
		const std::string& columns,
		const std::string& primary_key,
		const std::string& where_clause = ""
	);

	/**
	 * @brief Search indexed data using FTS5
	 * @param query FTS5 search query
	 * @param schema Optional schema filter
	 * @param table Optional table filter
	 * @param limit Max results (default 100)
	 * @param offset Pagination offset (default 0)
	 * @return JSON result with matches and snippets
	 */
	std::string fts_search(
		const std::string& query,
		const std::string& schema = "",
		const std::string& table = "",
		int limit = 100,
		int offset = 0
	);

	/**
	 * @brief List all FTS indexes with metadata
	 * @return JSON array of indexes
	 */
	std::string fts_list_indexes();

	/**
	 * @brief Remove an FTS index
	 * @param schema Schema name
	 * @param table Table name
	 * @return JSON result
	 */
	std::string fts_delete_index(const std::string& schema, const std::string& table);

	/**
	 * @brief Refresh an index with fresh data (full rebuild)
	 * @param schema Schema name
	 * @param table Table name
	 * @return JSON result
	 */
	std::string fts_reindex(const std::string& schema, const std::string& table);

	/**
	 * @brief Rebuild ALL FTS indexes with fresh data
	 * @return JSON result with summary
	 */
	std::string fts_rebuild_all();

	/**
	 * @brief Reinitialize FTS handler with a new database path
	 * @param fts_path New path to FTS database
	 * @return 0 on success, -1 on error
	 */
	int reinit_fts(const std::string& fts_path);
};

#endif /* PROXYSQL40 */
#endif /* CLASS_MYSQL_TOOL_HANDLER_H */
