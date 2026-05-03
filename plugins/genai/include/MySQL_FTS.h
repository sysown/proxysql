#ifndef CLASS_MYSQL_FTS_H
#define CLASS_MYSQL_FTS_H

#ifdef PROXYSQL40

#include "sqlite3db.h"
#include <string>
#include <vector>

// Forward declaration
class MySQL_Tool_Handler;

/**
 * @brief MySQL Full Text Search (FTS) for Fast Data Discovery
 *
 * This class manages a dedicated SQLite database that provides:
 * - Full-text search indexes for MySQL tables
 * - Fast data discovery before querying the actual MySQL database
 * - Cross-table search capabilities
 * - BM25 ranking with FTS5
 *
 * The FTS system serves as a fast local cache for AI agents to quickly
 * find relevant data before making targeted queries to MySQL backend.
 */
class MySQL_FTS {
private:
	SQLite3DB* db;
	std::string db_path;

	/**
	 * @brief Initialize FTS schema
	 * @return 0 on success, -1 on error
	 */
	int init_schema();

	/**
	 * @brief Create FTS metadata tables
	 * @return 0 on success, -1 on error
	 */
	int create_tables();

	/**
	 * @brief Create per-index tables (data and FTS5 virtual table)
	 * @param schema Schema name
	 * @param table Table name
	 * @return 0 on success, -1 on error
	 */
	int create_index_tables(const std::string& schema, const std::string& table);

	/**
	 * @brief Get sanitized data table name for a schema.table
	 * @param schema Schema name
	 * @param table Table name
	 * @return Sanitized table name
	 */
	std::string get_data_table_name(const std::string& schema, const std::string& table);

	/**
	 * @brief Get FTS search table name for a schema.table
	 * @param schema Schema name
	 * @param table Table name
	 * @return Sanitized FTS table name
	 */
	std::string get_fts_table_name(const std::string& schema, const std::string& table);

	/**
	 * @brief Sanitize a name for use as SQLite table name
	 * @param name Name to sanitize
	 * @return Sanitized name
	 */
	std::string sanitize_name(const std::string& name);

	/**
	 * @brief Escape single quotes for SQL
	 * @param str String to escape
	 * @return Escaped string
	 */
	std::string escape_sql(const std::string& str);

	/**
	 * @brief Escape identifier for SQLite (double backticks)
	 * @param identifier Identifier to escape
	 * @return Escaped identifier
	 */
	std::string escape_identifier(const std::string& identifier);

public:
	/**
	 * @brief Constructor
	 * @param path Path to the FTS database file
	 */
	MySQL_FTS(const std::string& path);

	// Prevent copy and move (class owns raw pointer)
	MySQL_FTS(const MySQL_FTS&) = delete;
	MySQL_FTS& operator=(const MySQL_FTS&) = delete;
	MySQL_FTS(MySQL_FTS&&) = delete;
	MySQL_FTS& operator=(MySQL_FTS&&) = delete;

	/**
	 * @brief Destructor
	 */
	~MySQL_FTS();

	/**
	 * @brief Initialize the FTS database
	 * @return 0 on success, -1 on error
	 */
	int init();

	/**
	 * @brief Close the FTS database
	 */
	void close();

	/**
	 * @brief Check if an index exists for a schema.table
	 * @param schema Schema name
	 * @param table Table name
	 * @return true if exists, false otherwise
	 */
	bool index_exists(const std::string& schema, const std::string& table);

	/**
	 * @brief Create and populate an FTS index for a MySQL table
	 *
	 * @param schema Schema name
	 * @param table Table name
	 * @param columns JSON array of column names to index
	 * @param primary_key Primary key column name
	 * @param where_clause Optional WHERE clause for filtering
	 * @param mysql_handler Pointer to MySQL_Tool_Handler for executing queries
	 * @return JSON result with success status and metadata
	 */
	std::string index_table(
		const std::string& schema,
		const std::string& table,
		const std::string& columns,
		const std::string& primary_key,
		const std::string& where_clause,
		MySQL_Tool_Handler* mysql_handler
	);

	/**
	 * @brief Search indexed data using FTS5
	 *
	 * @param query FTS5 search query
	 * @param schema Optional schema filter
	 * @param table Optional table filter
	 * @param limit Max results (default 100)
	 * @param offset Pagination offset (default 0)
	 * @return JSON result with matches and snippets
	 */
	std::string search(
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
	std::string list_indexes();

	/**
	 * @brief Remove an FTS index
	 *
	 * @param schema Schema name
	 * @param table Table name
	 * @return JSON result
	 */
	std::string delete_index(const std::string& schema, const std::string& table);

	/**
	 * @brief Refresh an index with fresh data (full rebuild)
	 *
	 * @param schema Schema name
	 * @param table Table name
	 * @param mysql_handler Pointer to MySQL_Tool_Handler for executing queries
	 * @return JSON result
	 */
	std::string reindex(
		const std::string& schema,
		const std::string& table,
		MySQL_Tool_Handler* mysql_handler
	);

	/**
	 * @brief Rebuild ALL FTS indexes with fresh data
	 *
	 * @param mysql_handler Pointer to MySQL_Tool_Handler for executing queries
	 * @return JSON result with summary
	 */
	std::string rebuild_all(MySQL_Tool_Handler* mysql_handler);

	/**
	 * @brief Get database handle for direct access
	 * @return SQLite3DB pointer
	 */
	SQLite3DB* get_db() { return db; }
};

#endif /* PROXYSQL40 */
#endif /* CLASS_MYSQL_FTS_H */
