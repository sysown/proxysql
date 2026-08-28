#ifndef CLASS_MYSQL_CATALOG_H
#define CLASS_MYSQL_CATALOG_H

#ifdef PROXYSQL40

#include "sqlite3db.h"
#include <string>
#include <vector>
#include <memory>

/**
 * @brief MySQL Catalog for LLM Exploration Memory
 *
 * This class manages a dedicated SQLite database that stores:
 * - Table summaries created by the LLM
 * - Domain summaries
 * - Join relationships discovered
 * - Query patterns and answerability catalog
 *
 * The catalog serves as the LLM's "external memory" for database exploration.
 */
class MySQL_Catalog {
private:
	SQLite3DB* db;
	std::string db_path;

	/**
	 * @brief Initialize catalog schema
	 * @return 0 on success, -1 on error
	 */
	int init_schema();

	/**
	 * @brief Create catalog tables
	 * @return 0 on success, -1 on error
	 */
	int create_tables();

public:
	/**
	 * @brief Constructor
	 * @param path Path to the catalog database file
	 */
	MySQL_Catalog(const std::string& path);

	/**
	 * @brief Destructor
	 */
	~MySQL_Catalog();

	/**
	 * @brief Initialize the catalog database
	 * @return 0 on success, -1 on error
	 */
	int init();

	/**
	 * @brief Close the catalog database
	 */
	void close();

	/**
	 * @brief Catalog upsert - create or update a catalog entry
	 *
	 * @param schema Schema name (e.g., "sales", "production") - empty for all schemas
	 * @param kind The kind of entry ("table", "view", "domain", "metric", "note")
	 * @param key Unique key (e.g., "orders", "customer_summary")
	 * @param document JSON document with summary/details
	 * @param tags Optional comma-separated tags
	 * @param links Optional comma-separated links to related keys
	 * @return 0 on success, -1 on error
	 */
	int upsert(
		const std::string& schema,
		const std::string& kind,
		const std::string& key,
		const std::string& document,
		const std::string& tags = "",
		const std::string& links = ""
	);

	/**
	 * @brief Get a catalog entry by schema, kind and key
	 *
	 * @param schema Schema name (empty for all schemas)
	 * @param kind The kind of entry
	 * @param key The unique key
	 * @param document Output: JSON document
	 * @return 0 on success, -1 if not found
	 */
	int get(
		const std::string& schema,
		const std::string& kind,
		const std::string& key,
		std::string& document
	);

	/**
	 * @brief Search catalog entries
	 *
	 * @param schema Schema name to filter (empty for all schemas)
	 * @param query Search query (searches in key, document, tags)
	 * @param kind Optional filter by kind
	 * @param tags Optional filter by tags (comma-separated)
	 * @param limit Max results (default 20)
	 * @param offset Pagination offset (default 0)
	 * @return JSON array of matching entries
	 */
	std::string search(
		const std::string& schema,
		const std::string& query,
		const std::string& kind = "",
		const std::string& tags = "",
		int limit = 20,
		int offset = 0
	);

	/**
	 * @brief List catalog entries with pagination
	 *
	 * @param schema Schema name to filter (empty for all schemas)
	 * @param kind Optional filter by kind
	 * @param limit Max results per page (default 50)
	 * @param offset Pagination offset (default 0)
	 * @return JSON array of entries with total count
	 */
	std::string list(
		const std::string& schema = "",
		const std::string& kind = "",
		int limit = 50,
		int offset = 0
	);

	/**
	 * @brief Merge multiple entries into a new summary
	 *
	 * @param keys Array of keys to merge
	 * @param target_key Key for the merged summary
	 * @param kind Kind for the merged entry (default "domain")
	 * @param instructions Optional instructions for merging
	 * @return 0 on success, -1 on error
	 */
	int merge(
		const std::vector<std::string>& keys,
		const std::string& target_key,
		const std::string& kind = "domain",
		const std::string& instructions = ""
	);

	/**
	 * @brief Delete a catalog entry
	 *
	 * @param schema Schema name (empty for all schemas)
	 * @param kind The kind of entry
	 * @param key The unique key
	 * @return 0 on success, -1 if not found
	 */
	int remove(
		const std::string& schema,
		const std::string& kind,
		const std::string& key
	);

	/**
	 * @brief Get database handle for direct access
	 * @return SQLite3DB pointer
	 */
	SQLite3DB* get_db() { return db; }
};

#endif /* PROXYSQL40 */
#endif /* CLASS_MYSQL_CATALOG_H */
