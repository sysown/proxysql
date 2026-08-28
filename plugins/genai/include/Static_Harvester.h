#ifndef CLASS_STATIC_HARVESTER_H
#define CLASS_STATIC_HARVESTER_H

#ifdef PROXYSQL40

#include "Discovery_Schema.h"
#include <string>
#include <vector>
#include <memory>
#include <pthread.h>

// Forward declaration for MYSQL
typedef struct st_mysql MYSQL;

/**
 * @brief Static Metadata Harvester from MySQL INFORMATION_SCHEMA
 *
 * This class performs deterministic metadata extraction from MySQL's
 * INFORMATION_SCHEMA and stores it in a Discovery_Schema catalog.
 *
 * Harvest stages:
 * 1. Schemas/Databases
 * 2. Objects (tables/views/routines/triggers)
 * 3. Columns with derived hints (is_time, is_id_like)
 * 4. Indexes and index columns
 * 5. Foreign keys and FK columns
 * 6. View definitions
 * 7. Quick profiles (metadata-based analysis)
 * 8. FTS5 index rebuild
 */
class Static_Harvester {
private:
	// MySQL connection
	std::string mysql_host;
	int mysql_port;
	std::string mysql_user;
	std::string mysql_password;
	std::string mysql_schema;  // Default schema (can be empty)
	MYSQL* mysql_conn;
	pthread_mutex_t conn_lock;  ///< Mutex protecting MySQL connection

	// Discovery schema
	Discovery_Schema* catalog;

	// Current run state
	int current_run_id;
	std::string source_dsn;
	std::string mysql_version;

	// Internal helper methods

	/**
	 * @brief Connect to MySQL server
	 * @return 0 on success, -1 on error
	 */
	int connect_mysql();

	/**
	 * @brief Disconnect from MySQL server
	 */
	void disconnect_mysql();

	/**
	 * @brief Execute query and return results
	 * @param query SQL query
	 * @param results Output: vector of result rows
	 * @return 0 on success, -1 on error
	 */
	int execute_query(const std::string& query, std::vector<std::vector<std::string>>& results);

	/**
	 * @brief Get MySQL version
	 * @return MySQL version string
	 */
	std::string get_mysql_version();

	/**
	 * @brief Check if data type is a time type
	 * @param data_type Data type string
	 * @return true if time type, false otherwise
	 */
	static bool is_time_type(const std::string& data_type);

	/**
	 * @brief Check if column name is ID-like
	 * @param column_name Column name
	 * @return true if ID-like, false otherwise
	 */
	static bool is_id_like_name(const std::string& column_name);

	/**
	 * @brief Validate schema name for safe use in SQL queries
	 *
	 * Validates that a schema name contains only safe characters
	 * (alphanumeric, underscore, dollar sign) to prevent SQL injection
	 * when used in string concatenation for INFORMATION_SCHEMA queries.
	 *
	 * @param name Schema name to validate
	 * @return true if safe to use, false otherwise
	 */
	static bool is_valid_schema_name(const std::string& name);

	/**
	 * @brief Escape a string for safe use in SQL queries
	 *
	 * Escapes single quotes by doubling them to prevent SQL injection
	 * when strings are used in string concatenation for SQL queries.
	 *
	 * @param str String to escape
	 * @return Escaped string with single quotes doubled
	 */
	static std::string escape_sql_string(const std::string& str);

public:
	/**
	 * @brief Constructor
	 *
	 * @param host MySQL host address
	 * @param port MySQL port
	 * @param user MySQL username
	 * @param password MySQL password
	 * @param schema Default schema (empty for all schemas)
	 * @param catalog_path Path to catalog database
	 */
	Static_Harvester(
		const std::string& host,
		int port,
		const std::string& user,
		const std::string& password,
		const std::string& schema,
		const std::string& catalog_path
	);

	/**
	 * @brief Destructor
	 */
	~Static_Harvester();

	/**
	 * @brief Initialize the harvester
	 * @return 0 on success, -1 on error
	 */
	int init();

	/**
	 * @brief Close connections and cleanup
	 */
	void close();

	/**
	 * @brief Start a new discovery run
	 *
	 * Creates a new run entry in the catalog and stores run_id.
	 *
	 * @param notes Optional notes for this run
	 * @return run_id on success, -1 on error
	 */
	int start_run(const std::string& target_id, const std::string& notes = "");

	/**
	 * @brief Finish the current discovery run
	 *
	 * Updates the run entry with finish timestamp and notes.
	 *
	 * @param notes Optional completion notes
	 * @return 0 on success, -1 on error
	 */
	int finish_run(const std::string& notes = "");

	/**
	 * @brief Get the current run ID
	 * @return Current run_id, or -1 if no active run
	 */
	int get_run_id() const { return current_run_id; }

	// ========== Harvest Stages ==========

	/**
	 * @brief Harvest schemas/databases
	 *
	 * Queries information_schema.SCHEMATA and inserts into catalog.
	 *
	 * @param only_schema Optional filter for single schema
	 * @return Number of schemas harvested, or -1 on error
	 */
	int harvest_schemas(const std::string& only_schema = "");

	/**
	 * @brief Harvest objects (tables/views/routines/triggers)
	 *
	 * Queries information_schema.TABLES and ROUTINES.
	 * Also harvests view definitions.
	 *
	 * @param only_schema Optional filter for single schema
	 * @return Number of objects harvested, or -1 on error
	 */
	int harvest_objects(const std::string& only_schema = "");

	/**
	 * @brief Harvest columns with derived hints
	 *
	 * Queries information_schema.COLUMNS and computes:
	 * - is_time: date/datetime/timestamp/time/year
	 * - is_id_like: column_name REGEXP '(^id$|_id$)'
	 *
	 * @param only_schema Optional filter for single schema
	 * @return Number of columns harvested, or -1 on error
	 */
	int harvest_columns(const std::string& only_schema = "");

	/**
	 * @brief Harvest indexes and index columns
	 *
	 * Queries information_schema.STATISTICS.
	 * Marks is_pk, is_unique, is_indexed on columns.
	 *
	 * @param only_schema Optional filter for single schema
	 * @return Number of indexes harvested, or -1 on error
	 */
	int harvest_indexes(const std::string& only_schema = "");

	/**
	 * @brief Harvest foreign keys
	 *
	 * Queries information_schema.KEY_COLUMN_USAGE and
	 * REFERENTIAL_CONSTRAINTS.
	 *
	 * @param only_schema Optional filter for single schema
	 * @return Number of foreign keys harvested, or -1 on error
	 */
	int harvest_foreign_keys(const std::string& only_schema = "");

	/**
	 * @brief Harvest view definitions
	 *
	 * Queries information_schema.VIEWS and stores VIEW_DEFINITION.
	 *
	 * @param only_schema Optional filter for single schema
	 * @return Number of views updated, or -1 on error
	 */
	int harvest_view_definitions(const std::string& only_schema = "");

	/**
	 * @brief Build quick profiles (metadata-only analysis)
	 *
	 * Analyzes metadata to derive:
	 * - guessed_kind: log/event, fact, entity, unknown
	 * - rows_est, size_bytes, engine
	 * - has_primary_key, has_foreign_keys, has_time_column
	 *
	 * Stores as 'table_quick' profile.
	 *
	 * @return 0 on success, -1 on error
	 */
	int build_quick_profiles();

	/**
	 * @brief Rebuild FTS5 index for current run
	 *
	 * Deletes and rebuilds fts_objects index.
	 *
	 * @return 0 on success, -1 on error
	 */
	int rebuild_fts_index();

	/**
	 * @brief Run full harvest (all stages)
	 *
	 * Executes all harvest stages in order:
	 * 1. Start run
	 * 2. Harvest schemas
	 * 3. Harvest objects
	 * 4. Harvest columns
	 * 5. Harvest indexes
	 * 6. Harvest foreign keys
	 * 7. Build quick profiles
	 * 8. Rebuild FTS index
	 * 9. Finish run
	 *
	 * @param only_schema Optional filter for single schema
	 * @param notes Optional run notes
	 * @return run_id on success, -1 on error
	 */
	int run_full_harvest(const std::string& target_id, const std::string& only_schema = "", const std::string& notes = "");

	/**
	 * @brief Get harvest statistics
	 *
	 * Returns counts of harvested objects for the current run.
	 *
	 * @return JSON string with statistics
	 */
	std::string get_harvest_stats();

	/**
	 * @brief Get harvest statistics for a specific run
	 *
	 * Returns counts of harvested objects for the specified run_id.
	 *
	 * @param run_id The run ID to get stats for
	 * @return JSON string with statistics
	 */
	std::string get_harvest_stats(int run_id);

	// ========== Data Structures for Query Results ==========

	/**
	 * @brief Schema row structure
	 */
	struct SchemaRow {
		std::string schema_name;
		std::string charset;
		std::string collation;
	};

	/**
	 * @brief Object row structure
	 */
	struct ObjectRow {
		std::string schema_name;
		std::string object_name;
		std::string object_type;
		std::string engine;
		long table_rows_est;
		long data_length;
		long index_length;
		std::string create_time;
		std::string update_time;
		std::string object_comment;
		std::string definition_sql;
	};

	/**
	 * @brief Column row structure
	 */
	struct ColumnRow {
		std::string schema_name;
		std::string object_name;
		int ordinal_pos;
		std::string column_name;
		std::string data_type;
		std::string column_type;
		int is_nullable;
		std::string column_default;
		std::string extra;
		std::string charset;
		std::string collation;
		std::string column_comment;
	};

	/**
	 * @brief Index row structure
	 */
	struct IndexRow {
		std::string schema_name;
		std::string object_name;
		std::string index_name;
		int is_unique;
		std::string index_type;
		int seq_in_index;
		std::string column_name;
		int sub_part;
		std::string collation;
		long cardinality;
	};

	/**
	 * @brief Foreign key row structure
	 */
	struct FKRow {
		std::string child_schema;
		std::string child_table;
		std::string fk_name;
		std::string child_column;
		std::string parent_schema;
		std::string parent_table;
		std::string parent_column;
		int seq;
		std::string on_update;
		std::string on_delete;
	};

	// ========== Helper Query Methods (for testing) ==========

	/**
	 * @brief Fetch schemas from MySQL
	 * @param filter Optional schema name filter
	 * @return Vector of SchemaRow
	 */
	std::vector<SchemaRow> fetch_schemas(const std::string& filter = "");

	/**
	 * @brief Fetch tables/views from MySQL
	 * @param filter Optional schema name filter
	 * @return Vector of ObjectRow
	 */
	std::vector<ObjectRow> fetch_tables_views(const std::string& filter = "");

	/**
	 * @brief Fetch columns from MySQL
	 * @param filter Optional schema name filter
	 * @return Vector of ColumnRow
	 */
	std::vector<ColumnRow> fetch_columns(const std::string& filter = "");

	/**
	 * @brief Fetch indexes from MySQL
	 * @param filter Optional schema name filter
	 * @return Vector of IndexRow
	 */
	std::vector<IndexRow> fetch_indexes(const std::string& filter = "");

	/**
	 * @brief Fetch foreign keys from MySQL
	 * @param filter Optional schema name filter
	 * @return Vector of FKRow
	 */
	std::vector<FKRow> fetch_foreign_keys(const std::string& filter = "");
};

#endif /* PROXYSQL40 */
#endif /* CLASS_STATIC_HARVESTER_H */
