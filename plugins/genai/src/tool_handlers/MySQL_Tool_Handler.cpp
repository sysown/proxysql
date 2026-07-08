#ifdef PROXYSQL40


#include "proxysql.h"
#include "MySQL_Tool_Handler.h"
#include "proxysql_debug.h"
#include "cpp.h"
#include <sstream>
#include <algorithm>
#include <regex>
#include <cstring>
#include <sys/stat.h>

// MySQL client library
#include <mysql.h>

// JSON library
#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

MySQL_Tool_Handler::MySQL_Tool_Handler(
	const std::string& hosts,
	const std::string& ports,
	const std::string& user,
	const std::string& password,
	const std::string& schema,
	const std::string& catalog_path,
	const std::string& fts_path
)
	: pool_size(0),
	  catalog(NULL),
	  fts(NULL),
	  max_rows(200),
	  timeout_ms(2000),
	  allow_select_star(false)
{
	// Initialize the pool mutex
	pthread_mutex_init(&pool_lock, NULL);
	// Initialize the FTS mutex
	pthread_mutex_init(&fts_lock, NULL);

	// Parse hosts
	std::istringstream h(hosts);
	std::string host;
	while (std::getline(h, host, ',')) {
		// Trim whitespace
		host.erase(0, host.find_first_not_of(" \t"));
		host.erase(host.find_last_not_of(" \t") + 1);
		if (!host.empty()) {
			mysql_hosts.push_back(host);
		}
	}

	// Parse ports
	std::istringstream p(ports);
	std::string port;
	while (std::getline(p, port, ',')) {
		port.erase(0, port.find_first_not_of(" \t"));
		port.erase(port.find_last_not_of(" \t") + 1);
		if (!port.empty()) {
			mysql_ports.push_back(atoi(port.c_str()));
		}
	}

	// Ensure ports array matches hosts array size
	while (mysql_ports.size() < mysql_hosts.size()) {
		mysql_ports.push_back(3306); // Default MySQL port
	}

	mysql_user = user;
	mysql_password = password;
	mysql_schema = schema;

	// Create catalog
	catalog = new MySQL_Catalog(catalog_path);

	// Create FTS if path is provided
	if (!fts_path.empty()) {
		fts = new MySQL_FTS(fts_path);
	}
}

MySQL_Tool_Handler::~MySQL_Tool_Handler() {
	close();
	if (catalog) {
		delete catalog;
	}
	if (fts) {
		delete fts;
	}
	// Destroy the pool mutex
	pthread_mutex_destroy(&pool_lock);
	// Destroy the FTS mutex
	pthread_mutex_destroy(&fts_lock);
}

int MySQL_Tool_Handler::init() {
	// Initialize catalog
	if (catalog->init()) {
		return -1;
	}

	// Initialize FTS if configured
	if (fts && fts->init()) {
		proxy_error("Failed to initialize FTS, continuing without FTS\n");
		// Continue without FTS - it's optional
		delete fts;
		fts = NULL;
	}

	// Initialize connection pool
	if (init_connection_pool()) {
		return -1;
	}

	proxy_info("MySQL Tool Handler initialized for schema '%s'\n", mysql_schema.c_str());
	return 0;
}

bool MySQL_Tool_Handler::reset_fts_path(const std::string& path) {
	MySQL_FTS* new_fts = NULL;

	// Initialize new FTS outside lock (blocking I/O)
	if (!path.empty()) {
		new_fts = new MySQL_FTS(path);
		if (new_fts->init()) {
			proxy_error("Failed to initialize FTS with new path: %s\n", path.c_str());
			delete new_fts;
			return false;
		}
	}

	// Swap pointer under lock (non-blocking)
	pthread_mutex_lock(&fts_lock);
	MySQL_FTS* old_fts = fts;
	fts = new_fts;
	pthread_mutex_unlock(&fts_lock);
	if (old_fts) delete old_fts;

	return true;
}

/**
 * @brief Close all MySQL connections and cleanup resources
 *
 * Thread-safe method that closes all connections in the pool,
 * clears the connection vector, and resets the pool size.
 */
void MySQL_Tool_Handler::close() {
	// Close all connections in the pool
	pthread_mutex_lock(&pool_lock);
	for (auto& conn : connection_pool) {
		if (conn.mysql) {
			mysql_close(conn.mysql);
			conn.mysql = NULL;
		}
	}
	connection_pool.clear();
	pool_size = 0;
	pthread_mutex_unlock(&pool_lock);
}

/**
 * @brief Initialize the MySQL connection pool
 *
 * Creates one MySQL connection per configured host:port pair.
 * Uses mysql_init() and mysql_real_connect() to establish connections.
 * Sets 5-second timeouts for connect, read, and write operations.
 * Thread-safe: acquires pool_lock during initialization.
 *
 * @return 0 on success, -1 on error (logs specific error via proxy_error)
 */
int MySQL_Tool_Handler::init_connection_pool() {
	// Create one connection per host/port pair
	size_t num_connections = std::min(mysql_hosts.size(), mysql_ports.size());

	if (num_connections == 0) {
		proxy_error("MySQL_Tool_Handler: No hosts configured\n");
		return -1;
	}

	pthread_mutex_lock(&pool_lock);

	for (size_t i = 0; i < num_connections; i++) {
		MySQLConnection conn;
		conn.host = mysql_hosts[i];
		conn.port = mysql_ports[i];
		conn.in_use = false;

		// Initialize MySQL connection
		conn.mysql = mysql_init(NULL);
		if (!conn.mysql) {
			proxy_error("MySQL_Tool_Handler: mysql_init failed for %s:%d\n",
				conn.host.c_str(), conn.port);
			// Clean up previously created connections
			for (auto& existing_conn : connection_pool) {
				if (existing_conn.mysql) {
					mysql_close(existing_conn.mysql);
				}
			}
			connection_pool.clear();
			pool_size = 0;
			pthread_mutex_unlock(&pool_lock);
			return -1;
		}

		// Set connection timeout
		unsigned int timeout = 5;
		mysql_options(conn.mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
		mysql_options(conn.mysql, MYSQL_OPT_READ_TIMEOUT, &timeout);
		mysql_options(conn.mysql, MYSQL_OPT_WRITE_TIMEOUT, &timeout);

		// Connect to MySQL server
		// GHSA-7wh6-2vcc-gcm4: backend connections used by MCP query tools
		// must not enable multi-statement support.  validate_readonly_query
		// inspects the query as a single statement; allowing the server
		// to execute multi-statement payloads would make a payload like
		// "SELECT 1; RENAME TABLE x TO y" slip past the substring/regex
		// validator and run the trailing side-effecting statement.
		if (!mysql_real_connect(
			conn.mysql,
			conn.host.c_str(),
			mysql_user.c_str(),
			mysql_password.c_str(),
			mysql_schema.empty() ? NULL : mysql_schema.c_str(),
			conn.port,
			NULL,
			0
		)) {
			proxy_error("MySQL_Tool_Handler: mysql_real_connect failed for %s:%d: %s\n",
				conn.host.c_str(), conn.port, mysql_error(conn.mysql));
			mysql_close(conn.mysql);
			// Clean up previously created connections
			for (auto& existing_conn : connection_pool) {
				if (existing_conn.mysql) {
					mysql_close(existing_conn.mysql);
				}
			}
			connection_pool.clear();
			pool_size = 0;
			pthread_mutex_unlock(&pool_lock);
			return -1;
		}

		connection_pool.push_back(conn);
		pool_size++;

		proxy_info("MySQL_Tool_Handler: Connected to %s:%d\n",
			conn.host.c_str(), conn.port);
	}

	pthread_mutex_unlock(&pool_lock);

	proxy_info("MySQL_Tool_Handler: Connection pool initialized with %d connection(s)\n", pool_size);
	return 0;
}

/**
 * @brief Validate SQL identifier (table name, column name, schema name)
 *
 * Checks that the identifier contains only valid characters (alphanumeric,
 * underscore, dollar sign) and doesn't start with a digit.
 *
 * @param identifier The identifier to validate
 * @return true if valid, false otherwise
 */
static bool validate_sql_identifier(const std::string& identifier) {
	if (identifier.empty()) {
		return false;
	}

	// Check length (MySQL identifiers max 64 characters for tables, 128 for some)
	if (identifier.length() > 128) {
		return false;
	}

	// First character must be letter or underscore
	if (!isalpha(identifier[0]) && identifier[0] != '_') {
		return false;
	}

	// All characters must be alphanumeric, underscore, or dollar sign
	for (char c : identifier) {
		if (!isalnum(c) && c != '_' && c != '$') {
			return false;
		}
	}

	return true;
}

/**
 * @brief Escape a string value for use in SQL queries
 *
 * Uses mysql_real_escape_string which requires a valid MySQL connection.
 * The caller must have a connection and return it after use.
 *
 * @param conn MySQL connection to use for escaping
 * @param value The string value to escape
 * @return Escaped string safe for use in SQL queries
 */
static std::string escape_string(MYSQL* conn, const std::string& value) {
	if (!conn) {
		return ""; // Return empty on error (caller should handle)
	}

	// Allocate buffer for escaped string (2 * input + 1 for null terminator)
	std::string escaped(value.length() * 2 + 1, '\0');

	// Escape the string and check for errors
	unsigned long result_len = mysql_real_escape_string(conn, &escaped[0], value.c_str(), value.length());
	if (result_len == (unsigned long)-1) {
		// Error during escaping (e.g., invalid character set)
		return "";
	}

	// Resize to actual escaped length
	escaped.resize(result_len);

	return escaped;
}

/**
 * @brief Get an available connection from the pool
 *
 * Thread-safe method that searches for a connection not currently in use.
 * Marks the connection as in_use before returning.
 *
 * @return Pointer to MYSQL connection, or NULL if no available connection
 *         (logs error via proxy_error if pool exhausted)
 */
MYSQL* MySQL_Tool_Handler::get_connection() {
	MYSQL* conn = NULL;

	pthread_mutex_lock(&pool_lock);

	// Find an available connection
	for (auto& c : connection_pool) {
		if (!c.in_use) {
			c.in_use = true;
			conn = c.mysql;
			break;
		}
	}

	pthread_mutex_unlock(&pool_lock);

	if (!conn) {
		proxy_error("MySQL_Tool_Handler: No available connection in pool\n");
	}

	return conn;
}

/**
 * @brief Return a connection to the pool for reuse
 *
 * Thread-safe method that marks a previously obtained connection
 * as available for other operations. Does not close the connection.
 *
 * @param mysql The MYSQL connection to return to the pool
 */
void MySQL_Tool_Handler::return_connection(MYSQL* mysql) {
	pthread_mutex_lock(&pool_lock);

	// Find the connection and mark as available
	for (auto& c : connection_pool) {
		if (c.mysql == mysql) {
			c.in_use = false;
			break;
		}
	}

	pthread_mutex_unlock(&pool_lock);
}

/**
 * @brief Execute a SQL query and return results as JSON
 *
 * Thread-safe method that:
 * 1. Gets a connection from the pool
 * 2. Executes the query via mysql_query()
 * 3. Fetches results via mysql_store_result()
 * 4. Converts rows/columns to JSON format
 * 5. Returns the connection to the pool
 *
 * @param query SQL query to execute
 * @return JSON string with format:
 *         - Success: {"success":true, "columns":[...], "rows":[...], "row_count":N}
 *         - Failure: {"success":false, "error":"...", "sql_error":code}
 */
std::string MySQL_Tool_Handler::execute_query(const std::string& query) {

	json result;
	result["success"] = false;

	MYSQL* mysql = get_connection();

	if (!mysql) {
		result["error"] = "No available database connection";
		return result.dump();
	}

	// Execute query
	if (mysql_query(mysql, query.c_str()) != 0) {
		result["error"] = mysql_error(mysql);
		result["sql_error"] = mysql_errno(mysql);
		return_connection(mysql);
		return result.dump();
	}

	// Store result
	MYSQL_RES* res = mysql_store_result(mysql);

	if (!res) {
		// No result set (e.g., INSERT, UPDATE, etc.)
		result["success"] = true;
		result["rows_affected"] = (int)mysql_affected_rows(mysql);
		return_connection(mysql);
		return result.dump();
	}

	// Get column names (convert to lowercase for consistency)
	json columns = json::array();
	std::vector<std::string> lowercase_columns;
	MYSQL_FIELD* field;
	int field_count = 0;
	while ((field = mysql_fetch_field(res))) {
		field_count++;
		// Check if field name is null (can happen in edge cases)
		// Use placeholder name to maintain column index alignment
		std::string col_name = field->name ? field->name : "unknown_field";
		// Convert to lowercase
		std::transform(col_name.begin(), col_name.end(), col_name.begin(), ::tolower);
		columns.push_back(col_name);
		lowercase_columns.push_back(col_name);
	}

	// Get rows
	json rows = json::array();
	MYSQL_ROW row;
	unsigned int num_fields = mysql_num_fields(res);
	while ((row = mysql_fetch_row(res))) {
		json json_row = json::object();
		for (unsigned int i = 0; i < num_fields; i++) {
			// Use empty string for NULL values instead of nullptr
			// to avoid std::string construction from null issues
			json_row[lowercase_columns[i]] = row[i] ? row[i] : "";
		}
		rows.push_back(json_row);
	}

	mysql_free_result(res);
	return_connection(mysql);

	result["success"] = true;
	result["columns"] = columns;
	result["rows"] = rows;
	result["row_count"] = (int)rows.size();

	return result.dump();
}

std::string MySQL_Tool_Handler::sanitize_query(const std::string& query) {
	// Basic SQL injection prevention
	std::string sanitized = query;

	// Remove comments
	std::regex comment_regex("--[^\\n]*\\n|/\\*.*?\\*/");
	sanitized = std::regex_replace(sanitized, comment_regex, " ");

	// Trim
	sanitized.erase(0, sanitized.find_first_not_of(" \t\n\r"));
	sanitized.erase(sanitized.find_last_not_of(" \t\n\r") + 1);

	return sanitized;
}

bool MySQL_Tool_Handler::is_dangerous_query(const std::string& query) {
	std::string upper = query;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	// GHSA-7wh6-2vcc-gcm4: expanded to match the keyword list in
	// Query_Tool_Handler::validate_readonly_query.  The pre-fix list
	// missed several MySQL/PostgreSQL keywords (RENAME, FLUSH, RESET,
	// LOCK/UNLOCK, KILL, REPAIR, OPTIMIZE, HANDLER, INSTALL/UNINSTALL,
	// PURGE, BEGIN/START/COMMIT/ROLLBACK, XA, SHUTDOWN, INTO DUMPFILE,
	// ANALYZE) and the original list could be bypassed by simply using
	// one of those side-effecting verbs.  ANALYZE is included to catch
	// EXPLAIN ANALYZE in any obfuscated form ("EXPLAIN/**/ANALYZE",
	// "EXPLAIN (ANALYZE)", etc.) and the standalone "ANALYZE TABLE" /
	// PostgreSQL "ANALYZE foo" statements.
	static const char* dangerous[] = {
		"DROP", "DELETE", "INSERT", "UPDATE", "TRUNCATE",
		"ALTER", "CREATE", "GRANT", "REVOKE", "EXECUTE",
		"SCRIPT", "INTO OUTFILE", "INTO DUMPFILE", "LOAD_FILE",
		"LOAD DATA", "SLEEP", "BENCHMARK", "WAITFOR", "DELAY",
		"RENAME", "FLUSH", "RESET", "LOCK", "UNLOCK", "KILL",
		"OPTIMIZE", "REPAIR", "HANDLER", "INSTALL", "UNINSTALL",
		"CHANGE", "PURGE", "SAVEPOINT", "RELEASE", "ROLLBACK",
		"COMMIT", "BEGIN", "START", "XA", "SHUTDOWN",
		"ANALYZE", "CALL", "REPLACE"
	};

	for (const char* word : dangerous) {
		if (upper.find(word) != std::string::npos) {
			proxy_debug(PROXY_DEBUG_GENERIC, 3, "Dangerous keyword found: %s\n", word);
			return true;
		}
	}

	return false;
}

bool MySQL_Tool_Handler::contains_multi_statement(const std::string& query) {
	// GHSA-7wh6-2vcc-gcm4: lexer-style scan tolerant of ';' inside
	// string literals, identifier-quoted names, and comments.  Mirrors
	// the implementation in Query_Tool_Handler — the two should stay
	// in sync, since both classes accept SQL from MCP tool callers.
	enum class S { Code, SingleStr, DoubleStr, BacktickIdent, LineComment, BlockComment };
	S state = S::Code;
	bool seen_separator = false;
	const size_t n = query.size();
	for (size_t i = 0; i < n; ++i) {
		const char c = query[i];
		const char next = (i + 1 < n) ? query[i + 1] : '\0';
		switch (state) {
			case S::Code:
				if (c == '\'') { state = S::SingleStr; seen_separator = false; }
				else if (c == '"') { state = S::DoubleStr; seen_separator = false; }
				else if (c == '`') { state = S::BacktickIdent; seen_separator = false; }
				else if (c == '-' && next == '-') { state = S::LineComment; ++i; }
				else if (c == '/' && next == '*') { state = S::BlockComment; ++i; }
				else if (c == ';') { seen_separator = true; }
				else if (seen_separator && !std::isspace(static_cast<unsigned char>(c))) {
					return true;
				}
				break;
			case S::SingleStr:
				if (c == '\\' && next != '\0') { ++i; }
				else if (c == '\'') { state = S::Code; }
				break;
			case S::DoubleStr:
				if (c == '\\' && next != '\0') { ++i; }
				else if (c == '"') { state = S::Code; }
				break;
			case S::BacktickIdent:
				if (c == '`') { state = S::Code; }
				break;
			case S::LineComment:
				if (c == '\n') { state = S::Code; }
				break;
			case S::BlockComment:
				if (c == '*' && next == '/') { state = S::Code; ++i; }
				break;
		}
	}
	return false;
}

bool MySQL_Tool_Handler::validate_readonly_query(const std::string& query) {
	// GHSA-7wh6-2vcc-gcm4: reject multi-statement payloads up front,
	// before any substring/regex inspection looks at the first keyword.
	if (contains_multi_statement(query)) {
		return false;
	}

	std::string upper = query;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	// Must start with SELECT
	if (upper.substr(0, 6) != "SELECT") {
		return false;
	}

	// Check for dangerous keywords
	if (is_dangerous_query(query)) {
		return false;
	}

	// Check for SELECT * without LIMIT
	if (!allow_select_star) {
		std::regex select_star_regex("\\bSELECT\\s+\\*\\s+FROM", std::regex_constants::icase);
		if (std::regex_search(upper, select_star_regex)) {
			// Allow if there's a LIMIT clause
			if (upper.find("LIMIT ") == std::string::npos) {
				proxy_debug(PROXY_DEBUG_GENERIC, 3, "SELECT * without LIMIT rejected\n");
				return false;
			}
		}
	}

	return true;
}

std::string MySQL_Tool_Handler::list_schemas(const std::string& page_token, int page_size) {
	// Build query to list schemas
	std::string query =
		"SELECT schema_name, "
		"  (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = s.schema_name) as table_count "
		"FROM information_schema.schemata s "
		"WHERE schema_name NOT IN ('information_schema', 'performance_schema', 'mysql', 'sys') "
		"ORDER BY schema_name "
		"LIMIT " + std::to_string(page_size);

	// Execute the query
	std::string response = execute_query(query);

	// Parse the response and format it for the tool
	json result;
	try {
		json query_result = json::parse(response);
		if (query_result["success"] == true) {
			result = json::array();
			for (const auto& row : query_result["rows"]) {
				json schema_entry;
				schema_entry["name"] = row["schema_name"];
				schema_entry["table_count"] = row["table_count"];
				result.push_back(schema_entry);
			}
		} else {
			result["error"] = query_result["error"];
		}
	} catch (const std::exception& e) {
		result["error"] = std::string("Failed to parse query result: ") + e.what();
	}

	return result.dump();
}

std::string MySQL_Tool_Handler::list_tables(
	const std::string& schema,
	const std::string& page_token,
	int page_size,
	const std::string& name_filter
) {
	json result;

	// Validate schema identifier
	std::string target_schema = schema.empty() ? mysql_schema : schema;
	if (!validate_sql_identifier(target_schema)) {
		result["error"] = "Invalid schema name: contains unsafe characters";
		return result.dump();
	}

	// Get connection for escaping
	MYSQL* conn = get_connection();
	if (!conn) {
		result["error"] = "Failed to get database connection";
		return result.dump();
	}

	// Build query to list tables with metadata
	std::string sql =
		"SELECT "
		"  t.table_name, "
		"  t.table_type, "
		"  COALESCE(t.table_rows, 0) as row_count, "
		"  COALESCE(t.data_length, 0) + COALESCE(t.index_length, 0) as total_size, "
		"  t.create_time, "
		"  t.update_time "
		"FROM information_schema.tables t "
		"WHERE t.table_schema = '" + target_schema + "' ";

	if (!name_filter.empty()) {
		// Escape the name_filter to prevent SQL injection
		std::string escaped_filter = escape_string(conn, name_filter);
		if (escaped_filter.empty() && !name_filter.empty()) {
			return_connection(conn);
			result["error"] = "Failed to escape filter string";
			return result.dump();
		}
		sql += " AND t.table_name LIKE '%" + escaped_filter + "%'";
	}

	sql += " ORDER BY t.table_name LIMIT " + std::to_string(page_size);

	return_connection(conn);

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "list_tables query: %s\n", sql.c_str());

	// Execute the query
	std::string response = execute_query(sql);

	// Debug: print raw response
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "list_tables raw response: %s\n", response.c_str());

	// Parse and format the response
	try {
		json query_result = json::parse(response);
		if (query_result["success"] == true) {
			result = json::array();
			for (const auto& row : query_result["rows"]) {
				json table_entry;
				table_entry["name"] = row["table_name"];
				table_entry["type"] = row["table_type"];
				table_entry["row_count"] = row["row_count"];
				table_entry["total_size"] = row["total_size"];
				table_entry["create_time"] = row["create_time"];
				table_entry["update_time"] = row["update_time"];
				result.push_back(table_entry);
			}
		} else {
			result["error"] = query_result["error"];
		}
	} catch (const std::exception& e) {
		result["error"] = std::string("Failed to parse query result: ") + e.what();
	}

	return result.dump();
}

std::string MySQL_Tool_Handler::describe_table(const std::string& schema, const std::string& table) {
	json result;
	result["schema"] = schema;
	result["table"] = table;

	// Validate schema and table identifiers
	std::string target_schema = schema.empty() ? mysql_schema : schema;
	if (!validate_sql_identifier(target_schema)) {
		result["error"] = "Invalid schema name: contains unsafe characters";
		return result.dump();
	}
	if (!validate_sql_identifier(table)) {
		result["error"] = "Invalid table name: contains unsafe characters";
		return result.dump();
	}

	// Query to get columns
	std::string columns_query =
		"SELECT "
		"  column_name, "
		"  data_type, "
		"  column_type, "
		"  is_nullable, "
		"  column_default, "
		"  column_comment, "
		"  character_set_name, "
		"  collation_name "
		"FROM information_schema.columns "
		"WHERE table_schema = '" + target_schema + "' "
		"AND table_name = '" + table + "' "
		"ORDER BY ordinal_position";

	std::string columns_response = execute_query(columns_query);
	json columns_result = json::parse(columns_response);

	result["columns"] = json::array();
	if (columns_result["success"] == true) {
		for (const auto& row : columns_result["rows"]) {
			json col;
			col["name"] = row["column_name"];
			col["data_type"] = row["data_type"];
			col["column_type"] = row["column_type"];
			col["nullable"] = (row["is_nullable"] == "YES");
			col["default"] = row["column_default"];
			col["comment"] = row["column_comment"];
			col["charset"] = row["character_set_name"];
			col["collation"] = row["collation_name"];
			result["columns"].push_back(col);
		}
	}

	// Query to get primary key
	std::string pk_query =
		"SELECT k.column_name "
		"FROM information_schema.table_constraints t "
		"JOIN information_schema.key_column_usage k "
		"  ON t.constraint_name = k.constraint_name "
		"  AND t.table_schema = k.table_schema "
		"WHERE t.table_schema = '" + target_schema + "' "
		"AND t.table_name = '" + table + "' "
		"AND t.constraint_type = 'PRIMARY KEY' "
		"ORDER BY k.ordinal_position";

	std::string pk_response = execute_query(pk_query);
	json pk_result = json::parse(pk_response);

	result["primary_key"] = json::array();
	if (pk_result["success"] == true) {
		for (const auto& row : pk_result["rows"]) {
			result["primary_key"].push_back(row["column_name"]);
		}
	}

	// Query to get indexes
	std::string indexes_query =
		"SELECT "
		"  index_name, "
		"  column_name, "
		"  seq_in_index, "
		"  index_type, "
		"  non_unique, "
		"  nullable "
		"FROM information_schema.statistics "
		"WHERE table_schema = '" + target_schema + "' "
		"AND table_name = '" + table + "' "
		"ORDER BY index_name, seq_in_index";

	std::string indexes_response = execute_query(indexes_query);
	json indexes_result = json::parse(indexes_response);

	result["indexes"] = json::array();
	if (indexes_result["success"] == true) {
		for (const auto& row : indexes_result["rows"]) {
			json idx;
			idx["name"] = row["index_name"];
			idx["column"] = row["column_name"];
			idx["seq_in_index"] = row["seq_in_index"];
			idx["type"] = row["index_type"];
			idx["unique"] = (row["non_unique"] == "0");
			idx["nullable"] = (row["nullable"] == "YES");
			result["indexes"].push_back(idx);
		}
	}

	result["constraints"] = json::array(); // Placeholder for constraints

	return result.dump();
}

std::string MySQL_Tool_Handler::get_constraints(const std::string& schema, const std::string& table) {
	// Get foreign keys, unique constraints, check constraints
	json result = json::array();
	return result.dump();
}

std::string MySQL_Tool_Handler::describe_view(const std::string& schema, const std::string& view) {
	// Get view definition and columns
	json result;
	result["schema"] = schema;
	result["view"] = view;
	result["definition"] = "";
	result["columns"] = json::array();
	return result.dump();
}

std::string MySQL_Tool_Handler::table_profile(
	const std::string& schema,
	const std::string& table,
	const std::string& mode
) {
	// Get table profile including:
	// - Estimated row count and size
	// - Time columns detected
	// - ID columns detected
	// - Column null percentages
	// - Top N distinct values for low-cardinality columns
	// - Min/max for numeric/date columns

	json result;
	result["schema"] = schema;
	result["table"] = table;
	result["row_estimate"] = 0;
	result["size_estimate"] = 0;
	result["time_columns"] = json::array();
	result["id_columns"] = json::array();
	result["column_stats"] = json::object();

	return result.dump();
}

std::string MySQL_Tool_Handler::column_profile(
	const std::string& schema,
	const std::string& table,
	const std::string& column,
	int max_top_values
) {
	// Get column profile:
	// - Null count and percentage
	// - Distinct count (approximate)
	// - Top N values (capped)
	// - Min/max for numeric/date types

	json result;
	result["schema"] = schema;
	result["table"] = table;
	result["column"] = column;
	result["null_count"] = 0;
	result["distinct_count"] = 0;
	result["top_values"] = json::array();
	result["min_value"] = nullptr;
	result["max_value"] = nullptr;

	return result.dump();
}

std::string MySQL_Tool_Handler::sample_rows(
	const std::string& schema,
	const std::string& table,
	const std::string& columns,
	const std::string& where,
	const std::string& order_by,
	int limit
) {
	json result;

	// Validate schema and table identifiers
	std::string target_schema = schema.empty() ? mysql_schema : schema;
	if (!validate_sql_identifier(target_schema)) {
		result["error"] = "Invalid schema name: contains unsafe characters";
		return result.dump();
	}
	if (!validate_sql_identifier(table)) {
		result["error"] = "Invalid table name: contains unsafe characters";
		return result.dump();
	}

	// Validate columns parameter (if provided) - parse and validate each column
	if (!columns.empty()) {
		// Helper lambda to validate a single column identifier
		auto validate_column_identifier = [](const std::string& col) -> bool {
			if (col.empty()) return false;

			// Check for basic SQL injection patterns first
			if (col.find("--") != std::string::npos ||
				col.find("/*") != std::string::npos ||
				col.find(";") != std::string::npos) {
				return false;
			}

			// Allow: identifier, identifier.identifier, or identifier AS identifier
			// This is a simplified check - we validate character by character
			bool has_dot = false;
			bool in_identifier = true;
			int identifier_count = 0;

			for (size_t i = 0; i < col.length(); i++) {
				char c = col[i];

				// Skip whitespace
				if (isspace(c)) {
					in_identifier = false;
					continue;
				}

				// Check for "AS" keyword (case-insensitive)
				if (!in_identifier && i + 1 < col.length()) {
					if ((c == 'A' || c == 'a') &&
						(col[i + 1] == 'S' || col[i + 1] == 's')) {
						i++;  // Skip the 'S'
						in_identifier = false;
						continue;
					}
				}

				// Check for dot (qualified identifier like table.column)
				if (c == '.') {
					if (has_dot || identifier_count == 0) {
						return false;  // Multiple dots or dot at start
					}
					has_dot = true;
					in_identifier = true;
					continue;
				}

				// Must be valid identifier character
				if (!isalnum(c) && c != '_' && c != '$') {
					return false;
				}

				if (!in_identifier) {
					in_identifier = true;
					identifier_count++;
				}
			}

			// Must have at least one valid identifier
			return identifier_count > 0;
		};

		// Parse comma-separated column list and validate each part
		std::stringstream col_stream(columns);
		std::string col_part;
		while (std::getline(col_stream, col_part, ',')) {
			// Trim whitespace
			size_t start = col_part.find_first_not_of(" \t\n\r");
			size_t end = col_part.find_last_not_of(" \t\n\r");
			if (start == std::string::npos || end == std::string::npos) {
				continue;  // Skip empty segments
			}
			std::string trimmed = col_part.substr(start, end - start + 1);

			if (!validate_column_identifier(trimmed)) {
				result["error"] = "Invalid columns parameter: '" + trimmed + "' is not a valid column specification";
				return result.dump();
			}
		}
	}

	// Validate WHERE clause for dangerous patterns
	if (!where.empty()) {
		std::string upper_where = where;
		std::transform(upper_where.begin(), upper_where.end(), upper_where.begin(), ::toupper);
		if (upper_where.find("--") != std::string::npos ||
			upper_where.find("/*") != std::string::npos ||
			upper_where.find(";") != std::string::npos ||
			upper_where.find("UNION") != std::string::npos ||
			upper_where.find("DROP ") != std::string::npos ||
			upper_where.find("DELETE ") != std::string::npos ||
			upper_where.find("INSERT ") != std::string::npos ||
			upper_where.find("UPDATE ") != std::string::npos) {
			result["error"] = "Invalid WHERE clause: contains unsafe patterns";
			return result.dump();
		}
	}

	// Validate ORDER BY for dangerous patterns
	if (!order_by.empty()) {
		std::string upper_order = order_by;
		std::transform(upper_order.begin(), upper_order.end(), upper_order.begin(), ::toupper);
		if (upper_order.find("--") != std::string::npos ||
			upper_order.find("/*") != std::string::npos ||
			upper_order.find(";") != std::string::npos) {
			result["error"] = "Invalid ORDER BY clause: contains unsafe patterns";
			return result.dump();
		}
	}

	// Build and execute sampling query with hard cap
	int actual_limit = std::min(limit, 20); // Hard cap at 20 rows

	std::string sql = "SELECT ";
	sql += columns.empty() ? "*" : columns;
	sql += " FROM " + target_schema + "." + table;

	if (!where.empty()) {
		sql += " WHERE " + where;
	}

	if (!order_by.empty()) {
		sql += " ORDER BY " + order_by;
	}

	sql += " LIMIT " + std::to_string(actual_limit);

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "sample_rows query: %s\n", sql.c_str());

	// Execute the query
	std::string response = execute_query(sql);

	// Parse and return the results
	try {
		json query_result = json::parse(response);
		if (query_result["success"] == true) {
			result = query_result["rows"];
		} else {
			result["error"] = query_result["error"];
		}
	} catch (const std::exception& e) {
		result["error"] = std::string("Failed to parse query result: ") + e.what();
	}

	return result.dump();
}

std::string MySQL_Tool_Handler::sample_distinct(
	const std::string& schema,
	const std::string& table,
	const std::string& column,
	const std::string& where,
	int limit
) {
	json result;

	// Validate schema, table, and column identifiers
	std::string target_schema = schema.empty() ? mysql_schema : schema;
	if (!validate_sql_identifier(target_schema)) {
		result["error"] = "Invalid schema name: contains unsafe characters";
		return result.dump();
	}
	if (!validate_sql_identifier(table)) {
		result["error"] = "Invalid table name: contains unsafe characters";
		return result.dump();
	}
	// Column names can have dots (table.column) so handle that case
	if (column.find('.') == std::string::npos) {
		// Simple column name, validate directly
		if (!validate_sql_identifier(column)) {
			result["error"] = "Invalid column name: contains unsafe characters";
			return result.dump();
		}
	} else {
		// Compound identifier like "table.column", validate each part
		size_t dot_pos = column.find('.');
		std::string table_part = column.substr(0, dot_pos);
		std::string col_part = column.substr(dot_pos + 1);
		if (!validate_sql_identifier(table_part) || !validate_sql_identifier(col_part)) {
			result["error"] = "Invalid column identifier: contains unsafe characters";
			return result.dump();
		}
	}

	// Validate WHERE clause for dangerous patterns
	if (!where.empty()) {
		std::string upper_where = where;
		std::transform(upper_where.begin(), upper_where.end(), upper_where.begin(), ::toupper);
		if (upper_where.find("--") != std::string::npos ||
			upper_where.find("/*") != std::string::npos ||
			upper_where.find(";") != std::string::npos ||
			upper_where.find("UNION") != std::string::npos ||
			upper_where.find("DROP ") != std::string::npos ||
			upper_where.find("DELETE ") != std::string::npos ||
			upper_where.find("INSERT ") != std::string::npos ||
			upper_where.find("UPDATE ") != std::string::npos) {
			result["error"] = "Invalid WHERE clause: contains unsafe patterns";
			return result.dump();
		}
	}

	// Build query to sample distinct values
	int actual_limit = std::min(limit, 50);

	std::string sql = "SELECT DISTINCT " + column + " as value, COUNT(*) as count ";
	sql += " FROM " + target_schema + "." + table;

	if (!where.empty()) {
		sql += " WHERE " + where;
	}

	sql += " GROUP BY " + column + " ORDER BY count DESC LIMIT " + std::to_string(actual_limit);

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "sample_distinct query: %s\n", sql.c_str());

	// Execute the query
	std::string response = execute_query(sql);

	// Parse and return the results
	try {
		json query_result = json::parse(response);
		if (query_result["success"] == true) {
			result = query_result["rows"];
		} else {
			result["error"] = query_result["error"];
		}
	} catch (const std::exception& e) {
		result["error"] = std::string("Failed to parse query result: ") + e.what();
	}

	return result.dump();
}

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
 * @note Does not handle \/\* *\/ style comments
 */
std::string MySQL_Tool_Handler::strip_leading_comments(const std::string& sql) {
	std::string result = sql;
	size_t pos = 0;
	size_t len = result.length();

	// Skip any leading whitespace
	while (pos < len && isspace(result[pos])) {
		pos++;
	}

	// Remove leading '-- ' comment lines
	while (pos < len && result.substr(pos, 3) == "-- ") {
		// Found a comment, skip to end of line
		while (pos < len && result[pos] != '\n') {
			pos++;
		}

		// Skip the newline
		if (pos < len && result[pos] == '\n') {
			pos++;
		}

		// Skip any leading whitespace before next comment
		while (pos < len && isspace(result[pos])) {
			pos++;
		}
	}

	// Return the query without leading comments
	return result.substr(pos);
}

std::string MySQL_Tool_Handler::run_sql_readonly(
	const std::string& sql,
	int max_rows,
	int timeout_sec
) {
	json result;
	result["success"] = false;

	// Strip leading comments from the query
	std::string query = strip_leading_comments(sql);

	// Validate query is read-only
	if (!validate_readonly_query(query)) {
		result["error"] = "Query validation failed: not SELECT-only or contains dangerous keywords";
		return result.dump();
	}

	// Add LIMIT if not present and not an aggregate query
	std::string upper = sql;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	bool has_limit = upper.find("LIMIT ") != std::string::npos;
	bool is_aggregate = upper.find("GROUP BY") != std::string::npos ||
	                     upper.find("COUNT(") != std::string::npos ||
                         upper.find("SUM(") != std::string::npos ||
                         upper.find("AVG(") != std::string::npos;

	if (!has_limit && !is_aggregate && !allow_select_star) {
		query += " LIMIT " + std::to_string(std::min(max_rows, 200));
	}

	// Execute the query
	std::string response = execute_query(query);

	// Parse and return the results
	try {
		json query_result = json::parse(response);
		if (query_result["success"] == true) {
			result["success"] = true;
			result["rows"] = query_result["rows"];
			result["row_count"] = query_result["row_count"];
			result["columns"] = query_result["columns"];
		} else {
			result["error"] = query_result["error"];
			if (query_result.contains("sql_error")) {
				result["sql_error"] = query_result["sql_error"];
			}
		}
	} catch (const std::exception& e) {
		result["error"] = std::string("Failed to parse query result: ") + e.what();
	}

	return result.dump();
}

std::string MySQL_Tool_Handler::explain_sql(const std::string& sql) {
	// GHSA-7wh6-2vcc-gcm4: explain_sql was previously prepending
	// "EXPLAIN " to attacker-controlled SQL with no validation at all,
	// so any side-effecting statement could ride through as
	// "EXPLAIN <stmt>" or "EXPLAIN <stmt>;<stmt2>".  Apply the same
	// read-only validation used by run_sql_readonly before we build
	// the EXPLAIN query.
	if (!validate_readonly_query(sql)) {
		json result;
		result["error"] = "SQL is not read-only";
		return result.dump();
	}

	// Run EXPLAIN on the query
	std::string query = "EXPLAIN " + sql;

	// Execute the query
	std::string response = execute_query(query);

	// Parse and return the results
	json result;
	try {
		json query_result = json::parse(response);
		if (query_result["success"] == true) {
			result = query_result["rows"];
		} else {
			result["error"] = query_result["error"];
		}
	} catch (const std::exception& e) {
		result["error"] = std::string("Failed to parse query result: ") + e.what();
	}

	return result.dump();
}

std::string MySQL_Tool_Handler::suggest_joins(
	const std::string& schema,
	const std::string& table_a,
	const std::string& table_b,
	int max_candidates
) {
	// Heuristic-based join suggestion:
	// 1. Check for matching column names (id, user_id, etc.)
	// 2. Check for matching data types
	// 3. Check index presence on potential join columns

	json result = json::array();
	return result.dump();
}

std::string MySQL_Tool_Handler::find_reference_candidates(
	const std::string& schema,
	const std::string& table,
	const std::string& column,
	int max_tables
) {
	// Find tables that might be referenced by this column
	// Look for primary keys with matching names in other tables

	json result = json::array();
	return result.dump();
}

// Catalog tools (LLM memory)

std::string MySQL_Tool_Handler::catalog_upsert(
	const std::string& schema,
	const std::string& kind,
	const std::string& key,
	const std::string& document,
	const std::string& tags,
	const std::string& links
) {
	int rc = catalog->upsert(schema, kind, key, document, tags, links);

	json result;
	result["success"] = (rc == 0);
	result["schema"] = schema;
	if (rc == 0) {
		result["kind"] = kind;
		result["key"] = key;
	} else {
		result["error"] = "Failed to upsert catalog entry";
	}

	return result.dump();
}

std::string MySQL_Tool_Handler::catalog_get(const std::string& schema, const std::string& kind, const std::string& key) {
	std::string document;
	int rc = catalog->get(schema, kind, key, document);

	json result;
	result["success"] = (rc == 0);
	result["schema"] = schema;
	if (rc == 0) {
		result["kind"] = kind;
		result["key"] = key;
		// Parse as raw JSON value to preserve nested structure
		try {
			result["document"] = json::parse(document);
		} catch (const json::parse_error& e) {
			// If not valid JSON, store as string
			result["document"] = document;
		}
	} else {
		result["error"] = "Entry not found";
	}

	return result.dump();
}

std::string MySQL_Tool_Handler::catalog_search(
	const std::string& schema,
	const std::string& query,
	const std::string& kind,
	const std::string& tags,
	int limit,
	int offset
) {
	std::string results = catalog->search(schema, query, kind, tags, limit, offset);

	json result;
	result["schema"] = schema;
	result["query"] = query;
	result["results"] = json::parse(results);

	return result.dump();
}

std::string MySQL_Tool_Handler::catalog_list(
	const std::string& schema,
	const std::string& kind,
	int limit,
	int offset
) {
	std::string results = catalog->list(schema, kind, limit, offset);

	json result;
	result["schema"] = schema.empty() ? "all" : schema;
	result["kind"] = kind.empty() ? "all" : kind;
	result["results"] = json::parse(results);

	return result.dump();
}

std::string MySQL_Tool_Handler::catalog_merge(
	const std::string& keys,
	const std::string& target_key,
	const std::string& kind,
	const std::string& instructions
) {
	// Parse keys JSON array
	json keys_json = json::parse(keys);
	std::vector<std::string> key_list;

	for (const auto& k : keys_json) {
		key_list.push_back(k.get<std::string>());
	}

	int rc = catalog->merge(key_list, target_key, kind, instructions);

	json result;
	result["success"] = (rc == 0);
	result["target_key"] = target_key;
	result["merged_keys"] = keys_json;

	return result.dump();
}

std::string MySQL_Tool_Handler::catalog_delete(const std::string& schema, const std::string& kind, const std::string& key) {
	int rc = catalog->remove(schema, kind, key);

	json result;
	result["success"] = (rc == 0);
	result["schema"] = schema;
	result["kind"] = kind;
	result["key"] = key;

	return result.dump();
}

// ========== FTS Tools (Full Text Search) ==========
// NOTE: The fts_lock is intentionally held during the entire FTS operation
// to serialize all FTS operations for correctness. This prevents race conditions
// where reset_fts_path() or reinit_fts() could delete the MySQL_FTS instance
// while an operation is in progress, which would cause use-after-free.
// If performance becomes an issue, consider reference counting instead.

std::string MySQL_Tool_Handler::fts_index_table(
	const std::string& schema,
	const std::string& table,
	const std::string& columns,
	const std::string& primary_key,
	const std::string& where_clause
) {
	pthread_mutex_lock(&fts_lock);
	if (!fts) {
		json result;
		result["success"] = false;
		result["error"] = "FTS not initialized";
		pthread_mutex_unlock(&fts_lock);
		return result.dump();
	}

	std::string out = fts->index_table(schema, table, columns, primary_key, where_clause, this);
	pthread_mutex_unlock(&fts_lock);
	return out;
}

std::string MySQL_Tool_Handler::fts_search(
	const std::string& query,
	const std::string& schema,
	const std::string& table,
	int limit,
	int offset
) {
	pthread_mutex_lock(&fts_lock);
	if (!fts) {
		json result;
		result["success"] = false;
		result["error"] = "FTS not initialized";
		pthread_mutex_unlock(&fts_lock);
		return result.dump();
	}

	std::string out = fts->search(query, schema, table, limit, offset);
	pthread_mutex_unlock(&fts_lock);
	return out;
}

std::string MySQL_Tool_Handler::fts_list_indexes() {
	pthread_mutex_lock(&fts_lock);
	if (!fts) {
		json result;
		result["success"] = false;
		result["error"] = "FTS not initialized";
		pthread_mutex_unlock(&fts_lock);
		return result.dump();
	}

	std::string out = fts->list_indexes();
	pthread_mutex_unlock(&fts_lock);
	return out;
}

std::string MySQL_Tool_Handler::fts_delete_index(const std::string& schema, const std::string& table) {
	pthread_mutex_lock(&fts_lock);
	if (!fts) {
		json result;
		result["success"] = false;
		result["error"] = "FTS not initialized";
		pthread_mutex_unlock(&fts_lock);
		return result.dump();
	}

	std::string out = fts->delete_index(schema, table);
	pthread_mutex_unlock(&fts_lock);
	return out;
}

std::string MySQL_Tool_Handler::fts_reindex(const std::string& schema, const std::string& table) {
	pthread_mutex_lock(&fts_lock);
	if (!fts) {
		json result;
		result["success"] = false;
		result["error"] = "FTS not initialized";
		pthread_mutex_unlock(&fts_lock);
		return result.dump();
	}

	std::string out = fts->reindex(schema, table, this);
	pthread_mutex_unlock(&fts_lock);
	return out;
}

std::string MySQL_Tool_Handler::fts_rebuild_all() {
	pthread_mutex_lock(&fts_lock);
	if (!fts) {
		json result;
		result["success"] = false;
		result["error"] = "FTS not initialized";
		pthread_mutex_unlock(&fts_lock);
		return result.dump();
	}

	std::string out = fts->rebuild_all(this);
	pthread_mutex_unlock(&fts_lock);
	return out;
}

int MySQL_Tool_Handler::reinit_fts(const std::string& fts_path) {
	proxy_info("MySQL_Tool_Handler: Reinitializing FTS with path: %s\n", fts_path.c_str());

	// Check if directory exists (SQLite can't create directories)
	std::string::size_type last_slash = fts_path.find_last_of("/");
	if (last_slash != std::string::npos && last_slash > 0) {
		std::string dir = fts_path.substr(0, last_slash);
		struct stat st;
		if (stat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
			proxy_error("MySQL_Tool_Handler: Directory does not exist for path '%s' (directory: '%s')\n",
				fts_path.c_str(), dir.c_str());
			return -1;
		}
	}

	// First, test if we can open the new database (outside lock)
	MySQL_FTS* new_fts = new MySQL_FTS(fts_path);
	if (!new_fts) {
		proxy_error("MySQL_Tool_Handler: Failed to create new FTS handler\n");
		return -1;
	}

	if (new_fts->init() != 0) {
		proxy_error("MySQL_Tool_Handler: Failed to initialize FTS at %s\n", fts_path.c_str());
		delete new_fts;
		return -1;  // Return error WITHOUT closing old FTS
	}

	// Success! Now swap the pointer under lock
	pthread_mutex_lock(&fts_lock);
	MySQL_FTS* old_fts = fts;
	fts = new_fts;
	pthread_mutex_unlock(&fts_lock);
	if (old_fts) delete old_fts;

	proxy_info("MySQL_Tool_Handler: FTS reinitialized successfully at %s\n", fts_path.c_str());
	return 0;
}

#endif /* PROXYSQL40 */
