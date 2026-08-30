#ifdef PROXYSQL40


#include "proxysql.h"
/**
 * @file RAG_Tool_Handler.cpp
 * @brief Implementation of RAG Tool Handler for MCP protocol
 *
 * Implements RAG-powered tools through MCP protocol for retrieval operations.
 * This file contains the complete implementation of all RAG functionality
 * including search, fetch, and administrative tools.
 *
 * The RAG subsystem provides:
 * - Full-text search using SQLite FTS5
 * - Semantic search using vector embeddings with sqlite3-vec
 * - Hybrid search combining both approaches with Reciprocal Rank Fusion
 * - Comprehensive filtering capabilities
 * - Security features including input validation and limits
 * - Performance optimizations
 *
 * @see RAG_Tool_Handler.h
 * @ingroup mcp
 * @ingroup rag
 */

#include "RAG_Tool_Handler.h"
#include "AI_Features_Manager.h"
#include "Discovery_Schema.h"
#include "GenAI_Thread.h"
#include "LLM_Bridge.h"
#include "backend_client.h"
#include "proxysql_debug.h"
#include "cpp.h"
#include <sstream>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <vector>
#include <utility>
#include <mysql.h>
#include <libpq-fe.h>

// Forward declaration for GloGATH
extern GenAI_Threads_Handler *GloGATH;

// JSON library
#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

// Forward declaration for GloGATH
extern GenAI_Threads_Handler *GloGATH;

// ============================================================================
// Tool Invocation Tracking
// ============================================================================

/**
 * @brief Track tool invocation (thread-safe)
 */
void track_tool_invocation(
	RAG_Tool_Handler* handler,
	const std::string& endpoint,
	const std::string& tool_name,
	const std::string& schema_name,
	unsigned long long duration_us
) {
	pthread_mutex_lock(&handler->counters_lock);
	handler->tool_usage_stats[endpoint][tool_name][schema_name].add_timing(duration_us, monotonic_time());
	pthread_mutex_unlock(&handler->counters_lock);
}

bool is_valid_sql_identifier(const std::string& identifier) {
	if (identifier.empty()) {
		return false;
	}
	if (!(std::isalpha(static_cast<unsigned char>(identifier[0])) || identifier[0] == '_')) {
		return false;
	}
	for (size_t i = 1; i < identifier.size(); ++i) {
		const unsigned char c = static_cast<unsigned char>(identifier[i]);
		if (!(std::isalnum(c) || identifier[i] == '_' || identifier[i] == '$')) {
			return false;
		}
	}
	return true;
}

std::string quote_mysql_identifier(const std::string& identifier) {
	std::string out = "`";
	for (char c : identifier) {
		if (c == '`') {
			out += "``";
		} else {
			out.push_back(c);
		}
	}
	out += "`";
	return out;
}

std::string quote_pgsql_identifier(const std::string& identifier) {
	std::string out = "\"";
	for (char c : identifier) {
		if (c == '"') {
			out += "\"\"";
		} else {
			out.push_back(c);
		}
	}
	out += "\"";
	return out;
}

std::string escape_mysql_literal(MYSQL* conn, const std::string& value) {
	std::string escaped;
	escaped.resize(value.size() * 2 + 1);
	unsigned long len = mysql_real_escape_string(conn, &escaped[0], value.c_str(), static_cast<unsigned long>(value.size()));
	escaped.resize(len);
	return "'" + escaped + "'";
}

std::string escape_pgsql_literal(PGconn* conn, const std::string& value, std::string& error) {
	char* escaped = PQescapeLiteral(conn, value.c_str(), value.size());
	if (!escaped) {
		error = "Failed to escape PostgreSQL literal";
		return "";
	}
	std::string out(escaped);
	PQfreemem(escaped);
	return out;
}

std::string json_scalar_to_sql_literal_mysql(MYSQL* conn, const json& value, std::string& error) {
	if (value.is_null()) {
		return "NULL";
	}
	if (value.is_string()) {
		return escape_mysql_literal(conn, value.get<std::string>());
	}
	if (value.is_boolean()) {
		return value.get<bool>() ? "1" : "0";
	}
	if (value.is_number()) {
		return value.dump();
	}
	error = "Primary key value must be a scalar";
	return "";
}

std::string json_scalar_to_sql_literal_pgsql(PGconn* conn, const json& value, std::string& error) {
	if (value.is_null()) {
		return "NULL";
	}
	if (value.is_string()) {
		std::string escaped = escape_pgsql_literal(conn, value.get<std::string>(), error);
		if (!error.empty()) {
			return "";
		}
		return escaped;
	}
	if (value.is_boolean()) {
		return value.get<bool>() ? "TRUE" : "FALSE";
	}
	if (value.is_number()) {
		return value.dump();
	}
	error = "Primary key value must be a scalar";
	return "";
}

bool append_source_pk_predicates_mysql(
	MYSQL* conn,
	const json& pk_json,
	const std::string& pk_column,
	std::string& where_clause,
	std::string& error
) {
	where_clause.clear();
	if (pk_json.is_object()) {
		if (pk_json.empty()) {
			error = "Source primary key JSON is empty";
			return false;
		}
		for (auto it = pk_json.begin(); it != pk_json.end(); ++it) {
			const std::string& key = it.key();
			if (!is_valid_sql_identifier(key)) {
				error = "Primary key column contains unsafe characters: " + key;
				return false;
			}
			std::string literal = json_scalar_to_sql_literal_mysql(conn, it.value(), error);
			if (!error.empty()) {
				return false;
			}
			if (!where_clause.empty()) {
				where_clause += " AND ";
			}
			where_clause += quote_mysql_identifier(key) + " = " + literal;
		}
		return true;
	}

	if (!is_valid_sql_identifier(pk_column)) {
		error = "Primary key column contains unsafe characters: " + pk_column;
		return false;
	}
	std::string literal = json_scalar_to_sql_literal_mysql(conn, pk_json, error);
	if (!error.empty()) {
		return false;
	}
	where_clause = quote_mysql_identifier(pk_column) + " = " + literal;
	return true;
}

bool append_source_pk_predicates_pgsql(
	PGconn* conn,
	const json& pk_json,
	const std::string& pk_column,
	std::string& where_clause,
	std::string& error
) {
	where_clause.clear();
	if (pk_json.is_object()) {
		if (pk_json.empty()) {
			error = "Source primary key JSON is empty";
			return false;
		}
		for (auto it = pk_json.begin(); it != pk_json.end(); ++it) {
			const std::string& key = it.key();
			if (!is_valid_sql_identifier(key)) {
				error = "Primary key column contains unsafe characters: " + key;
				return false;
			}
			std::string literal = json_scalar_to_sql_literal_pgsql(conn, it.value(), error);
			if (!error.empty()) {
				return false;
			}
			if (!where_clause.empty()) {
				where_clause += " AND ";
			}
			where_clause += quote_pgsql_identifier(key) + " = " + literal;
		}
		return true;
	}

	if (!is_valid_sql_identifier(pk_column)) {
		error = "Primary key column contains unsafe characters: " + pk_column;
		return false;
	}
	std::string literal = json_scalar_to_sql_literal_pgsql(conn, pk_json, error);
	if (!error.empty()) {
		return false;
	}
	where_clause = quote_pgsql_identifier(pk_column) + " = " + literal;
	return true;
}

json mysql_result_to_json(MYSQL_RES* res) {
	json out;
	out["columns"] = json::array();
	out["rows"] = json::array();

	if (!res) {
		return out;
	}

	MYSQL_FIELD* fields = mysql_fetch_fields(res);
	const unsigned int num_fields = mysql_num_fields(res);
	std::vector<std::string> column_names;
	column_names.reserve(num_fields);
	for (unsigned int i = 0; i < num_fields; ++i) {
		const char* name = fields && fields[i].name ? fields[i].name : "unknown_field";
		column_names.emplace_back(name);
		out["columns"].push_back(name);
	}

	MYSQL_ROW row;
	while ((row = mysql_fetch_row(res))) {
		json row_obj = json::object();
		for (unsigned int i = 0; i < num_fields; ++i) {
			row_obj[column_names[i]] = row[i] ? row[i] : "";
		}
		out["rows"].push_back(row_obj);
	}

	return out;
}

json pgsql_result_to_json(PGresult* res) {
	json out;
	out["columns"] = json::array();
	out["rows"] = json::array();

	if (!res) {
		return out;
	}

	const int num_fields = PQnfields(res);
	const int num_rows = PQntuples(res);
	std::vector<std::string> column_names;
	column_names.reserve(num_fields);
	for (int i = 0; i < num_fields; ++i) {
		const char* name = PQfname(res, i);
		column_names.emplace_back(name ? name : "unknown_field");
		out["columns"].push_back(name ? name : "unknown_field");
	}

	for (int r = 0; r < num_rows; ++r) {
		json row_obj = json::object();
		for (int c = 0; c < num_fields; ++c) {
			row_obj[column_names[c]] = PQgetisnull(res, r, c) ? "" : PQgetvalue(res, r, c);
		}
		out["rows"].push_back(row_obj);
	}

	return out;
}

// ============================================================================
// Constructor/Destructor
// ============================================================================

/**
 * @brief Constructor
 *
 * Initializes the RAG tool handler with configuration parameters from GenAI_Thread
 * if available, otherwise uses default values.
 *
 * Configuration parameters:
 * - k_max: Maximum number of search results (default: 50)
 * - candidates_max: Maximum number of candidates for hybrid search (default: 500)
 * - query_max_bytes: Maximum query length in bytes (default: 8192)
 * - response_max_bytes: Maximum response size in bytes (default: 5000000)
 * - timeout_ms: Operation timeout in milliseconds (default: 2000)
 *
 * @param ai_mgr Pointer to AI_Features_Manager for database access and configuration
 *
 * @see AI_Features_Manager
 * @see GenAI_Thread
 */
RAG_Tool_Handler::RAG_Tool_Handler(AI_Features_Manager* ai_mgr, const std::string& cat_path)
	: vector_db(NULL),
	  ai_manager(ai_mgr),
	  catalog(NULL),
	  catalog_path(cat_path),
	  k_max(50),
	  candidates_max(500),
	  query_max_bytes(8192),
	  response_max_bytes(5000000),
	  timeout_ms(2000)
{
	// Initialize counters mutex
	pthread_mutex_init(&counters_lock, NULL);
	refresh_runtime_dependencies(ai_mgr);

	proxy_debug(PROXY_DEBUG_GENAI, 3, "RAG_Tool_Handler created\n");
}

/**
 * @brief Destructor
 *
 * Cleans up resources and closes database connections.
 *
 * @see close()
 */
RAG_Tool_Handler::~RAG_Tool_Handler() {
	close();
	pthread_mutex_destroy(&counters_lock);
	proxy_debug(PROXY_DEBUG_GENAI, 3, "RAG_Tool_Handler destroyed\n");
}

// ============================================================================
// Lifecycle
// ============================================================================

/**
 * @brief Initialize the tool handler
 *
 * Initializes the RAG tool handler by establishing database connections
 * and preparing internal state. Must be called before executing any tools.
 *
 * @return 0 on success, -1 on error
 *
 * @see close()
 * @see vector_db
 * @see ai_manager
 */
int RAG_Tool_Handler::init() {
	refresh_runtime_dependencies(ai_manager);

	if (!vector_db) {
		proxy_error("RAG_Tool_Handler: Vector database not available\n");
		return -1;
	}

	// Initialize catalog for logging if path is provided
	if (!catalog_path.empty()) {
		catalog = new Discovery_Schema(catalog_path);
		if (catalog->init() != 0) {
			proxy_error("RAG_Tool_Handler: Failed to initialize catalog at %s\n", catalog_path.c_str());
			delete catalog;
			catalog = NULL;
			// Continue without catalog - logging will be skipped
		} else {
			proxy_info("RAG_Tool_Handler: Catalog initialized for logging\n");
		}
	}

	proxy_info("RAG_Tool_Handler initialized\n");
	return 0;
}

void RAG_Tool_Handler::refresh_runtime_dependencies(AI_Features_Manager* ai_mgr) {
	ai_manager = ai_mgr;
	vector_db = ai_manager ? ai_manager->get_vector_db() : NULL;

	if (GloGATH) {
		k_max = GloGATH->variables.genai_rag_k_max;
		candidates_max = GloGATH->variables.genai_rag_candidates_max;
		query_max_bytes = GloGATH->variables.genai_rag_query_max_bytes;
		response_max_bytes = GloGATH->variables.genai_rag_response_max_bytes;
		timeout_ms = GloGATH->variables.genai_rag_timeout_ms;
	}
}

/**
 * @brief Close and cleanup
 *
 * Cleans up resources and closes database connections. Called automatically
 * by the destructor.
 *
 * @see init()
 * @see ~RAG_Tool_Handler()
 */
void RAG_Tool_Handler::close() {
	if (catalog) {
		delete catalog;
		catalog = NULL;
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Extract string parameter from JSON
 *
 * Safely extracts a string parameter from a JSON object, handling type
 * conversion if necessary. Returns the default value if the key is not
 * found or cannot be converted to a string.
 *
 * @param j JSON object to extract from
 * @param key Parameter key to extract
 * @param default_val Default value if key not found
 * @return Extracted string value or default
 *
 * @see get_json_int()
 * @see get_json_bool()
 * @see get_json_string_array()
 * @see get_json_int_array()
 */
std::string RAG_Tool_Handler::get_json_string(const json& j, const std::string& key,
                                              const std::string& default_val) {
	if (j.contains(key) && !j[key].is_null()) {
		if (j[key].is_string()) {
			return j[key].get<std::string>();
		} else {
			// Convert to string if not already
			return j[key].dump();
		}
	}
	return default_val;
}

/**
 * @brief Extract int parameter from JSON
 *
 * Safely extracts an integer parameter from a JSON object, handling type
 * conversion from string if necessary. Returns the default value if the
 * key is not found or cannot be converted to an integer.
 *
 * @param j JSON object to extract from
 * @param key Parameter key to extract
 * @param default_val Default value if key not found
 * @return Extracted int value or default
 *
 * @see get_json_string()
 * @see get_json_bool()
 * @see get_json_string_array()
 * @see get_json_int_array()
 */
int RAG_Tool_Handler::get_json_int(const json& j, const std::string& key, int default_val) {
	if (j.contains(key) && !j[key].is_null()) {
		if (j[key].is_number()) {
			return j[key].get<int>();
		} else if (j[key].is_string()) {
			try {
				return std::stoi(j[key].get<std::string>());
			} catch (const std::exception& e) {
				proxy_error("RAG_Tool_Handler: Failed to convert string to int for key '%s': %s\n",
				           key.c_str(), e.what());
				return default_val;
			}
		}
	}
	return default_val;
}

/**
 * @brief Extract bool parameter from JSON
 *
 * Safely extracts a boolean parameter from a JSON object, handling type
 * conversion from string or integer if necessary. Returns the default
 * value if the key is not found or cannot be converted to a boolean.
 *
 * @param j JSON object to extract from
 * @param key Parameter key to extract
 * @param default_val Default value if key not found
 * @return Extracted bool value or default
 *
 * @see get_json_string()
 * @see get_json_int()
 * @see get_json_string_array()
 * @see get_json_int_array()
 */
bool RAG_Tool_Handler::get_json_bool(const json& j, const std::string& key, bool default_val) {
	if (j.contains(key) && !j[key].is_null()) {
		if (j[key].is_boolean()) {
			return j[key].get<bool>();
		} else if (j[key].is_string()) {
			std::string val = j[key].get<std::string>();
			return (val == "true" || val == "1");
		} else if (j[key].is_number()) {
			return j[key].get<int>() != 0;
		}
	}
	return default_val;
}

/**
 * @brief Extract string array from JSON
 *
 * Safely extracts a string array parameter from a JSON object, filtering
 * out non-string elements. Returns an empty vector if the key is not
 * found or is not an array.
 *
 * @param j JSON object to extract from
 * @param key Parameter key to extract
 * @return Vector of extracted strings
 *
 * @see get_json_string()
 * @see get_json_int()
 * @see get_json_bool()
 * @see get_json_int_array()
 */
std::vector<std::string> RAG_Tool_Handler::get_json_string_array(const json& j, const std::string& key) {
	std::vector<std::string> result;
	if (j.contains(key) && j[key].is_array()) {
		for (const auto& item : j[key]) {
			if (item.is_string()) {
				result.push_back(item.get<std::string>());
			}
		}
	}
	return result;
}

/**
 * @brief Extract int array from JSON
 *
 * Safely extracts an integer array parameter from a JSON object, handling
 * type conversion from string if necessary. Returns an empty vector if
 * the key is not found or is not an array.
 *
 * @param j JSON object to extract from
 * @param key Parameter key to extract
 * @return Vector of extracted integers
 *
 * @see get_json_string()
 * @see get_json_int()
 * @see get_json_bool()
 * @see get_json_string_array()
 */
std::vector<int> RAG_Tool_Handler::get_json_int_array(const json& j, const std::string& key) {
	std::vector<int> result;
	if (j.contains(key) && j[key].is_array()) {
		for (const auto& item : j[key]) {
			if (item.is_number()) {
				result.push_back(item.get<int>());
			} else if (item.is_string()) {
				try {
					result.push_back(std::stoi(item.get<std::string>()));
				} catch (const std::exception& e) {
					proxy_error("RAG_Tool_Handler: Failed to convert string to int in array: %s\n", e.what());
				}
			}
		}
	}
	return result;
}

/**
 * @brief Validate and limit k parameter
 *
 * Ensures the k parameter is within acceptable bounds (1 to k_max).
 * Returns default value of 10 if k is invalid.
 *
 * @param k Requested number of results
 * @return Validated k value within configured limits
 *
 * @see validate_candidates()
 * @see k_max
 */
int RAG_Tool_Handler::validate_k(int k) {
	if (k <= 0) return 10;  // Default
	if (k > k_max) return k_max;
	return k;
}

/**
 * @brief Validate and limit candidates parameter
 *
 * Ensures the candidates parameter is within acceptable bounds (1 to candidates_max).
 * Returns default value of 50 if candidates is invalid.
 *
 * @param candidates Requested number of candidates
 * @return Validated candidates value within configured limits
 *
 * @see validate_k()
 * @see candidates_max
 */
int RAG_Tool_Handler::validate_candidates(int candidates) {
	if (candidates <= 0) return 50;  // Default
	if (candidates > candidates_max) return candidates_max;
	return candidates;
}

/**
 * @brief Validate query length
 *
 * Checks if the query string length is within the configured query_max_bytes limit.
 *
 * @param query Query string to validate
 * @return true if query is within length limits, false otherwise
 *
 * @see query_max_bytes
 */
bool RAG_Tool_Handler::validate_query_length(const std::string& query) {
	return static_cast<int>(query.length()) <= query_max_bytes;
}

/**
 * @brief Escape FTS query string for safe use in MATCH clause
 *
 * Escapes single quotes in FTS query strings by doubling them,
 * which is the standard escaping method for SQLite FTS5.
 * This prevents FTS injection while allowing legitimate single quotes in queries.
 *
 * @param query Raw FTS query string from user input
 * @return Escaped query string safe for use in MATCH clause
 *
 * @see execute_tool()
 */
std::string RAG_Tool_Handler::escape_fts_query(const std::string& query) {
	std::string escaped;
	escaped.reserve(query.length() * 2); // Reserve space for potential escaping

	for (char c : query) {
		if (c == '\'') {
			escaped += "''"; // Escape single quote by doubling
		} else {
			escaped += c;
		}
	}

	return escaped;
}

/**
 * @brief Execute database query and return results
 *
 * Executes a SQL query against the vector database and returns the results.
 * Handles error checking and logging. The caller is responsible for freeing
 * the returned SQLite3_result.
 *
 * @param query SQL query string to execute
 * @return SQLite3_result pointer or NULL on error
 *
 * @see vector_db
 */
SQLite3_result* RAG_Tool_Handler::execute_query(const char* query) {
	if (!vector_db) {
		proxy_error("RAG_Tool_Handler: Vector database not available\n");
		return NULL;
	}

	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* result = vector_db->execute_statement(query, &error, &cols, &affected_rows);

	if (error) {
		proxy_error("RAG_Tool_Handler: SQL error: %s\n", error);
		(*proxy_sqlite3_free)(error);
		return NULL;
	}

	return result;
}

/**
 * @brief Execute parameterized database query with bindings
 *
 * Executes a parameterized SQL query against the vector database with bound parameters
 * and returns the results. This prevents SQL injection vulnerabilities.
 * Handles error checking and logging. The caller is responsible for freeing
 * the returned SQLite3_result.
 *
 * @param query SQL query string with placeholders to execute
 * @param text_bindings Vector of text parameter bindings (position, value)
 * @param int_bindings Vector of integer parameter bindings (position, value)
 * @return SQLite3_result pointer or NULL on error
 *
 * @see vector_db
 */
SQLite3_result* RAG_Tool_Handler::execute_parameterized_query(const char* query, const std::vector<std::pair<int, std::string>>& text_bindings, const std::vector<std::pair<int, int>>& int_bindings) {
	if (!vector_db) {
		proxy_error("RAG_Tool_Handler: Vector database not available\n");
		return NULL;
	}

	// Prepare the statement
	auto prepare_result = vector_db->prepare_v2(query);
	if (prepare_result.first != SQLITE_OK) {
		proxy_error("RAG_Tool_Handler: Failed to prepare statement: %s\n", (*proxy_sqlite3_errstr)(prepare_result.first));
		return NULL;
	}

	sqlite3_stmt* stmt = prepare_result.second.get();
	if (!stmt) {
		proxy_error("RAG_Tool_Handler: Prepared statement is NULL\n");
		return NULL;
	}

	// Bind text parameters
	for (const auto& binding : text_bindings) {
		int position = binding.first;
		const std::string& value = binding.second;
		int result = (*proxy_sqlite3_bind_text)(stmt, position, value.c_str(), -1, SQLITE_STATIC);
		if (result != SQLITE_OK) {
			proxy_error("RAG_Tool_Handler: Failed to bind text parameter at position %d: %s\n", position, (*proxy_sqlite3_errstr)(result));
			return NULL;
		}
	}

	// Bind integer parameters
	for (const auto& binding : int_bindings) {
		int position = binding.first;
		int value = binding.second;
		int result = (*proxy_sqlite3_bind_int)(stmt, position, value);
		if (result != SQLITE_OK) {
			proxy_error("RAG_Tool_Handler: Failed to bind integer parameter at position %d: %s\n", position, (*proxy_sqlite3_errstr)(result));
			return NULL;
		}
	}

	// Execute the prepared statement and get results
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* result = NULL;

	// Use execute_prepared to execute the bound statement, not the raw query
	if (!vector_db->execute_prepared(stmt, &error, &cols, &affected_rows, &result)) {
		if (error) {
			proxy_error("RAG_Tool_Handler: SQL error: %s\n", error);
			(*proxy_sqlite3_free)(error);
		}
		return NULL;
	}

	return result;
}

/**
 * @brief Build SQL filter conditions from JSON filters
 *
 * Builds SQL WHERE conditions from JSON filter parameters with proper input validation
 * to prevent SQL injection. This consolidates the duplicated filter building logic
 * across different search tools.
 *
 * @param filters JSON object containing filter parameters
 * @param sql Reference to SQL string to append conditions to
 * * @return true on success, false on validation error
 *
 * @see execute_tool()
 */
bool RAG_Tool_Handler::build_sql_filters(const json& filters, std::string& sql, bool add_where_clause) {
	// Add WHERE clause base for filter conditions if requested
	if (add_where_clause) {
		sql += " WHERE 1=1";
	}

	// Apply filters with input validation to prevent SQL injection
	if (filters.contains("source_ids") && filters["source_ids"].is_array()) {
		std::vector<int> source_ids = get_json_int_array(filters, "source_ids");
		if (!source_ids.empty()) {
			// Validate that all source_ids are integers (they should be by definition)
			std::string source_list = "";
			for (size_t i = 0; i < source_ids.size(); ++i) {
				if (i > 0) source_list += ",";
				source_list += std::to_string(source_ids[i]);
			}
			sql += " AND c.source_id IN (" + source_list + ")";
		}
	}

	if (filters.contains("source_names") && filters["source_names"].is_array()) {
		std::vector<std::string> source_names = get_json_string_array(filters, "source_names");
		if (!source_names.empty()) {
			// Validate source names to prevent SQL injection
			std::string source_list = "";
			for (size_t i = 0; i < source_names.size(); ++i) {
				const std::string& source_name = source_names[i];
				// Basic validation - check for dangerous characters
				if (source_name.find('\'') != std::string::npos ||
					source_name.find('\\') != std::string::npos ||
					source_name.find(';') != std::string::npos) {
					return false;
				}
				if (i > 0) source_list += ",";
				source_list += "'" + source_name + "'";
			}
			sql += " AND c.source_id IN (SELECT source_id FROM rag_sources WHERE name IN (" + source_list + "))";
		}
	}

	if (filters.contains("doc_ids") && filters["doc_ids"].is_array()) {
		std::vector<std::string> doc_ids = get_json_string_array(filters, "doc_ids");
		if (!doc_ids.empty()) {
			// Validate doc_ids to prevent SQL injection
			std::string doc_list = "";
			for (size_t i = 0; i < doc_ids.size(); ++i) {
				const std::string& doc_id = doc_ids[i];
				// Basic validation - check for dangerous characters
				if (doc_id.find('\'') != std::string::npos ||
					doc_id.find('\\') != std::string::npos ||
					doc_id.find(';') != std::string::npos) {
					return false;
				}
				if (i > 0) doc_list += ",";
				doc_list += "'" + doc_id + "'";
			}
			sql += " AND c.doc_id IN (" + doc_list + ")";
		}
	}

	// Metadata filters
	if (filters.contains("post_type_ids") && filters["post_type_ids"].is_array()) {
		std::vector<int> post_type_ids = get_json_int_array(filters, "post_type_ids");
		if (!post_type_ids.empty()) {
			// Validate that all post_type_ids are integers
			std::string post_type_conditions = "";
			for (size_t i = 0; i < post_type_ids.size(); ++i) {
				if (i > 0) post_type_conditions += " OR ";
				post_type_conditions += "json_extract(d.metadata_json, '$.PostTypeId') = " + std::to_string(post_type_ids[i]);
			}
			sql += " AND (" + post_type_conditions + ")";
		}
	}

	if (filters.contains("tags_any") && filters["tags_any"].is_array()) {
		std::vector<std::string> tags_any = get_json_string_array(filters, "tags_any");
		if (!tags_any.empty()) {
			// Validate tags to prevent SQL injection
			std::string tag_conditions = "";
			for (size_t i = 0; i < tags_any.size(); ++i) {
				const std::string& tag = tags_any[i];
				// Basic validation - check for dangerous characters
				if (tag.find('\'') != std::string::npos ||
					tag.find('\\') != std::string::npos ||
					tag.find(';') != std::string::npos) {
					return false;
				}
				if (i > 0) tag_conditions += " OR ";
				// Escape the tag for LIKE pattern matching
				std::string escaped_tag = tag;
				// Simple escaping - replace special characters
				size_t pos = 0;
				while ((pos = escaped_tag.find("'", pos)) != std::string::npos) {
					escaped_tag.replace(pos, 1, "''");
					pos += 2;
				}
				tag_conditions += "json_extract(d.metadata_json, '$.Tags') LIKE '%<" + escaped_tag + ">%' ESCAPE '\\'";
			}
			sql += " AND (" + tag_conditions + ")";
		}
	}

	if (filters.contains("tags_all") && filters["tags_all"].is_array()) {
		std::vector<std::string> tags_all = get_json_string_array(filters, "tags_all");
		if (!tags_all.empty()) {
			// Validate tags to prevent SQL injection
			std::string tag_conditions = "";
			for (size_t i = 0; i < tags_all.size(); ++i) {
				const std::string& tag = tags_all[i];
				// Basic validation - check for dangerous characters
				if (tag.find('\'') != std::string::npos ||
					tag.find('\\') != std::string::npos ||
					tag.find(';') != std::string::npos) {
					return false;
				}
				if (i > 0) tag_conditions += " AND ";
				// Escape the tag for LIKE pattern matching
				std::string escaped_tag = tag;
				// Simple escaping - replace special characters
				size_t pos = 0;
				while ((pos = escaped_tag.find("'", pos)) != std::string::npos) {
					escaped_tag.replace(pos, 1, "''");
					pos += 2;
				}
				tag_conditions += "json_extract(d.metadata_json, '$.Tags') LIKE '%<" + escaped_tag + ">%' ESCAPE '\\'";
			}
			sql += " AND (" + tag_conditions + ")";
		}
	}

	if (filters.contains("created_after") && filters["created_after"].is_string()) {
		std::string created_after = filters["created_after"].get<std::string>();
		// Validate date format to prevent SQL injection
		if (created_after.find('\'') != std::string::npos ||
			created_after.find('\\') != std::string::npos ||
			created_after.find(';') != std::string::npos) {
			return false;
		}
		// Filter by CreationDate in metadata_json
		sql += " AND json_extract(d.metadata_json, '$.CreationDate') >= '" + created_after + "'";
	}

	if (filters.contains("created_before") && filters["created_before"].is_string()) {
		std::string created_before = filters["created_before"].get<std::string>();
		// Validate date format to prevent SQL injection
		if (created_before.find('\'') != std::string::npos ||
			created_before.find('\\') != std::string::npos ||
			created_before.find(';') != std::string::npos) {
			return false;
		}
		// Filter by CreationDate in metadata_json
		sql += " AND json_extract(d.metadata_json, '$.CreationDate') <= '" + created_before + "'";
	}

	return true;
}

/**
 * @brief Compute Reciprocal Rank Fusion score
 *
 * Computes the Reciprocal Rank Fusion score for hybrid search ranking.
 * Formula: weight / (k0 + rank)
 *
 * @param rank Rank position (1-based)
 * @param k0 Smoothing parameter
 * @param weight Weight factor for this ranking
 * @return RRF score
 *
 * @see rag.search_hybrid
 */
double RAG_Tool_Handler::compute_rrf_score(int rank, int k0, double weight) {
	if (rank <= 0) return 0.0;
	return weight / (k0 + rank);
}

/**
 * @brief Normalize scores to 0-1 range (higher is better)
 *
 * Normalizes various types of scores to a consistent 0-1 range where
 * higher values indicate better matches. Different score types may
 * require different normalization approaches.
 *
 * @param score Raw score to normalize
 * @param score_type Type of score being normalized
 * @return Normalized score in 0-1 range
 */
double RAG_Tool_Handler::normalize_score(double score, const std::string& score_type) {
	// For now, return the score as-is
	// In the future, we might want to normalize different score types differently
	return score;
}

namespace {

struct RagSourceConfig {
	int source_id { 0 };
	std::string source_name;
	std::string backend_type;
	std::string backend_host;
	int backend_port { 0 };
	std::string backend_user;
	std::string backend_pass;
	std::string backend_db;
	std::string table_name;
	std::string pk_column;
	std::string where_sql;
	json pk_json;
};

bool fetch_rag_source_config(SQLite3DB* db, const std::string& doc_id, RagSourceConfig& cfg, std::string& error) {
	if (!db) {
		error = "Vector database not available";
		return false;
	}

	std::string escaped_doc_id = doc_id;
	size_t pos = 0;
	while ((pos = escaped_doc_id.find("'", pos)) != std::string::npos) {
		escaped_doc_id.replace(pos, 1, "''");
		pos += 2;
	}

	std::string sql =
		"SELECT d.source_id, s.name, s.backend_type, s.backend_host, s.backend_port, "
		"s.backend_user, s.backend_pass, s.backend_db, s.table_name, s.pk_column, s.where_sql, d.pk_json "
		"FROM rag_documents d "
		"JOIN rag_sources s ON s.source_id = d.source_id "
		"WHERE d.doc_id = '" + escaped_doc_id + "' AND d.deleted = 0 AND s.enabled = 1";

	char* sqlite_error = nullptr;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* result = db->execute_statement(sql.c_str(), &sqlite_error, &cols, &affected_rows);
	if (!result || result->rows.empty()) {
		if (sqlite_error) {
			error = sqlite_error;
			free(sqlite_error);
		} else {
			error = "Document not found or source disabled: " + doc_id;
		}
		if (result) {
			delete result;
		}
		return false;
	}

	const auto* row = result->rows.front();
	if (!row || row->cnt < 12) {
		error = "Invalid RAG source metadata for doc_id: " + doc_id;
		delete result;
		return false;
	}

	cfg.source_id = row->fields[0] ? std::atoi(row->fields[0]) : 0;
	cfg.source_name = row->fields[1] ? row->fields[1] : "";
	cfg.backend_type = row->fields[2] ? row->fields[2] : "";
	std::transform(cfg.backend_type.begin(), cfg.backend_type.end(), cfg.backend_type.begin(),
	               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	cfg.backend_host = row->fields[3] ? row->fields[3] : "";
	cfg.backend_port = row->fields[4] ? std::atoi(row->fields[4]) : 0;
	cfg.backend_user = row->fields[5] ? row->fields[5] : "";
	cfg.backend_pass = row->fields[6] ? row->fields[6] : "";
	cfg.backend_db = row->fields[7] ? row->fields[7] : "";
	cfg.table_name = row->fields[8] ? row->fields[8] : "";
	cfg.pk_column = row->fields[9] ? row->fields[9] : "";
	cfg.where_sql = row->fields[10] ? row->fields[10] : "";
	if (row->fields[11]) {
		try {
			cfg.pk_json = json::parse(row->fields[11]);
		} catch (const std::exception& e) {
			error = std::string("Failed to parse pk_json for doc_id ") + doc_id + ": " + e.what();
			delete result;
			return false;
		}
	} else {
		cfg.pk_json = json::object();
	}

	delete result;
	return true;
}

bool fetch_rag_rows_mysql(const RagSourceConfig& cfg, const std::string& doc_id, const std::vector<std::string>& columns, json& rows, std::string& error) {
	BackendTarget target;
	target.user = cfg.backend_user;
	target.password = cfg.backend_pass;
	target.default_schema = cfg.backend_db;

	MySQLDialResult dial = dial_mysql(cfg.backend_host, cfg.backend_port, target);
	if (!dial.conn) {
		error = dial.error;
		return false;
	}

	MYSQL* conn = dial.conn;
	if (!is_valid_sql_identifier(cfg.table_name)) {
		error = "Invalid source table name: " + cfg.table_name;
		mysql_close(conn);
		return false;
	}
	std::string where_clause;
	if (!append_source_pk_predicates_mysql(conn, cfg.pk_json, cfg.pk_column, where_clause, error)) {
		mysql_close(conn);
		return false;
	}

	std::string select_list = "*";
	if (!columns.empty()) {
		select_list.clear();
		for (size_t i = 0; i < columns.size(); ++i) {
			if (!is_valid_sql_identifier(columns[i])) {
				error = "Invalid source column name: " + columns[i];
				mysql_close(conn);
				return false;
			}
			if (i > 0) {
				select_list += ", ";
			}
			select_list += quote_mysql_identifier(columns[i]);
		}
	}

	std::string sql = "SELECT " + select_list + " FROM " + quote_mysql_identifier(cfg.table_name) + " WHERE " + where_clause;
	if (!cfg.where_sql.empty()) {
		sql += " AND (" + cfg.where_sql + ")";
	}
	sql += " LIMIT 2";

	if (mysql_query(conn, sql.c_str()) != 0) {
		error = mysql_error(conn);
		mysql_close(conn);
		return false;
	}

	MYSQL_RES* res = mysql_store_result(conn);
	if (!res) {
		error = "Source query returned no result set";
		mysql_close(conn);
		return false;
	}

	json converted = mysql_result_to_json(res);
	mysql_free_result(res);
	mysql_close(conn);

	if (converted["rows"].size() == 0) {
		error = "No source rows found for doc_id " + doc_id;
		return false;
	}
	if (converted["rows"].size() > 1) {
		error = "Source query returned multiple rows for doc_id " + doc_id;
		return false;
	}

	rows = converted["rows"];
	return true;
}

bool fetch_rag_rows_pgsql(const RagSourceConfig& cfg, const std::string& doc_id, const std::vector<std::string>& columns, json& rows, std::string& error) {
	BackendTarget target;
	target.user = cfg.backend_user;
	target.password = cfg.backend_pass;
	target.default_schema = cfg.backend_db;

	PgSQLDialResult dial = dial_pgsql(cfg.backend_host, cfg.backend_port, target);
	if (!dial.conn) {
		error = dial.error;
		return false;
	}

	PGconn* conn = dial.conn;
	if (!is_valid_sql_identifier(cfg.table_name)) {
		error = "Invalid source table name: " + cfg.table_name;
		PQfinish(conn);
		return false;
	}
	std::string where_clause;
	if (!append_source_pk_predicates_pgsql(conn, cfg.pk_json, cfg.pk_column, where_clause, error)) {
		PQfinish(conn);
		return false;
	}

	std::string select_list = "*";
	if (!columns.empty()) {
		select_list.clear();
		for (size_t i = 0; i < columns.size(); ++i) {
			if (!is_valid_sql_identifier(columns[i])) {
				error = "Invalid source column name: " + columns[i];
				PQfinish(conn);
				return false;
			}
			if (i > 0) {
				select_list += ", ";
			}
			select_list += quote_pgsql_identifier(columns[i]);
		}
	}

	std::string sql = "SELECT " + select_list + " FROM " + quote_pgsql_identifier(cfg.table_name) + " WHERE " + where_clause;
	if (!cfg.where_sql.empty()) {
		sql += " AND (" + cfg.where_sql + ")";
	}
	sql += " LIMIT 2";

	PGresult* res = PQexec(conn, sql.c_str());
	if (!res) {
		error = "Source query returned null result";
		PQfinish(conn);
		return false;
	}

	ExecStatusType status = PQresultStatus(res);
	if (status != PGRES_TUPLES_OK) {
		error = PQresultErrorMessage(res);
		PQclear(res);
		PQfinish(conn);
		return false;
	}

	json converted = pgsql_result_to_json(res);
	PQclear(res);
	PQfinish(conn);

	if (converted["rows"].size() == 0) {
		error = "No source rows found for doc_id " + doc_id;
		return false;
	}
	if (converted["rows"].size() > 1) {
		error = "Source query returned multiple rows for doc_id " + doc_id;
		return false;
	}

	rows = converted["rows"];
	return true;
}

} // namespace

// ============================================================================
// Tool List
// ============================================================================

/**
 * @brief Get list of available RAG tools
 *
 * Returns a comprehensive list of all available RAG tools with their
 * input schemas and descriptions. Tools include:
 * - rag.search_fts: Keyword search using FTS5
 * - rag.search_vector: Semantic search using vector embeddings
 * - rag.search_hybrid: Hybrid search combining FTS and vectors
 * - rag.get_chunks: Fetch chunk content by chunk_id
 * - rag.get_docs: Fetch document content by doc_id
 * - rag.fetch_from_source: Refetch authoritative data from source
 * - rag.admin.stats: Operational statistics
 *
 * @return JSON object containing tool definitions and schemas
 *
 * @see get_tool_description()
 * @see execute_tool()
 */
json RAG_Tool_Handler::get_tool_list() {
	json tools = json::array();

	// FTS search tool
	json fts_params = json::object();
	fts_params["type"] = "object";
	fts_params["properties"] = json::object();
	fts_params["properties"]["query"] = {
		{"type", "string"},
		{"description", "Keyword search query"}
	};
	fts_params["properties"]["k"] = {
		{"type", "integer"},
		{"description", "Number of results to return (default: 10, max: 50)"}
	};
	fts_params["properties"]["offset"] = {
		{"type", "integer"},
		{"description", "Offset for pagination (default: 0)"}
	};

	// Filters object
	json filters_obj = json::object();
	filters_obj["type"] = "object";
	filters_obj["properties"] = json::object();
	filters_obj["properties"]["source_ids"] = {
		{"type", "array"},
		{"items", {{"type", "integer"}}},
		{"description", "Filter by source IDs"}
	};
	filters_obj["properties"]["source_names"] = {
		{"type", "array"},
		{"items", {{"type", "string"}}},
		{"description", "Filter by source names"}
	};
	filters_obj["properties"]["doc_ids"] = {
		{"type", "array"},
		{"items", {{"type", "string"}}},
		{"description", "Filter by document IDs"}
	};
	filters_obj["properties"]["min_score"] = {
		{"type", "number"},
		{"description", "Minimum score threshold"}
	};
	filters_obj["properties"]["post_type_ids"] = {
		{"type", "array"},
		{"items", {{"type", "integer"}}},
		{"description", "Filter by post type IDs"}
	};
	filters_obj["properties"]["tags_any"] = {
		{"type", "array"},
		{"items", {{"type", "string"}}},
		{"description", "Filter by any of these tags"}
	};
	filters_obj["properties"]["tags_all"] = {
		{"type", "array"},
		{"items", {{"type", "string"}}},
		{"description", "Filter by all of these tags"}
	};
	filters_obj["properties"]["created_after"] = {
		{"type", "string"},
		{"format", "date-time"},
		{"description", "Filter by creation date (after)"}
	};
	filters_obj["properties"]["created_before"] = {
		{"type", "string"},
		{"format", "date-time"},
		{"description", "Filter by creation date (before)"}
	};

	fts_params["properties"]["filters"] = filters_obj;

	// Return object
	json return_obj = json::object();
	return_obj["type"] = "object";
	return_obj["properties"] = json::object();
	return_obj["properties"]["include_title"] = {
		{"type", "boolean"},
		{"description", "Include title in results (default: true)"}
	};
	return_obj["properties"]["include_metadata"] = {
		{"type", "boolean"},
		{"description", "Include metadata in results (default: true)"}
	};
	return_obj["properties"]["include_snippets"] = {
		{"type", "boolean"},
		{"description", "Include snippets in results (default: false)"}
	};

	fts_params["properties"]["return"] = return_obj;
	fts_params["required"] = json::array({"query"});

	tools.push_back({
		{"name", "rag.search_fts"},
		{"description", "Keyword search over documents using FTS5"},
		{"inputSchema", fts_params}
	});

	// Vector search tool
	json vec_params = json::object();
	vec_params["type"] = "object";
	vec_params["properties"] = json::object();
	vec_params["properties"]["query_text"] = {
		{"type", "string"},
		{"description", "Text to search semantically"}
	};
	vec_params["properties"]["k"] = {
		{"type", "integer"},
		{"description", "Number of results to return (default: 10, max: 50)"}
	};

	// Filters object (same as FTS)
	vec_params["properties"]["filters"] = filters_obj;

	// Return object (same as FTS)
	vec_params["properties"]["return"] = return_obj;

	// Embedding object for precomputed vectors
	json embedding_obj = json::object();
	embedding_obj["type"] = "object";
	embedding_obj["properties"] = json::object();
	embedding_obj["properties"]["model"] = {
		{"type", "string"},
		{"description", "Embedding model to use"}
	};

	vec_params["properties"]["embedding"] = embedding_obj;

	// Query embedding object for precomputed vectors
	json query_embedding_obj = json::object();
	query_embedding_obj["type"] = "object";
	query_embedding_obj["properties"] = json::object();
	query_embedding_obj["properties"]["dim"] = {
		{"type", "integer"},
		{"description", "Dimension of the embedding"}
	};
	query_embedding_obj["properties"]["values_b64"] = {
		{"type", "string"},
		{"description", "Base64 encoded float32 array"}
	};

	vec_params["properties"]["query_embedding"] = query_embedding_obj;
	vec_params["required"] = json::array({"query_text"});

	tools.push_back({
		{"name", "rag.search_vector"},
		{"description", "Semantic search over documents using vector embeddings"},
		{"inputSchema", vec_params}
	});

	// Hybrid search tool
	json hybrid_params = json::object();
	hybrid_params["type"] = "object";
	hybrid_params["properties"] = json::object();
	hybrid_params["properties"]["query"] = {
		{"type", "string"},
		{"description", "Search query for both FTS and vector"}
	};
	hybrid_params["properties"]["k"] = {
		{"type", "integer"},
		{"description", "Number of results to return (default: 10, max: 50)"}
	};
	hybrid_params["properties"]["mode"] = {
		{"type", "string"},
		{"description", "Search mode: 'fuse' or 'fts_then_vec'"}
	};

	// Filters object (same as FTS and vector)
	hybrid_params["properties"]["filters"] = filters_obj;

	// Fuse object for mode "fuse"
	json fuse_obj = json::object();
	fuse_obj["type"] = "object";
	fuse_obj["properties"] = json::object();
	fuse_obj["properties"]["fts_k"] = {
		{"type", "integer"},
		{"description", "Number of FTS results to retrieve for fusion (default: 50)"}
	};
	fuse_obj["properties"]["vec_k"] = {
		{"type", "integer"},
		{"description", "Number of vector results to retrieve for fusion (default: 50)"}
	};
	fuse_obj["properties"]["rrf_k0"] = {
		{"type", "integer"},
		{"description", "RRF smoothing parameter (default: 60)"}
	};
	fuse_obj["properties"]["w_fts"] = {
		{"type", "number"},
		{"description", "Weight for FTS scores in fusion (default: 1.0)"}
	};
	fuse_obj["properties"]["w_vec"] = {
		{"type", "number"},
		{"description", "Weight for vector scores in fusion (default: 1.0)"}
	};

	hybrid_params["properties"]["fuse"] = fuse_obj;

	// Fts_then_vec object for mode "fts_then_vec"
	json fts_then_vec_obj = json::object();
	fts_then_vec_obj["type"] = "object";
	fts_then_vec_obj["properties"] = json::object();
	fts_then_vec_obj["properties"]["candidates_k"] = {
		{"type", "integer"},
		{"description", "Number of FTS candidates to generate (default: 200)"}
	};
	fts_then_vec_obj["properties"]["rerank_k"] = {
		{"type", "integer"},
		{"description", "Number of candidates to rerank with vector search (default: 50)"}
	};
	fts_then_vec_obj["properties"]["vec_metric"] = {
		{"type", "string"},
		{"description", "Vector similarity metric (default: 'cosine')"}
	};

	hybrid_params["properties"]["fts_then_vec"] = fts_then_vec_obj;

	hybrid_params["required"] = json::array({"query"});

	tools.push_back({
		{"name", "rag.search_hybrid"},
		{"description", "Hybrid search combining FTS and vector"},
		{"inputSchema", hybrid_params}
	});

	// Get chunks tool
	json chunks_params = json::object();
	chunks_params["type"] = "object";
	chunks_params["properties"] = json::object();
	chunks_params["properties"]["chunk_ids"] = {
		{"type", "array"},
		{"items", {{"type", "string"}}},
		{"description", "List of chunk IDs to fetch"}
	};
	json return_params = json::object();
	return_params["type"] = "object";
	return_params["properties"] = json::object();
	return_params["properties"]["include_title"] = {
		{"type", "boolean"},
		{"description", "Include title in response (default: true)"}
	};
	return_params["properties"]["include_doc_metadata"] = {
		{"type", "boolean"},
		{"description", "Include document metadata in response (default: true)"}
	};
	return_params["properties"]["include_chunk_metadata"] = {
		{"type", "boolean"},
		{"description", "Include chunk metadata in response (default: true)"}
	};
	chunks_params["properties"]["return"] = return_params;
	chunks_params["required"] = json::array({"chunk_ids"});

	tools.push_back({
		{"name", "rag.get_chunks"},
		{"description", "Fetch chunk content by chunk_id"},
		{"inputSchema", chunks_params}
	});

	// Get docs tool
	json docs_params = json::object();
	docs_params["type"] = "object";
	docs_params["properties"] = json::object();
	docs_params["properties"]["doc_ids"] = {
		{"type", "array"},
		{"items", {{"type", "string"}}},
		{"description", "List of document IDs to fetch"}
	};
	json docs_return_params = json::object();
	docs_return_params["type"] = "object";
	docs_return_params["properties"] = json::object();
	docs_return_params["properties"]["include_body"] = {
		{"type", "boolean"},
		{"description", "Include body in response (default: true)"}
	};
	docs_return_params["properties"]["include_metadata"] = {
		{"type", "boolean"},
		{"description", "Include metadata in response (default: true)"}
	};
	docs_params["properties"]["return"] = docs_return_params;
	docs_params["required"] = json::array({"doc_ids"});

	tools.push_back({
		{"name", "rag.get_docs"},
		{"description", "Fetch document content by doc_id"},
		{"inputSchema", docs_params}
	});

	// Fetch from source tool
	json fetch_params = json::object();
	fetch_params["type"] = "object";
	fetch_params["properties"] = json::object();
	fetch_params["properties"]["doc_ids"] = {
		{"type", "array"},
		{"items", {{"type", "string"}}},
		{"description", "List of document IDs to refetch"}
	};
	fetch_params["properties"]["columns"] = {
		{"type", "array"},
		{"items", {{"type", "string"}}},
		{"description", "List of columns to fetch"}
	};

	// Limits object
	json limits_obj = json::object();
	limits_obj["type"] = "object";
	limits_obj["properties"] = json::object();
	limits_obj["properties"]["max_rows"] = {
		{"type", "integer"},
		{"description", "Maximum number of rows to return (default: 10, max: 100)"}
	};
	limits_obj["properties"]["max_bytes"] = {
		{"type", "integer"},
		{"description", "Maximum number of bytes to return (default: 200000, max: 1000000)"}
	};

	fetch_params["properties"]["limits"] = limits_obj;
	fetch_params["required"] = json::array({"doc_ids"});

	tools.push_back({
		{"name", "rag.fetch_from_source"},
		{"description", "Refetch authoritative data from source database"},
		{"inputSchema", fetch_params}
	});

	// Admin stats tool
	json stats_params = json::object();
	stats_params["type"] = "object";
	stats_params["properties"] = json::object();

	tools.push_back({
		{"name", "rag.admin.stats"},
		{"description", "Get operational statistics for RAG system"},
		{"inputSchema", stats_params}
	});

	json result;
	result["tools"] = tools;
	return result;
}

/**
 * @brief Get description of a specific tool
 *
 * Returns the schema and description for a specific RAG tool.
 *
 * @param tool_name Name of the tool to describe
 * @return JSON object with tool description or error response
 *
 * @see get_tool_list()
 * @see execute_tool()
 */
json RAG_Tool_Handler::get_tool_description(const std::string& tool_name) {
	json tools_list = get_tool_list();
	for (const auto& tool : tools_list["tools"]) {
		if (tool["name"] == tool_name) {
			return tool;
		}
	}
	return create_error_response("Tool not found: " + tool_name);
}

// ============================================================================
// Tool Execution
// ============================================================================

/**
 * @brief Execute a RAG tool
 *
 * Executes the specified RAG tool with the provided arguments. Handles
 * input validation, parameter processing, database queries, and result
 * formatting according to MCP specifications.
 *
 * Supported tools:
 * - rag.search_fts: Full-text search over documents
 * - rag.search_vector: Vector similarity search
 * - rag.search_hybrid: Hybrid search with two modes (fuse, fts_then_vec)
 * - rag.get_chunks: Retrieve chunk content by ID
 * - rag.get_docs: Retrieve document content by ID
 * - rag.fetch_from_source: Refetch data from authoritative source
 * - rag.admin.stats: Get operational statistics
 *
 * @param tool_name Name of the tool to execute
 * @param arguments JSON object containing tool arguments
 * @return JSON response with results or error information
 *
 * @see get_tool_list()
 * @see get_tool_description()
 */
json RAG_Tool_Handler::execute_tool(const std::string& tool_name, const json& arguments) {
	proxy_debug(PROXY_DEBUG_GENAI, 3, "RAG_Tool_Handler: execute_tool(%s)\n", tool_name.c_str());
	if (!vector_db) {
		return create_error_response("Vector database not available");
	}

	// Record start time for timing stats
	auto start_time = std::chrono::high_resolution_clock::now();

	try {
		json result;

		if (tool_name == "rag.search_fts") {
			// FTS search implementation
			std::string query = get_json_string(arguments, "query");
			int k = validate_k(get_json_int(arguments, "k", 10));
			int offset = get_json_int(arguments, "offset", 0);

			// Get filters
			json filters = json::object();
			if (arguments.contains("filters") && arguments["filters"].is_object()) {
				filters = arguments["filters"];

				// Validate filter parameters
				if (filters.contains("source_ids") && !filters["source_ids"].is_array()) {
					return create_error_response("Invalid source_ids filter: must be an array of integers");
				}

				if (filters.contains("source_names") && !filters["source_names"].is_array()) {
					return create_error_response("Invalid source_names filter: must be an array of strings");
				}

				if (filters.contains("doc_ids") && !filters["doc_ids"].is_array()) {
					return create_error_response("Invalid doc_ids filter: must be an array of strings");
				}

				if (filters.contains("post_type_ids") && !filters["post_type_ids"].is_array()) {
					return create_error_response("Invalid post_type_ids filter: must be an array of integers");
				}

				if (filters.contains("tags_any") && !filters["tags_any"].is_array()) {
					return create_error_response("Invalid tags_any filter: must be an array of strings");
				}

				if (filters.contains("tags_all") && !filters["tags_all"].is_array()) {
					return create_error_response("Invalid tags_all filter: must be an array of strings");
				}

				if (filters.contains("created_after") && !filters["created_after"].is_string()) {
					return create_error_response("Invalid created_after filter: must be a string in ISO 8601 format");
				}

				if (filters.contains("created_before") && !filters["created_before"].is_string()) {
					return create_error_response("Invalid created_before filter: must be a string in ISO 8601 format");
				}

				if (filters.contains("min_score") && !(filters["min_score"].is_number() || filters["min_score"].is_string())) {
					return create_error_response("Invalid min_score filter: must be a number or numeric string");
				}
			}

			// Get return parameters
			bool include_title = true;
			bool include_metadata = true;
			bool include_snippets = false;
			if (arguments.contains("return") && arguments["return"].is_object()) {
				const json& return_params = arguments["return"];
				include_title = get_json_bool(return_params, "include_title", true);
				include_metadata = get_json_bool(return_params, "include_metadata", true);
				include_snippets = get_json_bool(return_params, "include_snippets", false);
			}

			if (!validate_query_length(query)) {
				return create_error_response("Query too long");
			}

			// Validate FTS query for SQL injection patterns
			// This is a basic validation - in production, more robust validation should be used
			if (query.find(';') != std::string::npos ||
				query.find("--") != std::string::npos ||
				query.find("/*") != std::string::npos ||
				query.find("DROP") != std::string::npos ||
				query.find("DELETE") != std::string::npos ||
				query.find("INSERT") != std::string::npos ||
				query.find("UPDATE") != std::string::npos) {
				return create_error_response("Invalid characters in query");
			}

			// Log the RAG FTS search
			if (catalog) {
				std::string filters_str = filters.empty() ? "" : filters.dump();
				catalog->log_rag_search_fts(query, k, filters_str);
			}

			// Build FTS query with filters
			std::string sql = "SELECT c.chunk_id, c.doc_id, c.source_id, "
				"(SELECT name FROM rag_sources WHERE source_id = c.source_id) as source_name, "
				"c.title, bm25(rag_fts_chunks) as score_fts_raw, "
				"c.metadata_json, c.body "
				"FROM rag_fts_chunks f "
				"JOIN rag_chunks c ON c.chunk_id = f.chunk_id "
				"JOIN rag_documents d ON d.doc_id = c.doc_id "
				"WHERE rag_fts_chunks MATCH '" + escape_fts_query(query) + "'";

			// Apply filters using consolidated filter building function
			if (!build_sql_filters(filters, sql, false)) {
				return create_error_response("Invalid filter parameters");
			}

			sql += " ORDER BY score_fts_raw "
				"LIMIT " + std::to_string(k) + " OFFSET " + std::to_string(offset);

			SQLite3_result* db_result = execute_query(sql.c_str());
			if (!db_result) {
				return create_error_response("Database query failed");
			}

			// Build result array
			json results = json::array();
			double min_score = 0.0;
			bool has_min_score = false;
			if (filters.contains("min_score") && (filters["min_score"].is_number() || filters["min_score"].is_string())) {
				min_score = filters["min_score"].is_number() ?
					filters["min_score"].get<double>() :
					std::stod(filters["min_score"].get<std::string>());
				has_min_score = true;
			}

			for (const auto& row : db_result->rows) {
				if (row->fields) {
					json item;
					item["chunk_id"] = row->fields[0] ? row->fields[0] : "";
					item["doc_id"] = row->fields[1] ? row->fields[1] : "";
					item["source_id"] = row->fields[2] ? std::stoi(row->fields[2]) : 0;
					item["source_name"] = row->fields[3] ? row->fields[3] : "";

					// Normalize FTS score (bm25 - lower is better, so we invert it)
					double score_fts_raw = row->fields[5] ? std::stod(row->fields[5]) : 0.0;
					// Convert to 0-1 scale where higher is better
					double score_fts = 1.0 / (1.0 + std::abs(score_fts_raw));

					// Apply min_score filter
					if (has_min_score && score_fts < min_score) {
						continue; // Skip this result
					}

					item["score_fts"] = score_fts;

					if (include_title) {
						item["title"] = row->fields[4] ? row->fields[4] : "";
					}

					if (include_metadata && row->fields[6]) {
						try {
							item["metadata"] = json::parse(row->fields[6]);
						} catch (...) {
							item["metadata"] = json::object();
						}
					}

					if (include_snippets && row->fields[7]) {
						// For now, just include the first 200 characters as a snippet
						std::string body = row->fields[7];
						if (body.length() > 200) {
							item["snippet"] = body.substr(0, 200) + "...";
						} else {
							item["snippet"] = body;
						}
					}

					results.push_back(item);
				}
			}

			delete db_result;

			result["results"] = results;
			result["truncated"] = false;

			// Add timing stats
			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
			json stats;
			stats["k_requested"] = k;
			stats["k_returned"] = static_cast<int>(results.size());
			stats["ms"] = static_cast<int>(duration.count());
			result["stats"] = stats;

		} else if (tool_name == "rag.search_vector") {
			// Vector search implementation
			std::string query_text = get_json_string(arguments, "query_text");
			int k = validate_k(get_json_int(arguments, "k", 10));

			// Get filters
			json filters = json::object();
			if (arguments.contains("filters") && arguments["filters"].is_object()) {
				filters = arguments["filters"];

				// Validate filter parameters
				if (filters.contains("source_ids") && !filters["source_ids"].is_array()) {
					return create_error_response("Invalid source_ids filter: must be an array of integers");
				}

				if (filters.contains("source_names") && !filters["source_names"].is_array()) {
					return create_error_response("Invalid source_names filter: must be an array of strings");
				}

				if (filters.contains("doc_ids") && !filters["doc_ids"].is_array()) {
					return create_error_response("Invalid doc_ids filter: must be an array of strings");
				}

				if (filters.contains("post_type_ids") && !filters["post_type_ids"].is_array()) {
					return create_error_response("Invalid post_type_ids filter: must be an array of integers");
				}

				if (filters.contains("tags_any") && !filters["tags_any"].is_array()) {
					return create_error_response("Invalid tags_any filter: must be an array of strings");
				}

				if (filters.contains("tags_all") && !filters["tags_all"].is_array()) {
					return create_error_response("Invalid tags_all filter: must be an array of strings");
				}

				if (filters.contains("created_after") && !filters["created_after"].is_string()) {
					return create_error_response("Invalid created_after filter: must be a string in ISO 8601 format");
				}

				if (filters.contains("created_before") && !filters["created_before"].is_string()) {
					return create_error_response("Invalid created_before filter: must be a string in ISO 8601 format");
				}

				if (filters.contains("min_score") && !(filters["min_score"].is_number() || filters["min_score"].is_string())) {
					return create_error_response("Invalid min_score filter: must be a number or numeric string");
				}
			}

			// Get return parameters
			bool include_title = true;
			bool include_metadata = true;
			bool include_snippets = false;
			if (arguments.contains("return") && arguments["return"].is_object()) {
				const json& return_params = arguments["return"];
				include_title = get_json_bool(return_params, "include_title", true);
				include_metadata = get_json_bool(return_params, "include_metadata", true);
				include_snippets = get_json_bool(return_params, "include_snippets", false);
			}

			if (!validate_query_length(query_text)) {
				return create_error_response("Query text too long");
			}

			// Get embedding for query text
			std::vector<float> query_embedding;
			if (ai_manager && GloGATH) {
				GenAI_EmbeddingResult result = GloGATH->embed_documents({query_text});
				if (result.data && result.count > 0) {
					// Convert to std::vector<float>
					query_embedding.assign(result.data, result.data + result.embedding_size);
					// Free the result data (GenAI allocates with malloc)
					free(result.data);
				}
			}

			if (query_embedding.empty()) {
				return create_error_response("Failed to generate embedding for query");
			}

			// Convert embedding to JSON array format for sqlite-vec
			std::string embedding_json = "[";
			for (size_t i = 0; i < query_embedding.size(); ++i) {
				if (i > 0) embedding_json += ",";
				embedding_json += std::to_string(query_embedding[i]);
			}
			embedding_json += "]";

			// Build vector search query using sqlite-vec syntax with filters
			// Must use subquery approach: LIMIT must be at same query level as MATCH
			std::string sql = "SELECT v.chunk_id, c.doc_id, c.source_id, "
				"(SELECT name FROM rag_sources WHERE source_id = c.source_id) as source_name, "
				"c.title, v.distance as score_vec_raw, "
				"c.metadata_json, c.body "
				"FROM ("
				"  SELECT chunk_id, distance "
				"  FROM rag_vec_chunks "
				"  WHERE embedding MATCH '" + escape_fts_query(embedding_json) + "' "
				"  ORDER BY distance "
				"  LIMIT " + std::to_string(k) + " "
				") v "
				"JOIN rag_chunks c ON c.chunk_id = v.chunk_id "
				"JOIN rag_documents d ON d.doc_id = c.doc_id";

			// Apply filters using consolidated filter building function
			if (!build_sql_filters(filters, sql)) {
				return create_error_response("Invalid filter parameters");
			}

			sql += " ORDER BY v.distance";

			SQLite3_result* db_result = execute_query(sql.c_str());
			if (!db_result) {
				return create_error_response("Database query failed");
			}

			// Build result array
			json results = json::array();
			double min_score = 0.0;
			bool has_min_score = false;
			if (filters.contains("min_score") && (filters["min_score"].is_number() || filters["min_score"].is_string())) {
				min_score = filters["min_score"].is_number() ?
					filters["min_score"].get<double>() :
					std::stod(filters["min_score"].get<std::string>());
				has_min_score = true;
			}

			for (const auto& row : db_result->rows) {
				if (row->fields) {
					json item;
					item["chunk_id"] = row->fields[0] ? row->fields[0] : "";
					item["doc_id"] = row->fields[1] ? row->fields[1] : "";
					item["source_id"] = row->fields[2] ? std::stoi(row->fields[2]) : 0;
					item["source_name"] = row->fields[3] ? row->fields[3] : "";

					// Normalize vector score (distance - lower is better, so we invert it)
					double score_vec_raw = row->fields[5] ? std::stod(row->fields[5]) : 0.0;
					// Convert to 0-1 scale where higher is better
					double score_vec = 1.0 / (1.0 + score_vec_raw);

					// Apply min_score filter
					if (has_min_score && score_vec < min_score) {
						continue; // Skip this result
					}

					item["score_vec"] = score_vec;

					if (include_title) {
						item["title"] = row->fields[4] ? row->fields[4] : "";
					}

					if (include_metadata && row->fields[6]) {
						try {
							item["metadata"] = json::parse(row->fields[6]);
						} catch (...) {
							item["metadata"] = json::object();
						}
					}

					if (include_snippets && row->fields[7]) {
						// For now, just include the first 200 characters as a snippet
						std::string body = row->fields[7];
						if (body.length() > 200) {
							item["snippet"] = body.substr(0, 200) + "...";
						} else {
							item["snippet"] = body;
						}
					}

					results.push_back(item);
				}
			}

			delete db_result;

			result["results"] = results;
			result["truncated"] = false;

			// Add timing stats
			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
			json stats;
			stats["k_requested"] = k;
			stats["k_returned"] = static_cast<int>(results.size());
			stats["ms"] = static_cast<int>(duration.count());
			result["stats"] = stats;

		} else if (tool_name == "rag.search_hybrid") {
			// Hybrid search implementation
			std::string query = get_json_string(arguments, "query");
			int k = validate_k(get_json_int(arguments, "k", 10));
			std::string mode = get_json_string(arguments, "mode", "fuse");

			// Get filters
			json filters = json::object();
			if (arguments.contains("filters") && arguments["filters"].is_object()) {
				filters = arguments["filters"];

				// Validate filter parameters
				if (filters.contains("source_ids") && !filters["source_ids"].is_array()) {
					return create_error_response("Invalid source_ids filter: must be an array of integers");
				}

				if (filters.contains("source_names") && !filters["source_names"].is_array()) {
					return create_error_response("Invalid source_names filter: must be an array of strings");
				}

				if (filters.contains("doc_ids") && !filters["doc_ids"].is_array()) {
					return create_error_response("Invalid doc_ids filter: must be an array of strings");
				}

				if (filters.contains("post_type_ids") && !filters["post_type_ids"].is_array()) {
					return create_error_response("Invalid post_type_ids filter: must be an array of integers");
				}

				if (filters.contains("tags_any") && !filters["tags_any"].is_array()) {
					return create_error_response("Invalid tags_any filter: must be an array of strings");
				}

				if (filters.contains("tags_all") && !filters["tags_all"].is_array()) {
					return create_error_response("Invalid tags_all filter: must be an array of strings");
				}

				if (filters.contains("created_after") && !filters["created_after"].is_string()) {
					return create_error_response("Invalid created_after filter: must be a string in ISO 8601 format");
				}

				if (filters.contains("created_before") && !filters["created_before"].is_string()) {
					return create_error_response("Invalid created_before filter: must be a string in ISO 8601 format");
				}

				if (filters.contains("min_score") && !(filters["min_score"].is_number() || filters["min_score"].is_string())) {
					return create_error_response("Invalid min_score filter: must be a number or numeric string");
				}
			}

			if (!validate_query_length(query)) {
				return create_error_response("Query too long");
			}

			json results = json::array();

			if (mode == "fuse") {
				// Mode A: parallel FTS + vector, fuse results (RRF recommended)

				// Get FTS parameters from fuse object
				int fts_k = 50;
				int vec_k = 50;
				int rrf_k0 = 60;
				double w_fts = 1.0;
				double w_vec = 1.0;

				if (arguments.contains("fuse") && arguments["fuse"].is_object()) {
					const json& fuse_params = arguments["fuse"];
					fts_k = validate_k(get_json_int(fuse_params, "fts_k", 50));
					vec_k = validate_k(get_json_int(fuse_params, "vec_k", 50));
					rrf_k0 = get_json_int(fuse_params, "rrf_k0", 60);
					w_fts = get_json_int(fuse_params, "w_fts", 1.0);
					w_vec = get_json_int(fuse_params, "w_vec", 1.0);
				} else {
					// Fallback to top-level parameters for backward compatibility
					fts_k = validate_k(get_json_int(arguments, "fts_k", 50));
					vec_k = validate_k(get_json_int(arguments, "vec_k", 50));
					rrf_k0 = get_json_int(arguments, "rrf_k0", 60);
					w_fts = get_json_int(arguments, "w_fts", 1.0);
					w_vec = get_json_int(arguments, "w_vec", 1.0);
				}

				// Run FTS search with filters
				std::string fts_sql = "SELECT c.chunk_id, c.doc_id, c.source_id, "
					"(SELECT name FROM rag_sources WHERE source_id = c.source_id) as source_name, "
					"c.title, bm25(rag_fts_chunks) as score_fts_raw, "
					"c.metadata_json "
					"FROM rag_fts_chunks f "
					"JOIN rag_chunks c ON c.chunk_id = f.chunk_id "
					"JOIN rag_documents d ON d.doc_id = c.doc_id "
					"WHERE rag_fts_chunks MATCH '" + escape_fts_query(query) + "'";

				// Apply filters using consolidated filter building function
				if (!build_sql_filters(filters, fts_sql, false)) {
					return create_error_response("Invalid filter parameters");
				}

				if (filters.contains("source_names") && filters["source_names"].is_array()) {
					std::vector<std::string> source_names = get_json_string_array(filters, "source_names");
					if (!source_names.empty()) {
						std::string source_list = "";
						for (size_t i = 0; i < source_names.size(); ++i) {
							if (i > 0) source_list += ",";
							source_list += "'" + source_names[i] + "'";
						}
						fts_sql += " AND c.source_id IN (SELECT source_id FROM rag_sources WHERE name IN (" + source_list + "))";
					}
				}

				if (filters.contains("doc_ids") && filters["doc_ids"].is_array()) {
					std::vector<std::string> doc_ids = get_json_string_array(filters, "doc_ids");
					if (!doc_ids.empty()) {
						std::string doc_list = "";
						for (size_t i = 0; i < doc_ids.size(); ++i) {
							if (i > 0) doc_list += ",";
							doc_list += "'" + doc_ids[i] + "'";
						}
						fts_sql += " AND c.doc_id IN (" + doc_list + ")";
					}
				}

				// Metadata filters
				if (filters.contains("post_type_ids") && filters["post_type_ids"].is_array()) {
					std::vector<int> post_type_ids = get_json_int_array(filters, "post_type_ids");
					if (!post_type_ids.empty()) {
						// Filter by PostTypeId in metadata_json
						std::string post_type_conditions = "";
						for (size_t i = 0; i < post_type_ids.size(); ++i) {
							if (i > 0) post_type_conditions += " OR ";
							post_type_conditions += "json_extract(d.metadata_json, '$.PostTypeId') = " + std::to_string(post_type_ids[i]);
						}
						fts_sql += " AND (" + post_type_conditions + ")";
					}
				}

				if (filters.contains("tags_any") && filters["tags_any"].is_array()) {
					std::vector<std::string> tags_any = get_json_string_array(filters, "tags_any");
					if (!tags_any.empty()) {
						// Filter by any of the tags in metadata_json Tags field
						std::string tag_conditions = "";
						for (size_t i = 0; i < tags_any.size(); ++i) {
							if (i > 0) tag_conditions += " OR ";
							tag_conditions += "json_extract(d.metadata_json, '$.Tags') LIKE '%<" + tags_any[i] + ">%'";
						}
						fts_sql += " AND (" + tag_conditions + ")";
					}
				}

				if (filters.contains("tags_all") && filters["tags_all"].is_array()) {
					std::vector<std::string> tags_all = get_json_string_array(filters, "tags_all");
					if (!tags_all.empty()) {
						// Filter by all of the tags in metadata_json Tags field
						std::string tag_conditions = "";
						for (size_t i = 0; i < tags_all.size(); ++i) {
							if (i > 0) tag_conditions += " AND ";
							tag_conditions += "json_extract(d.metadata_json, '$.Tags') LIKE '%<" + tags_all[i] + ">%'";
						}
						fts_sql += " AND (" + tag_conditions + ")";
					}
				}

				if (filters.contains("created_after") && filters["created_after"].is_string()) {
					std::string created_after = filters["created_after"].get<std::string>();
					// Filter by CreationDate in metadata_json
					fts_sql += " AND json_extract(d.metadata_json, '$.CreationDate') >= '" + created_after + "'";
				}

				if (filters.contains("created_before") && filters["created_before"].is_string()) {
					std::string created_before = filters["created_before"].get<std::string>();
					// Filter by CreationDate in metadata_json
					fts_sql += " AND json_extract(d.metadata_json, '$.CreationDate') <= '" + created_before + "'";
				}

				fts_sql += " ORDER BY score_fts_raw "
					"LIMIT " + std::to_string(fts_k);

				SQLite3_result* fts_result = execute_query(fts_sql.c_str());
				if (!fts_result) {
					return create_error_response("FTS database query failed");
				}

				// Run vector search with filters
				std::vector<float> query_embedding;
				if (ai_manager && GloGATH) {
					GenAI_EmbeddingResult result = GloGATH->embed_documents({query});
					if (result.data && result.count > 0) {
						// Convert to std::vector<float>
						query_embedding.assign(result.data, result.data + result.embedding_size);
						// Free the result data (GenAI allocates with malloc)
						free(result.data);
					}
				}

				if (query_embedding.empty()) {
					delete fts_result;
					return create_error_response("Failed to generate embedding for query");
				}

				// Convert embedding to JSON array format for sqlite-vec
				std::string embedding_json = "[";
				for (size_t i = 0; i < query_embedding.size(); ++i) {
					if (i > 0) embedding_json += ",";
					embedding_json += std::to_string(query_embedding[i]);
				}
				embedding_json += "]";

				// Build vector search query using sqlite-vec syntax with filters
				// Must use subquery approach: LIMIT must be at same query level as MATCH
				std::string vec_sql = "SELECT v.chunk_id, c.doc_id, c.source_id, "
					"(SELECT name FROM rag_sources WHERE source_id = c.source_id) as source_name, "
					"c.title, v.distance as score_vec_raw, "
					"c.metadata_json "
					"FROM ("
					"  SELECT chunk_id, distance "
					"  FROM rag_vec_chunks "
					"  WHERE embedding MATCH '" + escape_fts_query(embedding_json) + "' "
					"  ORDER BY distance "
					"  LIMIT " + std::to_string(vec_k) + " "
					") v "
					"JOIN rag_chunks c ON c.chunk_id = v.chunk_id "
					"JOIN rag_documents d ON d.doc_id = c.doc_id";

				// Apply filters using consolidated filter building function
				// These filters are applied to the outer query after JOINs
				if (!build_sql_filters(filters, vec_sql)) {
					return create_error_response("Invalid filter parameters");
				}

				vec_sql += " ORDER BY v.distance";

				SQLite3_result* vec_result = execute_query(vec_sql.c_str());
				if (!vec_result) {
					delete fts_result;
					return create_error_response("Vector database query failed");
				}

				// Merge candidates by chunk_id and compute fused scores
				std::map<std::string, json> fused_results;

				// Process FTS results
				int fts_rank = 1;
				for (const auto& row : fts_result->rows) {
					if (row->fields) {
						std::string chunk_id = row->fields[0] ? row->fields[0] : "";
						if (!chunk_id.empty()) {
							json item;
							item["chunk_id"] = chunk_id;
							item["doc_id"] = row->fields[1] ? row->fields[1] : "";
							item["source_id"] = row->fields[2] ? std::stoi(row->fields[2]) : 0;
							item["source_name"] = row->fields[3] ? row->fields[3] : "";
							item["title"] = row->fields[4] ? row->fields[4] : "";
							double score_fts_raw = row->fields[5] ? std::stod(row->fields[5]) : 0.0;
							// Normalize FTS score (bm25 - lower is better, so we invert it)
							double score_fts = 1.0 / (1.0 + std::abs(score_fts_raw));
							item["score_fts"] = score_fts;
							item["rank_fts"] = fts_rank;
							item["rank_vec"] = 0;  // Will be updated if found in vector results
							item["score_vec"] = 0.0;

							// Add metadata if available
							if (row->fields[6]) {
								try {
									item["metadata"] = json::parse(row->fields[6]);
								} catch (...) {
									item["metadata"] = json::object();
								}
							}

							fused_results[chunk_id] = item;
							fts_rank++;
						}
					}
				}

				// Process vector results
				int vec_rank = 1;
				for (const auto& row : vec_result->rows) {
					if (row->fields) {
						std::string chunk_id = row->fields[0] ? row->fields[0] : "";
						if (!chunk_id.empty()) {
							double score_vec_raw = row->fields[5] ? std::stod(row->fields[5]) : 0.0;
							// For vector search, lower distance is better, so we invert it
							double score_vec = 1.0 / (1.0 + score_vec_raw);

							auto it = fused_results.find(chunk_id);
							if (it != fused_results.end()) {
								// Chunk already in FTS results, update vector info
								it->second["rank_vec"] = vec_rank;
								it->second["score_vec"] = score_vec;
							} else {
								// New chunk from vector results
								json item;
								item["chunk_id"] = chunk_id;
								item["doc_id"] = row->fields[1] ? row->fields[1] : "";
								item["source_id"] = row->fields[2] ? std::stoi(row->fields[2]) : 0;
								item["source_name"] = row->fields[3] ? row->fields[3] : "";
								item["title"] = row->fields[4] ? row->fields[4] : "";
								item["score_vec"] = score_vec;
								item["rank_vec"] = vec_rank;
								item["rank_fts"] = 0;  // Not found in FTS
								item["score_fts"] = 0.0;

								// Add metadata if available
								if (row->fields[6]) {
									try {
										item["metadata"] = json::parse(row->fields[6]);
									} catch (...) {
										item["metadata"] = json::object();
									}
								}

								fused_results[chunk_id] = item;
							}
							vec_rank++;
						}
					}
				}

				// Compute fused scores using RRF
				std::vector<std::pair<double, json>> scored_results;
				double min_score = 0.0;
				bool has_min_score = false;
				if (filters.contains("min_score") && (filters["min_score"].is_number() || filters["min_score"].is_string())) {
					min_score = filters["min_score"].is_number() ?
						filters["min_score"].get<double>() :
						std::stod(filters["min_score"].get<std::string>());
					has_min_score = true;
				}

				for (auto& pair : fused_results) {
					json& item = pair.second;
					int rank_fts = item["rank_fts"].get<int>();
					int rank_vec = item["rank_vec"].get<int>();
					double score_fts = item["score_fts"].get<double>();
					double score_vec = item["score_vec"].get<double>();

					// Compute fused score using weighted RRF
					double fused_score = 0.0;
					if (rank_fts > 0) {
						fused_score += w_fts / (rrf_k0 + rank_fts);
					}
					if (rank_vec > 0) {
						fused_score += w_vec / (rrf_k0 + rank_vec);
					}

					// Apply min_score filter
					if (has_min_score && fused_score < min_score) {
						continue; // Skip this result
					}

					item["score"] = fused_score;
					item["score_fts"] = score_fts;
					item["score_vec"] = score_vec;

					// Add debug info
					json debug;
					debug["rank_fts"] = rank_fts;
					debug["rank_vec"] = rank_vec;
					item["debug"] = debug;

					scored_results.push_back({fused_score, item});
				}

				// Sort by fused score descending
				std::sort(scored_results.begin(), scored_results.end(),
					[](const std::pair<double, json>& a, const std::pair<double, json>& b) {
						return a.first > b.first;
					});

				// Take top k results
				for (size_t i = 0; i < scored_results.size() && i < static_cast<size_t>(k); ++i) {
					results.push_back(scored_results[i].second);
				}

				delete fts_result;
				delete vec_result;

			} else if (mode == "fts_then_vec") {
				// Mode B: broad FTS candidate generation, then vector rerank

				// Get parameters from fts_then_vec object
				int candidates_k = 200;
				int rerank_k = 50;

				if (arguments.contains("fts_then_vec") && arguments["fts_then_vec"].is_object()) {
					const json& fts_then_vec_params = arguments["fts_then_vec"];
					candidates_k = validate_candidates(get_json_int(fts_then_vec_params, "candidates_k", 200));
					rerank_k = validate_k(get_json_int(fts_then_vec_params, "rerank_k", 50));
				} else {
					// Fallback to top-level parameters for backward compatibility
					candidates_k = validate_candidates(get_json_int(arguments, "candidates_k", 200));
					rerank_k = validate_k(get_json_int(arguments, "rerank_k", 50));
				}

				// Run FTS search to get candidates with filters
				std::string fts_sql = "SELECT c.chunk_id "
					"FROM rag_fts_chunks f "
					"JOIN rag_chunks c ON c.chunk_id = f.chunk_id "
					"JOIN rag_documents d ON d.doc_id = c.doc_id "
					"WHERE rag_fts_chunks MATCH '" + escape_fts_query(query) + "'";

				// Apply filters using consolidated filter building function
				if (!build_sql_filters(filters, fts_sql, false)) {
					return create_error_response("Invalid filter parameters");
				}

				if (filters.contains("source_names") && filters["source_names"].is_array()) {
					std::vector<std::string> source_names = get_json_string_array(filters, "source_names");
					if (!source_names.empty()) {
						std::string source_list = "";
						for (size_t i = 0; i < source_names.size(); ++i) {
							if (i > 0) source_list += ",";
							source_list += "'" + source_names[i] + "'";
						}
						fts_sql += " AND c.source_id IN (SELECT source_id FROM rag_sources WHERE name IN (" + source_list + "))";
					}
				}

				if (filters.contains("doc_ids") && filters["doc_ids"].is_array()) {
					std::vector<std::string> doc_ids = get_json_string_array(filters, "doc_ids");
					if (!doc_ids.empty()) {
						std::string doc_list = "";
						for (size_t i = 0; i < doc_ids.size(); ++i) {
							if (i > 0) doc_list += ",";
							doc_list += "'" + doc_ids[i] + "'";
						}
						fts_sql += " AND c.doc_id IN (" + doc_list + ")";
					}
				}

				// Metadata filters
				if (filters.contains("post_type_ids") && filters["post_type_ids"].is_array()) {
					std::vector<int> post_type_ids = get_json_int_array(filters, "post_type_ids");
					if (!post_type_ids.empty()) {
						// Filter by PostTypeId in metadata_json
						std::string post_type_conditions = "";
						for (size_t i = 0; i < post_type_ids.size(); ++i) {
							if (i > 0) post_type_conditions += " OR ";
							post_type_conditions += "json_extract(d.metadata_json, '$.PostTypeId') = " + std::to_string(post_type_ids[i]);
						}
						fts_sql += " AND (" + post_type_conditions + ")";
					}
				}

				if (filters.contains("tags_any") && filters["tags_any"].is_array()) {
					std::vector<std::string> tags_any = get_json_string_array(filters, "tags_any");
					if (!tags_any.empty()) {
						// Filter by any of the tags in metadata_json Tags field
						std::string tag_conditions = "";
						for (size_t i = 0; i < tags_any.size(); ++i) {
							if (i > 0) tag_conditions += " OR ";
							tag_conditions += "json_extract(d.metadata_json, '$.Tags') LIKE '%<" + tags_any[i] + ">%'";
						}
						fts_sql += " AND (" + tag_conditions + ")";
					}
				}

				if (filters.contains("tags_all") && filters["tags_all"].is_array()) {
					std::vector<std::string> tags_all = get_json_string_array(filters, "tags_all");
					if (!tags_all.empty()) {
						// Filter by all of the tags in metadata_json Tags field
						std::string tag_conditions = "";
						for (size_t i = 0; i < tags_all.size(); ++i) {
							if (i > 0) tag_conditions += " AND ";
							tag_conditions += "json_extract(d.metadata_json, '$.Tags') LIKE '%<" + tags_all[i] + ">%'";
						}
						fts_sql += " AND (" + tag_conditions + ")";
					}
				}

				if (filters.contains("created_after") && filters["created_after"].is_string()) {
					std::string created_after = filters["created_after"].get<std::string>();
					// Filter by CreationDate in metadata_json
					fts_sql += " AND json_extract(d.metadata_json, '$.CreationDate') >= '" + created_after + "'";
				}

				if (filters.contains("created_before") && filters["created_before"].is_string()) {
					std::string created_before = filters["created_before"].get<std::string>();
					// Filter by CreationDate in metadata_json
					fts_sql += " AND json_extract(d.metadata_json, '$.CreationDate') <= '" + created_before + "'";
				}

				fts_sql += " ORDER BY bm25(rag_fts_chunks) "
					"LIMIT " + std::to_string(candidates_k);

				SQLite3_result* fts_result = execute_query(fts_sql.c_str());
				if (!fts_result) {
					return create_error_response("FTS database query failed");
				}

				// Build candidate list
				std::vector<std::string> candidate_ids;
				for (const auto& row : fts_result->rows) {
					if (row->fields && row->fields[0]) {
						candidate_ids.push_back(row->fields[0]);
					}
				}

				delete fts_result;

				if (candidate_ids.empty()) {
					// No candidates found
				} else {
					// Run vector search on candidates with filters
					std::vector<float> query_embedding;
					if (ai_manager && GloGATH) {
						GenAI_EmbeddingResult result = GloGATH->embed_documents({query});
						if (result.data && result.count > 0) {
							// Convert to std::vector<float>
							query_embedding.assign(result.data, result.data + result.embedding_size);
							// Free the result data (GenAI allocates with malloc)
							free(result.data);
						}
					}

					if (query_embedding.empty()) {
						return create_error_response("Failed to generate embedding for query");
					}

					// Convert embedding to JSON array format for sqlite-vec
					std::string embedding_json = "[";
					for (size_t i = 0; i < query_embedding.size(); ++i) {
						if (i > 0) embedding_json += ",";
						embedding_json += std::to_string(query_embedding[i]);
					}
					embedding_json += "]";

					// Build candidate ID list for SQL
					std::string candidate_list = "'";
					for (size_t i = 0; i < candidate_ids.size(); ++i) {
						if (i > 0) candidate_list += "','";
						candidate_list += candidate_ids[i];
					}
					candidate_list += "'";

					// Build vector search query using sqlite-vec syntax with filters
					// Must use subquery approach: LIMIT must be at same query level as MATCH
					std::string vec_sql = "SELECT v.chunk_id, c.doc_id, c.source_id, "
						"(SELECT name FROM rag_sources WHERE source_id = c.source_id) as source_name, "
						"c.title, v.distance as score_vec_raw, "
						"c.metadata_json "
						"FROM ("
						"  SELECT chunk_id, distance "
						"  FROM rag_vec_chunks "
						"  WHERE embedding MATCH '" + escape_fts_query(embedding_json) + "' "
						"    AND chunk_id IN (" + candidate_list + ") "
						"  ORDER BY distance "
						"  LIMIT " + std::to_string(rerank_k) + " "
						") v "
						"JOIN rag_chunks c ON c.chunk_id = v.chunk_id "
						"JOIN rag_documents d ON d.doc_id = c.doc_id";

					// Apply filters using consolidated filter building function
					// These filters are applied to the outer query after JOINs
					if (!build_sql_filters(filters, vec_sql)) {
						return create_error_response("Invalid filter parameters");
					}

					vec_sql += " ORDER BY v.distance";

					SQLite3_result* vec_result = execute_query(vec_sql.c_str());
					if (!vec_result) {
						return create_error_response("Vector database query failed");
					}

					// Build results with min_score filtering
					int rank = 1;
					double min_score = 0.0;
					bool has_min_score = false;
					if (filters.contains("min_score") && (filters["min_score"].is_number() || filters["min_score"].is_string())) {
						min_score = filters["min_score"].is_number() ?
							filters["min_score"].get<double>() :
							std::stod(filters["min_score"].get<std::string>());
						has_min_score = true;
					}

					for (const auto& row : vec_result->rows) {
						if (row->fields) {
							double score_vec_raw = row->fields[5] ? std::stod(row->fields[5]) : 0.0;
							// For vector search, lower distance is better, so we invert it
							double score_vec = 1.0 / (1.0 + score_vec_raw);

							// Apply min_score filter
							if (has_min_score && score_vec < min_score) {
								continue; // Skip this result
							}

							json item;
							item["chunk_id"] = row->fields[0] ? row->fields[0] : "";
							item["doc_id"] = row->fields[1] ? row->fields[1] : "";
							item["source_id"] = row->fields[2] ? std::stoi(row->fields[2]) : 0;
							item["source_name"] = row->fields[3] ? row->fields[3] : "";
							item["title"] = row->fields[4] ? row->fields[4] : "";
							item["score"] = score_vec;
							item["score_vec"] = score_vec;
							item["rank"] = rank;

							// Add metadata if available
							if (row->fields[6]) {
								try {
									item["metadata"] = json::parse(row->fields[6]);
								} catch (...) {
									item["metadata"] = json::object();
								}
							}

							results.push_back(item);
							rank++;
						}
					}

					delete vec_result;
				}
			}

			result["results"] = results;
			result["truncated"] = false;

			// Add timing stats
			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
			json stats;
			stats["mode"] = mode;
			stats["k_requested"] = k;
			stats["k_returned"] = static_cast<int>(results.size());
			stats["ms"] = static_cast<int>(duration.count());
			result["stats"] = stats;

		} else if (tool_name == "rag.get_chunks") {
			// Get chunks implementation
			std::vector<std::string> chunk_ids = get_json_string_array(arguments, "chunk_ids");

			if (chunk_ids.empty()) {
				return create_error_response("No chunk_ids provided");
			}

			// Validate chunk_ids to prevent SQL injection
			for (const std::string& chunk_id : chunk_ids) {
				if (chunk_id.find('\'') != std::string::npos ||
					chunk_id.find('\\') != std::string::npos ||
					chunk_id.find(';') != std::string::npos) {
					return create_error_response("Invalid characters in chunk_ids");
				}
			}

			// Get return parameters
			bool include_title = true;
			bool include_doc_metadata = true;
			bool include_chunk_metadata = true;
			if (arguments.contains("return")) {
				const json& return_params = arguments["return"];
				include_title = get_json_bool(return_params, "include_title", true);
				include_doc_metadata = get_json_bool(return_params, "include_doc_metadata", true);
				include_chunk_metadata = get_json_bool(return_params, "include_chunk_metadata", true);
			}

			// Build chunk ID list for SQL with proper escaping
			std::string chunk_list = "";
			for (size_t i = 0; i < chunk_ids.size(); ++i) {
				if (i > 0) chunk_list += ",";
				// Properly escape single quotes in chunk IDs
				std::string escaped_chunk_id = chunk_ids[i];
				size_t pos = 0;
				while ((pos = escaped_chunk_id.find("'", pos)) != std::string::npos) {
					escaped_chunk_id.replace(pos, 1, "''");
					pos += 2;
				}
				chunk_list += "'" + escaped_chunk_id + "'";
			}

			// Build query with proper joins to get metadata
			std::string sql = "SELECT c.chunk_id, c.doc_id, c.title, c.body, "
				"d.metadata_json as doc_metadata, c.metadata_json as chunk_metadata "
				"FROM rag_chunks c "
				"LEFT JOIN rag_documents d ON d.doc_id = c.doc_id "
				"WHERE c.chunk_id IN (" + chunk_list + ")";

			SQLite3_result* db_result = execute_query(sql.c_str());
			if (!db_result) {
				return create_error_response("Database query failed");
			}

			// Build chunks array
			json chunks = json::array();
			for (const auto& row : db_result->rows) {
				if (row->fields) {
					json chunk;
					chunk["chunk_id"] = row->fields[0] ? row->fields[0] : "";
					chunk["doc_id"] = row->fields[1] ? row->fields[1] : "";

					if (include_title) {
						chunk["title"] = row->fields[2] ? row->fields[2] : "";
					}

					// Always include body for get_chunks
					chunk["body"] = row->fields[3] ? row->fields[3] : "";

					if (include_doc_metadata && row->fields[4]) {
						try {
							chunk["doc_metadata"] = json::parse(row->fields[4]);
						} catch (...) {
							chunk["doc_metadata"] = json::object();
						}
					}

					if (include_chunk_metadata && row->fields[5]) {
						try {
							chunk["chunk_metadata"] = json::parse(row->fields[5]);
						} catch (...) {
							chunk["chunk_metadata"] = json::object();
						}
					}

					chunks.push_back(chunk);
				}
			}

			delete db_result;

			result["chunks"] = chunks;
			result["truncated"] = false;

			// Add timing stats
			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
			json stats;
			stats["ms"] = static_cast<int>(duration.count());
			result["stats"] = stats;

		} else if (tool_name == "rag.get_docs") {
			// Get docs implementation
			std::vector<std::string> doc_ids = get_json_string_array(arguments, "doc_ids");

			if (doc_ids.empty()) {
				return create_error_response("No doc_ids provided");
			}

			// Get return parameters
			bool include_body = true;
			bool include_metadata = true;
			if (arguments.contains("return")) {
				const json& return_params = arguments["return"];
				include_body = get_json_bool(return_params, "include_body", true);
				include_metadata = get_json_bool(return_params, "include_metadata", true);
			}

			// Build doc ID list for SQL
			std::string doc_list = "'";
			for (size_t i = 0; i < doc_ids.size(); ++i) {
				if (i > 0) doc_list += "','";
				doc_list += doc_ids[i];
			}
			doc_list += "'";

			// Build query
			std::string sql = "SELECT doc_id, source_id, "
				"(SELECT name FROM rag_sources WHERE source_id = rag_documents.source_id) as source_name, "
				"pk_json, title, body, metadata_json "
				"FROM rag_documents "
				"WHERE doc_id IN (" + doc_list + ")";

			SQLite3_result* db_result = execute_query(sql.c_str());
			if (!db_result) {
				return create_error_response("Database query failed");
			}

			// Build docs array
			json docs = json::array();
			for (const auto& row : db_result->rows) {
				if (row->fields) {
					json doc;
					doc["doc_id"] = row->fields[0] ? row->fields[0] : "";
					doc["source_id"] = row->fields[1] ? std::stoi(row->fields[1]) : 0;
					doc["source_name"] = row->fields[2] ? row->fields[2] : "";
					doc["pk_json"] = row->fields[3] ? row->fields[3] : "{}";

					// Always include title
					doc["title"] = row->fields[4] ? row->fields[4] : "";

					if (include_body) {
						doc["body"] = row->fields[5] ? row->fields[5] : "";
					}

					if (include_metadata && row->fields[6]) {
						try {
							doc["metadata"] = json::parse(row->fields[6]);
						} catch (...) {
							doc["metadata"] = json::object();
						}
					}

					docs.push_back(doc);
				}
			}

			delete db_result;

			result["docs"] = docs;
			result["truncated"] = false;

			// Add timing stats
			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
			json stats;
			stats["ms"] = static_cast<int>(duration.count());
			result["stats"] = stats;

		} else if (tool_name == "rag.fetch_from_source") {
			// Fetch from source implementation
			std::vector<std::string> doc_ids = get_json_string_array(arguments, "doc_ids");
			std::vector<std::string> columns = get_json_string_array(arguments, "columns");

			// Get limits
			int max_rows = 10;
			int max_bytes = 200000;
			if (arguments.contains("limits")) {
				const json& limits = arguments["limits"];
				max_rows = get_json_int(limits, "max_rows", 10);
				max_bytes = get_json_int(limits, "max_bytes", 200000);
			}

			if (doc_ids.empty()) {
				return create_error_response("No doc_ids provided");
			}

			// Validate limits
			if (max_rows > 100) max_rows = 100;
			if (max_bytes > 1000000) max_bytes = 1000000;

			// Build rows array
			json rows = json::array();
			int total_bytes = 0;
			bool truncated = false;

			// Process each requested document in order
			for (const auto& doc_id : doc_ids) {
				if (rows.size() >= static_cast<size_t>(max_rows) || total_bytes >= max_bytes) {
					truncated = true;
					break;
				}

				RagSourceConfig cfg;
				std::string error;
				if (!fetch_rag_source_config(vector_db, doc_id, cfg, error)) {
					json result_row;
					result_row["doc_id"] = doc_id;
					result_row["error"] = error;
					result_row["source_name"] = "";
					std::string row_str = result_row.dump();
					if (total_bytes + static_cast<int>(row_str.length()) > max_bytes) {
						truncated = true;
						break;
					}
					total_bytes += static_cast<int>(row_str.length());
					rows.push_back(result_row);
					continue;
				}

				json fetched_rows = json::array();
				bool ok = false;
				if (cfg.backend_type == "mysql") {
					ok = fetch_rag_rows_mysql(cfg, doc_id, columns, fetched_rows, error);
				} else if (cfg.backend_type == "pgsql" || cfg.backend_type == "postgres" || cfg.backend_type == "postgresql") {
					ok = fetch_rag_rows_pgsql(cfg, doc_id, columns, fetched_rows, error);
				} else {
					error = "Unsupported backend type: " + cfg.backend_type;
				}

				json result_row;
				result_row["doc_id"] = doc_id;
				result_row["source_id"] = cfg.source_id;
				result_row["source_name"] = cfg.source_name;
				result_row["backend_type"] = cfg.backend_type;

				if (!ok) {
					result_row["error"] = error;
				} else {
					result_row["row"] = fetched_rows[0];
				}

				std::string row_str = result_row.dump();
				if (total_bytes + static_cast<int>(row_str.length()) > max_bytes) {
					truncated = true;
					break;
				}

				total_bytes += static_cast<int>(row_str.length());
				rows.push_back(result_row);
			}

			result["rows"] = rows;
			result["truncated"] = truncated;

			// Add timing stats
			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
			json stats;
			stats["ms"] = static_cast<int>(duration.count());
			result["stats"] = stats;

		} else if (tool_name == "rag.admin.stats") {
			// Admin stats implementation
			// Build query to get source statistics
			std::string sql = "SELECT s.source_id, s.name, "
				"COUNT(d.doc_id) as docs, "
				"COUNT(c.chunk_id) as chunks "
				"FROM rag_sources s "
				"LEFT JOIN rag_documents d ON d.source_id = s.source_id "
				"LEFT JOIN rag_chunks c ON c.source_id = s.source_id "
				"GROUP BY s.source_id, s.name";

			SQLite3_result* db_result = execute_query(sql.c_str());
			if (!db_result) {
				return create_error_response("Database query failed");
			}

			// Build sources array
			json sources = json::array();
			for (const auto& row : db_result->rows) {
				if (row->fields) {
					json source;
					source["source_id"] = row->fields[0] ? std::stoi(row->fields[0]) : 0;
					source["source_name"] = row->fields[1] ? row->fields[1] : "";
					source["docs"] = row->fields[2] ? std::stoi(row->fields[2]) : 0;
					source["chunks"] = row->fields[3] ? std::stoi(row->fields[3]) : 0;
					source["last_sync"] = nullptr;  // Placeholder
					sources.push_back(source);
				}
			}

			delete db_result;

			result["sources"] = sources;

			// Add timing stats
			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
			json stats;
			stats["ms"] = static_cast<int>(duration.count());
			result["stats"] = stats;

		} else {
			// Unknown tool
			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
			track_tool_invocation(this, "RAG", tool_name, "rag", duration_us);
			return create_error_response("Unknown tool: " + tool_name);
		}

		// Track invocation with timing
		auto end_time = std::chrono::high_resolution_clock::now();
		auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
		track_tool_invocation(this, "RAG", tool_name, "rag", duration_us);

		return create_success_response(result);

	} catch (const std::exception& e) {
		proxy_error("RAG_Tool_Handler: Exception in execute_tool: %s\n", e.what());
		return create_error_response(std::string("Exception: ") + e.what());
	} catch (...) {
		proxy_error("RAG_Tool_Handler: Unknown exception in execute_tool\n");
		return create_error_response("Unknown exception");
	}
}

// ============================================================================
// Tool Usage Statistics
// ============================================================================

RAG_Tool_Handler::ToolUsageStatsMap RAG_Tool_Handler::get_tool_usage_stats() {
	// Thread-safe copy of counters
	pthread_mutex_lock(&counters_lock);
	ToolUsageStatsMap copy = tool_usage_stats;
	pthread_mutex_unlock(&counters_lock);
	return copy;
}

SQLite3_result* RAG_Tool_Handler::get_tool_usage_stats_resultset(bool reset) {
	SQLite3_result* result = new SQLite3_result(9);
	result->add_column_definition(SQLITE_TEXT, "endpoint");
	result->add_column_definition(SQLITE_TEXT, "tool");
	result->add_column_definition(SQLITE_TEXT, "schema");
	result->add_column_definition(SQLITE_TEXT, "count");
	result->add_column_definition(SQLITE_TEXT, "first_seen");
	result->add_column_definition(SQLITE_TEXT, "last_seen");
	result->add_column_definition(SQLITE_TEXT, "sum_time");
	result->add_column_definition(SQLITE_TEXT, "min_time");
	result->add_column_definition(SQLITE_TEXT, "max_time");

	pthread_mutex_lock(&counters_lock);

	for (ToolUsageStatsMap::const_iterator endpoint_it = tool_usage_stats.begin();
	     endpoint_it != tool_usage_stats.end(); ++endpoint_it) {
		const std::string& endpoint = endpoint_it->first;
		const ToolStatsMap& tools = endpoint_it->second;

		for (ToolStatsMap::const_iterator tool_it = tools.begin();
		     tool_it != tools.end(); ++tool_it) {
			const std::string& tool_name = tool_it->first;
			const SchemaStatsMap& schemas = tool_it->second;

			for (SchemaStatsMap::const_iterator schema_it = schemas.begin();
			     schema_it != schemas.end(); ++schema_it) {
				const std::string& schema_name = schema_it->first;
				const ToolUsageStats& stats = schema_it->second;

				char** row = new char*[9];
				row[0] = strdup(endpoint.c_str());
				row[1] = strdup(tool_name.c_str());
				row[2] = strdup(schema_name.c_str());

				char buf[32];
				snprintf(buf, sizeof(buf), "%llu", stats.count);
				row[3] = strdup(buf);
				snprintf(buf, sizeof(buf), "%llu", stats.first_seen);
				row[4] = strdup(buf);
				snprintf(buf, sizeof(buf), "%llu", stats.last_seen);
				row[5] = strdup(buf);
				snprintf(buf, sizeof(buf), "%llu", stats.sum_time);
				row[6] = strdup(buf);
				snprintf(buf, sizeof(buf), "%llu", stats.min_time);
				row[7] = strdup(buf);
				snprintf(buf, sizeof(buf), "%llu", stats.max_time);
				row[8] = strdup(buf);

				result->add_row(row);
			}
		}
	}

	if (reset) {
		tool_usage_stats.clear();
	}

	pthread_mutex_unlock(&counters_lock);
	return result;
}

#endif /* PROXYSQL40 */
