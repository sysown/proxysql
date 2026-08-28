/**
 * @file RAG_Tool_Handler.h
 * @brief RAG Tool Handler for MCP protocol
 *
 * Provides RAG (Retrieval-Augmented Generation) tools via MCP protocol including:
 * - FTS search over documents
 * - Vector search over embeddings
 * - Hybrid search combining FTS and vectors
 * - Fetch tools for retrieving document/chunk content
 * - Refetch tool for authoritative source data
 * - Admin tools for operational visibility
 *
 * The RAG subsystem implements a complete retrieval system with:
 * - Full-text search using SQLite FTS5
 * - Semantic search using vector embeddings with sqlite3-vec
 * - Hybrid search combining both approaches
 * - Comprehensive filtering capabilities
 * - Security features including input validation and limits
 * - Performance optimizations
 *
 * @date 2026-01-19
 * @author ProxySQL Team
 * @copyright GNU GPL v3
 * @ingroup mcp
 * @ingroup rag
 */

#ifndef CLASS_RAG_TOOL_HANDLER_H
#define CLASS_RAG_TOOL_HANDLER_H

#ifdef PROXYSQL40

#include "MCP_Tool_Handler.h"
#include "sqlite3db.h"
#include "GenAI_Thread.h"
#include <string>
#include <vector>
#include <map>
#include <pthread.h>

// Forward declarations
class AI_Features_Manager;
class Discovery_Schema;

/**
 * @brief RAG Tool Handler for MCP
 *
 * Provides RAG-powered tools through the MCP protocol:
 * - rag.search_fts: Keyword search using FTS5
 * - rag.search_vector: Semantic search using vector embeddings
 * - rag.search_hybrid: Hybrid search combining FTS and vectors
 * - rag.get_chunks: Fetch chunk content by chunk_id
 * - rag.get_docs: Fetch document content by doc_id
 * - rag.fetch_from_source: Refetch authoritative data from source
 * - rag.admin.stats: Operational statistics
 *
 * The RAG subsystem implements a complete retrieval system with:
 * - Full-text search using SQLite FTS5
 * - Semantic search using vector embeddings with sqlite3-vec
 * - Hybrid search combining both approaches with Reciprocal Rank Fusion
 * - Comprehensive filtering capabilities by source, document, tags, dates, etc.
 * - Security features including input validation, limits, and timeouts
 * - Performance optimizations with prepared statements and connection management
 *
 * @ingroup mcp
 * @ingroup rag
 */
class RAG_Tool_Handler : public MCP_Tool_Handler {
private:
	/// Vector database connection
	SQLite3DB* vector_db;

	/// AI features manager for shared resources
	AI_Features_Manager* ai_manager;

	/// Discovery catalog for logging
	Discovery_Schema* catalog;

	/// Catalog path for database initialization
	std::string catalog_path;

	/// @name Configuration Parameters
	/// @{

	/// Maximum number of search results (default: 50)
	int k_max;

	/// Maximum number of candidates for hybrid search (default: 500)
	int candidates_max;

	/// Maximum query length in bytes (default: 8192)
	int query_max_bytes;

	/// Maximum response size in bytes (default: 5000000)
	int response_max_bytes;

	/// Operation timeout in milliseconds (default: 2000)
	int timeout_ms;

	/// @}

	// Statistics for a specific (tool, schema) pair
	struct ToolUsageStats {
		unsigned long long count;
		unsigned long long first_seen;
		unsigned long long last_seen;
		unsigned long long sum_time;
		unsigned long long min_time;
		unsigned long long max_time;

		ToolUsageStats() : count(0), first_seen(0), last_seen(0),
		                   sum_time(0), min_time(0), max_time(0) {}

		void add_timing(unsigned long long duration, unsigned long long timestamp) {
			count++;
			sum_time += duration;
			if (duration < min_time || min_time == 0) {
				if (duration) min_time = duration;
			}
			if (duration > max_time) {
				max_time = duration;
			}
			if (first_seen == 0) {
				first_seen = timestamp;
			}
			last_seen = timestamp;
		}
	};

	// Tool usage counters: endpoint -> tool_name -> schema_name -> ToolUsageStats
	typedef std::map<std::string, ToolUsageStats> SchemaStatsMap;
	typedef std::map<std::string, SchemaStatsMap> ToolStatsMap;
	typedef std::map<std::string, ToolStatsMap> ToolUsageStatsMap;
	ToolUsageStatsMap tool_usage_stats;
	pthread_mutex_t counters_lock;

	// Friend function for tracking tool invocations
	friend void track_tool_invocation(RAG_Tool_Handler*, const std::string&, const std::string&, const std::string&, unsigned long long);


	/**
	 * @brief Helper to extract string parameter from JSON
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
	static std::string get_json_string(const json& j, const std::string& key,
	                                    const std::string& default_val = "");

	/**
	 * @brief Helper to extract int parameter from JSON
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
	static int get_json_int(const json& j, const std::string& key, int default_val = 0);

	/**
	 * @brief Helper to extract bool parameter from JSON
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
	static bool get_json_bool(const json& j, const std::string& key, bool default_val = false);

	/**
	 * @brief Helper to extract string array from JSON
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
	static std::vector<std::string> get_json_string_array(const json& j, const std::string& key);

	/**
	 * @brief Helper to extract int array from JSON
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
	static std::vector<int> get_json_int_array(const json& j, const std::string& key);

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
	int validate_k(int k);

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
	int validate_candidates(int candidates);

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
	bool validate_query_length(const std::string& query);

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
	std::string escape_fts_query(const std::string& query);

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
	SQLite3_result* execute_query(const char* query);

	/**
	 * @brief Execute parameterized database query with bindings
	 *
	 * Executes a parameterized SQL query against the vector database with bound parameters
	 * and returns the results. This prevents SQL injection vulnerabilities.
	 * Handles error checking and logging. The caller is responsible for freeing
	 * the returned SQLite3_result.
	 *
	 * @param query SQL query string with placeholders to execute
	 * @param bindings Vector of parameter bindings (text, int, double)
	 * @return SQLite3_result pointer or NULL on error
	 *
	 * @see vector_db
	 */
	SQLite3_result* execute_parameterized_query(const char* query, const std::vector<std::pair<int, std::string>>& text_bindings = {}, const std::vector<std::pair<int, int>>& int_bindings = {});

	/**
	 * @brief Build SQL filter conditions from JSON filters
	 *
	 * Builds SQL WHERE conditions from JSON filter parameters with proper input validation
	 * to prevent SQL injection. This consolidates the duplicated filter building logic
	 * across different search tools.
	 *
	 * @param filters JSON object containing filter parameters
	 * @param sql Reference to SQL string to append conditions to
	 * @param add_where_clause If true, adds 'WHERE 1=1' before filters (default: true)
	 * @return true on success, false on validation error
	 *
	 * @see execute_tool()
	 */
	bool build_sql_filters(const json& filters, std::string& sql, bool add_where_clause = true);

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
	double compute_rrf_score(int rank, int k0, double weight);

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
	double normalize_score(double score, const std::string& score_type);

public:
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
	 * @param cat_path Path to the catalog database (for logging)
	 *
	 * @see AI_Features_Manager
	 * @see Discovery_Schema
	 * @see GenAI_Thread
	 */
	RAG_Tool_Handler(AI_Features_Manager* ai_mgr, const std::string& cat_path = "");

	/**
	 * @brief Destructor
	 *
	 * Cleans up resources and closes database connections.
	 *
	 * @see close()
	 */
	~RAG_Tool_Handler();

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
	int init() override;

	/**
	 * Refresh borrowed runtime resources and the configuration snapshot after
	 * LOAD GENAI VARIABLES.  The caller must hold the plugin runtime dependency
	 * mutex exclusively.
	 */
	void refresh_runtime_dependencies(AI_Features_Manager* ai_mgr);

	/**
	 * @brief Close and cleanup
	 *
	 * Cleans up resources and closes database connections. Called automatically
	 * by the destructor.
	 *
	 * @see init()
	 * @see ~RAG_Tool_Handler()
	 */
	void close() override;

	/**
	 * @brief Get handler name
	 *
	 * Returns the name of this tool handler for identification purposes.
	 *
	 * @return Handler name as string ("rag")
	 *
	 * @see MCP_Tool_Handler
	 */
	std::string get_handler_name() const override { return "rag"; }

	/**
	 * @brief Get list of available tools
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
	json get_tool_list() override;

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
	json get_tool_description(const std::string& tool_name) override;

	/**
	 * @brief Execute a tool with arguments
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
	json execute_tool(const std::string& tool_name, const json& arguments) override;

	/**
	 * @brief Set the vector database
	 *
	 * Sets the vector database connection for this tool handler.
	 *
	 * @param db Pointer to SQLite3DB vector database
	 *
	 * @see vector_db
	 * @see init()
	 */
	void set_vector_db(SQLite3DB* db) { vector_db = db; }

	/**
	 * @brief Get tool usage statistics (thread-safe copy)
	 * @return ToolUsageStatsMap copy with endpoint -> tool_name -> schema_name -> ToolUsageStats
	 */
	ToolUsageStatsMap get_tool_usage_stats();

	/**
	 * @brief Get tool usage statistics as SQLite3_result* with optional reset
	 * @param reset If true, resets internal counters after capturing data
	 * @return SQLite3_result* with columns: endpoint, tool, schema, count, first_seen, last_seen, sum_time, min_time, max_time. Caller must delete.
	 */
	SQLite3_result* get_tool_usage_stats_resultset(bool reset = false);
};

#endif /* PROXYSQL40 */
#endif /* CLASS_RAG_TOOL_HANDLER_H */
