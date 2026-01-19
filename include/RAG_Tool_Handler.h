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
 * @date 2026-01-19
 */

#ifndef CLASS_RAG_TOOL_HANDLER_H
#define CLASS_RAG_TOOL_HANDLER_H

#include "MCP_Tool_Handler.h"
#include "sqlite3db.h"
#include "GenAI_Thread.h"
#include <string>
#include <vector>
#include <map>

// Forward declarations
class AI_Features_Manager;

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
 */
class RAG_Tool_Handler : public MCP_Tool_Handler {
private:
	SQLite3DB* vector_db;
	AI_Features_Manager* ai_manager;

	// Configuration
	int k_max;
	int candidates_max;
	int query_max_bytes;
	int response_max_bytes;
	int timeout_ms;

	/**
	 * @brief Helper to extract string parameter from JSON
	 */
	static std::string get_json_string(const json& j, const std::string& key,
	                                    const std::string& default_val = "");

	/**
	 * @brief Helper to extract int parameter from JSON
	 */
	static int get_json_int(const json& j, const std::string& key, int default_val = 0);

	/**
	 * @brief Helper to extract bool parameter from JSON
	 */
	static bool get_json_bool(const json& j, const std::string& key, bool default_val = false);

	/**
	 * @brief Helper to extract string array from JSON
	 */
	static std::vector<std::string> get_json_string_array(const json& j, const std::string& key);

	/**
	 * @brief Helper to extract int array from JSON
	 */
	static std::vector<int> get_json_int_array(const json& j, const std::string& key);

	/**
	 * @brief Validate and limit k parameter
	 */
	int validate_k(int k);

	/**
	 * @brief Validate and limit candidates parameter
	 */
	int validate_candidates(int candidates);

	/**
	 * @brief Validate query length
	 */
	bool validate_query_length(const std::string& query);

	/**
	 * @brief Execute database query and return results
	 */
	SQLite3_result* execute_query(const char* query);

	/**
	 * @brief Compute Reciprocal Rank Fusion score
	 */
	double compute_rrf_score(int rank, int k0, double weight);

	/**
	 * @brief Normalize scores to 0-1 range (higher is better)
	 */
	double normalize_score(double score, const std::string& score_type);

public:
	/**
	 * @brief Constructor
	 */
	RAG_Tool_Handler(AI_Features_Manager* ai_mgr);

	/**
	 * @brief Destructor
	 */
	~RAG_Tool_Handler();

	/**
	 * @brief Initialize the tool handler
	 */
	int init() override;

	/**
	 * @brief Close and cleanup
	 */
	void close() override;

	/**
	 * @brief Get handler name
	 */
	std::string get_handler_name() const override { return "rag"; }

	/**
	 * @brief Get list of available tools
	 */
	json get_tool_list() override;

	/**
	 * @brief Get description of a specific tool
	 */
	json get_tool_description(const std::string& tool_name) override;

	/**
	 * @brief Execute a tool with arguments
	 */
	json execute_tool(const std::string& tool_name, const json& arguments) override;

	/**
	 * @brief Set the vector database
	 */
	void set_vector_db(SQLite3DB* db) { vector_db = db; }
};

#endif /* CLASS_RAG_TOOL_HANDLER_H */