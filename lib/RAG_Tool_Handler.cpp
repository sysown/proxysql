/**
 * @file RAG_Tool_Handler.cpp
 * @brief Implementation of RAG Tool Handler for MCP protocol
 *
 * Implements RAG-powered tools through MCP protocol for retrieval operations.
 *
 * @see RAG_Tool_Handler.h
 */

#include "RAG_Tool_Handler.h"
#include "AI_Features_Manager.h"
#include "GenAI_Thread.h"
#include "LLM_Bridge.h"
#include "proxysql_debug.h"
#include "cpp.h"
#include <sstream>
#include <algorithm>
#include <chrono>

// Forward declaration for GloGATH
extern GenAI_Threads_Handler *GloGATH;

// JSON library
#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

// Forward declaration for GloGATH
extern GenAI_Threads_Handler *GloGATH;

// ============================================================================
// Constructor/Destructor
// ============================================================================

/**
 * @brief Constructor
 */
RAG_Tool_Handler::RAG_Tool_Handler(AI_Features_Manager* ai_mgr)
	: vector_db(NULL),
	  ai_manager(ai_mgr),
	  k_max(50),
	  candidates_max(500),
	  query_max_bytes(8192),
	  response_max_bytes(5000000),
	  timeout_ms(2000)
{
	// Initialize configuration from GenAI_Thread if available
	if (ai_manager && GloGATH) {
		k_max = GloGATH->variables.genai_rag_k_max;
		candidates_max = GloGATH->variables.genai_rag_candidates_max;
		query_max_bytes = GloGATH->variables.genai_rag_query_max_bytes;
		response_max_bytes = GloGATH->variables.genai_rag_response_max_bytes;
		timeout_ms = GloGATH->variables.genai_rag_timeout_ms;
	}

	proxy_debug(PROXY_DEBUG_GENAI, 3, "RAG_Tool_Handler created\n");
}

/**
 * @brief Destructor
 */
RAG_Tool_Handler::~RAG_Tool_Handler() {
	close();
	proxy_debug(PROXY_DEBUG_GENAI, 3, "RAG_Tool_Handler destroyed\n");
}

// ============================================================================
// Lifecycle
// ============================================================================

/**
 * @brief Initialize the tool handler
 */
int RAG_Tool_Handler::init() {
	if (ai_manager) {
		vector_db = ai_manager->get_vector_db();
	}

	if (!vector_db) {
		proxy_error("RAG_Tool_Handler: Vector database not available\n");
		return -1;
	}

	proxy_info("RAG_Tool_Handler initialized\n");
	return 0;
}

/**
 * @brief Close and cleanup
 */
void RAG_Tool_Handler::close() {
	// Cleanup will be handled by AI_Features_Manager
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Extract string parameter from JSON
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
 */
int RAG_Tool_Handler::validate_k(int k) {
	if (k <= 0) return 10;  // Default
	if (k > k_max) return k_max;
	return k;
}

/**
 * @brief Validate and limit candidates parameter
 */
int RAG_Tool_Handler::validate_candidates(int candidates) {
	if (candidates <= 0) return 50;  // Default
	if (candidates > candidates_max) return candidates_max;
	return candidates;
}

/**
 * @brief Validate query length
 */
bool RAG_Tool_Handler::validate_query_length(const std::string& query) {
	return static_cast<int>(query.length()) <= query_max_bytes;
}

/**
 * @brief Execute database query and return results
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
		proxy_sqlite3_free(error);
		return NULL;
	}

	return result;
}

/**
 * @brief Compute Reciprocal Rank Fusion score
 */
double RAG_Tool_Handler::compute_rrf_score(int rank, int k0, double weight) {
	if (rank <= 0) return 0.0;
	return weight / (k0 + rank);
}

/**
 * @brief Normalize scores to 0-1 range (higher is better)
 */
double RAG_Tool_Handler::normalize_score(double score, const std::string& score_type) {
	// For now, return the score as-is
	// In the future, we might want to normalize different score types differently
	return score;
}

// ============================================================================
// Tool List
// ============================================================================

/**
 * @brief Get list of available RAG tools
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
 */
json RAG_Tool_Handler::execute_tool(const std::string& tool_name, const json& arguments) {
	proxy_debug(PROXY_DEBUG_GENAI, 3, "RAG_Tool_Handler: execute_tool(%s)\n", tool_name.c_str());

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

			// Build FTS query with filters
			std::string sql = "SELECT c.chunk_id, c.doc_id, c.source_id, "
				"(SELECT name FROM rag_sources WHERE source_id = c.source_id) as source_name, "
				"c.title, bm25(f) as score_fts_raw, "
				"c.metadata_json, c.body "
				"FROM rag_fts_chunks f "
				"JOIN rag_chunks c ON c.chunk_id = f.chunk_id "
				"JOIN rag_documents d ON d.doc_id = c.doc_id "
				"WHERE f MATCH '" + query + "'";

			// Apply filters
			if (filters.contains("source_ids") && filters["source_ids"].is_array()) {
				std::vector<int> source_ids = get_json_int_array(filters, "source_ids");
				if (!source_ids.empty()) {
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
					std::string source_list = "";
					for (size_t i = 0; i < source_names.size(); ++i) {
						if (i > 0) source_list += ",";
						source_list += "'" + source_names[i] + "'";
					}
					sql += " AND c.source_id IN (SELECT source_id FROM rag_sources WHERE name IN (" + source_list + "))";
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
					sql += " AND c.doc_id IN (" + doc_list + ")";
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
					sql += " AND (" + post_type_conditions + ")";
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
					sql += " AND (" + tag_conditions + ")";
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
					sql += " AND (" + tag_conditions + ")";
				}
			}

			if (filters.contains("created_after") && filters["created_after"].is_string()) {
				std::string created_after = filters["created_after"].get<std::string>();
				// Filter by CreationDate in metadata_json
				sql += " AND json_extract(d.metadata_json, '$.CreationDate') >= '" + created_after + "'";
			}

			if (filters.contains("created_before") && filters["created_before"].is_string()) {
				std::string created_before = filters["created_before"].get<std::string>();
				// Filter by CreationDate in metadata_json
				sql += " AND json_extract(d.metadata_json, '$.CreationDate') <= '" + created_before + "'";
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
			std::string sql = "SELECT v.chunk_id, c.doc_id, c.source_id, "
				"(SELECT name FROM rag_sources WHERE source_id = c.source_id) as source_name, "
				"c.title, v.distance as score_vec_raw, "
				"c.metadata_json, c.body "
				"FROM rag_vec_chunks v "
				"JOIN rag_chunks c ON c.chunk_id = v.chunk_id "
				"JOIN rag_documents d ON d.doc_id = c.doc_id "
				"WHERE v.embedding MATCH '" + embedding_json + "'";

			// Apply filters
			if (filters.contains("source_ids") && filters["source_ids"].is_array()) {
				std::vector<int> source_ids = get_json_int_array(filters, "source_ids");
				if (!source_ids.empty()) {
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
					std::string source_list = "";
					for (size_t i = 0; i < source_names.size(); ++i) {
						if (i > 0) source_list += ",";
						source_list += "'" + source_names[i] + "'";
					}
					sql += " AND c.source_id IN (SELECT source_id FROM rag_sources WHERE name IN (" + source_list + "))";
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
					sql += " AND c.doc_id IN (" + doc_list + ")";
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
					sql += " AND (" + post_type_conditions + ")";
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
					sql += " AND (" + tag_conditions + ")";
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
					sql += " AND (" + tag_conditions + ")";
				}
			}

			if (filters.contains("created_after") && filters["created_after"].is_string()) {
				std::string created_after = filters["created_after"].get<std::string>();
				// Filter by CreationDate in metadata_json
				sql += " AND json_extract(d.metadata_json, '$.CreationDate') >= '" + created_after + "'";
			}

			if (filters.contains("created_before") && filters["created_before"].is_string()) {
				std::string created_before = filters["created_before"].get<std::string>();
				// Filter by CreationDate in metadata_json
				sql += " AND json_extract(d.metadata_json, '$.CreationDate') <= '" + created_before + "'";
			}

			sql += " ORDER BY v.distance "
				"LIMIT " + std::to_string(k);

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
					"c.title, bm25(f) as score_fts_raw, "
					"c.metadata_json "
					"FROM rag_fts_chunks f "
					"JOIN rag_chunks c ON c.chunk_id = f.chunk_id "
					"JOIN rag_documents d ON d.doc_id = c.doc_id "
					"WHERE f MATCH '" + query + "'";

				// Apply filters
				if (filters.contains("source_ids") && filters["source_ids"].is_array()) {
					std::vector<int> source_ids = get_json_int_array(filters, "source_ids");
					if (!source_ids.empty()) {
						std::string source_list = "";
						for (size_t i = 0; i < source_ids.size(); ++i) {
							if (i > 0) source_list += ",";
							source_list += std::to_string(source_ids[i]);
						}
						fts_sql += " AND c.source_id IN (" + source_list + ")";
					}
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

				std::string vec_sql = "SELECT v.chunk_id, c.doc_id, c.source_id, "
					"(SELECT name FROM rag_sources WHERE source_id = c.source_id) as source_name, "
					"c.title, v.distance as score_vec_raw, "
					"c.metadata_json "
					"FROM rag_vec_chunks v "
					"JOIN rag_chunks c ON c.chunk_id = v.chunk_id "
					"JOIN rag_documents d ON d.doc_id = c.doc_id "
					"WHERE v.embedding MATCH '" + embedding_json + "'";

				// Apply filters
				if (filters.contains("source_ids") && filters["source_ids"].is_array()) {
					std::vector<int> source_ids = get_json_int_array(filters, "source_ids");
					if (!source_ids.empty()) {
						std::string source_list = "";
						for (size_t i = 0; i < source_ids.size(); ++i) {
							if (i > 0) source_list += ",";
							source_list += std::to_string(source_ids[i]);
						}
						vec_sql += " AND c.source_id IN (" + source_list + ")";
					}
				}

				if (filters.contains("source_names") && filters["source_names"].is_array()) {
					std::vector<std::string> source_names = get_json_string_array(filters, "source_names");
					if (!source_names.empty()) {
						std::string source_list = "";
						for (size_t i = 0; i < source_names.size(); ++i) {
							if (i > 0) source_list += ",";
							source_list += "'" + source_names[i] + "'";
						}
						vec_sql += " AND c.source_id IN (SELECT source_id FROM rag_sources WHERE name IN (" + source_list + "))";
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
						vec_sql += " AND c.doc_id IN (" + doc_list + ")";
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
						vec_sql += " AND (" + post_type_conditions + ")";
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
						vec_sql += " AND (" + tag_conditions + ")";
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
						vec_sql += " AND (" + tag_conditions + ")";
					}
				}

				if (filters.contains("created_after") && filters["created_after"].is_string()) {
					std::string created_after = filters["created_after"].get<std::string>();
					// Filter by CreationDate in metadata_json
					vec_sql += " AND json_extract(d.metadata_json, '$.CreationDate') >= '" + created_after + "'";
				}

				if (filters.contains("created_before") && filters["created_before"].is_string()) {
					std::string created_before = filters["created_before"].get<std::string>();
					// Filter by CreationDate in metadata_json
					vec_sql += " AND json_extract(d.metadata_json, '$.CreationDate') <= '" + created_before + "'";
				}

				vec_sql += " ORDER BY v.distance "
					"LIMIT " + std::to_string(vec_k);

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
					"WHERE f MATCH '" + query + "'";

				// Apply filters
				if (filters.contains("source_ids") && filters["source_ids"].is_array()) {
					std::vector<int> source_ids = get_json_int_array(filters, "source_ids");
					if (!source_ids.empty()) {
						std::string source_list = "";
						for (size_t i = 0; i < source_ids.size(); ++i) {
							if (i > 0) source_list += ",";
							source_list += std::to_string(source_ids[i]);
						}
						fts_sql += " AND c.source_id IN (" + source_list + ")";
					}
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

				fts_sql += " ORDER BY bm25(f) "
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

					std::string vec_sql = "SELECT v.chunk_id, c.doc_id, c.source_id, "
						"(SELECT name FROM rag_sources WHERE source_id = c.source_id) as source_name, "
						"c.title, v.distance as score_vec_raw, "
						"c.metadata_json "
						"FROM rag_vec_chunks v "
						"JOIN rag_chunks c ON c.chunk_id = v.chunk_id "
						"JOIN rag_documents d ON d.doc_id = c.doc_id "
						"WHERE v.embedding MATCH '" + embedding_json + "' "
						"AND v.chunk_id IN (" + candidate_list + ")";

					// Apply filters
					if (filters.contains("source_ids") && filters["source_ids"].is_array()) {
						std::vector<int> source_ids = get_json_int_array(filters, "source_ids");
						if (!source_ids.empty()) {
							std::string source_list = "";
							for (size_t i = 0; i < source_ids.size(); ++i) {
								if (i > 0) source_list += ",";
								source_list += std::to_string(source_ids[i]);
							}
							vec_sql += " AND c.source_id IN (" + source_list + ")";
						}
					}

					if (filters.contains("source_names") && filters["source_names"].is_array()) {
						std::vector<std::string> source_names = get_json_string_array(filters, "source_names");
						if (!source_names.empty()) {
							std::string source_list = "";
							for (size_t i = 0; i < source_names.size(); ++i) {
								if (i > 0) source_list += ",";
								source_list += "'" + source_names[i] + "'";
							}
							vec_sql += " AND c.source_id IN (SELECT source_id FROM rag_sources WHERE name IN (" + source_list + "))";
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
							vec_sql += " AND c.doc_id IN (" + doc_list + ")";
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
							vec_sql += " AND (" + post_type_conditions + ")";
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
							vec_sql += " AND (" + tag_conditions + ")";
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
							vec_sql += " AND (" + tag_conditions + ")";
						}
					}

					if (filters.contains("created_after") && filters["created_after"].is_string()) {
						std::string created_after = filters["created_after"].get<std::string>();
						// Filter by CreationDate in metadata_json
						vec_sql += " AND json_extract(d.metadata_json, '$.CreationDate') >= '" + created_after + "'";
					}

					if (filters.contains("created_before") && filters["created_before"].is_string()) {
						std::string created_before = filters["created_before"].get<std::string>();
						// Filter by CreationDate in metadata_json
						vec_sql += " AND json_extract(d.metadata_json, '$.CreationDate') <= '" + created_before + "'";
					}

					vec_sql += " ORDER BY v.distance "
						"LIMIT " + std::to_string(rerank_k);

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

			// Build chunk ID list for SQL
			std::string chunk_list = "'";
			for (size_t i = 0; i < chunk_ids.size(); ++i) {
				if (i > 0) chunk_list += "','";
				chunk_list += chunk_ids[i];
			}
			chunk_list += "'";

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

			// Build doc ID list for SQL
			std::string doc_list = "'";
			for (size_t i = 0; i < doc_ids.size(); ++i) {
				if (i > 0) doc_list += "','";
				doc_list += doc_ids[i];
			}
			doc_list += "'";

			// Look up documents to get source connection info
			std::string doc_sql = "SELECT d.doc_id, d.source_id, d.pk_json, d.source_name, "
				"s.backend_type, s.backend_host, s.backend_port, s.backend_user, s.backend_pass, s.backend_db, "
				"s.table_name, s.pk_column "
				"FROM rag_documents d "
				"JOIN rag_sources s ON s.source_id = d.source_id "
				"WHERE d.doc_id IN (" + doc_list + ")";

			SQLite3_result* doc_result = execute_query(doc_sql.c_str());
			if (!doc_result) {
				return create_error_response("Database query failed");
			}

			// Build rows array
			json rows = json::array();
			int total_bytes = 0;
			bool truncated = false;

			// Process each document
			for (const auto& row : doc_result->rows) {
				if (row->fields && rows.size() < static_cast<size_t>(max_rows) && total_bytes < max_bytes) {
					std::string doc_id = row->fields[0] ? row->fields[0] : "";
					// int source_id = row->fields[1] ? std::stoi(row->fields[1]) : 0;
					std::string pk_json = row->fields[2] ? row->fields[2] : "{}";
					std::string source_name = row->fields[3] ? row->fields[3] : "";
					// std::string backend_type = row->fields[4] ? row->fields[4] : "";
					// std::string backend_host = row->fields[5] ? row->fields[5] : "";
					// int backend_port = row->fields[6] ? std::stoi(row->fields[6]) : 0;
					// std::string backend_user = row->fields[7] ? row->fields[7] : "";
					// std::string backend_pass = row->fields[8] ? row->fields[8] : "";
					// std::string backend_db = row->fields[9] ? row->fields[9] : "";
					// std::string table_name = row->fields[10] ? row->fields[10] : "";
					std::string pk_column = row->fields[11] ? row->fields[11] : "";

					// For now, we'll return a simplified response since we can't actually connect to external databases
					// In a full implementation, this would connect to the source database and fetch the data
					json result_row;
					result_row["doc_id"] = doc_id;
					result_row["source_name"] = source_name;

					// Parse pk_json to get the primary key value
					try {
						json pk_data = json::parse(pk_json);
						json row_data = json::object();

						// If specific columns are requested, only include those
						if (!columns.empty()) {
							for (const std::string& col : columns) {
								// For demo purposes, we'll just echo back some mock data
								if (col == "Id" && pk_data.contains("Id")) {
									row_data["Id"] = pk_data["Id"];
								} else if (col == pk_column) {
									// This would be the actual primary key value
									row_data[col] = "mock_value";
								} else {
									// For other columns, provide mock data
									row_data[col] = "mock_" + col + "_value";
								}
							}
						} else {
							// If no columns specified, include basic info
							row_data["Id"] = pk_data.contains("Id") ? pk_data["Id"] : json(0);
							row_data[pk_column] = "mock_pk_value";
						}

						result_row["row"] = row_data;

						// Check size limits
						std::string row_str = result_row.dump();
						if (total_bytes + static_cast<int>(row_str.length()) > max_bytes) {
							truncated = true;
							break;
						}

						total_bytes += static_cast<int>(row_str.length());
						rows.push_back(result_row);
					} catch (...) {
						// Skip malformed pk_json
						continue;
					}
				} else if (rows.size() >= static_cast<size_t>(max_rows) || total_bytes >= max_bytes) {
					truncated = true;
					break;
				}
			}

			delete doc_result;

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
			return create_error_response("Unknown tool: " + tool_name);
		}

		return create_success_response(result);

	} catch (const std::exception& e) {
		proxy_error("RAG_Tool_Handler: Exception in execute_tool: %s\n", e.what());
		return create_error_response(std::string("Exception: ") + e.what());
	} catch (...) {
		proxy_error("RAG_Tool_Handler: Unknown exception in execute_tool\n");
		return create_error_response("Unknown exception");
	}
}