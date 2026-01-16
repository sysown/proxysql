/**
 * @file AI_Tool_Handler.cpp
 * @brief Implementation of AI Tool Handler for MCP protocol
 *
 * Implements AI-powered tools through MCP protocol, primarily
 * the ai_nl2sql_convert tool for natural language to SQL conversion.
 *
 * @see AI_Tool_Handler.h
 */

#include "AI_Tool_Handler.h"
#include "NL2SQL_Converter.h"
#include "Anomaly_Detector.h"
#include "AI_Features_Manager.h"
#include "proxysql_debug.h"
#include "cpp.h"
#include <sstream>
#include <algorithm>

// JSON library
#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

// ============================================================================
// Constructor/Destructor
// ============================================================================

/**
 * @brief Constructor using existing AI components
 */
AI_Tool_Handler::AI_Tool_Handler(NL2SQL_Converter* nl2sql, Anomaly_Detector* anomaly)
	: nl2sql_converter(nl2sql),
	  anomaly_detector(anomaly),
	  owns_components(false)
{
	proxy_debug(PROXY_DEBUG_GENAI, 3, "AI_Tool_Handler created (wrapping existing components)\n");
}

/**
 * @brief Constructor - creates own components
 * Note: This implementation uses global instances
 */
AI_Tool_Handler::AI_Tool_Handler()
	: nl2sql_converter(NULL),
	  anomaly_detector(NULL),
	  owns_components(false)
{
	// Use global instances from AI_Features_Manager
	if (GloAI) {
		nl2sql_converter = GloAI->get_nl2sql();
		anomaly_detector = GloAI->get_anomaly_detector();
	}
	proxy_debug(PROXY_DEBUG_GENAI, 3, "AI_Tool_Handler created (using global instances)\n");
}

/**
 * @brief Destructor
 */
AI_Tool_Handler::~AI_Tool_Handler() {
	close();
	proxy_debug(PROXY_DEBUG_GENAI, 3, "AI_Tool_Handler destroyed\n");
}

// ============================================================================
// Lifecycle
// ============================================================================

/**
 * @brief Initialize the tool handler
 */
int AI_Tool_Handler::init() {
	if (!nl2sql_converter) {
		proxy_error("AI_Tool_Handler: NL2SQL converter not available\n");
		return -1;
	}
	proxy_info("AI_Tool_Handler initialized\n");
	return 0;
}

/**
 * @brief Close and cleanup
 */
void AI_Tool_Handler::close() {
	if (owns_components) {
		// Components would be cleaned up here
		// For now, we use global instances managed by AI_Features_Manager
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Extract string parameter from JSON
 */
std::string AI_Tool_Handler::get_json_string(const json& j, const std::string& key,
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
int AI_Tool_Handler::get_json_int(const json& j, const std::string& key, int default_val) {
	if (j.contains(key) && !j[key].is_null()) {
		if (j[key].is_number()) {
			return j[key].get<int>();
		} else if (j[key].is_string()) {
			return std::stoi(j[key].get<std::string>());
		}
	}
	return default_val;
}

// ============================================================================
// Tool List
// ============================================================================

/**
 * @brief Get list of available AI tools
 */
json AI_Tool_Handler::get_tool_list() {
	json tools = json::array();

	// NL2SQL tool
	json nl2sql_params = json::object();
	nl2sql_params["type"] = "object";
	nl2sql_params["properties"] = json::object();
	nl2sql_params["properties"]["natural_language"] = {
		{"type", "string"},
		{"description", "Natural language query to convert to SQL"}
	};
	nl2sql_params["properties"]["schema"] = {
		{"type", "string"},
		{"description", "Database/schema name for context"}
	};
	nl2sql_params["properties"]["context_tables"] = {
		{"type", "string"},
		{"description", "Comma-separated list of relevant tables (optional)"}
	};
	nl2sql_params["properties"]["max_latency_ms"] = {
		{"type", "integer"},
		{"description", "Maximum acceptable latency in milliseconds (optional)"}
	};
	nl2sql_params["properties"]["allow_cache"] = {
		{"type", "boolean"},
		{"description", "Whether to check semantic cache (default: true)"}
	};
	nl2sql_params["required"] = json::array({"natural_language"});

	tools.push_back({
		{"name", "ai_nl2sql_convert"},
		{"description", "Convert natural language query to SQL using LLM"},
		{"inputSchema", nl2sql_params}
	});

	json result;
	result["tools"] = tools;
	return result;
}

/**
 * @brief Get description of a specific tool
 */
json AI_Tool_Handler::get_tool_description(const std::string& tool_name) {
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
 * @brief Execute an AI tool
 */
json AI_Tool_Handler::execute_tool(const std::string& tool_name, const json& arguments) {
	proxy_debug(PROXY_DEBUG_GENAI, 3, "AI_Tool_Handler: execute_tool(%s)\n", tool_name.c_str());

	try {
		// NL2SQL conversion tool
		if (tool_name == "ai_nl2sql_convert") {
			if (!nl2sql_converter) {
				return create_error_response("NL2SQL converter not available");
			}

			// Extract parameters
			std::string natural_language = get_json_string(arguments, "natural_language");
			if (natural_language.empty()) {
				return create_error_response("Missing required parameter: natural_language");
			}

			std::string schema = get_json_string(arguments, "schema");
			int max_latency_ms = get_json_int(arguments, "max_latency_ms", 0);
			bool allow_cache = true;
			if (arguments.contains("allow_cache") && !arguments["allow_cache"].is_null()) {
				if (arguments["allow_cache"].is_boolean()) {
					allow_cache = arguments["allow_cache"].get<bool>();
				} else if (arguments["allow_cache"].is_string()) {
					std::string val = arguments["allow_cache"].get<std::string>();
					allow_cache = (val == "true" || val == "1");
				}
			}

			// Parse context_tables
			std::vector<std::string> context_tables;
			std::string tables_str = get_json_string(arguments, "context_tables");
			if (!tables_str.empty()) {
				std::istringstream ts(tables_str);
				std::string table;
				while (std::getline(ts, table, ',')) {
					table.erase(0, table.find_first_not_of(" \t"));
					table.erase(table.find_last_not_of(" \t") + 1);
					if (!table.empty()) {
						context_tables.push_back(table);
					}
				}
			}

			// Create NL2SQL request
			NL2SQLRequest req;
			req.natural_language = natural_language;
			req.schema_name = schema;
			req.max_latency_ms = max_latency_ms;
			req.allow_cache = allow_cache;
			req.context_tables = context_tables;

			// Call NL2SQL converter
			NL2SQLResult result = nl2sql_converter->convert(req);

			// Build response
			json response_data;
			response_data["sql_query"] = result.sql_query;
			response_data["confidence"] = result.confidence;
			response_data["explanation"] = result.explanation;
			response_data["cached"] = result.cached;
			response_data["cache_id"] = result.cache_id;

			// Add tables used if available
			if (!result.tables_used.empty()) {
				response_data["tables_used"] = result.tables_used;
			}

			proxy_info("AI_Tool_Handler: NL2SQL conversion complete. SQL: %s, Confidence: %.2f\n",
			         result.sql_query.c_str(), result.confidence);

			return create_success_response(response_data);
		}

		// Unknown tool
		return create_error_response("Unknown tool: " + tool_name);

	} catch (const std::exception& e) {
		proxy_error("AI_Tool_Handler: Exception in execute_tool: %s\n", e.what());
		return create_error_response(std::string("Exception: ") + e.what());
	} catch (...) {
		proxy_error("AI_Tool_Handler: Unknown exception in execute_tool\n");
		return create_error_response("Unknown exception");
	}
}
