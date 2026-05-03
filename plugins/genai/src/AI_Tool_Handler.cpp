#ifdef PROXYSQL40


#include "proxysql.h"
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
#include "LLM_Bridge.h"
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
 * @brief Constructor using an existing LLM_Bridge.
 *
 * @note Pre-Step 3 this constructor also accepted an Anomaly_Detector*
 *       which was stored but never read; the field was removed when
 *       Anomaly_Detector moved into the genai plugin.
 */
AI_Tool_Handler::AI_Tool_Handler(LLM_Bridge* llm)
	: llm_bridge(llm),
	  owns_components(false)
{
	proxy_debug(PROXY_DEBUG_GENAI, 3, "AI_Tool_Handler created (wrapping existing LLM_Bridge)\n");
}

/**
 * @brief Default constructor — pulls the LLM_Bridge from the global
 *        AI_Features_Manager.
 */
AI_Tool_Handler::AI_Tool_Handler()
	: llm_bridge(NULL),
	  owns_components(false)
{
	if (GloAI) {
		llm_bridge = GloAI->get_llm_bridge();
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
	if (!llm_bridge) {
		proxy_error("AI_Tool_Handler: LLM bridge not available\n");
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
			try {
				return std::stoi(j[key].get<std::string>());
			} catch (const std::exception& e) {
				proxy_error("AI_Tool_Handler: Failed to convert string to int for key '%s': %s\n",
				           key.c_str(), e.what());
				return default_val;
			}
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
		// LLM processing tool (generic, replaces NL2SQL)
		if (tool_name == "ai_nl2sql_convert") {
			// NOTE: The ai_nl2sql_convert tool is deprecated.
			// NL2SQL functionality has been replaced with a generic LLM bridge.
			// Future NL2SQL will be implemented as a Web UI using external agents (Claude Code + MCP server).
			return create_error_response("The ai_nl2sql_convert tool is deprecated. "
			                             "Use the generic LLM: queries via MySQL protocol instead.");
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

#endif /* PROXYSQL40 */
