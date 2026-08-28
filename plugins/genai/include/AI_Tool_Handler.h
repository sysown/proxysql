/**
 * @file ai_tool_handler.h
 * @brief AI Tool Handler for MCP protocol
 *
 * Provides AI-related tools via MCP protocol including:
 * - NL2SQL (Natural Language to SQL) conversion
 * - Anomaly detection queries
 * - Vector storage operations
 *
 * @date 2025-01-16
 */

#ifndef CLASS_AI_TOOL_HANDLER_H
#define CLASS_AI_TOOL_HANDLER_H

#ifdef PROXYSQL40

#include "MCP_Tool_Handler.h"
#include <string>
#include <vector>
#include <map>

// Forward declarations
class LLM_Bridge;

/**
 * @brief AI Tool Handler for MCP
 *
 * Provides AI-powered tools through the MCP protocol:
 * - ai_nl2sql_convert: Convert natural language to SQL
 * - Future: vector operations
 *
 * @note Pre-Step 3 of the GenAI plugin carve-out, this class also held
 *       a borrowed Anomaly_Detector pointer that was never read.  The
 *       field and its constructor parameter were removed when
 *       Anomaly_Detector moved into plugins/genai/.
 */
class AI_Tool_Handler : public MCP_Tool_Handler {
private:
	LLM_Bridge* llm_bridge;
	bool owns_components;

	/**
	 * @brief Helper to extract string parameter from JSON
	 */
	static std::string get_json_string(const json& j, const std::string& key,
	                                    const std::string& default_val = "");

	/**
	 * @brief Helper to extract int parameter from JSON
	 */
	static int get_json_int(const json& j, const std::string& key, int default_val = 0);

public:
	/**
	 * @brief Constructor — wraps an existing LLM_Bridge.
	 */
	AI_Tool_Handler(LLM_Bridge* llm);

	/**
	 * @brief Default constructor — pulls the LLM_Bridge from the
	 *        global AI_Features_Manager.
	 */
	AI_Tool_Handler();

	/**
	 * @brief Destructor
	 */
	~AI_Tool_Handler();

	/**
	 * @brief Initialize the tool handler
	 */
	int init() override;

	/** Rebind the borrowed bridge after a GenAI runtime reload. */
	void set_llm_bridge(LLM_Bridge* llm) { llm_bridge = llm; }

	/**
	 * @brief Close and cleanup
	 */
	void close() override;

	/**
	 * @brief Get handler name
	 */
	std::string get_handler_name() const override { return "ai"; }

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
};

#endif /* PROXYSQL40 */
#endif /* CLASS_AI_TOOL_HANDLER_H */
