#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "Config_Tool_Handler.h"
#include "MCP_Thread.h"
#include "proxysql_debug.h"
#include "proxysql_utils.h"

#include <cstring>

Config_Tool_Handler::Config_Tool_Handler(MCP_Threads_Handler* handler)
	: mcp_handler(handler)
{
	pthread_mutex_init(&handler_lock, NULL);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Config_Tool_Handler created\n");
}

Config_Tool_Handler::~Config_Tool_Handler() {
	close();
	pthread_mutex_destroy(&handler_lock);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Config_Tool_Handler destroyed\n");
}

int Config_Tool_Handler::init() {
	proxy_info("Config_Tool_Handler initialized\n");
	return 0;
}

void Config_Tool_Handler::close() {
	proxy_debug(PROXY_DEBUG_GENERIC, 2, "Config_Tool_Handler closed\n");
}

json Config_Tool_Handler::get_tool_list() {
	json tools = json::array();

	// get_config
	tools.push_back(create_tool_description(
		"get_config",
		"Get the current value of a ProxySQL MCP configuration variable",
		{
			{"type", "object"},
			{"properties", {
				{"variable_name", {
					{"type", "string"},
					{"description", "Variable name (without 'mcp-' prefix)"}
				}}
			}},
			{"required", {"variable_name"}}
		}
	));

	// set_config
	tools.push_back(create_tool_description(
		"set_config",
		"Set the value of a ProxySQL MCP configuration variable",
		{
			{"type", "object"},
			{"properties", {
				{"variable_name", {
					{"type", "string"},
					{"description", "Variable name (without 'mcp-' prefix)"}
				}},
				{"value", {
					{"type", "string"},
					{"description", "New value for the variable"}
				}}
			}},
			{"required", {"variable_name", "value"}}
		}
	));

	// reload_config
	tools.push_back(create_tool_description(
		"reload_config",
		"Reload ProxySQL MCP configuration from disk/memory to runtime",
		{
			{"type", "object"},
			{"properties", {
				{"scope", {
					{"type", "string"},
					{"enum", {"disk", "memory", "runtime"}},
					{"description", "Reload scope: 'disk' (from disk to memory), 'memory' (not applicable), 'runtime' (from memory to runtime)"}
				}}
			}},
			{"required", {"scope"}}
		}
	));

	// list_variables
	tools.push_back(create_tool_description(
		"list_variables",
		"List all ProxySQL MCP configuration variables",
		{
			{"type", "object"},
			{"properties", {
				{"filter", {
					{"type", "string"},
					{"description", "Optional filter pattern (e.g., 'mysql_%' for MySQL-related variables)"}
				}}
			}}
		}
	));

	// get_status
	tools.push_back(create_tool_description(
		"get_status",
		"Get ProxySQL MCP server status information",
		{
			{"type", "object"},
			{"properties", {}}
		}
	));

	json result;
	result["tools"] = tools;
	return result;
}

json Config_Tool_Handler::get_tool_description(const std::string& tool_name) {
	// For now, just return the basic description from the list
	// In a full implementation, this would provide more detailed schema info
	json tools_list = get_tool_list();
	for (const auto& tool : tools_list["tools"]) {
		if (tool["name"] == tool_name) {
			return tool;
		}
	}
	return create_error_response("Tool not found: " + tool_name);
}

json Config_Tool_Handler::execute_tool(const std::string& tool_name, const json& arguments) {
	pthread_mutex_lock(&handler_lock);

	json result;

	try {
		if (tool_name == "get_config") {
			std::string var_name = arguments.value("variable_name", "");
			result = handle_get_config(var_name);
		} else if (tool_name == "set_config") {
			std::string var_name = arguments.value("variable_name", "");
			std::string var_value = arguments.value("value", "");
			result = handle_set_config(var_name, var_value);
		} else if (tool_name == "reload_config") {
			std::string scope = arguments.value("scope", "runtime");
			result = handle_reload_config(scope);
		} else if (tool_name == "list_variables") {
			std::string filter = arguments.value("filter", "");
			result = handle_list_variables(filter);
		} else if (tool_name == "get_status") {
			result = handle_get_status();
		} else {
			result = create_error_response("Unknown tool: " + tool_name);
		}
	} catch (const std::exception& e) {
		result = create_error_response(std::string("Exception: ") + e.what());
	}

	pthread_mutex_unlock(&handler_lock);
	return result;
}

json Config_Tool_Handler::handle_get_config(const std::string& var_name) {
	if (!mcp_handler) {
		return create_error_response("MCP handler not initialized");
	}

	char val[1024];
	if (mcp_handler->get_variable(var_name.c_str(), val) == 0) {
		json result;
		result["variable_name"] = var_name;
		result["value"] = val;
		return create_success_response(result);
	} else {
		return create_error_response("Variable not found: " + var_name);
	}
}

json Config_Tool_Handler::handle_set_config(const std::string& var_name, const std::string& var_value) {
	if (!mcp_handler) {
		return create_error_response("MCP handler not initialized");
	}

	if (mcp_handler->set_variable(var_name.c_str(), var_value.c_str()) == 0) {
		json result;
		result["variable_name"] = var_name;
		result["value"] = var_value;
		result["message"] = "Variable set successfully. Use 'reload_config' to load to runtime.";
		return create_success_response(result);
	} else {
		return create_error_response("Failed to set variable: " + var_name);
	}
}

json Config_Tool_Handler::handle_reload_config(const std::string& scope) {
	if (!mcp_handler) {
		return create_error_response("MCP handler not initialized");
	}

	// This is a stub - actual implementation would call Admin_FlushVariables
	// For now, return success with a message
	json result;
	result["scope"] = scope;
	result["message"] = "Configuration reload functionality to be implemented";
	return create_success_response(result);
}

json Config_Tool_Handler::handle_list_variables(const std::string& filter) {
	if (!mcp_handler) {
		return create_error_response("MCP handler not initialized");
	}

	char** vars = mcp_handler->get_variables_list();
	if (!vars) {
		return create_error_response("Failed to get variables list");
	}

	json variables = json::array();

	// Filter and list variables
	for (int i = 0; vars[i] != NULL; i++) {
		std::string var_name = vars[i];

		// Apply filter if provided
		if (!filter.empty()) {
			// Simple pattern matching (expand to full SQL LIKE pattern later)
			if (var_name.find(filter) == std::string::npos) {
				continue;
			}
		}

		char val[1024];
		if (mcp_handler->get_variable(var_name.c_str(), val) == 0) {
			json var;
			var["name"] = var_name;
			var["value"] = val;
			variables.push_back(var);
		}

		free(vars[i]);
	}
	free(vars);

	json result;
	result["variables"] = variables;
	result["count"] = variables.size();
	return create_success_response(result);
}

json Config_Tool_Handler::handle_get_status() {
	if (!mcp_handler) {
		return create_error_response("MCP handler not initialized");
	}

	json status;
	status["enabled"] = mcp_handler->variables.mcp_enabled;
	status["port"] = mcp_handler->variables.mcp_port;
	status["total_requests"] = mcp_handler->status_variables.total_requests;
	status["failed_requests"] = mcp_handler->status_variables.failed_requests;
	status["active_connections"] = mcp_handler->status_variables.active_connections;

	return create_success_response(status);
}
