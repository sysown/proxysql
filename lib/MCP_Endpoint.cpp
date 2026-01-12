#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "MCP_Endpoint.h"
#include "MCP_Thread.h"
#include "MySQL_Tool_Handler.h"
#include "MCP_Tool_Handler.h"
#include "proxysql_debug.h"
#include "cpp.h"

using namespace httpserver;

MCP_JSONRPC_Resource::MCP_JSONRPC_Resource(MCP_Threads_Handler* h, MCP_Tool_Handler* th, const std::string& name)
	: handler(h), tool_handler(th), endpoint_name(name)
{
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Created MCP JSON-RPC resource for endpoint '%s'\n", name.c_str());
}

MCP_JSONRPC_Resource::~MCP_JSONRPC_Resource() {
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Destroyed MCP JSON-RPC resource for endpoint '%s'\n", endpoint_name.c_str());
}

bool MCP_JSONRPC_Resource::authenticate_request(const httpserver::http_request& req) {
	if (!handler) {
		proxy_error("MCP authentication on %s: handler is NULL\n", endpoint_name.c_str());
		return false;
	}

	// Get the expected auth token for this endpoint
	char* expected_token = nullptr;

	if (endpoint_name == "config") {
		expected_token = handler->variables.mcp_config_endpoint_auth;
	} else if (endpoint_name == "observe") {
		expected_token = handler->variables.mcp_observe_endpoint_auth;
	} else if (endpoint_name == "query") {
		expected_token = handler->variables.mcp_query_endpoint_auth;
	} else if (endpoint_name == "admin") {
		expected_token = handler->variables.mcp_admin_endpoint_auth;
	} else if (endpoint_name == "cache") {
		expected_token = handler->variables.mcp_cache_endpoint_auth;
	} else {
		proxy_error("MCP authentication on %s: unknown endpoint\n", endpoint_name.c_str());
		return false;
	}

	// If no auth token is configured, allow the request (no authentication required)
	if (!expected_token || strlen(expected_token) == 0) {
		proxy_debug(PROXY_DEBUG_GENERIC, 4, "MCP authentication on %s: no auth configured, allowing request\n", endpoint_name.c_str());
		return true;
	}

	// Try to get Bearer token from Authorization header
	std::string auth_header = req.get_header("Authorization");

	if (auth_header.empty()) {
		// Try getting from query parameter as fallback
		const std::map<std::string, std::string, http::arg_comparator>& args = req.get_args();
		auto it = args.find("token");
		if (it != args.end()) {
			auth_header = "Bearer " + it->second;
		}
	}

	if (auth_header.empty()) {
		proxy_debug(PROXY_DEBUG_GENERIC, 4, "MCP authentication on %s: no Authorization header or token param\n", endpoint_name.c_str());
		return false;
	}

	// Check if it's a Bearer token
	const std::string bearer_prefix = "Bearer ";
	if (auth_header.length() <= bearer_prefix.length() ||
	    auth_header.compare(0, bearer_prefix.length(), bearer_prefix) != 0) {
		proxy_debug(PROXY_DEBUG_GENERIC, 4, "MCP authentication on %s: invalid Authorization header format\n", endpoint_name.c_str());
		return false;
	}

	// Extract the token
	std::string provided_token = auth_header.substr(bearer_prefix.length());

	// Trim whitespace
	size_t start = provided_token.find_first_not_of(" \t\n\r");
	size_t end = provided_token.find_last_not_of(" \t\n\r");
	if (start != std::string::npos && end != std::string::npos) {
		provided_token = provided_token.substr(start, end - start + 1);
	}

	// Compare tokens
	bool authenticated = (provided_token == expected_token);

	if (authenticated) {
		proxy_debug(PROXY_DEBUG_GENERIC, 4, "MCP authentication on %s: success\n", endpoint_name.c_str());
	} else {
		proxy_debug(PROXY_DEBUG_GENERIC, 4, "MCP authentication on %s: failed (token mismatch)\n", endpoint_name.c_str());
	}

	return authenticated;
}

std::string MCP_JSONRPC_Resource::create_jsonrpc_response(
	const std::string& result,
	const std::string& id
) {
	json j;
	j["jsonrpc"] = "2.0";
	j["result"] = json::parse(result);
	j["id"] = id;
	return j.dump();
}

std::string MCP_JSONRPC_Resource::create_jsonrpc_error(
	int code,
	const std::string& message,
	const std::string& id
) {
	json j;
	j["jsonrpc"] = "2.0";
	json error;
	error["code"] = code;
	error["message"] = message;
	j["error"] = error;
	j["id"] = id;
	return j.dump();
}

std::shared_ptr<http_response> MCP_JSONRPC_Resource::handle_jsonrpc_request(
	const httpserver::http_request& req
) {
	// Update statistics
	if (handler) {
		handler->status_variables.total_requests++;
	}

	// Get request body
	std::string req_body = req.get_content();
	std::string req_path = req.get_path();

	proxy_debug(PROXY_DEBUG_GENERIC, 2, "MCP request on %s: %s\n", req_path.c_str(), req_body.c_str());

	// Validate JSON
	json req_json;
	try {
		req_json = json::parse(req_body);
	} catch (json::parse_error& e) {
		proxy_error("MCP request on %s: Invalid JSON - %s\n", req_path.c_str(), e.what());
		if (handler) {
			handler->status_variables.failed_requests++;
		}
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32700, "Parse error", ""),
			http::http_utils::http_bad_request
		));
		response->with_header("Content-Type", "application/json");
		return response;
	}

	// Validate JSON-RPC 2.0 basic structure
	if (!req_json.contains("jsonrpc") || req_json["jsonrpc"] != "2.0") {
		proxy_error("MCP request on %s: Missing or invalid jsonrpc version\n", req_path.c_str());
		if (handler) {
			handler->status_variables.failed_requests++;
		}
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32600, "Invalid Request", ""),
			http::http_utils::http_bad_request
		));
		response->with_header("Content-Type", "application/json");
		return response;
	}

	if (!req_json.contains("method")) {
		proxy_error("MCP request on %s: Missing method field\n", req_path.c_str());
		if (handler) {
			handler->status_variables.failed_requests++;
		}
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32600, "Invalid Request", ""),
			http::http_utils::http_bad_request
		));
		response->with_header("Content-Type", "application/json");
		return response;
	}

	// Get request ID (optional but recommended)
	std::string req_id = "";
	if (req_json.contains("id")) {
		if (req_json["id"].is_string()) {
			req_id = req_json["id"].get<std::string>();
		} else if (req_json["id"].is_number()) {
			req_id = std::to_string(req_json["id"].get<int>());
		}
	}

	// Get method name
	std::string method = req_json["method"].get<std::string>();
	proxy_debug(PROXY_DEBUG_GENERIC, 2, "MCP method '%s' requested on endpoint '%s'\n", method.c_str(), endpoint_name.c_str());

	// Handle different methods
	json result;

	if (method == "tools/call" || method == "tools/list" || method == "tools/describe") {
		// Route tool-related methods to the endpoint's tool handler
		if (!tool_handler) {
			proxy_error("MCP request on %s: Tool Handler not initialized\n", req_path.c_str());
			if (handler) {
				handler->status_variables.failed_requests++;
			}
			auto response = std::shared_ptr<http_response>(new string_response(
				create_jsonrpc_error(-32000, "Tool Handler not initialized for endpoint: " + endpoint_name, req_id),
				http::http_utils::http_internal_server_error
			));
			response->with_header("Content-Type", "application/json");
			return response;
		}

		// Route to appropriate tool handler method
		if (method == "tools/list") {
			result = handle_tools_list();
		} else if (method == "tools/describe") {
			result = handle_tools_describe(req_json);
		} else if (method == "tools/call") {
			result = handle_tools_call(req_json);
		}
	} else if (method == "initialize" || method == "ping") {
		// Handle MCP protocol methods
		if (method == "initialize") {
			result["protocolVersion"] = "2024-11-05";
			result["capabilities"] = json::object();
			result["serverInfo"] = {
				{"name", "proxysql-mcp-mysql-tools"},
				{"version", MCP_THREAD_VERSION}
			};
		} else if (method == "ping") {
			result["status"] = "ok";
		}
	} else {
		// Unknown method
		proxy_info("MCP: Unknown method '%s' on endpoint '%s'\n", method.c_str(), endpoint_name.c_str());
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32601, "Method not found", req_id),
			http::http_utils::http_not_found
		));
		response->with_header("Content-Type", "application/json");
		return response;
	}

	auto response = std::shared_ptr<http_response>(new string_response(
		create_jsonrpc_response(result.dump(), req_id),
		http::http_utils::http_ok
	));
	response->with_header("Content-Type", "application/json");
	return response;
}

const std::shared_ptr<http_response> MCP_JSONRPC_Resource::render_POST(
	const httpserver::http_request& req
) {
	std::string req_path = req.get_path();
	proxy_debug(PROXY_DEBUG_GENERIC, 2, "Received MCP POST request on %s\n", req_path.c_str());

	// Check Content-Type header
	std::string content_type = req.get_header(http::http_utils::http_header_content_type);
	if (content_type.empty() ||
		(content_type.find("application/json") == std::string::npos &&
		 content_type.find("text/json") == std::string::npos)) {
		proxy_error("MCP request on %s: Invalid Content-Type '%s'\n", req_path.c_str(), content_type.c_str());
		if (handler) {
			handler->status_variables.failed_requests++;
		}
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32600, "Invalid Request: Content-Type must be application/json", ""),
			http::http_utils::http_unsupported_media_type
		));
		response->with_header("Content-Type", "application/json");
		return response;
	}

	// Authenticate request
	if (!authenticate_request(req)) {
		proxy_error("MCP request on %s: Authentication failed\n", req_path.c_str());
		if (handler) {
			handler->status_variables.failed_requests++;
		}
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32001, "Unauthorized", ""),
			http::http_utils::http_unauthorized
		));
		response->with_header("Content-Type", "application/json");
		return response;
	}

	// Handle the JSON-RPC request
	return handle_jsonrpc_request(req);
}

// Helper method to handle tools/list
json MCP_JSONRPC_Resource::handle_tools_list() {
	if (!tool_handler) {
		json result;
		result["error"] = "Tool handler not initialized";
		return result;
	}
	return tool_handler->get_tool_list();
}

// Helper method to handle tools/describe
json MCP_JSONRPC_Resource::handle_tools_describe(const json& req_json) {
	if (!tool_handler) {
		json result;
		result["error"] = "Tool handler not initialized";
		return result;
	}

	if (!req_json.contains("params") || !req_json["params"].contains("name")) {
		json result;
		result["error"] = "Missing tool name";
		return result;
	}

	std::string tool_name = req_json["params"]["name"].get<std::string>();
	return tool_handler->get_tool_description(tool_name);
}

// Helper method to handle tools/call
json MCP_JSONRPC_Resource::handle_tools_call(const json& req_json) {
	if (!tool_handler) {
		json result;
		result["error"] = "Tool handler not initialized";
		return result;
	}

	if (!req_json.contains("params") || !req_json["params"].contains("name")) {
		json result;
		result["error"] = "Missing tool name";
		return result;
	}

	std::string tool_name = req_json["params"]["name"].get<std::string>();
	json arguments = req_json["params"].contains("arguments") ? req_json["params"]["arguments"] : json::object();

	proxy_debug(PROXY_DEBUG_GENERIC, 2, "MCP tool call: %s with args: %s\n", tool_name.c_str(), arguments.dump().c_str());

	return tool_handler->execute_tool(tool_name, arguments);
}
