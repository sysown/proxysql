#ifdef PROXYSQL40


#include "proxysql.h"
#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "MCP_Endpoint.h"
#include "genai_plugin.h"
#include "MCP_Thread.h"
#include "MySQL_Tool_Handler.h"
#include "MCP_Tool_Handler.h"
#include "proxysql_debug.h"
#include "cpp.h"

using namespace httpserver;

MCP_JSONRPC_Resource::MCP_JSONRPC_Resource(
	MCP_Threads_Handler* h,
	MCP_Tool_Handler* th,
	const std::string& name,
	GenAIRWLock* dependencies_mutex
)
	: handler(h),
	  tool_handler(th),
	  endpoint_name(name),
	  runtime_dependencies_mutex(dependencies_mutex)
{
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Created MCP JSON-RPC resource for endpoint '%s'\n", name.c_str());
}

MCP_JSONRPC_Resource::~MCP_JSONRPC_Resource() {
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Destroyed MCP JSON-RPC resource for endpoint '%s'\n", endpoint_name.c_str());
}

bool MCP_JSONRPC_Resource::validate_bearer_token(const std::string& auth_header, const std::string& expected_token) {
	// Empty auth header means no token provided
	if (auth_header.empty()) {
		return false;
	}

	// Check if it's a Bearer token (RFC 7235: auth-scheme is case-insensitive)
	const std::string bearer_prefix = "Bearer ";
	if (auth_header.length() <= bearer_prefix.length() ||
	    strncasecmp(auth_header.c_str(), bearer_prefix.c_str(), bearer_prefix.length()) != 0) {
		return false;
	}

	// Extract the token
	std::string provided_token = auth_header.substr(bearer_prefix.length());

	// Trim whitespace
	size_t start = provided_token.find_first_not_of(" \t\n\r");
	size_t end = provided_token.find_last_not_of(" \t\n\r");
	if (start != std::string::npos && end != std::string::npos) {
		provided_token = provided_token.substr(start, end - start + 1);
	} else {
		// Token is all whitespace
		return false;
	}

	// Compare tokens
	return (provided_token == expected_token);
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
	} else if (endpoint_name == "stats") {
		expected_token = handler->variables.mcp_stats_endpoint_auth;
	} else if (endpoint_name == "query") {
		expected_token = handler->variables.mcp_query_endpoint_auth;
	} else if (endpoint_name == "admin") {
		expected_token = handler->variables.mcp_admin_endpoint_auth;
	} else if (endpoint_name == "cache") {
		expected_token = handler->variables.mcp_cache_endpoint_auth;
	} else if (endpoint_name == "ai") {
		expected_token = handler->variables.mcp_ai_endpoint_auth;
	} else if (endpoint_name == "rag") {
		expected_token = handler->variables.mcp_rag_endpoint_auth;
	} else {
		proxy_error("MCP authentication on %s: unknown endpoint\n", endpoint_name.c_str());
		return false;
	}

	// GHSA-7wh6-2vcc-gcm4: every MCP endpoint can read or mutate
	// non-trivial proxy state.  /mcp/query executes SQL on configured
	// target backends; /mcp/admin exposes kill_query, flush_cache,
	// reload; /mcp/cache, /mcp/config, /mcp/stats expose internal
	// runtime state and (for config) credentials; /mcp/ai and /mcp/rag
	// can dispatch backend SQL via LLM-driven tool calls.  Allowing any
	// of these unauthenticated when reachable on the network is unsafe.
	//
	// Require an explicit non-empty bearer token on every endpoint.
	// Operators must set the corresponding `mcp-<endpoint>_endpoint_auth`
	// variable to a non-empty value before that endpoint will accept
	// requests.  The pre-fix permissive "empty token = allow anyone"
	// behaviour is removed.
	if (!expected_token || strlen(expected_token) == 0) {
		proxy_error("MCP authentication on %s: mcp-%s_endpoint_auth is empty; refusing request. Set mcp-%s_endpoint_auth to a non-empty bearer token to enable the /mcp/%s endpoint.\n",
			endpoint_name.c_str(), endpoint_name.c_str(),
			endpoint_name.c_str(), endpoint_name.c_str());
		return false;
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

	bool authenticated = validate_bearer_token(auth_header, std::string(expected_token));

	if (authenticated) {
		proxy_debug(PROXY_DEBUG_GENERIC, 4, "MCP authentication on %s: success\n", endpoint_name.c_str());
	} else {
		proxy_debug(PROXY_DEBUG_GENERIC, 4, "MCP authentication on %s: failed (token mismatch)\n", endpoint_name.c_str());
	}

	return authenticated;
}

const std::shared_ptr<http_response> MCP_JSONRPC_Resource::render_GET(
	const httpserver::http_request& req
) {
	std::string req_path = req.get_path();
	proxy_debug(PROXY_DEBUG_GENERIC, 2, "Received MCP GET request on %s - returning 405 Method Not Allowed\n", req_path.c_str());

	// According to the MCP specification (Streamable HTTP transport):
	// "The server MUST either return Content-Type: text/event-stream in response to
	// this HTTP GET, or else return HTTP 405 Method Not Allowed, indicating that
	// the server does not offer an SSE stream at this endpoint."
	//
	// This server does not currently support SSE streaming, so we return 405.
	auto response = std::shared_ptr<http_response>(new string_response(
		"",
		http::http_utils::http_method_not_allowed  // 405
	));
	response->with_header("Allow", "POST");  // Tell client what IS allowed

	if (handler) {
		handler->status_variables.total_requests++;
	}

	return response;
}

const std::shared_ptr<http_response> MCP_JSONRPC_Resource::render_OPTIONS(
	const httpserver::http_request& req
) {
	std::string req_path = req.get_path();
	proxy_debug(PROXY_DEBUG_GENERIC, 2, "Received MCP OPTIONS request on %s\n", req_path.c_str());

	// Handle CORS preflight requests for MCP HTTP transport
	// Return 200 OK with appropriate CORS headers
	auto response = std::shared_ptr<http_response>(new string_response(
		"",
		http::http_utils::http_ok
	));
	response->with_header("Content-Type", "application/json");
	response->with_header("Access-Control-Allow-Origin", "*");
	response->with_header("Access-Control-Allow-Methods", "POST, OPTIONS");
	response->with_header("Access-Control-Allow-Headers", "Content-Type, Authorization");

	if (handler) {
		handler->status_variables.total_requests++;
	}

	return response;
}

const std::shared_ptr<http_response> MCP_JSONRPC_Resource::render_DELETE(
	const httpserver::http_request& req
) {
	std::string req_path = req.get_path();
	proxy_debug(PROXY_DEBUG_GENERIC, 2, "Received MCP DELETE request on %s - returning 405 Method Not Allowed\n", req_path.c_str());

	// ProxySQL doesn't support session termination
	// Return 405 Method Not Allowed with Allow header indicating supported methods
	auto response = std::shared_ptr<http_response>(new string_response(
		"",
		http::http_utils::http_method_not_allowed  // 405
	));
	response->with_header("Allow", "POST, OPTIONS");  // Tell client what IS allowed

	if (handler) {
		handler->status_variables.total_requests++;
	}

	return response;
}

std::string MCP_JSONRPC_Resource::create_jsonrpc_response(
	const std::string& result,
	const json& id
) {
	nlohmann::ordered_json j;  // Use ordered_json to preserve field order
	j["jsonrpc"] = "2.0";
	// Only include id if it's not null (per JSON-RPC 2.0 and MCP spec)
	if (!id.is_null()) {
		j["id"] = id;
	}
	j["result"] = json::parse(result);
	return j.dump();
}

std::string MCP_JSONRPC_Resource::create_jsonrpc_error(
	int code,
	const std::string& message,
	const json& id
) {
	nlohmann::ordered_json j;  // Use ordered_json to preserve field order
	j["jsonrpc"] = "2.0";
	json error;
	error["code"] = code;
	error["message"] = message;
	j["error"] = error;
	// Only include id if it's not null (per JSON-RPC 2.0 and MCP spec)
	if (!id.is_null()) {
		j["id"] = id;
	}
	return j.dump();
}

std::shared_ptr<http_response> MCP_JSONRPC_Resource::handle_jsonrpc_request(
	const httpserver::http_request& req
) {
	// Declare these outside the try block so they're available in catch handlers
	std::string req_body;
	std::string req_path;

	// Wrap entire request handling in try-catch to catch any unexpected exceptions
	try {
		// Update statistics
		if (handler) {
			handler->status_variables.total_requests++;
		}

		// Get request body and path
		req_body = req.get_content();
		req_path = req.get_path();

		proxy_debug(PROXY_DEBUG_GENERIC, 2, "MCP request on %s: %s\n", req_path.c_str(), req_body.c_str());

		// Validate JSON
		json req_json;
		try {
			req_json = json::parse(req_body);
		} catch (json::parse_error& e) {
		proxy_error("MCP request on %s: Invalid JSON - %s\n", req_path.c_str(), e.what());
		proxy_error("MCP request payload that failed to parse: %s\n", req_body.c_str());
		if (handler) {
			handler->status_variables.failed_requests++;
		}
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32700, "Parse error", nullptr),
			http::http_utils::http_bad_request
		));
		response->with_header("Content-Type", "application/json");
		return response;
	}

	// Extract request ID immediately after parsing (JSON-RPC 2.0 spec)
	// This must be done BEFORE validation so we can include the ID in error responses
	json req_id = nullptr;
	if (req_json.contains("id")) {
		req_id = req_json["id"];
	}

	// Validate JSON-RPC 2.0 basic structure
	if (!req_json.contains("jsonrpc") || req_json["jsonrpc"] != "2.0") {
		proxy_error("MCP request on %s: Missing or invalid jsonrpc version\n", req_path.c_str());
		if (handler) {
			handler->status_variables.failed_requests++;
		}
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32600, "Invalid Request", req_id),
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
		// Use -32601 "Method not found" for compatibility with MCP clients
		// (even though -32600 "Invalid Request" is technically correct per JSON-RPC spec)
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32601, "Method not found", req_id),
			http::http_utils::http_bad_request
		));
		response->with_header("Content-Type", "application/json");
		return response;
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
	} else if (method == "prompts/list") {
		result = handle_prompts_list();
	} else if (method == "resources/list") {
		result = handle_resources_list();
	} else if (method == "initialize") {
		// Handle MCP protocol methods
		result["protocolVersion"] = "2025-06-18";
		result["capabilities"]["tools"] = json::object();  // Explicitly declare tools support
		result["serverInfo"] = {
			{"name", "proxysql-mcp-server"},
			{"version", MCP_THREAD_VERSION}
		};
	} else if (method == "ping") {
		result["status"] = "ok";
	} else if (method.compare(0, strlen("notifications/"), "notifications/") == 0) {
		// Handle notifications sent by the client
		// notifications/initialized
		// - https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle#initialization
		// notifications/cancelled
		// - https://modelcontextprotocol.io/specification/2025-06-18/basic/utilities/cancellation#cancellation-flow

		proxy_debug(PROXY_DEBUG_GENERIC, 2, "MCP notification '%s' received on endpoint '%s'\n", method.c_str(), endpoint_name.c_str());
		// simple acknowledgement with HTTP 202 Accepted (no response body)
		return std::shared_ptr<http_response>(new string_response("",http::http_utils::http_accepted));
	} else {
		// Unknown method
		proxy_info("MCP: Unknown method '%s' on endpoint '%s'\n", method.c_str(), endpoint_name.c_str());
		// Return HTTP 200 OK with JSON-RPC error (not HTTP 404) for compatibility with MCP clients
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32601, "Method not found", req_id),
			http::http_utils::http_ok
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

	} catch (const std::exception& e) {
		// Catch any unexpected exceptions and return a proper error response
		proxy_error("MCP request on %s: Unexpected exception - %s\n", req_path.c_str(), e.what());
		proxy_error("MCP request payload that caused exception: %s\n", req_body.c_str());
		if (handler) {
			handler->status_variables.failed_requests++;
		}
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32603, "Internal error: " + std::string(e.what()), ""),
			http::http_utils::http_internal_server_error
		));
		response->with_header("Content-Type", "application/json");
		return response;
	} catch (...) {
		// Catch any other exceptions
		proxy_error("MCP request on %s: Unknown exception\n", req_path.c_str());
		proxy_error("MCP request payload that caused exception: %s\n", req_body.c_str());
		if (handler) {
			handler->status_variables.failed_requests++;
		}
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32603, "Internal error: Unknown exception", ""),
			http::http_utils::http_internal_server_error
		));
		response->with_header("Content-Type", "application/json");
		return response;
	}
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
		// Use nullptr for ID since we haven't parsed JSON yet (JSON-RPC 2.0 spec)
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32600, "Invalid Request: Content-Type must be application/json", nullptr),
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
		// Use nullptr for ID since we haven't parsed JSON yet (JSON-RPC 2.0 spec)
		auto response = std::shared_ptr<http_response>(new string_response(
			create_jsonrpc_error(-32001, "Unauthorized", nullptr),
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
	auto trim_for_log = [](const std::string& input, size_t max_len) -> std::string {
		if (input.size() <= max_len) {
			return input;
		}
		return input.substr(0, max_len) + "...";
	};

	proxy_info("MCP TOOL CALL: endpoint='%s' tool='%s'\n", endpoint_name.c_str(), tool_name.c_str());
	proxy_debug(PROXY_DEBUG_GENERIC, 2, "MCP tool call: %s with args: %s\n", tool_name.c_str(), arguments.dump().c_str());

	// AI/RAG handlers borrow the vector DB, LLM bridge, and GenAI worker
	// manager.  LOAD GENAI VARIABLES replaces those resources in place.  Hold
	// the shared side only across the handler call so the reload can wait for
	// current users and rebind the persistent handler before admitting the
	// next request.
	std::shared_lock<GenAIRWLock> runtime_guard;
	if (runtime_dependencies_mutex != nullptr) {
		runtime_guard = std::shared_lock<GenAIRWLock>(*runtime_dependencies_mutex);
	}
	json response = tool_handler->execute_tool(tool_name, arguments);

	// Check if this is a ProxySQL tool response with success/result wrapper
	if (response.is_object() && response.contains("success")) {
		bool success = response["success"].get<bool>();
		if (!success) {
			// Tool execution failed - log the error with full context and return in MCP format
			std::string error_msg = response.contains("error") ? response["error"].get<std::string>() : "Tool execution failed";
			std::string args_str = arguments.dump();
			std::string target_id = (arguments.contains("target_id") && arguments["target_id"].is_string()) ? arguments["target_id"].get<std::string>() : "";
			std::string schema = (arguments.contains("schema") && arguments["schema"].is_string()) ? arguments["schema"].get<std::string>() : "";
			std::string sql = (arguments.contains("sql") && arguments["sql"].is_string()) ? arguments["sql"].get<std::string>() : "";
			proxy_error("MCP TOOL CALL FAILED: endpoint='%s' tool='%s' error='%s'\n",
				endpoint_name.c_str(), tool_name.c_str(), error_msg.c_str());
			proxy_error("MCP TOOL CALL FAILED: arguments='%s'\n", args_str.c_str());
			if (!target_id.empty() || !schema.empty() || !sql.empty()) {
				proxy_error(
					"MCP TOOL CALL FAILED DETAILS: target_id='%s' schema='%s' sql='%s'\n",
					target_id.c_str(),
					schema.c_str(),
					trim_for_log(sql, 512).c_str()
				);
			}
			json mcp_result;
			mcp_result["content"] = json::array();
			json error_content;
			error_content["type"] = "text";
			error_content["text"] = error_msg;
			mcp_result["content"].push_back(error_content);
			mcp_result["isError"] = true;
			return mcp_result;
		}
		// Success - extract the result field if it exists, otherwise use the whole response
		proxy_info("MCP TOOL CALL SUCCESS: endpoint='%s' tool='%s'\n", endpoint_name.c_str(), tool_name.c_str());
		if (response.contains("result")) {
			response = response["result"];
		}
	}

	// Wrap the response (or the 'result' field) in MCP-compliant format
	// Per MCP spec: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
	json mcp_result;
	json text_content;
	text_content["type"] = "text";

	if (response.is_string()) {
		text_content["text"] = response.get<std::string>();
	} else {
		text_content["text"] = response.dump(2);  // Pretty-print JSON with 2-space indent
	}

	mcp_result["content"] = json::array({text_content});
	// Note: Per MCP spec, only include isError when true (error case)
	// For success responses, omit the isError field entirely
	return mcp_result;
}

// Helper method to handle prompts/list
json MCP_JSONRPC_Resource::handle_prompts_list() {
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "MCP: prompts/list called\n");
	// Returns an empty prompts array since ProxySQL doesn't support prompts
	json result;
	result["prompts"] = json::array();
	return result;
}

// Helper method to handle resources/list
json MCP_JSONRPC_Resource::handle_resources_list() {
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "MCP: resources/list called\n");
	// Returns an empty resources array since ProxySQL doesn't support resources
	json result;
	result["resources"] = json::array();
	return result;
}

#endif /* PROXYSQL40 */
