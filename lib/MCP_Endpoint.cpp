#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "MCP_Endpoint.h"
#include "MCP_Thread.h"
#include "MySQL_Tool_Handler.h"
#include "proxysql_debug.h"
#include "cpp.h"

using namespace httpserver;

MCP_JSONRPC_Resource::MCP_JSONRPC_Resource(MCP_Threads_Handler* h, const std::string& name)
	: handler(h), endpoint_name(name)
{
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Created MCP JSON-RPC resource for endpoint '%s'\n", name.c_str());
}

MCP_JSONRPC_Resource::~MCP_JSONRPC_Resource() {
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Destroyed MCP JSON-RPC resource for endpoint '%s'\n", endpoint_name.c_str());
}

bool MCP_JSONRPC_Resource::authenticate_request(const httpserver::http_request& req) {
	// TODO: Implement proper authentication
	// Future implementation will:
	// 1. Extract auth token from Authorization header or query parameter
	// 2. Validate against endpoint-specific credentials stored in handler
	// 3. Support multiple auth methods (API key, JWT, mTLS)
	// 4. Return true if authenticated, false otherwise

	// For now, always allow
	return true;
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
		// Route tool-related methods to MySQL_Tool_Handler
		if (!handler || !handler->mysql_tool_handler) {
			proxy_error("MCP request on %s: MySQL Tool Handler not initialized\n", req_path.c_str());
			if (handler) {
				handler->status_variables.failed_requests++;
			}
			auto response = std::shared_ptr<http_response>(new string_response(
				create_jsonrpc_error(-32000, "MySQL Tool Handler not initialized", req_id),
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

	// Authenticate request (placeholder - always returns true for now)
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
	json result;
	result["tools"] = json::array();

	// Inventory Tools
	{
		json tool;
		tool["name"] = "list_schemas";
		tool["description"] = "List available schemas/databases";
		tool["inputSchema"] = json::object();
		tool["inputSchema"]["type"] = "object";
		tool["inputSchema"]["properties"] = json::object();
		tool["inputSchema"]["properties"]["page_token"] = json::object();
		tool["inputSchema"]["properties"]["page_token"]["type"] = "string";
		tool["inputSchema"]["properties"]["page_size"] = json::object();
		tool["inputSchema"]["properties"]["page_size"]["type"] = "integer";
		tool["inputSchema"]["properties"]["page_size"]["default"] = 50;
		result["tools"].push_back(tool);
	}

	{
		json tool;
		tool["name"] = "list_tables";
		tool["description"] = "List tables in a schema";
		tool["inputSchema"] = json::object();
		tool["inputSchema"]["type"] = "object";
		tool["inputSchema"]["properties"] = json::object();
		tool["inputSchema"]["properties"]["schema"] = json::object();
		tool["inputSchema"]["properties"]["schema"]["type"] = "string";
		tool["inputSchema"]["properties"]["page_token"] = json::object();
		tool["inputSchema"]["properties"]["page_token"]["type"] = "string";
		tool["inputSchema"]["properties"]["page_size"] = json::object();
		tool["inputSchema"]["properties"]["page_size"]["type"] = "integer";
		tool["inputSchema"]["properties"]["page_size"]["default"] = 50;
		tool["inputSchema"]["properties"]["name_filter"] = json::object();
		tool["inputSchema"]["properties"]["name_filter"]["type"] = "string";
		result["tools"].push_back(tool);
	}

	// Structure Tools
	{
		json tool;
		tool["name"] = "describe_table";
		tool["description"] = "Get detailed table schema";
		tool["inputSchema"] = json::object();
		tool["inputSchema"]["type"] = "object";
		tool["inputSchema"]["properties"] = json::object();
		tool["inputSchema"]["properties"]["schema"] = json::object();
		tool["inputSchema"]["properties"]["schema"]["type"] = "string";
		tool["inputSchema"]["properties"]["table"] = json::object();
		tool["inputSchema"]["properties"]["table"]["type"] = "string";
		tool["inputSchema"]["required"] = json::array();
		tool["inputSchema"]["required"].push_back("schema");
		tool["inputSchema"]["required"].push_back("table");
		result["tools"].push_back(tool);
	}

	// Sampling Tools
	{
		json tool;
		tool["name"] = "sample_rows";
		tool["description"] = "Sample rows from a table (max 20 rows)";
		tool["inputSchema"] = json::object();
		tool["inputSchema"]["type"] = "object";
		tool["inputSchema"]["properties"] = json::object();
		tool["inputSchema"]["properties"]["schema"] = json::object();
		tool["inputSchema"]["properties"]["schema"]["type"] = "string";
		tool["inputSchema"]["properties"]["table"] = json::object();
		tool["inputSchema"]["properties"]["table"]["type"] = "string";
		tool["inputSchema"]["properties"]["columns"] = json::object();
		tool["inputSchema"]["properties"]["columns"]["type"] = "string";
		tool["inputSchema"]["properties"]["where"] = json::object();
		tool["inputSchema"]["properties"]["where"]["type"] = "string";
		tool["inputSchema"]["properties"]["order_by"] = json::object();
		tool["inputSchema"]["properties"]["order_by"]["type"] = "string";
		tool["inputSchema"]["properties"]["limit"] = json::object();
		tool["inputSchema"]["properties"]["limit"]["type"] = "integer";
		tool["inputSchema"]["properties"]["limit"]["default"] = 20;
		tool["inputSchema"]["required"] = json::array();
		tool["inputSchema"]["required"].push_back("schema");
		tool["inputSchema"]["required"].push_back("table");
		result["tools"].push_back(tool);
	}

	{
		json tool;
		tool["name"] = "run_sql_readonly";
		tool["description"] = "Execute read-only SQL with guardrails (max 200 rows, 2s timeout)";
		tool["inputSchema"] = json::object();
		tool["inputSchema"]["type"] = "object";
		tool["inputSchema"]["properties"] = json::object();
		tool["inputSchema"]["properties"]["sql"] = json::object();
		tool["inputSchema"]["properties"]["sql"]["type"] = "string";
		tool["inputSchema"]["properties"]["max_rows"] = json::object();
		tool["inputSchema"]["properties"]["max_rows"]["type"] = "integer";
		tool["inputSchema"]["properties"]["max_rows"]["default"] = 200;
		tool["inputSchema"]["properties"]["timeout_sec"] = json::object();
		tool["inputSchema"]["properties"]["timeout_sec"]["type"] = "integer";
		tool["inputSchema"]["properties"]["timeout_sec"]["default"] = 2;
		tool["inputSchema"]["required"] = json::array();
		tool["inputSchema"]["required"].push_back("sql");
		result["tools"].push_back(tool);
	}

	// Catalog Tools (LLM Memory)
	{
		json tool;
		tool["name"] = "catalog_upsert";
		tool["description"] = "Upsert catalog entry for LLM memory";
		tool["inputSchema"] = json::object();
		tool["inputSchema"]["type"] = "object";
		tool["inputSchema"]["properties"] = json::object();
		tool["inputSchema"]["properties"]["kind"] = json::object();
		tool["inputSchema"]["properties"]["kind"]["type"] = "string";
		tool["inputSchema"]["properties"]["key"] = json::object();
		tool["inputSchema"]["properties"]["key"]["type"] = "string";
		tool["inputSchema"]["properties"]["document"] = json::object();
		tool["inputSchema"]["properties"]["document"]["type"] = "string";
		tool["inputSchema"]["properties"]["tags"] = json::object();
		tool["inputSchema"]["properties"]["tags"]["type"] = "string";
		tool["inputSchema"]["properties"]["links"] = json::object();
		tool["inputSchema"]["properties"]["links"]["type"] = "string";
		tool["inputSchema"]["required"] = json::array();
		tool["inputSchema"]["required"].push_back("kind");
		tool["inputSchema"]["required"].push_back("key");
		tool["inputSchema"]["required"].push_back("document");
		result["tools"].push_back(tool);
	}

	{
		json tool;
		tool["name"] = "catalog_search";
		tool["description"] = "Search catalog entries";
		tool["inputSchema"] = json::object();
		tool["inputSchema"]["type"] = "object";
		tool["inputSchema"]["properties"] = json::object();
		tool["inputSchema"]["properties"]["query"] = json::object();
		tool["inputSchema"]["properties"]["query"]["type"] = "string";
		tool["inputSchema"]["properties"]["kind"] = json::object();
		tool["inputSchema"]["properties"]["kind"]["type"] = "string";
		tool["inputSchema"]["properties"]["tags"] = json::object();
		tool["inputSchema"]["properties"]["tags"]["type"] = "string";
		tool["inputSchema"]["properties"]["limit"] = json::object();
		tool["inputSchema"]["properties"]["limit"]["type"] = "integer";
		tool["inputSchema"]["properties"]["limit"]["default"] = 20;
		result["tools"].push_back(tool);
	}

	return result;
}

// Helper method to handle tools/describe
json MCP_JSONRPC_Resource::handle_tools_describe(const json& req_json) {
	json result;

	if (!req_json.contains("params") || !req_json["params"].contains("name")) {
		result["error"] = "Missing tool name";
		return result;
	}

	std::string tool_name = req_json["params"]["name"].get<std::string>();

	// Return tool description based on name
	if (tool_name == "list_schemas") {
		result["name"] = "list_schemas";
		result["description"] = "List available schemas/databases";
	} else if (tool_name == "list_tables") {
		result["name"] = "list_tables";
		result["description"] = "List tables in a schema";
	} else if (tool_name == "describe_table") {
		result["name"] = "describe_table";
		result["description"] = "Get detailed table schema";
	} else if (tool_name == "sample_rows") {
		result["name"] = "sample_rows";
		result["description"] = "Sample rows from a table (max 20 rows)";
	} else if (tool_name == "run_sql_readonly") {
		result["name"] = "run_sql_readonly";
		result["description"] = "Execute read-only SQL with guardrails (max 200 rows, 2s timeout)";
	} else if (tool_name == "catalog_upsert") {
		result["name"] = "catalog_upsert";
		result["description"] = "Upsert catalog entry for LLM memory";
	} else if (tool_name == "catalog_search") {
		result["name"] = "catalog_search";
		result["description"] = "Search catalog entries";
	} else {
		result["error"] = "Tool not found: " + tool_name;
	}

	return result;
}

// Helper method to handle tools/call
json MCP_JSONRPC_Resource::handle_tools_call(const json& req_json) {
	json result;

	if (!req_json.contains("params") || !req_json["params"].contains("name")) {
		result["error"] = "Missing tool name";
		return result;
	}

	std::string tool_name = req_json["params"]["name"].get<std::string>();
	json arguments = req_json["params"].contains("arguments") ? req_json["params"]["arguments"] : json::object();

	proxy_debug(PROXY_DEBUG_GENERIC, 2, "MCP tool call: %s with args: %s\n", tool_name.c_str(), arguments.dump().c_str());

	// Route to MySQL_Tool_Handler methods
	MySQL_Tool_Handler* th = handler->mysql_tool_handler;

	if (tool_name == "list_schemas") {
		std::string page_token = arguments.count("page_token") ? arguments["page_token"].get<std::string>() : "";
		int page_size = arguments.count("page_size") ? arguments["page_size"].get<int>() : 50;
		std::string response = th->list_schemas(page_token, page_size);
		result = json::parse(response);
	}
	else if (tool_name == "list_tables") {
		std::string schema = arguments.count("schema") ? arguments["schema"].get<std::string>() : "";
		std::string page_token = arguments.count("page_token") ? arguments["page_token"].get<std::string>() : "";
		int page_size = arguments.count("page_size") ? arguments["page_size"].get<int>() : 50;
		std::string name_filter = arguments.count("name_filter") ? arguments["name_filter"].get<std::string>() : "";
		std::string response = th->list_tables(schema, page_token, page_size, name_filter);
		result = json::parse(response);
	}
	else if (tool_name == "describe_table") {
		if (!arguments.count("schema") || !arguments.count("table")) {
			result["error"] = "Missing required parameters: schema, table";
		} else {
			std::string response = th->describe_table(arguments["schema"].get<std::string>(), arguments["table"].get<std::string>());
			result = json::parse(response);
		}
	}
	else if (tool_name == "sample_rows") {
		if (!arguments.count("schema") || !arguments.count("table")) {
			result["error"] = "Missing required parameters: schema, table";
		} else {
			std::string columns = arguments.count("columns") ? arguments["columns"].get<std::string>() : "";
			std::string where = arguments.count("where") ? arguments["where"].get<std::string>() : "";
			std::string order_by = arguments.count("order_by") ? arguments["order_by"].get<std::string>() : "";
			int limit = arguments.count("limit") ? arguments["limit"].get<int>() : 20;
			std::string response = th->sample_rows(arguments["schema"].get<std::string>(), arguments["table"].get<std::string>(), columns, where, order_by, limit);
			result = json::parse(response);
		}
	}
	else if (tool_name == "run_sql_readonly") {
		if (!arguments.count("sql")) {
			result["error"] = "Missing required parameter: sql";
		} else {
			int max_rows = arguments.count("max_rows") ? arguments["max_rows"].get<int>() : 200;
			int timeout_sec = arguments.count("timeout_sec") ? arguments["timeout_sec"].get<int>() : 2;
			std::string response = th->run_sql_readonly(arguments["sql"].get<std::string>(), max_rows, timeout_sec);
			result = json::parse(response);
		}
	}
	else if (tool_name == "catalog_upsert") {
		if (!arguments.count("kind") || !arguments.count("key") || !arguments.count("document")) {
			result["error"] = "Missing required parameters: kind, key, document";
		} else {
			std::string tags = arguments.count("tags") ? arguments["tags"].get<std::string>() : "";
			std::string links = arguments.count("links") ? arguments["links"].get<std::string>() : "";
			std::string response = th->catalog_upsert(arguments["kind"].get<std::string>(), arguments["key"].get<std::string>(), arguments["document"].get<std::string>(), tags, links);
			result = json::parse(response);
		}
	}
	else if (tool_name == "catalog_search") {
		std::string query = arguments.count("query") ? arguments["query"].get<std::string>() : "";
		std::string kind = arguments.count("kind") ? arguments["kind"].get<std::string>() : "";
		std::string tags = arguments.count("tags") ? arguments["tags"].get<std::string>() : "";
		int limit = arguments.count("limit") ? arguments["limit"].get<int>() : 20;
		std::string response = th->catalog_search(query, kind, tags, limit, 0);
		result = json::parse(response);
	}
	else {
		result["error"] = "Unknown tool: " + tool_name;
	}

	return result;
}
