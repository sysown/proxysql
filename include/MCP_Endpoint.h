#ifndef CLASS_MCP_ENDPOINT_H
#define CLASS_MCP_ENDPOINT_H

#include "proxysql.h"
#include "cpp.h"
#include <string>
#include <memory>

// Forward declarations
class MCP_Threads_Handler;
class MCP_Tool_Handler;

// Include httpserver after proxysql.h
#include "httpserver.hpp"

// Include JSON library
#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

/**
 * @brief MCP JSON-RPC 2.0 Resource class
 *
 * This class extends httpserver::http_resource to provide JSON-RPC 2.0
 * endpoints for MCP protocol communication. Each endpoint handles
 * POST requests with JSON-RPC 2.0 formatted payloads.
 *
 * Each endpoint has its own dedicated tool handler that provides
 * endpoint-specific tools.
 */
class MCP_JSONRPC_Resource : public httpserver::http_resource {
private:
	MCP_Threads_Handler* handler;       ///< Pointer to MCP handler for variable access
	MCP_Tool_Handler* tool_handler;     ///< Pointer to endpoint's dedicated tool handler
	std::string endpoint_name;           ///< Endpoint name (config, query, admin, etc.)

	/**
	 * @brief Authenticate the incoming request
	 *
	 * Placeholder for future authentication implementation.
	 * Currently always returns true.
	 *
	 * @param req The HTTP request
	 * @return true if authenticated, false otherwise
	 */
	bool authenticate_request(const httpserver::http_request& req);

	/**
	 * @brief Handle JSON-RPC 2.0 request
	 *
	 * Processes the JSON-RPC request and returns an appropriate response.
	 *
	 * @param req The HTTP request
	 * @return HTTP response with JSON-RPC response
	 */
	std::shared_ptr<httpserver::http_response> handle_jsonrpc_request(
		const httpserver::http_request& req
	);

	/**
	 * @brief Create a JSON-RPC 2.0 success response
	 *
	 * @param result The result data to include
	 * @param id The request ID
	 * @return JSON string representing the response
	 */
	std::string create_jsonrpc_response(
		const std::string& result,
		const std::string& id = "1"
	);

	/**
	 * @brief Create a JSON-RPC 2.0 error response
	 *
	 * @param code The error code (JSON-RPC standard or custom)
	 * @param message The error message
	 * @param id The request ID
	 * @return JSON string representing the error response
	 */
	std::string create_jsonrpc_error(
		int code,
		const std::string& message,
		const std::string& id = ""
	);

	/**
	 * @brief Handle tools/list method
	 *
	 * Returns a list of available MySQL exploration tools.
	 *
	 * @return JSON with tools array
	 */
	json handle_tools_list();

	/**
	 * @brief Handle tools/describe method
	 *
	 * Returns detailed information about a specific tool.
	 *
	 * @param req_json The JSON-RPC request
	 * @return JSON with tool description
	 */
	json handle_tools_describe(const json& req_json);

	/**
	 * @brief Handle tools/call method
	 *
	 * Executes a tool with the provided arguments.
	 *
	 * @param req_json The JSON-RPC request
	 * @return JSON with tool execution result
	 */
	json handle_tools_call(const json& req_json);

public:
	/**
	 * @brief Constructor for MCP_JSONRPC_Resource
	 *
	 * @param h Pointer to the MCP_Threads_Handler instance
	 * @param th Pointer to the endpoint's dedicated tool handler
	 * @param name The name of this endpoint (e.g., "config", "query")
	 */
	MCP_JSONRPC_Resource(MCP_Threads_Handler* h, MCP_Tool_Handler* th, const std::string& name);

	/**
	 * @brief Destructor
	 */
	~MCP_JSONRPC_Resource();

	/**
	 * @brief Handle POST requests
	 *
	 * Processes incoming JSON-RPC 2.0 POST requests.
	 *
	 * @param req The HTTP request
	 * @return HTTP response with JSON-RPC response
	 */
	const std::shared_ptr<httpserver::http_response> render_POST(
		const httpserver::http_request& req
	) override;
};

#endif /* CLASS_MCP_ENDPOINT_H */
