#ifndef CLASS_MCP_ENDPOINT_H
#define CLASS_MCP_ENDPOINT_H

#ifdef PROXYSQL40

#include "proxysql.h"
#include <string>
#include <memory>
#include <shared_mutex>

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
	// Allow unit tests to access private members for testing
	friend class MCP_Endpoint_Test;
private:
	MCP_Threads_Handler* handler;       ///< Pointer to MCP handler for variable access
	MCP_Tool_Handler* tool_handler;     ///< Pointer to endpoint's dedicated tool handler
	std::string endpoint_name;           ///< Endpoint name (config, query, admin, etc.)
	std::shared_mutex* runtime_dependencies_mutex; ///< Optional guard for borrowed GenAI runtime state

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
	 * @param id The request ID (can be string, number, or null)
	 * @return JSON string representing the response
	 */
	std::string create_jsonrpc_response(
		const std::string& result,
		const json& id = nullptr
	);

	/**
	 * @brief Create a JSON-RPC 2.0 error response
	 *
	 * @param code The error code (JSON-RPC standard or custom)
	 * @param message The error message
	 * @param id The request ID (can be string, number, or null)
	 * @return JSON string representing the error response
	 */
	std::string create_jsonrpc_error(
		int code,
		const std::string& message,
		const json& id = nullptr
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

	/**
	 * @brief Handle prompts/list method
	 *
	 * Returns an empty prompts array since ProxySQL doesn't support prompts.
	 *
	 * @return JSON with empty prompts array
	 */
	json handle_prompts_list();

	/**
	 * @brief Handle resources/list method
	 *
	 * Returns an empty resources array since ProxySQL doesn't support resources.
	 *
	 * @return JSON with empty resources array
	 */
	json handle_resources_list();

public:
	/**
	 * @brief Validate a Bearer token from an Authorization header value
	 *
	 * Pure validation function that extracts and compares a Bearer token
	 * from the given Authorization header against an expected token.
	 * Handles whitespace trimming and "Bearer " prefix validation.
	 *
	 * @param auth_header The full Authorization header value (e.g., "Bearer mytoken")
	 * @param expected_token The expected token to compare against
	 * @return true if the token matches, false otherwise
	 */
	static bool validate_bearer_token(const std::string& auth_header, const std::string& expected_token);

	/**
	 * @brief Constructor for MCP_JSONRPC_Resource
	 *
	 * @param h Pointer to the MCP_Threads_Handler instance
	 * @param th Pointer to the endpoint's dedicated tool handler
	 * @param name The name of this endpoint (e.g., "config", "query")
	 * @param dependencies_mutex Optional lifecycle guard for handlers that
	 *        borrow replaceable GenAI runtime resources
	 */
	MCP_JSONRPC_Resource(
		MCP_Threads_Handler* h,
		MCP_Tool_Handler* th,
		const std::string& name,
		std::shared_mutex* dependencies_mutex = nullptr
	);

	/**
	 * @brief Destructor
	 */
	~MCP_JSONRPC_Resource();

	/**
	 * @brief Handle GET requests
	 *
	 * Returns HTTP 405 Method Not Allowed for GET requests.
	 *
	 * According to the MCP specification 2025-06-18 (Streamable HTTP transport):
	 * "The server MUST either return Content-Type: text/event-stream in response to
	 * this HTTP GET, or else return HTTP 405 Method Not Allowed, indicating that
	 * the server does not offer an SSE stream at this endpoint."
	 *
	 * @param req The HTTP request
	 * @return HTTP 405 response with Allow: POST header
	 */
	const std::shared_ptr<httpserver::http_response> render_GET(
		const httpserver::http_request& req
	) override;

	/**
	 * @brief Handle OPTIONS requests (CORS preflight)
	 *
	 * Returns CORS headers for OPTIONS preflight requests.
	 *
	 * @param req The HTTP request
	 * @return HTTP response with CORS headers
	 */
	const std::shared_ptr<httpserver::http_response> render_OPTIONS(
		const httpserver::http_request& req
	) override;

	/**
	 * @brief Handle DELETE requests
	 *
	 * Returns HTTP 405 Method Not Allowed for DELETE requests.
	 *
	 * According to the MCP specification 2025-06-18 (Streamable HTTP transport):
	 * "The server MAY respond to this request with HTTP 405 Method Not Allowed,
	 * indicating that the server does not allow clients to terminate sessions."
	 *
	 * @param req The HTTP request
	 * @return HTTP 405 response with Allow header
	 */
	const std::shared_ptr<httpserver::http_response> render_DELETE(
		const httpserver::http_request& req
	) override;

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

#endif /* PROXYSQL40 */
#endif /* CLASS_MCP_ENDPOINT_H */
