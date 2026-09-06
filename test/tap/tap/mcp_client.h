#ifndef MCP_CLIENT_H
#define MCP_CLIENT_H

#include <string>
#include <memory>
#include <curl/curl.h>
#include "json.hpp"

using json = nlohmann::json;

/**
 * @brief Error classification for MCP responses
 *
 * Categorizes errors by the layer at which they occurred:
 * - NONE: No error (success)
 * - TRANSPORT: Network/CURL layer errors (connection failed, timeout, DNS)
 * - HTTP: HTTP protocol errors (4xx, 5xx) WITHOUT valid JSON-RPC error in body
 * - JSON_RPC: JSON-RPC protocol or tool errors (parse errors, invalid format, tool failures)
 */
enum class MCPErrorType {
    NONE,        ///< No error - successful response
    TRANSPORT,   ///< CURL/network layer errors
    HTTP,        ///< HTTP protocol errors without JSON-RPC error in body
    JSON_RPC,    ///< JSON-RPC protocol errors (parse, format, invalid structure)
    MCP          ///< MCP tool/content errors (validation failures, tool execution errors)
};

/**
 * @brief Response class for MCP tool calls
 *
 * Encapsulates parsed JSON-RPC response with multi-layer error classification.
 * Provides clean API for test assertions and error handling.
 *
 * Error Handling Philosophy:
 * - error_type: Identifies which layer the error occurred at
 * - error_code: Numeric error code (CURL code, HTTP status, or JSON-RPC code)
 * - error_message: Human-readable error description
 * - http_code/http_response: Always preserved for debugging
 *
 * Usage:
 *   MCPResponse resp = client.call_tool("stats", "show_status", args);
 *   if (resp.is_success()) {
 *       json& data = resp.get_result();
 *   } else if (resp.is_jsonrpc_error()) {
 *       diag("Tool error: %s (code %d)", resp.get_error_message().c_str(), resp.get_error_code());
 *   }
 */
class MCPResponse {
public:
    /**
     * @brief Default constructor - creates successful empty response
     */
    MCPResponse()
        : result_(nullptr)
        , error_type_(MCPErrorType::NONE)
        , error_code_(0)
        , http_code_(0) {}

    // ========================================================================
    // Result Access
    // ========================================================================

    /**
     * @brief Get the result data (for success responses)
     * @return Reference to JSON result object
     * @throws std::runtime_error if result is null (error occurred)
     */
    json& get_result() {
        if (!result_) {
            throw std::runtime_error("Cannot get result from error response");
        }
        return *result_;
    }

    /**
     * @brief Get the result data (const version)
     * @return Const reference to JSON result object
     * @throws std::runtime_error if result is null (error occurred)
     */
    const json& get_result() const {
        if (!result_) {
            throw std::runtime_error("Cannot get result from error response");
        }
        return *result_;
    }

    /**
     * @brief Check if result is available
     * @return true if result exists
     */
    bool has_result() const { return result_ != nullptr; }

    // ========================================================================
    // Error Classification
    // ========================================================================

    /**
     * @brief Get the error type (layer where error occurred)
     * @return Error type enum
     */
    MCPErrorType get_error_type() const { return error_type_; }

    /**
     * @brief Get numeric error code
     * @return Error code (context depends on error_type)
     */
    int get_error_code() const { return error_code_; }

    /**
     * @brief Get human-readable error message
     * @return Error message string
     */
    const std::string& get_error_message() const { return error_message_; }

    // ========================================================================
    // HTTP Context (always available for debugging)
    // ========================================================================

    /**
     * @brief Get HTTP status code
     * @return HTTP status code (0 if request didn't complete)
     */
    long get_http_code() const { return http_code_; }

    /**
     * @brief Get raw HTTP response body
     * @return HTTP response body string
     */
    const std::string& get_http_response() const { return http_response_; }

    // ========================================================================
    // Convenience Helpers
    // ========================================================================

    /**
     * @brief Check if response is successful
     * @return true if no error occurred
     */
    bool is_success() const { return error_type_ == MCPErrorType::NONE; }

    /**
     * @brief Check if any error occurred
     * @return true if error occurred at any layer
     */
    bool has_error() const { return error_type_ != MCPErrorType::NONE; }

    /**
     * @brief Check if error is at transport layer
     * @return true if CURL/network error
     */
    bool is_transport_error() const { return error_type_ == MCPErrorType::TRANSPORT; }

    /**
     * @brief Check if error is at HTTP layer
     * @return true if HTTP protocol error without JSON-RPC error in body
     */
    bool is_http_error() const { return error_type_ == MCPErrorType::HTTP; }

    /**
     * @brief Check if error is at JSON-RPC layer
     * @return true if JSON-RPC protocol or tool error
     */
    bool is_jsonrpc_error() const { return error_type_ == MCPErrorType::JSON_RPC; }

    /**
     * @brief Check if error is at MCP layer
     * @return true if MCP tool or content error
     */
    bool is_mcp_error() const { return error_type_ == MCPErrorType::MCP; }

    // ========================================================================
    // Internal Setters (for MCPClient use)
    // ========================================================================

    void set_result(std::unique_ptr<json> result) { result_ = std::move(result); }
    void set_error_type(MCPErrorType type) { error_type_ = type; }
    void set_error_code(int code) { error_code_ = code; }
    void set_error_message(const std::string& msg) { error_message_ = msg; }
    void set_http_code(long code) { http_code_ = code; }
    void set_http_response(const std::string& response) { http_response_ = response; }

private:
    // Result data (present only on success)
    std::unique_ptr<json> result_;

    // Error classification
    MCPErrorType error_type_;     ///< Which layer the error occurred at

    // Error details (universal placeholders)
    int error_code_;              ///< Numeric error code (context depends on error_type)
    std::string error_message_;   ///< Human-readable error message

    // HTTP context (always present for debugging)
    long http_code_;              ///< HTTP status code (0 if request didn't complete)
    std::string http_response_;   ///< Raw HTTP response body
};

/**
 * @brief Generic MCP Client for ProxySQL MCP Server
 *
 * Provides a C++ interface to ProxySQL's JSON-RPC 2.0 MCP server over HTTP.
 * Supports all MCP endpoints: config, query, admin, stats, rag, ai, cache.
 *
 * MCP Endpoints:
 *   /mcp/config   - Configuration and server discovery
 *   /mcp/query    - Query tools (run_sql_readonly, run_sql, etc.)
 *   /mcp/admin    - Administration tools
 *   /mcp/stats    - Statistics tools
 *   /mcp/rag      - RAG tools (search_fts, search_vector, get_chunks, etc.)
 *   /mcp/ai       - AI tools
 *   /mcp/cache    - Cache tools
 *
 * Configuration sources (in order of precedence):
 *   1. Constructor parameters
 *   2. Setter methods
 *   3. Defaults (127.0.0.1:6071)
 *
 * Usage:
 *   CommandLine cl;
 *   cl.getEnv();  // Reads TAP_ADMINHOST, TAP_MCP_PORT from environment
 *   MCPClient mcp(cl.host, cl.mcp_port);  // Pass values from CommandLine
 *
 *   json args = {{"query", "mysql"}, {"k", 10}};
 *   MCPResponse resp = mcp.call_tool("rag", "rag.search_fts", args);
 *
 *   if (resp.is_success()) {
 *       std::cout << resp.get_result()["results"] << std::endl;
 *   }
 */
class MCPClient {
public:
    // ========================================================================
    // Construction / Destruction
    // ========================================================================

    /**
     * @brief Construct MCP Client with optional configuration
     *
     * All parameters are optional. If not provided, defaults are used:
     *   - host: defaults to "127.0.0.1"
     *   - port: defaults to 6071
     *   - timeout_ms: defaults to 30000 (30 seconds)
     *
     * @param host MCP server hostname (empty = use default "127.0.0.1")
     * @param port MCP server port (0 = use default 6071)
     * @param timeout_ms Request timeout in milliseconds (default: 30000)
     *
     * @throws std::runtime_error if libcurl initialization fails
     */
    MCPClient(
        const std::string& host = "",
        int port = 0,
        long timeout_ms = 30000
    );

    /**
     * @brief Destructor - cleans up curl resources
     */
    ~MCPClient();

    // Disable copy (curl handle is not copyable)
    MCPClient(const MCPClient&) = delete;
    MCPClient& operator=(const MCPClient&) = delete;

    // ========================================================================
    // Configuration Methods
    // ========================================================================

    /**
     * @brief Set MCP server hostname
     * @param host Hostname or IP address
     */
    void set_host(const std::string& host);

    /**
     * @brief Set MCP server port
     * @param port Port number
     */
    void set_port(int port);

    /**
     * @brief Set request timeout
     * @param timeout_ms Timeout in milliseconds
     */
    void set_timeout(long timeout_ms);

    /**
     * @brief Set authentication token for all MCP endpoints
     *
     * Token is added as HTTP header: "Authorization: Bearer <token>"
     * Applies to all endpoints. To clear token, pass an empty string.
     *
     * @param token Authentication token (empty string to clear)
     */
    void set_auth_token(const std::string& token);

    /**
     * @brief Enable or disable SSL/HTTPS
     *
     * When enabled, the client uses https:// instead of http://
     * Also configures curl to skip certificate verification for testing.
     *
     * @param use_ssl true to use HTTPS, false for HTTP (default: false)
     */
    void set_use_ssl(bool use_ssl);

    // ========================================================================
    // Server Connectivity
    // ========================================================================

    /**
     * @brief Check if MCP server is accessible
     *
     * Sends a ping request to /mcp/config with the configured bearer token and
     * requires HTTP 200 plus a matching JSON-RPC result response.
     *
     * @return true if server responds successfully
     */
    bool check_server();

    // ========================================================================
    // Tool Invocation
    // ========================================================================

    /**
     * @brief Call an MCP tool on a specific endpoint
     *
     * Constructs JSON-RPC 2.0 request and sends it to the specified endpoint.
     *
     * JSON-RPC Request Format:
     *   {
     *     "jsonrpc": "2.0",
     *     "method": "tools/call",
     *     "params": {
     *       "name": "<tool_name>",
     *       "arguments": <arguments>
     *     },
     *     "id": <request_id>
     *   }
     *
     * Example - RAG FTS Search:
     *   json args = {{"query", "mysql"}, {"k", 10}};
     *   MCPResponse resp = mcp.call_tool("rag", "rag.search_fts", args);
     *
     * Example - Query SQL:
     *   json args = {{"sql", "SELECT * FROM users LIMIT 10"}};
     *   MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);
     *
     * Example - Admin Stats:
     *   json args = {};
     *   MCPResponse resp = mcp.call_tool("admin", "admin.get_stats", args);
     *
     * @param endpoint MCP endpoint (e.g., "rag", "query", "admin", "config")
     * @param tool_name Tool name (e.g., "rag.search_fts", "run_sql_readonly")
     * @param arguments JSON object with tool arguments
     *
     * @return MCPResponse with result or error
     */
    MCPResponse call_tool(
        const std::string& endpoint,
        const std::string& tool_name,
        const json& arguments
    );

    /**
     * @brief Call tool with JSON string arguments (convenience overload)
     *
     * @param endpoint MCP endpoint
     * @param tool_name Tool name
     * @param arguments_json JSON string with arguments
     *
     * @return MCPResponse with result or error
     */
    MCPResponse call_tool(
        const std::string& endpoint,
        const std::string& tool_name,
        const std::string& arguments_json
    );

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /**
     * @brief Get current timeout setting
     * @return Timeout in milliseconds
     */
    long get_timeout() const { return timeout_ms_; }

    /**
     * @brief Get last error message
     * @return Error message from last failed operation
     */
    std::string get_last_error() const { return last_error_; }

    /**
     * @brief Get base URL
     * @return Full base URL (e.g., "http://127.0.0.1:6071")
     */
    std::string get_base_url() const { return base_url_; }

    /**
     * @brief Get connection info string
     * @return String like "127.0.0.1:6071"
     */
    std::string get_connection_info() const;

private:
    // ========================================================================
    // Private Members
    // ========================================================================

    CURL* curl_;                       ///< libcurl handle
    std::string host_;                 ///< Server hostname
    int port_;                         ///< Server port
    long timeout_ms_;                  ///< Request timeout
    bool use_ssl_;                     ///< Use HTTPS instead of HTTP
    std::string last_error_;           ///< Last error message
    std::string base_url_;             ///< Full base URL
    unsigned int request_id_;          ///< JSON-RPC request ID counter
    std::string auth_token_;           ///< Authentication token for all endpoints

    // ========================================================================
    // Private Methods
    // ========================================================================

    /**
     * @brief Initialize libcurl
     */
    void init_curl();

    /**
     * @brief Build endpoint URL
     * @param endpoint Endpoint path
     * @return Full URL
     */
    std::string build_url(const std::string& endpoint) const;

    /**
     * @brief Build JSON-RPC request
     * @param tool_name Tool name
     * @param arguments Arguments
     * @return JSON request object
     */
    json build_request(const std::string& tool_name, const json& arguments);

    /**
     * @brief Parse JSON-RPC response with error classification
     * @param raw_response Raw JSON string
     * @param http_code HTTP status code
     * @param curl_result CURL result code
     * @return MCPResponse with proper error classification
     */
    MCPResponse parse_response(const std::string& raw_response, long http_code, CURLcode curl_result);

    /**
     * @brief libcurl write callback
     */
    static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp);
};

#endif // MCP_CLIENT_H
