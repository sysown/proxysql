#include "mcp_client.h"
#include <cstdlib>
#include <cstring>
#include <stdexcept>

// ============================================================================
// Constructor / Destructor
// ============================================================================

MCPClient::MCPClient(
    const std::string& host,
    int port,
    long timeout_ms
)
    : curl_(nullptr)
    , host_(host)
    , port_(port)
    , timeout_ms_(timeout_ms)
    , use_ssl_(false)
    , request_id_(1)
{
    // Apply defaults if not provided
    if (host_.empty()) {
        host_ = "127.0.0.1";
    }

    if (port_ == 0) {
        port_ = 6071;
    }

    // Initialize curl
    init_curl();

    // Build base URL
    base_url_ = "http://" + host_ + ":" + std::to_string(port_);
}

MCPClient::~MCPClient() {
    if (curl_) {
        curl_easy_cleanup(curl_);
        curl_ = nullptr;
    }
}

// ============================================================================
// Configuration Methods
// ============================================================================

void MCPClient::set_host(const std::string& host) {
    host_ = host;
    std::string protocol = use_ssl_ ? "https://" : "http://";
    base_url_ = protocol + host_ + ":" + std::to_string(port_);
}

void MCPClient::set_port(int port) {
    port_ = port;
    std::string protocol = use_ssl_ ? "https://" : "http://";
    base_url_ = protocol + host_ + ":" + std::to_string(port_);
}

void MCPClient::set_timeout(long timeout_ms) {
    timeout_ms_ = timeout_ms;
    if (curl_) {
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT_MS, timeout_ms_);
    }
}

void MCPClient::set_auth_token(const std::string& token) {
    auth_token_ = token;
}

void MCPClient::set_use_ssl(bool use_ssl) {
    use_ssl_ = use_ssl;
    std::string protocol = use_ssl_ ? "https://" : "http://";
    base_url_ = protocol + host_ + ":" + std::to_string(port_);

    // Configure curl for SSL
    if (curl_) {
        if (use_ssl_) {
            // Skip certificate verification for testing
            curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 0L);
        } else {
            curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 2L);
        }
    }
}

std::string MCPClient::get_connection_info() const {
    return host_ + ":" + std::to_string(port_);
}

// ============================================================================
// Private Methods - Initialization
// ============================================================================

void MCPClient::init_curl() {
    curl_ = curl_easy_init();
    if (!curl_) {
        last_error_ = "Failed to initialize libcurl";
        throw std::runtime_error(last_error_);
    }

    // Common options
    curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl_, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl_, CURLOPT_TIMEOUT_MS, timeout_ms_);

    // Write callback
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_callback);
}

// ============================================================================
// Private Methods - URL Building
// ============================================================================

std::string MCPClient::build_url(const std::string& endpoint) const {
    return base_url_ + "/mcp/" + endpoint;
}

// ============================================================================
// Private Methods - Request/Response Handling
// ============================================================================

json MCPClient::build_request(const std::string& tool_name, const json& arguments) {
    return json{
        {"jsonrpc", "2.0"},
        {"method", "tools/call"},
        {"params", {
            {"name", tool_name},
            {"arguments", arguments}
        }},
        {"id", request_id_++}
    };
}

MCPResponse MCPClient::parse_response(const std::string& raw_response, long http_code, CURLcode curl_result) {
    MCPResponse resp;

    // Always preserve HTTP context for debugging
    resp.set_http_code(http_code);
    resp.set_http_response(raw_response);

    // 1. TRANSPORT layer errors (CURL failures)
    if (curl_result != CURLE_OK) {
        resp.set_error_type(MCPErrorType::TRANSPORT);
        resp.set_error_code(curl_result);
        resp.set_error_message("CURL error: " + std::string(curl_easy_strerror(curl_result)));
        return resp;
    }

    // 2. Try to parse response body as JSON
    json j;
    try {
        j = json::parse(raw_response);
    } catch (const json::parse_error& e) {
        // Not valid JSON
        if (http_code != 200) {
            // HTTP error with non-JSON body
            resp.set_error_type(MCPErrorType::HTTP);
            resp.set_error_code(http_code);
            resp.set_error_message("HTTP error: " + std::to_string(http_code));
        } else {
            // HTTP 200 but can't parse JSON
            resp.set_error_type(MCPErrorType::JSON_RPC);
            resp.set_error_message("JSON parse error: " + std::string(e.what()));
        }
        return resp;
    }

    // 3. We have valid JSON - check for JSON-RPC error
    bool has_jsonrpc_error = j.contains("error");

    if (has_jsonrpc_error) {
        // JSON-RPC error (regardless of HTTP status code)
        // Per MCP spec: HTTP error responses MAY contain JSON-RPC error in body
        resp.set_error_type(MCPErrorType::JSON_RPC);
        json error_obj = j["error"];
        resp.set_error_code(error_obj.value("code", 0));
        resp.set_error_message(error_obj.value("message", "Unknown error"));
        return resp;
    }

    // 4. No JSON-RPC error, check HTTP status
    if (http_code != 200) {
        // HTTP error without JSON-RPC error in body
        resp.set_error_type(MCPErrorType::HTTP);
        resp.set_error_code(http_code);
        resp.set_error_message("HTTP error: " + std::to_string(http_code));
        return resp;
    }

    // 5. HTTP 200 with valid JSON - validate JSON-RPC format
    if (!j.contains("jsonrpc") || j["jsonrpc"] != "2.0") {
        resp.set_error_type(MCPErrorType::JSON_RPC);
        resp.set_error_message("Invalid JSON-RPC response format");
        return resp;
    }

    // 6. Check for result
    if (!j.contains("result")) {
        // Malformed JSON-RPC (no result, no error)
        resp.set_error_type(MCPErrorType::JSON_RPC);
        resp.set_error_message("Malformed JSON-RPC response: missing result and error");
        return resp;
    }

    json mcp_result = j["result"];

    // 7. Parse MCP tool response format
    // Per MCP spec: https://modelcontextprotocol.io/specification/2025-06-18/server/tools
    resp.set_error_type(MCPErrorType::MCP);

    // Validate MCP response structure
    if (!mcp_result.is_object()) {
        resp.set_error_message("MCP error: result is not an object");
        return resp;
    }

    if (!mcp_result.contains("content")) {
        resp.set_error_message("MCP error: missing 'content' field");
        return resp;
    }

    if (!mcp_result["content"].is_array()) {
        resp.set_error_message("MCP error: 'content' is not an array");
        return resp;
    }

    if (mcp_result["content"].empty()) {
        resp.set_error_message("MCP error: 'content' array is empty");
        return resp;
    }

    // 7a. Check for tool execution error (isError: true)
    if (mcp_result.contains("isError") && mcp_result["isError"] == true) {
        // Extract error message from content[0].text
        json first_content = mcp_result["content"][0];
        if (first_content.contains("text")) {
            resp.set_error_message(first_content["text"].get<std::string>());
        } else {
            resp.set_error_message("Tool execution failed");
        }
        return resp;
    }

    // 7b. Extract tool result from content array
    json first_content = mcp_result["content"][0];

    // Validate content item structure
    if (!first_content.is_object()) {
        resp.set_error_message("MCP error: content item is not an object");
        return resp;
    }

    if (!first_content.contains("type")) {
        resp.set_error_message("MCP error: content item missing 'type' field");
        return resp;
    }

    std::string content_type = first_content["type"].get<std::string>();

    // Handle text content (ProxySQL returns JSON as text)
    if (content_type == "text") {
        if (!first_content.contains("text")) {
            resp.set_error_message("MCP error: text content missing 'text' field");
            return resp;
        }

        std::string text_content = first_content["text"].get<std::string>();

        // Try to parse as JSON (ProxySQL serializes tool results as JSON strings)
        try {
            json tool_result = json::parse(text_content);
            resp.set_error_type(MCPErrorType::NONE);
            resp.set_result(std::make_unique<json>(tool_result));
            return resp;
        } catch (const json::parse_error& e) {
            // JSON parsing failed - treat as MCP error
            resp.set_error_message("MCP error: failed to parse text content as JSON: " +
                                  std::string(e.what()));
            return resp;
        }
    }

    // Handle other content types (image, audio, resource_link, resource)
    // For now, we don't support these in ProxySQL, so treat as error
    resp.set_error_message("MCP error: unsupported content type '" + content_type + "'");
    return resp;
}

size_t MCPClient::write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), total_size);
    return total_size;
}

// ============================================================================
// Tool Invocation
// ============================================================================

MCPResponse MCPClient::call_tool(
    const std::string& endpoint,
    const std::string& tool_name,
    const json& arguments
) {
    std::string response_body;

    // Build JSON-RPC request
    json rpc_request = build_request(tool_name, arguments);
    std::string request_body = rpc_request.dump();

    // Prepare HTTP headers
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    // Add authentication token if configured
    if (!auth_token_.empty()) {
        std::string auth_header = "Authorization: Bearer " + auth_token_;
        headers = curl_slist_append(headers, auth_header.c_str());
    }

    // Configure curl for this request
    std::string url = build_url(endpoint);
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_POST, 1L);
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, request_body.c_str());
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response_body);

    // Execute request
    CURLcode res = curl_easy_perform(curl_);
    long http_code = 0;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);

    // Cleanup headers
    curl_slist_free_all(headers);

    // Parse response with full error classification
    MCPResponse resp = parse_response(response_body, http_code, res);

    // Update last_error_ for backwards compatibility
    if (resp.has_error()) {
        last_error_ = resp.get_error_message();
    }

    return resp;
}

MCPResponse MCPClient::call_tool(
    const std::string& endpoint,
    const std::string& tool_name,
    const std::string& arguments_json
) {
    try {
        json args = json::parse(arguments_json);
        return call_tool(endpoint, tool_name, args);
    }
    catch (const json::parse_error& e) {
        MCPResponse resp;
        resp.set_error_type(MCPErrorType::JSON_RPC);

        resp.set_error_message("Invalid JSON arguments: " + std::string(e.what()));
        return resp;
    }
}

// ============================================================================
// Server Connectivity
// ============================================================================

bool MCPClient::check_server() {
    const unsigned int ping_id = request_id_++;
    json ping_request = {
        {"jsonrpc", "2.0"},
        {"method", "ping"},
        {"id", ping_id}
    };

    std::string url = build_url("config");
    std::string request_body = ping_request.dump();
    std::string response_body;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!auth_token_.empty()) {
        const std::string auth_header = "Authorization: Bearer " + auth_token_;
        headers = curl_slist_append(headers, auth_header.c_str());
    }

    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_POST, 1L);
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, request_body.c_str());
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response_body);

    CURLcode res = curl_easy_perform(curl_);
    long http_code = 0;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        last_error_ = curl_easy_strerror(res);
        return false;
    }

    if (http_code != 200) {
        last_error_ = "HTTP error: " + std::to_string(http_code);
        return false;
    }

    json response;
    try {
        response = json::parse(response_body);
    } catch (const json::parse_error& e) {
        last_error_ = "JSON parse error: " + std::string(e.what());
        return false;
    }

    if (!response.is_object() ||
        !response.contains("jsonrpc") || response["jsonrpc"] != "2.0" ||
        !response.contains("id") || response["id"] != ping_id ||
        !response.contains("result")) {
        last_error_ = "Invalid JSON-RPC readiness response";
        return false;
    }

    last_error_.clear();
    return true;
}
