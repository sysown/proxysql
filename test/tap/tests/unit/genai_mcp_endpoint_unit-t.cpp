/**
 * @file genai_mcp_endpoint_unit-t.cpp
 * @brief Unit tests for MCP_JSONRPC_Resource pure functions.
 *
 * Tests pure validation and formatting functions from lib/MCP_Endpoint.cpp:
 *   - validate_bearer_token()   -- Bearer token extraction and validation
 *   - create_jsonrpc_response() -- JSON-RPC 2.0 success response formatting
 *   - create_jsonrpc_error()    -- JSON-RPC 2.0 error response formatting
 *
 * Built with all v4.0 plugins under PROXYSQL40=1 (auto-detected from libproxysql.a).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

#ifdef PROXYSQL40

#include "MCP_Endpoint.h"
#include "MCP_Thread.h"

#include <string>

/**
 * @brief Test accessor class for MCP_JSONRPC_Resource private members.
 *
 * Declared as friend in MCP_JSONRPC_Resource to access private methods
 * create_jsonrpc_response() and create_jsonrpc_error() for unit testing.
 */
class MCP_Endpoint_Test {
public:
	/**
	 * @brief Create a testable MCP_JSONRPC_Resource with a real handler.
	 *
	 * The handler's auth tokens are left null (no auth required) unless
	 * explicitly configured by the test.
	 */
	static MCP_JSONRPC_Resource make_resource(
		MCP_Threads_Handler* handler,
		const std::string& name
	) {
		return MCP_JSONRPC_Resource(handler, nullptr, name);
	}

	static std::string call_create_jsonrpc_response(
		MCP_JSONRPC_Resource& r,
		const std::string& result,
		const json& id = nullptr
	) {
		return r.create_jsonrpc_response(result, id);
	}

	static std::string call_create_jsonrpc_error(
		MCP_JSONRPC_Resource& r,
		int code,
		const std::string& message,
		const json& id = nullptr
	) {
		return r.create_jsonrpc_error(code, message, id);
	}
};

// ============================================================
// validate_bearer_token() -- Bearer token extraction/validation
// ============================================================

static void test_valid_bearer_token() {
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer mysecrettoken", "mysecrettoken"
	);
	ok(result == true, "validate_bearer_token: valid Bearer token accepted");
}

static void test_valid_bearer_token_complex() {
	// Token with special characters
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer abc123-def456_ghi.789", "abc123-def456_ghi.789"
	);
	ok(result == true, "validate_bearer_token: token with special chars accepted");
}

static void test_invalid_wrong_token() {
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer wrongtoken", "correcttoken"
	);
	ok(result == false, "validate_bearer_token: wrong token rejected");
}

static void test_missing_auth_header() {
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"", "expectedtoken"
	);
	ok(result == false, "validate_bearer_token: empty auth header rejected");
}

static void test_bearer_prefix_lowercase() {
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"bearer mytoken", "mytoken"
	);
	ok(result == true, "validate_bearer_token: lowercase 'bearer' accepted (RFC 7235 case-insensitive)");
}

static void test_malformed_bearer_prefix_no_space() {
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearermytoken", "mytoken"
	);
	ok(result == false, "validate_bearer_token: 'Bearer' without space rejected");
}

static void test_malformed_basic_auth() {
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"
	);
	ok(result == false, "validate_bearer_token: Basic auth scheme rejected");
}

static void test_empty_token_after_bearer() {
	// "Bearer " with nothing after it
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer ", "expectedtoken"
	);
	ok(result == false, "validate_bearer_token: empty token after 'Bearer ' rejected");
}

static void test_whitespace_only_token() {
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer    ", "expectedtoken"
	);
	ok(result == false, "validate_bearer_token: whitespace-only token rejected");
}

static void test_token_with_leading_whitespace() {
	// Token with leading spaces should be trimmed and still match
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer   mytoken", "mytoken"
	);
	ok(result == true, "validate_bearer_token: leading whitespace trimmed, token matches");
}

static void test_token_with_trailing_whitespace() {
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer mytoken   ", "mytoken"
	);
	ok(result == true, "validate_bearer_token: trailing whitespace trimmed, token matches");
}

static void test_token_with_surrounding_whitespace() {
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer  \t mytoken \t  ", "mytoken"
	);
	ok(result == true, "validate_bearer_token: surrounding whitespace trimmed, token matches");
}

static void test_bearer_only_no_token() {
	// Just "Bearer" without the trailing space
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer", "anytoken"
	);
	ok(result == false, "validate_bearer_token: 'Bearer' without space or token rejected");
}

static void test_case_sensitive_token() {
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer MyToken", "mytoken"
	);
	ok(result == false, "validate_bearer_token: token comparison is case-sensitive");
}

static void test_long_token() {
	std::string long_token(256, 'x');
	bool result = MCP_JSONRPC_Resource::validate_bearer_token(
		"Bearer " + long_token, long_token
	);
	ok(result == true, "validate_bearer_token: long token (256 chars) accepted");
}

// ============================================================
// create_jsonrpc_response() -- JSON-RPC 2.0 success responses
// ============================================================

static void test_jsonrpc_response_with_string_id() {
	MCP_Threads_Handler handler;
	auto resource = MCP_Endpoint_Test::make_resource(&handler, "config");

	std::string result = MCP_Endpoint_Test::call_create_jsonrpc_response(
		resource, "{\"status\":\"ok\"}", json("req-1")
	);

	json parsed = json::parse(result);
	ok(parsed["jsonrpc"] == "2.0", "create_jsonrpc_response: jsonrpc version is 2.0");
	ok(parsed["id"] == "req-1", "create_jsonrpc_response: id is 'req-1'");
	ok(parsed["result"]["status"] == "ok", "create_jsonrpc_response: result contains status ok");
}

static void test_jsonrpc_response_with_numeric_id() {
	MCP_Threads_Handler handler;
	auto resource = MCP_Endpoint_Test::make_resource(&handler, "config");

	std::string result = MCP_Endpoint_Test::call_create_jsonrpc_response(
		resource, "{\"data\":42}", json(123)
	);

	json parsed = json::parse(result);
	ok(parsed["jsonrpc"] == "2.0", "create_jsonrpc_response: jsonrpc version is 2.0 (numeric id)");
	ok(parsed["id"] == 123, "create_jsonrpc_response: numeric id preserved");
	ok(parsed["result"]["data"] == 42, "create_jsonrpc_response: result data is 42");
}

static void test_jsonrpc_response_with_null_id() {
	MCP_Threads_Handler handler;
	auto resource = MCP_Endpoint_Test::make_resource(&handler, "config");

	std::string result = MCP_Endpoint_Test::call_create_jsonrpc_response(
		resource, "{\"ok\":true}", nullptr
	);

	json parsed = json::parse(result);
	ok(parsed["jsonrpc"] == "2.0", "create_jsonrpc_response: jsonrpc version is 2.0 (null id)");
	ok(!parsed.contains("id"), "create_jsonrpc_response: null id is omitted from response");
	ok(parsed["result"]["ok"] == true, "create_jsonrpc_response: result ok is true");
}

// ============================================================
// create_jsonrpc_error() -- JSON-RPC 2.0 error responses
// ============================================================

static void test_jsonrpc_error_parse_error() {
	MCP_Threads_Handler handler;
	auto resource = MCP_Endpoint_Test::make_resource(&handler, "config");

	std::string result = MCP_Endpoint_Test::call_create_jsonrpc_error(
		resource, -32700, "Parse error", json("req-1")
	);

	json parsed = json::parse(result);
	ok(parsed["jsonrpc"] == "2.0", "create_jsonrpc_error: jsonrpc version is 2.0");
	ok(parsed["error"]["code"] == -32700, "create_jsonrpc_error: error code is -32700");
	ok(parsed["error"]["message"] == "Parse error", "create_jsonrpc_error: error message is 'Parse error'");
	ok(parsed["id"] == "req-1", "create_jsonrpc_error: id is 'req-1'");
}

static void test_jsonrpc_error_method_not_found() {
	MCP_Threads_Handler handler;
	auto resource = MCP_Endpoint_Test::make_resource(&handler, "config");

	std::string result = MCP_Endpoint_Test::call_create_jsonrpc_error(
		resource, -32601, "Method not found", json(42)
	);

	json parsed = json::parse(result);
	ok(parsed["error"]["code"] == -32601, "create_jsonrpc_error: error code is -32601");
	ok(parsed["error"]["message"] == "Method not found", "create_jsonrpc_error: error message correct");
	ok(parsed["id"] == 42, "create_jsonrpc_error: numeric id preserved in error");
}

static void test_jsonrpc_error_null_id() {
	MCP_Threads_Handler handler;
	auto resource = MCP_Endpoint_Test::make_resource(&handler, "config");

	std::string result = MCP_Endpoint_Test::call_create_jsonrpc_error(
		resource, -32600, "Invalid Request", nullptr
	);

	json parsed = json::parse(result);
	ok(parsed["jsonrpc"] == "2.0", "create_jsonrpc_error: jsonrpc 2.0 with null id");
	ok(parsed["error"]["code"] == -32600, "create_jsonrpc_error: error code is -32600");
	ok(!parsed.contains("id"), "create_jsonrpc_error: null id is omitted from error response");
}

static void test_jsonrpc_error_unauthorized() {
	MCP_Threads_Handler handler;
	auto resource = MCP_Endpoint_Test::make_resource(&handler, "config");

	std::string result = MCP_Endpoint_Test::call_create_jsonrpc_error(
		resource, -32001, "Unauthorized", nullptr
	);

	json parsed = json::parse(result);
	ok(parsed["error"]["code"] == -32001, "create_jsonrpc_error: custom error code -32001");
	ok(parsed["error"]["message"] == "Unauthorized", "create_jsonrpc_error: Unauthorized message");
}

#endif /* PROXYSQL40 */

int main() {
#ifdef PROXYSQL40
	plan(36);
	test_init_minimal();

	// validate_bearer_token tests (15)
	test_valid_bearer_token();                    // 1
	test_valid_bearer_token_complex();            // 1
	test_invalid_wrong_token();                   // 1
	test_missing_auth_header();                   // 1
	test_bearer_prefix_lowercase();               // 1
	test_malformed_bearer_prefix_no_space();      // 1
	test_malformed_basic_auth();                  // 1
	test_empty_token_after_bearer();              // 1
	test_whitespace_only_token();                 // 1
	test_token_with_leading_whitespace();         // 1
	test_token_with_trailing_whitespace();        // 1
	test_token_with_surrounding_whitespace();     // 1
	test_bearer_only_no_token();                  // 1
	test_case_sensitive_token();                  // 1
	test_long_token();                            // 1

	// create_jsonrpc_response tests (9)
	test_jsonrpc_response_with_string_id();       // 3
	test_jsonrpc_response_with_numeric_id();      // 3
	test_jsonrpc_response_with_null_id();         // 3

	// create_jsonrpc_error tests (12)
	test_jsonrpc_error_parse_error();             // 4
	test_jsonrpc_error_method_not_found();        // 3
	test_jsonrpc_error_null_id();                 // 3
	test_jsonrpc_error_unauthorized();            // 2

	test_cleanup_minimal();
	return exit_status();
#else
	plan(1);
	ok(1, "SKIP: GenAI not enabled in libproxysql.a");
	return exit_status();
#endif
}
