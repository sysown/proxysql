/**
 * @file unit-k8s_auth_plugin-t.cpp
 * @brief Unit tests for K8s auth plugin using mock Kubernetes client
 *
 * Tests the K8s_Auth_Plugin class in isolation using MockKubernetesClient
 * for dependency injection. No actual K8s cluster or ProxySQL required.
 *
 * Test cases:
 *   1. Valid token with matching username
 *   2. Valid token with mismatched username
 *   3. Invalid/expired token
 *   4. API error response
 *   5. Empty token
 *   6. Backend username mapping from attributes
 *   7. NULL username parameter
 *   8. NULL attributes parameter
 *   9. Non-ServiceAccount token
 *  10. Malformed attributes JSON
 *  11. HTTP 500 error from TokenReview API
 *  12. Request timeout error handling
 *  13. Slow API response (simulates stuck server)
 */

#include <cstdlib>
#include <cstring>
#include <string>
#include <memory>
#include <chrono>

#include "tap.h"

// Include plugin class and mock client
#include "../../../plugins/MySQL_AuthPlugin/k8s/k8s_auth_plugin.h"
#include "../../../plugins/MySQL_AuthPlugin/k8s/mock_kubernetes_client.h"

// Helper to free result strings
void free_result(ProxySQL_Auth_Result& result) {
    if (result.backend_username) free((void*)result.backend_username);
    if (result.error_msg) free((void*)result.error_msg);
}

int main(int argc, char** argv) {
    plan(24);

    // Test 1: Valid token with matching username
    {
        auto mock = std::make_unique<MockKubernetesClient>();
        mock->addValidToken("valid-token-1", "proxysql", "testuser");

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s"})";
        ProxySQL_Auth_Result result = plugin.validate("proxysql/testuser", "valid-token-1", attrs);

        ok(result.success, "Test 1: Valid token with matching username should succeed");
        free_result(result);
        plugin.deinit();
    }

    // Test 2: Valid token with mismatched username
    {
        auto mock = std::make_unique<MockKubernetesClient>();
        mock->addValidToken("valid-token-2", "proxysql", "testuser");

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s"})";
        ProxySQL_Auth_Result result = plugin.validate("proxysql/wronguser", "valid-token-2", attrs);

        ok(!result.success, "Test 2: Mismatched username should fail");
        ok(result.error_msg && strstr(result.error_msg, "username mismatch") != nullptr,
           "Test 2: Error should mention username mismatch");
        free_result(result);
        plugin.deinit();
    }

    // Test 3: Invalid/expired token
    {
        auto mock = std::make_unique<MockKubernetesClient>();
        mock->addInvalidToken("expired-token");

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s"})";
        ProxySQL_Auth_Result result = plugin.validate("proxysql/testuser", "expired-token", attrs);

        ok(!result.success, "Test 3: Invalid token should fail");
        ok(result.error_msg && strstr(result.error_msg, "not authenticated") != nullptr,
           "Test 3: Error should mention authentication failure");
        free_result(result);
        plugin.deinit();
    }

    // Test 4: API error response
    {
        auto mock = std::make_unique<MockKubernetesClient>();
        mock->addErrorToken("error-token", "connection timeout");

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s"})";
        ProxySQL_Auth_Result result = plugin.validate("proxysql/testuser", "error-token", attrs);

        ok(!result.success, "Test 4: API error should fail");
        ok(result.error_msg && strstr(result.error_msg, "connection timeout") != nullptr,
           "Test 4: Error message should contain API error");
        free_result(result);
        plugin.deinit();
    }

    // Test 5: Empty token
    {
        auto mock = std::make_unique<MockKubernetesClient>();

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s"})";
        ProxySQL_Auth_Result result = plugin.validate("proxysql/testuser", "", attrs);

        ok(!result.success, "Test 5: Empty token should fail");
        ok(result.error_msg && strstr(result.error_msg, "empty token") != nullptr,
           "Test 5: Error should mention empty token");
        free_result(result);
        plugin.deinit();
    }

    // Test 6: Backend username mapping from attributes
    {
        auto mock = std::make_unique<MockKubernetesClient>();
        mock->addValidToken("token-with-mapping", "app", "myservice");

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s", "backend_username": "dbuser"})";
        ProxySQL_Auth_Result result = plugin.validate("app/myservice", "token-with-mapping", attrs);

        ok(result.success && result.backend_username &&
           strcmp(result.backend_username, "dbuser") == 0,
           "Test 6: Backend username mapping should work");
        free_result(result);
        plugin.deinit();
    }

    // Test 7: NULL username parameter
    {
        auto mock = std::make_unique<MockKubernetesClient>();

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s"})";
        ProxySQL_Auth_Result result = plugin.validate(nullptr, "some-token", attrs);

        ok(!result.success, "Test 7: NULL username should fail");
        ok(result.error_msg && strstr(result.error_msg, "missing required parameters") != nullptr,
           "Test 7: Error should mention missing parameters");
        free_result(result);
        plugin.deinit();
    }

    // Test 8: NULL attributes parameter
    {
        auto mock = std::make_unique<MockKubernetesClient>();

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        ProxySQL_Auth_Result result = plugin.validate("proxysql/testuser", "some-token", nullptr);

        ok(!result.success, "Test 8: NULL attributes should fail");
        ok(result.error_msg && strstr(result.error_msg, "missing required parameters") != nullptr,
           "Test 8: Error should mention missing parameters");
        free_result(result);
        plugin.deinit();
    }

    // Test 9: Non-ServiceAccount token (user token without system:serviceaccount: prefix)
    {
        auto mock = std::make_unique<MockKubernetesClient>();
        // Simulate a user token that authenticates but isn't a ServiceAccount
        TokenReviewResult user_token_result;
        user_token_result.success = true;
        user_token_result.authenticated = true;
        user_token_result.username = "user:admin";  // Not a ServiceAccount
        mock->addTokenResponse("user-token", user_token_result);

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s"})";
        ProxySQL_Auth_Result result = plugin.validate("proxysql/testuser", "user-token", attrs);

        ok(!result.success, "Test 9: Non-ServiceAccount token should fail");
        ok(result.error_msg && strstr(result.error_msg, "not a ServiceAccount token") != nullptr,
           "Test 9: Error should mention ServiceAccount");
        free_result(result);
        plugin.deinit();
    }

    // Test 10: Malformed attributes JSON
    {
        auto mock = std::make_unique<MockKubernetesClient>();
        mock->addValidToken("valid-token", "proxysql", "testuser");

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = "not valid json {{{";
        ProxySQL_Auth_Result result = plugin.validate("proxysql/testuser", "valid-token", attrs);

        ok(!result.success, "Test 10: Malformed JSON should fail");
        // JSON parse errors come from nlohmann::json
        ok(result.error_msg != nullptr, "Test 10: Should have error message");
        free_result(result);
        plugin.deinit();
    }

    // Test 11: HTTP 500 error from TokenReview API
    {
        auto mock = std::make_unique<MockKubernetesClient>();
        // Simulate HTTP 500 error (matches K8sHttpClient error format)
        mock->addErrorToken("token-500", "TokenReview API returned HTTP 500");

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s"})";
        ProxySQL_Auth_Result result = plugin.validate("proxysql/testuser", "token-500", attrs);

        ok(!result.success, "Test 11: HTTP 500 should fail");
        ok(result.error_msg && strstr(result.error_msg, "HTTP 500") != nullptr,
           "Test 11: Error should mention HTTP 500");
        free_result(result);
        plugin.deinit();
    }

    // Test 12: Request timeout error handling
    {
        auto mock = std::make_unique<MockKubernetesClient>();
        // Simulate curl timeout error (matches K8sHttpClient error format)
        mock->addErrorToken("token-timeout", "HTTP request failed: Timeout was reached");

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s"})";
        ProxySQL_Auth_Result result = plugin.validate("proxysql/testuser", "token-timeout", attrs);

        ok(!result.success, "Test 12: Timeout error should fail");
        ok(result.error_msg && strstr(result.error_msg, "Timeout") != nullptr,
           "Test 12: Error should mention timeout");
        free_result(result);
        plugin.deinit();
    }

    // Test 13: Slow API response (simulates stuck server)
    {
        auto mock = std::make_unique<MockKubernetesClient>();
        // Add a token that takes 100ms to respond
        mock->addSlowToken("slow-token", 100, "proxysql", "testuser");

        K8s_Auth_Plugin plugin(std::move(mock));
        plugin.init();

        const char* attrs = R"({"auth_plugin": "k8s"})";

        auto start = std::chrono::steady_clock::now();
        ProxySQL_Auth_Result result = plugin.validate("proxysql/testuser", "slow-token", attrs);
        auto end = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        ok(result.success, "Test 13: Slow token should eventually succeed");
        ok(elapsed_ms >= 100, "Test 13: Should have waited at least 100ms (actual: %ldms)", elapsed_ms);
        free_result(result);
        plugin.deinit();
    }

    return exit_status();
}
