/**
 * @file mock_kubernetes_client.h
 * @brief Mock Kubernetes client for unit testing
 */

#ifndef MOCK_KUBERNETES_CLIENT_H
#define MOCK_KUBERNETES_CLIENT_H

#include "kubernetes_client.h"
#include <map>
#include <thread>
#include <chrono>

class MockKubernetesClient : public KubernetesClient {
private:
    // Map token -> TokenReviewResult
    std::map<std::string, TokenReviewResult> token_responses;
    // Map token -> delay in milliseconds
    std::map<std::string, int> token_delays;
    TokenReviewResult default_response;
    int default_delay_ms = 0;

public:
    MockKubernetesClient() {
        default_response = {false, false, "", "token not found in mock"};
    }

    ~MockKubernetesClient() override = default;

    bool init() override {
        return true;
    }

    void deinit() override {
    }

    /**
     * @brief Add a canned response for a specific token
     */
    void addTokenResponse(const std::string& token, const TokenReviewResult& response) {
        token_responses[token] = response;
    }

    /**
     * @brief Add a valid token with specified identity
     */
    void addValidToken(const std::string& token, const std::string& ns, const std::string& sa) {
        TokenReviewResult result;
        result.success = true;
        result.authenticated = true;
        result.username = "system:serviceaccount:" + ns + ":" + sa;
        token_responses[token] = result;
    }

    /**
     * @brief Add an invalid/expired token
     */
    void addInvalidToken(const std::string& token) {
        TokenReviewResult result;
        result.success = true;
        result.authenticated = false;
        token_responses[token] = result;
    }

    /**
     * @brief Simulate API error for a token
     */
    void addErrorToken(const std::string& token, const std::string& error) {
        TokenReviewResult result;
        result.success = false;
        result.error = error;
        token_responses[token] = result;
    }

    /**
     * @brief Add a slow token that delays response by specified milliseconds
     */
    void addSlowToken(const std::string& token, int delay_ms, const std::string& ns, const std::string& sa) {
        addValidToken(token, ns, sa);
        token_delays[token] = delay_ms;
    }

    /**
     * @brief Set default delay for all responses
     */
    void setDefaultDelay(int delay_ms) {
        default_delay_ms = delay_ms;
    }

    TokenReviewResult tokenReview(const std::string& token) override {
        // Check for per-token delay
        auto delay_it = token_delays.find(token);
        int delay = (delay_it != token_delays.end()) ? delay_it->second : default_delay_ms;

        if (delay > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }

        auto it = token_responses.find(token);
        if (it != token_responses.end()) {
            return it->second;
        }
        return default_response;
    }

    /**
     * @brief Clear all canned responses
     */
    void clear() {
        token_responses.clear();
    }
};

#endif /* MOCK_KUBERNETES_CLIENT_H */
