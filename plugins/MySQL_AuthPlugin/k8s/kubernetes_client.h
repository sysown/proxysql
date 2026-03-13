/**
 * @file kubernetes_client.h
 * @brief Abstract interface for Kubernetes API operations
 *
 * Provides an abstraction layer for K8s API calls, enabling:
 * - Real implementation using HTTP/curl for production
 * - Mock implementation for unit testing
 */

#ifndef KUBERNETES_CLIENT_H
#define KUBERNETES_CLIENT_H

#include <string>

/**
 * @brief Result of a TokenReview API call
 */
struct TokenReviewResult {
    bool success;           // API call succeeded
    bool authenticated;     // Token is valid
    std::string username;   // e.g., "system:serviceaccount:namespace:sa"
    std::string error;      // Error message if !success
};

/**
 * @brief Abstract interface for Kubernetes API operations
 */
class KubernetesClient {
public:
    virtual ~KubernetesClient() = default;

    /**
     * @brief Initialize the client
     * @return true on success
     */
    virtual bool init() = 0;

    /**
     * @brief Cleanup resources
     */
    virtual void deinit() = 0;

    /**
     * @brief Validate a ServiceAccount token via TokenReview API
     * @param token The JWT token to validate
     * @return TokenReviewResult with authentication status and user info
     */
    virtual TokenReviewResult tokenReview(const std::string& token) = 0;
};

#endif /* KUBERNETES_CLIENT_H */
