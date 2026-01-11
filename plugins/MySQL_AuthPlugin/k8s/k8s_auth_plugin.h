/**
 * @file k8s_auth_plugin.h
 * @brief Kubernetes ServiceAccount authentication plugin class definition
 *
 * Separated into header for testability via dependency injection.
 */

#ifndef K8S_AUTH_PLUGIN_H
#define K8S_AUTH_PLUGIN_H

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <memory>

#include "../../../include/MySQL_AuthPlugin.h"
#include "../../../deps/json/json.hpp"
#include "kubernetes_client.h"

using json = nlohmann::json;

class K8s_Auth_Plugin : public ProxySQL_Auth_Plugin {
private:
    std::unique_ptr<KubernetesClient> k8s_client;

public:
    // Constructor for dependency injection (testing)
    explicit K8s_Auth_Plugin(std::unique_ptr<KubernetesClient> client)
        : k8s_client(std::move(client)) {}

    ~K8s_Auth_Plugin() override = default;

    bool init() override {
        if (!k8s_client->init()) {
            return false;
        }
        fprintf(stderr, "K8s Auth Plugin initialized\n");
        return true;
    }

    void deinit() override {
        k8s_client->deinit();
        fprintf(stderr, "K8s Auth Plugin destroyed\n");
    }

    const char* name() override {
        return "k8s";
    }

    void print_version() override {
        fprintf(stderr, "ProxySQL K8s Auth Plugin v1.0\n");
    }

    ProxySQL_Auth_Result validate(
        const char* username,
        const char* credential,
        const char* attributes
    ) override {
        ProxySQL_Auth_Result result = { false, nullptr, nullptr };

        if (!username || !credential || !attributes) {
            result.error_msg = strdup("missing required parameters");
            return result;
        }

        if (strlen(credential) == 0) {
            result.error_msg = strdup("empty token");
            return result;
        }

        try {
            json attrs = json::parse(attributes);

            // Call TokenReview API
            TokenReviewResult review = k8s_client->tokenReview(credential);

            if (!review.success) {
                result.error_msg = strdup(review.error.c_str());
                return result;
            }

            if (!review.authenticated) {
                result.error_msg = strdup("token not authenticated");
                return result;
            }

            // Parse token username: system:serviceaccount:<namespace>:<sa>
            const std::string prefix = "system:serviceaccount:";
            if (review.username.rfind(prefix, 0) != 0) {
                result.error_msg = strdup("token is not a ServiceAccount token");
                return result;
            }

            std::string sa_identity = review.username.substr(prefix.length());

            // Convert to "namespace/serviceaccount" format for comparison
            size_t colon_pos = sa_identity.find(':');
            if (colon_pos == std::string::npos) {
                result.error_msg = strdup("invalid ServiceAccount identity format");
                return result;
            }

            std::string expected_username = sa_identity.substr(0, colon_pos) + "/" + sa_identity.substr(colon_pos + 1);

            // Validate username matches token identity
            if (expected_username != username) {
                std::string err = "username mismatch: expected '" + expected_username + "', got '" + username + "'";
                result.error_msg = strdup(err.c_str());
                return result;
            }

            // Authentication successful
            result.success = true;

            // Check for backend_username in attributes (static mapping)
            auto backend_it = attrs.find("backend_username");
            if (backend_it != attrs.end()) {
                std::string bu = backend_it->get<std::string>();
                result.backend_username = strdup(bu.c_str());
            }

            return result;

        } catch (json::exception& e) {
            result.error_msg = strdup(e.what());
            return result;
        }
    }
};

#endif /* K8S_AUTH_PLUGIN_H */
