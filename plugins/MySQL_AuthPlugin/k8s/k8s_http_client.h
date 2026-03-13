/**
 * @file k8s_http_client.h
 * @brief Real Kubernetes client implementation using HTTP/curl
 */

#ifndef K8S_HTTP_CLIENT_H
#define K8S_HTTP_CLIENT_H

#include "kubernetes_client.h"
#include <fstream>
#include <sstream>
#include <curl/curl.h>
#include "../../../deps/json/json.hpp"

using json = nlohmann::json;

// In-cluster defaults
static const char* DEFAULT_K8S_API_SERVER = "https://kubernetes.default.svc";
static const char* DEFAULT_K8S_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
static const char* DEFAULT_K8S_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";
static const long DEFAULT_K8S_TIMEOUT_MS = 5000;  // 5 seconds

class K8sHttpClient : public KubernetesClient {
private:
    bool curl_initialized = false;
    std::string api_server;
    std::string ca_path;
    std::string token_path;
    std::string sa_token;
    long timeout_ms = DEFAULT_K8S_TIMEOUT_MS;

    static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t realsize = size * nmemb;
        std::string* str = static_cast<std::string*>(userp);
        str->append(static_cast<char*>(contents), realsize);
        return realsize;
    }

    bool read_file(const std::string& path, std::string& contents) {
        std::ifstream file(path);
        if (!file.is_open()) return false;
        std::stringstream buffer;
        buffer << file.rdbuf();
        contents = buffer.str();
        return true;
    }

public:
    K8sHttpClient() = default;
    ~K8sHttpClient() override { deinit(); }

    bool init() override {
        CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (res != CURLE_OK) {
            fprintf(stderr, "K8sHttpClient: curl_global_init failed: %s\n", curl_easy_strerror(res));
            return false;
        }
        curl_initialized = true;

        const char* env_val;
        env_val = getenv("K8S_API_SERVER");
        api_server = env_val ? env_val : DEFAULT_K8S_API_SERVER;

        env_val = getenv("K8S_CA_PATH");
        ca_path = env_val ? env_val : DEFAULT_K8S_CA_PATH;

        env_val = getenv("K8S_TOKEN_PATH");
        token_path = env_val ? env_val : DEFAULT_K8S_TOKEN_PATH;

        env_val = getenv("K8S_TIMEOUT_MS");
        if (env_val) {
            timeout_ms = std::atol(env_val);
            if (timeout_ms <= 0) timeout_ms = DEFAULT_K8S_TIMEOUT_MS;
        }

        if (!read_file(token_path, sa_token)) {
            fprintf(stderr, "K8sHttpClient: warning: could not read SA token from %s\n", token_path.c_str());
        }

        fprintf(stderr, "K8sHttpClient initialized (api_server=%s, timeout_ms=%ld)\n", api_server.c_str(), timeout_ms);
        return true;
    }

    void deinit() override {
        if (curl_initialized) {
            curl_global_cleanup();
            curl_initialized = false;
        }
    }

    TokenReviewResult tokenReview(const std::string& token) override {
        TokenReviewResult result = {false, false, "", ""};

        // Refresh SA token (may have been rotated)
        if (!read_file(token_path, sa_token)) {
            result.error = "failed to read SA token for API auth";
            return result;
        }

        CURL* curl = curl_easy_init();
        if (!curl) {
            result.error = "failed to initialize curl";
            return result;
        }

        // Build TokenReview request
        json request_body;
        request_body["apiVersion"] = "authentication.k8s.io/v1";
        request_body["kind"] = "TokenReview";
        request_body["spec"]["token"] = token;
        std::string body = request_body.dump();

        std::string url = api_server + "/apis/authentication.k8s.io/v1/tokenreviews";
        std::string response;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        std::string auth_header = "Authorization: Bearer " + sa_token;
        headers = curl_slist_append(headers, auth_header.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path.c_str());

        CURLcode res = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            result.error = std::string("HTTP request failed: ") + curl_easy_strerror(res);
            return result;
        }

        if (http_code != 200 && http_code != 201) {
            result.error = "TokenReview API returned HTTP " + std::to_string(http_code);
            return result;
        }

        // Parse response
        try {
            json resp = json::parse(response);

            if (!resp.contains("status") || !resp["status"].contains("authenticated")) {
                result.error = "invalid TokenReview response";
                return result;
            }

            result.success = true;
            result.authenticated = resp["status"]["authenticated"].get<bool>();

            if (result.authenticated && resp["status"].contains("user") &&
                resp["status"]["user"].contains("username")) {
                result.username = resp["status"]["user"]["username"].get<std::string>();
            }
        } catch (json::exception& e) {
            result.error = e.what();
            return result;
        }

        return result;
    }
};

#endif /* K8S_HTTP_CLIENT_H */
