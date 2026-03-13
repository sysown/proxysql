/**
 * @file auth_k8s.cpp
 * @brief Kubernetes ServiceAccount authentication plugin for ProxySQL
 *
 * Validates Kubernetes ServiceAccount JWT tokens via K8s TokenReview API.
 * Username must be in "namespace/serviceaccount" format and must match the token identity.
 *
 * Configuration:
 *   Environment variables (optional, for overriding in-cluster defaults):
 *     K8S_API_SERVER  - K8s API server URL (default: https://kubernetes.default.svc)
 *     K8S_CA_PATH     - Path to CA cert (default: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)
 *     K8S_TOKEN_PATH  - Path to SA token (default: /var/run/secrets/kubernetes.io/serviceaccount/token)
 *
 *   User attributes example:
 *     INSERT INTO mysql_users (username, password, attributes, frontend, backend)
 *     VALUES ('proxysql/testuser', '',
 *             '{"auth_plugin": "k8s", "backend_username": "dbuser"}',
 *             1, 0);
 *
 * The client sends their ServiceAccount JWT token as the password.
 * The username "proxysql/testuser" must match token's namespace and serviceaccount.
 */

#include "k8s_auth_plugin.h"
#include "k8s_http_client.h"

// Production plugin uses K8sHttpClient as the KubernetesClient implementation
class K8s_Auth_Plugin_Production : public K8s_Auth_Plugin {
public:
    K8s_Auth_Plugin_Production()
        : K8s_Auth_Plugin(std::make_unique<K8sHttpClient>()) {}
};

// Plugin exports
extern "C" {
    ProxySQL_Auth_Plugin* proxysql_mysql_auth_plugin_create() {
        return new K8s_Auth_Plugin_Production();
    }

    void proxysql_mysql_auth_plugin_destroy(ProxySQL_Auth_Plugin* plugin) {
        delete plugin;
    }
}
