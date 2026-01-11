/**
 * @file auth_static.cpp
 * @brief Static authentication plugin for ProxySQL
 *
 * Validates credentials against a static password in the user's attributes JSON.
 *
 * Configuration example:
 *   INSERT INTO mysql_users (username, password, attributes, frontend, backend)
 *   VALUES ('testuser', '',
 *           '{"auth_plugin": "static", "static_password": "secret123", "backend_username": "dbuser"}',
 *           1, 0);
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../../../include/MySQL_AuthPlugin.h"
#include "../../../deps/json/json.hpp"

using json = nlohmann::json;

class Static_Auth_Plugin : public ProxySQL_Auth_Plugin {
public:
    Static_Auth_Plugin() {}
    ~Static_Auth_Plugin() override {}

    bool init() override {
        fprintf(stderr, "Static Auth Plugin initialized\n");
        return true;
    }

    void deinit() override {
        fprintf(stderr, "Static Auth Plugin destroyed\n");
    }

    const char* name() override {
        return "static";
    }

    void print_version() override {
        fprintf(stderr, "ProxySQL Static Auth Plugin v1.0\n");
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

        try {
            json attrs = json::parse(attributes);

            // Get static_password from attributes
            auto it = attrs.find("static_password");
            if (it == attrs.end()) {
                result.error_msg = strdup("'static_password' not found in attributes");
                return result;
            }

            std::string expected_password = it->get<std::string>();

            // Compare passwords
            if (expected_password != credential) {
                result.error_msg = strdup("password mismatch");
                return result;
            }

            // Authentication successful
            result.success = true;

            // Check for backend_username mapping
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

// Plugin exports
extern "C" {
    ProxySQL_Auth_Plugin* proxysql_mysql_auth_plugin_create() {
        return new Static_Auth_Plugin();
    }

    void proxysql_mysql_auth_plugin_destroy(ProxySQL_Auth_Plugin* plugin) {
        delete plugin;
    }
}
