/**
 * @file MySQL_AuthPlugin.h
 * @brief Interface for ProxySQL per-user authentication plugins (MySQL only)
 *
 * Plugins are configured per-user via the `attributes` JSON field in mysql_users.
 *
 * Example:
 *   INSERT INTO mysql_users (username, attributes, frontend, backend)
 *   VALUES ('myuser', '{"auth_plugin": "myplugin", "backend_username": "dbuser", ...}', 1, 0);
 */

#ifndef MYSQL_AUTHPLUGIN_H
#define MYSQL_AUTHPLUGIN_H

#include <cstddef>

/**
 * @brief Result of authentication validation
 */
struct ProxySQL_Auth_Result {
    bool success;              // true if authentication succeeded
    char* backend_username;    // optional: map to different backend user (caller frees, NULL = same user)
    char* error_msg;           // optional: error message on failure (caller frees, NULL = generic error)
};

/**
 * @brief Base class for ProxySQL authentication plugins
 */
class ProxySQL_Auth_Plugin {
public:
    virtual ~ProxySQL_Auth_Plugin() {}

    /**
     * @brief Initialize the plugin (called once on load)
     * @return true on success
     */
    virtual bool init() { return true; }

    /**
     * @brief Cleanup the plugin (called once on unload)
     */
    virtual void deinit() {}

    /**
     * @brief Validate user credentials
     *
     * @param username    Username from client
     * @param credential  Clear-text credential from client (password, token, etc.)
     * @param attributes  JSON attributes from mysql_users.attributes
     *
     * @return ProxySQL_Auth_Result with success status and optional backend_username
     */
    virtual ProxySQL_Auth_Result validate(
        const char* username,
        const char* credential,
        const char* attributes
    ) = 0;

    /**
     * @brief Get plugin name
     */
    virtual const char* name() = 0;

    /**
     * @brief Print version info (called on load)
     */
    virtual void print_version() = 0;
};

// Plugin factory function type
extern "C" {
    typedef ProxySQL_Auth_Plugin* (*proxysql_mysql_auth_plugin_create_t)();
    typedef void (*proxysql_mysql_auth_plugin_destroy_t)(ProxySQL_Auth_Plugin*);
}

#endif /* MYSQL_AUTHPLUGIN_H */
