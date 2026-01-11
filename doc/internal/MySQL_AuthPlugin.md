# Per-User Authentication Plugins Design

## Overview

This document describes the per-user authentication plugin framework in ProxySQL. Users can authenticate using different methods (e.g., Kubernetes ServiceAccount tokens, static passwords) by setting the `auth_plugin` attribute in `mysql_users.attributes`.

## Motivation

ProxySQL already supports:
1. **Client/backend auth separation**: Clients can authenticate to ProxySQL differently than ProxySQL authenticates to backends
2. **LDAP authentication**: Via an enterprise plugin loaded at startup
3. **User attributes**: JSON field in `mysql_users` for per-user configuration

This framework extends the architecture to support per-user auth plugin selection for users in `mysql_users`, enabling scenarios like Kubernetes ServiceAccount authentication.

### Use Case: Kubernetes ServiceAccount Authentication

Applications running in Kubernetes authenticate to ProxySQL using their ServiceAccount token:

```
Client (SA token) → ProxySQL (validates via TokenReview API) → MariaDB (regular credentials)
```

Benefits:
- No static passwords in application configs
- Tokens are short-lived and auto-rotated
- Identity tied to Kubernetes workload identity

## User Configuration

### Enabling Auth Plugin for a User

```sql
-- User with static auth plugin (frontend-only)
INSERT INTO mysql_users (username, password, attributes, default_hostgroup, frontend, backend)
VALUES (
    'app_user',
    '',
    '{"auth_plugin": "static", "static_password": "secret123", "backend_username": "dbuser"}',
    1, 1, 0
);

-- Backend-only user for the actual database connection
INSERT INTO mysql_users (username, password, default_hostgroup, frontend, backend)
VALUES ('dbuser', 'db_password', 1, 0, 1);

LOAD MYSQL USERS TO RUNTIME;
```

### Standard Users (Unchanged)

```sql
-- Users without auth_plugin attribute use standard password auth
INSERT INTO mysql_users (username, password, default_hostgroup)
VALUES ('regular_user', 'password123', 1);
```

## ProxySQL Configuration

### Config File (`proxysql.cfg`)

```
# Existing LDAP plugin (unchanged, backward compatible)
ldap_auth_plugin="/path/to/ldap.so"

# Per-user auth plugins (comma-separated paths)
auth_plugins="/usr/lib/proxysql/auth_static.so"
```

## Plugin Interface

Plugins implement the `ProxySQL_Auth_Plugin` interface defined in `include/MySQL_AuthPlugin.h`.

### Interface Definition

```cpp
struct ProxySQL_Auth_Result {
    bool success;              // true if authentication succeeded
    char* backend_username;    // optional: map to different backend user (caller frees)
    char* error_msg;           // optional: error message on failure (caller frees)
};

class ProxySQL_Auth_Plugin {
public:
    virtual ~ProxySQL_Auth_Plugin() {}

    // Initialize the plugin (called once on load)
    virtual bool init() { return true; }

    // Cleanup the plugin (called once on unload)
    virtual void deinit() {}

    // Validate user credentials
    // Returns ProxySQL_Auth_Result with success status and optional backend_username
    virtual ProxySQL_Auth_Result validate(
        const char* username,     // Username from client
        const char* credential,   // Clear-text credential (password, token, etc.)
        const char* attributes    // JSON attributes from mysql_users.attributes
    ) = 0;

    // Get plugin name (must match "auth_plugin" value in attributes)
    virtual const char* name() = 0;

    // Print version info (called on load)
    virtual void print_version() = 0;
};
```

### Required Exports

Each plugin `.so` must export:

```cpp
extern "C" {
    // Create plugin instance
    ProxySQL_Auth_Plugin* proxysql_mysql_auth_plugin_create();

    // Destroy plugin instance
    void proxysql_mysql_auth_plugin_destroy(ProxySQL_Auth_Plugin* plugin);
}
```

## Included Plugins

### Static Auth Plugin (`auth_static.so`)

For testing and simple use cases. Validates credentials against a static password in attributes.

```sql
INSERT INTO mysql_users (username, password, attributes, frontend, backend)
VALUES ('testuser', '',
        '{"auth_plugin": "static", "static_password": "secret123", "backend_username": "dbuser"}',
        1, 0);
```

**Source**: `plugins/MySQL_AuthPlugin/static/auth_static.cpp`

### Kubernetes Auth Plugin (`auth_k8s.so`)

Validates Kubernetes ServiceAccount JWT tokens via the K8s TokenReview API.

```sql
INSERT INTO mysql_users (username, password, attributes, frontend, backend)
VALUES ('proxysql/myapp', '',
        '{"auth_plugin": "k8s", "backend_username": "dbuser"}',
        1, 0);
```

Username format: `<namespace>/<serviceaccount>` - must match the token's identity.

**Environment Variables** (optional, for overriding in-cluster defaults):
- `K8S_API_SERVER` - K8s API server URL (default: `https://kubernetes.default.svc`)
- `K8S_CA_PATH` - Path to CA cert (default: `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`)
- `K8S_TOKEN_PATH` - Path to SA token (default: `/var/run/secrets/kubernetes.io/serviceaccount/token`)
- `K8S_TIMEOUT_MS` - HTTP request timeout in milliseconds (default: `5000`)

**Source**: `plugins/MySQL_AuthPlugin/k8s/`

## Implementation Details

### Plugin Loading

**File**: `src/main.cpp` - `LoadPlugins()`

Plugins are loaded on startup from the comma-separated `auth_plugins` config value:

```cpp
std::map<std::string, ProxySQL_Auth_Plugin*> GloAuthPlugins;

// For each plugin path:
void* handle = dlopen(plugin_path.c_str(), RTLD_NOW);
auto create_func = (proxysql_mysql_auth_plugin_create_t)
    dlsym(handle, "proxysql_mysql_auth_plugin_create");
ProxySQL_Auth_Plugin* plugin = create_func();
plugin->init();
GloAuthPlugins[plugin->name()] = plugin;
```

### Authentication Flow

**File**: `lib/MySQL_Protocol.cpp` - `PPHR_1()`

```cpp
// 1. Lookup user in mysql_users
account_details = GloMyAuth->lookup(username, USERNAME_FRONTEND, dup_details);

// 2. Check for per-user auth plugin
ProxySQL_Auth_Plugin* user_auth_plugin = get_user_auth_plugin(account_details.attributes, username);

if (user_auth_plugin) {
    if (switching_auth_stage == 0) {
        // 3. Send AUTH_SWITCH to get clear-text credential
        generate_pkt_auth_switch_request(true, NULL, NULL);
        return;
    }

    // 4. After AUTH_SWITCH, validate via plugin
    ProxySQL_Auth_Result result = user_auth_plugin->validate(username, password, attributes);

    if (result.success) {
        // 5. Auth successful - use backend_username if provided
        if (result.backend_username) {
            // Map to different backend user
        }
    }
}
```

## Authentication Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Client connects                                              │
│    Username: "app_user"                                         │
│    Password: <initial - may be hashed>                          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. ProxySQL: Lookup user in mysql_users                         │
│    Found: attributes = '{"auth_plugin": "static", ...}'         │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. ProxySQL: Check GloAuthPlugins["static"]                     │
│    - Not found? → Error: "Auth plugin 'static' not loaded"      │
│    - Found? → Continue                                          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. ProxySQL: AUTH_SWITCH to mysql_clear_password                │
│    Sends: 0xFE + "mysql_clear_password" + 0x00                  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. Client: Resends password in clear text                       │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. ProxySQL: Call plugin->validate(username, password, attrs)   │
│    Plugin compares password against static_password in attrs    │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
┌───────────────────────────┐ ┌───────────────────────────────────┐
│ 7a. Validation SUCCESS    │ │ 7b. Validation FAILED             │
│     - Auth complete       │ │     - Return auth error to client │
│     - Use backend_username│ │                                   │
└───────────────────────────┘ └───────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. ProxySQL: Connect to backend with mapped credentials         │
│    Frontend "app_user" → Backend "dbuser"                       │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
plugins/MySQL_AuthPlugin/
├── static/
│   ├── auth_static.cpp      # Static password auth plugin
│   └── Makefile
└── k8s/
    ├── auth_k8s.cpp         # K8s auth plugin entry point
    ├── k8s_auth_plugin.h    # Plugin class (testable)
    ├── kubernetes_client.h  # Abstract K8s client interface
    ├── k8s_http_client.h    # Production HTTP client
    ├── mock_kubernetes_client.h  # Mock for unit tests
    └── Makefile
```

## Testing

### Integration Tests

Static plugin has integration tests requiring ProxySQL and MySQL:

```bash
# Run integration tests
./test/tap/tests/run_mysql_authplugin_test.sh
```

**Source**: `test/tap/tests/test_mysql_authplugin-t.cpp`

### Unit Tests (K8s Plugin)

K8s plugin has unit tests using mock dependency injection:

```bash
# Build and run unit tests
make build_tap_tests
./test/tap/tests/unit-k8s_auth_plugin-t
```

**Source**: `test/tap/tests/unit-k8s_auth_plugin-t.cpp`

## Backward Compatibility

| Aspect | Behavior |
|--------|----------|
| Existing `ldap_auth_plugin` config | Unchanged, still works |
| Existing `GloMyLdapAuth` global | Unchanged, still works |
| Users without `auth_plugin` attribute | Standard password auth |
| LDAP "user not found" flow | Unchanged |
| Existing mysql_users entries | No migration needed |

## Security Considerations

1. **Clear-text tokens**: Tokens are sent in clear after AUTH_SWITCH. TLS should be required for production.
2. **Token validation**: Plugins should validate tokens against trusted sources (K8s API, OAuth provider).
3. **Backend credentials**: Backend users should have strong passwords and limited privileges.
4. **Plugin trust**: Only load plugins from trusted paths.

## Future Enhancements

1. **Admin commands**: `SHOW AUTH PLUGINS` to list loaded plugins
2. **Runtime reload**: Reload plugins without restart
3. **Plugin variables**: Per-plugin configuration via admin interface
4. **Metrics**: Authentication stats per plugin

## References

- [ProxySQL Users Configuration](https://proxysql.com/documentation/users-configuration/)
- [ProxySQL Password Management](https://proxysql.com/documentation/password-management/)
- [MySQL Authentication Plugins](https://dev.mysql.com/doc/refman/8.0/en/pluggable-authentication.html)
- [Kubernetes ServiceAccount Tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens)
- [Kubernetes TokenReview API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
