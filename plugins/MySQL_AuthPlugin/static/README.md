# ProxySQL Static Auth Plugin

A simple authentication plugin that validates credentials against a static password stored in the user's `attributes` JSON field.

## Use Cases

### 1. ProxySQL-Only Users

Create frontend users that don't exist in upstream MySQL databases. Multiple frontend users can map to a single backend database user:

```
app-team-a (frontend) ──┐
                        ├──► app_backend (backend) ──► MySQL
app-team-b (frontend) ──┘
```

This enables:
- **Credential isolation**: Each team/service gets unique credentials without creating MySQL users
- **Credential rotation**: Rotate frontend passwords without touching the database
- **Access auditing**: Track which frontend user connected via ProxySQL logs

### 2. Testing and Development

Test the per-user auth plugin system without external dependencies (no K8s, no LDAP, etc.).

## Build

```bash
cd plugins/MySQL_AuthPlugin/static
make
```

This produces `auth_static.so`.

## Configuration

### 1. Configure ProxySQL to load the plugin

In `proxysql.cfg`:

```
auth_plugins="/path/to/auth_static.so"
```

### 2. Create a user with static auth

```sql
INSERT INTO mysql_users (username, password, attributes, default_hostgroup, frontend, backend)
VALUES (
    'testuser',
    '',
    '{"auth_plugin": "static", "static_password": "secret123"}',
    1,
    1,
    0
);

LOAD MYSQL USERS TO RUNTIME;
```

### 3. Connect

```bash
mysql -h 127.0.0.1 -P 6033 -u testuser -psecret123
```

## Attributes

| Attribute | Required | Description |
|-----------|----------|-------------|
| `auth_plugin` | Yes | Must be `"static"` |
| `static_password` | Yes | The password to validate against |
| `backend_username` | No | Map to a different backend user |

## Backend User Mapping

You can map the frontend user to a different backend user:

```sql
-- Frontend user authenticates with static password
INSERT INTO mysql_users (username, password, attributes, default_hostgroup, frontend, backend)
VALUES (
    'app_frontend',
    '',
    '{"auth_plugin": "static", "static_password": "token123", "backend_username": "app_backend"}',
    1,
    1,
    0
);

-- Backend user for actual database connections
INSERT INTO mysql_users (username, password, default_hostgroup, frontend, backend)
VALUES ('app_backend', 'real_db_password', 1, 0, 1);

LOAD MYSQL USERS TO RUNTIME;
```
