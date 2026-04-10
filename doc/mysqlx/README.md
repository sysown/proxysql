# ProxySQL MySQL X Protocol Plugin — Reference Manual

## 1. Overview

The **mysqlx plugin** is a dynamically loaded plugin that adds MySQL X Protocol support to ProxySQL. X Protocol is MySQL's modern document-oriented protocol, exposed on port 33060 by default, supporting CRUD operations on documents and SQL statements.

### Current Scope (Phase 1)

| Feature | Status |
|---------|--------|
| MYSQL41 authentication | Supported |
| PLAIN authentication | Supported (insecure without TLS) |
| Pass-through query routing | Supported |
| TLS | Not available |
| Connection pooling | Not available (1:1 frontend/backend mapping) |
| CRUD / Document API | Not available (SQL statements only) |
| Query rules / policy engine | Not available |
| Cluster sync | Not available |

The mysqlx plugin differs from ProxySQL's built-in classic MySQL protocol support: it listens on a separate port, speaks the X Protocol binary format (Protobuf-based), and has its own configuration tables for users, routes, and backend endpoints.

## 2. Installation and Loading

### 2.1. Building the Plugin

```bash
cd plugins/mysqlx && make
```

This produces `ProxySQL_MySQLX_Plugin.so`.

### 2.2. Configuration

Add the plugin path to the `plugins` array in `proxysql.cnf`:

```
plugins = (
    "/path/to/ProxySQL_MySQLX_Plugin.so"
)
```

The `plugins` array is read during startup. Each entry is a path to a plugin `.so` file.

### 2.3. Loading Order

The plugin is loaded after the Admin module initializes. The sequence is:

1. ProxySQL reads `proxysql.cnf`.
2. The `plugins` array is parsed into `GloVars.plugin_modules`.
3. The Admin module initializes (creates SQLite databases).
4. The plugin manager calls `dlopen()` on each plugin path.
5. The plugin's `init()` function registers tables and commands.
6. The plugin's `start()` function loads configuration from runtime tables and starts listeners.

## 3. Admin Tables

### 3.1. `mysqlx_users` (Configuration Table)

Define X Protocol user accounts and authentication settings.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| username | VARCHAR NOT NULL | — | Proxy username (must exist in `mysql_users`) |
| active | INT CHECK (0,1) | 1 | Whether this user entry is active |
| require_tls | INT CHECK (0,1) | 0 | Require TLS for X Protocol connections (not enforced in Phase 1) |
| allowed_auth_methods | VARCHAR | `'MYSQL41,PLAIN'` | Comma-separated list of allowed authentication methods |
| default_route | VARCHAR | `''` | Default route name for this user |
| policy_profile | VARCHAR | `''` | Policy profile name (reserved for future use) |
| backend_auth_mode | VARCHAR CHECK | `'mapped'` | Backend authentication mode: `mapped`, `service_account`, or `pass_through` |
| backend_username | VARCHAR | `''` | Backend username (used in `service_account` mode) |
| backend_password | VARCHAR | `''` | Backend password (used in `service_account` mode) |
| attributes | VARCHAR | `''` | JSON attributes for future extensions |

### 3.2. `runtime_mysqlx_users` (Runtime Table)

Mirror of `mysqlx_users` loaded into runtime memory. Populated by `LOAD MYSQLX USERS TO RUNTIME`.

### 3.3. `mysqlx_routes` (Configuration Table)

Define X Protocol listener routes.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| name | VARCHAR NOT NULL | — | Route name (unique identifier) |
| bind | VARCHAR NOT NULL | `'0.0.0.0:33060'` | Listen address and port. Supports IPv4 (`0.0.0.0:33060`), IPv6 (`[::1]:33060`), and `hostname:port` |
| destination_hostgroup | INT | `0` | Target hostgroup for backend connections |
| fallback_hostgroup | INT | `-1` | Fallback hostgroup when primary has no available servers (`-1` = disabled) |
| strategy | VARCHAR | `'first_available'` | Server selection strategy: `first_available` or `round_robin` |
| active | INT CHECK (0,1) | `1` | Whether this route is active |
| attributes | VARCHAR | `''` | JSON attributes for future extensions |

### 3.4. `runtime_mysqlx_routes` (Runtime Table)

Mirror of `mysqlx_routes`. Populated by `LOAD MYSQLX ROUTES TO RUNTIME`.

### 3.5. `mysqlx_backend_endpoints` (Configuration Table)

Maps backend servers to their X Protocol ports.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| hostname | VARCHAR NOT NULL | — | Backend server hostname or IP |
| mysql_port | INT | `3306` | Classic MySQL port |
| mysqlx_port | INT | `33060` | X Protocol port on the backend |
| use_ssl | INT CHECK (0,1) | `0` | Use SSL for backend X Protocol connection (not enforced in Phase 1) |
| attributes | VARCHAR | `''` | JSON attributes |

### 3.6. `runtime_mysqlx_backend_endpoints` (Runtime Table)

Mirror of `mysqlx_backend_endpoints`. Populated by `LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME`.

### 3.7. `stats_mysqlx_routes` (Statistics Table)

Per-route connection statistics.

| Column | Type | Description |
|--------|------|-------------|
| name | VARCHAR | Route name |
| destination_hostgroup | INT | Target hostgroup |
| ConnOK | INT | Successful connections |
| ConnERR | INT | Failed connections |
| ConnUsed | INT | Active connections |
| Bytes_data_sent | INT | Bytes sent to backend |
| Bytes_data_recv | INT | Bytes received from backend |

### 3.8. `stats_mysqlx_processlist` (Statistics Table)

Current active sessions (registered but not populated in Phase 1).

## 4. Admin Commands

All commands follow the standard ProxySQL admin convention.

### 4.1. LOAD Commands (Configuration → Runtime)

```sql
LOAD MYSQLX USERS TO RUNTIME;
LOAD MYSQLX ROUTES TO RUNTIME;
LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME;
```

Aliases: `TO RUN`, `FROM MEMORY`, `FROM MEM`.

### 4.2. SAVE Commands (Runtime → Configuration)

```sql
SAVE MYSQLX USERS TO MEMORY;
SAVE MYSQLX ROUTES TO MEMORY;
SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY;
```

Aliases: `TO MEM`, `FROM RUNTIME`, `FROM RUN`.

## 5. Authentication

### 5.1. Supported Methods (Phase 1)

| Method | Description |
|--------|-------------|
| **MYSQL41** | Challenge-response using double-SHA1. Recommended for production. The password is never sent in cleartext. |
| **PLAIN** | Password sent in cleartext. Should only be used over TLS (not available in Phase 1). |

### 5.2. Authentication Flow

1. Client connects to the X Protocol port.
2. Server sends `CapabilitiesGet` (available auth methods).
3. Client sends `CapabilitiesSet` (chosen auth method).
4. Server sends `AuthenticateStart` with a 20-byte random challenge.
5. Client sends `AuthContinue` with the MYSQL41 scramble response.
6. Server verifies the scramble and resolves identity via `MysqlxConfigStore`.
7. On success: `AuthenticateOk`. On failure: `Error`.

### 5.3. Dual-Mode Identity Resolution

The plugin uses a two-stage identity resolution:

1. **Canonical lookup**: Find the user in `runtime_mysql_users` (must have `frontend=1` and `active=1`).
2. **X Protocol overlay**: If the user exists in `runtime_mysqlx_users`, merge the overlay settings (`allowed_auth_methods`, `backend_auth_mode`, `default_route`, etc.).

If a user exists in `mysql_users` but not `mysqlx_users`, they can still connect with default X Protocol settings (all auth methods, mapped backend auth).

### 5.4. Backend Authentication Modes

| Mode | Description |
|------|-------------|
| **mapped** (default) | Use the credentials from `mysql_users.backend_username` / `mysql_users.backend_password`. |
| **service_account** | Use explicit `mysqlx_users.backend_username` / `mysqlx_users.backend_password`. |
| **pass_through** | Forward the client's credentials to the backend. **Not supported in Phase 1** — returns error. |

## 6. Routing

### 6.1. Route Matching

When a client connects to an X Protocol listener:

1. The listener's bind address is matched to a route name.
2. The route's `destination_hostgroup` determines which backend server group to use.
3. Server selection uses the route's `strategy`:
   - `first_available`: Always pick the first online server.
   - `round_robin`: Cycle through online servers.

### 6.2. Backend Endpoint Resolution

For each backend server in the target hostgroup:

1. Check `mysqlx_backend_endpoints` for an X Protocol port override.
2. If no override exists, use the default `mysqlx_port=33060`.
3. Connect to the backend on the resolved X Protocol port.

### 6.3. Fallback Hostgroups

If `fallback_hostgroup` is set (not `-1`) and the primary hostgroup has no online servers, the plugin tries the fallback hostgroup.

## 7. Quick Start Example

```sql
-- Step 1: Ensure the plugin is loaded (in proxysql.cnf):
--   plugins=("/path/to/ProxySQL_MySQLX_Plugin.so")

-- Step 2: Add a backend MySQL 8.x server.
INSERT INTO mysql_servers (hostgroup_id, hostname, port, weight)
    VALUES (0, '10.0.0.1', 3306, 1);
LOAD MYSQL SERVERS TO RUNTIME;

-- Step 3: Register the backend's X Protocol port.
INSERT INTO mysqlx_backend_endpoints (hostname, mysql_port, mysqlx_port)
    VALUES ('10.0.0.1', 3306, 33060);
LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME;

-- Step 4: Create a route listening on port 33060.
INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, strategy)
    VALUES ('rw', '0.0.0.0:33060', 0, 'round_robin');
LOAD MYSQLX ROUTES TO RUNTIME;

-- Step 5: Allow root to connect via X Protocol.
INSERT INTO mysqlx_users (username, allowed_auth_methods)
    VALUES ('root', 'MYSQL41');
LOAD MYSQLX USERS TO RUNTIME;
```

Connect with MySQL Shell:

```bash
mysqlsh root@127.0.0.1:33060 --sql
```

## 8. Limitations (Phase 1)

| Limitation | Detail |
|------------|--------|
| No TLS | PLAIN auth sends passwords in cleartext. |
| No connection pooling | 1:1 frontend/backend mapping; each client connection opens a backend connection. |
| No query rules or policy engine | All traffic is routed based on route configuration only. |
| No cluster sync | MYSQLX tables are not replicated between ProxySQL nodes. |
| No Group Replication notifications | Not supported. |
| No prepared statement support | Not supported over X Protocol. |
| No CRUD / Document API | SQL statements only. |
| `pass_through` backend auth not implemented | Returns error if used. |
| `stats_mysqlx_processlist` not populated | Table exists but contains no rows. |

## 9. Plugin ABI Version

The mysqlx plugin uses **ProxySQL Plugin ABI version 1**. It requires:

- Same C++ compiler and standard library as the ProxySQL core build.
- Same `-std=` flag (C++17).
- Protobuf 3.21+ linked.
