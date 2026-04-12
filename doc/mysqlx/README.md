# ProxySQL MySQL X Protocol Plugin — Reference Manual (v2.0.0)

## 1. Overview

The **mysqlx plugin** is a dynamically loaded plugin that adds MySQL X Protocol support to ProxySQL. X Protocol is MySQL's modern document-oriented protocol, exposed on port 33060 by default, supporting CRUD operations on documents and SQL statements.

**Version 2.0.0** introduces an event-driven architecture with a configurable thread pool, protocol-aware frame forwarding for all 23 client message types, connection pooling, and TLS support.

### Feature Matrix (v2)

| Feature | Status |
|---------|--------|
| MYSQL41 authentication | Supported |
| PLAIN authentication | Supported (insecure without TLS) |
| Protocol-aware frame forwarding | Supported (all 23 message types) |
| Event-driven thread pool | Supported (configurable, default 4 threads) |
| Connection pooling | Supported (per-thread cache, hostgroup/user/schema matching) |
| TLS (frontend) | Supported (3 modes: Disabled/Preferred/Required, OpenSSL Memory BIO) |
| TLS (backend) | Supported (via CapabilitiesSet negotiation, PREFERRED mode) |
| CRUD / Document API | Forwarded to backend |
| Prepared Statements | Forwarded to backend |
| Cursors | Forwarded to backend |
| Query rules / policy engine | Not available |
| Cluster sync | Not available |

The mysqlx plugin differs from ProxySQL's built-in classic MySQL protocol support: it listens on a separate port, speaks the X Protocol binary format (Protobuf-based), and has its own configuration tables for users, routes, and backend endpoints.

## 2. Installation and Loading

### 2.1. Building the Plugin

```bash
cd plugins/mysqlx && make
```

This produces `mysqlx_plugin.so`.

### 2.2. Configuration

Add the plugin path to the `plugins` array in `proxysql.cnf`:

```
plugins = (
    "/path/to/mysqlx_plugin.so"
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
6. The plugin's `start()` function loads configuration from runtime tables, creates the thread pool, and starts listeners.

## 3. Admin Variables (v2)

### 3.1. `mysqlx_variables` Table

Global configuration variables for the mysqlx plugin.

| Variable | Default | Description |
|----------|---------|-------------|
| `mysqlx_thread_pool_size` | `4` | Number of event loop threads. Range: 1–64. Each thread runs an independent `poll()` loop handling thousands of concurrent sessions. |
| `mysqlx_connect_timeout` | `10000` | Backend connection timeout in milliseconds. Applied to non-blocking `connect()` + backend authentication. |
| `mysqlx_tls_mode` | `DISABLED` | Frontend TLS mode: `DISABLED`, `PREFERRED`, or `REQUIRED`. See [TLS Modes](#81-tls-modes). |
| `mysqlx_tls_cert` | *(empty)* | Path to TLS certificate file (PEM format). |
| `mysqlx_tls_key` | *(empty)* | Path to TLS private key file (PEM format). |
| `mysqlx_tls_ca` | *(empty)* | Path to CA certificate file for backend TLS verification. |
| `mysqlx_tls_backend_mode` | `DISABLED` | Backend TLS mode: `DISABLED` or `PREFERRED`. |
| `mysqlx_max_cached_connections_per_thread` | `100` | Maximum number of idle backend connections cached per thread. Connections are matched by hostgroup, user, and schema. |

```sql
-- View current variables
SELECT * FROM mysqlx_variables;

-- Update a variable
UPDATE mysqlx_variables SET variable_value='8' WHERE variable_name='mysqlx_thread_pool_size';
LOAD MYSQLX VARIABLES TO RUNTIME;
```

## 4. Admin Tables

### 4.1. `mysqlx_users` (Configuration Table)

Define X Protocol user accounts and authentication settings.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| username | VARCHAR NOT NULL | — | Proxy username (must exist in `mysql_users`) |
| active | INT CHECK (0,1) | 1 | Whether this user entry is active |
| require_tls | INT CHECK (0,1) | 0 | Require TLS for X Protocol connections |
| allowed_auth_methods | VARCHAR | `''` | Comma-separated list of allowed authentication methods (empty = all) |
| default_route | VARCHAR | `''` | Default route name for this user |
| policy_profile | VARCHAR | `''` | Policy profile name (reserved for future use) |
| backend_auth_mode | VARCHAR CHECK | `'mapped'` | Backend authentication mode: `mapped`, `service_account`, or `pass_through` |
| backend_username | VARCHAR | `''` | Backend username (used in `service_account` mode) |
| backend_password | VARCHAR | `''` | Backend password (used in `service_account` mode) |
| attributes | VARCHAR | `''` | JSON attributes for future extensions |
| comment | VARCHAR | `''` | User comment |

### 4.2. `runtime_mysqlx_users` (Runtime Table)

Mirror of `mysqlx_users` loaded into runtime memory. Populated by `LOAD MYSQLX USERS TO RUNTIME`.

### 4.3. `mysqlx_routes` (Configuration Table)

Define X Protocol listener routes.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| name | VARCHAR NOT NULL | — | Route name (unique identifier) |
| bind | VARCHAR NOT NULL | `'0.0.0.0:33060'` | Listen address and port |
| destination_hostgroup | INT | `0` | Target hostgroup for backend connections |
| fallback_hostgroup | INT | `-1` | Fallback hostgroup when primary has no available servers |
| strategy | VARCHAR | `'first_available'` | Server selection strategy: `first_available` or `round_robin` |
| active | INT CHECK (0,1) | `1` | Whether this route is active |
| attributes | VARCHAR | `''` | JSON attributes for future extensions |
| comment | VARCHAR | `''` | Route comment |

### 4.4. `runtime_mysqlx_routes` (Runtime Table)

Mirror of `mysqlx_routes`. Populated by `LOAD MYSQLX ROUTES TO RUNTIME`.

### 4.5. `mysqlx_backend_endpoints` (Configuration Table)

Maps backend servers to their X Protocol ports.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| hostname | VARCHAR NOT NULL | — | Backend server hostname or IP |
| mysql_port | INT | `3306` | Classic MySQL port |
| mysqlx_port | INT | `33060` | X Protocol port on the backend |
| use_ssl | INT CHECK (0,1) | `0` | Use SSL for backend X Protocol connection |
| attributes | VARCHAR | `''` | JSON attributes |
| comment | VARCHAR | `''` | Endpoint comment |

### 4.6. `runtime_mysqlx_backend_endpoints` (Runtime Table)

Mirror of `mysqlx_backend_endpoints`. Populated by `LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME`.

### 4.7. `stats_mysqlx_routes` (Statistics Table)

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

### 4.8. `stats_mysqlx_processlist` (Statistics Table)

Current active sessions.

## 5. Admin Commands

All commands follow the standard ProxySQL admin convention.

### 5.1. LOAD Commands (Configuration → Runtime)

```sql
LOAD MYSQLX USERS TO RUNTIME;
LOAD MYSQLX ROUTES TO RUNTIME;
LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME;
LOAD MYSQLX VARIABLES TO RUNTIME;
```

Aliases: `TO RUN`, `FROM MEMORY`, `FROM MEM`.

### 5.2. SAVE Commands (Runtime → Configuration)

```sql
SAVE MYSQLX USERS TO MEMORY;
SAVE MYSQLX ROUTES TO MEMORY;
SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY;
SAVE MYSQLX VARIABLES TO MEMORY;
```

Aliases: `TO MEM`, `FROM RUNTIME`, `FROM RUN`.

### 5.3. DISK Commands

#### 5.3.1. LOAD FROM DISK (Disk → Configuration)

```sql
LOAD MYSQLX USERS FROM DISK;
LOAD MYSQLX ROUTES FROM DISK;
LOAD MYSQLX BACKEND ENDPOINTS FROM DISK;
LOAD MYSQLX VARIABLES FROM DISK;
```

Loads persisted configuration from the on-disk SQLite database into the in-memory configuration tables.

#### 5.3.2. SAVE TO DISK (Configuration → Disk)

```sql
SAVE MYSQLX USERS TO DISK;
SAVE MYSQLX ROUTES TO DISK;
SAVE MYSQLX BACKEND ENDPOINTS TO DISK;
SAVE MYSQLX VARIABLES TO DISK;
```

Persists the in-memory configuration tables to the on-disk SQLite database, surviving ProxySQL restarts.

## 6. Authentication

### 6.1. Supported Methods

| Method | Description |
|--------|-------------|
| **MYSQL41** | Challenge-response using double-SHA1. Recommended for production. The password is never sent in cleartext. |
| **PLAIN** | Password sent in cleartext. Should only be used over TLS. |

### 6.2. Authentication Flow

1. Client connects to the X Protocol port.
2. Server sends `CapabilitiesGet` (available auth methods + optional TLS).
3. Client sends `CapabilitiesSet` (chosen auth method, optional TLS upgrade).
4. Server sends `AuthenticateStart` with a 20-byte random challenge.
5. Client sends `AuthContinue` with the MYSQL41 scramble response.
6. Server verifies the scramble and resolves identity via `MysqlxConfigStore`.
7. On success: `AuthenticateOk`. On failure: `Error`.

### 6.3. Dual-Mode Identity Resolution

The plugin uses a two-stage identity resolution:

1. **Canonical lookup**: Find the user in `runtime_mysql_users` (must have `frontend=1` and `active=1`).
2. **X Protocol overlay**: If the user exists in `runtime_mysqlx_users`, merge the overlay settings (`allowed_auth_methods`, `backend_auth_mode`, `default_route`, etc.).

If a user exists in `mysql_users` but not `mysqlx_users`, they can still connect with default X Protocol settings (all auth methods, mapped backend auth).

### 6.4. Backend Authentication Modes

| Mode | Description |
|------|-------------|
| **mapped** (default) | Use the credentials from `mysql_users.backend_username` / `mysql_users.backend_password`. |
| **service_account** | Use explicit `mysqlx_users.backend_username` / `mysqlx_users.backend_password`. |
| **pass_through** | Forward the client's credentials to the backend. **Not supported** — returns error. |

## 7. Supported X Protocol Message Types

The v2 plugin handles all 23 client message types defined in the X Protocol specification:

### Connection Management
| Type | Action |
|------|--------|
| `CON_CAPABILITIES_GET` | Handle locally — send server capabilities |
| `CON_CAPABILITIES_SET` | Handle locally — process TLS request |
| `CON_CLOSE` | Handle locally — close session |

### Session Management
| Type | Action |
|------|--------|
| `SESS_AUTHENTICATE_START` | Handle locally — start authentication |
| `SESS_AUTHENTICATE_CONTINUE` | Handle locally — continue authentication |
| `SESS_RESET` | Forward to backend — reset session state |
| `SESS_CLOSE` | Handle locally — close session |

### SQL Execution
| Type | Action |
|------|--------|
| `SQL_STMT_EXECUTE` | Forward to backend |

### CRUD Operations
| Type | Action |
|------|--------|
| `CRUD_FIND` | Forward to backend |
| `CRUD_INSERT` | Forward to backend |
| `CRUD_UPDATE` | Forward to backend |
| `CRUD_DELETE` | Forward to backend |

### Prepared Statements
| Type | Action |
|------|--------|
| `PREPARE_PREPARE` | Forward to backend (marks connection as having prepared statement) |
| `PREPARE_EXECUTE` | Forward to backend |
| `PREPARE_DEALLOCATE` | Forward to backend |

### Cursors
| Type | Action |
|------|--------|
| `CURSOR_OPEN` | Forward to backend |
| `CURSOR_FETCH` | Forward to backend |
| `CURSOR_CLOSE` | Forward to backend |

### Expect
| Type | Action |
|------|--------|
| `EXPECT_OPEN` | Forward to backend |
| `EXPECT_CLOSE` | Forward to backend |

### Views
| Type | Action |
|------|--------|
| `CRUD_CREATE_VIEW` | Forward to backend |
| `CRUD_MODIFY_VIEW` | Forward to backend |
| `CRUD_DROP_VIEW` | Forward to backend |

Unknown message types receive `ER_X_BAD_MESSAGE` error.

## 8. TLS

### 8.1. TLS Modes

| Mode | Description |
|------|-------------|
| `DISABLED` | No TLS capability advertised. Plaintext only. |
| `PREFERRED` | TLS capability advertised. Client chooses whether to upgrade. |
| `REQUIRED` | TLS capability advertised. Connection rejected if client does not upgrade. |

### 8.2. Configuration

```sql
UPDATE mysqlx_variables SET variable_value='PREFERRED' WHERE variable_name='mysqlx_tls_mode';
UPDATE mysqlx_variables SET variable_value='/path/to/cert.pem' WHERE variable_name='mysqlx_tls_cert';
UPDATE mysqlx_variables SET variable_value='/path/to/key.pem' WHERE variable_name='mysqlx_tls_key';
LOAD MYSQLX VARIABLES TO RUNTIME;
```

## 9. Connection Pooling

### 9.1. How It Works

Each thread maintains a local cache of idle backend connections. When a session needs a backend connection:

1. Check the thread-local cache for a matching connection (same hostgroup, user, schema).
2. If found, reuse it (skip connect + auth).
3. If not found, create a new connection with non-blocking `connect()`.
4. After query completion, return the connection to the cache if it's healthy.

### 9.2. Reuse Rules

A connection is eligible for reuse only if:
- Same hostgroup, user, and schema
- State is `IDLE`
- No active transaction
- No prepared statement

### 9.3. Configuration

```sql
-- Set max cached connections per thread (default: 100)
UPDATE mysqlx_variables SET variable_value='200' WHERE variable_name='mysqlx_max_cached_connections_per_thread';
LOAD MYSQLX VARIABLES TO RUNTIME;
```

## 10. Routing

### 10.1. Route Matching

When a client connects to an X Protocol listener:

1. The listener's bind address is matched to a route name.
2. The route's `destination_hostgroup` determines which backend server group to use.
3. Server selection uses the route's `strategy`:
   - `first_available`: Always pick the first online server.
   - `round_robin`: Cycle through online servers.

### 10.2. Backend Endpoint Resolution

For each backend server in the target hostgroup:

1. Check `mysqlx_backend_endpoints` for an X Protocol port override.
2. If no override exists, use the default `mysqlx_port=33060`.
3. Connect to the backend on the resolved X Protocol port.

### 10.3. Fallback Hostgroups

If `fallback_hostgroup` is set (not `-1`) and the primary hostgroup has no online servers, the plugin tries the fallback hostgroup.

## 11. Quick Start Example

```sql
-- Step 1: Ensure the plugin is loaded (in proxysql.cnf):
--   plugins=("/path/to/mysqlx_plugin.so")

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

-- Step 6: (Optional) Configure thread pool size.
UPDATE mysqlx_variables SET variable_value='8'
    WHERE variable_name='mysqlx_thread_pool_size';
LOAD MYSQLX VARIABLES TO RUNTIME;
```

Connect with MySQL Shell:

```bash
mysqlsh root@127.0.0.1:33060 --sql
```

## 12. Limitations (v2)

| Limitation | Detail |
|------------|--------|
| TLS requires OpenSSL | TLS uses OpenSSL Memory BIO pattern. Certificates must be configured via `mysqlx_tls_*` variables. |
| No query rules or policy engine | All traffic is routed based on route configuration only. |
| No cluster sync | MYSQLX tables are not replicated between ProxySQL nodes. |
| No Group Replication notifications | Not supported. |
| `pass_through` backend auth not implemented | Returns error if used. |
| No query caching | Framework is ready but not yet implemented. |
| No metadata/GR awareness | Static routes only. |

## 13. Plugin ABI Version

The mysqlx plugin uses **ProxySQL Plugin ABI version 1**. It requires:

- Same C++ compiler and standard library as the ProxySQL core build.
- Same `-std=` flag (C++17).
- Protobuf 3.21+ linked.
