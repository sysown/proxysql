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
6. The plugin's `start()` function syncs disk → memory for the editable `mysqlx_*` admin tables, then drives the four `MysqlxConfigStore::install_*_from_admin` calls (each SELECTing the editable table plus the relevant cross-module `runtime_mysql_*` projection), creates the thread pool, and starts listeners.

## 3. Admin Variables (v2)

### 3.1. `mysqlx_variables` Table

Global configuration variables for the mysqlx plugin.

Only the five variables below are wired through `MysqlxConfigStore`'s
install/save round-trip. Operator-defined rows with any other
`variable_name` are accepted by the table's CHECK constraints and may be
inserted, but are silently ignored on `LOAD MYSQLX VARIABLES TO RUNTIME`
and *deleted* by the next `SAVE MYSQLX VARIABLES TO MEMORY` (the SAVE
path replaces the entire table with the canonical scalars from the
store). Reserved-but-not-wired TLS variables: `mysqlx_tls_cert`,
`mysqlx_tls_key`, `mysqlx_tls_ca` — see issue tracker.

| Variable | Default | Description |
|----------|---------|-------------|
| `mysqlx_thread_pool_size` | `4` | Number of event loop threads. Range: 1–64. Each thread runs an independent `poll()` loop handling thousands of concurrent sessions. |
| `mysqlx_connect_timeout` | `10000` | Backend connection timeout in milliseconds. Applied to non-blocking `connect()` + backend authentication. |
| `mysqlx_tls_mode` | `DISABLED` | Frontend TLS mode: `DISABLED`, `PREFERRED`, or `REQUIRED`. See [TLS Modes](#81-tls-modes). |
| `mysqlx_tls_backend_mode` | `as_client` | Backend (proxy→backend) TLS mode: `disabled`, `preferred`, `required`, or `as_client`. See [Backend TLS Modes](#82-backend-tls-modes). |
| `mysqlx_max_cached_connections_per_thread` | `100` | Maximum number of idle backend connections cached per thread. Connections are matched by hostgroup, user, schema, *and* backend TLS state. |

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

### 4.2. `runtime_mysqlx_users` (Runtime View)

A read-only **view** of the in-memory user state held by `MysqlxConfigStore`. It is **not** a persistent mirror of `mysqlx_users` — the table holds no rows of its own.

Whenever an admin client runs a `SELECT` that references `runtime_mysqlx_users`, the chassis (`proxysql_refresh_configured_plugin_runtime_views` in `lib/ProxySQL_PluginManager.cpp`) invokes the mysqlx plugin's refresh callback before the query executes. The callback wipes the table and re-projects the current store contents (`DELETE FROM runtime_mysqlx_users; INSERT INTO runtime_mysqlx_users <store dump>`). This matches how core's `runtime_mysql_users` is projected from `GloMyAuth`.

Notes for operators:

* `LOAD MYSQLX USERS TO RUNTIME` does **not** write to this table. It reads `mysqlx_users` (plus `runtime_mysql_users` for canonical identity) and pushes the rows directly into the in-memory store.
* `SAVE MYSQLX USERS FROM RUNTIME TO MEMORY` does **not** read this table. It dumps the in-memory store directly into `mysqlx_users`.
* The schema mirrors `mysqlx_users` so the view is convenient to inspect, but treat it as a debugging snapshot, not as truth: the store is truth.

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
| tls_mode | VARCHAR | `'inherit'` | Per-route TLS posture: `inherit` (use `mysqlx_tls_mode`), `disabled`, `preferred`, `required`, or `passthrough`. See [§8.1](#81-frontend-tls-modes-client--proxy) and [§8.4](#84-end-to-end-tls-passthrough-per-route). |

### 4.4. `runtime_mysqlx_routes` (Runtime View)

A read-only view of the route map held by `MysqlxConfigStore`, projected on demand. Same mechanism as [`runtime_mysqlx_users`](#42-runtime_mysqlx_users-runtime-view): the table is wiped and refilled by a chassis-registered refresh callback before any `SELECT`. `LOAD MYSQLX ROUTES TO RUNTIME` writes the in-memory store from `mysqlx_routes` directly and never touches this view; `SAVE MYSQLX ROUTES FROM RUNTIME TO MEMORY` reads the store and writes `mysqlx_routes` directly.

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

### 4.6. `runtime_mysqlx_backend_endpoints` (Runtime View)

A read-only view of the per-host X-Protocol port overrides held by `MysqlxConfigStore`, projected on demand. Same mechanism as [`runtime_mysqlx_users`](#42-runtime_mysqlx_users-runtime-view): refilled by a chassis-registered refresh callback before any `SELECT`, never written by LOAD, never read by SAVE.

### 4.7. `runtime_mysqlx_variables` (Runtime View)

A read-only view of the five mysqlx tunables held by `MysqlxConfigStore` (`mysqlx_thread_pool_size`, `mysqlx_connect_timeout`, `mysqlx_tls_mode`, `mysqlx_tls_backend_mode`, `mysqlx_max_cached_connections_per_thread`). Same mechanism as [`runtime_mysqlx_users`](#42-runtime_mysqlx_users-runtime-view): refilled by a chassis-registered refresh callback before any `SELECT`, never written by LOAD, never read by SAVE.

`LOAD MYSQLX VARIABLES TO RUNTIME` reads `mysqlx_variables` directly into the store; `SAVE MYSQLX VARIABLES FROM RUNTIME TO MEMORY` writes the store's four scalars back into `mysqlx_variables` (replacing the entire table). Operator-added rows in `mysqlx_variables` whose `variable_name` is not one of the four canonical names are not retained on SAVE — only the four known tunables round-trip.

### 4.8. `stats_mysqlx_routes` (Statistics Table)

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

### 4.9. `stats_mysqlx_processlist` (Statistics Table)

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

Identity resolution is performed entirely in process memory by `MysqlxConfigStore::resolve_identity(username)`, which reads from the in-memory `identities_` map. That map is built by `install_users_from_admin` at startup (and on every `LOAD MYSQLX USERS TO RUNTIME`) by joining two sources:

1. **Canonical lookup** — `SELECT` against `runtime_mysql_users` (must have `frontend=1` and `active=1`). This is core's projection of `GloMyAuth`, owned by the MySQL_Authentication module; the mysqlx plugin consumes it read-only.
2. **X Protocol overlay** — `SELECT` against the editable `mysqlx_users WHERE active=1`. If a row exists for the username, its X-side settings (`allowed_auth_methods`, `backend_auth_mode`, `default_route`, etc.) overlay the canonical row.

The merged result is cached in `MysqlxConfigStore`. Authentication never re-reads either SQLite table — it consults the store's `identities_` map under a shared lock. (`runtime_mysqlx_users` is the projected view, not the source of truth, so identity resolution does not look at it.)

A user must exist in **both** `mysql_users` (for canonical identity — password, default_hostgroup, max_connections) **and** `mysqlx_users` with `active=1` (to opt into X Protocol with whatever overlay the operator configured). `install_users_from_admin` explicitly drops any canonical-only user from the store, since a row with no `mysqlx_users` overlay has no `x_enabled` flag and would never authenticate via X anyway. To enable X Protocol for an existing mysql user, insert the corresponding `mysqlx_users` row, then run `LOAD MYSQLX USERS TO RUNTIME`.

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

### 8.1. Frontend TLS Modes (client → proxy)

Driven by `mysqlx_tls_mode` (uppercase values for backwards compatibility
with the legacy mysql-side mode names).

| Mode | Description |
|------|-------------|
| `DISABLED` | No TLS capability advertised. Plaintext only. |
| `PREFERRED` | TLS capability advertised. Client chooses whether to upgrade. |
| `REQUIRED` | TLS capability advertised. Connection rejected if client does not upgrade. |

#### Per-route override: `mysqlx_routes.tls_mode`

The deployment-wide `mysqlx_tls_mode` can be overridden at the route
level via the `tls_mode` column on `mysqlx_routes`. Default is
`inherit`, which defers to `mysqlx_tls_mode` and matches the previous
deployment-wide-only behaviour exactly.

| Per-route value | Description |
|-----------------|-------------|
| `inherit` | Use the deployment-wide `mysqlx_tls_mode`. Default. |
| `disabled` | This route never advertises TLS, regardless of the global mode. |
| `preferred` | This route advertises TLS; client decides whether to upgrade. |
| `required` | This route advertises TLS; reject the session if the client does not upgrade. |
| `passthrough` | After `CapabilitiesSet(tls=true)`, the proxy splices raw bytes between client and backend without decrypting. End-to-end TLS — see §8.4. |

Use case for the override: dedicate a single compliance-pinned route to
`passthrough` while leaving the others on `inherit` so admin / monitoring
routes still get the proxy's pooling, query-level routing, and
multiplexing.

### 8.2. Backend TLS Modes (proxy → backend)

Driven by `mysqlx_tls_backend_mode` (lowercase values, matching MySQL
Router 8.0's `client_ssl_mode` / `server_ssl_mode` taxonomy). Default is
`as_client`, which matches the legacy implicit behaviour where backend
TLS was tied to the frontend leg's TLS state.

| Mode | Description |
|------|-------------|
| `disabled` | Never use TLS for the proxy→backend leg, regardless of frontend TLS. Plaintext only. |
| `preferred` | Send `CapabilitiesSet(tls=true)` to the backend; on `Mysqlx::Error`, silently downgrade to plaintext on the same TCP connection and continue with `AuthenticateStart`. Best-effort encryption — works against fleets with mixed TLS configurations. |
| `required` | Send `CapabilitiesSet(tls=true)`; on `Mysqlx::Error`, fail the backend connect with error 3152 (`Backend TLS handshake failed`). Use when policy mandates encryption proxy↔backend. |
| `as_client` | Mirror the client's TLS choice. If the client connected over TLS, the backend leg is encrypted; if the client connected in plaintext, the backend leg is plaintext. Matches MySQL Router's AsClient mode. |

The per-endpoint flag `mysqlx_backend_endpoints.use_ssl=1` is an
operator-controlled override that **promotes** plaintext to TLS for that
specific endpoint regardless of mode (it can never demote — there is no
way to opt a single backend out of `mode=required`). Use it when one
sensitive backend must always be encrypted under a deployment-wide
`mode=disabled` or `mode=as_client` policy.

#### Migration notes from MySQL Router AsClient

Pre-mode-aware ProxySQL implicitly behaved like Router's AsClient mode:
the backend leg was encrypted iff the client leg was. Setting
`mysqlx_tls_backend_mode='as_client'` (the new default) preserves that
behaviour exactly. Operators wanting Router-`Required` semantics should
set `mysqlx_tls_backend_mode='required'`; Router-`PassthroughEncrypt` /
`Disabled` map to `mysqlx_tls_backend_mode='disabled'`.

#### Connection pool partitioning

The per-thread connection cache key is
`(hostgroup, user, schema, tls_active)`. An AsClient or required-TLS
session never receives a plaintext-pooled backend (and vice versa) —
the encryption posture is part of the cache identity. Operators with a
mixed-mode workload (some sessions over TLS, some plaintext) will see
two parallel pools per backend identity, which is intentional and
correct: handing a plaintext connection to a TLS-frontend session
would silently corrupt the wire protocol.

### 8.3. Configuration

```sql
-- Frontend TLS:
UPDATE mysqlx_variables SET variable_value='PREFERRED' WHERE variable_name='mysqlx_tls_mode';

-- Backend TLS (asymmetric example: client-required, backend-best-effort):
UPDATE mysqlx_variables SET variable_value='REQUIRED'   WHERE variable_name='mysqlx_tls_mode';
UPDATE mysqlx_variables SET variable_value='preferred'  WHERE variable_name='mysqlx_tls_backend_mode';

LOAD MYSQLX VARIABLES TO RUNTIME;
```

Note: certificate / key paths are not configurable via `mysqlx_variables`
yet — the only TLS-related variables currently wired through the
`MysqlxConfigStore` install/save round-trip are `mysqlx_tls_mode` and
`mysqlx_tls_backend_mode`.

### 8.4. End-to-end TLS Passthrough (per-route)

When operator policy forbids the proxy from decrypting traffic
(compliance, original cert/SNI/ALPN preservation, third-party audit
requirements), a route can be flagged for raw-record passthrough.
ProxySQL still terminates the TCP connection on the listening port
but, once the client requests TLS via `CapabilitiesSet(tls=true)`,
hands off raw bytes between client and backend without ever decrypting
them. The client and the backend establish a single end-to-end TLS
session that the proxy is mechanically incapable of inspecting.

```sql
INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, tls_mode)
       VALUES ('compliance', '0.0.0.0:33099', 99, 'passthrough');
LOAD MYSQLX ROUTES TO RUNTIME;
```

What the operator gives up by selecting passthrough on a route:

* **No connection pooling.** The proxy cannot reuse a passthrough
  backend connection across sessions — it never saw the auth
  exchange, so it has no idea what user-state or transactional state
  the backend session is in.
* **No multiplexing / query-level routing.** The proxy cannot parse
  X-Protocol frames once TLS is up, so it cannot dispatch a query to
  a different hostgroup than the one originally bound at session
  start.
* **No observability beyond byte counts.** Per-query metrics, query
  cache, and frame-level stats are unavailable for passthrough
  sessions. Only TCP-level byte counters and session age are
  recorded.

What the operator keeps:

* **Original certificate.** The client validates the backend's
  certificate directly; SNI, ALPN, and the certificate chain are not
  altered by the proxy.
* **Per-route binding.** Different listening ports (route
  `bind` columns) can independently use `passthrough`, `inherit`,
  `required`, etc. An admin route can stay proxy-terminated while a
  customer-facing route uses passthrough.

If both compliance and pooling are required, dedicate two listening
ports to two routes targeting the same hostgroup: one with
`tls_mode='passthrough'` for the compliance traffic, and one with
`tls_mode='inherit'` (or `required`) for the bulk of the workload.

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

The mysqlx plugin sets `abi_version = PROXYSQL_PLUGIN_ABI_VERSION` (currently **3** — adds `services.register_runtime_view` for declaring admin-side projections of module state, on top of the ABI-2 `register_schemas` / four-phase lifecycle). The chassis loader accepts ABI 1, 2, and 3 plugins. It requires:

- Same C++ compiler and standard library as the ProxySQL core build.
- Same `-std=` flag (C++17).
- Protobuf 3.21+ linked.
