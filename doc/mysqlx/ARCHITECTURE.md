# ProxySQL MySQL X Protocol Plugin — Architecture & Design

## 1. Executive Summary

The mysqlx plugin is ProxySQL's first dynamically loaded plugin. It adds MySQL X Protocol support without modifying the core proxy engine. The plugin uses the ProxySQL Plugin ABI (version 1) to register admin tables, commands, and manage its own listener sockets and worker threads.

Traditional MySQL connections use the classic wire protocol (port 3306). MySQL 8.x introduced the X Protocol (default port 33060), a document-oriented, protobuf-based protocol that supports CRUD operations, prepared statements, and pipelined commands. The mysqlx plugin makes ProxySQL a transparent proxy for X Protocol clients, handling authentication, connection routing, and bidirectional relay while reusing ProxySQL's admin SQLite infrastructure for configuration.

## 2. Architecture Diagram

```
                              ┌─────────────────────────────────────┐
                              │         ProxySQL Core               │
                              │                                     │
                              │  ┌──────────┐  ┌───────────────┐  │
                              │  │ Admin    │  │ Plugin        │  │
                              │  │ Handler  │  │ Manager       │  │
                              │  │          │  │               │  │
                              │  │ MYSQLX   │  │ dlopen/dlsym  │  │
                              │  │ aliases  │  │ register_table│  │
                              │  │    ↓     │  │ register_cmd  │  │
                              │  │ dispatch │  │ dispatch_cmd  │  │
                              │  └────┬─────┘  └───────┬───────┘  │
                              │       │                │           │
                              └───────┼────────────────┼───────────┘
                                      │                │
                    ┌─────────────────┼────────────────┼──────────────┐
                    │  ProxySQL_MySQLX_Plugin.so       │              │
                    │                                  │              │
                    │  ┌───────────────────┐  ┌───────┴────────┐    │
                    │  │  mysqlx_worker    │  │ mysqlx_admin_   │    │
                    │  │                   │  │ schema          │    │
                    │  │  Listeners (poll) │  │                  │    │
                    │  │  Workers (thread) │  │ Table DDL        │    │
                    │  │  Accept loop      │  │ LOAD/SAVE cmds   │    │
                    │  └────────┬──────────┘  └────────────────┘    │
                    │           │                                      │
                    │  ┌────────┴──────────┐                         │
                    │  │ mysqlx_frontend_   │                         │
                    │  │ session            │                         │
                    │  │                    │                         │
                    │  │ Handshake state    │                         │
                    │  │ Auth (MYSQL41/PLAIN│                         │
                    │  │ Identity resolve   │                         │
                    │  └────────┬──────────┘                         │
                    │           │                                      │
                    │  ┌────────┴──────────┐                         │
                    │  │ mysqlx_backend_    │                         │
                    │  │ session            │                         │
                    │  │                    │                         │
                    │  │ Connect (getaddrinfo)                       │
                    │  │ Auth (MYSQL41)     │                         │
                    │  │ Relay (poll)       │──────────┐             │
                    │  └────────────────────┘          │             │
                    │                                  │             │
                    │  ┌──────────────────┐   ┌───────┴────────┐   │
                    │  │ mysqlx_config_   │   │ mysqlx_stats   │   │
                    │  │ store            │   │                │   │
                    │  │                  │   │ Atomic counters│   │
                    │  │ Identity cache   │   │ SQLite flush   │   │
                    │  │ Route cache      │   │                │   │
                    │  │ Endpoint cache   │   │                │   │
                    │  │ Topology gen     │   │                │   │
                    │  └──────────────────┘   └────────────────┘   │
                    │                                                  │
                    └──────────────────────────────────────────────────┘
                                              │
                                              ▼
                                    ┌──────────────────┐
                                    │  MySQL 8.x       │
                                    │  (X Protocol     │
                                    │   port 33060)    │
                                    └──────────────────┘
```

## 3. Component Descriptions

### 3.1 ProxySQL_PluginManager

| | |
|---|---|
| **Header** | `include/ProxySQL_Plugin.h` |
| **Source** | `lib/ProxySQL_PluginManager.cpp` |
| **Responsibility** | Core plugin loader. Manages the full plugin lifecycle: `load` → `init` → `start` → `stop`. |
| **Key methods** | `load(path)` — dlopen the shared library, dlsym the descriptor symbol. `init_all()` — call each plugin's `init()`, which triggers table/command registration. `start_all()` / `stop_all()` — lifecycle control. `dispatch_command(sql)` — route an admin SQL command to the owning plugin. |
| **Thread safety** | `std::mutex g_active_plugin_manager_mutex` guards the active plugin list and dispatch. Table registration uses a lock-free `std::deque` appended during `init_all()` (single-writer, no concurrent readers yet). Command dispatch acquires the mutex per invocation. |

### 3.2 mysqlx_plugin (Entry Point)

| | |
|---|---|
| **Header** | `plugins/mysqlx/mysqlx_plugin.h` |
| **Source** | `plugins/mysqlx/mysqlx_plugin.cpp` |
| **Responsibility** | Plugin entry point. Exports `proxysql_plugin_descriptor_v1` — the single symbol the PluginManager resolves. Owns the plugin context: a `MysqlxConfigStore`, a `MysqlxStatsStore`, and the cached `ProxySQL_PluginServices*`. |
| **Key methods** | `mysqlx_init(services)` — create config/stats stores, register admin tables and commands via the services pointer. `mysqlx_start()` — load config from runtime SQLite, start listener threads. `mysqlx_stop()` — join listener and worker threads, free resources. `mysqlx_status_json()` — return a JSON string for monitoring. |
| **Thread safety** | The descriptor functions are called sequentially by the PluginManager during startup/shutdown. No concurrent access to the plugin context during `init`/`start`/`stop`. |

### 3.3 mysqlx_worker

| | |
|---|---|
| **Header** | `plugins/mysqlx/mysqlx_worker.h` |
| **Source** | `plugins/mysqlx/mysqlx_worker.cpp` |
| **Responsibility** | Listener and worker thread management. Each configured bind address spawns one listener thread that runs a `poll()` accept loop. Accepted file descriptors are dispatched round-robin to a pool of worker threads. Supports IPv4 and IPv6 via `getaddrinfo`. |
| **Key methods** | `mysqlx_start_listeners_from_runtime_routes(config_store)` — resolve all configured bind addresses, spawn one listener thread per address. `mysqlx_listener_thread(arg)` — poll loop: `poll()` on the listening socket, `accept()` incoming connections, enqueue the fd to a worker's queue. `mysqlx_worker_thread(arg)` — dequeue an fd, create a `MysqlxFrontendSession`, run the handshake/auth/relay lifecycle. |
| **Thread safety** | Each worker owns a `std::mutex` + `std::condition_variable` for its fd queue. The round-robin counter is protected by a separate `std::mutex` inside the config store. Listener threads never touch shared state beyond the worker queues. |

### 3.4 mysqlx_frontend_session

| | |
|---|---|
| **Header** | `plugins/mysqlx/mysqlx_frontend_session.h` |
| **Source** | `plugins/mysqlx/mysqlx_frontend_session.cpp` |
| **Responsibility** | Client-side X Protocol handshake state machine. Handles the full client connection lifecycle: Capabilities exchange → AuthenticateStart → MYSQL41 or PLAIN auth → identity resolution → backend connection setup → bidirectional relay. |
| **Key methods** | `run()` — top-level entry point called by the worker thread. Reads the client greeting, sends `ServerCapabilities`, processes `CapabilitiesSet`, then enters the auth phase. `handle_auth_mysql41(challenge)` — compute the double-SHA1 scramble, compare via `CRYPTO_memcmp`. `handle_auth_plain(username, password)` — direct password verification. `resolve_identity(username)` — query the config store for the user's default hostgroup and credentials. |
| **Thread safety** | Each `MysqlxFrontendSession` is owned by exactly one worker thread for its entire lifetime. No cross-thread access. The session reads from `MysqlxConfigStore` using shared (reader) locks. |

### 3.5 mysqlx_backend_session

| | |
|---|---|
| **Header** | `plugins/mysqlx/mysqlx_backend_session.h` |
| **Source** | `plugins/mysqlx/mysqlx_backend_session.cpp` |
| **Responsibility** | Backend connection establishment and bidirectional relay. Opens a TCP connection to the target MySQL X Protocol endpoint, performs MYSQL41 authentication, then relays X Protocol frames between the frontend client and the backend server. |
| **Key methods** | `connect(host, port)` — `getaddrinfo` for DNS resolution, `socket()` + `connect()`. `authenticate(username, password, challenge)` — perform MYSQL41 handshake against the backend X Protocol server. `relay(client_fd)` — poll-based bidirectional relay. Uses `poll()` with two fds (client and backend). Reads a complete X Protocol frame (4-byte header + payload), writes it to the other side. Runs until either side closes or an error occurs. |
| **Thread safety** | Each `MysqlxBackendSession` is owned by exactly one worker thread (the same thread that owns the corresponding frontend session). No concurrent access. |

### 3.6 mysqlx_protocol

| | |
|---|---|
| **Header** | `plugins/mysqlx/mysqlx_protocol.h` |
| **Source** | `plugins/mysqlx/mysqlx_protocol.cpp` |
| **Responsibility** | Low-level X Protocol frame encoding and decoding. Provides helpers for MYSQL41 authentication (double-SHA1), socket I/O with EINTR handling, and frame construction (error frames, OK frames, capability frames). |
| **Key methods** | `read_frame(fd, msg)` — read 4-byte header (payload length + type byte), then payload. Handles partial reads and `EINTR`. `write_frame(fd, type, data, len)` — write header + payload with EINTR retry. `build_server_capabilities()` — construct the `ServerCapabilities` protobuf message. `build_error_frame(code, sql_state, msg)` — construct an `Error` frame. `mysqlx_mysql41_scramble(password, challenge, scramble_out)` — compute the double-SHA1 scramble for MYSQL41 auth. |
| **Thread safety** | All functions are stateless and reentrant. They operate on raw file descriptors passed as arguments. Safe to call from any thread. |

### 3.7 mysqlx_config_store

| | |
|---|---|
| **Header** | `plugins/mysqlx/mysqlx_config_store.h` |
| **Source** | `plugins/mysqlx/mysqlx_config_store.cpp` |
| **Responsibility** | In-memory configuration cache loaded from SQLite runtime tables. Maintains caches for: identities (user → hostgroup + credentials), routes (listen address → backend endpoints), endpoints (backend host + port with health metadata), and topology generation tracking for cache invalidation. |
| **Key methods** | `load_from_runtime(services)` — execute `SELECT` queries against the runtime SQLite database, populate in-memory caches. Acquires an exclusive write lock. `resolve_identity(username)` — look up a user's hostgroup and credentials. Acquires a shared read lock. `pick_endpoint(hostgroup)` — select a backend endpoint from the route cache for the given hostgroup, using round-robin selection. Acquires a shared read lock for the endpoint list, a separate mutex for the round-robin counter. |
| **Thread safety** | `std::shared_mutex` — shared (reader) lock for all lookup methods (`resolve_identity`, `pick_endpoint`, `get_routes`). Exclusive (writer) lock for `load_from_runtime`. Round-robin counters are protected by per-route `std::mutex` instances. |

### 3.8 mysqlx_stats

| | |
|---|---|
| **Header** | `plugins/mysqlx/mysqlx_stats.h` |
| **Source** | `plugins/mysqlx/mysqlx_stats.cpp` |
| **Responsibility** | Per-route atomic counters tracking connections, queries, errors, and bytes transferred. Periodically flushes aggregated statistics to the `stats_mysqlx_routes` SQLite table. |
| **Key methods** | `inc_connections(route_id)` — atomically increment the connection counter for a route. `inc_queries(route_id)` — atomically increment the query counter. `inc_errors(route_id)` — atomically increment the error counter. `add_bytes_sent(route_id, n)` / `add_bytes_recv(route_id, n)` — atomically add byte counters. `flush_to_sqlite(services)` — write all counters to the `stats_mysqlx_routes` table via the stats database handle. |
| **Thread safety** | All counters are `std::atomic<uint64_t>`. Increment/add operations are lock-free. Route creation (first access to a new route_id) acquires `std::mutex`. The `flush_to_sqlite` method is called from a single maintenance thread. |

### 3.9 mysqlx_admin_schema

| | |
|---|---|
| **Header** | `plugins/mysqlx/mysqlx_admin_schema.h` |
| **Source** | `plugins/mysqlx/mysqlx_admin_schema.cpp` |
| **Responsibility** | Admin table DDL definitions and LOAD/SAVE command handlers. Defines the schema for runtime configuration tables (`mysqlx_users`, `mysqlx_routes`, `mysqlx_endpoints`) and implements the `LOAD MYSQLX USERS TO RUNTIME`, `SAVE MYSQLX USERS FROM RUNTIME`, and similar commands. |
| **Key methods** | `register_tables(services)` — call `services->register_table()` for each table definition. `register_commands(services)` — call `services->register_command()` for each LOAD/SAVE command. `cmd_load_users_to_runtime(services, result)` — copy `mysqlx_users` from the admin DB to the runtime DB, then trigger `config_store->load_from_runtime()`. `cmd_save_users_from_runtime(services, result)` — copy `mysqlx_users` from the runtime DB to the admin DB. |
| **Thread safety** | Registration methods are called during `init()`, which is single-threaded. Command handlers are called from the admin thread via the PluginManager dispatch mutex. The handlers copy data between SQLite databases using the services-provided database pointers (valid only during the callback). |

## 4. Data Flow Diagrams

### 4.1 Client Connection Flow

```
Client                Worker           FrontendSession    ConfigStore         BackendSession     MySQL
  │                     │                    │                 │                    │              │
  │── TCP connect ────→│                    │                 │                    │              │
  │                     │── accept ─────→   │                 │                    │              │
  │←── CapabilitiesGet ────────────────────│                 │                    │              │
  │── CapabilitiesSet ─────────────────────→│                 │                    │              │
  │←── AuthenticateStart ──────────────────│                 │                    │              │
  │                     │                    │── resolve ───→ │                    │              │
  │                     │                    │←─ identity ────│                    │              │
  │── AuthContinue ─────────────────────────→│                │                    │              │
  │                     │                    │── verify ─────→│ (check password)   │              │
  │←── AuthenticateOk ──────────────────────│                │                    │              │
  │                     │                    │── pick_endpoint──────────────→     │              │
  │                     │                    │                 │    │── getaddrinfo│              │
  │                     │                    │                 │    │── connect ──────────────→   │
  │                     │                    │                 │    │── MYSQL41 auth ─────────→  │
  │── SQL statement ────────────────────────│                 │    │←── Ok ────────────────── │
  │                     │                    │── relay ───────────────────────→   │              │
  │                     │                    │                 │    │── forward ──────────────→ │
  │                     │                    │                 │    │←── resultset ─────────── │
  │←── resultset ───────────────────────────│                │    │←── relay ─────────────── │
  │                     │                    │                 │                    │              │
```

**Step-by-step description:**

1. **TCP connect** — The client opens a TCP connection to the configured X Protocol listen port (e.g., 0.0.0.0:33060). The listener thread's `poll()` loop detects the incoming connection.

2. **accept** — The listener thread calls `accept()`, obtains the client file descriptor, and enqueues it to a worker thread's fd queue (round-robin across workers).

3. **CapabilitiesGet** — The worker creates a `MysqlxFrontendSession` and begins the handshake. It sends a `ServerCapabilities` frame to the client, advertising supported auth mechanisms (MYSQL41, PLAIN) and TLS availability.

4. **CapabilitiesSet** — The client responds with its selected capabilities, choosing an auth mechanism.

5. **AuthenticateStart** — The frontend session sends an `AuthenticateStart` frame containing the auth mechanism name and initial auth data.

6. **resolve identity** — The frontend session calls `config_store->resolve_identity(username)` to look up the user's hostgroup and credentials in the in-memory cache.

7. **identity returned** — The config store returns the user's default hostgroup, password hash, and any attribute overrides.

8. **AuthContinue** — The client sends its authentication response (e.g., the MYSQL41 scramble).

9. **verify** — The frontend session verifies the scramble against the stored credentials. For PLAIN auth, the password is compared directly. For MYSQL41, the double-SHA1 scramble is recomputed and compared with `CRYPTO_memcmp`.

10. **AuthenticateOk** — If verification succeeds, the frontend sends an `AuthenticateOk` frame. If it fails, an `Error` frame is sent and the connection is closed.

11. **pick_endpoint** — The frontend session calls `config_store->pick_endpoint(hostgroup)` to select a backend server from the route's endpoint list (round-robin).

12. **getaddrinfo** — The backend session resolves the endpoint's hostname and port.

13. **connect** — The backend session opens a TCP connection to the MySQL X Protocol port.

14. **MYSQL41 auth** — The backend session performs X Protocol MYSQL41 authentication with the backend MySQL server using the user's credentials.

15. **Ok from backend** — The backend MySQL server responds with `AuthenticateOk`.

16. **SQL statement** — The client sends an X Protocol `StmtExecute` or `CrudFind`/`CrudInsert`/etc. message.

17. **relay** — The frontend session delegates to the backend session's relay loop. The `relay()` method uses `poll()` on both fds (client and backend).

18. **forward** — The relay reads the client's X Protocol frame and writes it verbatim to the backend socket.

19. **resultset from backend** — The backend MySQL server processes the statement and returns result frames.

20. **relay back** — The relay reads the backend's response frames and writes them verbatim to the client socket. The relay loop continues until one side closes the connection or an error occurs.

### 4.2 Admin Command Flow

```
Admin Client          Admin Handler       PluginManager      mysqlx_admin_schema    ConfigStore
     │                     │                    │                      │                    │
     │── LOAD MYSQLX ────→│                    │                      │                    │
     │   USERS TO RUNTIME │                    │                      │                    │
     │                     │── alias match ───→│                      │                    │
     │                     │                    │── dispatch ────────→│                    │
     │                     │                    │                      │── copy_table ────→│
     │                     │                    │                      │  (SQLite → SQLite)│
     │                     │                    │                      │── reload_config──→│
     │                     │                    │                      │  (SQLite → memory)│
     │←── OK ─────────────│←──────────────────│←────────────────────│                    │
     │                     │                    │                      │                    │
```

**Step-by-step description:**

1. **LOAD MYSQLX USERS TO RUNTIME** — An admin client (e.g., the ProxySQL admin console or a management tool) issues the command.

2. **alias match** — The Admin Handler recognizes the `MYSQLX` prefix and matches it against registered plugin command aliases. The `LOAD MYSQLX USERS TO RUNTIME` command was registered by the mysqlx plugin during `init()`.

3. **dispatch** — The Admin Handler calls `PluginManager::dispatch_command(sql)`, which acquires `g_active_plugin_manager_mutex`, finds the owning plugin, and calls its registered callback.

4. **copy_table** — The `cmd_load_users_to_runtime` handler obtains the admin DB and runtime DB pointers from the services struct. It copies the `mysqlx_users` table from admin to runtime using `INSERT OR REPLACE ... SELECT` across the two SQLite databases.

5. **reload_config** — After the SQLite copy, the handler calls `config_store->load_from_runtime(services)`, which executes `SELECT` queries against the runtime database and populates the in-memory caches (identity cache, route cache, endpoint cache). This acquires the config store's exclusive write lock, blocking lookups briefly.

6. **OK** — The command handler returns a `ProxySQL_PluginCommandResult` with success status. The PluginManager returns it to the Admin Handler, which formats the standard ProxySQL admin OK response to the client.

## 5. Thread Model

```
Main Thread
  ├── ProxySQL_PluginManager::load()        (dlopen, dlsym)
  ├── ProxySQL_PluginManager::init_all()    (register tables/commands)
  ├── ProxySQL_PluginManager::start_all()   (start listeners)
  │     └── mysqlx_start()
  │           ├── config_store->load_from_runtime()   (SQLite → memory)
  │           └── mysqlx_start_listeners_from_runtime_routes()
  │                 ├── Listener Thread 1 (poll, accept on 0.0.0.0:33060)
  │                 └── Listener Thread N (...)
  │                       └── on accept → enqueue to Worker
  ├── Worker Thread 1
  │     ├── FrontendSession::run_handshake_and_auth()
  │     ├── BackendSession::connect() + authenticate
  │     └── BackendSession::relay() (poll loop)
  └── Worker Thread N
        └── (same)
```

### Thread Lifecycle

1. **Startup (Main Thread)**: The main thread calls `PluginManager::load()` which dlopens the plugin shared library. Then `init_all()` invokes the plugin's `init()` callback, which registers admin tables and commands. Then `start_all()` invokes `mysqlx_start()`, which loads configuration from SQLite into the in-memory config store and spawns listener threads.

2. **Listener Threads**: Each listener thread runs a `poll()` loop on its assigned bind address. When a client connects, the listener calls `accept()`, picks the next worker thread (round-robin), enqueues the client fd to that worker's queue, and signals the worker's condition variable. The listener thread never performs I/O on the client connection.

3. **Worker Threads**: Each worker thread blocks on its condition variable waiting for enqueued fds. When woken, the worker creates a `MysqlxFrontendSession` for the client fd, runs the full connection lifecycle (handshake, auth, backend connect, relay), then returns to waiting. A worker handles one client connection at a time (synchronous, blocking I/O within the relay loop).

4. **Shutdown (Main Thread)**: The main thread calls `PluginManager::stop_all()`, which invokes `mysqlx_stop()`. This sets a global shutdown flag, signals all listener and worker condition variables, and joins all threads.

### Thread Safety Summary

| Resource | Mechanism | Scope |
|---|---|---|
| `MysqlxConfigStore` caches | `std::shared_mutex` | Shared for reads (identity lookup, endpoint selection), exclusive for `load_from_runtime` |
| `MysqlxStatsStore` counters | `std::atomic<uint64_t>` | Lock-free per-counter increments |
| `MysqlxStatsStore` route creation | `std::mutex` | Guards insertion of new route entries |
| `ProxySQL_PluginManager` dispatch | `std::mutex` (`g_active_plugin_manager_mutex`) | Guards command dispatch |
| Worker fd queues | `std::mutex` + `std::condition_variable` | Per-worker queue of pending client fds |
| Round-robin counters | `std::mutex` (per-route) | Guards endpoint selection index |
| `MysqlxFrontendSession` / `MysqlxBackendSession` | None needed | Single-owner (one worker thread) |

## 6. Plugin ABI

The Plugin ABI defines the contract between ProxySQL core and dynamically loaded plugins. It is versioned so that future ABI changes can be detected at load time.

### 6.1 ABI Structure

```
┌─────────────────────────────────────┐
│        ProxySQL_Plugin.h            │
│                                     │
│  ProxySQL_PluginDescriptor          │
│  ├── name                           │
│  ├── abi_version (= 1)              │
│  ├── init(services) → bool          │
│  ├── start() → bool                 │
│  ├── stop() → bool                  │
│  └── status_json() → const char*    │
│                                     │
│  ProxySQL_PluginServices            │
│  ├── register_table(def)            │
│  ├── register_command(sql, cb)       │
│  ├── get_admindb() → SQLite3DB*     │
│  ├── get_configdb() → SQLite3DB*     │
│  ├── get_statsdb() → SQLite3DB*     │
│  ├── log_message(level, msg)         │
│  └── snapshot callbacks             │
└─────────────────────────────────────┘
```

### 6.2 ABI Version Contract

- The plugin exports a single C symbol: `proxysql_plugin_descriptor_v1` of type `ProxySQL_PluginDescriptor`.
- The PluginManager calls `dlsym(handle, "proxysql_plugin_descriptor_v1")`.
- If the symbol is not found, the load fails with an error logged.
- The `abi_version` field must match `1`. A mismatch causes the load to fail.

### 6.3 Lifecycle Callbacks

| Callback | When Called | Purpose |
|---|---|---|
| `init(services)` | After `dlopen`, before any other callbacks | Register tables and commands. Store the `services` pointer. Return `true` on success. |
| `start()` | After `init` succeeds | Start listener threads, load runtime config. Return `true` on success. |
| `stop()` | During graceful shutdown | Join threads, free resources. Return `true` on success. |
| `status_json()` | On admin `SELECT plugin_status` or monitoring | Return a JSON-formatted status string. Caller does not free. |

### 6.4 Memory Ownership Rules

The Plugin ABI has strict memory ownership rules to avoid use-after-free and double-free bugs across the plugin boundary:

| Operation | Ownership | Lifetime |
|---|---|---|
| `register_table(table_name, table_def)` | Core copies both strings into stable storage (`std::deque`) | Plugin can free its strings immediately after `init()` returns |
| `register_command(sql, callback)` | Core copies the SQL string | Plugin can free its string immediately after `init()` returns |
| `get_admindb()` / `get_configdb()` / `get_statsdb()` | Core owns the database handle | Returned pointer is valid **only during the callback invocation**. The plugin must not store the pointer for later use. |
| `ProxySQL_PluginCommandResult.message` | Core reads the `std::string` | ABI constraint: plugin and core must be compiled against the same C++ standard library (same `std::string` ABI). In practice, both use the ProxySQL build toolchain. |
| `status_json()` return value | Plugin owns the string | Must remain valid until the next call to `status_json()` or `stop()` |
| `log_message(level, msg)` | Core copies the message during the call | Plugin can free its string immediately after the call returns |

### 6.5 Callback Registration During init()

```
PluginManager::init_all()
  └── mysqlx_init(services)
        ├── services->register_table("mysqlx_users", CREATE TABLE ...)
        ├── services->register_table("mysqlx_routes", CREATE TABLE ...)
        ├── services->register_table("mysqlx_endpoints", CREATE TABLE ...)
        ├── services->register_command("LOAD MYSQLX USERS TO RUNTIME", cmd_load_users)
        ├── services->register_command("SAVE MYSQLX USERS FROM RUNTIME", cmd_save_users)
        ├── services->register_command("LOAD MYSQLX ROUTES TO RUNTIME", cmd_load_routes)
        ├── services->register_command("SAVE MYSQLX ROUTES FROM RUNTIME", cmd_save_routes)
        └── (etc.)
```

After `init()` returns, the PluginManager publishes the registered tables and commands to the Admin Handler. The Admin Handler creates SQL aliases so that `LOAD MYSQLX USERS TO RUNTIME` is recognized as a valid admin command and dispatched to the plugin.

## 7. Build System

### 7.1 Build Pipeline

The mysqlx plugin is built as a standalone shared library, separate from the core ProxySQL binary.

```
plugins/mysqlx/
  ├── Makefile                 # Plugin-specific build rules
  ├── mysqlx_plugin.cpp        # Entry point
  ├── mysqlx_worker.cpp/.h     # Listener/worker threads
  ├── mysqlx_frontend_session.cpp/.h
  ├── mysqlx_backend_session.cpp/.h
  ├── mysqlx_protocol.cpp/.h   # Frame encode/decode
  ├── mysqlx_config_store.cpp/.h
  ├── mysqlx_stats.cpp/.h
  ├── mysqlx_admin_schema.cpp/.h
  └── protobuf/                # Pre-generated protobuf sources
      ├── mysqlx_connection.pb.cc/.h
      ├── mysqlx_crud.pb.cc/.h
      ├── mysqlx_expect.pb.cc/.h
      ├── mysqlx_expr.pb.cc/.h
      ├── mysqlx_notice.pb.cc/.h
      ├── mysqlx_resultset.pb.cc/.h
      ├── mysqlx_session.pb.cc/.h
      ├── mysqlx_sql.pb.cc/.h
      └── mysqlx_stmt.pb.cc/.h
```

### 7.2 Build Commands

```bash
# Build the plugin (from project root or plugins/mysqlx/)
make -C plugins/mysqlx

# Output: plugins/mysqlx/ProxySQL_MySQLX_Plugin.so
```

### 7.3 Build Flags

| Flag | Purpose |
|---|---|
| `-std=c++17` | Required C++ standard |
| `-fPIC` | Position-independent code for shared library |
| `-pthread` | POSIX threads |
| `-I include/` | ProxySQL core headers (for `ProxySQL_Plugin.h`) |
| `-I deps/protobuf/...` | Protobuf headers |

### 7.4 Dependencies

| Dependency | Purpose |
|---|---|
| **protobuf** | X Protocol message serialization/deserialization |
| **OpenSSL** | SHA1 hash computation for MYSQL41 auth, `CRYPTO_memcmp` for constant-time comparison |
| **SQLite3** | Admin/runtime database access (via PluginServices pointers at runtime, not linked at build time) |

### 7.5 Protobuf Code Generation

The protobuf `.pb.cc` and `.pb.h` files are pre-generated from MySQL 8.4 proto definitions and committed to the repository. They are not regenerated during a normal build. To regenerate:

```bash
# Requires protoc >= 3.19 with C++ plugin
cd plugins/mysqlx/protobuf
protoc --cpp_out=. *.proto
```

## 8. MYSQL41 Authentication Internals

X Protocol supports multiple authentication mechanisms. The mysqlx plugin implements **MYSQL41**, which is the native MySQL authentication adapted for the X Protocol. It uses a challenge-response mechanism based on double-SHA1 hashing.

### 8.1 Double-SHA1 Algorithm

```
hash_stage1 = SHA1(password)
hash_stage2 = SHA1(hash_stage1)
scramble    = XOR(hash_stage1, SHA1(challenge + hash_stage2))
```

**Detailed steps:**

1. **hash_stage1**: The client computes `SHA1(plaintext_password)` to produce a 20-byte digest. This is the "stored hash" that would be in `mysql.user.authentication_string`.

2. **hash_stage2**: The client computes `SHA1(hash_stage1)` to produce a second 20-byte digest. This is used as the "secret" in the challenge-response.

3. **challenge**: The server sends a 20-byte random nonce during the `AuthenticateStart` phase.

4. **scramble**: The client concatenates the challenge with `hash_stage2`, computes `SHA1(challenge || hash_stage2)`, then XORs the result with `hash_stage1`. The XOR output is the auth data sent to the server in `AuthContinue`.

### 8.2 Server-Side Verification

The backend MySQL server (or the frontend session when verifying client credentials against stored hashes) performs:

```
received_scramble = auth_data from client
hash_stage2       = SHA1(stored_hash)            -- stored_hash is hash_stage1
candidate         = SHA1(challenge || hash_stage2)
hash_stage1       = XOR(received_scramble, candidate)
computed_stage2   = SHA1(hash_stage1)

verified = CRYPTO_memcmp(computed_stage2, hash_stage2, 20) == 0
```

The `CRYPTO_memcmp` function from OpenSSL performs a constant-time comparison to prevent timing side-channel attacks.

### 8.3 Authentication Flow Diagram

```
Client                          ProxySQL (Frontend)               MySQL (Backend)
  │                                    │                               │
  │── AuthenticateStart ──────────────→│                               │
  │   (mechanism: MYSQL41)             │                               │
  │←── AuthenticateContinue ───────────│                               │
  │   (challenge: 20-byte nonce)       │                               │
  │                                    │                               │
  │   scramble = XOR(SHA1(pwd),        │                               │
  │     SHA1(challenge + SHA1(SHA1(pwd))))                             │
  │                                    │                               │
  │── AuthContinue ───────────────────→│                               │
  │   (auth_data: 20-byte scramble)    │                               │
  │                                    │                               │
  │                                    │── verify scramble ──→         │
  │                                    │   (if proxying auth)          │
  │                                    │                               │
  │                                    │   OR                          │
  │                                    │                               │
  │                                    │── connect to backend ────────→│
  │                                    │── AuthenticateStart ─────────→│
  │                                    │←── AuthenticateContinue ─────│
  │                                    │   (challenge: 20-byte nonce)  │
  │                                    │── AuthContinue ──────────────→│
  │                                    │   (recomputed scramble)       │
  │                                    │←── AuthenticateOk ───────────│
  │                                    │                               │
  │←── AuthenticateOk ────────────────│                               │
  │                                    │                               │
```

### 8.4 PLAIN Authentication

As an alternative, X Protocol supports PLAIN authentication where the client sends the plaintext password over the wire. The mysqlx plugin supports PLAIN auth for client connections (the password is verified against the stored double-SHA1 hash by computing the hash and comparing). However, the plugin always uses MYSQL41 when authenticating to backend MySQL servers, as PLAIN is typically disabled on MySQL X Protocol listeners for security.

### 8.5 Security Considerations

- **No password storage in plugin**: The plugin stores the double-SHA1 hash (`SHA1(SHA1(password))`), not the plaintext password. This matches MySQL's `mysql.user.authentication_string` format.
- **Constant-time comparison**: All hash comparisons use `CRYPTO_memcmp` to prevent timing attacks.
- **Challenge freshness**: The 20-byte challenge is generated per-connection using OpenSSL's `RAND_bytes`.
- **TLS recommended**: PLAIN authentication should only be enabled when the client connection uses TLS. The plugin advertises TLS capability in the capabilities exchange.
