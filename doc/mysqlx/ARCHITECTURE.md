# ProxySQL MySQL X Protocol Plugin — Architecture & Design (v2)

## 1. Executive Summary

The mysqlx plugin is ProxySQL's first dynamically loaded plugin. It adds MySQL X Protocol support without modifying the core proxy engine. The plugin uses the ProxySQL Plugin ABI (currently version 3 — descriptor ABI 2 four-phase lifecycle plus the ABI-3 `services.register_runtime_view` callback for declaring admin-side projections of module state) to register admin tables, commands, runtime-view refreshes, and manage its own listener sockets and worker threads.

**v2** introduces an event-driven architecture replacing the Phase 1 single-threaded blocking model. Instead of one thread handling one session at a time with blocking I/O, v2 uses N configurable threads each running an independent `poll()` event loop, cooperatively multiplexing thousands of concurrent X Protocol sessions — matching ProxySQL's core `MySQL_Thread` / `PgSQL_Thread` design.

Traditional MySQL connections use the classic wire protocol (port 3306). MySQL 8.x introduced the X Protocol (default port 33060), a document-oriented, protobuf-based protocol that supports CRUD operations, prepared statements, and pipelined commands. The mysqlx plugin makes ProxySQL a transparent proxy for X Protocol clients, handling authentication, connection routing, protocol-aware frame forwarding for all 23 client message types, connection pooling, and bidirectional relay while reusing ProxySQL's admin SQLite infrastructure for configuration.

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
                     │  │  Mysqlx_Thread    │  │ mysqlx_admin_   │    │
                     │  │  (x N threads)    │  │ schema          │    │
                     │  │                   │  │                  │    │
                     │  │  poll() loop      │  │ Table DDL        │    │
                     │  │  Accept (builtin) │  │ LOAD/SAVE cmds   │    │
                     │  │  Session dispatch │  │ Variables        │    │
                     │  └────────┬──────────┘  └────────────────┘    │
                     │           │                                      │
                     │  ┌────────┴──────────┐                         │
                     │  │ MysqlxSession     │                         │
                     │  │ (per connection)  │                         │
                     │  │                   │                         │
                     │  │ 22 states         │                         │
                     │  │  Auth (MYSQL41)   │                         │
                     │  │  Message dispatch │                         │
                     │  │  Frame forwarding │                         │
                     │  └────┬─────────┬────┘                         │
                     │       │         │                              │
                     │  ┌────┴───┐ ┌───┴──────────┐                  │
                     │  │client  │ │server         │                  │
                     │  │DS      │ │DS             │                  │
                     │  │        │ │               │                  │
                     │  │Frame   │ │Frame          │                  │
                     │  │parse   │ │forward        │                  │
                     │  └────────┘ └──────┬────────┘                  │
                     │                    │                            │
                     │  ┌─────────────────┴──────────┐                │
                     │  │ MysqlxConnection (pooled)   │                │
                     │  │                              │                │
                     │  │ Per-thread cache + global    │                │
                     │  │ Match by hostgroup/user/schema│               │
                     │  └──────────────────────────────┘                │
                     │                                                  │
                     │  ┌──────────────────┐   ┌────────────────┐     │
                     │  │ mysqlx_config_   │   │ mysqlx_stats   │     │
                     │  │ store            │   │                │     │
                     │  │                  │   │ Atomic counters│     │
                     │  │ Identity cache   │   │ SQLite flush   │     │
                     │  │ Route cache      │   │                │     │
                     │  │ Endpoint cache   │   │                │     │
                     │  │ TLS config       │   │                │     │
                     │  └──────────────────┘   └────────────────┘     │
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

### 3.1 Mysqlx_Thread — Event Loop

| | |
|---|---|
| **Header** | `plugins/mysqlx/include/mysqlx_thread.h` |
| **Source** | `plugins/mysqlx/src/mysqlx_thread.cpp` |
| **Responsibility** | Core event loop. Each thread runs an independent `poll()` loop, accepting new connections (listeners are built into the poll set), processing session state machines, and managing a per-thread connection cache. Multiple threads run in parallel (configurable via `mysqlx_thread_pool_size`, default 4, max 64). |
| **Key methods** | `init(thread_index)` — create signal pipe, initialize poll set. `start()` / `stop()` — thread lifecycle. `run()` — main poll loop: `poll()` → `process_ready_fds()` → `process_all_sessions()`. `add_listener(addr, port)` — add a listener socket to the poll set as `XDS_LISTENER`. `get_connection_from_cache(hostgroup, user, schema)` — per-thread pool lookup. `return_connection_to_cache(conn)` — return a reusable connection. |
| **Thread safety** | Each `Mysqlx_Thread` is independent — no shared state between threads. The per-thread connection cache uses a `std::mutex` for safety. Signal pipe for wakeup on shutdown. |

### 3.2 MysqlxSession — State Machine

| | |
|---|---|
| **Header** | `plugins/mysqlx/include/mysqlx_session.h` |
| **Source** | `plugins/mysqlx/src/mysqlx_session.cpp` |
| **Responsibility** | X Protocol session state machine with 22 states. Handles the full client connection lifecycle cooperatively: capabilities exchange → TLS negotiation → MYSQL41/PLAIN auth → identity resolution → backend connection (pool-first) → message dispatch → frame forwarding → session close. Each handler returns control immediately when waiting for I/O. |
| **Key states** | `CONNECTING_CLIENT` → `X_CAPABILITIES_GET` → `X_CAPABILITIES_SET` → `X_TLS_ACCEPT_*` (optional) → `X_AUTH_START` → `X_AUTH_CHALLENGE_SENT` → `X_AUTH_OK_SENT` → `WAITING_CLIENT_XMSG` → `CONNECTING_SERVER` → `WAITING_SERVER_XMSG` → `X_FAST_FORWARD` → `X_SESSION_CLOSING` |
| **Key methods** | `handler()` — top-level dispatcher using `switch(status)` with `to_process` flag. `handler_connecting_client()` — wait for first frame, detect message type. `handler_capabilities_get()` — build and send `ServerCapabilities`. `handler_capabilities_set()` — process TLS request, send OK. `handler_auth_start()` / `handler_auth_challenge_response()` — MYSQL41 challenge-response. `dispatch_client_message(msg_type)` — protocol-aware dispatch for all 23 client message types. `handler_waiting_server_msg()` — forward backend frames to client. `handler_fast_forward()` — bidirectional frame relay. |
| **Thread safety** | Each session is owned by exactly one `Mysqlx_Thread`. No cross-thread access. The session reads from `MysqlxConfigStore` using shared (reader) locks. |

### 3.3 MysqlxDataStream — Non-Blocking Frame I/O

| | |
|---|---|
| **Header** | `plugins/mysqlx/include/mysqlx_data_stream.h` |
| **Source** | `plugins/mysqlx/src/mysqlx_data_stream.cpp` |
| **Responsibility** | Non-blocking X Protocol frame parsing from raw TCP byte streams. Handles partial reads: accumulates bytes in a read buffer, parses complete frames (5-byte header + protobuf body), and queues them for the session. Writes are buffered and flushed when `POLLOUT` is available. Supports TLS mode via OpenSSL (encrypted flag). |
| **Key methods** | `init(type, fd)` — set type (FRONTEND/BACKEND/LISTENER) and non-blocking fd. `feed_bytes(data, len)` — append bytes, trigger frame parsing. `has_complete_frame()` / `front_frame()` / `pop_frame()` — frame queue access. `enqueue_frame(msg_type, body, len)` — buffer an X Protocol frame for writing. `read_from_net()` — `recv()` → `feed_bytes()`. `write_to_net()` — flush write buffer via `send()`. |
| **Thread safety** | Each data stream is owned by exactly one session, which is owned by one thread. No concurrent access. |
| **Constants** | `X_FRAME_HEADER_SIZE = 5` (4 bytes LE payload size + 1 byte message type). `X_MAX_PAYLOAD_SIZE = 16MB`. |

### 3.4 MysqlxConnection — Pooled Backend Connection

| | |
|---|---|
| **Header** | `plugins/mysqlx/include/mysqlx_connection.h` |
| **Source** | `plugins/mysqlx/src/mysqlx_connection.cpp` |
| **Responsibility** | Backend connection object for connection pooling. Tracks connection state (CREATED → CONNECTING → AUTHENTICATING → IDLE → IN_USE), multiplexing eligibility (transactions and prepared statements disable reuse), and connection metadata (hostgroup, user, schema, address, port). Supports non-blocking `connect()` with `EINPROGRESS`. |
| **Key methods** | `is_reusable()` — true only if state is IDLE, not in transaction, no prepared statements. `reset()` — clear transaction/stmt flags, mark reusable. `start_connect(host, port)` — non-blocking `socket(SOCK_NONBLOCK)` + `connect()`, returns 0 (immediate), 1 (EINPROGRESS), or -1 (error). `check_connect()` — verify `SO_ERROR == 0` after poll returns. |
| **Thread safety** | Owned by one thread at a time. When in the per-thread cache, protected by the thread's `conn_cache_mutex_`. |

### 3.5 mysqlx_plugin (Entry Point)

| | |
|---|---|
| **Header** | `plugins/mysqlx/include/mysqlx_plugin.h` |
| **Source** | `plugins/mysqlx/src/mysqlx_plugin.cpp` |
| **Responsibility** | Plugin entry point. Exports `proxysql_plugin_descriptor_v1` — the single symbol the PluginManager resolves. Owns the plugin context: a `MysqlxConfigStore`, the cached `ProxySQL_PluginServices*`, the `Mysqlx_Thread` pool, and the `route_to_thread` mapping. Creates N `Mysqlx_Thread` instances on start, joins them on stop. |
| **Key methods** | `mysqlx_init(services)` — create config/stats stores, register admin tables and commands via the services pointer. `mysqlx_start()` — load config from runtime SQLite, create thread pool, add listeners to threads, start all threads. `mysqlx_stop()` — stop and join all threads, free resources. `mysqlx_status_json()` — return a JSON string for monitoring. |
| **Thread safety** | The descriptor functions are called sequentially by the PluginManager during startup/shutdown. No concurrent access to the plugin context during `init`/`start`/`stop`. |

### 3.6 mysqlx_config_store

| | |
|---|---|
| **Header** | `plugins/mysqlx/include/mysqlx_config_store.h` |
| **Source** | `plugins/mysqlx/src/mysqlx_config_store.cpp` |
| **Responsibility** | Authoritative in-memory store of mysqlx configuration. **This is the canonical state** — the editable `mysqlx_*` admin tables are persistent input, the `runtime_mysqlx_*` tables are admin-side projections of this store (see §10.2). Maintains: identities (user → hostgroup + credentials), routes (name → listener bind + destination hostgroup), endpoint overrides (per-host X-Protocol port), per-hostgroup endpoint lists rebuilt from `runtime_mysql_servers`, topology generation tracking, TLS configuration, and connection pool settings. |
| **Key methods** | Per-entity install (LOAD path): `install_users_from_admin(db, err)`, `install_routes_from_admin(db, err)`, `install_endpoints_from_admin(db, err)`, `install_variables_from_admin(db, err)` — each SELECTs the editable `mysqlx_<X>` table (plus, for users, `runtime_mysql_users` for canonical identity, and for endpoints, `runtime_mysql_servers` for the hostgroup → host topology), builds a fresh local map, and atomically swaps it under the exclusive lock. Per-entity save (SAVE path): `save_users_to_admin_table(db)`, `save_routes_to_admin_table(db)`, `save_endpoints_to_admin_table(db)`, `save_variables_to_admin_table(db)` — dump current store state into the editable `mysqlx_<X>` table (UPDATE active=0, then REPLACE INTO with active=1). Per-entity projection (runtime-view refresh): `project_users_to_runtime_view(db)` etc. — `DELETE FROM runtime_mysqlx_<X>; INSERT ... <store dump>`. Lookups: `resolve_identity(username)`, `pick_endpoint(route_name)`, `route_exists(route_name)`. |
| **Thread safety** | `std::shared_mutex` — shared (reader) lock for lookups and projections, exclusive (writer) lock for the install/save paths. |

### 3.7 mysqlx_stats

| | |
|---|---|
| **Header** | `plugins/mysqlx/include/mysqlx_stats.h` |
| **Source** | `plugins/mysqlx/src/mysqlx_stats.cpp` |
| **Responsibility** | Per-route atomic counters tracking connections, queries, errors, and bytes transferred. Periodically flushes aggregated statistics to the `stats_mysqlx_routes` SQLite table. |
| **Thread safety** | All counters are `std::atomic<uint64_t>`. Lock-free per-counter increments. |

### 3.8 mysqlx_admin_schema

| | |
|---|---|
| **Header** | `plugins/mysqlx/include/mysqlx_admin_schema.h` |
| **Source** | `plugins/mysqlx/src/mysqlx_admin_schema.cpp` |
| **Responsibility** | Admin table DDL definitions, variable definitions, LOAD/SAVE command handlers, and runtime-view refresh callbacks. Defines the schema for the editable tables (`mysqlx_users`, `mysqlx_routes`, `mysqlx_backend_endpoints`, `mysqlx_variables`) and the projected views (`runtime_mysqlx_*`). LOAD/SAVE callbacks interact with `MysqlxConfigStore` directly (via `install_*_from_admin` / `save_*_to_admin_table`) — they do NOT do SQLite-to-SQLite copies between editable and runtime tables. The four `refresh_<X>_runtime_view` free functions are registered with the chassis via `services.register_runtime_view()` during schema registration; they fire when admin executes a `SELECT` against a `runtime_mysqlx_*` table and call `MysqlxConfigStore::project_<X>_to_runtime_view`. |
| **New v2 variables** | `mysqlx_thread_pool_size` (default 4), `mysqlx_connect_timeout` (default 10000ms), `mysqlx_tls_mode` (default DISABLED), `mysqlx_tls_cert`, `mysqlx_tls_key`, `mysqlx_tls_ca`, `mysqlx_tls_backend_mode` (default DISABLED), `mysqlx_max_cached_connections_per_thread` (default 100). |

## 4. Thread Pool Architecture

### 4.1 Thread Pool Diagram

```
                    mysqlx_start()
                         │
           ┌─────────────┼─────────────┐
           │             │             │
    ┌──────┴──────┐ ┌────┴─────┐ ┌────┴──────┐
    │Mysqlx_Thread│ │Mysqlx_   │ │Mysqlx_    │
    │     #0      │ │Thread #1 │ │Thread #N  │
    │             │ │          │ │           │
    │ poll() {    │ │ poll() { │ │ poll() {  │
    │   listener  │ │  ...     │ │  ...      │
    │   sess[0]   │ │          │ │           │
    │   sess[1]   │ │          │ │           │
    │   ...       │ │          │ │           │
    │   sess[K]   │ │          │ │           │
    │   signal_fd │ │          │ │           │
    │ }           │ │ }        │ │ }         │
    │             │ │          │ │           │
    │ conn_cache  │ │conn_cache│ │conn_cache │
    └─────────────┘ └──────────┘ └───────────┘

    Each thread:
    - Independent poll() loop (200ms timeout)
    - Listeners baked into poll set (no separate accept thread)
    - Thousands of concurrent sessions
    - Per-thread connection cache (no lock contention)
```

### 4.2 Cooperative Multitasking Model

Sessions never block. Each session's `handler()` method:
1. Reads available bytes from the client data stream
2. Dispatches based on the current session state
3. Processes any complete frames
4. Flushes pending writes
5. Returns control to the thread

If a session needs more data (e.g., waiting for a client response), it returns immediately. The thread's `poll()` call will wake up when data arrives and call the session's handler again.

```
  Thread run() loop:
  ┌────────────────────────────────────────┐
  │ while (running):                       │
  │   housekeeping()                       │
  │   nfds = poll(poll_fds, timeout=200ms) │
  │   process_ready_fds(nfds)              │
  │     → accept new connections           │
  │     → mark sessions with pending data  │
  │   process_all_sessions()               │
  │     → for each session:                │
  │       sess.handler()                   │
  │       update poll events               │
  │       cleanup if unhealthy             │
  └────────────────────────────────────────┘
```

## 5. Session State Machine

### 5.1 State Diagram

```
                    ┌─────────────────┐
                    │  NONE           │
                    └────────┬────────┘
                             │ init(fd)
                    ┌────────▼────────┐
                    │ CONNECTING_     │──── wait for first frame
                    │ CLIENT          │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼──────┐      │      ┌───────▼────────┐
     │ X_CAPABILITIES│      │      │ X_AUTH_START   │
     │ _GET          │      │      │ (skip caps)    │
     └────────┬──────┘      │      └───────┬────────┘
              │              │              │
     ┌────────▼──────┐      │              │
     │ X_CAPABILITIES│      │              │
     │ _SET          │      │              │
     └────────┬──────┘      │              │
              │              │              │
     ┌────────▼──────┐      │              │
     │ X_TLS_ACCEPT_ │──────┤              │
     │ INIT/CONT/DONE│      │              │
     │ (if TLS)      │      │              │
     └────────┬──────┘      │              │
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │ X_AUTH_START    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ X_AUTH_CHALLENGE│
                    │ _SENT           │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ X_AUTH_OK_SENT  │──── or X_AUTH_FAILED → closing
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ WAITING_CLIENT_ │◄────────────────────────┐
                    │ XMSG            │                         │
                    └────────┬────────┘                         │
                             │ dispatch_client_message()        │
              ┌──────────────┼──────────────┐                   │
              │              │              │                   │
     ┌────────▼──────┐      │      ┌───────▼────────┐          │
     │ CONNECTING_   │      │      │ forward to     │          │
     │ SERVER        │      │      │ backend        │          │
     └────────┬──────┘      │      └───────┬────────┘          │
              │              │              │                   │
              │              │      ┌───────▼────────┐          │
              │              │      │ WAITING_SERVER_│          │
              │              │      │ XMSG           │          │
              │              │      └───────┬────────┘          │
              │              │              │                   │
              │              │      ┌───────▼────────┐          │
              │              │      │ X_FAST_FORWARD │──────────┘
              │              │      └────────────────┘
              │              │
     ┌────────▼──────────────▼───────┐
     │ X_SESSION_CLOSING / X_SESSION │
     │ _CLOSED                       │
     └───────────────────────────────┘
```

### 5.2 State Reference (22 States)

| State | Description |
|-------|-------------|
| `NONE` | Initial state before `init()` |
| `CONNECTING_CLIENT` | Waiting for first client frame |
| `X_CAPABILITIES_GET` | Processing CapabilitiesGet |
| `X_CAPABILITIES_SET` | Processing CapabilitiesSet (may trigger TLS) |
| `X_AUTH_START` | Authentication initiated |
| `X_AUTH_CHALLENGE_SENT` | MYSQL41 challenge sent, waiting for response |
| `X_AUTH_OK_SENT` | Authentication successful |
| `X_AUTH_FAILED` | Authentication failed |
| `WAITING_CLIENT_XMSG` | Main loop: waiting for client message (dispatches all 23 types) |
| `PROCESSING_X_QUERY` | Processing a SQL statement |
| `CONNECTING_SERVER` | Establishing backend connection (pool-first, then async connect) |
| `WAITING_SERVER_XMSG` | Waiting for backend response frames |
| `X_FAST_FORWARD` | Bidirectional frame relay |
| `X_TLS_ACCEPT_INIT` | Starting TLS handshake (server-side, client connection) |
| `X_TLS_ACCEPT_CONT` | TLS handshake in progress |
| `X_TLS_ACCEPT_DONE` | TLS handshake complete |
| `X_TLS_CONNECT_INIT` | Starting TLS handshake (client-side, backend connection) |
| `X_TLS_CONNECT_CONT` | Backend TLS in progress |
| `X_TLS_CONNECT_DONE` | Backend TLS complete |
| `X_SESSION_CLOSING` | Session shutting down |
| `X_SESSION_CLOSED` | Session terminated |
| `X_SESSION_RESET_WAITING` | Waiting for backend response to SESS_RESET |

## 6. Data Stream I/O — Non-Blocking Frame Parsing

### 6.1 Frame Format

X Protocol frames consist of a 5-byte header followed by a protobuf body:

```
┌───────────────────────────────────────────────┐
│ payload_size (4 bytes, little-endian)          │  ← includes msg_type byte
│ msg_type (1 byte)                              │
│ protobuf body (payload_size - 1 bytes)         │
└───────────────────────────────────────────────┘
```

### 6.2 Partial Frame Buffering

`MysqlxDataStream` handles partial reads from non-blocking sockets:

```
  recv() returns N bytes (may be less than a full frame)
       │
       ▼
  feed_bytes(data, N)
       │
       ▼
  read_buf_ += data
       │
       ▼
  try_parse_frame()
       │
       ├── available < 5 bytes? → return false (need header)
       │
       ├── decode payload_size from header
       │   payload_size < 1 or > 16MB? → parse error
       │
       ├── available < frame_total? → return false (need body)
       │
       └── copy frame → complete_frames_.push()
           advance read_offset_
           try again (may be more frames in buffer)
```

### 6.3 Write Buffering

```
  enqueue_frame(msg_type, body, body_len)
       │
       ▼
  write_buf_ += [4-byte payload_size][msg_type][body]
       │
       ▼
  Thread sets POLLOUT on fd when write_buf_ is non-empty
       │
       ▼
  write_to_net() → send() → advance write_offset_
       │
       ▼
  write_buf_.clear() when fully flushed
```

## 7. Connection Pool

### 7.1 Two-Tier Pool Model

```
  Session needs backend connection
       │
       ▼
  ┌─────────────────────────────────┐
  │ Tier 1: Per-thread cache        │
  │ (no lock contention)            │
  │                                 │
  │ Search: hostgroup + user +      │
  │ schema match, reusable, no      │
  │ active transaction/stmt         │
  │                                 │
  │ Found? → attach, set IN_USE     │
  │ Not found? → ↓                  │
  └─────────────┬───────────────────┘
                │
                ▼
  ┌─────────────────────────────────┐
  │ Create new connection           │
  │                                 │
  │ Non-blocking connect()          │
  │ Authenticate via MYSQL41        │
  │ Set IDLE + reusable             │
  └─────────────────────────────────┘

  When query completes:
       │
       ▼
  return_connection_to_cache()
       │
       ├── reset() — clear tx/stmt flags
       ├── set_state(IDLE)
       └── push to thread's conn_cache_
              │
              ├── cache size > max_cached_?
              │   → evict oldest (FIFO)
              └── done
```

### 7.2 Pool Matching Rules

A cached connection is returned only if ALL match:
- Same `hostgroup`
- Same `user`
- Same `schema`
- `is_reusable() == true` (state is IDLE, no transaction, no prepared statement)

### 7.3 Pool Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `mysqlx_max_cached_connections_per_thread` | 100 | Max cached connections per thread |

## 8. Frame Forwarding — Protocol-Aware Dispatch

### 8.1 All 23 Client Message Types

The session's `dispatch_client_message()` handles every X Protocol client message type:

| Message | Action | Category |
|---------|--------|----------|
| `CON_CAPABILITIES_GET` | Handle locally (send capabilities) | Connection |
| `CON_CAPABILITIES_SET` | Handle locally (process TLS request) | Connection |
| `CON_CLOSE` | Handle locally (close session) | Connection |
| `SESS_AUTHENTICATE_START` | Handle locally (start auth) | Session |
| `SESS_AUTHENTICATE_CONTINUE` | Handle locally (continue auth) | Session |
| `SESS_RESET` | Forward to backend | Session |
| `SESS_CLOSE` | Handle locally (close session) | Session |
| `SQL_STMT_EXECUTE` | Forward to backend | SQL |
| `CRUD_FIND` | Forward to backend | CRUD |
| `CRUD_INSERT` | Forward to backend | CRUD |
| `CRUD_UPDATE` | Forward to backend | CRUD |
| `CRUD_DELETE` | Forward to backend | CRUD |
| `EXPECT_OPEN` | Forward to backend | Expect |
| `EXPECT_CLOSE` | Forward to backend | Expect |
| `CRUD_CREATE_VIEW` | Forward to backend | View |
| `CRUD_MODIFY_VIEW` | Forward to backend | View |
| `CRUD_DROP_VIEW` | Forward to backend | View |
| `PREPARE_PREPARE` | Forward to backend (mark conn has stmt) | Prepared Stmt |
| `PREPARE_EXECUTE` | Forward to backend | Prepared Stmt |
| `PREPARE_DEALLOCATE` | Forward to backend | Prepared Stmt |
| `CURSOR_OPEN` | Forward to backend | Cursor |
| `CURSOR_CLOSE` | Forward to backend | Cursor |
| `CURSOR_FETCH` | Forward to backend | Cursor |

Unknown message types receive `ER_X_BAD_MESSAGE` error and session closure.

### 8.2 Backend Response Forwarding

Multi-frame responses from the backend (e.g., column metadata → rows → fetch done) are forwarded frame-by-frame to the client. The session reads all available frames from the server data stream and enqueues each one on the client data stream.

## 9. TLS Architecture

### 9.1 TLS Modes

| Mode | Frontend Behavior | Backend Behavior |
|------|-------------------|------------------|
| `DISABLED` | No `tls` capability advertised. Plaintext only. | Plaintext only. |
| `PREFERRED` | `tls` capability advertised. Client chooses. | TLS if backend supports. |
| `REQUIRED` | `tls` capability advertised. Reject client that doesn't upgrade. | TLS required. |

Default: `DISABLED`. Frontend TLS uses OpenSSL Memory BIO pattern (SSL_new, BIO_new_mem_buf, SSL_set_accept_state). Backend TLS negotiates via CapabilitiesSet.

### 9.2 TLS State Machine

TLS negotiation integrates into the session state machine:

```
  X_CAPABILITIES_SET
       │
       ├── client requests TLS? AND tls_mode != DISABLED
       │         │
       │         ▼
       │   X_TLS_ACCEPT_INIT
       │         │
       │         ▼
       │   X_TLS_ACCEPT_CONT (SSL_accept loop)
       │         │
       │         ▼
       │   X_TLS_ACCEPT_DONE
       │         │
       │         ▼
       │   X_AUTH_START
       │
       └── no TLS requested
              │
              ▼
         X_AUTH_START
```

### 9.3 OpenSSL Memory BIO Pattern

Following the same pattern as `MySQL_Data_Stream`:

```
  Read path:
    recv(fd) → BIO_write(rbio_ssl) → SSL_read(ssl) → feed_bytes()

  Write path:
    SSL_write(ssl, data) → BIO_read(wbio_ssl) → send(fd)
```

Each `MysqlxDataStream` has `encrypted_` flag, `SSL*`, `rbio_ssl`, `wbio_ssl` members.

## 10. Data Flow Diagrams

### 10.1 Client Connection Flow (v2)

```
Client         Mysqlx_Thread      MysqlxSession     ConfigStore      MysqlxConnection   MySQL
  │                  │                  │                 │                  │              │
  │── TCP connect ──→│                  │                 │                  │              │
  │                  │── accept ──────→ │                 │                  │              │
  │                  │   (in poll set)  │                 │                  │              │
  │←── Capabilities ──────────────────│                 │                  │              │
  │── CapSet ────────────────────────→│                 │                  │              │
  │                  │                  │ (optional TLS)  │                  │              │
  │←── AuthStart ─────────────────────│                 │                  │              │
  │                  │                  │── resolve ────→│                  │              │
  │── AuthContinue ──────────────────→│                 │                  │              │
  │←── AuthOk ────────────────────────│                 │                  │              │
  │                  │                  │── pool lookup ──────────────────→│              │
  │                  │                  │   (miss)        │                  │              │
  │                  │                  │── async connect ─────────────────────────────→  │
  │── SQL/CRUD ─────────────────────→│                 │                  │── forward ──→│
  │                  │                  │                 │                  │←── result ───│
  │←── result ────────────────────────│                 │                  │              │
```

### 10.2 Admin Command Flow

The mysqlx plugin follows the canonical Admin/module separation of duties used by core's `mysql_users` / `GloMyAuth` / `runtime_mysql_users` triplet (see `lib/ProxySQL_Admin.cpp::save_mysql_users_runtime_to_database`):

* **Admin** owns the editable tables (`mysqlx_users`, `mysqlx_routes`, `mysqlx_backend_endpoints`, `mysqlx_variables`) and the chassis dispatch glue.
* **`MysqlxConfigStore`** owns the authoritative runtime state in process memory.
* **`runtime_mysqlx_*`** are *not* persistent storage. They are admin-side **views** of the store, rebuilt on demand by a refresh callback that the plugin registered via `services.register_runtime_view()`.

#### 10.2.1 LOAD path — editable table → module

`LOAD MYSQLX USERS TO RUNTIME` does **not** copy `mysqlx_users` into `runtime_mysqlx_users`. The runtime table is never written by this path.

```
Admin Client       Admin Handler   PluginManager   mysqlx_admin_schema           MysqlxConfigStore
     │                  │                │                  │                            │
     │── LOAD MYSQLX ──→│                │                  │                            │
     │   USERS TO       │                │                  │                            │
     │   RUNTIME        │                │                  │                            │
     │                  │── alias ─────→│                  │                            │
     │                  │   normalize    │── dispatch ────→│                            │
     │                  │                │                  │── install_users_from_admin →│
     │                  │                │                  │   reads:                   │   SELECT runtime_mysql_users
     │                  │                │                  │   - runtime_mysql_users    │   SELECT mysqlx_users
     │                  │                │                  │     (canonical identity)   │     WHERE active=1
     │                  │                │                  │   - mysqlx_users           │
     │                  │                │                  │     (X-side overlay)       │   build new unordered_map,
     │                  │                │                  │                            │   atomic swap under
     │                  │                │                  │                            │   shared_mutex.
     │←── OK ──────────│←──────────────│←────────────────│←──────────────────────────│
```

Same shape for `LOAD MYSQLX ROUTES`, `LOAD MYSQLX BACKEND ENDPOINTS`, and `LOAD MYSQLX VARIABLES TO RUNTIME` — each calls its own `install_<X>_from_admin`. None of them touch `runtime_mysqlx_<X>`.

#### 10.2.2 Runtime-view refresh — module → projected view (on SELECT)

When an operator runs `SELECT * FROM runtime_mysqlx_users`, Admin's pre-SELECT hook detects the table name and walks the chassis registry of runtime views (see `proxysql_refresh_configured_plugin_runtime_views` in `lib/ProxySQL_PluginManager.cpp`). For each registered view whose `table_name` appears as a whole identifier in the query, it invokes the plugin-supplied refresh callback **before** the SELECT runs.

```
Admin Client       Admin pre-SELECT hook        Chassis dispatch         mysqlx refresh cb        MysqlxConfigStore
     │                    │                            │                         │                         │
     │── SELECT * ───────→│                            │                         │                         │
     │   FROM runtime_    │── refresh views? ────────→│                         │                         │
     │   mysqlx_users     │                            │── matches view ───────→│                         │
     │                    │                            │   "runtime_mysqlx_     │── project_users_to_     →│
     │                    │                            │    users"              │   runtime_view(admindb)  │
     │                    │                            │                         │                         │   under shared_mutex:
     │                    │                            │                         │                         │   DELETE FROM
     │                    │                            │                         │                         │     runtime_mysqlx_users;
     │                    │                            │                         │                         │   INSERT INTO
     │                    │                            │                         │                         │     runtime_mysqlx_users
     │                    │                            │                         │                         │     <dump store state>
     │                    │── now run SELECT ─────────────────────────────────────────────────────────────→│
     │←── rows ───────────│                                                                                  │
```

The view is wiped and refilled on every qualifying SELECT, so deletions in the store always propagate. There is brief duplication (data lives in the module *and* in the projected admin table during the query) — that is by design, mirroring the canonical core pattern.

#### 10.2.3 SAVE path — module → editable table

`SAVE MYSQLX USERS FROM RUNTIME TO MEMORY` does **not** read `runtime_mysqlx_users`. It dumps the store directly into `mysqlx_users` (UPDATE active=0, then REPLACE INTO with active=1, mirror of the canonical pattern).

```
Admin Client       Admin Handler   PluginManager   mysqlx_admin_schema           MysqlxConfigStore
     │                  │                │                  │                            │
     │── SAVE MYSQLX ──→│                │                  │                            │
     │   USERS FROM     │                │                  │                            │
     │   RUNTIME TO     │── alias ─────→│                  │                            │
     │   MEMORY         │   normalize    │── dispatch ────→│                            │
     │                  │                │                  │── save_users_to_admin_ ───→│
     │                  │                │                  │   table(admindb)           │
     │                  │                │                  │                            │   under shared_mutex:
     │                  │                │                  │   writes:                  │   UPDATE mysqlx_users
     │                  │                │                  │   - mysqlx_users           │     SET active=0;
     │                  │                │                  │     (editable, persistent) │   REPLACE INTO
     │                  │                │                  │                            │     mysqlx_users
     │                  │                │                  │                            │     <dump store state,
     │                  │                │                  │                            │      active=1>
     │←── OK ──────────│←──────────────│←────────────────│←──────────────────────────│
```

#### 10.2.4 Disk tier

`LOAD MYSQLX <X> FROM DISK` and `SAVE MYSQLX <X> TO DISK` are unchanged — those copy between disk-backed and in-memory editable tables and have no module involvement. They remain plain `BEGIN; DELETE; INSERT; COMMIT` admin-tier persistence.

#### 10.2.5 What changed from earlier versions

Earlier revisions of this plugin treated `runtime_mysqlx_users` (and the other `runtime_mysqlx_*` tables) as authoritative SQLite-backed mirrors populated by `LOAD ... TO RUNTIME` via `INSERT INTO runtime_mysqlx_users SELECT * FROM mysqlx_users`. `MysqlxConfigStore` had a single `load_from_runtime()` that read those mirrors back into memory, and `mysqlx_admin_schema` did a `copy_table` SQLite-to-SQLite copy on every LOAD. Operators relying on that mental model need to unlearn it: the runtime tables now hold no persistent rows of their own, the LOAD path bypasses them entirely, and only the on-demand projection callback ever touches them.

## 11. Thread Model

```
Main Thread
  ├── ProxySQL_PluginManager::load()        (dlopen, dlsym)
  ├── ProxySQL_PluginManager::init_all()    (register tables/commands)
  ├── ProxySQL_PluginManager::start_all()   (start thread pool)
  │     └── mysqlx_start()
  │           ├── sync_disk_to_memory()              (disk → editable mysqlx_* tables)
  │           ├── config_store->install_users_from_admin()       (mysqlx_users → store)
  │           ├── config_store->install_routes_from_admin()      (mysqlx_routes → store)
  │           ├── config_store->install_endpoints_from_admin()   (mysqlx_backend_endpoints → store)
  │           ├── config_store->install_variables_from_admin()   (mysqlx_variables → store)
  │           └── Create N Mysqlx_Thread instances
  │                 ├── Mysqlx_Thread #0 (poll loop, listeners, sessions, conn cache)
  │                 ├── Mysqlx_Thread #1 (poll loop, listeners, sessions, conn cache)
  │                 └── Mysqlx_Thread #N ...
  └── ProxySQL_PluginManager::stop_all()
        └── mysqlx_stop()
              └── Stop and join all Mysqlx_Thread instances
```

### Thread Lifecycle

1. **Startup (Main Thread)**: The main thread calls `PluginManager::load()` which dlopens the plugin shared library. Then `init_all()` invokes the plugin's `init()` callback, which registers admin tables, commands, and the four runtime-view refresh callbacks via `services.register_runtime_view()`. Then `start_all()` invokes `mysqlx_start()`, which (1) syncs the on-disk admin tables into the in-memory editable tables, (2) drives the four `install_<X>_from_admin` calls to populate `MysqlxConfigStore` from those editable tables (plus `runtime_mysql_users` for canonical identity), (3) creates N `Mysqlx_Thread` instances, (4) adds listeners based on configured routes, and (5) starts all threads.

2. **Mysqlx_Thread**: Each thread runs an independent `poll()` loop. Listener sockets are baked into the poll set (no separate accept thread). When `POLLIN` fires on a listener fd, the thread calls `accept()`, creates a `MysqlxSession`, and adds the client data stream to the poll set. Sessions are processed cooperatively — each session's `handler()` returns immediately when waiting for I/O.

3. **Shutdown (Main Thread)**: The main thread calls `PluginManager::stop_all()`, which invokes `mysqlx_stop()`. This sets the running flag to false on each thread, writes to the signal pipe to wake up `poll()`, and joins all threads.

### Thread Safety Summary

| Resource | Mechanism | Scope |
|---|---|---|
| `MysqlxConfigStore` caches | `std::shared_mutex` | Shared for reads (`resolve_identity`, `pick_endpoint`, `project_<X>_to_runtime_view`); exclusive for the install / save paths |
| `MysqlxStatsStore` counters | `std::atomic<uint64_t>` | Lock-free per-counter increments |
| `ProxySQL_PluginManager` dispatch | `std::mutex` | Guards command dispatch |
| Per-thread connection cache | `std::mutex` | Per-thread, no inter-thread contention |
| `MysqlxSession` / `MysqlxDataStream` | None needed | Single-owner (one thread) |

## 12. Build System

### 12.1 File Structure (v2)

```
plugins/mysqlx/
  ├── Makefile
  ├── mysqlx_plugin.cpp/.h             # Entry point (rewritten for v2)
  ├── mysqlx_thread.cpp/.h             # Event loop (NEW)
  ├── mysqlx_session.cpp/.h            # State machine (NEW)
  ├── mysqlx_data_stream.cpp/.h        # Non-blocking frame I/O (NEW)
  ├── mysqlx_connection.cpp/.h         # Pooled backend connection (NEW)
  ├── mysqlx_protocol.cpp/.h           # Frame encode/decode helpers
  ├── mysqlx_config_store.cpp/.h       # Config cache (modified for v2)
  ├── mysqlx_stats.cpp/.h              # Stats counters
  ├── mysqlx_admin_schema.cpp/.h       # Admin tables/commands (new variables)
  └── protobuf/                        # Pre-generated protobuf sources
```

### 12.2 Build Commands

```bash
# Build the plugin (from project root or plugins/mysqlx/)
make -C plugins/mysqlx

# Output: plugins/mysqlx/mysqlx_plugin.so
```

### 12.3 Dependencies

| Dependency | Purpose |
|---|---|
| **protobuf** | X Protocol message serialization/deserialization |
| **OpenSSL** | SHA1 hash for MYSQL41 auth, TLS (Memory BIOs), `CRYPTO_memcmp` |
| **SQLite3** | Admin/runtime database access (via PluginServices pointers) |

## 13. Comparison: Phase 1 vs Phase 2 vs MySQL Router

| Aspect | Phase 1 | Phase 2 (v2) | MySQL Router |
|--------|---------|--------------|--------------|
| **Threading** | 1 thread, 1 session, blocking | N threads, thousands of sessions per thread | Event-driven |
| **I/O model** | Blocking `read()`/`write()` | Non-blocking `poll()` | Non-blocking I/O |
| **Frame forwarding** | Blind TCP relay | Protocol-aware: all 23 message types | Protocol-aware |
| **TLS** | Not implemented | 3 modes (Disabled/Preferred/Required) | 3 modes + passthrough |
| **Connection pooling** | None (1:1 pinned) | Two-tier: per-thread + global | None |
| **Backend connect** | Blocking `connect()` | Non-blocking `connect()` with `EINPROGRESS` | Non-blocking |
| **Error handling** | Basic string errors | Full X Protocol error frames | Full error frames |
| **Message awareness** | 5 types (handshake) | All 23 client + server types | All types |
| **Routing** | Static route → single endpoint | Hostgroup-based with pool | Static routing |
| **Auth** | MYSQL41/PLAIN verify | MYSQL41/PLAIN + credential mapping | Passthrough |
| **Admin interface** | LOAD/SAVE MYSQLX tables | Same + new variables | Config file only |
| **Concurrency** | 1 session at a time | Thousands per thread | Concurrent |

## 14. MYSQL41 Authentication Internals

X Protocol supports multiple authentication mechanisms. The mysqlx plugin implements **MYSQL41**, which is the native MySQL authentication adapted for the X Protocol. It uses a challenge-response mechanism based on double-SHA1 hashing.

### 14.1 Double-SHA1 Algorithm

```
hash_stage1 = SHA1(password)
hash_stage2 = SHA1(hash_stage1)
scramble    = XOR(hash_stage1, SHA1(challenge + hash_stage2))
```

### 14.2 Server-Side Verification

```
received_scramble = auth_data from client
hash_stage2       = SHA1(stored_hash)
candidate         = SHA1(challenge || hash_stage2)
hash_stage1       = XOR(received_scramble, candidate)
computed_stage2   = SHA1(hash_stage1)

verified = CRYPTO_memcmp(computed_stage2, hash_stage2, 20) == 0
```

### 14.3 Authentication Flow Diagram

```
Client                          ProxySQL (Frontend)               MySQL (Backend)
  │                                    │                               │
  │── AuthenticateStart ──────────────→│                               │
  │   (mechanism: MYSQL41)             │                               │
  │←── AuthenticateContinue ───────────│                               │
  │   (challenge: 20-byte nonce)       │                               │
  │                                    │                               │
  │── AuthContinue ───────────────────→│                               │
  │   (auth_data: 20-byte scramble)    │                               │
  │                                    │── verify scramble ──→         │
  │                                    │   (if proxying auth)          │
  │                                    │                               │
  │                                    │── connect to backend ────────→│
  │                                    │── AuthenticateStart ─────────→│
  │                                    │←── AuthenticateContinue ─────│
  │                                    │── AuthContinue ──────────────→│
  │                                    │←── AuthenticateOk ───────────│
  │                                    │                               │
  │←── AuthenticateOk ────────────────│                               │
  │                                    │                               │
```

### 14.4 Security Considerations

- **No password storage in plugin**: The plugin stores the double-SHA1 hash, not the plaintext password.
- **Constant-time comparison**: All hash comparisons use `CRYPTO_memcmp` to prevent timing attacks.
- **Challenge freshness**: The 20-byte challenge is generated per-connection using OpenSSL's `RAND_bytes`.
- **TLS recommended**: PLAIN authentication should only be enabled when the client connection uses TLS.
