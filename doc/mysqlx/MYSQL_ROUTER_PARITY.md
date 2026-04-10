# MySQL Router X Protocol Parity Comparison

Comparison between MySQL Router 8.0's X Protocol implementation and the
ProxySQL X Protocol plugin, highlighting architectural differences, feature
gaps, and areas where ProxySQL is superior.

## Feature Comparison Table

| Feature | MySQL Router 8.0 | ProxySQL X Plugin |
|---|---|---|
| Source | `x_connection.cc` (~3200 lines) | `mysqlx_session.cpp` + `mysqlx_thread.cpp` (~970 lines) |
| Architecture | Async callback-based (ASIO-style) | poll()-based synchronous event loop |
| State machine | ~100 enum states | 15 states in `MysqlxSession::Status` |
| TLS modes | 5: Disabled, Preferred, Required, AsClient, Passthrough | Stub only (not yet implemented) |
| TLS termination | Full: Router terminates TLS, re-encrypts to backend | Not implemented |
| TLS passthrough | Yes - raw TLS record forwarding at record layer | No |
| Asymmetric TLS | Yes (client-TLS + backend-plain, or vice versa) | No |
| Authentication | Pass-through to backend (never sees passwords) | Local validation via credential_lookup callback |
| Auth methods | Whatever backend supports (proxied) | MYSQL41 and PLAIN (PLAIN requires TLS) |
| Lazy backend connect | Yes (on SESS_AUTH_START) | Yes (on first query via CONNECTING_SERVER) |
| Connection pooling | None for X Protocol | Per-thread LRU cache (default 100 conns) |
| Query-level routing | No (session pinned to one backend) | Yes via hostgroups |
| Routing strategies | FirstAvailable, NextAvailable, RoundRobin, RoundRobinWithFallback | Hostgroup-based with backend selection |
| Message types | 23 client types with dedicated response states | 23+ types dispatched via dispatch_client_message() |
| Terminal frame detection | Per-message-type state machine | Single is_terminal_server_frame() function |
| Capabilities handling | Full: generates own, checks server TLS capability | Generates own (MYSQL41 + PLAIN), sends Ok |
| Session Reset | Forwarded with response tracking | Forwarded |
| Session Close | Forwarded to backend | Client-side close, returns backend to pool |
| Prepared statements | Forwarded with per-type response states | Forwarded; tracks has_prepared_statement for pooling |
| Cursor operations | Full: CURSOR_OPEN/FETCH/CLOSE with dedicated states | Forwarded |
| View operations | Full: CREATE_VIEW/MODIFY_VIEW/DROP_VIEW | Forwarded |
| Expect blocks | Full: EXPECT_OPEN/CLOSE with dedicated states | Forwarded |
| Compression | Rejected with specific X Protocol error code | Rejected with generic "not supported" |
| Notice forwarding | Explicit mid-stream forwarding in all states | Part of normal frame forwarding |
| Max frame size | 16MB | 16MB (X_MAX_PAYLOAD_SIZE) |
| Handshake timeout | 9s (kDefaultClientConnectTimeout) | 10s (HANDSHAKE_TIMEOUT_MS) |
| Idle timeout | 0 (disabled by default) | 8h (IDLE_TIMEOUT_MS) |
| Max connections | Configurable, 0=unlimited | 10,000 per thread (max_sessions_) |
| Backend connect timeout | Configurable (destination_connect_timeout) | No explicit timeout (relies on TCP) |
| Thread model | Connection-per-thread from thread pool | Dedicated thread(s) with poll() loop |
| Admin interface | Config file based | SQL-based admin (mysqlx_admin_schema) |
| Plugin architecture | Compiled in, cannot be loaded/unloaded | Dynamically loaded .so plugin |

## Architectural Differences

### Authentication Philosophy

MySQL Router is a pure pass-through. It forwards AuthStart to the backend,
relays AuthContinue challenges to the client, and never sees or validates
passwords. This simplifies the router but prevents connection pooling.

ProxySQL validates credentials locally via the credential_lookup callback
against stored SHA1(SHA1(password)) hashes. This enables hostgroup-based
routing (different users to different backends) and connection pooling
(the router knows the credentials and can share connections across sessions).

### TLS Architecture

MySQL Router has an extremely sophisticated 5-mode TLS model:

- **Disabled**: No TLS on either side
- **Preferred**: TLS if client requests it via CapabilitiesSet
- **Required**: Reject client if they don't use TLS
- **AsClient**: Match client's TLS choice on backend
- **Passthrough**: Forward raw TLS records without termination

The Router's server_init_tls() orchestrates checking server capabilities,
sending CapabilitiesSet(tls=true) to backend, handling Ok/Error responses,
then calling tls_connect().

ProxySQL has TLS stubs only. handler_tls_accept_init() is a no-op. The
encrypted_ flag exists on MysqlxDataStream but is never set to true. This
is the biggest feature gap.

### Connection Lifecycle

MySQL Router: 1:1 client-to-backend mapping for the entire session. Backend
connected lazily on auth start, held until session ends. No pooling.

ProxySQL: Multiplexing architecture. Backend connections acquired from pool
per-query, returned after terminal response. Different queries can go to
different hostgroups/backends within the same client session.

### Response State Tracking

MySQL Router: Each message type has its own mini state machine with separate
forward/forward_last states. For example, StmtExecute knows that
ColumnMetaData and Row are non-terminal, while StmtExecuteOk and Error are
terminal.

ProxySQL: Single is_terminal_server_frame() function with a hardcoded list
of 7 terminal message types. All frames forwarded until terminal frame seen.

## Feature Gaps (Priority Order)

| Priority | Feature | Notes |
|---|---|---|
| P0 | TLS termination | Without TLS, PLAIN auth is unusable and MYSQL41 credentials are exposed |
| P0 | Backend TLS | Needed for end-to-end encryption; Router initiates TLS to backend via CapabilitiesSet |
| P1 | TLS passthrough | Forward raw TLS records without termination |
| P1 | Per-message response state machines | More robust handling of multi-frame responses |
| P1 | CapabilitiesSet TLS negotiation | Properly handle client requesting TLS via CapabilitiesSet |
| P2 | Backend connect timeout | Router has destination_connect_timeout; we rely on TCP |
| P2 | Notice forwarding awareness | Explicitly handle notices as non-terminal in all states |
| P2 | Compression protocol error code | Match MySQL's specific X Protocol error code |
| P3 | Session Reset passthrough | Full response tracking with pool invalidation |
| P3 | TLS error messages | Meaningful errors when backend TLS fails |

## Where ProxySQL is Superior

| Feature | Why ProxySQL Wins |
|---|---|
| Connection pooling | Per-thread LRU cache with reuse validation (transaction state, prepared statements). Router has zero X Protocol pooling. |
| Query-level routing | Routes queries to different hostgroups within a single session. Router pins session to one backend. |
| Local authentication | Validates credentials locally, enabling connection sharing. Router is pass-through with 1:1 mapping. |
| Multiplexing | Multiple client queries can share a single backend connection via pooling. Router cannot. |
| Dynamic configuration | SQL-based admin interface, runtime changes. Router requires config file changes and restart. |
| Session limits | Per-thread connection limits (default 10K). Router uses global limits. |
| Plugin architecture | Dynamically loaded .so. Router's X Protocol is compiled in. |
| Idle timeout | 8h idle timeout built in. Router defaults to disabled. |

## Summary

MySQL Router has a more mature protocol implementation (especially TLS with
5 modes, per-message-type state machines, and proper Capabilities negotiation),
but ProxySQL has a fundamentally superior proxy architecture (connection
pooling, query-level routing, multiplexing, local auth) that MySQL Router
does not support with its pass-through design.

The biggest gap to close is TLS; everything else is either a nice-to-have
or already handled differently by design.
