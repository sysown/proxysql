# MySQL Router X Protocol Parity Comparison

Comparison between MySQL Router 8.0's X Protocol implementation and the
ProxySQL X Protocol plugin, highlighting architectural differences, feature
gaps, and areas where ProxySQL is superior.

## Feature Comparison Table

| Feature | MySQL Router 8.0 | ProxySQL X Plugin |
|---|---|---|
| Source | `x_connection.cc` (~3200 lines) | `mysqlx_session.cpp` + `mysqlx_thread.cpp` (~970 lines) |
| Architecture | Async callback-based (ASIO-style) | poll()-based synchronous event loop |
| State machine | ~100 enum states | 23 states in `MysqlxSession::Status` |
| TLS modes | 5: Disabled, Preferred, Required, AsClient, Passthrough | All five at frontend × 4 backend: frontend `mysqlx_tls_mode` Disabled/Preferred/Required + per-route `mysqlx_routes.tls_mode` adds inherit/passthrough + backend disabled/preferred/required/as_client |
| TLS termination | Full: Router terminates TLS, re-encrypts to backend | Frontend: OpenSSL Memory BIO; Backend: CapabilitiesSet negotiation with mode-driven posture |
| TLS passthrough | Yes - raw TLS record forwarding at record layer | Yes via `mysqlx_routes.tls_mode='passthrough'` (issue #5692) — opt-in per route; the proxy splices raw bytes after CapabilitiesSet(tls=true) and never sees plaintext |
| Asymmetric TLS | Yes (client-TLS + backend-plain, or vice versa) | Yes via `mysqlx_tls_backend_mode` (issue #5693) — independent frontend / backend modes, AsClient parity |
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
| Backend connect timeout | Configurable (destination_connect_timeout) | 10s (HANDSHAKE_TIMEOUT_MS), configurable via mysqlx_connect_timeout |
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

MySQL Router has an extremely sophisticated 5-mode TLS model. ProxySQL
exposes equivalent posture via three orthogonal handles: the deployment-
wide `mysqlx_tls_mode` (frontend, three values), the deployment-wide
`mysqlx_tls_backend_mode` (backend, four values), and a per-route
override on `mysqlx_routes.tls_mode` (five values, including `passthrough`),
giving full Router parity including raw-record passthrough at route
granularity.

Frontend modes (`mysqlx_tls_mode`):

- **DISABLED**: No TLS capability advertised. Plaintext only.
- **PREFERRED**: TLS capability advertised. Client chooses to upgrade.
- **REQUIRED**: TLS capability advertised. Reject client if it does not upgrade.

Backend modes (`mysqlx_tls_backend_mode`, lowercase, default `as_client`):

- **disabled**: Never use TLS proxy↔backend.
- **preferred**: Try `CapabilitiesSet(tls=true)`; on backend `Mysqlx::Error`, silently downgrade to plaintext on the same TCP connection. Best-effort.
- **required**: TLS mandatory; backend `Mysqlx::Error` fails the connect with code 3152.
- **as_client**: Mirror the frontend leg's encryption choice (Router AsClient parity).

The per-endpoint flag `mysqlx_backend_endpoints.use_ssl=1` promotes
plaintext to TLS for one specific backend regardless of mode (override).

ProxySQL implements frontend TLS using OpenSSL Memory BIOs (SSL_new,
BIO_new_mem_buf, SSL_set_accept_state), integrated into the session state
machine via X_TLS_ACCEPT_INIT/CONT/DONE states. Backend TLS is negotiated
via CapabilitiesSet, with the per-session decision driven by
`mysqlx_resolve_backend_tls_decision()` against the four-mode runtime
variable.

Per-route passthrough (`mysqlx_routes.tls_mode='passthrough'`,
issue #5692) takes a different path: once the client sends
`CapabilitiesSet(tls=true)` on a passthrough-flagged route, the session
transitions to `X_PASSTHROUGH_FORWARD` and stops parsing X-Protocol
frames entirely. From that point bytes are spliced verbatim with
`read(2)`/`write(2)` between the client and a single dedicated backend
fd; the proxy never sees the TLS handshake or any application data.
Pooling, multiplexing, and per-query routing are intentionally disabled
for the session — the operator's choice to opt into passthrough is the
choice to give up those features in exchange for end-to-end encryption
the proxy cannot inspect.

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
| ✅  | ~~TLS passthrough~~ | Implemented via `mysqlx_routes.tls_mode='passthrough'` (#5692). Per-route opt-in. |
| ✅  | ~~Asymmetric TLS / AsClient~~ | Implemented via `mysqlx_tls_backend_mode` (#5693). |
| ✅  | ~~Per-message response state machines~~ | Implemented (#5694). |
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

MySQL Router has a more mature protocol implementation (per-message-type
state machines, 5-mode TLS with passthrough, and proper Capabilities negotiation),
but ProxySQL has a fundamentally superior proxy architecture (connection
pooling, query-level routing, multiplexing, local auth) that MySQL Router
does not support with its pass-through design.

The core TLS gap (frontend termination + backend negotiation) is now closed.
Asymmetric TLS / AsClient mode landed via `mysqlx_tls_backend_mode` (issue
#5693) — Router's full four-mode backend posture (disabled / preferred /
required / as_client) is now exposed, plus per-endpoint TLS overrides.
Raw-record passthrough mode landed via `mysqlx_routes.tls_mode='passthrough'`
(issue #5692), exposed at per-route granularity rather than per-deployment
so an operator can dedicate a single compliance-pinned route to passthrough
while leaving neighbouring routes on the default proxy-terminated path.
ProxySQL's mysqlx plugin now matches all five Router TLS modes.
