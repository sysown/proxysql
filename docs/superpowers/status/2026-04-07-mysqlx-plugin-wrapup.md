# MySQLX Plugin Branch Wrap-Up

Date: 2026-04-07
Branch: `mysqlx-plugin-impl`
Worktree: `/data/rene/proxysql/.worktrees/mysqlx-plugin-impl`

## All 9 Tasks Complete

| Task | Description | Commit | Tests |
|------|-------------|--------|-------|
| 1 | Generic plugin ABI and loader | `7e1a12b8f` | plugin_manager_unit-t |
| 2 | Plugin configuration and core lifecycle | `804771271` | plugin_config_unit-t |
| 3 | Plugin-owned admin table/command registration | `cd15afdd1` | plugin_registry_unit-t |
| 4 | mysqlx plugin scaffold and build integration | `19d48bdc1` | test_mysqlx_plugin_load-t (6/6) |
| 5 | Config store, runtime tables, dual-mode identity | `0b11bce37` | mysqlx_config_store_unit-t (16/16), test_mysqlx_admin_tables-t (20/20) |
| 6 | Listener sockets and worker threads | `5b5bbfbca` | test_mysqlx_listener_smoke-t (8/8) |
| 7 | Frontend X handshake, auth, account enforcement | `05ca510f2` | mysqlx_protocol_unit-t (10/10) |
| 8 | Backend X sessions and hostgroup-based routing | `e087fdda4` | mysqlx_route_store_unit-t (8/8) |
| 9 | Stats, topology invalidation hooks | `c2e90d369` | mysqlx_stats_unit-t (7/7) |

## Plugin Module Map

| File | Responsibility |
|------|----------------|
| `mysqlx_plugin.h/cpp` | Plugin descriptor, context, lifecycle hooks |
| `mysqlx_admin_schema.h/cpp` | DDL registration, LOAD TO RUNTIME commands, stats table schema |
| `mysqlx_config_store.h/cpp` | Runtime caches, dual-mode identity merge, round_robin routing |
| `mysqlx_worker.h/cpp` | Listener sockets, accept loop, worker threads |
| `mysqlx_protocol.h/cpp` | X frame encode/decode, MYSQL41 scramble auth, protobuf helpers |
| `mysqlx_frontend_session.h/cpp` | Client handshake state machine (CapabilitiesGet/Set, Auth) |
| `mysqlx_backend_session.h/cpp` | Backend X connect, MYSQL41 auth, bidirectional byte relay |
| `mysqlx_stats.h/cpp` | Atomic route counters, SQLite stats flush |
| `proto/*.pb.h/cc` | Compiled X Protocol protobuf messages |

## Config/Runtime Tables

- `mysqlx_users` / `runtime_mysqlx_users` — X-specific overrides for dual-mode accounts
- `mysqlx_routes` / `runtime_mysqlx_routes` — route definitions with bind/hostgroup
- `mysqlx_backend_endpoints` / `runtime_mysqlx_backend_endpoints` — X port mapping
- `stats_mysqlx_routes` — per-route connection and byte counters
- `stats_mysqlx_processlist` — (schema registered, flush not yet wired)

## Admin Commands

- `LOAD MYSQLX USERS TO RUNTIME` (aliases: `TO RUN`, `FROM MEMORY`, `FROM MEM`)
- `SAVE MYSQLX USERS TO MEMORY` (aliases: `TO MEM`, `FROM RUNTIME`, `FROM RUN`)
- `LOAD MYSQLX ROUTES TO RUNTIME` (aliases: same pattern)
- `SAVE MYSQLX ROUTES TO MEMORY` (aliases: same pattern)
- `LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME` (aliases: same pattern)
- `SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY` (aliases: same pattern)

## Auth Methods Supported

- MYSQL41 (challenge-response SHA1)
- PLAIN (plaintext, should require TLS in production)

## Routing Strategies

- `first_available` — first ONLINE server in hostgroup
- `round_robin` — rotate across ONLINE servers
- `round_robin_with_fallback` — round_robin, then fallback_hostgroup

## Phase 2 Seams

- Topology generation counter captured at session bind time
- `bump_topology_generation()` available for future GR notification observer
- Policy profile field present on resolved identity but not enforced

## Known Limitations (Phase 1)

- One frontend session = one backend session (no pooling)
- `pass_through` backend auth mode explicitly rejected
- Stats processlist table registered but not flushed during relay
- TLS negotiation acknowledged but not implemented in CapabilitiesSet
- No end-to-end integration test with a live MySQL X backend (requires Docker infrastructure)
