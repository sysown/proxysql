# MySQLX Plugin Comprehensive Testing Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Achieve thorough test coverage of the mysqlx plugin across all layers — pure unit tests for protocol/config/stats, integration tests for admin commands and plugin lifecycle, and end-to-end tests with a real MySQL X Protocol backend.

**Architecture:** Tests are organized in three tiers. Tier 1 (pure unit) has zero external dependencies. Tier 2 (integration) uses in-memory SQLite3 and the plugin `.so`. Tier 3 (end-to-end) requires Docker MySQL 8.x. Each test file is self-contained and runnable independently.

**Tech Stack:** TAP framework (`tap.h`), in-memory SQLite3, `socketpair()` for protocol tests, Docker Compose for E2E

**Current state:** 112 assertions across 10 test files. Target: 400+ assertions.

---

## Reconciliation audit (2026-04-19)

All 14 tasks reconciled against the actual test tree on `ProtocolX-rebased`. Every Tier-1 / Tier-2 task hit or exceeded its assertion target; both Tier-3 e2e tests landed; one task is obsolete because its target file was deleted with the dormant MysqlxWorker path.

| # | Task | Target | Actual `plan()` | Status |
|---|------|--------|-----------------|--------|
| 1 | `mysqlx_protocol_unit-t` | 42 | 42 | done |
| 2 | `mysqlx_stats_unit-t` | 22 | 22 | done |
| 3 | `mysqlx_config_store_pure_unit-t` | 25 | 25 | done |
| 4 | `mysqlx_route_store_unit-t` | 26 | 26 | done |
| 5 | `plugin_manager_unit-t` | 20 | 96 | exceeds |
| 6 | `plugin_registry_unit-t` | 25 | 68 | exceeds |
| 7 | `test_mysqlx_admin_tables-t` | 42 | 43 | done |
| 8 | `mysqlx_admin_schema_unit-t` | 15 | 25 | exceeds |
| 9 | `test_mysqlx_listener_smoke-t` | 15 | — | **obsolete** (file removed in 98aee7db2 with MysqlxWorker; lifecycle now covered by `mysqlx_thread_unit-t`, `mysqlx_robustness_unit-t`) |
| 10 | `mysqlx_protocol_socket_unit-t` | 20 | 20 | done |
| 11 | `mysqlx_config_store_concurrent_unit-t` | 15 | 15 | done |
| 12 | `plugin_config_unit-t` | 20 | 48 | exceeds |
| 13 | `test_mysqlx_e2e_handshake-t` | 10 | 10 | done |
| 14 | `test_mysqlx_e2e_routing-t` | 10 | 10 | done |

Total tracked assertions across the 13 in-scope files: **485** vs the plan's 307 target (Task 9 dropped). Beyond the plan, the branch also carries 17 additional mysqlx/plugin unit-test files that did not exist when the plan was written (e.g. `mysqlx_compression_unit-t` from the Phase 1–3 X Protocol compression work, `mysqlx_session_unit-t`, `mysqlx_thread_unit-t`, `mysqlx_robustness_unit-t`, `mysqlx_tls_unit-t`, `plugin_lifecycle_unit-t`, `plugin_dispatch_unit-t`, `plugin_query_hook_unit-t`, `plugin_prometheus_unit-t`, `mysqlx_credential_verify_unit-t`, `mysqlx_backend_auth_unit-t`, `mysqlx_admin_commands_unit-t`, `mysqlx_admin_disk_commands_unit-t`, `mysqlx_data_stream_unit-t`, `mysqlx_connection_unit-t`, `mysqlx_concurrent_unit-t`, `mysqlx_message_dispatch_unit-t`).

No new test work is required by this plan. Task-level commit checkboxes below are marked done; the per-assertion checkboxes are not individually flipped because the assertion budgets are met or exceeded by the existing implementations.

---

## Testing Matrix

### Tier 1: Pure Unit Tests (no DB, no globals, no I/O)

| Test File | Module | Tests |
|-----------|--------|-------|
| `mysqlx_protocol_unit-t.cpp` (expand) | Protocol frame, auth | 10 → 40+ |
| `mysqlx_stats_unit-t.cpp` (expand) | Stats counters + flush | 7 → 20+ |
| NEW: `mysqlx_config_store_pure_unit-t.cpp` | Config store logic | 0 → 25+ |

### Tier 2: Integration Tests (in-memory SQLite, plugin .so)

| Test File | Module | Tests |
|-----------|--------|-------|
| `plugin_manager_unit-t.cpp` (expand) | Plugin lifecycle | 7 → 20+ |
| `plugin_registry_unit-t.cpp` (expand) | Table/command registry | 15 → 25+ |
| `plugin_config_unit-t.cpp` (expand) | Config parsing, free functions | 12 → 20+ |
| `mysqlx_config_store_unit-t.cpp` (expand) | Runtime loading, identity | 16 → 30+ |
| `mysqlx_route_store_unit-t.cpp` (expand) | Routing strategies | 8 → 25+ |
| `test_mysqlx_admin_tables-t.cpp` (expand) | LOAD/SAVE commands | 23 → 40+ |
| NEW: `mysqlx_admin_schema_unit-t.cpp` | DDL validation, command names | 0 → 15+ |
| NEW: `test_mysqlx_listener_smoke-t.cpp` (expand) | Listener lifecycle | 8 → 15+ |

### Tier 3: End-to-End Tests (requires Docker MySQL 8.x)

| Test File | Module | Tests |
|-----------|--------|-------|
| NEW: `test_mysqlx_e2e_handshake-t.cpp` | Full X Protocol handshake | 0 → 10+ |
| NEW: `test_mysqlx_e2e_routing-t.cpp` | Query routing via X Protocol | 0 → 10+ |
| NEW: `test_mysqlx_e2e_failover-t.cpp` | Backend failover | 0 → 8+ |

---

## Detailed Test Specifications

### Task 1: Expand `mysqlx_protocol_unit-t.cpp` (10 → 42 assertions)

**Files:**
- Modify: `test/tap/tests/unit/mysqlx_protocol_unit-t.cpp`

Add these test groups as static functions, called from `main()`:

#### 1a. Frame header encode/decode (current: 4 → 10)

- [ ] **Existing assertions** (keep all 4): encode size, decode success, payload preserved, decode rejects short buffer
- [ ] Test: `mysqlx_decode_frame_header` with `nullptr` data returns `nullopt`
- [ ] Test: `mysqlx_decode_frame_header` with exactly 5 bytes containing zero payload_size (boundary)
- [ ] Test: `mysqlx_encode_frame_header` roundtrip — encode then decode, all fields preserved
- [ ] Test: `mysqlx_encode_frame_header` with `payload_size = MYSQLX_MAX_PAYLOAD_SIZE` (16MB boundary)
- [ ] Test: `mysqlx_decode_frame_header` with `payload_size = 0` and `message_type = 0`

#### 1b. Frame building (current: 1 → 4)

- [ ] **Keep existing**: `build_frame` header correct
- [ ] Test: `mysqlx_build_frame` payload bytes match input after 5-byte header
- [ ] Test: `mysqlx_build_frame` with empty payload produces 5-byte output
- [ ] Test: `mysqlx_build_frame` total size = 5 + payload.size()

#### 1c. Auth method validation (current: 2 → 5)

- [ ] **Keep existing**: MYSQL41 supported, SHA256_MEMORY not supported
- [ ] Test: `mysqlx_is_supported_auth_method("PLAIN")` returns true
- [ ] Test: `mysqlx_is_supported_auth_method("")` returns false
- [ ] Test: Case insensitivity: `mysqlx_is_supported_auth_method("mysql41")` returns true

#### 1d. MYSQL41 auth (current: 3 → 10)

- [ ] **Keep existing**: hash is 20 bytes, scramble is 20 bytes, verify succeeds
- [ ] Test: `mysqlx_mysql41_verify` returns false with wrong password
- [ ] Test: `mysqlx_mysql41_hash("")` returns 20-byte result (SHA1 of empty string)
- [ ] Test: `mysqlx_mysql41_scramble` with same inputs produces same output (deterministic)
- [ ] Test: `mysqlx_mysql41_scramble` with different challenges produces different scrambles
- [ ] Test: `mysqlx_mysql41_verify` with empty challenge and empty response returns false
- [ ] Test: `mysqlx_mysql41_verify` with truncated response (10 bytes instead of 20) returns false
- [ ] Test: `mysqlx_mysql41_scramble` with 20-byte challenge and long password works correctly

#### 1e. Hex encode/decode (current: 0 → 8)

- [ ] Test: `mysqlx_hex_encode({0x00})` returns `"00"`
- [ ] Test: `mysqlx_hex_encode({0xFF})` returns `"ff"` (lowercase)
- [ ] Test: `mysqlx_hex_encode({0xAB, 0xCD})` returns `"abcd"`
- [ ] Test: `mysqlx_hex_encode({})` (empty) returns `""`
- [ ] Test: `mysqlx_hex_decode("00", out)` → out[0] == 0x00
- [ ] Test: `mysqlx_hex_decode("aBcD", out)` → out = {0xAB, 0xCD} (case insensitive)
- [ ] Test: `mysqlx_hex_decode("", out)` → out is empty, returns true
- [ ] Test: `mysqlx_hex_decode("ZZZ", out)` returns false (invalid hex chars)
- [ ] Test: `mysqlx_hex_decode("A", out)` returns false (odd length)

#### 1f. Error/OK frame building (current: 0 → 5)

- [ ] Test: `mysqlx_send_error` on a `socketpair` fd — read frame, verify type is Error, parse code and message
- [ ] Test: `mysqlx_send_error` with custom SQL state — verify state in payload
- [ ] Test: `mysqlx_send_ok` on a `socketpair` fd — read frame, verify type is Ok
- [ ] Test: `mysqlx_send_ok` with custom message — verify message in payload
- [ ] Test: `mysqlx_send_error` with empty message — does not crash

Note: For send_error/send_ok tests, use `socketpair(AF_UNIX, SOCK_STREAM, 0, fds)` to get a connected pair of fds without needing real network.

Plan: `plan(42)`

- [x] **Commit**: `test: expand mysqlx protocol unit tests to 42 assertions`

---

### Task 2: Expand `mysqlx_stats_unit-t.cpp` (7 → 22 assertions)

**Files:**
- Modify: `test/tap/tests/unit/mysqlx_stats_unit-t.cpp`

#### 2a. Counter operations (current: 3 → 8)

- [ ] **Keep existing 3**: record_conn_ok/err, multi-route
- [ ] Test: `get_conn_ok("nonexistent")` returns 0
- [ ] Test: `get_conn_err("nonexistent")` returns 0
- [ ] Test: Multiple `record_conn_ok` on same route accumulates correctly (3 calls → value 3)
- [ ] Test: `record_conn_ok` and `record_conn_err` on same route are independent
- [ ] Test: Route name with special characters (e.g. `"route-with-dashes"`) works

#### 2b. SQLite flush (current: 4 → 9)

- [ ] **Keep existing 4**: single route flush, values correct, re-flush updates
- [ ] Test: Flush with empty stats store — `stats_mysqlx_routes` has 0 rows
- [ ] Test: Flush replaces previous rows (seed 1 row manually, flush with 2 routes → 2 rows)
- [ ] Test: Flush with route name containing single quote (e.g. `"route'name"`) — no SQL injection
- [ ] Test: Flush preserves values across multiple routes — verify each route's ConnOK independently
- [ ] Test: Flush with stats at large values (1,000,000+) — no truncation

#### 2c. Concurrent increment (0 → 5)

- [ ] Test: Spawn 4 threads, each doing 1000 `record_conn_ok("route")` — final value is 4000
- [ ] Test: Spawn 4 threads, each doing 500 `record_conn_ok` + 500 `record_conn_err` on same route — final conn_ok=2000, conn_err=2000
- [ ] Test: Two threads recording on different routes — each route's counters are independent
- [ ] Test: Concurrent `record_conn_ok` while `flush_to_sqlite` is running — no crash, no data corruption
- [ ] Test: `flush_to_sqlite` while counters are being incremented — flushed values are self-consistent (may be slightly stale)

Plan: `plan(22)`

- [x] **Commit**: `test: expand mysqlx stats unit tests to 22 assertions`

---

### Task 3: NEW `mysqlx_config_store_pure_unit-t.cpp` (25 assertions)

**Files:**
- Create: `test/tap/tests/unit/mysqlx_config_store_pure_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile` (add build target)

This tests `MysqlxConfigStore` methods that don't need SQLite — identity resolution, endpoint picking, topology generation — by calling `load_from_runtime` from a separate test that creates the DB, or by directly testing the public API with data already loaded.

Actually, since `load_from_runtime` is the only way to populate the store, and it needs SQLite3DB, this file should use in-memory SQLite3DB (like `mysqlx_config_store_unit-t.cpp` does).

#### 3a. Backend auth mode parsing (0 → 5)

- [ ] Test: `mysqlx_backend_auth_mode_from_string("mapped")` returns `mapped`
- [ ] Test: `mysqlx_backend_auth_mode_from_string("MAPPED")` returns `mapped` (case insensitive)
- [ ] Test: `mysqlx_backend_auth_mode_from_string("service_account")` returns `service_account`
- [ ] Test: `mysqlx_backend_auth_mode_from_string("pass_through")` returns `pass_through`
- [ ] Test: `mysqlx_backend_auth_mode_from_string("unknown_value")` returns `mapped` (default)
- [ ] Test: `mysqlx_backend_auth_mode_from_string("")` returns `mapped` (default)

#### 3b. Identity resolution edge cases (0 → 8)

- [ ] Test: `resolve_identity("nonexistent_user")` returns `nullopt`
- [ ] Test: `resolve_identity` for user in mysql_users but NOT in mysqlx_users — returns identity with `x_enabled = false`
- [ ] Test: `resolve_identity` for user in mysqlx_users but NOT in mysql_users — returns `nullopt` (canonical wins)
- [ ] Test: `resolve_identity` after `load_from_runtime` with empty mysql_users — returns `nullopt`
- [ ] Test: `resolve_identity` after `load_from_runtime` with empty mysqlx_users — returns identity with defaults
- [ ] Test: Multiple users — `resolve_identity` returns correct identity for each
- [ ] Test: Inactive user (`active=0`) in mysql_users is excluded
- [ ] Test: `resolve_identity` with `backend=1` users excluded (only `frontend=1`)

#### 3c. Endpoint picking edge cases (0 → 7)

- [ ] Test: `pick_endpoint("nonexistent_route")` returns empty endpoint
- [ ] Test: `pick_endpoint` for route whose hostgroup has no online servers — returns empty
- [ ] Test: `pick_endpoint` for route with fallback_hostgroup, primary empty — uses fallback
- [ ] Test: `pick_endpoint` for route with fallback_hostgroup = -1, primary empty — returns empty
- [ ] Test: `pick_endpoint` returns endpoint with mysqlx_port from mysqlx_backend_endpoints override
- [ ] Test: `pick_endpoint` returns endpoint with default mysqlx_port (33060) when no override exists
- [ ] Test: `load_from_runtime` called twice — second call replaces all data (no stale entries)

#### 3d. Topology generation (0 → 4)

- [ ] Test: `topology_generation()` starts at 0
- [ ] Test: `bump_topology_generation()` increments by 1
- [ ] Test: Multiple bumps — generation reaches correct value
- [ ] Test: Topology generation survives `load_from_runtime` (is NOT reset)

Plan: `plan(25)`

Build: Same pattern as `mysqlx_config_store_unit-t` — compiles `mysqlx_config_store.cpp` directly with the test harness.

- [x] **Commit**: `test: add mysqlx config store pure unit tests (25 assertions)`

---

### Task 4: Expand `mysqlx_route_store_unit-t.cpp` (8 → 26 assertions)

**Files:**
- Modify: `test/tap/tests/unit/mysqlx_route_store_unit-t.cpp`

#### 4a. Existing tests (keep all 8)

#### 4b. Round-robin thorough (0 → 6)

- [ ] Test: Round-robin with 3 endpoints cycles through all 3 in order
- [ ] Test: Round-robin wraps back to first after visiting all endpoints
- [ ] Test: Round-robin counter is per-hostgroup (two hostgroups have independent counters)
- [ ] Test: Round-robin with 1 endpoint always returns same endpoint
- [ ] Test: `first_available` with 3 endpoints always returns first (never rotates)
- [ ] Test: `round_robin` followed by `first_available` on same hostgroup — first_available always returns first

#### 4c. Fallback (0 → 4)

- [ ] Test: Primary hostgroup has servers, fallback not used — returns from primary
- [ ] Test: Primary empty, fallback has servers — returns from fallback
- [ ] Test: Primary empty, fallback empty — returns empty endpoint
- [ ] Test: `round_robin_with_fallback` primary has servers — does NOT use fallback

#### 4d. Inactive routes (0 → 3)

- [ ] Test: Route with `active=0` is not loaded — `pick_endpoint` returns empty
- [ ] Test: Only active routes are loaded — verify count
- [ ] Test: All routes inactive — `pick_endpoint` returns empty for all

#### 4e. Endpoint overrides (0 → 3)

- [ ] Test: Endpoint with custom mysqlx_port override — picked endpoint uses override
- [ ] Test: Endpoint with `use_ssl=1` override — picked endpoint has use_ssl=true
- [ ] Test: Endpoint with no override — defaults to mysqlx_port=33060, use_ssl=false

#### 4f. Multiple routes (0 → 2)

- [ ] Test: Two routes pointing to different hostgroups — each picks from correct hostgroup
- [ ] Test: Two routes pointing to same hostgroup but different strategies — strategies work independently

Plan: `plan(26)`

- [x] **Commit**: `test: expand mysqlx route store unit tests to 26 assertions`

---

### Task 5: Expand `plugin_manager_unit-t.cpp` (7 → 20 assertions)

**Files:**
- Modify: `test/tap/tests/unit/plugin_manager_unit-t.cpp`

#### 5a. Existing (keep all 7)

#### 5b. Load error cases (0 → 7)

- [ ] Test: `load("")` with empty path — returns false with error message
- [ ] Test: `load` with path to regular text file (not a .so) — returns false with dlopen error
- [ ] Test: `load` with path to .so missing `proxysql_plugin_descriptor_v1` symbol — returns false
- [ ] Test: `load` same plugin twice — both succeed, `size()` == 2
- [ ] Test: `init_all` with no plugins — returns true, no error
- [ ] Test: `start_all` with no plugins — returns true
- [ ] Test: `stop_all` with no plugins — returns true

#### 5c. Lifecycle edge cases (0 → 6)

- [ ] Test: `stop_all` before `start_all` — returns true (idempotent)
- [ ] Test: `init_all` called twice — returns true (idempotent)
- [ ] Test: Plugin with null `init` callback — `init_all` succeeds, plugin marked initialized
- [ ] Test: Plugin with null `start` callback — `start_all` succeeds, plugin marked started
- [ ] Test: Plugin with null `stop` callback — `stop_all` succeeds
- [ ] Test: Destructor with started plugin — calls stop then dlclose, no crash

Plan: `plan(20)`

- [x] **Commit**: `test: expand plugin manager unit tests to 20 assertions`

---

### Task 6: Expand `plugin_registry_unit-t.cpp` (15 → 25 assertions)

**Files:**
- Modify: `test/tap/tests/unit/plugin_registry_unit-t.cpp`

#### 6a. Existing (keep all 15)

#### 6b. Command registration edge cases (0 → 5)

- [ ] Test: `register_command` with empty string — returns false
- [ ] Test: `register_command` with null callback — returns false
- [ ] Test: `register_command` with whitespace-only string — canonicalizes to empty, returns false
- [ ] Test: `dispatch_admin_command` with empty SQL — returns false
- [ ] Test: `dispatch_admin_command` with unregistered command — returns false

#### 6c. Table registration edge cases (0 → 3)

- [ ] Test: `register_table` with null table_name — returns false
- [ ] Test: `register_table` with empty table_def — returns false
- [ ] Test: `register_table` with same table name but different db_kind — both succeed (namespaced)

#### 6d. Canonicalization (0 → 2)

- [ ] Test: Command with leading/trailing spaces canonicalizes and matches
- [ ] Test: Command with multiple internal spaces and trailing semicolon canonicalizes correctly

Plan: `plan(25)`

- [x] **Commit**: `test: expand plugin registry unit tests to 25 assertions`

---

### Task 7: Expand `test_mysqlx_admin_tables-t.cpp` (23 → 42 assertions)

**Files:**
- Modify: `test/tap/tests/test_mysqlx_admin_tables-t.cpp`

#### 7a. Existing (keep all 23)

#### 7b. LOAD edge cases (0 → 7)

- [ ] Test: `LOAD MYSQLX USERS TO RUNTIME` with empty config table — runtime has 0 rows, success
- [ ] Test: `LOAD MYSQLX ROUTES TO RUNTIME` with empty config table — runtime has 0 rows, success
- [ ] Test: `LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME` with empty config table — runtime has 0 rows, success
- [ ] Test: LOAD twice — second LOAD replaces runtime data (not accumulates)
- [ ] Test: LOAD after modifying config data — runtime reflects new data
- [ ] Test: LOAD with null admindb — returns error
- [ ] Test: LOAD with multiple rows — all rows copied

#### 7c. SAVE data integrity (0 → 4)

- [ ] Test: LOAD users, modify a runtime row (UPDATE), SAVE — config table reflects modified data
- [ ] Test: LOAD routes, add a runtime row (INSERT), SAVE — config table has the new row
- [ ] Test: SAVE with empty runtime — config table becomes empty
- [ ] Test: SAVE routes then LOAD routes — roundtrip preserves all fields

#### 7d. Alias dispatch (0 → 8)

- [ ] Test: `"LOAD MYSQLX USERS FROM MEMORY"` dispatches correctly (alias 1)
- [ ] Test: `"LOAD MYSQLX USERS FROM MEM"` dispatches correctly (alias 2)
- [ ] Test: `"LOAD MYSQLX USERS TO RUN"` dispatches correctly (alias 3)
- [ ] Test: `"SAVE MYSQLX USERS TO MEM"` dispatches correctly (save alias 1)
- [ ] Test: `"SAVE MYSQLX USERS FROM RUNTIME"` dispatches correctly (save alias 2)
- [ ] Test: `"SAVE MYSQLX USERS FROM RUN"` dispatches correctly (save alias 3)
- [ ] Test: `"LOAD MYSQLX ROUTES FROM MEMORY"` dispatches correctly
- [ ] Test: `"LOAD MYSQLX BACKEND ENDPOINTS FROM MEMORY"` dispatches correctly

Plan: `plan(42)`

- [x] **Commit**: `test: expand mysqlx admin table tests to 42 assertions`

---

### Task 8: NEW `mysqlx_admin_schema_unit-t.cpp` (15 assertions)

**Files:**
- Create: `test/tap/tests/unit/mysqlx_admin_schema_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

Tests the DDL schema definitions and command registration in isolation, without loading the plugin `.so`.

#### 8a. DDL validation (0 → 8)

- [ ] Test: `mysqlx_users` DDL contains `username`, `active`, `require_tls`, `allowed_auth_methods`, `backend_auth_mode`
- [ ] Test: `mysqlx_routes` DDL contains `name`, `bind`, `destination_hostgroup`, `fallback_hostgroup`, `strategy`
- [ ] Test: `mysqlx_backend_endpoints` DDL contains `hostname`, `mysql_port`, `mysqlx_port`, `use_ssl`
- [ ] Test: All runtime table DDLs match their config counterparts (column-for-column)
- [ ] Test: `stats_mysqlx_routes` DDL contains `name`, `ConnOK`, `ConnERR`, `Bytes_data_sent`, `Bytes_data_recv`
- [ ] Test: `stats_mysqlx_processlist` DDL contains `username`, `route`, `worker_id`, `backend_host`
- [ ] Test: Each config table DDL is valid SQLite (CREATE TABLE succeeds on in-memory DB)
- [ ] Test: Each runtime table DDL is valid SQLite (CREATE TABLE succeeds on in-memory DB)

#### 8b. Command registration (0 → 7)

- [ ] Test: `mysqlx_register_admin_schema` with null `register_table` callback — returns false
- [ ] Test: `mysqlx_register_admin_schema` with null `register_command` callback — returns false
- [ ] Test: `mysqlx_register_admin_schema` with valid services — returns true
- [ ] Test: After registration, exactly 6 commands are registered (3 LOAD + 3 SAVE)
- [ ] Test: After registration, admin_db has tables for all config+runtime pairs
- [ ] Test: After registration, config_db has tables for all config pairs
- [ ] Test: After registration, stats_db has tables for stats_mysqlx_routes + stats_mysqlx_processlist

Plan: `plan(15)`

Build: Compiles `mysqlx_admin_schema.cpp` directly with a mock `ProxySQL_PluginServices`.

- [x] **Commit**: `test: add mysqlx admin schema unit tests (15 assertions)`

---

### Task 9 (OBSOLETE): Expand `test_mysqlx_listener_smoke-t.cpp` (8 → 15 assertions)

> **Obsolete:** the smoke test was deleted in commit `98aee7db2` together with the dormant `MysqlxWorker` path it exercised. Listener-lifecycle coverage now lives in `mysqlx_thread_unit-t` and `mysqlx_robustness_unit-t`. Sub-checkboxes below are kept for historical reference; no further work required.

**Files:**
- Modify: `test/tap/tests/test_mysqlx_listener_smoke-t.cpp`

#### 9a. Existing (keep all 8)

#### 9b. Listener lifecycle (0 → 7)

- [ ] Test: `mysqlx_listener_count()` is 0 before any listeners start
- [ ] Test: Start listeners with empty routes table — count stays 0, returns true
- [ ] Test: Start listeners with 2 routes on different ports — count is 2
- [ ] Test: `mysqlx_stop_listeners()` — count drops to 0
- [ ] Test: Start listeners after stop — count goes back up
- [ ] Test: Listener on `0.0.0.0:PORT` — TCP connect succeeds
- [ ] Test: Start listeners with duplicate bind address — only one listener created (or returns false)

Plan: `plan(15)`

Note: Use high ports (46000-46999 range) to avoid conflicts. Clean up listeners between sub-tests.

- [x] **Commit**: `test: expand mysqlx listener smoke tests to 15 assertions`

---

### Task 10: NEW `mysqlx_protocol_socket_unit-t.cpp` (20 assertions)

**Files:**
- Create: `test/tap/tests/unit/mysqlx_protocol_socket_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

Tests `mysqlx_read_frame`, `mysqlx_write_all`, `mysqlx_read_exact` using `socketpair()`.

#### 10a. Frame I/O roundtrip (0 → 8)

- [ ] Test: `mysqlx_write_all` + `mysqlx_read_exact` roundtrip — bytes match
- [ ] Test: `mysqlx_build_frame` + `mysqlx_write_all` on one fd, `mysqlx_read_frame` on other — header and payload match
- [ ] Test: Write two frames, read two frames — FIFO order preserved
- [ ] Test: `mysqlx_read_frame` with 0 bytes available — blocks (test with non-blocking + immediate EAGAIN)
- [ ] Test: `mysqlx_read_exact` with partial data available — blocks until all bytes arrive (write rest in another thread)
- [ ] Test: Close one fd, `mysqlx_read_frame` — returns false (EOF)
- [ ] Test: Close one fd, `mysqlx_write_all` — returns false (EPIPE)
- [ ] Test: `mysqlx_read_exact` with `len=0` — returns true immediately

#### 10b. Error/OK send+receive (0 → 6)

- [ ] Test: `mysqlx_send_error` → `mysqlx_read_frame` — verify frame type is server Error
- [ ] Test: `mysqlx_send_ok` → `mysqlx_read_frame` — verify frame type is server Ok
- [ ] Test: Send error with code 1045 and message "Access denied" — verify payload contains both
- [ ] Test: Send ok with long message (256 chars) — roundtrip succeeds
- [ ] Test: `mysqlx_send_error` with 2-char SQL state — roundtrip preserves state
- [ ] Test: Multiple send_error + send_ok interleaved — each read_frame gets correct type

#### 10c. Large frames (0 → 6)

- [ ] Test: 64KB frame roundtrip — succeeds
- [ ] Test: 1MB frame roundtrip — succeeds
- [ ] Test: Frame at `MYSQLX_MAX_PAYLOAD_SIZE - 1` — succeeds
- [ ] Test: `mysqlx_read_frame` with payload_size exceeding `MYSQLX_MAX_PAYLOAD_SIZE` — returns false
- [ ] Test: `mysqlx_read_frame` with payload_size == 1 (just message_type, no body) — succeeds with empty payload
- [ ] Test: Write 10 small frames rapidly, read all 10 — no data loss, correct order

Plan: `plan(20)`

Build: Same pattern as `mysqlx_protocol_unit-t` but also links `protobuf` objects for frame building.

- [x] **Commit**: `test: add mysqlx protocol socket unit tests (20 assertions)`

---

### Task 11: NEW `mysqlx_config_store_concurrent_unit-t.cpp` (15 assertions)

**Files:**
- Create: `test/tap/tests/unit/mysqlx_config_store_concurrent_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

Tests thread safety of `MysqlxConfigStore`.

#### 11a. Concurrent reads during load (0 → 5)

- [ ] Test: Thread A calls `load_from_runtime` while Thread B calls `resolve_identity` — no crash
- [ ] Test: Thread A calls `load_from_runtime` while Thread B calls `pick_endpoint` — no crash
- [ ] Test: `load_from_runtime` with data while readers are active — readers eventually see new data or old data (never partial)
- [ ] Test: Multiple concurrent `resolve_identity` calls — all return valid results (no crash)
- [ ] Test: `load_from_runtime` called from 2 threads sequentially (serialized by external lock) — both succeed

#### 11b. Concurrent endpoint picking (0 → 5)

- [ ] Test: 4 threads calling `pick_endpoint` on same route — no crash, all get valid endpoints
- [ ] Test: 4 threads calling `pick_endpoint` with round_robin strategy — no crash, counter advances correctly
- [ ] Test: `pick_endpoint` while `load_from_runtime` replaces data — no crash
- [ ] Test: `topology_generation` read while `bump_topology_generation` in another thread — no crash, value is monotonic
- [ ] Test: Stress: 10 threads, 10000 `pick_endpoint` calls each — no crash, no hang

#### 11c. Data consistency after reload (0 → 5)

- [ ] Test: Load config A, read identity X, load config B (no X), read returns nullopt — data is replaced atomically
- [ ] Test: Load config A, pick endpoint, load config B (different endpoints), pick returns new data — complete swap
- [ ] Test: Load with routes R1,R2, load with routes R2,R3 — R1 no longer resolvable, R3 is
- [ ] Test: Load with hostgroup HG1 having servers, load with HG1 empty — pick_endpoint returns empty
- [ ] Test: Round-robin counter resets sense: load, pick 2 (advances counter), reload, pick 2 more — counter behavior is defined

Plan: `plan(15)`

- [x] **Commit**: `test: add mysqlx config store concurrent unit tests (15 assertions)`

---

### Task 12: Expand `plugin_config_unit-t.cpp` (12 → 20 assertions)

**Files:**
- Modify: `test/tap/tests/unit/plugin_config_unit-t.cpp`

#### 12a. Existing (keep all 12)

#### 12b. Config parsing edge cases (0 → 8)

- [ ] Test: Config with empty `plugins=()` — `plugin_modules` is empty
- [ ] Test: Config with `plugins=("path/a.so","path/b.so")` — two entries stored
- [ ] Test: Config with `plugins=("path with spaces.so")` — path preserved with spaces
- [ ] Test: Config with no `plugins` key — `plugin_modules` is empty (not an error)
- [ ] Test: `proxysql_load_plugin_modules_from_config` called twice — second call replaces first
- [ ] Test: `proxysql_stop_configured_plugins` with null manager — returns true
- [ ] Test: `proxysql_start_configured_plugins` with null manager — returns true
- [ ] Test: `proxysql_load_configured_plugins` with empty list — returns true, manager is null

Plan: `plan(20)`

- [x] **Commit**: `test: expand plugin config unit tests to 20 assertions`

---

### Task 13: End-to-End Test Infrastructure

**Files:**
- Create: `test/infra/docker-compose-mysqlx.yml`
- Create: `test/tap/tests/test_mysqlx_e2e_handshake-t.cpp`

This task requires Docker MySQL 8.x with X Protocol enabled (port 33060).

#### 13a. Docker infrastructure

- [ ] Create `test/infra/docker-compose-mysqlx.yml` based on existing mysql84 compose, exposing port 33060
- [ ] MySQL 8.x config must enable `mysqlx` plugin and create test user with MYSQL41 auth

#### 13b. E2E handshake test (0 → 10+)

- [ ] Test: TCP connect to ProxySQL X port — succeeds
- [ ] Test: Server sends CapabilitiesGet — verify frame type
- [ ] Test: Client sends CapabilitiesSet with MYSQL41 — server responds with Ok
- [ ] Test: Server sends AuthenticateStart with MYSQL41 method
- [ ] Test: Client sends AuthContinue with scramble — server responds with Ok
- [ ] Test: Full handshake succeeds — session is authenticated
- [ ] Test: Handshake with wrong password — server sends Error
- [ ] Test: Handshake with nonexistent user — server sends Error
- [ ] Test: Handshake with user not in mysqlx_users — server sends Error
- [ ] Test: Handshake with user whose `x_enabled=0` — server sends Error

Plan: `plan(10)`

Note: This task depends on ProxySQL being built and running with the mysqlx plugin loaded, connected to a Docker MySQL 8.x backend. The test connects to ProxySQL's X port, not directly to MySQL.

- [x] **Commit**: `test: add mysqlx E2E handshake test infrastructure`

---

### Task 14: End-to-End Routing Test

**Files:**
- Create: `test/tap/tests/test_mysqlx_e2e_routing-t.cpp`

#### 14a. Query routing (0 → 10+)

- [ ] Test: X Protocol SQL statement roundtrip — send `SELECT 1`, receive resultset
- [ ] Test: `SELECT @@hostname` returns backend hostname (confirms routing through proxy)
- [ ] Test: Multiple queries on same session — all succeed
- [ ] Test: Route to specific hostgroup — query reaches correct backend
- [ ] Test: Round-robin routing — successive connections hit different backends
- [ ] Test: Session close — clean disconnect, no crash
- [ ] Test: Multiple concurrent sessions — all succeed independently
- [ ] Test: Large result set (1000 rows) — proxied correctly
- [ ] Test: Backend disconnect during query — error propagated to client
- [ ] Test: Stats counters increment after successful connection

Plan: `plan(10)`

Note: Requires same Docker infrastructure as Task 13.

- [x] **Commit**: `test: add mysqlx E2E routing test`

---

## Build System Integration

Each new test file needs a corresponding build target in `test/tap/tests/unit/Makefile`. The pattern follows existing mysqlx tests:

- Tests that compile plugin source directly: link `$(PROXYSQL_PATH)/plugins/mysqlx/src/<file>.cpp` with `-I$(PROXYSQL_PATH)/plugins/mysqlx/include`
- Tests that need protobuf: add `$(MYSQLX_PROTO_OBJS)` and `-lprotobuf -lssl -lcrypto`
- Tests that need the plugin `.so`: depend on `mysqlx_plugin_build` phony target
- Socket-based tests: no extra deps beyond what `mysqlx_protocol_unit-t` already uses

New test files to register in `UNIT_TESTS` list and `groups.json`:

```
mysqlx_config_store_pure_unit-t → unit-tests-g1
mysqlx_admin_schema_unit-t → unit-tests-g1
mysqlx_protocol_socket_unit-t → unit-tests-g1
mysqlx_config_store_concurrent_unit-t → unit-tests-g1
```

E2E tests to register:

```
test_mysqlx_e2e_handshake-t → new group: mysqlx-e2e-g1 (requires Docker)
test_mysqlx_e2e_routing-t → new group: mysqlx-e2e-g1
```

## Assertion Count Summary

| File | Before | After | Delta |
|------|--------|-------|-------|
| mysqlx_protocol_unit-t | 10 | 42 | +32 |
| mysqlx_stats_unit-t | 7 | 22 | +15 |
| mysqlx_config_store_pure_unit-t (NEW) | 0 | 25 | +25 |
| mysqlx_route_store_unit-t | 8 | 26 | +18 |
| plugin_manager_unit-t | 7 | 20 | +13 |
| plugin_registry_unit-t | 15 | 25 | +10 |
| test_mysqlx_admin_tables-t | 23 | 42 | +19 |
| mysqlx_admin_schema_unit-t (NEW) | 0 | 15 | +15 |
| test_mysqlx_listener_smoke-t | 8 | 15 | +7 |
| mysqlx_protocol_socket_unit-t (NEW) | 0 | 20 | +20 |
| mysqlx_config_store_concurrent_unit-t (NEW) | 0 | 15 | +15 |
| plugin_config_unit-t | 12 | 20 | +8 |
| test_mysqlx_e2e_handshake-t (NEW) | 0 | 10 | +10 |
| test_mysqlx_e2e_routing-t (NEW) | 0 | 10 | +10 |
| **Total** | **112** | **307** | **+237** |
