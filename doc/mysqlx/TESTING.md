# MySQL X Protocol Plugin — Testing Documentation (v2)

## 1. Overview

The mysqlx plugin has **600+ test assertions** across **24 test files** in three tiers:

| Tier | Scope | Dependencies | Count |
|------|-------|-------------|-------|
| **Tier 1: Pure Unit Tests** | No external dependencies, no database, no globals | None | 21 files |
| **Tier 2: Integration Tests** | In-memory SQLite3, plugin `.so` loading, TCP listener | Built plugin `.so` | 3 files |
| **Tier 3: End-to-End Tests** | Real MySQL 8.x backend with X Protocol | MySQL 8.x sandbox | 2 files |

---

## 2. Test File Index

### Phase 1 Tests (Retained)

| File | Tier | Assertions | What It Tests |
|------|------|------------|---------------|
| `mysqlx_protocol_unit-t.cpp` | Unit | 42 | Frame header encode/decode, MYSQL41 hash/scramble/verify, hex encode/decode, error/ok frame via socketpair, auth method validation |
| `mysqlx_protocol_socket_unit-t.cpp` | Unit | 20 | Socket I/O roundtrip (socketpair), FIFO ordering, EOF/EPIPE detection, large frames (64KB/1MB/16MB), binary data preservation |
| `mysqlx_stats_unit-t.cpp` | Unit | 22 | Counter operations, SQLite flush, concurrent multi-thread stress tests |
| `mysqlx_config_store_unit-t.cpp` | Unit | 16 | Runtime loading, identity resolution, endpoint picking, topology generation |
| `mysqlx_config_store_pure_unit-t.cpp` | Unit | 25 | Auth mode parsing, identity edge cases (inactive/backend users), endpoint edge cases, topology generation atomicity |
| `mysqlx_config_store_concurrent_unit-t.cpp` | Unit | 15 | Thread safety: concurrent resolve/pick/reload, data consistency after reload, 10-thread stress |
| `mysqlx_route_store_unit-t.cpp` | Unit | 26 | Routing strategies (first_available, round_robin, round_robin_with_fallback), inactive routes, endpoint overrides |
| `mysqlx_admin_schema_unit-t.cpp` | Unit | 15 | DDL registration, command registration, null guards |
| `plugin_manager_unit-t.cpp` | Unit | 20 | Plugin lifecycle (load/init/start/stop), error cases, double lifecycle |
| `plugin_registry_unit-t.cpp` | Unit | 25 | Table/command registration, duplicate rejection, canonicalization |
| `plugin_config_unit-t.cpp` | Unit | 20 | Config parsing, lifecycle free functions, dispatch after stop |
| `test_mysqlx_admin_tables-t.cpp` | Integration | 42 | Full LOAD/SAVE roundtrip with real plugin `.so`, alias dispatch, data integrity |
| `test_mysqlx_listener_smoke-t.cpp` | Integration | 15 | Listener lifecycle, multi-port, TCP connect verification |
| `test_mysqlx_plugin_load-t.cpp` | Integration | 6 | Plugin `.so` loading, schema registration |
| `test_mysqlx_e2e_handshake-t.cpp` | E2E | 10 | Full X Protocol handshake against real MySQL, auth failure cases |
| `test_mysqlx_e2e_routing-t.cpp` | E2E | 10 | Query routing through ProxySQL X listener, DDL/DML roundtrip |

### v2 Tests (New)

| File | Tier | Assertions | What It Tests |
|------|------|------------|---------------|
| `mysqlx_data_stream_unit-t.cpp` | Unit | 15 | Non-blocking frame header parsing, partial frame buffering, multiple concatenated frames, write buffer format, feed_bytes accumulation |
| `mysqlx_connection_unit-t.cpp` | Unit | 10 | Connection state transitions, hostgroup/user/schema metadata, multiplexing eligibility (transaction/stmt disable reuse), reusable flag logic |
| `mysqlx_session_unit-t.cpp` | Unit | 42 | 22 session state transitions, capabilities negotiation flow, MYSQL41 auth challenge-response, auth failure handling, session reset, backend connection flow, frame forwarding, session closing |
| `mysqlx_thread_unit-t.cpp` | Unit | 22 | Thread initialization, listener add/remove, poll set management, session registration/unregistration, connection cache operations, pool matching (hostgroup/user/schema), pool exclusion (transaction/stmt), max cache eviction |
| `mysqlx_message_dispatch_unit-t.cpp` | Unit | 49 | All 23 client message type dispatch (locally handled vs forwarded), multi-frame response forwarding, unknown message type error generation, SESS_RESET forwarding, CRUD operations, prepared statement tracking, cursor operations, expect operations |
| `mysqlx_concurrent_unit-t.cpp` | Unit | 15 | Multi-thread session stress: concurrent handler invocations, session registration/deregistration, connection cache races |
| `mysqlx_backend_auth_unit-t.cpp` | Unit | 15 | Backend authentication modes (mapped/service_account/pass_through), credential override, auth mode validation |
| `mysqlx_credential_verify_unit-t.cpp` | Unit | 15 | MYSQL41 credential verification: correct/incorrect password, empty password, edge cases, constant-time comparison |
| `mysqlx_robustness_unit-t.cpp` | Unit | 20 | Session robustness: unexpected disconnects, malformed frames, resource cleanup, error recovery |
| `mysqlx_tls_unit-t.cpp` | Unit | 20 | TLS handshake states, Memory BIO pattern, encrypted read/write paths, TLS mode enforcement (DISABLED/PREFERRED/REQUIRED) |
| `mysqlx_admin_commands_unit-t.cpp` | Unit | 15 | LOAD/SAVE admin command dispatch, alias resolution, error handling |
| `mysqlx_admin_disk_commands_unit-t.cpp` | Unit | 15 | LOAD FROM DISK / SAVE TO DISK commands, disk-to-memory roundtrip |
| `mysqlx_admin_alias_resolution_unit-t.cpp` | Unit | 10 | Admin command alias resolution: TO RUN/FROM MEM/FROM RUN aliases |

**Total: 600+ assertions across 24 files.**

---

## 3. Running Tests

### 3.1 Unit Tests (no infrastructure)

Unit tests require no database, no ProxySQL binary, and no network. They link
against `libproxysql.a` via the custom test harness.

```bash
cd test/tap/tests/unit
make mysqlx_protocol_unit-t mysqlx_stats_unit-t mysqlx_config_store_unit-t \
     mysqlx_config_store_pure_unit-t mysqlx_config_store_concurrent_unit-t \
     mysqlx_route_store_unit-t mysqlx_admin_schema_unit-t \
     mysqlx_admin_commands_unit-t mysqlx_admin_disk_commands_unit-t \
     mysqlx_admin_alias_resolution_unit-t \
     plugin_manager_unit-t plugin_registry_unit-t plugin_config_unit-t \
     mysqlx_data_stream_unit-t mysqlx_connection_unit-t \
     mysqlx_session_unit-t mysqlx_thread_unit-t \
     mysqlx_message_dispatch_unit-t mysqlx_concurrent_unit-t \
     mysqlx_backend_auth_unit-t mysqlx_credential_verify_unit-t \
     mysqlx_robustness_unit-t mysqlx_tls_unit-t

# Run all unit tests
for t in mysqlx_*_unit-t plugin_*_unit-t; do
    ./$t
done
```

Unit tests are also runnable via the test group system:

```bash
cd test/tap
make group-tests GROUP=unit-tests-g1
```

### 3.2 Integration Tests (need plugin .so built)

Integration tests load the actual mysqlx plugin shared object and may start a
TCP listener. The plugin must be built first.

```bash
# Build the plugin
cd plugins/mysqlx && make

# Build and run integration tests
cd ../../test/tap/tests
make test_mysqlx_admin_tables-t test_mysqlx_listener_smoke-t test_mysqlx_plugin_load-t

./test_mysqlx_admin_tables-t
./test_mysqlx_listener_smoke-t
./test_mysqlx_plugin_load-t
```

### 3.3 E2E Tests (need MySQL 8.x with X Protocol)

End-to-end tests connect to a real MySQL 8.x instance with X Protocol enabled.
They skip gracefully when the required environment variables are not set.

```bash
# Using dbdeployer:
dbdeployer deploy single 8.4.8

export MYSQLX_E2E_HOST=127.0.0.1
export MYSQLX_E2E_PORT=33060
export MYSQLX_E2E_USER=mysqlx_test
export MYSQLX_E2E_PASS=mysqlx_test

cd test/tap/tests
make test_mysqlx_e2e_handshake-t test_mysqlx_e2e_routing-t

./test_mysqlx_e2e_handshake-t
./test_mysqlx_e2e_routing-t
```

**E2E environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `MYSQLX_E2E_HOST` | *(none — tests skip)* | MySQL X Protocol host |
| `MYSQLX_E2E_PORT` | `33060` | MySQL X Protocol port |
| `MYSQLX_E2E_USER` | `mysqlx_test` | Username for authentication |
| `MYSQLX_E2E_PASS` | `mysqlx_test` | Password for authentication |

If `MYSQLX_E2E_HOST` is not set, all E2E tests print a diagnostic and exit
with success (TAP skip).

E2E tests are also runnable via the test group system:

```bash
cd test/tap
make group-tests GROUP=mysqlx-e2e-g1
```

---

## 4. Test Infrastructure

### 4.1 Test Harness

The unit test harness provides minimal initialization without requiring a full
ProxySQL daemon:

| File | Purpose |
|------|---------|
| `test/tap/test_helpers/test_globals.h/cpp` | Minimal global state initialization ( jemalloc, threading ) |
| `test/tap/test_helpers/test_init.h/cpp` | Component initialization helpers for SQLite3, protobuf, etc. |
| `test/tap/test_helpers/fake_plugin.cpp` | Test plugin `.so` with env-var-driven behavior for integration tests |

### 4.2 In-Memory SQLite3 Pattern

Most unit tests use in-memory SQLite3 databases to avoid filesystem side
effects:

```cpp
SQLite3DB db;
db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
db.execute("CREATE TABLE mysqlx_endpoints (id INTEGER PRIMARY KEY, ...)");
db.execute("INSERT INTO mysqlx_endpoints VALUES (1, ...)");
```

This pattern is used by:
- `mysqlx_config_store_unit-t.cpp`
- `mysqlx_config_store_pure_unit-t.cpp`
- `mysqlx_config_store_concurrent_unit-t.cpp`
- `mysqlx_route_store_unit-t.cpp`
- `mysqlx_stats_unit-t.cpp`
- `mysqlx_admin_schema_unit-t.cpp`

### 4.3 Socket Pair Pattern

Protocol tests use `socketpair()` to create connected file descriptor pairs
without real networking:

```cpp
int fds[2];
socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

// Write an error frame on one end
mysqlx_send_error(fds[0], 1045, "Access denied");

// Read and verify on the other end
mysqlx_read_frame(fds[1], header, payload);

close(fds[0]);
close(fds[1]);
```

This pattern is used by:
- `mysqlx_protocol_unit-t.cpp` — error/ok frame roundtrips
- `mysqlx_protocol_socket_unit-t.cpp` — large frames, FIFO ordering, EOF detection

### 4.4 Concurrent Test Pattern

Thread-safety tests spawn multiple threads and verify exact counter values
after all threads join:

```cpp
const int N_THREADS = 10;
const int N_ITER    = 10000;
std::atomic<int> barrier{0};

auto worker = [&]() {
    barrier.fetch_add(1);
    while (barrier.load() < N_THREADS) { /* spin */ }
    for (int i = 0; i < N_ITER; i++) {
        store.resolve_identity(...);
    }
};

std::vector<std::thread> threads;
for (int i = 0; i < N_THREADS; i++) threads.emplace_back(worker);
for (auto& t : threads) t.join();

ok(total_resolves == N_THREADS * N_ITER, "all resolves accounted for");
```

This pattern is used by:
- `mysqlx_config_store_concurrent_unit-t.cpp`
- `mysqlx_stats_unit-t.cpp` (multi-thread stress section)

### 4.5 Data Stream Feed Pattern (v2)

v2 data stream tests use the `feed_bytes()` method to simulate network input:

```cpp
MysqlxDataStream ds;

// Feed a complete frame
uint8_t frame[] = {0x0a, 0x00, 0x00, 0x00, 0x01, /* body */};
ds.feed_bytes(frame, sizeof(frame));

ok(ds.has_complete_frame(), "complete frame detected");
auto& pkt = ds.front_frame();
ok(pkt[4] == 0x01, "message type is CON_CAPABILITIES_GET");
ds.pop_frame();
ok(!ds.has_complete_frame(), "no more frames after pop");
```

### 4.6 Session State Transition Pattern (v2)

v2 session tests exercise state transitions by calling handlers directly:

```cpp
MysqlxSession sess;
sess.set_status(MysqlxSession::CONNECTING_CLIENT);
sess.handler_connecting_client();
ok(sess.get_status() == MysqlxSession::X_CAPABILITIES_GET,
   "transitioned to X_CAPABILITIES_GET");
```

---

## 5. CI Integration

### 5.1 GitHub Actions Workflow

**File:** `.github/workflows/CI-mysqlx.yml`

The CI workflow defines two jobs:

#### Job 1: `unit-tests`

- Checks out the repository
- Installs build dependencies (cmake, g++, protobuf, sqlite3 dev packages)
- Builds the plugin `.so`
- Runs all 17 unit tests
- No backend database needed
- Runs on every push and pull request

#### Job 2: `e2e-tests`

- Checks out the repository
- Installs dbdeployer and MySQL 8.4 tarball
- Deploys a single MySQL 8.4 sandbox
- Verifies X Protocol is listening on port 33060
- Creates the test user
- Runs E2E tests
- Tears down the sandbox
- Runs on push to `main` and on pull requests (with manual trigger option)

### 5.2 dbdeployer Setup

dbdeployer is used instead of Docker Compose for backend provisioning. MySQL
8.x enables X Protocol by default on port 33060.

```bash
# Install dbdeployer
curl -s https://raw.githubusercontent.com/ProxySQL/dbdeployer/master/scripts/dbdeployer-install.sh | bash

# Download and deploy MySQL 8.4
dbdeployer downloads get-by-version 8.4 --newest --minimal
dbdeployer unpack mysql-8.4.*.tar.xz
dbdeployer deploy single 8.4.8

# Verify X Protocol is active
mysql -u root -S ~/sandboxes/msb_8_4_8/socket.sock -e "SELECT @@mysqlx_port"
# Expected: 33060
```

### 5.3 Test Groups

Tests are registered in `test/tap/groups/groups.json`:

| Group | Tests | Infrastructure |
|-------|-------|----------------|
| `unit-tests-g1` | All 21 unit tests | None (`SKIP_PROXYSQL=1`) |
| `mysqlx-e2e-g1` | 2 E2E tests | dbdeployer MySQL 8.4 sandbox |

---

## 6. Test Coverage Map

### v1 Component Coverage

| Component | Unit | Integration | E2E | Concurrent |
|-----------|------|-------------|-----|------------|
| Protocol frames | 42 | — | 10 | — |
| Socket I/O | 20 | — | — | — |
| MYSQL41 auth | *(within 42)* | — | 10 | — |
| Config store | 41 | — | — | 15 |
| Route store | 26 | — | — | — |
| Stats | 22 | — | — | *(within 22)* |
| Admin schema | 15 | 42 | — | — |
| Plugin lifecycle | 45 | 6 | — | — |
| Listener | — | 15 | — | — |
| Full handshake | — | — | 10 | — |
| Query routing | — | — | 10 | — |

### v2 Component Coverage

| Component | Unit | Integration | E2E | Concurrent |
|-----------|------|-------------|-----|------------|
| Data stream (frame I/O) | 15 | — | — | — |
| Connection (pooled object) | 10 | — | — | — |
| Session state machine | 42 | — | — | — |
| Thread (event loop) | 22 | — | — | — |
| Message dispatch (23 types) | 49 | — | — | — |

### Coverage by Tier

```
Unit:           500+ assertions  (83%)
Integration:     63 assertions   (11%)
E2E:             20 assertions   ( 3%)
Concurrent:      30 assertions   ( 3%)
                    ─────────
Total:          600+ assertions
```

---

## 7. Adding New Tests

### 7.1 Naming Conventions

| Tier | Directory | Naming Pattern |
|------|-----------|----------------|
| Unit | `test/tap/tests/unit/` | `mysqlx_<component>_unit-t.cpp` |
| Integration | `test/tap/tests/` | `test_mysqlx_<feature>-t.cpp` |
| E2E | `test/tap/tests/` | `test_mysqlx_e2e_<feature>-t.cpp` |

### 7.2 TAP Protocol Requirements

Every test file must:

1. Call `plan(N)` at the top of `main()` where `N` is the exact number of `ok()` calls
2. Use `diag()` for diagnostic output (visible on failure)
3. Use `BAIL_OUT()` for fatal, unrecoverable failures
4. Use `skip()` or `todo()` when conditions are not met
5. Return `exit_status()` at the end of `main()`

```cpp
#include "tap.h"

int main() {
    plan(5);

    ok(1 + 1 == 2, "basic arithmetic");
    is_str("hello", "hello", "string equality");
    ok(true, "simple boolean");

    if (!some_condition) {
        skip(2, "condition not met");
    } else {
        ok(test_a(), "test A");
        ok(test_b(), "test B");
    }

    return exit_status();
}
```

### 7.3 Registration

New tests must be registered in two places:

1. **Makefile target** — add to `test/tap/tests/unit/Makefile` (for unit tests)
   or `test/tap/tests/Makefile` (for integration/E2E tests)

2. **Test group** — add to the appropriate group in
   `test/tap/groups/groups.json`:
   ```json
   {
     "unit-tests-g1": {
       "tests": [
         "unit/mysqlx_my_new_component_unit-t"
       ]
     }
   }
   ```

### 7.4 Guidelines by Tier

#### Unit Tests

- No filesystem writes, no network, no real database
- Use in-memory SQLite3 (`":memory:"`) for any SQL needs
- Use `socketpair()` for any I/O testing
- Use `feed_bytes()` for data stream testing
- Link against `libproxysql.a` via the test harness
- Include `test_globals.h` and `test_init.h` for minimal initialization

#### Integration Tests

- May load the real plugin `.so`
- May start TCP listeners on ephemeral ports (use port 0 for OS-assigned)
- Use `fake_plugin.cpp` from test_helpers when you need a controllable plugin
- Clean up all resources (close sockets, free memory, delete temp files)

#### E2E Tests

- Always check for `MYSQLX_E2E_HOST` and skip if unset
- Do not assume specific data exists — create and clean up your own
- Use unique table/database names to avoid collisions with parallel runs
- Keep tests idempotent — runnable multiple times with the same result

#### Concurrent Tests

- Use `std::thread` (not pthread directly)
- Use a barrier (`std::atomic<int>`) to ensure all threads start simultaneously
- Verify exact counter values after all threads join
- Keep iteration counts reasonable (10,000 per thread is usually sufficient)
- Do not depend on timing or scheduling order

### 7.5 Example: Adding a New v2 Unit Test

```cpp
// test/tap/tests/unit/mysqlx_pool_unit-t.cpp
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "mysqlx_connection.h"
#include "mysqlx_thread.h"

int main() {
    plan(6);
    test_globals_init();

    // Test pool matching
    Mysqlx_Thread thr;
    thr.init(0);

    MysqlxConnection* conn = new MysqlxConnection();
    conn->set_hostgroup(1);
    conn->set_user("appuser");
    conn->set_schema("appdb");
    conn->set_state(MysqlxConnection::IDLE);
    conn->set_reusable(true);
    thr.return_connection_to_cache(conn);

    MysqlxConnection* found = thr.get_connection_from_cache(1, "appuser", "appdb");
    ok(found != nullptr, "connection found by matching hostgroup/user/schema");
    ok(found == conn, "got the same connection back");

    found = thr.get_connection_from_cache(1, "otheruser", "appdb");
    ok(found == nullptr, "no match for different user");

    found = thr.get_connection_from_cache(1, "appuser", "otherdb");
    ok(found == nullptr, "no match for different schema");

    found = thr.get_connection_from_cache(2, "appuser", "appdb");
    ok(found == nullptr, "no match for different hostgroup");

    ok(thr.get_cached_connection_count() == 0, "cache empty after all retrieved");

    return exit_status();
}
```

Then register in `test/tap/tests/unit/Makefile` and `test/tap/groups/groups.json`.
