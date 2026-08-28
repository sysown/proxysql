# mysqlx Route Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** wire user-driven route resolution into the active mysqlx session path so sessions no longer connect to empty address + port 0 on cache miss.

**Architecture:** Widen the session's identity callback from `MysqlxCredentials` to `std::optional<MysqlxResolvedIdentity>` (already-existing richer struct in `plugins/mysqlx/include/mysqlx_config_store.h`). At auth-complete time, call a new `resolve_backend_target()` that reads `identity_->default_route`, looks up endpoint + hostgroup via the config store, and populates `target_*` fields. Three distinct error codes (4000/4001/4002) for the three failure modes. No changes to the dormant `MysqlxWorker` path.

**Tech Stack:** C++17, GNU Make build, TAP unit tests in `test/tap/tests/unit/`, gtest-free (uses `ok(cond, msg)` + `plan(N)`).

**Reference spec:** `docs/superpowers/specs/2026-04-17-mysqlx-route-identity-design.md`

---

## File Structure

**Headers modified:**
- `plugins/mysqlx/include/mysqlx_config_store.h` — add `route_exists()` predicate
- `plugins/mysqlx/include/mysqlx_session.h` — swap credentials→identity ABI

**Implementation modified:**
- `plugins/mysqlx/src/mysqlx_config_store.cpp` — implement `route_exists()`
- `plugins/mysqlx/src/mysqlx_session.cpp` — migrate to `identity_`, add `resolve_backend_target()`, wire into auth
- `plugins/mysqlx/src/mysqlx_thread.cpp` — collapse credential lambda

**Tests modified:**
- `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp` — update fake lookups, add six new tests

---

## Task 1: Add `route_exists()` predicate to MysqlxConfigStore

**Rationale:** `resolve_backend_target()` must distinguish "unknown route" (4001) from "route exists with no backend" (4002). `route_hostgroup()` returns 0 for both unknown routes and routes pointing at hostgroup 0, so a separate predicate is needed.

**Files:**
- Modify: `plugins/mysqlx/include/mysqlx_config_store.h`
- Modify: `plugins/mysqlx/src/mysqlx_config_store.cpp`
- Modify: `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp`

- [ ] **Step 1: Write the failing test**

Add to `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp` (find the bottom of the `main()` plan and add new test cases; bump `plan(N)` count by 3):

```cpp
// --- route_exists() tests ---
{
    MysqlxConfigStore store;
    ok(store.route_exists("nope") == false,
       "route_exists returns false for unknown route on empty store");
}
{
    MysqlxConfigStore store;
    std::string err;
    // Populate store by calling load_from_runtime against a fixture admin db,
    // OR by direct swap — pattern already used elsewhere in the test file.
    // Use the existing test fixture pattern; abbreviated here:
    // (See existing tests for how MysqlxConfigStore is populated under test.)
    // After populating with a route named "reads":
    // ok(store.route_exists("reads") == true, "...");
    // ok(store.route_exists("writes") == false, "...");
}
```

Note: the second test case depends on the pattern used elsewhere in the file for populating a config store. If no such pattern exists yet, add two tests using a friend helper or a minimal fixture. Prefer reusing existing patterns.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd test/tap/tests/unit
make mysqlx_robustness_unit-t 2>&1 | tail -20
```

Expected: compilation error — `'class MysqlxConfigStore' has no member named 'route_exists'`.

- [ ] **Step 3: Add declaration**

In `plugins/mysqlx/include/mysqlx_config_store.h`, after the `route_hostgroup(...)` declaration near line 67, add:

```cpp
bool route_exists(const std::string& route_name) const;
```

- [ ] **Step 4: Add implementation**

In `plugins/mysqlx/src/mysqlx_config_store.cpp`, after the `route_hostgroup` definition near line 335, add:

```cpp
bool MysqlxConfigStore::route_exists(const std::string& route_name) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return routes_.find(route_name) != routes_.end();
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd test/tap/tests/unit
make mysqlx_robustness_unit-t && ./mysqlx_robustness_unit-t 2>&1 | tail -30
```

Expected: new test cases report `ok`. Overall test plan passes.

- [ ] **Step 6: Commit**

```bash
git add plugins/mysqlx/include/mysqlx_config_store.h \
        plugins/mysqlx/src/mysqlx_config_store.cpp \
        test/tap/tests/unit/mysqlx_robustness_unit-t.cpp
git commit -m "feat(mysqlx): add route_exists() predicate to MysqlxConfigStore

Needed to distinguish unknown-route from route-with-no-backend when
resolving a session's backend target. route_hostgroup() returns 0 in
both cases and can't be used for disambiguation."
```

---

## Task 2: Replace `MysqlxCredentials` with `MysqlxResolvedIdentity` in session ABI

**Rationale:** The session needs `default_route` and other identity fields; widening the callback to return the existing `MysqlxResolvedIdentity` struct delivers all current and likely-future fields without a second migration.

This task is a pure refactor — no behavior change. The session still authenticates the same way; it just reads identity data from a different struct shape. All existing tests must still pass after this task.

**Files:**
- Modify: `plugins/mysqlx/include/mysqlx_session.h:14-21` (remove `MysqlxCredentials` + `MysqlxCredentialLookup`), `:84` (rename setter), `:138` (swap member)
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp:29-40` (constructor init list), `:52-65` (`init()`), `:67-79` (`reset()`), `:233-278` (`handle_auth_plain`), `:321-388` (`handler_auth_challenge_response`)
- Modify: `plugins/mysqlx/src/mysqlx_thread.cpp:225-244` (credential lambda)
- Modify: `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp` (fake lookups return new shape)

- [ ] **Step 1: Verify existing tests pass as baseline**

```bash
cd test/tap/tests/unit
make mysqlx_robustness_unit-t && ./mysqlx_robustness_unit-t 2>&1 | tail -5
```

Expected: baseline passes. Record the assertion count for comparison after refactor.

- [ ] **Step 2: Update header — replace credentials with identity**

In `plugins/mysqlx/include/mysqlx_session.h`:

- Add `#include "mysqlx_config_store.h"` near the top (after existing `#include "mysqlx_connection.h"`)
- Remove the `MysqlxCredentials` struct (lines 14-19)
- Replace `typedef std::function<MysqlxCredentials(const std::string& username)> MysqlxCredentialLookup;` with:

```cpp
using MysqlxIdentityLookup =
    std::function<std::optional<MysqlxResolvedIdentity>(const std::string& username)>;
```

- Add `#include <optional>` if not already present.
- Rename `set_credential_lookup` to `set_identity_lookup` at line 84:

```cpp
void set_identity_lookup(MysqlxIdentityLookup lookup) { identity_lookup_ = std::move(lookup); }
```

- Replace the private member at line 138:

```cpp
MysqlxIdentityLookup identity_lookup_;
std::optional<MysqlxResolvedIdentity> identity_;
```

- [ ] **Step 3: Update session constructor + init/reset**

In `plugins/mysqlx/src/mysqlx_session.cpp`:

Constructor (near line 29) — no changes needed (identity_ default-constructs to empty optional).

`init()` (ensure `identity_` is reset):

```cpp
void MysqlxSession::init(int fd, Mysqlx_Thread* thread_ptr) {
    client_ds_.init(XDS_FRONTEND, fd);
    client_ds_.set_nonblocking();
    status_ = CONNECTING_CLIENT;
    healthy = true;
    to_process = false;
    thread_ptr_ = thread_ptr;
    backend_conn_ = nullptr;
    target_hostgroup_ = 0;
    target_address_.clear();
    target_port_ = 0;
    identity_.reset();
    start_time_ = monotonic_time_ms();
    last_active_time_ = start_time_;
}
```

`reset()`:

```cpp
void MysqlxSession::reset() {
    status_ = NONE;
    healthy = true;
    to_process = false;
    username_.clear();
    schema_.clear();
    auth_method_.clear();
    auth_challenge_.clear();
    backend_conn_ = nullptr;
    target_hostgroup_ = 0;
    target_address_.clear();
    target_port_ = 0;
    identity_.reset();
}
```

- [ ] **Step 4: Migrate `handle_auth_plain`**

In `plugins/mysqlx/src/mysqlx_session.cpp` around line 256-273, replace the credential-lookup block:

Old:
```cpp
if (!credential_lookup_) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}
MysqlxCredentials creds = credential_lookup_(username_);
if (!creds.x_enabled || creds.password_hash.empty() || creds.password_hash.size() != 20) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}
std::vector<uint8_t> input_hash_vec = mysqlx_mysql41_hash(password);
if (input_hash_vec.size() != 20 ||
    CRYPTO_memcmp(input_hash_vec.data(), creds.password_hash.data(), 20) != 0) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}
```

New:
```cpp
if (!identity_lookup_) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}
identity_ = identity_lookup_(username_);
if (!identity_ || !identity_->x_enabled) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}

std::vector<uint8_t> stored_hash;
if (!derive_stored_hash(identity_->password, stored_hash)) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}

std::vector<uint8_t> input_hash_vec = mysqlx_mysql41_hash(password);
if (input_hash_vec.size() != 20 ||
    CRYPTO_memcmp(input_hash_vec.data(), stored_hash.data(), 20) != 0) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}
```

Add a private helper at the top of `mysqlx_session.cpp` (in the anonymous namespace around line 17):

```cpp
// Derive the 20-byte mysql_native_password hash from the stored form.
// Accepts either the "*HEX40" format or a cleartext password.
bool derive_stored_hash(const std::string& stored, std::vector<uint8_t>& out) {
    out.clear();
    if (stored.empty()) return false;
    if (stored[0] == '*') {
        if (!mysqlx_hex_decode(stored.substr(1), out) || out.size() != 20) {
            out.clear();
            return false;
        }
        return true;
    }
    auto hash = mysqlx_mysql41_hash(stored);
    if (hash.size() != 20) return false;
    out.assign(hash.begin(), hash.end());
    return true;
}
```

The helper relies on `mysqlx_hex_decode` and `mysqlx_mysql41_hash`, both of which are already used elsewhere in this file (`mysqlx_session.cpp:355`, `:267`). No new includes needed.

- [ ] **Step 5: Migrate `handler_auth_challenge_response`**

In `plugins/mysqlx/src/mysqlx_session.cpp` around line 361-377, replace:

Old:
```cpp
if (!credential_lookup_) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}
MysqlxCredentials creds = credential_lookup_(username_);
if (!creds.x_enabled || creds.password_hash.empty() || creds.password_hash.size() != 20) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}
std::vector<uint8_t> stored_hash(creds.password_hash.begin(), creds.password_hash.end());
if (!mysqlx_mysql41_verify_hash(auth_challenge_, scramble, stored_hash)) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}
```

New:
```cpp
if (!identity_lookup_) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}
identity_ = identity_lookup_(username_);
if (!identity_ || !identity_->x_enabled) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}

std::vector<uint8_t> stored_hash;
if (!derive_stored_hash(identity_->password, stored_hash)) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}

if (!mysqlx_mysql41_verify_hash(auth_challenge_, scramble, stored_hash)) {
    send_error(1045, "Access denied for user");
    healthy = false;
    return;
}
```

- [ ] **Step 6: Collapse credential lambda in thread**

In `plugins/mysqlx/src/mysqlx_thread.cpp`, replace lines 224-244:

Old:
```cpp
const MysqlxConfigStore* store = config_store_;
sess->set_credential_lookup([store](const std::string& username) -> MysqlxCredentials {
    MysqlxCredentials creds {};
    if (!store) return creds;
    auto identity = store->resolve_identity(username);
    if (!identity) return creds;
    creds.x_enabled = identity->x_enabled;
    creds.allowed_auth = identity->allowed_auth_methods;
    creds.backend_password = identity->backend_password;
    const std::string& pwd = identity->password;
    if (!pwd.empty() && pwd[0] == '*') {
        std::vector<uint8_t> hash_bytes;
        if (mysqlx_hex_decode(pwd.substr(1), hash_bytes) && hash_bytes.size() == 20) {
            creds.password_hash.assign(hash_bytes.begin(), hash_bytes.end());
        }
    } else if (!pwd.empty()) {
        auto hash = mysqlx_mysql41_hash(pwd);
        creds.password_hash.assign(hash.begin(), hash.end());
    }
    return creds;
});
```

New:
```cpp
const MysqlxConfigStore* store = config_store_;
sess->set_identity_lookup(
    [store](const std::string& username) -> std::optional<MysqlxResolvedIdentity> {
        if (!store) return std::nullopt;
        return store->resolve_identity(username);
    }
);
```

- [ ] **Step 7: Update unit-test fake lookups**

In `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp`, find every place that constructs `MysqlxCredentials` or calls `set_credential_lookup`. For each, update to return `std::optional<MysqlxResolvedIdentity>` and call `set_identity_lookup`.

Pattern replacement (for each test fixture that previously did this):

Old (illustrative):
```cpp
sess.set_credential_lookup([&](const std::string&) {
    MysqlxCredentials c{};
    c.x_enabled = true;
    c.password_hash.assign(pwd_hash.begin(), pwd_hash.end());
    c.allowed_auth = "MYSQL41";
    return c;
});
```

New:
```cpp
sess.set_identity_lookup([&](const std::string& u) -> std::optional<MysqlxResolvedIdentity> {
    MysqlxResolvedIdentity id{};
    id.username = u;
    id.x_enabled = true;
    id.password = TEST_PASSWORD;  // derive_stored_hash will mysqlx_mysql41_hash this
    id.allowed_auth_methods = "MYSQL41";
    id.default_route = "";  // test task-2 refactor only; routing tested in Task 3/4
    return id;
});
```

- [ ] **Step 8: Build + run existing tests**

```bash
cd test/tap/tests/unit
make mysqlx_robustness_unit-t 2>&1 | tail -20
./mysqlx_robustness_unit-t 2>&1 | tail -30
```

Expected: same assertion count and all-pass as the baseline from Step 1. No behavior change.

- [ ] **Step 9: Commit**

```bash
git add plugins/mysqlx/include/mysqlx_session.h \
        plugins/mysqlx/src/mysqlx_session.cpp \
        plugins/mysqlx/src/mysqlx_thread.cpp \
        test/tap/tests/unit/mysqlx_robustness_unit-t.cpp
git commit -m "refactor(mysqlx): replace MysqlxCredentials with MysqlxResolvedIdentity

The session's identity-lookup callback now returns the full
MysqlxResolvedIdentity struct from the config store rather than a
stripped-down MysqlxCredentials. Password-hash derivation moves into
the session via a private derive_stored_hash helper. No behavior
change; existing tests pass unchanged assertion count."
```

---

## Task 3: Add `resolve_backend_target()` — new method, unit-tested in isolation

**Rationale:** Adding the resolution logic as a separate method lets unit tests exercise it without driving the full session state machine. Task 4 wires it into the auth flow.

**Files:**
- Modify: `plugins/mysqlx/include/mysqlx_session.h` (add private method declaration)
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp` (implement)
- Modify: `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp` (four new tests)

- [ ] **Step 1: Write failing tests**

Add to `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp` (bump `plan(N)` by 7):

```cpp
// --- resolve_backend_target tests ---

// test_routing_happy_path
{
    MysqlxConfigStore store;
    // Populate store with user->identity where default_route="reads",
    // route "reads" -> hostgroup 20, endpoint (host=127.0.0.1, port=33060).
    // Use the existing fixture pattern in this test file.
    // (Pattern: construct a fake runtime-SQLite or call load_from_runtime
    //  against a fixture admin db — whichever already exists.)

    MysqlxSession sess;
    Mysqlx_Thread thr;
    thr.init(0);
    thr.set_config_store(&store);
    sess.init(/*fd=*/-1, &thr);

    // Inject identity as if auth had just succeeded:
    sess.inject_identity_for_test("testuser");  // see Step 3 below

    int rc = sess.resolve_backend_target_for_test();
    ok(rc == 0, "resolve_backend_target returns 0 on happy path");
    ok(sess.target_hostgroup_for_test() == 20, "target hostgroup is 20");
    ok(sess.target_address_for_test() == "127.0.0.1", "target address populated");
    ok(sess.target_port_for_test() == 33060, "target port populated");
}

// test_routing_no_default_route
{
    MysqlxConfigStore store;  // empty

    MysqlxSession sess;
    Mysqlx_Thread thr;
    thr.init(0);
    thr.set_config_store(&store);
    sess.init(-1, &thr);

    MysqlxResolvedIdentity id{};
    id.username = "u";
    id.x_enabled = true;
    id.default_route = "";  // no default route
    sess.inject_identity_for_test(id);

    int rc = sess.resolve_backend_target_for_test();
    ok(rc == 4000, "resolve returns 4000 for empty default_route");
}

// test_routing_unknown_route
{
    MysqlxConfigStore store;  // no "nope" route

    MysqlxSession sess;
    Mysqlx_Thread thr;
    thr.init(0);
    thr.set_config_store(&store);
    sess.init(-1, &thr);

    MysqlxResolvedIdentity id{};
    id.username = "u";
    id.x_enabled = true;
    id.default_route = "nope";
    sess.inject_identity_for_test(id);

    int rc = sess.resolve_backend_target_for_test();
    ok(rc == 4001, "resolve returns 4001 for unknown route");
}

// test_routing_no_backend
{
    MysqlxConfigStore store;
    // Populate: route "reads" exists (hostgroup 20), but hostgroup 20 has
    // zero endpoints. Use existing fixture pattern.

    MysqlxSession sess;
    Mysqlx_Thread thr;
    thr.init(0);
    thr.set_config_store(&store);
    sess.init(-1, &thr);

    MysqlxResolvedIdentity id{};
    id.username = "u";
    id.x_enabled = true;
    id.default_route = "reads";
    sess.inject_identity_for_test(id);

    int rc = sess.resolve_backend_target_for_test();
    ok(rc == 4002, "resolve returns 4002 when route has no endpoints");
}

// test_routing_stats_on_failure — verify mysqlx_stats().record_conn_err
// is called with the right (route, hg) tuple for each failure mode.
// Requires a stats-recording spy; if mysqlx_stats is a singleton with no
// injection seam, add a minimal test hook (e.g. MysqlxStats::reset_for_test()
// and MysqlxStats::get_last_conn_err_for_test() returning optional<pair<string,int>>)
// before using it in this test.
{
    // For empty default_route: expect ("", 0)
    MysqlxConfigStore store;
    MysqlxSession sess;
    Mysqlx_Thread thr;
    thr.init(0);
    thr.set_config_store(&store);
    sess.init(-1, &thr);
    MysqlxResolvedIdentity id{};
    id.x_enabled = true;
    id.default_route = "";
    sess.inject_identity_for_test(id);
    mysqlx_stats().reset_for_test();
    sess.resolve_backend_target_for_test();
    auto last = mysqlx_stats().get_last_conn_err_for_test();
    ok(last.has_value() && last->first == "" && last->second == 0,
       "stats recorded ('', 0) for empty default_route");
}

// test_routing_unknown_user — identity_lookup returns nullopt; covered by the
// existing auth tests in the file (see setup_authenticated_session at line 69).
// This test adds explicit coverage of the nullopt branch by driving auth with
// a fake lookup that always returns nullopt.
{
    int fds[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    MysqlxSession sess;
    Mysqlx_Thread thr;
    thr.init(0);
    sess.init(fds[0], &thr);
    sess.set_identity_lookup([](const std::string&) { return std::nullopt; });

    // Drive handshake to auth-start via the same sequence as
    // setup_authenticated_session (lines 83-122 of this test file). After
    // writing AUTHENTICATE_START with mech MYSQL41 + "testuser", the session
    // should emit Error(1045) and mark itself unhealthy without ever sending
    // AUTHENTICATE_CONTINUE.

    // ... (use existing write_x_frame + sess.handler() pattern) ...

    ok(!sess.is_healthy(), "session unhealthy on unknown user");
    close(fds[0]); close(fds[1]);
}
```

The tests use `inject_identity_for_test` / `resolve_backend_target_for_test` / `target_*_for_test` friend-style accessors added in Step 3. These accessors exist only so the unit test can drive the method without standing up the full auth state machine.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd test/tap/tests/unit
make mysqlx_robustness_unit-t 2>&1 | tail -20
```

Expected: compilation error — `'class MysqlxSession' has no member named 'resolve_backend_target_for_test'` (and the other `_for_test` helpers).

- [ ] **Step 3: Declare `resolve_backend_target()` + test accessors**

In `plugins/mysqlx/include/mysqlx_session.h`, under the `private:` section add:

```cpp
int resolve_backend_target();
```

Also in the `public:` section (grouped with the other `_for_test` / test hooks the file may already expose — if none, add them here):

```cpp
// Test-only accessors. Not used by production code.
void inject_identity_for_test(const MysqlxResolvedIdentity& id) { identity_ = id; }
void inject_identity_for_test(const std::string& username);  // convenience overload; see .cpp
int  resolve_backend_target_for_test() { return resolve_backend_target(); }
int  target_hostgroup_for_test() const { return target_hostgroup_; }
const std::string& target_address_for_test() const { return target_address_; }
int  target_port_for_test() const { return target_port_; }
```

The convenience overload `inject_identity_for_test(const std::string&)` is implemented in `.cpp` because it may use `thread_ptr_->get_config_store()->resolve_identity(username)` to simulate a real lookup. Tests that want full control pass a pre-built `MysqlxResolvedIdentity` to the first overload.

- [ ] **Step 4: Implement `resolve_backend_target()`**

In `plugins/mysqlx/src/mysqlx_session.cpp`, add this method (place it near the other handler methods, e.g. just before `handler_connecting_server`):

```cpp
int MysqlxSession::resolve_backend_target() {
    if (!identity_) {
        // Invariant: caller ensured auth succeeded before calling.
        // Treat as a programming error manifesting as no-backend.
        send_error(4002, "No backend available: missing identity");
        healthy = false;
        return 4002;
    }

    const std::string& route_name = identity_->default_route;
    if (route_name.empty()) {
        send_error(4000, "User has no default_route configured");
        mysqlx_stats().record_conn_err("", 0);
        healthy = false;
        return 4000;
    }

    MysqlxConfigStore* cs = thread_ptr_ ? thread_ptr_->get_config_store() : nullptr;
    if (!cs) {
        send_error(4002, "No backend available: config store unavailable");
        mysqlx_stats().record_conn_err(route_name, 0);
        healthy = false;
        return 4002;
    }

    if (!cs->route_exists(route_name)) {
        std::string msg = "Route '";
        msg += route_name;
        msg += "' not found";
        send_error(4001, msg.c_str());
        mysqlx_stats().record_conn_err(route_name, 0);
        healthy = false;
        return 4001;
    }

    int hg = cs->route_hostgroup(route_name);
    MysqlxBackendEndpoint ep = cs->pick_endpoint(route_name);
    if (ep.hostname.empty()) {
        std::string msg = "No backend available for route '";
        msg += route_name;
        msg += "'";
        send_error(4002, msg.c_str());
        mysqlx_stats().record_conn_err(route_name, hg);
        healthy = false;
        return 4002;
    }

    target_hostgroup_ = hg;
    target_address_   = ep.hostname;
    target_port_      = ep.mysqlx_port;
    return 0;
}
```

Add `#include "mysqlx_stats.h"` at the top of `mysqlx_session.cpp` if not already present (check via `grep "mysqlx_stats" plugins/mysqlx/src/mysqlx_session.cpp` — if no hit, add the include).

Implement the convenience test-accessor overload in `mysqlx_session.cpp`:

```cpp
void MysqlxSession::inject_identity_for_test(const std::string& username) {
    if (!thread_ptr_) return;
    MysqlxConfigStore* cs = thread_ptr_->get_config_store();
    if (!cs) return;
    auto id = cs->resolve_identity(username);
    if (id) identity_ = *id;
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd test/tap/tests/unit
make mysqlx_robustness_unit-t && ./mysqlx_robustness_unit-t 2>&1 | tail -30
```

Expected: all new test cases report `ok`. Previous tests still pass.

- [ ] **Step 6: Commit**

```bash
git add plugins/mysqlx/include/mysqlx_session.h \
        plugins/mysqlx/src/mysqlx_session.cpp \
        test/tap/tests/unit/mysqlx_robustness_unit-t.cpp
git commit -m "feat(mysqlx): add resolve_backend_target() on session

Resolves identity.default_route to target hostgroup / address / port via
the config store. Returns 4000/4001/4002 for empty-default-route /
unknown-route / no-backend respectively, records stats, and emits an
X-Protocol Error frame. Not yet wired into auth flow — that follows in
the next commit. Unit-testable in isolation via *_for_test accessors."
```

---

## Task 4: Wire `resolve_backend_target()` into the auth flow

**Rationale:** With the method working in isolation, insert the call at both auth-success sites (PLAIN and MYSQL41) — before `send_auth_ok()`, so a routing failure surfaces as an X-Protocol `Error` rather than after the client thinks it's authenticated.

**Files:**
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp` (two call sites: `handle_auth_plain` line 275, `handler_auth_challenge_response` line 384)
- Modify: `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp` (integration tests covering the wired flow)

- [ ] **Step 1: Write failing integration test**

Add to `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp` (bump `plan(N)` by 3):

```cpp
// --- auth flow integration: routing failure prevents Ok ---

// Scenario: PLAIN auth succeeds credential-wise, but user has no default_route.
// Expect: session sends Error(4000) and transitions to X_SESSION_CLOSING
// without ever setting status to WAITING_CLIENT_XMSG.
{
    MysqlxConfigStore store;
    // Populate store such that resolve_identity("testuser") returns an
    // identity with x_enabled=true, password=TEST_PASSWORD, default_route="".
    // Follow existing fixture pattern.

    MysqlxSession sess;
    Mysqlx_Thread thr;
    thr.init(0);
    thr.set_config_store(&store);
    int client_pair[2];
    // Use the existing pattern in the test file for creating a
    // mock client socketpair and feeding a PLAIN auth frame.

    sess.init(client_pair[1], &thr);
    // ...drive session through CONNECTING_CLIENT -> X_AUTH_START ->
    //    handle_auth_plain with valid TEST_PASSWORD over TLS-marked ds...

    ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSING,
       "session closing after routing failure");
    ok(!sess.is_healthy(), "session unhealthy after routing failure");

    // Inspect the frame written to client_pair[0]: assert it's an X Error
    // with code 4000.
    uint8_t buf[256];
    ssize_t r = read(client_pair[0], buf, sizeof(buf));
    ok(r > 5 && buf[4] == Mysqlx::ServerMessages_Type_ERROR,
       "client received Error frame for routing failure");
}
```

Note: this test uses the existing socketpair + frame-drive pattern already in the file (see the test around line 193-200 for the happy-path reference). Adapt to the existing helper if one exists.

- [ ] **Step 2: Run to verify failure**

```bash
cd test/tap/tests/unit
make mysqlx_robustness_unit-t && ./mysqlx_robustness_unit-t 2>&1 | tail -30
```

Expected: the test fails — session reaches `WAITING_CLIENT_XMSG` with `Ok` on the wire instead of `X_SESSION_CLOSING` with an `Error`.

- [ ] **Step 3: Wire into `handle_auth_plain`**

In `plugins/mysqlx/src/mysqlx_session.cpp`, in `handle_auth_plain` around line 275, replace:

Old:
```cpp
last_active_time_ = monotonic_time_ms();
send_auth_ok();
status_ = WAITING_CLIENT_XMSG;
```

New:
```cpp
if (resolve_backend_target() != 0) {
    status_ = X_SESSION_CLOSING;
    return;
}

last_active_time_ = monotonic_time_ms();
send_auth_ok();
status_ = WAITING_CLIENT_XMSG;
```

- [ ] **Step 4: Wire into `handler_auth_challenge_response`**

In `plugins/mysqlx/src/mysqlx_session.cpp`, in `handler_auth_challenge_response` around line 384, replace:

Old:
```cpp
last_active_time_ = monotonic_time_ms();
send_auth_ok();
status_ = WAITING_CLIENT_XMSG;
to_process = true;
```

New:
```cpp
if (resolve_backend_target() != 0) {
    status_ = X_SESSION_CLOSING;
    to_process = true;
    return;
}

last_active_time_ = monotonic_time_ms();
send_auth_ok();
status_ = WAITING_CLIENT_XMSG;
to_process = true;
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd test/tap/tests/unit
make mysqlx_robustness_unit-t && ./mysqlx_robustness_unit-t 2>&1 | tail -30
```

Expected: integration test now passes. All pre-existing tests still pass (in particular, any happy-path auth test must have its fixture updated to set `default_route` non-empty and register a usable route — if not already done implicitly).

If pre-existing happy-path auth tests break because their fixtures don't provide a `default_route`, update those fixtures in this same commit: set `id.default_route = "test_route"` and register a fixture route pointing at a reachable hostgroup + endpoint. This is expected — it reflects the new invariant that a session needs a resolvable route to complete auth.

- [ ] **Step 6: Build full plugin + run TAP sweep**

```bash
cd /data/rene/proxysql
make build_tap_tests 2>&1 | tail -5
cd test/tap/tests
# Run only mysqlx-related binaries; avoid running every TAP test in this step.
for t in test_mysqlx_*-t; do [ -x "$t" ] || continue; echo "== $t =="; ./"$t" 2>&1 | tail -5; done
```

Expected: mysqlx unit + smoke tests pass. E2E routing test still skips (needs Phase 1b CI infrastructure, out of scope for this plan).

- [ ] **Step 7: Commit**

```bash
git add plugins/mysqlx/src/mysqlx_session.cpp \
        test/tap/tests/unit/mysqlx_robustness_unit-t.cpp
git commit -m "feat(mysqlx): wire resolve_backend_target() into auth flow

Both auth paths (PLAIN and MYSQL41) now resolve the user's default_route
to a concrete backend target before sending the X-Protocol Ok frame.
Routing failures (empty default_route, unknown route, no backend) emit
an Error frame with code 4000/4001/4002 and close the session.

Fixes the bug where sessions with empty target_* fields attempted to
connect to \"\" on port 0 after auth completed."
```

---

## Task 5 (optional, can be separate commit): Retire dead worker code

**Scope check:** The spec lists this as "out of scope for this spec" but the implementation plan includes it as an optional trailing commit since it's small, mechanical, and naturally closes the architectural loop of "two parallel implementations → one".

**Files:**
- Delete: `plugins/mysqlx/src/mysqlx_worker.cpp`, `plugins/mysqlx/include/mysqlx_worker.h`
- Modify: `plugins/mysqlx/Makefile` (remove worker.o from build)

- [ ] **Step 1: Verify worker is genuinely unused**

```bash
grep -rn "mysqlx_worker\|MysqlxWorker\|g_workers\|g_listeners\|MysqlxListenerHandle\|mysqlx_start_listeners_from_runtime_routes" \
    plugins/mysqlx/src/ plugins/mysqlx/include/ lib/ src/ 2>&1 \
    | grep -v -e "\.o:" -e "\.so:" -e "plugins/mysqlx/src/mysqlx_worker.cpp" -e "plugins/mysqlx/include/mysqlx_worker.h"
```

Expected: no output. If there are hits, stop — the worker path is in use somewhere and this task needs rework.

- [ ] **Step 2: Delete the files**

```bash
rm plugins/mysqlx/src/mysqlx_worker.cpp plugins/mysqlx/include/mysqlx_worker.h
```

- [ ] **Step 3: Remove from Makefile**

In `plugins/mysqlx/Makefile`, find any reference to `mysqlx_worker` (e.g., in an OBJECTS or SOURCES list) and remove it.

```bash
grep -n "mysqlx_worker" plugins/mysqlx/Makefile
```

Remove any matching lines.

- [ ] **Step 4: Build and test**

```bash
cd /data/rene/proxysql
make 2>&1 | tail -10
cd test/tap/tests/unit
make mysqlx_robustness_unit-t && ./mysqlx_robustness_unit-t 2>&1 | tail -5
```

Expected: clean build; tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A plugins/mysqlx/
git commit -m "chore(mysqlx): remove dead worker implementation

MysqlxWorker / g_workers / g_listeners / MysqlxListenerHandle and the
mysqlx_start_listeners_from_runtime_routes entry point were an earlier
parallel implementation that never became reachable from any call site.
Route resolution now lives in the active MysqlxSession path (see
previous commit), so the dormant code no longer serves as a reference
or migration target."
```

---

## Self-review notes

- **Spec coverage:** Every spec section has at least one task: identity-lookup widening (Task 2), session state (Task 2), resolve step (Task 3), state transitions (Task 4), files-modified table (Tasks 1–4), all six planned unit tests (distributed across Tasks 1, 3, 4), route_exists disambiguation (Task 1).
- **Non-goals preserved:** listener-driven routing (not in plan), CI infra (not in plan), error-code reconciliation (not in plan). Dead worker removal surfaced as optional Task 5 — if undesired, drop it.
- **Test-accessor pattern:** Tasks 3 and 4 rely on a small number of `_for_test` public methods on `MysqlxSession`. This is a standard pattern for unit-testing internal state without `friend` declarations; preferred over `FRIEND_TEST` macros to keep test-only code clearly labelled.
- **Assumed fixture helpers:** Tasks 1, 3, and 4 refer to "the existing fixture pattern". The test file currently has `setup_authenticated_session(fds, sess)` at `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp:69` which drives an end-to-end socketpair-based handshake, and helpers `write_x_frame` / `read_x_frame` (`:27` / `:41`). There is **no** existing helper for populating `MysqlxConfigStore` directly — the store's `routes_`/`hostgroup_endpoints_` maps are private and `load_from_runtime` wants a `SQLite3DB&`. Before starting Task 1, add a small test-only helper on `MysqlxConfigStore`:

```cpp
// In mysqlx_config_store.h, public section:
void install_for_test(
    std::unordered_map<std::string, MysqlxRoute> routes,
    std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints);
```

Implementation in `mysqlx_config_store.cpp`:

```cpp
void MysqlxConfigStore::install_for_test(
    std::unordered_map<std::string, MysqlxRoute> routes,
    std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints
) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    routes_ = std::move(routes);
    hostgroup_endpoints_ = std::move(endpoints);
}
```

Add this helper as the first commit, before Task 1. All subsequent tests use it to set up store state.
- **Stats test hook:** Task 3's `test_routing_stats_on_failure` assumes `MysqlxStats` has `reset_for_test()` and `get_last_conn_err_for_test()` methods. If `mysqlx_stats` is a singleton without these, add them as a small prelude (analogous to the store helper above) or drop the stats test and rely on integration testing to verify the stats code path — decide during implementation based on how intrusive the hook is.
- **Test for unknown_user:** Implemented in Task 3 rather than Task 2 because it needs the new `set_identity_lookup` setter in place. Behavior (Error 1045, unhealthy session) is unchanged from the pre-refactor state.
