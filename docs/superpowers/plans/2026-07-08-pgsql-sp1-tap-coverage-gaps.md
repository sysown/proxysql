# PostgreSQL SP-1 — TAP Coverage Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the known behavioral gaps in ProxySQL's PostgreSQL TAP suite — a deliberate frontend auth-method matrix (cleartext/md5/scram), a systematic data-type/binary-encoding matrix, server-side cursors, pool-churn/session-isolation, and a LISTEN/NOTIFY per-mode contract test — all in the existing TAP/C++ harness, gating per-PR.

**Architecture:** New `test/tap/tests/pgsql-*-t.cpp` files driven through two existing clients: **libpq** (via the `PGConnPtr` pattern) for functional/data tests, and the hand-rolled raw-socket **`pg_lite_client`** for byte-level control (auth framing, result formats, portal suspend). The auth matrix requires first extending `pg_lite_client` to speak MD5 and SCRAM-SHA-256 (today it only does cleartext), reusing the vendored `deps/libscram` client-side functions rather than hand-rolling crypto. Each test registers in `test/tap/groups/groups.json` under the pgsql16-backed `legacy-g4`/`mysql-*-g4` group set and runs under the isolated Docker harness.

**Tech Stack:** C++17, TAP (`tap.h`, `command_line.h`), libpq (`libpq-fe.h`), raw sockets (`pg_lite_client.{h,cpp}`), `deps/libscram` (SCRAM-SHA-256 client), OpenSSL (MD5, already linked), Docker-based `test/infra` harness, `run-tests-isolated.bash`.

## Global Constraints

- **Debug build required** for the isolated harness (`proxysql-tester.py` issues `#ifdef DEBUG` admin commands). Build with `PROXYSQL31=1 make debug` and pass the SAME tier flag on every make; `make clean` when switching tiers (per `CLAUDE.md`).
- **Never manually set up Docker** — always use `test/infra/control/ensure-infras.bash` / `run-tests-isolated.bash`. After rebuilding proxysql, re-run `test/infra/control/start-proxysql-isolated.bash` to swap the binary.
- **Single-test runs** use the `TEST_PY_TAP_INCL` regex filter against the test's real group — never invent a throwaway group.
- **Frontend auth method** is the server variable `pgsql-authentication_method` (int, range 1–3): `1`=CLEAR_TEXT_PASSWORD, `2`=MD5_PASSWORD, `3`=SASL_SCRAM_SHA_256. Change it via admin `SET pgsql-authentication_method=N; LOAD PGSQL VARIABLES TO RUNTIME;`. Default is `3`.
- **CommandLine members** (from `test/tap/tap/command_line.h`): frontend/unprivileged test conn = `cl.pgsql_host` / `cl.pgsql_port` (6133) / `cl.pgsql_username` (`testuser`) / `cl.pgsql_password` (`testuser`); admin = `cl.admin_host` / `cl.admin_port` / `cl.admin_username` / `cl.admin_password`; direct backend = `cl.pgsql_server_host` / `cl.pgsql_server_port`. Guard every `main()` with `if (cl.getEnv()) return exit_status();`.
- **Discovery-phase framing (spec §2.1):** these SP-1 tests target existing libpq-path behavior and are expected to pass; where a case exercises the young native backend path (`pgsql-use_native_backend_protocol=on`), mark it xfail rather than failing the suite.
- **Makefile:** plain single-file libpq tests need NO Makefile edit (wildcard `*-t.cpp` + generic `%-t` rule). Tests that compile `pg_lite_client.cpp` need an explicit rule; tests that also link SCRAM need `-lscram -lusual -Wl,--allow-multiple-definition` appended.

---

## Relationship to PR #5865 (PostgreSQL auth) — READ FIRST

PR **#5865** ("SCRAM verifier & md5 credential storage with SCRAM/md5 backend pass-through", open, base `v3.0`) overlaps the auth portion of this plan and must be coordinated with:

- **It already adds** `pgsql-verifier_auth-t` (~10 integration assertions), `pgsql-verifier_passthrough-t` (backend pass-through), and `pgsql_reconcile_unit-t` (9 unit cases) — registered in the **same** `legacy-g4` + `mysql-*-g4` group set this plan uses.
- **It already covers**, via **libpq**: the credential-storage-type × floor matrix (plaintext / `md5<hex>` / `SCRAM-SHA-256$…` verifier, users created at runtime with `PQencryptPasswordConn()`), floor reconciliation with `pgsql-authentication_method` 1/2/3, out-of-range floor (4) clamping, SCRAM-not-downgraded-under-cleartext-floor, anti-enumeration (identical error templates), and malformed-verifier-rejected-at-LOAD.
- **It does NOT** assert the wire-level auth **challenge type**, and **runs no queries** — its own note: *"Verifies FRONTEND auth only (connect succeeds/fails); no queries are run."* libpq hides which challenge (cleartext/md5/SASL) ProxySQL actually presented.
- It keeps `pgsql-authentication_method` an integer floor 1–3 (unchanged), and does **not** add SCRAM-SHA-256-PLUS / channel binding. It does **not** touch `pg_lite_client`.

**Consequences for this plan:**
1. **De-duplicate.** Do NOT re-test what #5865 covers (storage-type × floor success/fail, anti-enumeration, malformed verifier, backend pass-through). This plan's auth test is repositioned to the **wire-level complement**: assert the *actual challenge type* ProxySQL presents for each floor and that the authenticated session executes a query — neither of which #5865 can do through libpq.
2. **The MD5/SCRAM enabler (Tasks 2–3) stands unchanged** — #5865 doesn't touch `pg_lite_client`, and SP-2 + the data-type/cursor tests need raw-client MD5/SCRAM regardless.
3. **Merge order.** Both touch `groups.json` and add pgsql auth tests. Develop this plan **on top of #5865** (or rebase onto it once merged) to avoid `groups.json` conflicts and to reuse its runtime user-creation pattern (`PQencryptPasswordConn()`) for the optional storage-type extension in Task 3 Step 7.

---

## File Structure

**New test files (all in `test/tap/tests/`):**
- `pgsql-auth_method_matrix-t.cpp` — frontend cleartext/md5/scram success + failure paths (uses `pg_lite_client`).
- `pgsql-datatype_matrix-t.cpp` — per-type text+binary round-trips asserting value, type OID, format code (uses `pg_lite_client`).
- `pgsql-server_side_cursors-t.cpp` — DECLARE/FETCH/MOVE/CLOSE + extended-protocol portal suspension (libpq + `pg_lite_client`).
- `pgsql-pool_churn-t.cpp` — connection storm vs max_connections + session-state isolation across multiplexed reuse (libpq).
- `pgsql-listen_notify_contract-t.cpp` — per-mode LISTEN rejection / NOTIFY-as-query contract (libpq).

**Modified harness files:**
- `test/tap/tests/pg_lite_client.h` — declare MD5 + SCRAM auth helpers.
- `test/tap/tests/pg_lite_client.cpp` — implement MD5 (Task 2) and SCRAM (Task 3) in `handleAuthentication`.
- `test/tap/tests/Makefile` — explicit build rules for the four `pg_lite_client`-using tests (Task 1/2/3/4/5), with `-lscram -lusual` on the auth-matrix rule.
- `test/tap/groups/groups.json` — register the five new tests.

**Interfaces produced by the harness tasks (consumed by later tasks):**
- `pg_lite_client` gains no signature changes to `connect()`; MD5/SCRAM are handled internally inside `handleAuthentication(const std::string& password)`. After Task 3, `PgConnection::connect(host, port, dbname, user, password)` succeeds against a ProxySQL frontend configured for cleartext, md5, or scram.

---

## Task 1: Wire-level auth-challenge test scaffold + cleartext case

**Purpose (post-#5865): the wire-level complement.** #5865 already proves *connect success/fail* per storage-type × floor through libpq. This test proves the thing libpq hides — that ProxySQL presents the **correct challenge type on the wire** for the configured floor, and that the authenticated session **runs a query**. Task 1 establishes the file, the admin floor-toggling helper, a tiny `pg_lite_client` accessor exposing the observed challenge type, and the cleartext case (challenge type `3`, already supported).

**Files:**
- Create: `test/tap/tests/pgsql-auth_method_matrix-t.cpp`
- Modify: `test/tap/tests/pg_lite_client.h` + `pg_lite_client.cpp` (add `getLastAuthType()` accessor)
- Modify: `test/tap/tests/Makefile` (add explicit rule compiling `pg_lite_client.cpp`)
- Modify: `test/tap/groups/groups.json` (register the test)

**Interfaces:**
- Consumes: `pg_lite_client.h` `PgConnection::connect/execute`, `command_line.h` `CommandLine`.
- Produces: `PgConnection::getLastAuthType()` (first non-zero auth request type observed during `connect()`); helpers `set_frontend_auth_method(MYSQL*, int)` and `try_frontend_login(user, password, int& observed_auth_type)` reused by Tasks 2–3.
- **Challenge-type codes** (PostgreSQL `Authentication*` request type ints): cleartext = `3`, md5 = `5`, SASL/SCRAM = `10`.

- [ ] **Step 1a: Add the `getLastAuthType()` accessor to pg_lite_client**

In `test/tap/tests/pg_lite_client.h`, add a public member + getter to `PgConnection` (near `getSocket()`):

```cpp
    inline int getLastAuthType() const { return last_auth_type_; }
```
and in the `private:` data section:
```cpp
    int last_auth_type_ = 0;
```
In `test/tap/tests/pg_lite_client.cpp`, inside `handleAuthentication`, set it the first time a non-zero `authType` is seen — add `if (last_auth_type_ == 0 && authType != 0) last_auth_type_ = authType;` immediately after `authType` is computed from the `AUTH_TYPE` message (so cleartext records `3`; Tasks 2–3 will make it record `5`/`10`).

- [ ] **Step 1b: Write the failing test (cleartext case)**

Create `test/tap/tests/pgsql-auth_method_matrix-t.cpp`:

```cpp
#include <unistd.h>
#include <string>
#include <sstream>
#include <mysql.h>          // admin interface is reached via the MySQL client
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

// Admin connection (MySQL protocol) used to flip pgsql-authentication_method.
static MYSQL* admin_connect() {
    MYSQL* conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, cl.admin_host, cl.admin_username, cl.admin_password,
                            NULL, cl.admin_port, NULL, 0)) {
        diag("admin connect failed: %s", mysql_error(conn));
        mysql_close(conn);
        return NULL;
    }
    return conn;
}

static bool set_frontend_auth_method(MYSQL* admin, int method) {
    std::string q = "SET pgsql-authentication_method=" + std::to_string(method);
    if (mysql_query(admin, q.c_str())) { diag("SET failed: %s", mysql_error(admin)); return false; }
    if (mysql_query(admin, "LOAD PGSQL VARIABLES TO RUNTIME")) { diag("LOAD failed: %s", mysql_error(admin)); return false; }
    return true;
}

// Attempts a frontend login with pg_lite_client, running a query to prove the
// session is usable. On success, observed_auth_type = the challenge type ProxySQL
// presented (3=cleartext, 5=md5, 10=scram). Returns true on successful auth+query.
static bool try_frontend_login(const std::string& user, const std::string& password,
                               int& observed_auth_type) {
    observed_auth_type = 0;
    try {
        PgConnection c(2000);
        c.connect(cl.pgsql_host, cl.pgsql_port, user /*dbname==user in this infra*/, user, password);
        observed_auth_type = c.getLastAuthType();
        c.execute("SELECT 1");   // #5865 runs NO queries; proving the session works is our value-add
        c.disconnect();
        return true;
    } catch (const PgException& e) {
        diag("login threw: %s", e.what());
        return false;
    }
}

int main(int argc, char** argv) {
    if (cl.getEnv()) return exit_status();

    // Per method: (login succeeds + query runs) AND (observed challenge type matches floor).
    // Task 1 lands cleartext only (2 assertions); Tasks 2-3 add md5, scram, and failures.
    plan(2);

    MYSQL* admin = admin_connect();
    if (!admin) BAIL_OUT("cannot reach admin");

    // --- Cleartext floor (method = 1) -> expect challenge type 3 on the wire ---
    set_frontend_auth_method(admin, 1);   // affects NEW frontend connections
    int auth_type = 0;
    bool logged_in = try_frontend_login(cl.pgsql_username, cl.pgsql_password, auth_type);
    ok(logged_in, "cleartext floor: login + query succeed");
    ok(auth_type == 3, "cleartext floor: ProxySQL presented challenge type 3 (got %d)", auth_type);

    // restore default before exit
    set_frontend_auth_method(admin, 3);
    mysql_close(admin);
    return exit_status();
}
```

- [ ] **Step 2: Add the explicit Makefile rule**

In `test/tap/tests/Makefile`, alongside the other `pg_lite_client.cpp` rules (near line 370), add:

```make
pgsql-auth_method_matrix-t: pgsql-auth_method_matrix-t.cpp pg_lite_client.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< pg_lite_client.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -lscram -lusual -Wl,--allow-multiple-definition -o $@
```

(The `-lscram -lusual` is added now so Task 3 needs no further Makefile change.)

- [ ] **Step 3: Register in groups.json**

In `test/tap/groups/groups.json`, add an entry mirroring `pgsql-scram_cache_invalidation-t` (the pgsql16-backed group set):

```json
  "pgsql-auth_method_matrix-t" : [ "legacy-g4","mysql-auto_increment_delay_multiplex=0-g4","mysql-multiplexing=false-g4","mysql-query_digests=0-g4","mysql-query_digests_keep_comment=1-g4" ],
```

- [ ] **Step 4: Build proxysql (debug) + the test, then start infra**

```bash
PROXYSQL31=1 make -j$(nproc) debug
PROXYSQL31=1 make build_tap_test_debug
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 test/infra/control/ensure-infras.bash
```

- [ ] **Step 5: Run the single test, expect PASS**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-auth_method_matrix-t" \
  test/infra/control/run-tests-isolated.bash
```
Expected: 2/2 assertions pass (cleartext already works). If the cleartext login fails, confirm `pg_lite_client` cleartext path (`handleAuthentication` authType==3) and that `pgsql_users` contains `testuser`.

- [ ] **Step 6: Commit**

```bash
git add test/tap/tests/pgsql-auth_method_matrix-t.cpp test/tap/tests/Makefile test/tap/groups/groups.json
git commit -m "test(pgsql): auth-method matrix scaffold + cleartext case"
```

---

## Task 2: MD5 frontend auth (pg_lite_client + matrix case)

Extend `pg_lite_client` to answer an `AuthenticationMD5Password` (authType 5) challenge, then add the md5 success + wrong-password cases.

**Files:**
- Modify: `test/tap/tests/pg_lite_client.cpp` (`handleAuthentication`, new `sendMD5Password`)
- Modify: `test/tap/tests/pg_lite_client.h` (declare `sendMD5Password`)
- Modify: `test/tap/tests/pgsql-auth_method_matrix-t.cpp` (add md5 cases, bump plan)

**Interfaces:**
- Consumes: OpenSSL `MD5()` (already linked via `-lcrypto`), `PgConnection::user_` (private member set in `connect()`).
- Produces: MD5 handling inside `handleAuthentication`; no public signature change.

- [ ] **Step 1: Write the failing test (add md5 cases)**

In `pgsql-auth_method_matrix-t.cpp`, bump `plan(2)` → `plan(4)` and after the cleartext block add:

```cpp
    // --- MD5 floor (method = 2) -> expect challenge type 5 on the wire ---
    set_frontend_auth_method(admin, 2);
    int md5_auth = 0;
    ok(try_frontend_login(cl.pgsql_username, cl.pgsql_password, md5_auth),
       "md5 floor: login + query succeed");
    ok(md5_auth == 5, "md5 floor: ProxySQL presented challenge type 5 (got %d)", md5_auth);
```

(No extra `pg_lite_client` change is needed to observe the type — the generic `last_auth_type_` capture from Task 1 Step 1a records `5` as soon as the MD5 branch added below runs.)

- [ ] **Step 2: Rebuild the test and run — expect FAIL**

```bash
PROXYSQL31=1 make build_tap_test_debug
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-auth_method_matrix-t" test/infra/control/run-tests-isolated.bash
```
Expected: the md5 login assertion FAILS — `pg_lite_client` throws `Unsupported authentication method: 5`.

- [ ] **Step 3: Declare the MD5 helper**

In `test/tap/tests/pg_lite_client.h`, in the `private:` section of `PgConnection` (near `sendPassword`), add:

```cpp
    void sendMD5Password(const std::string& password, const uint8_t salt[4]);
```

- [ ] **Step 4: Implement MD5 in pg_lite_client.cpp**

In `test/tap/tests/pg_lite_client.cpp`, add the include near the top:

```cpp
#include <openssl/md5.h>
```

Add the helper (near `sendPassword`, ~line 343):

```cpp
static std::string md5_hex(const std::string& in) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(in.data()), in.size(), digest);
    static const char* hx = "0123456789abcdef";
    std::string out;
    out.reserve(MD5_DIGEST_LENGTH * 2);
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        out.push_back(hx[digest[i] >> 4]);
        out.push_back(hx[digest[i] & 0x0f]);
    }
    return out;
}

// PostgreSQL MD5 auth: "md5" + md5( md5(password + user) + salt )
void PgConnection::sendMD5Password(const std::string& password, const uint8_t salt[4]) {
    std::string inner = md5_hex(password + user_);
    std::string with_salt = inner;
    with_salt.append(reinterpret_cast<const char*>(salt), 4);
    std::string token = "md5" + md5_hex(with_salt);
    std::vector<uint8_t> packet;
    writeStringToBuffer(packet, token);   // null-terminated C string
    sendMessage('p', packet);
}
```

In `handleAuthentication`, add a branch after the `authType == 3` block, before the `else { throw ... }`:

```cpp
            else if (authType == 5) {  // AuthenticationMD5Password (4-byte salt follows)
                if (buffer.size() < 8) throw PgException("Invalid MD5 auth message");
                uint8_t salt[4];
                memcpy(salt, buffer.data() + 4, 4);
                sendMD5Password(password, salt);
                readMessage(type, buffer);
                if (type == AUTH_TYPE) {
                    authType = ntohl(*reinterpret_cast<int32_t*>(buffer.data()));
                    if (authType == 0) return;
                }
                // fall through to error handling on non-OK
            }
```

- [ ] **Step 5: Rebuild + run — expect PASS**

```bash
PROXYSQL31=1 make build_tap_test_debug
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-auth_method_matrix-t" test/infra/control/run-tests-isolated.bash
```
Expected: 4/4 pass.

- [ ] **Step 6: Commit**

```bash
git add test/tap/tests/pg_lite_client.h test/tap/tests/pg_lite_client.cpp test/tap/tests/pgsql-auth_method_matrix-t.cpp
git commit -m "test(pgsql): pg_lite_client MD5 frontend auth + matrix md5 case"
```

---

## Task 3: SCRAM-SHA-256 frontend auth (pg_lite_client + matrix case + failure paths)

Extend `pg_lite_client` to complete a SASL/SCRAM-SHA-256 exchange using the vendored `deps/libscram` client functions, then add the scram success case and wrong-password failure cases for all three methods.

**Files:**
- Modify: `test/tap/tests/pg_lite_client.cpp` (SASL branch + `sendSASLInitial`/`sendSASLResponse` helpers)
- Modify: `test/tap/tests/pg_lite_client.h` (declare helpers)
- Modify: `test/tap/tests/pgsql-auth_method_matrix-t.cpp` (scram + wrong-password cases)

**Interfaces:**
- Consumes: `deps/libscram/include/scram.h` — `scram_state_init`, `build_client_first_message`, `read_server_first_message`, `build_client_final_message`, `read_server_final_message`, `verify_server_signature`, `free_scram_state`, `PgCredentials`, `ScramState`. Linked via the `-lscram -lusual` already on this test's Makefile rule (Task 1).
- Produces: SASL handling inside `handleAuthentication`.

- [ ] **Step 1: Write the failing test (add scram + wrong-password cases)**

In `pgsql-auth_method_matrix-t.cpp`, bump `plan(4)` → `plan(9)` and add:

```cpp
    // --- SCRAM floor (method = 3) -> expect challenge type 10 on the wire ---
    set_frontend_auth_method(admin, 3);
    int scram_auth = 0;
    ok(try_frontend_login(cl.pgsql_username, cl.pgsql_password, scram_auth),
       "scram floor: login + query succeed");
    ok(scram_auth == 10, "scram floor: ProxySQL presented SASL/SCRAM challenge type 10 (got %d)", scram_auth);

    // --- Wrong-password failure paths, one per floor (challenge type irrelevant) ---
    int ignore = 0;
    set_frontend_auth_method(admin, 1);
    ok(!try_frontend_login(cl.pgsql_username, "wrong-pw", ignore), "cleartext floor: wrong password rejected");
    set_frontend_auth_method(admin, 2);
    ok(!try_frontend_login(cl.pgsql_username, "wrong-pw", ignore), "md5 floor: wrong password rejected");
    set_frontend_auth_method(admin, 3);
    ok(!try_frontend_login(cl.pgsql_username, "wrong-pw", ignore), "scram floor: wrong password rejected");
```

- [ ] **Step 2: Rebuild + run — expect FAIL**

```bash
PROXYSQL31=1 make build_tap_test_debug
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-auth_method_matrix-t" test/infra/control/run-tests-isolated.bash
```
Expected: the scram success assertion FAILS (`Unsupported authentication method: 10`). The wrong-password md5/cleartext assertions should already pass; scram wrong-password will also fail to run until SASL is implemented.

- [ ] **Step 3: Declare SASL helpers**

In `test/tap/tests/pg_lite_client.h` `private:` section add:

```cpp
    void doSASLAuth(const std::string& password, const std::vector<uint8_t>& mechListMsg);
```

- [ ] **Step 4: Implement the SASL exchange using libscram**

In `test/tap/tests/pg_lite_client.cpp` add near the top:

```cpp
extern "C" {
#include "scram.h"
}
```

Add the helper (near `sendPassword`):

```cpp
// Completes a SCRAM-SHA-256 SASL exchange as the CLIENT, reusing deps/libscram.
// mechListMsg is the AuthenticationSASL(10) payload after the 4-byte authType:
// a sequence of null-terminated mechanism names terminated by an extra null.
void PgConnection::doSASLAuth(const std::string& password,
                              const std::vector<uint8_t>& /*mechListMsg*/) {
    ScramState* st = scram_state_init();
    PgCredentials cred;
    memset(&cred, 0, sizeof(cred));
    snprintf(cred.name, sizeof(cred.name), "%s", user_.c_str());
    snprintf(cred.passwd, sizeof(cred.passwd), "%s", password.c_str());
    cred.has_scram_keys = false;

    // 1) SASLInitialResponse ('p'): mechanism name + Int32 length + client-first-message
    char* client_first = build_client_first_message(st);   // e.g. "n,,n=,r=<nonce>"
    if (!client_first) { free_scram_state(st); throw PgException(std::string("scram client-first: ") + scram_error()); }
    {
        std::vector<uint8_t> pkt;
        const char* mech = "SCRAM-SHA-256";
        writeStringToBuffer(pkt, mech);                    // null-terminated mechanism
        int32_t clen = htonl((int32_t)strlen(client_first));
        const uint8_t* cp = reinterpret_cast<const uint8_t*>(&clen);
        pkt.insert(pkt.end(), cp, cp + 4);                 // Int32 length
        pkt.insert(pkt.end(), client_first, client_first + strlen(client_first));
        sendMessage('p', pkt);
    }

    // 2) Expect AuthenticationSASLContinue (authType 11) with server-first-message
    char type; std::vector<uint8_t> buffer;
    readMessage(type, buffer);
    if (type != AUTH_TYPE || buffer.size() < 4 ||
        ntohl(*reinterpret_cast<int32_t*>(buffer.data())) != 11) {
        free(client_first); free_scram_state(st);
        throw PgException("expected AuthenticationSASLContinue(11)");
    }
    std::string server_first(reinterpret_cast<const char*>(buffer.data()) + 4, buffer.size() - 4);
    char* server_nonce = nullptr; char* salt = nullptr; int saltlen = 0; int iterations = 0;
    if (!read_server_first_message(st, const_cast<char*>(server_first.c_str()),
                                   &server_nonce, &salt, &saltlen, &iterations)) {
        free(client_first); free_scram_state(st);
        throw PgException(std::string("scram read server-first: ") + scram_error());
    }

    // 3) SASLResponse ('p'): client-final-message (with proof)
    char* client_final = build_client_final_message(st, &cred, server_nonce, salt, saltlen, iterations);
    if (!client_final) { free(client_first); free_scram_state(st); throw PgException(std::string("scram client-final: ") + scram_error()); }
    {
        std::vector<uint8_t> pkt(client_final, client_final + strlen(client_final));
        sendMessage('p', pkt);
    }

    // 4) Expect AuthenticationSASLFinal (authType 12) with server-final (v=ServerSignature)
    readMessage(type, buffer);
    if (type != AUTH_TYPE || buffer.size() < 4 ||
        ntohl(*reinterpret_cast<int32_t*>(buffer.data())) != 12) {
        free(client_first); free(client_final); free_scram_state(st);
        throw PgException("expected AuthenticationSASLFinal(12)");
    }
    {
        std::string server_final(reinterpret_cast<const char*>(buffer.data()) + 4, buffer.size() - 4);
        char server_sig[256] = {0};
        if (!read_server_final_message(const_cast<char*>(server_final.c_str()), server_sig) ||
            !verify_server_signature(st, &cred, server_sig)) {
            free(client_first); free(client_final); free_scram_state(st);
            throw PgException("scram server signature verification failed");
        }
    }
    free(client_first); free(client_final); free_scram_state(st);

    // 5) Expect AuthenticationOk (0)
    readMessage(type, buffer);
    if (type == AUTH_TYPE && ntohl(*reinterpret_cast<int32_t*>(buffer.data())) == 0) return;
    throw PgException("scram: no AuthenticationOk after SASLFinal");
}
```

In `handleAuthentication`, add the branch:

```cpp
            else if (authType == 10) {  // AuthenticationSASL (mechanism list follows)
                doSASLAuth(password, buffer);
                return;   // doSASLAuth consumes through AuthenticationOk
            }
```

- [ ] **Step 5: Rebuild + run — observe, adjust framing if needed, expect PASS**

```bash
PROXYSQL31=1 make build_tap_test_debug
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-auth_method_matrix-t" test/infra/control/run-tests-isolated.bash
```
Expected: 9/9 pass. If the scram case fails on `read_server_first_message` or signature verify, `diag()` the raw `client_first`/`server_first` strings and confirm two libscram specifics: (a) whether `build_client_first_message` already includes the `n,,` GS2 header (if not, prepend it before sending); (b) that `PgCredentials.passwd` (plaintext) is the field `build_client_final_message` derives `SaltedPassword` from. Adjust and re-run.

- [ ] **Step 6: Commit**

```bash
git add test/tap/tests/pg_lite_client.h test/tap/tests/pg_lite_client.cpp test/tap/tests/pgsql-auth_method_matrix-t.cpp
git commit -m "test(pgsql): pg_lite_client SCRAM-SHA-256 frontend auth + matrix scram/failure cases"
```

- [ ] **Step 7 (OPTIONAL — only after #5865 is merged): wire-level no-downgrade assertion for a SCRAM-verifier user**

This is the one storage-type case worth adding at the wire level, because it proves #5865's assertion 5 (*"SCRAM verifier NOT downgraded under cleartext floor"*) in a way #5865's libpq test cannot — by observing the challenge byte. Skip entirely until #5865 lands (it provides the verifier-user creation path).

Add near the top of `main`, before the failure block, and bump `plan(9)` → `plan(11)`:

```cpp
    // Requires #5865: create a user whose stored secret is a SCRAM verifier.
    // Reuse #5865's runtime pattern: PQencryptPasswordConn(conn, "verifier_pw", "scram_user", "scram-sha-256")
    // then INSERT INTO pgsql_users(username,password,...) VALUES('scram_user', <that verifier>, ...); LOAD PGSQL USERS TO RUNTIME.
    // (Factor #5865's helper out or copy its ~5-line create_verifier_user() here.)
    create_verifier_user(admin, "scram_user", "verifier_pw");   // from #5865

    set_frontend_auth_method(admin, 1);   // cleartext FLOOR...
    int vt = 0;
    bool v_ok = try_frontend_login("scram_user", "verifier_pw", vt);
    ok(v_ok, "verifier user authenticates under cleartext floor");
    ok(vt == 10, "no-downgrade: verifier user still challenged with SCRAM(10) under cleartext floor (got %d)", vt);
```

If #5865 is not yet merged when SP-1 is implemented, leave this step unchecked and keep `plan(9)`; add it in a follow-up once #5865 lands. Re-run and commit as `test(pgsql): wire-level no-downgrade assertion for SCRAM verifier (depends on #5865)`.

---

## Task 4: Data-type / binary-encoding matrix

Systematic per-type round-trips through `pg_lite_client`, each type asserted in **both** text and binary result format, checking the returned value, the column type OID, and the format code.

**Files:**
- Create: `test/tap/tests/pgsql-datatype_matrix-t.cpp`
- Modify: `test/tap/tests/Makefile` (explicit rule with `pg_lite_client.cpp`, no scram needed)
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: `PgConnection::prepareStatement/bindStatementSingleFormat/executePortal` OR `executeParams(stmtName, query, params, resultFormats)`; `PgResult` accessors (`getValue`, `columnFormat`, `isNull`). Result rows come back via `readResult()` — confirm in Step 2 whether `executeParams` populates a `PgResult`; if `readResult()` is unimplemented for a path, use `readMessage`/`BufferReader` to parse `RowDescription`(T)/`DataRow`(D) directly (the header exposes both).
- Produces: nothing consumed downstream.

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/pgsql-datatype_matrix-t.cpp`:

```cpp
#include <string>
#include <vector>
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

struct Case {
    const char* label;
    const char* select_expr;   // e.g. "SELECT '\\xdeadbeef'::bytea"
    const char* expected_text; // expected value in TEXT format
    int32_t expected_oid;      // PostgreSQL type OID
    const char* expected_binary_hex; // exact wire bytes in BINARY format
};

// Everything observed for one round-trip of a case at a given result format.
struct Observed {
    bool got_result = false;        // RowDescription+DataRow returned (no ErrorResponse)
    int32_t oid = 0;                // type OID from RowDescription
    int16_t col_format = -1;        // per-column result format code (0=text, 1=binary)
    bool is_null = true;            // DataRow value length == -1 ?
    std::string text_value;         // value decoded as text (meaningful when col_format==0)
    std::vector<uint8_t> raw_bytes; // raw DataRow payload for column 0 (both formats)
};

// Lowercase hex of a raw payload, for comparison and diagnostics.
static std::string to_hex(const std::vector<uint8_t>& bytes);

// One representative literal per type; expand freely -- adding a row is the unit
// of work. expected_binary_hex is the exact payload PostgreSQL's *_send() emits,
// so the binary assertion compares bytes rather than merely checking the OID.
//
// Excerpt only -- the shipped test carries the full table (bool, int4, int8,
// float8, numeric, text_utf8, bytea, uuid, timestamptz, jsonb, int4_array, inet)
// and is the source of truth for the expected encodings:
//   test/tap/tests/pgsql-datatype_matrix-t.cpp
static const std::vector<Case> cases = {
    { "int4",        "SELECT 2147483647::int4",            "2147483647",     23,
      "7fffffff" },
    // A genuine timestamptz (OID 1184). Applying AT TIME ZONE 'UTC' would yield
    // timestamp *without* time zone (OID 1114) and never exercise timestamptz at
    // all; instead the session pins TimeZone=UTC so the text form is deterministic.
    { "timestamptz", "SELECT '2020-01-01 00:00:00+00'::timestamptz",
                                                           "2020-01-01 00:00:00+00", 1184,
      "00023e0786c26000" },
    { "bytea",       "SELECT '\\xdeadbeef'::bytea",        "\\xdeadbeef",    17,
      "deadbeef" },
};

// Runs one case through pg_lite_client at the given result format (0=text,1=binary),
// capturing the RowDescription OID + per-column format code and the raw DataRow bytes.
static bool run_case(const Case& c, int16_t fmt, Observed& obs);

int main(int argc, char** argv) {
    if (cl.getEnv()) return exit_status();

    // For each case: 1 text assertion (value+oid) + 1 binary assertion
    // (oid + format code + exact payload bytes).
    plan((int)cases.size() * 2);

    for (const auto& c : cases) {
        Observed t;
        bool ok_text = run_case(c, 0, t);
        ok(ok_text && t.col_format == 0 && t.oid == c.expected_oid && t.text_value == c.expected_text,
           "%s text: oid=%d value='%s'", c.label, t.oid, t.text_value.c_str());

        // The binary half must compare the DataRow payload byte-for-byte against
        // the expected encoding. Asserting only the OID is NOT enough: a silent
        // text fallback, a truncated payload, or a byte-order regression all keep
        // the OID intact and would pass. Each Case therefore carries the exact
        // bytes PostgreSQL's *_send() emits for its literal.
        Observed b;
        bool ok_bin = run_case(c, 1, b);
        ok(ok_bin && b.col_format == 1 && b.oid == c.expected_oid
               && !b.is_null && to_hex(b.raw_bytes) == c.expected_binary_hex,
           "%s binary: oid=%d payload=%s (expected %s)",
           c.label, b.oid, to_hex(b.raw_bytes).c_str(), c.expected_binary_hex);
    }
    return exit_status();
}
```

- [ ] **Step 2: Implement `run_case` using the raw message path**

Append to the file (parses `RowDescription`/`DataRow` directly, which the header's `BufferReader` + message constants support):

```cpp
static bool run_case(const Case& c, int16_t fmt, Observed& obs) {
    try {
        PgConnection conn(2000);
        conn.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);

        // Pin the session time zone so the TEXT rendering of timestamptz is
        // deterministic regardless of the backend's configured TimeZone.
        conn.execute("SET TIME ZONE 'UTC'");
        conn.consumeInputUntilReady();

        // Extended protocol: unnamed prepared statement, single result format = fmt.
        // These queries take NO bind parameters, so the param-format array must be
        // empty: bindStatementSingleFormat() would send a 1-element param-format
        // array for a 0-param Bind, tripping issue #5899. bindStatementEx() with an
        // explicit empty paramFormats array is the protocol-correct 0-param bind.
        conn.prepareStatement("", c.select_expr, false, {});
        conn.bindStatementEx("", "", {}, {}, { fmt }, false);
        conn.describePortal("", false);
        conn.executePortal("", 0, true);   // sync

        // Read: ParseComplete(1), BindComplete(2), RowDescription(T), DataRow(D), CommandComplete(C), ReadyForQuery(Z)
        char type; std::vector<uint8_t> buf;
        while (true) {
            conn.readMessage(type, buf);
            if (type == PgConnection::ROW_DESCRIPTION) {
                BufferReader r(buf);
                int16_t nfields = r.readInt16();
                if (nfields >= 1) {
                    r.readString();                 // field name
                    r.readInt32();                  // table oid
                    r.readInt16();                  // column attr
                    obs.oid = r.readInt32();        // type oid
                    r.readInt16();                  // type size
                    r.readInt32();                  // type modifier
                    obs.col_format = r.readInt16(); // per-column result FORMAT CODE
                }
            } else if (type == PgConnection::DATA_ROW) {
                BufferReader r(buf);
                int16_t ncols = r.readInt16();
                if (ncols >= 1) {
                    int32_t len = r.readInt32();
                    if (len >= 0) {
                        obs.raw_bytes = r.readBytes(len);
                        obs.is_null = false;
                        // Decoded as text for the text-format assertion; in binary
                        // format the payload is opaque and text_value is unused.
                        obs.text_value.assign(obs.raw_bytes.begin(), obs.raw_bytes.end());
                        obs.got_result = true;
                    } else {
                        obs.is_null = true;
                        obs.got_result = true;
                    }
                }
            } else if (type == PgConnection::READY_FOR_QUERY) {
                break;
            } else if (type == PgConnection::ERROR_RESPONSE) {
                conn.disconnect();
                return false;
            }
        }
        conn.disconnect();
        return obs.got_result;
    } catch (const PgException& e) {
        diag("%s fmt=%d threw: %s", c.label, (int)fmt, e.what());
        return false;
    }
}
```

- [ ] **Step 3: Add Makefile rule**

```make
pgsql-datatype_matrix-t: pgsql-datatype_matrix-t.cpp pg_lite_client.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< pg_lite_client.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@
```

- [ ] **Step 4: Register in groups.json**

```json
  "pgsql-datatype_matrix-t" : [ "legacy-g4","mysql-auto_increment_delay_multiplex=0-g4","mysql-multiplexing=false-g4","mysql-query_digests=0-g4","mysql-query_digests_keep_comment=1-g4" ],
```

- [ ] **Step 5: Build + run**

```bash
PROXYSQL31=1 make build_tap_test_debug
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-datatype_matrix-t" test/infra/control/run-tests-isolated.bash
```
Expected: all `cases.size()*2` pass. Any OID/value mismatch is a real finding — `diag` shows the observed value; record genuine transparency divergences per spec §2.1 rather than loosening the assertion.

- [ ] **Step 6: Commit**

```bash
git add test/tap/tests/pgsql-datatype_matrix-t.cpp test/tap/tests/Makefile test/tap/groups/groups.json
git commit -m "test(pgsql): data-type/binary-encoding matrix (text+binary, oid+value)"
```

---

## Task 5: Server-side cursors + portal suspension

DECLARE/FETCH/MOVE/CLOSE over libpq (simple protocol) plus extended-protocol portal suspension (`Execute` with a max-row count → `PortalSuspended`) via `pg_lite_client`.

**Files:**
- Create: `test/tap/tests/pgsql-server_side_cursors-t.cpp`
- Modify: `test/tap/tests/Makefile` (explicit rule, `pg_lite_client.cpp`)
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: libpq `PQexec`/`PQntuples`; `PgConnection::executePortal(portalName, maxRows, send_sync)`, message constant `PORTAL_SUSPENDED` (`'s'`).
- Produces: nothing downstream.

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/pgsql-server_side_cursors-t.cpp`:

```cpp
#include <string>
#include <sstream>
#include "libpq-fe.h"
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr backend_conn() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
       << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
       << " dbname=" << cl.pgsql_username << " sslmode=disable";
    PGconn* c = PQconnectdb(ss.str().c_str());
    return PGConnPtr(c, &PQfinish);
}

// Extended-protocol portal suspension: Execute with maxRows=2 over a 5-row result.
static bool portal_suspends_at_2() {
    try {
        PgConnection conn(2000);
        conn.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
        conn.prepareStatement("", "SELECT g FROM generate_series(1,5) g", false, {});
        conn.bindStatementSingleFormat("", "", {}, 0, { 0 }, false);
        conn.executePortal("", 2, true);   // maxRows=2 -> expect 2 DataRows then PortalSuspended
        char type; std::vector<uint8_t> buf; int rows = 0; bool suspended = false;
        while (true) {
            conn.readMessage(type, buf);
            if (type == PgConnection::DATA_ROW) rows++;
            else if (type == PgConnection::PORTAL_SUSPENDED) { suspended = true; }
            else if (type == PgConnection::READY_FOR_QUERY) break;
            else if (type == PgConnection::ERROR_RESPONSE) { conn.disconnect(); return false; }
        }
        conn.disconnect();
        return rows == 2 && suspended;
    } catch (const PgException& e) { diag("portal test threw: %s", e.what()); return false; }
}

int main(int argc, char** argv) {
    if (cl.getEnv()) return exit_status();
    plan(4);

    PGConnPtr c = backend_conn();
    ok(c && PQstatus(c.get()) == CONNECTION_OK, "connected for cursor test");

    // DECLARE / FETCH / MOVE / CLOSE inside a transaction (cursors require a txn).
    PQexec(c.get(), "BEGIN");
    PQexec(c.get(), "DECLARE cur CURSOR FOR SELECT g FROM generate_series(1,10) g");
    PGresult* r = PQexec(c.get(), "FETCH 3 cur");
    ok(PQntuples(r) == 3, "FETCH 3 returns 3 rows");
    PQclear(r);
    r = PQexec(c.get(), "MOVE 2 cur");           // skip 2
    PQclear(r);
    r = PQexec(c.get(), "FETCH 10 cur");         // remaining 5
    ok(PQntuples(r) == 5, "MOVE 2 then FETCH returns remaining 5 rows");
    PQclear(r);
    PQexec(c.get(), "CLOSE cur");
    PQexec(c.get(), "COMMIT");

    ok(portal_suspends_at_2(), "extended-protocol portal suspends at maxRows=2");

    return exit_status();
}
```

- [ ] **Step 2: Add Makefile rule + groups.json entry**

```make
pgsql-server_side_cursors-t: pgsql-server_side_cursors-t.cpp pg_lite_client.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $< pg_lite_client.cpp $(IDIRS) $(LDIRS) $(OPT) $(MYLIBS) $(STATIC_LIBS) -o $@
```
```json
  "pgsql-server_side_cursors-t" : [ "legacy-g4","mysql-auto_increment_delay_multiplex=0-g4","mysql-multiplexing=false-g4","mysql-query_digests=0-g4","mysql-query_digests_keep_comment=1-g4" ],
```

- [ ] **Step 3: Build + run — expect PASS**

```bash
PROXYSQL31=1 make build_tap_test_debug
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-server_side_cursors-t" test/infra/control/run-tests-isolated.bash
```
Expected: 4/4. If portal suspension does not occur (rows != 2 or no `'s'`), that is a genuine multiplexing/portal finding — record per §2.1.

- [ ] **Step 4: Commit**

```bash
git add test/tap/tests/pgsql-server_side_cursors-t.cpp test/tap/tests/Makefile test/tap/groups/groups.json
git commit -m "test(pgsql): server-side cursors (DECLARE/FETCH/MOVE) + portal suspension"
```

---

## Task 6: Pool churn + session-state isolation

A connection storm exceeding `pgsql-max_connections`, plus the classic pooler-correctness check: session state set on one frontend connection must not leak to another via a reused backend.

**Files:**
- Create: `test/tap/tests/pgsql-pool_churn-t.cpp`
- Modify: `test/tap/groups/groups.json` (no Makefile rule needed — pure libpq)

**Interfaces:**
- Consumes: libpq; admin (MySQL client) to read pool counters / set `pgsql-max_connections` if needed.
- Produces: nothing downstream.

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/pgsql-pool_churn-t.cpp`:

```cpp
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr mk() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
       << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
       << " dbname=" << cl.pgsql_username << " sslmode=disable";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static std::string scalar(PGconn* c, const char* q) {
    PGresult* r = PQexec(c, q);
    std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) ? PQgetvalue(r, 0, 0) : "";
    PQclear(r);
    return v;
}

int main(int argc, char** argv) {
    if (cl.getEnv()) return exit_status();
    plan(3);

    // 1) Connection storm: open many short-lived connections; none should error out.
    bool all_ok = true;
    for (int i = 0; i < 100; ++i) {
        PGConnPtr c = mk();
        if (!c || PQstatus(c.get()) != CONNECTION_OK) { all_ok = false; break; }
        if (scalar(c.get(), "SELECT 1") != "1") { all_ok = false; break; }
    }
    ok(all_ok, "100 sequential short connections all succeed (no pool leak/exhaustion)");

    // 2) Session-state isolation across multiplexed reuse.
    // Connection A sets a session GUC; a fresh connection B must NOT observe it.
    {
        PGConnPtr a = mk();
        PQexec(a.get(), "SET application_name = 'churn_A'");
        std::string a_val = scalar(a.get(), "SHOW application_name");
        ok(a_val == "churn_A", "connection A sees its own SET application_name");

        PGConnPtr b = mk();
        std::string b_val = scalar(b.get(), "SHOW application_name");
        ok(b_val != "churn_A", "connection B does NOT inherit A's session state (got '%s')", b_val.c_str());
    }

    return exit_status();
}
```

- [ ] **Step 2: Register in groups.json (no Makefile change — pure libpq)**

```json
  "pgsql-pool_churn-t" : [ "legacy-g4","mysql-auto_increment_delay_multiplex=0-g4","mysql-multiplexing=false-g4","mysql-query_digests=0-g4","mysql-query_digests_keep_comment=1-g4" ],
```

- [ ] **Step 3: Build + run — expect PASS**

```bash
PROXYSQL31=1 make build_tap_test_debug
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-pool_churn-t" test/infra/control/run-tests-isolated.bash
```
Expected: 3/3. A state-leak (B inherits A) is a real correctness bug — do NOT relax the assertion; capture it. Note: under `multiplexing=false` group variants, reuse behaves differently — the isolation assertion must hold in all variants.

- [ ] **Step 4: Commit**

```bash
git add test/tap/tests/pgsql-pool_churn-t.cpp test/tap/groups/groups.json
git commit -m "test(pgsql): pool churn + session-state isolation across reuse"
```

---

## Task 7: LISTEN/NOTIFY per-mode contract

Pins the current contract: LISTEN is rejected with SQLSTATE `0A000` on the libpq backend path (both simple and extended protocol); NOTIFY-as-a-query completes cleanly and leaves the connection usable. The native-path portion is asserted xfail-tolerant per spec §2.2/§3.5.

**Files:**
- Create: `test/tap/tests/pgsql-listen_notify_contract-t.cpp`
- Modify: `test/tap/groups/groups.json` (pure libpq — no Makefile rule)

**Interfaces:**
- Consumes: libpq `PQexec`/`PQresultStatus`/`PQresultErrorField(PG_DIAG_SQLSTATE)`; admin (MySQL client) to toggle `pgsql-use_native_backend_protocol`.
- Produces: nothing downstream.

- [ ] **Step 1: Write the failing test**

Create `test/tap/tests/pgsql-listen_notify_contract-t.cpp`:

```cpp
#include <string>
#include <sstream>
#include <mysql.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr mk() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
       << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
       << " dbname=" << cl.pgsql_username << " sslmode=disable";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static std::string sqlstate_of(PGresult* r) {
    const char* s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
    return s ? s : "";
}

int main(int argc, char** argv) {
    if (cl.getEnv()) return exit_status();
    plan(4);

    PGConnPtr c = mk();
    ok(c && PQstatus(c.get()) == CONNECTION_OK, "connected for listen/notify contract");

    // LISTEN over simple protocol -> 0A000 feature_not_supported (libpq path).
    PGresult* r = PQexec(c.get(), "LISTEN chan1");
    ok(PQresultStatus(r) == PGRES_FATAL_ERROR && sqlstate_of(r) == "0A000",
       "simple LISTEN rejected with 0A000 (got status=%d sqlstate=%s)",
       PQresultStatus(r), sqlstate_of(r).c_str());
    PQclear(r);

    // LISTEN over extended protocol (PQexecParams uses Parse/Bind/Execute) -> same 0A000.
    r = PQexecParams(c.get(), "LISTEN chan2", 0, NULL, NULL, NULL, NULL, 0);
    ok(PQresultStatus(r) == PGRES_FATAL_ERROR && sqlstate_of(r) == "0A000",
       "extended LISTEN rejected with 0A000 (got sqlstate=%s)", sqlstate_of(r).c_str());
    PQclear(r);

    // NOTIFY as a plain query completes cleanly and the connection stays usable.
    PGConnPtr c2 = mk();
    PGresult* rn = PQexec(c2.get(), "NOTIFY chan1, 'hello'");
    bool notify_ok = (PQresultStatus(rn) == PGRES_COMMAND_OK);
    PQclear(rn);
    PGresult* rq = PQexec(c2.get(), "SELECT 1");
    bool still_usable = (PQresultStatus(rq) == PGRES_TUPLES_OK);
    PQclear(rq);
    ok(notify_ok && still_usable, "NOTIFY completes cleanly and connection remains usable");

    return exit_status();
}
```

- [ ] **Step 2: Register in groups.json**

```json
  "pgsql-listen_notify_contract-t" : [ "legacy-g4","mysql-auto_increment_delay_multiplex=0-g4","mysql-multiplexing=false-g4","mysql-query_digests=0-g4","mysql-query_digests_keep_comment=1-g4" ],
```

- [ ] **Step 3: Build + run — expect PASS on the libpq path**

```bash
PROXYSQL31=1 make build_tap_test_debug
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-listen_notify_contract-t" test/infra/control/run-tests-isolated.bash
```
Expected: 4/4 with the default (libpq) backend path. Do not add native-path (`pgsql-use_native_backend_protocol=on`) assertions here yet — per §3.5 the native NOTIFY contract is owned by PR #5882's `pgsql-native_notify-t`; a native-path branch is added only once that lands, marked xfail where incomplete.

- [ ] **Step 4: Commit**

```bash
git add test/tap/tests/pgsql-listen_notify_contract-t.cpp test/tap/groups/groups.json
git commit -m "test(pgsql): LISTEN 0A000 rejection + NOTIFY-as-query contract (libpq path)"
```

---

## Self-Review

**Spec coverage (SP-1 items → tasks):**
- Auth-method matrix → Tasks 1–3 ✓, **repositioned around PR #5865**: #5865 owns the storage-type × floor success/fail matrix + anti-enumeration + malformed-verifier (via libpq); this plan owns the **wire-level challenge-type** assertion + post-auth query (which libpq can't see), plus the reusable `pg_lite_client` MD5/SCRAM enabler. Optional no-downgrade wire assertion (Task 3 Step 7) is gated on #5865 merging.
- Data-type/binary matrix → Task 4 ✓ (text+binary, OID+value).
- Server-side cursors → Task 5 ✓ (DECLARE/FETCH/MOVE + portal suspend).
- Pool churn / session-isolation → Task 6 ✓.
- LISTEN/NOTIFY per-mode contract → Task 7 ✓ (libpq path pinned; native deferred to #5882 per §3.5).
- Backend-mode axis (§2.2): honored by keeping SP-1 on the default libpq path and explicitly deferring native-path assertions; cert-only frontend auth is left to the existing `pgsql-reg_test_5284_frontend_ssl_enforcement-t` (not duplicated here).

**Dependency / merge order:** Auth tasks (1–3) coordinate with **PR #5865** (open, base `v3.0`) — see the "Relationship to PR #5865" section. Develop on top of / rebase onto it to avoid `groups.json` conflicts; the enabler and wire-level test do not conflict semantically, only textually in `groups.json`.

**Placeholder scan:** No TBD/TODO. Three honest verification points are embedded as concrete observe-and-adjust steps (Task 3 Step 5 libscram framing; Task 3 Step 7 optional #5865-gated extension; Task 4 Step 2 `readResult` vs raw-parse) — each names the exact thing to check and the fallback, which is guidance, not a placeholder.

**Type consistency:** Helper names are stable across tasks (`set_frontend_auth_method`, `try_frontend_login(user, password, int&)`, `run_case`, `mk`, `scalar`, `sqlstate_of`). `pg_lite_client` additions (`getLastAuthType`, `sendMD5Password`, `doSASLAuth`) are declared in the header before use. Message constants (`ROW_DESCRIPTION`, `DATA_ROW`, `PORTAL_SUSPENDED`, `READY_FOR_QUERY`, `ERROR_RESPONSE`, `AUTH_TYPE`) match `pg_lite_client.h`.

**Open dependency for the implementer:** the auth-matrix test relies on `pgsql_users` containing `testuser` with password `testuser` and a matching database — already true in `docker-pgsql16-single`'s `config.sql` + `docker-pgsql-post.bash`. No infra change is required for SP-1 (frontend auth is a server variable, not a per-user backend setting).
