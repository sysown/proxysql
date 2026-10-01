# PostgreSQL Native Backend Protocol — Phase 0 + Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land a native PostgreSQL backend connection that performs TCP connect, optional TLS, and authentication (cleartext/trust, md5, SCRAM-SHA-256; channel binding `-PLUS` deferred — see Task 1.5), then idles correctly in the connection pool — all behind a runtime flag with libpq fallback, verified by a differential auth test against the libpq path.

**Architecture:** Approach A from the design spec (`docs/superpowers/specs/2026-06-11-pgsql-native-protocol-design.md`). A single `PgSQL_Connection` class dispatches each async handler (`connect_cont`, `query_cont`, `fetch_result_cont`) on a runtime `native_mode` flag. Native mode owns the fd through the existing backend-side `PgSQL_Data_Stream` and drives a new `PgSQL_Backend_Protocol` decoder + auth state machine. The outbound encoder reuses the existing `PG_pkt`/`PgSQL_Protocol` machinery. The libpq branch is untouched and serves as both fallback and differential-test oracle.

**Tech Stack:** C++17, GNU Make, libproxysql.a unit-test harness (`test/tap/tests/unit/`), TAP + Docker infra (`test/infra/`), vendored `libscram`, OpenSSL, libev.

**Phase boundary:** This plan covers Phase 0 (scaffolding) and Phase 1 (connect/auth/TLS) only. Phase 2 (simple query + result decoder) and Phase 3 (extended protocol + named portals) are separate plans written after this one lands and its differential tests are green.

---

## Build environment (this workspace)

- This working tree is standardized on the **`PROXYSQL40=1`** feature tier for this effort (per user decision). Build with `PROXYSQL40=1 make` and run unit tests with `PROXYSQL40=1 make -C test/tap/tests/unit <name>-t`. The native-protocol code is tier-agnostic (no `#ifdef` guards), so it compiles identically at any tier; standardizing avoids relink churn from a mixed-tier object tree.
- `pkg-config` lives at `/opt/homebrew/bin` and is not on the default shell PATH; prefix builds with `PATH=/opt/homebrew/bin:$PATH` if the top-level `make` aborts entering `deps`.
- Always use plain `make` (auto-detects a sane `-j`) — **never** a bare unbounded `make -j`.

## Pre-flight (read before Task 1)

Confirm these facts in the codebase before starting; they are the interfaces every later task binds to. None of these are changes — they are reads to orient the engineer.

- `include/PgSQL_Connection.h` — the async state machine: `PG_ASYNC_ST handler(short event)`, `connect_start()`, `connect_cont(short event)`, members `PGconn* pgsql_conn` (line ~624), `PgSQL_Data_Stream* myds` (line ~650), and the `get_pg_*()` accessor cluster (lines ~486–516) that wrap libpq and must gain native equivalents.
- `lib/PgSQL_Connection.cpp` — the libpq implementations of `connect_cont` (~1104), `connect_start`/`PQconnectStart` (~1080), and how `fd = PQsocket(pgsql_conn)` is registered with the event loop (~275, ~1100). This is the exact code path native mode mirrors.
- `lib/PgSQL_Thread.cpp` — pgsql runtime variable registration: the variables table around line 422 (`server_version`), `get_variable`/`set_variable` (~1430, ~1638), and defaults init (~1118). New flag is added here.
- `include/PgSQL_Protocol.h` — the `PG_pkt` encoder and `write_StartupMessage` (~230), `write_PasswordMessage` (~233). Outbound encoding reuses these.
- `include/PgSQL_Data_Stream.h` — backend data stream: how `myds` is constructed, its inbound/outbound buffer accessors, and how the client side reads framed bytes. The native decoder consumes from the same buffer API.
- `test/tap/tests/unit/` + `doc/agents/project-conventions.md` — the `test_globals.h` / `test_init.h` unit harness pattern. All pure-component tests below use it.
- `deps/libscram/` — the vendored SCRAM library headers; confirm the client-side API (mechanism init, client-first message, server-first parse, client-final with proof, server-final verify).

---

## File Structure

**Create:**
- `include/PgSQL_Backend_Protocol.h` — backend decoder + auth driver class interface.
- `lib/PgSQL_Backend_Protocol.cpp` — implementation: message framer, auth sub-state-machine, ParameterStatus/BackendKeyData/ReadyForQuery handling.
- `lib/PgSQL_Backend_Auth.cpp` — auth response builders (cleartext, md5, SCRAM glue over libscram). Split from the protocol file because auth is self-contained, pure, and heavily unit-tested; keeping it separate keeps each file focused.
- `test/tap/tests/unit/pgsql_backend_framing-t.cpp` — unit tests for the message framer.
- `test/tap/tests/unit/pgsql_backend_auth-t.cpp` — unit tests for md5 + SCRAM builders against known vectors.
- `test/tap/tests/pgsql-native_auth_differential-t.cpp` — TAP differential auth test (native vs libpq).

**Modify:**
- `lib/PgSQL_Thread.cpp` — register `use_native_backend_protocol` variable.
- `include/PgSQL_Thread.h` — add the variable to the pgsql variables struct.
- `include/PgSQL_Connection.h` — add `native_mode` member, `PgSQL_Backend_Protocol* bp` member, native accessor declarations.
- `lib/PgSQL_Connection.cpp` — `native_mode` init, `if (native_mode)` dispatch in `connect_cont`/`query_cont`/`fetch_result_cont`, native connect state machine.
- `lib/Makefile` / `lib/Makefile`'s object list — add the two new `.cpp` files (confirm how `lib/` globs sources; if it auto-globs `*.cpp`, no edit needed).
- `test/tap/tests/unit/Makefile` — register the two unit test binaries if not covered by the pattern rule.
- `test/tap/groups/groups.json` — register the differential test in a `pgsql*` group.

---

# Phase 0 — Scaffolding

Lands inert: the flag exists, native mode is selectable, and the dispatch skeleton falls back to libpq with a one-time log. No behavior change at default settings.

### Task 0.1: Add the `use_native_backend_protocol` runtime variable

**Files:**
- Modify: `include/PgSQL_Thread.h` (pgsql variables struct)
- Modify: `lib/PgSQL_Thread.cpp` (variables table ~422, defaults ~1118, get/set ~1430/~1638)

- [ ] **Step 1: Add the struct member**

In `include/PgSQL_Thread.h`, in the same `variables` struct that holds `threshold_query_length` and `server_version`, add:

```cpp
bool use_native_backend_protocol;
```

- [ ] **Step 2: Register the variable name in the table**

In `lib/PgSQL_Thread.cpp`, in the variables name table near line 422 (where `"server_version"` is listed), add an entry following the exact surrounding style:

```cpp
(char*)"use_native_backend_protocol",
```

- [ ] **Step 3: Set the default**

In the defaults init block near line 1118 (where `variables.threshold_query_length = 512 * 1024;`), add:

```cpp
variables.use_native_backend_protocol = false;
```

- [ ] **Step 4: Wire get_variable / set_variable**

In `get_variable` (~1430) and the second accessor (~1547), follow the existing bool-variable pattern in this file (search for an existing `bool` pgsql variable such as one returning `"true"`/`"false"`) and add the matching `if (!strcasecmp(name, "use_native_backend_protocol")) ...` branches for both get paths and the `set_variable` path (~1638). Use the same bool parse/format helper the neighboring bool variables use — do not invent a new one.

- [ ] **Step 5: Build**

Run: `make` (plain `make` auto-detects a sane `-j` from nproc/hw.ncpu per CLAUDE.md — never use a bare unbounded `make -j`)
Expected: clean compile of `lib/PgSQL_Thread.cpp`.

- [ ] **Step 6: Manual round-trip check**

Start proxysql, then via the pgsql admin interface:
```
SET pgsql-use_native_backend_protocol='true';
LOAD PGSQL VARIABLES TO RUNTIME;
SELECT * FROM runtime_global_variables WHERE variable_name='pgsql-use_native_backend_protocol';
```
Expected: value `true`. Reset to `false` after.

- [ ] **Step 7: Commit**

```bash
git add include/PgSQL_Thread.h lib/PgSQL_Thread.cpp
git commit -m "feat(pgsql): add pgsql-use_native_backend_protocol runtime variable (default off)"
```

### Task 0.2: Add native_mode selection to PgSQL_Connection

**Files:**
- Modify: `include/PgSQL_Connection.h`
- Modify: `lib/PgSQL_Connection.cpp` (connection init)

- [ ] **Step 1: Add members**

In `include/PgSQL_Connection.h`, near the existing `PGconn* pgsql_conn;` (~624) and `PgSQL_Data_Stream* myds;` (~650), add:

```cpp
bool native_mode = false;          // true → native wire protocol, false → libpq
class PgSQL_Backend_Protocol* bp = NULL;  // owned in native mode only; NULL in libpq mode
```

Add a forward declaration `class PgSQL_Backend_Protocol;` near the top of the header with the other forward declarations.

- [ ] **Step 2: Initialize native_mode at connection creation**

In `lib/PgSQL_Connection.cpp`, in the constructor / init path that runs before `connect_start`, set the mode from the thread variable. Mirror how other per-connection settings read `pgsql_thread___*` globals (grep `pgsql_thread___` in this file for the pattern):

```cpp
native_mode = pgsql_thread___use_native_backend_protocol;
```

If a `pgsql_thread___use_native_backend_protocol` accessor global does not yet exist, add it alongside the other `pgsql_thread___*` definitions (grep `pgsql_thread___threshold_query_length` to find where these are declared/defined and replicate exactly for the new bool).

- [ ] **Step 3: Build**

Run: `make`
Expected: clean compile; `native_mode` defaults false, no behavior change.

- [ ] **Step 4: Commit**

```bash
git add include/PgSQL_Connection.h lib/PgSQL_Connection.cpp
git commit -m "feat(pgsql): add native_mode + backend protocol member to PgSQL_Connection"
```

### Task 0.3: Add fallback dispatch skeleton

**Files:**
- Modify: `lib/PgSQL_Connection.cpp` (`connect_cont`, `query_cont`, `fetch_result_cont`)

- [ ] **Step 1: Add native branch that falls back**

At the top of `connect_cont` (~1104), `query_cont` (~1187), and `fetch_result_cont` (~1202), add:

```cpp
if (native_mode) {
    // Phase 0: native path not implemented yet → log once, disable, fall back to libpq.
    static thread_local bool warned = false;
    if (!warned) {
        proxy_warning("native_mode requested but unimplemented at this stage; falling back to libpq for hg %u %s:%d\n",
            parent->myhgc->hid, parent->address, parent->port);
        warned = true;
    }
    native_mode = false;
    // fall through to existing libpq path below
}
```

Confirm `parent->myhgc->hid`, `parent->address`, `parent->port` are the correct field accesses by matching the existing `proxy_error` call already in `connect_cont` (~340) which uses exactly these.

- [ ] **Step 2: Build and smoke test**

Run: `make`
Then start proxysql with `pgsql-use_native_backend_protocol='true'`, connect a psql client, run `SELECT 1;`.
Expected: works (fell back to libpq), and the proxysql log shows the one-time native fallback warning.

- [ ] **Step 3: Commit**

```bash
git add lib/PgSQL_Connection.cpp
git commit -m "feat(pgsql): native_mode dispatch skeleton with libpq fallback (Phase 0 inert)"
```

---

# Phase 1 — Connect, Auth, TLS

Builds the native connect path. Pure components (framer, auth builders) are TDD'd against `libproxysql.a`; the I/O state machine is integration-tested by the Task 1.8 differential harness.

### Task 1.1: Backend message framer (pure)

The framer takes a byte buffer and yields complete backend messages `{ type:char, payload_ptr, payload_len }`, signaling "need more bytes" on a partial trailing message. Backend message format: 1 byte type, 4-byte big-endian length (length includes itself but not the type byte), then `length-4` payload bytes.

**Files:**
- Create: `include/PgSQL_Backend_Protocol.h`
- Create: `lib/PgSQL_Backend_Protocol.cpp`
- Create: `test/tap/tests/unit/pgsql_backend_framing-t.cpp`

- [ ] **Step 1: Write the failing test**

`test/tap/tests/unit/pgsql_backend_framing-t.cpp` (follow the `test_globals.h`/`test_init.h` harness pattern from a sibling unit test):

```cpp
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include "tap.h"

// Build one backend message into buf, return total bytes written.
static size_t put_msg(unsigned char* buf, char type, const char* payload, uint32_t plen) {
    buf[0] = (unsigned char)type;
    uint32_t len = plen + 4;               // length field includes itself, excludes type byte
    buf[1] = (len >> 24) & 0xff; buf[2] = (len >> 16) & 0xff;
    buf[3] = (len >> 8) & 0xff;  buf[4] = len & 0xff;
    memcpy(buf + 5, payload, plen);
    return 5 + plen;
}

int main(int, char**) {
    plan(6);
    PgSQL_Backend_Msg_Framer f;
    unsigned char buf[64];

    // One complete message frames cleanly.
    size_t n = put_msg(buf, 'Z', "I", 1);  // ReadyForQuery, txn state 'I'
    f.feed(buf, n);
    PgSQL_Backend_Msg m;
    ok(f.next(m) == FRAME_OK, "complete message framed");
    ok(m.type == 'Z', "type is Z");
    ok(m.payload_len == 1 && m.payload[0] == 'I', "payload correct");
    ok(f.next(m) == FRAME_NEED_MORE, "buffer drained → need more");

    // Partial header is held until completed.
    PgSQL_Backend_Msg_Framer f2;
    f2.feed(buf, 3);                        // only 3 of 6 bytes
    ok(f2.next(m) == FRAME_NEED_MORE, "partial message → need more");
    f2.feed(buf + 3, n - 3);                // rest arrives
    ok(f2.next(m) == FRAME_OK && m.type == 'Z', "completes after remaining bytes");

    return exit_status();
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `make -C test/tap/tests/unit pgsql_backend_framing-t`
Expected: FAIL to compile — `PgSQL_Backend_Msg_Framer` undefined.

- [ ] **Step 3: Implement the framer**

In `include/PgSQL_Backend_Protocol.h`:

```cpp
#ifndef __CLASS_PGSQL_BACKEND_PROTOCOL_H
#define __CLASS_PGSQL_BACKEND_PROTOCOL_H
#include <cstdint>
#include <cstddef>

enum PgSQL_Frame_Result { FRAME_OK, FRAME_NEED_MORE, FRAME_ERROR };

struct PgSQL_Backend_Msg {
    char type;
    const unsigned char* payload;   // points into the framer's fed buffer
    uint32_t payload_len;
};

// Frames raw backend bytes into messages. Caller feeds bytes (possibly partial);
// next() returns FRAME_OK with a message view, FRAME_NEED_MORE when the trailing
// bytes are an incomplete message, or FRAME_ERROR on a malformed length.
class PgSQL_Backend_Msg_Framer {
    public:
    void feed(const unsigned char* data, size_t len);
    PgSQL_Frame_Result next(PgSQL_Backend_Msg& out);
    void reset();
    private:
    unsigned char* buf = nullptr;
    size_t len = 0, cap = 0, pos = 0;
    void compact();
};
#endif
```

In `lib/PgSQL_Backend_Protocol.cpp`:

```cpp
#include "PgSQL_Backend_Protocol.h"
#include <cstdlib>
#include <cstring>

static inline uint32_t be32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

void PgSQL_Backend_Msg_Framer::feed(const unsigned char* data, size_t n) {
    if (len + n > cap) {
        size_t ncap = cap ? cap : 4096;
        while (ncap < len + n) ncap *= 2;
        buf = (unsigned char*)realloc(buf, ncap);
        cap = ncap;
    }
    memcpy(buf + len, data, n);
    len += n;
}

PgSQL_Frame_Result PgSQL_Backend_Msg_Framer::next(PgSQL_Backend_Msg& out) {
    if (len - pos < 5) return FRAME_NEED_MORE;          // need type + length
    uint32_t msglen = be32(buf + pos + 1);
    if (msglen < 4) return FRAME_ERROR;                 // length includes its own 4 bytes
    size_t total = 1 + msglen;                          // type byte + length-prefixed body
    if (len - pos < total) return FRAME_NEED_MORE;
    out.type = (char)buf[pos];
    out.payload = buf + pos + 5;
    out.payload_len = msglen - 4;
    pos += total;
    if (pos == len) { pos = 0; len = 0; }               // fully drained → cheap reset
    return FRAME_OK;
}

void PgSQL_Backend_Msg_Framer::reset() { pos = 0; len = 0; }
```

(`compact()` is declared for a later refinement that shifts unconsumed bytes to the front when `pos>0` and the buffer fills; for Phase 1, the drain-reset in `next()` plus realloc growth is sufficient. Leave the declaration; implement as a no-op body to keep the symbol resolved, or remove the declaration — engineer's choice, no functional difference yet.)

- [ ] **Step 4: Run to verify it passes**

Run: `make -C test/tap/tests/unit pgsql_backend_framing-t && ./test/tap/tests/unit/pgsql_backend_framing-t`
Expected: `1..6` all `ok`.

- [ ] **Step 5: Commit**

```bash
git add include/PgSQL_Backend_Protocol.h lib/PgSQL_Backend_Protocol.cpp test/tap/tests/unit/pgsql_backend_framing-t.cpp
git commit -m "feat(pgsql): native backend message framer with partial-message handling + unit tests"
```

### Task 1.2: Startup and SSLRequest encoding (pure)

Reuse the existing `PG_pkt`/`write_StartupMessage` encoder; add a thin helper that produces the exact bytes for the startup and SSLRequest packets so they can be asserted in a unit test.

**Files:**
- Modify: `lib/PgSQL_Backend_Auth.cpp` (create)
- Modify: `include/PgSQL_Backend_Protocol.h`
- Modify: `test/tap/tests/unit/pgsql_backend_auth-t.cpp` (create)

- [ ] **Step 1: Write the failing test**

`test/tap/tests/unit/pgsql_backend_auth-t.cpp`:

```cpp
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include "tap.h"

int main(int, char**) {
    plan(2);

    // SSLRequest is a fixed 8 bytes: length=8, code=80877103 (0x04d2162f).
    unsigned char ssl[8];
    pg_build_ssl_request(ssl);
    unsigned char expect_ssl[8] = {0x00,0x00,0x00,0x08, 0x04,0xd2,0x16,0x2f};
    ok(memcmp(ssl, expect_ssl, 8) == 0, "SSLRequest bytes exact");

    // Startup message: int32 length, int32 protocol 196608 (3.0), then key\0value\0... \0.
    unsigned char sm[256]; size_t smlen = 0;
    pg_build_startup(sm, &smlen, "alice", "shop");
    // protocol version at offset 4 must be 0x00030000
    ok(sm[4]==0x00 && sm[5]==0x03 && sm[6]==0x00 && sm[7]==0x00, "startup protocol 3.0");

    return exit_status();
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `make -C test/tap/tests/unit pgsql_backend_auth-t`
Expected: FAIL — `pg_build_ssl_request` / `pg_build_startup` undefined.

- [ ] **Step 3: Implement**

Declare in `include/PgSQL_Backend_Protocol.h`:

```cpp
void pg_build_ssl_request(unsigned char out[8]);
void pg_build_startup(unsigned char* out, size_t* out_len, const char* user, const char* database);
```

Implement in `lib/PgSQL_Backend_Auth.cpp`. Prefer delegating to the existing `PG_pkt::write_StartupMessage` if its output is directly capturable; otherwise write the bytes directly per the protocol (both are acceptable — the unit test pins correctness either way):

```cpp
#include "PgSQL_Backend_Protocol.h"
#include <cstring>

static void put_be32(unsigned char* p, uint32_t v) {
    p[0]=(v>>24)&0xff; p[1]=(v>>16)&0xff; p[2]=(v>>8)&0xff; p[3]=v&0xff;
}

void pg_build_ssl_request(unsigned char out[8]) {
    put_be32(out, 8);
    put_be32(out + 4, 80877103u);   // 0x04d2162f
}

void pg_build_startup(unsigned char* out, size_t* out_len, const char* user, const char* database) {
    size_t off = 8;                 // reserve length(4) + protocol(4)
    auto add = [&](const char* s){ size_t l = strlen(s) + 1; memcpy(out + off, s, l); off += l; };
    add("user"); add(user);
    add("database"); add(database);
    out[off++] = 0;                 // terminating empty key
    put_be32(out, (uint32_t)off);   // total length
    put_be32(out + 4, 196608u);     // protocol 3.0 = 0x00030000
    *out_len = off;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `make -C test/tap/tests/unit pgsql_backend_auth-t && ./test/tap/tests/unit/pgsql_backend_auth-t`
Expected: `1..2` all `ok`.

- [ ] **Step 5: Commit**

```bash
git add include/PgSQL_Backend_Protocol.h lib/PgSQL_Backend_Auth.cpp test/tap/tests/unit/pgsql_backend_auth-t.cpp
git commit -m "feat(pgsql): native startup + SSLRequest encoders with unit tests"
```

### Task 1.3: md5 password auth (pure)

Postgres md5: `"md5" + md5_hex( md5_hex(password + username) + salt )`, where salt is the 4 bytes from `AuthenticationMD5Password`.

**Files:**
- Modify: `lib/PgSQL_Backend_Auth.cpp`
- Modify: `include/PgSQL_Backend_Protocol.h`
- Modify: `test/tap/tests/unit/pgsql_backend_auth-t.cpp` (extend)

- [ ] **Step 1: Extend the test (raise plan, add assertion)**

Change `plan(2)` to `plan(3)` and add a known-vector check. Vector: user `postgres`, password `postgres`, salt `{0x01,0x02,0x03,0x04}`. Compute the expected once with a reference (e.g. a one-off Python `hashlib` snippet) and paste the literal hex:

```cpp
    char md5buf[36];
    unsigned char salt[4] = {0x01,0x02,0x03,0x04};
    pg_build_md5(md5buf, "postgres", "postgres", salt);
    // Expected computed via reference impl and pinned here:
    ok(strncmp(md5buf, "md5", 3) == 0 && strlen(md5buf) == 35, "md5 response shape correct");
    // NOTE: replace the line above with an exact-string compare once the reference
    // hex is computed: ok(strcmp(md5buf, "md5<32 hex chars>") == 0, "md5 exact");
```

(Compute the exact 32-hex digest with the reference impl during implementation and pin the full-string compare — do not ship the shape-only assertion.)

- [ ] **Step 2: Run to verify it fails**

Run: `make -C test/tap/tests/unit pgsql_backend_auth-t`
Expected: FAIL — `pg_build_md5` undefined.

- [ ] **Step 3: Implement using the project's existing MD5**

Find the MD5 helper already in the tree (grep `MD5_Init\|proxy_md5\|MD5(` in `lib/` and `deps/`; ProxySQL already hashes for MySQL auth). Reuse it — do not add a new MD5 dependency.

```cpp
#include "PgSQL_Backend_Protocol.h"
// include the project's md5 header found via grep

static void md5_hex(const unsigned char* in, size_t inlen, char out_hex[33]) {
    unsigned char digest[16];
    // call the project MD5 over (in, inlen) → digest
    static const char* h = "0123456789abcdef";
    for (int i = 0; i < 16; i++) { out_hex[i*2]=h[digest[i]>>4]; out_hex[i*2+1]=h[digest[i]&0xf]; }
    out_hex[32] = 0;
}

void pg_build_md5(char out[36], const char* user, const char* password, const unsigned char salt[4]) {
    char inner[33];
    {   // md5(password + user)
        size_t l = strlen(password) + strlen(user);
        unsigned char* tmp = (unsigned char*)alloca(l);
        memcpy(tmp, password, strlen(password));
        memcpy(tmp + strlen(password), user, strlen(user));
        md5_hex(tmp, l, inner);
    }
    char outer[33];
    {   // md5(inner_hex + salt)
        unsigned char tmp[36];
        memcpy(tmp, inner, 32);
        memcpy(tmp + 32, salt, 4);
        md5_hex(tmp, 36, outer);
    }
    memcpy(out, "md5", 3);
    memcpy(out + 3, outer, 33);     // includes NUL
}
```

Declare `void pg_build_md5(char out[36], const char* user, const char* password, const unsigned char salt[4]);` in the header.

- [ ] **Step 4: Run to verify it passes**

Run: `make -C test/tap/tests/unit pgsql_backend_auth-t && ./test/tap/tests/unit/pgsql_backend_auth-t`
Expected: `1..3` all `ok` (with the exact-hex compare pinned).

- [ ] **Step 5: Commit**

```bash
git add include/PgSQL_Backend_Protocol.h lib/PgSQL_Backend_Auth.cpp test/tap/tests/unit/pgsql_backend_auth-t.cpp
git commit -m "feat(pgsql): native md5 password auth builder with known-vector unit test"
```

### Task 1.4: SCRAM-SHA-256 exchange over libscram (pure)

Wrap vendored `libscram` into four steps: client-first (`SASLInitialResponse` payload), parse server-first (`AuthenticationSASLContinue`), client-final with proof (`SASLResponse`), verify server-final (`AuthenticationSASLFinal`). This task is plain SCRAM-SHA-256 (no channel binding; `gs2-cbind-flag = "n"`).

**Files:**
- Modify: `lib/PgSQL_Backend_Auth.cpp`
- Modify: `include/PgSQL_Backend_Protocol.h`
- Modify: `test/tap/tests/unit/pgsql_backend_auth-t.cpp` (extend)

- [ ] **Step 1: Confirm the libscram client API**

Read `deps/libscram/` headers. Identify the client-side entry points (mechanism context alloc, client-first-message build, server-first parse + salted-password derivation, client-final + client-proof, server-signature verify). Note exact function names — the implementation below uses placeholder names `scram_client_*` that must be replaced with the real ones.

- [ ] **Step 2: Write the failing test (RFC 7677 / RFC 5802 test vector)**

Use the published SCRAM-SHA-256 example (RFC 7677 §5): user `user`, password `pencil`, client nonce `rOprNGfwEbeRWgbNEkqO`, server-first `r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`. Expected client-final: `c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndM=`. Add to the test (raise plan to 5):

```cpp
    PgSQL_Scram_State scram;
    char first[256]; size_t firstlen;
    pg_scram_client_first(&scram, "user", "rOprNGfwEbeRWgbNEkqO", first, &firstlen, /*channel_binding=*/false, nullptr, 0);
    ok(strstr(first, "n=user") && strstr(first, "r=rOprNGfwEbeRWgbNEkqO"), "client-first contains user+nonce");

    const char* server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    char finalmsg[512]; size_t finallen;
    int rc = pg_scram_client_final(&scram, "pencil", server_first, strlen(server_first), finalmsg, &finallen);
    ok(rc == 0, "client-final computed");
    ok(strstr(finalmsg, "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndM=") != nullptr, "client proof matches RFC 7677 vector");
```

- [ ] **Step 3: Run to verify it fails**

Run: `make -C test/tap/tests/unit pgsql_backend_auth-t`
Expected: FAIL — SCRAM symbols undefined.

- [ ] **Step 4: Implement the SCRAM glue**

Add `struct PgSQL_Scram_State` to the header (holding the libscram context, client nonce, and the cached `auth_message` needed to verify the server signature). Implement `pg_scram_client_first`, `pg_scram_client_final`, and `pg_scram_verify_server_final` in `lib/PgSQL_Backend_Auth.cpp`, delegating the crypto to libscram (the real `scram_client_*` names from Step 1). The functions only build/parse the SASL message bodies — the SASL wrapper messages (`SASLInitialResponse` with mechanism name + length, `SASLResponse`) are added by the connect state machine in Task 1.6.

```cpp
struct PgSQL_Scram_State {
    // libscram context handle(s) per the real API
    char client_nonce[64];
    char* auth_message = nullptr;   // saved for server-signature verification; free in dtor
    // ... fields the libscram API requires
};

int pg_scram_client_first(PgSQL_Scram_State* s, const char* user, const char* client_nonce,
                          char* out, size_t* out_len, bool channel_binding,
                          const unsigned char* cbind_data, size_t cbind_len);
int pg_scram_client_final(PgSQL_Scram_State* s, const char* password,
                          const char* server_first, size_t server_first_len,
                          char* out, size_t* out_len);
int pg_scram_verify_server_final(PgSQL_Scram_State* s, const char* server_final, size_t len);
```

- [ ] **Step 5: Run to verify it passes**

Run: `make -C test/tap/tests/unit pgsql_backend_auth-t && ./test/tap/tests/unit/pgsql_backend_auth-t`
Expected: `1..5` all `ok`, including the RFC 7677 proof match.

- [ ] **Step 6: Commit**

```bash
git add include/PgSQL_Backend_Protocol.h lib/PgSQL_Backend_Auth.cpp test/tap/tests/unit/pgsql_backend_auth-t.cpp
git commit -m "feat(pgsql): native SCRAM-SHA-256 client exchange over libscram, RFC 7677 vector test"
```

### Task 1.5: SCRAM channel binding (-PLUS) (pure) — **DEFERRED (out of this plan's scope, per user decision 2026-06-11)**

> **Status: deferred to a follow-up phase (Phase 1b).** The vendored `libscram`
> (pgbouncer-derived) has no client channel-binding support — `build_client_final_message`
> hardcodes `c=biws` (`deps/libscram/src/scram.c:535`) and only handles cbind flags `n`/`y`.
> Implementing `-PLUS` therefore requires either patching vendored libscram or adding a
> custom cbind layer, which the user chose to defer. v1 ships `trust`/`md5`/plain
> `SCRAM-SHA-256`. A server that offers **only** `SCRAM-SHA-256-PLUS` is a capability gap →
> libpq fallback (handled in Task 1.6's mechanism selection). The original Task 1.5 steps
> below are retained for the follow-up phase but are NOT executed now.

Channel binding adds `gs2-cbind-flag = "p=tls-server-end-point"` and binds `cbind-input = gs2-header || tls-server-end-point-hash`. The hash is the server certificate's signature-hash digest (per RFC 5929 `tls-server-end-point`).

**Files:**
- Modify: `lib/PgSQL_Backend_Auth.cpp`
- Modify: `test/tap/tests/unit/pgsql_backend_auth-t.cpp` (extend)

- [ ] **Step 1: Implement tls-server-end-point digest helper**

Add `int pg_tls_server_end_point(SSL* ssl, unsigned char* out, size_t* out_len);` computing the digest of the peer cert using the cert's own signature hash algorithm (upgrading MD5/SHA-1 to SHA-256 per RFC 5929). Use the OpenSSL `X509_get0_signature` / `X509_get_signature_info` + `X509_digest` path. This binds to the SSL object the connect path already owns.

- [ ] **Step 2: Write the failing test**

Channel binding is awkward to unit-test without a live TLS cert, so assert the *composition*: given a fixed `cbind_data` blob, `pg_scram_client_first(..., channel_binding=true, cbind_data, cbind_len)` must emit `gs2-cbind-flag` `p=tls-server-end-point` and the client-final `c=` field must be the base64 of `gs2-header || cbind_data`. Raise plan to 6 and add:

```cpp
    PgSQL_Scram_State sc2;
    unsigned char cb[4] = {0xde,0xad,0xbe,0xef};
    char cf[256]; size_t cfl;
    pg_scram_client_first(&sc2, "user", "rOprNGfwEbeRWgbNEkqO", cf, &cfl, /*channel_binding=*/true, cb, sizeof(cb));
    ok(strstr(cf, "p=tls-server-end-point") != nullptr, "client-first advertises tls-server-end-point cbind");
```

- [ ] **Step 3: Run to verify it fails, then implement, then verify it passes**

Run: `make -C test/tap/tests/unit pgsql_backend_auth-t && ./test/tap/tests/unit/pgsql_backend_auth-t`
Expected after implementation: `1..6` all `ok`.

The full `c=` base64 binding correctness is additionally covered end-to-end by the Task 1.8 differential test against a real `scram-sha-256` + TLS backend, which is where channel binding is exercised against a live server.

- [ ] **Step 4: Commit**

```bash
git add lib/PgSQL_Backend_Auth.cpp test/tap/tests/unit/pgsql_backend_auth-t.cpp
git commit -m "feat(pgsql): SCRAM channel binding (tls-server-end-point) for SCRAM-SHA-256-PLUS"
```

### Task 1.6: Native connect/auth state machine in connect_cont

Wire the pure components into the async path: own the fd via `myds`, do TLS, send startup, run the auth dispatch, consume post-auth messages to `ReadyForQuery`, enter the pool. This is integration code; it is validated by Task 1.8.

**Files:**
- Modify: `include/PgSQL_Connection.h` (native accessors, new async sub-states if needed)
- Modify: `lib/PgSQL_Connection.cpp` (`connect_cont` native branch, native `get_pg_*` equivalents)
- Modify: `lib/PgSQL_Backend_Protocol.cpp` (post-auth message handling)

- [ ] **Step 1: Replace the Phase-0 fallback in connect_cont with the real native branch**

Structure the native branch as its own sub-state-machine. Mirror the libpq `connect_cont` (~1104) for event-loop registration and error handling. Pseudocode skeleton (bind buffer ops to the real `PgSQL_Data_Stream` API confirmed in pre-flight):

```cpp
if (native_mode) {
    switch (native_st) {
      case PG_NATIVE_TCP_CONNECTING:
        // non-blocking connect() completion check on myds->fd; on success →
        if (tls_required) { send SSLRequest via myds outbound; native_st = PG_NATIVE_SSL_REPLY; }
        else { send startup via pg_build_startup; native_st = PG_NATIVE_AUTH; }
        break;
      case PG_NATIVE_SSL_REPLY:
        // read 1 byte 'S'/'N'; on 'S' run existing backend OpenSSL handshake on myds,
        //   then send startup; on 'N' honor sslmode → error or continue cleartext.
        break;
      case PG_NATIVE_AUTH:
        // frame messages via bp; on 'R' dispatch by subtype (Task 1.2–1.5 builders);
        // on 'E' → auth error; on AuthenticationOk → native_st = PG_NATIVE_STARTUP_TAIL.
        break;
      case PG_NATIVE_STARTUP_TAIL:
        // consume 'S' ParameterStatus → cached map; 'K' BackendKeyData → store;
        // 'Z' ReadyForQuery → record txn state, connection ready, return to pool.
        break;
    }
    return; // do not fall through to libpq
}
```

Add `PG_NATIVE_*` to a `native_st` enum member on the connection. Capability gap (GSSAPI/SSPI `R` subtype 7/8/9, or unimplemented combo): tear down, set `native_mode=false`, retry via libpq `connect_start`, log once per backend.

- [ ] **Step 2: Implement native get_pg_* equivalents**

The accessors at `include/PgSQL_Connection.h:486–516` currently call libpq. Add native-aware versions for the ones used after connect: `get_pg_server_version` (from cached `ParameterStatus["server_version"]`), `get_pg_parameter_status` (cached map lookup), `get_pg_backend_pid` (from `BackendKeyData`), `get_pg_transaction_status` (last `ReadyForQuery` byte), `get_pg_ssl_in_use` (myds TLS state), `get_pg_error_message` (native error buffer). Pattern:

```cpp
inline int get_pg_server_version() {
    if (native_mode) return native_server_version;  // parsed from ParameterStatus
    return PQserverVersion(pgsql_conn);
}
```

- [ ] **Step 3: Implement post-auth message handlers in PgSQL_Backend_Protocol.cpp**

Add methods to parse `ParameterStatus` (two C-strings: name, value), `BackendKeyData` (int32 pid, int32 key), `ReadyForQuery` (1 byte), and `ErrorResponse` (delegate to the existing `PgSQL_Error_Helper` field walker — reuse, do not reimplement). These populate the connection's native fields.

- [ ] **Step 4: Build**

Run: `make`
Expected: clean compile. (Behavioral verification is Task 1.8 — there is no cheap unit test for live socket I/O; that is deliberately covered by the differential harness.)

- [ ] **Step 5: Commit**

```bash
git add include/PgSQL_Connection.h lib/PgSQL_Connection.cpp lib/PgSQL_Backend_Protocol.cpp
git commit -m "feat(pgsql): native connect/TLS/auth state machine + post-auth message handling"
```

### Task 1.7: Make the new sources build into libproxysql.a and the unit harness

**Files:**
- Modify: `lib/Makefile` (only if it does not auto-glob `*.cpp`)
- Modify: `test/tap/tests/unit/Makefile` (only if the pattern rule doesn't cover the new tests)

- [ ] **Step 1: Confirm lib build inclusion**

Run: `grep -n "wildcard\|\.cpp" lib/Makefile | head`
If `lib/` compiles via `$(wildcard *.cpp)`, the two new files are already included — no edit. Otherwise add `PgSQL_Backend_Protocol.o` and `PgSQL_Backend_Auth.o` to the object list exactly as neighboring objects are listed.

- [ ] **Step 2: Confirm unit-test inclusion**

Per CLAUDE.md, `test/tap/tests/unit/` (and `test/tap/tests/`) build via a pattern rule `<name>-t` from `<name>-t.cpp`. Verify both new `-t` binaries build:

Run: `make -C test/tap/tests/unit pgsql_backend_framing-t pgsql_backend_auth-t`
Expected: both link against `libproxysql.a` and run green.

- [ ] **Step 3: Commit (if any Makefile changed)**

```bash
git add lib/Makefile test/tap/tests/unit/Makefile
git commit -m "build(pgsql): include native backend protocol sources + unit tests"
```

### Task 1.8: Differential auth test (native vs libpq)

End-to-end proof: for each auth method and TLS setting, a connection through native mode reaches `ReadyForQuery` and runs a trivial query identically to the libpq path. This is the Phase 1 correctness gate.

**Files:**
- Create: `test/tap/tests/pgsql-native_auth_differential-t.cpp`
- Modify: `test/tap/groups/groups.json`

- [ ] **Step 1: Write the test**

Follow an existing `pgsql*` TAP test in `test/tap/tests/` for the connect/config boilerplate (admin connection, setting `pgsql-*` variables, connecting through ProxySQL). The test, for each scenario in {`trust`, `md5`, `scram-sha-256`, `scram-sha-256` over **TLS without channel binding** (the client selects plain `SCRAM-SHA-256` even if the server also offers `-PLUS`)}. (Channel binding `-PLUS` is deferred — see Task 1.5; a separate scenario where the server requires `-PLUS` and the native path must fall back to libpq can be added when convenient.)

```cpp
// Pseudocode of the assertion structure — fill with the project's PgSQL TAP helpers.
for (auto& method : {"trust","md5","scram-sha-256","scram-sha-256-tls"}) {
    // 1. Configure a backend hostgroup whose server enforces `method`.
    // 2. SET pgsql-use_native_backend_protocol='false'; LOAD PGSQL VARIABLES TO RUNTIME;
    //    open a client conn, run "SELECT 1;", capture rows + status. (libpq oracle)
    // 3. SET pgsql-use_native_backend_protocol='true';  LOAD PGSQL VARIABLES TO RUNTIME;
    //    new client conn (forces a fresh backend conn), run "SELECT 1;", capture. (native)
    // 4. ok(native_result == libpq_result, "auth method %s: native matches libpq", method);
    // 5. ok(no native-fallback warning appeared in proxysql log for this method,
    //       "method %s used native path, did not fall back", method);
}
```

Assertion 5 is essential: it proves the native path actually ran rather than silently falling back to libpq. Scrape the proxysql log produced by the run for the Task 0.3 fallback warning string and require its absence per method.

- [ ] **Step 2: Register in groups.json**

Add `pgsql-native_auth_differential-t` to an appropriate `pgsql*` group (e.g. `pgsql16-g1`). Match the JSON structure of a neighboring entry exactly.

- [ ] **Step 3: Build the test binary**

Run: `make build_tap_tests` (release) — confirm `pgsql-native_auth_differential-t` builds via the pattern rule.

- [ ] **Step 4: Run via the isolated runner (NEVER set up Docker manually)**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=pgsql16-g1 test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=pgsql16-g1 test/infra/control/run-tests-isolated.bash
```

Expected: `pgsql-native_auth_differential-t` passes — native matches libpq for trust/md5/scram/scram+TLS, and no fallback warning fired for any method.

- [ ] **Step 5: If a backend in the infra doesn't offer all auth methods**

If the existing `pgsql*` infra's `pg_hba.conf` doesn't enforce per-method auth, extend the infra fixture (under `test/infra/`) to add a backend or hba entries per method. Document the addition in the test file header. Do not skip a method silently — a method we can't exercise is logged in the test output as skipped with the reason.

- [ ] **Step 6: Commit**

```bash
git add test/tap/tests/pgsql-native_auth_differential-t.cpp test/tap/groups/groups.json
git commit -m "test(pgsql): differential native-vs-libpq auth test (trust/md5/scram/scram+TLS)"
```

---

## Self-Review

**Spec coverage (against the design spec §2 decisions and §4/§8 Phase 0–1 content):**
- Runtime flag + libpq fallback → Tasks 0.1–0.3. ✓
- Data-path-only scope → nothing here touches Monitor/genai. ✓
- Auth: cleartext/trust, md5, SCRAM-SHA-256 → Tasks 1.2–1.4, exercised in 1.8. ✓ SCRAM-SHA-256-PLUS (channel binding, Task 1.5) **deferred** to Phase 1b; `-PLUS`-only servers → capability-gap libpq fallback (Task 1.6 mechanism selection). GSSAPI/SSPI deferred → capability-gap fallback in Task 1.6 Step 1. ✓
- TLS via existing OpenSSL stack → Task 1.6 Step 1 (SSL reply + handshake). Channel-binding digest deferred with Task 1.5. ✓
- Own the fd via backend `PgSQL_Data_Stream` → Task 1.6. ✓
- Cached `ParameterStatus`/`BackendKeyData`/txn-state replacing `PQ*` accessors → Task 1.6 Steps 2–3. ✓
- Differential, byte-level correctness bar → Task 1.8 (Phase 1 scope is auth/connect; the result-byte comparison corpus from spec §7 lands with Phase 2's query path). ✓ for Phase 1's surface.
- Cancellation (`CancelRequest`) → deferred to Phase 2 with the query path (not needed to idle in pool); noted, not in this plan.

**Placeholder scan:** Two deliberate, called-out spots require a value computed during implementation, not left vague: Task 1.3 Step 1 (pin the exact md5 hex from the reference impl — instruction is explicit not to ship the shape-only assertion) and Task 1.4 Step 1 (replace placeholder `scram_client_*` names with the real libscram symbols). Both are unavoidable (a hash digest / an external lib's symbol names) and are flagged as required actions, not hand-waves.

**Type consistency:** `PgSQL_Backend_Msg_Framer`, `PgSQL_Backend_Msg`, `PgSQL_Frame_Result`/`FRAME_*`, `PgSQL_Scram_State`, and the free functions `pg_build_ssl_request`/`pg_build_startup`/`pg_build_md5`/`pg_scram_client_first`/`pg_scram_client_final`/`pg_scram_verify_server_final`/`pg_tls_server_end_point` are used consistently across Tasks 1.1–1.6 and declared in `include/PgSQL_Backend_Protocol.h`. `native_mode`, `native_st`/`PG_NATIVE_*`, and `bp` are consistent across Tasks 0.2–1.6.
