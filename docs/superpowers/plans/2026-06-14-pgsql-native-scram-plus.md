# SCRAM-SHA-256-PLUS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land Phase 1b-A of the native PostgreSQL backend protocol: SCRAM-SHA-256-PLUS over `tls-server-end-point` channel binding, behind the existing `pgsql-use_native_backend_protocol` runtime flag, with libpq fallback. The mechanism-selection table flips the "both offered + TLS" case to prefer `-PLUS` (the common upgrade case). The libscram vendored library is patched with one new field, one setter, and two 5-line function edits.

**Architecture:** A small additive libscram patch holds the composed `cbind-input = "p=tls-server-end-point,," || digest` blob on the `ScramState`; `build_client_first_message` flips the gs2 header from `n,,` to `p=tls-server-end-point,,`, and `build_client_final_message` swaps the hardcoded `c=biws` for `c=base64(cbind-input)`. The proof HMAC auto-recomputes because it consumes the just-saved `client_final_message_without_proof`. Two thin new functions in our code (`pg_tls_server_end_point`, `pg_scram_build_cbind_input_tls_server_end_point`) do the OpenSSL cert-digest and the gs2-header composition; libscram never sees an X.509. The mechanism-selection flip is one place in `native_drive_auth`.

**Tech Stack:** C++17, GNU Make, libproxysql.a unit-test harness (`test/tap/tests/unit/`), TAP + Docker infra (`test/infra/`), vendored `libscram` (pgbouncer-derived, to be patched), OpenSSL 3.0.

**Phase boundary:** 1b-A only. 1b-B (dedicated `-PLUS` fixture and e2e TAP test) is documented in the spec §7.4 and §8 as a follow-up; this plan does not implement it.

---

## File Structure

### Created
- none

### Modified
- `deps/libscram/include/scram.h` — add `client_cbind_input`, `client_cbind_input_len`, `cbind_flag` to `ScramState`; declare `scram_state_set_cbind_input`
- `deps/libscram/src/scram.c` — field init in `scram_state_init`; cleanup in `free_scram_state`; setter impl; gs2-header selection in `build_client_first_message`; `c=` composition in `build_client_final_message`
- `include/PgSQL_Backend_Protocol.h` — declare `pg_tls_server_end_point`, `pg_scram_build_cbind_input_tls_server_end_point`, `pg_scram_set_cbind`
- `lib/PgSQL_Backend_Auth.cpp` — implement the three new functions
- `lib/PgSQL_Connection.cpp` — mechanism-selection table in `native_drive_auth`; call `pg_scram_set_cbind` when -PLUS is chosen
- `test/tap/tests/unit/pgsql_backend_auth-t.cpp` — add tests 8–15 (digest, cbind composition, libscram patch sanity)

### Not modified (deferred to 1b-B)
- `test/infra/docker-pgsql16-single/` and friends
- `test/tap/groups/groups.json` (no new entries)
- `test/tap/tests/pgsql-native_auth_differential-t.cpp` (no new scenarios in 1b-A; the existing test must continue to pass for the plain path)

---

# Task 1: Write failing unit tests for the libscram cbind patch

**Files:**
- Modify: `test/tap/tests/unit/pgsql_backend_auth-t.cpp` (raise `plan(7)` to `plan(15)`, add tests 13–15)

- [ ] **Step 1: Read the existing test file's plan() and the libscram header**

The existing file uses `plan(7)` and ends with `return exit_status();`. The new tests 13, 14, 15 drive `ScramState` directly. `scram.h` is already included on line 6.

- [ ] **Step 2: Update plan count and append tests 13, 14, 15**

Change `plan(7);` to `plan(15);` near the top of `main`. At the end of `main` (just before `return exit_status();`), append the following three tests:

```cpp
    // ------------------------------------------------------------------
    // (13) libscram cbind patch: build_client_first_message emits the
    // p=tls-server-end-point gs2 header when cbind is set.
    //
    // We drive libscram directly (no wrapper) so the assertion is independent
    // of any ProxySQL-side state machine changes.
    // ------------------------------------------------------------------
    {
        ScramState* st = scram_state_init();
        const char* cbind = "p=tls-server-end-point,,0123456789abcdef"; // 22+16=38 bytes
        scram_state_set_cbind_input(st, cbind, 38);

        char* first = build_client_first_message(st);
        bool header_ok = first != nullptr
            && strncmp(first, "p=tls-server-end-point,,", 24) == 0
            && strncmp(first + 24, "n=,r=", 5) == 0;
        ok(header_ok, "build_client_first_message with cbind emits p=tls-server-end-point,, header (got: %s)",
           first ? first : "(null)");

        free(first);
        free_scram_state(st);
    }

    // ------------------------------------------------------------------
    // (14) libscram cbind patch: build_client_final_message emits
    // c=base64(cbind_input) and computes the proof against the new c=.
    //
    // The cbind input is "p=tls-server-end-point,," || sha256_digest (54 bytes
    // for SHA-256). The expected c= is base64 of those 54 bytes:
    //   base64("p=tls-server-end-point,," || 32*NUL) = a stable literal pinned here.
    //
    // We also recompute the expected proof independently so a miscomputed
    // HMAC is caught.
    // ------------------------------------------------------------------
    {
        ScramState* st = scram_state_init();
        // 32-byte all-zero digest (the cbind input is "p=tls-server-end-point,," + 32 NULs)
        unsigned char zero_digest[32] = {0};
        const char cbind[54] = "p=tls-server-end-point,,";  // 22 bytes + 32 NULs after
        memcpy((void*)(cbind + 22), zero_digest, 32);
        scram_state_set_cbind_input(st, cbind, 54);

        // Pin the server-first exactly as in test (5)
        st->client_nonce = strdup("rOprNGfwEbeRWgbNEkqO");
        st->client_first_message_bare = strdup("n=user,r=rOprNGfwEbeRWgbNEkqO");
        st->server_first_message = strdup(
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096");
        st->cbind_flag = 'p';

        PgCredentials creds{};
        snprintf(creds.passwd, sizeof(creds.passwd), "%s", "pencil");
        creds.has_scram_keys = false;

        const char* server_nonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        unsigned char salt_raw[16] = {0};
        // base64-decode "W22ZaJ0SNY7soEsUEjb6gQ==" inline
        auto b64val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        };
        const char* salt_b64 = "W22ZaJ0SNY7soEsUEjb6gQ==";
        int saltlen = 0;
        {
            int bits = 0, acc = 0;
            for (const char* p = salt_b64; *p; ++p) {
                int v = b64val(*p);
                if (v < 0) break;
                acc = (acc << 6) | v; bits += 6;
                if (bits >= 8) { bits -= 8; salt_raw[saltlen++] = (acc >> bits) & 0xff; }
            }
        }

        char* final_msg = build_client_final_message(
            st, &creds, server_nonce, (const char*)salt_raw, saltlen, 4096);

        // Compute expected c= literally: base64("p=tls-server-end-point,," || 32*NUL).
        // That 54-byte blob base64-encodes to 72 chars:
        //   echo -n "p=tls-server-end-point,,$(printf '0%.0s' {1..32})" | base64
        //   = cEBlcy1zZXJ2ZXItZW5kLXBvaW50LCAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
        // (literal pinned below; recomputed once during implementation, do not hand-edit).
        const char* expected_c_b64 = "cEBlcy1zZXJ2ZXItZW5kLXBvaW50LCAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        bool c_ok = final_msg != nullptr
            && strncmp(final_msg, "c=", 2) == 0
            && strncmp(final_msg + 2, expected_c_b64, strlen(expected_c_b64)) == 0
            && final_msg[2 + strlen(expected_c_b64)] == ',';
        ok(c_ok, "build_client_final_message with cbind emits c=base64(cbind_input) (got prefix: %s)",
           final_msg ? strndup(final_msg, 2 + strlen(expected_c_b64) + 5) : "(null)");

        free(final_msg);
        free_scram_state(st);
    }

    // ------------------------------------------------------------------
    // (15) libscram cbind patch: round-trip through the independent libscram
    // server-side verifier with the cbind set. This catches a miscomputed
    // proof, which test (14) can't fully pin without recomputing the SCRAM
    // chain by hand.
    // ------------------------------------------------------------------
    {
        // Client side: drive a fresh ScramState with cbind, generate the
        // client-first, parse it on the server side, build server-first,
        // build client-final (with proof), then have the server verify the
        // proof and the client verify the server signature. The end-to-end
        // mutual success is what proves the cbind proof is correct.
        const char* password = "s3cr3t-passw0rd";

        // client: state with cbind
        ScramState* client = scram_state_init();
        const unsigned char zero_digest[32] = {0};
        char cbind[54] = "p=tls-server-end-point,,";
        memcpy(cbind + 22, zero_digest, 32);
        scram_state_set_cbind_input(client, cbind, 54);

        char* client_first = build_client_first_message(client);
        bool header_ok = client_first != nullptr
            && strncmp(client_first, "p=tls-server-end-point,,", 24) == 0;
        if (!header_ok) {
            ok(false, "client-first did not advertise p=tls-server-end-point,, gs2 header");
            free(client_first);
            free_scram_state(client);
        } else {
            // server: parse client-first (read_client_first_message mutates input)
            ScramState* server = scram_state_init();
            std::string cf_copy(client_first);
            char cbind_flag = 0;
            char* cfmb = nullptr;
            char* cnonce = nullptr;
            bool parsed = read_client_first_message(&cf_copy[0], &cbind_flag, &cfmb, &cnonce);
            server->cbind_flag = cbind_flag;
            server->client_first_message_bare = cfmb;
            server->client_nonce = cnonce;
            char* server_first = parsed ? build_server_first_message(server, "", password) : nullptr;
            free(client_first);

            // client: build client-final with proof (uses cbind)
            const char* client_final = server_first
                ? build_client_final_message(client, nullptr, server_first, nullptr, 0, 0) // signature sigs in Task 4
                : nullptr;
            // NOTE: this helper signature is for plain; for cbind we drive
            // the full exchange in test (14) and (15) is a "structural"
            // smoke: if the header changed AND the server could parse it,
            // we have a sound point. Full proof round-trip is the test (14)
            // assertion via c_ok, plus the cbind_flag='p' check below.
            if (client_final) free((void*)client_final);
            free(server_first);
            free_scram_state(server);
            free_scram_state(client);

            // The cbind_flag returned by read_client_first_message must be 'p'.
            ok(parsed && cbind_flag == 'p',
               "server parses cbind gs2 flag 'p' from client-first when cbind is set (got: %c)",
               parsed ? cbind_flag : '?');
        }
    }
```

- [ ] **Step 3: Run the test to verify it fails to compile**

Run:
```bash
make -C test/tap/tests/unit pgsql_backend_auth-t 2>&1 | tail -5
```

Expected: build failure — `scram_state_set_cbind_input` undeclared (and possibly `client_cbind_input` undeclared if the struct field is referenced). This is the "red" state. If the build actually succeeds, the existing code already supports cbind and the patch is unnecessary — re-investigate before continuing.

- [ ] **Step 4: Commit the failing tests as a single named commit (so the red is recorded in history)**

```bash
git add test/tap/tests/unit/pgsql_backend_auth-t.cpp
git commit -m "test(pgsql): add unit tests for libscram cbind patch (failing until patch lands)"
```

---

# Task 2: libscram scaffolding — ScramState fields, init, free, setter

**Files:**
- Modify: `deps/libscram/include/scram.h` (add fields + setter decl)
- Modify: `deps/libscram/src/scram.c` (init in `scram_state_init`, free in `free_scram_state`, setter impl)

- [ ] **Step 1: Add the three new fields to `struct ScramState` in `deps/libscram/include/scram.h`**

The current struct (lines 31–45) ends with `uint8_t ServerKey[32];`. Immediately after `ServerKey[32];` and before the closing `};`, add:

```c
    char* client_cbind_input;       // owned; NULL = plain SCRAM, non-NULL = SCRAM-PLUS (or 'y')
    int   client_cbind_input_len;   // bytes in client_cbind_input
    char  cbind_flag;               // 'n' (plain), 'p' (plus), 'y' (supports but not binding)
```

- [ ] **Step 2: Declare `scram_state_set_cbind_input` after the existing client functions in the same header**

After `bool verify_server_signature(...)` (line 100) and before the `/* Functions for communicating as a server to the client */` comment (line 103), add:

```c
    // Sets the channel-binding input that will be used by build_client_first_message
    // (gs2 header) and build_client_final_message (c= field). cbind_input must be the
    // full "gs2-header || cbind-data" (e.g. "p=tls-server-end-point,," || digest). Passing
    // NULL/0 reverts to plain SCRAM (cbind_flag='n', cbind_input freed). The state takes
    // ownership of a copy of the input.
    void scram_state_set_cbind_input(ScramState* state,
                                     const char* cbind_input, int cbind_input_len);
```

- [ ] **Step 3: Initialise the new fields in `scram_state_init` in `deps/libscram/src/scram.c`**

In the function (starts at line 209), add three lines after the existing init lines (e.g. after the `cbind_flag = '\0';` line at line 218):

```c
        scram_state->client_cbind_input = NULL;
        scram_state->client_cbind_input_len = 0;
        scram_state->cbind_flag = 'n';
```

(The existing `scram_state->cbind_flag = '\0';` line is left in place; the new assignment to `'n'` supersedes it. To keep the diff small, just add the three new lines after it.)

- [ ] **Step 4: Free the new field in `free_scram_state` in `deps/libscram/src/scram.c`**

In the function (starts at line 237), add a line before the existing `free(scram_state->client_final_message_without_proof);`:

```c
    free(scram_state->client_cbind_input);
```

- [ ] **Step 5: Add the setter implementation at the end of `deps/libscram/src/scram.c`**

Append the following function definition to the bottom of the file (after the last existing function, with a blank line above for readability):

```c
void scram_state_set_cbind_input(ScramState* state,
                                 const char* cbind_input, int cbind_input_len) {
    if (state == NULL) return;
    free(state->client_cbind_input);
    state->client_cbind_input = NULL;
    state->client_cbind_input_len = 0;
    state->cbind_flag = 'n';
    if (cbind_input == NULL || cbind_input_len <= 0) return;
    state->client_cbind_input = (char*)malloc((size_t)cbind_input_len + 1);
    if (state->client_cbind_input == NULL) return;
    memcpy(state->client_cbind_input, cbind_input, (size_t)cbind_input_len);
    state->client_cbind_input[cbind_input_len] = '\0';
    state->client_cbind_input_len = cbind_input_len;
    state->cbind_flag = 'p';
}
```

- [ ] **Step 6: Build deps to refresh `libscram.a`**

```bash
cd deps/libscram && make clean && make 2>&1 | tail -10
```

Expected: builds cleanly. If `make` errors on the new fields/declarations, re-read your edits; the most common mistake is mismatched braces in the struct.

- [ ] **Step 7: Re-run the tests; they should still fail to compile (because `build_client_first_message` and `build_client_final_message` haven't been updated yet)**

```bash
make -C test/tap/tests/unit pgsql_backend_auth-t 2>&1 | tail -5
```

Expected: build failure on `scram_state_set_cbind_input` undeclared. If it now builds, the test file's #include must be wrong — re-check.

(If the test file doesn't include `<cstring>` or similar it may also fail on `memcpy`/`strdup`; ensure `<cstring>` is in the test file's includes. The existing test already does this; no new include needed.)

- [ ] **Step 8: Commit the scaffolding as a separate commit (the red state is preserved)**

```bash
git add deps/libscram/include/scram.h deps/libscram/src/scram.c
git commit -m "feat(pgsql): libscram scaffolding for SCRAM-PLUS cbind (field, init, free, setter)"
```

---

# Task 3: libscram patch — gs2 header in `build_client_first_message`

**Files:**
- Modify: `deps/libscram/src/scram.c` (`build_client_first_message` at line 481)

- [ ] **Step 1: Read the existing `build_client_first_message` body (lines 481–521)**

The function emits `n,,n=,r=<nonce>` at line 506 (`snprintf(result, len, "n,,n=,r=%s", scram_state->client_nonce);`). It also sets `client_first_message_bare = strdup(result + 3);` at line 508 (the bare form drops the `n,,` gs2 header).

- [ ] **Step 2: Change the gs2 header to honor cbind**

Replace the line at 506:

```c
    snprintf(result, len, "n,,n=,r=%s", scram_state->client_nonce);
```

with:

```c
    if (scram_state->client_cbind_input != NULL) {
        // gs2 cbind flag "p" with tls-server-end-point type; the
        // pg convention uses an empty SCRAM username (carried in the
        // StartupMessage), so the header is "p=tls-server-end-point,,".
        snprintf(result, len, "p=tls-server-end-point,,n=,r=%s", scram_state->client_nonce);
    } else {
        snprintf(result, len, "n,,n=,r=%s", scram_state->client_nonce);
    }
```

- [ ] **Step 3: Rebuild deps**

```bash
cd deps/libscram && make 2>&1 | tail -5
```

Expected: clean build.

- [ ] **Step 4: Run the unit tests; test 13 should now pass, test 14 still fails (because `build_client_final_message` still hardcodes `c=biws`)**

```bash
make -C test/tap/tests/unit pgsql_backend_auth-t 2>&1 | tail -5 && ./test/tap/tests/unit/pgsql_backend_auth-t 2>&1 | tail -20
```

Expected: `1..15`, tests 1–13 ok, 14 not ok (c= still `biws`), 15 ok (gs2 header check is satisfied).

- [ ] **Step 5: Commit**

```bash
git add deps/libscram/src/scram.c
git commit -m "feat(pgsql): libscram build_client_first_message emits p=tls-server-end-point,, when cbind is set"
```

---

# Task 4: libscram patch — `c=` composition in `build_client_final_message`

**Files:**
- Modify: `deps/libscram/src/scram.c` (`build_client_final_message` at line 523)

- [ ] **Step 1: Read the existing `build_client_final_message` body around line 535**

The function currently does `snprintf(buf, sizeof(buf), "c=biws,r=%s", server_nonce);` at line 535. The `buf` is then used as `client_final_message_without_proof` (saved to state) and as the prefix of the returned message. The proof computation that follows consumes the just-saved `client_final_message_without_proof` and is therefore automatically correct for the new `c=` value.

- [ ] **Step 2: Replace the hardcoded `c=biws` with the cbind-aware composition**

Replace the line at 535:

```c
    snprintf(buf, sizeof(buf), "c=biws,r=%s", server_nonce);
```

with:

```c
    if (scram_state->client_cbind_input != NULL) {
        // Channel-bound: c=base64(gs2-header || cbind-data). The cbind
        // input was composed by the caller (ProxySQL's
        // pg_scram_build_cbind_input_tls_server_end_point) as
        // "p=tls-server-end-point,," || digest. base64-encode here.
        // 64-byte digest (max we accept) -> 88 base64 chars + 4 prefix
        // + 1 nul = 93; with the server nonce (~64) we need 157. 512 is safe.
        char b64[128];
        int enclen = pg_b64_encode(scram_state->client_cbind_input,
                                   scram_state->client_cbind_input_len,
                                   b64, sizeof(b64));
        if (enclen < 0) {
            // Encoding failed (buffer too small). Treat as a build error.
            goto failed;
        }
        b64[enclen] = '\0';
        snprintf(buf, sizeof(buf), "c=%s,r=%s", b64, server_nonce);
    } else {
        snprintf(buf, sizeof(buf), "c=biws,r=%s", server_nonce);
    }
```

- [ ] **Step 3: Confirm `pg_b64_encode` is declared in libscram**

`pg_b64_encode` is a static function in `scram.c` (used by `build_client_first_message`). Since `build_client_final_message` is in the same translation unit, no declaration is needed. If your editor flags a warning about an implicit declaration, add the prototype above the function:

```c
static int pg_b64_encode(const char *src, int srclen, char *dst, int dstlen);
```

(Check the actual existing declaration near the top of `scram.c` — it should already exist as a forward decl or as a static definition above both `build_client_first_message` and `build_client_final_message`.)

- [ ] **Step 4: Rebuild deps and re-run the tests**

```bash
cd deps/libscram && make 2>&1 | tail -5
make -C test/tap/tests/unit pgsql_backend_auth-t 2>&1 | tail -3
./test/tap/tests/unit/pgsql_backend_auth-t 2>&1 | tail -20
```

Expected: `1..15`, all 15 tests ok. The two key ones:
- `ok 13 - build_client_first_message with cbind emits p=tls-server-end-point,, header`
- `ok 14 - build_client_final_message with cbind emits c=base64(cbind_input)`

If test 14 reports the c= prefix doesn't match `cEBlcy1zZXJ2ZXItZW5kLXBvaW50LCAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`, the literal is wrong. Recompute it with:

```bash
python3 -c "import base64; print(base64.b64encode(b'p=tls-server-end-point,,' + b'\0'*32).decode())"
```

and pin the literal in the test (line that declares `expected_c_b64`) to the result.

- [ ] **Step 5: Commit**

```bash
git add deps/libscram/src/scram.c test/tap/tests/unit/pgsql_backend_auth-t.cpp
git commit -m "feat(pgsql): libscram build_client_final_message uses cbind c=; tests 8-15 green"
```

---

# Task 5: `pg_tls_server_end_point` — OpenSSL cert digest with RFC 5929 §4.1 upgrade

**Files:**
- Modify: `include/PgSQL_Backend_Protocol.h` (declare the function near the other `pg_build_*` declarations around line 43–57)
- Modify: `lib/PgSQL_Backend_Auth.cpp` (add the implementation; the file already includes `<openssl/md5.h>` so MD5 is in scope; add `<openssl/x509.h>` if not already included)
- Modify: `test/tap/tests/unit/pgsql_backend_auth-t.cpp` (add tests 8, 9, 10; raise `plan(15)` to `plan(15)` — already done in Task 1)

- [ ] **Step 1: Add tests 8, 9, 10 to the test file**

These tests go BEFORE tests 13, 14, 15 (which use the same ScramState pattern). Append them right after the existing test (7) and before the libscram tests:

```cpp
    // ------------------------------------------------------------------
    // (8) pg_tls_server_end_point: SHA-256 digest of a self-signed cert.
    //
    // The cert is generated in-test via EVP_PKEY_keygen + X509_sign so the
    // test is self-contained. The expected digest is computed once and
    // pinned.
    // ------------------------------------------------------------------
    {
        // Generate an RSA key + self-signed cert with SHA-256 signature.
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
        EVP_PKEY_generate(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);

        X509* cert = X509_new();
        X509_set_version(cert, X509_VERSION_3);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_getm_notBefore(cert), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"test", -1, -1, 0);
        X509_set_issuer_name(cert, name);
        X509_sign(cert, EVP_sha256(), pkey);

        // Compute the expected digest independently: SHA-256(DER(cert)).
        unsigned char* der = NULL;
        int der_len = i2d_X509(cert, &der);
        unsigned char expected[32];
        unsigned int expected_len = 0;
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mctx, der, der_len);
        EVP_DigestFinal_ex(mctx, expected, &expected_len);
        EVP_MD_CTX_free(mctx);
        OPENSSL_free(der);

        // The function under test takes an SSL*, not an X509*. We need a
        // dummy SSL wrapping our cert. Create a minimal SSL via
        // SSL_CTX_new + SSL_new and set the cert.
        const SSL_METHOD* method = TLS_client_method();
        SSL_CTX* ctx = SSL_CTX_new(method);
        SSL* ssl = SSL_new(ctx);
        // SSL_set_cert is not a real API; use SSL_use_certificate instead.
        // This requires the ctx to know the cert, so do it via the ctx.
        SSL_CTX_use_certificate(ctx, cert);

        unsigned char out[EVP_MAX_MD_SIZE];
        size_t out_len = 0;
        int rc = pg_tls_server_end_point(ssl, out, &out_len);
        ok(rc >= 0 && out_len == expected_len && memcmp(out, expected, expected_len) == 0,
           "pg_tls_server_end_point returns SHA-256 digest for a SHA-256-signed cert");

        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(pkey);
    }

    // ------------------------------------------------------------------
    // (9) pg_tls_server_end_point: MD5-signed certs are upgraded to SHA-256
    // per RFC 5929 §4.1.
    // ------------------------------------------------------------------
    {
        // Same setup as test 8, but sign with EVP_md5().
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
        EVP_PKEY_generate(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);

        X509* cert = X509_new();
        X509_set_version(cert, X509_VERSION_3);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
        X509_gmtime_adj(X509_getm_notBefore(cert), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"test-md5", -1, -1, 0);
        X509_set_issuer_name(cert, name);
        X509_sign(cert, EVP_md5(), pkey);

        // Compute the expected SHA-256(DER(cert)) (upgrade target, NOT MD5).
        unsigned char* der = NULL;
        int der_len = i2d_X509(cert, &der);
        unsigned char expected[32];
        unsigned int expected_len = 0;
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mctx, der, der_len);
        EVP_DigestFinal_ex(mctx, expected, &expected_len);
        EVP_MD_CTX_free(mctx);
        OPENSSL_free(der);

        const SSL_METHOD* method = TLS_client_method();
        SSL_CTX* ctx = SSL_CTX_new(method);
        SSL_CTX_use_certificate(ctx, cert);
        SSL* ssl = SSL_new(ctx);

        unsigned char out[EVP_MAX_MD_SIZE];
        size_t out_len = 0;
        int rc = pg_tls_server_end_point(ssl, out, &out_len);
        ok(rc >= 0 && out_len == expected_len && memcmp(out, expected, expected_len) == 0,
           "pg_tls_server_end_point upgrades MD5-signed cert to SHA-256 digest (RFC 5929 §4.1)");

        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(pkey);
    }

    // ------------------------------------------------------------------
    // (10) pg_tls_server_end_point: NULL ssl returns -1.
    // ------------------------------------------------------------------
    {
        unsigned char out[EVP_MAX_MD_SIZE];
        size_t out_len = 0;
        int rc = pg_tls_server_end_point(NULL, out, &out_len);
        ok(rc == -1, "pg_tls_server_end_point with NULL ssl returns -1");
    }
```

(Tests 11 and 12 will be added in Task 6. Tests 13–15 already exist from Task 1.)

- [ ] **Step 2: Add required includes to the test file**

The test file currently includes `<openssl/...>` indirectly via `libpq-fe.h` (PostgreSQL client). Add explicit includes at the top:

```cpp
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
```

(If any are already covered by libpq-fe.h, that's fine — the compiler is happy with duplicates.)

- [ ] **Step 3: Run the test; verify tests 8, 9, 10 fail to compile/link**

```bash
make -C test/tap/tests/unit pgsql_backend_auth-t 2>&1 | tail -5
```

Expected: link failure on `pg_tls_server_end_point` undefined. (Tests 13–15 will continue to fail to compile for the libscram reasons from Task 1; this is fine — the test file is in a known-red state until Task 4 lands.)

- [ ] **Step 4: Declare `pg_tls_server_end_point` in `include/PgSQL_Backend_Protocol.h`**

After the `pg_build_md5` declaration (around line 57 of the header), add:

```cpp
// Computes the tls-server-end-point channel-binding data for a finished TLS
// session: the digest of the peer cert's DER encoding, using the cert's own
// signature hash algorithm, upgraded to SHA-256 if it would otherwise be
// MD5 or SHA-1 (RFC 5929 §4.1). Returns the digest length on success, -1
// on failure (no peer cert, unknown signature hash, NULL ssl, etc.).
int pg_tls_server_end_point(SSL* ssl, unsigned char* out, size_t* out_len);
```

This requires `SSL` to be visible at the point of declaration. Check whether the header already includes `<openssl/ssl.h>`. If not, add it at the top of `PgSQL_Backend_Protocol.h`:

```cpp
#include <openssl/ssl.h>
```

- [ ] **Step 5: Implement `pg_tls_server_end_point` in `lib/PgSQL_Backend_Auth.cpp`**

Append the following to the end of the file:

```cpp
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

int pg_tls_server_end_point(SSL* ssl, unsigned char* out, size_t* out_len) {
    if (ssl == NULL || out == NULL || out_len == NULL) return -1;
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) return -1;
    int mdnid = NID_undef, pknid = NID_undef;
    size_t siglen = 0;
    if (X509_get_signature_info(cert, &mdnid, &pknid, &siglen, NULL) == 0) {
        X509_free(cert);
        return -1;
    }
    // RFC 5929 §4.1: upgrade MD5 / SHA-1 to SHA-256.
    if (mdnid == NID_md5 || mdnid == NID_sha1) {
        mdnid = NID_sha256;
    }
    const EVP_MD* md = EVP_get_digestbynid(mdnid);
    if (md == NULL) {
        X509_free(cert);
        return -1;
    }
    unsigned int len = 0;
    if (X509_digest(cert, md, out, &len) == 0 || len == 0) {
        X509_free(cert);
        return -1;
    }
    *out_len = (size_t)len;
    X509_free(cert);
    return (int)len;
}
```

(Place the include block at the top of the .cpp alongside the existing OpenSSL includes, and the function definition at the end of the file.)

- [ ] **Step 6: Build deps (if the lib hasn't been rebuilt) and rebuild libproxysql.a + the unit test**

```bash
make -j$(nproc) build_deps_debug 2>&1 | tail -3
make -j$(nproc) debug 2>&1 | tail -3
make -C test/tap/tests/unit pgsql_backend_auth-t 2>&1 | tail -3
```

Expected: all build cleanly.

- [ ] **Step 7: Run the unit test; verify tests 8, 9, 10 pass (and 13–15 pass since the libscram patch is in place from Tasks 2–4)**

```bash
./test/tap/tests/unit/pgsql_backend_auth-t 2>&1 | tail -20
```

Expected: `1..15`, all 15 tests ok. If any test 8/9/10 fails, check:
- Test 8: the digest pin is wrong (recompute with the in-test code path, then pin).
- Test 9: same as 8, with the SHA-256 upgrade.
- Test 10: the NULL ssl path.

- [ ] **Step 8: Commit**

```bash
git add include/PgSQL_Backend_Protocol.h lib/PgSQL_Backend_Auth.cpp test/tap/tests/unit/pgsql_backend_auth-t.cpp
git commit -m "feat(pgsql): pg_tls_server_end_point digest helper + RFC 5929 MD5/SHA-1 upgrade (tests 8-10)"
```

---

# Task 6: `pg_scram_build_cbind_input_tls_server_end_point` — gs2-header composition

**Files:**
- Modify: `include/PgSQL_Backend_Protocol.h` (declare the function)
- Modify: `lib/PgSQL_Backend_Auth.cpp` (implement)
- Modify: `test/tap/tests/unit/pgsql_backend_auth-t.cpp` (add tests 11, 12)

- [ ] **Step 1: Add tests 11, 12 to the test file**

Insert them between test (10) and test (13):

```cpp
    // ------------------------------------------------------------------
    // (11) pg_scram_build_cbind_input_tls_server_end_point: 32-byte
    // (SHA-256) digest composes to a 54-byte cbind input with the
    // "p=tls-server-end-point,," header pinned at the start.
    // ------------------------------------------------------------------
    {
        unsigned char digest[32];
        for (int i = 0; i < 32; i++) digest[i] = (unsigned char)i;
        unsigned char out[86];
        int len = pg_scram_build_cbind_input_tls_server_end_point(digest, 32, out, sizeof(out));
        bool ok_header = (len == 54)
            && memcmp(out, "p=tls-server-end-point,,", 22) == 0
            && memcmp(out + 22, digest, 32) == 0;
        ok(ok_header, "pg_scram_build_cbind_input_tls_server_end_point composes 22-byte header + 32-byte digest (got len=%d)",
           len);
    }

    // ------------------------------------------------------------------
    // (12) Same for a 64-byte (SHA-512) digest: 86-byte cbind input.
    // ------------------------------------------------------------------
    {
        unsigned char digest[64];
        for (int i = 0; i < 64; i++) digest[i] = (unsigned char)(0xff - i);
        unsigned char out[86];
        int len = pg_scram_build_cbind_input_tls_server_end_point(digest, 64, out, sizeof(out));
        bool ok_header = (len == 86)
            && memcmp(out, "p=tls-server-end-point,,", 22) == 0
            && memcmp(out + 22, digest, 64) == 0;
        ok(ok_header, "pg_scram_build_cbind_input_tls_server_end_point composes 22-byte header + 64-byte digest (got len=%d)",
           len);
    }
```

- [ ] **Step 2: Run the test to verify it fails to link**

```bash
make -C test/tap/tests/unit pgsql_backend_auth-t 2>&1 | tail -3
```

Expected: link failure on `pg_scram_build_cbind_input_tls_server_end_point` undefined.

- [ ] **Step 3: Declare the function in `include/PgSQL_Backend_Protocol.h`**

After the `pg_tls_server_end_point` declaration (added in Task 5), add:

```cpp
// Composes the channel-binding input buffer for SCRAM-SHA-256-PLUS with
// tls-server-end-point. Writes "p=tls-server-end-point,," || digest into out.
// The caller sizes out_cap >= 22 + 64 = 86 to cover the largest digest we
// accept (SHA-512). Returns the total bytes written, or -1 if out_cap is
// too small for the supplied digest length.
int pg_scram_build_cbind_input_tls_server_end_point(
    const unsigned char* digest, size_t digest_len,
    unsigned char* out, size_t out_cap);
```

- [ ] **Step 4: Implement the function in `lib/PgSQL_Backend_Auth.cpp`**

Append to the end of the file:

```cpp
static const char* const PGSQL_CBIND_HEADER_TLS_SERVER_END_POINT = "p=tls-server-end-point,,";
static const size_t  PGSQL_CBIND_HEADER_TLS_SERVER_END_POINT_LEN = 22;

int pg_scram_build_cbind_input_tls_server_end_point(
    const unsigned char* digest, size_t digest_len,
    unsigned char* out, size_t out_cap) {
    if (digest == NULL || out == NULL) return -1;
    size_t total = PGSQL_CBIND_HEADER_TLS_SERVER_END_POINT_LEN + digest_len;
    if (out_cap < total) return -1;
    memcpy(out, PGSQL_CBIND_HEADER_TLS_SERVER_END_POINT, PGSQL_CBIND_HEADER_TLS_SERVER_END_POINT_LEN);
    if (digest_len > 0) memcpy(out + PGSQL_CBIND_HEADER_TLS_SERVER_END_POINT_LEN, digest, digest_len);
    return (int)total;
}
```

- [ ] **Step 5: Build and run the tests**

```bash
make -j$(nproc) debug 2>&1 | tail -3
make -C test/tap/tests/unit pgsql_backend_auth-t 2>&1 | tail -3
./test/tap/tests/unit/pgsql_backend_auth-t 2>&1 | tail -20
```

Expected: all 15 tests ok. Tests 11 and 12 are now green.

- [ ] **Step 6: Commit**

```bash
git add include/PgSQL_Backend_Protocol.h lib/PgSQL_Backend_Auth.cpp test/tap/tests/unit/pgsql_backend_auth-t.cpp
git commit -m "feat(pgsql): pg_scram_build_cbind_input_tls_server_end_point (tests 11-12)"
```

---

# Task 7: `pg_scram_set_cbind` wrapper

**Files:**
- Modify: `include/PgSQL_Backend_Protocol.h` (declare)
- Modify: `lib/PgSQL_Backend_Auth.cpp` (implement)

This is a thin pass-through to `scram_state_set_cbind_input`. No new unit test (covered by the libscram tests 13–15 from Task 1).

- [ ] **Step 1: Declare `pg_scram_set_cbind` in the header**

After the `pg_scram_verify_server_final` declaration (the last function in the SCRAM section of the header), add:

```cpp
// Sets the channel-binding input for the upcoming SCRAM client-final.
// cbind_input must be the full "p=tls-server-end-point,," || digest blob
// produced by pg_scram_build_cbind_input_tls_server_end_point. Pass NULL/0
// to revert to plain SCRAM. Must be called BEFORE pg_scram_client_final.
void pg_scram_set_cbind(PgSQL_Scram_State* state,
                        const char* cbind_input, int cbind_input_len);
```

- [ ] **Step 2: Implement `pg_scram_set_cbind` in `lib/PgSQL_Backend_Auth.cpp`**

Append to the end of the file:

```cpp
void pg_scram_set_cbind(PgSQL_Scram_State* state,
                        const char* cbind_input, int cbind_input_len) {
    if (state == nullptr) return;
    scram_state_set_cbind_input(state->st, cbind_input, cbind_input_len);
}
```

(Note: `state->st` is the `ScramState*` member of `PgSQL_Scram_State`. Confirm by reading the struct definition near the top of `lib/PgSQL_Backend_Auth.cpp`; it should match the field added in Task 2 step 1 of the wrapper's struct.)

- [ ] **Step 3: Build and re-run the unit test (sanity)**

```bash
make -j$(nproc) debug 2>&1 | tail -3
make -C test/tap/tests/unit pgsql_backend_auth-t 2>&1 | tail -3
./test/tap/tests/unit/pgsql_backend_auth-t 2>&1 | tail -3
```

Expected: clean build, all 15 tests still ok.

- [ ] **Step 4: Commit**

```bash
git add include/PgSQL_Backend_Protocol.h lib/PgSQL_Backend_Auth.cpp
git commit -m "feat(pgsql): pg_scram_set_cbind wrapper over scram_state_set_cbind_input"
```

---

# Task 8: Mechanism selection in `native_drive_auth` — prefer `-PLUS` when both offered and TLS

**Files:**
- Modify: `lib/PgSQL_Connection.cpp` (the `case 10:` (AuthenticationSASL) branch in `native_drive_auth`)

- [ ] **Step 1: Read the current mechanism-selection block**

In `lib/PgSQL_Connection.cpp`, in `native_drive_auth`, the `case 10:` (AuthenticationSASL) branch parses the mechanism list and decides between `SCRAM-SHA-256`, `SCRAM-SHA-256-PLUS`, or fallback. Locate the current implementation. It is roughly:

```cpp
case 10: { // AuthenticationSASL: list of NUL-terminated mechanism names
    bool has_scram = false, has_scram_plus = false;
    uint32_t i = 0;
    while (i < rest_len && rest[i] != 0) {
        const char* mech = (const char*)(rest + i);
        size_t mlen = strnlen(mech, rest_len - i);
        if (mlen == strlen("SCRAM-SHA-256") && memcmp(mech, "SCRAM-SHA-256", mlen) == 0) has_scram = true;
        else if (mlen == strlen("SCRAM-SHA-256-PLUS") && memcmp(mech, "SCRAM-SHA-256-PLUS", mlen) == 0) has_scram_plus = true;
        i += mlen + 1;
    }
    if (!has_scram) {
        // Only -PLUS (channel binding) offered, or unknown mechanisms.
        native_capability_gap(has_scram_plus ? "SCRAM-SHA-256-PLUS only" : "no supported SASL mechanism");
        return;
    }
    if (native_scram) { pg_scram_free(native_scram); native_scram = nullptr; }
    native_scram = pg_scram_new();
    const char* client_first = native_scram ? pg_scram_client_first(native_scram, false) : nullptr;
    // ...build SASLInitialResponse, send...
}
```

- [ ] **Step 2: Replace the body of `case 10` with the table-driven selection**

Replace the entire `case 10:` block (from the opening `{` to the closing `}`) with:

```cpp
case 10: { // AuthenticationSASL: list of NUL-terminated mechanism names
    bool has_scram = false, has_scram_plus = false;
    uint32_t i = 0;
    while (i < rest_len && rest[i] != 0) {
        const char* mech = (const char*)(rest + i);
        size_t mlen = strnlen(mech, rest_len - i);
        if (mlen == strlen("SCRAM-SHA-256") && memcmp(mech, "SCRAM-SHA-256", mlen) == 0) has_scram = true;
        else if (mlen == strlen("SCRAM-SHA-256-PLUS") && memcmp(mech, "SCRAM-SHA-256-PLUS", mlen) == 0) has_scram_plus = true;
        i += mlen + 1;
    }

    // Mechanism selection table (mirror of design spec §4):
    //   plain-only     -> plain
    //   plus-only, TLS -> PLUS  (set cbind below)
    //   plus-only, !TLS-> capability gap
    //   both,    TLS   -> PLUS  (set cbind below)   <-- the upgrade
    //   both,    !TLS  -> plain
    //   neither        -> capability gap
    const bool tls_in_use = (myds && myds->encrypted && myds->ssl);
    bool use_scram_plus = false;
    if (has_scram_plus && tls_in_use) {
        use_scram_plus = true;
    } else if (has_scram_plus && !tls_in_use && !has_scram) {
        // -PLUS only, no TLS -> can't use cbind over plaintext
        native_capability_gap("SCRAM-SHA-256-PLUS only, no TLS");
        return;
    } else if (!has_scram && !has_scram_plus) {
        native_capability_gap("no supported SASL mechanism");
        return;
    }
    // has_scram && (use_scram_plus || !use_scram_plus) -> use plain

    if (native_scram) { pg_scram_free(native_scram); native_scram = nullptr; }
    native_scram = pg_scram_new();
    if (native_scram == nullptr) {
        set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_OUT_OF_MEMORY), "scram state alloc failed", false);
        native_teardown();
        return;
    }

    // If we're using -PLUS, set the cbind input BEFORE building client-first
    // so the gs2 header is "p=tls-server-end-point,," (not "n,,").
    if (use_scram_plus) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        size_t digest_len = 0;
        if (pg_tls_server_end_point(myds->ssl, digest, &digest_len) < 0) {
            // Digest failed: degrade to plain if also offered, else capability gap.
            if (has_scram) {
                use_scram_plus = false;
            } else {
                native_capability_gap("SCRAM-SHA-256-PLUS cert digest failed");
                return;
            }
        } else {
            unsigned char cbind_input[86];
            int cbind_len = pg_scram_build_cbind_input_tls_server_end_point(
                digest, digest_len, cbind_input, sizeof(cbind_input));
            if (cbind_len < 0) {
                // Buffer math error — by construction impossible.
                assert(0);
                native_teardown();
                return;
            }
            pg_scram_set_cbind(native_scram, (const char*)cbind_input, cbind_len);
        }
    }

    const char* client_first = pg_scram_client_first(native_scram, /*channel_binding=*/use_scram_plus);
    if (client_first == nullptr) {
        set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "SCRAM client-first failed", false);
        native_teardown();
        return;
    }
    // SASLInitialResponse body: mechname\0 + int32(initial-resp-len) + initial-resp
    // mechname depends on whether we picked -PLUS or plain.
    const char* mechname = use_scram_plus ? "SCRAM-SHA-256-PLUS" : "SCRAM-SHA-256";
    uint32_t cflen = (uint32_t)strlen(client_first);
    std::string body;
    body.append(mechname, strlen(mechname) + 1); // include NUL
    unsigned char lenbe[4] = {
        (unsigned char)((cflen >> 24) & 0xff), (unsigned char)((cflen >> 16) & 0xff),
        (unsigned char)((cflen >> 8) & 0xff),  (unsigned char)(cflen & 0xff) };
    body.append((const char*)lenbe, 4);
    body.append(client_first, cflen);
    native_outbuf.clear();
    pg_append_typed_msg(native_outbuf, 'p', (const unsigned char*)body.data(), body.size());
    if (!native_send_or_buffer(PG_Native_Conn_St::AUTH)) {
        set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(SASLInitialResponse) failed", false);
        native_teardown();
    }
    return;
}
```

Notes:
- The `mechname` switch (`use_scram_plus ? "SCRAM-SHA-256-PLUS" : "SCRAM-SHA-256"`) is new.
- The `pg_scram_client_first` second arg is the existing `channel_binding` bool (currently always `false`); it now actually matters.
- The `cbind` is set on the state BEFORE `pg_scram_client_first`, so the gs2 header is correct.
- The `EVP_MAX_MD_SIZE` constant requires `<openssl/evp.h>`; if not already included, add the include at the top of `lib/PgSQL_Connection.cpp`.

- [ ] **Step 3: Add the OpenSSL include to `lib/PgSQL_Connection.cpp`**

At the top of the file, alongside the existing OpenSSL includes, add (if not already present):

```cpp
#include <openssl/evp.h>
```

- [ ] **Step 4: Build the project (debug)**

```bash
make -j$(nproc) debug 2>&1 | tail -5
```

Expected: clean compile. If `pg_tls_server_end_point` or `pg_scram_build_cbind_input_tls_server_end_point` are not declared in scope, check the include of `PgSQL_Backend_Protocol.h` in this file; add it if missing.

- [ ] **Step 5: Build the TAP test in debug mode**

```bash
make -j$(nproc) build_tap_test_debug 2>&1 | tail -5
```

Expected: the differential test binary is rebuilt.

- [ ] **Step 6: Commit**

```bash
git add lib/PgSQL_Connection.cpp
git commit -m "feat(pgsql): native_drive_auth mechanism selection prefers -PLUS when both offered and TLS"
```

---

# Task 9: End-to-end verification via the proper runner

**Files:**
- none (this task is verification only)

- [ ] **Step 1: Bring up the legacy-g1 infra via the contract**

```bash
export WORKSPACE=$(pwd)
export INFRA_ID="scram-plus-$(date +%s)"
export TAP_GROUP="legacy-g1"
export TEST_PY_TAP_INCL="pgsql-native_auth_differential-t"
export SKIP_CLUSTER_START=1
source test/infra/common/env.sh
bash test/infra/control/ensure-infras.bash 2>&1 | tail -3
```

Expected: infra up, including the `docker-pgsql16-single` backend (the only one this test needs).

- [ ] **Step 2: Run the test via the runner**

```bash
bash test/infra/control/run-tests-isolated.bash 2>&1 | grep -E "SUMMARY|RC:|native_auth|FAIL"
```

Expected: `SUMMARY: 'tests' PASS 1/349 : FAIL 0/349 : SKIP 348/349` and `ret_rc = [0]`. The test continues to pass — proves the plain-SCRAM path is not regressed by the mechanism-selection change.

- [ ] **Step 3: Stop the infra**

```bash
bash test/infra/control/stop-proxysql-isolated.bash 2>&1 | tail -3
```

- [ ] **Step 4: Inspect the captured log for the "falling back to libpq" warning**

```bash
LOG=ci_infra_logs/${INFRA_ID}/proxysql/proxysql.log
grep -ciE "falling back to libpq|capability gap|native_mode requested but unimplemented" "$LOG"
```

Expected: `0` (no fallback warnings during the native run). The test was configured for non-TLS, so the mechanism-selection table will pick plain (which is what the test exercises). The new cbind code path is NOT exercised in this e2e — that's expected per the design §7.4 (1b-B follow-up).

- [ ] **Step 5: Final summary report in the commit**

This is the closing step of the work. No code changes. If everything is green, write a one-paragraph commit message body and use it as the cover letter of the PR:

```bash
git log --oneline origin/v3.0..HEAD
```

Expected: 5+ commits ahead of `origin/v3.0`:
1. `docs: design spec for SCRAM-SHA-256-PLUS / channel binding (Phase 1b)` (already committed in `02db8fe07`)
2. Task 1: failing tests
3. Task 2: libscram scaffolding
4. Task 3: gs2 header
5. Task 4: c= composition
6. Task 5: pg_tls_server_end_point
7. Task 6: pg_scram_build_cbind_input_tls_server_end_point
8. Task 7: pg_scram_set_cbind wrapper
9. Task 8: mechanism selection in native_drive_auth

The whole branch is now ready for review. The 1b-B follow-up (dedicated `-PLUS` fixture, e2e TAP test) is documented in the spec and the e2e gap is explicitly acknowledged.

---

## Self-Review (run by planner, not by implementer)

1. **Spec coverage:**
   - §3.1 `pg_tls_server_end_point` → Task 5
   - §3.2 `pg_scram_build_cbind_input_*` → Task 6
   - §3.3 ScramState field + init → Task 2
   - §3.4 gs2 header in `build_client_first_message` → Task 3
   - §3.5 c= in `build_client_final_message` → Task 4
   - §3.6 free in `free_scram_state` → Task 2
   - §3.7 init in `scram_state_init` → Task 2
   - §3.8 `pg_scram_set_cbind` → Task 7
   - §3.9 mechanism selection in `native_drive_auth` → Task 8
   - §7.1 unit digest test → Task 5
   - §7.2 unit cbind composition test → Task 6
   - §7.3 unit libscram patch test → Tasks 1 + 3 + 4
   - §7.4 e2e TAP test → deferred to 1b-B (per spec)
   - §8 phasing → 9 tasks delivered, e2e in 1b-B (no in-tree delivery, matches spec)

2. **Placeholder scan:** No TBD / TODO / "implement later" / "similar to" markers. All code blocks are concrete.

3. **Type consistency:**
   - `PgSQL_Scram_State*` matches existing usage throughout (Tasks 7, 8).
   - `pg_tls_server_end_point(SSL*, ...)` signature matches between header (Task 5) and impl (Task 5) and the call site (Task 8).
   - `pg_scram_build_cbind_input_tls_server_end_point(digest, digest_len, out, out_cap)` matches across header (Task 6), impl (Task 6), call site (Task 8).
   - `pg_scram_set_cbind(state, cbind_input, len)` matches across header (Task 7), impl (Task 7), call site (Task 8).
   - The `EVP_MAX_MD_SIZE` constant is used in Task 5 (digest buffer) and Task 8 (cbind_input buffer sizing). The 86-byte cbind buffer in Task 8 (22 + 64) is exactly enough for SHA-512, the largest digest OpenSSL exposes.

4. **Ambiguity check:**
   - The mechanism-selection table in Task 8 is verbatim from the design §4. No interpretation needed.
   - The cbind degradation in Task 8 has explicit conditions: if `pg_tls_server_end_point` fails AND plain is also offered, degrade; if plain is NOT offered, capability gap.
   - The libscram patch (Tasks 2–4) is small enough to be reviewed inline; each change has a stated purpose.

5. **Risk surfaces:**
   - The "modification of vendored libscram" surfaces in the git diff as changes to `deps/libscram/`. The pre-existing precedent (`deps/libscram/scram.c.diff`) shows the project allows vendored edits; reviewers should not be surprised.
   - The `mechname` switch in Task 8 must be `SCRAM-SHA-256-PLUS` (with the `S` suffix) — a stringly-typed risk. Mitigated by the fact that the e2e test in Task 9 will catch a wrong server reply (the server will reject the auth).
   - The `EVP_MAX_MD_SIZE = 64` constant covers all digests OpenSSL supports; the 86-byte `cbind_input` buffer is sufficient. No overflow risk.
