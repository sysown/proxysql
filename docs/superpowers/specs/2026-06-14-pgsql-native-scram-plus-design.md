# SCRAM-SHA-256-PLUS (Channel Binding) for the Native Backend Protocol

**Date:** 2026-06-14
**Status:** Approved design, pending implementation plan
**Author:** René Cannaò (with Claude)
**Scope:** Phase 1b of the native PostgreSQL backend protocol (`feature/pgsql-native-backend-protocol`). Adds SCRAM-SHA-256-PLUS (channel binding) with `tls-server-end-point` to the auth flow, behind the existing `pgsql-use_native_backend_protocol` runtime flag.

---

## 1. Motivation

Phase 1 (Tasks 1.1–1.6a/b/c) implemented plain `SCRAM-SHA-256` over the native path with libpq fallback. Task 1.5 (`SCRAM-SHA-256-PLUS`) was explicitly deferred because vendored `libscram` (pgbouncer-derived) hardcodes the client channel-binding data to `c=biws` and only handles gs2-cbind flags `n`/`y` (see `deps/libscram/src/scram.c:535`, `:917-918`). Channel binding is the only material gap between the native auth path and what libpq supports by default over TLS.

What `-PLUS` adds: the SCRAM session is cryptographically bound to the TLS session. An attacker who can present a valid-but-wrong cert (cert misissuance, weak validation, `sslmode=require` with no verify) cannot relay the SCRAM exchange to the real backend. Without `-PLUS`, plain SCRAM over `sslmode=require` provides user authentication and confidentiality but no MITM protection on the inner channel.

Cost is essentially zero: one SHA-256 over the peer cert at SCRAM time, no extra round trips, no behavior change for non-TLS backends.

---

## 2. Key Decisions

| Decision | Choice |
|---|---|
| cbind layer location | **Patch vendored libscram.** A new `client_cbind_input` field on `ScramState` + a setter + a 5-line change in `build_client_final_message` to use it. No new code in our wrapper for proof composition. |
| Mechanism selection | **Prefer `-PLUS` when offered AND TLS is in use.** When both `SCRAM-SHA-256` and `SCRAM-SHA-256-PLUS` are offered and `myds->encrypted == true`, choose `-PLUS`. When only plain is offered, choose plain. When only `-PLUS` is offered and no TLS, capability gap → libpq fallback. When neither is offered, capability gap → libpq fallback. |
| Channel-binding type | **`tls-server-end-point`** (RFC 5929). Computes `SHA-256(DER(cert))` (upgraded to SHA-256 if the cert's own signature hash is MD5 or SHA-1). |
| Composition location for the digest | **In our code** (`lib/PgSQL_Backend_Auth.cpp`). libscram receives only the composed `cbind_input = "p=tls-server-end-point,," || digest` blob; it does not know about OpenSSL or X.509. |
| Fallback on digest failure | If `pg_tls_server_end_point` returns -1 (no peer cert, unknown signature hash, etc.), **degrade to plain SCRAM** if plain is also offered; otherwise treat as capability gap → libpq fallback. Log once per backend. |
| TLS upgrade on a `-PLUS`-only server, no TLS | Capability gap → libpq fallback. `-PLUS` over plaintext is not a thing. |
| Phasing | **1b-A (this PR):** libscram patch + digest helper + cbind composition + unit tests + mechanism-selection flip. **1b-B (follow-up PR):** dedicated `test/infra/docker-pgsql16-single-scram-plus/` fixture and an extended differential TAP assertion. |

---

## 3. Components & Ownership

### 3.1 New: `pg_tls_server_end_point` (in `lib/PgSQL_Backend_Auth.cpp`)

```cpp
// Computes the tls-server-end-point channel-binding data for a finished TLS
// session: the digest of the peer cert's DER encoding, using the cert's own
// signature hash algorithm, upgraded to SHA-256 if it would otherwise be
// MD5 or SHA-1 (RFC 5929 §4.1). Returns the digest length on success, -1
// on failure with error_info set.
int pg_tls_server_end_point(SSL* ssl, unsigned char* out, size_t* out_len);
```

Implementation outline:
- `X509* cert = SSL_get_peer_certificate(ssl);` if NULL → return -1
- `int mdnid, pknid; size_t siglen;` `X509_get_signature_info(cert, &mdnid, &pknid, &siglen, NULL)`
- If `mdnid == NID_md5 || mdnid == NID_sha1` → override to `EVP_sha256()`
- Else `mdnid` is the hash to use
- `EVP_MD* md = EVP_get_digestbynid(mdnid);` null-check
- `unsigned int len = 0; X509_digest(cert, md, out, &len); *out_len = len;`
- `X509_free(cert);` return `(int)len;`

`out` must be at least `EVP_MAX_MD_SIZE` (64) bytes by the caller.

### 3.2 New: `pg_scram_build_cbind_input_tls_server_end_point` (in `lib/PgSQL_Backend_Auth.cpp`)

```cpp
// Composes the channel-binding input buffer for SCRAM-SHA-256-PLUS with
// tls-server-end-point. Writes "p=tls-server-end-point,," || digest into out.
// Returns the total bytes written, or -1 if out_cap is too small. The caller
// sizes out_cap >= 22 + 64 = 86 to cover SHA-512 (worst case we accept); the
// common case is 22 + 32 = 54 for SHA-256.
int pg_scram_build_cbind_input_tls_server_end_point(
    const unsigned char* digest, size_t digest_len,
    unsigned char* out, size_t out_cap);
```

Implementation: `memcpy(out, "p=tls-server-end-point,,", 22); memcpy(out+22, digest, digest_len); return 22 + (int)digest_len;` — bounded by `out_cap`.

### 3.3 New: scram state field + setter (in `deps/libscram/`)

In `deps/libscram/include/scram.h`:
```c
struct ScramState {
    // ...existing fields...
    char* client_cbind_input;       // owned; NULL = plain SCRAM, non-NULL = -PLUS
    int   client_cbind_input_len;
    char  cbind_flag;               // 'n' (plain), 'p' (plus), 'y' (supports but not binding)
};
```

New function in `scram.h`:
```c
// Sets the channel-binding input that will be used by build_client_final_message
// (and the gs2 header in build_client_first_message). cbind_input must be the
// full "gs2-header || cbind-data" (e.g. "p=tls-server-end-point,," || digest).
// Passing NULL/0 reverts to plain SCRAM.
void scram_state_set_cbind_input(ScramState* state,
                                 const char* cbind_input, int cbind_input_len);
```

### 3.4 Modified: `build_client_first_message` (in `deps/libscram/src/scram.c:481`)

Currently always emits `n,,n=,r=<nonce>`. Change: if `scram_state->cbind_input` is non-NULL, emit `p=tls-server-end-point,,n=,r=<nonce>` instead. (The trailing `n=` empty SCRAM username is unchanged — the PostgreSQL convention carries the real username in the StartupMessage.)

### 3.5 Modified: `build_client_final_message` (in `deps/libscram/src/scram.c:523`)

Currently hardcodes `snprintf(buf, sizeof(buf), "c=biws,r=%s", server_nonce)`. Change: if `scram_state->client_cbind_input` is non-NULL, base64-encode the cbind input and emit `c=<b64>,r=<server_nonce>`. The proof HMAC that follows already uses `scram_state->client_final_message_without_proof` as input, so it auto-recomputes against the new `c=` field. No change to the proof path.

### 3.6 Modified: `free_scram_state` (in `deps/libscram/src/scram.c:237`)

Add `free(scram_state->client_cbind_input);`.

### 3.7 Modified: `scram_state_init` (in `deps/libscram/src/scram.c:209`)

Add `scram_state->client_cbind_input = NULL; scram_state->client_cbind_input_len = 0; scram_state->cbind_flag = 'n';`.

### 3.8 Modified: `PgSQL_Scram_State` wrapper (in `lib/PgSQL_Backend_Auth.cpp`)

Add a new function that delegates to `scram_state_set_cbind_input`:

```cpp
// Before pg_scram_client_final is called, set the channel-binding input for
// the upcoming client-final. Pass NULL/0 to revert to plain SCRAM.
// The blob must be the full "p=tls-server-end-point,," || digest produced
// by pg_scram_build_cbind_input_tls_server_end_point.
void pg_scram_set_cbind(PgSQL_Scram_State* state,
                        const char* cbind_input, int cbind_input_len);
```

### 3.9 Modified: `native_drive_auth` (in `lib/PgSQL_Connection.cpp`)

After receiving `R` with subtype 10 (AuthenticationSASL), when choosing between mechanisms (currently a single `if/else`):

```cpp
// After parsing the mechanism list and determining which to use:
if (use_scram_plus) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t digest_len = 0;
    if (pg_tls_server_end_point(myds->ssl, digest, &digest_len) < 0) {
        // Digest failed: degrade to plain if offered, else capability gap.
        if (has_plain) { use_scram_plus = false; }
        else { native_capability_gap("SCRAM-SHA-256-PLUS cert digest failed"); return; }
    } else {
        unsigned char cbind_input[86];
        int cbind_len = pg_scram_build_cbind_input_tls_server_end_point(
            digest, digest_len, cbind_input, sizeof(cbind_input));
        if (cbind_len < 0) {
            // Buffer math error — assert. (Should be impossible given sizes.)
            assert(0);
            native_teardown();
            return;
        }
        // Apply cbind to the SCRAM state BEFORE building client-first.
        // The libscram setter also sets cbind_flag='p', which flips the gs2
        // header in build_client_first_message to "p=tls-server-end-point,,".
        pg_scram_set_cbind(native_scram, (const char*)cbind_input, cbind_len);
    }
}
```

`use_scram_plus` is derived from the mechanism list per the table in §4.

---

## 4. Mechanism Selection (one place, no scattered `if`s)

Driven by the server's mechanism list (parsed from the `R/10` payload) and the current `myds->encrypted` state:

| Server offers | TLS in use | Choose | Rationale |
|---|---|---|---|
| `SCRAM-SHA-256` only | either | plain | Only choice the server accepts. |
| `SCRAM-SHA-256-PLUS` only | yes | **-PLUS** | cbind computed from the TLS cert we just shook hands on. |
| `SCRAM-SHA-256-PLUS` only | no | capability gap → libpq fallback | `-PLUS` over plaintext is not a thing; the server would reject us. |
| both | yes | **-PLUS** | Matches libpq's default. Strictly stronger than plain over the same cert; the only scenario where it differs from current behavior. |
| both | no | plain | No TLS → no cert → cbind makes no sense. |
| neither | n/a | capability gap → libpq fallback | Unchanged from Phase 1. |

The `use_scram_plus` flag is computed once when the mechanism list is parsed, before any `pg_scram_*` call.

---

## 5. Connect & Auth Data Flow (with `-PLUS`)

Driven by `native_drive_auth` on libev readiness, same event-loop contract as Phase 1:

1. (Pre-AUTH) TLS handshake completes via the existing `native_drive_ssl_handshake`. `myds->encrypted == true` and `myds->ssl != NULL`.
2. `R` (AuthenticationSASL, subtype 10) arrives. Parse the NUL-terminated mechanism list.
3. **Mechanism selection** per §4. Sets `use_scram_plus` and (if applicable) `pg_scram_set_cbind` with the cert digest blob. For -PLUS, the SCRAM state now has `cbind_input != NULL` and `cbind_flag == 'p'`.
4. `pg_scram_client_first` → `"p=tls-server-end-point,,n=,r=<nonce>"` (vs `"n,,n=,r=<nonce>"` for plain). `native_outbuf` gets the `SASLInitialResponse` (`'p'`, body = `"SCRAM-SHA-256-PLUS\0" + be32(len) + client-first`).
5. `R` (AuthenticationSASLContinue, subtype 11) → `pg_scram_client_final`. libscram reads server-first, derives the salted password, builds `client-final-without-proof` as `c=base64("p=tls-server-end-point,," || digest),r=<server_nonce>`, computes the proof HMAC against that `c=`, appends `,p=<proof>`. Send as `SASLResponse`.
6. `R` (AuthenticationSASLFinal, subtype 12) → `pg_scram_verify_server_final`. Same as plain.
7. AuthenticationOk → `native_st = PG_Native_Conn_St::STARTUP_TAIL`. Same as plain.

The only behavioral delta from the Phase 1 plain path is: the cbind flag in the gs2 header, the `c=` value, and the proof (because the proof depends on `c=` via the AuthMessage). Everything else is identical.

---

## 6. Edge Cases & Failure Handling

| Failure | Action |
|---|---|
| TLS not in use (`myds->encrypted == false`) | `-PLUS` not available; mechanism selection picks plain if offered, else capability gap. |
| `SSL_get_peer_certificate(myds->ssl) == NULL` (peer sent no cert — shouldn't happen on a verified TLS connection) | log once per backend; degrade to plain if also offered, else libpq fallback. |
| `X509_get_signature_info` returns an `mdnid` not in OpenSSL's digest table | log once per backend; degrade to plain if also offered, else libpq fallback. |
| Cert signed with MD5 or SHA-1 | Upgrade to SHA-256 per RFC 5929 §4.1. This is the *upgrade*, not a fallback. |
| Cert signed with SHA-2 family | Use that algorithm directly. |
| `X509_digest` returns 0 | log once per backend; degrade to plain if also offered, else libpq fallback. |
| cbind_input buffer too small for digest (impossible by construction — caller allocates 86 bytes, max digest is 64) | assert; native_teardown. |
| Server offers `-PLUS`-only and we don't have TLS | capability gap → native_capability_gap("SCRAM-SHA-256-PLUS only, no TLS"); libpq fallback. |
| Server offers `-PLUS`-only and TLS but our `pg_tls_server_end_point` fails | degrade to plain if also offered, else capability gap. |
| Server rejects our `-PLUS` auth (proof mismatch, c= mismatch) | tear down native, fall back to libpq, log once. The same path as the Phase 1 capability-gap fallback. |
| Server accepts `-PLUS` | silent. No log on the success path. |

The "log once per backend" pattern uses `static thread_local bool warned_no_cert_digest = false;` (or one bool per distinct failure class), mirroring `native_capability_gap` which already uses this idiom.

---

## 7. Testing Strategy

### 7.1 Unit: cert digest (`pg_tls_server_end_point`)

Add to `test/tap/tests/unit/pgsql_backend_auth-t.cpp`:
- Test 8: `pg_tls_server_end_point` on a self-signed SHA-256 cert produces the expected `SHA-256(DER(cert))` digest. The cert is generated in-test via `EVP_PKEY_keygen` + `X509_sign` so the test is self-contained. The expected digest is computed once and pinned.
- Test 9: `pg_tls_server_end_point` on an MD5-signed cert produces a SHA-256 digest (not the MD5 digest), per RFC 5929 §4.1 upgrade.
- Test 10: `pg_tls_server_end_point` with `ssl == NULL` returns -1.

### 7.2 Unit: cbind composition

Add to the same file:
- Test 11: `pg_scram_build_cbind_input_tls_server_end_point` with a known 32-byte digest produces a 54-byte buffer: `"p=tls-server-end-point,,"` || digest. Pinned via `memcmp`.
- Test 12: With a 64-byte digest, produces a 86-byte buffer. Pinned.

### 7.3 Unit: libscram patch sanity

Add to the same file, driving `ScramState` directly (bypassing the wrapper to test libscram's own behavior):
- Test 13: After `scram_state_set_cbind_input(state, "p=tls-server-end-point,,||digest", 22+digest_len)`, `build_client_first_message` emits `p=tls-server-end-point,,n=,r=<nonce>`. (The gs2 header changes.)
- Test 14: `build_client_final_message` with the same state emits `c=base64("p=tls-server-end-point,,"||digest),r=<server_nonce>,p=<proof>`. The `p=<proof>` is the HMAC(StoredKey, AuthMessage) where AuthMessage includes the new `c=`. We compute the expected proof independently (PBKDF2-HMAC-SHA-256 chain + HMAC) and compare.
- Test 15: Round-trip through the independent libscram server-side verifier (existing test pattern at `pgsql_backend_auth-t.cpp:106-165`) succeeds with the new cbind. This is the test that catches a miscomputed proof.

### 7.4 TAP: end-to-end (deferred to Phase 1b-B)

Current infra `docker-pgsql16-single` has:
```
host    all all all scram-sha-256    # non-TLS
hostssl all all all cert             # TLS, cert-auth
```
Neither is `-PLUS`-over-TLS. To exercise the e2e path requires either:
- (i) Extending the existing pg_hba.conf with a new `hostssl ... scram-sha-256` line (affects every legacy-g* test — explicitly warned against by the existing test header).
- (ii) A new fixture `test/infra/docker-pgsql16-single-scram-plus/` with its own pg_hba.conf, registered in `groups.json` under a new group like `pgsql-scram-plus-g1`. Isolated; correct architecture.

Option (ii) is the right call but is a sizeable PR of its own. For 1b-A, document the test plan and the infra gap in a follow-up issue; do not extend the existing infra in this PR.

What we *can* verify in 1b-A's TAP without new infra: the existing `pgsql-native_auth_differential-t` continues to pass (SCRAM-SHA-256 non-TLS, libpq oracle byte-equality, "no fallback" log-scrape). This proves the mechanism selection didn't regress the plain path. The new cbind code path is exercised by unit tests only.

---

## 8. Phasing

**1b-A — this PR (alongside the rest of native):**
1. libscram patch (§3.3, §3.4, §3.5, §3.6, §3.7).
2. `pg_tls_server_end_point` (§3.1).
3. `pg_scram_build_cbind_input_tls_server_end_point` (§3.2).
4. `pg_scram_set_cbind` wrapper (§3.8).
5. Mechanism-selection table in `native_drive_auth` (§3.9, §4).
6. Unit tests (7.1, 7.2, 7.3) — extend `pgsql_backend_auth-t.cpp`.
7. Existing `pgsql-native_auth_differential-t` continues to pass via `run-tests-isolated.bash` (proves the plain path isn't regressed).

**1b-B — follow-up PR:**
1. New fixture `test/infra/docker-pgsql16-single-scram-plus/` with `hostssl ... scram-sha-256`.
2. New TAP group `pgsql-scram-plus-g1` in `groups.json`.
3. Extend `pgsql-native_auth_differential-t` (or add a new test) to:
   - connect to the new fixture with TLS;
   - set `pgsql-use_native_backend_protocol='true'`;
   - run a query set; compare against libpq oracle;
   - assert no fallback warning appeared in the log;
   - assert the backend's mechanism list (via `R/10` payload captured in a proxy-side log) was `SCRAM-SHA-256-PLUS`.

---

## 9. Files Touched

### Created
- none

### Modified
- `deps/libscram/include/scram.h` — add `client_cbind_input` field + `scram_state_set_cbind_input` declaration
- `deps/libscram/src/scram.c` — field init, setter impl, `build_client_first_message` gs2 header selection, `build_client_final_message` c= composition, `free_scram_state` cleanup
- `include/PgSQL_Backend_Protocol.h` — declare `pg_tls_server_end_point`, `pg_scram_build_cbind_input_tls_server_end_point`, `pg_scram_set_cbind`
- `lib/PgSQL_Backend_Auth.cpp` — implement the three new functions; thread them through `PgSQL_Scram_State`
- `lib/PgSQL_Connection.cpp` — mechanism selection table; cbind call site in `native_drive_auth`
- `test/tap/tests/unit/pgsql_backend_auth-t.cpp` — add tests 8–15 (7.1, 7.2, 7.3)

### Not modified
- `test/tap/groups/groups.json` — no new entries in 1b-A
- `test/tap/tests/pgsql-native_auth_differential-t.cpp` — no changes in 1b-A; covered by 1b-B
- `include/PgSQL_Connection.h` — no new members; the existing `native_scram` already carries cbind state via libscram

---

## 10. Out of Scope

- Cancellation in native mode (`PQcancel` replacement, deferred since Phase 1).
- Materialize-on-feature overlay for cache/rewrite/firewall (Phase 2 remainder).
- Extended protocol / named portals (Phase 3).
- GSSAPI / SSPI auth (explicitly deferred in the design spec §2).
- Server-cert verification mode policy for the native TLS path: this PR doesn't change `native_ssl_mode`; the digester is called only when `native_ssl_requested && myds->encrypted`. The user's existing sslmode configuration governs whether the cert is trusted at all. SCRAM-PLUS is a *post*-trust check; it cannot rescue a TLS connection that has been configured not to verify.
- e2e TAP test for `-PLUS`: deferred to 1b-B (see §7.4).
