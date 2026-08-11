# Ed25519 Authentication for MySQL Client Connections — Design

**Date:** 2026-08-11
**Status:** Approved
**Tier:** v3.1+ (`PROXYSQL31`)

## Goal

Support MariaDB's ed25519 authentication scheme (`client_ed25519` client plugin /
`auth_ed25519` server plugin) on both sides of ProxySQL:

- **Frontend**: MySQL/MariaDB clients authenticate to ProxySQL using `client_ed25519`.
- **Backend**: ProxySQL authenticates to MariaDB backends whose users are defined
  `IDENTIFIED VIA ed25519`.

Oracle MySQL has no ed25519 plugin; this is a MariaDB-ecosystem feature.

## Background and key constraint

MariaDB ed25519 is challenge–response: the server sends a 32-byte scramble, the
client returns a 64-byte Ed25519 signature over it, and the server verifies the
signature against a stored public key (43-char base64 in
`mysql.user.authentication_string`).

Key derivation is a MariaDB variant of Ed25519: the secret expansion is
`az = SHA512(password)` where the password is arbitrary-length (standard Ed25519
hashes a fixed 32-byte seed). Consequences:

- Signature **verification** is standard Ed25519 verify.
- Deriving the public key from a cleartext password requires ref10-style
  `ge_scalarmult_base`, which OpenSSL's EVP API does not expose.
- **ProxySQL can never learn the cleartext password from the handshake**, and a
  signature cannot be replayed to a backend (different scramble). This makes
  ed25519 fundamentally incompatible with passthrough-auth learning.

Current frontend auth supports exactly three plugins hard-coded at
`lib/MySQL_Protocol.cpp:91` (`mysql_native_password`, `mysql_clear_password`,
`caching_sha2_password`). Backend auth is delegated entirely to the vendored
MariaDB Connector/C, which already contains the full ref10 Ed25519 implementation
and a `client_ed25519` plugin — currently built DYNAMIC and not shipped.

## Approach (chosen: ref10 reuse)

Reuse the connector's public-domain ref10 sources as the single crypto path for
both public-key derivation and signature verification. Alternatives rejected:

- *OpenSSL verify + ref10 derive*: two crypto paths, ref10 still required.
- *libsodium*: new vendored dependency, and its `crypto_sign` API uses standard
  seed derivation, so the MariaDB variant would still need hand-rolling.

## 1. Build & feature gating

- New feature macro **`PROXYSQLED25519`**, implied by `PROXYSQL31` (same Makefile
  pattern as `PROXYSQLFFTO`/`PROXYSQLTSDB`). All frontend ed25519 code is guarded
  by `#ifdef PROXYSQLED25519`.
- **Crypto sources**: the connector patch (§4) flips `client_ed25519` from
  DYNAMIC to STATIC, pulling the ref10 objects (`sign.c`, `open.c`, `keypair.c`,
  `ge_*.c`, `fe_*.c`, `sc_*.c`) into `libmariadbclient.a`, which ProxySQL already
  links. Preferred: call those symbols directly from a thin wrapper —
  `lib/MySQL_Ed25519.cpp` + `include/MySQL_Ed25519.h` — exposing exactly:
  - `derive_public_key(const char *password, size_t len, uint8_t out[32])`
  - `verify(const uint8_t sig[64], const uint8_t scramble[32], const uint8_t pubkey[32]) → bool`

  Fallback if symbol naming/visibility is unusable: compile the ref10 `.c` files
  into `libproxysql.a` via a `lib/Makefile` rule, sourcing them from `deps/`
  (no file copying).
- **Accepted asymmetry**: `deps/` builds are not tier-parameterized, so the
  STATIC connector patch applies to every tier. Backend ed25519 therefore works
  passively even in stable 3.0 builds (zero ProxySQL code involved); frontend
  ed25519 is 3.1+ only. Making deps tier-aware was rejected — the build system
  does not support it.

## 2. Credential storage in `mysql_users.password`

Runtime format detection, extending the existing chain (`*<40 hex>` → SHA1
native, `$A$0…` length 70 → caching_sha2):

| Stored format | Detection | Capability |
|---|---|---|
| `$ED$<43-char base64>` (47 chars) | `strncasecmp(password, "$ED$", 4) == 0` | Frontend verification only |
| cleartext (no known-hash format match) | existing fallthrough | Frontend verification **and** backend ed25519 auth |

- The base64 payload is MariaDB's encoding of the 32-byte public key; migration
  from MariaDB = prefix the `authentication_string` value with `$ED$`.
- A bare 43-char base64 string is **not** auto-detected (indistinguishable from a
  legitimate cleartext password); the prefix is mandatory.
- Dual-password (PRIMARY/ADDITIONAL) works for both formats: the verify loop
  retries against the additional credential, mirroring the existing retry at
  `lib/MySQL_Protocol.cpp:3654`.
- Derived public keys are computed per-auth (one SHA512 + one scalar mult;
  microseconds). No caching in v1.

## 3. Frontend protocol flow

- **Greeting unchanged.** `mysql-default_authentication_plugin` keeps its two
  allowed values (`mysql_native_password`, `caching_sha2_password`). ed25519
  cannot be advertised in the initial handshake: the greeting carries a
  20+1-byte scramble while ed25519 signs a 32-byte challenge. MariaDB itself
  always routes ed25519 through an Auth Switch. Flow:

  ```
  greeting (native|sha2) → HandshakeResponse
    → AuthSwitchRequest "client_ed25519" + 32-byte scramble
    → 64-byte signature → OK / ERR
  ```

- **Plugin registry**: `plugins[]` grows to 4 with `"client_ed25519"`; new enum
  value `AUTH_MYSQL_ED25519 = 3` in `include/MySQL_Protocol.h:36`. `PPHR_3`
  recognizes the name; the switch matrix in `process_pkt_handshake_response`
  gains the new row.
- **Switch policy** — ProxySQL switches the client to ed25519 when:
  1. the stored credential is `$ED$…` (mandatory — only verifiable scheme), or
  2. the client's HandshakeResponse explicitly requested `client_ed25519` and a
     usable credential exists (cleartext or `$ED$`).

  All other combinations keep existing behavior (switch to native, etc.).
- **Verification**: response must be exactly 64 bytes (enforced via the
  `auth_response_has` bounds pattern); standard Ed25519 verify of the 32-byte
  scramble against the stored or derived public key.
- **Scramble storage**: the switch machinery currently assumes 20-byte
  scrambles; the ed25519 path stores its 32-byte challenge on the data stream
  alongside the existing `switching_auth_*` state
  (`include/MySQL_Data_Stream.h:175`). Generated with OpenSSL `RAND_bytes`.
- **COM_CHANGE_USER**: supported via the existing auth-switch-in-change-user
  machinery (`lib/MySQL_Protocol.cpp:1829-1840`) extended with an ed25519 branch
  in `verify_user_pass`. The caching_sha2 change-user limitation (#4618) is not
  reproduced — ed25519's switch flow has no RSA/TLS sub-protocol.
- **Interactions**:
  - TLS not required: the signature never exposes a secret (unlike
    clear/sha2-cleartext paths). No `CLIENT_SSL` forcing.
  - LDAP `clear_password` selection logic untouched.
  - **Passthrough auth is incompatible by construction** (no replay, no
    cleartext learning). When a user authenticates via ed25519, passthrough
    learning is skipped. Documented.

## 4. Backend connections

- Single change: in `deps/mariadb-client-library/plugin_auth_CMakeLists.txt.patch`,
  add `client_ed25519` to the DYNAMIC→STATIC flips (joining `caching_sha2_password`,
  `sha256_password`, `mysql_clear_password`). The connector then answers a
  MariaDB server's ed25519 auth switch transparently using `userinfo->password`.
  No `MYSQL_DEFAULT_AUTH` plumbing; no changes to `lib/mysql_connection.cpp`.
- Applies everywhere the connector is used: backend pools, Monitor (an ed25519
  monitor user works with a cleartext `mysql-monitor_password`), cluster sync.
- **`$ED$`-only users on the backend**: the connector would send the literal
  `$ED$…` string as the password and fail. On first such failure ProxySQL logs
  one explicit warning — "user X has an ed25519 public-key-only credential;
  backend authentication requires the cleartext password" — instead of generic
  access-denied noise. `$ED$` storage is documented as frontend-verification-only.

## 5. Admin & observability

- **No new admin variables.** The feature is driven entirely by credential
  format and client plugin choice.
- On `LOAD MYSQL USERS TO RUNTIME`, a `$ED$` password with malformed base64 or
  wrong length produces a load-time warning in the error log; the user still
  loads, and every auth attempt fails cleanly with access-denied.
- The auth-event JSON dump in `lib/mysql_data_stream.cpp:1936` gains the new
  plugin name.

## 6. Error handling

- Wrong signature, malformed response length (≠ 64 bytes), or undecodable stored
  key → standard `ER_ACCESS_DENIED_ERROR` (1045), byte-identical message to a
  wrong password. No information distinguishing "bad key format" from "wrong
  password" leaks to the client.
- Derived key material wiped with `OPENSSL_cleanse` following the existing
  `cleanse_and_free_password` idiom.

## 7. Testing & documentation

- **Unit tests** (`test/tap/tests/unit/`, harness per
  `doc/agents/project-conventions.md`): known-answer vectors from the MariaDB
  test suite — password → public-key derivation, valid/invalid signature
  verification, `$ED$` parsing edge cases (bad base64, wrong length, prefix
  case-insensitivity).
- **End-to-end TAP** on `infra-mariadb10` (backend installs `auth_ed25519` via
  `INSTALL SONAME`): new `test_ed25519_auth-t.cpp` covering:
  - cleartext-stored user: frontend ed25519 + backend ed25519, through to query
    execution;
  - `$ED$`-stored user: frontend OK, backend fails with the documented warning;
  - wrong password / bad signature → 1045;
  - additional-password retry;
  - `COM_CHANGE_USER` to and from an ed25519 user;
  - non-ed25519 client connecting as an `$ED$` user (switched, or denied if the
    client lacks the plugin).

  Test binaries link the vendored connector, which after the STATIC patch speaks
  `client_ed25519` natively — no external client needed.
- **Docs**: `doc/ed25519_authentication.md` following the structure of
  `doc/caching_sha2_password_rsa.md` — formats, migration from MariaDB, backend
  behavior, passthrough incompatibility, tier availability.

## Out of scope (explicit)

- MariaDB PARSEC (11.6+ default auth scheme).
- Advertising ed25519 in the initial handshake / new values for
  `mysql-default_authentication_plugin`.
- PostgreSQL frontend/backend.
- Caching of derived public keys.
- Making `deps/` builds tier-aware.
