# COM_CHANGE_USER for `caching_sha2_password` clients (#4618) — design

## Intent

A client authenticated with `caching_sha2_password` (the MySQL 8 default) must be able
to run `COM_CHANGE_USER` (`mysql_change_user()`, connection-pool "reset by change
user") against ProxySQL, with the same outcome as a fresh connection by the target user.
Today it gets `ProxySQL Error: Access denied ... (using password: YES)` with a correct
password. A colleague reported it as a blocker; the client involved is unknown, so the
fix must cover every client behaviour, not one connector.

## How clients send COM_CHANGE_USER with `caching_sha2_password`

Two behaviours exist in the wild, and ProxySQL fails both:

| Client | Auth response in COM_CHANGE_USER | What ProxySQL does today |
|---|---|---|
| Oracle libmysqlclient (5.7/8.x), MariaDB Connector/C | **empty**; the plugin waits for the server to send a scramble | Auth Switch to `mysql_native_password` (#3504). Fails whenever native cannot verify the stored credential (`$A$` hash without cached clear text), and fails for the cases listed under *Reproduction* |
| Connector/J, Connector/Python, Rust `mysql_async`, ... | **inline 32-byte SHA-256 scramble**, computed against the nonce of the initial handshake | `verify_user_pass()` → hard-coded `ret = false` (`FIXME` referencing #4618). Always fails |

## Reproduction (before the fix)

Measured on `v3.0` @ `116e34f67`, `PROXYSQL31=1` debug build, `mysql84-g6` infra
(full table under *Test results*):

- **libmysqlclient 8.4** (empty auth data): clear-text and native-hash targets already
  work through the native switch — including the exact reproducer attached to the issue,
  which was written against 2024 code. A target stored as a `caching_sha2_password` hash
  (`$A$005...`) fails on every transport.
- **mysql-connector-python** (inline scramble): **every** correct-password case fails,
  whatever the stored format, transport, or `mysql-default_authentication_plugin`.
- Separate pre-existing bug found by the matrix: on a **compressed** connection, after any
  change-user Auth Switch completes (native included), the next command is rejected with
  `Unexpected packet from client ... Session_status: 5 , client_status: 0 Disconnecting
  it`. The client stream stays in `STATE_CLIENT_AUTH_OK`: the output path only moves it to
  `STATE_SLEEP` in its *uncompressed* branch (`mysql_data_stream.cpp`, "compression is
  enabled *after* the first OK").

## Tier: v3.1+ only (maintainer decision)

This fixes a long-standing bug, but it changes the authentication core, so it ships as
new behaviour in the Innovative tier and the Stable tier stays as it is: every change
(including the compression fix below) sits behind `#ifdef PROXYSQL31`, and both new
tests are tagged `@proxysql_min_version:3.1`. This is a deliberate exception to the
"correctness fixes are not confined to v3.1+" rule of `doc/agents/invariants.md` I-2,
decided by the maintainer on this PR. On v3.0 the limitation stays documented
(authentication-methods → Limitations).

Verified: with `PROXYSQL31` undefined, `lib/MySQL_Protocol.cpp` and
`lib/MySQL_Session.cpp` preprocess to the same token stream as `v3.0` (`497814d46`), once
line numbers and file paths are normalised. Re-checked on the merged result (`e1a7dc6c2`,
including items 6–8): the merge changes only `include/MySQL_Protocol.h`,
`lib/MySQL_Protocol.cpp` and `lib/MySQL_Session.cpp`, and with `PROXYSQL31` undefined
and comments removed, each one has the same tokens as its parent on `v3.0`.

## Decision

When the client names `caching_sha2_password` in `COM_CHANGE_USER` **and** ProxySQL
advertised `caching_sha2_password` in this connection's initial handshake
(`sent_auth_plugin_id`), ProxySQL answers with an **Auth Switch Request to
`caching_sha2_password`**, whatever auth data the client sent inline, and hands the
response to the normal handshake state machine (`process_pkt_handshake_response` →
`PPHR_1` → `PPHR_verify_password`).

That state machine already implements everything `caching_sha2_password` needs for a
fresh connection: fast auth against a clear-text or cached clear-text password (`0x01
0x03`), full auth (`0x01 0x04`) over TLS or the RSA key exchange (v3.1), stored `*`
(native) and `$A$` (sha2) hashes, the additional password, caching the clear text on
success. Reusing it means COM_CHANGE_USER authenticates **exactly like a fresh
connection** of the target user on the same transport — same successes, same failures,
same error messages. No new verification code.

When ProxySQL advertised `mysql_native_password` (`mysql-default_authentication_plugin
= mysql_native_password`), a fresh connection by a `caching_sha2_password` client is
switched to native (`PPHR_3`/`PPHR_4auth0`). COM_CHANGE_USER does the same: Auth Switch
to `mysql_native_password`, including when the client sent an inline sha2 scramble
(today that case is denied).

Everything else is unchanged: native and clear-text clients, empty stored passwords,
ed25519, SPIFFE/x509 policy, pass-through rejection, ClickHouse/admin sessions.

### Why an Auth Switch instead of verifying the inline scramble

- Libmysqlclient-style clients send no data, so a switch is needed anyway.
- Verifying inline data only works for clear-text (or cached) passwords; hashed passwords
  need full auth, which from the COM_CHANGE_USER entry point would need a second copy of
  the full-auth continuation. A switch reuses the one we have.
- The MySQL protocol explicitly allows the server to answer COM_CHANGE_USER with an Auth
  Switch Request, and every connector handles it (it is what MySQL does when the
  plugin differs).
- Cost: one extra round trip per COM_CHANGE_USER for inline-data clients. Accepted.

The switch reuses the connection's scramble (`scramble_buff`), as the existing native
switch does and as MySQL does for COM_CHANGE_USER. The RSA path also decrypts against
`scramble_buff`, so they stay consistent.

## Changes

1. **`MySQL_Protocol::process_pkt_COM_CHANGE_USER`** — after the existing gates (SPIFFE,
   x509 policy, pass-through, ed25519) and only when the stored password is non-empty
   and the session is MySQL/SQLite/DuckDB (the session types the handler accepts):
   - client plugin `caching_sha2_password` and `sent_auth_plugin_id ==
     AUTH_MYSQL_CACHING_SHA2_PASSWORD` → Auth Switch to `caching_sha2_password`;
   - client plugin `caching_sha2_password`, ProxySQL advertised native → Auth Switch to
     `mysql_native_password` (same as the existing `pass_len == 0` branch);
   - otherwise unchanged (`pass_len == 0` → native switch, else inline verification).

   Before sending the switch, reset the per-exchange auth state left over from the
   initial login: `switching_auth_stage = 0`, `auth_in_progress = 0`. Today a
   connection whose initial login did a full auth keeps `switching_auth_stage == 5`
   forever, which would make the sha2 state machine treat the scramble as a clear-text
   password.
2. **`MySQL_Protocol::PPHR_1`** — after an Auth Switch to `caching_sha2_password` the
   response is the raw 32-byte scramble (not NUL-terminated, like native), or a single
   `0x00` for an empty password. Accept both at stage 0; keep the NUL-terminated rule for
   the stage-5 clear-text response.
3. **`MySQL_Session::handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE`** — the
   final OK of a change-user Auth Switch is hard-coded to sequence id 3. With
   `caching_sha2_password` there are more packets in between (fast auth: OK is 4; full
   auth over TLS: 5; RSA: 7). Use `pkt_sid + 1`, which is what the initial handshake and
   the error path already use, for the `caching_sha2_password` switch. Keep 3 for the
   native switch to stay byte-identical there.
4. **`verify_user_pass()`** — the `caching_sha2_password` branch stays `ret = false`
   (fail closed); it becomes unreachable from COM_CHANGE_USER for MySQL sessions. Update
   the `FIXME` comment to say why.
5. **Compressed connections** (separate commit, pre-existing bug) — after a change-user
   Auth Switch succeeds, set the client stream to `STATE_SLEEP` directly instead of
   `STATE_CLIENT_AUTH_OK`. Compression was already negotiated at login, so the
   login-time "enable compression on the first OK" transition is not needed, and on an
   already-compressed connection it never fires. This matches the COM_CHANGE_USER path
   that needs no switch, which already sets `STATE_SLEEP`.
6. **zstd across Auth Switch packets** (added after review). Two things lost zstd:
   - Every reply packet of the auth exchange (the Auth Switch response, `caching_sha2`
     full auth, RSA) goes through `PPHR_SetConnAttrs`, which recomputes
     `options.compression_zstd` from `vars1`. On those packets `vars1` has the capabilities
     but no zstd fields, so zstd was turned off and ProxySQL answered a zstd client with
     zlib. Fix: `PPHR_keep_compression()` copies the zstd choice from the connection into
     `vars1` for every reply packet (end of `PPHR_1`, and the RSA decrypt path).
   - When the client's first login packet is answered with an Auth Switch,
     `PPHR_SetConnAttrs` does not run for that packet, so the client's zstd request was
     never recorded. This affected plain logins too, with no change-user involved: a zstd
     client offering `caching_sha2_password` against `mysql-default_authentication_plugin
     = mysql_native_password` lost the connection on its first query (ProxySQL logged
     `RECEIVED AN UNKNOWN COMMAND: 0`). Fix: `PPHR_2` stores `compression_zstd` and
     `zstd_compression_level` on the connection as soon as it parses the first packet.
7. **Pass-through re-check on the switch response** (added after review). The pass-through
   gate in `process_pkt_COM_CHANGE_USER` runs before the switch is sent. If the target row
   becomes pass-through eligible before the client answers (an admin `LOAD MYSQL USERS TO
   RUNTIME` in between), `PPHR_verify_password` would take the pass-through
   `empty_pw_case` / `unknown_user_case` path for a change-user. It now refuses that while
   `change_user_auth_switch` is set, with the same generic error as the up-front gate.
8. **`PPHR_1` without a session** (found by `protocol_unit-t` under ASAN). The stage-0 check
   for the raw sha2 scramble (item 2) read `(*myds)->sess` unconditionally, and the unit
   tests build a stream with no session. The check now looks at the stream's own state
   first and reads `sess` only when it is set.

## Goals

- Both client behaviours succeed with a correct password for every stored format the
  same transport would accept for a fresh connection.
- Wrong password → `1045 Access denied`, as today.
- Consecutive COM_CHANGE_USER on one connection keep working (no stale state).
- No change for clients using `mysql_native_password` / `mysql_clear_password`, or when
  `mysql-default_authentication_plugin = mysql_native_password` and the client sends
  empty data.

## Non-goals

- Accepting the inline scramble without a round trip (optimisation; can come later).
- A fresh nonce for the switch (MySQL and the native switch both reuse the scramble).
- COM_CHANGE_USER for pass-through users or SPIFFE sessions (explicitly rejected today;
  item 7 keeps it rejected when the target becomes pass-through mid-switch).
- Fixing the zstd problems of item 6 on the Stable tier. They exist there too, but every
  change here is v3.1+ only (see *Tier*).
- `max_connections` accounting on COM_CHANGE_USER (existing `FIXME`, separate issue).

## Anti-goals

- Accepting a COM_CHANGE_USER that a fresh connection by the same user on the same
  transport would reject (e.g. a `$A$` hash on a plain connection without the RSA key
  exchange). Weakening authentication is never an acceptable way to make the test pass.

## Behaviour change to call out

With `mysql-default_authentication_plugin = caching_sha2_password`, a libmysqlclient
client using `caching_sha2_password` that changes to a user whose password is stored as a
native `*` hash used to get a native Auth Switch (one round trip, no TLS needed). It now
gets a `caching_sha2_password` switch, which for a `*` hash requires full authentication:
TLS, or the RSA key exchange (v3.1+, and the client must request the key). On a plain
v3.0 connection without cached clear text this now fails — exactly as a fresh connection
by that user already fails there. *Builder's call:* accepted in favour of "change user
behaves like connect"; easy to revisit by keeping native for `*` hashes on plain
connections without an RSA key.

## Tests

- `reg_test_4618-change_user_caching_sha2_libmysql-t` (C++, Oracle libmysqlclient 8.4,
  empty-data behaviour): stored clear/native/sha2 × TLS / plain+RSA / plain without key,
  wrong password, consecutive change-user, default plugin native, and zlib and zstd
  compression for each of: sha2 default + sha2 hash, sha2 default + clear text, native
  default + clear text (38 assertions). Each run uses its own account names
  (`cu4618_<pid>_*`) and saves and restores `mysql-default_authentication_plugin`,
  `mysql-have_ssl` and `mysql-have_compress` (in-memory and runtime values).
- `reg_test_4618-change_user_caching_sha2_inline-t.py` (mysql-connector-python pure,
  inline-scramble behaviour): stored clear/native/sha2 over TLS, clear over plain, wrong
  password, default plugin native. Accounts are `cu4618i_<pid>_*`, and the wrong-password
  case counts only a 1045 that comes from `cmd_change_user()`, not a setup failure.
- Existing: `reg_test_3504-change_user-t` (native/clear/sha2 clients with default native),
  `test_auth_methods-t`, `test_ed25519_auth-t`, `reg_test_5988-caching_sha2_rsa-t`.

## Test results

`mysql84-g6`, `PROXYSQL31=1` debug build. "before" = `v3.0` @ `116e34f67`, "after" = this
branch.

`reg_test_4618-change_user_caching_sha2_libmysql-t` (correct-password assertions; every
wrong-password assertion was already rejected before and still is):

| default plugin | stored | transport | before | after |
|---|---|---|---|---|
| caching_sha2 | clear | TLS / plain+RSA / plain | ok | ok |
| caching_sha2 | native `*` | TLS / plain+RSA | ok | ok |
| caching_sha2 | sha2 `$A$` | TLS | **Access denied** | ok |
| caching_sha2 | sha2 `$A$` | plain+RSA | **Access denied** | ok |
| caching_sha2 | sha2 `$A$` | plain, no key | rejected (expected) | rejected (expected) |
| caching_sha2 | native `*` | plain, no key | ok (native switch) | rejected — the behaviour change above (added after the red run) |
| caching_sha2 | sha2 `$A$` | TLS + compression | **Access denied** | ok |
| caching_sha2 | clear | TLS + compression | **disconnected on next query** | ok |
| caching_sha2 | sha2 `$A$` / clear | TLS + zstd | not measured | ok |
| native | clear | TLS + zlib / zstd | not measured | ok |

The zstd and native-compressed rows were added after review and were not run against
`v3.0`. During development, before item 6, native + zstd failed with `Lost connection`
(ProxySQL: `RECEIVED AN UNKNOWN COMMAND: 0`); the same login reproduced with the `mysql`
CLI (`--compression-algorithms=zstd --default-auth=caching_sha2_password` against
`mysql-default_authentication_plugin = mysql_native_password`), without any change-user.
| native | clear / native `*` | TLS / plain | ok | ok |
| consecutive change-user (sha2 → clear → source → sha2) | | TLS / plain+RSA | **fail** | ok |

`reg_test_4618-change_user_caching_sha2_inline-t` (mysql-connector-python 9.7.0,
pure): before, 6/6 correct-password cases **Access denied**; after, 12/12 ok.
