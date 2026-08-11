# Client-Pinned caching_sha2_password RSA Key Design

## Purpose

Extend ProxySQL's `caching_sha2_password` RSA full-authentication support so a
non-TLS Oracle MySQL client configured with `--server-public-key-path` can send
its RSA-encrypted password directly after ProxySQL's `0x04` full-authentication
challenge. The existing `--get-server-public-key` exchange remains supported
without behavior changes.

## Product tiers

- The extension is available only when `PROXYSQL31` is compiled in.
- ProxySQL 3.1 enables it directly.
- ProxySQL 4.0 inherits it because `PROXYSQL40=1` implies `PROXYSQL31=1`.
- ProxySQL Stable 3.0 must not expose or execute the new path. Stable product
  objects must not contain new helper names or diagnostics introduced by this
  work, and existing Stable authentication behavior must remain unchanged.
- The focused integration test remains registered with
  `@proxysql_min_version:3.1` and therefore does not run against Stable 3.0.

## Current behavior

ProxySQL currently supports the key-request form of MySQL RSA authentication:

1. ProxySQL sends `AuthMoreData{0x04}` to request full authentication.
2. The client sends the one-byte public-key request `0x02`.
3. ProxySQL acquires an immutable RSA key snapshot, sends its PEM public key,
   and advances to authentication stage 6.
4. The client encrypts its password with that key and returns the ciphertext.
5. ProxySQL validates and decrypts the ciphertext, then reuses the existing
   stage-5 cleartext password verifier.

With `--server-public-key-path`, the client already has a public key and skips
step 2. Its ciphertext therefore arrives while ProxySQL is in stage 5. The
current non-TLS stage-5 guard rejects every packet other than `0x02`, so the
valid ciphertext never reaches RSA decryption.

## Approaches considered

### Capture the key when ciphertext arrives

This is the smallest source change and naturally covers every caller that can
initiate full authentication. It is not selected because a concurrent key
reload between the `0x04` challenge and the response could select a different
private key from the one active when the exchange began.

### Add a dedicated pinned-key protocol stage

This makes the source of ciphertext explicit but creates an artificial extra
state. The pinned-key client sends its ciphertext as the direct response to
the existing full-authentication challenge, so no additional network stage is
present to model.

### Capture at the full-authentication challenge and share decryption

This is the selected approach. It preserves one immutable key snapshot across
the complete authentication exchange and routes both ciphertext forms through
one security-sensitive decryption implementation.

## Protocol design

When ProxySQL successfully generates the `0x04` full-authentication packet for
a non-TLS `caching_sha2_password` exchange, it acquires and stores the current
immutable RSA snapshot on `MySQL_Protocol`. Both active challenge producers
must do this:

- `MySQL_Protocol::PPHR_sha2full()` for a configured frontend user; and
- `MySQL_Protocol::PPHR_passthrough_init()` for pass-through authentication.

Snapshot acquisition and all new dispatch/decryption code are enclosed in
`#ifdef PROXYSQL31`. TLS authentication does not acquire an RSA snapshot.

After stage 4 advances to stage 5, a non-TLS caching-SHA2 response is handled
as follows:

1. An exact one-byte `0x02` payload is the existing key-request form. ProxySQL
   serves the public key from the snapshot captured at the `0x04` challenge,
   advances to stage 6, and waits for ciphertext.
2. Any other payload is treated as a candidate direct RSA response. ProxySQL
   requires an available snapshot and requires the payload length to equal the
   snapshot's RSA ciphertext size before invoking OpenSSL decryption.
3. Successful decryption restores stage 5 and populates the existing sensitive
   password fields. Existing configured-user or pass-through verification then
   determines the authentication result.
4. No non-TLS stage-5 packet is ever interpreted as cleartext.

The stage-6 response used by `--get-server-public-key` and the direct stage-5
response used by `--server-public-key-path` call one private
`MySQL_Protocol` decryption helper. The helper consumes and resets the retained
snapshot, validates exact ciphertext length, calls the existing
`MySQL_Caching_Sha2_RSA::decrypt_password()`, marks the recovered allocation as
sensitive, and prepares the existing verifier inputs. It does not log either
ciphertext or recovered cleartext.

## Key lifecycle and rotation

The connection retains the snapshot that was active when ProxySQL emitted the
full-authentication challenge. A concurrent `LOAD MYSQL VARIABLES TO RUNTIME`
may publish a new snapshot without invalidating the in-flight exchange.

A client-pinned public key must correspond to the configured ProxySQL private
key. A stale or unrelated public key produces ciphertext that the retained
private key cannot decrypt and authentication fails. Operators must distribute
a replacement public key to pinned clients as part of a coordinated rotation.
There is no fallback to a different or newer key and no downgrade to cleartext.

The snapshot is reset after a ciphertext response is consumed and by the
existing protocol initialization path. Error exits must not retain recovered
password material.

## Failure behavior

- No RSA snapshot: fail with the existing RSA-unavailable `1045` behavior and
  TLS-or-key guidance.
- Wrong-size payload: reject before OpenSSL decryption with normal access
  denied behavior.
- OAEP failure, stale key, malformed plaintext, or wrong password: fail with
  normal `1045` / `28000` access denied without disclosing which validation
  failed.
- Allocation failure: terminate authentication without exposing sensitive
  data.
- A one-byte payload other than `0x02` remains invalid; it is never accepted as
  a password.
- TLS cleartext full authentication and empty-password handling remain
  unchanged.

## Test design

Extend `test/tap/tests/reg_test_5988-caching_sha2_rsa-t.cpp`; do not create a
second fixture with duplicate RSA configuration. Replace the helper's Boolean
key-request argument with an explicit client key mode:

- no key option;
- `--get-server-public-key`; or
- `--server-public-key-path=<generated-public-key>`.

The generated public key is already written beneath `REGULAR_INFRA_DATADIR`,
which is shared with the isolated test runner and already used by the fixture
for cleanup. The test must confirm that the installed Oracle MySQL CLI exposes
`server-public-key-path` before running the matrix.

Add two assertions:

1. A non-TLS client with the generated public key and correct password connects
   successfully without requesting the key from ProxySQL.
2. The same pinned-key flow with a wrong password fails with MySQL error 1045.

Keep all existing assertions for no-key rejection, requested-key success,
wrong-password rejection, unavailable keys, grouped variable rollback,
internal-session password redaction, and cleanup. The focused test continues
to use a local OK query rule and therefore remains backend-independent.

## Documentation

Update `doc/caching_sha2_password_rsa.md` to show both client forms. Explain
that `--get-server-public-key` obtains the currently active key during the
connection, while `--server-public-key-path` relies on an operator-distributed
key and requires coordinated rotation. Continue recommending TLS because RSA
password encryption alone does not provide transport integrity or protect the
rest of the session.

## Verification

Verification must start from clean objects whenever the tier changes.

For Innovative 3.1:

- build a clean DEBUG binary and all relevant TAP binaries with
  `PROXYSQL31=1`;
- observe the new pinned-key assertions fail before production changes;
- pass the complete #5988 test after implementation;
- pass the caching-SHA2 RSA unit and protocol unit tests;
- pass relevant pass-through, COM_CHANGE_USER, and authentication regression
  tests.

For Stable 3.0:

- build a clean default DEBUG binary;
- verify the changed production objects contain none of the new helper or
  diagnostic symbols;
- pass existing authentication and COM_CHANGE_USER regressions.

For 4.0:

- build a clean DEBUG binary with `PROXYSQL40=1`;
- run the focused #5988 integration test and confirm both RSA client forms are
  available.

Finally run repository formatting/lint checks and `git diff --check`.

## Non-goals

- Changing RSA key formats, generation, variable names, or cluster transport.
- Adding a new public-key configuration option to ProxySQL.
- Supporting additional client drivers in this change.
- Allowing cleartext caching-SHA2 passwords over non-TLS connections.
- Changing TLS, SPIFFE, X.509 policy, or COM_CHANGE_USER semantics.
- Backporting any part of this behavior to ProxySQL Stable 3.0.
