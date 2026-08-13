# MariaDB ed25519 Authentication

ProxySQL supports MariaDB's ed25519 authentication scheme
(`client_ed25519` client plugin / `auth_ed25519` server plugin) on both
sides of the proxy.

## Availability

| Side | Tier | Mechanism |
|------|------|-----------|
| Backend (ProxySQL → MariaDB) | all tiers | The bundled MariaDB Connector/C links `client_ed25519` statically and answers the server's auth switch transparently. |
| Frontend (client → ProxySQL) | v3.1+ (`PROXYSQL31`) | ProxySQL verifies `client_ed25519` signatures itself. |

Oracle MySQL has no ed25519 plugin; this is a MariaDB-ecosystem feature.

## Credential formats in `mysql_users.password`

| Format | Example | Frontend auth | Backend auth |
|--------|---------|---------------|--------------|
| cleartext | `my_password` | yes (key derived on the fly) | yes (connector signs with it) |
| `$ED$` + 43-char base64 public key | `$ED$ZIgUREUg5PVgQ6LskhXmO+eZLS0nC8be6HPjYWR4YJY` | yes (signature verified against the key) | **no** — the password is unknown |

The `$ED$` payload is exactly the value MariaDB stores in
`mysql.user.authentication_string` for an ed25519 user — to migrate,
prefix it with `$ED$`. The prefix is case-insensitive and mandatory: a
bare 43-character string is treated as a cleartext password.

A malformed `$ED$` value (wrong length or invalid base64) logs a warning
at `LOAD MYSQL USERS TO RUNTIME` time and every authentication attempt
for that user fails with the standard access-denied error.

## Protocol behavior

ed25519 is never advertised in the initial handshake (its challenge is
32 bytes; the greeting scramble is 20). ProxySQL sends an
`AuthSwitchRequest` naming `client_ed25519` with a fresh 32-byte nonce
whenever:

- the stored credential is `$ED$…` (whatever plugin the client offered), or
- the client explicitly requested `client_ed25519` and the stored
  credential is cleartext or `$ED$`.

The client answers with a 64-byte signature. This mirrors MariaDB's own
behavior, so any client able to authenticate against MariaDB ed25519
works unchanged. `COM_CHANGE_USER` into an ed25519 user is supported via
the same auth-switch mechanism.

TLS is not required: the exchange never transmits a secret.

**Frontend ed25519 requires `mysql-default_authentication_plugin=mysql_native_password`**
(this is ProxySQL's built-in default, so no change is needed unless it was
overridden). If it is set to `caching_sha2_password` instead, ProxySQL
advertises `caching_sha2_password` in its initial handshake greeting, and an
ordinary client — one that has not explicitly requested `client_ed25519` —
switches early to `caching_sha2_password` before ProxySQL has a chance to
route it into the ed25519 exchange. On that early-switch path, a `$ED$`
stored user is denied unconditionally (see Limitations below): it never
reaches the ed25519 verification code at all.

## Upgrading from 3.0

The `$ED$` prefix becomes reserved as of this feature: any stored
`mysql_users.password` value that literally begins with `$ED$` is now
parsed as an ed25519 credential, never compared as cleartext. The
reservation is **case-insensitive** — `$ed$`, `$Ed$` and `$eD$` count too
(matching how ProxySQL already detects the `$A$0` caching_sha2 format
case-insensitively). If an
existing 3.0 deployment happens to have a cleartext password that starts
with those four characters in any case combination (coincidental, but
possible), that account stops authenticating after the upgrade — this is
fail-closed by design (human-approved: silently falling back to cleartext
comparison for an unparseable "$ED$..." value was judged more dangerous
than a hard failure). ProxySQL warns once at `LOAD MYSQL USERS TO
RUNTIME` time for a malformed `$ED$` value, and once per user when a
backend connection is attempted with a `$ED$` credential. Fix by renaming
the credential to not start with `$ED$`, or by re-issuing it as a proper
`$ED$<public-key>` ed25519 credential if that was the intent.

## Limitations

- `$ED$` (public-key-only) users cannot open backend connections: the
  signature scheme is not replayable and the cleartext is unknown.
  ProxySQL logs an explicit warning when such a user's backend
  connection fails. Store the cleartext password for full functionality.
- Pass-through authentication (`mysql-passthrough_auth_*`) cannot learn
  credentials from an ed25519 exchange, by construction.
- If a client triggers an early switch to `mysql_native_password`
  (e.g. it offered `caching_sha2_password` against a native greeting),
  a stored-`$ED$` user cannot be verified on that connection — the
  MySQL protocol allows a single auth switch. Standard MariaDB clients
  do not hit this.
- A `$ED$` public key stored as the *additional* password (the
  `additional_password` attribute) while the primary credential is an
  ordinary password requires the client to explicitly request
  `client_ed25519` (e.g. `--default-auth=client_ed25519`). ProxySQL
  decides the auth switch from the primary credential and the client's
  requested plugin; it deliberately does not force every client of such
  an account through ed25519, because that would break clients without
  the `client_ed25519` plugin whose primary credential is perfectly
  valid.
- MariaDB PARSEC (11.6+) is not supported.
