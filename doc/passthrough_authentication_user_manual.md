# Pass-Through Authentication — User Manual

> **Availability:** Pass-through authentication is a feature of the ProxySQL
> **Innovative tier (3.1.x)** and **AI/MCP tier (4.0.x)**, from 3.1.10 / 4.0.10
> onward. The code ships in the **Stable tier (3.0.x)** as well, but it
> **cannot be enabled there** — on a Stable build, setting
> `mysql-passthrough_auth_enabled=true` is refused at
> `LOAD MYSQL VARIABLES TO RUNTIME` (forced back to `false` with a log message).
> Use a 3.1.x or 4.0.x build to enable it.
> **Scope:** MySQL protocol only. PostgreSQL is not affected.
> **Status:** Phase 1 (`caching_sha2_password` only). Disabled by default.
>
> For the exhaustive list of variables, tables, commands, and error
> behavior, see the companion
> [Pass-Through Authentication — Reference Manual](passthrough_authentication_reference.md).

---

## 1. What pass-through authentication is

Normally a MySQL client cannot authenticate *through* ProxySQL unless the user is
provisioned in `mysql_users` **with a usable password** — either cleartext or a
hash ProxySQL can match. That forces an out-of-band step on every deployment:
someone must export passwords from the database and load them into ProxySQL
before the proxy can serve traffic.

**Pass-through authentication removes that step.** When ProxySQL does not have a
password for a user, it borrows the cleartext password the client sends during
the standard `caching_sha2_password` *full-auth* exchange, uses it to open a
connection to a backend, and — if the backend accepts it — lets the client in and
**caches the learned credential in memory** so later connections are validated
locally without another backend round-trip.

Key properties:

- **ProxySQL never writes to `mysql_users`.** Learned credentials live only in a
  separate in-memory cache. `mysql_users` remains admin-managed.
- **The cache is in-memory only.** A restart starts cold and warms up again as
  clients reconnect. It is not persisted and not synchronized across a cluster.
- **The backend is the source of truth.** ProxySQL does not decide whether a
  password is correct — it hands the credential to a backend and uses the
  backend's `OK`/`ERR` as the verdict.

### When to use it

- You want ProxySQL in front of a database **without pre-loading every user's
  password** into `mysql_users`.
- Your applications already authenticate with `caching_sha2_password` (the
  default for MySQL 8.0+ clients and connectors).
- You can require **TLS** between clients and ProxySQL (strongly recommended, and
  the default).

### When *not* to use it

- Your clients use `mysql_native_password` — **not supported** in Phase 1 (the
  cleartext password is never available to ProxySQL for that plugin).
- You rely on `mysql_users` rows with an **empty password** to allow *passwordless*
  login — enabling pass-through changes that behavior (see §4).
- You cannot enforce TLS and cannot accept sending a cleartext password over a
  plaintext link. (Non-TLS pass-through via RSA public key is deferred to a later
  phase.)

---

## 2. Prerequisites

1. **Client plugin must be `caching_sha2_password`.** Pass-through is only engaged
   for clients that authenticate with `caching_sha2_password`. This is the default
   in MySQL 8.0+ `mysql` clients, Connector/J, Connector/Python, Go drivers, etc.
   Make sure ProxySQL advertises it so clients select it — set:
   ```sql
   SET mysql-default_authentication_plugin='caching_sha2_password';
   LOAD MYSQL VARIABLES TO RUNTIME;
   ```
2. **TLS from client to ProxySQL** (default requirement). With
   `mysql-passthrough_auth_require_tls=true` (the default), ProxySQL refuses to run
   the full-auth exchange on a non-TLS frontend connection. Configure ProxySQL's
   frontend TLS as usual and have clients connect with SSL enabled.
3. **A reachable backend in the probe hostgroup.** For unknown users, the probe
   targets `mysql-passthrough_default_hg`; for empty-password rows, it targets that
   user's `default_hostgroup`. The hostgroup must have a healthy server.

---

## 3. The two modes

Pass-through has **one master switch** and **two independent modes**. The master
switch must be on for either mode to take effect.

| Mode | Trigger | Gate variable | Default |
|---|---|---|---|
| **Empty-password row** | A row exists in `mysql_users` with `password=''` | `mysql-passthrough_auth_empty_password` | `true` |
| **Unknown user** | No row exists in `mysql_users` for the username | `mysql-passthrough_auth_unknown_users` | `false` |

Master switch: `mysql-passthrough_auth_enabled` (default `false`).

- In **empty-password mode**, you list the users you want to allow in
  `mysql_users` (with an empty password) and set their `default_hostgroup`,
  `max_connections`, etc. as usual. This is the safer, explicit-allowlist mode.
- In **unknown-user mode**, *any* username the client presents is eligible (subject
  to the allowlist and rate limits). This is powerful but expands the
  credential-stuffing surface — keep it off unless you need it, and always pair it
  with `mysql-passthrough_auth_username_pattern` (see §6).

---

## 4. Important behavior change: empty-password rows

In stock ProxySQL, a `mysql_users` row with `password=''` permits **passwordless
login** — a client sending no password is accepted.

When **both** `mysql-passthrough_auth_enabled=true` **and**
`mysql-passthrough_auth_empty_password=true`, an empty-password row is reinterpreted
as a **pass-through signal only**. Clients must now send a password, which ProxySQL
probes against the backend. Passwordless login for those rows no longer works.

This is a deliberate, gated change. If you depend on passwordless login for some
accounts, **do not enable the empty-password gate** (or keep the master switch
off).

---

## 5. Quick start

### 5.1 Empty-password mode (explicit allowlist)

```sql
-- 1) Advertise caching_sha2_password so clients use it
SET mysql-default_authentication_plugin='caching_sha2_password';

-- 2) Turn on pass-through, empty-password mode (unknown-users stays off)
SET mysql-passthrough_auth_enabled='true';
SET mysql-passthrough_auth_empty_password='true';
SET mysql-passthrough_auth_unknown_users='false';
SET mysql-passthrough_auth_require_tls='true';       -- default; keep it on
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;

-- 3) Allow specific users by adding empty-password rows and routing them
INSERT INTO mysql_users (username, password, default_hostgroup)
VALUES ('appuser', '', 10);
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
```

Now `appuser` can connect through ProxySQL over TLS with its **real backend
password**. On the first connect ProxySQL probes hostgroup 10; on success it
serves the session and caches the credential. Subsequent connects are validated
from the cache.

### 5.2 Unknown-user mode (no `mysql_users` row)

```sql
SET mysql-default_authentication_plugin='caching_sha2_password';
SET mysql-passthrough_auth_enabled='true';
SET mysql-passthrough_auth_unknown_users='true';

-- REQUIRED for safety: bound which usernames may be probed
SET mysql-passthrough_auth_username_pattern='^(app|svc)_[a-z0-9]+$';

-- Where unknown users are routed / default schema
SET mysql-passthrough_default_hg=10;
SET mysql-passthrough_default_schema='appdb';

SET mysql-passthrough_auth_require_tls='true';
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```

Any client whose username matches the pattern, over TLS, is probed against
hostgroup 10. No row is inserted into `mysql_users`. Session defaults
(hostgroup, schema, `max_connections`, etc.) are re-derived from the global
variables **on every connect**, so changing `mysql-passthrough_default_hg` affects
routing on the next connect with no cache flush.

---

## 6. Securing pass-through

Pass-through turns ProxySQL into something that will try client-supplied
credentials against your backend, so it ships with several guardrails. Review all
of them before enabling in production.

- **Require TLS** (`mysql-passthrough_auth_require_tls=true`, default). Keeps the
  borrowed cleartext password off the wire in plaintext. Do not disable it unless
  the entire client↔ProxySQL path is otherwise trusted.
- **Username allowlist** (`mysql-passthrough_auth_username_pattern`). A regular
  expression; only matching usernames are eligible. **Empty means allow all.** If
  you enable `unknown_users`, ProxySQL logs a warning at load time when the
  pattern is empty — set a pattern. An invalid regex **fails safe (deny)**.
- **Per-user and per-IP rate limiting.** A sliding window
  (`mysql-passthrough_auth_failure_window_s`, default 60s) counts credential
  failures. When a username exceeds `mysql-passthrough_auth_max_failures_per_user`
  (default 3) or a source IP exceeds `mysql-passthrough_auth_max_failures_per_ip`
  (default 10) within the window, further attempts are rejected for the rest of
  the window. Backend **timeouts do not count** — a slow backend cannot lock you
  out.
- **Global in-flight probe cap** (`mysql-passthrough_auth_max_inflight_probes`,
  default 100). Bounds how many backend probes can be in flight at once, protecting
  the backend from a thundering herd (e.g. after a mass password rotation).
- **Audit logging.** Every pass-through decision emits an audit event
  (`MySQL_Client_Connect_Passthrough_OK` / `..._FAIL`) with username, source IP,
  and hostgroup, when the ProxySQL audit log is enabled.
- **Generic error messages.** Failures return a generic `Access denied` to the
  client; the backend's real error is never forwarded, so ProxySQL does not leak
  topology or become an oracle.

> **Enumeration caveat:** `stats_mysql_passthrough_auth_cache` lists every
> username that has successfully authenticated via pass-through. With
> `unknown_users=true`, that set is exactly the accounts an attacker has confirmed
> exist. Treat the admin port as sensitive and prefer a tight `username_pattern`.

---

## 7. Operating pass-through

### 7.1 Is it working / healthy?

```sql
SELECT * FROM stats_mysql_passthrough_auth_metrics;
```

Useful signals:

- `probes_ok / probes_attempted` — success ratio; a healthy deployment trends high.
- `cache_hits` — climbing means most connects are served from cache (no probe).
- `lockouts_user + lockouts_ip` spiking — attack pressure or a misconfigured app.
- `cache_invalidations` spiking — backend passwords are being rotated.
- `inflight_cap_rejects` climbing — you may need a higher
  `mysql-passthrough_auth_max_inflight_probes`.

### 7.2 Who is cached?

```sql
SELECT username, age_s, hostgroup_probed FROM stats_mysql_passthrough_auth_cache;
```

Passwords are **never** exposed by this view.

### 7.3 Expiring cached credentials

- **TTL:** set `mysql-passthrough_auth_cache_ttl_s` (default `0` = never expire).
  Entries older than the TTL are treated as misses and re-probed on next connect.
- **Automatic invalidation:** if a *previously learned* credential is later
  rejected by the backend with `Access denied` (1045) during normal query traffic
  (e.g. the password was rotated), ProxySQL evicts that user's cache entry
  immediately. The current connection still fails, but the next connect re-probes.
- **Manual flush:**
  ```sql
  PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE;                 -- clear everything
  PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER 'appuser';   -- clear one user
  ```

---

## 8. Troubleshooting

| Symptom | Likely cause | What to check |
|---|---|---|
| Client gets `Access denied`, pass-through never triggers | Client isn't using `caching_sha2_password` | Confirm `mysql-default_authentication_plugin='caching_sha2_password'` and that the client/connector uses it |
| `Access denied` on a plaintext connection | TLS required | Connect with SSL, or (not recommended) set `require_tls=false` |
| First connect works, later ones fail after a rotation | Stale cached password | It self-heals on next connect via invalidation; or `PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER '<u>'` |
| Legitimate user locked out | Too many recent failures | Inspect `stats_mysql_passthrough_auth_metrics`; wait out `failure_window_s` or raise `max_failures_per_user` |
| Unknown users rejected despite gate on | Username allowlist / no route | Check `mysql-passthrough_auth_username_pattern` matches, and `mysql-passthrough_default_hg` has a healthy server |
| Passwordless login stopped working | Empty-password behavior change | Expected when the empty-password gate is on — see §4 |
| `COM_CHANGE_USER` fails for a pass-through user | Not supported in Phase 1 | Reconnect instead of switching users |

Enable ProxySQL's error/audit logs to see per-attempt reasons; failures are also
reflected in the `probes_failed_credentials` / `probes_failed_transport` metrics.

---

## 9. Limitations (Phase 1)

- **`caching_sha2_password` only.** `mysql_clear_password` (LDAP-style) and
  `mysql_native_password` are not supported yet.
- **`COM_CHANGE_USER` to a pass-through user is rejected.** Open a new connection.
- **No persistence.** The cache is lost on restart (cold start).
- **No cluster sync.** Each ProxySQL instance learns and caches independently.
- **TLS required by default.** Non-TLS pass-through (RSA public key) is deferred.
- **PostgreSQL is not covered.**

See the [Reference Manual](passthrough_authentication_reference.md) for the full
compatibility matrix and the roadmap of later phases.
