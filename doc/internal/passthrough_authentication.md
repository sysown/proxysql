# Pass-Through Authentication — Design

Status: draft / proposal
Target branch: `v3.0`
History: supersedes the never-merged POC PR [#4221](https://github.com/sysown/proxysql/pull/4221), which targeted `v2.x` on top of the broader `caching_sha2_password` rework PR [#4220](https://github.com/sysown/proxysql/pull/4220) (since landed in `v3.0`).

## 1. Motivation

Today a MySQL client cannot authenticate through ProxySQL unless the user is provisioned in `mysql_users` *with a usable password* (either cleartext or in a hashed form ProxySQL can match against). This forces an out-of-band hand-off step on every deployment: someone must export passwords from MySQL and load them into ProxySQL before the proxy can serve traffic.

**Pass-through authentication** removes that step. When ProxySQL doesn't have a password for a user, it borrows the cleartext password sent by the client during the standard `caching_sha2_password` *full-auth* exchange, uses it to authenticate against a backend, and — on success — caches the credential so subsequent connections fast-path through the normal verification flow.

## 2. Goals & non-goals

### Goals
- Allow client authentication to succeed through ProxySQL without prior password provisioning, when the backend would accept the same credentials.
- Cache learned credentials in ProxySQL's in-memory auth tables so subsequent connections do not require a backend round-trip.
- Support both an **explicit opt-in** mode (rows in `mysql_users` with empty password) and an **auto-fallback** mode (user not in `mysql_users` at all).
- Optionally persist learned credentials to the on-disk admin DB so restarts don't trigger a re-probe storm.

### Non-goals
- Make `mysql_native_password` work in pass-through. The client never sends the password in cleartext for that plugin; relaying the scramble end-to-end is possible but deferred.
- Replace LDAP or any other auth backend. Pass-through is orthogonal — it borrows the client's password; LDAP validates it against a directory.
- Sync learned credentials across a ProxySQL cluster by default.

## 3. User-facing model

### 3.1 Two cases, two gates

| Case | Signal | Gate variable | Default |
|---|---|---|---|
| Row exists, `password=''` | Empty password in `mysql_users` | `mysql-passthrough_auth_empty_password` | `true` (when master gate is on) |
| Row does not exist | Unknown username from client | `mysql-passthrough_auth_unknown_users` | `false` |

Both paths require the master gate `mysql-passthrough_auth_enabled=true` (default `false`).

### 3.2 Empty-password row behavior change

In current `v3.0`, a row with `password=''` allows passwordless login: a client sending no password is accepted. When `mysql-passthrough_auth_enabled=true` *and* `mysql-passthrough_auth_empty_password=true`, this changes: an empty-password row is treated **only** as a pass-through signal. Clients must send a password; ProxySQL probes the backend with it.

This is a deliberate, documented behavior change, gated behind the master switch. Admins relying on passwordless login do not enable the pass-through gate.

### 3.3 Variables

```
mysql-passthrough_auth_enabled                  bool   default false
mysql-passthrough_auth_empty_password           bool   default true
mysql-passthrough_auth_unknown_users            bool   default false
mysql-passthrough_default_hg                    int    default 0
mysql-passthrough_default_schema                str    default ''
mysql-passthrough_auth_require_tls              bool   default true
mysql-passthrough_auth_cache_ttl_s              int    default 0       (0 = never)
mysql-passthrough_auth_cache_persist            bool   default false
mysql-passthrough_auth_username_pattern         str    default ''      (regex; '' = allow all)
mysql-passthrough_auth_max_failures_per_user    int    default 3
mysql-passthrough_auth_max_failures_per_ip      int    default 10
mysql-passthrough_auth_failure_window_s         int    default 60
```

`mysql-passthrough_auth_empty_password` and `mysql-passthrough_auth_unknown_users` are only honored when `mysql-passthrough_auth_enabled=true`.

### 3.4 No new `mysql_users` columns

Learned rows are indistinguishable from manually-provisioned ones. The "is this row learned?" question is answered by behavior, not by a column: a row whose password is empty is eligible for (re-)probing; a row with a password is treated as provisioned. Cache invalidation = set password back to empty.

This intentionally keeps the schema simple. Trade-off: admins cannot distinguish learned vs. manually-provisioned rows from `SELECT * FROM mysql_users`. The cost is accepted; if visibility becomes a need later, a marker column can be added without protocol-level changes.

### 3.5 Auto-creation of rows for unknown users

When `mysql-passthrough_auth_unknown_users=true` and a client authenticates with a username not in `mysql_users`, a successful probe inserts a row:

| Column | Value |
|---|---|
| `username` | from the client |
| `password` | learned cleartext (memory only by default) |
| `default_hostgroup` | `mysql-passthrough_default_hg` |
| `default_schema` | `mysql-passthrough_default_schema` (or `mysql-default_schema` if empty) |
| other columns | global defaults |

After this insert, the user is identical to any other configured user. Subsequent invalidation either clears the password back to `''` (and the row stays, ready to re-probe via the empty-password path on the next connect) or — admin choice — deletes the row entirely. v1 ships with "clear password, keep row".

## 4. Protocol flow

### 4.1 `caching_sha2_password` (the primary case)

```
Client                                              ProxySQL                          Backend
  | --- TCP connect ----------------------------------> |
  | <-- HandshakeV10 (auth=caching_sha2_password) ----- |
  | --- HandshakeResponse (user=U, scrambled_pw) -----> |
  |                                                    | lookup(U):
  |                                                    |   no row || password=''
  |                                                    | pass-through eligible
  |                                                    | (TLS required if require_tls)
  | <-- AuthMoreData{0x04} perform_full_auth ---------- |
  | --- AuthSwitchResponse(cleartext_pw) -------------> |
  |                                                    | -- TCP connect ----------------> |
  |                                                    | -- handshake as (U, cleartext)-> |
  |                                                    | <-- OK ------------------------- |
  |                                                    | cache (U, cleartext) into
  |                                                    | GloMyAuth.creds_frontends
  |                                                    | (insert row if needed)
  | <-- OK -------------------------------------------- |                                 |
  |                                                    | return probe conn to pool       |
```

### 4.2 `mysql_clear_password` (LDAP-style; deferred to Phase 2)

Client already sends cleartext; the only difference is no `AuthMoreData{0x04}` round-trip. Same probe-and-cache step.

### 4.3 `mysql_native_password`

Not supported. The client sends `SHA1(pw) XOR SHA1(scramble || SHA1(SHA1(pw)))`; cleartext is never available to ProxySQL. End-to-end scramble relay is possible (backend handshake captures backend's scramble, ProxySQL uses *that* in its own handshake with the client, then forwards the client's response) but couples frontend handshake latency to backend connect latency. Deferred.

### 4.4 Compatibility matrix

| Stored in `mysql_users` | Client plugin | Outcome |
|---|---|---|
| `password='<hash>'` | any | normal flow, no change |
| `password=''`, gate on | `caching_sha2_password` | Phase 1: pass-through |
| `password=''`, gate on | `mysql_clear_password` | Phase 2: pass-through |
| `password=''`, gate on | `mysql_native_password` | Phase 1: reject (Phase 3 maybe) |
| no row, gate on | `caching_sha2_password` | Phase 1: pass-through + auto-insert |
| no row, gate on | `mysql_clear_password` | Phase 2 |
| no row, gate on | `mysql_native_password` | Phase 1: reject |

## 5. State machine

### 5.1 New session state

Add to `enum session_status` (in `include/proxysql_structs.h`):

```c
AUTHENTICATING_BACKEND_FOR_CLIENT,
```

Modeled after `LDAP_AUTH_CLIENT` — a state for "session is doing out-of-band auth before it can hand the client an OK".

### 5.2 Transitions

```
WAITING_CLIENT_AUTH (caching_sha2 full-auth response received)
         │
         │  PPHR_verify_password() determines pass-through applies
         │  (vars1.password == NULL or empty), cleartext captured
         ▼
AUTHENTICATING_BACKEND_FOR_CLIENT
         │
         │  open fresh connection in
         │  (user_row ? user_row.default_hg : mysql-passthrough_default_hg)
         │  with userinfo = (U, cleartext)
         │
   ┌─────┴─────┐
   │           │
backend OK   backend ERR / timeout / rate-limited
   │           │
   │           ▼
   │      send generic "Access denied" → close session
   ▼
GloMyAuth->set_clear_text_password (or insert row first
if unknown-user path)
   │
   ▼
send OK to client, return probe conn to pool,
state = WAITING_CLIENT_DATA
```

### 5.3 Why a dedicated state, not the POC's `CONNECTING_CLIENT_RESUME`

PR #4221 piggy-backed on `CONNECTING_SERVER` with a marker on the `previous_status` stack. This required three special-cases scattered across `generate_pkt_ERR`, `handler_again___status_CONNECTING_SERVER`, and the `create_mybackend` path. A dedicated state localizes the logic to one handler and one switch arm.

### 5.4 `COM_CHANGE_USER` to a pass-through user

Same state, entered from the `COM_CHANGE_USER` packet handler instead of from initial handshake. Subtleties:

- The session already has a bound backend connection. Probe with a *fresh* connection (don't disturb in-flight transactions on the bound one).
- On probe success, the existing backend connection may or may not be reusable. If the old user's connection charset/schema/vars carry forward sensibly, reuse; otherwise close and let pool replenish. For v1: close the old bound conn on every successful CHANGE_USER pass-through, accept the cost.

## 6. Probe details

### 6.1 Target hostgroup

- Row exists (empty-password case): use `row.default_hostgroup`.
- Row missing (unknown-user case): use `mysql-passthrough_default_hg`.

ProxySQL does not care about backend topology (single, master-slave, GR, Aurora). It picks a healthy backend from the hostgroup, same selection logic as any other connection request.

### 6.2 Connect timeout

Apply `mysql-connect_timeout_server_max` to the probe. On timeout, treat as failure (does not count against rate-limit counters, since timeout != bad credentials — admins shouldn't get locked out because a backend is slow).

### 6.3 Probe success → cache + (optionally) insert

On `OK`:
1. If row didn't exist, `INSERT` it (see §3.5).
2. `GloMyAuth->set_clear_text_password(U, USERNAME_FRONTEND, cleartext, PRIMARY)`.
3. Pre-compute and stash hashes that allow future fast-paths:
   - `mysql_native_password` hash (`SHA1(SHA1(pw))`) — populated into `ad->sha1_pass`.
   - `caching_sha2_password` upstream-format `$A$...` digest — populated into the appropriate slot for fast-auth-success matching.
4. Update `last_refreshed_ts` in the in-memory timestamp map (used for TTL).
5. If `mysql-passthrough_auth_cache_persist=true`, write the row through to the on-disk admin DB.
6. Return probe conn to pool.
7. Send `OK` to client; session → `WAITING_CLIENT_DATA`.

### 6.4 Probe failure

- Send a generic ERR (`Access denied for user 'U'@'host'`) to the client. Do not forward the backend's ERR verbatim — it could leak backend topology or message variations.
- Increment per-user and per-IP failure counters.
- Tear down session.

## 7. Security model

### 7.1 Threats opened by pass-through

| Threat | Mitigation |
|---|---|
| ProxySQL becomes a credential-stuffing amplifier | Per-user and per-IP rate limits with tarpit/lockout on threshold |
| Username enumeration via timing or message diff | Generic ERR; constant-ish failure timing if possible |
| Cleartext password exposure on the wire | `mysql-passthrough_auth_require_tls=true` by default; refuse to send `AuthMoreData{0x04}` without TLS (or RSA pubkey support, see §7.4) |
| Backend DoS from runaway probes | Rate limits + a global concurrency cap on in-flight probes (`mysql-passthrough_auth_max_inflight_probes`, not in §3.3 yet — TBD) |
| Stale cached password after backend rotation | TTL + invalidate-on-backend-rejection during real traffic |
| Unintended exposure of unknown-user code path | `mysql-passthrough_auth_unknown_users` defaults to `false`; `username_pattern` allowlist for further restriction |

### 7.2 Rate limiting

Maintain two sliding-window counters:
- per `username` → failure count over `failure_window_s`
- per source IP → failure count over `failure_window_s`

When either exceeds its threshold, subsequent probe requests are rejected immediately with the generic ERR for the rest of the window. Successful probes do not decrement counters but do not increment either.

Implementation hint: reuse the existing `client_addr` parsing in `MySQL_Session`; counters live in `MySQL_Authentication` (next to existing auth-failure tracking).

### 7.3 Audit logging

Every probe attempt (success and failure) emits an entry via `GloMyLogger->log_audit_entry`. New event types:

- `PROXYSQL_MYSQL_AUTH_PASSTHROUGH_OK`
- `PROXYSQL_MYSQL_AUTH_PASSTHROUGH_FAIL`

Entry includes username, source IP, hostgroup probed, outcome. Useful for forensics and ops dashboards.

### 7.4 RSA public key for non-TLS clients

MySQL's `caching_sha2_password` allows non-TLS clients to encrypt the cleartext password with the server's RSA public key. If we want to support non-TLS pass-through, ProxySQL needs to publish a public key (`caching_sha2_password_public_key_path`) and decrypt with the matching private key. Phase 1 ships without this; clients must use TLS. Phase 2 may add RSA support if there's demand.

## 8. Caching & invalidation

### 8.1 TTL

When `mysql-passthrough_auth_cache_ttl_s > 0`, a background sweep (or lazy check on connect) evicts learned passwords older than the TTL. Eviction = clear `password` field back to `''`. Next client connect re-enters pass-through via the empty-password path.

In-memory map `unordered_map<string,uint64_t> passthrough_refreshed_at` tracks last-learned timestamps. Not persisted (acceptable: post-restart, TTL clock effectively resets).

### 8.2 Backend rejection during real traffic

If a query-time backend connection is rejected with `ER_ACCESS_DENIED_ERROR` (1045) using a previously-learned password, invalidate that user's cached credential immediately:

```
set password = ''
remove from passthrough_refreshed_at
```

The current client connection still fails (we can't transparently re-auth mid-session safely), but the *next* connect re-probes. This bounds stale-password damage to one connection.

### 8.3 Persistence as cache layer

When `mysql-passthrough_auth_cache_persist=true`:
- On successful probe and cache write, write the single row through to the on-disk admin DB (`UPDATE OR INSERT mysql_users ...`).
- On `proxysql` startup, the on-disk rows load normally into in-memory creds; no special "is this learned?" handling needed.
- `LOAD MYSQL USERS FROM CONFIG` wipes learned rows because they aren't in the cnf. Acceptable: re-probe is cheap, and CONFIG-as-truth is the existing semantic.

### 8.4 Manual flush

```sql
-- via admin interface
UPDATE mysql_users SET password='' WHERE username='alice';
LOAD MYSQL USERS TO RUNTIME;
```

Existing primitives suffice. No new admin command in Phase 1.

## 9. Code layout

### 9.1 Entry point

`MySQL_Protocol::PPHR_verify_password()` (lib/MySQL_Protocol.cpp around L2395) is the natural fork point. Today the `vars1.password == NULL` branch tries LDAP and otherwise fails. Replace the bottom of that branch with:

```cpp
if (vars1.password == NULL || (vars1.password[0] == '\0')) {
    if (passthrough_eligible(vars1, account_details)) {
        return PPHR_passthrough_init(ret, vars1, account_details);
    }
    // existing LDAP / fail path
}
```

`passthrough_eligible()` checks the gate variables, the username pattern, TLS requirement, and rate-limit state.

### 9.2 New protocol helper

`MySQL_Protocol::PPHR_passthrough_init` — sends `AuthMoreData{0x04}` if needed (caching_sha2 first stage), sets `switching_auth_stage=4`, marks the session as entering `AUTHENTICATING_BACKEND_FOR_CLIENT` on stage-5 receipt of cleartext.

`MySQL_Protocol::PPHR_passthrough_complete` — called from the session handler on probe completion; updates `GloMyAuth`, inserts row if needed, generates the OK packet.

### 9.3 New session handler

`MySQL_Session::handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT()` — drives the probe connection lifecycle. Modeled on `handler_again___status_CONNECTING_SERVER` but with the probe-specific success/failure handling and without touching `previous_status`.

### 9.4 Auth tier hook

`MySQL_Authentication::set_clear_text_password` (lib/MySQL_Authentication.cpp:555) currently returns `false` silently for unknown users. Either:

- Loosen it to insert when absent (with sensible defaults), or
- Add a sibling `insert_or_update_clear_text_password()` for the pass-through path.

The second is cleaner: existing callers don't get surprise inserts. Pass-through uses the new function.

### 9.5 Probe pool ownership

The probe connection is *not* the connection that will serve client queries. It is allocated, used for one handshake, and either returned to pool (if healthy and the user's connection limits allow it) or destroyed. The session then takes its query-path backend connection through the normal `CONNECTING_SERVER` path on first query.

## 10. Phasing

### Phase 1 (this proposal)
- `caching_sha2_password` only
- Empty-password rows: opt-in via `mysql-passthrough_auth_empty_password`
- Unknown users: opt-in via `mysql-passthrough_auth_unknown_users`
- TLS required (`require_tls=true` default)
- Generic ERR responses
- Rate limiting (per-user, per-IP)
- Audit log entries
- TTL eviction
- Backend-rejection-triggered invalidation
- Optional persistence (`cache_persist=true`)
- Pre-population of `mysql_native_password` and `caching_sha2_password` hashes after successful learn (in-memory only)

### Phase 2 (follow-up)
- `mysql_clear_password` plugin (LDAP-style cleartext) — easier, no full-auth round-trip
- RSA public-key support for non-TLS `caching_sha2_password`
- Admin command `PROXYSQL PASSTHROUGH FLUSH [username]`

### Phase 3 (if demand)
- `mysql_native_password` via scramble relay (couples frontend handshake to backend connect)
- Cluster sync of learned rows (opt-in)
- Per-row TTL override

## 11. Open questions

1. Should successful probes count against backend connection limits (`max_connections` in `mysql_servers`)? Probably yes — they're real connections. But probes are short-lived and quickly returned to pool, so impact should be minor.
2. Global concurrency cap on in-flight probes (`max_inflight_probes`)? Useful to prevent thundering herd after a large backend password rotation. Suggest yes; default high (e.g., 100). Not in §3.3 yet.
3. Pre-computing the `$A$` `caching_sha2_password` hash requires running `sha256_crypt_r` with configurable rounds. Should rounds default to MySQL 8's default (5000)? Yes. Configurable per `mysql-default_caching_sha2_password_rounds` or similar — likely already a variable post-PR #4220, to check.
4. If the same user races (two concurrent unknown-user logins for the same U), do we serialize probes per-username or allow parallel? Suggest a per-username lock during probe; the second waits on the first's outcome to avoid two inserts and two backend probes for the same credential.
5. What does `COM_CHANGE_USER` to an unknown user look like in v1? Allowed under the same gates, or rejected for simplicity? Suggest: allowed only if `unknown_users=true`; same code path; same rate limits.
6. Hot-reload of the gate variables: if `mysql-passthrough_auth_enabled` flips from `true` to `false`, what happens to learned rows? Suggest: nothing — they remain valid, just no *new* pass-through happens. Admins who want them gone run an UPDATE.
