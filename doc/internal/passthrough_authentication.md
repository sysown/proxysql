# Pass-Through Authentication — Design

Status: draft / proposal
Target branch: `v3.0`
History: supersedes the never-merged POC PR [#4221](https://github.com/sysown/proxysql/pull/4221), which targeted `v2.x` on top of the broader `caching_sha2_password` rework PR [#4220](https://github.com/sysown/proxysql/pull/4220) (since landed in `v3.0`).

## 1. Motivation

Today a MySQL client cannot authenticate through ProxySQL unless the user is provisioned in `mysql_users` *with a usable password* (either cleartext or in a hashed form ProxySQL can match against). This forces an out-of-band hand-off step on every deployment: someone must export passwords from MySQL and load them into ProxySQL before the proxy can serve traffic.

**Pass-through authentication** removes that step. When ProxySQL doesn't have a password for a user, it borrows the cleartext password sent by the client during the standard `caching_sha2_password` *full-auth* exchange, uses it to authenticate against a backend, and — on success — caches the credential in an in-memory cache so subsequent connections fast-path through the normal verification flow.

## 2. Goals & non-goals

### Goals
- Allow client authentication to succeed through ProxySQL without prior password provisioning, when the backend would accept the same credentials.
- Cache learned credentials in an in-memory cache so subsequent connections do not require a backend round-trip.
- Support both an **explicit opt-in** mode (rows in `mysql_users` with empty password) and an **auto-fallback** mode (user not in `mysql_users` at all).
- Never write to `mysql_users`. The cache is a separate in-memory structure; `mysql_users` is only modified by admins.

### Non-goals
- Make `mysql_native_password` work in pass-through. The client never sends the password in cleartext for that plugin; relaying the scramble end-to-end is possible but deferred.
- Replace LDAP or any other auth backend. Pass-through is orthogonal — it borrows the client's password; LDAP validates it against a directory.
- Persist the cache across ProxySQL restarts. After a restart, the cache starts cold and warms up as clients re-connect.
- Sync learned credentials across a ProxySQL cluster.

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
mysql-passthrough_auth_max_inflight_probes      int    default 100
mysql-passthrough_auth_username_pattern         str    default ''      (regex; '' = allow all)
mysql-passthrough_auth_max_failures_per_user    int    default 3
mysql-passthrough_auth_max_failures_per_ip      int    default 10
mysql-passthrough_auth_failure_window_s         int    default 60
mysql-passthrough_auth_failure_map_cap          int    default 100000  (max distinct keys retained in failure deques)
```

`mysql-passthrough_auth_empty_password` and `mysql-passthrough_auth_unknown_users` are only honored when `mysql-passthrough_auth_enabled=true`.

### 3.4 No writes to `mysql_users`

`mysql_users` is admin-managed and is **never** modified by ProxySQL as a result of pass-through. Learned credentials live exclusively in a separate in-memory cache structure (§8). The "is this user known?" question is still answered by `mysql_users`; the "what is their password?" question is answered by the cache when the row's password is empty or the row is absent.

### 3.5 Routing & defaults for unknown users

When pass-through completes for a user not in `mysql_users`, no row is inserted. Session-state defaults are derived from global variables at each connect:

| Property | Source |
|---|---|
| `default_hostgroup` | `mysql-passthrough_default_hg` |
| `default_schema` | `mysql-passthrough_default_schema` (falls back to `mysql-default_schema` if empty) |
| `max_connections`, `schema_locked`, `transaction_persistent`, `fast_forward`, etc. | global defaults |

Because these are re-evaluated each connect, changing `mysql-passthrough_default_hg` immediately affects routing on the next connect from a cached unknown user — no cache flush required.

### 3.6 Frontend certificate policy (v3.1+/v4 only)

A row-backed frontend account can set `attributes.require_x509=true`. On v3.1+ and v4, that requires the configured password/authentication-plugin step and a trusted certificate on the physical frontend TLS connection. A SPIFFE row is excluded from pass-through because `spiffe_id` is an identity policy, not an empty-password pass-through signal. Unknown-user pass-through has no row or attributes object, so its existing `mysql-passthrough_auth_require_tls` transport gate is unchanged; it is not a per-user X.509 rule.

## 4. Protocol flow

### 4.1 `caching_sha2_password` (the primary case)

```
Client                                              ProxySQL                          Backend
  | --- TCP connect ----------------------------------> |
  | <-- HandshakeV10 (auth=caching_sha2_password) ----- |
  | --- HandshakeResponse (user=U, scrambled_pw) -----> |
  |                                                    | lookup(U) in mysql_users:
  |                                                    |   row missing  OR  password=''
  |                                                    | check passthrough_auth_cache[U]:
  |                                                    |   miss → pass-through eligible
  |                                                    | (TLS required if require_tls)
  | <-- AuthMoreData{0x04} perform_full_auth ---------- |
  | --- AuthSwitchResponse(cleartext_pw) -------------> |
  |                                                    | -- TCP connect ----------------> |
  |                                                    | -- handshake as (U, cleartext)-> |
  |                                                    | <-- OK ------------------------- |
  |                                                    | insert (U, cleartext, ts)
  |                                                    | into passthrough_auth_cache
  | <-- OK -------------------------------------------- |                                 |
  |                                                    | return probe conn to pool       |
```

On a subsequent connection from the same user before TTL expiry, `passthrough_auth_cache[U]` hits; the cleartext is used to verify the client's response inline (no backend probe).

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
| no row, gate on | `caching_sha2_password` | Phase 1: pass-through (cache only) |
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
         │  (row missing OR row.password=='') AND cache miss,
         │  cleartext captured from client
         ▼
AUTHENTICATING_BACKEND_FOR_CLIENT
         │
         │  open fresh connection in
         │  (row ? row.default_hg : mysql-passthrough_default_hg)
         │  with userinfo = (U, cleartext)
         │
   ┌─────┴─────┐
   │           │
backend OK   backend ERR / timeout / rate-limited / inflight-cap
   │           │
   │           ▼
   │      send generic "Access denied" → close session
   ▼
insert (U, cleartext, now) into passthrough_auth_cache
   │
   ▼
send OK to client, return probe conn to pool,
state = WAITING_CLIENT_DATA
```

### 5.3 Why a dedicated state, not the POC's `CONNECTING_CLIENT_RESUME`

PR #4221 piggy-backed on `CONNECTING_SERVER` with a marker on the `previous_status` stack. This required three special-cases scattered across `generate_pkt_ERR`, `handler_again___status_CONNECTING_SERVER`, and the `create_mybackend` path. A dedicated state localizes the logic to one handler and one switch arm.

### 5.4 `COM_CHANGE_USER`

For Phase 1, `COM_CHANGE_USER` targeting a user that would require pass-through (empty-password row, or no row with `unknown_users` enabled) is **rejected**. Same generic ERR as any other pass-through failure. Rationale: keeps the state machine simple, avoids the subtleties of probing a fresh backend while a bound backend connection has in-flight session state.

Implementation: `process_pkt_COM_CHANGE_USER` in `lib/MySQL_Protocol.cpp` returns early with `ret=false` when the target's stored password is empty and the master gate is on. The check runs BEFORE the function's unconditional session-state mutations (`sess->default_hostgroup`, `transaction_persistent`, `user_attributes`) so a rejected attempt has no observable side effects on the already-authenticated session.

The directions are intentionally asymmetric: a pass-through target is rejected even when the original connection carries a valid certificate, while a pass-through-authenticated source may change to an ordinary password-backed target. The SPIFFE source/target prohibition remains separate: an SPIFFE-authenticated source and every SPIFFE target are rejected. `COM_CHANGE_USER` relies on immutable certificate evidence from the original connection and never renegotiates TLS.

May be revisited in a later phase if there's demand.

## 6. Probe details

### 6.1 Target hostgroup

- Row exists (empty-password case): use `row.default_hostgroup`.
- Row missing (unknown-user case): use `mysql-passthrough_default_hg`.

ProxySQL does not care about backend topology (single, master-slave, GR, Aurora). It picks a healthy backend from the hostgroup, same selection logic as any other connection request.

### 6.2 Connect timeout

The backend connect is driven by the existing non-blocking `CONNECTING_SERVER` path, so timeout handling is inherited from it: `mysql_servers.max_connect_time` / `mysql-connect_timeout_server_max` apply as for any backend acquisition. On timeout (a transport-class failure), the connect is treated as failure and does **not** count against rate-limit failure counters (§6.4) — admins shouldn't get locked out because a backend is slow.

### 6.3 Backend connect → cache

There is no separate "probe." The client's captured cleartext is treated as *potentially right*: it is placed on `userinfo->password`, a backend connection is acquired, and the normal non-blocking connect authenticates to the backend with it. The backend's `OK`/`ERR` **is** the credential verdict.

On `OK` (the `CONNECTING_SERVER` connect succeeds and the session resumes in `AUTHENTICATING_BACKEND_FOR_CLIENT` Phase B):
1. Insert `(U, cleartext, now)` into the in-memory `passthrough_auth_cache`.
2. Return the now-authenticated backend connection to the pool (it is valid and reusable; the client's first query re-acquires through the normal lazy `CONNECTING_SERVER` path with the now-cached credential).
3. Send `OK` to the client; session → `WAITING_CLIENT_DATA`.

No pre-computation of hashes is performed. The existing verification code already handles `stored=cleartext, client=any-supported-plugin`:
- `mysql_native_password` client → `proxy_scramble(reply, scramble_buff, cleartext)` and memcmp.
- `caching_sha2_password` client (fast-auth path) → `PPHR_6auth2` derives the expected scrambled response from the cached cleartext.

#### Connection lifecycle (non-blocking, pooled)

The pass-through backend connect reuses the **existing** `CONNECTING_SERVER` machinery — the same non-blocking `async_connect` → `mysql_real_connect_start`/`connect_cont` path every other backend connection uses. The handler `AUTHENTICATING_BACKEND_FOR_CLIENT` is a thin two-phase wrapper:

- **Phase A** (first entry): run the pre-checks (rate limiting, in-flight cap), acquire a **fresh** pooled connection via `MyHGM->get_MyConn_from_pool(..., ff=true)`, copy the client userinfo (credential included) onto it, kick off `async_connect`, push the resume target onto `previous_status`, and transition to `CONNECTING_SERVER`.
- **Phase B** (resumed after `CONNECTING_SERVER` success): cache the verified credential, enforce the frontend connection caps, return the authed connection to the pool, send the client `OK`, and go to `WAITING_CLIENT_DATA`.

The connection is acquired with `ff=true` (force-new). This is **load-bearing for correctness**: the connection pool reuses connections by username only (`requires_CHANGE_USER` compares username, `match_tracked_options` compares client flags — neither checks the password). A reused connection authenticated for `alice` with password X would silently satisfy a pass-through request for `alice` with a *wrong* password Y, never validating Y — defeating the entire credential verdict. `ff=true` skips the reuse arms and forces the create-new path (a connection with `fd == -1`), so `connect_start` runs `mysql_real_connect_start` with the borrowed credential.

Consequences of using the pool:

- The pass-through connect **is** counted against `mysql_servers.max_connections` and the pool's throttle, exactly like any backend acquisition. This is correct backpressure (the earlier "bypasses `max_connections`" one-shot design was a hole, not a feature). The global `mysql-passthrough_auth_max_inflight_probes` remains as an additional pass-through-specific ceiling.
- The connect **is** non-blocking: it never blocks the worker event-loop thread. Credential-stuffing load cannot pin worker threads the way the former synchronous `mysql_real_connect` did.
- `mysql_thread___connect_retries_on_failure` does not apply: a credential verdict is a single-attempt outcome, and the pass-through divert in `CONNECTING_SERVER` (§6.4) intercepts the failure before the retry loop.

### 6.4 Backend-connect failure (credential or transport)

When `CONNECTING_SERVER` fails while servicing a pass-through auth (detected via the session's `passthrough_connect_in_flight` marker), it **diverts** instead of taking its default failure path. The default path is wrong for pass-through on three counts: it forwards the backend's actual error message (leaking topology — §6.4 forbids this), it transitions to `WAITING_CLIENT_DATA` without tearing the session down, and it retries a credential verdict to other backends (pointless — same bad password).

The divert classifies the `mysql_errno` and:

- **Credential-class** (1045 `ER_ACCESS_DENIED_ERROR`, 1698, 1130): records a failure against the per-user/per-IP sliding windows (§7.2), bumps `probes_failed_credentials`.
- **Transport-class** (everything else, including timeouts and 2xxx client errors): bumps `probes_failed_transport` and does **not** record a failure (timeouts must not lock out — §6.2).

It then hands the disposition back to the pass-through handler via the `passthrough_connect_failed` channel, which drives a single, shared teardown:

- Sends a generic ERR (`Access denied for user 'U'`) to the client. The backend's message is never forwarded — no topology leak.
- Tears down the session.
- Does **not** insert any negative-cache entry. Failed connects are not cached.

The §8.4 invalidation eviction (a *later* 1045 during real query traffic against a previously-learned credential) is a separate, gated mechanism that remains in `CONNECTING_SERVER`'s 1045 case, scoped by the `passthrough_credential` flag.

## 7. Security model

### 7.1 Threats opened by pass-through

| Threat | Mitigation |
|---|---|
| ProxySQL becomes a credential-stuffing amplifier | Per-user and per-IP rate limits with tarpit/lockout on threshold |
| Username enumeration via timing or message diff | Generic ERR; constant-ish failure timing if possible |
| Cleartext password exposure on the wire | `mysql-passthrough_auth_require_tls=true` by default; refuse to send `AuthMoreData{0x04}` without TLS (or RSA pubkey support, see §7.4) |
| Backend DoS from runaway probes | Per-user/per-IP rate limits *plus* a global concurrency cap `mysql-passthrough_auth_max_inflight_probes` (default 100) |
| Stale cached password after backend rotation | TTL + invalidate-on-backend-rejection during real traffic |
| Unintended exposure of unknown-user code path | `mysql-passthrough_auth_unknown_users` defaults to `false`; `username_pattern` allowlist for further restriction |

For a row-backed authentication attempt, the security ordering is:

```text
row lookup
  -> require_x509 / SPIFFE classification
  -> username allowlist
  -> pass-through TLS gate
  -> cache lookup
  -> cleartext request
  -> backend probe
```

Cold-probe completion sends the frontend OK from `MySQL_Session::handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT()`. Certificate policy must therefore be decided before dispatch, rather than relying only on the normal handshake epilogue. The frontend certificate is not sent to the backend, and this ordering does not change the unknown-user TLS transport gate into a per-user X.509 rule.

### 7.2 Rate limiting

Maintain two sliding-window counters:
- per `username` → failure count over `failure_window_s`
- per source IP → failure count over `failure_window_s`

When either exceeds its threshold, subsequent probe requests are rejected immediately with the generic ERR for the rest of the window. Successful probes do not decrement counters but do not increment either.

Implementation hint: reuse the existing `client_addr` parsing in `MySQL_Session`; counters live next to existing auth-failure tracking.

**Defense against churn:** the two failure maps are bounded by `mysql-passthrough_auth_failure_map_cap` (default 100000). An attacker who churns unique usernames/IPs would otherwise grow the maps line-rate (each unique key persists for at least one window). On record_failure, if a map exceeds the cap, `evict_oldest` opportunistically sweeps empty-deque entries left over from expired windows and, if still above the cap, drops the deque with the smallest front()-timestamp. Costs O(N) under the failure_lock at-cap, but in steady-state under hostile traffic the bound holds.

### 7.3 In-flight probe cap

A global counter tracks probes currently in `AUTHENTICATING_BACKEND_FOR_CLIENT`. When `mysql-passthrough_auth_max_inflight_probes` is reached, new pass-through attempts are rejected with the generic ERR until a slot frees up. Protects against thundering-herd after a large backend password rotation.

This also bounds concurrent same-username races: even without an explicit per-username lock, the global cap limits how many simultaneous probes for the same user can fire. v1 accepts a small amount of duplicate probing in exchange for simplicity; if it becomes a problem, a per-username lock can be added.

### 7.4 Audit logging

Every probe attempt (success and failure) emits an entry via `GloMyLogger->log_audit_entry`. New event types:

| C++ enum (`log_event_type`)              | JSON `event` string an operator sees in the audit log |
|------------------------------------------|-------------------------------------------------------|
| `PROXYSQL_MYSQL_AUTH_PASSTHROUGH_OK`     | `MySQL_Client_Connect_Passthrough_OK`                 |
| `PROXYSQL_MYSQL_AUTH_PASSTHROUGH_FAIL`   | `MySQL_Client_Connect_Passthrough_FAIL`               |

Entry includes username, source IP, hostgroup probed, outcome. Useful for forensics and ops dashboards.

### 7.5 RSA public key for non-TLS clients

MySQL's `caching_sha2_password` allows non-TLS clients to encrypt the cleartext password with the server's RSA public key. If we want to support non-TLS pass-through, ProxySQL needs to publish a public key (`caching_sha2_password_public_key_path`) and decrypt with the matching private key. Phase 1 ships without this; clients must use TLS. Phase 2 may add RSA support if there's demand.

## 8. The cache

### 8.1 Structure

A new in-memory singleton, `MySQL_Passthrough_Auth_Cache` (or sibling of `GloMyAuth`):

```cpp
struct entry_t {                       // named entry_t in the implementation
    std::string cleartext_password;
    uint64_t    learned_at_us;         // monotonic_time() microseconds
    int         hostgroup_probed;      // hostgroup the probe targeted; surfaced
                                       // via stats_mysql_passthrough_auth_cache
};

// keyed by frontend username
std::unordered_map<std::string, entry_t> entries;
pthread_rwlock_t lock;
```

In-memory only. Not persisted. Restart = cold start.

### 8.2 Lookup path

`MySQL_Protocol::PPHR_verify_password()` checks the cache after `GloMyAuth->lookup()` returns:

```
acc = GloMyAuth->lookup(U)
if acc.password is set:
    normal verification
else if pass-through gate applies (empty-password row OR no row with unknown_users on):
    entry = passthrough_auth_cache.get(U)
    if entry and not expired:
        use entry.cleartext_password as if it were acc.password
        normal verification continues
    else:
        enter AUTHENTICATING_BACKEND_FOR_CLIENT
else:
    fail (existing LDAP / unknown-user path)
```

### 8.3 TTL

When `mysql-passthrough_auth_cache_ttl_s > 0`, the lookup path treats entries older than the TTL as misses (lazy eviction) and removes them. No background sweep needed in Phase 1; a periodic sweep can be added later if memory growth in long-uptime deployments becomes a concern.

### 8.4 Backend-rejection invalidation

If a query-time backend connection is rejected with `ER_ACCESS_DENIED_ERROR` (1045) using a previously-learned password, evict that user's cache entry immediately. The current client connection still fails (we can't transparently re-auth mid-session safely), but the *next* connect re-probes. This bounds stale-password damage to one connection.

### 8.5 Manual flush

A new admin command:

```
PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE
PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER 'alice'
```

Modeled on existing `PROXYSQL FLUSH LOGS` / `PROXYSQL FLUSH CONFIGDB`. The no-argument form clears the entire cache; the `FOR USER` form clears a single entry.

### 8.6 Observability

Two read-only stats views for ops (not authoritative, snapshots in-memory state):

**Cache contents:**

```
stats_mysql_passthrough_auth_cache:
  username          TEXT
  learned_at        BIGINT   (monotonic_time microseconds since process start)
  age_s             INTEGER
  hostgroup_probed  INTEGER
```

Password column is **not** exposed. Useful for "is alice's password cached?" debugging.

> **Security note (username enumeration):** the `username` column of
> `stats_mysql_passthrough_auth_cache` lists every account that has
> successfully authenticated via pass-through. When
> `mysql-passthrough_auth_unknown_users=true`, this set is exactly the
> set of usernames an attacker has *confirmed* are valid backend
> accounts in `mysql-passthrough_default_hg`. Any holder of admin
> console access can therefore enumerate valid backend users. Admin
> console access is already privileged, but operators who enable
> `unknown_users` (which expands the credential-stuffing surface) MUST
> treat this view as sensitive: restrict who can reach the admin port,
> and prefer setting `mysql-passthrough_auth_username_pattern` so the
> probed-user population is bounded by policy rather than discovered by
> attacker traffic.

**Counters / gauges** (`stats_mysql_passthrough_auth_metrics`):

```
metric_name                   metric_value
----------------------------  ------------
probes_attempted              uint64   probes that actually attempted a backend
                                       connection (past all eligibility gates)
probes_ok                     uint64   probes that succeeded; cache populated
probes_failed_credentials     uint64   probes rejected by backend with a
                                       credential-class errno (1045/1698/1130)
probes_failed_transport       uint64   probes that failed at transport (errno
                                       2xxx, timeouts, infrastructure problems)
lockouts_user                 uint64   per-user sliding-window cap fired
lockouts_ip                   uint64   per-source-IP sliding-window cap fired
inflight_cap_rejects          uint64   max_inflight_probes saturated
cache_hits                    uint64   PPHR_verify_password served a cleartext
                                       from the cache (no probe needed)
cache_invalidations           uint64   ER_ACCESS_DENIED_ERROR (1045) during query
                                       traffic evicted a cached entry that came
                                       from pass-through (see N4 gate)
inflight_probes               uint64   current in-flight probe count (gauge)
cache_entries                 uint64   current cache size (gauge)
```

All counter values are monotonic since process start; reset only by restart. The two gauges read live state. None of the counters expose passwords or any cleartext credential material. Operator tooling that watches `probes_ok / probes_attempted` ratio gets a good "is pass-through healthy?" signal; `lockouts_user + lockouts_ip` spiking signals attack pressure; `cache_invalidations` spiking signals backend password rotation activity.

## 9. Code layout

### 9.1 New cache class

`include/MySQL_Passthrough_Auth_Cache.h` + `lib/MySQL_Passthrough_Auth_Cache.cpp`. Singleton `GloMyPTAuthCache`. Methods:

```cpp
bool   lookup(const std::string& user, std::string& out_cleartext, uint32_t ttl_s);
void   insert(const std::string& user, const std::string& cleartext, int hostgroup_probed);
bool   evict(const std::string& user);   // true if the entry was present
void   clear();
size_t size() const;
std::vector<passthrough_entry_view> snapshot() const;  // for stats_mysql_passthrough_auth_cache

// Allowlist (spec §7.1)
bool   username_allowed(const std::string& username, const std::string& pattern);

// In-flight probe cap (spec §7.3)
bool   try_acquire_inflight(int max_inflight);
void   release_inflight();
int    inflight() const;

// Sliding-window rate limit (spec §7.2)
bool   would_lockout_user(const std::string& username, int max_failures, uint32_t window_s) const;
bool   would_lockout_ip(const std::string& ip, int max_failures, uint32_t window_s) const;
void   record_failure(const std::string& username, const std::string& ip, int max_keys);

// Observability counters (spec §8.6)
void   bump_probes_attempted();
void   bump_probes_ok();
void   bump_probes_failed_credentials();
void   bump_probes_failed_transport();
void   bump_lockouts_user();
void   bump_lockouts_ip();
void   bump_inflight_cap_rejects();
void   bump_cache_hits();
void   bump_cache_invalidations();
std::vector<metric_kv> metrics_snapshot() const;    // for stats_mysql_passthrough_auth_metrics
```

Does not modify or depend on `GloMyAuth` internals.

### 9.2 Entry point in protocol code

`MySQL_Protocol::PPHR_verify_password()` (lib/MySQL_Protocol.cpp ~L2395). Insert the cache-check + pass-through dispatch in the `vars1.password == NULL` and `strlen(vars1.password)==0` branches, before the existing LDAP / fail paths.

### 9.3 New protocol helpers

- `MySQL_Protocol::PPHR_passthrough_init` — sends `AuthMoreData{0x04}` if needed (caching_sha2 first stage), sets `switching_auth_stage=4`, transitions the session to `AUTHENTICATING_BACKEND_FOR_CLIENT` on stage-5 receipt of cleartext.
- `MySQL_Protocol::PPHR_passthrough_complete` — called from the session handler on probe completion; inserts into `GloMyPTAuthCache`, generates the OK packet.

### 9.4 New session handler

`MySQL_Session::handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT()` — drives the probe connection lifecycle. Modeled on `handler_again___status_CONNECTING_SERVER` but with the probe-specific success/failure handling and without touching `previous_status`.

### 9.5 Connection lifecycle (non-blocking, pooled)

There is no dedicated probe handle. The backend connect that validates the borrowed credential goes through the **normal** `CONNECTING_SERVER` non-blocking path, exactly like any backend acquisition. See §6.3 "Connection lifecycle (non-blocking, pooled)" for the two-phase `AUTHENTICATING_BACKEND_FOR_CLIENT` wrapper, the `ff=true` force-new rationale, and why the connect is pooled and counted against `mysql_servers.max_connections`.

The connection that authenticates the credential is returned to the pool on success; the client's first query then acquires its query-path backend connection through the normal lazy `CONNECTING_SERVER` path (it may even reuse the one just returned).

### 9.6 Admin command

`Admin_Handler.cpp` — register `PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE [FOR USER '<name>']`, calling `GloMyPTAuthCache->clear()` / `->evict(name)`.

### 9.7 Stats tables

Register two `stats_mysql_*` virtual tables in `lib/Admin_Bootstrap.cpp` and `lib/ProxySQL_Admin.cpp`:

- `stats_mysql_passthrough_auth_cache` — snapshot of cache entries (no passwords); populated from `GloMyPTAuthCache->snapshot()` on query. Schema in §8.6.
- `stats_mysql_passthrough_auth_metrics` — 9 monotonic counters + 2 current-state gauges; populated from `GloMyPTAuthCache->metrics_snapshot()` on query. Schema and per-metric semantics in §8.6.

Both are read-only and refresh from `GloMyPTAuthCache` on every SELECT.

## 10. Phasing

### Phase 1 (this proposal)
- `caching_sha2_password` only
- Empty-password rows: opt-in via `mysql-passthrough_auth_empty_password`
- Unknown users: opt-in via `mysql-passthrough_auth_unknown_users`
- In-memory `MySQL_Passthrough_Auth_Cache` (no persistence)
- TTL eviction (lazy)
- Backend-rejection-triggered invalidation
- `PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE [FOR USER ...]` admin command
- `stats_mysql_passthrough_auth_cache` virtual table
- TLS required (`require_tls=true` default)
- Generic ERR responses
- Rate limiting (per-user, per-IP) and global in-flight cap
- Audit log entries
- `COM_CHANGE_USER` to pass-through users → rejected

### Phase 2 (follow-up)
- `mysql_clear_password` plugin (LDAP-style cleartext) — easier, no full-auth round-trip
- RSA public-key support for non-TLS `caching_sha2_password`

### Phase 3 (if demand)
- `mysql_native_password` via scramble relay (couples frontend handshake to backend connect)
- `COM_CHANGE_USER` to pass-through users
- Per-username probe serialization (currently bounded only by the global in-flight cap)

## 11. Resolved decisions (formerly open questions)

1. **Probes count against `mysql_servers.max_connections`** — **yes**. The backend connect that validates the borrowed credential goes through the normal pooled, non-blocking `CONNECTING_SERVER` path and is counted against `mysql_servers.max_connections` and the pool's throttle, exactly like any backend acquisition. There is no separate one-shot probe handle (the earlier design bypassed the pool and was both a self-DoS vector — it blocked the worker thread — and a `max_connections` hole; it was removed). The pass-through-specific `mysql-passthrough_auth_max_inflight_probes` remains as an additional ceiling.
2. **Global in-flight probe cap** — yes, added as `mysql-passthrough_auth_max_inflight_probes` (default 100).
3. **Pre-compute hashes after successful learn** — no. Storing cleartext is sufficient; existing verification paths handle `stored=cleartext, client=any-supported-plugin` on the fly.
4. **Concurrent probes for the same username** — not serialized in Phase 1. The global in-flight cap implicitly bounds them; minor duplicate probing accepted.
5. **`COM_CHANGE_USER` to pass-through user** — rejected in Phase 1. May be revisited.
6. **Hot-reload when the master gate flips off** — existing cache entries remain valid (no new pass-through happens); admins drop them with `PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE` if desired.
7. **Routing/defaults for cached unknown users** — re-derived from globals each connect, not stored in cache entries.
8. **No writes to `mysql_users`** — confirmed; the cache is a separate in-memory structure.
9. **No persistence** — cache is in-memory only; restart starts cold.
