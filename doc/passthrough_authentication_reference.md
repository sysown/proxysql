# Pass-Through Authentication — Reference Manual

> **Availability:** Innovative tier (3.1.x) and AI/MCP tier (4.0.x), from
> 3.1.10 / 4.0.10 onward. The code ships in the Stable tier (3.0.x) but cannot be
> enabled there — `mysql-passthrough_auth_enabled=true` is refused at
> `LOAD MYSQL VARIABLES TO RUNTIME` on a Stable build and forced to `false`.
> Both 3.1.x and 4.0.x builds define `PROXYSQL31` (4.0 implies 3.1), which is the
> compile flag that permits the feature to be armed. MySQL protocol only.
> **Companion:** task-oriented guidance is in the
> [Pass-Through Authentication — User Manual](passthrough_authentication_user_manual.md).
> The internal design rationale is in
> [`doc/internal/passthrough_authentication.md`](internal/passthrough_authentication.md).

This document is a complete reference for every configuration variable, stats
table, admin command, audit event, and behavioral rule of pass-through
authentication. All names, defaults, and ranges below are taken from the shipped
implementation.

---

## 1. Configuration variables

All variables are `mysql-` global variables. Set them with `SET
mysql-<name>=<value>`, apply with `LOAD MYSQL VARIABLES TO RUNTIME`, and persist
with `SAVE MYSQL VARIABLES TO DISK`. All are **dynamic** (no restart required).
None are read-only.

### 1.1 Master and mode gates

| Variable | Type | Default | Meaning |
|---|---|---|---|
| `mysql-passthrough_auth_enabled` | bool | `false` | Master switch. When `false`, all pass-through logic is inert and the other variables have no effect. **Stable tier (3.0.x): forced to `false`** — a build without `PROXYSQL31` refuses to arm the feature and coerces this back to `false` at `LOAD MYSQL VARIABLES TO RUNTIME`, logging an error. |
| `mysql-passthrough_auth_empty_password` | bool | `true` | When the master switch is on, treat `mysql_users` rows with `password=''` as a pass-through signal (see §5). Only honored if `passthrough_auth_enabled=true`. |
| `mysql-passthrough_auth_unknown_users` | bool | `false` | When the master switch is on, allow pass-through for usernames with **no** `mysql_users` row. Only honored if `passthrough_auth_enabled=true`. |
| `mysql-passthrough_auth_require_tls` | bool | `true` | Refuse to run the full-auth exchange (and thus refuse pass-through) on a non-TLS frontend connection. |

### 1.2 Routing / defaults for unknown users

| Variable | Type | Default | Range | Meaning |
|---|---|---|---|---|
| `mysql-passthrough_default_hg` | int | `0` | `0`–`1048576` | Hostgroup used to probe, and to route, users with no `mysql_users` row. |
| `mysql-passthrough_default_schema` | string | `''` (empty) | — | Default schema for unknown users. When empty, falls back to `mysql-default_schema`. |

### 1.3 Cache

| Variable | Type | Default | Range | Meaning |
|---|---|---|---|---|
| `mysql-passthrough_auth_cache_ttl_s` | int | `0` | `0`–`604800` (7 days) | Cache entry lifetime in seconds. `0` = never expire (lazy eviction only on lookup when > 0). |

### 1.4 Allowlist

| Variable | Type | Default | Meaning |
|---|---|---|---|
| `mysql-passthrough_auth_username_pattern` | string (regex) | `''` (empty) | Only usernames matching this regular expression are eligible for pass-through. **Empty = allow all.** An **invalid** regex fails safe (deny all). When `unknown_users=true` and the pattern is empty, ProxySQL logs a warning at `LOAD MYSQL VARIABLES TO RUNTIME`. |

### 1.5 Rate limiting and probe concurrency

| Variable | Type | Default | Range | Meaning |
|---|---|---|---|---|
| `mysql-passthrough_auth_max_inflight_probes` | int | `100` | `1`–`10000` | Global cap on the number of backend probes in flight simultaneously. New attempts are rejected while saturated. |
| `mysql-passthrough_auth_max_failures_per_user` | int | `3` | `1`–`1000000` | Credential failures per username within the window before that username is locked out for the rest of the window. |
| `mysql-passthrough_auth_max_failures_per_ip` | int | `10` | `1`–`1000000` | Credential failures per source IP within the window before that IP is locked out for the rest of the window. |
| `mysql-passthrough_auth_failure_window_s` | int | `60` | `1`–`604800` | Sliding-window length, in seconds, for both failure counters. |
| `mysql-passthrough_auth_failure_map_cap` | int | `100000` | `1000`–`100000000` | Maximum distinct keys retained in the per-user and per-IP failure maps (churn defense; see §7.2). |

> **Interaction rule:** `mysql-passthrough_auth_empty_password` and
> `mysql-passthrough_auth_unknown_users` are only consulted when
> `mysql-passthrough_auth_enabled=true`. With the master switch off, ProxySQL
> behaves exactly as a build without pass-through.

---

## 2. Stats tables

Both tables are read-only virtual tables on the **stats** admin interface. They
are re-populated from the live in-memory cache on every `SELECT`. Neither table
exposes any password or cleartext credential material.

### 2.1 `stats_mysql_passthrough_auth_cache`

One row per cached (learned) credential.

```
CREATE TABLE stats_mysql_passthrough_auth_cache (
    username         VARCHAR NOT NULL PRIMARY KEY,
    learned_at       BIGINT  NOT NULL,
    age_s            INT     NOT NULL,
    hostgroup_probed INT     NOT NULL
)
```

| Column | Meaning |
|---|---|
| `username` | Frontend username whose credential is cached. |
| `learned_at` | Monotonic timestamp (microseconds since process start) when the entry was learned. |
| `age_s` | Age of the entry in seconds at query time. |
| `hostgroup_probed` | Hostgroup the successful probe targeted. |

> **Security:** with `unknown_users=true`, this list is exactly the set of
> usernames confirmed to be valid backend accounts. Restrict admin-port access and
> prefer a bounded `username_pattern`.

### 2.2 `stats_mysql_passthrough_auth_metrics`

Key/value counters and gauges. Counters are monotonic since process start and
reset only on restart; gauges reflect live state.

```
CREATE TABLE stats_mysql_passthrough_auth_metrics (
    metric_name  VARCHAR NOT NULL PRIMARY KEY,
    metric_value BIGINT  NOT NULL
)
```

| `metric_name` | Kind | Meaning |
|---|---|---|
| `probes_attempted` | counter | Probes that reached a backend connection (passed all eligibility gates). |
| `probes_ok` | counter | Probes the backend accepted; cache populated. |
| `probes_failed_credentials` | counter | Probes rejected by the backend with a credential-class errno (1045 / 1698 / 1130). |
| `probes_failed_transport` | counter | Probes that failed at transport (2xxx client errors, timeouts, infrastructure). Do **not** count toward lockout. |
| `lockouts_user` | counter | Times a per-user sliding-window cap fired. |
| `lockouts_ip` | counter | Times a per-source-IP sliding-window cap fired. |
| `inflight_cap_rejects` | counter | Attempts rejected because `max_inflight_probes` was saturated. |
| `cache_hits` | counter | Verifications served from the cache without a backend probe. |
| `cache_invalidations` | counter | Cached entries evicted because a later query-time backend connection was rejected with 1045 (see §8). |
| `inflight_probes` | gauge | Current number of in-flight probes. |
| `cache_entries` | gauge | Current number of cache entries. |

---

## 3. Admin commands

### `PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE`

Clears the **entire** in-memory pass-through credential cache.

### `PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER '<name>'`

Evicts a **single** user's cache entry. The username may be quoted with single
quotes (`'`), double quotes (`"`), or backticks (`` ` ``), or given unquoted; a
trailing `;` and surrounding whitespace are tolerated. Evicting a user that is not
cached is a no-op and still returns `OK`.

Both forms return an OK packet and log an informational line. They are modeled on
`PROXYSQL FLUSH LOGS` / `PROXYSQL FLUSH CONFIGDB`.

---

## 4. Audit log events

When the ProxySQL audit log is enabled, every pass-through decision emits one
entry. The JSON `event` field is one of:

| Internal event (`log_event_type`) | Audit-log `event` string |
|---|---|
| `PROXYSQL_MYSQL_AUTH_PASSTHROUGH_OK` | `MySQL_Client_Connect_Passthrough_OK` |
| `PROXYSQL_MYSQL_AUTH_PASSTHROUGH_FAIL` | `MySQL_Client_Connect_Passthrough_FAIL` |

Each entry includes the username, source IP, and the hostgroup probed.

---

## 5. Empty-password row semantics

| Condition | Behavior |
|---|---|
| `passthrough_auth_enabled=false` | A `mysql_users` row with `password=''` allows **passwordless login** (stock behavior). |
| `passthrough_auth_enabled=true` **and** `passthrough_auth_empty_password=true` | A `password=''` row is a **pass-through signal only**. The client must send a password, which is probed against the row's `default_hostgroup`. Passwordless login no longer works for these rows. |
| `passthrough_auth_enabled=true` **and** `passthrough_auth_empty_password=false` | Empty-password rows are not used for pass-through; stock empty-password handling applies. |

This behavior change is deliberate and fully gated behind the master switch.

---

## 6. Session defaults for unknown users

When pass-through completes for a user with **no** `mysql_users` row, no row is
inserted. Session state is derived from globals **at each connect**:

| Session property | Source |
|---|---|
| `default_hostgroup` | `mysql-passthrough_default_hg` |
| `default_schema` | `mysql-passthrough_default_schema`, falling back to `mysql-default_schema` if empty |
| `max_connections`, `schema_locked`, `transaction_persistent`, `fast_forward`, … | global defaults |

Because these are re-evaluated per connect, changing `mysql-passthrough_default_hg`
affects routing on the **next** connect from a cached unknown user — no cache
flush required.

For an **empty-password row**, the probe and routing use that row's own
`default_hostgroup` and other `mysql_users` attributes, exactly as for a normal
user.

---

## 7. Security model

### 7.1 TLS requirement

With `mysql-passthrough_auth_require_tls=true` (default), ProxySQL will not perform
the `caching_sha2_password` full-auth exchange that yields the cleartext password
unless the frontend connection is over TLS. Non-TLS `caching_sha2_password` via an
RSA public key is **not** supported in Phase 1.

### 7.2 Rate limiting

Two sliding-window failure counters are maintained: one keyed by **username**, one
by **source IP**, both over `mysql-passthrough_auth_failure_window_s` seconds. When
a key exceeds its threshold (`max_failures_per_user` / `max_failures_per_ip`),
further pass-through attempts for that key are rejected with the generic error for
the remainder of the window.

- **Only credential-class failures** (backend errno 1045 / 1698 / 1130) count.
- **Transport-class failures** (2xxx, timeouts) do **not** count — a slow or
  unreachable backend cannot lock out legitimate users.
- Successful probes neither increment nor decrement the counters.

**Churn defense.** The two failure maps are bounded by
`mysql-passthrough_auth_failure_map_cap`. On recording a failure, if a map exceeds
the cap, ProxySQL first sweeps empty (expired-window) entries and, if still over
the cap, drops the deque with the oldest front timestamp. This bounds memory under
hostile traffic that churns unique usernames or IPs.

### 7.3 In-flight probe cap

A global counter tracks probes currently authenticating a backend. When it reaches
`mysql-passthrough_auth_max_inflight_probes`, new pass-through attempts are rejected
(counted in `inflight_cap_rejects`) until a slot frees. This also implicitly bounds
concurrent same-username probe races.

### 7.4 Username allowlist

`mysql-passthrough_auth_username_pattern` is a regex; only matching usernames are
eligible. Empty = allow all. An **invalid** regex fails safe (deny). Enabling
`unknown_users` with an empty pattern logs a warning at runtime load.

### 7.5 Error handling / non-oracle behavior

All pass-through failures return a **generic** `Access denied for user '<U>'` to
the client. The backend's actual error is never forwarded, so ProxySQL does not
leak backend topology and cannot be used as a username/password oracle via message
differences.

---

## 8. Cache lifecycle

| Event | Effect |
|---|---|
| Successful probe | `(username, cleartext, learned_at, hostgroup_probed)` inserted into the in-memory cache. |
| Subsequent connect within TTL | Cache hit; the client's response is verified locally against the cached cleartext — no backend probe. `cache_hits` incremented. |
| TTL expiry (`cache_ttl_s > 0`) | On the next lookup, an entry older than the TTL is treated as a miss and removed (lazy eviction). No background sweep. |
| Backend rejects a **learned** credential with 1045 during query traffic | The user's cache entry is evicted immediately (`cache_invalidations` incremented). The current connection still fails; the next connect re-probes. |
| `PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE [FOR USER ...]` | Manual eviction (all / one user). |
| ProxySQL restart | Cache is lost (in-memory only; cold start). |

The cache is **never** written to `mysql_users`, is **not** persisted, and is
**not** synchronized across a ProxySQL cluster.

---

## 9. Protocol / plugin compatibility matrix

| Stored in `mysql_users` | Client auth plugin | Gate on? | Outcome |
|---|---|---|---|
| `password='<hash>'` | any | — | Normal flow; pass-through not involved. |
| `password=''` | `caching_sha2_password` | `empty_password=true` | **Pass-through (probe & cache).** |
| `password=''` | `mysql_clear_password` | `empty_password=true` | Not supported in Phase 1 (planned Phase 2). |
| `password=''` | `mysql_native_password` | `empty_password=true` | **Rejected** (cleartext never available). |
| no row | `caching_sha2_password` | `unknown_users=true` | **Pass-through (cache only).** |
| no row | `mysql_clear_password` | `unknown_users=true` | Not supported in Phase 1 (planned Phase 2). |
| no row | `mysql_native_password` | `unknown_users=true` | **Rejected.** |

`COM_CHANGE_USER` targeting a user that would require pass-through is **rejected**
in Phase 1 (generic error), before any session state is mutated. Reconnect
instead.

---

## 10. Behavioral internals (informational)

These details are not configuration but explain observable behavior:

- **The probe is a real, pooled, non-blocking backend connection.** It goes through
  the standard `CONNECTING_SERVER` path and is **counted against
  `mysql_servers.max_connections`** and the pool throttle, exactly like any backend
  acquisition. `mysql-passthrough_auth_max_inflight_probes` is an *additional*
  pass-through-specific ceiling.
- The connection is acquired **force-new** so the pool cannot satisfy a probe by
  reusing a connection authenticated earlier with a different password — the
  backend must actually validate the borrowed credential.
- **`mysql_thread___connect_retries_on_failure` does not apply** to a probe: a
  credential verdict is a single-attempt outcome.
- On success, the now-authenticated backend connection is returned to the pool;
  the client's first query acquires its backend connection through the normal lazy
  path (and may reuse the one just returned).
- A dedicated session state, `AUTHENTICATING_BACKEND_FOR_CLIENT`, drives the probe
  lifecycle (modeled on the LDAP out-of-band auth state).

---

## 11. Roadmap (subject to change)

| Phase | Scope |
|---|---|
| **Phase 1 (current)** | `caching_sha2_password`; empty-password and unknown-user modes; in-memory cache with TTL + backend-rejection invalidation; `PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE`; two stats tables; TLS required; per-user/per-IP rate limiting + global in-flight cap; audit logging; `COM_CHANGE_USER` to pass-through users rejected. |
| **Phase 2** | `mysql_clear_password` (LDAP-style cleartext); RSA public-key support for non-TLS `caching_sha2_password`. |
| **Phase 3 (if demand)** | `mysql_native_password` via scramble relay; `COM_CHANGE_USER` to pass-through users; per-username probe serialization. |

Non-goals (not planned): making `mysql_native_password` cleartext-free
pass-through work without scramble relay; replacing LDAP or other auth backends;
persisting the cache; cluster-syncing learned credentials.

---

## 12. Variable quick-reference

```
mysql-passthrough_auth_enabled                bool    false      master switch
mysql-passthrough_auth_empty_password         bool    true       empty-pw rows → pass-through
mysql-passthrough_auth_unknown_users          bool    false      no-row users → pass-through
mysql-passthrough_auth_require_tls            bool    true       require TLS frontend
mysql-passthrough_default_hg                  int     0          [0..1048576]  probe/route hg for unknown users
mysql-passthrough_default_schema              string  ''         default schema (falls back to mysql-default_schema)
mysql-passthrough_auth_cache_ttl_s            int     0          [0..604800]   0 = never expire
mysql-passthrough_auth_username_pattern       string  ''         regex allowlist ('' = allow all; invalid = deny all)
mysql-passthrough_auth_max_inflight_probes    int     100        [1..10000]
mysql-passthrough_auth_max_failures_per_user  int     3          [1..1000000]
mysql-passthrough_auth_max_failures_per_ip    int     10         [1..1000000]
mysql-passthrough_auth_failure_window_s       int     60         [1..604800]
mysql-passthrough_auth_failure_map_cap        int     100000     [1000..100000000]
```
