# mysqlx Route Identity — Design Spec

**Status:** Draft, pending review
**Date:** 2026-04-17
**Scope:** Phase 4 item 1 of `docs/superpowers/plans/2026-04-17-plugin-chassis-extraction.md` — fix the critical routing bug in the active mysqlx path where sessions connect to empty address + port 0 on cache miss.

---

## Problem

`plugins/mysqlx/src/mysqlx_session.cpp:60-62` and `:76-78` clear `target_hostgroup_`, `target_address_`, `target_port_` at `init()` and `reset()`. `handler_connecting_server` at `:687,692` uses them for cache lookup and `start_connect()`. Nothing in the active path ever assigns them. The only wiring in `mysqlx_thread.cpp:224-244` sets up a `credential_lookup_` callback that returns `MysqlxCredentials` — which contains password material but not routing fields. On cache miss, the session connects to `""` on port `0`.

The codebase also contains a dormant parallel implementation in `plugins/mysqlx/src/mysqlx_worker.cpp` (`MysqlxWorker` + `g_workers` + `MysqlxListenerHandle`). That path already solves route identity: it uses `identity.default_route → config_store->pick_endpoint(route_name)` (`mysqlx_worker.cpp:185`) and per-listener `route_name` tracking (`mysqlx_worker.cpp:261`). But `mysqlx_start_listeners_from_runtime_routes` — the only entry point into the worker path — has zero call sites. The dormant path is dead code.

This spec migrates the worker path's user-driven route-resolution semantics into the active session path. It does **not** migrate the listener-to-route mapping; that stays a possible future iteration.

## Semantics

**User-driven route resolution.** Routes are resolved from `identity.default_route`. The listener a client connects to is treated as a bare network entry point; it does not influence route choice. `mysqlx_users.default_route` is the authoritative field.

**Three distinct failure modes** at auth-complete time, each with its own error code, each sent as an X-Protocol `Error` frame **before** the X-Protocol `Ok` frame. Once `Ok` is on the wire, the session cannot cleanly report a routing error.

| Condition | Code | Message |
|---|---|---|
| `identity.default_route.empty()` | 4000 | `User has no default_route configured` |
| route not in config store | 4001 | `Route '<name>' not found` |
| route exists but `pick_endpoint` returns empty endpoint | 4002 | `No backend available for route '<name>'` |

Codes 4000/4001/4002 mirror the dormant worker path (`mysqlx_worker.cpp:188,200`). They are working values; final reconciliation with ProxySQL's project-wide error-code policy is deferred to a separate follow-up commit.

All three failure modes record via `mysqlx_stats().record_conn_err(route_name, hg)`. `hg` is the route's hostgroup when known, `0` when the route itself is unknown.

## Architecture

### Identity lookup

Replace the `MysqlxCredentialLookup` callback and `MysqlxCredentials` struct in `plugins/mysqlx/include/mysqlx_session.h` with a callback returning `std::optional<MysqlxResolvedIdentity>`. The struct already exists in `plugins/mysqlx/include/mysqlx_config_store.h` and carries every field the session needs now (`username`, `password`, `x_enabled`, `require_tls`, `allowed_auth_methods`, `default_route`, `backend_username`, `backend_password`, `backend_auth_mode`) plus fields the session may need later (`policy_profile`, `attributes`, `default_hostgroup`, `max_connections`). Widening the ABI now avoids a second migration later.

Note: `MysqlxResolvedIdentity` has `password` (stored form — either cleartext or the `*HEX` mysql_native_password format) but **not** `password_hash`. The 20-byte hash derivation currently done by the credential-lookup lambda in `mysqlx_thread.cpp:232-242` moves into the session's auth handlers. The session takes `identity_->password`, dispatches on whether the first char is `*`, and calls either `mysqlx_hex_decode` or `mysqlx_mysql41_hash` as the lambda does today. Same logic, different location.

New typedef:

```cpp
using MysqlxIdentityLookup =
    std::function<std::optional<MysqlxResolvedIdentity>(const std::string& username)>;
```

### Session state

`MysqlxSession` gains one member: `std::optional<MysqlxResolvedIdentity> identity_`. The existing `username_`, `schema_`, `auth_method_`, `auth_challenge_` members stay (they are protocol-level state, not identity data). The three target fields — `target_hostgroup_`, `target_address_`, `target_port_` — stay, because `handler_connecting_server` uses them for cache lookup; they become populated outputs of the resolve step rather than always-zero placeholders.

`init()` and `reset()` clear `identity_` in addition to what they already clear.

### Resolve step

A new private method:

```cpp
int MysqlxSession::resolve_backend_target();
```

Returns `0` on success with `target_*` populated. Returns a nonzero error code (`4000|4001|4002`) on failure, having already emitted the X-Protocol `Error` frame and called `mysqlx_stats().record_conn_err(...)`.

Called once, at auth-complete, from the auth handler, **before** sending `Ok`. Pseudocode:

```
if (!identity_) return unreachable;  // invariant: auth succeeded

const std::string& route_name = identity_->default_route;
if (route_name.empty()) {
    send_error(4000, "User has no default_route configured");
    mysqlx_stats().record_conn_err("", 0);
    return 4000;
}

MysqlxConfigStore* cs = thread_ptr_->get_config_store();
int hg = cs->route_hostgroup(route_name);
if (hg == 0 && !cs->route_exists(route_name)) {  // see note on route_exists
    send_error(4001, "Route '" + route_name + "' not found");
    mysqlx_stats().record_conn_err(route_name, 0);
    return 4001;
}

MysqlxBackendEndpoint ep = cs->pick_endpoint(route_name);
if (ep.hostname.empty()) {
    send_error(4002, "No backend available for route '" + route_name + "'");
    mysqlx_stats().record_conn_err(route_name, hg);
    return 4002;
}

target_hostgroup_ = hg;
target_address_   = ep.hostname;
target_port_      = ep.mysqlx_port;
return 0;
```

Note on `route_exists`: `MysqlxConfigStore::route_hostgroup` returns 0 both when the route is missing and when the route has `destination_hostgroup=0`. To distinguish unknown-route (4001) from a legitimate hostgroup-0 configuration that happens to have no endpoints (4002), the spec assumes a predicate `bool route_exists(const std::string&) const` exists or is added on `MysqlxConfigStore`. If adding it is undesirable, an alternative is to have `pick_endpoint` return a tri-state (`UNKNOWN_ROUTE | NO_BACKEND | ok+endpoint`). The simpler option is preferred; pick during implementation.

### State transitions

```
[handler_auth_challenge_response]
         │
         ▼
  auth credentials OK?
         │
    yes ─┤
         ▼
  resolve_backend_target()
         │
     0 ──┤                       nonzero ──┐
         ▼                                  ▼
  send X-Proto Ok                   send X-Proto Error (4000|4001|4002)
  status_ = CONNECTING_SERVER        healthy_ = false
                                     status_ = X_SESSION_CLOSING
```

### Config store access

The session reaches the config store via `thread_ptr_->get_config_store()`. This is already the pattern the thread uses when building the credential lambda (`mysqlx_thread.cpp:224`). No new injection seam.

## Components and files

### Files modified

| File | Change |
|---|---|
| `plugins/mysqlx/include/mysqlx_session.h` | Remove `MysqlxCredentials`, `MysqlxCredentialLookup`. Add `#include "mysqlx_config_store.h"`. Add `MysqlxIdentityLookup` typedef. Add `std::optional<MysqlxResolvedIdentity> identity_` member. Add `int resolve_backend_target()` private method. Rename `set_credential_lookup` → `set_identity_lookup`. |
| `plugins/mysqlx/src/mysqlx_session.cpp` | `init()` and `reset()` clear `identity_`. Auth handlers populate `identity_` from lookup result; derive the 20-byte password hash from `identity_->password` in the session itself (logic moved from `mysqlx_thread.cpp:232-242`). Implement `resolve_backend_target()`. Call it at auth-complete, pre-`Ok`. |
| `plugins/mysqlx/src/mysqlx_thread.cpp` | Collapse the 20-line `credential_lookup` lambda (`:225-244`) to `[store](const std::string& u) { return store->resolve_identity(u); }`. Update call site to `set_identity_lookup`. |
| `plugins/mysqlx/include/mysqlx_config_store.h` | Add `bool route_exists(const std::string&) const` if the simpler disambiguation option is chosen (see "Resolve step" note). |
| `plugins/mysqlx/src/mysqlx_config_store.cpp` | Implement `route_exists` if added. |
| `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp` | Update existing fake lookups to return `MysqlxResolvedIdentity`. Add six new tests (below). |

### Files intentionally not modified

- `plugins/mysqlx/src/mysqlx_worker.cpp`, `plugins/mysqlx/include/mysqlx_worker.h` — dead code. A separate tight commit will remove them after this lands.
- `plugins/mysqlx/src/mysqlx_connection.cpp` — backend connect uses the populated `target_*` fields exactly as today.
- `plugins/mysqlx/src/mysqlx_plugin.cpp`, `plugins/mysqlx/src/mysqlx_admin_schema.cpp` — no data-model changes.
- `test/tap/tests/test_mysqlx_e2e_routing-t.cpp` — correct as written; will start passing once Phase 1b brings up proxysql+mysqlx in CI.

## Testing

### Unit tests (added to `test/tap/tests/unit/mysqlx_robustness_unit-t.cpp`)

1. **`test_routing_happy_path`** — lookup returns identity with valid `default_route`; config store has route pointing at hostgroup with one endpoint. After auth, `target_hostgroup_` / `target_address_` / `target_port_` are populated and `status_` is `CONNECTING_SERVER`.
2. **`test_routing_unknown_user`** — lookup returns `nullopt`. Existing auth-error path fires. Regression coverage for the pre-existing behavior.
3. **`test_routing_no_default_route`** — identity has `default_route=""`. Session emits error 4000, `healthy_=false`, `status_=X_SESSION_CLOSING`, no `Ok` frame on wire.
4. **`test_routing_unknown_route`** — `default_route="nope"`, route absent from store. Error 4001.
5. **`test_routing_no_backend`** — valid route, but `pick_endpoint` returns empty (no endpoints registered for the hostgroup). Error 4002.
6. **`test_routing_stats_on_failure`** — `mysqlx_stats().record_conn_err` receives `("", 0)` for no-default-route, `("nope", 0)` for unknown-route, `(route_name, hg)` for no-backend.

All six tests use a fake `MysqlxConfigStore` or a real one with fixture-configured routes/endpoints. No real backend needed.

### E2E validation

`test/tap/tests/test_mysqlx_e2e_routing-t.cpp` already exists and already assumes a working routing implementation. Once Phase 1b lands (`docs/superpowers/plans/2026-04-17-plugin-chassis-extraction.md` task #2: build proxysql, configure a route, start the mysqlx plugin listener in CI), this test runs end-to-end. Out of scope for this spec but blocks closure of Phase 4 item 1.

## Explicit non-goals

- Listener-driven or hybrid routing (original brainstorm options B and C). User-driven is chosen for this iteration; listener-driven can be a future spec with its own design.
- Removing the dead worker path (`mysqlx_worker.cpp`, `mysqlx_worker.h`, `MysqlxListenerHandle`, `g_workers`, `g_listeners`). Separate tight commit after this lands.
- Reconciling error codes 4000/4001/4002 with a project-wide ProxySQL error-code range. Follow-up commit.
- Phase 1b CI infrastructure. Tracked separately.

## Risks

- **Tri-state vs predicate for route-existence check.** Choice deferred to implementation. Both options are small; worst case we refactor after feedback. Captured in the "Resolve step" note.
- **Pre-`Ok` error semantics during auth.** Sending an `Error` frame before `Ok` is conventional in X Protocol auth flow, but three distinct codes for what are technically post-auth failures is a small semantic stretch. Documented here so reviewers don't flag it as a bug.
- **Interaction with connection cache.** Cache key is `(target_hostgroup_, username, schema)`. Since `target_hostgroup_` is now derived from the resolved route, cache semantics are preserved for the common case. A user whose `default_route` changes at runtime will get a new hostgroup and naturally miss the old cache entries. No code change needed.
