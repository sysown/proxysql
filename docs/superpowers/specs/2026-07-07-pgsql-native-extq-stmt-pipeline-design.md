# PgSQL Native Extended Query via the Prepared-Statement Pipeline — Design

**Date:** 2026-07-07
**Status:** Parity + Describe cache IMPLEMENTED (Tasks A-E of the companion plan, 2026-07-07);
named portals (§4) IMPLEMENTED (Tasks P1-P3 of `2026-07-07-pgsql-native-named-portals-plan.md`,
2026-07-08): registry + immediate native Bind dispatch (BIND stmt phase), Execute/Describe/Close
routing with max_rows + PortalSuspended resume, txn-scoped lifetime + sticky pinning, raw-wire
differential vs direct PostgreSQL (SCRAM-capable pg_lite_client) — zero divergences. Known
follow-up: cross-hostgroup registry-clear edge under transaction_persistent=0 (pre-existing
shape; tie clearing to the portal-holding conn). Approved in-session by René Cannaò (4 decisions
recorded below)
**Branch:** `feature/pgsql-native-backend-protocol`
**Supersedes:** §3.3 of `2026-06-14-pgsql-native-txn-copy-prepared-design.md` (raw pass-through, "no pooling") — that approach was implemented (commits `051dd25ec`..`a254976dd`) and is REMOVED by this design.

## 1. Decisions (locked, 2026-07-07)

1. **Architecture:** native extended query retains ProxySQL's ENTIRE prepared-statement pipeline — `handle_post_sync_*` handlers, `GloPgStmt` global cache (hash-dedup, refcounts), `local_stmts` client registry, the backend-id reuse decision (`PgSQL_Session.cpp:3474`: `find_backend_stmt_id_from_global_id` == 0 → implicit-Parse detour, else reuse `proxysql_ps_<id>`), and the ack-synthesis rules. Only the **wire layer** is swapped: the `stmt_*_start` bodies emit native Parse/Bind/Describe/Execute + Flush/Sync instead of `PQsendPrepare`/`PQsendDescribePrepared`/`PQsendDescribePortal`/`PQsendQueryPrepared`, and the result side consumes real backend messages instead of rebuilding from `PGresult`.
2. **The raw pass-through machinery is dead code — remove it** (session raw capture, `async_native_extq`, `query_start` extq branch, connection frame/inflight state, `pg_native_build_extq_outbuf`, session native-dispatch branch + COPY/LISTEN gates). Keep: the CopyFail safety net + flush preamble in `native_fetch_result_cont` (Task 2), `pg_native_build_copyfail`.
3. **Describe metadata caching: yes.** Cache the statement-level Describe results (ParameterDescription `'t'` payload + RowDescription `'T'` payload / NoData marker) on `PgSQL_STMT_Global_info`, set-once, serve subsequent statement-level Describes from cache in BOTH modes (libpq and native). Portal-level Describe is never cached (depends on bound result formats). DDL staleness accepted and documented (same class of trade-off as MySQL stmt metadata caching).
4. **Named portals must be supported** — a primary motivation for leaving libpq (libpq cannot express them). Phasing: parity first (named portals still rejected, exactly as today), then named-portal support as the immediately-following phase on this branch. Named portals are a native-mode-only capability; their tests compare ProxySQL-native against DIRECT PostgreSQL (libpq mode cannot serve as oracle).

## 2. Wire-layer swap (parity phase)

### Send side — new frontend-message builders

Free functions in `PgSQL_Backend_Protocol.{h,cpp}` (unit-testable, byte-exact):
- `pg_build_parse(out, stmt_name, query, param_oids)` — `'P'`
- `pg_build_bind(out, portal, stmt_name, param_formats, param_values/lengths (with NULL = -1), result_formats)` — `'B'`; encodes the client's Bind faithfully from the already-parsed `PgSQL_Bind_Message` data (same source `stmt_execute_start` feeds libpq)
- `pg_build_describe(out, 'S'|'P', name)` — `'D'`
- `pg_build_execute(out, portal, max_rows)` — `'E'` (max_rows 0 for parity phase)
- `pg_build_close(out, 'S'|'P', name)` — `'C'` (parity phase: unused on the wire, mirroring libpq mode where Close is local-only; needed for named portals + future GC)
- `pg_build_flush(out)` — `'H'`; `pg_build_sync(out)` — `'S'`

### Native `stmt_*` drives (in `PgSQL_Connection`)

Native branches of `stmt_prepare_start` / `stmt_describe_start` / `stmt_execute_start` append the step's messages to `native_outbuf`, terminated by Flush or Sync per the SAME existing flags (`PGSQL_EXTENDED_QUERY_FLAG_SYNC` / `_IMPLICIT_PREPARE`) that gate `PQsendFlushRequest` vs `PQsendPipelineSync` today. Execute prepends Bind (and Describe('P') when `send_describe_portal_result`).

### Receive side — per-step drain with expected terminators

The native drain (extension of the Task-2-hardened pump) needs per-phase termination instead of 'Z'-only:
- PREPARE: complete on `'1'` (Flush-terminated) or `'1'`+`'Z'` (Sync-terminated); on `'E'`, enter aborted-until-Sync handling.
- DESCRIBE('S'): `'t'` then `'T'`|`'n'`; DESCRIBE('P'): `'T'`|`'n'`.
- EXECUTE: `'2'` (suppressed), optional `'T'`|`'n'` (only when Describe('P') was folded in), `'D'`* stream-through, `'C'` (or `'I'`), then `'Z'` if Sync-terminated. `'s'` PortalSuspended handled defensively (unreachable at max_rows 0).

**Ack filtering (parity with libpq-mode synthesis):** suppress backend `'2'` BindComplete (session already synthesized it at Bind intake); suppress `'1'` for implicit prepares (client never asked); forward `'1'` for real client Parses (cache-miss); `'3'` CloseComplete never expected (Close is local). Error mid-frame: mirror the libpq pipeline-abort semantics — the session's existing `handler___rc*_PROCESSING_STMT_*` error paths are the contract; the native drive must surface equivalent rc/error state and drain to `'Z'` after Sync.

### What falls out for free
- `DEALLOCATE`/Close parity (client names registered in `local_stmts` by the shared handlers) — fixes P11/P14/P15.
- Cross-session statement dedup, per-backend reuse, implicit-Parse, refcounting, stats — all shared code.
- Describe forwards the backend's exact `'t'`/`'T'` bytes (better than libpq's rebuild).

## 3. Describe metadata cache

On `PgSQL_STMT_Global_info`: set-once cached `param_desc` (payload of `'t'`) and `row_desc` (payload of `'T'`, or explicit NoData marker), guarded for concurrent set (fill-if-empty under the manager's lock or atomic pointer). Populated from the first successful statement-level Describe in either mode (native: raw payload; libpq: encode from PGresult once). `handle_post_sync_describe_message` serves statement-level Describe from cache when present — no backend round trip, both modes. Cache lives/dies with the global statement entry (purged by the existing GC). Portal Describe always round-trips.

## 4. Named portals (follow-on phase, this branch)

- Lift the three "only unnamed portals are supported" rejections (Bind/Describe/Execute sites) for native-mode sessions only; libpq-mode keeps rejecting.
- Session portal registry: portal name → (bound Bind message, global stmt). Named Bind is sent to the backend immediately (not deferred like the unnamed stash) on the transaction-pinned connection; BindComplete forwarding follows the real backend ack (no synthesis for named portals).
- Portal lifetime: destroyed at Sync outside an explicit transaction, at transaction end, or by Close('P') (forwarded natively; CloseComplete from backend). Execute with max_rows > 0 and `'s'` PortalSuspended resume supported.
- Multiplexing: named-portal use pins the connection (same mechanism as active-transaction pinning) until all named portals are closed/invalidated.
- Tests: differential vs DIRECT PostgreSQL (same corpus through proxy-native and straight to the backend), since libpq-as-client cannot emit named portals through PQsend* — the test crafts extended-query messages explicitly or uses a minimal wire client helper.

## 5. Testing

- Parity phase: `pgsql-native_prepared-t` strict (escape hatch removed), P11/P14/P15 green, EXT_* byte-equal, plus implicit-prepare-on-second-connection and cross-session-dedup cases if expressible.
- Cache phase: new cases proving second Describe of the same statement is served identically (byte-equal) and (via stats or log) without a backend round trip.
- Portal phase: direct-vs-proxy differential for named Bind/Describe/Execute/Close, partial Execute + resume, portal-in-txn lifetime, error paths.
- Unit tests for every new builder (byte-exact) and for the metadata-cache set-once behavior.
