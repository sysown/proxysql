# PgSQL Native Named Portals — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox syntax.
> Spec: `docs/superpowers/specs/2026-07-07-pgsql-native-extq-stmt-pipeline-design.md` §4 (user decision: named portals REQUIRED — a primary motivation for leaving libpq).

**Goal:** Native-mode sessions accept named portals — Bind/Describe('P')/Execute/Close('P') with a non-empty portal name, including `max_rows` execution with PortalSuspended/resume — while libpq-mode sessions keep rejecting them exactly as today. Tested with the in-tree raw-wire client (`pg_lite_client`) against a direct-PostgreSQL oracle.

**Architecture:** A session-level portal registry (name → bound Bind message + statement info + suspended flag) replaces nothing — the existing single-slot `bind_waiting_for_execute` unnamed-portal path stays byte-identical. Named Bind dispatches to the backend immediately as a new 4th statement phase (`PROCESSING_STMT_BIND` / `PGSQL_EXTENDED_QUERY_TYPE_BIND` / native `stmt_bind_start`), forwarding the backend's real BindComplete; Execute/Describe('P')/Close('P') route by portal name through the existing native drives with the portal name and client `max_rows` threaded into the already-parameterized builders. Portal lifetime: evicted on real CloseComplete, cleared when a cycle ends with ReadyForQuery txn-state `'I'` (backend destroyed them), on session reset/destroy. The connection stays pinned while the registry is non-empty via the existing `sticky_backend_connection` mechanism.

**Tech Stack:** C++17; existing native drives + builders; `pg_lite_client` raw-wire TAP client; libscram wrappers for the direct-backend oracle leg.

## Global Constraints

- Build DEBUG ONLY: `make debug -j$(nproc)` (never plain `make` — shared lib/obj poisoning; never unbounded `-j`). After every rebuild: `docker restart proxysql.dev-rene-natproto`.
- Infra: `INFRA_ID="dev-rene-natproto"`, `TAP_GROUP="legacy-g1"`, `SKIP_CLUSTER_START=1`, `source test/infra/common/env.sh`; single test `TEST_PY_TAP_INCL=<name>`; ensure-infras workarounds in `.superpowers/sdd/task-2-report.md` (COMPOSE_PROJECT) and `taskD-report.md` (INFRA/ROOT_PASSWORD).
- Commit style + trailer `Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7`.
- **Behavioral invariants (hard):** (1) libpq-mode sessions keep ALL FOUR "only unnamed portals are supported" rejections byte-identically; (2) the unnamed-portal flow (single-slot stash, synthesized BindComplete/CloseComplete, `max_rows` forced 0) is UNCHANGED in both modes — the existing differential suite is the regression net and must stay green (`pgsql-native_prepared-t` 27/27 etc.); (3) named-portal support is native-mode-only.
- Key code map (verified 2026-07-07 at HEAD c4d6c7051 — re-verify, lines shift): rejections `lib/PgSQL_Session.cpp:6986` (Bind), `:6772` (Describe P), `:7079` (Execute), `:6952` (Close P); single-slot stash set `:7060`, consumed `:7085-7112` (assert at `:7091`), resets `:2605,:3182,:3610,:3616,:6957,:7237`; reuse/implicit-Parse decision `:3474-3506` (statuses DESCRIBE|EXECUTE); RunQuery stmt dispatch `:3056-3110`; finishQuery sticky path `:6224-6228`, entry `:3585-3605` (`has_pending_messages`); `PgSQL_Extended_Query_Info` `include/PgSQL_Session.h:149-159` (`stmt_client_portal_name` today always ""); Execute max_rows parsed-but-ignored (`PgSQL_Extended_Query_Data::max_rows`, `include/PgSQL_Extended_Query_Message.h:319`); native builders call sites `lib/PgSQL_Connection.cpp:3717` (`pg_build_bind(..., portal="", ...)` inside stmt_execute_start), `:3733` (`pg_build_describe('P',"")`), `:3736` (`pg_build_execute(native_outbuf,"",0)`); native EXECUTE terminator already accepts `'s'` `:2916-2921`; `'s'` classified ACK `lib/PgSQL_Protocol.cpp:2781`; native ack filtering suppresses `'2'` always and `'3'` is never expected (both must become step-conditional); `PG_Native_Stmt_Step` enum `include/PgSQL_Connection.h` (Task C).
- Raw client: `test/tap/tests/pg_lite_client.{h,cpp}` — `PgConnection` with `prepareStatement/bindStatement/describePortal/executePortal/closePortal/sendSync` (named-portal capable), cleartext auth only (`pg_lite_client.cpp:296-336`, throws on SASL). Makefile per-test rules with `pg_lite_client.cpp` at `test/tap/tests/Makefile:347-360`. Frontend cleartext precedent: `pgsql-extended_query_protocol_test-t.cpp:5075` (`SET pgsql-authentication_method=1`). Direct backend (`cl.pgsql_server_host/port`) demands scram-sha-256 on ALL TCP (`test/infra/docker-pgsql16-single/conf/pgsql/pgsql1/pg_hba.conf:20-29`); SCRAM client wrappers exist in libproxysql.a (`pg_scram_new/client_first/client_final/verify_server_final`, `include/PgSQL_Backend_Protocol.h:96-121`) but need `-lscram -lusual` added to the test's link rule (galera rules at Makefile:204,207 are the precedent).

---

### Task P1: Portal registry + named-Bind dispatch (new BIND statement phase)

**Files:** `include/PgSQL_Session.h`, `lib/PgSQL_Session.cpp`, `include/PgSQL_Connection.h`, `lib/PgSQL_Connection.cpp`, `include/proxysql_structs.h` (only if a new `PG_ASYNC_ST` state is needed — prefer reusing `ASYNC_STMT_EXECUTE_*` states with the step enum distinguishing, decide by reading), plus whatever enum carries `PGSQL_EXTENDED_QUERY_TYPE_*` (find it — likely `include/PgSQL_Connection.h` or `proxysql_structs.h`).

**Interfaces produced (later tasks consume):**
- Session member: `std::map<std::string, PgSQL_Portal_Entry> named_portals;` with
  ```cpp
  struct PgSQL_Portal_Entry {
      std::unique_ptr<const PgSQL_Bind_Message> bind_msg;  // owns raw bytes (param re-readers work)
      std::shared_ptr<const PgSQL_STMT_Global_info> stmt_info;
      bool bound_on_backend = false;   // real backend Bind completed
      bool suspended = false;          // last Execute ended with PortalSuspended
  };
  ```
  plus `void clear_named_portals();` (called from: cycle-completion when the drained ReadyForQuery carried txn-state `'I'` — read it from `myconn->native_txn_status` after rc==0; `reset()`/destructor; `reset_extended_query_frame` is NOT the right place — portals outlive frames inside a txn).
- New extended-query type `PGSQL_EXTENDED_QUERY_TYPE_BIND` + session status `PROCESSING_STMT_BIND` + native step `PG_Native_Stmt_Step::BIND` (terminator `'2'`, which is FORWARDED during this step — see ack-filter change).
- `handle_post_sync_bind_message` named-portal branch (native-only).

**Steps:**
- [ ] **P1.1 Gate lift, native-only.** In all four rejection sites, replace the unconditional error with:
  ```cpp
  if (<name>[0] != '\0') {
      PgSQL_Connection* fe_conn = client_myds->myconn; // frontend conn: NOT the backend
      if (!pgsql_thread___use_native_backend_protocol) {
          handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
              "only unnamed portals are supported", false);
          return 2;
      }
      // named-portal path (this plan)
  }
  ```
  IMPORTANT: the gate must key on the THREAD VARIABLE (the mode the session's backend connections will use), not on an already-bound backend conn (none exists at Bind time). Flag-flip edge (flag turned off mid-session with portals open): document that open portals on an already-pinned native conn continue to work (routing goes to the pinned conn); NEW named binds after the flip get the rejection. Keep each site's libpq-mode bytes identical (same errcode/message/order).
- [ ] **P1.2 Registry + Bind dispatch.** In `handle_post_sync_bind_message`, named branch: resolve `stmt_client_name` via `local_stmts->find_stmt_info_from_stmt_name` (reuse the function's EXISTING unknown-statement error path — read what it does for unnamed and keep bytes identical); create/overwrite `named_portals[name]` entry holding the released bind_msg + stmt_info; set `CurrentQuery.extended_query_info` (stmt fields, `bind_msg` pointer to the registry-owned message, `stmt_client_portal_name` = registry key c_str, flags SYNC per frame position); `find_or_create_backend`, `status = PROCESSING_STMT_BIND`, `return 1` — mirroring the tail of `handle_post_sync_execute_message` (`:7184-7206`) including `pgsql_real_query` handling (read what Execute transfers there; Bind has no query text — check what DESCRIBE transfers as the closest no-text precedent).
  Overwrite semantics: PostgreSQL errors on Bind to an existing portal name ("portal already exists", 42P03) — DO NOT silently overwrite; pass the Bind to the backend and let it error naturally (registry entry replaced only on successful BindComplete — hook the success path).
- [ ] **P1.3 Reuse/implicit-Parse integration.** Extend the decision block at `:3474-3506` to include `PROCESSING_STMT_BIND` alongside DESCRIBE/EXECUTE (a named Bind on a backend lacking the statement needs the implicit-Parse detour; `previous_status.push(status)` mechanics identical). Extend `RunQuery` (`:3056-3110`) with the BIND case: `backend_stmt_name` built the same way; dispatch `async_query(..., PGSQL_EXTENDED_QUERY_TYPE_BIND, &extended_query_info)`.
- [ ] **P1.4 Native BIND drive.** In `lib/PgSQL_Connection.cpp`: `async_query`'s type→state mapping gains BIND (decide: new `ASYNC_STMT_BIND_START/END` states, or reuse EXECUTE states + `PG_Native_Stmt_Step::BIND` — pick whichever needs less state-machine surgery after reading `handler()`'s stmt-state cases; document the choice). `stmt_bind_start` (or the BIND branch): `pg_build_bind(native_outbuf, portal_name, backend_stmt_name, <param arrays read exactly as stmt_execute_start reads them from extended_query_info.bind_msg>)` + Flush/Sync per flags; `native_stmt_step = BIND`. Drain: BIND completes on `'2'`; the ack filter FORWARDS `'2'` during a BIND step (today suppressed unconditionally — make suppression conditional on `native_stmt_step != BIND`). libpq drive for BIND: unreachable (libpq mode rejected at the gate) — put `assert(native_mode)` + a defensive error.
  Session rc0 epilogue for PROCESSING_STMT_BIND: on success mark the registry entry `bound_on_backend = true` (find where rc0 handlers live — `handler___rc0_PROCESSING_STMT_PREPARE` at `:7676` is the pattern; Bind needs a small one: mark entry, pop implicit-detour status if any... actually the detour pops BEFORE Bind runs. Read the rc==0 flow for STMT_EXECUTE at `:3574+` and mirror).
- [ ] **P1.5 Pinning.** In the cycle-completion path (`:3585-3605`), extend: `has_pending_messages = has_pending_messages || (named_portals.empty() == false);` so `finishQuery` takes the sticky branch while portals are open. In the same completion path, after `handle_transaction_state()`: `if (myconn->native_txn_status == 'I') clear_named_portals();` (backend destroyed them at txn end / implicit-txn Sync). Verify `native_txn_status` is current at that point (updated by the drained `'Z'`).
- [ ] **P1.6 Build + targeted verification.** `make debug -j$(nproc)`; container restart; run `pgsql-native_prepared-t` (27/27 — unnamed flows untouched) + `pgsql-native_transactions-t`. Named-portal behavior is only smoke-testable by hand until P3's test lands — do a manual `pg_lite_client`-style check ONLY if trivially possible via the existing `pgsql-extended_query_protocol_test-t` binary (it may already contain named-portal rejection cases that now behave differently in native mode — RUN IT in both modes and report what changed; if it asserts the old rejection in native mode, note it for P3 to update).
- [ ] **P1.7 Commit** `feat(pgsql): named-portal registry + immediate native Bind dispatch (new BIND stmt phase)`.

---

### Task P2: Execute / Describe('P') / Close('P') by name; max_rows + PortalSuspended/resume

**Files:** `lib/PgSQL_Session.cpp`, `lib/PgSQL_Connection.cpp`, `include/PgSQL_Connection.h` (if drain state needs a bit), `include/PgSQL_Session.h`.

**Steps:**
- [ ] **P2.1 Execute(named).** In `handle_post_sync_execute_message`: named branch looks up `named_portals`; missing → the EXISTING `ERRCODE_UNDEFINED_CURSOR` "portal \"X\" does not exist" error (`:7087-7089` — same bytes, now with the real name). Found → `extended_query_info.bind_msg = entry.bind_msg.get()`; stmt fields from `entry.stmt_info`; `stmt_client_portal_name` = name. The drive must NOT re-send Bind for an already-bound portal: add a flag (e.g. `PGSQL_EXTENDED_QUERY_FLAG_PORTAL_ALREADY_BOUND`) consumed by `stmt_execute_start`'s native branch to skip `pg_build_bind` (and skip the folded Describe unless requested) and emit only `pg_build_execute(native_outbuf, portal_name, max_rows)`.
  **max_rows:** thread `execute_data.max_rows` into the drive for NAMED portals only (`pg_build_execute(..., max_rows)`); unnamed stays 0 (invariant 2 — document the divergence-from-protocol as inherited libpq-parity behavior).
- [ ] **P2.2 PortalSuspended/resume.** Drain already terminates EXECUTE on `'s'` and forwards it (ACK-classified). On rc0 where the final forwarded terminator was `'s'` (plumb a connection flag, e.g. `native_last_execute_suspended`, set in the drain, read in the session epilogue): mark `entry.suspended = true`, do NOT evict. Subsequent Execute of the same portal = P2.1 path with ALREADY_BOUND (resume is just another Execute on the wire). On `'C'`/`'I'` completion: `entry.suspended = false` (portal stays open until Close/txn-end — PostgreSQL keeps completed portals until Sync/Close; verify against the docs and let the backend be authoritative for double-Execute-after-complete errors — pass them through).
- [ ] **P2.3 Describe('P', named).** Named branch: registry lookup (missing → UNDEFINED_CURSOR, same bytes as `:6781-6783` with real name); set portal name into `extended_query_info`; dispatch the DESCRIBE_P drive with `pg_build_describe('P', portal_name)` (thread the name to `:3733`'s call — currently `""`). The Describe-fold optimization (`send_describe_portal_result`) applies only when the NEXT frame message is an Execute of the SAME portal name — extend the peek check (`:6793-6797`) to compare names; different name → standalone dispatch. NO caching for portal describes (spec §3).
- [ ] **P2.4 Close('P', named).** Named branch: registry lookup; missing → PostgreSQL returns CloseComplete for non-existent portals (Close is idempotent per protocol — VERIFY in the PG docs; if so, forward a real backend Close anyway OR synthesize '3' matching backend behavior — choose passing through to the backend as authoritative). Found or not: dispatch a real backend Close via a small CLOSE drive (`PG_Native_Stmt_Step::CLOSE_P`, `pg_build_close('P', name)` + Flush/Sync, terminator `'3'`, ack filter forwards `'3'` during CLOSE_P step), evict the entry on success. Unnamed Close('P') keeps the local synthesis (invariant 2).
- [ ] **P2.5 Lifetime hardening.** `clear_named_portals()` also from session `reset()` (DISCARD ALL / CHANGE_USER / RESET_CONNECTION — find the reset at `:385` area) and the destructor. Error-path: after an injected-Sync recovery or rc==-1 cycle where the drained `'Z'` says `'I'`, the P1.5 hook already clears — verify it runs on error epilogues too (the error path `:3634` area) and add if not.
- [ ] **P2.6 Build + regression.** Full unnamed regression: `pgsql-native_prepared-t` 27/27, `pgsql-native_transactions-t`, `pgsql-native_query_differential-t`, `pgsql-native_stress-t`. Report `pgsql-extended_query_protocol_test-t` behavior in both modes (P1.6 note).
- [ ] **P2.7 Commit** `feat(pgsql): named-portal Execute/Describe/Close routing, max_rows + PortalSuspended resume`.

---

### Task P3: Raw-wire named-portal test with direct-PostgreSQL oracle

**Files:** Create `test/tap/tests/pgsql-native_portals-t.cpp`; modify `test/tap/tests/pg_lite_client.{h,cpp}` (SCRAM support), `test/tap/tests/Makefile` (rule with `pg_lite_client.cpp` + `-lscram -lusual`, pattern at `:347-360` and galera libs at `:204,207`), `test/tap/groups/groups.json` (register under legacy-g1, same group list as the other pgsql-native tests).

**Steps:**
- [ ] **P3.1 SCRAM in pg_lite_client.** Extend the auth loop (`pg_lite_client.cpp:296-336`) to handle AuthenticationSASL(10)/Continue(11)/Final(12) using the in-tree wrappers `pg_scram_new/pg_scram_client_first/pg_scram_client_final/pg_scram_verify_server_final` (`include/PgSQL_Backend_Protocol.h:96-121` — read `lib/PgSQL_Backend_Auth.cpp` and the native connect code that already drives them for the exact message body layout: SASLInitialResponse must carry the mechanism name "SCRAM-SHA-256" + int32 length + client-first). Unit-smoke: connect DIRECTLY to `cl.pgsql_server_host:cl.pgsql_server_port` as postgres/$ROOT_PASSWORD and run `SELECT 1` via simple query. If the wrappers prove unusable from test context after a genuine attempt, STOP and report BLOCKED with specifics (fallback decision — absolute assertions instead of direct-oracle — is the controller's, not yours).
- [ ] **P3.2 The test.** Structure per case: run an identical raw-wire script twice — (A) direct backend, (B) through ProxySQL with `pgsql-use_native_backend_protocol=true` — and compare the response message sequences (type + payload) with normalization ONLY of: BackendKeyData pid/secret, ParameterStatus set differences at startup, error fields carrying server addresses. Frontend auth for leg B: `SET pgsql-authentication_method=1` via admin (RAII restore — copy the DebugLogScope pattern from pgsql-native_prepared-t); leg A uses SCRAM (P3.1). Corpus (kinds for CoverageRecorder from pgsql-native_tracking.h):
  1. PORTAL_BASIC: Parse s1 → Bind p1(s1, params) → Describe('P',p1) → Execute(p1, 0) → Close('P',p1) → Sync.
  2. PORTAL_MULTI: two portals p1,p2 over one statement with different params, executed interleaved (Execute p2 then p1).
  3. PORTAL_SUSPEND: Execute(p1, max_rows=2) over a 5-row result → expect 2×'D' + 's'; Execute(p1, 2) again → 2×'D' + 's'; Execute(p1, 0) → 1×'D' + 'C'.
  4. PORTAL_TXN: BEGIN (simple query); bind p1; Sync; NEW frame Execute(p1) — portal survives across Sync inside txn; COMMIT; Execute(p1) → undefined-cursor error (both legs).
  5. PORTAL_SYNC_DESTROY: bind p1 outside txn; Sync; Execute(p1) in next frame → undefined-cursor (backend destroyed it at implicit-txn end) — both legs identical.
  6. PORTAL_CLOSE_IDEMPOTENT: Close('P', "nonexistent") → whatever the direct backend does (CloseComplete per protocol) — proxy must match.
  7. PORTAL_ERR_BIND_DUP: Bind p1 twice without close → backend 42P03 — proxy must match.
  8. PORTAL_LIBPQ_MODE_REJECTS: leg B only, with `pgsql-use_native_backend_protocol=false`: named Bind → FEATURE_NOT_SUPPORTED "only unnamed portals are supported" (regression guard for invariant 1).
  9. PORTAL_UNNAMED_UNCHANGED: unnamed flow through raw client in native mode → same responses as direct backend EXCEPT the known synthesis differences (BindComplete/CloseComplete timing) — assert the CLIENT-visible sequence matches libpq-mode ProxySQL (run leg B twice, both modes, unnamed corpus — byte-equal).
  Multiplexing check: after case 4's COMMIT + portal invalidation, verify via admin `stats_pgsql_...`/`SHOW ...` (or the runtime connection-pool table) that the conn returned to the pool (pin released) — find the right stats table by reading what other tests query.
- [ ] **P3.3 Register + run.** groups.json; build; run via `TEST_PY_TAP_INCL=pgsql-native_portals-t`; all green; quote the coverage summary.
- [ ] **P3.4 Commit** `test(pgsql): raw-wire named-portal differential vs direct PostgreSQL (+SCRAM in pg_lite_client)`.

---

### Task P4: Full-suite regression + docs + final review

- [ ] All 9 `pgsql-native_*` TAP tests + `pgsql-extended_query_protocol_test-t` (both modes) + unit tests green; full legacy-g1 group run; compare failures against the known set (#5883-#5887) — anything NEW gets root-caused per CLAUDE.md.
- [ ] Spec §4 status → Implemented; note the raw-wire client now also partially closes the "PGresult-level only" differential gap for the portal corpus (raw sequences compared message-by-message).
- [ ] Final whole-branch review of the phase's commits (controller dispatches); push; the PR (#5882) description gets a comment noting named portals landed.
