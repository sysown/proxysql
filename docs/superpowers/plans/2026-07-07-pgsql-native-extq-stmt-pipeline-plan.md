# PgSQL Native ExtQ via Stmt Pipeline — Implementation Plan (parity + Describe cache)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox syntax.
> Spec: `docs/superpowers/specs/2026-07-07-pgsql-native-extq-stmt-pipeline-design.md` (4 locked user decisions).
> Named portals (spec §4) are planned in a FOLLOW-UP plan doc after this plan's parity gate is green.

**Goal:** Native-mode extended queries run through ProxySQL's full prepared-statement pipeline (GloPgStmt, local_stmts, backend-id reuse, ack synthesis) with only the wire layer swapped from libpq `PQsend*` to native frontend messages; statement-level Describe metadata is cached globally for both modes.

**Architecture:** Remove the raw pass-through (superseded). Add typed frontend builders (Parse/Bind/Describe/Execute/Close/Flush/Sync). Give the three `stmt_*_start` bodies native branches that append wire messages to `native_outbuf` with the same Flush/Sync flag logic as the libpq pipeline calls, and extend the native drain with per-step expected terminators + ack filtering that reproduces the session's synthesis rules. Cache `'t'`/`'T'` payloads set-once on `PgSQL_STMT_Global_info`.

**Tech Stack:** C++17, native PgSQL wire machinery, TAP + unit tests.

## Global Constraints

- Build: `make -j$(nproc)` / `make debug -j$(nproc)` — never unbounded `-j`, never serial builds. TAP infra REQUIRES the debug build.
- Infra: `INFRA_ID="dev-rene-natproto"` (dev-$USER is contested by another worktree — never use it), `TAP_GROUP="legacy-g1"`, `SKIP_CLUSTER_START=1`, `source test/infra/common/env.sh`; single test via `TEST_PY_TAP_INCL=<name>`. ensure-infras COMPOSE_PROJECT workaround documented in `.superpowers/sdd/task-2-report.md`. Never hand-create docker resources.
- Commit style `feat|fix|test|refactor(pgsql): ...` + trailer `Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7`.
- Differential divergence = hard failure. The libpq path's behavior is the oracle for every parity decision.
- Key code map (verify lines, they shift): reuse decision `lib/PgSQL_Session.cpp:3474-3506`; `build_backend_stmt_name` `:3056` (`"proxysql_ps_" + id`); RunQuery stmt dispatch `:3064-3110`; post-prepare bookkeeping `handler___rc0_PROCESSING_STMT_PREPARE` `:7676-7718`; libpq wire calls `lib/PgSQL_Connection.cpp:3226-3506` (`stmt_prepare_start` :3226 `PQsendPrepare`, `stmt_describe_start` :3279 `PQsendDescribePrepared`/`Portal`, `stmt_execute_start` :3368 `PQsendQueryPrepared`, pipeline enter/flush/sync at :3232/:3253/:3285/:3320/:3374/:3483); result dispatch by `fetch_result_end_st` `:529-705`; synthesis: BindComplete always synthesized (`PgSQL_Session.cpp:7075`), CloseComplete always (`:6980`), ParseComplete on cache hit (`:6725`,`:6748`); Describe rebuild `lib/PgSQL_Protocol.cpp:2437`; global cache `lib/PgSQL_PreparedStatement.cpp` (`add_prepared_statement` :331, `find_backend_stmt_id_from_global_id` :197, `backend_insert` :192); native pump `native_fetch_result_cont` (flush preamble + CopyFail net from Task 2).

---

### Task A: Remove the pass-through dead code

**Files:** `include/PgSQL_Connection.h`, `lib/PgSQL_Connection.cpp`, `include/PgSQL_Session.h`, `lib/PgSQL_Session.cpp`, `include/PgSQL_Backend_Protocol.h`, `lib/PgSQL_Backend_Protocol.cpp`, `test/tap/tests/unit/pgsql_backend_extq-t.cpp`, plus commit the new spec + this plan doc.

Remove (introduced by commits `051dd25ec`, `5cfa4f353`, `c9c0073c2`, `a254976dd`, and Task 1's extq builder):
- Session: `native_extq_client_frame`, `free_native_extq_client_frame()` (member, definition, ALL call sites: destructor, `reset_extended_query_frame`, `:3194`-area cleanup, `:3635`-area epilogue, `:7253`-area empty-Sync), `native_extq_gated`, the 5 intake capture blocks (restore the pre-capture code shape: just parse + push, no raw capture, no snapshot locals), `handler_native_extended_query_sync()` (decl + def), the native dispatch/gate logic and rc==3/rc==1 native handling in `handler___status_PROCESSING_EXTENDED_QUERY_SYNC` + the main-loop case (restore libpq-only flow), COPY/LISTEN gate additions in the PARSE intake handler.
- Connection: `async_native_extq` (decl+def), the `native_extq_inflight` branch in `query_start()` (restore unconditional `'Q'` build), `native_extq_frame`, `native_extq_inflight`, `native_extq_buffer`, `native_extq_reset`, the big extq comment block; RESTORE the `async_query` extq intercept comment to say "native extended query lands via the native stmt_* drives; this intercept is the safety net until then / for unsupported combos". KEEP: `native_copy_intercepted` + CopyFail net + flush preamble + any `async_free_result()` fix from a254976dd **if** it fixes a defect that also affects the simple-query path (READ it; if it's extq-only, remove).
- Backend protocol: `pg_native_build_extq_outbuf` (decl+def); KEEP `pg_native_build_copyfail` + `pg_native_append_be32`. Unit test: drop the extq_outbuf assertions, keep/rename the CopyFail ones (file becomes the future home of the Task-B builder tests — keep the name `pgsql_backend_extq-t.cpp`, adjust `plan()`).

Steps: (1) revert-by-editing with the diffs of the four commits as the checklist (`git show <sha>` each); (2) `make debug -j$(nproc)` clean; (3) unit tests `pgsql_backend_framing-t`, `pgsql_backend_auth-t`, `pgsql_backend_extq-t` green; (4) TAP `pgsql-native_prepared-t` — expect 22/22 WITH the escape hatch satisfied again (EXT_* return FEATURE_NOT_SUPPORTED gracefully — pre-Task-5 state); `pgsql-native_transactions-t` green; (5) commit `refactor(pgsql): remove native extq raw pass-through (superseded by stmt-pipeline design); add revised spec+plan`.

---

### Task B: Frontend-message builders + unit tests

**Files:** `include/PgSQL_Backend_Protocol.h`, `lib/PgSQL_Backend_Protocol.cpp`, `test/tap/tests/unit/pgsql_backend_extq-t.cpp`.

**Interfaces (later tasks consume verbatim):**
```cpp
void pg_build_parse(std::string& out, const char* stmt_name, const char* query,
                    const uint32_t* param_oids, uint16_t n_oids);
// 'B': param_values[i]==nullptr means SQL NULL (length -1). n_param_formats/n_result_formats
// follow protocol semantics (0 = all default, 1 = all same, n = per-param).
void pg_build_bind(std::string& out, const char* portal, const char* stmt_name,
                   const uint16_t* param_formats, uint16_t n_param_formats,
                   const char* const* param_values, const int32_t* param_lengths, uint16_t n_params,
                   const uint16_t* result_formats, uint16_t n_result_formats);
void pg_build_describe(std::string& out, char kind /* 'S'|'P' */, const char* name);
void pg_build_execute(std::string& out, const char* portal, uint32_t max_rows);
void pg_build_close(std::string& out, char kind /* 'S'|'P' */, const char* name);
void pg_build_flush(std::string& out);   // 'H' 00000004
void pg_build_sync(std::string& out);    // 'S' 00000004
```
All length fields include themselves, exclude the type byte; strings NUL-terminated; ints big-endian (reuse `pg_native_append_be32`, add `pg_native_append_be16`).

Steps: (1) failing unit tests asserting exact bytes for each builder — include: Parse with 0 and 2 OIDs; Bind with 0 params; Bind with 2 params where one is NULL (-1 length) and per-param formats; Bind n_param_formats==1 broadcast; Describe S/P; Execute max_rows 0 and 5; Close S; Flush; Sync. Verify expected byte strings against the PostgreSQL protocol doc layout written into test comments. (2) implement; (3) unit test green + `make -j$(nproc)` lib build clean; (4) commit `feat(pgsql): native frontend-message builders for extended query (Parse/Bind/Describe/Execute/Close/Flush/Sync) with byte-exact unit tests`.

---

### Task C: Native stmt drives (the core)

**Files:** `include/PgSQL_Connection.h`, `lib/PgSQL_Connection.cpp`, small touches in `lib/PgSQL_Session.cpp` only if a verified structural need arises (report it).

**C.1 State.** Add to `PgSQL_Connection`: `enum class PG_Native_Stmt_Step { NONE, PARSE, DESCRIBE_S, DESCRIBE_P, EXECUTE }` + `native_stmt_step`, `bool native_step_complete`, `bool native_suppress_parse_complete` (implicit prepare), and whatever minimal per-step bookkeeping the drain needs. Reset alongside `native_result_complete` in `query_start()`-style entry points.

**C.2 Send.** In `stmt_prepare_start` / `stmt_describe_start` / `stmt_execute_start`, add `if (native_mode) { ... return; }` branches BEFORE the libpq code:
- PREPARE: `pg_build_parse(native_outbuf, backend_stmt_name, query.ptr, oids, n)` — the OID array from the same `extended_query_info` source the libpq call uses; then Flush or Sync exactly per the flag logic the libpq branch applies to `PQsendFlushRequest`/`PQsendPipelineSync` (READ it: `PGSQL_EXTENDED_QUERY_FLAG_SYNC`, `_IMPLICIT_PREPARE`); `native_send_or_buffer`, set `async_exit_status` like `query_start()` does; `native_stmt_step = PARSE`; `native_suppress_parse_complete = (flags & IMPLICIT_PREPARE)`.
- DESCRIBE: `pg_build_describe(native_outbuf, 'S'|'P', name)` per the same statement-vs-portal branch libpq takes; + Flush/Sync; step = DESCRIBE_S/P.
- EXECUTE: decode the client Bind params EXACTLY where the libpq branch decodes them for `PQsendQueryPrepared` (`:3389-3466` readers incl. the 1-format-broadcast normalization) but hand them to `pg_build_bind` preserving the client's per-param/result formats faithfully (protocol-native; note in a comment that libpq mode collapses result formats — corpus clients use uniform formats so the differential is unaffected); if `send_describe_portal_result`, append `pg_build_describe('P', "")`; `pg_build_execute(native_outbuf, "", 0)`; + Flush/Sync; step = EXECUTE.

**C.3 Drain.** Extend the native result pump for stmt steps (either inside `native_fetch_result_cont` switch on `native_stmt_step`, or a sibling `native_stmt_fetch_cont` sharing the recv/framer/flush-preamble core — choose by reading; prefer the least duplication). Per-message rules:
- `'1'` ParseComplete: forward via `add_native_backend_message` UNLESS `native_suppress_parse_complete`; PARSE step completes on it when Flush-terminated.
- `'2'` BindComplete: ALWAYS suppress (session synthesized it).
- `'t'`/`'T'`/`'n'`: forward; DESCRIBE_S completes after `'t'`+(`'T'`|`'n'`); DESCRIBE_P after `'T'`|`'n'`. During EXECUTE they appear only for the folded Describe('P') — forward.
- `'D'`/`'C'`/`'I'`: forward (stream-through); EXECUTE completes on `'C'`/`'I'`/`'s'` when Flush-terminated.
- `'Z'`: forward; completes any Sync-terminated step (existing `native_result_complete` logic).
- `'E'`: forward; parse into `error_info` (existing `'E'` side effect does this); mark step failed. Sync-terminated: drain to `'Z'` (backend sends it). Flush-terminated: the backend is now in aborted-extended-query state and will NOT send `'Z'` until a Sync arrives — READ how the libpq pipeline path gets out of this (the rc!=0 handlers around `handler___rc*_PROCESSING_STMT_*` and pipeline-abort handling in `PgSQL_Connection`) and mirror the observable behavior: whatever ensures a Sync reaches the backend and the drain completes so the session's error path can run. Document precisely what you found and did — this is the hardest 10% of the task and the reviewer will focus on it.
- `'G'`/`'W'`: existing CopyFail net stays active.
- `'S'` ParameterStatus / `'N'` / `'A'`: existing side-effect handling (forward/absorb per current `add_native_backend_message` rules).
**Suppression mechanics:** suppression must skip `add_native_backend_message` entirely (no client bytes) while still letting per-type side effects that matter run — check whether `'1'` has side effects today (it does not; it's default-forwarded). Implement suppression in the drain loop, not inside `add_native_backend_message`.

**C.4 async_query dispatch.** In `async_query`, the `PGSQL_EXTENDED_QUERY_TYPE_*` → `ASYNC_STMT_*_START` mapping is shared; the native intercept (`native_mode && extended_query_info && !pgsql_conn → FEATURE_NOT_SUPPORTED`) is DELETED in this task (the drives now exist). Verify `set_query()` stores `backend_stmt_name`/`extended_query_info` for native identically. The `ASYNC_STMT_*_CONT`/`_END` states: add native branches mirroring the `ASYNC_QUERY_CONT`/`ASYNC_USE_RESULT_CONT` native pattern (flush cont → drain → END on step complete/failure). Return codes must match what the session's `handler___rc*_PROCESSING_STMT_*` epilogues expect from the libpq path (0 complete / -1 error / 1 pending) — those epilogues (`:7676+`) then do add_prepared_statement/backend_insert/client_insert bookkeeping IDENTICALLY for native.

**C.5 Post-prepare bookkeeping sanity.** `handler___rc0_PROCESSING_STMT_PREPARE` and friends must run unchanged for native. Verify no libpq-only calls inside them (e.g. anything touching `pgsql_conn` or PGresult) — if found, report before adapting.

**Verify:** `make debug -j$(nproc)`; TAP `pgsql-native_prepared-t` (escape hatch still present but should be UNUSED now — grep the log to prove zero FEATURE_NOT_SUPPORTED and P11/P14/P15 GREEN including the DEALLOCATE step); `pgsql-native_transactions-t`; `pgsql-native_query_differential-t` (simple-query regression); `pgsql-native_stress-t` (200x PREPARE/SELECT/txn exercises reuse + implicit-prepare across pool). Commit `feat(pgsql): native extended-query wire drives through the prepared-statement pipeline`.

*Split guidance for the controller: dispatch C as one implementer task; if it reports BLOCKED on size, split C.2/C.3-PARSE+DESCRIBE first, then EXECUTE.*

---

### Task D: Strictify the prepared test (absorbs old Task 6)

**Files:** `test/tap/tests/pgsql-native_prepared-t.cpp`.
1. Remove the FEATURE_NOT_SUPPORTED escape hatch (`result_match=true` block) — byte-equality required for every case.
2. Extend `nativeFallbackObserved` regex with the extq warning string (regression tripwire).
3. Update the header comment (pass-through history → stmt-pipeline design; P11/P14 note obsolete).
4. Add cases: (a) `EXT_MULTI_CYCLE` — two consecutive extended cycles on one session; (b) `EXT_REUSE` — same statement name re-prepared after DEALLOCATE; (c) if cheaply expressible, two sessions preparing the identical query text (global-cache dedup path). Bump `plan()`.
5. Run: prepared test strict green; quote the coverage summary.
Commit `test(pgsql): prepared differential strict — byte-equality for all EXT_* + reuse/multi-cycle cases`.

---

### Task E: Describe metadata cache (both modes)

**Files:** `include/PgSQL_PreparedStatement.h`, `lib/PgSQL_PreparedStatement.cpp`, `lib/PgSQL_Session.cpp` (`handle_post_sync_describe_message`), `lib/PgSQL_Protocol.cpp` (capture points), unit test `test/tap/tests/unit/pgsql_stmt_meta_cache-t.cpp` (+Makefile), TAP additions to the prepared test.

1. `PgSQL_STMT_Global_info`: add set-once describe cache — suggested shape: `std::atomic<const PgSQL_Describe_Cache*> describe_cache` where the struct holds `std::string param_desc_payload; std::string row_desc_payload; bool no_data;` — publish with compare-exchange from null; losers delete their candidate. Freed in the global-info destructor. (Members are inside a `shared_ptr<const ...>` — the atomic-pointer pattern keeps const-correctness honest; adjust to the codebase's style if a simpler guarded set-once fits better, and justify.)
2. Capture: native — in the DESCRIBE_S drain, copy the `'t'`/`'T'`(/NoData) payloads into a candidate and publish after successful step; libpq — in `copy_describe_completion_to_PgSQL_Query_Result`/`add_describe_completion` for statement-level describes, encode once into a candidate and publish.
3. Serve: in `handle_post_sync_describe_message`, statement-level Describe with a populated cache → synthesize `'t'`+`'T'`/`'n'` to the client directly (existing `PG_pkt` client-bound writers), bump a new status counter `pgsql_stmt_describe_cache_hits` if a natural counter home exists (report if not), and complete the cycle WITHOUT backend dispatch — mirroring the cache-hit ParseComplete synthesis flow. Portal describes bypass the cache entirely.
4. Unit test: set-once semantics (two racing publishes → one survives, no leak — single-threaded simulation acceptable), payload fidelity.
5. TAP: new prepared-test cases — Describe same statement twice, byte-equal in both modes; second Describe served from cache (assert via the counter if implemented, else via proxysql log line added at debug level).
Commit `feat(pgsql): statement-level Describe metadata cache on PgSQL_STMT_Global_info (both backend modes)`.

---

### Task F: Full-suite verification + docs

1. All 8 `pgsql-native_*` TAP tests + all pgsql unit tests green on `dev-rene-natproto` (full `legacy-g1` group run for the final gate, not single-test mode). Root-cause any failure per CLAUDE.md standard.
2. Update `docs/superpowers/specs/2026-06-14-...` status header (supersession note) and the new spec's status (parity+cache: Implemented; named portals: next plan).
3. Write the named-portals plan doc skeleton reference (goals from spec §4) — planning happens next session/phase.
4. Final whole-branch review (controller dispatches per subagent-driven-development), then report: test matrix, coverage lines, limitations (DDL staleness of describe cache; libpq-mode result-format collapse note), leftover `openssl_flags.mk` local tweak.
