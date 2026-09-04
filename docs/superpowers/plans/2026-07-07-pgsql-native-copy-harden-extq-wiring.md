# PgSQL Native Protocol: COPY Hardening + Extended-Query Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the native PostgreSQL backend protocol handle extended queries (Parse/Bind/Describe/Execute/Close/Sync) end-to-end as a raw pass-through, and harden the native drive against COPY messages, so all differential TAP tests pass byte-equal with no FEATURE_NOT_SUPPORTED escape hatch.

**Architecture:** Extended queries are forwarded verbatim: the session captures raw client message bytes at intake (keyed on the runtime flag, not on a bound connection), transfers them to the native connection at Sync, and the connection drives flush+drain through the *existing* `ASYNC_QUERY_START → ASYNC_QUERY_CONT → ASYNC_USE_RESULT_*` state machine (the same one native simple queries use), so poll re-arming, TLS, threshold flushing, error classification, and transaction-state tracking are all inherited. COPY keeps its current routing (session fast_forward for `FROM STDIN` shapes, native stream-through for `TO STDOUT`); we add a connection-level CopyFail safety net so a CopyInResponse that ever reaches the native drive fails cleanly instead of hanging, and we make the copy test's coverage reporting truthful.

**Tech Stack:** C++17, ProxySQL native PgSQL wire machinery (`PgSQL_Backend_Msg_Framer`, `PgSQL_Connection` native_* members), TAP tests (libpq client), unit tests linking `libproxysql.a`.

**User decision (2026-07-07):** "Harden + keep fast_forward" — do NOT implement the spec §3.2 connection-level COPY state machine. fast_forward already forwards COPY IN byte-equal and zero-copy; PR 2 scope is reduced to hardening + truthful tracking. Extended-query wiring (PR 3) is the main work.

## Global Constraints

- Build with `make -j$(nproc)` / `make debug -j$(nproc)` (the top-level Makefile's own documented form — lib/src sub-makes do NOT inherit parallelism from plain `make`). Never unbounded `-j` (no number).
- TAP tests: `make -C test/tap/tests <name>-t` per test; infra via `test/infra/control/ensure-infras.bash` + `run-tests-isolated.bash` with `WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g1`. Never hand-roll Docker.
- Unit tests: `test/tap/tests/unit/`, pattern `#include "test_globals.h"` + `#include "test_init.h"`, registered in `UNIT_TESTS` in `test/tap/tests/unit/Makefile`, built with `make -C test/tap/tests/unit <name>-t`.
- Commit style (from branch history): `feat(pgsql): ...`, `fix(pgsql): ...`, `test(pgsql): ...`, `fix+feat(pgsql): ...`. Append trailer `Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7`.
- A native/libpq differential divergence is a hard failure. Never normalize it away.
- Line numbers below are from commit `86caf1283` + the uncommitted stats fix; verify before editing (functions may shift a few lines).

## Key facts an implementer must know (from code exploration, 2026-07-07)

1. **Native simple-query flow** (the template to imitate): `PgSQL_Session::RunQuery` (`lib/PgSQL_Session.cpp:3050`) → `PgSQL_Connection::async_query` (`lib/PgSQL_Connection.cpp:2818`) → `handler(event)` state machine (`:324`): `ASYNC_QUERY_START` → `query_start()` (`:2445`, native branch builds `'Q'` into `native_outbuf`, sends via `native_send_or_buffer`) → `ASYNC_QUERY_CONT` → `query_cont()` (`:2507`, flushes via `native_flush_outbuf()`) → `ASYNC_USE_RESULT_START` (allocates `query_result` via `init_query_result()`) → `ASYNC_USE_RESULT_CONT` → `native_fetch_result_cont()` (`:2614`, recv → framer → `query_result->add_native_backend_message(...)`, sets `native_result_complete=true` on `'Z'`) → `ASYNC_QUERY_END`. Async waits: the handler sets `async_exit_status` (PG_EVENT_READ/WRITE) and `next_event(<state>)` (`:298`) converts it to `wait_events` (POLLIN/POLLOUT); `PgSQL_Data_Stream::set_pollout` (`lib/PgSQL_Data_Stream.cpp:869`) uses `myconn->wait_events` when `DSS` is in the `STATE_MARIADB_*` range (`async_query` sets `myds->DSS = STATE_MARIADB_QUERY` at `:2852-2856`); the thread resumes the connection at `lib/PgSQL_Thread.cpp:3679` (`myds->myconn->handler(revents)`) and the session re-enters via its status case.
2. **`async_query` return codes:** 0 = complete no error; -1 = complete with error (`is_error_present()`); 1 = still running; 2/3 = multi-statement.
3. **Extended-query intake:** `get_pkts_from_client` splits client bytes into exactly one protocol message per `pkt` and dispatches `'P'/'D'/'C'/'B'/'E'/'S'` (`lib/PgSQL_Session.cpp:2559-2622`). The five intake handlers (`:7383`, `:7414`, `:7443`, `:7471`, `:7500`) each parse into a struct pushed to `extended_query_frame` (a `std::queue` of `std::variant<unique_ptr<...>>`) and currently call `myconn->native_extq_buffer(pkt.ptr, pkt.size)` **guarded on `mybe->server_myds->myconn && native_mode`** — which is null on a session's first cycle, so raw bytes are never captured then. The Sync pkt itself is freed at `:2603` and never buffered; the `'S'` case loops `handler___...PGSQL_SYNC()` while `rc==0 && !extended_query_frame.empty()` (`:2608-2620`).
4. **Sync processing:** `handler___..._PGSQL_SYNC` (`:7220`): empty frame → bare ReadyForQuery; else delegates to `handler___status_PROCESSING_EXTENDED_QUERY_SYNC()` (`:7255`), which has a native dispatch at `:7267-7270` (dead on first cycle) and otherwise pops ONE struct and `std::visit`s to `handle_post_sync_*_message`. Those set `status = PROCESSING_STMT_PREPARE/EXECUTE`, `find_or_create_backend(current_hostgroup)`, `pgsql_real_query.init(&pkt)`, and `return 1`. rc==2 → error → `reset_extended_query_frame()`, normalized to 0.
5. **Main-loop case `PROCESSING_EXTENDED_QUERY_SYNC`** (`:3175-3213`): rc==-1 → destroy; rc==0 → `NEXT_IMMEDIATE(PROCESSING_EXTENDED_QUERY_SYNC)` if frame non-empty, else cleanup (`bind_waiting_for_execute.reset`, `extended_query_phase = EXTQ_PHASE_IDLE`, DEBUG `assert(dbg_extended_query_backend_conn == myds->myconn)`, `finishQuery`) — then **unconditional `goto handler_again`**. rc==1 today means "status was changed to PROCESSING_STMT_*" so handler_again dispatches the new status. A native "pending I/O" must NOT reuse rc==1 (status unchanged → infinite loop); it needs its own code that `break`s to the poll loop.
6. **Backend acquisition:** only `find_or_create_backend` + push `previous_status` + `NEXT_IMMEDIATE(CONNECTING_SERVER)` establishes a connection; `handler_again___status_CONNECTING_SERVER` (`:1551`) pops `previous_status` and `NEXT_IMMEDIATE_NEW(st)` back into the pushed status. `set_previous_status_mode3` (`:6401`) `assert(0)`s on statuses outside PROCESSING_QUERY/STMT_*, so push `PROCESSING_EXTENDED_QUERY_SYNC` directly with `previous_status.push(...)` (precedent: `:2246`, `:3472`).
7. **The current stop-gap:** `async_query` intercepts `native_mode && extended_query_info != nullptr && !pgsql_conn` at `lib/PgSQL_Connection.cpp:2834-2846` → FEATURE_NOT_SUPPORTED. Keep it as an unreachable-in-normal-operation safety net; update its comment.
8. **Existing scaffolding to reuse/retire:** `native_extq_frame` (`include/PgSQL_Connection.h:705`), `native_extq_inflight` (`:706`), `native_extq_buffer`/`native_extq_reset` (`lib/PgSQL_Connection.cpp:4620`, `:4631` — keep), `native_extq_flush_and_drain` (`:4639-4727` — RETIRE, its drain duplicates `native_fetch_result_cont` and it never appends the Sync message, ignores `event`, and can't resume). `handler_native_extended_query_sync` (`lib/PgSQL_Session.cpp:7333`) — REWRITE.
9. **COPY routing:** `copy_cmd_matcher` regex `\bCOPY\b[^;]*?\bFROM\b[^;]*?\b(?:STDIN|STDOUT)\b` (`include/PgSQL_Thread.h:142`) intercepts at `lib/PgSQL_Session.cpp:3479-3518` (statuses PROCESSING_QUERY and PROCESSING_STMT_PREPARE) → fast_forward, or FEATURE_NOT_SUPPORTED for extended protocol. `COPY t TO STDOUT` (no `FROM`) misses the regex and works natively via verbatim stream-through. `COPY (SELECT ... FROM ...) TO STDOUT` matches (over-match) → fast_forward. The native decoder has NO explicit cases for `'G'/'H'/'W'/'d'/'c'` (default = forward verbatim, no state): a `'G'` reaching the native drive would hang (backend waits for CopyData the drive never sends).
10. **LISTEN gate parity:** libpq extq path rejects `LISTEN` in `handle_post_sync_parse_message` (`lib/PgSQL_Session.cpp:6564-6568`) via `strncasecmp("LISTEN ", query, 7)`; the COPY-in-extq gate is at `:3479` on `PROCESSING_STMT_PREPARE`. The native pass-through must produce the same client bytes for these → route gated statements down the libpq per-message path (see Task 5).
11. **Tests:** `test/tap/tests/pgsql-native_copy-t.cpp` infers "native" from *absence* of a fallback log warning (`nativeFallbackObserved()`, `:130-135`) — wrong for fast_forward cases. `test/tap/tests/pgsql-native_prepared-t.cpp` has an escape hatch (`:481-494`) accepting FEATURE_NOT_SUPPORTED as success for EXT_* cases, and documents a real bug: on second cycles (connection already bound) the half-wired native path runs and produces wrong bytes (cases P11/P14).
12. **Named statements vs multiplexing:** native pass-through does no client→backend statement-name remapping, so a named Parse lives only on that backend connection → set `STATUS_PGSQL_CONNECTION_NO_MULTIPLEX` (`include/PgSQL_Connection.h:29`) on any native extq use.

---

### Task 0: Commit the pending working-tree fixes

**Files:**
- Commit as-is: `lib/PgSQL_HostGroups_Manager.cpp` (stats-thread crash fix: `SQL3_Free_Connections` dereferences libpq accessors on `pgsql_conn==NULL` native connections)
- Commit as-is: `test/tap/tests/unit/Makefile` (registers `pgsql_backend_framing-t` and `pgsql_backend_auth-t` in `UNIT_TESTS`)
- Do NOT commit: `common_mk/openssl_flags.mk` (local build workaround pinning `libssl.so*3*`; leave in the working tree and flag it in the final report)

**Interfaces:** none — pure housekeeping.

- [ ] **Step 1: Verify the diff is exactly what's described**

Run: `git diff --stat`
Expected: exactly 3 files — `common_mk/openssl_flags.mk`, `lib/PgSQL_HostGroups_Manager.cpp`, `test/tap/tests/unit/Makefile`. Read `git diff lib/PgSQL_HostGroups_Manager.cpp` and confirm it only adds the `conn->pgsql_conn == NULL` branch emitting a minimal native JSON record.

- [ ] **Step 2: Build to prove it compiles**

Run: `make 2>&1 | tail -5`
Expected: successful link of `src/proxysql` (or "Nothing to be done" if already built — in that case `touch lib/PgSQL_HostGroups_Manager.cpp && make 2>&1 | tail -5` to force the object rebuild).

- [ ] **Step 3: Commit**

```bash
git add lib/PgSQL_HostGroups_Manager.cpp test/tap/tests/unit/Makefile
git commit -m "fix(pgsql): stats SQL3_Free_Connections crash on native connections; register backend unit tests

Native connections keep pgsql_conn==NULL; the libpq accessors (get_pg_user,
get_pg_host, ...) call PQxxx on the null pointer and crash the stats thread.
Emit a minimal native record instead.

Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7"
```

---

### Task 1: Wire-message builders for CopyFail and the extended-query frame (pure functions + unit tests)

**Files:**
- Modify: `include/PgSQL_Backend_Protocol.h` (add two free-function declarations at the end, before the closing `#endif`)
- Modify: `lib/PgSQL_Backend_Protocol.cpp` (implement them)
- Create: `test/tap/tests/unit/pgsql_backend_extq-t.cpp`
- Modify: `test/tap/tests/unit/Makefile` (add `pgsql_backend_extq-t` to `UNIT_TESTS`)

**Interfaces:**
- Produces: `void pg_native_build_copyfail(std::string& out, const char* reason)` — appends a complete frontend CopyFail message (`'f'` + be32 length + NUL-terminated reason) to `out`.
- Produces: `void pg_native_build_extq_outbuf(std::vector<PtrSize_t>& frame, std::string& out)` — appends every frame entry's raw bytes to `out` in order, frees each entry with `l_free` and clears the vector, then appends the 5-byte Sync message `'S' 00 00 00 04`.
- Consumes: `PtrSize_t` (from `proxysql_structs.h`), `l_alloc`/`l_free`.

- [ ] **Step 1: Write the failing unit test**

Create `test/tap/tests/unit/pgsql_backend_extq-t.cpp`:

```cpp
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include "proxysql_structs.h"
#include <cstring>
#include <string>
#include <vector>
#include "tap.h"

// Helper: allocate a PtrSize_t entry holding one fake client message.
static PtrSize_t mk_entry(const char* bytes, size_t len) {
    PtrSize_t e;
    e.ptr = l_alloc(len);
    memcpy(e.ptr, bytes, len);
    e.size = (unsigned int)len;
    return e;
}

int main(int, char**) {
    plan(8);

    // --- pg_native_build_copyfail ---
    std::string out;
    pg_native_build_copyfail(out, "native COPY not supported");
    const char* reason = "native COPY not supported";
    size_t rlen = strlen(reason) + 1;              // includes NUL
    ok(out.size() == 5 + rlen, "copyfail total size = 5 + reason + NUL");
    ok(out[0] == 'f', "copyfail type byte is 'f'");
    uint32_t len = ((unsigned char)out[1] << 24) | ((unsigned char)out[2] << 16) |
                   ((unsigned char)out[3] << 8) | (unsigned char)out[4];
    ok(len == 4 + rlen, "copyfail length field = 4 + body");
    ok(memcmp(out.data() + 5, reason, rlen) == 0, "copyfail body is NUL-terminated reason");

    // --- pg_native_build_extq_outbuf ---
    // Two fake raw client messages: a Parse-ish and a Bind-ish blob.
    const char m1[] = { 'P', 0, 0, 0, 8, 'a', 'b', 'c', 0 };   // 9 bytes
    const char m2[] = { 'B', 0, 0, 0, 5, 0 };                  // 6 bytes
    std::vector<PtrSize_t> frame;
    frame.push_back(mk_entry(m1, sizeof(m1)));
    frame.push_back(mk_entry(m2, sizeof(m2)));
    std::string ob;
    pg_native_build_extq_outbuf(frame, ob);
    ok(frame.empty(), "frame consumed (entries freed and cleared)");
    ok(ob.size() == sizeof(m1) + sizeof(m2) + 5, "outbuf = msgs + 5-byte Sync");
    ok(memcmp(ob.data(), m1, sizeof(m1)) == 0 &&
       memcmp(ob.data() + sizeof(m1), m2, sizeof(m2)) == 0, "messages concatenated in order");
    const char syncmsg[] = { 'S', 0, 0, 0, 4 };
    ok(memcmp(ob.data() + ob.size() - 5, syncmsg, 5) == 0, "trailing Sync message appended");

    return exit_status();
}
```

- [ ] **Step 2: Register in the unit Makefile and verify the test fails to build**

In `test/tap/tests/unit/Makefile`, in the `UNIT_TESTS :=` list, change the line added in Task 0's committed state:

```make
	pgsql_backend_framing-t pgsql_backend_auth-t \
```
to
```make
	pgsql_backend_framing-t pgsql_backend_auth-t pgsql_backend_extq-t \
```

Run: `make -C test/tap/tests/unit pgsql_backend_extq-t 2>&1 | tail -5`
Expected: FAIL — undefined reference / undeclared `pg_native_build_copyfail`.

- [ ] **Step 3: Implement the builders**

In `include/PgSQL_Backend_Protocol.h`, after the `PgSQL_Backend_Msg_Framer` class (before the final `#endif`), add:

```cpp
#include <string>
#include <vector>
#include "proxysql_structs.h"

// Build a frontend CopyFail ('f') message: used as a safety net when a
// CopyInResponse reaches the native drive (which cannot supply CopyData).
void pg_native_build_copyfail(std::string& out, const char* reason);

// Concatenate the raw client extended-query frame (Parse/Bind/Describe/
// Execute/Close messages captured verbatim) into `out`, freeing and
// clearing the frame, then append the 5-byte Sync message the backend
// needs to answer with ReadyForQuery. (The session never buffers the
// client's own Sync packet — see get_pkts_from_client 'S' handling.)
void pg_native_build_extq_outbuf(std::vector<PtrSize_t>& frame, std::string& out);
```

In `lib/PgSQL_Backend_Protocol.cpp`, append:

```cpp
static void pg_native_append_be32(std::string& out, uint32_t v) {
	out.push_back((char)((v >> 24) & 0xff));
	out.push_back((char)((v >> 16) & 0xff));
	out.push_back((char)((v >> 8) & 0xff));
	out.push_back((char)(v & 0xff));
}

void pg_native_build_copyfail(std::string& out, const char* reason) {
	const size_t rlen = strlen(reason) + 1;        // include NUL terminator
	out.push_back('f');
	pg_native_append_be32(out, (uint32_t)(4 + rlen));
	out.append(reason, rlen);
}

void pg_native_build_extq_outbuf(std::vector<PtrSize_t>& frame, std::string& out) {
	for (auto& p : frame) {
		if (p.ptr) {
			out.append((const char*)p.ptr, p.size);
			l_free(p.size, p.ptr);
			p.ptr = nullptr;
			p.size = 0;
		}
	}
	frame.clear();
	out.push_back('S');
	pg_native_append_be32(out, 4);
}
```

(If `l_free`/`PtrSize_t` need headers here, `lib/PgSQL_Backend_Protocol.cpp` already includes ProxySQL core headers via its existing includes; add `#include "proxysql_structs.h"` if the build complains.)

- [ ] **Step 4: Build libproxysql and run the unit test**

Run: `make 2>&1 | tail -3 && make -C test/tap/tests/unit pgsql_backend_extq-t 2>&1 | tail -3 && ./test/tap/tests/unit/pgsql_backend_extq-t`
Expected: `1..8` all ok.

Also run the two existing backend unit tests to catch regressions:
`./test/tap/tests/unit/pgsql_backend_framing-t && ./test/tap/tests/unit/pgsql_backend_auth-t`
Expected: all ok.

- [ ] **Step 5: Commit**

```bash
git add include/PgSQL_Backend_Protocol.h lib/PgSQL_Backend_Protocol.cpp \
        test/tap/tests/unit/pgsql_backend_extq-t.cpp test/tap/tests/unit/Makefile
git commit -m "feat(pgsql): native wire builders for CopyFail and extended-query frame (+Sync) with unit tests

Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7"
```

---

### Task 2: COPY hardening in the native drive

**Files:**
- Modify: `lib/PgSQL_Connection.cpp` — `native_fetch_result_cont()` (`:2614`): CopyIn/CopyBoth safety net
- Modify: `lib/PgSQL_Protocol.cpp` — `add_native_backend_message()` per-type switch (`:2716-2808`): explicit `'H'/'d'/'c'` side-effect cases
- Modify: `include/PgSQL_Connection.h` — add one member flag `native_copy_intercepted`

**Interfaces:**
- Consumes: `pg_native_build_copyfail` (Task 1), `native_outbuf`, `native_send_or_buffer`, `PGSQL_QUERY_RESULT_COPY_OUT` flag (`include/PgSQL_Protocol.h:299-306`).
- Produces: behavioral guarantee — a `'G'` (CopyInResponse) or `'W'` (CopyBothResponse) arriving in the native drive is NOT forwarded to the client; a CopyFail is sent to the backend; the drive keeps draining to the backend's ErrorResponse + ReadyForQuery, so the client sees a clean error and the connection stays usable.

**Why this is safe:** the backend, on receiving CopyFail during COPY-in, aborts the COPY with an ErrorResponse and (for simple query) then sends ReadyForQuery. Both are already forwarded verbatim and terminate the cycle via the existing `'Z'` logic. The client never saw `'G'`, so it never enters COPY mode — it just receives ErrorResponse + ReadyForQuery, a perfectly normal failed query. This branch is defense-in-depth: today no simple-query COPY-IN reaches the native drive (the fast_forward regex pre-empts it) and Task 5 pre-empts extended-query COPY. It exists so a future regex gap degrades to a clean error instead of a protocol hang.

- [ ] **Step 1: Add the member flag**

In `include/PgSQL_Connection.h`, next to `native_result_complete` (`:711`), add:

```cpp
	bool native_copy_intercepted = false;   // set when a CopyInResponse ('G'/'W') was answered with CopyFail
```

- [ ] **Step 2: Add the safety net in `native_fetch_result_cont`**

In `lib/PgSQL_Connection.cpp:2614`, inside the `for(;;)` frame loop, BEFORE the `query_result->add_native_backend_message(...)` call, insert:

```cpp
		if (fr == FRAME_OK) {
			if (msg.type == 'G' || msg.type == 'W') {
				// CopyInResponse / CopyBothResponse: the native drive cannot
				// supply client CopyData (COPY ... FROM STDIN is routed to the
				// session fast_forward path before it reaches us — see
				// copy_cmd_matcher). If one slips through, abort the COPY
				// cleanly: suppress the message (the client must not enter
				// COPY mode) and send CopyFail; the backend responds with
				// ErrorResponse + ReadyForQuery, which complete the cycle.
				if (!native_copy_intercepted) {
					native_copy_intercepted = true;
					proxy_warning("native backend protocol: unexpected CopyInResponse ('%c'); sending CopyFail\n", msg.type);
					pg_native_build_copyfail(native_outbuf, "ProxySQL native backend protocol cannot drive COPY FROM STDIN on this path");
					if (!native_send_or_buffer(PG_Native_Conn_St::DONE)) {
						set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE),
							"send(CopyFail) failed", true);
						return;
					}
				}
				continue;   // do NOT forward 'G'/'W' to the client
			}
			query_result->add_native_backend_message(msg.type, msg.payload, msg.payload_len);
			...
```

(Keep the existing `'Z'` completion and `FRAME_NEED_MORE`/`FRAME_ERROR` logic untouched. Match the actual `set_error` signature used elsewhere in this function — copy the style of the adjacent `"backend closed during result fetch"` call.) Reset the flag where `native_framer.reset()` is done in `query_start()`'s native branch (`:2452-2453`): add `native_copy_intercepted = false;` next to `native_result_complete = false;`.

- [ ] **Step 3: Add explicit `'H'/'d'/'c'` cases in `add_native_backend_message`**

In `lib/PgSQL_Protocol.cpp`, in the per-type switch (`:2716-2808`), before the `default:` case, add:

```cpp
		case 'H':   // CopyOutResponse: bytes forwarded verbatim (stream-through)
			result_flags |= PGSQL_QUERY_RESULT_COPY_OUT;
			break;
		case 'd':   // CopyData: count as a row for stats parity with the libpq
			num_rows++;   // path (add_copy_out_row also increments num_rows)
			break;
		case 'c':   // CopyDone: no side effect; CommandComplete follows
			break;
```

Match the exact member names used by the neighboring cases (`result_flags`/`num_rows` — copy whatever identifiers the `'T'`/`'D'` cases use, e.g. if they use `set flags via |=` on a differently-named member, mirror it). Update the `default:` comment to say only `'A'` NotificationResponse (and unknown types) stream through without side effects.

- [ ] **Step 4: Build and run the existing COPY differential test**

```bash
make 2>&1 | tail -3
make -C test/tap/tests pgsql-native_copy-t 2>&1 | tail -3
cd /data/rene/proxysql4/proxysql
export WORKSPACE=$(pwd) INFRA_ID="dev-$USER" TAP_GROUP="legacy-g1" SKIP_CLUSTER_START=1
source test/infra/common/env.sh
bash test/infra/control/ensure-infras.bash 2>&1 | tail -2
bash test/infra/control/run-tests-isolated.bash 2>&1 | grep -E "pgsql-native_copy-t|SUMMARY|FAIL" | head -20
```
Expected: `pgsql-native_copy-t` passes 15/15 (byte-equality unchanged — 'H'/'d'/'c' cases only set flags/counters, and the 'G' branch is unreachable from this corpus). If it fails, read `ci_infra_logs/${INFRA_ID}/tests/.../pgsql-native_copy-t.log` and root-cause; do not weaken assertions.

- [ ] **Step 5: Commit**

```bash
git add include/PgSQL_Connection.h lib/PgSQL_Connection.cpp lib/PgSQL_Protocol.cpp
git commit -m "feat(pgsql): native-drive COPY hardening — CopyFail safety net for 'G'/'W', explicit 'H'/'d'/'c' stats cases

Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7"
```

---

### Task 3: Truthful COPY coverage reporting in the copy test

**Files:**
- Modify: `test/tap/tests/pgsql-native_copy-t.cpp`

**Interfaces:**
- Consumes: existing `OpRecord`/`CoverageRecorder` from `test/tap/tests/pgsql-native_tracking.h` (`native_path_used` field).
- Produces: coverage summary that reflects actual routing: cases whose SQL matches the fast_forward regex are recorded `native_path_used=false` with detail `"routed via session fast_forward (by design)"`; plain `TO STDOUT` cases keep log-based native detection.

**Background:** `nativeFallbackObserved()` scrapes for fallback warnings that never fire on the COPY corpus, so today ALL cases are recorded "native" — including `COPY ... FROM STDIN` (fast_forward) and `COPY (SELECT ... FROM ...) TO STDOUT` (regex over-match → fast_forward). Byte-equality assertions stay exactly as they are; only the *coverage* classification and the file-header comment change.

- [ ] **Step 1: Add a routing classifier mirroring the production regex**

Near `nativeFallbackObserved()` in `pgsql-native_copy-t.cpp`, add:

```cpp
// Mirrors CopyCmdMatcher (include/PgSQL_Thread.h:142): queries matching this
// are intercepted by the session and routed through fast_forward BEFORE the
// native connection drive ever sees them. That is the intended design after
// the 2026-07-07 decision (harden + keep fast_forward): fast_forward is raw
// byte forwarding, already zero-copy and byte-equal. We record such cases as
// native_path_used=false so the coverage summary is truthful.
static bool routed_via_fast_forward(const std::string& sql) {
    static const std::regex re(
        R"(\bCOPY\b[^;]*?\bFROM\b[^;]*?\b(?:STDIN|STDOUT)\b)",
        std::regex::icase);
    return std::regex_search(sql, re);
}
```

(Include `<regex>` if not already included.)

- [ ] **Step 2: Use it when recording each case**

In `run_out_case` / `run_in_case` (where `OpRecord.native_path_used = !fell_back` is set, around `:571`/`:575`), change to:

```cpp
    bool ff = routed_via_fast_forward(<the case's SQL string>);
    rec.native_path_used = ff ? false : !fell_back;
    if (ff) rec.detail += " [routed via session fast_forward (by design)]";
```

Adapt variable names to the actual code (`r.native_path_used`, `detail` stream, etc. — read the function before editing).

- [ ] **Step 3: Rewrite the file-header "EXPECTED CURRENT STATE" comment (`:20-30`)**

Replace with:

```cpp
// ROUTING (as of the 2026-07 COPY-hardening decision):
//  - COPY t TO STDOUT (no FROM token)      -> native stream-through (native drive)
//  - COPY ... FROM STDIN                   -> session fast_forward (raw byte forwarding, by design)
//  - COPY (SELECT ... FROM ...) TO STDOUT  -> session fast_forward (regex over-match; still byte-equal)
// Both routes must produce byte-equal results vs the libpq oracle. The
// coverage summary reports which route each case took; fast_forward cases
// are native_path_used=false with an explanatory detail. A CopyInResponse
// reaching the native drive is answered with CopyFail (clean error, no hang).
```

- [ ] **Step 4: Build, run, and eyeball the summary**

```bash
make -C test/tap/tests pgsql-native_copy-t 2>&1 | tail -3
bash test/infra/control/run-tests-isolated.bash 2>&1 | grep -E "pgsql-native_copy-t|SUMMARY|FAIL" | head -20
```
Expected: still 15/15 ok (byte-equality asserts unchanged; the summary line is `ok` unconditionally but now reads e.g. `COPY_OUT 4/7 native (3 fast_forward), COPY_IN 0/7 native (7 fast_forward)`). Quote the new summary line in the task report.

- [ ] **Step 5: Commit**

```bash
git add test/tap/tests/pgsql-native_copy-t.cpp
git commit -m "test(pgsql): truthful COPY coverage — classify fast_forward-routed cases as non-native by design

Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7"
```

---

### Task 4: Session-level raw capture of the extended-query frame

**Files:**
- Modify: `include/PgSQL_Session.h` — add member + helper declarations
- Modify: `lib/PgSQL_Session.cpp` — capture in the 5 intake handlers; free in `reset_extended_query_frame` and the destructor; remove the old myconn-guarded `native_extq_buffer` calls

**Interfaces:**
- Produces: `std::vector<PtrSize_t> native_extq_client_frame` (session member) — raw client bytes, one entry per message, captured whenever `pgsql_thread___use_native_backend_protocol` is true at intake, regardless of backend binding. `void free_native_extq_client_frame()` — l_frees entries and clears.
- Consumes: `pgsql_thread___use_native_backend_protocol` (the same thread-variable accessor `PgSQL_Connection` reads at `lib/PgSQL_Connection.cpp:337` — copy the exact identifier from there), `l_alloc`/`l_free`.

**Design note:** capture is keyed on the runtime flag, NOT on the (usually not-yet-bound) backend connection. If the flag is on but Sync later binds a pooled libpq-mode connection, the raw frame is simply freed and the libpq path runs (Task 5). If the flag is off but Sync binds an old native connection (flag flipped mid-flight), the raw frame is empty and the cycle degrades to the existing graceful FEATURE_NOT_SUPPORTED intercept — same behavior as today, documented edge.

- [ ] **Step 1: Add the member and helper**

In `include/PgSQL_Session.h`, near the `extended_query_frame` member declaration, add:

```cpp
	// Native extended-query pass-through: raw client message bytes
	// (Parse/Bind/Describe/Execute/Close), one PtrSize_t per message,
	// captured at intake when pgsql-use_native_backend_protocol is on.
	// Ownership moves to the connection's native_extq_frame at Sync when a
	// native backend connection is bound; freed otherwise.
	std::vector<PtrSize_t> native_extq_client_frame;
	void free_native_extq_client_frame();
```

In `lib/PgSQL_Session.cpp`, implement (near `reset_extended_query_frame`):

```cpp
void PgSQL_Session::free_native_extq_client_frame() {
	for (auto& p : native_extq_client_frame) {
		if (p.ptr) l_free(p.size, p.ptr);
	}
	native_extq_client_frame.clear();
}
```

Call `free_native_extq_client_frame()` from: (a) `reset_extended_query_frame()` (find it and append the call), and (b) the session destructor (next to where `reset_extended_query_frame` or equivalent cleanup happens — grep `~PgSQL_Session`).

- [ ] **Step 2: Replace the five intake capture sites**

In each of the five handlers (`PGSQL_PARSE` `:7404-7409`, `PGSQL_DESCRIBE` `:7435-7438`, `PGSQL_CLOSE` `:7463-7466`, `PGSQL_BIND` `:7491-7494`, `PGSQL_EXECUTE` `:7520-7523`), replace the block

```cpp
	if (mybe && mybe->server_myds && mybe->server_myds->myconn &&
	    mybe->server_myds->myconn->native_mode) {
		mybe->server_myds->myconn->native_extq_buffer((const char*)pkt.ptr, pkt.size);
	}
```

with

```cpp
	// Native pass-through: capture the raw client bytes now — a backend
	// connection is usually NOT bound yet at intake, so the decision to use
	// them (or free them) is made at Sync. See design spec §3.3.
	if (pgsql_thread___use_native_backend_protocol) {
		PtrSize_t raw;
		raw.ptr = l_alloc(pkt.size);
		memcpy(raw.ptr, pkt.ptr, pkt.size);
		raw.size = pkt.size;
		native_extq_client_frame.push_back(raw);
	}
```

(Use the exact flag identifier found at `lib/PgSQL_Connection.cpp:337`. IMPORTANT: this must run BEFORE any code path that frees or detaches `pkt` in each handler — place it right after the successful `msg->parse(pkt)` check, where the old block was.)

- [ ] **Step 3: Build**

Run: `make 2>&1 | tail -3`
Expected: clean build. (No behavior change yet — nothing consumes the frame until Task 5; it is freed at cycle end via `reset_extended_query_frame`. Verify `reset_extended_query_frame` IS called on every cycle end in the libpq path — grep its call sites; it is called at `:7314` on error and in Sync completion paths.)

- [ ] **Step 4: Quick no-regression TAP check (prepared test, libpq + current native stop-gap)**

```bash
make -C test/tap/tests pgsql-native_prepared-t 2>&1 | tail -3
bash test/infra/control/run-tests-isolated.bash 2>&1 | grep -E "pgsql-native_prepared-t|SUMMARY|FAIL" | head -20
```
Expected: 22/22 as before (capture is inert; memory is freed each cycle).

- [ ] **Step 5: Commit**

```bash
git add include/PgSQL_Session.h lib/PgSQL_Session.cpp
git commit -m "feat(pgsql): capture raw extended-query client bytes at session intake for native pass-through

Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7"
```

---

### Task 5: Drive native extended query through the connection's async state machine

**Files:**
- Modify: `include/PgSQL_Connection.h` — declare `async_native_extq`; remove `native_extq_flush_and_drain` declaration
- Modify: `lib/PgSQL_Connection.cpp` — implement `async_native_extq`; extend `query_start()` native branch; DELETE `native_extq_flush_and_drain` (`:4639-4727`); rewrite the big comment block (`:4596-4619`); update the `async_query` intercept comment (`:2826-2833`)
- Modify: `lib/PgSQL_Session.cpp` — rewrite `handler_native_extended_query_sync` (`:7333-7381`); extend native dispatch in `handler___status_PROCESSING_EXTENDED_QUERY_SYNC` (`:7267-7270`); extend the main-loop case (`:3175-3213`); update the stale comment at `:7246-7251`

**Interfaces:**
- Consumes: `pg_native_build_extq_outbuf` (Task 1), `native_extq_frame`/`native_extq_inflight`/`native_extq_reset` (existing), `native_send_or_buffer`, `native_fetch_result_cont`, `find_or_create_backend`, `previous_status.push`, `CONNECTING_SERVER`, `PgSQL_Result_to_PgSQL_wire`, `handle_transaction_state`, `STATUS_PGSQL_CONNECTION_NO_MULTIPLEX`, `free_native_extq_client_frame` (Task 4).
- Produces: `int PgSQL_Connection::async_native_extq(short event)` — 0 = cycle complete (ReadyForQuery received; backend SQL errors are still 0 — pass-through semantics), -1 = transport/protocol failure (connection unusable), 1 = pending I/O. Session rc 3 from `handler___status_PROCESSING_EXTENDED_QUERY_SYNC` = "connect a backend first".

- [ ] **Step 1: Connection side — `async_native_extq` + `query_start` extension**

In `include/PgSQL_Connection.h`: delete the `native_extq_flush_and_drain` declaration (`:776` area, keep `native_extq_buffer`/`native_extq_reset`); add next to it:

```cpp
	// Drive one native extended-query cycle (frame flush + drain to
	// ReadyForQuery) through the standard ASYNC_QUERY_* state machine.
	// Returns 0 = cycle complete (including backend SQL errors — the
	// ErrorResponse was forwarded verbatim), -1 = transport/protocol
	// failure, 1 = pending I/O (async_exit_status/wait_events set).
	int async_native_extq(short event);
```

In `lib/PgSQL_Connection.cpp`, DELETE `native_extq_flush_and_drain` entirely (`:4639-4727`) and replace the comment block at `:4596-4619` with:

```cpp
// -----------------------------------------------------------------------------
// Native extended-query pass-through (PR 3 / Phase 3).
//
// The session captures raw client Parse/Bind/Describe/Execute/Close bytes
// (PgSQL_Session::native_extq_client_frame) and, at Sync — once a native
// backend connection is bound — transfers them into native_extq_frame and
// calls async_native_extq(). That drives the SAME ASYNC_QUERY_START →
// ASYNC_QUERY_CONT → ASYNC_USE_RESULT_* machinery as native simple queries:
// query_start() sees native_extq_inflight and builds the outbound buffer
// from the frame (+ a trailing Sync message, since the session never
// buffers the client's own Sync packet) instead of a 'Q' message; the
// result pump (native_fetch_result_cont) then drains backend messages
// verbatim to the client until ReadyForQuery. Message contents are never
// parsed: client statement/portal names ARE the backend names (no pooling,
// no remapping), which is why the session pins the connection with
// STATUS_PGSQL_CONNECTION_NO_MULTIPLEX.
// -----------------------------------------------------------------------------
```

Implement `async_native_extq` where `native_extq_flush_and_drain` used to be:

```cpp
int PgSQL_Connection::async_native_extq(short event) {
	PROXY_TRACE();
	assert(native_mode && !pgsql_conn);
	if (async_state_machine == ASYNC_IDLE) {
		native_extq_inflight = true;
		async_state_machine = ASYNC_QUERY_START;
	}
	if (myds) {
		if (myds->DSS != STATE_MARIADB_QUERY) {
			myds->DSS = STATE_MARIADB_QUERY;   // poll uses wait_events in this range
		}
	}
	handler(event);
	if (async_state_machine == ASYNC_QUERY_END) {
		native_extq_inflight = false;
		if (native_result_complete) {
			return 0;    // ReadyForQuery reached; any ErrorResponse was forwarded verbatim
		}
		return -1;       // transport/protocol failure mid-cycle
	}
	return 1;            // pending I/O
}
```

(Check how `async_query` sets `myds->DSS` at `:2852-2856` and mirror it exactly, including any guards. Check what `ASYNC_QUERY_END` handling in `handler()` does with `fetch_result_end_st` — for a simple query the end state is `ASYNC_QUERY_END`; confirm `query_start`'s native flow uses the same end state and that `async_state_machine` rests at `ASYNC_QUERY_END` until the next `async_query`/reset, matching how `async_query` `:2861` detects completion on re-entry.)

In `query_start()` (`:2445`), extend the native branch: after `native_result_complete = false; native_framer.reset(); native_outbuf.clear();` insert:

```cpp
		if (native_extq_inflight) {
			// Extended-query pass-through: flush the captured client frame
			// verbatim, terminated by a Sync message.
			pg_native_build_extq_outbuf(native_extq_frame, native_outbuf);
		} else {
			// ... existing 'Q' message construction (unchanged) ...
		}
```

with the existing send logic (`native_send_or_buffer(...)`, `async_exit_status` fallout) shared by both branches. Also ensure the guard clause in `async_query` that builds `set_query(...)` is not hit by the extq path — `async_native_extq` bypasses `async_query` entirely, so `query.ptr` may be null in `query_start()`; verify the native branch doesn't dereference `query.ptr` when `native_extq_inflight` (the 'Q'-building code that uses `query.ptr` must be inside the `else`).

Add `#include` for nothing new (builders come via `PgSQL_Backend_Protocol.h`, already included).

Update the `async_query` intercept comment (`:2826-2833`) to say the intercept is now a safety net for the flag-flip edge (raw frame not captured because the flag was off at intake, but a pooled native connection was bound at Sync) and for any future path that reaches `async_query` with `extended_query_info` on a native connection.

- [ ] **Step 2: Session side — rewrite `handler_native_extended_query_sync` (`:7333`)**

Replace the whole function with:

```cpp
// Native extended-query pass-through (see design spec §3.3 and the comment
// block above async_native_extq in PgSQL_Connection.cpp). Called from
// handler___status_PROCESSING_EXTENDED_QUERY_SYNC once a NATIVE backend
// connection is bound. Return codes: 0 = cycle complete (client response
// queued), 1 = pending backend I/O (main loop must break to poll), -1 = fatal.
int PgSQL_Session::handler_native_extended_query_sync() {
	PROXY_TRACE();
	PgSQL_Data_Stream* myds = mybe->server_myds;
	PgSQL_Connection* myconn = myds->myconn;

	if (myconn->async_state_machine == ASYNC_IDLE) {
		// First entry for this cycle: hand the raw client frame to the
		// connection (ownership moves; no copy) and pin the connection —
		// named statements/portals created by the pass-through live only on
		// this backend connection, so it must not be multiplexed away.
		for (auto& p : native_extq_client_frame) {
			myconn->native_extq_frame.push_back(p);
		}
		native_extq_client_frame.clear();
		myconn->set_status(true, STATUS_PGSQL_CONNECTION_NO_MULTIPLEX);
#ifdef DEBUG
		dbg_extended_query_backend_conn = myconn;
#endif
		if (myconn->query_result == nullptr) {
			myconn->query_result = new PgSQL_Query_Result();
		}
		// match how the libpq path initializes query_result — if
		// init_query_result()/an init(...) call with proto/conn wiring is
		// required (see ASYNC_USE_RESULT_START at PgSQL_Connection.cpp:486),
		// replicate it; add_native_backend_message dereferences
		// query_result->conn and ->proto.
	}

	int rc = myconn->async_native_extq(myds->revents);
	if (rc == 1) {
		return 1;   // pending: main loop breaks; poll re-armed via DSS/wait_events
	}

	// Cycle over (complete or transport failure): parsed structs are no
	// longer needed either way.
	reset_extended_query_frame();   // also frees native_extq_client_frame (Task 4)
	myconn->native_extq_reset();

	if (rc < 0) {
		// Transport/protocol failure: no ReadyForQuery. Surface the
		// connection error to the client and let the session error path
		// destroy the backend connection.
		if (myconn->is_error_present()) {
			client_myds->myprot.generate_error_packet(true, true,
				myconn->error_info.message.c_str(), myconn->error_info.code, false, true);
		}
		return -1;
	}

	// rc == 0: the full backend response (through ReadyForQuery, including
	// any ErrorResponse, verbatim) is in query_result. Queue it to the client.
	PgSQL_Result_to_PgSQL_wire(myconn, myconn->myds);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->DSS = STATE_SLEEP;
	status = WAITING_CLIENT_DATA;
	extended_query_phase = EXTQ_PHASE_IDLE;
	return 0;
}
```

Notes for the implementer:
- `handle_transaction_state()` is already invoked by the `'Z'` handler inside `add_native_backend_message` (`lib/PgSQL_Protocol.cpp:2800-2802`); the simple-query path calls it a second time harmlessly — mirror the simple path if in doubt (add the call after `PgSQL_Result_to_PgSQL_wire`).
- `dbg_extended_query_backend_conn` — grep its declaration; assign only under `#ifdef DEBUG` exactly as the libpq path does, else the DEBUG assert in the main-loop rc==0 cleanup fires.
- Verify `PgSQL_Result_to_PgSQL_wire(myconn, myconn->myds)` matches the call signature used at `:3575`; the second arg there is `myconn->myds`.
- Check `query_result` initialization: read `ASYNC_USE_RESULT_START` (`lib/PgSQL_Connection.cpp:486-497`) — if `init_query_result()` runs there anyway when the state machine passes through it, the manual `new PgSQL_Query_Result()` above may be unnecessary or even wrong (double init). Prefer letting the state machine do it; only pre-create if `add_native_backend_message` can run before `ASYNC_USE_RESULT_START` initializes it (it cannot — messages are only drained in `ASYNC_USE_RESULT_CONT`). **Likely the right move is to NOT allocate here at all; delete the manual allocation if `init_query_result()` covers it.** Decide by reading the code, and remove the old manual `new` in the previous version of this function either way.

- [ ] **Step 3: Session side — native dispatch + backend acquisition in `handler___status_PROCESSING_EXTENDED_QUERY_SYNC` (`:7255`)**

Replace the block at `:7267-7270` with:

```cpp
	// Native pass-through dispatch. Eligible when raw client bytes were
	// captured at intake (pgsql-use_native_backend_protocol was on).
	if (native_extq_client_frame.empty() == false ||
	    (mybe && mybe->server_myds && mybe->server_myds->myconn &&
	     mybe->server_myds->myconn->native_mode &&
	     mybe->server_myds->myconn->async_state_machine != ASYNC_IDLE)) {
		// The second disjunct covers re-entry mid-cycle: the frame was
		// already transferred to the connection and the drive is inflight.
		if (mybe == NULL || mybe->server_myds == NULL ||
		    mybe->server_myds->myconn == NULL ||
		    mybe->server_myds->DSS == STATE_NOT_INITIALIZED) {
			// No backend yet: connect first. CONNECTING_SERVER pops
			// previous_status and re-enters this status once connected.
			mybe = find_or_create_backend(current_hostgroup);
			if (mybe->server_myds->DSS == STATE_NOT_INITIALIZED) {
				return 3;   // caller: push status, NEXT_IMMEDIATE(CONNECTING_SERVER)
			}
		}
		PgSQL_Connection* myconn = mybe->server_myds->myconn;
		if (myconn->native_mode) {
			return handler_native_extended_query_sync();
		}
		// Pooled libpq-mode connection: the raw frame is useless — free it
		// and let the parsed-struct path below handle the cycle normally.
		free_native_extq_client_frame();
	}
```

And update the now-wrong comment at `:7246-7251` in `handler___..._PGSQL_SYNC` (it says "the backend is not yet associated ... we cannot decide here" — now the decision + connect happens inside `handler___status_PROCESSING_EXTENDED_QUERY_SYNC`).

- [ ] **Step 4: Session side — main-loop case rc==3 and rc==1 (`:3175-3213`)**

In the `case PROCESSING_EXTENDED_QUERY_SYNC:` block, after the `rc == -1` check add:

```cpp
		if (rc == 3) {
			// Native pass-through needs a backend connection first.
			previous_status.push(PROCESSING_EXTENDED_QUERY_SYNC);
			NEXT_IMMEDIATE(CONNECTING_SERVER);
		}
		if (rc == 1 && status == PROCESSING_EXTENDED_QUERY_SYNC) {
			// Native pass-through waiting on backend I/O. Break to the poll
			// loop; set_pollout() picks up myconn->wait_events (DSS is
			// STATE_MARIADB_QUERY) and the thread re-enters this case on the
			// next event. (libpq-path rc==1 changes status to
			// PROCESSING_STMT_*, so it is excluded by the status check.)
			break;
		}
```

CAREFUL: the existing `goto handler_again;` at the end of the rc==0 block must remain; the new `break` must exit the switch so control reaches `__exit_DSS__STATE_NOT_INITIALIZED` (writeout + poll re-arm), exactly like `PROCESSING_QUERY`'s rc==1 path (`:3688-3704`). Verify by reading the surrounding braces — the current structure is `if (rc == 0) { ... } goto handler_again;` inside the case; restructure minimally so rc==1-native reaches `break` instead of `goto handler_again`.

- [ ] **Step 5: Extended-query gates for COPY and LISTEN (byte-parity with libpq path)**

The libpq path rejects `LISTEN` (at `handle_post_sync_parse_message` `:6564`) and `COPY ... FROM STDIN|STDOUT` in extended protocol (at `:3479-3499`, status `PROCESSING_STMT_PREPARE`). The native pass-through must produce the SAME client bytes. Mechanism: when capturing raw bytes in the `PGSQL_PARSE` intake handler (Task 4 site), also check the just-parsed query text; on a gate match, free the raw frame and mark it dead so Sync falls into the libpq per-message path, which generates the identical gate errors before ever touching the backend:

In the `PGSQL_PARSE` handler, extend the Task 4 capture block:

```cpp
	if (pgsql_thread___use_native_backend_protocol) {
		const PgSQL_Parse_Data& pd = parse_msg->data();
		bool gated = false;
		if (pd.query_string) {
			if (strncasecmp("LISTEN ", pd.query_string, 7) == 0) gated = true;
			re2::StringPiece m;
			if (!gated && thread->copy_cmd_matcher &&
			    strcasestr(pd.query_string, "COPY ") != NULL &&
			    thread->copy_cmd_matcher->match(pd.query_string, &m)) gated = true;
		}
		if (gated) {
			// Statement unsupported on the pass-through: discard the raw
			// frame; Sync will take the libpq per-message path, whose
			// existing gates produce the exact same error bytes as libpq
			// mode. (Non-gated statements in the same batch then hit the
			// async_query FEATURE_NOT_SUPPORTED safety net — a documented
			// mixed-batch limitation.)
			free_native_extq_client_frame();
			native_extq_gated = true;      // new session bool, see below
		} else if (!native_extq_gated) {
			PtrSize_t raw; raw.ptr = l_alloc(pkt.size);
			memcpy(raw.ptr, pkt.ptr, pkt.size); raw.size = pkt.size;
			native_extq_client_frame.push_back(raw);
		}
	}
```

Add `bool native_extq_gated = false;` next to `native_extq_client_frame` in `include/PgSQL_Session.h`; reset it to `false` in `reset_extended_query_frame()` (alongside `free_native_extq_client_frame()`). The other four intake handlers append only when `!native_extq_gated`:

```cpp
	if (pgsql_thread___use_native_backend_protocol && !native_extq_gated) { ...capture... }
```

(`copy_cmd_matcher` is a `PgSQL_Thread` member — `include/PgSQL_Thread.h:233`; access as `thread->copy_cmd_matcher`. Verify the `match(const char*, re2::StringPiece*)` signature at `include/PgSQL_Thread.h:135-150` and the includes needed for `re2::StringPiece` — `PgSQL_Session.cpp` already uses it at `:3480`.)

- [ ] **Step 6: Build**

Run: `make 2>&1 | tail -5`
Expected: clean build. Fix compile errors by reading the real signatures (this task touches the most code; expect small naming drift from the plan).

- [ ] **Step 7: Manual smoke test against live infra**

```bash
cd /data/rene/proxysql4/proxysql
export WORKSPACE=$(pwd) INFRA_ID="dev-$USER" TAP_GROUP="legacy-g1" SKIP_CLUSTER_START=1
source test/infra/common/env.sh
bash test/infra/control/ensure-infras.bash 2>&1 | tail -2
```
Then enable the flag through the ProxySQL admin of the infra (find admin port from the infra env/scripts; the TAP tests do it via `setNativeMode` — see `pgsql-native_prepared-t.cpp:87-91` for the exact admin SQL: `UPDATE global_variables SET variable_value='true' WHERE variable_name='pgsql-use_native_backend_protocol'; LOAD PGSQL VARIABLES TO RUNTIME;`) and run via psql (or a 5-line libpq scratch program in the scratchpad) an extended-protocol round trip:
`psql "host=<proxy> port=<pgport> user=<u> password=<p> dbname=<db>" -c 'SELECT 1' --no-psqlrc` uses simple protocol; instead use `PGOPTIONS` irrelevant — simplest: run the existing prepared test, which is the real smoke test:

```bash
make -C test/tap/tests pgsql-native_prepared-t 2>&1 | tail -3
bash test/infra/control/run-tests-isolated.bash 2>&1 | grep -E "pgsql-native_prepared-t|SUMMARY|FAIL" | head -30
```
Expected at this point: the test still passes 22/22 — EXT_* cases should now be BYTE-EQUAL (real native pass-through) rather than passing via the FEATURE_NOT_SUPPORTED escape hatch. Read the test log and confirm the detail strings no longer contain "native returned FEATURE_NOT_SUPPORTED". P11/P14 (named statements — previously wrong bytes) must be byte-equal. If anything fails: read `ci_infra_logs/${INFRA_ID}/tests/.../pgsql-native_prepared-t.log` + the proxysql log next to it and root-cause (superpowers:systematic-debugging); the most likely trouble spots are `query_result` double-init (Step 2 note), the rc==1 break structure (Step 4), and DSS/poll re-arming.

- [ ] **Step 8: Commit**

```bash
git add include/PgSQL_Connection.h include/PgSQL_Session.h lib/PgSQL_Connection.cpp lib/PgSQL_Session.cpp
git commit -m "feat(pgsql): native extended-query pass-through wired through the async state machine

- session captures raw P/B/D/E/C bytes at intake (flag-keyed), transfers to
  the connection at Sync; connection flushes frame + Sync and drains via the
  standard ASYNC_QUERY_* machinery (poll re-arm, TLS, thresholds inherited)
- backend acquisition via CONNECTING_SERVER with previous_status push (rc 3)
- pending-I/O resume via new rc==1 break in PROCESSING_EXTENDED_QUERY_SYNC
- COPY/LISTEN statements gated to the libpq per-message path for byte-parity
- connection pinned NO_MULTIPLEX (client names ARE backend names)
- retire native_extq_flush_and_drain (duplicated drain, never appended Sync)

Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7"
```

---

### Task 6: Strictify the prepared test and extend coverage

**Files:**
- Modify: `test/tap/tests/pgsql-native_prepared-t.cpp`

**Interfaces:**
- Consumes: the now-working native pass-through (Task 5).
- Produces: EXT_* cases assert strict byte-equality (escape hatch removed); a new pipelined case; fixed fallback detection.

- [ ] **Step 1: Remove the FEATURE_NOT_SUPPORTED escape hatch**

Delete the block at `:481-494` (the `feature_marker` / `unsupported_msg` special-case that sets `result_match = true`). EXT_* cases must now be byte-equal, full stop.

- [ ] **Step 2: Fix `nativeFallbackObserved` (`:138-143`)**

Add the actual extended-query warning string to the regex alternation so any future regression is *detected* rather than silently passing:

```cpp
    const std::string re =
        ".*(native_mode requested but unimplemented at this stage; falling back to libpq"
        "|native backend auth capability gap .* falling back to libpq"
        "|Native backend protocol does not yet support extended queries).*";
```

- [ ] **Step 3: Update the stale header comment (`:28-38`)**

Replace the "known real bug P11/P14" and "expected until PR 3" text with a note that the native pass-through is wired (this plan) and EXT_* cases assert byte-equality.

- [ ] **Step 4: Add a pipelined-cycles case**

Append one case to `build_extq_cases()` exercising two back-to-back extended-query cycles queued before reading (libpq queues the second cycle's messages while the first is in flight — sequential Syncs, each answered by one ReadyForQuery):

```cpp
    // P21: two queued extended-query cycles (sequential Syncs). Uses
    // PQsendQueryParams twice before consuming results — exercises the
    // per-cycle Sync/ReadyForQuery accounting of the native pass-through.
```

Implementation sketch (adapt to the file's existing helpers/serialization):

```cpp
static std::string run_two_cycles(PGconn* c) {
    std::string out;
    if (PQsendQueryParams(c, "SELECT 41+1", 0, nullptr, nullptr, nullptr, nullptr, 0) != 1)
        return std::string("send1 failed: ") + PQerrorMessage(c);
    // Consume first result fully before sending the second (libpq without
    // pipeline mode requires it) — the PROXY still sees two full extended
    // cycles on one session/connection, which is what we are testing.
    while (PGresult* r = PQgetResult(c)) { out += serialize_result(r); PQclear(r); }
    if (PQsendQueryParams(c, "SELECT 'two'", 0, nullptr, nullptr, nullptr, nullptr, 0) != 1)
        return out + " send2 failed";
    while (PGresult* r = PQgetResult(c)) { out += serialize_result(r); PQclear(r); }
    return out;
}
```

Record it with kind `"EXT_MULTI_CYCLE"`, differential libpq-vs-native as the other cases, and bump `plan()` accordingly.

- [ ] **Step 5: Build, run, verify strict**

```bash
make -C test/tap/tests pgsql-native_prepared-t 2>&1 | tail -3
bash test/infra/control/run-tests-isolated.bash 2>&1 | grep -E "pgsql-native_prepared-t|SUMMARY|FAIL" | head -30
```
Expected: all cases ok (now 23+), EXT_* summary shows full native coverage, no FEATURE_NOT_SUPPORTED anywhere in the log.

- [ ] **Step 6: Commit**

```bash
git add test/tap/tests/pgsql-native_prepared-t.cpp
git commit -m "test(pgsql): prepared differential goes strict — byte-equality required for EXT_*, +multi-cycle case

Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7"
```

---

### Task 7: Full-suite verification and docs

**Files:**
- Modify: `docs/superpowers/specs/2026-06-14-pgsql-native-txn-copy-prepared-design.md` (status header + §7 phasing outcome note)
- No production code (unless verification finds bugs — then systematic-debugging, fix, and note in the report)

- [ ] **Step 1: Run ALL native TAP tests + unit tests**

```bash
cd /data/rene/proxysql4/proxysql
make 2>&1 | tail -3
make -C test/tap/tests pgsql-native_auth_differential-t pgsql-native_query_differential-t \
    pgsql-native_streaming-t pgsql-native_transactions-t pgsql-native_copy-t \
    pgsql-native_prepared-t pgsql-native_notify-t pgsql-native_stress-t 2>&1 | tail -3
export WORKSPACE=$(pwd) INFRA_ID="dev-$USER" TAP_GROUP="legacy-g1" SKIP_CLUSTER_START=1
source test/infra/common/env.sh
bash test/infra/control/ensure-infras.bash 2>&1 | tail -2
bash test/infra/control/run-tests-isolated.bash 2>&1 | grep -E "pgsql-native|SUMMARY|FAIL"
for t in pgsql_backend_framing pgsql_backend_auth pgsql_backend_extq; do \
    make -C test/tap/tests/unit ${t}-t >/dev/null 2>&1 && ./test/tap/tests/unit/${t}-t | tail -2; done
bash test/infra/control/stop-proxysql-isolated.bash 2>&1 | tail -2
```
Expected: every `pgsql-native_*` test green; unit tests green. Any failure: root-cause per the CLAUDE.md CI-failure standard (read logs, quote lines, separate "caused by this change" from "broken regardless") — never dismiss.

- [ ] **Step 2: Update the design-spec status**

In `docs/superpowers/specs/2026-06-14-pgsql-native-txn-copy-prepared-design.md`: change `**Status:**` to `Implemented (PR 2 re-scoped 2026-07-07: COPY hardening + truthful tracking, fast_forward kept by user decision; PR 3 native extended-query wired via async state machine)`. In §7, annotate PR 2/PR 3 bullets with the same one-liners.

- [ ] **Step 3: Commit + final report**

```bash
git add docs/superpowers/specs/2026-06-14-pgsql-native-txn-copy-prepared-design.md
git commit -m "docs(pgsql): record PR2 re-scope (COPY hardening) + PR3 completion in the design spec

Claude-Session: https://claude.ai/code/session_015yDEBKWSWyDYq9MFxS69p7"
```

Final report to the user must include: per-test pass counts, the new coverage summary lines (copy + prepared), the retirement of `native_extq_flush_and_drain`, the mixed-batch gate limitation (a batch mixing LISTEN/COPY Parses with normal ones degrades to per-message libpq handling → FEATURE_NOT_SUPPORTED on the native conn for the normal ones), the flag-flip edge (intake-off/Sync-native → graceful error, as today), and the still-uncommitted `common_mk/openssl_flags.mk` local tweak.
