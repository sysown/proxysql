# PgSQL Native Protocol: Transactions, COPY, and Prepared Statements Coverage

**Status:** Superseded in part (2026-07-07). PR 1 (tests) implemented as designed. PR 2 re-scoped by
user decision: COPY hardening + truthful coverage tracking, session fast_forward KEPT for COPY IN
(see `2026-07-07-pgsql-native-copy-harden-extq-wiring` plan). PR 3's §3.3 raw pass-through was
implemented, then REPLACED by user decision with the prepared-statement-pipeline design — see
`2026-07-07-pgsql-native-extq-stmt-pipeline-design.md` (native extq now retains GloPgStmt /
local_stmts / backend-id reuse with only the wire layer swapped, plus Describe metadata caching).
**Date:** 2026-06-14
**Branch:** `feature/pgsql-native-backend-protocol`
**Author:** Claude (designed with René Cannaò)
**Extends:** `2026-06-11-pgsql-native-protocol-design.md`, `2026-06-14-pgsql-native-scram-plus-design.md`

## 1. Problem Statement

The native protocol implementation on `feature/pgsql-native-backend-protocol` currently covers simple-Query (`Q`) traffic only. Three major protocol feature areas are not exercised by the differential test corpus, and two of them are not on the native path at all:

| Area | Simple-Query path? | Extended-Query path? | Current native status |
|---|---|---|---|
| **Transactions** (BEGIN / COMMIT / ROLLBACK / SAVEPOINT) | Yes (simple Query) | n/a | Native path handles it (just a `'Q'` message). No implementation work needed; coverage is missing. |
| **COPY** (IN / OUT, with/without header, text/CSV/binary) | Yes (routes to fast_forward for COPY IN; libpq path for COPY OUT) | n/a | Native path **streams 'G'/'H'/'d'/'c' verbatim** in `PgSQL_Query_Result::add_native_backend_message()` but the **client→backend direction is not driven** in native mode. COPY IN falls back to the libpq/fast_forward path; COPY OUT uses libpq `PGRES_COPY_OUT` handling. |
| **Prepared statements** | Yes (SQL `PREPARE` / `EXECUTE` / `DEALLOCATE`) | Yes (Parse/Bind/Describe/Execute/Close/Sync) | The comment at `lib/PgSQL_Connection.cpp:2823` says: *"the native state machine. (Extended/prepared queries are not native yet.)"* Confirmed: extended query falls back to the libpq path entirely. |

What the user asked for: comprehensive differential test coverage for all three areas, plus implementation of the missing native path for COPY and extended query. The "tracking" emphasis (`we need to track them all!!`) means the tests must also emit a per-operation coverage summary so we can see exactly which operations the native path handles and which it does not.

## 2. Design

### 2.1 Three-test structure

Three new test files in `test/tap/tests/`, all registered in `test/tap/groups/groups.json` under `legacy-g1`:

```
test/tap/tests/pgsql-native_transactions-t.cpp       (15 cases, ~60 TAP lines)
test/tap/tests/pgsql-native_copy-t.cpp               (14 cases, ~55 TAP lines)
test/tap/tests/pgsql-native_prepared-t.cpp           (30 cases, ~95 TAP lines)
```

The differential test pattern (libpq vs native, byte-equal results, no-fallback assertion, plus a coverage summary) is already established by the existing auth/query/streaming tests. We extend it with a **per-operation tracking** mode that records which protocol path was used and surfaces a summary line at the end.

### 2.2 Test infrastructure helper

A small C++ helper, in the same header-only style as the existing `Test_Compat.h`, that the three tests share:

```cpp
// test/tap/tests/pgsql-native_tracking.h
struct OpRecord {
    std::string label;       // human-readable: "BEGIN; INSERT; ROLLBACK"
    std::string kind;        // "TXN_BEGIN" | "TXN_COMMIT" | "TXN_ROLLBACK" | "COPY_IN" | "COPY_OUT" | "PREPARE_SQL" | "EXT_PARSE" | ...
    bool native_path_used;   // true iff no fallback warning in log after the operation
    bool result_match;       // true iff native result byte-equals libpq result
    std::string detail;      // optional diff detail
};

class CoverageRecorder {
    std::vector<OpRecord> records;
public:
    void record(OpRecord r);
    // Emits one ok/not-ok per record plus a summary line at the end.
    // The summary line aggregates by `kind` and reports the per-kind
    // native coverage rate, e.g.:
    //   "TXN_BEGIN: 6/6 native, TXN_COMMIT: 4/4 native, COPY_OUT: 3/5 native (2 fell back)"
    void emit_tap();
};
```

The recorder lives inside the test process and prints its summary as a single `ok` line with the per-kind breakdown in the diagnostic. This is the "tracking" piece.

### 2.3 Test 1: Transactions (`pgsql-native_transactions-t.cpp`)

Corpus:

1. **Single-statement txn control**: `BEGIN; SELECT 1; COMMIT` — verify ReadyForQuery returns `'I'` (idle) after the COMMIT.
2. **Rollback**: `BEGIN; INSERT; ROLLBACK` — verify the row is absent on a fresh connection.
3. **Commit**: `BEGIN; INSERT; COMMIT` — verify the row is present.
4. **Savepoint**: `BEGIN; INSERT id=1; SAVEPOINT s1; INSERT id=2; ROLLBACK TO s1; COMMIT` — verify only id=1 is present.
5. **Release savepoint**: `BEGIN; SAVEPOINT s1; INSERT; RELEASE s1; COMMIT` — verify the row is present.
6. **Nested savepoints**: `BEGIN; SAVEPOINT s1; SAVEPOINT s2; INSERT; ROLLBACK TO s2; RELEASE s1; COMMIT` — verify no row.
7. **Error-in-tx auto-rollback**: `BEGIN; INSERT; <syntax error>; ROLLBACK` — Postgres auto-rolls back; verify no row. Then `COMMIT` and verify still no row.
8. **Multi-statement mixed**: `BEGIN; SELECT 1; INSERT; UPDATE; SELECT 2; COMMIT` — verify final state and ReadyForQuery.
9. **Isolation level**: `BEGIN ISOLATION LEVEL SERIALIZABLE; SELECT 1; COMMIT` — verify the SET TRANSACTION command was honored (compare txn status bytes between libpq and native).
10. **Long transaction**: `BEGIN; SELECT pg_sleep(0.5); COMMIT` — verify both paths handle the in-tx pause correctly.
11. **Empty transaction**: `BEGIN; COMMIT` — no work; verify ReadyForQuery cycles to `'I'`.
12. **Failure after commit**: `BEGIN; COMMIT; <bad SQL>` — verify the connection survives (error after commit is at top level, not in-tx).
13. **Multiple cycles on one connection**: cycle BEGIN/INSERT/COMMIT three times on the same native connection — verify pool reuses the connection correctly.
14. **Server-side prepared + tx**: `BEGIN; EXECUTE p1; COMMIT` (with `PREPARE p1 AS SELECT $1::int`) — covers the SQL-side prepared + transactional combination.
15. **Idle-in-transaction timeout (informational)**: start a tx, sleep past `idle_in_transaction_session_timeout` (configured to 500ms for the test), verify the backend terminates — verifies that the native path surfaces connection-termination correctly.

For each case, the test runs the case via libpq, then via native, on a fresh per-case table (idempotent: each case uses a unique table name suffixed with the test timestamp), and asserts:

- The two result sets are byte-equal (or both empty for non-row-returning commands).
- The ReadyForQuery transaction-status byte (`'I'`/`'T'`/`'E'`) matches between the two paths.
- The native path did not fall back to libpq (log scrape).
- The coverage recorder logs the operation as `TXN_*` with the result.

### 2.4 Test 2: COPY (`pgsql-native_copy-t.cpp`)

Corpus:

1. **COPY TO STDOUT (text)**: `COPY t TO STDOUT` — read all `CopyData` messages, concatenate, compare to libpq's concatenated output. Verify byte-equal.
2. **COPY TO STDOUT (CSV with HEADER)**: `COPY t TO STDOUT WITH (FORMAT csv, HEADER true)` — same shape, CSV mode.
3. **COPY TO STDOUT (programmatic column list)**: `COPY t(id, val) TO STDOUT` — partial column copy.
4. **COPY TO STDOUT (query, not table)**: `COPY (SELECT id, name FROM t WHERE id < 100) TO STDOUT` — query as source.
5. **COPY FROM STDIN (text)**: `COPY t FROM STDIN` then stream 1000 tab-separated rows, terminate with `CopyDone`. Verify the table contains the rows and the CommandComplete reports the count.
6. **COPY FROM STDIN (CSV with HEADER)**: 1000 CSV rows.
7. **COPY FROM STDIN (with quoted/escaped values)**: rows containing embedded tabs, newlines, and the quote character.
8. **COPY FROM STDIN (NULL marker)**: `COPY t FROM STDIN WITH (NULL '...')` — non-default null marker.
9. **COPY FROM STDIN (DEFAULT values for some columns)**: 4-col table, stream 2-col rows, fill the other 2 from defaults.
10. **Error during COPY IN**: stream 100 good rows then a row that violates a constraint. Verify the backend sends `ErrorResponse`, the proxy surfaces it, and the connection is still usable for non-COPY queries afterward.
11. **Cancel a COPY IN mid-stream**: open a `COPY t FROM STDIN`, stream 10 rows, send `CopyFail` (not `CopyDone`). Verify the backend sends `ErrorResponse` with the failure message and the connection is still usable.
12. **COPY to program (psql-style `\copy`)**: skip — psql is the client and `\copy` is a psql-side transformation, not a wire-protocol feature. The libpq path is what `\copy` ultimately uses, so this case is redundant with case 5.
13. **Large COPY OUT (10 MB)**: verify stream-through doesn't buffer the entire 10 MB client-side (assert via memory footprint or a timing threshold).
14. **Bounded COPY (LIMIT)**: `COPY (SELECT * FROM t LIMIT 50) TO STDOUT` — verify the row count.
15. **Empty COPY**: `COPY (SELECT * FROM t WHERE false) TO STDOUT` — verify zero rows + `CommandComplete`.

For each case, the test runs via libpq, then via native, and asserts:
- The concatenated CopyData bytes are byte-equal.
- The CommandComplete tag matches (e.g. `COPY 1000`).
- For COPY IN: the row count in the table after the COPY matches.
- For error cases: the ErrorResponse SQLSTATE matches.
- The coverage recorder logs each operation as `COPY_IN` or `COPY_OUT` with the result.

### 2.5 Test 3: Prepared statements (`pgsql-native_prepared-t.cpp`)

Two sub-suites: SQL-side (`PREPARE` / `EXECUTE` / `DEALLOCATE` as simple queries) and extended-query (`Parse` / `Bind` / `Describe` / `Execute` / `Close` / `Sync` raw messages).

#### 2.5.1 SQL-side prepared statements (uses native path)

1. **PREPARE + EXECUTE + DEALLOCATE**: `PREPARE p1 AS SELECT $1::int + $1`; `EXECUTE p1(5)` → `10`; `DEALLOCATE p1`.
2. **Multiple EXECUTEs of one PREPARE**: prepare once, execute 100 times with different params, verify each result.
3. **PREPARE with no params**: `PREPARE p AS SELECT 42`; `EXECUTE p`.
4. **PREPARE with NULL param**: `PREPARE p AS SELECT $1::int IS NULL`; `EXECUTE p(NULL)`.
5. **PREPARE with text result type**: `PREPARE p AS SELECT $1::text`; `EXECUTE p('hello')` → `hello`.
6. **Re-PREPARE same name**: `PREPARE p AS SELECT 1`; `PREPARE p AS SELECT 2`; `EXECUTE p` → `2` (overwrite).
7. **EXECUTE of unknown name**: error response.
8. **DEALLOCATE of unknown name**: error response.
9. **PREPARE in a transaction**: `BEGIN; PREPARE p AS SELECT 1; EXECUTE p; COMMIT` — verify the prepared survives the commit and is per-session.
10. **PREPARE + DML**: `PREPARE ins AS INSERT ... RETURNING *`; `EXECUTE ins(99, 'z')` → returns the new row.

#### 2.5.2 Extended-query prepared statements (currently falls back to libpq)

11. **Parse + Bind + Describe + Execute + Sync (unnamed)**: client sends `Parse "" AS SELECT $1::int` + `Bind "" "" $1=42` + `Describe ""` (portal) + `Execute "" 0` + `Sync`. Verify the response: ParseComplete, BindComplete, RowDescription, DataRow, CommandComplete, ReadyForQuery.
12. **Same with named statement**: `Parse "s1" AS SELECT $1::int`, etc. Verify name round-trips (proxy can see statement name).
13. **Multiple params, mixed types**: `Parse "" AS SELECT $1::int, $2::text, $3::bool`, bind (1, 'a', true).
14. **Binary result format**: `Bind "" "" $1=1` with `result_format_codes = {1}` — verify the DataRow contains binary int4 (length 4, value `\x00\x00\x00\x01`).
15. **Binary param format**: `Parse "" AS SELECT $1::int` (with `paramTypes = {23}`), `Bind "" "" format=1 value=\x00\x00\x00\x05` — verify the result.
16. **Re-execute named statement**: Parse once, Bind+Execute three times, Sync. Verify statement is reused.
17. **Close statement**: Parse "s1", Close "s1", Sync. Verify CloseComplete.
18. **Close portal**: Parse "s1" AS SELECT 1, Bind "p1" "" 1, Close portal "p1", Sync.
19. **Describe statement (not portal)**: Parse "s1" AS SELECT $1::int, Describe 'S' "s1" → ParameterDescription (no RowDescription for a statement describe). Verify the response.
20. **Error in Bind (type mismatch)**: Parse "s1" AS SELECT $1::int, Bind "s1" "" $1='not an int' → ErrorResponse. Verify the error SQLSTATE and that Sync still gets a ReadyForQuery.
21. **Error in Parse (bad SQL)**: Parse "" AS "NOT VALID SQL" → ErrorResponse on Parse, Sync → ReadyForQuery. Verify the proxy recovers.
22. **Error in Execute (e.g. divide by zero)**: Parse + Bind + Execute a `SELECT 1/0` → ErrorResponse. Sync still completes. Connection usable for next query.
23. **Multiple statements in one Sync batch**: `Parse s1 AS SELECT 1; Parse s2 AS SELECT 2; Bind; Execute; Sync` — verify all responses come back in order.
24. **Parse with type OIDs**: `Parse "" AS SELECT $1::int, $2::text` with `paramTypes = {23, 25}` (int4, text) — verify the backend accepts the Parse.
25. **Parse with empty param list (no type OIDs)**: `Parse "" AS SELECT 1` (no OIDs sent) — verify the backend infers no params.
26. **Re-Parse same name (overwrite)**: Parse "s1" AS SELECT 1, Parse "s1" AS SELECT 2, Execute s1 → 2.
27. **EmptyStatement in Parse**: Parse "" AS "" (empty query string) → EmptyQueryResponse. Verify the byte.
28. **Pipeline (multi-Sync)**: Parse + Bind + Execute + Sync + Parse + Bind + Execute + Sync — verify both Syncs produce ReadyForQuery in order.
29. **Large result via extended query (10k rows)**: byte-equal comparison of all DataRow bytes between libpq and native (when native implements it) or libpq-only (when native falls back).
30. **Cyclic reuse of the same prepared statement 100 times** (100 × Parse + Bind + Execute + Sync, all with the same name): verify memory-stable (no leak) and that the 100th result is identical to the 1st.

For each case, the test:
- Runs via libpq first, captures the entire extended-query response (every backend message) as a serialized byte stream.
- Runs via native, captures the same.
- Asserts the two byte streams are byte-equal.
- The coverage recorder logs each operation as `EXT_PARSE` / `EXT_BIND` / `EXT_EXECUTE` / `EXT_SYNC` / `PREPARE_SQL` / `EXECUTE_SQL` / `DEALLOCATE_SQL`, with the result.

### 2.6 Coverage summary

Each test ends with a single `ok` line that summarizes:

```
ok N - coverage: TXN_BEGIN 6/6 native, TXN_COMMIT 4/4 native, ...
```

If any operation falls back, the summary lists the kind with the count and the message: `COPY_IN 1/8 native (7 fell back to fast_forward — see known gap)`. The known gap is the implementation work in §3.

This gives the user a single TAP line per test that shows the current native coverage, and as we implement more native support, the rate goes up.

## 3. Implementation Work

The test phase identifies what falls back. The implementation phase closes the gaps. Approximate scope:

### 3.1 Transactions — no implementation work

Transactions are simple Query messages. The native path already handles them. The test just provides coverage and proves it.

### 3.2 COPY — implement native COPY

**State machine** (in `PgSQL_Connection::native_drive_copy_*`):

- `NATIVE_COPY_IDLE` → client sends `Query("COPY ...")` → backend sends CopyInResponse (`'G'`) or CopyOutResponse (`'H'`) → transition to `NATIVE_COPY_IN_PROGRESS` or `NATIVE_COPY_OUT_PROGRESS`.
- `NATIVE_COPY_OUT_PROGRESS`: drain backend `CopyData` (`'d'`) messages, forward to client. Backend sends CommandComplete (`'C'`) and ReadyForQuery (`'Z'`) when done. Transition back to `NATIVE_COPY_IDLE` on `ReadyForQuery`.
- `NATIVE_COPY_IN_PROGRESS`: enter **fast-stream mode** at the connection level. Forward client `CopyData` (`'d'`) / `CopyDone` (`'c'`) / `CopyFail` (`'f'`) bytes to backend verbatim. Read backend responses (`CommandComplete` / `ErrorResponse` + `ReadyForQuery`). Transition back to `NATIVE_COPY_IDLE` on `ReadyForQuery`.
- On `ErrorResponse` mid-stream: forward to client, continue draining until `ReadyForQuery`, then re-enter idle.

The connection-level state machine is distinct from the existing session-level `session_fast_forward` mechanism (`lib/PgSQL_Session.cpp:3233` and `switch_normal_to_fast_forward_mode`). The session-level one operates in libpq mode and routes the entire client stream through a raw byte forwarder. The native one operates below the session — the connection is the one driving the backend — and uses the existing native framer to read backend messages. COPY is connection-scoped (the next message after `ReadyForQuery` is a normal `Query`, not a `CopyData`), so the state lives in the connection, not the session.

**Scope**: ~200-300 lines of new code in `lib/PgSQL_Connection.cpp` + a new file `lib/PgSQL_Backend_Copy.cpp` (mirroring the libpq-path code in the existing `handle_copy_out` / `add_copy_out_response_*`).

### 3.3 Extended query — implement native Parse/Bind/Execute

**State machine** (in `PgSQL_Connection::native_drive_extended_query_*`):

- Client sends one or more of `P` (Parse) / `D` (Describe) / `B` (Bind) / `E` (Execute) / `C` (Close). These are buffered in the connection's `native_extended_query_frame` (a `std::vector<PtrSize_t>` of raw client bytes). This is a **separate** buffer from the existing session-level `extended_query_frame` (`lib/PgSQL_Session.cpp`) which holds parsed message structs for the libpq path; we do not share them.
- Client sends `S` (Sync). At this point:
  1. Forward the entire frame to the backend in order (raw bytes, no parsing).
  2. Enter `NATIVE_EXTQ_DRAINING` state.
  3. Read backend messages, forwarding each one to the client verbatim via the existing `add_native_backend_message()`.
  4. The response frame ends with `ReadyForQuery` (`'Z'`). Transition back to idle.
- On `ErrorResponse`: forward it, drain until `ReadyForQuery` (per protocol spec — the backend always sends ReadyForQuery after a Sync even on error), then transition to idle.
- `Pipelining` (multiple Syncs in one batch): keep draining until we see one ReadyForQuery per Sync. The native framer already counts messages; we can correlate by Sync count.

**Scope**: ~300-500 lines of new code in `lib/PgSQL_Connection.cpp` + an extended-query frame buffer in `PgSQL_Connection`. The native path does **not** parse the message contents — it just forwards them. The existing libpq path parses the messages for prepared-statement tracking (mapping client names to backend names); for the native pass-through, the client name **is** the backend name (no remapping).

**Trade-off**: the native pass-through does not get ProxySQL's prepared-statement pooling benefits. Statements are re-parsed by the backend on every new connection. This is the same trade-off as MySQL's `mysql_stmt_*` family when the client uses session-level prepared statements. For the differential test, byte-equality is what matters; pooling optimization is a future enhancement.

## 4. Out of Scope

- **Prepared-statement pooling / server-side statement reuse across connections**: out of scope for this round. The native path forwards client names directly to the backend; no remapping, no pooling.
- **LISTEN / NOTIFY** (async notifications): out of scope; spec'd separately.
- **COPY ... FROM PROGRAM** (`COPY ... FROM PROGRAM 'cmd'`): the `'p'` format code in CopyInResponse; not exercised by the differential test. Can be added later.
- **Binary COPY format** (PostgreSQL's `COPY ... BINARY`): not exercised. Adds the `'w'` / `'c'` message types with length-prefixed binary framing. Text/CSV is the common case.
- **Performance benchmarks**: not in scope. We measure correctness (byte-equality) and coverage (which operations are native).

## 5. Test Infrastructure

Same as the existing auth/query/streaming tests:

- Build with `make -C test/tap/tests pgsql-native_{transactions,copy,prepared}-t` (no Makefile change needed — pattern rule).
- Register in `test/tap/groups/groups.json` under `legacy-g1`.
- Run via `run-tests-isolated.bash` (TAP runner; the infra does not need a new TAP group).
- No new Docker fixtures needed — the existing `docker-pgsql16-single` covers all three areas with SCRAM + no TLS.
- The new `pgsql-native_tracking.h` header is shared across the three new tests; it lives in `test/tap/tests/`.

## 6. Risks

1. **Pool reuse across the tests** — each test uses unique table names suffixed with the timestamp, so concurrent runs of the same test don't collide. This is the same pattern as the existing `pgsql-native_query_differential-t`.
2. **Server-side prepared statements are per-session** — if the test issues `PREPARE p1` on connection A and then the pool reuses connection A for a different test, the prepared statement is still there. This is fine: the test uses unique statement names, and the per-test cleanup `DEALLOCATE` at the end of the SQL-prepared sub-suite avoids leaking.
3. **Extended-query `Close` semantics** — closing a non-existent statement should be a no-op on the backend (it returns `CloseComplete` either way). The test asserts this.
4. **COPY OUT streaming through a TLS tunnel** — the differential test runs over the same TLS state as the auth test. The native COPY path inherits the same TLS framing as the rest of the native protocol. No additional test is needed.
5. **Long COPY (10 MB)** — the differential test asserts byte-equal content, not memory ceiling. We can't directly assert "we didn't buffer the whole thing" without instrumentation, but we can assert correctness and observe timing for future perf work.

## 7. Phasing

This work is split into three PRs:

**PR 1 (test work, this PR — no production code change):**
- Write the shared `pgsql-native_tracking.h` helper (`CoverageRecorder`).
- Write all three new tests.
- Register them in `test/tap/groups/groups.json` under `legacy-g1`.
- Run them via `run-tests-isolated.bash`.
- The coverage summary lines in each test show the current native protocol coverage. Expected from the audit:
  - `pgsql-native_transactions-t`: `TXN_*` 100% native (simple Query).
  - `pgsql-native_copy-t`: `COPY_IN` and `COPY_OUT` 0% native (they go through fast_forward / libpq). The differential test still passes because the libpq fallback produces byte-equal results.
  - `pgsql-native_prepared-t`: `PREPARE_SQL`/`EXECUTE_SQL`/`DEALLOCATE_SQL` 100% native; `EXT_PARSE`/`EXT_BIND`/`EXT_EXECUTE`/`EXT_SYNC`/etc. 0% native (libpq path; the comment at `lib/PgSQL_Connection.cpp:2823` confirms).
- The summary lines are the deliverable. They give the user a per-feature native coverage report.

**PR 2 (native COPY implementation, follow-up):**
- Implement the native COPY state machine in `lib/PgSQL_Backend_Copy.cpp` + the connection-level driver in `lib/PgSQL_Connection.cpp`.
- Re-run `pgsql-native_copy-t`. The `COPY_IN` and `COPY_OUT` coverage lines go from `0/N` to `N/N`.

**PR 3 (native extended-query implementation, follow-up):**
- Implement the native extended-query state machine in `lib/PgSQL_Connection.cpp`.
- Re-run `pgsql-native_prepared-t`. The `EXT_*` coverage lines go from `0/M` to `M/M`.
- Final state: all 3 tests report 100% native coverage for their respective operations.

## 8. Decisions (locked)

1. **Byte-equal assertion when native falls back**: always assert byte-equal. The libpq fallback is the same code path as the libpq control, so byte-equality is automatic. Asserting it doesn't exercise the native path, but it doesn't lie either. Simpler code, simpler diagnostics.
2. **COPY IN with quoted/escaped values**: raw wire format. No `\r\n` rewriting. Matches what a real libpq client would send on the wire.
3. **10-MB COPY OUT**: byte-equal + record elapsed time in the TAP diagnostic. No hard memory ceiling.
4. **PR staging**: two PRs. PR 1 = the 3 tests + `CoverageRecorder` helper + no production code change. PR 2 = implement native COPY + native extended query.
