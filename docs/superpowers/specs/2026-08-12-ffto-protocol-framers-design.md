# FFTO Protocol Framers Design

**Date:** 2026-08-12  
**Status:** Approved for implementation planning  
**Tier:** `PROXYSQL31=1` / `PROXYSQLFFTO`  
**Related:** sql-tap packet-parsing gap analysis; `MySQLFFTO.cpp`, `PgSQLFFTO.cpp`

## 1. Context

ProxySQL FFTO (Fast Forward Traffic Observer) passively parses MySQL and PostgreSQL wire traffic on Fast Forward sessions and records query digests (`stats_*_query_digest`) with duration, `rows_sent`, and `affected_rows`.

A comparison against [mickamy/sql-tap](https://github.com/mickamy/sql-tap) (core proxy packet parsing only; no TUI) showed:

| Area | MySQL FFTO | PostgreSQL FFTO vs sql-tap |
|------|------------|----------------------------|
| Result framing with `CLIENT_DEPRECATE_EOF` | **Broken / incomplete** | N/A (Postgres protocol) |
| Multi-result / multi-statement | Incomplete (`SERVER_MORE_RESULTS_EXISTS` ignored) | Simple multi-statement + pipeline already handled |
| Cursor fetch | `COM_STMT_FETCH` not tracked | Portal Execute + `PortalSuspended` + SQL `FETCH`/`MOVE` tags present |
| Bind args / Describe OIDs / tx UI ops | Out of scope (digest-only) | sql-tap-only extras; out of scope |
| Pipelining | Single in-flight | Ahead of sql-tap (`m_pending_queries`) |
| Testability of parsers | Logic embedded in session-coupled FFTO | Same |

sql-tap avoids MySQL `CLIENT_DEPRECATE_EOF` by stripping the capability at handshake. ProxySQL defaults `enable_client_deprecate_eof=true` and must parse the real wire format. Approach chosen: **extract pure protocol framers** (approach C), unit-test them, and wire them into both FFTOs—fixing MySQL gaps and hardening/extracting PostgreSQL for parity of architecture and coverage.

## 2. Goals

1. **MySQL correctness**
   - Resultsets with and without `CLIENT_DEPRECATE_EOF`
   - Multi-result sets via `SERVER_MORE_RESULTS_EXISTS`
   - `COM_STMT_FETCH` attributed to the prepared statement SQL
2. **PostgreSQL structural parity**
   - Extract response framing (and keep client stmt/portal maps in FFTO)
   - Unit-test pipeline / multi-statement / PortalSuspended / error-drain rules that today live only in integration tests
   - Harden any edge cases found while extracting (no intentional behavior regression)
3. **Testability**
   - Framers are pure: byte payloads in → events out; no `MySQL_Session` / `PgSQL_Session` / thread globals
4. **Digest semantics preserved**
   - One digest update per logical client command when the full server response finishes (including multi-result accumulation under one command)

## 3. Non-goals

- TUI, EXPLAIN, N+1 detection, bind-parameter value capture (sql-tap UI features)
- Changing advertised MySQL capabilities (no stripping `CLIENT_DEPRECATE_EOF`)
- PostgreSQL bind-arg decoding or Describe/`ParameterDescription` OID tracking
- MySQL client command pipelining queue (remains single in-flight; document limitation)
- TiDB-specific behavior beyond MySQL protocol compatibility
- UI or admin schema changes

## 4. Architecture

```
MySQL client/server packets          PostgreSQL client/server messages
         │                                        │
         ▼                                        ▼
┌─────────────────────────┐            ┌──────────────────────────┐
│ MySQLResultsetFramer    │            │ PgSQLResponseFramer      │
│ (pure, unit-tested)     │            │ (pure, unit-tested)      │
└───────────┬─────────────┘            └────────────┬─────────────┘
            │ events                                 │ events
            ▼                                        ▼
┌─────────────────────────┐            ┌──────────────────────────┐
│ MySQLFFTO               │            │ PgSQLFFTO                │
│ reassembly, stmt map,   │            │ reassembly, stmt/portal  │
│ prepare skip, digests   │            │ maps, pending queue,     │
│                         │            │ digests                  │
└─────────────────────────┘            └──────────────────────────┘
```

### 4.1 Ownership split

| Concern | Framer | FFTO |
|---------|--------|------|
| Packet/message reassembly across TCP reads | | yes |
| Max buffer / `ffto_bypassed` | | yes |
| Stmt id / name → SQL maps | | yes |
| Portal name → stmt (Pg) | | yes |
| Prepare OK + skip param/column defs (MySQL) | optional small helper | yes (default) |
| Resultset / response state machine | **yes** | calls framer |
| Digest + error stats reporting | | yes |
| Session / hostgroup / userinfo | | yes |

### 4.2 New / touched files (expected)

**New**

- `include/MySQLResultsetFramer.h`
- `lib/MySQLResultsetFramer.cpp`
- `include/PgSQLResponseFramer.h`
- `lib/PgSQLResponseFramer.cpp`
- `test/tap/tests/unit/mysql_resultset_framer_unit-t.cpp`
- `test/tap/tests/unit/pgsql_response_framer_unit-t.cpp`

**Modified**

- `include/MySQLProtocolUtils.h`, `lib/MySQLProtocolUtils.cpp` — OK/EOF/status helpers as needed
- `include/PgSQLCommandComplete.h` (or sibling) — keep tag parsing reusable
- `include/MySQLFFTO.hpp`, `lib/MySQLFFTO.cpp`
- `include/PgSQLFFTO.hpp`, `lib/PgSQLFFTO.cpp`
- `lib/Makefile` (object list)
- Unit test Makefile / registration as required by existing unit harness
- TAP: extend `test_ffto_mysql*` for deprecate_eof matrix, multi-statement, `COM_STMT_FETCH`; extend Pg TAP only if extraction reveals gaps not covered by `test_ffto_pgsql_*`

## 5. MySQLResultsetFramer

### 5.1 API (normative sketch)

```cpp
enum class MySQLRSEventKind {
	None,
	Row,                 // one resultset row observed
	OKNoResultset,       // DML/OK without column-count path
	ResultsetComplete,   // end of one resultset (EOF or OK-as-EOF)
	Error,
};

struct MySQLRSEvent {
	MySQLRSEventKind kind { MySQLRSEventKind::None };
	uint64_t rows_sent_total { 0 };    // rows counted in current resultset
	uint64_t affected_rows { 0 };      // from OK when applicable
	uint16_t status_flags { 0 };
	uint16_t error_code { 0 };
	bool more_results { false };       // SERVER_MORE_RESULTS_EXISTS
};

class MySQLResultsetFramer {
public:
	void reset();
	bool active() const;

	// binary_protocol: COM_STMT_EXECUTE / COM_STMT_FETCH rows
	// deprecate_eof: session client_flag & CLIENT_DEPRECATE_EOF
	void begin(bool binary_protocol, bool deprecate_eof);

	// First server payload after a tracked client command
	MySQLRSEvent on_first_payload(const unsigned char* p, size_t n);

	// Subsequent payloads while active()
	MySQLRSEvent on_payload(const unsigned char* p, size_t n);
};
```

Payloads are **MySQL packet bodies only** (no 3-byte length + seq header). FFTO continues to reassemble headers.

### 5.2 States

```
Idle
  └─ begin() → AwaitingFirst
AwaitingFirst
  ├─ OK (0x00)     → emit OKNoResultset → Idle  (unless more_results → AwaitingFirst)
  ├─ ERR (0xFF)    → emit Error → Idle
  ├─ EOF (rare)    → emit ResultsetComplete → ...
  └─ column_count  → ReadingColumns (store count via lenenc)
ReadingColumns
  ├─ count field-definition packets
  ├─ if !deprecate_eof: after N defs, expect intermediate EOF → ReadingRows
  └─ if  deprecate_eof: after N defs → ReadingRows immediately (no intermediate EOF)
ReadingRows
  ├─ ERR → Error → Idle
  ├─ classic EOF (0xFE, payload len < 9) → ResultsetComplete
  ├─ if deprecate_eof and payload is OK terminator → ResultsetComplete
  └─ else → Row (increment rows)
```

**Protocol note (ProxySQL-confirmed):** With `CLIENT_DEPRECATE_EOF`, the intermediate EOF after column definitions is **omitted**, not replaced; only the final terminator becomes an OK packet (`MySQL_ResultSet.cpp` only emits intermediate EOF when `!deprecate_eof_active`).

### 5.3 OK vs binary row

When `deprecate_eof && binary_protocol` and payload starts with `0x00`:

1. Know `column_count` and null-bitmap length: `(column_count + 7 + 2) / 8`.
2. If payload parses cleanly as an OK packet (status + warnings at expected offsets after two lenenc ints) **and** is inconsistent with a binary row layout for `column_count`, treat as terminator.
3. Otherwise treat as binary row.

Text protocol + deprecate_eof: prefer OK parse for terminator; text rows are length-encoded field sequences. Prefer structural parse over “length >= 7” heuristics alone; add unit cases for empty first column.

### 5.4 Multi-result

On `ResultsetComplete` or `OKNoResultset` with `status_flags & SERVER_MORE_RESULTS_EXISTS`:

- Set `more_results = true` on the event.
- Framer returns to `AwaitingFirst` **without** full `reset` of command context (FFTO keeps same query text + start time).
- FFTO **accumulates** `rows_sent` / `affected_rows` across resultsets.
- FFTO calls `report_query_stats` **once** when a completing event has `more_results == false`, or on Error (report what is known, then clear).

### 5.5 COM_STMT_FETCH

In `MySQLFFTO::process_client_packet`:

- Command `_MYSQL_COM_STMT_FETCH` (`0x1C`): read `stmt_id`, lookup `m_statements`; if found, set current query, start time, `framer.begin(binary=true, deprecate_eof=...)`.
- Unknown `stmt_id`: ignore (same as unknown EXECUTE today).
- Each FETCH round-trip is its own digest sample (same model as EXECUTE), not folded into the original EXECUTE.

Prepare response handling stays in FFTO: on `COM_STMT_PREPARE` OK, store stmt_id → SQL; ignore following param/column def packets by returning to idle observer state (current behavior), optionally via a tiny skip counter for clarity.

### 5.6 Helpers (MySQLProtocolUtils)

Add pure functions as needed (names indicative):

- `mysql_is_eof_payload(p, n)`
- `mysql_is_ok_payload(p, n)` / `mysql_parse_ok_payload(...)` → affected_rows, status_flags, warnings
- `mysql_read_lenenc_int` (already present)
- `mysql_err_packet` (already present)

## 6. PgSQLResponseFramer

### 6.1 API (normative sketch)

```cpp
enum class PgSQLRSEventKind {
	None,
	CommandComplete,   // rows + is_select from tag
	EmptyQuery,        // 'I'
	PortalSuspended,   // 's'
	ReadyForQuery,     // 'Z'
	Error,             // 'E' (payload left for FFTO report_error)
};

struct PgSQLRSEvent {
	PgSQLRSEventKind kind { PgSQLRSEventKind::None };
	uint64_t rows { 0 };
	bool is_select { false };
	// Error: framer may only signal kind; FFTO parses fields via existing helper
};

class PgSQLResponseFramer {
public:
	void reset();
	// Mirrors current finalize_on_sync / response_seen rules for the active query
	void set_finalize_on_sync(bool v);
	bool response_seen() const;

	PgSQLRSEvent on_message(char type, const unsigned char* payload, size_t len);
};
```

### 6.2 Rules (preserve existing FFTO semantics)

Move these from `PgSQLFFTO::process_server_message` without changing meaning:

1. **CommandComplete (`C`)** — parse tag via existing `parse_pgsql_command_complete` / `extract_pg_rows_affected`; mark response seen; if `!finalize_on_sync`, signal “query complete” to FFTO (extended Execute path).
2. **EmptyQuery (`I`) / PortalSuspended (`s`)** — mark response seen; same finalize rule as CommandComplete for extended path.
3. **ReadyForQuery (`Z`)** — finalize current query **only if** `response_seen` (not merely `finalize_on_sync`), to avoid attributing a stale RFQ to a newly activated pipelined query.
4. **Error (`E`)** — complete current with error; FFTO clears pending queue (policy stays in FFTO).

Client-side Parse/Bind/Execute/Close/Query/`X` and `m_pending_queries` remain in `PgSQLFFTO`.

### 6.3 Hardening while extracting

- Keep FETCH/MOVE/COPY/MERGE tag handling in the shared CommandComplete parser.
- Ensure multi-statement simple query (`Q` with multiple commands) still: accumulate row counters across multiple `C`, single finalize on qualifying `Z`.
- No new requirement to emit one digest per sub-statement inside one `Q` (would change metrics cardinality).

## 7. FFTO integration

### 7.1 MySQLFFTO

- Member: `MySQLResultsetFramer m_rs`.
- Replace `READING_COLUMNS` / `READING_ROWS` branches with framer calls; simplify `State` to at least `IDLE`, `AWAITING_PREPARE_OK`, `AWAITING_RESPONSE` (or keep enums but delegate).
- On completing events: `report_query_stats` / `report_error` as today.
- `on_close`: if in-flight query, report partial stats (existing behavior).
- New client command while a resultset is active: best-effort finalize or drop prior in-flight (document single in-flight); prefer finalize-with-current-counters to avoid silent loss when possible.

### 7.2 PgSQLFFTO

- Member: `PgSQLResponseFramer m_rs` (name flexible).
- `process_server_message` becomes thin wrapper: framer event → update counters / `finalize_current_query` / `report_error`.
- Client path and pending queue unchanged unless a bug is found during extraction.

### 7.3 Build

- Framer `.cpp` files compiled into `libproxysql.a` under the same `PROXYSQLFFTO` / `PROXYSQL31` guards as existing FFTO objects.
- Unit tests link framer objects with `test_init` harness; guard with `#ifdef PROXYSQLFFTO` like `ffto_state_machine_unit-t.cpp`.

## 8. Testing strategy

### 8.1 Unit — MySQL framer

Synthetic payloads (no server):

| Case | Expect |
|------|--------|
| Text SELECT, `deprecate_eof=false` | column_count → N defs → EOF → rows → EOF; rows_sent=N |
| Text SELECT, `deprecate_eof=true` | column_count → N defs → rows → OK; rows_sent=N |
| Binary SELECT, deprecate_eof true | binary rows vs final OK distinguished |
| OK DML | OKNoResultset + affected_rows |
| ERR after columns / mid-rows | Error |
| Multi-result OK/EOF with MORE_RESULTS | two resultsets, more_results flags, cumulative rows at FFTO layer (framer per-resultset) |
| Empty first text column | not mistaken for OK terminator |
| 0-row SELECT | defs then terminator, rows_sent=0 |

### 8.2 Unit — PgSQL framer

| Case | Expect |
|------|--------|
| Simple path: C then Z with finalize_on_sync | finalize only after response_seen + Z |
| Extended: C with !finalize_on_sync | complete on C |
| I / s | same as extended complete |
| Z without response_seen | no finalize |
| Multiple C then Z | counters accumulate at FFTO; framer emits multiple CommandComplete |
| E | Error event |

### 8.3 TAP / integration

- MySQL: run with `mysql-enable_client_deprecate_eof=true` and `false`; assert digests for SELECT rows_sent.
- MySQL: multi-statement (`CLIENT_MULTI_STATEMENTS`) single COM_QUERY producing multiple resultsets → one digest, sensible cumulative metrics.
- MySQL: prepared statement + cursor fetch path (`COM_STMT_FETCH`) → digest text matches prepare SQL, count increases per fetch round-trip.
- PgSQL: existing pipeline / stmt_portal / command_types suites must remain green; add unit coverage so regressions are caught without full infra when possible.

### 8.4 Verification commands

```bash
# After clean tier switch:
make clean
PROXYSQL31=1 make -j$(nproc) debug
# unit (pattern per project conventions):
# build + run mysql_resultset_framer_unit-t / pgsql_response_framer_unit-t
# TAP via run-tests-isolated.bash with TEST_PY_TAP_INCL for ffto_mysql / ffto_pgsql
```

## 9. Error handling & performance

- Malformed length / impossible state: framer resets to idle and returns None or Error; FFTO drops in-flight tracking for that command; no abort.
- Existing `ffto_max_buffer_size` bypass unchanged.
- Framer must stay allocation-light (no per-row heap); stack/state only. FFTO still owns query strings.
- Budget: framer work is O(packet) with small constants; must not change Fast Forward throughput character beyond current FFTO cost.

## 10. Rollout plan

1. Land pure framers + unit tests (MySQL + PgSQL), not yet wired (or wired behind same call sites with behavior match for Pg).
2. Wire `MySQLFFTO` to MySQL framer (behavior fix for deprecate_eof / multi-result / FETCH).
3. Wire `PgSQLFFTO` to Pg framer (behavior-preserving extract).
4. Extend TAP for MySQL gap areas; confirm Pg TAP green.
5. No new global variables required.

## 11. Risks

| Risk | Mitigation |
|------|------------|
| OK vs binary row misclassification | Unit matrix; track column_count + binary flag |
| Multi-result status flag endian/offset bugs | Use shared OK/EOF parsers; test known packet dumps |
| Pg extract accidental semantic drift | Golden unit tests from current comments/cases; full pgsql FFTO TAP |
| Prepare metadata packets confused with resultsets | Keep prepare path separate from framer `begin()` |
| Tests pass only with deprecate_eof off today | Explicit true/false matrix in TAP |

## 12. Success criteria

1. Unit tests prove MySQL framer handles deprecate_eof on/off, multi-result flags, and binary OK terminator.
2. FFTO MySQL TAP shows SELECT digests with correct `sum_rows_sent` under default deprecate_eof.
3. Multi-statement MySQL query produces digest(s) per §5.4 without leaving the observer stuck.
4. `COM_STMT_FETCH` produces digests keyed to prepared SQL.
5. PgSQL FFTO TAP suites remain green; response rules covered by unit tests.
6. No new capability negotiation changes; Fast Forward data path still unmodified by FFTO (observe-only).

## 13. Decision log

- **2026-08-12:** Compare sql-tap vs FFTO; MySQL framing gaps identified; Pg ahead for digest core.
- **2026-08-12:** Scope = DEPRECATE_EOF + multi-result + FETCH (not sql-tap UI parity).
- **2026-08-12:** Approach **C** — pure shared framers, dual-protocol.
- **2026-08-12:** Multi-result = one digest per client command with accumulated counters.
- **2026-08-12:** FETCH = per round-trip digest, not folded into EXECUTE.
