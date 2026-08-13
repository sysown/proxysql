# FFTO Protocol Framers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close MySQL FFTO packet-parsing gaps (`CLIENT_DEPRECATE_EOF`, multi-result, `COM_STMT_FETCH`) and extract dual-protocol pure framers (MySQL + PostgreSQL) for unit-testable digest observation on Fast Forward sessions.

**Architecture:** Add `MySQLResultsetFramer` and `PgSQLResponseFramer` as pure payload→event state machines with no Session dependencies. Wire them into `MySQLFFTO` / `PgSQLFFTO`, which keep reassembly, stmt maps, and digest reporting. Spec: `docs/superpowers/specs/2026-08-12-ffto-protocol-framers-design.md`.

**Tech Stack:** C++17, ProxySQL `libproxysql.a`, TAP unit harness (`test/tap/tests/unit`), FFTO TAP tests under `PROXYSQL31=1`.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `include/MySQLProtocolUtils.h` | Modify | OK/EOF classifiers + OK field parse |
| `lib/MySQLProtocolUtils.cpp` | Modify | Implement helpers |
| `include/MySQLResultsetFramer.h` | Create | MySQL resultset state machine API |
| `lib/MySQLResultsetFramer.cpp` | Create | Implementation |
| `include/PgSQLResponseFramer.h` | Create | Pg server-message framer API |
| `lib/PgSQLResponseFramer.cpp` | Create | Implementation (from current FFTO rules) |
| `lib/Makefile` | Modify | Add framer `.oo` under `PROXYSQLFFTO` |
| `include/MySQLFFTO.hpp` / `lib/MySQLFFTO.cpp` | Modify | Use framer; add FETCH |
| `include/PgSQLFFTO.hpp` / `lib/PgSQLFFTO.cpp` | Modify | Use Pg framer |
| `test/tap/tests/unit/Makefile` | Modify | Register new unit binaries |
| `test/tap/tests/unit/mysql_resultset_framer_unit-t.cpp` | Create | MySQL framer tests |
| `test/tap/tests/unit/pgsql_response_framer_unit-t.cpp` | Create | Pg framer tests |
| `test/tap/tests/unit/ffto_protocol_unit-t.cpp` | Modify | OK/EOF helper tests |
| `test/tap/tests/test_ffto_mysql_deprecate_eof-t.cpp` | Create | TAP: deprecate_eof on/off SELECT digests |
| `test/tap/tests/test_ffto_mysql_multi_result-t.cpp` | Create | TAP: multi-statement digests |
| `test/tap/tests/test_ffto_mysql_stmt_fetch-t.cpp` | Create | TAP: COM_STMT_FETCH digests |
| `test/tap/groups/groups.json` | Modify | Register new TAP tests in appropriate mysql group |

**Build tier (every make):**

```bash
make clean   # when switching tiers or unsure
PROXYSQL31=1 make -j$(nproc) debug
PROXYSQL31=1 make build_tap_test_debug
```

**Unit test run pattern:**

```bash
cd test/tap/tests/unit
PROXYSQL31=1 make -j$(nproc) mysql_resultset_framer_unit-t
./mysql_resultset_framer_unit-t
```

---

### Task 1: MySQL OK/EOF protocol helpers

**Files:**
- Modify: `include/MySQLProtocolUtils.h`
- Modify: `lib/MySQLProtocolUtils.cpp`
- Modify: `test/tap/tests/unit/ffto_protocol_unit-t.cpp`

- [ ] **Step 1: Write failing unit tests for OK/EOF helpers**

Append to `ffto_protocol_unit-t.cpp` (and bump `plan()` count accordingly):

```cpp
static void test_mysql_is_eof_payload() {
	unsigned char eof5[] = {0xFE, 0x00, 0x00, 0x02, 0x00}; // warnings=0, status=AUTOCOMMIT
	ok(mysql_is_eof_payload(eof5, sizeof(eof5)) == true, "EOF: 5-byte classic EOF");
	unsigned char not_eof[] = {0xFE, 0x01, 0, 0, 0, 0, 0, 0, 0}; // lenenc 8-byte style length
	ok(mysql_is_eof_payload(not_eof, sizeof(not_eof)) == false, "EOF: 0xFE with len>=9 is not EOF");
	unsigned char okpkt[] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
	ok(mysql_is_eof_payload(okpkt, sizeof(okpkt)) == false, "EOF: OK is not EOF");
}

static void test_mysql_parse_ok_payload() {
	// OK: header 0x00, affected=1, last_insert=0, status=0x0002, warnings=0
	unsigned char okp[] = {0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00};
	MySQLOkFields f{};
	ok(mysql_parse_ok_payload(okp, sizeof(okp), &f) == true, "OK parse: success");
	ok(f.affected_rows == 1, "OK parse: affected_rows=1");
	ok(f.status_flags == 0x0002, "OK parse: status AUTOCOMMIT");
	ok((f.status_flags & SERVER_MORE_RESULTS_EXIST) == 0, "OK parse: no MORE_RESULTS");
}

static void test_mysql_parse_ok_more_results() {
	// status = SERVER_MORE_RESULTS_EXIST (8) | AUTOCOMMIT (2) = 10
	unsigned char okp[] = {0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00};
	MySQLOkFields f{};
	ok(mysql_parse_ok_payload(okp, sizeof(okp), &f) == true, "OK more: parse ok");
	ok((f.status_flags & SERVER_MORE_RESULTS_EXIST) != 0, "OK more: MORE_RESULTS set");
}

static void test_mysql_eof_status_flags() {
	unsigned char eof5[] = {0xFE, 0x00, 0x00, 0x0A, 0x00}; // warnings=0, status=0x000A
	uint16_t st = 0, wr = 0;
	ok(mysql_parse_eof_payload(eof5, sizeof(eof5), &wr, &st) == true, "EOF parse: ok");
	ok(st == 0x000A, "EOF parse: status has MORE_RESULTS|AUTOCOMMIT");
}
```

Include `MySQLProtocolUtils.h`. Use `SERVER_MORE_RESULTS_EXIST` from MariaDB headers already pulled via `proxysql.h` / test includes; if missing in the unit TU, define:

```cpp
#ifndef SERVER_MORE_RESULTS_EXIST
#define SERVER_MORE_RESULTS_EXIST 8
#endif
```

Call the new tests from `main()` and increase `plan(N)`.

- [ ] **Step 2: Run tests — expect link/compile failure (symbols missing)**

```bash
cd /data/rene/proxysql
PROXYSQL31=1 make -j$(nproc) debug 2>&1 | tail -5
cd test/tap/tests/unit && PROXYSQL31=1 make -j$(nproc) ffto_protocol_unit-t 2>&1 | tail -20
```

Expected: compile error on undeclared `mysql_is_eof_payload` / `mysql_parse_ok_payload`.

- [ ] **Step 3: Implement helpers**

In `include/MySQLProtocolUtils.h` add:

```cpp
struct MySQLOkFields {
	uint64_t affected_rows;
	uint64_t last_insert_id;
	uint16_t status_flags;
	uint16_t warnings;
};

bool mysql_is_eof_payload(const unsigned char* p, size_t n);
bool mysql_is_ok_header(const unsigned char* p, size_t n); // first byte 0x00 and n>=1
bool mysql_parse_ok_payload(const unsigned char* p, size_t n, MySQLOkFields* out);
bool mysql_parse_eof_payload(const unsigned char* p, size_t n, uint16_t* warnings, uint16_t* status_flags);
```

In `lib/MySQLProtocolUtils.cpp`:

```cpp
bool mysql_is_eof_payload(const unsigned char* p, size_t n) {
	// Classic EOF: 0xFE and payload length < 9
	return p && n >= 1 && n < 9 && p[0] == 0xFE;
}

bool mysql_is_ok_header(const unsigned char* p, size_t n) {
	return p && n >= 1 && p[0] == 0x00;
}

bool mysql_parse_ok_payload(const unsigned char* p, size_t n, MySQLOkFields* out) {
	if (!p || !out || n < 1 || p[0] != 0x00) return false;
	const unsigned char* cur = p + 1;
	size_t rem = n - 1;
	out->affected_rows = mysql_read_lenenc_int(cur, rem);
	out->last_insert_id = mysql_read_lenenc_int(cur, rem);
	if (rem < 4) return false;
	out->status_flags = (uint16_t)(cur[0] | (cur[1] << 8));
	out->warnings = (uint16_t)(cur[2] | (cur[3] << 8));
	return true;
}

bool mysql_parse_eof_payload(const unsigned char* p, size_t n, uint16_t* warnings, uint16_t* status_flags) {
	if (!mysql_is_eof_payload(p, n) || n < 5) return false;
	if (warnings) *warnings = (uint16_t)(p[1] | (p[2] << 8));
	if (status_flags) *status_flags = (uint16_t)(p[3] | (p[4] << 8));
	return true;
}
```

Note: `mysql_read_lenenc_int` takes `const unsigned char*&` — ensure signature matches existing helper.

- [ ] **Step 4: Rebuild and run unit test**

```bash
PROXYSQL31=1 make -j$(nproc) debug
cd test/tap/tests/unit && PROXYSQL31=1 make -j$(nproc) ffto_protocol_unit-t && ./ffto_protocol_unit-t
```

Expected: all OK lines, exit 0.

- [ ] **Step 5: Commit**

```bash
git add include/MySQLProtocolUtils.h lib/MySQLProtocolUtils.cpp test/tap/tests/unit/ffto_protocol_unit-t.cpp
git commit -m "feat(ffto): MySQL OK/EOF payload helpers for resultset framer"
```

---

### Task 2: MySQLResultsetFramer — API + build + first failing tests

**Files:**
- Create: `include/MySQLResultsetFramer.h`
- Create: `lib/MySQLResultsetFramer.cpp` (stub returning None)
- Modify: `lib/Makefile` — under `ifeq ($(PROXYSQLFFTO),1)` add `MySQLResultsetFramer.oo`
- Create: `test/tap/tests/unit/mysql_resultset_framer_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile` — add `mysql_resultset_framer_unit-t` next to `ffto_state_machine_unit-t`

- [ ] **Step 1: Add header API**

Create `include/MySQLResultsetFramer.h`:

```cpp
#ifndef MYSQL_RESULTSET_FRAMER_H
#define MYSQL_RESULTSET_FRAMER_H

#include <cstdint>
#include <cstddef>

enum class MySQLRSEventKind {
	None = 0,
	Row,
	OKNoResultset,
	ResultsetComplete,
	Error
};

struct MySQLRSEvent {
	MySQLRSEventKind kind { MySQLRSEventKind::None };
	uint64_t rows_sent_total { 0 };
	uint64_t affected_rows { 0 };
	uint16_t status_flags { 0 };
	uint16_t error_code { 0 };
	bool more_results { false };
};

class MySQLResultsetFramer {
public:
	void reset();
	bool active() const;
	void begin(bool binary_protocol, bool deprecate_eof);
	MySQLRSEvent on_first_payload(const unsigned char* p, size_t n);
	MySQLRSEvent on_payload(const unsigned char* p, size_t n);

private:
	enum class State {
		Idle,
		AwaitingFirst,
		ReadingColumns,
		ReadingRows
	};

	State m_state { State::Idle };
	bool m_binary { false };
	bool m_deprecate_eof { false };
	uint64_t m_column_count { 0 };
	uint64_t m_columns_seen { 0 };
	uint64_t m_rows_sent { 0 };
	bool m_saw_intermediate_eof { false };

	MySQLRSEvent make_complete(uint16_t status, uint64_t affected);
	MySQLRSEvent make_error(uint16_t code);
	bool looks_like_ok_terminator(const unsigned char* p, size_t n) const;
};

#endif
```

- [ ] **Step 2: Stub implementation**

Create `lib/MySQLResultsetFramer.cpp` with `reset`/`begin`/`active` working and `on_*` returning `{None}` until Task 3.

```cpp
#include "MySQLResultsetFramer.h"
#include "MySQLProtocolUtils.h"
#include <cstring>

void MySQLResultsetFramer::reset() {
	m_state = State::Idle;
	m_binary = false;
	m_deprecate_eof = false;
	m_column_count = 0;
	m_columns_seen = 0;
	m_rows_sent = 0;
	m_saw_intermediate_eof = false;
}

bool MySQLResultsetFramer::active() const {
	return m_state != State::Idle;
}

void MySQLResultsetFramer::begin(bool binary_protocol, bool deprecate_eof) {
	reset();
	m_binary = binary_protocol;
	m_deprecate_eof = deprecate_eof;
	m_state = State::AwaitingFirst;
}

MySQLRSEvent MySQLResultsetFramer::on_first_payload(const unsigned char* p, size_t n) {
	(void)p; (void)n;
	return {};
}

MySQLRSEvent MySQLResultsetFramer::on_payload(const unsigned char* p, size_t n) {
	(void)p; (void)n;
	return {};
}
```

- [ ] **Step 3: Makefile entries**

`lib/Makefile` FFTO block:

```make
ifeq ($(PROXYSQLFFTO),1)
_OBJ_CXX += MySQLFFTO.oo PgSQLFFTO.oo MySQLResultsetFramer.oo PgSQLResponseFramer.oo
endif
```

(Include `PgSQLResponseFramer.oo` only after Task 5 creates the file; until then add only `MySQLResultsetFramer.oo`.)

`test/tap/tests/unit/Makefile` — add to `UNIT_TESTS`:

```make
	mysql_resultset_framer_unit-t \
	ffto_state_machine_unit-t \
```

- [ ] **Step 4: Write failing behavioral unit tests**

Create `test/tap/tests/unit/mysql_resultset_framer_unit-t.cpp`:

```cpp
#ifdef PROXYSQLFFTO
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "MySQLResultsetFramer.h"
#include "MySQLProtocolUtils.h"
#include <vector>
#include <cstring>

#ifndef SERVER_MORE_RESULTS_EXIST
#define SERVER_MORE_RESULTS_EXIST 8
#endif

// Helpers to feed column-count + N dummy column defs + terminator
static std::vector<unsigned char> colcount(uint8_t n) { return { n }; }
static std::vector<unsigned char> dummy_coldef() {
	// minimal-ish field packet starting with lenenc "def"
	return { 3,'d','e','f', 0, 0, 0, 0, 0, 0x0c, 0x3f,0x00, 0,0,0,0, 0xfd, 0,0,0,0,0,0 };
}
static std::vector<unsigned char> eof_pkt(uint16_t status = 0x0002) {
	return { 0xFE, 0x00, 0x00, (uint8_t)(status & 0xFF), (uint8_t)(status >> 8) };
}
static std::vector<unsigned char> ok_term(uint16_t status = 0x0002) {
	return { 0x00, 0x00, 0x00, (uint8_t)(status & 0xFF), (uint8_t)(status >> 8), 0x00, 0x00 };
}
static std::vector<unsigned char> text_row_one() {
	// one column value "1" → lenenc 1 + '1'
	return { 0x01, '1' };
}

static void test_text_select_classic_eof() {
	MySQLResultsetFramer f;
	f.begin(false, false);
	auto e = f.on_first_payload(colcount(1).data(), 1);
	ok(e.kind == MySQLRSEventKind::None && f.active(), "classic: after colcount still active");
	e = f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	ok(e.kind == MySQLRSEventKind::None, "classic: coldef");
	e = f.on_payload(eof_pkt().data(), eof_pkt().size());
	ok(e.kind == MySQLRSEventKind::None, "classic: intermediate EOF → rows");
	e = f.on_payload(text_row_one().data(), text_row_one().size());
	ok(e.kind == MySQLRSEventKind::Row && e.rows_sent_total == 1, "classic: row counted");
	e = f.on_payload(eof_pkt().data(), eof_pkt().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.rows_sent_total == 1 && !e.more_results,
		"classic: final EOF completes");
	ok(!f.active(), "classic: idle after complete");
}

static void test_text_select_deprecate_eof() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	f.on_first_payload(colcount(1).data(), 1);
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	// NO intermediate EOF
	auto e = f.on_payload(text_row_one().data(), text_row_one().size());
	ok(e.kind == MySQLRSEventKind::Row && e.rows_sent_total == 1, "dep_eof: row without intermediate EOF");
	e = f.on_payload(ok_term().data(), ok_term().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.rows_sent_total == 1, "dep_eof: OK terminates");
}

static void test_ok_dml() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	unsigned char okp[] = {0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00}; // affected=5
	auto e = f.on_first_payload(okp, sizeof(okp));
	ok(e.kind == MySQLRSEventKind::OKNoResultset && e.affected_rows == 5, "DML OK affected=5");
	ok(!f.active(), "DML: idle");
}

int main() {
	plan(10);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal");
	test_text_select_classic_eof();
	test_text_select_deprecate_eof();
	test_ok_dml();
	test_cleanup_minimal();
	return exit_status();
}
#else
#include "tap.h"
int main() { plan(1); ok(1, "skipped without PROXYSQLFFTO"); return exit_status(); }
#endif
```

Adjust `plan()` to match actual assertion count.

- [ ] **Step 5: Build stub; run tests — expect FAIL on assertions**

```bash
PROXYSQL31=1 make -j$(nproc) debug
cd test/tap/tests/unit && PROXYSQL31=1 make -j$(nproc) mysql_resultset_framer_unit-t && ./mysql_resultset_framer_unit-t
```

Expected: binary runs, assertions fail (stub returns None).

- [ ] **Step 6: Commit stub + failing tests**

```bash
git add include/MySQLResultsetFramer.h lib/MySQLResultsetFramer.cpp lib/Makefile \
  test/tap/tests/unit/mysql_resultset_framer_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "test(ffto): MySQLResultsetFramer scaffold and failing unit tests"
```

---

### Task 3: Implement MySQLResultsetFramer core (EOF + deprecate_eof + DML/ERR)

**Files:**
- Modify: `lib/MySQLResultsetFramer.cpp`

- [ ] **Step 1: Implement state machine**

Replace stubs with full logic. Critical rules:

```cpp
MySQLRSEvent MySQLResultsetFramer::on_first_payload(const unsigned char* p, size_t n) {
	if (m_state != State::AwaitingFirst || !p || n == 0) return {};
	if (p[0] == 0xFF) {
		uint16_t code = (n >= 3) ? (uint16_t)(p[1] | (p[2] << 8)) : 0;
		reset();
		return make_error(code);
	}
	if (p[0] == 0x00) {
		MySQLOkFields okf{};
		if (!mysql_parse_ok_payload(p, n, &okf)) { reset(); return {}; }
		bool more = (okf.status_flags & SERVER_MORE_RESULTS_EXIST) != 0;
		MySQLRSEvent ev = make_complete(okf.status_flags, okf.affected_rows);
		ev.kind = MySQLRSEventKind::OKNoResultset;
		ev.more_results = more;
		if (more) {
			// stay in command: prepare for next resultset
			m_rows_sent = 0;
			m_columns_seen = 0;
			m_column_count = 0;
			m_state = State::AwaitingFirst;
		} else {
			reset();
		}
		return ev;
	}
	// column count (lenenc). For small counts first byte is the count.
	const unsigned char* cur = p;
	size_t rem = n;
	m_column_count = mysql_read_lenenc_int(cur, rem);
	m_columns_seen = 0;
	m_rows_sent = 0;
	if (m_column_count == 0) {
		// empty column count edge: treat subsequent as rows phase
		m_state = m_deprecate_eof ? State::ReadingRows : State::ReadingColumns;
		// if !deprecate_eof, still expect EOF before rows; with 0 cols servers send EOF immediately
	}
	m_state = State::ReadingColumns;
	return {};
}

MySQLRSEvent MySQLResultsetFramer::on_payload(const unsigned char* p, size_t n) {
	if (!active() || m_state == State::AwaitingFirst) {
		return on_first_payload(p, n);
	}
	if (!p || n == 0) return {};

	if (m_state == State::ReadingColumns) {
		if (p[0] == 0xFF) {
			uint16_t code = (n >= 3) ? (uint16_t)(p[1] | (p[2] << 8)) : 0;
			reset();
			return make_error(code);
		}
		if (!m_deprecate_eof && mysql_is_eof_payload(p, n)) {
			m_state = State::ReadingRows;
			return {};
		}
		// column definition packet
		m_columns_seen++;
		if (m_columns_seen >= m_column_count) {
			if (m_deprecate_eof) {
				m_state = State::ReadingRows;
			}
			// else wait for intermediate EOF
		}
		return {};
	}

	if (m_state == State::ReadingRows) {
		if (p[0] == 0xFF) {
			uint16_t code = (n >= 3) ? (uint16_t)(p[1] | (p[2] << 8)) : 0;
			MySQLRSEvent ev = make_error(code);
			ev.rows_sent_total = m_rows_sent;
			reset();
			return ev;
		}
		if (!m_deprecate_eof && mysql_is_eof_payload(p, n)) {
			uint16_t st = 0, wr = 0;
			mysql_parse_eof_payload(p, n, &wr, &st);
			return finish_resultset(st, 0);
		}
		if (m_deprecate_eof && looks_like_ok_terminator(p, n)) {
			MySQLOkFields okf{};
			mysql_parse_ok_payload(p, n, &okf);
			return finish_resultset(okf.status_flags, okf.affected_rows);
		}
		// row
		m_rows_sent++;
		MySQLRSEvent ev;
		ev.kind = MySQLRSEventKind::Row;
		ev.rows_sent_total = m_rows_sent;
		return ev;
	}
	return {};
}

// finish_resultset: emit ResultsetComplete; if MORE_RESULTS keep AwaitingFirst else reset
// looks_like_ok_terminator: mysql_parse_ok_payload succeeds; if m_binary, also reject packets
// that match binary row layout (null bitmap length (m_column_count+9)/8 present and n larger than minimal OK in a row-like way).
// Prefer: if parse OK succeeds AND ( !m_binary OR n is consistent with OK and not with mandatory null-bitmap+values ), treat as OK.
```

Define `SERVER_MORE_RESULTS_EXIST` as 8 if not included via a lightweight constant in the cpp file (avoid pulling full proxysql.h into the pure framer if possible):

```cpp
static constexpr uint16_t kServerMoreResultsExist = 8;
```

- [ ] **Step 2: Run unit tests — expect PASS for Task 2 cases**

```bash
PROXYSQL31=1 make -j$(nproc) debug
cd test/tap/tests/unit && PROXYSQL31=1 make -j$(nproc) mysql_resultset_framer_unit-t && ./mysql_resultset_framer_unit-t
```

- [ ] **Step 3: Commit**

```bash
git add lib/MySQLResultsetFramer.cpp include/MySQLResultsetFramer.h
git commit -m "feat(ffto): MySQLResultsetFramer handles classic and deprecate_eof resultsets"
```

---

### Task 4: Multi-result + binary row vs OK unit coverage

**Files:**
- Modify: `test/tap/tests/unit/mysql_resultset_framer_unit-t.cpp`
- Modify: `lib/MySQLResultsetFramer.cpp` if gaps appear

- [ ] **Step 1: Add tests**

```cpp
static void test_multi_result_two_selects_dep_eof() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	// RS1: 1 col, 1 row, OK with MORE_RESULTS
	f.on_first_payload(colcount(1).data(), 1);
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	f.on_payload(text_row_one().data(), text_row_one().size());
	auto e = f.on_payload(ok_term(0x0002 | SERVER_MORE_RESULTS_EXIST).data(), 7);
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.more_results && e.rows_sent_total == 1,
		"multi: first RS complete more=1");
	ok(f.active(), "multi: still active for next RS");
	// RS2
	f.on_payload(colcount(1).data(), 1); // or on_first via on_payload idle-first path
	// Use on_payload which delegates to on_first when AwaitingFirst
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	f.on_payload(text_row_one().data(), text_row_one().size());
	e = f.on_payload(ok_term(0x0002).data(), 7);
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && !e.more_results && e.rows_sent_total == 1,
		"multi: second RS complete more=0");
}

static void test_binary_row_not_ok() {
	MySQLResultsetFramer f;
	f.begin(true, true);
	f.on_first_payload(colcount(1).data(), 1);
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	// binary row: 0x00 + null_bitmap (1 byte for 1 col) + int32 value 7
	unsigned char brow[] = { 0x00, 0x00, 0x07, 0x00, 0x00, 0x00 };
	auto e = f.on_payload(brow, sizeof(brow));
	ok(e.kind == MySQLRSEventKind::Row, "binary: row not mistaken for OK");
	e = f.on_payload(ok_term().data(), ok_term().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete, "binary: OK ends RS");
}

static void test_err_mid_rows() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	f.on_first_payload(colcount(1).data(), 1);
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	unsigned char err[] = { 0xFF, 0x15, 0x04, '#', 'H','Y','0','0','0', 'x' };
	auto e = f.on_payload(err, sizeof(err));
	ok(e.kind == MySQLRSEventKind::Error && e.error_code == 1045, "ERR mid-rows");
	ok(!f.active(), "idle after ERR");
}
```

- [ ] **Step 2: Fix `looks_like_ok_terminator` until tests pass**

Binary null-bitmap length: `(column_count + 7 + 2) / 8` per MySQL binary protocol (extra 2 bits offset).

Heuristic that works for unit cases:
1. If `!mysql_parse_ok_payload` → not OK.
2. If `!m_binary` → OK terminator.
3. If `m_binary`: compute `nb = (m_column_count + 9) / 8`; if `n >= 1 + nb` and packet is longer than a minimal OK **and** looks like it has row payload after bitmap, treat as row; else if parse OK and `n` equals typical OK size without row tail, terminator.

Keep the implementation conservative and covered by tests; refine with TAP later if needed.

- [ ] **Step 3: Run unit tests PASS**

```bash
PROXYSQL31=1 make -j$(nproc) debug
cd test/tap/tests/unit && PROXYSQL31=1 make mysql_resultset_framer_unit-t && ./mysql_resultset_framer_unit-t
```

- [ ] **Step 4: Commit**

```bash
git add lib/MySQLResultsetFramer.cpp test/tap/tests/unit/mysql_resultset_framer_unit-t.cpp
git commit -m "test(ffto): multi-result and binary-vs-OK coverage for MySQL framer"
```

---

### Task 5: Wire MySQLFFTO to framer + COM_STMT_FETCH

**Files:**
- Modify: `include/MySQLFFTO.hpp`
- Modify: `lib/MySQLFFTO.cpp`

- [ ] **Step 1: Header changes**

- Include `MySQLResultsetFramer.h`
- Add member `MySQLResultsetFramer m_rs;`
- Keep `m_statements`, buffers, prepare state
- Simplify `State` enum to: `IDLE`, `AWAITING_PREPARE_OK`, `AWAITING_RESPONSE` (remove READING_COLUMNS/ROWS or leave unused)
- Add accumulators if needed: `m_total_rows_sent`, `m_total_affected` for multi-result across framer resets of per-RS counters

- [ ] **Step 2: Client path**

In `process_client_packet`:

```cpp
} else if (command == _MYSQL_COM_STMT_FETCH) {
	if (len >= 5) {
		uint32_t stmt_id; memcpy(&stmt_id, data + 1, 4);
		auto it = m_statements.find(stmt_id);
		if (it != m_statements.end()) {
			// optional: finalize previous in-flight
			m_current_query = it->second;
			m_query_start_time = monotonic_time();
			m_affected_rows = 0; m_rows_sent = 0;
			m_state = AWAITING_RESPONSE;
			bool dep = /* client_flag & CLIENT_DEPRECATE_EOF */ false;
			if (m_session && m_session->client_myds && m_session->client_myds->myconn)
				dep = (m_session->client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF);
			m_rs.begin(/*binary*/true, dep);
		}
	}
}
```

Same `m_rs.begin(false/true, dep)` for COM_QUERY / COM_STMT_EXECUTE when starting a tracked query.

- [ ] **Step 3: Server path**

Replace READING_* branches with:

```cpp
if (m_state == AWAITING_PREPARE_OK) { /* existing prepare OK handling */ return; }

if (m_state == AWAITING_RESPONSE || m_rs.active()) {
	MySQLRSEvent ev = m_rs.active() && m_rs /* already begun */
		? (/* if first packet of command already consumed use on_payload */ m_rs.on_payload(data, len))
		: m_rs.on_first_payload(data, len);
	// Simpler approach: always begin() on client command; always on_payload on server which
	// routes AwaitingFirst internally via on_first when state is AwaitingFirst.
	// So server only calls: MySQLRSEvent ev = m_rs.on_payload(data, len);
	// and on_payload delegates to on_first when AwaitingFirst.

	switch (ev.kind) {
	case MySQLRSEventKind::Row:
		m_rows_sent = ev.rows_sent_total; // or accumulate across multi RS in FFTO
		break;
	case MySQLRSEventKind::OKNoResultset:
		m_affected_rows += ev.affected_rows;
		if (!ev.more_results) {
			report_query_stats(m_current_query, monotonic_time() - m_query_start_time, m_affected_rows, m_rows_sent);
			m_state = IDLE; clear_active_query(); m_rs.reset();
		}
		break;
	case MySQLRSEventKind::ResultsetComplete:
		m_rows_sent += /* delta: track last */ // easiest: keep m_rows_sent as sum; framer returns per-RS total
		// Spec: accumulate across multi-result
		// Implementation: on each Complete, m_rows_sent += ev.rows_sent_total (framer resets per RS)
		if (!ev.more_results) {
			report_query_stats(...);
			m_state = IDLE; clear_active_query(); m_rs.reset();
		}
		break;
	case MySQLRSEventKind::Error:
		report_query_stats(...);
		report_error(data, len);
		m_state = IDLE; clear_active_query(); m_rs.reset();
		break;
	default: break;
	}
}
```

**Accumulation detail (normative):**  
On each `ResultsetComplete` / `OKNoResultset`, add `ev.rows_sent_total` to `m_rows_sent` and `ev.affected_rows` to `m_affected_rows`. Framer’s `rows_sent_total` is per-resultset only. Report once when `!more_results`.

- [ ] **Step 4: Build lib + existing unit smoke**

```bash
PROXYSQL31=1 make -j$(nproc) debug
cd test/tap/tests/unit && PROXYSQL31=1 make ffto_state_machine_unit-t mysql_resultset_framer_unit-t && ./ffto_state_machine_unit-t && ./mysql_resultset_framer_unit-t
```

- [ ] **Step 5: Commit**

```bash
git add include/MySQLFFTO.hpp lib/MySQLFFTO.cpp
git commit -m "feat(ffto): wire MySQLFFTO to ResultsetFramer; track COM_STMT_FETCH"
```

---

### Task 6: PgSQLResponseFramer extract + unit tests

**Files:**
- Create: `include/PgSQLResponseFramer.h`
- Create: `lib/PgSQLResponseFramer.cpp`
- Modify: `lib/Makefile` — ensure `PgSQLResponseFramer.oo` in FFTO list
- Create: `test/tap/tests/unit/pgsql_response_framer_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile` — add `pgsql_response_framer_unit-t`

- [ ] **Step 1: Header**

```cpp
#ifndef PGSQL_RESPONSE_FRAMER_H
#define PGSQL_RESPONSE_FRAMER_H

#include <cstdint>
#include <cstddef>

enum class PgSQLRSEventKind {
	None = 0,
	CommandComplete,
	EmptyQuery,
	PortalSuspended,
	ReadyForQuery,
	Error
};

struct PgSQLRSEvent {
	PgSQLRSEventKind kind { PgSQLRSEventKind::None };
	uint64_t rows { 0 };
	bool is_select { false };
};

class PgSQLResponseFramer {
public:
	void reset();
	void set_finalize_on_sync(bool v);
	bool response_seen() const { return m_response_seen; }
	bool finalize_on_sync() const { return m_finalize_on_sync; }

	// Returns event; sets m_response_seen on C/I/s; does not clear on Z (caller decides)
	PgSQLRSEvent on_message(char type, const unsigned char* payload, size_t len);

	// Call when FFTO activates a new current query
	void on_query_activated(bool finalize_on_sync);

private:
	bool m_finalize_on_sync { false };
	bool m_response_seen { false };
};

#endif
```

- [ ] **Step 2: Implementation using `parse_pgsql_command_complete`**

```cpp
#include "PgSQLResponseFramer.h"
#include "PgSQLCommandComplete.h"

void PgSQLResponseFramer::reset() {
	m_finalize_on_sync = false;
	m_response_seen = false;
}

void PgSQLResponseFramer::on_query_activated(bool finalize_on_sync) {
	m_finalize_on_sync = finalize_on_sync;
	m_response_seen = false;
}

void PgSQLResponseFramer::set_finalize_on_sync(bool v) { m_finalize_on_sync = v; }

PgSQLRSEvent PgSQLResponseFramer::on_message(char type, const unsigned char* payload, size_t len) {
	PgSQLRSEvent ev;
	switch (type) {
	case 'C': {
		auto r = parse_pgsql_command_complete(payload, len);
		ev.kind = PgSQLRSEventKind::CommandComplete;
		ev.rows = r.rows;
		ev.is_select = r.is_select;
		m_response_seen = true;
		return ev;
	}
	case 'I':
		ev.kind = PgSQLRSEventKind::EmptyQuery;
		m_response_seen = true;
		return ev;
	case 's':
		ev.kind = PgSQLRSEventKind::PortalSuspended;
		m_response_seen = true;
		return ev;
	case 'Z':
		ev.kind = PgSQLRSEventKind::ReadyForQuery;
		return ev;
	case 'E':
		ev.kind = PgSQLRSEventKind::Error;
		return ev;
	default:
		return ev;
	}
}
```

- [ ] **Step 3: Unit tests (behavior of finalize gating is FFTO’s job; framer tests event emission + response_seen)**

```cpp
static void test_command_complete_select() {
	PgSQLResponseFramer f;
	f.on_query_activated(true);
	const char* tag = "SELECT 3";
	auto e = f.on_message('C', (const unsigned char*)tag, 8);
	ok(e.kind == PgSQLRSEventKind::CommandComplete && e.rows == 3 && e.is_select, "C SELECT");
	ok(f.response_seen(), "response_seen after C");
}

static void test_portal_suspended() {
	PgSQLResponseFramer f;
	f.on_query_activated(false);
	auto e = f.on_message('s', nullptr, 0);
	ok(e.kind == PgSQLRSEventKind::PortalSuspended && f.response_seen(), "s sets seen");
}

static void test_ready_for_query_no_side_effect() {
	PgSQLResponseFramer f;
	f.on_query_activated(true);
	auto e = f.on_message('Z', (const unsigned char*)"I", 1);
	ok(e.kind == PgSQLRSEventKind::ReadyForQuery, "Z event");
	ok(!f.response_seen(), "Z alone does not set response_seen");
}
```

- [ ] **Step 4: Build + run**

```bash
PROXYSQL31=1 make -j$(nproc) debug
cd test/tap/tests/unit && PROXYSQL31=1 make pgsql_response_framer_unit-t && ./pgsql_response_framer_unit-t
```

- [ ] **Step 5: Commit**

```bash
git add include/PgSQLResponseFramer.h lib/PgSQLResponseFramer.cpp lib/Makefile \
  test/tap/tests/unit/pgsql_response_framer_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "feat(ffto): extract PgSQLResponseFramer with unit tests"
```

---

### Task 7: Wire PgSQLFFTO to PgSQLResponseFramer

**Files:**
- Modify: `include/PgSQLFFTO.hpp`
- Modify: `lib/PgSQLFFTO.cpp`

- [ ] **Step 1: Replace server switch body**

Keep client path and pending queue. In `process_server_message`:

```cpp
void PgSQLFFTO::process_server_message(char type, const unsigned char* payload, size_t len) {
	if (m_state == IDLE) return;
	PgSQLRSEvent ev = m_rs.on_message(type, payload, len);
	switch (ev.kind) {
	case PgSQLRSEventKind::CommandComplete:
		if (ev.is_select) m_rows_sent += ev.rows;
		else m_affected_rows += ev.rows;
		m_response_seen = m_rs.response_seen();
		if (!m_current_finalize_on_sync) finalize_current_query();
		break;
	case PgSQLRSEventKind::EmptyQuery:
	case PgSQLRSEventKind::PortalSuspended:
		m_response_seen = true;
		if (!m_current_finalize_on_sync) finalize_current_query();
		break;
	case PgSQLRSEventKind::ReadyForQuery:
		if (m_rs.response_seen() || m_response_seen) finalize_current_query();
		break;
	case PgSQLRSEventKind::Error:
		// existing report path
		...
		m_rs.reset();
		break;
	default: break;
	}
}
```

On `track_query` / `activate_next_query`, call `m_rs.on_query_activated(finalize_on_sync)` and keep `m_current_finalize_on_sync` in sync (or drop duplicate flags if framer becomes source of truth — prefer single source: framer holds `finalize_on_sync` and `response_seen`; FFTO may keep mirrors only if needed for on_close).

**Behavior must match pre-extract semantics** (especially RFQ gated on response_seen). Re-read comments in current `PgSQLFFTO.cpp` lines 277–331 when wiring.

- [ ] **Step 2: Build + unit + existing ffto_state_machine**

```bash
PROXYSQL31=1 make -j$(nproc) debug
cd test/tap/tests/unit && PROXYSQL31=1 make pgsql_response_framer_unit-t ffto_state_machine_unit-t && ./pgsql_response_framer_unit-t && ./ffto_state_machine_unit-t
```

- [ ] **Step 3: Commit**

```bash
git add include/PgSQLFFTO.hpp lib/PgSQLFFTO.cpp
git commit -m "feat(ffto): wire PgSQLFFTO to PgSQLResponseFramer (behavior-preserving)"
```

---

### Task 8: TAP tests — MySQL deprecate_eof / multi-result / FETCH

**Files:**
- Create: `test/tap/tests/test_ffto_mysql_deprecate_eof-t.cpp`
- Create: `test/tap/tests/test_ffto_mysql_multi_result-t.cpp`
- Create: `test/tap/tests/test_ffto_mysql_stmt_fetch-t.cpp`
- Modify: `test/tap/groups/groups.json` — add tests to the same group(s) as `test_ffto_mysql-t` (search existing entry)

- [ ] **Step 1: deprecate_eof TAP**

Mirror setup from `test_ffto_mysql-t.cpp` + `ffto_mysql_helpers.h`.

For each of `enable_client_deprecate_eof=0` and `=1` (and matching server flag if required for FF):

1. Enable FFTO + fast_forward  
2. Reset digests  
3. `CREATE TABLE` / `INSERT` / `SELECT id FROM ...` expecting N rows  
4. `verify_digest` for SELECT with `expected_rows_sent=N`

Use admin:

```sql
SET mysql-enable_client_deprecate_eof='true'|'false';
SET mysql-enable_server_deprecate_eof='true'|'false';
LOAD MYSQL VARIABLES TO RUNTIME;
```

Reconnect client after variable change so handshake picks up capabilities.

- [ ] **Step 2: multi-result TAP**

Connect with `CLIENT_MULTI_STATEMENTS` (mysql_real_connect flag). Run:

```sql
SELECT 1; SELECT 2,3;
```

Drain all results with `mysql_next_result`. Expect one digest for the multi query text (or normalized form) with cumulative `sum_rows_sent` reflecting both sets (1+1=2 rows if two single-row selects — assert actual ProxySQL digest normalization).

- [ ] **Step 3: FETCH TAP**

Use prepared statement with cursor if the client library supports it (`CURSOR_TYPE_READ_ONLY` via `mysql_stmt_attr_set`), then `mysql_stmt_execute` + loop `mysql_stmt_fetch`. If the environment’s libmysqlclient cannot open server-side cursors through ProxySQL FF, use raw packet test via existing helpers or document skip with `skip()` and still unit-test FETCH client command path with a minimal integration that sends COM_STMT_FETCH after prepare/execute with cursor — prefer real stmt API first.

Assert digest text matches prepared SQL and `count_star >= 1`.

- [ ] **Step 4: Register in groups.json**

Find the group containing `test_ffto_mysql-t` and append the three new basenames.

- [ ] **Step 5: Run isolated TAP (DEBUG binary)**

```bash
PROXYSQL31=1 make -j$(nproc) debug
PROXYSQL31=1 make build_tap_test_debug
# determine TAP_GROUP from groups.json for the new tests
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=<group> \
  TEST_PY_TAP_INCL='ffto_mysql_deprecate_eof|ffto_mysql_multi_result|ffto_mysql_stmt_fetch' \
  test/infra/control/run-tests-isolated.bash
```

Expected: all three pass.

- [ ] **Step 6: Commit**

```bash
git add test/tap/tests/test_ffto_mysql_deprecate_eof-t.cpp \
  test/tap/tests/test_ffto_mysql_multi_result-t.cpp \
  test/tap/tests/test_ffto_mysql_stmt_fetch-t.cpp \
  test/tap/groups/groups.json
git commit -m "test(ffto): TAP coverage for deprecate_eof, multi-result, COM_STMT_FETCH"
```

---

### Task 9: Regression — existing FFTO TAP + final check

- [ ] **Step 1: Run broader FFTO filters**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=<mysql-ffto-group> \
  TEST_PY_TAP_INCL='ffto_mysql' \
  test/infra/control/run-tests-isolated.bash

WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=<pgsql-ffto-group> \
  TEST_PY_TAP_INCL='ffto_pgsql' \
  test/infra/control/run-tests-isolated.bash
```

- [ ] **Step 2: Unit suite subset**

```bash
cd test/tap/tests/unit
PROXYSQL31=1 make -j$(nproc) \
  mysql_resultset_framer_unit-t pgsql_response_framer_unit-t \
  ffto_protocol_unit-t ffto_state_machine_unit-t pgsql_command_complete_unit-t
./mysql_resultset_framer_unit-t
./pgsql_response_framer_unit-t
./ffto_protocol_unit-t
./ffto_state_machine_unit-t
./pgsql_command_complete_unit-t
```

- [ ] **Step 3: Spec success criteria checklist**

- [ ] deprecate_eof on/off SELECT digests correct  
- [ ] multi-result does not stick observer; cumulative metrics  
- [ ] COM_STMT_FETCH digests  
- [ ] Pg TAP green  
- [ ] No capability stripping  

- [ ] **Step 4: Final commit only if cleanup/docs needed**

```bash
git status
# optional: short note in CHANGELOG if project requires it for the feature PR
```

---

## Spec coverage (self-review)

| Spec requirement | Task |
|------------------|------|
| MySQLResultsetFramer pure API | 2–4 |
| CLIENT_DEPRECATE_EOF framing | 3, 8 |
| Multi-result MORE_RESULTS | 4, 5, 8 |
| COM_STMT_FETCH | 5, 8 |
| OK/EOF helpers | 1 |
| PgSQLResponseFramer extract | 6–7 |
| Unit tests both framers | 2–4, 6 |
| TAP MySQL gaps | 8 |
| Pg behavior preserved | 7, 9 |
| Makefile PROXYSQLFFTO objects | 2, 6 |
| No capability changes / no UI | throughout |

## Type/name consistency

- `MySQLRSEventKind`, `MySQLRSEvent`, `MySQLResultsetFramer`
- `PgSQLRSEventKind`, `PgSQLRSEvent`, `PgSQLResponseFramer`
- Helpers: `mysql_is_eof_payload`, `mysql_parse_ok_payload`, `mysql_parse_eof_payload`, `MySQLOkFields`
- Flag constant: `SERVER_MORE_RESULTS_EXIST` (value 8) or local `kServerMoreResultsExist`
