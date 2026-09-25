# MariaDB GTID Causal Reads Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ProxySQL causal reads accept MariaDB `domain-server-seq` as well as MySQL `uuid:seq`, matching on domain sequence watermarks.

**Architecture:** Auto-detect per string. Reuse `GTID_Set` with MariaDB key = decimal `domain_id`. Snapshot/OK-packet MariaDB positions insert `[1, seq]`. Wire `ST=`/`I1=` already works if the id has no dashes (`I1=0:271`); `to_string()` must not UUID-dash short keys. Write GTID collection keeps `SESSION_TRACK_GTIDS` and, on MariaDB, `gtid_binlog_pos` via `session_track_system_variables`.

**Tech Stack:** C++17, existing TAP unit harness (`test/tap/tests/unit`), `libproxysql.a`.

**Worktree:** `/data/rene/proxysql2/proxysql/.worktrees/mariadb-gtid-causal-reads` (branch `feature/mariadb-gtid-causal-reads`).

**Spec:** `docs/superpowers/specs/2026-09-23-mariadb-gtid-causal-reads-design.md`

**Build:** `PROXYSQL31=1 make debug` / unit tests via `make -C test/tap/tests/unit gtid_parse_unit-t gtid_set_unit-t gtid_server_data_unit-t` after `PROXYSQL31=1 make build_lib`. Do not symlink artifacts from other worktrees.

---

## File map

- Modify: `include/proxysql_gtid.h`, `lib/proxysql_gtid.cpp` — `ParsedGTID`, `parse_gtid`, `parse_gtid_set`, display string, `last_server_id`
- Create: `test/tap/tests/unit/gtid_parse_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile` — append `gtid_parse_unit-t`
- Modify: `test/tap/tests/unit/gtid_set_unit-t.cpp` — domain `to_string`
- Modify: `lib/GTID_Server_Data.cpp` — `add_gtid_from_ok` MariaDB; ST= numeric ids
- Modify: `test/tap/tests/unit/gtid_server_data_unit-t.cpp`
- Modify: `lib/MySQL_Query_Processor.cpp` — `_is_valid_gtid`
- Modify: `lib/MySQL_Session.cpp` — routing parse
- Modify: `lib/mysql_connection.cpp` — `get_gtid` MariaDB fallback
- Modify: `lib/MySQL_Session.cpp` — MariaDB session_track_system_variables

---

### Task 1: `parse_gtid` / `parse_gtid_set`

**Files:**
- Create: `test/tap/tests/unit/gtid_parse_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile` (`UNIT_TESTS` list near `gtid_set_unit-t`)
- Modify: `include/proxysql_gtid.h`
- Modify: `lib/proxysql_gtid.cpp`

- [ ] **Step 1: Write the failing test**

`test/tap/tests/unit/gtid_parse_unit-t.cpp`:

```cpp
#include "tap.h"
#include "proxysql_gtid.h"

int main() {
	plan(14);
	ParsedGTID p;

	ok(parse_gtid("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:42", &p)
	       && p.id == "aaaaaaaa000011112222aaaaaaaaaaaa" && p.trxid == 42
	       && p.server_id == 0 && !p.mariadb,
	   "MySQL dashed UUID");
	ok(parse_gtid("aaaaaaaa000011112222aaaaaaaaaaaa:42", &p) && !p.mariadb
	       && p.trxid == 42,
	   "MySQL dash-free UUID");
	ok(parse_gtid("0-1-100", &p) && p.mariadb && p.id == "0"
	       && p.trxid == 100 && p.server_id == 1,
	   "MariaDB domain-server-seq");
	ok(!parse_gtid("0-1", &p), "reject two-field");
	ok(!parse_gtid("0-1-0", &p), "reject seq 0");
	ok(!parse_gtid("00-1-1", &p), "reject leading zeros");
	ok(!parse_gtid("not-a-gtid", &p), "reject junk");
	ok(!parse_gtid(nullptr, &p), "reject null");

	GTID_Set set;
	ok(parse_gtid_set("0-1-270,1-2-50", &set)
	       && set.has_gtid("0", 100) && set.has_gtid("0", 270)
	       && !set.has_gtid("0", 271) && set.has_gtid("1", 50),
	   "MariaDB set is per-domain watermark [1, seq]");
	ok(parse_gtid_set("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:1-3:5", &set)
	       && set.has_gtid("aaaaaaaa000011112222aaaaaaaaaaaa", 3)
	       && !set.has_gtid("aaaaaaaa000011112222aaaaaaaaaaaa", 4)
	       && set.has_gtid("aaaaaaaa000011112222aaaaaaaaaaaa", 5),
	   "MySQL set keeps sparse intervals");
	ok(!parse_gtid_set("0-1-270,aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:1", &set),
	   "reject mixed flavors in one set");
	ok(!parse_gtid_set("", &set), "reject empty");
	ok(parse_gtid(" 0-1-100 ", &p) == false || p.trxid == 100,
	   "whitespace: either reject or trim; pick reject");
	ok(!parse_gtid("0-1-100", nullptr), "reject null out");
	return exit_status();
}
```

Pick **reject** for surrounding whitespace (no silent trim on single GTIDs). Sets may trim comma-separator whitespace like the reader.

Append `gtid_parse_unit-t` next to `gtid_set_unit-t` in `UNIT_TESTS`.

- [ ] **Step 2: Run to verify fail**

```bash
PROXYSQL31=1 make -C test/tap/tests/unit gtid_parse_unit-t
./test/tap/tests/unit/gtid_parse_unit-t
```

Expected: compile error (`ParsedGTID` / `parse_gtid` undeclared).

- [ ] **Step 3: Implement**

`include/proxysql_gtid.h`:

```cpp
struct ParsedGTID {
	std::string id;
	trxid_t trxid;
	uint32_t server_id;
	bool mariadb;
};

bool parse_gtid(const char* s, ParsedGTID* out);
bool parse_gtid_set(const char* encoded, GTID_Set* out);
```

`lib/proxysql_gtid.cpp`:

- `parse_gtid`: null checks. If `strchr(s, ':')`: MySQL — split on last `:`, strip dashes from UUID, require 32 hex, `strtoull` seq `> 0`, no trailing junk. Else MariaDB — scan `domain-server-seq` with `strtoul`/`strtoull`, no leading zeros, exactly two dashes, seq `> 0`, end of string.
- `parse_gtid_set`: if any token contains `:`, every token must be MySQL (existing interval grammar). If none contain `:`, every token is MariaDB; `add(id, 1, seq)` and `set_server_id`. Mixed → false.

- [ ] **Step 4: Run — PASS (14 assertions)**

- [ ] **Step 5: Commit**

```bash
git add include/proxysql_gtid.h lib/proxysql_gtid.cpp \
  test/tap/tests/unit/gtid_parse_unit-t.cpp test/tap/tests/unit/Makefile
git commit -m "feat: parse MySQL and MariaDB GTID strings"
```

---

### Task 2: Domain-key `to_string` / display / `last_server_id`

**Files:**
- Modify: `include/proxysql_gtid.h`, `lib/proxysql_gtid.cpp`
- Modify: `test/tap/tests/unit/gtid_set_unit-t.cpp`

`stats_mysql_gtid_executed` uses `to_string()`. Reader wire also uses `to_string()`. UUID dash-insert at index 8 throws for key `"0"`.

- `to_string()` = wire: 32-hex → dashed UUID + `:` intervals; domain → `0:1-270`
- `to_display_string()` = domain → `0-1-270` (last_server_id or 0); 32-hex unchanged from `to_string()`

`gtid_executed_to_string()` in `GTID_Server_Data` will switch to `to_display_string()` in Task 3.

- [ ] **Step 1: Failing tests in `gtid_set_unit-t.cpp`**

Add `test_mariadb_domain_keys()` and raise `plan()`:

```cpp
static void test_mariadb_domain_keys() {
	GTID_Set gs;
	gs.add("0", trxid_t(1), trxid_t(270));
	gs.set_server_id("0", 1);
	ok(gs.has_gtid("0", 100), "domain watermark contains 100");
	ok(!gs.has_gtid("0", 271), "domain watermark excludes 271");
	ok(gs.to_string() == "0:1-270", "wire string is domain:1-seq");
	ok(gs.to_display_string() == "0-1-270", "display is native MariaDB");
	GTID_Set cp = gs.copy();
	ok(cp.get_server_id("0") == 1, "copy preserves server_id");
	gs.clear();
	ok(gs.to_string().empty() && gs.get_server_id("0") == 0, "clear drops server_id");
}
```

Existing `test_to_string` must still pass.

- [ ] **Step 2: Run `gtid_set_unit-t` — FAIL / compile error**

- [ ] **Step 3: Implement**

On `GTID_Set`: `last_server_id` map, `set_server_id`, `get_server_id` (0 if missing), `to_display_string`. Guard `to_string()` dash inserts with `uuid.size()==32`. `copy`/`clear` include `last_server_id`.

- [ ] **Step 4: Run `gtid_set_unit-t` and `gtid_parse_unit-t` — PASS**

- [ ] **Step 5: Commit**

```bash
git add include/proxysql_gtid.h lib/proxysql_gtid.cpp \
  test/tap/tests/unit/gtid_set_unit-t.cpp
git commit -m "feat: serialize MariaDB GTID domain keys"
```

---

### Task 3: `add_gtid_from_ok` + wire ST=/I1= domain ids

**Files:**
- Modify: `lib/GTID_Server_Data.cpp`
- Modify: `include/GTID_Server_Data.h` (only if `gtid_executed_to_string` comment)
- Modify: `test/tap/tests/unit/gtid_server_data_unit-t.cpp`

- [ ] **Step 1: Failing tests**

Raise `plan()`. Add:

```cpp
static void test_ok_mariadb_gtid() {
	GTID_Server_Data sd(nullptr, LOOPBACK_ADDRESS, 0, 3306);
	ok(sd.add_gtid_from_ok("0-1-100"), "OK MariaDB GTID accepted");
	char domain[] = "0";
	ok(sd.gtid_exists(domain, 1) && sd.gtid_exists(domain, 100)
	       && !sd.gtid_exists(domain, 101),
	   "OK MariaDB GTID is watermark [1, seq]");
	ok(sd.gtid_executed_to_string() == "0-1-100",
	   "stats display is native MariaDB");
	ok(!sd.add_gtid_from_ok("0-1-50"),
	   "lower watermark is not an update");
	ok(sd.add_gtid_from_ok("0-2-105"), "failover server_id still updates seq");
	ok(sd.gtid_exists(domain, 105), "domain match ignores server_id");
}

static void test_wire_mariadb_domain() {
	GTID_Server_Data sd(nullptr, LOOPBACK_ADDRESS, 0, 3306);
	stuff_buffer(sd, std::string("ST=0:1-270\n"));
	ok(sd.read_next_gtid() == true && sd.active == true, "ST= domain bootstrap");
	char domain[] = "0";
	ok(sd.gtid_exists(domain, 100), "ST=0:1-270 contains 100");
	stuff_buffer(sd, std::string("I1=0:271\n"));
	ok(sd.read_next_gtid() == true, "I1= domain");
	ok(sd.gtid_exists(domain, 271), "I1=0:271 appended");
}
```

Call them from `main`.

- [ ] **Step 2: Run `gtid_server_data_unit-t` — FAIL** (`add_gtid_from_ok` requires `:`)

- [ ] **Step 3: Implement**

Replace `add_gtid_from_ok` body with `parse_gtid`. If MariaDB: `gtid_executed.add(id, 1, trxid)` then `set_server_id`. If MySQL: keep current `add(uuid, seq)` (single point, not `[1, seq]`).

`gtid_executed_to_string` / snapshot text: use `to_display_string()`.

`read_next_gtid` ST= dash-stripping: if the uuid token is all digits, copy as-is (no dash strip). `I1=0:271` already copies as-is.

- [ ] **Step 4: Run — PASS, existing 109 MySQL assertions still pass**

- [ ] **Step 5: Commit**

```bash
git add lib/GTID_Server_Data.cpp test/tap/tests/unit/gtid_server_data_unit-t.cpp
git commit -m "feat: ingest MariaDB GTIDs from OK packets and wire protocol"
```

---

### Task 4: `_is_valid_gtid` + session routing parse

**Files:**
- Modify: `lib/MySQL_Query_Processor.cpp`
- Modify: `lib/MySQL_Session.cpp`
- Modify: `test/tap/tests/unit/gtid_parse_unit-t.cpp` (routing helper)

Extract the session block at `MySQL_Session.cpp` ~9090 into:

```cpp
bool parse_gtid_for_routing(const char* gtid, char* id_buf, size_t id_buf_len,
                            uint64_t* trxid);
```

in `proxysql_gtid.cpp` (wraps `parse_gtid`, copies `id` into `id_buf`).

- [ ] **Step 1: Failing tests**

```cpp
	char id[64];
	uint64_t trx = 0;
	ok(parse_gtid_for_routing("0-1-100", id, sizeof(id), &trx)
	       && std::string(id) == "0" && trx == 100,
	   "routing parse MariaDB");
	ok(parse_gtid_for_routing("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:9",
	                          id, sizeof(id), &trx)
	       && std::string(id) == "aaaaaaaa000011112222aaaaaaaaaaaa" && trx == 9,
	   "routing parse MySQL");
	ok(!parse_gtid_for_routing("nope", id, sizeof(id), &trx), "routing reject");
```

- [ ] **Step 2: Run — FAIL**

- [ ] **Step 3: Implement**

`_is_valid_gtid`:

```cpp
bool MySQL_Query_Processor::_is_valid_gtid(const char* gtid, size_t) {
	ParsedGTID parsed;
	return parse_gtid(gtid, &parsed);
}
```

Session checkout: replace colon-split / dash-strip with `parse_gtid_for_routing(gtid_uuid, uuid, sizeof(uuid), &trxid)`. On failure set `gtid_uuid = NULL` (same as invalid today).

- [ ] **Step 4: Run `gtid_parse_unit-t` — PASS**

- [ ] **Step 5: Commit**

```bash
git add include/proxysql_gtid.h lib/proxysql_gtid.cpp \
  lib/MySQL_Query_Processor.cpp lib/MySQL_Session.cpp \
  test/tap/tests/unit/gtid_parse_unit-t.cpp
git commit -m "feat: accept MariaDB min_gtid in query routing"
```

---

### Task 5: Collect MariaDB write GTIDs from OK packets

**Files:**
- Modify: `lib/mysql_connection.cpp` (`get_gtid`)
- Modify: `lib/MySQL_Session.cpp` (`handler_again___verify_backend_session_track_gtids`)

MariaDB has no `SESSION_TRACK_GTIDS`. Track `gtid_binlog_pos` in `session_track_system_variables`.

Detect MariaDB: `mysql->server_version` contains `"MariaDB"`.

- [ ] **Step 1: Unit-test `select_session_gtid` in `proxysql_gtid.cpp`**

```cpp
bool select_session_gtid(
	const char* session_track_gtids, size_t gtids_len,
	const std::unordered_map<std::string, std::string>& sysvars,
	char* buf, size_t buf_len);
```

Tests in `gtid_parse_unit-t.cpp`:

- MySQL payload `"uuid:42"` is copied into `buf` and returns true.
- Empty GTIDS + sysvar `gtid_binlog_pos=0-1-100` copies that string.
- Prefer `gtid_binlog_pos` over `gtid_current_pos` if both exist.
- Return false when the selected string equals the current `buf` contents.

`get_gtid` calls this helper after reading `SESSION_TRACK_GTIDS` and/or system variables.

- [ ] **Step 2: Run — FAIL**

- [ ] **Step 3: Implement**

`get_gtid`: keep `SESSION_TRACK_GTIDS` first. If that fails, iterate `SESSION_TRACK_SYSTEM_VARIABLES` like `get_variables()` and look for `gtid_binlog_pos` then `gtid_current_pos`. Copy native string into `gtid_uuid` / `buff`. Leave `*trx_id` unused as today (caller parses later).

`handler_again___verify_backend_session_track_gtids`: if backend `server_version` contains `MariaDB`, do not `SET SESSION_TRACK_GTIDS=OWN_GTID`. Instead, if client/default wants GTIDs, set status to set

`session_track_system_variables` to include `gtid_binlog_pos`.

Reuse `handler_again___status_SETTING_GENERIC_VARIABLE` with name `session_track_system_variables`. If the connection already has a non-empty list, append `,gtid_binlog_pos` when missing. If MariaDB rejects `SESSION_TRACK_GTIDS`, never send it.

Keep MySQL path unchanged.

- [ ] **Step 4: Rebuild lib; run all three GTID unit binaries — PASS**

Existing `test_gtid_from_ok-t` / `test_gtid_forwarding-t` are MySQL TAP; do not change them. After implementation they must still pass when TAP infra is available.

- [ ] **Step 5: Commit**

```bash
git add include/proxysql_gtid.h lib/proxysql_gtid.cpp \
  lib/mysql_connection.cpp lib/MySQL_Session.cpp \
  test/tap/tests/unit/gtid_parse_unit-t.cpp
git commit -m "feat: collect MariaDB gtid_binlog_pos from OK packets"
```

---

### Task 6: MariaDB TAP for min_gtid (only if `mariadb10-galera` can run it)

**Files:**
- Create: `test/tap/tests/test_mariadb_min_gtid-t.cpp` only if session tracking exposes `gtid_binlog_pos` on that infra
- Modify: `test/tap/groups/groups.json` — register on `mariadb10-galera-g1` (or the group that has a writer)

This task is skipped if a probe `SELECT @@session_track_system_variables` / enabling `gtid_binlog_pos` fails on that image. Do not invent a MariaDB-binlog TAP group.

Probe first:

```sql
SET SESSION session_track_system_variables = 'gtid_binlog_pos';
INSERT INTO test.t VALUES (1);
```

If the OK packet has no tracked GTID, skip this task and rely on unit tests. Note the skip in the commit message of Task 5; do not leave a failing TAP.

If the probe works, clone `test_gtid_from_ok-t.cpp` structure:

1. Write through ProxySQL.
2. Read `min_gtid=0-1-<seq>` against a reader hostgroup.
3. Assert the read succeeds when the writer GTID is in the same domain watermark.

- [ ] **Step 1: Probe or skip**
- [ ] **Step 2: If probe works, TDD the TAP then implement nothing extra (code already in Tasks 4–5)**
- [ ] **Step 3: Commit TAP only if it passes**

```bash
git add test/tap/tests/test_mariadb_min_gtid-t.cpp test/tap/groups/groups.json
git commit -m "test: MariaDB min_gtid causal read TAP"
```

---

### Task 7: Verification

- [ ] `PROXYSQL31=1 make -C test/tap/tests/unit gtid_parse_unit-t gtid_set_unit-t gtid_server_data_unit-t`
- [ ] Run the three binaries — all PASS
- [ ] `PROXYSQL31=1 make build_lib` — compiles
- [ ] Existing MySQL GTID unit counts remain green (`gtid_set_unit-t` original cases, `gtid_server_data_unit-t` original cases)

Do not claim TAP integration pass without running `run-tests-isolated.bash`.

---

## Spec coverage

| Spec item | Task |
| --- | --- |
| Auto-detect formats | 1 |
| Domain-keyed compare / watermark | 1, 3 |
| `to_string` no UUID dashes on domain keys | 2 |
| Display `domain-server-seq` | 2, 3 |
| `add_gtid_from_ok` MariaDB | 3 |
| Wire `ST=0:1-270` / `I1=0:271` | 3 |
| `_is_valid_gtid` / `min_gtid` | 4 |
| Session routing parse | 4 |
| `SESSION_TRACK_GTIDS` + `gtid_binlog_pos` | 5 |
| Mixed flavors on one endpoint rejected | 1 |
| No new MariaDB-binlog TAP group | 6 |
| MySQL causal-read tests unchanged | 7 |
