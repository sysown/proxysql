# Cluster Leader Election Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deterministic, ballot-free leader election for ProxySQL Cluster (liveness + election + read-only config steering), per spec `docs/superpowers/specs/2026-08-11-cluster-leader-election-design.md`.

**Architecture:** Pure election logic lives in new files (`ProxySQL_Cluster_Leader.{h,cpp}`); liveness is bookkeeping on the existing per-peer `GLOBAL_CHECKSUM()` poll loop; peer UUIDs are learned via a new `SELECT GLOBAL_UUID()` admin intercept; an election tick in the Admin main loop drives a tri-state read-only mode (`AUTO`/`FORCED_RO`/`FORCED_RW`) that gates admin SQL writes plus `LOAD … TO RUNTIME`/`SAVE … TO DISK`.

**Tech Stack:** C++17, pthreads, GCC atomic builtins (`__sync_*`) matching surrounding code, SQLite3 (admin), libmariadb (cluster transport), prometheus-cpp, TAP tests.

## Global Constraints

- Build with the tier flag on EVERY make invocation: `PROXYSQL31=1 make debug` (never bare `make`; `make clean` first if the tree was built under a different tier). See CLAUDE.md.
- All election/tri-state code compiles **unconditionally in every tier**. The ONLY `#ifdef PROXYSQL31` allowed is around the registration of the `admin-cluster_leader_election` variable (name list, get_variable, set_variable). No other new `#ifdef`s.
- The feature must be a no-op when `admin-cluster_leader_election=false` (the default): bit-for-bit today's behavior.
- Cluster-initiated syncs (direct C++ calls `GloAdmin->load_*_to_runtime()` from `lib/ProxySQL_Cluster.cpp`) must NEVER be blocked by read-only mode.
- Naming: classes `PascalCase` with `ProxySQL_`/`Cluster_` prefixes, members `snake_case`, macros `UPPER_SNAKE_CASE`. Tabs for indentation (match surrounding code).
- New admin variables and defaults (exact values from spec): `admin-cluster_leader_election` = `false`; `admin-cluster_leader_node_timeout_ms` = `3000` (range 1000–600000); `admin-cluster_leader_grace_ms` = `3000` (range 0–600000).
- Election rule (exact): among candidates that are `alive` **and** have a known (non-empty) UUID, highest `weight` wins; ties broken by lexicographically smallest UUID; no electable candidate → no leader.
- Commit after every task. Branch: `feat/cluster-leader-election` (already exists, spec committed there).

---

### Task 1: Pure election engine + unit test

**Files:**
- Create: `include/ProxySQL_Cluster_Leader.h`
- Create: `lib/ProxySQL_Cluster_Leader.cpp`
- Modify: `lib/Makefile:91` (add `ProxySQL_Cluster_Leader.oo` to `_OBJ_CXX`)
- Create: `test/tap/tests/unit/cluster_leader_election_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile:387+` (add to `UNIT_TESTS`)
- Modify: `test/tap/groups/groups.json` (register unit test in `unit-tests-g1`)

**Interfaces:**
- Consumes: nothing (pure logic, standalone header).
- Produces (used by Tasks 2, 4, 6):
  - `struct Cluster_Leader_Candidate { std::string uuid; std::string hostname; uint16_t port; uint64_t weight; bool alive; }`
  - `int cluster_elect_leader(const std::vector<Cluster_Leader_Candidate>& candidates)` → index into `candidates`, or `-1`
  - `class Cluster_Leader_State` with `bool update(const std::string& computed_uuid, unsigned long long now_ms, unsigned long long grace_ms)` (returns true when effective leader changed), `void reset()`, public members `current_leader_uuid`, `pending_leader_uuid`, `pending_since_ms`.

- [ ] **Step 1: Write the failing unit test**

Create `test/tap/tests/unit/cluster_leader_election_unit-t.cpp` (pure-logic test, no `test_init_minimal()`, same style as `cluster_sync_unit-t.cpp`):

```cpp
/**
 * @file cluster_leader_election_unit-t.cpp
 * @brief Unit tests for the pure cluster leader election logic
 *  (cluster_elect_leader + Cluster_Leader_State grace-window machine).
 */

#include <string>
#include <vector>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_Cluster_Leader.h"

static Cluster_Leader_Candidate mk(const char* uuid, uint64_t weight, bool alive) {
	Cluster_Leader_Candidate c;
	c.uuid = uuid;
	c.hostname = "host";
	c.port = 6032;
	c.weight = weight;
	c.alive = alive;
	return c;
}

// 7 oks
static void test_elect_leader() {
	std::vector<Cluster_Leader_Candidate> v;
	ok(cluster_elect_leader(v) == -1, "empty candidate set elects nobody");

	v = { mk("aaa", 0, false), mk("bbb", 0, false) };
	ok(cluster_elect_leader(v) == -1, "no alive candidate elects nobody");

	v = { mk("aaa", 0, true) };
	ok(cluster_elect_leader(v) == 0, "single alive candidate is leader");

	v = { mk("aaa", 100, true), mk("bbb", 300, true), mk("ccc", 200, true) };
	ok(cluster_elect_leader(v) == 1, "highest weight wins");

	v = { mk("ccc", 100, true), mk("aaa", 100, true), mk("bbb", 100, true) };
	ok(cluster_elect_leader(v) == 1, "equal weight: lexicographically smallest uuid wins");

	v = { mk("aaa", 300, false), mk("bbb", 100, true) };
	ok(cluster_elect_leader(v) == 1, "dead high-weight candidate is skipped");

	v = { mk("", 300, true), mk("bbb", 100, true) };
	ok(cluster_elect_leader(v) == 1, "candidate with unknown uuid is not electable");
}

// 10 oks
static void test_grace_state() {
	Cluster_Leader_State s;
	ok(s.current_leader_uuid.empty(), "initial state has no leader");

	// First observation enters pending, no change yet (grace 1000ms)
	ok(s.update("aaa", 1000, 1000) == false, "new leader is pending, not applied");
	ok(s.current_leader_uuid.empty(), "leader unchanged during grace");

	// Still pending, grace not elapsed
	ok(s.update("aaa", 1500, 1000) == false, "grace not elapsed yet");

	// Grace elapsed -> applied
	ok(s.update("aaa", 2100, 1000) == true, "leader applied after grace");
	ok(s.current_leader_uuid == "aaa", "current leader is aaa");

	// Stable: no change
	ok(s.update("aaa", 3000, 1000) == false, "stable leader: no change");

	// Flap within grace: bbb appears then aaa returns before grace elapses
	s.update("bbb", 4000, 1000);
	ok(s.update("aaa", 4500, 1000) == false && s.current_leader_uuid == "aaa",
		"flap within grace window is ignored");

	// Loss of leader ("" computed) also honors grace
	s.update("", 5000, 1000);
	ok(s.update("", 6100, 1000) == true && s.current_leader_uuid.empty(),
		"leader loss applied after grace");

	// grace_ms == 0 applies on the same update
	Cluster_Leader_State z;
	ok(z.update("ccc", 100, 0) == true && z.current_leader_uuid == "ccc",
		"zero grace applies immediately");
}

// 2 oks
static void test_reset() {
	Cluster_Leader_State s;
	s.update("aaa", 100, 0);
	s.update("bbb", 200, 5000);
	s.reset();
	ok(s.current_leader_uuid.empty() && s.pending_leader_uuid.empty() && s.pending_since_ms == 0,
		"reset clears all state");
	ok(s.update("aaa", 300, 0) == true, "state machine works again after reset");
}

int main() {
	plan(19);
	test_elect_leader();   // 7
	test_grace_state();    // 10
	test_reset();          // 2
	return exit_status();
}
```

- [ ] **Step 2: Create the header and a stub, verify test FAILS**

Create `include/ProxySQL_Cluster_Leader.h`:

```cpp
#ifndef __CLASS_PROXYSQL_CLUSTER_LEADER_H
#define __CLASS_PROXYSQL_CLUSTER_LEADER_H

#include <cstdint>
#include <string>
#include <vector>

struct Cluster_Leader_Candidate {
	std::string uuid;      // empty = unknown (not electable)
	std::string hostname;
	uint16_t port = 0;
	uint64_t weight = 0;
	bool alive = false;
};

// Deterministic, ballot-free election over a locally-observed candidate set.
// Electable = alive && uuid non-empty. Highest weight wins; ties broken by
// lexicographically smallest uuid. Returns index into candidates, or -1.
int cluster_elect_leader(const std::vector<Cluster_Leader_Candidate>& candidates);

// Grace-window state machine: a computed leader (or leader loss, "") must be
// observed continuously for grace_ms before it becomes effective.
class Cluster_Leader_State {
	public:
	std::string current_leader_uuid;   // empty = no leader
	std::string pending_leader_uuid;
	unsigned long long pending_since_ms = 0;
	// Returns true when the effective leader changed.
	bool update(const std::string& computed_uuid, unsigned long long now_ms, unsigned long long grace_ms);
	void reset();
};

#endif // __CLASS_PROXYSQL_CLUSTER_LEADER_H
```

Create `lib/ProxySQL_Cluster_Leader.cpp` as a failing stub:

```cpp
#include "ProxySQL_Cluster_Leader.h"

int cluster_elect_leader(const std::vector<Cluster_Leader_Candidate>& candidates) {
	(void)candidates;
	return -1;
}

bool Cluster_Leader_State::update(const std::string& computed_uuid, unsigned long long now_ms, unsigned long long grace_ms) {
	(void)computed_uuid; (void)now_ms; (void)grace_ms;
	return false;
}

void Cluster_Leader_State::reset() {
}
```

Edit `lib/Makefile:91`: in the `_OBJ_CXX :=` list, insert `ProxySQL_Cluster_Leader.oo` immediately after `ProxySQL_Cluster.oo`.

Edit `test/tap/tests/unit/Makefile`: add `cluster_leader_election_unit-t` to the `UNIT_TESTS :=` list (starts at line 387; keep alphabetical-ish placement near `cluster_sync_unit-t`). The generic `%-t:` pattern rule (line 862) handles the build — no explicit rule needed.

Run:
```bash
cd /data/rene/proxysql7/proxysql && PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -5
cd test/tap/tests/unit && PROXYSQL31=1 make cluster_leader_election_unit-t && ./cluster_leader_election_unit-t
```
Expected: builds, test runs, multiple `not ok` lines (stub returns -1/false). If the build fails on the new files, fix before proceeding.

- [ ] **Step 3: Implement the real logic**

Replace `lib/ProxySQL_Cluster_Leader.cpp` body:

```cpp
#include "ProxySQL_Cluster_Leader.h"

int cluster_elect_leader(const std::vector<Cluster_Leader_Candidate>& candidates) {
	int best = -1;
	for (size_t i = 0; i < candidates.size(); i++) {
		const Cluster_Leader_Candidate& c = candidates[i];
		if (c.alive == false || c.uuid.empty()) {
			continue;
		}
		if (best == -1) {
			best = (int)i;
			continue;
		}
		const Cluster_Leader_Candidate& b = candidates[best];
		if (c.weight > b.weight || (c.weight == b.weight && c.uuid < b.uuid)) {
			best = (int)i;
		}
	}
	return best;
}

bool Cluster_Leader_State::update(const std::string& computed_uuid, unsigned long long now_ms, unsigned long long grace_ms) {
	if (computed_uuid == current_leader_uuid) {
		pending_leader_uuid.clear();
		pending_since_ms = 0;
		return false;
	}
	if (pending_since_ms == 0 || pending_leader_uuid != computed_uuid) {
		pending_leader_uuid = computed_uuid;
		pending_since_ms = now_ms;
	}
	if (now_ms - pending_since_ms >= grace_ms) {
		current_leader_uuid = pending_leader_uuid;
		pending_leader_uuid.clear();
		pending_since_ms = 0;
		return true;
	}
	return false;
}

void Cluster_Leader_State::reset() {
	current_leader_uuid.clear();
	pending_leader_uuid.clear();
	pending_since_ms = 0;
}
```

Note on the grace semantics the test encodes: a *brand new* pending observation at time T becomes effective at the first `update()` call with `now_ms >= T + grace_ms`; with `grace_ms == 0` it is effective on the same call. `pending_since_ms == 0` is the "no pending" sentinel — `update()` is never called with a real `now_ms` of 0 in production (monotonic µs / 1000), and the unit test uses now_ms ≥ 100 everywhere.

- [ ] **Step 4: Run the unit test — expect PASS**

```bash
cd test/tap/tests/unit && PROXYSQL31=1 make cluster_leader_election_unit-t && ./cluster_leader_election_unit-t
```
Expected: `1..19`, all `ok`, exit 0.

- [ ] **Step 5: Register in groups.json and commit**

In `test/tap/groups/groups.json` add (one line, compact array, keep alphabetical order with neighbors — same format as `"cluster_sync_unit-t"`):
```json
"cluster_leader_election_unit-t" : [ "unit-tests-g1" ],
```

```bash
python3 test/tap/groups/lint_groups_json.py
git add include/ProxySQL_Cluster_Leader.h lib/ProxySQL_Cluster_Leader.cpp lib/Makefile \
  test/tap/tests/unit/cluster_leader_election_unit-t.cpp test/tap/tests/unit/Makefile \
  test/tap/groups/groups.json
git commit -m "feat(cluster): pure leader election engine with grace-window state machine"
```

---

### Task 2: Liveness bookkeeping + peer UUID exchange

**Files:**
- Modify: `include/ProxySQL_Cluster.hpp` (node entry fields ~:270-280, accessors ~:286-311; `ProxySQL_Cluster_Nodes` methods ~:403-414; `ProxySQL_Cluster` forwarders ~:667-672)
- Modify: `lib/ProxySQL_Cluster.cpp` (ctor ~:400-480 region where entry members init; `Update_Global_Checksum` :4051-4073; monitor thread :236-244 and failure branch :331-342; new methods near :4088)
- Modify: `lib/Admin_Handler.cpp` (new `SELECT GLOBAL_UUID()` intercept after :3795)

**Interfaces:**
- Consumes: nothing from Task 1 yet.
- Produces (used by Tasks 4, 6):
  - `ProxySQL_Node_Entry` new fields + inline accessors: `const char* get_uuid()` (NULL until known), `unsigned long long get_last_success_at_us()`, `uint64_t get_global_version()`, `uint64_t get_checks_ok()`, `uint64_t get_checks_err()`
  - `ProxySQL_Cluster::Update_Node_UUID(char* hostname, uint16_t port, const char* uuid)` (public forwarder into nodes, takes nodes mutex)
  - `ProxySQL_Cluster::Update_Node_Failure(char* hostname, uint16_t port)` (increments `checks_err` under nodes mutex)
  - Admin intercept: `SELECT GLOBAL_UUID()` returns one row/one column `UUID` = `GloVars.uuid`.

- [ ] **Step 1: Add fields to `ProxySQL_Node_Entry`**

In `include/ProxySQL_Cluster.hpp`, in the private section of `ProxySQL_Node_Entry` (after `char* ip_addr;` ~:275):

```cpp
	char *uuid;                              // learned via SELECT GLOBAL_UUID(); NULL until known
	unsigned long long last_success_at_us;   // monotonic_time() of last successful GLOBAL_CHECKSUM poll; 0 = never
	uint64_t global_version;                 // number of observed global checksum changes on this peer
	uint64_t checks_ok;
	uint64_t checks_err;
```

In the public section (near `get_hostname()` ~:301), add inline accessors and a setter:

```cpp
	const char * get_uuid() { return uuid; }
	void set_uuid(const char* u);            // strdup, frees previous
	unsigned long long get_last_success_at_us() { return last_success_at_us; }
	uint64_t get_global_version() { return global_version; }
	uint64_t get_checks_ok() { return checks_ok; }
	uint64_t get_checks_err() { return checks_err; }
```

In `lib/ProxySQL_Cluster.cpp`: initialize all five in BOTH `ProxySQL_Node_Entry` constructors (find them near :400-480; every other pointer member like `ip_addr` is NULLed there — mirror that): `uuid = NULL; last_success_at_us = 0; global_version = 0; checks_ok = 0; checks_err = 0;`. In the destructor (frees `hostname`/`comment`/`ip_addr`), add `if (uuid) { free(uuid); uuid = NULL; }`. Implement:

```cpp
void ProxySQL_Node_Entry::set_uuid(const char* u) {
	if (uuid) {
		free(uuid);
		uuid = NULL;
	}
	if (u) {
		uuid = strdup(u);
	}
}
```

- [ ] **Step 2: Record success/failure in the poll loop**

`lib/ProxySQL_Cluster.cpp`, `ProxySQL_Cluster_Nodes::Update_Global_Checksum` (:4051-4073) — it already locks `mutex`, finds the node entry, and compares the fetched checksum. Inside the "entry found" branch add, before returning:

```cpp
		node->last_success_at_us = monotonic_time();
		node->checks_ok++;
```
and in the sub-branch where the fetched global checksum **differs** from `node->global_checksum` (the `update_checksum = true` path): `node->global_version++;`.

Add the failure counterpart on `ProxySQL_Cluster_Nodes` (implementation next to `Update_Node_Metrics` ~:4137) plus declaration in the hpp (~:408) and a public forwarder on `ProxySQL_Cluster` (declare near the other forwarders ~:667-672):

```cpp
void ProxySQL_Cluster_Nodes::Update_Node_Failure(char * _hostname, uint16_t _port) {
	uint64_t hash_ = generate_hash(_hostname, _port);
	pthread_mutex_lock(&mutex);
	auto ite = umap_proxy_nodes.find(hash_);
	if (ite != umap_proxy_nodes.end()) {
		ite->second->checks_err++;
	}
	pthread_mutex_unlock(&mutex);
}
```
Forwarder: `void ProxySQL_Cluster::Update_Node_Failure(char* h, uint16_t p) { nodes.Update_Node_Failure(h, p); }`.

Call it from the monitor thread's query-failure branch (:331-342, where the error for a failed `rc_query` is handled): `GloProxyCluster->Update_Node_Failure(node->hostname, node->port);`.

- [ ] **Step 3: `SELECT GLOBAL_UUID()` admin intercept**

`lib/Admin_Handler.cpp`, immediately after the `GLOBAL_CHECKSUM()` block (after :3795, before the `PROXYSQL ` section at :3798), add the mirror (string column instead of longlong):

```cpp
		if ((query_no_space_length == strlen("SELECT GLOBAL_UUID()")) && (!strncasecmp("SELECT GLOBAL_UUID()", query_no_space, strlen("SELECT GLOBAL_UUID()")))) {
			const char *uuid_val = (GloVars.uuid ? GloVars.uuid : "");
			uint16_t setStatus = 0;
			auto *myds=sess->client_myds;
			auto *myprot=&sess->client_myds->myprot;
			myds->DSS=STATE_QUERY_SENT_DS;
			int sid=1;
			myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"UUID",(char *)"",33,36,MYSQL_TYPE_VAR_STRING,0,0,false,0,NULL); sid++;
			myds->DSS=STATE_COLUMN_DEFINITION;
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			char **p=(char **)malloc(sizeof(char*)*1);
			unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
			l[0]=strlen(uuid_val);
			p[0]=(char *)uuid_val;
			myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
			myds->DSS=STATE_ROW;
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			myds->DSS=STATE_SLEEP;
			run_query=false;
			free(l);
			free(p);
			goto __run_query;
		}
```

- [ ] **Step 4: Monitor thread queries the peer's UUID**

`lib/ProxySQL_Cluster.cpp`, monitor thread body: right after the `PROXYSQL CLUSTER_NODE_UUID` announce block (:236-244, i.e. once per successful (re)connection, inside the same connected branch), add:

```cpp
				rc_query = mysql_query(conn, (char *)"SELECT GLOBAL_UUID()");
				if (rc_query == 0) {
					MYSQL_RES *uuid_res = mysql_store_result(conn);
					if (uuid_res) {
						MYSQL_ROW urow = mysql_fetch_row(uuid_res);
						if (urow && urow[0] && strlen(urow[0]) > 0) {
							GloProxyCluster->Update_Node_UUID(node->hostname, node->port, urow[0]);
						}
						mysql_free_result(uuid_res);
					}
				}
```

Add `Update_Node_UUID` on `ProxySQL_Cluster_Nodes` (same shape as `Update_Node_Failure`, but calls `ite->second->set_uuid(_uuid);`), declaration in hpp ~:408, and public forwarder `void ProxySQL_Cluster::Update_Node_UUID(char* h, uint16_t p, const char* u) { nodes.Update_Node_UUID(h, p, u); }`.

- [ ] **Step 5: Build, smoke-check, commit**

```bash
PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -5
```
Expected: clean build. Manual smoke check of the intercept (no infra needed):
```bash
src/proxysql --idle-threads -f -c /etc/proxysql.cnf -D /tmp/claude-1004/-data-rene-proxysql7-proxysql/dc518716-1df1-4e06-9608-25ec703bd0b2/scratchpad/px-smoke -M &
sleep 3
mysql -uadmin -padmin -h127.0.0.1 -P6032 -e "SELECT GLOBAL_UUID()"
mysql -uadmin -padmin -h127.0.0.1 -P6032 -e "PROXYSQL SHUTDOWN" || true
```
(If no default config exists, generate a minimal one in the scratchpad with `datadir` + `admin_variables.mysql_ifaces="0.0.0.0:6032"`.) Expected: one row, a 36-char UUID.

```bash
git add include/ProxySQL_Cluster.hpp lib/ProxySQL_Cluster.cpp lib/Admin_Handler.cpp
git commit -m "feat(cluster): per-node liveness bookkeeping and GLOBAL_UUID() peer identity exchange"
```

---

### Task 3: Tri-state admin read-only mode + `PROXYSQL READONLY AUTO`

**Files:**
- Modify: `include/proxysql_admin.h` (:646-647 replace inline get/set; add enum + atomics near the `variables` struct)
- Modify: `lib/ProxySQL_Admin.cpp` (:2900 default init; :4816-4826 `set_variable` for `read_only`)
- Modify: `lib/Admin_Handler.cpp` (:745-760 PROXYSQL READONLY/READWRITE handlers + new AUTO command; :3697, :3722, :5369 enforcement call sites)

**Interfaces:**
- Consumes: nothing yet (the follower flag is fed by Task 4).
- Produces (used by Tasks 4, 5):
  - `enum admin_ro_mode_t { ADMIN_RO_MODE_AUTO = 0, ADMIN_RO_MODE_FORCED_RO = 1, ADMIN_RO_MODE_FORCED_RW = 2 };`
  - `bool ProxySQL_Admin::effective_read_only()`
  - `void ProxySQL_Admin::set_ro_mode(admin_ro_mode_t m)`
  - `void ProxySQL_Admin::set_cluster_follower(bool f)`
  - Admin commands: `PROXYSQL READONLY` → FORCED_RO, `PROXYSQL READWRITE` → FORCED_RW, `PROXYSQL READONLY AUTO` → AUTO.

- [ ] **Step 1: Replace the boolean API in the header**

`include/proxysql_admin.h`: above `class ProxySQL_Admin` (or right before it), add:

```cpp
enum admin_ro_mode_t {
	ADMIN_RO_MODE_AUTO = 0,      // read-only iff this node is a cluster follower (leader election)
	ADMIN_RO_MODE_FORCED_RO = 1, // operator-forced read-only (PROXYSQL READONLY)
	ADMIN_RO_MODE_FORCED_RW = 2, // operator-forced read-write (PROXYSQL READWRITE)
};
```

Keep the `bool admin_read_only;` field at :373 (it remains the storage for the `admin-read_only` boot variable). Replace the two inlines at :646-647 with:

```cpp
	bool effective_read_only() {
		int m = ro_mode.load(std::memory_order_relaxed);
		if (m == ADMIN_RO_MODE_FORCED_RO) return true;
		if (m == ADMIN_RO_MODE_FORCED_RW) return false;
		return cluster_follower.load(std::memory_order_relaxed);
	}
	void set_ro_mode(admin_ro_mode_t m) { ro_mode.store((int)m, std::memory_order_relaxed); }
	admin_ro_mode_t get_ro_mode() { return (admin_ro_mode_t)ro_mode.load(std::memory_order_relaxed); }
	void set_cluster_follower(bool f) { cluster_follower.store(f, std::memory_order_relaxed); }
```

and add the two members next to other member declarations (e.g. near `SerialExposer` :358):

```cpp
	std::atomic<int> ro_mode { ADMIN_RO_MODE_AUTO };
	std::atomic<bool> cluster_follower { false };
```

(`<atomic>` is already available in this header's include set; add `#include <atomic>` at the top if the build says otherwise.)

- [ ] **Step 2: Update all former `get_read_only()` / `set_read_only()` call sites**

There are exactly five (verified by grep):
1. `lib/Admin_Handler.cpp:5369` — `if (SPA->get_read_only())` → `if (SPA->effective_read_only())` (the `PRAGMA query_only` wrapper).
2. `lib/Admin_Handler.cpp:3697` — `bool ro=SPA->get_read_only();` → `bool ro=SPA->effective_read_only();` (`SHOW GLOBAL VARIABLES LIKE 'read_only'` canned response — external HA tooling now sees follower state).
3. `lib/Admin_Handler.cpp:3722` — same change (`SELECT @@global.read_only` canned response).
4. `lib/Admin_Handler.cpp:749` — `SPA->set_read_only(true);` → `SPA->set_ro_mode(ADMIN_RO_MODE_FORCED_RO);`
5. `lib/Admin_Handler.cpp:757` — `SPA->set_read_only(false);` → `SPA->set_ro_mode(ADMIN_RO_MODE_FORCED_RW);`

Add the new command as a separate exact-length block adjacent to the two existing ones (after :760; ordering is irrelevant because matching is exact-length):

```cpp
	if (query_no_space_length==strlen("PROXYSQL READONLY AUTO") && !strncasecmp("PROXYSQL READONLY AUTO",query_no_space, query_no_space_length)) {
		// returns read-only control to the cluster leader election (AUTO mode)
		proxy_info("Received PROXYSQL READONLY AUTO command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->set_ro_mode(ADMIN_RO_MODE_AUTO);
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}
```

Also add a `proxy_info` on each mode change by extending the two existing handlers' log lines (they already `proxy_info` the command; that satisfies the spec's transition logging together with Task 4's election logs).

- [ ] **Step 3: Map the `admin-read_only` boot variable onto the tri-state**

`lib/ProxySQL_Admin.cpp` `set_variable`, the `read_only` branch (:4816-4826): after `variables.admin_read_only` is assigned, add:

```cpp
			set_ro_mode(variables.admin_read_only ? ADMIN_RO_MODE_FORCED_RO : ADMIN_RO_MODE_AUTO);
```

(Default init at :2900 stays `variables.admin_read_only=false;`; the atomic already defaults to AUTO. With election disabled the follower flag is always false, so AUTO ⇒ read-write ⇒ today's behavior exactly.)

- [ ] **Step 4: Build and behavior-check, commit**

```bash
PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -5
```
Manual check against a scratch instance (same spawn recipe as Task 2 Step 5):
- `INSERT INTO mysql_servers (hostgroup_id,hostname) VALUES (1,'127.0.0.1');` succeeds (AUTO, no election).
- `PROXYSQL READONLY` → the same INSERT now fails with `attempt to write a readonly database`.
- `PROXYSQL READONLY AUTO` → INSERT succeeds again.
- `SELECT @@global.read_only` reflects each state (0/1/0).

```bash
git add include/proxysql_admin.h lib/ProxySQL_Admin.cpp lib/Admin_Handler.cpp
git commit -m "feat(admin): tri-state read-only mode (AUTO/FORCED_RO/FORCED_RW) with PROXYSQL READONLY AUTO"
```

---

### Task 4: Admin variables, election tick, and leader state on ProxySQL_Cluster

**Files:**
- Modify: `include/proxysql_admin.h` (:379 region — 3 new fields in `variables` struct)
- Modify: `lib/ProxySQL_Admin.cpp` (name list :390-461; defaults :2900-2930; `get_variable` :3731 region; `set_variable` :4236 region)
- Modify: `include/ProxySQL_Cluster.hpp` (`ProxySQL_Cluster` members :607-631 region + method declarations)
- Modify: `lib/ProxySQL_Cluster.cpp` (ctor defaults :5494-5526; new methods; `#include "ProxySQL_Cluster_Leader.h"`)
- Modify: `lib/ProxySQL_Admin.cpp` `admin_main_loop` (:2624-2640 region — tick call)
- Modify: `test/tap/tests/proxysql_reference_select_config_file.cnf`, `test/tap/tests/test_cluster_sync-t.cpp`, `test/tap/tests/reg_test_3847_admin_lock-t.cpp` (reference lists of admin variables — see Step 5)

**Interfaces:**
- Consumes: Task 1 (`cluster_elect_leader`, `Cluster_Leader_State`), Task 2 (`get_uuid()`, `get_last_success_at_us()`), Task 3 (`set_cluster_follower()`).
- Produces (used by Tasks 5, 6, 7):
  - `ProxySQL_Cluster` fields: `int cluster_leader_election;` (0/1), `int cluster_leader_node_timeout_ms;`, `int cluster_leader_grace_ms;` (all `__sync_*` access)
  - `void ProxySQL_Cluster::leader_election_tick(unsigned long long curtime_us)`
  - `bool ProxySQL_Cluster::is_leader()` — true iff current effective leader uuid == `GloVars.uuid`
  - `void ProxySQL_Cluster::get_leader_info(std::string& hostname, int& port, std::string& uuid)` — all empty/0 when no leader
  - `std::vector<Cluster_Leader_Candidate> ProxySQL_Cluster_Nodes::get_leader_candidates(unsigned long long alive_timeout_us)`

- [ ] **Step 1: Wire the three admin variables**

`include/proxysql_admin.h`, in the `variables` struct next to `cluster_check_interval_ms` (:379):

```cpp
		bool cluster_leader_election;
		int cluster_leader_node_timeout_ms;
		int cluster_leader_grace_ms;
```

`lib/ProxySQL_Admin.cpp` `admin_variables_names[]` (insert after `(char *)"cluster_check_interval_ms",` at :412):

```cpp
#ifdef PROXYSQL31
	(char *)"cluster_leader_election",
#endif /* PROXYSQL31 */
	(char *)"cluster_leader_node_timeout_ms",
	(char *)"cluster_leader_grace_ms",
```

Defaults (next to :2904):

```cpp
	variables.cluster_leader_election=false;
	variables.cluster_leader_node_timeout_ms=3000;
	variables.cluster_leader_grace_ms=3000;
```

`get_variable` (next to the `cluster_check_interval_ms` block at :3731):

```cpp
#ifdef PROXYSQL31
	if (!strcasecmp(name,"cluster_leader_election")) {
		return strdup((variables.cluster_leader_election ? "true" : "false"));
	}
#endif /* PROXYSQL31 */
	if (!strcasecmp(name,"cluster_leader_node_timeout_ms")) {
		sprintf(intbuf,"%d",variables.cluster_leader_node_timeout_ms);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_leader_grace_ms")) {
		sprintf(intbuf,"%d",variables.cluster_leader_grace_ms);
		return strdup(intbuf);
	}
```

`set_variable` (next to the `cluster_check_interval_ms` block at :4236; same `__sync_lock_test_and_set` push pattern):

```cpp
#ifdef PROXYSQL31
	if (!strcasecmp(name,"cluster_leader_election")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_leader_election=true;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_leader_election, 1);
			// Spec: with election enabled a node is effective-RO until the first
			// election settles. Assume follower immediately; the next tick corrects
			// it (the elected leader flips back to RW within tick+grace).
			set_cluster_follower(true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_leader_election=false;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_leader_election, 0);
			set_cluster_follower(false); // immediate, don't wait for the next tick
			return true;
		}
		return false;
	}
#endif /* PROXYSQL31 */
	if (!strcasecmp(name,"cluster_leader_node_timeout_ms")) {
		int intv=atoi(value);
		if (intv >= 1000 && intv <= 600000) {
			variables.cluster_leader_node_timeout_ms=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_leader_node_timeout_ms, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_leader_grace_ms")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 600000) {
			variables.cluster_leader_grace_ms=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_leader_grace_ms, intv);
			return true;
		} else {
			return false;
		}
	}
```

- [ ] **Step 2: Leader state on `ProxySQL_Cluster` + candidate collection**

`include/ProxySQL_Cluster.hpp`: add `#include "ProxySQL_Cluster_Leader.h"` at the top (after the existing includes). On `ProxySQL_Cluster_Nodes` (public, near :403):

```cpp
	std::vector<Cluster_Leader_Candidate> get_leader_candidates(unsigned long long alive_timeout_us);
```

On `ProxySQL_Cluster` (public, near :607):

```cpp
	int cluster_leader_election;          // 0/1, __sync access
	int cluster_leader_node_timeout_ms;
	int cluster_leader_grace_ms;
	pthread_mutex_t leader_mutex;         // guards leader_state + leader_hostname/leader_port
	Cluster_Leader_State leader_state;
	char * leader_hostname;               // NULL = no leader
	int leader_port;
	unsigned long long leader_next_check_at; // monotonic us, 0 initially
	void leader_election_tick(unsigned long long curtime_us);
	bool is_leader();
	void get_leader_info(std::string& hostname, int& port, std::string& uuid);
```

`lib/ProxySQL_Cluster.cpp` ctor (:5494-5526 region): `cluster_leader_election = 0; cluster_leader_node_timeout_ms = 3000; cluster_leader_grace_ms = 3000; leader_hostname = NULL; leader_port = 0; leader_next_check_at = 0; pthread_mutex_init(&leader_mutex, NULL);`.

Candidate collection (implementation near the other stats builders, ~:4640):

```cpp
std::vector<Cluster_Leader_Candidate> ProxySQL_Cluster_Nodes::get_leader_candidates(unsigned long long alive_timeout_us) {
	std::vector<Cluster_Leader_Candidate> candidates;
	unsigned long long now = monotonic_time();
	pthread_mutex_lock(&mutex);
	for (auto it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); it++) {
		ProxySQL_Node_Entry * node = it->second;
		Cluster_Leader_Candidate c;
		c.uuid = (node->get_uuid() ? node->get_uuid() : "");
		c.hostname = node->get_hostname();
		c.port = node->get_port();
		c.weight = node->get_weight();
		bool is_self = (GloVars.uuid && node->get_uuid() && strcmp(node->get_uuid(), GloVars.uuid) == 0);
		unsigned long long last = node->get_last_success_at_us();
		c.alive = is_self || (last != 0 && (now - last) < alive_timeout_us);
		candidates.push_back(c);
	}
	pthread_mutex_unlock(&mutex);
	return candidates;
}
```

(Self-identification is UUID equality; a node's own entry gets its uuid from the node polling its own admin port, which every standard cluster deployment does. A node that cannot reach even its own admin interface has no electable self — acceptable and noted in the spec's edge cases.)

- [ ] **Step 3: The election tick**

`lib/ProxySQL_Cluster.cpp` (near `p_update_metrics` ~:5543):

```cpp
void ProxySQL_Cluster::leader_election_tick(unsigned long long curtime_us) {
	if (curtime_us < leader_next_check_at) return;
	leader_next_check_at = curtime_us + 500000; // evaluate at most every 500ms
	int enabled = __sync_fetch_and_add(&cluster_leader_election, 0);
	char *c_user = NULL; char *c_pass = NULL;
	get_credentials(&c_user, &c_pass);
	bool clustering_active = (c_user && strlen(c_user) > 0);
	free(c_user); free(c_pass);
	bool am_leader_or_standalone = true;
	if (enabled == 0 || clustering_active == false) {
		pthread_mutex_lock(&leader_mutex);
		leader_state.reset();
		if (leader_hostname) { free(leader_hostname); leader_hostname = NULL; }
		leader_port = 0;
		pthread_mutex_unlock(&leader_mutex);
	} else {
		unsigned long long timeout_us = (unsigned long long)__sync_fetch_and_add(&cluster_leader_node_timeout_ms, 0) * 1000ULL;
		unsigned long long grace_ms = (unsigned long long)__sync_fetch_and_add(&cluster_leader_grace_ms, 0);
		std::vector<Cluster_Leader_Candidate> candidates = nodes.get_leader_candidates(timeout_us);
		if (candidates.empty()) {
			// proxysql_servers is empty: standalone behavior
			pthread_mutex_lock(&leader_mutex);
			leader_state.reset();
			if (leader_hostname) { free(leader_hostname); leader_hostname = NULL; }
			leader_port = 0;
			pthread_mutex_unlock(&leader_mutex);
		} else {
			int idx = cluster_elect_leader(candidates);
			std::string computed = (idx >= 0 ? candidates[idx].uuid : "");
			pthread_mutex_lock(&leader_mutex);
			bool changed = leader_state.update(computed, curtime_us / 1000, grace_ms);
			if (changed) {
				if (leader_hostname) { free(leader_hostname); leader_hostname = NULL; }
				leader_port = 0;
				if (idx >= 0 && leader_state.current_leader_uuid == candidates[idx].uuid) {
					leader_hostname = strdup(candidates[idx].hostname.c_str());
					leader_port = candidates[idx].port;
				}
				proxy_info("Cluster leader changed: new leader is %s (%s:%d)\n",
					(leader_state.current_leader_uuid.empty() ? "NONE" : leader_state.current_leader_uuid.c_str()),
					(leader_hostname ? leader_hostname : ""), leader_port);
				metrics.p_counter_array[p_cluster_counter::cluster_leader_changes]->Increment();
			}
			am_leader_or_standalone = (GloVars.uuid && leader_state.current_leader_uuid == GloVars.uuid);
			pthread_mutex_unlock(&leader_mutex);
		}
	}
	GloAdmin->set_cluster_follower(enabled != 0 && clustering_active && am_leader_or_standalone == false);
}
```

Note: `p_cluster_counter::cluster_leader_changes` is added in Step 4 of THIS task (so this task compiles standalone); Task 7 adds only the gauge and the per-node metric.

`is_leader()` / `get_leader_info()`:

```cpp
bool ProxySQL_Cluster::is_leader() {
	pthread_mutex_lock(&leader_mutex);
	bool r = (GloVars.uuid && leader_state.current_leader_uuid.empty() == false && leader_state.current_leader_uuid == GloVars.uuid);
	pthread_mutex_unlock(&leader_mutex);
	return r;
}

void ProxySQL_Cluster::get_leader_info(std::string& hostname, int& port, std::string& uuid) {
	pthread_mutex_lock(&leader_mutex);
	hostname = (leader_hostname ? leader_hostname : "");
	port = leader_port;
	uuid = leader_state.current_leader_uuid;
	pthread_mutex_unlock(&leader_mutex);
}
```

Semantics encoded above (matches spec): election enabled + clustering active + this node is not the effective leader (including "no leader yet") ⇒ follower ⇒ AUTO means read-only. Election disabled, or clustering unconfigured, or `proxysql_servers` empty ⇒ not a follower ⇒ AUTO means read-write.

- [ ] **Step 4: Counter enum + tick call in the Admin main loop**

`include/ProxySQL_Cluster.hpp` `p_cluster_counter` enum (:433-510): add `cluster_leader_changes,` before `SIZE_`. In `lib/ProxySQL_Cluster.cpp` `cluster_counter_vector` (starts ~:4872), add:

```cpp
	std::make_tuple (
		p_cluster_counter::cluster_leader_changes,
		"proxysql_cluster_leader_changes_total",
		"Number of times this node observed an effective cluster leader change.",
		metric_tags {}
	),
```

`lib/ProxySQL_Admin.cpp` `admin_main_loop`, right after the `#endif` of the TSDB block (:2640), **outside** any `#ifdef`:

```cpp
		if (GloProxyCluster) {
			GloProxyCluster->leader_election_tick(curtime);
		}
```

(`curtime` is the monotonic µs captured at :2486; worst-case tick resolution is ~500ms — fine against a 3000ms default grace.)

- [ ] **Step 5: Update admin-variable reference fixtures**

Some tests enumerate admin variables. Run:
```bash
grep -n "cluster_check_interval_ms" test/tap/tests/proxysql_reference_select_config_file.cnf \
  test/tap/tests/test_cluster_sync-t.cpp test/tap/tests/reg_test_3847_admin_lock-t.cpp
```
For **each** occurrence found, mirror the same entry style for `cluster_leader_node_timeout_ms` and `cluster_leader_grace_ms` (the two ungated variables). Do NOT add `cluster_leader_election` to fixtures that a stable-tier CI build would also exercise — it only exists under PROXYSQL31; add it only where the fixture is tier-aware (if unclear, leave it out; the TAP test in Task 8 covers it).

- [ ] **Step 6: Build, verify, commit**

```bash
PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -5
```
Scratch-instance check: `SELECT * FROM global_variables WHERE variable_name LIKE 'admin-cluster_leader%'` shows all three with defaults; `SET admin-cluster_leader_election='true'; LOAD ADMIN VARIABLES TO RUNTIME;` then (with empty `proxysql_servers`) verify writes still work (standalone short-circuit). Also build once WITHOUT the tier flag to prove the ifdef discipline:
```bash
make clean && make -j$(nproc) 2>&1 | tail -3 && make clean && PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -3
```
Expected: both build; in the stable build `admin-cluster_leader_election` does not exist.

```bash
git add include/proxysql_admin.h lib/ProxySQL_Admin.cpp include/ProxySQL_Cluster.hpp lib/ProxySQL_Cluster.cpp \
  test/tap/tests/proxysql_reference_select_config_file.cnf test/tap/tests/test_cluster_sync-t.cpp \
  test/tap/tests/reg_test_3847_admin_lock-t.cpp
git commit -m "feat(cluster): leader election tick, admin variables (PROXYSQL31-gated switch), follower steering"
```

---

### Task 5: Gate `LOAD … TO RUNTIME` / `SAVE … TO DISK` under effective read-only

**Files:**
- Modify: `lib/Admin_Handler.cpp` (`admin_handler_command_load_or_save()`, top of function ~:1416)

**Interfaces:**
- Consumes: Task 3 `effective_read_only()`, Task 4 `get_leader_info()`.
- Produces: operator-facing refusal with leader identity; nothing consumed by later tasks.

- [ ] **Step 1: Add the gate at the single choke point**

Every `LOAD *`/`SAVE *` admin command flows through `admin_handler_command_load_or_save()` (dispatch at `lib/Admin_Handler.cpp:3836-3840`). Cluster syncs bypass it (direct C++ calls) — exactly what we want. At the top of the function (~:1416, after `SPA` is available; add the cast if the function derives it later):

```cpp
	{
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (SPA->effective_read_only()) {
			bool is_load = (!strncasecmp("LOAD ", query_no_space, 5));
			bool is_save = (!strncasecmp("SAVE ", query_no_space, 5));
			bool refuse = false;
			if (query_no_space_length > 11 && !strncasecmp(" TO RUNTIME", query_no_space+query_no_space_length-11, 11)) {
				refuse = true; // LOAD ... TO RUNTIME
			}
			if (query_no_space_length > 8 && is_save && !strncasecmp(" TO DISK", query_no_space+query_no_space_length-8, 8)) {
				refuse = true; // SAVE ... TO DISK
			}
			if (query_no_space_length > 12 && (is_load || is_save) && !strncasecmp(" FROM MEMORY", query_no_space+query_no_space_length-12, 12)) {
				refuse = true; // aliases: LOAD x FROM MEMORY == LOAD x TO RUNTIME ; SAVE x FROM MEMORY == SAVE x TO DISK
			}
			if (refuse) {
				std::string l_host; int l_port = 0; std::string l_uuid;
				GloProxyCluster->get_leader_info(l_host, l_port, l_uuid);
				char msg[512];
				if (l_host.length()) {
					snprintf(msg, sizeof(msg),
						"Admin is in read-only mode (cluster follower). Current leader is %s:%d (%s). Use PROXYSQL READWRITE to override.",
						l_host.c_str(), l_port, l_uuid.c_str());
				} else {
					snprintf(msg, sizeof(msg),
						"Admin is in read-only mode. Use PROXYSQL READWRITE to override.");
				}
				proxy_warning("Refused '%s' : %s\n", query_no_space, msg);
				SPA->send_error_msg_to_client(sess, msg);
				return false;
			}
		}
	}
```

Check the actual signature of `send_error_msg_to_client` at its declaration in `include/proxysql_admin.h` and match it (it is used at `lib/Admin_Handler.cpp:734` as `SPA->send_error_msg_to_client(sess, (char *)"...")` — cast `msg` to `(char *)` if required). `GloProxyCluster` is already an `extern` visible in `Admin_Handler.cpp` (used at :686-745); add the extern declaration at the top of the file if the compiler disagrees.

- [ ] **Step 2: Build, verify, commit**

```bash
PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -5
```
Scratch-instance check: `PROXYSQL READONLY`, then `LOAD MYSQL SERVERS TO RUNTIME` → error containing "read-only mode"; `SAVE MYSQL SERVERS TO DISK` → same; `LOAD MYSQL SERVERS FROM DISK` → still allowed; `PROXYSQL READWRITE` → all allowed again.

```bash
git add lib/Admin_Handler.cpp
git commit -m "feat(admin): refuse LOAD ... TO RUNTIME / SAVE ... TO DISK in effective read-only mode"
```

---

### Task 6: Implement `stats_proxysql_servers_status`

**Files:**
- Modify: `include/ProxySQL_Admin_Tables_Definitions.h:289` (add `uuid` column)
- Modify: `include/ProxySQL_Cluster.hpp` (declare producer + forwarder)
- Modify: `lib/ProxySQL_Cluster.cpp` (producer implementation)
- Modify: `include/proxysql_admin.h:809` region (declare `stats___proxysql_servers_status()`)
- Modify: `lib/ProxySQL_Admin_Stats.cpp` (implementation, modeled on :1516-1563)
- Modify: `lib/ProxySQL_Admin.cpp` (:1345, :1492-1496, :1724-1727 — re-enable the three commented blocks)

**Interfaces:**
- Consumes: Task 2 node-entry accessors, Task 4 `get_leader_info()` + `cluster_leader_node_timeout_ms`.
- Produces: queryable `stats_proxysql_servers_status` table (used by Task 8's TAP test); `SQLite3_result * ProxySQL_Cluster::get_stats_proxysql_servers_status()`.

- [ ] **Step 1: Schema — append the uuid column**

`include/ProxySQL_Admin_Tables_Definitions.h:289`, change the define to (only addition: `uuid`):

```c
#define STATS_SQLITE_TABLE_PROXYSQL_SERVERS_STATUS "CREATE TABLE stats_proxysql_servers_status (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , master VARCHAR NOT NULL , global_version INT NOT NULL , check_age_us INT NOT NULL , ping_time_us INT NOT NULL, checks_OK INT NOT NULL , checks_ERR INT NOT NULL , uuid VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostname, port) )"
```

- [ ] **Step 2: Producer on the cluster side**

`include/ProxySQL_Cluster.hpp`: on `ProxySQL_Cluster_Nodes` (near the other stats declarations ~:413):
```cpp
	SQLite3_result * stats_proxysql_servers_status(const std::string& leader_uuid, unsigned long long alive_timeout_us);
```
On `ProxySQL_Cluster` (forwarders ~:667-672):
```cpp
	SQLite3_result * get_stats_proxysql_servers_status();
```

`lib/ProxySQL_Cluster.cpp` (next to `stats_proxysql_servers_metrics` ~:4581; same 100%-strdup/SQLITE_TEXT pattern as `dump_table_proxysql_servers` :4635):

```cpp
SQLite3_result * ProxySQL_Cluster_Nodes::stats_proxysql_servers_status(const std::string& leader_uuid, unsigned long long alive_timeout_us) {
	const int colnum = 10;
	SQLite3_result *result = new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"hostname");
	result->add_column_definition(SQLITE_TEXT,"port");
	result->add_column_definition(SQLITE_TEXT,"weight");
	result->add_column_definition(SQLITE_TEXT,"master");
	result->add_column_definition(SQLITE_TEXT,"global_version");
	result->add_column_definition(SQLITE_TEXT,"check_age_us");
	result->add_column_definition(SQLITE_TEXT,"ping_time_us");
	result->add_column_definition(SQLITE_TEXT,"checks_OK");
	result->add_column_definition(SQLITE_TEXT,"checks_ERR");
	result->add_column_definition(SQLITE_TEXT,"uuid");
	(void)alive_timeout_us; // liveness is derivable from check_age_us; kept for future use
	unsigned long long now = monotonic_time();
	char buf[64];
	pthread_mutex_lock(&mutex);
	for (auto it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); it++) {
		ProxySQL_Node_Entry * node = it->second;
		char **pta = (char **)malloc(sizeof(char *)*colnum);
		pta[0] = strdup(node->get_hostname());
		sprintf(buf, "%d", node->get_port()); pta[1] = strdup(buf);
		sprintf(buf, "%lu", node->get_weight()); pta[2] = strdup(buf);
		const char *nuuid = node->get_uuid();
		bool is_master = (nuuid && leader_uuid.empty() == false && leader_uuid == nuuid);
		pta[3] = strdup(is_master ? "YES" : "NO");
		sprintf(buf, "%lu", (unsigned long)node->get_global_version()); pta[4] = strdup(buf);
		unsigned long long last = node->get_last_success_at_us();
		if (last == 0) {
			pta[5] = strdup("-1");
		} else {
			sprintf(buf, "%llu", now - last); pta[5] = strdup(buf);
		}
		ProxySQL_Node_Metrics *curr = node->get_metrics_curr();
		sprintf(buf, "%llu", (curr ? curr->response_time_us : 0)); pta[6] = strdup(buf);
		sprintf(buf, "%lu", (unsigned long)node->get_checks_ok()); pta[7] = strdup(buf);
		sprintf(buf, "%lu", (unsigned long)node->get_checks_err()); pta[8] = strdup(buf);
		pta[9] = strdup(nuuid ? nuuid : "");
		result->add_row(pta);
		for (int k = 0; k < colnum; k++) {
			if (pta[k]) free(pta[k]);
		}
		free(pta);
	}
	pthread_mutex_unlock(&mutex);
	return result;
}

SQLite3_result * ProxySQL_Cluster::get_stats_proxysql_servers_status() {
	std::string l_host; int l_port = 0; std::string l_uuid;
	get_leader_info(l_host, l_port, l_uuid);
	unsigned long long timeout_us = (unsigned long long)__sync_fetch_and_add(&cluster_leader_node_timeout_ms, 0) * 1000ULL;
	return nodes.stats_proxysql_servers_status(l_uuid, timeout_us);
}
```

(Check the exact field name for response time in `ProxySQL_Node_Metrics` at `include/ProxySQL_Cluster.hpp:233-249` — the member measured in `set_metrics` — and use that name; if the metrics ring has never been filled, `get_metrics_curr()` returns a zeroed entry, which yields 0.)

- [ ] **Step 3: Admin side — `stats___proxysql_servers_status()` + re-enable interception**

`include/proxysql_admin.h`: next to `:809` (`stats___proxysql_servers_metrics`), declare `void stats___proxysql_servers_status();`.

`lib/ProxySQL_Admin_Stats.cpp`: implement modeled on `stats___proxysql_servers_checksums` (:1516-1563) **including the `sql_query_global_mutex` unlock/relock dance** (the producer takes the cluster nodes mutex — same deadlock hazard documented at :1517-1529):

```cpp
void ProxySQL_Admin::stats___proxysql_servers_status() {
	// Same deadlock avoidance as stats___proxysql_servers_checksums:
	// release sql_query_global_mutex while calling into the cluster nodes mutex.
	pthread_mutex_unlock(&pa->sql_query_global_mutex);
	SQLite3_result *resultset = GloProxyCluster->get_stats_proxysql_servers_status();
	pthread_mutex_lock(&pa->sql_query_global_mutex);
	if (resultset == NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_proxysql_servers_status");
	char *query = (char *)"INSERT INTO stats_proxysql_servers_status VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
	sqlite3_stmt *statement = NULL;
	int rc = statsdb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, statsdb);
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		SQLite3_row *r = *it;
		rc = (*proxy_sqlite3_bind_text)(statement, 1, r->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_int64)(statement, 2, atoll(r->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_int64)(statement, 3, atoll(r->fields[2])); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_text)(statement, 4, r->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_int64)(statement, 5, atoll(r->fields[4])); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_int64)(statement, 6, atoll(r->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_int64)(statement, 7, atoll(r->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_int64)(statement, 8, atoll(r->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_int64)(statement, 9, atoll(r->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_text)(statement, 10, r->fields[9], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
		SAFE_SQLITE3_STEP2(statement);
		rc = (*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, statsdb);
	}
	(*proxy_sqlite3_finalize)(statement);
	statsdb->execute("COMMIT");
	delete resultset;
}
```

Open the template at `lib/ProxySQL_Admin_Stats.cpp:1516-1563` first and copy its EXACT idioms (the `pa->` handle, bind function pointer names, `ASSERT_SQLITE_OK`, finalize call) — the snippet above shows structure and column order; the template file is authoritative for helper spellings.

`lib/ProxySQL_Admin.cpp` — re-enable the three commented blocks exactly:
- `:1345` → `bool stats_proxysql_servers_status = false;`
- `:1492-1496` → 
```cpp
	if (strstr(query_no_space,"stats_proxysql_servers_status"))
		{ stats_proxysql_servers_status = true; refresh = true; }
```
- `:1724-1727` →
```cpp
		if (stats_proxysql_servers_status) {
			stats___proxysql_servers_status();
		}
```

- [ ] **Step 4: Build, verify, commit**

```bash
PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -5
```
Scratch check: with empty `proxysql_servers`, `SELECT * FROM stats_proxysql_servers_status` returns 0 rows (not an error). (Populated-path verification happens in Task 8's multi-node TAP test.)

```bash
git add include/ProxySQL_Admin_Tables_Definitions.h include/ProxySQL_Cluster.hpp lib/ProxySQL_Cluster.cpp \
  include/proxysql_admin.h lib/ProxySQL_Admin_Stats.cpp lib/ProxySQL_Admin.cpp
git commit -m "feat(cluster): implement stats_proxysql_servers_status with leader flag and liveness data"
```

---

### Task 7: Prometheus metrics (leader gauge + per-node alive gauge)

**Files:**
- Modify: `include/ProxySQL_Cluster.hpp` (`p_cluster_gauge` :512-516; `p_cluster_nodes_dyn_gauge` :352-364; map member :386-401)
- Modify: `lib/ProxySQL_Cluster.cpp` (`cluster_gauge_vector` :5491; `cluster_nodes_dyn_gauge_vector` ~:3890; `update_prometheus_nodes_metrics` :4681+ update/cleanup lists; `p_update_metrics` :5543)

**Interfaces:**
- Consumes: Task 4 `is_leader()`, node-entry liveness from Task 2. (`proxysql_cluster_leader_changes_total` was already added in Task 4.)
- Produces: `/metrics` families `proxysql_cluster_leader_status` (0/1) and per-node `proxysql_servers_alive{hostname,port}`.

- [ ] **Step 1: Static leader gauge**

`include/ProxySQL_Cluster.hpp` `p_cluster_gauge` (:512-516, currently only `SIZE_`): add `cluster_leader_status,` before `SIZE_`. In `lib/ProxySQL_Cluster.cpp`, populate the empty `cluster_gauge_vector {}` (:5491):

```cpp
	cluster_gauge_vector {
		std::make_tuple (
			p_cluster_gauge::cluster_leader_status,
			"proxysql_cluster_leader_status",
			"1 when this node is the elected cluster leader, 0 otherwise.",
			metric_tags {}
		),
	}
```

In `ProxySQL_Cluster::p_update_metrics()` (:5543-5545), add:

```cpp
	metrics.p_gauge_array[p_cluster_gauge::cluster_leader_status]->Set(is_leader() ? 1 : 0);
```

- [ ] **Step 2: Per-node alive gauge**

Four edits, following the existing per-node dyn-gauge pattern exactly (use `proxysql_servers_checksums_updated_at` or a neighbor as the template):
1. `include/ProxySQL_Cluster.hpp` `p_cluster_nodes_dyn_gauge` (:352-364): add `proxysql_servers_alive,` before `SIZE_`.
2. Same header, map members (:386-401): add `std::map<std::string, prometheus::Gauge*> p_proxysql_servers_alive {};`.
3. `lib/ProxySQL_Cluster.cpp` `cluster_nodes_dyn_gauge_vector` (~:3890): add
```cpp
	std::make_tuple (
		p_cluster_nodes_dyn_gauge::proxysql_servers_alive,
		"proxysql_servers_alive",
		"1 when the peer answered the cluster liveness poll within admin-cluster_leader_node_timeout_ms, 0 otherwise.",
		metric_tags {}
	),
```
4. `update_prometheus_nodes_metrics()` (:4681+): inside the per-node loop (where `m_common_labels`/`m_id` are built, :4696-4697), compute and publish:
```cpp
		unsigned long long alive_timeout_us = (unsigned long long)__sync_fetch_and_add(&GloProxyCluster->cluster_leader_node_timeout_ms, 0) * 1000ULL;
		unsigned long long last_ok = entry->get_last_success_at_us();
		bool node_alive = (last_ok != 0 && (monotonic_time() - last_ok) < alive_timeout_us);
		p_update_map_gauge(p_proxysql_servers_alive,
			gauge_array[p_cluster_nodes_dyn_gauge::proxysql_servers_alive],
			m_id, m_common_labels, node_alive ? 1 : 0);
```
(Match the local variable names actually used in that function — the entry pointer and the gauge family array are already in scope; hoist the `alive_timeout_us` computation above the loop.) Then add `p_proxysql_servers_alive` to the `gauge_maps` cleanup list (:4793-4803) and to the `metric_gauges` update vector (:4750-4754) following how the neighboring gauge maps appear in each.

- [ ] **Step 3: Build, verify, commit**

```bash
PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -5
```
Scratch check: `curl -s http://127.0.0.1:6070/metrics | grep -E "proxysql_cluster_leader_status|proxysql_cluster_leader_changes"` shows the gauge at 0 and the counter at 0.

```bash
git add include/ProxySQL_Cluster.hpp lib/ProxySQL_Cluster.cpp
git commit -m "feat(cluster): prometheus leader-status gauge and per-node alive gauge"
```

---

### Task 8: End-to-end TAP test (3-node self-spawned cluster)

**Files:**
- Create: `test/tap/tests/test_cluster_leader_election-t.cpp`
- Modify: `test/tap/groups/groups.json` (register)

**Interfaces:**
- Consumes: everything above, through the admin protocol only.
- Produces: CI coverage. No code consumers.

**Design:** self-spawned nodes (pattern of `test_cluster_sync-t.cpp:1288-1330`), NOT the shared infra cluster nodes — this test kills its leader and force-flips read-only modes, which must not disturb other tests sharing the infra cluster. All 3 nodes run on 127.0.0.1 inside the test-runner container with bespoke generated configs. Weights 300/200/100 ⇒ deterministic leader order node1 → node2 → node3. Fast timings: `cluster_check_interval_ms=200`, `cluster_leader_node_timeout_ms=1000`, `cluster_leader_grace_ms=500`.

One deliberate deviation from the spec's illustrative test list: after the killed ex-leader rejoins, it has the highest weight and therefore **retakes** leadership (weight is priority, keepalived-style — the deterministic-election design implies this). The test asserts retake, not rejoin-as-follower.

- [ ] **Step 1: Write the test**

Create `test/tap/tests/test_cluster_leader_election-t.cpp`:

```cpp
/**
 * @file test_cluster_leader_election-t.cpp
 * @brief E2E test for ProxySQL Cluster leader election (PROXYSQL31 feature).
 *
 * Spawns a self-contained 3-node ProxySQL cluster on 127.0.0.1 (bespoke
 * configs, weights 300/200/100), then verifies: convergence to a single
 * leader, follower write refusal (SQL + LOAD TO RUNTIME + SAVE TO DISK),
 * FORCED_RW stickiness, leader failover on kill, leadership retake on
 * rejoin, and full-RW behavior with election disabled.
 * Skips (plan 1) on non-PROXYSQL31 builds where the master switch is absent.
 */

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

struct node_t {
	int idx;            // 1..3
	int admin_port;     // 16062/16072/16082
	int weight;         // 300/200/100
	string datadir;
	string cnf_path;
	std::atomic<pid_t> pid { -1 };
	std::thread* runner = nullptr;
};

static node_t nodes_def[3];

static string workdir_path;

static void write_node_config(node_t& n) {
	FILE* f = fopen(n.cnf_path.c_str(), "w");
	if (f == NULL) { return; }
	fprintf(f, "datadir=\"%s\"\n", n.datadir.c_str());
	fprintf(f, "admin_variables = {\n");
	fprintf(f, "\tadmin_credentials=\"admin:admin;cluster1:secret1pass\"\n");
	fprintf(f, "\tmysql_ifaces=\"0.0.0.0:%d\"\n", n.admin_port);
	fprintf(f, "\tcluster_username=\"cluster1\"\n");
	fprintf(f, "\tcluster_password=\"secret1pass\"\n");
	fprintf(f, "\tcluster_check_interval_ms=200\n");
	fprintf(f, "\tcluster_leader_election=\"true\"\n");
	fprintf(f, "\tcluster_leader_node_timeout_ms=1000\n");
	fprintf(f, "\tcluster_leader_grace_ms=500\n");
	fprintf(f, "}\n");
	fprintf(f, "mysql_variables = {\n");
	fprintf(f, "\tthreads=2\n");
	fprintf(f, "\tinterfaces=\"0.0.0.0:%d\"\n", n.admin_port + 1);
	fprintf(f, "}\n");
	fprintf(f, "proxysql_servers = (\n");
	for (int i = 0; i < 3; i++) {
		fprintf(f, "\t{ hostname=\"127.0.0.1\"; port=%d; weight=%d; comment=\"node%d\"; }%s\n",
			nodes_def[i].admin_port, nodes_def[i].weight, nodes_def[i].idx, (i < 2 ? "," : ""));
	}
	fprintf(f, ")\n");
	fclose(f);
}

static void spawn_node(node_t& n, bool initial) {
	const string binary = workdir_path + "../../../src/proxysql";
	const string stderr_f = n.datadir + "/node_stderr.txt";
	string cmd = binary + " -f -M -c " + n.cnf_path + " -D " + n.datadir;
	if (initial) { cmd += " --initial"; }
	cmd += " >> " + stderr_f + " 2>&1";
	n.runner = new std::thread([&n, cmd]() {
		pid_t p = fork();
		if (p == 0) { execl("/bin/sh", "sh", "-c", cmd.c_str(), (char*)nullptr); _exit(127); }
		n.pid.store(p);
		int status = 0;
		waitpid(p, &status, 0);
	});
	// give fork+exec a moment before callers start polling the admin port
	usleep(500 * 1000);
}

static void join_node(node_t& n) {
	if (n.runner) { n.runner->join(); delete n.runner; n.runner = nullptr; }
	n.pid.store(-1);
}

static MYSQL* admin_conn(int port) {
	conn_opts_t opts {};
	opts.host = "127.0.0.1";
	opts.user = "admin";
	opts.pass = "admin";
	opts.port = port;
	return wait_for_proxysql(opts, 15);
}

// Returns the admin_port of the row with master='YES' as seen by `conn`,
// or -1 if there is not exactly one leader row.
static int observed_leader(MYSQL* conn) {
	if (mysql_query(conn, "SELECT port, master FROM stats_proxysql_servers_status")) { return -1; }
	MYSQL_RES* res = mysql_store_result(conn);
	if (res == NULL) { return -1; }
	int leader = -1; int leaders = 0;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(res))) {
		if (row[1] && strcasecmp(row[1], "YES") == 0) { leaders++; leader = atoi(row[0]); }
	}
	mysql_free_result(res);
	return (leaders == 1 ? leader : -1);
}

// Polls until `conn` observes `expected_port` as the unique leader.
static bool wait_leader(MYSQL* conn, int expected_port, int timeout_s) {
	for (int i = 0; i < timeout_s * 2; i++) {
		if (observed_leader(conn) == expected_port) { return true; }
		usleep(500 * 1000);
	}
	return false;
}

static bool query_ok(MYSQL* conn, const char* q) {
	return mysql_query(conn, q) == 0;
}

// true if the query FAILED (as expected for a follower); stores the error.
static bool query_refused(MYSQL* conn, const char* q, string& err) {
	if (mysql_query(conn, q) == 0) { err = ""; return false; }
	err = mysql_error(conn);
	return true;
}

static const char* Q_INSERT = "INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (9999, '127.0.0.1', 13306)";
static const char* Q_DELETE = "DELETE FROM mysql_servers WHERE hostgroup_id=9999";
static const char* Q_LOAD   = "LOAD MYSQL SERVERS TO RUNTIME";
static const char* Q_SAVE   = "SAVE MYSQL SERVERS TO DISK";

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("Failed to get the required environmental variables."); return -1; }
	workdir_path = cl.workdir;

	const string base = workdir_path + "test_cluster_leader_election_config";
	mkdir(base.c_str(), 0777);
	for (int i = 0; i < 3; i++) {
		nodes_def[i].idx = i + 1;
		nodes_def[i].admin_port = 16062 + i * 10;
		nodes_def[i].weight = 300 - i * 100;
		nodes_def[i].datadir = base + "/node" + std::to_string(i + 1);
		nodes_def[i].cnf_path = nodes_def[i].datadir + "/node.cnf";
		mkdir(nodes_def[i].datadir.c_str(), 0777);
		write_node_config(nodes_def[i]);
		spawn_node(nodes_def[i], true);
	}

	MYSQL* a1 = admin_conn(nodes_def[0].admin_port);
	MYSQL* a2 = admin_conn(nodes_def[1].admin_port);
	MYSQL* a3 = admin_conn(nodes_def[2].admin_port);
	if (a1 == NULL || a2 == NULL || a3 == NULL) {
		fprintf(stderr, "File %s, line %d, Error: failed to start the 3 cluster nodes\n", __FILE__, __LINE__);
		for (int i = 0; i < 3; i++) {
			pid_t p = nodes_def[i].pid.load();
			if (p > 0) { kill(p, SIGKILL); }
			join_node(nodes_def[i]);
		}
		return -1;
	}

	// Feature detection: skip everything on non-PROXYSQL31 builds.
	bool feature = false;
	if (mysql_query(a1, "SELECT count(*) FROM global_variables WHERE variable_name='admin-cluster_leader_election'") == 0) {
		MYSQL_RES* res = mysql_store_result(a1);
		MYSQL_ROW row = mysql_fetch_row(res);
		feature = (row && row[0] && atoi(row[0]) == 1);
		mysql_free_result(res);
	}
	if (feature == false) {
		plan(1);
		ok(1, "admin-cluster_leader_election not present (non-PROXYSQL31 build) - skipping");
	} else {
		plan(27);
		string err;

		// --- Convergence: all 3 nodes agree node1 (16062) is leader --- (3)
		ok(wait_leader(a1, 16062, 15), "node1 observes node1 as the unique leader");
		ok(wait_leader(a2, 16062, 15), "node2 observes node1 as the unique leader");
		ok(wait_leader(a3, 16062, 15), "node3 observes node1 as the unique leader");

		// --- Leader accepts writes --- (3)
		ok(query_ok(a1, Q_INSERT), "leader accepts INSERT: %s", mysql_error(a1));
		ok(query_ok(a1, Q_LOAD), "leader accepts LOAD TO RUNTIME: %s", mysql_error(a1));
		ok(query_ok(a1, Q_SAVE), "leader accepts SAVE TO DISK: %s", mysql_error(a1));
		query_ok(a1, Q_DELETE); query_ok(a1, Q_LOAD); query_ok(a1, Q_SAVE); // cleanup

		// --- Follower refuses writes --- (3 + 1)
		ok(query_refused(a2, Q_INSERT, err), "follower refuses INSERT (%s)", err.c_str());
		ok(query_refused(a2, Q_LOAD, err), "follower refuses LOAD TO RUNTIME (%s)", err.c_str());
		ok(strstr(err.c_str(), "16062") != NULL, "refusal error names the leader: %s", err.c_str());
		ok(query_refused(a2, Q_SAVE, err), "follower refuses SAVE TO DISK (%s)", err.c_str());

		// --- FORCED_RW override is sticky across election ticks --- (6)
		ok(query_ok(a2, "PROXYSQL READWRITE"), "PROXYSQL READWRITE accepted on follower");
		ok(query_ok(a2, Q_INSERT), "FORCED_RW follower accepts INSERT: %s", mysql_error(a2));
		ok(query_ok(a2, Q_LOAD), "FORCED_RW follower accepts LOAD TO RUNTIME: %s", mysql_error(a2));
		sleep(3); // several election ticks + grace periods
		ok(query_ok(a2, "DELETE FROM mysql_servers WHERE hostgroup_id=9999"), "FORCED_RW sticks across election ticks: %s", mysql_error(a2));
		query_ok(a2, Q_LOAD); // cleanup runtime on node2
		ok(query_ok(a2, "PROXYSQL READONLY AUTO"), "PROXYSQL READONLY AUTO accepted");
		ok(query_refused(a2, Q_INSERT, err), "AUTO follower refuses INSERT again (%s)", err.c_str());

		// --- Leader failover on kill --- (3)
		{
			pid_t p1 = nodes_def[0].pid.load();
			if (p1 > 0) { kill(p1, SIGKILL); }
			join_node(nodes_def[0]);
			mysql_close(a1); a1 = NULL;
		}
		ok(wait_leader(a2, 16072, 15), "after leader kill, node2 observes node2 as leader");
		ok(wait_leader(a3, 16072, 15), "after leader kill, node3 observes node2 as leader");
		ok(query_ok(a2, Q_INSERT), "new leader accepts INSERT: %s", mysql_error(a2));
		query_ok(a2, Q_DELETE); query_ok(a2, Q_LOAD); // cleanup

		// --- Ex-leader rejoins and retakes leadership (highest weight) --- (5)
		spawn_node(nodes_def[0], false); // keep datadir: same uuid, config from db
		a1 = admin_conn(nodes_def[0].admin_port);
		ok(a1 != NULL, "ex-leader restarted and reachable");
		ok(a1 != NULL && wait_leader(a1, 16062, 20), "rejoined node1 observes itself as leader again");
		ok(wait_leader(a2, 16062, 20), "node2 observes node1 as leader again");
		ok(wait_leader(a3, 16062, 20), "node3 observes node1 as leader again");
		ok(query_refused(a2, Q_INSERT, err), "node2 is follower again (%s)", err.c_str());

		// --- Election disabled: everyone read-write --- (3)
		MYSQL* conns[3] = { a1, a2, a3 };
		for (int i = 0; i < 3; i++) {
			if (conns[i] == NULL) { continue; }
			query_ok(conns[i], "PROXYSQL READWRITE");
			query_ok(conns[i], "SET admin-cluster_leader_election='false'");
			query_ok(conns[i], "LOAD ADMIN VARIABLES TO RUNTIME");
			query_ok(conns[i], "PROXYSQL READONLY AUTO");
		}
		sleep(2); // let ticks observe the disable
		ok(query_ok(a1, Q_INSERT), "election disabled: node1 accepts writes: %s", mysql_error(a1));
		ok(query_ok(a2, Q_INSERT), "election disabled: node2 accepts writes: %s", mysql_error(a2));
		ok(query_ok(a3, Q_INSERT), "election disabled: node3 accepts writes: %s", mysql_error(a3));
	}

	// Teardown: shut all nodes down.
	MYSQL* conns[3] = { a1, a2, a3 };
	for (int i = 0; i < 3; i++) {
		if (conns[i]) {
			mysql_query(conns[i], "PROXYSQL SHUTDOWN");
			mysql_close(conns[i]);
		}
		pid_t p = nodes_def[i].pid.load();
		if (p > 0) {
			for (int w = 0; w < 10 && kill(p, 0) == 0; w++) { usleep(500 * 1000); }
			if (kill(p, 0) == 0) { kill(p, SIGKILL); }
		}
		join_node(nodes_def[i]);
	}
	return exit_status();
}
```

- [ ] **Step 2: Build the test binary**

```bash
cd test/tap/tests && make test_cluster_leader_election-t
```
(The `%-t:` wildcard rule at `test/tap/tests/Makefile:266` picks it up — no Makefile edit needed.) Expected: clean compile. Fix any `conn_opts_t`/`wait_for_proxysql` signature mismatches against `test/tap/tap/utils.h:550/567`.

- [ ] **Step 3: Register in groups.json**

Add (same groups as `test_cluster_sync-t`'s core set):
```json
"test_cluster_leader_election-t" : [ "legacy-g5", "mysql84-g5", "mysql90-g5", "mysql95-g5" ],
```
Run the linters:
```bash
python3 test/tap/groups/lint_groups_json.py && python3 test/tap/groups/lint_group_coverage.py
```

- [ ] **Step 4: Run the test through the isolated harness**

The binary under test must be the debug build (`PROXYSQL31=1 make debug` already done in earlier tasks) and the test needs no backends beyond the runner:
```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g5 test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g5 \
  TEST_PY_TAP_INCL="test_cluster_leader_election-t" \
  test/infra/control/run-tests-isolated.bash
```
Expected: `1..27`, all ok. On failure, read the per-node `node_stderr.txt` files under the test's config dir and the test output — do not retry blindly.

- [ ] **Step 5: Run the full unit group + commit**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=unit-tests-g1 test/infra/control/run-tests-isolated.bash 2>&1 | tail -20
git add test/tap/tests/test_cluster_leader_election-t.cpp test/tap/groups/groups.json
git commit -m "test(cluster): E2E leader election test with 3-node self-spawned cluster"
```

---

### Task 9: Final verification sweep

**Files:** none (verification only).

- [ ] **Step 1: Tier-discipline build matrix**

```bash
make clean && make -j$(nproc) 2>&1 | tail -3            # stable tier: must build, feature unenableable
make clean && PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -3   # target tier, debug
PROXYSQL31=1 make build_tap_test_debug 2>&1 | tail -3
```

- [ ] **Step 2: Re-run both new tests**

```bash
cd test/tap/tests/unit && PROXYSQL31=1 make cluster_leader_election_unit-t && ./cluster_leader_election_unit-t
cd ../../../.. || cd /data/rene/proxysql7/proxysql
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g5 \
  TEST_PY_TAP_INCL="test_cluster_leader_election-t" test/infra/control/run-tests-isolated.bash
```

- [ ] **Step 3: Regression spot-check on cluster suite**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g5 \
  TEST_PY_TAP_INCL="test_cluster_sync-t|test_cluster1-t" test/infra/control/run-tests-isolated.bash
```
Expected: both pass (election defaults to off ⇒ no behavior change). Per CLAUDE.md: any failure here gets a root-cause analysis, not a "flaky" label.

- [ ] **Step 4: Commit anything outstanding; leave branch ready for PR**

```bash
git status --short && git log --oneline v3.0..HEAD
```
