# Backup Weight Threshold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When `hostgroup_settings.backup_weight_threshold` is `T > 0`, send traffic only to servers with `weight >= T` until none of those primaries are available, then use servers with `0 < weight < T`.

**Architecture:** Two-pass selection inside `get_random_MySrvC` (MySQL and PgSQL). Config is two JSON keys on existing `hostgroup_settings` (no table alter). `backup_availability` only decides whether to run pass 2; a returned server always passes today’s eligibility filters. Feature, parse, two-pass, and Prometheus counters are `#ifdef PROXYSQL31`. The extracted `ServerSelection.cpp` algorithm (not wired to production) gets the same split so unit tests cover it.

**Tech Stack:** C++17, `nlohmann::json`, prometheus-cpp dyn counters, TAP + `test/tap/tests/unit/`, GNU Make, `PROXYSQL31=1`.

**Spec:** `docs/superpowers/specs/2026-09-23-backup-weight-threshold-design.md`

## Global constraints

- `PROXYSQL31=1` on every `make` in a session. `make clean` before switching tiers.
- `weight = 0` never selected. `T = 0` is a no-op.
- No DDL change to `mysql_hostgroup_attributes` / `pgsql_hostgroup_attributes`.
- Do not wire production `get_random_MySrvC` to `ServerSelection.cpp`.
- Do not add `fallback_hostgroup` or a `backup` server flag.
- TAP via `run-tests-isolated.bash` only. DEBUG binary.
- Do not commit unless the user explicitly asks during execution; commit steps below are for a human/agent that has been told to commit.

## File map

| File | Responsibility |
|---|---|
| `include/ServerSelection.h`, `lib/ServerSelection.cpp` | Pure two-pass + availability (unit tests only) |
| `test/tap/tests/unit/server_selection_unit-t.cpp` | Unit tests for the split |
| `include/Base_HostGroups_Manager.h`, `lib/BaseHGC.cpp` | Attribute fields + defaults |
| `lib/MySQL_HostGroups_Manager.cpp` | Parse JSON; Prometheus scrape |
| `lib/PgSQL_HostGroups_Manager.cpp` | Parse JSON; Prometheus scrape |
| `lib/MyHGC.cpp` | Production two-pass + counter increment |
| `lib/PgSQL_HostGroups_Manager.cpp` (`PgSQL_HGC::get_random_MySrvC`) | Production two-pass + counter increment |
| `include/MySQL_HostGroups_Manager.h`, `include/PgSQL_HostGroups_Manager.h` | Dyn counter enum + scrape maps |
| `test/tap/tests/mysql-backup_weight_threshold-t.cpp` | MySQL TAP |
| `test/tap/tests/pgsql-backup_weight_threshold-t.cpp` | PgSQL TAP |
| `test/tap/groups/groups.json` | Register TAP tests |
| `CHANGELOG.md` | 3.1 user-facing note |

---

### Task 1: Failing unit tests for the weight-tier split

**Files:**
- Modify: `include/ServerSelection.h`
- Modify: `test/tap/tests/unit/server_selection_unit-t.cpp`

- [ ] **Step 1: Extend the extracted API with defaults so existing tests keep compiling**

In `include/ServerSelection.h`, after `ServerCandidate`, add:

```cpp
enum BackupAvailability : int8_t {
	BACKUP_AVAIL_SELECTABLE = 0,
	BACKUP_AVAIL_STATUS = 1,
	BACKUP_AVAIL_CAPACITY = 2
};
```

Change `select_server_from_candidates` to:

```cpp
int select_server_from_candidates(
	const ServerCandidate *candidates,
	int count,
	unsigned int random_seed,
	int64_t backup_weight_threshold = 0,
	BackupAvailability backup_availability = BACKUP_AVAIL_SELECTABLE
);
```

Document: `T = 0` preserves today’s behaviour; `weight = 0` never selected; pass 2 only when no primary is present under `backup_availability`.

- [ ] **Step 2: Add tests (do not implement the algorithm yet)**

In `server_selection_unit-t.cpp`, after `test_mixed_eligibility`, add:

```cpp
static void test_backup_threshold_noop() {
	ServerCandidate candidates[2];
	candidates[0] = make_candidate(0, 100);
	candidates[1] = make_candidate(1, 1);
	int n0 = 0;
	for (int seed = 0; seed < 200; seed++) {
		if (select_server_from_candidates(candidates, 2, seed, 0) == 0) n0++;
	}
	ok(n0 > 0 && n0 < 200, "T=0: low-weight server still selected sometimes");
}

static void test_backup_not_used_when_primary_up() {
	ServerCandidate candidates[2];
	candidates[0] = make_candidate(0, 100);
	candidates[1] = make_candidate(1, 1);
	int pass = 0;
	for (int seed = 0; seed < 200; seed++) {
		if (select_server_from_candidates(candidates, 2, seed, 10) == 0) pass++;
	}
	ok(pass == 200, "T=10: never select weight=1 while primary eligible");
}

static void test_backup_used_when_primary_down() {
	ServerCandidate candidates[2];
	candidates[0] = make_candidate(0, 100);
	candidates[0].status = SERVER_SHUNNED;
	candidates[1] = make_candidate(1, 1);
	int pass = 0;
	for (int seed = 0; seed < 100; seed++) {
		if (select_server_from_candidates(candidates, 2, seed, 10) == 1) pass++;
	}
	ok(pass == 100, "T=10: backup selected when primary not ONLINE");
}

static void test_weight_zero_never_backup() {
	ServerCandidate candidates[2];
	candidates[0] = make_candidate(0, 100);
	candidates[0].status = SERVER_SHUNNED;
	candidates[1] = make_candidate(1, 0);
	ok(select_server_from_candidates(candidates, 2, 1, 10) == -1,
		"weight=0 is never a backup");
}

static void test_all_below_threshold_used() {
	ServerCandidate candidates[2];
	candidates[0] = make_candidate(0, 1);
	candidates[1] = make_candidate(1, 2);
	int r = select_server_from_candidates(candidates, 2, 1, 10);
	ok(r == 0 || r == 1, "all below T: backups used (no deadlock)");
}

static void test_availability_status_busy_primary() {
	ServerCandidate candidates[2];
	candidates[0] = make_candidate(0, 100, 10);
	candidates[0].current_connections = 10;
	candidates[1] = make_candidate(1, 1);
	ok(select_server_from_candidates(candidates, 2, 1, 10, BACKUP_AVAIL_STATUS) == -1,
		"status: ONLINE primary at max_conn does not open backups");
	ok(select_server_from_candidates(candidates, 2, 1, 10, BACKUP_AVAIL_SELECTABLE) == 1,
		"selectable: primary ineligible → backup");
	ok(select_server_from_candidates(candidates, 2, 1, 10, BACKUP_AVAIL_CAPACITY) == 1,
		"capacity: primary at max_conn → backup");
}

static void test_availability_latency_does_not_open_capacity() {
	ServerCandidate candidates[2];
	candidates[0] = make_candidate(0, 100);
	candidates[0].max_latency_us = 1000;
	candidates[0].current_latency_us = 5000;
	candidates[1] = make_candidate(1, 1);
	ok(select_server_from_candidates(candidates, 2, 1, 10, BACKUP_AVAIL_CAPACITY) == -1,
		"capacity: high-latency ONLINE primary with free slots does not open backups");
	ok(select_server_from_candidates(candidates, 2, 1, 10, BACKUP_AVAIL_SELECTABLE) == 1,
		"selectable: high latency → backup");
}

static void test_backup_weighted_among_backups() {
	ServerCandidate candidates[3];
	candidates[0] = make_candidate(0, 100);
	candidates[0].status = SERVER_SHUNNED;
	candidates[1] = make_candidate(1, 3);
	candidates[2] = make_candidate(2, 1);
	int c1 = 0;
	const int N = 4000;
	for (int seed = 0; seed < N; seed++) {
		if (select_server_from_candidates(candidates, 3, seed, 10) == 1) c1++;
	}
	double pct = (double)c1 / N * 100;
	ok(pct > 60 && pct < 90, "backups 3:1: idx 1 selected %.1f%% (expect ~75%%)", pct);
}
```

Update `main()`:

```cpp
	plan(21 + 9);

	// existing 21 assertions (including test_init_minimal)
	test_backup_threshold_noop();                 // 1
	test_backup_not_used_when_primary_up();       // 1
	test_backup_used_when_primary_down();         // 1
	test_weight_zero_never_backup();              // 1
	test_all_below_threshold_used();              // 1
	test_availability_status_busy_primary();      // 3
	test_availability_latency_does_not_open_capacity(); // 2
	test_backup_weighted_among_backups();         // 1
```

`21 + 9 = 30`. Existing tests still call the 3-arg overload (`T=0`).

- [ ] **Step 3: Build and run — new tests must fail**

```bash
PROXYSQL31=1 make -C test/tap/tests/unit -j"$(nproc)" server_selection_unit-t
./test/tap/tests/unit/server_selection_unit-t
```

Expected: `T=10: never select weight=1 while primary eligible` fails (low-weight still chosen). Do not implement yet.

- [ ] **Step 4: Commit if asked**

```bash
git add include/ServerSelection.h test/tap/tests/unit/server_selection_unit-t.cpp
git commit -m "test: cover backup_weight_threshold server selection"
```

---

### Task 2: Implement the extracted two-pass

**Files:**
- Modify: `lib/ServerSelection.cpp`

- [ ] **Step 1: Replace `select_server_from_candidates` body**

Keep `is_candidate_eligible` unchanged. Implement:

```cpp
static bool weight_is_primary(int64_t weight, int64_t T) {
	return weight > 0 && weight >= T;
}

static bool weight_is_backup(int64_t weight, int64_t T) {
	return weight > 0 && weight < T;
}

static bool primary_present(
	const ServerCandidate *candidates,
	int count,
	int64_t T,
	BackupAvailability mode)
{
	for (int i = 0; i < count; i++) {
		const ServerCandidate &c = candidates[i];
		if (!weight_is_primary(c.weight, T)) {
			continue;
		}
		if (mode == BACKUP_AVAIL_SELECTABLE) {
			if (is_candidate_eligible(c)) {
				return true;
			}
		} else if (mode == BACKUP_AVAIL_STATUS) {
			if (c.status == SERVER_ONLINE) {
				return true;
			}
		} else if (mode == BACKUP_AVAIL_CAPACITY) {
			if (c.status == SERVER_ONLINE && c.current_connections < c.max_connections) {
				return true;
			}
		}
	}
	return false;
}

static int select_eligible_in_tier(
	const ServerCandidate *candidates,
	int count,
	unsigned int random_seed,
	int64_t T,
	bool backups)
{
	int64_t total_weight = 0;
	for (int i = 0; i < count; i++) {
		const bool in_tier = backups ? weight_is_backup(candidates[i].weight, T)
					     : weight_is_primary(candidates[i].weight, T);
		if (in_tier && is_candidate_eligible(candidates[i])) {
			total_weight += candidates[i].weight;
		}
	}
	if (total_weight == 0) {
		return -1;
	}
	unsigned int rng_state = random_seed;
	rng_state = rng_state * 1664525u + 1013904223u;
	int64_t target = (int64_t)(rng_state % (uint64_t)total_weight) + 1;
	int64_t cumulative = 0;
	for (int i = 0; i < count; i++) {
		const bool in_tier = backups ? weight_is_backup(candidates[i].weight, T)
					     : weight_is_primary(candidates[i].weight, T);
		if (in_tier && is_candidate_eligible(candidates[i])) {
			cumulative += candidates[i].weight;
			if (cumulative >= target) {
				return candidates[i].index;
			}
		}
	}
	return -1;
}

int select_server_from_candidates(
	const ServerCandidate *candidates,
	int count,
	unsigned int random_seed,
	int64_t backup_weight_threshold,
	BackupAvailability backup_availability)
{
	if (candidates == nullptr || count <= 0) {
		return -1;
	}
	if (backup_weight_threshold <= 0) {
		return select_eligible_in_tier(candidates, count, random_seed, 0, false);
	}
	int idx = select_eligible_in_tier(candidates, count, random_seed, backup_weight_threshold, false);
	if (idx >= 0) {
		return idx;
	}
	if (!primary_present(candidates, count, backup_weight_threshold, backup_availability)) {
		return select_eligible_in_tier(candidates, count, random_seed, backup_weight_threshold, true);
	}
	return -1;
}
```

`T <= 0`: `weight_is_primary` is `weight > 0 && weight >= 0` → all positive weights, same as today.

- [ ] **Step 2: Run unit tests**

```bash
PROXYSQL31=1 make -C test/tap/tests/unit -j"$(nproc)" server_selection_unit-t
./test/tap/tests/unit/server_selection_unit-t
```

Expected: all 30 tests pass.

- [ ] **Step 3: Commit if asked**

```bash
git add lib/ServerSelection.cpp include/ServerSelection.h
git commit -m "feat: two-pass backup weight selection in ServerSelection"
```

---

### Task 3: Hostgroup attribute fields and JSON parse

**Files:**
- Modify: `include/Base_HostGroups_Manager.h` (`attributes` struct ~102–118)
- Modify: `lib/BaseHGC.cpp` (`reset_attributes` ~60–87)
- Modify: `lib/MySQL_HostGroups_Manager.cpp` (`init_myhgc_hostgroup_settings` ~6250–6278)
- Modify: `lib/PgSQL_HostGroups_Manager.cpp` (`init_myhgc_hostgroup_settings` ~3849–3872)

Values: `BACKUP_AVAIL_SELECTABLE = 0`, `STATUS = 1`, `CAPACITY = 2` (same integers as `ServerSelection.h`; do not include that header from `Base_HostGroups_Manager.h`).

- [ ] **Step 1: Fields and defaults**

In `attributes` inside `#ifdef PROXYSQL31`:

```cpp
#ifdef PROXYSQL31
		int64_t backup_weight_threshold;
		int8_t backup_availability;
#endif
```

In `reset_attributes()`, after `default_query_timeout = -1`:

```cpp
#ifdef PROXYSQL31
	attributes.backup_weight_threshold = 0;
	attributes.backup_availability = 0; // selectable
#endif
```

- [ ] **Step 2: Parse MySQL JSON**

Inside the `try` in `init_myhgc_hostgroup_settings` (MySQL), after `default_query_timeout`:

```cpp
#ifdef PROXYSQL31
			const auto backup_weight_threshold_check = [](int64_t v) -> bool {
				return v >= 0 && v <= 10000000;
			};
			const int64_t backup_weight_threshold = j_get_srv_default_int_val<int64_t>(
				j, hid, "backup_weight_threshold", backup_weight_threshold_check);
			if (backup_weight_threshold != static_cast<int64_t>(-1)) {
				myhgc->attributes.backup_weight_threshold = backup_weight_threshold;
			}

			if (j.find("backup_availability") != j.end()) {
				if (j["backup_availability"].type() == json::value_t::string) {
					const std::string mode = j["backup_availability"].get<std::string>();
					if (mode == "selectable") {
						myhgc->attributes.backup_availability = 0;
					} else if (mode == "status") {
						myhgc->attributes.backup_availability = 1;
					} else if (mode == "capacity") {
						myhgc->attributes.backup_availability = 2;
					} else {
						proxy_error(
							"Invalid value '%s' supplied for 'mysql_hostgroup_attributes.hostgroup_settings.backup_availability' for hostgroup %d. Value NOT UPDATED.\n",
							mode.c_str(), hid);
					}
				} else {
					proxy_error(
						"Invalid type supplied for 'mysql_hostgroup_attributes.hostgroup_settings.backup_availability' for hostgroup %d. Value NOT UPDATED.\n",
						hid);
				}
			}
#endif
```

Extend the function `@details` list with the two keys and their ranges.

Mirror the same block in PgSQL `init_myhgc_hostgroup_settings`, using `PgSQL_j_get_srv_default_int_val` and the `pgsql_hostgroup_attributes...` error strings.

Invalid sibling keys must not prevent a valid `backup_weight_threshold` in the same object from applying (parse independently, same as `handle_warnings`).

- [ ] **Step 3: Compile lib**

```bash
PROXYSQL31=1 make -C lib -j"$(nproc)"
```

Expected: success.

- [ ] **Step 4: Commit if asked**

```bash
git add include/Base_HostGroups_Manager.h lib/BaseHGC.cpp lib/MySQL_HostGroups_Manager.cpp lib/PgSQL_HostGroups_Manager.cpp
git commit -m "feat: parse backup_weight_threshold hostgroup_settings"
```

---

### Task 4: Production two-pass in `MyHGC::get_random_MySrvC`

**Files:**
- Modify: `lib/MyHGC.cpp`
- Modify: `include/Base_HostGroups_Manager.h` (atomic counter)

- [ ] **Step 1: Counter on the hostgroup**

In `BaseHGC`, next to `num_online_servers`, inside `#ifdef PROXYSQL31`:

```cpp
#ifdef PROXYSQL31
	std::atomic<uint64_t> backup_servers_selected;
#endif
```

Initialize to `0` in `BaseHGC::BaseHGC` (same file as the constructor in `lib/BaseHGC.cpp`).

- [ ] **Step 2: Tier filter before desperate unshun**

In `lib/MyHGC.cpp`, add file-scope helpers inside `#ifdef PROXYSQL31` (anonymous namespace):

```cpp
#ifdef PROXYSQL31
namespace {

bool mysql_weight_is_primary(int weight, int64_t T) {
	return weight > 0 && static_cast<int64_t>(weight) >= T;
}

bool mysql_primary_present(MyHGC *hgc, int64_t T, int8_t mode) {
	const unsigned int n = hgc->mysrvs->cnt();
	for (unsigned int i = 0; i < n; i++) {
		MySrvC *s = hgc->mysrvs->idx(i);
		if (!mysql_weight_is_primary(s->weight, T)) {
			continue;
		}
		if (mode == 0) { // selectable: handled via candidate list
			continue;
		} else if (mode == 1) { // status
			if (s->get_status() == MYSQL_SERVER_STATUS_ONLINE) {
				return true;
			}
		} else if (mode == 2) { // capacity
			if (s->get_status() == MYSQL_SERVER_STATUS_ONLINE &&
				s->ConnectionsUsed->conns_length() < s->max_connections) {
				return true;
			}
		}
	}
	return false;
}

void mysql_compact_candidates(
	MySrvC **cands, unsigned int &num, unsigned int &sum, unsigned int &used,
	int64_t T, bool backups)
{
	unsigned int w = 0, u = 0, n = 0;
	for (unsigned int i = 0; i < num; i++) {
		MySrvC *s = cands[i];
		const bool keep = backups
			? (s->weight > 0 && static_cast<int64_t>(s->weight) < T)
			: mysql_weight_is_primary(s->weight, T);
		if (keep) {
			cands[n++] = s;
			w += s->weight;
			u += s->ConnectionsUsed->conns_length();
		}
	}
	num = n;
	sum = w;
	used = u;
}

void mysql_apply_backup_weight_threshold(
	MyHGC *hgc, MySrvC **cands, unsigned int &num, unsigned int &sum, unsigned int &used,
	bool &used_backup)
{
	used_backup = false;
	const int64_t T = hgc->attributes.backup_weight_threshold;
	if (T <= 0) {
		return;
	}
	unsigned int pri_sum = 0;
	for (unsigned int i = 0; i < num; i++) {
		if (mysql_weight_is_primary(cands[i]->weight, T)) {
			pri_sum += cands[i]->weight;
		}
	}
	if (pri_sum > 0) {
		mysql_compact_candidates(cands, num, sum, used, T, false);
		return;
	}
	const int8_t mode = hgc->attributes.backup_availability;
	bool present = (mode == 0) ? false : mysql_primary_present(hgc, T, mode);
	if (!present) {
		mysql_compact_candidates(cands, num, sum, used, T, true);
		used_backup = (num > 0);
		return;
	}
	mysql_compact_candidates(cands, num, sum, used, T, false);
}

}
#endif
```

In `get_random_MySrvC`, declare `bool used_backup = false;` next to `num_candidates`.

After the candidate-building `for (j=0; j<l; j++)` loop ends (after Aurora replica filter, **before** `if (sum==0)` desperate unshun ~line 186):

```cpp
#ifdef PROXYSQL31
		mysql_apply_backup_weight_threshold(this, mysrvcCandidates, num_candidates, sum, TotalUsedConn, used_backup);
#endif
```

When returning a server (~line 347), if `used_backup`:

```cpp
#ifdef PROXYSQL31
				if (used_backup) {
					backup_servers_selected.fetch_add(1, std::memory_order_relaxed);
					static time_t last_backup_log = 0;
					time_t now = time(NULL);
					if (now - last_backup_log > 1) {
						last_backup_log = now;
						proxy_warning("Hostgroup %u: selecting backup-weight server %s:%d\n",
							hid, mysrvc->address, mysrvc->port);
					}
				}
#endif
```

Do not run the tier filter again after desperate unshun.

- [ ] **Step 3: Compile**

```bash
PROXYSQL31=1 make -C lib -j"$(nproc)"
```

- [ ] **Step 4: Commit if asked**

```bash
git add lib/MyHGC.cpp include/Base_HostGroups_Manager.h lib/BaseHGC.cpp
git commit -m "feat: apply backup_weight_threshold in MySQL get_random_MySrvC"
```

---

### Task 5: Production two-pass in `PgSQL_HGC::get_random_MySrvC`

**Files:**
- Modify: `lib/PgSQL_HostGroups_Manager.cpp` (`get_random_MySrvC` ~1966)

- [ ] **Step 1: PgSQL helpers and call sites**

In an anonymous namespace in this file (`#ifdef PROXYSQL31`), add `pgsql_weight_is_primary`, `pgsql_primary_present`, `pgsql_compact_candidates`, `pgsql_apply_backup_weight_threshold` with the same control flow as Task 4, substituting:

- `MyHGC` → `PgSQL_HGC`, `MySrvC` → `PgSQL_SrvC`
- `s->get_status()` → `s->status`
- `MYSQL_SERVER_STATUS_ONLINE` stays (PgSQL uses the same enum)

In `PgSQL_HGC::get_random_MySrvC`: `bool used_backup = false;`. After the candidate-building loop and before `if (sum==0)` desperate unshun, call `pgsql_apply_backup_weight_threshold(this, mysrvcCandidates, num_candidates, sum, TotalUsedConn, used_backup);`. On the successful return of a server, if `used_backup`, `backup_servers_selected.fetch_add(1)` and the same 1-second `proxy_warning`.

`BaseHGC` already has the atomic from Task 4.

- [ ] **Step 2: Compile**

```bash
PROXYSQL31=1 make -C lib -j"$(nproc)"
```

- [ ] **Step 3: Commit if asked**

```bash
git add lib/PgSQL_HostGroups_Manager.cpp
git commit -m "feat: apply backup_weight_threshold in PgSQL get_random_MySrvC"
```

---

### Task 6: Prometheus counters

**Files:**
- Modify: `include/MySQL_HostGroups_Manager.h` (`p_hg_dyn_counter`, `status` maps)
- Modify: `include/PgSQL_HostGroups_Manager.h` (same)
- Modify: `lib/MySQL_HostGroups_Manager.cpp` (metrics map + `p_update_metrics`)
- Modify: `lib/PgSQL_HostGroups_Manager.cpp` (same)

- [ ] **Step 1: Enum and map**

In `p_hg_dyn_counter` inside the existing `#ifdef PROXYSQL31` block, add:

```cpp
		hostgroup_backup_server_selected,
```

In `status`, next to `p_hostgroup_pool_acquisitions_map`:

```cpp
		std::map<std::string, prometheus::Counter*> p_hostgroup_backup_server_selected_map {};
```

In the dyn-counter vector, next to `hostgroup_pool_wait_time`:

```cpp
		std::make_tuple (
			p_hg_dyn_counter::hostgroup_backup_server_selected,
			"proxysql_mysql_hostgroup_backup_server_selected_total",
			"Times a backup-weight server was selected because no primary was available.",
			metric_tags {{ "protocol", "mysql" }}
		)
```

In `p_update_metrics`, in the existing PROXYSQL31 hostgroup-label block (~3485), after the pool stats updates:

```cpp
		p_update_map_counter(status.p_hostgroup_backup_server_selected_map,
			status.p_dyn_counter_array[p_hg_dyn_counter::hostgroup_backup_server_selected],
			hostgroup_id, labels, myhgc->backup_servers_selected.load(std::memory_order_relaxed));
```

Mirror for PgSQL: metric name `proxysql_pgsql_hostgroup_backup_server_selected_total`, tag `protocol=pgsql`.

- [ ] **Step 2: Compile**

```bash
PROXYSQL31=1 make -j"$(nproc)"
```

Expected: `src/proxysql` links.

- [ ] **Step 3: Commit if asked**

```bash
git add include/MySQL_HostGroups_Manager.h include/PgSQL_HostGroups_Manager.h lib/MySQL_HostGroups_Manager.cpp lib/PgSQL_HostGroups_Manager.cpp
git commit -m "feat: Prometheus counters for backup-weight selection"
```

---

### Task 7: MySQL TAP

**Files:**
- Create: `test/tap/tests/mysql-backup_weight_threshold-t.cpp`
- Modify: `test/tap/groups/groups.json`

Pattern: `test/tap/tests/test_hostgroup_default_query_timeout-t.cpp` (discover backends, dedicated HG, restore on exit). Prometheus: `SHOW PROMETHEUS METRICS\\G` + `parse_prometheus_metrics` from `test/tap/tap/utils.h` (see `test_prometheus_metrics-t.cpp`).

- [ ] **Step 1: Write the test**

Dedicated hostgroup `9001`. Unique query `SELECT 1 /*backup_wt_9001*/`. Two distinct `(hostname,port)` from `runtime_mysql_servers`. Weights 100 and 1. JSON `{"backup_weight_threshold":10,"backup_availability":"selectable"}`. Query rule `destination_hostgroup=9001`. Restore servers, rules, attributes in a destructor/cleanup.

Assertions:

1. After `SELECT * FROM stats.stats_mysql_connection_pool_reset` and 30 queries: Queries on weight-100 `> 0`, Queries on weight-1 `== 0`.
2. Prometheus `proxysql_mysql_hostgroup_backup_server_selected_total{hostgroup="9001"}` is missing or `0`.
3. `UPDATE mysql_servers SET status='OFFLINE_SOFT'` on the weight-100 row; `LOAD MYSQL SERVERS TO RUNTIME`; 30 more queries: Queries on weight-1 increase; Prometheus counter `>= 30`.
4. Set weight-100 back `ONLINE`; `LOAD`; 30 more queries: new Queries go to weight-100, not weight-1.
5. Invalid JSON: `hostgroup_settings='{"backup_weight_threshold":-1,"backup_availability":"selectable"}'` then `LOAD MYSQL SERVERS TO RUNTIME` — runtime still has previous threshold (traffic still prefers weight 100). Then `{"backup_weight_threshold":10,"backup_availability":"nope"}` — availability stays `selectable` (busy-primary behaviour not required here; just confirm LOAD succeeds and threshold 10 still applies).

If fewer than two backends exist, `BAIL_OUT`.

- [ ] **Step 2: Register**

In `test/tap/groups/groups.json` (alphabetical):

```json
  "mysql-backup_weight_threshold-t" : [ "mysql84-g1","@proxysql_min_version:3.1" ],
```

No extra Makefile target (pattern rule).

- [ ] **Step 3: Build TAP binary and run isolated**

DEBUG `PROXYSQL31=1` tree. Recreate ProxySQL container after rebuild (`start-proxysql-isolated.bash`).

```bash
PROXYSQL31=1 make -C test/tap/tests -j"$(nproc)" mysql-backup_weight_threshold-t
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=mysql84-g1 \
  TEST_PY_TAP_INCL="mysql-backup_weight_threshold-t" \
  test/infra/control/run-tests-isolated.bash
```

Expected: all TAP assertions pass.

- [ ] **Step 4: Commit if asked**

```bash
git add test/tap/tests/mysql-backup_weight_threshold-t.cpp test/tap/groups/groups.json
git commit -m "test: MySQL TAP for backup_weight_threshold"
```

---

### Task 8: PgSQL TAP

**Files:**
- Create: `test/tap/tests/pgsql-backup_weight_threshold-t.cpp`
- Modify: `test/tap/groups/groups.json`

Same scenario on PostgreSQL: `pgsql_servers`, `pgsql_hostgroup_attributes`, `pgsql_query_rules`, `stats_pgsql_connection_pool`, metric `proxysql_pgsql_hostgroup_backup_server_selected_total`. Follow `pgsql-hostgroup_default_query_timeout-t.cpp` for admin/pgsql connections.

```json
  "pgsql-backup_weight_threshold-t" : [ "legacy-g4","@proxysql_min_version:3.1" ],
```

```bash
PROXYSQL31=1 make -C test/tap/tests -j"$(nproc)" pgsql-backup_weight_threshold-t
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-backup_weight_threshold-t" \
  test/infra/control/run-tests-isolated.bash
```

- [ ] **Step 1: Write test**
- [ ] **Step 2: Register and run**
- [ ] **Step 3: Commit if asked**

```bash
git add test/tap/tests/pgsql-backup_weight_threshold-t.cpp test/tap/groups/groups.json
git commit -m "test: PgSQL TAP for backup_weight_threshold"
```

---

### Task 9: Docs

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `@details` on both `init_myhgc_hostgroup_settings` (if not done in Task 3)

- [ ] **Step 1: CHANGELOG**

Under Unreleased, a 3.1-only bullet:

```
- `hostgroup_settings.backup_weight_threshold` / `backup_availability`: servers with
  `0 < weight < T` are selected only when no primary (`weight >= T`) is available
  in the same hostgroup (MySQL and PostgreSQL). Default `T=0` is a no-op.
  `weight=0` remains never selected. PROXYSQL31 only.
```

Also document the two Prometheus metric names.

- [ ] **Step 2: Commit if asked**

```bash
git add CHANGELOG.md lib/MySQL_HostGroups_Manager.cpp lib/PgSQL_HostGroups_Manager.cpp
git commit -m "docs: backup_weight_threshold hostgroup_settings"
```

---

## Spec coverage

| Spec requirement | Task |
|---|---|
| JSON keys, no table alter | 3 |
| `T=0` no-op, `weight=0` never | 1, 2, 4, 5, 7, 8 |
| Two-pass, backups before desperate unshun | 4, 5 |
| `selectable` / `status` / `capacity` | 1, 2, 4, 5 |
| Both protocols | 3–8 |
| `PROXYSQL31` only | 3–6, TAP min version |
| Prometheus counters | 6, 7, 8 |
| Rate-limited warning | 4, 5 |
| Unit tests | 1, 2 |
| TAP MySQL + PgSQL | 7, 8 |
| Invalid JSON leaves field | 3, 7 |
| Not fallback HG / not backup flag | non-goal, no task |
| `ServerSelection.cpp` not wired to production | 2 vs 4/5 |
