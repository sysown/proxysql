# Cluster Stats Aggregation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The cluster leader replicates every node's TSDB samples into its own `tsdb_metrics_cluster` table (pull + watermark over the admin channel), per spec `docs/superpowers/specs/2026-08-11-cluster-stats-aggregation-design.md`.

**Architecture:** Pure watermark/fetch planning in new files (`TSDB_Cluster_Aggregator.{h,cpp}`); an aggregator worker thread owned by `ProxySQL_Statistics`, started/stopped by a cheap check in the Admin main loop on leadership transitions; peers queried via `stats_history.tsdb_metrics` over MySQL connections using cluster credentials; self replicated via local `INSERT OR IGNORE ... SELECT`. Query surface: `node=` param on `/api/tsdb/query`, new `/api/tsdb/nodes`, status extension, minimal dashboard node selector.

**Tech Stack:** C++17, pthreads + `std::atomic`, SQLite3 (`statsdb_disk`), libmariadb, libhttpserver, TAP tests.

## Global Constraints

- Branch: `feat/cluster-stats-aggregation` (stacked on `feat/cluster-leader-election`). Build with `PROXYSQL31=1` on EVERY make (never bare `make`); after editing any header, `touch src/*.cpp` before an incremental build (src/Makefile lacks header-dep tracking). Before running cluster TAP tests after making commits, do a full `make clean && PROXYSQL31=1 make debug` (per-TU version-string skew otherwise makes nodes refuse to cluster — see memory `build-version-skew`).
- ALL new TSDB code lives inside the existing `#ifdef PROXYSQLTSDB` regions. No new tier flags. The pure planner files compile unconditionally (like `ProxySQL_Cluster_Leader.cpp`).
- New variables (TSDB family, exact names/defaults/ranges from spec — defaults are provisional placeholders pending sizing data): `tsdb-cluster_aggregation`=1 (0/1), `tsdb-cluster_interval`=10 (5–300 s), `tsdb-cluster_backfill_hours`=24 (0–168), `tsdb-cluster_retention_days`=3 (1–30), `tsdb-cluster_batch_rows`=10000 (1000–100000).
- Node identity in the cluster table: `hostname:port` exactly as in `proxysql_servers`. UUID is NOT used.
- Ingest uses `INSERT OR IGNORE` (replicated samples immutable; PK makes replication idempotent).
- The aggregator writes only via internal `statsdb_disk` handles — admin read-only mode never applies to it. Cluster-monitor connection options are copied verbatim (1s connect timeout, SSL enforce, keylog callback); no read/write timeouts.
- Tabs for indentation; match surrounding idioms (this module uses `strtol` validation, `SAFE_SQLITE3_STEP2`, explicit BEGIN/COMMIT batching).
- Commit after every task.

---

### Task 1: Pure watermark/fetch planner + unit test

**Files:**
- Create: `include/TSDB_Cluster_Aggregator.h`
- Create: `lib/TSDB_Cluster_Aggregator.cpp`
- Modify: `lib/Makefile:91` (add `TSDB_Cluster_Aggregator.oo` to `_OBJ_CXX`, after `ProxySQL_Cluster_Leader.oo`)
- Create: `test/tap/tests/unit/tsdb_cluster_aggregator_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile` `UNIT_TESTS :=` list (line ~387)
- Modify: `test/tap/groups/groups.json` (register in `unit-tests-g1`, alphabetical)

**Interfaces:**
- Consumes: nothing.
- Produces (used by Task 3):
  - `long tsdb_agg_effective_watermark(long existing_max_ts, long now, int backfill_hours)` — start-point for a node: `max(existing_max_ts, now - backfill_hours*3600)`; `existing_max_ts <= 0` means "none yet".
  - `struct Tsdb_Agg_Fetch_Result { long new_watermark; bool caught_up; };`
  - `Tsdb_Agg_Fetch_Result tsdb_agg_apply_fetch(long prev_watermark, int rows_fetched, long last_row_ts, int limit)` — 0 rows → watermark unchanged, caught_up; `rows < limit` → watermark=last_row_ts, caught_up; `rows == limit` → watermark=last_row_ts, NOT caught_up.

- [ ] **Step 1: Write the failing unit test**

Create `test/tap/tests/unit/tsdb_cluster_aggregator_unit-t.cpp`:

```cpp
/**
 * @file tsdb_cluster_aggregator_unit-t.cpp
 * @brief Unit tests for the pure TSDB cluster aggregation planner
 *  (effective watermark + fetch-result bookkeeping).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "TSDB_Cluster_Aggregator.h"

int main() {
	plan(11);

	const long now = 1000000000L;

	// --- tsdb_agg_effective_watermark (5 oks) ---
	ok(tsdb_agg_effective_watermark(0, now, 24) == now - 24*3600,
		"no existing data: watermark = now - backfill horizon");
	ok(tsdb_agg_effective_watermark(-1, now, 24) == now - 24*3600,
		"negative existing max treated as none");
	ok(tsdb_agg_effective_watermark(now - 100, now, 24) == now - 100,
		"recent existing max wins over horizon");
	ok(tsdb_agg_effective_watermark(now - 200000, now, 24) == now - 24*3600,
		"stale existing max (deposed leader) clamped forward to horizon");
	ok(tsdb_agg_effective_watermark(now - 100, now, 0) == now,
		"zero backfill hours: horizon is now (no history pulled)");

	// --- tsdb_agg_apply_fetch (6 oks) ---
	Tsdb_Agg_Fetch_Result r = tsdb_agg_apply_fetch(500, 0, 0, 1000);
	ok(r.new_watermark == 500 && r.caught_up == true,
		"empty fetch: watermark unchanged, caught up");

	r = tsdb_agg_apply_fetch(500, 999, 750, 1000);
	ok(r.new_watermark == 750, "partial fetch advances watermark to last row ts");
	ok(r.caught_up == true, "partial fetch (rows < limit) means caught up");

	r = tsdb_agg_apply_fetch(500, 1000, 800, 1000);
	ok(r.new_watermark == 800, "full fetch advances watermark to last row ts");
	ok(r.caught_up == false, "full fetch (rows == limit) means more to pull");

	r = tsdb_agg_apply_fetch(500, 1, 501, 1000);
	ok(r.new_watermark == 501 && r.caught_up == true,
		"single-row fetch advances and completes");

	return exit_status();
}
```

- [ ] **Step 2: Header + failing stub, verify FAIL**

Create `include/TSDB_Cluster_Aggregator.h`:

```cpp
#ifndef __CLASS_TSDB_CLUSTER_AGGREGATOR_H
#define __CLASS_TSDB_CLUSTER_AGGREGATOR_H

// Pure planning logic for TSDB cluster aggregation (leader pulls peers'
// tsdb_metrics with a per-node watermark). Kept dependency-free so it is
// unit-testable in every tier.

struct Tsdb_Agg_Fetch_Result {
	long new_watermark = 0;
	bool caught_up = false;
};

// Start-point for replicating a node: the max timestamp already replicated,
// clamped forward to the backfill horizon (now - backfill_hours).
// existing_max_ts <= 0 means "nothing replicated yet".
long tsdb_agg_effective_watermark(long existing_max_ts, long now, int backfill_hours);

// Bookkeeping after one fetch of up to `limit` rows ordered by timestamp,
// where `last_row_ts` is the max timestamp among the fetched rows
// (ignored when rows_fetched == 0).
Tsdb_Agg_Fetch_Result tsdb_agg_apply_fetch(long prev_watermark, int rows_fetched, long last_row_ts, int limit);

#endif // __CLASS_TSDB_CLUSTER_AGGREGATOR_H
```

Create `lib/TSDB_Cluster_Aggregator.cpp` as a failing stub:

```cpp
#include "TSDB_Cluster_Aggregator.h"

long tsdb_agg_effective_watermark(long existing_max_ts, long now, int backfill_hours) {
	(void)existing_max_ts; (void)now; (void)backfill_hours;
	return 0;
}

Tsdb_Agg_Fetch_Result tsdb_agg_apply_fetch(long prev_watermark, int rows_fetched, long last_row_ts, int limit) {
	(void)prev_watermark; (void)rows_fetched; (void)last_row_ts; (void)limit;
	return Tsdb_Agg_Fetch_Result {};
}
```

Edit `lib/Makefile` `_OBJ_CXX` (line ~91): insert `TSDB_Cluster_Aggregator.oo` right after `ProxySQL_Cluster_Leader.oo`. Edit `test/tap/tests/unit/Makefile`: add `tsdb_cluster_aggregator_unit-t` to `UNIT_TESTS` (generic `%-t:` rule handles the build).

Run:
```bash
cd /data/rene/proxysql7/proxysql && PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -3
cd test/tap/tests/unit && PROXYSQL31=1 make tsdb_cluster_aggregator_unit-t && ./tsdb_cluster_aggregator_unit-t
```
Expected: builds; multiple `not ok`.

- [ ] **Step 3: Implement**

```cpp
#include "TSDB_Cluster_Aggregator.h"

long tsdb_agg_effective_watermark(long existing_max_ts, long now, int backfill_hours) {
	long horizon = now - (long)backfill_hours * 3600L;
	if (existing_max_ts > horizon) {
		return existing_max_ts;
	}
	return horizon;
}

Tsdb_Agg_Fetch_Result tsdb_agg_apply_fetch(long prev_watermark, int rows_fetched, long last_row_ts, int limit) {
	Tsdb_Agg_Fetch_Result r;
	if (rows_fetched == 0) {
		r.new_watermark = prev_watermark;
		r.caught_up = true;
		return r;
	}
	r.new_watermark = last_row_ts;
	r.caught_up = (rows_fetched < limit);
	return r;
}
```

- [ ] **Step 4: Run test — expect PASS (1..11 all ok)**

- [ ] **Step 5: Register + lint + commit**

groups.json (alphabetical, compact one-line style): `"tsdb_cluster_aggregator_unit-t" : [ "unit-tests-g1" ],`

```bash
python3 test/tap/groups/lint_groups_json.py
git add include/TSDB_Cluster_Aggregator.h lib/TSDB_Cluster_Aggregator.cpp lib/Makefile \
  test/tap/tests/unit/tsdb_cluster_aggregator_unit-t.cpp test/tap/tests/unit/Makefile test/tap/groups/groups.json
git commit -m "feat(tsdb): pure watermark/fetch planner for cluster aggregation"
```

---

### Task 2: Schema, variables, retention

**Files:**
- Modify: `include/ProxySQL_Statistics.hpp` (schema define after :111; variables struct :158-165)
- Modify: `lib/ProxySQL_Statistics.cpp` (defaults :147-153; meta table :157-168; `set_variable` :170-191; `get_variable` :193-213; table registration ~:297; index ~:327; `tsdb_retention_cleanup` :1590-1615)
- Modify: `test/tap/tests/test_tsdb_variables-t.cpp:119` (runtime `tsdb-%` count 5 → 10; scan the file for other hardcoded counts/lists of tsdb variables and update all of them)

**Interfaces:**
- Consumes: nothing.
- Produces (used by Tasks 3, 4, 6): table `tsdb_metrics_cluster(node, timestamp, metric_name, labels, value)` in `statsdb_disk` AND `statsdb_mem` (both are built from `tables_defs_statsdb_disk`); `variables.tsdb_cluster_aggregation`, `variables.tsdb_cluster_interval`, `variables.tsdb_cluster_backfill_hours`, `variables.tsdb_cluster_retention_days`, `variables.tsdb_cluster_batch_rows` (all `int`).

- [ ] **Step 1: Schema define + registration + index**

`include/ProxySQL_Statistics.hpp` after the `STATSDB_SQLITE_TABLE_TSDB_BACKEND_HEALTH` define (:111):

```c
#define STATSDB_SQLITE_TABLE_TSDB_METRICS_CLUSTER "CREATE TABLE IF NOT EXISTS tsdb_metrics_cluster (node VARCHAR NOT NULL , timestamp INTEGER NOT NULL , metric_name VARCHAR NOT NULL , labels VARCHAR NOT NULL DEFAULT '{}' , value REAL , PRIMARY KEY (node, timestamp, metric_name, labels)) WITHOUT ROWID"
```

(Match the exact `CREATE TABLE` prefix style of the sibling defines — check whether they use `IF NOT EXISTS`; mirror them.)

`lib/ProxySQL_Statistics.cpp` in `init()` next to the other three (`~:297`):
```cpp
	insert_into_tables_defs(tables_defs_statsdb_disk,"tsdb_metrics_cluster", STATSDB_SQLITE_TABLE_TSDB_METRICS_CLUSTER);
```
Index next to the others (~:327):
```cpp
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_tsdb_metrics_cluster_node_metric_time ON tsdb_metrics_cluster (node, metric_name, timestamp)");
```
No schema-upgrade block (brand-new table).

- [ ] **Step 2: Variables**

`include/ProxySQL_Statistics.hpp` variables struct (:158-165), add:
```cpp
		int tsdb_cluster_aggregation;
		int tsdb_cluster_interval;
		int tsdb_cluster_backfill_hours;
		int tsdb_cluster_retention_days;
		int tsdb_cluster_batch_rows;
```

`lib/ProxySQL_Statistics.cpp` ctor defaults (:147-153):
```cpp
	variables.tsdb_cluster_aggregation = 1;
	variables.tsdb_cluster_interval = 10;
	variables.tsdb_cluster_backfill_hours = 24;
	variables.tsdb_cluster_retention_days = 3;
	variables.tsdb_cluster_batch_rows = 10000;
```

Meta table (:157-168) — append BEFORE the `{NULL,0,0}` terminator (names are WITHOUT the `tsdb-` prefix):
```c
	{"cluster_aggregation", 0, 1},
	{"cluster_interval", 5, 300},
	{"cluster_backfill_hours", 0, 168},
	{"cluster_retention_days", 1, 30},
	{"cluster_batch_rows", 1000, 100000},
```

`set_variable` (:170-191) dispatches by POSITIONAL index — existing entries are `i==0..4`; append:
```cpp
	} else if (i == 5) {
		variables.tsdb_cluster_aggregation = (int)v;
	} else if (i == 6) {
		variables.tsdb_cluster_interval = (int)v;
	} else if (i == 7) {
		variables.tsdb_cluster_backfill_hours = (int)v;
	} else if (i == 8) {
		variables.tsdb_cluster_retention_days = (int)v;
	} else if (i == 9) {
		variables.tsdb_cluster_batch_rows = (int)v;
	}
```
(Match the exact local variable names in the function — the parsed value variable may not be called `v`; anchor on the `i == 4` branch and continue the pattern.)

`get_variable` (:193-213) — add the five `strcasecmp` branches following the existing shape, e.g.:
```cpp
	if (!strcasecmp(name, "cluster_aggregation")) {
		sprintf(buf, "%d", variables.tsdb_cluster_aggregation);
		return strdup(buf);
	}
```
(one per variable; match the actual buffer name in the function).

`get_variables_list`/`has_variable`/Admin flush paths are auto-derived from the meta table — no other edits.

- [ ] **Step 3: Retention**

`tsdb_retention_cleanup()` (:1590-1615) — add after the existing three DELETEs, same `snprintf`+`execute` pattern:
```cpp
	const int cluster_retention_days = std::max(1, variables.tsdb_cluster_retention_days);
	snprintf(delete_buf, sizeof(delete_buf), "DELETE FROM tsdb_metrics_cluster WHERE timestamp < %ld", ts - 86400L*cluster_retention_days);
	statsdb_disk->execute(delete_buf);
```

- [ ] **Step 4: Update the tsdb variables test**

`test/tap/tests/test_tsdb_variables-t.cpp`: line ~119 asserts the runtime `tsdb-%` variable count is `"5"` — change to `"10"`. Grep the file for `5` in variable-count contexts, any enumerated variable-name lists, and any plan-count that depends on the variable count; update consistently.

- [ ] **Step 5: Build, verify, commit**

```bash
PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -3
```
Scratch instance (ports 16032/16033, `--initial`; recipe: minimal cnf with datadir + admin_variables { admin_credentials="admin:admin" mysql_ifaces="0.0.0.0:16032" } + mysql_variables { interfaces="0.0.0.0:16033" }):
- `SELECT variable_name, variable_value FROM global_variables WHERE variable_name LIKE 'tsdb-cluster%'` → 5 rows with the defaults.
- `SET tsdb-cluster_interval='3'; LOAD TSDB VARIABLES TO RUNTIME;` → value rejected (below range floor 5, stays 10); `SET tsdb-cluster_interval='30'` → accepted.
- `SELECT COUNT(*) FROM stats_history.tsdb_metrics_cluster` → 0 rows, no error.

```bash
git add include/ProxySQL_Statistics.hpp lib/ProxySQL_Statistics.cpp test/tap/tests/test_tsdb_variables-t.cpp
git commit -m "feat(tsdb): tsdb_metrics_cluster table, cluster aggregation variables, retention"
```

---

### Task 3: Aggregator engine (worker thread + replication cycle)

**Files:**
- Modify: `include/ProxySQL_Statistics.hpp` (members + method declarations, `#ifdef PROXYSQLTSDB` region; includes `<atomic>`, `<pthread.h>` if missing)
- Modify: `lib/ProxySQL_Statistics.cpp` (thread fn, lifecycle check, cycle, self/peer replication; `#include "TSDB_Cluster_Aggregator.h"`, `#include "ProxySQL_Cluster.hpp"`, `extern ProxySQL_Cluster* GloProxyCluster;`; also `#include "proxysql_sslkeylog.h"` if `proxysql_keylog_write_line_callback` needs it — check how `ProxySQL_Cluster.cpp` gets it)
- Modify: `lib/ProxySQL_Admin.cpp:2637` (invoke the lifecycle check inside the PROXYSQLTSDB block, before `#endif`)

**Interfaces:**
- Consumes: Task 1 planner functions; Task 2 table + variables; from the leader-election branch: `GloProxyCluster->is_leader()`, `get_leader_info(std::string&,int&,std::string&)`, `dump_table_proxysql_servers()` (SQLite3_result*, 4 TEXT cols hostname/port/weight/comment, caller deletes), `get_credentials()` → `cluster_creds_t{ std::string user, pass; }` (empty user = clustering off).
- Produces (used by Task 4): `std::atomic<bool> tsdb_agg_active`, `std::atomic<long long> tsdb_agg_rows_total`, `std::atomic<long long> tsdb_agg_last_cycle_ts`, `std::atomic<bool> tsdb_agg_cap_hit_last_cycle` (public members, read by status/REST); method `void tsdb_cluster_aggregation_check(unsigned long long curtime)` (called from admin loop).

- [ ] **Step 1: Declarations**

`include/ProxySQL_Statistics.hpp`, inside the class's `#ifdef PROXYSQLTSDB` region — private members (next to `next_timer_tsdb_*`, :132-141):

```cpp
	unsigned long long next_timer_tsdb_cluster_check = 0;
	pthread_t tsdb_agg_thread;
	bool tsdb_agg_thread_started = false;       // only touched by the admin main loop thread
	std::atomic<bool> tsdb_agg_stop { false };
	sqlite3_stmt *stmt_insert_tsdb_cluster_metric = NULL;
```

Public members + declarations (next to the loop declarations, :254-262):

```cpp
	std::atomic<bool> tsdb_agg_active { false };            // thread running (read by REST)
	std::atomic<long long> tsdb_agg_rows_total { 0 };       // rows replicated since start
	std::atomic<long long> tsdb_agg_last_cycle_ts { 0 };    // unix ts of last completed cycle
	std::atomic<bool> tsdb_agg_cap_hit_last_cycle { false };
	void tsdb_cluster_aggregation_check(unsigned long long curtime);
	void tsdb_cluster_aggregation_thread_loop();            // thread body (public for the C trampoline)
	SQLite3_result * get_tsdb_cluster_nodes();              // implemented in Task 4
private:
	void tsdb_cluster_aggregation_cycle();
	long tsdb_cluster_node_max_ts(const std::string& node);
	void tsdb_cluster_replicate_self(const std::string& node, long watermark, int limit);
	bool tsdb_cluster_replicate_peer(const std::string& host, int port, const std::string& node, long watermark, int limit, const std::string& user, const std::string& pass);
```

(Adjust access-section placement to fit the class's existing public/private layout; keep the trampoline-callable pieces public.)

- [ ] **Step 2: Lifecycle (check + thread body + teardown)**

`lib/ProxySQL_Statistics.cpp` (inside `#ifdef PROXYSQLTSDB`):

```cpp
static void * tsdb_cluster_agg_thread_fn(void *arg) {
	set_thread_name("TSDBClusterAgg"); // only if a set_thread_name helper exists in this codebase; otherwise omit
	((ProxySQL_Statistics *)arg)->tsdb_cluster_aggregation_thread_loop();
	return NULL;
}

void ProxySQL_Statistics::tsdb_cluster_aggregation_check(unsigned long long curtime) {
	if (curtime < next_timer_tsdb_cluster_check) return;
	next_timer_tsdb_cluster_check = curtime + 1000000ULL; // evaluate at most every 1s
	bool desired = false;
	if (variables.tsdb_enabled && variables.tsdb_cluster_aggregation) {
		if (GloProxyCluster && GloProxyCluster->is_leader()) {
			desired = true;
		}
	}
	if (desired == true && tsdb_agg_thread_started == false) {
		tsdb_agg_stop.store(false);
		if (pthread_create(&tsdb_agg_thread, NULL, tsdb_cluster_agg_thread_fn, this) == 0) {
			tsdb_agg_thread_started = true;
			tsdb_agg_active.store(true);
			proxy_info("TSDB cluster aggregation: started (this node is the cluster leader)\n");
		} else {
			proxy_error("TSDB cluster aggregation: failed to create worker thread\n");
		}
	} else if (desired == false && tsdb_agg_thread_started == true) {
		tsdb_agg_stop.store(true);
		pthread_join(tsdb_agg_thread, NULL);
		tsdb_agg_thread_started = false;
		tsdb_agg_active.store(false);
		proxy_info("TSDB cluster aggregation: stopped\n");
	}
}

void ProxySQL_Statistics::tsdb_cluster_aggregation_thread_loop() {
	while (tsdb_agg_stop.load() == false) {
		tsdb_cluster_aggregation_cycle();
		tsdb_agg_last_cycle_ts.store((long long)time(NULL));
		int sleep_s = variables.tsdb_cluster_interval;
		if (sleep_s < 5) sleep_s = 5;
		for (int i = 0; i < sleep_s * 10 && tsdb_agg_stop.load() == false; i++) {
			usleep(100000);
		}
	}
}
```

Notes: `is_leader()` takes `leader_mutex` — cheap, once per second. `variables.*` reads from the worker thread are unsynchronized plain-int reads, consistent with existing module style (sampler reads them the same way from the admin thread). Add teardown to `~ProxySQL_Statistics()` (:235-250): if `tsdb_agg_thread_started`, `tsdb_agg_stop.store(true); pthread_join(...);` then finalize `stmt_insert_tsdb_cluster_metric` next to the other two stmt finalizations.

`lib/ProxySQL_Admin.cpp` — inside the TSDB block, after the retention line (:2635-2637), before `#endif`:
```cpp
		GloProxyStats->tsdb_cluster_aggregation_check(curtime);
```
(Unlike the other four, this is called every loop iteration — it self-throttles to 1s and must react to leadership changes promptly.)

- [ ] **Step 3: The cycle**

```cpp
void ProxySQL_Statistics::tsdb_cluster_aggregation_cycle() {
	if (GloProxyCluster == NULL) return;
	if (GloProxyCluster->is_leader() == false) return; // deposed between checks
	std::string self_host; int self_port = 0; std::string self_uuid;
	GloProxyCluster->get_leader_info(self_host, self_port, self_uuid);
	if (self_host.length() == 0) return;
	std::string self_node = self_host + ":" + std::to_string(self_port);
	cluster_creds_t creds = GloProxyCluster->get_credentials();
	SQLite3_result *servers = GloProxyCluster->dump_table_proxysql_servers();
	if (servers == NULL) return;
	long now = (long)time(NULL);
	int limit = variables.tsdb_cluster_batch_rows;
	if (limit < 1000) limit = 1000;
	bool cap_hit = false;
	for (std::vector<SQLite3_row *>::iterator it = servers->rows.begin(); it != servers->rows.end(); ++it) {
		if (tsdb_agg_stop.load()) break;
		SQLite3_row *r = *it;
		std::string node = std::string(r->fields[0]) + ":" + std::string(r->fields[1]);
		long wm = tsdb_agg_effective_watermark(tsdb_cluster_node_max_ts(node), now, variables.tsdb_cluster_backfill_hours);
		if (node == self_node) {
			tsdb_cluster_replicate_self(node, wm, limit);
		} else {
			if (creds.user.length() == 0) continue; // clustering unconfigured
			bool hit = tsdb_cluster_replicate_peer(r->fields[0], atoi(r->fields[1]), node, wm, limit, creds.user, creds.pass);
			if (hit) cap_hit = true;
		}
	}
	tsdb_agg_cap_hit_last_cycle.store(cap_hit);
	delete servers;
}

long ProxySQL_Statistics::tsdb_cluster_node_max_ts(const std::string& node) {
	char *error = NULL; int cols = 0; int affected_rows = 0;
	SQLite3_result *res = NULL;
	std::string q = "SELECT COALESCE(MAX(timestamp),0) FROM tsdb_metrics_cluster WHERE node='" + escape_sql_string_literal(node) + "'";
	statsdb_disk->execute_statement(q.c_str(), &error, &cols, &affected_rows, &res);
	long max_ts = 0;
	if (error == NULL && res != NULL && res->rows_count > 0) {
		max_ts = atol(res->rows[0]->fields[0]);
	}
	if (error) free(error);
	if (res) delete res;
	return max_ts;
}
```

(`escape_sql_string_literal` is an anon-namespace helper in this file at ~:28 — confirm its exact signature and adapt; if it is not visible at the new code's position, move the new functions below it.)

- [ ] **Step 4: Self + peer replication**

```cpp
void ProxySQL_Statistics::tsdb_cluster_replicate_self(const std::string& node, long watermark, int limit) {
	char buf[512];
	std::string esc_node = escape_sql_string_literal(node);
	snprintf(buf, sizeof(buf),
		"INSERT OR IGNORE INTO tsdb_metrics_cluster (node, timestamp, metric_name, labels, value) "
		"SELECT '%s', timestamp, metric_name, labels, value FROM tsdb_metrics "
		"WHERE timestamp > %ld ORDER BY timestamp LIMIT %d",
		esc_node.c_str(), watermark, limit);
	statsdb_disk->execute(buf);
}

bool ProxySQL_Statistics::tsdb_cluster_replicate_peer(const std::string& host, int port, const std::string& node, long watermark, int limit, const std::string& user, const std::string& pass) {
	MYSQL *conn = mysql_init(NULL);
	if (conn == NULL) return false;
	// Same options as the cluster monitor threads (lib/ProxySQL_Cluster.cpp:207-217)
	unsigned int timeout = 1;
	mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	{
		unsigned char val = 1;
		mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val);
		mysql_options(conn, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void *)proxysql_keylog_write_line_callback);
	}
	if (mysql_real_connect(conn, host.c_str(), user.c_str(), pass.c_str(), NULL, port, NULL, 0) == NULL) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "TSDB cluster aggregation: cannot connect to %s : %s\n", node.c_str(), mysql_error(conn));
		mysql_close(conn);
		return false;
	}
	char q[512];
	snprintf(q, sizeof(q),
		"SELECT timestamp, metric_name, labels, value FROM stats_history.tsdb_metrics "
		"WHERE timestamp > %ld ORDER BY timestamp LIMIT %d",
		watermark, limit);
	bool cap_hit = false;
	if (mysql_query(conn, q) == 0) {
		MYSQL_RES *res = mysql_store_result(conn);
		if (res) {
			int rc = 0;
			if (stmt_insert_tsdb_cluster_metric == NULL) {
				rc = statsdb_disk->prepare_v2(
					"INSERT OR IGNORE INTO tsdb_metrics_cluster (node, timestamp, metric_name, labels, value) VALUES (?1, ?2, ?3, ?4, ?5)",
					&stmt_insert_tsdb_cluster_metric);
				// on failure: log once and bail (match the error idiom of stmt_insert_tsdb_metric at :1478-1485)
			}
			int rows = 0;
			long last_row_ts = watermark;
			statsdb_disk->execute("BEGIN");
			MYSQL_ROW row;
			while ((row = mysql_fetch_row(res))) {
				(*proxy_sqlite3_bind_text)(stmt_insert_tsdb_cluster_metric, 1, node.c_str(), -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_int64)(stmt_insert_tsdb_cluster_metric, 2, atoll(row[0]));
				(*proxy_sqlite3_bind_text)(stmt_insert_tsdb_cluster_metric, 3, row[1], -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_text)(stmt_insert_tsdb_cluster_metric, 4, (row[2] ? row[2] : "{}"), -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_double)(stmt_insert_tsdb_cluster_metric, 5, (row[3] ? atof(row[3]) : 0.0));
				SAFE_SQLITE3_STEP2(stmt_insert_tsdb_cluster_metric);
				(*proxy_sqlite3_clear_bindings)(stmt_insert_tsdb_cluster_metric);
				(*proxy_sqlite3_reset)(stmt_insert_tsdb_cluster_metric);
				last_row_ts = atol(row[0]);
				rows++;
			}
			statsdb_disk->execute("COMMIT");
			tsdb_agg_rows_total.fetch_add(rows);
			Tsdb_Agg_Fetch_Result fr = tsdb_agg_apply_fetch(watermark, rows, last_row_ts, limit);
			cap_hit = (fr.caught_up == false);
			// fr.new_watermark is informational here: the watermark is re-derived
			// from MAX(timestamp) in the table each cycle (restart-safe by design).
			mysql_free_result(res);
		}
	} else {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "TSDB cluster aggregation: query failed on %s : %s\n", node.c_str(), mysql_error(conn));
	}
	mysql_close(conn);
	return cap_hit;
}
```

Also track per-peer progress for the spec's visibility requirement: a `std::map<std::string, long> tsdb_agg_peer_last_wm` member (worker-thread-only) — when a peer's watermark hasn't advanced for 10+ consecutive cycles while the node is reachable, `proxy_info` once ("TSDB cluster aggregation: no new samples from %s — peer TSDB likely disabled"), and clear the once-flag when it advances again.

Copy the EXACT bind/step/reset helper spellings from `insert_tsdb_metric` (:1478-1503) — the snippet above shows structure; that function is authoritative for the `proxy_sqlite3_*` function-pointer names and error handling, including the `prepare_v2` overload actually available on `SQLite3DB` for a cached raw `sqlite3_stmt*` (Task 6 of the leader-election plan used the RAII overload; for a CACHED statement follow `stmt_insert_tsdb_metric`'s form instead). Add a `proxy_warning` when `cap_hit` was true for the same peer on 3+ consecutive cycles (simple `std::map<std::string,int>` member, admin-thread-free since only the worker touches it).

- [ ] **Step 5: Build, verify with a scratch 2-node setup, commit**

```bash
PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -3   # header changed → touch src/*.cpp first
```
Manual verification (two scratch instances A=16032/16033 and B=16042/16043, both `--initial`, same recipe as Task 2 plus `cluster_username`/`cluster_password` in admin_variables and a `proxysql_servers` block listing both on 127.0.0.1): on both — `SET tsdb-enabled='1'; SET admin-cluster_leader_election='true'; LOAD TSDB VARIABLES TO RUNTIME; LOAD ADMIN VARIABLES TO RUNTIME;` (order matters: do all SETs while still RW). Wait ~10s for election + a cycle, then on the leader: `SELECT node, COUNT(*) FROM stats_history.tsdb_metrics_cluster GROUP BY node` → rows for BOTH nodes growing; on the follower → 0 rows. `PROXYSQL SHUTDOWN` both.

```bash
git add include/ProxySQL_Statistics.hpp lib/ProxySQL_Statistics.cpp lib/ProxySQL_Admin.cpp
git commit -m "feat(tsdb): cluster aggregation worker - leader replicates peers' TSDB via pull+watermark"
```

---

### Task 4: Query surface (query node param, /api/tsdb/nodes, status)

**Files:**
- Modify: `include/ProxySQL_Statistics.hpp` (`query_tsdb_metrics` signature :238-242; `get_tsdb_cluster_nodes` already declared in Task 3)
- Modify: `lib/ProxySQL_Statistics.cpp` (`query_tsdb_metrics` :1735-1797; new `get_tsdb_cluster_nodes`)
- Modify: `lib/ProxySQL_RESTAPI_Server.cpp` (`tsdb_resource::render_GET` :356-451; registration :536-550)

**Interfaces:**
- Consumes: Task 2 table, Task 3 atomics (`tsdb_agg_active`, `tsdb_agg_rows_total`, `tsdb_agg_last_cycle_ts`, `tsdb_agg_cap_hit_last_cycle`).
- Produces (used by Tasks 5, 6):
  - `SQLite3_result* query_tsdb_metrics(const std::string& metric_name, const std::map<std::string,std::string>& label_filters, time_t from, time_t to, const std::string& aggregation = "", const std::string& node = "")` — `node` empty: existing local behavior unchanged; `node` non-empty: query `tsdb_metrics_cluster` (always raw, never the hourly table), filtered `AND node='<esc>'` unless `node == "*"`.
  - `SQLite3_result* get_tsdb_cluster_nodes()` — columns `node`, `last_timestamp`, `datapoints` (`SELECT node, MAX(timestamp), COUNT(*) FROM tsdb_metrics_cluster GROUP BY node ORDER BY node`).
  - REST: `/api/tsdb/query?...&node=X`; `/api/tsdb/nodes` → `[{node, last_timestamp, watermark_age_s, datapoints}]`; `/api/tsdb/status` gains `cluster_aggregation_active`, `cluster_rows_replicated`, `cluster_last_cycle`, `cluster_cap_hit_last_cycle`.

- [ ] **Step 1: Extend `query_tsdb_metrics`**

Add the trailing defaulted `node` parameter (declaration + definition). In the implementation (:1735-1797): when `node.length() > 0`, force the raw path (`use_hourly = false`), set the table name to `tsdb_metrics_cluster`, and when `node != "*"` append `" AND node='" + escape_sql_string_literal(node) + "'"` to the WHERE clause. Everything else (label filters via `json_extract`, ordering, column list) is unchanged — the cluster table has the same 4 queried columns plus `node`.

- [ ] **Step 2: `get_tsdb_cluster_nodes`**

```cpp
SQLite3_result * ProxySQL_Statistics::get_tsdb_cluster_nodes() {
	char *error = NULL; int cols = 0; int affected_rows = 0;
	SQLite3_result *res = NULL;
	statsdb_disk->execute_statement(
		"SELECT node, MAX(timestamp) AS last_timestamp, COUNT(*) AS datapoints FROM tsdb_metrics_cluster GROUP BY node ORDER BY node",
		&error, &cols, &affected_rows, &res);
	if (error) {
		proxy_error("get_tsdb_cluster_nodes: %s\n", error);
		free(error);
	}
	return res; // may be NULL on error; callers must handle
}
```

- [ ] **Step 3: REST wiring**

In `tsdb_resource::render_GET` (`lib/ProxySQL_RESTAPI_Server.cpp:356`):
- `/api/tsdb/query` branch: before the label-filter loop add `std::string node = req.get_arg("node");` and add `"node"` to the exclusion condition at :414 (`key != "metric" && key != "from" && key != "to" && key != "agg" && key != "node"`); pass `node` as the new last argument to `query_tsdb_metrics`.
- New branch after the status branch (:449):
```cpp
	} else if (req_path == "/api/tsdb/nodes") {
		nlohmann::json nodes_arr = nlohmann::json::array();
		SQLite3_result *res = GloProxyStats->get_tsdb_cluster_nodes();
		time_t now = time(NULL);
		if (res) {
			for (std::vector<SQLite3_row *>::iterator it = res->rows.begin(); it != res->rows.end(); ++it) {
				SQLite3_row *r = *it;
				nlohmann::json jn;
				jn["node"] = r->fields[0];
				long last_ts = atol(r->fields[1]);
				jn["last_timestamp"] = last_ts;
				jn["watermark_age_s"] = (long)now - last_ts;
				jn["datapoints"] = atoll(r->fields[2]);
				nodes_arr.push_back(jn);
			}
			delete res;
		}
		j_resp = nodes_arr;
	}
```
(Match the file's actual json type alias — it may use `json` unqualified; mirror the neighboring branches.)
- `/api/tsdb/status` branch (:437-449): add
```cpp
		j_resp["cluster_aggregation_active"] = GloProxyStats->tsdb_agg_active.load();
		j_resp["cluster_rows_replicated"] = GloProxyStats->tsdb_agg_rows_total.load();
		j_resp["cluster_last_cycle"] = GloProxyStats->tsdb_agg_last_cycle_ts.load();
		j_resp["cluster_cap_hit_last_cycle"] = GloProxyStats->tsdb_agg_cap_hit_last_cycle.load();
```
- Registration (:541 area): `ws->register_resource("/api/tsdb/nodes", tsdb_endpoint.get(), true);`

- [ ] **Step 4: Build, verify, commit**

Rebuild (`touch src/*.cpp` — header changed). Reuse the Task 3 two-node scratch setup with `restapi_enabled="true"; restapi_port=16070` in node A's admin_variables:
- `curl -s http://127.0.0.1:16070/api/tsdb/nodes` → JSON array with both nodes, sane `watermark_age_s`.
- `curl -s "http://127.0.0.1:16070/api/tsdb/query?metric=proxysql_uptime_seconds_total&node=127.0.0.1:16042"` → rows only from node B.
- `curl -s http://127.0.0.1:16070/api/tsdb/status` → the four new fields present.
- Regression: same query WITHOUT `node=` → identical behavior to before (local table).

```bash
git add include/ProxySQL_Statistics.hpp lib/ProxySQL_Statistics.cpp lib/ProxySQL_RESTAPI_Server.cpp
git commit -m "feat(tsdb): node-scoped queries, /api/tsdb/nodes, aggregator status fields"
```

---

### Task 5: Dashboard node selector

**Files:**
- Modify: `lib/TSDB_Dashboard_html.cpp` (embedded HTML/JS string)

**Interfaces:**
- Consumes: Task 4 REST endpoints. Produces: UI only; nothing downstream.

- [ ] **Step 1: Read the embedded dashboard source and add the selector**

Read `lib/TSDB_Dashboard_html.cpp` first — it is one large C string containing the page. Behavioral contract (exact):
1. Next to the existing metric selector control, add `<select id="nodeSel"><option value="">local</option></select>`.
2. On page load, `fetch('/api/tsdb/nodes')` and append one `<option value="{node}">{node} ({watermark_age_s}s behind)</option>` per entry; if the fetch fails or returns an empty array, leave only "local" (feature dormant → dashboard unchanged).
3. Wherever the page builds the `/api/tsdb/query?...` URL, append `&node=` + `encodeURIComponent(sel.value)` when `nodeSel.value` is non-empty.
4. Changing the selector triggers the same refresh path as changing the metric.
No other layout changes. Keep the JS style of the surrounding code (plain ES5/ES6, no new libraries — CSP note: the page must stay self-contained).

- [ ] **Step 2: Verify manually, commit**

Rebuild; on the Task 4 scratch setup open `http://127.0.0.1:16070/tsdb` (or `curl` the HTML and grep for `nodeSel` + the fetch call). Verify: selector present, populated with both nodes, switching changes the plotted series (or at minimum the query URL — check the browser network tab or add a temporary `console.log`; remove it before committing).

```bash
git add lib/TSDB_Dashboard_html.cpp
git commit -m "feat(tsdb): dashboard node selector for cluster view"
```

---

### Task 6: E2E TAP test with synthetic backfill history

**Files:**
- Create: `test/tap/tests/test_cluster_tsdb_aggregation-t.cpp`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: everything, via admin protocol + REST. Produces: CI coverage + the storage-sizing diagnostic.

**Test design (from spec §7):** 3 self-spawned nodes (pattern of `test_cluster_leader_election-t.cpp` — reuse its `node_t`/`write_node_config`/`spawn_node`/`wait_leader` shapes, DIFFERENT ports: admin 16162/16172/16182, mysql +1, weights 300/200/100). Config adds `restapi_enabled`/`restapi_port` (16165/16175/16185). TSDB and aggregation vars are set at runtime under `PROXYSQL READWRITE` (no `tsdb_variables` cnf section exists). Synthetic seed: 3 metrics × 6h at 5s spacing = 12,960 rows/node, distinct values per node, inserted via multi-row INSERTs (500 rows/statement) into `stats_history.tsdb_metrics`. Aggregation tuned for the test: `tsdb-cluster_interval=5`, `tsdb-cluster_batch_rows=1000`, `tsdb-cluster_backfill_hours=2` (horizon = 1,440 rows/metric/node; total in-horizon synthetic per node = 4,320 → ≥5 cycles to catch up, exercising the cap path).

- [ ] **Step 1: Write the test**

Create `test/tap/tests/test_cluster_tsdb_aggregation-t.cpp`:

```cpp
/**
 * @file test_cluster_tsdb_aggregation-t.cpp
 * @brief E2E test for TSDB cluster aggregation (leader pulls peers' tsdb_metrics).
 *
 * Spawns a self-contained 3-node cluster (127.0.0.1:16162/16172/16182,
 * weights 300/200/100), seeds 6h of synthetic history per node, then
 * verifies: leader-only aggregation of all 3 nodes (incl. itself),
 * backfill-horizon trimming, multi-cycle batch-cap catch-up, per-node
 * exactness, /api/tsdb/nodes, failover backfill from peers' retention,
 * and watermark resume after the old leader rejoins.
 * Skips (plan 1) on builds without TSDB or leader election.
 */

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <atomic>
#include <string>
#include <thread>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

struct node_t {
	int idx;
	int admin_port;
	int restapi_port;
	int weight;
	string datadir;
	string cnf_path;
	std::atomic<pid_t> pid { -1 };
	std::thread* runner = nullptr;
};

static node_t nodes_def[3];
static string workdir_path;

static const int SEED_METRICS = 3;
static const long SEED_SPAN_S = 6 * 3600;   // 6h of history
static const long SEED_STEP_S = 5;          // 5s grid
static const int BACKFILL_HOURS = 2;        // horizon << seeded span

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
	fprintf(f, "\trestapi_enabled=\"true\"\n");
	fprintf(f, "\trestapi_port=%d\n", n.restapi_port);
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
	// 'exec' is load-bearing: without it sh forks and the recorded pid is the
	// shell, so SIGKILL would not kill proxysql (see test_cluster_leader_election-t).
	string cmd = "exec " + binary + " -f -M -c " + n.cnf_path + " -D " + n.datadir;
	if (initial) { cmd += " --initial"; }
	cmd += " >> " + stderr_f + " 2>&1";
	n.runner = new std::thread([&n, cmd]() {
		pid_t p = fork();
		if (p == 0) { execl("/bin/sh", "sh", "-c", cmd.c_str(), (char*)nullptr); _exit(127); }
		n.pid.store(p);
		int status = 0;
		waitpid(p, &status, 0);
	});
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

static bool query_ok(MYSQL* conn, const char* q) {
	return mysql_query(conn, q) == 0;
}

static long long single_ll(MYSQL* conn, const string& q, long long defval = -1) {
	if (mysql_query(conn, q.c_str())) { return defval; }
	MYSQL_RES* res = mysql_store_result(conn);
	if (res == NULL) { return defval; }
	MYSQL_ROW row = mysql_fetch_row(res);
	long long v = (row && row[0]) ? atoll(row[0]) : defval;
	mysql_free_result(res);
	return v;
}

static bool var_exists(MYSQL* conn, const char* name) {
	string q = "SELECT count(*) FROM global_variables WHERE variable_name='" + string(name) + "'";
	return single_ll(conn, q, 0) == 1;
}

// Seeds SEED_METRICS synthetic series covering [now-SEED_SPAN_S, now] on the
// node behind `conn`. Values encode the node index for cross-checks.
static bool seed_synthetic(MYSQL* conn, int node_idx, long now) {
	const int rows_per_stmt = 500;
	for (int m = 1; m <= SEED_METRICS; m++) {
		long n_rows = SEED_SPAN_S / SEED_STEP_S;
		long done = 0;
		while (done < n_rows) {
			string q = "INSERT INTO stats_history.tsdb_metrics (timestamp, metric_name, labels, value) VALUES ";
			int in_stmt = 0;
			while (in_stmt < rows_per_stmt && done < n_rows) {
				long ts = now - SEED_SPAN_S + done * SEED_STEP_S;
				if (in_stmt) { q += ","; }
				q += "(" + std::to_string(ts) + ",'synthetic_metric_" + std::to_string(m)
					+ "','{}'," + std::to_string(node_idx * 1000000 + done) + ")";
				in_stmt++;
				done++;
			}
			if (mysql_query(conn, q.c_str())) {
				diag("seed failed on node %d metric %d: %s", node_idx, m, mysql_error(conn));
				return false;
			}
		}
	}
	return true;
}

static string node_id(int i) {
	return "127.0.0.1:" + std::to_string(nodes_def[i].admin_port);
}

static long long cluster_count(MYSQL* conn, const string& node, const string& metric) {
	return single_ll(conn,
		"SELECT COUNT(*) FROM stats_history.tsdb_metrics_cluster WHERE node='" + node
		+ "' AND metric_name='" + metric + "'", -1);
}

// Polls until the count is stable (two equal consecutive reads) or timeout.
static long long wait_stable_count(MYSQL* conn, const string& node, const string& metric, int timeout_s) {
	long long prev = -2;
	for (int i = 0; i < timeout_s; i++) {
		long long c = cluster_count(conn, node, metric);
		if (c >= 0 && c == prev) { return c; }
		prev = c;
		sleep(1);
	}
	return prev;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("Failed to get the required environmental variables."); return -1; }
	workdir_path = cl.workdir;

	const string base = workdir_path + "test_cluster_tsdb_aggregation_config";
	mkdir(base.c_str(), 0777);
	for (int i = 0; i < 3; i++) {
		nodes_def[i].idx = i + 1;
		nodes_def[i].admin_port = 16162 + i * 10;
		nodes_def[i].restapi_port = 16165 + i * 10;
		nodes_def[i].weight = 300 - i * 100;
		nodes_def[i].datadir = base + "/node" + std::to_string(i + 1);
		nodes_def[i].cnf_path = nodes_def[i].datadir + "/node.cnf";
	}
	for (int i = 0; i < 3; i++) {
		mkdir(nodes_def[i].datadir.c_str(), 0777);
		write_node_config(nodes_def[i]);
		spawn_node(nodes_def[i], true);
	}

	MYSQL* a[3] = { admin_conn(nodes_def[0].admin_port), admin_conn(nodes_def[1].admin_port), admin_conn(nodes_def[2].admin_port) };
	if (a[0] == NULL || a[1] == NULL || a[2] == NULL) {
		fprintf(stderr, "File %s, line %d, Error: failed to start the 3 cluster nodes\n", __FILE__, __LINE__);
		for (int i = 0; i < 3; i++) {
			pid_t p = nodes_def[i].pid.load();
			if (p > 0) { kill(p, SIGKILL); }
			join_node(nodes_def[i]);
		}
		return -1;
	}

	bool feature = var_exists(a[0], "admin-cluster_leader_election") && var_exists(a[0], "tsdb-enabled");
	if (feature == false) {
		plan(1);
		ok(1, "TSDB or leader election not compiled in this build - skipping");
	} else {
		plan(27);
		long seed_now = (long)time(NULL);

		// --- Setup under FORCED_RW: tsdb vars + synthetic seed --- (3+3+3)
		for (int i = 0; i < 3; i++) {
			ok(query_ok(a[i], "PROXYSQL READWRITE"), "node%d: PROXYSQL READWRITE", i + 1);
		}
		for (int i = 0; i < 3; i++) {
			bool vars_ok =
				query_ok(a[i], "SET tsdb-enabled='1'") &&
				query_ok(a[i], "SET tsdb-sample_interval='1'") &&
				query_ok(a[i], "SET tsdb-cluster_interval='5'") &&
				query_ok(a[i], "SET tsdb-cluster_batch_rows='1000'") &&
				query_ok(a[i], ("SET tsdb-cluster_backfill_hours='" + std::to_string(BACKFILL_HOURS) + "'").c_str()) &&
				query_ok(a[i], "LOAD TSDB VARIABLES TO RUNTIME");
			ok(vars_ok, "node%d: tsdb variables configured: %s", i + 1, mysql_error(a[i]));
		}
		for (int i = 0; i < 3; i++) {
			ok(seed_synthetic(a[i], i + 1, seed_now), "node%d: synthetic history seeded (%ld rows)",
				i + 1, (long)SEED_METRICS * (SEED_SPAN_S / SEED_STEP_S));
		}

		// --- Release to election --- (3 + 1)
		for (int i = 0; i < 3; i++) {
			ok(query_ok(a[i], "PROXYSQL READONLY AUTO"), "node%d: PROXYSQL READONLY AUTO", i + 1);
		}
		bool leader_ok = false;
		for (int i = 0; i < 30; i++) {
			if (single_ll(a[0], "SELECT COUNT(*) FROM stats_proxysql_servers_status WHERE master='YES' AND port=16162", 0) == 1) { leader_ok = true; break; }
			usleep(500 * 1000);
		}
		ok(leader_ok, "node1 (highest weight) becomes leader");

		// --- Incremental catch-up (batch cap forces multiple cycles) --- (1)
		long long c1 = -1, c2 = -1;
		for (int i = 0; i < 60; i++) {
			long long c = cluster_count(a[0], node_id(1), "synthetic_metric_1");
			if (c > 0 && c1 < 0) { c1 = c; }
			else if (c1 >= 0 && c > c1) { c2 = c; break; }
			sleep(1);
		}
		ok(c1 > 0 && c2 > c1, "replication progresses incrementally across cycles (%lld -> %lld)", c1, c2);

		// --- Exactness within the horizon --- (3)
		// Horizon = 2h at 5s grid = 1440 synthetic rows/metric/node. The leader's
		// first cycle ran within ~60s of seed_now; allow generous slack.
		for (int i = 0; i < 3; i++) {
			long long c = wait_stable_count(a[0], node_id(i), "synthetic_metric_1", 90);
			ok(c >= 1380 && c <= 1470, "node%d synthetic rows within horizon replicated exactly (got %lld, expect ~1440)", i + 1, c);
		}

		// --- Horizon trim: nothing older than ~2h replicated --- (1)
		long long min_ts = single_ll(a[0],
			"SELECT MIN(timestamp) FROM stats_history.tsdb_metrics_cluster WHERE metric_name LIKE 'synthetic_%'", -1);
		ok(min_ts >= seed_now - SEED_SPAN_S + 3 * 3600,
			"backfill horizon trimmed 6h of history to ~2h (min replicated ts %lld)", min_ts);

		// --- Followers do not aggregate --- (2)
		ok(single_ll(a[1], "SELECT COUNT(*) FROM stats_history.tsdb_metrics_cluster", -1) == 0, "node2 (follower) cluster table empty");
		ok(single_ll(a[2], "SELECT COUNT(*) FROM stats_history.tsdb_metrics_cluster", -1) == 0, "node3 (follower) cluster table empty");

		// --- REST /api/tsdb/nodes on the leader --- (1)
		{
			string curl_cmd = "curl -s --max-time 5 http://127.0.0.1:" + std::to_string(nodes_def[0].restapi_port) + "/api/tsdb/nodes";
			FILE* p = popen(curl_cmd.c_str(), "r");
			string out;
			if (p) {
				char buf[4096]; size_t n;
				while ((n = fread(buf, 1, sizeof(buf), p)) > 0) { out.append(buf, n); }
				int rc = pclose(p);
				if (rc != 0 && out.empty()) {
					skip(1, "curl unavailable in the runner");
				} else {
					ok(out.find(node_id(0)) != string::npos && out.find(node_id(1)) != string::npos && out.find(node_id(2)) != string::npos,
						"/api/tsdb/nodes lists all three nodes: %s", out.substr(0, 200).c_str());
				}
			} else {
				skip(1, "popen failed for curl");
			}
		}

		// Storage sizing diagnostic (spec: defaults are placeholders until sized)
		{
			long long rows = single_ll(a[0], "SELECT COUNT(*) FROM stats_history.tsdb_metrics_cluster", -1);
			long long pc = single_ll(a[0], "PRAGMA stats_history.page_count", -1);
			long long ps = single_ll(a[0], "PRAGMA stats_history.page_size", -1);
			diag("SIZING: tsdb_metrics_cluster rows=%lld stats_db_bytes=%lld", rows, (pc > 0 && ps > 0) ? pc * ps : -1);
		}

		// --- Failover: node2 takes over and backfills history it never observed --- (3)
		long long node3_hist_before = cluster_count(a[0], node_id(2), "synthetic_metric_1");
		{
			pid_t p1 = nodes_def[0].pid.load();
			if (p1 > 0) { kill(p1, SIGKILL); }
			join_node(nodes_def[0]);
			mysql_close(a[0]); a[0] = NULL;
		}
		bool failover_ok = false;
		for (int i = 0; i < 30; i++) {
			if (single_ll(a[1], "SELECT COUNT(*) FROM stats_proxysql_servers_status WHERE master='YES' AND port=16172", 0) == 1) { failover_ok = true; break; }
			usleep(500 * 1000);
		}
		ok(failover_ok, "after leader kill, node2 becomes leader");
		long long c_n3 = wait_stable_count(a[1], node_id(2), "synthetic_metric_1", 90);
		ok(c_n3 >= 1380, "new leader backfilled node3 synthetic history predating its leadership (got %lld)", c_n3);
		long long c_self = wait_stable_count(a[1], node_id(1), "synthetic_metric_1", 30);
		ok(c_self >= 1380, "new leader backfilled its own synthetic history (got %lld)", c_self);

		// --- Old leader rejoins, retakes leadership, resumes from its table --- (3)
		spawn_node(nodes_def[0], false);
		a[0] = admin_conn(nodes_def[0].admin_port);
		ok(a[0] != NULL, "node1 restarted and reachable");
		bool retake_ok = false;
		for (int i = 0; i < 40; i++) {
			if (a[0] && single_ll(a[0], "SELECT COUNT(*) FROM stats_proxysql_servers_status WHERE master='YES' AND port=16162", 0) == 1) { retake_ok = true; break; }
			usleep(500 * 1000);
		}
		ok(retake_ok, "rejoined node1 retakes leadership (highest weight)");
		long long c_resume = wait_stable_count(a[0], node_id(2), "synthetic_metric_1", 90);
		ok(a[0] != NULL && c_resume >= node3_hist_before, "node1 resumed aggregation from its surviving watermarks (%lld >= %lld)", c_resume, node3_hist_before);
	}

	// Teardown
	for (int i = 0; i < 3; i++) {
		if (a[i]) {
			mysql_query(a[i], "PROXYSQL SHUTDOWN");
			mysql_close(a[i]);
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

Assertion count check (feature path): 3 (RW) + 3 (vars) + 3 (seed) + 3 (AUTO) + 1 (leader) + 1 (incremental) + 3 (exact) + 1 (horizon) + 2 (followers) + 1 (REST, or skip) + 1 (failover leader) + 1 (node3 backfill) + 1 (self backfill) + 1 (restart) + 1 (retake) + 1 (resume) = **27** = `plan(27)`.

Note on `PRAGMA stats_history.page_count` through the admin interface: if the PRAGMA is rejected or returns nothing, `single_ll` returns -1 and the diag prints -1 — the sizing diagnostic is best-effort, never an assertion.

- [ ] **Step 2: Build and run locally**

```bash
cd test/tap/tests && make test_cluster_tsdb_aggregation-t
# kill any leftovers on 16162/16172/16182 first (ss -ltn | grep 1616)
TAP_WORKDIR="$(pwd)/" LD_LIBRARY_PATH=../tap ./test_cluster_tsdb_aggregation-t
```
Expected: `1..27` all ok. Iterate on timing constants (poll timeouts, not sleeps) if the box is slow. If a failure implicates feature code rather than test timing, STOP and report it — do not adjust the test to mask it. Run twice consecutively clean.

- [ ] **Step 3: Register + lint + commit**

groups.json: `"test_cluster_tsdb_aggregation-t" : [ "legacy-g5", "mysql84-g5", "mysql90-g5", "mysql95-g5" ],`

```bash
python3 test/tap/groups/lint_groups_json.py && python3 test/tap/groups/lint_group_coverage.py
git add test/tap/tests/test_cluster_tsdb_aggregation-t.cpp test/tap/groups/groups.json
git commit -m "test(tsdb): E2E cluster aggregation test with synthetic backfill history"
```

---

### Task 7: Final verification sweep

**Files:** none (verification only).

- [ ] **Step 1: Full clean rebuild (version-string consistency) + build matrix**

```bash
make clean && make -j$(nproc) 2>&1 | tail -3                       # stable tier
make clean && PROXYSQL31=1 make debug -j$(nproc) 2>&1 | tail -3    # target tier — tree must END here
```
Note: `make clean` wipes TAP binaries; rebuild the ones needed below (`cd test/tap/tests && make test_cluster_tsdb_aggregation-t test_cluster_leader_election-t test_cluster_sync-t test_cluster1-t`; unit binaries via `cd test/tap/tests/unit && PROXYSQL31=1 make tsdb_cluster_aggregator_unit-t cluster_leader_election_unit-t`).

- [ ] **Step 2: Unit + E2E on the final tree**

```bash
cd test/tap/tests/unit && ./tsdb_cluster_aggregator_unit-t && ./cluster_leader_election_unit-t
cd ../ && TAP_WORKDIR="$(pwd)/" LD_LIBRARY_PATH=../tap ./test_cluster_tsdb_aggregation-t
TAP_WORKDIR="$(pwd)/" LD_LIBRARY_PATH=../tap ./test_cluster_leader_election-t
```
Expected: all green (1..11, 1..19, 1..27, 1..30).

- [ ] **Step 3: Harness runs (E2E + regressions)**

Long harness invocations MUST run via background execution (a mid-run kill poisons the shared primary and orphans replicas — memory `tap-infra-gotchas` item 7). Known workaround if `ensure-infras` errors on running backends: `export COMPOSE_PROJECT=placeholder`.

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g5 test/infra/control/start-proxysql-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g5 test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g5 \
  TEST_PY_TAP_INCL="test_cluster_tsdb_aggregation-t|test_cluster_leader_election-t" test/infra/control/run-tests-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g5 \
  TEST_PY_TAP_INCL="test_cluster_sync-t|test_cluster1-t|test_tsdb_variables-t" test/infra/control/run-tests-isolated.bash
```
Expected: all PASS. Per CLAUDE.md: any failure gets root-cause analysis (test log + proxysql log + code path), never a "flaky" label.

- [ ] **Step 4: Final state**

```bash
git status --short && git log --oneline v3.0..HEAD
```
Clean except expected untracked `*_config/` run debris; commit list matches the tasks.
