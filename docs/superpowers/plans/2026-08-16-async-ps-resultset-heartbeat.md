# Async Prepared-Statement Resultset Heartbeat Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the established 256 MiB worker-progress heartbeat while an asynchronous prepared statement converts a very large buffered resultset.

**Architecture:** Extend the binary prepared-statement row insertion point, `MySQL_ResultSet::add_row(MYSQL_ROWS *)`, with the same resultset-size boundary check already used by `init_with_stmt()`. The row loop, packet generation, buffer ownership, resultset throttling, and watchdog configuration remain unchanged; only a boundary crossing performs a clock read and heartbeat store.

**Tech Stack:** C++17, MariaDB Connector/C prepared-statement result structures, ProxySQL MySQL worker watchdog, GitHub Actions ASAN TAP integration tests.

## Global Constraints

- Work only on `ci/verify-asan-label`, the branch for PR 6083.
- Keep the existing `0xFFFFFFF` resultset progress boundary used by `init_with_stmt()`.
- Do not update `atomic_curtime` for every row or packet; update it only when output crosses another 256 MiB boundary.
- Do not change watchdog timeouts, `restart_on_missing_heartbeats`, loop bounds, resultset suspension thresholds, or MariaDB coroutine-buffer ownership.
- Leave `CI-unit-tests-asan-coverage` unchanged.
- Leave `mysql84-binlog-g1` to the agent already handling that known issue.
- Preserve the unrelated untracked dependency and lock-file artifacts in the worktree.

---

### Task 1: Restore heartbeat progress in the async PS row-copy path

**Files:**
- Modify: `lib/MySQL_ResultSet.cpp:324-333`
- Test: `test/tap/tests/test_ps_large_result-t.cpp:142-245` (existing regression test; no source modification)

**Interfaces:**
- Consumes: `MySQL_ResultSet::resultset_size`, the packet byte count returned by `MySQL_Protocol::generate_pkt_row3()`, and the owning `myds->sess->thread` worker pointer.
- Produces: one `atomic_curtime` refresh whenever successfully converted prepared-statement output crosses a `0xFFFFFFF` byte boundary.

- [ ] **Step 1: Confirm the existing regression test is red**

Inspect the already-recorded failing ASAN job:

```bash
gh run view 31945039923 --job 95159626833 --log | rg 'test_ps_large_result-t|Missed heartbeat|assert'
```

Expected: `test_ps_large_result-t` starts, the MySQL worker accumulates missed
heartbeats, and ProxySQL aborts before the TAP can fetch all 10,000,000 rows.
This is the required failing end-to-end test; do not weaken or replace it.

- [ ] **Step 2: Implement the minimal boundary-crossing heartbeat**

In `MySQL_ResultSet::add_row(MYSQL_ROWS *rows)`, after
`generate_pkt_row3()` returns `pkt_length` and before incrementing
`resultset_size`, add:

```cpp
const unsigned long long next_resultset_size = resultset_size + pkt_length;
if (
	resultset_size / 0xFFFFFFF != next_resultset_size / 0xFFFFFFF
	&& myds && myds->sess && myds->sess->thread
) {
	myds->sess->thread->atomic_curtime = monotonic_time();
}
```

Replace `resultset_size+=pkt_length;` with:

```cpp
resultset_size = next_resultset_size;
```

Keep packet sequence and row-count updates in their existing order. Do not
modify either loop in `lib/mysql_connection.cpp`.

- [ ] **Step 3: Compile the affected translation unit with ASAN enabled**

Run:

```bash
make -B -C lib obj/MySQL_ResultSet.oo WITHASAN=1 NOJEMALLOC=1
```

Expected: `MySQL_ResultSet.cpp` compiles successfully with
`-fsanitize=address` and no new compiler diagnostics.

- [ ] **Step 4: Review the minimal diff**

Run:

```bash
git diff --check
git diff -- lib/MySQL_ResultSet.cpp
git status --short
```

Expected: no whitespace errors; the production diff is limited to the
boundary check and existing counter assignment; only the plan and intended
source file are tracked changes. The pre-existing untracked artifacts remain
untouched.

- [ ] **Step 5: Commit the production fix**

```bash
git add lib/MySQL_ResultSet.cpp
git commit -m "fix: heartbeat during large PS resultsets"
```

Expected: the commit contains only `lib/MySQL_ResultSet.cpp`.

### Task 2: Publish and verify the ASAN regression fix on PR 6083

**Files:**
- Modify: no additional files unless verification demonstrates a defect in the approved heartbeat implementation.
- Test: PR 6083 check `CI-mysql84-g8`, including `test_ps_large_result-t`.

**Interfaces:**
- Consumes: the `ci:asan` label already attached to PR 6083 and the branch commits from Task 1.
- Produces: a new label-selected ASAN CI run in which `test_ps_large_result-t` completes without a watchdog abort.

- [ ] **Step 1: Publish the branch**

```bash
git push origin ci/verify-asan-label
```

Expected: PR 6083 advances to the pushed implementation head. Adding or
removing labels is not used to trigger the run.

- [ ] **Step 2: Verify the PR still selects ASAN solely through its label**

```bash
gh pr view 6083 --json url,headRefName,headRefOid,labels
```

Expected: the head branch is `ci/verify-asan-label` and the labels include
`ci:asan`.

- [ ] **Step 3: Wait for the new PR checks**

```bash
gh pr checks 6083 --watch --interval 30
```

Expected: a new build and fan-out run is associated with the pushed head. Do
not retrigger it by changing labels.

- [ ] **Step 4: Verify the large-result regression specifically**

Resolve the latest branch run for `CI-mysql84-g8` and search its log:

```bash
heartbeat_g8_run_id=$(gh run list --workflow CI-mysql84-g8.yml --branch ci/verify-asan-label --limit 1 --json databaseId --jq '.[0].databaseId')
gh run view "$heartbeat_g8_run_id" --log | rg -C 4 'test_ps_large_result-t|Missed heartbeat|Fetched 10000000 rows|Fetched 4GB'
```

Expected: `test_ps_large_result-t` reports both `Fetched 10000000 rows` and
`Fetched 4GB`, with no watchdog missed-heartbeat termination and no ASAN
finding. If another test fails, classify it separately before making any
additional code change.

- [ ] **Step 5: Report remaining independent failures accurately**

Run:

```bash
gh pr checks 6083
```

Expected: report the heartbeat regression independently from known
`mysql84-binlog-g1` work and from the AI workflow handoff fix tracked in PR
6097. Do not claim PR 6083 is entirely green unless every required check has
actually passed.
