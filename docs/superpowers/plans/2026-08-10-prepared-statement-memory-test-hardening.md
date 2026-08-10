# Prepared-Statement Memory Test Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `test_prepare_statement_memory_usage-t` retain its memory-counter coverage without failing when unrelated prepared statements are concurrently released.

**Architecture:** The TAP test will take stable statement-table/memory samples, compare complete statement snapshots with the target query removed, and retry only contaminated measurement windows. Process-unique queries preserve new-statement semantics across retries, while condition polling replaces the fixed close delay.

**Tech Stack:** C++17, MariaDB/MySQL client prepared-statement API, ProxySQL Admin SQLite tables, project TAP and `utils.h` helpers, isolated MySQL 8.4 Docker test infrastructure.

## Global Constraints

- Modify only `test/tap/tests/test_prepare_statement_memory_usage-t.cpp` plus the approved design and plan documents.
- Preserve checks of `prepare_statement_metadata_memory` and `prepare_statement_backend_memory`.
- Preserve four logical checks and exactly twelve TAP assertions.
- Do not change ProxySQL prepared-statement accounting, CI group membership, or test ordering.
- Do not flush shared connection pools or mutate infrastructure-wide state.
- Use bounded condition polling; do not add an arbitrary fixed sleep as synchronization.
- Base the branch on the latest `origin/v3.0`.

---

## File Structure

- Modify: `test/tap/tests/test_prepare_statement_memory_usage-t.cpp`
  - Owns Admin snapshot reads, stable sampling, contamination detection,
    statement-close synchronization, the four memory measurements, and TAP
    reporting. Keeping these helpers in the test avoids adding test-only APIs
    to production classes.
- Existing: `docs/superpowers/specs/2026-08-10-prepared-statement-memory-test-hardening-design.md`
  - Records the approved behavior and trade-offs.
- Create: `docs/superpowers/plans/2026-08-10-prepared-statement-memory-test-hardening.md`
  - Records this executable checklist.

---

### Task 1: Record the Existing Failure and Establish the Baseline

**Files:**
- Inspect: `test/tap/tests/test_prepare_statement_memory_usage-t.cpp`
- Inspect: `test/tap/groups/groups.json`
- Inspect: `ci_infra_logs` produced by the isolated run

**Interfaces:**
- Consumes: the existing twelve-assertion TAP executable and the
  `mysql84-g8` group ordering.
- Produces: RED evidence showing that a correct target prepare can be hidden by
  unrelated statement-reference cleanup.

- [ ] **Step 1: Build the current debug daemon and focused TAP binaries**

Run:

```bash
make -j32 debug
make -C test/tap/tests -j32 test_noise_injection-t test_prepare_statement_memory_usage-t
```

Expected: both commands exit 0 and `src/proxysql` contains DEBUG Admin command support.

- [ ] **Step 2: Run the current test after the noise test in isolated MySQL 8.4 infrastructure**

Run:

```bash
export INFRA_ID="prepared-memory-red-20260810"
export TAP_GROUP="mysql84-g8"
./test/infra/control/ensure-infras.bash
./test/infra/control/start-proxysql-isolated.bash
TEST_PY_TAP_INCL='^(test_noise_injection-t|test_prepare_statement_memory_usage-t)$' \
  ./test/infra/control/run-tests-isolated.bash
```

Expected RED when the race is hit: `test_prepare_statement_memory_usage-t`
reports a metadata or backend counter decrease even though the target query is
present in `stats_mysql_prepared_statements_info`. If local timing does not hit
the race, retain the already captured RED evidence from GitHub Actions run
`31398168744`, where metadata fell `27618 -> 25834`, backend fell
`65824 -> 59536`, and five unrelated server reference counts decreased.

- [ ] **Step 3: Clean the isolated RED infrastructure**

Run:

```bash
docker rm -f "test-runner.prepared-memory-red-20260810" >/dev/null 2>&1 || true
INFRA_ID="prepared-memory-red-20260810" TAP_GROUP="mysql84-g8" \
  ./test/infra/control/destroy-infras.bash
```

Expected: the ProxySQL container, test runner, backend infrastructure, and
isolated network for this exact `INFRA_ID` are absent.

---

### Task 2: Add Stable Samples and Contamination Detection

**Files:**
- Modify: `test/tap/tests/test_prepare_statement_memory_usage-t.cpp`

**Interfaces:**
- Consumes: `mysql_query_ext_rows(MYSQL*, const std::string&)`,
  `monotonic_time()`, `mysql_stmt_prepare`, and the Admin tables
  `stats_memory_metrics` and `stats_mysql_prepared_statements_info`.
- Produces:
  - `PreparedStatementInfo` and `StatementSnapshot`
  - `MemoryUsage` and `StableSample`
  - `read_statement_snapshot(MYSQL*, StatementSnapshot&, std::string&)`
  - `read_memory_usage(MYSQL*, MemoryUsage&, std::string&)`
  - `read_stable_sample(MYSQL*, StableSample&, std::string&)`
  - `same_unrelated_statements(const StatementSnapshot&, const StatementSnapshot&, const std::string&)`

- [ ] **Step 1: Define typed snapshots and comparison semantics**

Add explicit C++ standard-library includes and these test-local shapes:

```cpp
struct PreparedStatementInfo {
    std::string schemaname;
    std::string username;
    std::string digest;
    uint64_t ref_count_client {0};
    uint64_t ref_count_server {0};
    uint64_t num_columns {0};
    uint64_t num_params {0};
    std::string query;

    bool operator==(const PreparedStatementInfo& rhs) const;
};

using StatementSnapshot = std::map<uint64_t, PreparedStatementInfo>;

struct MemoryUsage {
    uint64_t metadata {0};
    uint64_t backend {0};
};

struct StableSample {
    MemoryUsage memory;
    StatementSnapshot statements;
};
```

The equality operator must compare every field. The full snapshot is keyed by
`global_stmt_id`; target filtering removes every row whose `query` exactly
matches the process-unique target query.

- [ ] **Step 2: Read complete prepared-statement snapshots**

Implement `read_statement_snapshot` with `mysql_query_ext_rows` and this exact
column order:

```sql
SELECT global_stmt_id, schemaname, username, digest,
       ref_count_client, ref_count_server, num_columns, num_params, query
FROM stats_mysql_prepared_statements_info
ORDER BY global_stmt_id
```

Require nine fields per row, convert numeric fields with `std::stoull`, and
return `EXIT_FAILURE` with an error string for query, row-shape, or conversion
failures. Do not emit TAP assertions from this helper.

- [ ] **Step 3: Replace the current memory reader with typed error handling**

Implement `read_memory_usage` using `mysql_query_ext_rows`. Require exactly the
two named metrics, reject duplicate, missing, unknown, malformed, or
non-numeric rows, and populate `MemoryUsage`. The helper returns status and an
error string without consuming the TAP plan.

- [ ] **Step 4: Read a stable snapshot-memory-snapshot sample**

Implement `read_stable_sample` with a five-second monotonic deadline and a
10-millisecond poll interval:

```cpp
StatementSnapshot before;
StatementSnapshot after;
while (monotonic_time() < deadline) {
    read_statement_snapshot(admin, before, error);
    read_memory_usage(admin, sample.memory, error);
    read_statement_snapshot(admin, after, error);
    if (before == after) {
        sample.statements = std::move(after);
        return EXIT_SUCCESS;
    }
    usleep(kPollIntervalUs);
}
```

Return immediately on an Admin query or parse error. On timeout, report that a
stable prepared-statement sample could not be obtained.

- [ ] **Step 5: Detect only unrelated changes**

Implement `same_unrelated_statements` by filtering the exact target query from
copies of both snapshots and comparing the remaining maps. Add a diagnostic
helper that reports added, removed, or changed `global_stmt_id` values when a
measurement is discarded.

- [ ] **Step 6: Compile after adding the sampling layer**

Run:

```bash
make -C test/tap/tests -j32 test_prepare_statement_memory_usage-t
```

Expected: exit 0 with no new warnings from this test file.

---

### Task 3: Retry Contaminated Measurements and Synchronize Statement Close

**Files:**
- Modify: `test/tap/tests/test_prepare_statement_memory_usage-t.cpp`

**Interfaces:**
- Consumes: the stable-sample interfaces from Task 2 and one established
  frontend connection, whose backend-local cache is required by reuse checks.
- Produces:
  - `MeasurementStatus { kAccepted, kContaminated, kError }`
  - `MeasurementResult { status, query, before, after, error }`
  - `wait_for_client_release(MYSQL*, const std::string&, std::string&)`
  - `measure_once(MYSQL*, MYSQL*, const std::string&)`
  - `measure_new_statement(MYSQL*, MYSQL*, uint64_t&)`
  - `measure_existing_statement(MYSQL*, MYSQL*, const std::string&)`

- [ ] **Step 1: Add state-based close synchronization**

Implement `wait_for_client_release` with the same five-second deadline and
10-millisecond polling. Re-read the statement snapshot until every row matching
the exact target query has `ref_count_client == 0`; a missing target row also
means released. Return query failures and deadline expiration explicitly.

- [ ] **Step 2: Implement one guarded prepare measurement**

`measure_once` must perform these actions in order:

```text
read stable before sample
initialize and prepare MYSQL_STMT
read stable after sample while MYSQL_STMT remains open
compare all unrelated statement rows
close MYSQL_STMT
wait until the target client reference reaches zero
return accepted metrics, contaminated status, or terminal error
```

An Admin/read/prepare/close-settle failure is `kError`. A successful prepare
whose unrelated snapshots differ is `kContaminated`; emit diagnostics but no
TAP assertions.

- [ ] **Step 3: Retry new statements with process-unique queries**

Generate candidates in this form, incrementing `sequence` for every attempt:

```cpp
"SELECT 1 AS test_prepare_statement_memory_usage_" +
    std::to_string(getpid()) + "_" + std::to_string(sequence++)
```

Retry `kContaminated` results until the five-second measurement deadline.
Return the accepted query so later checks reuse that exact statement. Never
retry `kError`.

- [ ] **Step 4: Retry reuse measurements without changing the query**

`measure_existing_statement` applies the same bounded contamination retry to
the exact accepted query. Because `wait_for_client_release` has observed zero
client references before the next attempt, each retry measures the same
client-mapping allocation while preserving the backend-local prepared
statement.

- [ ] **Step 5: Emit exactly three assertions per logical measurement**

Replace the bit-mask comparison enum and the old helper with one reporter that
always emits:

```cpp
ok(result.status == MeasurementStatus::kAccepted,
   "Prepare succeeded with an uncontaminated sample: %s", result.query.c_str());
ok(accepted && result.after.metadata > result.before.metadata,
   "Prepared-statement metadata memory increased: %lu -> %lu", ...);
ok(accepted && (expect_backend_equal
       ? result.after.backend == result.before.backend
       : result.after.backend >= result.before.backend),
   "Prepared-statement backend memory %s: %lu -> %lu", ...);
```

Run two new-statement measurements, then reuse each accepted query. If a new
measurement fails, construct an explicit error result for its dependent reuse
check so the test still emits all twelve planned assertions. Remove the fixed
`usleep(10000)`.

- [ ] **Step 6: Build the hardened TAP binary**

Run:

```bash
make -C test/tap/tests -j32 test_prepare_statement_memory_usage-t
```

Expected: exit 0 with no compiler errors or warnings introduced by the change.

- [ ] **Step 7: Review the focused diff before runtime validation**

Run:

```bash
git diff --check
git diff -- test/tap/tests/test_prepare_statement_memory_usage-t.cpp
```

Expected: whitespace check exits 0; the code diff contains only snapshot
sampling, bounded retry/synchronization, unique queries, and TAP reporting.

---

### Task 4: Prove GREEN in Clean and Polluted Infrastructure

**Files:**
- Test: `test/tap/tests/test_prepare_statement_memory_usage-t.cpp`
- Inspect: `ci_infra_logs/prepared-memory-green-20260810/`

**Interfaces:**
- Consumes: the hardened test binary from Task 3 and the debug daemon from
  Task 1.
- Produces: fresh runtime evidence for clean and post-noise execution.

- [ ] **Step 1: Start fresh isolated MySQL 8.4 infrastructure**

Run:

```bash
export INFRA_ID="prepared-memory-green-20260810"
export TAP_GROUP="mysql84-g8"
./test/infra/control/ensure-infras.bash
./test/infra/control/start-proxysql-isolated.bash
```

Expected: backend and `proxysql.prepared-memory-green-20260810` containers are
healthy and the Admin endpoint is reachable.

- [ ] **Step 2: Run the hardened test alone**

Run:

```bash
TEST_PY_TAP_INCL='^test_prepare_statement_memory_usage-t$' \
  ./test/infra/control/run-tests-isolated.bash
```

Expected: exactly `1..12`, twelve `ok` assertions, and exit 0.

- [ ] **Step 3: Restart ProxySQL and run the noise-to-memory ordering**

Run:

```bash
INFRA_ID="prepared-memory-green-20260810" TAP_GROUP="mysql84-g8" \
  ./test/infra/control/start-proxysql-isolated.bash
TEST_PY_TAP_INCL='^(test_noise_injection-t|test_prepare_statement_memory_usage-t)$' \
  ./test/infra/control/run-tests-isolated.bash
```

Expected: both tests pass. The memory test may diagnose and retry contaminated
windows, but it emits exactly twelve successful TAP assertions.

- [ ] **Step 4: Clean the isolated GREEN infrastructure**

Run:

```bash
docker rm -f "test-runner.prepared-memory-green-20260810" >/dev/null 2>&1 || true
INFRA_ID="prepared-memory-green-20260810" TAP_GROUP="mysql84-g8" \
  ./test/infra/control/destroy-infras.bash
```

Expected: no containers or network remain for the exact GREEN `INFRA_ID`.

---

### Task 5: Final Verification, Commit, Push, and Draft PR

**Files:**
- Modify: `test/tap/tests/test_prepare_statement_memory_usage-t.cpp`
- Include: `docs/superpowers/specs/2026-08-10-prepared-statement-memory-test-hardening-design.md`
- Include: `docs/superpowers/plans/2026-08-10-prepared-statement-memory-test-hardening.md`

**Interfaces:**
- Consumes: all prior GREEN evidence.
- Produces: one focused branch and a dedicated draft PR targeting `v3.0`.

- [ ] **Step 1: Run fresh static and repository checks**

Run:

```bash
git diff --check
python3 test/tap/groups/lint_groups_json.py
git status --short --branch
```

Expected: both checks exit 0; status lists only the intended test and plan
changes before committing.

- [ ] **Step 2: Commit the implementation**

Run:

```bash
git add test/tap/tests/test_prepare_statement_memory_usage-t.cpp \
  docs/superpowers/plans/2026-08-10-prepared-statement-memory-test-hardening.md
git commit -m "test: isolate prepared statement memory measurements"
```

Expected: the implementation commit contains no production code or group
membership changes.

- [ ] **Step 3: Verify the complete branch after committing**

Run:

```bash
git diff --check origin/v3.0...HEAD
git log --oneline origin/v3.0..HEAD
git status --short --branch
```

Expected: two focused commits (design, implementation), clean working tree,
and no whitespace errors.

- [ ] **Step 4: Push the dedicated branch**

Run:

```bash
git push -u origin agent/harden-prepared-statement-memory-test
```

Expected: the remote branch advances to the verified local HEAD.

- [ ] **Step 5: Open a draft PR targeting `v3.0`**

Create a draft PR titled:

```text
test: harden prepared statement memory measurements
```

The body must explain the global-counter race, the snapshot contamination
guard, state-based close synchronization, preserved twelve assertions, and
the exact clean and post-noise validation results.
