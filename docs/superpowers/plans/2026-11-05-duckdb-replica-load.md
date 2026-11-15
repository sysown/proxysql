# DuckDB replica load characterization implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline in the existing feature worktree.

**Goal:** Measure snapshot cost, apply throughput, commit-to-visible latency and child RSS with and without analytical readers, while checking replicated rows and coordinates.
**Architecture:** Reuse the recovery test's isolated child/source fixture through a shared test header. An opt-in TAP benchmark runs paced writes, concurrent full-table aggregates and a large source transaction. A replicated marker per transaction gives local-clock visibility latency for every committed transaction, including transactions coalesced into one apply batch. Source/replica exact equality is audited outside each timed interval.
**Tech Stack:** C++17, MySQL 8.4, DuckDB 1.4.5, TAP, Linux /proc RSS sampling.
**Spec:** docs/superpowers/specs/2026-11-05-duckdb-mysql-replica-design.md sections 7, 9 and 10.3.

## Global Constraints

- No production changes or speed thresholds. This characterizes the current applier rather than prescribing a performance target.
- Explicit RUN_DUCKDB_REPLICA_BENCH=1 opt-in; default test skips without creating a child or touching MySQL.
- Own private ProxySQL ports/files and source account/schema; keep parent-death handling and cleanup from the recovery test.
- No full-row audits inside timed intervals. Poll only a small replicated transaction ledger; measure lag from source COMMIT response to observer receipt on one monotonic clock.
- Report achieved source rate separately from requested rate, include drain time, and label row throughput as source data rows (excluding marker rows).

## Review Focus

- Coalesced marker observations must count every transaction; late publication of commit timestamps must not lose a marker or create negative latency.
- A failed or stalled replica must fail the benchmark rather than report misleading throughput.
- Worker connections must remain thread-confined and all workers must join before fixture teardown.
- Shared helper extraction must preserve real SIGKILL recovery behavior; seed-row count is bounded to the existing SQL generator's capacity.
- RSS is child-process resident memory, sampled per interval, not DuckDB allocation or whole-host memory; hardware and settings go in the report.

### Task 1: Reusable fixture and benchmark

**Files:** new test/tap/tests/duckdb_replica_test_utils.h; modify recovery test/Makefile/groups; new test/tap/tests/test_duckdb_replica_bench-t.cpp.

- [x] Extract the existing real fixture unchanged except a bounded configurable source row count; rerun recovery19.
- [x] Add opt-in and validated REPLICA_BENCH_ROWS/SECONDS/RATE/TXN_ROWS/READERS/LARGE_TXN_ROWS/TIMEOUT controls.
- [x] Time snapshot readiness and sample child RSS; audit exact contents/coordinates after stopping the timer.
- [x] Run paced updates plus one inserted marker per source transaction without readers, then with the requested number of readers; capture every commit-to-visible latency, aggregate query latency and completion/drain rates.
- [x] Run one large transaction to measure replay completion independently of source pacing; audit exact rows/coordinates for every phase.
- [x] Verify skip mode, run a negative stalled-applier check, and record three repeated default workloads.

### Task 2: Review and report

**Files:** docs/superpowers/benchmarks/2026-11-05-duckdb-replica-load.md; handoff and plan.

- [x] Record observed rates, lag, RSS and settings; distinguish measurements from bottleneck hypotheses and avoid extrapolating an SLA.
- [x] Obtain one read-only review, fix concrete issues and rerun affected cases.
- [x] Preserve the prior handoff correction withdrawing the unproven 4 GB truncation claim, then commit the validated benchmark and report.

## Completed evidence

- Default disabled run skips without creating resources; small enabled smoke passes11.
- Stopped owned applier fails the committed-marker deadline, with failure cleanup passing.
- Shared-fixture recovery regression passes19; the recovery scenario body is unchanged.
- Three default RATE50 and three RATE5 runs each pass11, auditing exact source/target contents and coordinates for every phase.
- Read-only review caught missing grouped-runner environment forwarding; opt-in and all seven controls now forward, with shell syntax valid. Code review cleared material findings.
- Measured report and 24-phase CSV are in docs/superpowers/benchmarks/2026-11-05-duckdb-replica-load.{md,csv}.
- No production changes or performance optimization; the prior correction withdrawing the unproven truncation claim is preserved in the handoff.
