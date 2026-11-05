# DuckDB replica crash and snapshot concurrency implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline in the existing feature worktree.

**Goal:** Validate the handoff's crash-recovery and concurrent-snapshot-write contracts against real MySQL and a real ProxySQL process.
**Architecture:** A new TAP scenario owns a child ProxySQL, temporary configuration/data directory and loopback ports. It uses SQL-visible snapshot progress to establish overlap, kills only its own child with SIGKILL, then reopens the same files. No production test switches or timing hooks.
**Tech Stack:** C++17, POSIX process/socket APIs, MySQL 8.4, DuckDB 1.4.5, TAP.
**Spec:** docs/superpowers/specs/2026-11-05-duckdb-mysql-replica-design.md sections 6, 7, 9 and 10.3.

## Global Constraints

- File-backed DuckDB; ROW/FULL GTID source; ordinary query routing unchanged.
- Exact row equality and durable file/position/GTID must converge after recovery; no gap or duplicate.
- Source credentials never printed. Only process, files, user and schema owned by this fixture may be destroyed.
- Preserve the normal test-group ProxySQL. Snapshot must really overlap committed writes and really be incomplete when killed; a missed timing window fails explicitly.

## Review Focus

- Incomplete snapshot must not leave a committed manifest or position that skips a new snapshot.
- Multi-table source transactions committed during snapshot must appear exactly once after catch-up.
- Recovery after a committed batch must resume without needing RELOAD (no silent resnapshot).
- Abrupt termination during backlog apply must recover complete transactions with the matching checkpoint, regardless of which side of COMMIT the crash hits.
- Failed setup/assertions must reap the child and drop only fixture-owned source objects; retain logs on failure.

### Task 1: Self-managed recovery scenario

**Files:** new test/tap/tests/test_duckdb_replica_recovery-t.cpp; test/tap/tests/Makefile; test/tap/groups/groups.json.
**Interfaces:** source credentials use standard TAP_MYSQL*; binary/plugin paths default to repository build paths with TAP_PROXYSQL_BINARY and TAP_DUCKDB_PLUGIN overrides. The child owns dynamic loopback ports; parent never signals a test-group server.

- [x] Add child process lifecycle, local temporary config, bounded readiness/waits, source schema and least-privilege replica account.
- [x] Seed enough source rows to observe positive snapshot progress; commit insert/update/delete across two tables while snapshotting, assert actual overlap and exact final row equality plus checkpoint agreement.
- [x] STOP/RESET and START; wait for positive snapshot progress with no visible durable metadata, SIGKILL, add offline source changes, restart and assert a fresh correct snapshot.
- [x] Commit a recognizable batch; keep a source transaction open across SIGKILL then roll it back; add offline commits, revoke RELOAD, restart and assert exact resume without duplicates or rolled-back changes.
- [x] Create a large replay backlog; crash while catch-up is active, restart and assert exact convergence and final checkpoint agreement. The before/after COMMIT outcome is deliberately allowed; partial commits are not.
- [x] Run with NONE and CRC32. Confirm the assertions detect representative broken snapshot/checkpoint behavior by a temporary production mutation, then restore it.

### Task 2: Fix exposed defects, validate and document

**Files:** only production files implicated by an observed failing test; handoff and this plan.

- [x] For any real defect, keep the failing regression, fix minimally and rerun affected tests.
- [x] Run existing live replica coverage and the appropriate affected unit/listener coverage.
- [x] Request one read-only code review; address material findings, update handoff/evidence, commit validated work.

## Boundaries

This tests process crashes, not power loss or torn filesystem writes. It does not deterministically interrupt the instruction between DuckDB DML and checkpoint COMMIT; atomic recovery is checked through observable rows and coordinates. Large positions, read-only authorization, performance and packaging remain separate.

## Validation results

- New recovery scenario: 19/19 with NONE and CRC32; Linux full child ProxySQL SIGKILL, source MySQL 8.4.8, DuckDB 1.4.5.
- Mutation: omit START TRANSACTION WITH CONSISTENT SNAPSHOT -> concurrent-table INSERT duplicates id5 and fails check5.
- Mutation: ignore persisted checkpoint -> revoked RELOAD rejects unintended resnapshot and fails check10.
- Both mutations restored byte-for-byte; no production source changes were required.
- All nine DuckDB unit binaries remain green: 371 assertions.
- Review found Linux CI timeout orphan handling; SIGKILLing TAP parent reproduced a surviving child before PR_SET_PDEATHSIG. With the fix and PID-race check the child dies; follow-up review cleared material findings.
- Final reviewed CRC32 rerun: 19/19. Existing ordinary replica: 31/31; compatibility: 39/39; Admin tables: 22/22; MySQL listener: 17/17. The handoff retains the six known baseline PostgreSQL failures; this test-only change does not alter that listener.
