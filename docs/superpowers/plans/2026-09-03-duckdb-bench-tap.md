# DuckDB TAP Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Local-only TAP harness comparing native DuckDB, plugin MySQL/PG, and SQLite3 Server.

**Architecture:** One TAP binary in `duckdb-e2e-g1`. Skip unless `RUN_DUCKDB_BENCH=1`. Native path uses the DuckDB C API; wire paths use libmysqlclient/libpq. Numbers go to `diag()`; TAP `ok()` is errors==0 only.

**Tech Stack:** C++17, DuckDB C API, libmysqlclient, libpq, TAP, GNU Make.

**Spec:** `docs/superpowers/specs/2026-09-03-duckdb-bench-tap-design.md`

## File structure

| File | Responsibility |
|---|---|
| `test/tap/tests/test_duckdb_bench-t.cpp` | Harness |
| `test/tap/tests/Makefile` | PROXYSQL40 link recipe + v3 error |
| `test/tap/groups/groups.json` | `duckdb-e2e-g1` |
| `test/infra/control/run-tests-isolated.bash` | Forward `RUN_DUCKDB_BENCH` / `BENCH_*` |
| `doc/duckdb/operations.md` | How to run |

### Task 1: TAP binary

- [x] Create `test/tap/tests/test_duckdb_bench-t.cpp` per spec (skip gate, four targets, three workloads, fairness table).

### Task 2: Build and registration

- [x] Filter `test_duckdb_bench-t` from v3 `TESTS_CPP`; PROXYSQL40 recipe links `DUCKDB_ARS`.
- [x] `groups.json` entry on `duckdb-e2e-g1`.
- [x] Docker `-e` forwarding in `run-tests-isolated.bash`.

### Task 3: Docs

- [x] `doc/duckdb/operations.md` section **Local benchmark TAP**.

### Task 4: Verify

- [ ] `cd test/tap/tests && make test_duckdb_bench-t` on a v3/unbuilt tree prints `ERROR: test_duckdb_bench-t is PROXYSQL40-only`.
- [ ] With a PROXYSQL40 debug build: skip path (unset `RUN_DUCKDB_BENCH`) yields 12 skipped; `RUN_DUCKDB_BENCH=1` via `run-tests-isolated.bash` prints the table.
